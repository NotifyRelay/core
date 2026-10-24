use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::protocol::codec;
use crate::SafeContext;

/// 在线判定窗口（秒）：last_seen 在此窗口内视为已连接，跳过自动握手
const RECENT_SEEN_SECS: i64 = 15;

/// 重连目标设备信息
#[derive(Clone)]
struct ReconnectTarget {
    ip: String,
    last_attempt: Option<Instant>,
}

pub struct ReconnectState {
    inner: Arc<Mutex<ReconnectInner>>,
    running: Arc<AtomicBool>,
}

struct ReconnectInner {
    targets: HashMap<String, ReconnectTarget>,
    /// 重连间隔（秒）
    retry_interval_secs: u64,
    /// 最大重连次数（0=无限）
    max_retries: u32,
    /// 当前重连尝试次数
    attempt_counts: HashMap<String, u32>,
}

impl ReconnectState {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(ReconnectInner {
                targets: HashMap::new(),
                retry_interval_secs: 10,
                max_retries: 0,
                attempt_counts: HashMap::new(),
            })),
            running: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl Default for ReconnectState {
    fn default() -> Self {
        Self::new()
    }
}

impl ReconnectState {
    /// 添加重连目标
    pub fn add_target(&self, uuid: &str, ip: &str) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.targets.insert(
                uuid.to_string(),
                ReconnectTarget {
                    ip: ip.to_string(),
                    last_attempt: None,
                },
            );
            guard.attempt_counts.entry(uuid.to_string()).or_insert(0);
        }
    }

    /// 移除重连目标（连接成功或放弃）
    pub fn remove_target(&self, uuid: &str) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.targets.remove(uuid);
            guard.attempt_counts.remove(uuid);
        }
    }

    /// 设置重连参数
    pub fn configure(&self, interval_secs: u64, max_retries: u32) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.retry_interval_secs = interval_secs;
            guard.max_retries = max_retries;
        }
    }

    /// 启动重连检测线程
    pub fn start(&self, ctx_ptr: usize) {
        if self.running.load(Ordering::Relaxed) {
            return;
        }
        self.running.store(true, Ordering::Relaxed);

        let inner = self.inner.clone();
        let running = self.running.clone();

        thread::Builder::new()
            .name("reconnect".to_string())
            .spawn(move || {
                loop {
                    if !running.load(Ordering::Relaxed) {
                        break;
                    }

                    let mut to_reconnect: Vec<(String, String)> = Vec::new();

                    let mut to_remove: Vec<String> = Vec::new();
                    if let Ok(mut guard) = inner.lock() {
                        let now = Instant::now();
                        let uuids: Vec<String> = guard.targets.keys().cloned().collect();

                        for uuid in &uuids {
                            // 跳过本机自身（重连目标中不应包含本机）
                            let is_self = {
                                // 后台线程：通过 lock() 取锁，与 FFI/扫描回调共用同一把锁
                                let ctx = unsafe { &*(ctx_ptr as *const SafeContext) };
                                ctx.lock()
                                    .ok()
                                    .and_then(|g| {
                                        g.broadcast_info.as_ref().map(|b| b.uuid == *uuid)
                                    })
                                    .unwrap_or(false)
                            };
                            if is_self {
                                guard.attempt_counts.remove(uuid);
                                to_remove.push(uuid.clone());
                                continue;
                            }

                            // 在线判定：最近收到过对方心跳（last_seen 在窗口内）即视为已连接。
                            // 不依赖 TCP 会话：协议连接均为短连接（session 随连接关闭立即移除），
                            // 用 tcp.is_connected 判定会永远失败，导致无限重复握手。
                            let connected = {
                                let ctx = unsafe { &*(ctx_ptr as *const SafeContext) };
                                match ctx.lock() {
                                    Ok(guard) => {
                                        guard.heartbeat.is_recently_seen(uuid, RECENT_SEEN_SECS)
                                    }
                                    Err(_) => false,
                                }
                            };

                            if connected {
                                guard.attempt_counts.remove(uuid);
                                to_remove.push(uuid.clone());
                                continue;
                            }

                            let count = guard.attempt_counts.get(uuid).copied().unwrap_or(0);
                            if guard.max_retries > 0 && count >= guard.max_retries {
                                log::warn!("重连: 达到最大重连次数 uuid={}", uuid);
                                guard.attempt_counts.remove(uuid);
                                to_remove.push(uuid.clone());
                                continue;
                            }

                            let should_retry = guard
                                .targets
                                .get(uuid)
                                .and_then(|t| t.last_attempt)
                                .map(|t| {
                                    // 指数退避：间隔 = retry_interval * 2^attempt，上限 60s
                                    let backoff =
                                        (guard.retry_interval_secs << count.min(4)).min(60);
                                    now.duration_since(t).as_secs() >= backoff
                                })
                                .unwrap_or(true);

                            if should_retry {
                                if let Some(ip) = guard.targets.get(uuid).map(|t| t.ip.clone()) {
                                    to_reconnect.push((uuid.clone(), ip));
                                }
                                if let Some(count) = guard.attempt_counts.get_mut(uuid) {
                                    *count += 1;
                                }
                            }
                        }

                        for uuid in &to_remove {
                            guard.targets.remove(uuid);
                        }
                    }

                    for (uuid, ip) in to_reconnect {
                        log::info!("重连: 尝试连接 uuid={}, ip={}", uuid, ip);
                        // 携带本机真实电量，避免 -1 被对端当作真实电量覆盖显示
                        let handshake_msg = {
                            // 后台线程：通过 lock() 取锁，与 FFI/扫描回调共用同一把锁
                            let ctx = unsafe { &*(ctx_ptr as *const SafeContext) };
                            let Ok(guard) = ctx.lock() else {
                                continue;
                            };
                            let local_uuid = guard
                                .broadcast_info
                                .as_ref()
                                .map(|i| i.uuid.clone())
                                .unwrap_or_default();
                            let local_battery = guard
                                .broadcast_info
                                .as_ref()
                                .map(|i| i.battery)
                                .unwrap_or(0);
                            let dt = guard
                                .broadcast_info
                                .as_ref()
                                .map(|i| i.device_type.clone())
                                .unwrap_or_default();
                            let local_ip = crate::utils::get_local_ip();
                            codec::encode_handshake(&local_uuid, &local_ip, local_battery, &dt)
                        };

                        let resp = crate::network::oneshot_send_receive_bin(
                            &handshake_msg,
                            &ip,
                            codec::DEFAULT_TCP_PORT,
                            5000,
                        );
                        if let Some((msg_type, payload)) = resp {
                            // REJECT 表示对端明确拒绝（如 core 版本不兼容）：不得记为在线，
                            // 否则不兼容设备会被反复判定为已连接，掩盖真实失败原因。
                            if msg_type == crate::protocol::header::MessageType::REJECT {
                                let reason = codec::decode_reject_payload(&payload)
                                    .map(|(_, r)| r)
                                    .unwrap_or_else(|| "unknown".to_string());
                                log::warn!("重连: 对端拒绝握手 uuid={}, reason={}", uuid, reason);
                            } else {
                                // 握手成功即视为在线：记录心跳时间，避免短连接协议下无限重复握手
                                let ctx = unsafe { &*(ctx_ptr as *const SafeContext) };
                                if let Ok(mut guard) = ctx.lock() {
                                    guard.heartbeat.record(&uuid);
                                }
                            }
                        }

                        // 更新最后尝试时间
                        if let Ok(mut guard) = inner.lock() {
                            if let Some(target) = guard.targets.get_mut(&uuid) {
                                target.last_attempt = Some(Instant::now());
                            }
                        }
                    }

                    // 无重连目标时降频到 30s，有目标时 10s（实际重连间隔由上面的指数退避控制）
                    let idle = inner.lock().map(|g| g.targets.is_empty()).unwrap_or(true);
                    thread::sleep(Duration::from_secs(if idle { 30 } else { 10 }));
                }
            })
            .expect("启动重连线程失败");
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

// ===== 上下文级重连入口 =====

/// 创建重连状态机并登记句柄（供统一启动入口调用）。返回句柄，0 表示失败。
pub fn create_state_for(ctx_ptr: usize) -> u64 {
    if ctx_ptr == 0 {
        return 0;
    }
    let state = Box::new(ReconnectState::new());
    let handle = crate::handle::put(Box::into_raw(state) as *mut std::os::raw::c_void);
    let ctx = unsafe { &*(ctx_ptr as *const crate::SafeContext) };
    if let Ok(mut guard) = ctx.lock() {
        guard.reconnect_state = handle;
    }
    handle
}

/// 添加重连目标（状态机由统一启动入口创建，内部从上下文获取）。
pub fn add_target(ctx: &mut crate::CoreContext, uuid: &str, ip: &str) {
    // 忽略本机自身，避免自我重连
    let is_self = ctx
        .broadcast_info
        .as_ref()
        .map(|b| b.uuid == uuid)
        .unwrap_or(false);
    if is_self {
        return;
    }
    let state_handle = ctx.reconnect_state;
    if state_handle == 0 {
        return;
    }
    let state = unsafe { &*(crate::handle::get(state_handle) as *const ReconnectState) };
    state.add_target(uuid, ip);
}

/// 移除重连目标。
pub fn remove_target(ctx: &mut crate::CoreContext, uuid: &str) {
    let state_handle = ctx.reconnect_state;
    if state_handle == 0 {
        return;
    }
    let state = unsafe { &*(crate::handle::get(state_handle) as *const ReconnectState) };
    state.remove_target(uuid);
}

/// 启动重连检测（供统一启动入口调用）。
pub fn start_for(ctx_ptr: usize, state_handle: u64, interval_secs: u64, max_retries: u32) {
    if ctx_ptr == 0 || state_handle == 0 {
        return;
    }
    let state = unsafe { &*(crate::handle::get(state_handle) as *const ReconnectState) };
    state.configure(interval_secs, max_retries);
    state.start(ctx_ptr);
}
