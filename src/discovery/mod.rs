use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

pub mod mdns;

use crate::network;
use crate::protocol::codec;
use crate::SafeContext;

/// 在线判定窗口（秒）：last_seen 在此窗口内视为已连接，跳过自动握手
const RECENT_SEEN_SECS: i64 = 15;

/// 已知设备条目：地址 + 最近一次被发现的时刻。
///
/// 时刻用于过期清理：对端进程被强杀时 mDNS 不会发出 Goodbye，
/// 仅靠 ServiceRemoved 无法感知下线，必须依赖超时兜底。
#[derive(Clone)]
struct KnownDevice {
    ip: String,
    last_seen: i64,
}

/// 已知设备过期窗口（秒）：超过该时长未再次被发现即移除。
///
/// 取 10 分钟：mDNS 通告间隔通常为分钟级，短于此值会误删活跃设备。
const KNOWN_DEVICE_TTL_SECS: i64 = 600;

pub struct DiscoveryState {
    /// 发现扫描线程
    scanner_running: Arc<AtomicBool>,
    /// 已知设备列表（用于自动连接已配对设备）
    known_devices: Arc<Mutex<HashMap<String, KnownDevice>>>,
}

impl Default for DiscoveryState {
    fn default() -> Self {
        Self::new()
    }
}

impl DiscoveryState {
    pub fn new() -> Self {
        Self {
            scanner_running: Arc::new(AtomicBool::new(false)),
            known_devices: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// 添加已知设备（已配对的，用于自动重连发现），同时刷新发现时刻。
    pub fn add_known_device(&self, uuid: &str, ip: &str) {
        if let Ok(mut guard) = self.known_devices.lock() {
            let now = crate::device_registry::now_sec();
            match guard.get_mut(uuid) {
                Some(entry) => {
                    // 地址为空时不覆盖已有有效地址（握手路径会传空串）
                    if !ip.is_empty() {
                        entry.ip = ip.to_string();
                    }
                    entry.last_seen = now;
                }
                None => {
                    guard.insert(
                        uuid.to_string(),
                        KnownDevice {
                            ip: ip.to_string(),
                            last_seen: now,
                        },
                    );
                }
            }
        }
    }

    /// 清理长期未被再次发现的条目，返回被移除的 uuid。
    ///
    /// 对端进程被强杀时 mDNS 不会发出 Goodbye，只能靠超时兜底，
    /// 否则该设备会永久留在已知列表并被反复重拨。
    pub fn prune_expired(&self) -> Vec<String> {
        let now = crate::device_registry::now_sec();
        let mut removed = Vec::new();
        if let Ok(mut guard) = self.known_devices.lock() {
            guard.retain(|uuid, entry| {
                let keep = now.saturating_sub(entry.last_seen) <= KNOWN_DEVICE_TTL_SECS;
                if !keep {
                    removed.push(uuid.clone());
                }
                keep
            });
        }
        removed
    }

    /// 移除已知设备
    pub fn remove_known_device(&self, uuid: &str) {
        if let Ok(mut guard) = self.known_devices.lock() {
            guard.remove(uuid);
        }
    }

    pub fn get_known_devices(&self) -> HashMap<String, String> {
        self.known_devices
            .lock()
            .map(|guard| {
                guard
                    .iter()
                    .map(|(uuid, entry)| (uuid.clone(), entry.ip.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// 启动自动发现扫描
    /// 定期尝试连接已知设备（用于网络恢复后的重连）
    pub fn start_known_device_scanner(&self, ctx_ptr: usize) {
        if self.scanner_running.load(Ordering::Relaxed) {
            return;
        }
        self.scanner_running.store(true, Ordering::Relaxed);

        let running = self.scanner_running.clone();
        let known = self.known_devices.clone();

        thread::Builder::new()
            .name("discovery-scanner".to_string())
            .spawn(move || {
                loop {
                    if !running.load(Ordering::Relaxed) || crate::lifecycle::is_shutdown_requested()
                    {
                        break;
                    }

                    // 每轮扫描前清理长期未被发现的条目：
                    // 对端进程被强杀时收不到 mDNS Goodbye，只能超时兜底。
                    {
                        let now = crate::device_registry::now_sec();
                        if let Ok(mut guard) = known.lock() {
                            let before = guard.len();
                            guard.retain(|uuid, entry| {
                                let keep =
                                    now.saturating_sub(entry.last_seen) <= KNOWN_DEVICE_TTL_SECS;
                                if !keep {
                                    log::info!("发现扫描: 已知设备过期移除 uuid={}", uuid);
                                }
                                keep
                            });
                            let _ = before;
                        }
                    }

                    let known_list: Vec<(String, String)> = known
                        .lock()
                        .map(|g| g.iter().map(|(k, v)| (k.clone(), v.ip.clone())).collect())
                        .unwrap_or_default();

                    // 是否存在未连接（需扫描握手）的设备：有则保持短周期，无则降频
                    let mut has_offline = false;

                    // 本机身份每轮只取一次：逐设备重复取锁既无必要，也把锁持有次数放大到设备数倍。
                    let (local_uuid, local_battery, local_dt) = {
                        let ctx = unsafe { &*(ctx_ptr as *const SafeContext) };
                        match ctx.lock() {
                            Ok(guard) => {
                                let bi = guard.broadcast_info.as_ref();
                                (
                                    bi.map(|i| i.uuid.clone()).unwrap_or_default(),
                                    bi.map(|i| i.battery).unwrap_or(0),
                                    bi.map(|i| i.device_type.clone()).unwrap_or_default(),
                                )
                            }
                            Err(_) => (String::new(), 0, String::new()),
                        }
                    };
                    let local_ip = crate::utils::get_local_ip();

                    for (uuid, ip) in known_list {
                        // 跳过本机自身（已知设备中不应包含本机）
                        let is_self = !local_uuid.is_empty() && local_uuid == uuid;
                        if is_self {
                            continue;
                        }

                        // 在线判定：最近收到过对方心跳（last_seen 在窗口内）即视为已连接。
                        // 不依赖 TCP 会话：session 随连接关闭立即移除，用它判定会永远失败。
                        let connected = {
                            let ctx = unsafe { &*(ctx_ptr as *const SafeContext) };
                            match ctx.lock() {
                                Ok(guard) => {
                                    guard.heartbeat.is_recently_seen(&uuid, RECENT_SEEN_SECS)
                                }
                                Err(_) => false,
                            }
                        };

                        if connected {
                            continue;
                        }
                        log::debug!("发现扫描: 判定离线并发起握手 uuid={}, ip={}", uuid, ip);
                        has_offline = true;

                        // 尝试握手建立连接（携带本机真实电量，避免 -1 被对端当作真实电量覆盖显示）
                        let handshake = codec::handshake_payload(
                            &local_uuid,
                            &local_ip,
                            local_battery,
                            &local_dt,
                        );

                        let resp = network::request_response_over_quic(
                            ctx_ptr,
                            &uuid,
                            &ip,
                            codec::DEFAULT_TCP_PORT,
                            crate::processing::CTRL_HANDSHAKE,
                            &handshake,
                            3000,
                        );
                        if let Some((resp_header, payload)) = resp {
                            // REJECT 表示对端明确拒绝（如 core 版本不兼容）：
                            // 不能视为"在线"，否则设备会被错误标记为可用并反复握手。
                            if resp_header == crate::processing::CTRL_REJECT {
                                let reason = codec::decode_reject_payload(&payload)
                                    .map(|(_, r)| r)
                                    .unwrap_or_else(|| "unknown".to_string());
                                log::warn!(
                                    "发现扫描: 对端拒绝握手 uuid={}, reason={}",
                                    uuid,
                                    reason
                                );
                                continue;
                            }
                            // 握手成功即视为在线：记录心跳时间，避免短连接协议下每轮扫描重复握手
                            let ctx = unsafe { &*(ctx_ptr as *const SafeContext) };
                            if let Ok(mut guard) = ctx.lock() {
                                guard.heartbeat.record(&uuid);
                            }
                        }
                    }

                    // 有待连接设备时保持 5s 周期（及时感知设备上线），全部在线/无设备时降频到 15s
                    thread::sleep(Duration::from_secs(if has_offline { 5 } else { 15 }));
                }
            })
            .expect("启动发现扫描线程失败");
    }
}

// ===== 上下文级发现入口 =====

/// 登记已知设备（已配对设备信息）；忽略本机自身。
pub fn add_known_device(ctx: &mut crate::CoreContext, uuid: &str, ip: &str) {
    // 忽略本机自身，避免自我扫描连接
    let is_self = ctx
        .broadcast_info
        .as_ref()
        .map(|b| b.uuid == uuid)
        .unwrap_or(false);
    if is_self {
        return;
    }
    ctx.discovery.add_known_device(uuid, ip);
}

/// 移除已知设备。
pub fn remove_known_device(ctx: &mut crate::CoreContext, uuid: &str) {
    ctx.discovery.remove_known_device(uuid);
}

/// 启动已知设备自动扫描（网络变化后调用）。
pub fn start_known_device_scanner_for(ctx_ptr: usize) {
    if ctx_ptr == 0 {
        return;
    }
    let ctx = unsafe { &*(ctx_ptr as *const crate::SafeContext) };
    let Ok(guard) = ctx.lock() else {
        return;
    };
    guard.discovery.start_known_device_scanner(ctx_ptr);
}
