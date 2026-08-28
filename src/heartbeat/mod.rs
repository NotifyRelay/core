use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;

use crate::network;
use crate::protocol::codec;
use crate::SafeContext;

/// 心跳指数退避上限（毫秒）：离线设备退避到该间隔后不再增加（约 1 分钟）
const MAX_HEARTBEAT_INTERVAL_MS: u64 = 60_000;

pub struct HeartbeatState {
    pub last_seen: HashMap<String, i64>,
}

impl HeartbeatState {
    pub fn new() -> Self {
        Self {
            last_seen: HashMap::new(),
        }
    }

    pub fn record(&mut self, uuid: &str) {
        let now = now_sec();
        self.last_seen.insert(uuid.to_string(), now);
    }

    pub fn check_timeouts(&self, timeout_sec: i64) -> Vec<String> {
        let now = now_sec();
        self.last_seen
            .iter()
            .filter(|(_, &ts)| now - ts > timeout_sec)
            .map(|(uuid, _)| uuid.clone())
            .collect()
    }

    pub fn remove(&mut self, uuid: &str) {
        self.last_seen.remove(uuid);
    }
}

fn now_sec() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub fn parse_udp_heartbeat(line: &str) -> Option<(String, String, u16, i32, String)> {
    let parts: Vec<&str> = line.split(':').collect();
    if parts.len() < 5 {
        return None;
    }
    Some((
        parts[0].to_string(),
        parts[1].to_string(),
        parts[2].parse().unwrap_or(codec::DEFAULT_TCP_PORT),
        parts[3].parse().unwrap_or(0),
        parts[4].to_string(),
    ))
}

/// 心跳发送器参数（可通过 FFI 更新）
pub struct HeartbeatSenderParams {
    pub uuid: Mutex<String>,
    pub name_b64: Mutex<String>,
    pub battery: AtomicI32,
    pub device_type: Mutex<String>,
    pub ip: Mutex<String>,
}

pub struct HeartbeatHandle {
    pub running: Arc<AtomicBool>,
    // 保存心跳参数引用，供更新用
    params: Arc<HeartbeatSenderParams>,
}

/// 心跳发送模式（TCP 备用：定向发送到目标设备）
pub const HEARTBEAT_MODE_TCP: i32 = 1;

impl HeartbeatHandle {
    /// 启动心跳发送线程
    pub fn start(
        _ctx_ptr: usize,
        uuid: &str,
        name: &str,
        battery: i32,
        device_type: &str,
        ip: &str,
        interval_ms: u64,
        _mode: i32,
        network_state: Arc<Mutex<crate::network::TcpServerState>>,
    ) -> Result<Self, String> {
        let running = Arc::new(AtomicBool::new(true));
        let name_b64 = base64::engine::general_purpose::STANDARD.encode(name.as_bytes());

        let params = Arc::new(HeartbeatSenderParams {
            uuid: Mutex::new(uuid.to_string()),
            name_b64: Mutex::new(name_b64),
            battery: AtomicI32::new(battery),
            device_type: Mutex::new(device_type.to_string()),
            ip: Mutex::new(ip.to_string()),
        });

        let r = running.clone();
        let p = params.clone();
        let net = network_state.clone();

        thread::Builder::new()
            .name("heartbeat-sender".to_string())
            .spawn(move || {
                let mut next_interval_ms = interval_ms;

                loop {
                    if !r.load(Ordering::Relaxed) {
                        break;
                    }

                    let uuid = p.uuid.lock().ok().map(|g| g.clone()).unwrap_or_default();
                    let name_b64 = p
                        .name_b64
                        .lock()
                        .ok()
                        .map(|g| g.clone())
                        .unwrap_or_default();
                    let battery = p.battery.load(Ordering::Relaxed);
                    let device_type = p
                        .device_type
                        .lock()
                        .ok()
                        .map(|g| g.clone())
                        .unwrap_or_default();
                    let port = codec::DEFAULT_TCP_PORT;

                    if uuid.is_empty() {
                        thread::sleep(Duration::from_millis(next_interval_ms));
                        continue;
                    }

                    // TCP 备用心跳：优先通过已有会话发送，无会话时 oneshot
                    let msg =
                        codec::encode_heartbeat_tcp(&uuid, &name_b64, port, battery, &device_type);
                    let ip_str = p.ip.lock().ok().map(|g| g.clone()).unwrap_or_default();
                    let sent = if let Ok(mut tcp) = net.lock() {
                        match tcp.send_through_session(&uuid, &msg) {
                            Ok(true) => true, // 通过已有会话发送成功
                            Ok(false) => {
                                // 无已有会话，fallback 到 oneshot
                                if !ip_str.is_empty() {
                                    network::oneshot_send_only(&msg, &ip_str, port, 3000)
                                } else {
                                    false
                                }
                            }
                            Err(()) => {
                                // 会话写入失败（已移除），fallback 到 oneshot
                                if !ip_str.is_empty() {
                                    network::oneshot_send_only(&msg, &ip_str, port, 3000)
                                } else {
                                    false
                                }
                            }
                        }
                    } else {
                        false
                    };

                    if sent {
                        next_interval_ms = interval_ms;
                    } else {
                        // 离线设备指数退避：2s → 4s → 8s → 16s → 32s → 60s 封顶，
                        // 对端恢复连接后下一次发送成功即恢复基础间隔
                        next_interval_ms = (next_interval_ms * 2).min(MAX_HEARTBEAT_INTERVAL_MS);
                    }

                    thread::sleep(Duration::from_millis(next_interval_ms));
                }
            })
            .map_err(|e| format!("启动心跳发送线程失败: {}", e))?;

        Ok(Self { running, params })
    }

    /// 更新心跳参数（电池、名称、目标 IP 等）
    pub fn update(&self, uuid: &str, name: &str, battery: i32, device_type: &str, ip: &str) {
        if !uuid.is_empty() {
            if let Ok(mut u) = self.params.uuid.lock() {
                *u = uuid.to_string();
            }
        }
        if !name.is_empty() {
            let b64 = base64::engine::general_purpose::STANDARD.encode(name.as_bytes());
            if let Ok(mut n) = self.params.name_b64.lock() {
                *n = b64;
            }
        }
        // 负数表示放电（有效状态），超出 [-100,100]（-101）表示未知才不覆盖
        if battery.abs() <= 100 {
            self.params.battery.store(battery, Ordering::Relaxed);
        }
        if !device_type.is_empty() {
            if let Ok(mut d) = self.params.device_type.lock() {
                *d = device_type.to_string();
            }
        }
        // 目标 IP 实时同步（known_devices 更新后心跳发往最新地址，避免发往过期 IP）
        if !ip.is_empty() {
            if let Ok(mut i) = self.params.ip.lock() {
                *i = ip.to_string();
            }
        }
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

/// 启动离线检测线程
pub fn start_offline_detector(
    ctx_ptr: usize,
    check_interval_ms: u64,
    timeout_sec: i64,
) -> Result<Arc<AtomicBool>, String> {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    thread::Builder::new()
        .name("offline-detector".to_string())
        .spawn(move || loop {
            if !r.load(Ordering::Relaxed) {
                break;
            }

            let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
            let (timeouts, on_timeout_cb, user_data) = {
                let guard = ctx.get_mut().unwrap();
                let timed_out = guard.heartbeat.check_timeouts(timeout_sec);
                let cb = guard.router.on_device_timeout;
                let ud = guard.router.user_data;
                (timed_out, cb, ud)
            };

            for uuid in &timeouts {
                log::info!("设备状态变化: 已超时 uuid={}", uuid);
                if let Some(cb) = on_timeout_cb {
                    if let Ok(uuid_c) = std::ffi::CString::new(uuid.as_str()) {
                        cb(uuid_c.as_ptr(), user_data);
                    }
                }
                {
                    let guard = ctx.get_mut().unwrap();
                    guard.heartbeat.remove(uuid);
                    guard.registry.mark_disconnected(uuid);
                    if let Ok(mut tcp) = guard.network.tcp.lock() {
                        tcp.remove_session(uuid);
                    }
                }
            }

            thread::sleep(Duration::from_millis(check_interval_ms));
        })
        .map_err(|e| format!("启动离线检测线程失败: {}", e))?;

    Ok(running)
}

/// 统一心跳调度器
///
/// 单线程管理每个已知设备的 HeartbeatHandle：
/// - 每轮扫描 known_devices（平台只喂过 uuid+ip）：无 handle 且已配对 → 启动 AUTO 心跳（复用现有回退逻辑）
/// - 设备从 known_devices 移除 → 停止并移除 handle
/// - 本机参数（broadcast_info）变化 → 遍历 handle 调用现有 update()
pub struct HeartbeatScheduler {
    running: Arc<AtomicBool>,
}

impl HeartbeatScheduler {
    pub fn start(ctx_ptr: usize, interval_ms: u64) -> Result<Self, String> {
        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();

        thread::Builder::new()
            .name("heartbeat-scheduler".to_string())
            .spawn(move || loop {
                if !r.load(Ordering::Relaxed) {
                    break;
                }

                // 每轮工作在一个块内完成，避免长期持有 ctx 锁（MutexGuard 临时量随块结束释放）
                {
                    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
                    let guard = match ctx.get_mut() {
                        Ok(g) => g,
                        Err(_) => break,
                    };

                    // 本机身份参数来自 broadcast_info（由 FFI 写入）
                    let (local_uuid, local_name_b64, local_battery, local_device_type) = guard
                        .broadcast_info
                        .as_ref()
                        .map(|b| {
                            (
                                b.uuid.clone(),
                                b.name_b64.clone(),
                                b.battery,
                                b.device_type.clone(),
                            )
                        })
                        .unwrap_or_default();
                    let local_name = if local_name_b64.is_empty() {
                        String::new()
                    } else {
                        String::from_utf8(
                            base64::engine::general_purpose::STANDARD
                                .decode(&local_name_b64)
                                .unwrap_or_default(),
                        )
                        .unwrap_or(local_name_b64)
                    };

                    let known_devices = guard.discovery.get_known_devices();
                    let paired: Vec<String> = guard.crypto.device_keys.keys().cloned().collect();
                    // 广播主用（默认）：UDP 广播 2s 兼发现+心跳，不启动每设备心跳；
                    // TCP 备用（锁屏/WLAN直连）：为已配对设备启动每设备 TCP 定向心跳
                    let tcp_backup = guard.heartbeat_tcp_backup.load(Ordering::Relaxed);

                    // 已配对设备的 handle 注册表（uuid -> HeartbeatHandle，跨轮次持久）
                    let mut handles = std::mem::take(&mut guard.heartbeat_scheduler_handles);

                    // 0. 广播主用模式：停止全部每设备心跳（广播已承担心跳职责）
                    if !tcp_backup {
                        for (_, h) in handles.drain() {
                            h.stop();
                        }
                        guard.heartbeat_scheduler_handles = handles;
                        thread::sleep(Duration::from_millis(interval_ms.min(2000)));
                        continue;
                    }

                    // 1. 移除已不在 known_devices 的 handle
                    let stale: Vec<String> = handles.keys().cloned().collect();
                    for s in stale {
                        if !known_devices.contains_key(&s) {
                            if let Some(h) = handles.remove(&s) {
                                h.stop();
                            }
                        }
                    }

                    // 2. 为已配对且无 handle 的已知设备启动心跳（TCP 定向）
                    for (uuid, ip) in &known_devices {
                        if handles.contains_key(uuid) {
                            continue;
                        }
                        if !paired.contains(uuid) {
                            continue;
                        }
                        // 跳过本机自身（known_devices 中不应存在本机，防御历史残留）
                        if !local_uuid.is_empty() && *uuid == local_uuid {
                            continue;
                        }
                        if local_uuid.is_empty() {
                            break;
                        }
                        match HeartbeatHandle::start(
                            ctx_ptr,
                            &local_uuid,
                            &local_name,
                            local_battery,
                            &local_device_type,
                            ip,
                            interval_ms,
                            HEARTBEAT_MODE_TCP,
                            guard.network.tcp.clone(),
                        ) {
                            Ok(h) => {
                                log::info!("心跳调度器: 启动心跳 uuid={} ip={}", uuid, ip);
                                handles.insert(uuid.clone(), h);
                            }
                            Err(e) => {
                                log::warn!("心跳调度器: 启动心跳失败 uuid={} err={}", uuid, e);
                            }
                        }
                    }

                    // 3. 本机参数变化 → 更新全部 handle（复用现有 update；目标 IP 同步 known_devices 最新值）
                    for (uuid, ip) in &known_devices {
                        if let Some(h) = handles.get(uuid) {
                            h.update(
                                &local_uuid,
                                &local_name,
                                local_battery,
                                &local_device_type,
                                ip,
                            );
                        }
                    }

                    // 4. 将 handle 表存回调度器共享状态
                    guard.heartbeat_scheduler_handles = handles;
                }

                thread::sleep(Duration::from_millis(interval_ms.min(2000)));
            })
            .map_err(|e| format!("启动心跳调度线程失败: {}", e))?;

        Ok(Self { running })
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}
