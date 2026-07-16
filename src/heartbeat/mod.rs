use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;

use crate::protocol::codec;
use crate::network;
use crate::SafeContext;

pub struct HeartbeatState {
    pub last_seen: HashMap<String, i64>,
}

impl HeartbeatState {
    pub fn new() -> Self {
        Self { last_seen: HashMap::new() }
    }

    pub fn record(&mut self, uuid: &str) {
        let now = now_sec();
        self.last_seen.insert(uuid.to_string(), now);
    }

    pub fn check_timeouts(&self, timeout_sec: i64) -> Vec<String> {
        let now = now_sec();
        self.last_seen.iter()
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
}

pub struct HeartbeatHandle {
    pub running: Arc<AtomicBool>,
    // 保存心跳参数引用，供更新用
    params: Arc<HeartbeatSenderParams>,
}

/// 心跳发送模式
pub const HEARTBEAT_MODE_UDP: i32 = 0;
pub const HEARTBEAT_MODE_TCP: i32 = 1;
pub const HEARTBEAT_MODE_AUTO: i32 = 2;

impl HeartbeatHandle {
    /// 启动心跳发送线程
    pub fn start(
        ctx_ptr: usize,
        uuid: &str,
        name: &str,
        battery: i32,
        device_type: &str,
        interval_ms: u64,
        mode: i32,
    ) -> Result<Self, String> {
        let running = Arc::new(AtomicBool::new(true));
        let name_b64 = base64::engine::general_purpose::STANDARD.encode(name.as_bytes());

        let params = Arc::new(HeartbeatSenderParams {
            uuid: Mutex::new(uuid.to_string()),
            name_b64: Mutex::new(name_b64),
            battery: AtomicI32::new(battery),
            device_type: Mutex::new(device_type.to_string()),
        });

        let r = running.clone();
        let p = params.clone();
        let mode_actual = Arc::new(AtomicI32::new(mode));
        let m = mode_actual.clone();

        thread::Builder::new()
            .name("heartbeat-sender".to_string())
            .spawn(move || {
                let mut consecutive_failures = 0;
                let mut current_mode = if mode == HEARTBEAT_MODE_AUTO {
                    HEARTBEAT_MODE_TCP
                } else {
                    mode
                };
                let mut since_tcp_check = 0u32;

                loop {
                    if !r.load(Ordering::Relaxed) { break; }

                    let uuid = p.uuid.lock().ok().map(|g| g.clone()).unwrap_or_default();
                    let name_b64 = p.name_b64.lock().ok().map(|g| g.clone()).unwrap_or_default();
                    let battery = p.battery.load(Ordering::Relaxed);
                    let device_type = p.device_type.lock().ok().map(|g| g.clone()).unwrap_or_default();
                    let port = codec::DEFAULT_TCP_PORT;

                    if uuid.is_empty() {
                        thread::sleep(Duration::from_millis(interval_ms));
                        continue;
                    }

                    let sent = if current_mode == HEARTBEAT_MODE_TCP {
                        let msg = codec::encode_heartbeat_tcp(&uuid, &name_b64, port, battery, &device_type);
                        let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
                        match ctx.lock() {
                            Ok(guard) => {
                                let mut tcp = match guard.network.tcp.lock() {
                                    Ok(t) => t,
                                    Err(_) => { thread::sleep(Duration::from_millis(interval_ms)); continue; }
                                };
                                tcp.send_to_device(&uuid, &msg)
                            }
                            Err(_) => false,
                        }
                    } else {
                        let msg = codec::encode_udp_broadcast(&uuid, &name_b64, port, battery, &device_type);
                        network::send_udp_broadcast(&msg).is_ok()
                    };

                    if sent {
                        consecutive_failures = 0;
                    } else {
                        consecutive_failures += 1;
                    }

                    // Auto 模式逻辑
                    let mode_now = m.load(Ordering::Relaxed);
                    if mode_now == HEARTBEAT_MODE_AUTO {
                        if current_mode == HEARTBEAT_MODE_TCP && consecutive_failures >= 3 {
                            log::info!("心跳 Auto 模式: TCP 连续失败 {} 次, 回退到 UDP", consecutive_failures);
                            current_mode = HEARTBEAT_MODE_UDP;
                            consecutive_failures = 0;
                            since_tcp_check = 0;
                        } else if current_mode == HEARTBEAT_MODE_UDP && sent {
                            since_tcp_check += 1;
                            if since_tcp_check >= 5 {
                                since_tcp_check = 0;
                                current_mode = HEARTBEAT_MODE_TCP;
                                log::info!("心跳 Auto 模式: 尝试切回 TCP");
                            }
                        }
                    } else {
                        current_mode = mode_now;
                    }

                    thread::sleep(Duration::from_millis(interval_ms));
                }
            })
            .map_err(|e| format!("启动心跳发送线程失败: {}", e))?;

        Ok(Self { running, params })
    }

    /// 更新心跳参数（电池、名称等）
    pub fn update(&self, uuid: &str, name: &str, battery: i32, device_type: &str) {
        if !uuid.is_empty() {
            if let Ok(mut u) = self.params.uuid.lock() { *u = uuid.to_string(); }
        }
        if !name.is_empty() {
            let b64 = base64::engine::general_purpose::STANDARD.encode(name.as_bytes());
            if let Ok(mut n) = self.params.name_b64.lock() { *n = b64; }
        }
        if battery >= 0 {
            self.params.battery.store(battery, Ordering::Relaxed);
        }
        if !device_type.is_empty() {
            if let Ok(mut d) = self.params.device_type.lock() { *d = device_type.to_string(); }
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
        .spawn(move || {
            loop {
                if !r.load(Ordering::Relaxed) { break; }

                let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
                let (timeouts, on_timeout_cb, user_data) = match ctx.lock() {
                    Ok(guard) => {
                        let timed_out = guard.heartbeat.check_timeouts(timeout_sec);
                        let cb = guard.router.on_device_timeout;
                        let ud = guard.router.user_data;
                        (timed_out, cb, ud)
                    }
                    Err(_) => { thread::sleep(Duration::from_millis(check_interval_ms)); continue; }
                };

                for uuid in &timeouts {
                    log::info!("离线检测: 设备超时 uuid={}", uuid);
                    if let Some(cb) = on_timeout_cb {
                        if let Ok(uuid_c) = std::ffi::CString::new(uuid.as_str()) {
                            cb(uuid_c.as_ptr(), user_data);
                        }
                    }
                    if let Ok(mut guard) = ctx.lock() {
                        guard.heartbeat.remove(uuid);
                        guard.network.tcp.lock().ok().map(|mut tcp| tcp.remove_session(uuid));
                    }
                }

                thread::sleep(Duration::from_millis(check_interval_ms));
            }
        })
        .map_err(|e| format!("启动离线检测线程失败: {}", e))?;

    Ok(running)
}
