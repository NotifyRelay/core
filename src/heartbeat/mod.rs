use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;

use crate::protocol::codec;
use crate::SafeContext;

/// 心跳指数退避上限（毫秒）：离线设备退避到该间隔后不再增加（约 1 分钟）
/// 心跳失败时的最大退避间隔。
///
/// 必须小于平台侧在线判定窗口（12s）：退避一旦超过该窗口，
/// 对端在本机恢复发送之前就已把本机判为离线，
/// 表现为设备「掉了之后长时间回不来」。
const MAX_HEARTBEAT_INTERVAL_MS: u64 = 8_000;

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

    /// UUID 只有在已记录心跳且记录仍位于在线窗口内时才视为在线。
    pub fn is_recently_seen(&self, uuid: &str, timeout_sec: i64) -> bool {
        let now = now_sec();
        self.last_seen
            .get(uuid)
            .map(|&ts| now.saturating_sub(ts) <= timeout_sec)
            .unwrap_or(false)
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

/// 心跳发送器参数（可通过 FFI 更新）
pub struct HeartbeatSenderParams {
    /// 目标设备 uuid：仅用于寻址传输层连接。
    pub target_uuid: Mutex<String>,
    /// 本机 uuid：写入心跳载荷，供对端识别来源。
    pub local_uuid: Mutex<String>,
    pub name_b64: Mutex<String>,
    pub battery: AtomicI32,
    pub device_type: Mutex<String>,
    pub ip: Mutex<String>,
}

pub struct HeartbeatHandle {
    pub running: Arc<AtomicBool>,
    // 保存心跳参数引用，供更新用
    params: Arc<HeartbeatSenderParams>,
    /// 发送线程句柄：用于判断线程是否真的存活。
    ///
    /// `running` 只是「请求停止」的标志，创建时即为 true，线程死亡不会自动置位；
    /// 若只用它判断，线程异常退出后会留下僵尸 handle，调度器误以为心跳正常，
    /// 导致该设备永远收不到本机心跳（表现为对端显示本机离线）。
    thread: Arc<Mutex<Option<thread::JoinHandle<()>>>>,
}

/// 心跳发送模式（TCP 备用：定向发送到目标设备）
pub const HEARTBEAT_MODE_TCP: i32 = 1;

impl HeartbeatHandle {
    /// 启动心跳发送线程
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        ctx_ptr: usize,
        local_uuid: &str,
        target_uuid: &str,
        name: &str,
        battery: i32,
        device_type: &str,
        ip: &str,
        interval_ms: u64,
        _mode: i32,
        network_state: Arc<Mutex<crate::network::TransportState>>,
    ) -> Result<Self, String> {
        let running = Arc::new(AtomicBool::new(true));
        let name_b64 = base64::engine::general_purpose::STANDARD.encode(name.as_bytes());

        let params = Arc::new(HeartbeatSenderParams {
            target_uuid: Mutex::new(target_uuid.to_string()),
            local_uuid: Mutex::new(local_uuid.to_string()),
            name_b64: Mutex::new(name_b64),
            battery: AtomicI32::new(battery),
            device_type: Mutex::new(device_type.to_string()),
            ip: Mutex::new(ip.to_string()),
        });

        let r = running.clone();
        let p = params.clone();
        let _net = network_state.clone();

        let spawned = thread::Builder::new()
            .name("heartbeat-sender".to_string())
            .spawn(move || {
                let mut next_interval_ms = interval_ms;

                loop {
                    if !r.load(Ordering::Relaxed) {
                        break;
                    }

                    let target_uuid = p
                        .target_uuid
                        .lock()
                        .ok()
                        .map(|g| g.clone())
                        .unwrap_or_default();
                    let local_uuid = p
                        .local_uuid
                        .lock()
                        .ok()
                        .map(|g| g.clone())
                        .unwrap_or_default();
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

                    if target_uuid.is_empty() || local_uuid.is_empty() {
                        thread::sleep(Duration::from_millis(next_interval_ms));
                        continue;
                    }

                    // 载荷携带**本机** uuid：对端据此识别来源设备。
                    // 传输层寻址使用**目标** uuid，二者不可混用。
                    let hb = crate::protocol::binary_codec::HeartbeatPayload {
                        uuid: local_uuid.clone(),
                        name: name_b64.clone(),
                        port,
                        battery,
                        device_type: device_type.clone(),
                    };
                    let payload = serde_json::to_string(&hb).unwrap_or_default();
                    let ip_str = p.ip.lock().ok().map(|g| g.clone()).unwrap_or_default();
                    let sent = match HeartbeatHandle::send_heartbeat(
                        ctx_ptr,
                        &target_uuid,
                        &ip_str,
                        &payload,
                        port,
                    ) {
                        Ok(v) => v,
                        Err(_) => {
                            thread::sleep(Duration::from_millis(next_interval_ms));
                            continue;
                        }
                    };

                    if sent {
                        next_interval_ms = interval_ms;
                    } else {
                        // 指数退避：2s → 4s → 8s 封顶。
                        // 上限收紧到在线判定窗口以内，保证恢复发送先于对端判离线。
                        next_interval_ms = (next_interval_ms * 2).min(MAX_HEARTBEAT_INTERVAL_MS);
                    }

                    thread::sleep(Duration::from_millis(next_interval_ms));
                }
            })
            .map_err(|e| format!("启动心跳发送线程失败: {}", e))?;

        Ok(Self {
            running,
            params,
            thread: Arc::new(Mutex::new(Some(spawned))),
        })
    }

    /// 发送线程是否仍在运行（用于识别僵尸 handle）。
    pub fn is_alive(&self) -> bool {
        match self.thread.lock() {
            Ok(g) => match g.as_ref() {
                Some(t) => !t.is_finished(),
                None => false,
            },
            Err(_) => false,
        }
    }

    /// 发送一次心跳：优先走已建立的 QUIC 会话；无会话时按已知 IP 主动建连后发送。
    ///
    /// 返回 `Ok(true)` 表示已交付传输层；`Ok(false)` 表示当前不可达（触发退避）；
    /// `Err(())` 表示上下文取锁失败（心跳线程按不可达处理）。
    fn send_heartbeat(
        ctx_ptr: usize,
        uuid: &str,
        ip: &str,
        payload: &str,
        port: u16,
    ) -> Result<bool, ()> {
        let ctx = unsafe { &*(ctx_ptr as *const crate::SafeContext) };

        // 1) 已有会话直接发
        let (transport, connected) = {
            let Ok(guard) = ctx.lock() else {
                return Err(());
            };
            match guard.quic.as_ref() {
                Some(t) => (Some(t.clone()), t.is_connected(uuid)),
                None => (None, false),
            }
        };
        let Some(transport) = transport else {
            log::debug!("心跳: QUIC 传输层未启动 uuid={}", uuid);
            return Ok(false);
        };
        if connected {
            if transport
                .send(uuid, crate::processing::CTRL_HEARTBEAT, payload.as_bytes())
                .is_ok()
            {
                return Ok(true);
            }
            // 会话登记仍存在但写入失败：连接已不可用。
            // 必须先移除该登记，否则后续 ensure_link 会因 is_connected 仍为真
            // 而反复返回同一条死连接，心跳永远发不出去。
            log::debug!("心跳: 连接写入失败，丢弃旧连接 uuid={}", uuid);
            transport.disconnect(uuid);
        }

        // 2) 无可用会话：走统一建连入口（汇总全部已知地址逐个尝试）。
        // 只用传入的单个 IP 会在该地址过期时永久发不出心跳，对端随即判本机离线。
        let Some(transport) = crate::network::ensure_link(ctx, uuid, ip, port) else {
            log::debug!("心跳: 建连失败 uuid={}, ip={}", uuid, ip);
            return Ok(false);
        };
        Ok(transport
            .send(uuid, crate::processing::CTRL_HEARTBEAT, payload.as_bytes())
            .is_ok())
    }

    /// 更新心跳参数（本机身份、电池、名称、目标 IP 等）
    ///
    /// local_uuid 只影响载荷中的来源标识；目标设备由创建时的 target_uuid 固定。
    pub fn update(&self, local_uuid: &str, name: &str, battery: i32, device_type: &str, ip: &str) {
        if !local_uuid.is_empty() {
            if let Ok(mut u) = self.params.local_uuid.lock() {
                *u = local_uuid.to_string();
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

            let ctx = unsafe { &*(ctx_ptr as *const SafeContext) };
            let (timeouts, on_timeout_cb) = {
                // 后台线程：通过 lock() 取锁，与扫描回调、导出层共用同一把锁
                let Ok(guard) = ctx.lock() else {
                    thread::sleep(Duration::from_millis(check_interval_ms));
                    continue;
                };
                let timed_out = guard.heartbeat.check_timeouts(timeout_sec);
                let cb = guard.router.on_device_timeout.clone();
                (timed_out, cb)
            };

            for uuid in &timeouts {
                log::info!("设备状态变化: 已超时 uuid={}", uuid);
                if let Some(cb) = on_timeout_cb.as_ref() {
                    cb(uuid);
                }
                {
                    let Ok(mut guard) = ctx.lock() else {
                        continue;
                    };
                    guard.heartbeat.remove(uuid);
                    guard.registry.mark_disconnected(uuid);
                    // 只标记状态，**不拆传输层连接**。
                    //
                    // 拆连接会造成自毁式循环：心跳稍慢 → 判超时 → 断长连接 →
                    // 对端立刻掉线 → 双方互判离线，且每次都要重新握手。
                    // 连接释放交由 QUIC 自身的空闲回收与对端关闭处理。
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
    pub fn start(
        ctx_ptr: usize,
        interval_ms: u64,
        network_state: Arc<Mutex<crate::network::TransportState>>,
    ) -> Result<Self, String> {
        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();

        thread::Builder::new()
            .name("heartbeat-scheduler".to_string())
            .spawn(move || {
                while r.load(Ordering::Relaxed) {
                    // 第一段（持锁）：读取身份/设备表、回收失效 handle、更新参数
                    let ctx = unsafe { &*(ctx_ptr as *const SafeContext) };

                    let mut to_start: Vec<(String, String)> = Vec::new();
                    let (local_uuid, local_name, local_battery, local_device_type);

                    {
                        let Ok(mut guard) = ctx.lock() else {
                            thread::sleep(Duration::from_millis(interval_ms));
                            continue;
                        };

                        let (uuid, name_b64, battery, device_type) = guard
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
                        local_uuid = uuid;
                        local_battery = battery;
                        local_device_type = device_type.clone();
                        local_name = if name_b64.is_empty() {
                            String::new()
                        } else {
                            String::from_utf8(
                                base64::engine::general_purpose::STANDARD
                                    .decode(&name_b64)
                                    .unwrap_or_default(),
                            )
                            .unwrap_or(name_b64)
                        };

                        let known_devices = guard.discovery.get_known_devices();
                        let paired: Vec<String> =
                            guard.crypto.device_keys.keys().cloned().collect();
                        // 地址来源不限于发现层：对端主动连入时入站回调会写入 device_ips，
                        // mDNS 抖动导致 known_devices 掉条目时该地址依然有效。
                        let device_ips: HashMap<String, String> = guard
                            .device_ips
                            .lock()
                            .map(|m| m.clone())
                            .unwrap_or_default();

                        let mut handles = std::mem::take(&mut guard.heartbeat_scheduler_handles);

                        // 心跳目标集合 = 全部已配对设备。
                        // 判定依据只能是「本机是否与该设备配对」，不能是「发现层当前是否看到它」：
                        // mDNS 掉条目时若据此停发心跳，对端 last_seen 会超时并把本机判为离线。
                        let targets: Vec<(String, String)> = paired
                            .iter()
                            .filter(|u| !local_uuid.is_empty() && u.as_str() != local_uuid)
                            .map(|u| {
                                let ip = known_devices
                                    .get(u)
                                    .or_else(|| device_ips.get(u))
                                    .cloned()
                                    .unwrap_or_default();
                                (u.clone(), ip)
                            })
                            .collect();

                        // 回收条件仅为「已不再配对」或「发送线程已不存活」。
                        // 用线程存活而非 running 标志——running 创建即 true，线程死亡不会复位。
                        let stale: Vec<String> = handles
                            .iter()
                            .filter(|(u, h)| !paired.contains(u) || !h.is_alive())
                            .map(|(u, _)| u.clone())
                            .collect();
                        for s in &stale {
                            if let Some(h) = handles.remove(s) {
                                h.stop();
                                log::info!("心跳调度器: 回收失效 handle uuid={}", s);
                            }
                        }

                        // 收集待启动设备（只收集，不创建线程）
                        for (uuid, ip) in &targets {
                            if handles.contains_key(uuid) || local_uuid.is_empty() {
                                continue;
                            }
                            to_start.push((uuid.clone(), ip.clone()));
                        }

                        // 更新既有 handle 的本机参数与目标地址
                        for (uuid, ip) in &targets {
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

                        guard.heartbeat_scheduler_handles = handles;
                    }

                    // 第二段（**锁外**）：创建心跳线程。
                    // 新线程体第一步就 ctx.lock()，若在持锁时创建会与其永久互锁，
                    // 表现为「线程已创建但从不发送心跳」。
                    if !to_start.is_empty() {
                        let mut started: Vec<(String, HeartbeatHandle)> = Vec::new();
                        for (uuid, ip) in to_start {
                            match HeartbeatHandle::start(
                                ctx_ptr,
                                &local_uuid,
                                &uuid,
                                &local_name,
                                local_battery,
                                &local_device_type,
                                &ip,
                                interval_ms,
                                HEARTBEAT_MODE_TCP,
                                network_state.clone(),
                            ) {
                                Ok(h) => {
                                    log::info!("心跳调度器: 启动心跳 uuid={} ip={}", uuid, ip);
                                    started.push((uuid, h));
                                }
                                Err(e) => {
                                    log::warn!("心跳调度器: 启动心跳失败 uuid={} err={}", uuid, e);
                                }
                            }
                        }
                        if !started.is_empty() {
                            if let Ok(mut g) = ctx.lock() {
                                for (uuid, h) in started {
                                    g.heartbeat_scheduler_handles.insert(uuid, h);
                                }
                            }
                        }
                    }

                    thread::sleep(Duration::from_millis(interval_ms.min(2000)));
                }
            })
            .map_err(|e| format!("启动心跳调度线程失败: {}", e))?;

        Ok(Self { running })
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

// ===== 上下文级心跳与离线检测入口 =====

/// 启动离线检测（供统一启动入口调用）。返回运行开关句柄，0 表示失败。
pub fn start_offline_detector_for(ctx_ptr: usize, timeout_sec: i64, check_interval_ms: u64) -> u64 {
    if ctx_ptr == 0 {
        return 0;
    }
    match start_offline_detector(ctx_ptr, check_interval_ms, timeout_sec) {
        Ok(running) => {
            let ctx = unsafe { &*(ctx_ptr as *const SafeContext) };
            let Ok(mut guard) = ctx.lock() else {
                return 0;
            };
            let boxed = Box::new(running);
            let handle = crate::handle::put(Box::into_raw(boxed) as *mut std::os::raw::c_void);
            guard.offline_detector_handle = handle;
            handle
        }
        Err(_) => 0,
    }
}

/// 启动统一心跳调度器（供统一启动入口调用）。
///
/// 内部扫描 known_devices：为已配对设备自动启动/停止每设备心跳（AUTO 模式）；
/// 本机身份参数（uuid/name/battery/device_type）写入 `broadcast_info`。返回句柄，0 表示失败。
pub fn start_scheduler_for(
    ctx_ptr: usize,
    uuid: &str,
    name: &str,
    battery: i32,
    device_type: &str,
    interval_ms: u64,
) -> u64 {
    if ctx_ptr == 0 {
        return 0;
    }
    let name_b64 = base64::engine::general_purpose::STANDARD.encode(name.as_bytes());

    let ctx = unsafe { &*(ctx_ptr as *const SafeContext) };
    let Ok(mut guard) = ctx.lock() else {
        return 0;
    };
    // 重复启动时先停止旧调度器
    if guard.heartbeat_scheduler != 0 {
        let old = crate::handle::take(guard.heartbeat_scheduler)
            as *mut crate::heartbeat::HeartbeatScheduler;
        if !old.is_null() {
            let boxed = unsafe { Box::from_raw(old) };
            boxed.stop();
        }
        guard.heartbeat_scheduler = 0;
        for (_, h) in guard.heartbeat_scheduler_handles.drain() {
            h.stop();
        }
    }
    let local_uuid = uuid.to_string();
    guard.broadcast_info = Some(crate::BroadcastInfo {
        uuid: uuid.to_string(),
        name_b64,
        battery,
        device_type: device_type.to_string(),
    });
    // 同步广播信息到 TCP 层（供发现请求响应使用）
    crate::network::set_broadcast_info(
        guard.network.transport.clone(),
        guard.broadcast_info.clone(),
    );
    // 同步本机 uuid 到持久化（读取接口前自动落盘）与 TCP 层状态
    // 仅库值缺失时采用平台传入值：uuid 已由 Rust 生成持有，空值或与库值冲突时均不得覆盖库值
    if !local_uuid.is_empty() {
        guard.ensure_persistence_loaded();
        if guard.local_uuid.is_empty() {
            guard.local_uuid = local_uuid.clone();
            guard.mark_persistence_dirty();
        }
        guard.persistence_activated = true;
    }
    crate::network::set_local_uuid(guard.network.transport.clone(), &local_uuid);
    let transport_state = guard.network.transport.clone();
    // 先释放 ctx 锁：调度线程第一轮即取锁，持锁启动会与其互锁
    drop(guard);

    match HeartbeatScheduler::start(ctx_ptr, interval_ms, transport_state) {
        Ok(scheduler) => {
            let boxed = Box::new(scheduler);
            let handle = crate::handle::put(Box::into_raw(boxed) as *mut std::os::raw::c_void);
            // 重新取锁写回句柄（前面已释放，避免与调度线程互锁）
            if let Ok(mut g) = ctx.lock() {
                g.heartbeat_scheduler = handle;
            }
            handle
        }
        Err(e) => {
            log::error!("启动心跳调度器失败: {}", e);
            0
        }
    }
}

/// 更新心跳调度器本机参数（更新 broadcast_info，全部 handle 由调度线程同步）。
pub fn update_scheduler_params(
    ctx: &crate::SafeContext,
    name: &str,
    battery: i32,
    device_type: &str,
) {
    let Ok(mut guard) = ctx.lock() else {
        return;
    };
    if let Some(ref mut b) = guard.broadcast_info {
        if !name.is_empty() {
            b.name_b64 = base64::engine::general_purpose::STANDARD.encode(name.as_bytes());
        }
        if battery.abs() <= 100 {
            b.battery = battery;
        }
        if !device_type.is_empty() {
            b.device_type = device_type.to_string();
        }
    }
    crate::network::set_broadcast_info(
        guard.network.transport.clone(),
        guard.broadcast_info.clone(),
    );
    // 电量变化必须同步到 mDNS TXT 记录，否则对端发现时读到的仍是启动时电量
    guard.refresh_mdns_battery();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recently_seen_requires_an_existing_record() {
        let mut state = HeartbeatState::new();
        assert!(!state.is_recently_seen("missing", 15));

        state.record("peer");
        assert!(state.is_recently_seen("peer", 15));
    }
}
