use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::network;
use crate::protocol::codec;
use crate::SafeContext;

/// 在线判定窗口（秒）：last_seen 在此窗口内视为已连接，跳过自动握手
const RECENT_SEEN_SECS: i64 = 15;

pub struct DiscoveryState {
    /// 发现扫描线程
    scanner_running: Arc<AtomicBool>,
    /// 已知设备列表（用于自动连接已配对设备）
    known_devices: Arc<Mutex<HashMap<String, String>>>, // uuid -> ip
}

impl DiscoveryState {
    pub fn new() -> Self {
        Self {
            scanner_running: Arc::new(AtomicBool::new(false)),
            known_devices: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// 添加已知设备（已配对的，用于自动重连发现）
    pub fn add_known_device(&self, uuid: &str, ip: &str) {
        if let Ok(mut guard) = self.known_devices.lock() {
            guard.insert(uuid.to_string(), ip.to_string());
        }
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
            .map(|guard| guard.clone())
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
                    if !running.load(Ordering::Relaxed) {
                        break;
                    }

                    let known_list: Vec<(String, String)> = known
                        .lock()
                        .map(|g| g.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                        .unwrap_or_default();

                    // 是否存在未连接（需扫描握手）的设备：有则保持短周期，无则降频
                    let mut has_offline = false;

                    for (uuid, ip) in known_list {
                        // 跳过本机自身（已知设备中不应包含本机）
                        let is_self = {
                            let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
                            ctx.get_mut()
                                .unwrap()
                                .broadcast_info
                                .as_ref()
                                .map(|b| b.uuid == uuid)
                                .unwrap_or(false)
                        };
                        if is_self {
                            continue;
                        }

                        // 在线判定：最近收到过对方心跳（last_seen 在窗口内）即视为已连接。
                        // 不依赖 TCP 会话：协议连接均为短连接（session 随连接关闭立即移除），
                        // 用 tcp.is_connected 判定会永远失败，导致每轮扫描无限重复握手。
                        let connected = {
                            let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
                            let guard = ctx.get_mut().unwrap();
                            let timed_out = guard.heartbeat.check_timeouts(RECENT_SEEN_SECS);
                            !timed_out.contains(&uuid)
                        };

                        if connected {
                            continue;
                        }
                        has_offline = true;

                        // 尝试握手建立连接（携带本机真实电量，避免 -1 被对端当作真实电量覆盖显示）
                        let (local_uuid, local_pub, local_battery, local_ip) = {
                            let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
                            let guard = ctx.get_mut().unwrap();
                            let bi = guard.broadcast_info.as_ref();
                            (
                                bi.map(|i| i.uuid.clone()).unwrap_or_default(),
                                guard.crypto.local_pub_key_b64.clone().unwrap_or_default(),
                                bi.map(|i| i.battery).unwrap_or(0),
                                crate::ffi::utils::get_local_ip_impl().unwrap_or_default(),
                            )
                        };
                        let dt = {
                            let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
                            ctx.get_mut()
                                .unwrap()
                                .broadcast_info
                                .as_ref()
                                .map(|i| i.device_type.clone())
                                .unwrap_or_default()
                        };
                        let handshake = codec::encode_handshake(
                            &local_uuid,
                            &local_pub,
                            &local_ip,
                            local_battery,
                            &dt,
                        );

                        let resp = network::oneshot_send_receive(
                            &handshake,
                            &ip,
                            codec::DEFAULT_TCP_PORT,
                            3000,
                        );
                        if resp.is_some() {
                            // 握手成功即视为在线：记录心跳时间，避免短连接协议下每轮扫描重复握手
                            let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
                            if let Ok(guard) = ctx.get_mut() {
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
