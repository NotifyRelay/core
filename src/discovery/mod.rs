use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::protocol::codec;
use crate::network;
use crate::SafeContext;

/// 发现的设备信息
#[derive(Debug, Clone)]
pub struct DiscoveredDevice {
    pub uuid: String,
    pub name: String,
    pub ip: String,
    pub port: u16,
    pub battery: i32,
    pub device_type: String,
    pub last_seen: Instant,
}

pub struct DiscoveryState {
    /// 已发现的设备
    pub devices: Arc<Mutex<HashMap<String, DiscoveredDevice>>>,
    /// 发现扫描线程
    scanner_running: Arc<AtomicBool>,
    /// 已知设备列表（用于自动连接已配对设备）
    known_devices: Arc<Mutex<HashMap<String, String>>>, // uuid -> ip
}

impl DiscoveryState {
    pub fn new() -> Self {
        Self {
            devices: Arc::new(Mutex::new(HashMap::new())),
            scanner_running: Arc::new(AtomicBool::new(false)),
            known_devices: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// 添加/更新发现的设备
    pub fn record_device(&self, uuid: &str, name: &str, ip: &str, port: u16, battery: i32, device_type: &str) {
        if let Ok(mut guard) = self.devices.lock() {
            guard.insert(uuid.to_string(), DiscoveredDevice {
                uuid: uuid.to_string(),
                name: name.to_string(),
                ip: ip.to_string(),
                port,
                battery,
                device_type: device_type.to_string(),
                last_seen: Instant::now(),
            });
        }
    }

    /// 获取发现的设备列表
    pub fn get_devices(&self) -> Vec<DiscoveredDevice> {
        self.devices.lock()
            .map(|guard| guard.values().cloned().collect())
            .unwrap_or_default()
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
        self.known_devices.lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    /// 启动自动发现扫描
    /// 定期尝试连接已知设备（用于网络恢复后的重连）
    pub fn start_known_device_scanner(&self, ctx_ptr: usize) {
        if self.scanner_running.load(Ordering::Relaxed) { return; }
        self.scanner_running.store(true, Ordering::Relaxed);

        let running = self.scanner_running.clone();
        let known = self.known_devices.clone();

        thread::Builder::new()
            .name("discovery-scanner".to_string())
            .spawn(move || {
                loop {
                    if !running.load(Ordering::Relaxed) { break; }

                    let known_list: Vec<(String, String)> = known.lock()
                        .map(|g| g.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                        .unwrap_or_default();

                    for (uuid, ip) in known_list {
                        // 检查是否已连接
                        let connected = match unsafe { &mut *(ctx_ptr as *mut SafeContext) }.lock() {
                            Ok(ctx) => ctx.network.tcp.lock()
                                .map(|tcp| tcp.is_connected(&uuid))
                                .unwrap_or(false),
                            Err(_) => false,
                        };

                        if connected {
                            continue;
                        }

                        // 尝试握手建立连接
                        let handshake = match unsafe { &mut *(ctx_ptr as *mut SafeContext) }.lock() {
                            Ok(guard) => {
                                let local_uuid = guard.broadcast_info.as_ref().map(|i| i.uuid.clone()).unwrap_or_default();
                                let local_pub = guard.crypto.local_pub_key_b64.clone().unwrap_or_default();
                                let dt = guard.broadcast_info.as_ref().map(|i| i.device_type.clone()).unwrap_or_default();
                                codec::encode_handshake(&local_uuid, &local_pub, &ip, -1, &dt)
                            }
                            Err(_) => continue,
                        };

                        let resp = network::oneshot_send_receive(&handshake, &ip, codec::DEFAULT_TCP_PORT, 3000);
                        if let Some(_line) = resp {
                            let _ = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
                            // 响应会通过 process_line 处理并建立 TCP 会话
                        }
                    }

                    thread::sleep(Duration::from_secs(5));
                }
            })
            .expect("启动发现扫描线程失败");
    }

    pub fn stop_scanner(&self) {
        self.scanner_running.store(false, Ordering::Relaxed);
    }
}
