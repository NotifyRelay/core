use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// 当前时间（epoch 秒）
pub fn now_sec() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// 注册设备状态（平台端可读快照，不含 displayName 等 UI 元数据）
#[derive(Debug, Clone)]
pub struct RegisteredDevice {
    pub uuid: String,
    pub name: String,
    pub ip: String,
    pub port: u16,
    pub battery: i32,
    pub device_type: String,
    pub last_seen: i64,
    pub connected: bool,
}

/// 统一状态注册表：所有运行时设备状态（心跳/连接/发现）统一写入此处
pub struct DeviceRegistry {
    devices: Arc<Mutex<HashMap<String, RegisteredDevice>>>,
}

impl DeviceRegistry {
    pub fn new() -> Self {
        Self {
            devices: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// 登记/刷新设备状态（心跳、mDNS 发现），刷新 last_seen
    /// 非空字段才覆盖旧值（握手等缺少名称的场景不覆盖已有名称）
    pub fn upsert(
        &self,
        uuid: &str,
        name: &str,
        ip: &str,
        port: u16,
        battery: i32,
        device_type: &str,
    ) {
        if uuid.is_empty() {
            return;
        }
        if let Ok(mut guard) = self.devices.lock() {
            let entry = guard
                .entry(uuid.to_string())
                .or_insert_with(|| RegisteredDevice {
                    uuid: uuid.to_string(),
                    name: String::new(),
                    ip: String::new(),
                    port: 0,
                    battery: -1,
                    device_type: String::new(),
                    last_seen: 0,
                    connected: false,
                });
            if !name.is_empty() {
                entry.name = name.to_string();
            }
            if !ip.is_empty() && ip != "0.0.0.0" {
                entry.ip = ip.to_string();
            }
            if port > 0 {
                entry.port = port;
            }
            entry.battery = battery;
            if !device_type.is_empty() {
                entry.device_type = device_type.to_string();
            }
            entry.last_seen = now_sec();
        }
    }

    /// 登记设备状态但不刷新 last_seen（握手场景：仅补充身份信息）
    pub fn upsert_no_seen(
        &self,
        uuid: &str,
        name: &str,
        ip: &str,
        port: u16,
        battery: i32,
        device_type: &str,
    ) {
        if uuid.is_empty() {
            return;
        }
        if let Ok(mut guard) = self.devices.lock() {
            let entry = guard
                .entry(uuid.to_string())
                .or_insert_with(|| RegisteredDevice {
                    uuid: uuid.to_string(),
                    name: String::new(),
                    ip: String::new(),
                    port: 0,
                    battery: -1,
                    device_type: String::new(),
                    last_seen: 0,
                    connected: false,
                });
            if !name.is_empty() {
                entry.name = name.to_string();
            }
            if !ip.is_empty() && ip != "0.0.0.0" {
                entry.ip = ip.to_string();
            }
            if port > 0 {
                entry.port = port;
            }
            entry.battery = battery;
            if !device_type.is_empty() {
                entry.device_type = device_type.to_string();
            }
        }
    }

    /// TCP 连接建立
    pub fn mark_connected(&self, uuid: &str, ip: &str) {
        if let Ok(mut guard) = self.devices.lock() {
            let entry = guard
                .entry(uuid.to_string())
                .or_insert_with(|| RegisteredDevice {
                    uuid: uuid.to_string(),
                    name: String::new(),
                    ip: String::new(),
                    port: 0,
                    battery: -1,
                    device_type: String::new(),
                    last_seen: now_sec(),
                    connected: false,
                });
            if !ip.is_empty() && ip != "0.0.0.0" {
                entry.ip = ip.to_string();
            }
            entry.connected = true;
        }
    }

    /// TCP 连接断开 / 超时
    pub fn mark_disconnected(&self, uuid: &str) {
        if let Ok(mut guard) = self.devices.lock() {
            if let Some(entry) = guard.get_mut(uuid) {
                entry.connected = false;
            }
        }
    }

    /// 移除设备（删除配对时调用，保持内部一致）
    pub fn remove(&self, uuid: &str) {
        if let Ok(mut guard) = self.devices.lock() {
            guard.remove(uuid);
        }
    }

    /// 快照
    pub fn snapshot(&self) -> Vec<RegisteredDevice> {
        self.devices
            .lock()
            .map(|guard| {
                let mut list: Vec<RegisteredDevice> = guard.values().cloned().collect();
                list.sort_by(|a, b| a.uuid.cmp(&b.uuid));
                list
            })
            .unwrap_or_default()
    }

    /// 查询单个设备
    pub fn get(&self, uuid: &str) -> Option<RegisteredDevice> {
        self.devices
            .lock()
            .ok()
            .and_then(|guard| guard.get(uuid).cloned())
    }
}

impl Default for DeviceRegistry {
    fn default() -> Self {
        Self::new()
    }
}
