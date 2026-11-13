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

/// 未知电量约定值：超出 [-100,100] 区间的值均视为未知
pub const BATTERY_UNKNOWN: i32 = -101;

/// 电量阈值：|v| 超过该值视为未知（单一来源，平台端不再各自硬编码 100）
pub const BATTERY_THRESHOLD: i32 = 100;

/// 未识别设备类型占位值（core 派生 has_known_device_type 的单一来源）
pub const UNKNOWN_DEVICE_TYPE: &str = "unknown";

/// 电量是否未知：|v| > 阈值
pub fn battery_is_unknown(battery: i32) -> bool {
    battery.abs() > BATTERY_THRESHOLD
}

/// 电量百分比；未知时为 -1
pub fn battery_percent(battery: i32) -> i32 {
    if battery_is_unknown(battery) {
        -1
    } else {
        battery.abs()
    }
}

/// 是否充电中；电量未知时为 false
pub fn is_charging(battery: i32) -> bool {
    !battery_is_unknown(battery) && battery >= 0
}

/// 设备类型是否有效（非空白且非 unknown 占位）
pub fn has_known_device_type(device_type: &str) -> bool {
    !device_type.trim().is_empty() && device_type != UNKNOWN_DEVICE_TYPE
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

    /// 登记/刷新设备状态（心跳、UDP 广播发现），刷新 last_seen
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
                    battery: BATTERY_UNKNOWN,
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
            // 未知电量（超出 [-100,100]）不覆盖已有值
            if battery.abs() <= BATTERY_THRESHOLD {
                entry.battery = battery;
            }
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
                    battery: BATTERY_UNKNOWN,
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
            // 未知电量（超出 [-100,100]）不覆盖已有值
            if battery.abs() <= BATTERY_THRESHOLD {
                entry.battery = battery;
            }
            if !device_type.is_empty() {
                entry.device_type = device_type.to_string();
            }
        }
    }

    /// TCP 连接建立（同时刷新 last_seen：TCP 建立即视为在线，无需等待首次心跳）
    pub fn mark_connected(&self, uuid: &str, ip: &str) {
        if let Ok(mut guard) = self.devices.lock() {
            let entry = guard
                .entry(uuid.to_string())
                .or_insert_with(|| RegisteredDevice {
                    uuid: uuid.to_string(),
                    name: String::new(),
                    ip: String::new(),
                    port: 0,
                    battery: BATTERY_UNKNOWN,
                    device_type: String::new(),
                    last_seen: now_sec(),
                    connected: false,
                });
            if !ip.is_empty() && ip != "0.0.0.0" {
                entry.ip = ip.to_string();
            }
            entry.connected = true;
            entry.last_seen = now_sec();
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

// ===== 设备状态快照 =====

use std::collections::HashSet;

/// 已配对设备在线判定默认窗口（毫秒）：平台端传 <=0 时使用
pub const DEFAULT_AUTHED_ONLINE_MS: i64 = 12_000;
/// 未配对设备在线判定默认窗口（毫秒）：平台端传 <=0 时使用。
/// 需大于扫描周期（10s），否则扫描间隔内设备会被判定离线而在列表中闪烁
pub const DEFAULT_UNAUTHED_ONLINE_MS: i64 = 20_000;

/// 构建设备状态快照 JSON 数组。
///
/// 每项: {uuid, name, ip, port, battery, deviceType, lastSeen, connected, paired, online,
///        batteryPercent, isCharging, batteryUnknown, hasKnownDeviceType}
/// online = now - lastSeen <= 已配对 ? authed_timeout_ms : unauthed_timeout_ms
/// 在线判定完全基于 lastSeen 时效（mark_connected 已刷新 lastSeen），
/// 避免 TCP 半开连接（对端断网无 FIN/RST）导致 connected 粘滞而永远在线；
/// connected 仅作快照展示字段。在线判定归 core。
/// 可见性同样归 core：未配对、且未被平台登记（known_devices / 私有库设备行）且已离线的
/// 设备不再返回，平台端只负责展示，不再各自实现过滤策略（两端行为保持一致）。
/// 设备名称/IP 数据源：私有库设备行（改名/历史）+ 运行时注册表（实时），
/// 读取前自动落盘（保证库与内存一致）。
pub fn device_list_json(
    ctx: &mut crate::CoreContext,
    authed_timeout_ms: i64,
    unauthed_timeout_ms: i64,
) -> String {
    // 平台端传 <=0 表示使用 core 内建阈值（保持 ABI 兼容）
    let authed_timeout_ms = if authed_timeout_ms > 0 {
        authed_timeout_ms
    } else {
        DEFAULT_AUTHED_ONLINE_MS
    };
    let unauthed_timeout_ms = if unauthed_timeout_ms > 0 {
        unauthed_timeout_ms
    } else {
        DEFAULT_UNAUTHED_ONLINE_MS
    };
    ctx.ensure_persistence_loaded();
    let _ = ctx.flush_persistence();
    let now = now_sec();
    let paired: HashSet<String> = ctx.crypto.device_keys.keys().cloned().collect();
    let mut devices = ctx.registry.snapshot();

    // 补全：已登记已知设备（known_devices，平台只喂 uuid+ip）但尚未收到心跳的设备，
    // 以离线占位显示，保持平台端「已配对设备始终在列表」的旧行为
    let mut known_uuids: HashSet<String> = HashSet::new();
    for (uuid, ip) in ctx.discovery.get_known_devices() {
        known_uuids.insert(uuid.clone());
        if !devices.iter().any(|d| d.uuid == uuid) {
            devices.push(RegisteredDevice {
                uuid,
                name: String::new(),
                ip,
                port: crate::protocol::codec::DEFAULT_TCP_PORT,
                battery: BATTERY_UNKNOWN,
                device_type: String::new(),
                last_seen: 0,
                connected: false,
            });
        }
    }
    // 已配对（存在密钥）但从未登记过状态的设备同样以离线占位
    for uuid in &paired {
        if !devices.iter().any(|d| d.uuid == *uuid) {
            devices.push(RegisteredDevice {
                uuid: uuid.clone(),
                name: String::new(),
                ip: String::new(),
                port: 0,
                battery: BATTERY_UNKNOWN,
                device_type: String::new(),
                last_seen: 0,
                connected: false,
            });
        }
    }
    // 私有库设备行（含改名/元数据）以离线占位补全，名称/IP 优先于运行时空值
    let persisted: Vec<crate::persistence::PersistedDevice> =
        ctx.persisted_devices.values().cloned().collect();
    let persisted_uuids: HashSet<String> = persisted.iter().map(|r| r.uuid.clone()).collect();
    for row in &persisted {
        if !devices.iter().any(|d| d.uuid == row.uuid) {
            devices.push(RegisteredDevice {
                uuid: row.uuid.clone(),
                name: row.display_name.clone(),
                ip: row.last_ip.clone(),
                port: row.last_port,
                battery: BATTERY_UNKNOWN,
                device_type: String::new(),
                last_seen: 0,
                connected: false,
            });
        }
    }

    let list: Vec<serde_json::Value> = devices
        .into_iter()
        .filter_map(|mut d| {
            let is_paired = paired.contains(&d.uuid)
                || ctx
                    .persisted_devices
                    .get(&d.uuid)
                    .map(|x| x.is_accepted)
                    .unwrap_or(false);
            // 名称：库行（改名/历史）优先，运行时更新兜底
            if let Some(row) = ctx.persisted_devices.get(&d.uuid) {
                if !row.display_name.is_empty() {
                    d.name = row.display_name.clone();
                }
                if d.ip.is_empty() && !row.last_ip.is_empty() {
                    d.ip = row.last_ip.clone();
                }
                if d.port == 0 && row.last_port > 0 {
                    d.port = row.last_port;
                }
            }
            let threshold = if is_paired {
                authed_timeout_ms
            } else {
                unauthed_timeout_ms
            };
            let online =
                threshold > 0 && now.saturating_sub(d.last_seen).saturating_mul(1000) <= threshold;
            // 可见性归 core：未配对、未被平台登记（known_devices/私有库设备行）且已离线的设备不进入列表。
            // 仅由扫描/心跳临时发现的设备离线后即消失，平台端不再各自实现过滤策略
            if !is_paired
                && !known_uuids.contains(&d.uuid)
                && !persisted_uuids.contains(&d.uuid)
                && !online
            {
                return None;
            }
            Some(serde_json::json!({
                "uuid": d.uuid,
                "name": d.name,
                "ip": d.ip,
                "port": d.port,
                "battery": d.battery,
                "deviceType": d.device_type,
                "lastSeen": d.last_seen,
                "connected": d.connected,
                "paired": is_paired,
                "online": online,
                "batteryPercent": battery_percent(d.battery),
                "isCharging": is_charging(d.battery),
                "batteryUnknown": battery_is_unknown(d.battery),
                "hasKnownDeviceType": has_known_device_type(&d.device_type),
            }))
        })
        .collect();
    serde_json::to_string(&list).unwrap_or_else(|_| "[]".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn battery_is_unknown_threshold() {
        assert!(!battery_is_unknown(0));
        assert!(!battery_is_unknown(100));
        assert!(!battery_is_unknown(-100));
        assert!(battery_is_unknown(101));
        assert!(battery_is_unknown(-101));
        assert!(battery_is_unknown(BATTERY_UNKNOWN));
    }

    #[test]
    fn battery_percent_known_and_unknown() {
        assert_eq!(battery_percent(80), 80);
        assert_eq!(battery_percent(-50), 50);
        assert_eq!(battery_percent(100), 100);
        assert_eq!(battery_percent(-100), 100);
        assert_eq!(battery_percent(BATTERY_UNKNOWN), -1);
        assert_eq!(battery_percent(200), -1);
    }

    #[test]
    fn is_charging_sign_and_unknown() {
        assert!(is_charging(80));
        assert!(is_charging(0)); // 0% 视为充电中（battery >= 0，与两端既有语义一致）
        assert!(!is_charging(-50));
        assert!(!is_charging(BATTERY_UNKNOWN)); // 未知 → false
        assert!(!is_charging(200)); // 未知 → false
    }

    #[test]
    fn has_known_device_type_cases() {
        assert!(has_known_device_type("android"));
        assert!(has_known_device_type("pc"));
        assert!(!has_known_device_type(UNKNOWN_DEVICE_TYPE));
        assert!(!has_known_device_type(""));
        assert!(!has_known_device_type("   "));
    }
}
