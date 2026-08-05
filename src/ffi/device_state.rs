use std::collections::HashSet;
use std::os::raw::{c_char, c_void};

use super::common::{to_cstr, with_ctx};

/// 获取设备状态快照（JSON 数组）
/// 每项: {uuid, name, ip, port, battery, deviceType, lastSeen, connected, paired, online}
/// online = now - lastSeen <= 已配对 ? authed_timeout_ms : unauthed_timeout_ms
/// 在线判定完全基于 lastSeen 时效（mark_connected 已刷新 lastSeen），
/// 避免 TCP 半开连接（对端断网无 FIN/RST）导致 connected 粘滞而永远在线；
/// connected 仅作快照展示字段。在线判定归 Rust；displayName 等 UI 元数据由平台端用 uuid 与 Room 匹配
#[no_mangle]
pub unsafe extern "C" fn nrc_get_device_list(
    ctx_ptr: *mut c_void,
    authed_timeout_ms: i64,
    unauthed_timeout_ms: i64,
) -> *mut c_char {
    let json = with_ctx(ctx_ptr, |ctx| {
        let now = crate::device_registry::now_sec();
        let paired: HashSet<String> = ctx.crypto.device_keys.keys().cloned().collect();
        let mut devices = ctx.registry.snapshot();

        // 补全：已登记已知设备（known_devices，平台只喂 uuid+ip）但尚未收到心跳的设备，
        // 以离线占位显示，保持平台端「已配对设备始终在列表」的旧行为
        for (uuid, ip) in ctx.discovery.get_known_devices() {
            if !devices.iter().any(|d| d.uuid == uuid) {
                devices.push(crate::device_registry::RegisteredDevice {
                    uuid,
                    name: String::new(),
                    ip,
                    port: crate::protocol::codec::DEFAULT_TCP_PORT,
                    battery: crate::device_registry::BATTERY_UNKNOWN,
                    device_type: String::new(),
                    last_seen: 0,
                    connected: false,
                });
            }
        }
        // 已配对（存在密钥）但从未登记过状态的设备同样以离线占位
        for uuid in &paired {
            if !devices.iter().any(|d| d.uuid == *uuid) {
                devices.push(crate::device_registry::RegisteredDevice {
                    uuid: uuid.clone(),
                    name: String::new(),
                    ip: String::new(),
                    port: 0,
                    battery: crate::device_registry::BATTERY_UNKNOWN,
                    device_type: String::new(),
                    last_seen: 0,
                    connected: false,
                });
            }
        }

        let list: Vec<serde_json::Value> = devices
            .into_iter()
            .map(|d| {
                let is_paired = paired.contains(&d.uuid);
                let threshold = if is_paired {
                    authed_timeout_ms
                } else {
                    unauthed_timeout_ms
                };
                let online = threshold > 0
                    && now.saturating_sub(d.last_seen).saturating_mul(1000) <= threshold;
                serde_json::json!({
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
                })
            })
            .collect();
        serde_json::to_string(&list).unwrap_or_else(|_| "[]".to_string())
    });
    to_cstr(&json)
}
