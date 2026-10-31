use super::version;
use crate::protocol::header::FeatureFlag;

pub const DEFAULT_TCP_PORT: u16 = 23333;

/// 配对初始化载荷（QUIC 控制帧 `CTRL_PAIRING_INIT` 的明文）。
///
/// 字段顺序须与 `processing::process_pairing_init` 解析一致：
/// uuid : coreVersion : spake2_pub : ip : battery : device_type
pub fn pairing_init_payload(
    uuid: &str,
    spake2_pub: &str,
    ip: &str,
    battery: i32,
    device_type: &str,
) -> String {
    if battery >= 0 {
        format!(
            "{}:{}:{}:{}:{}+:{}",
            uuid,
            version::CORE_VERSION,
            spake2_pub,
            ip,
            battery,
            device_type
        )
    } else {
        // 负数电量（放电）需保留负号：解析端按 i32 解析，abs() 会把 -1 变成 1
        format!(
            "{}:{}:{}:{}:{}:{}",
            uuid,
            version::CORE_VERSION,
            spake2_pub,
            ip,
            battery,
            device_type
        )
    }
}

/// 配对响应载荷（QUIC 控制帧 `CTRL_PAIRING_RESP` 的明文）。
///
/// 字段顺序：uuid : coreVersion : spake2_pub : lt_pub : ip : battery : device_type
pub fn pairing_resp_payload(
    uuid: &str,
    spake2_pub: &str,
    lt_pub: &str,
    ip: &str,
    battery: i32,
    device_type: &str,
) -> String {
    if battery >= 0 {
        format!(
            "{}:{}:{}:{}:{}:{}+:{}",
            uuid,
            version::CORE_VERSION,
            spake2_pub,
            lt_pub,
            ip,
            battery,
            device_type
        )
    } else {
        format!(
            "{}:{}:{}:{}:{}:{}:{}",
            uuid,
            version::CORE_VERSION,
            spake2_pub,
            lt_pub,
            ip,
            battery,
            device_type
        )
    }
}

/// ACCEPT 载荷（QUIC 控制帧 `CTRL_ACCEPT` 的明文）：uuid : coreVersion : enc_lt_pub。
///
/// 接收方在 ACCEPT 阶段需要发起方的长期公钥以完成长期密钥派生，
/// 否则 `device_keys.remote_pub_key` 为空，导致平台侧 deriveSharedSecret 失败。
pub fn accept_payload(uuid: &str, lt_pub_key: &str) -> String {
    format!("{}:{}:{}", uuid, version::CORE_VERSION, lt_pub_key)
}

/// REJECT 载荷：`uuid` 或 `uuid:reason`。
pub fn reject_payload(uuid: &str) -> String {
    uuid.to_string()
}

/// 带原因的 REJECT 载荷。
pub fn reject_payload_with_reason(uuid: &str, reason: &str) -> String {
    format!("{}:{}", uuid, reason)
}

/// 拒绝原因码（REJECT 负载第二段），供平台端把失败原因明确呈现给用户，
/// 避免所有失败都被笼统归类为"配对超时/验证失败"而无法定位。
pub struct RejectReason;

impl RejectReason {
    /// 版本不兼容（跨 major.minor），两端需升级到同一版本
    pub const VERSION_MISMATCH: &'static str = "version_mismatch";
    /// 用户主动拒绝/取消
    pub const REJECTED: &'static str = "rejected";
}

/// ACK 载荷：对方 uuid。
pub fn ack_payload(uuid: &str) -> String {
    uuid.to_string()
}

/// 握手载荷（JSON，QUIC 控制帧 `CTRL_HANDSHAKE` 的明文）。
pub fn handshake_payload(uuid: &str, ip: &str, battery: i32, device_type: &str) -> String {
    let flags = FeatureFlag::supported();
    let hb = super::binary_codec::HeartbeatPayload {
        uuid: uuid.to_string(),
        name: String::new(),
        port: DEFAULT_TCP_PORT,
        battery,
        device_type: device_type.to_string(),
    };
    // 握手与心跳共用同一 JSON 结构，额外补充 IP 与特性位
    serde_json::json!({
        "uuid": hb.uuid,
        "deviceName": "",
        "ip": ip,
        "port": hb.port,
        "battery": hb.battery,
        "deviceType": hb.device_type,
        "coreVersion": version::CORE_VERSION,
        "featureFlag": flags,
    })
    .to_string()
}

/// 心跳载荷（JSON，QUIC 控制帧 `CTRL_HEARTBEAT` 的明文）。
pub fn heartbeat_payload(
    uuid: &str,
    name_b64: &str,
    port: u16,
    battery: i32,
    device_type: &str,
) -> String {
    serde_json::json!({
        "uuid": uuid,
        "name": name_b64,
        "port": port,
        "battery": battery,
        "device_type": device_type,
    })
    .to_string()
}

/// 发现请求报文（UDP 广播用，非 QUIC 通道）。
pub fn encode_discovery_request(
    uuid: &str,
    name_b64: &str,
    port: u16,
    battery: i32,
    device_type: &str,
) -> String {
    format!("{}:{}:{}:{}:{}", uuid, name_b64, port, battery, device_type)
}

/// 解析发现请求报文。
pub fn decode_discovery_request(line: &str) -> Option<(String, String, u16, i32, String)> {
    let parts: Vec<&str> = line.splitn(5, ':').collect();
    if parts.len() < 5 {
        return None;
    }
    Some((
        parts[0].to_string(),
        parts[1].to_string(),
        parts[2].parse().ok()?,
        parts[3].trim_end_matches('+').parse().ok()?,
        parts[4].to_string(),
    ))
}

/// 解析 REJECT 负载为 `(uuid, reason)`；旧格式（仅 uuid）原因回落为 `rejected`。
///
/// 空负载返回 None。集中在此避免发现扫描 / 重连 / 处理三处重复解析逻辑。
pub fn decode_reject_payload(payload: &[u8]) -> Option<(String, String)> {
    let text = std::str::from_utf8(payload).ok()?.trim();
    let (uuid, reason) = match text.split_once(':') {
        Some((u, r)) => (u.trim(), r.trim()),
        None => (text, ""),
    };
    if uuid.is_empty() {
        return None;
    }
    let reason = if reason.is_empty() {
        RejectReason::REJECTED
    } else {
        reason
    };
    Some((uuid.to_string(), reason.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_init_carries_version_as_second_field() {
        let text = pairing_init_payload("uuid-a", "spake", "1.2.3.4", 50, "phone");
        assert_eq!(text.split(':').nth(1), Some(version::CORE_VERSION));
    }

    #[test]
    fn pairing_resp_carries_version_as_second_field() {
        let text = pairing_resp_payload("uuid-b", "spake", "enc", "1.2.3.4", 50, "pc");
        assert_eq!(text.split(':').nth(1), Some(version::CORE_VERSION));
    }

    #[test]
    fn accept_carries_version_as_second_field() {
        let text = accept_payload("uuid-a", "enc_lt");
        assert_eq!(text.split(':').nth(1), Some(version::CORE_VERSION));
    }

    #[test]
    fn handshake_carries_core_version() {
        let text = handshake_payload("uuid-1", "127.0.0.1", 50, "desktop");
        assert!(
            text.contains(&format!("\"coreVersion\":\"{}\"", version::CORE_VERSION)),
            "HANDSHAKE 必须携带 coreVersion: {}",
            text
        );
        let v: serde_json::Value = serde_json::from_str(&text).expect("握手载荷应是合法 JSON");
        assert_eq!(v["uuid"], "uuid-1");
        assert_eq!(v["ip"], "127.0.0.1");
    }

    #[test]
    fn heartbeat_carries_expected_fields() {
        let text = heartbeat_payload("uuid-h", "bmFtZQ==", 23333, -20, "pc");
        let v: serde_json::Value = serde_json::from_str(&text).expect("心跳载荷应是合法 JSON");
        assert_eq!(v["uuid"], "uuid-h");
        assert_eq!(v["port"], 23333);
        assert_eq!(v["battery"], -20, "放电电量须保留负号");
        assert_eq!(v["device_type"], "pc");
    }

    #[test]
    fn reject_reason_roundtrip() {
        let text = reject_payload_with_reason("uuid-r", RejectReason::VERSION_MISMATCH);
        let (uuid, reason) = decode_reject_payload(text.as_bytes()).expect("解析 REJECT");
        assert_eq!(uuid, "uuid-r");
        assert_eq!(reason, RejectReason::VERSION_MISMATCH);
        // 无原因时回落为 rejected
        let (_, reason2) =
            decode_reject_payload(reject_payload("uuid-r").as_bytes()).expect("解析");
        assert_eq!(reason2, RejectReason::REJECTED);
    }

    #[test]
    fn discovery_roundtrip() {
        let line = encode_discovery_request("uuid-d", "bmFtZQ==", 23333, 80, "phone");
        let (uuid, name, port, battery, dt) = decode_discovery_request(&line).expect("解析发现");
        assert_eq!(uuid, "uuid-d");
        assert_eq!(name, "bmFtZQ==");
        assert_eq!(port, 23333);
        assert_eq!(battery, 80);
        assert_eq!(dt, "phone");
    }
}
