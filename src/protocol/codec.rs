use super::binary_codec;
use super::version;
use crate::protocol::header::{FeatureFlag, MessageType};

pub const DEFAULT_TCP_PORT: u16 = 23333;

pub fn encode_pairing_init(
    uuid: &str,
    spake2_pub: &str,
    ip: &str,
    battery: i32,
    device_type: &str,
) -> Vec<u8> {
    // 字段顺序须与 processing::process_pairing_init 解析一致：
    // uuid : coreVersion : spake2_pub : ip : battery : device_type
    let payload = if battery >= 0 {
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
    };
    binary_codec::encode_pairing_frame(MessageType::PAIRING_INIT, &payload)
}

pub fn encode_pairing_resp(
    uuid: &str,
    spake2_pub: &str,
    lt_pub: &str,
    ip: &str,
    battery: i32,
    device_type: &str,
) -> Vec<u8> {
    // 字段顺序须与 processing::process_pairing_resp 解析一致：
    // uuid : coreVersion : spake2_pub : lt_pub : ip : battery : device_type
    let payload = if battery >= 0 {
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
        // 同 encode_pairing_init：负数电量保留负号（abs() 会丢失符号）
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
    };
    binary_codec::encode_pairing_frame(MessageType::PAIRING_RESP, &payload)
}

pub fn encode_accept(
    uuid: &str,
    lt_pub_key: &str,
    _ip: &str,
    _battery: i32,
    _device_type: &str,
) -> Vec<u8> {
    // 接收方在 ACCEPT 阶段需要发起方的长期公钥以完成长期密钥派生，
    // 否则 device_keys.remote_pub_key 为空，导致 Kotlin 侧 deriveSharedSecret 失败。
    // 负载格式与配对消息帧一致：uuid:coreVersion:enc_lt_pub
    // （base64 不含冒号，splitn(3, ':') 安全）。
    let payload = format!("{}:{}:{}", uuid, version::CORE_VERSION, lt_pub_key);
    binary_codec::encode_pairing_frame(MessageType::ACCEPT, &payload)
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

pub fn encode_reject(uuid: &str) -> Vec<u8> {
    binary_codec::encode_control_frame(MessageType::REJECT, uuid)
}

/// 编码带原因的 REJECT 帧：`uuid:reason`。
///
/// 兼容旧接收端：旧端只取首段作为 uuid（`splitn(2, ':')`），多余段被忽略；
/// 新接收端解析出 reason 后通过 `on_pairing("REJECT")` 的 data 字段上抛。
pub fn encode_reject_with_reason(uuid: &str, reason: &str) -> Vec<u8> {
    binary_codec::encode_control_frame(MessageType::REJECT, &format!("{}:{}", uuid, reason))
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

pub fn encode_ack(uuid: &str) -> Vec<u8> {
    binary_codec::encode_control_frame(MessageType::ACK, uuid)
}

pub fn encode_handshake(uuid: &str, ip: &str, battery: i32, device_type: &str) -> Vec<u8> {
    let flags = FeatureFlag::supported();
    binary_codec::encode_handshake_frame(uuid, ip, device_type, battery, &flags)
}

pub fn encode_heartbeat_tcp(
    uuid: &str,
    name: &str,
    port: u16,
    battery: i32,
    device_type: &str,
) -> Vec<u8> {
    binary_codec::encode_heartbeat_frame(uuid, name, port, battery, device_type)
}

pub fn encode_data_message(
    header: &str,
    local_uuid: &str,
    local_pub_key: &str,
    encrypted_payload: &str,
) -> Vec<u8> {
    let msg_type = binary_codec::data_header_to_type(header);
    // 保留调用方给定的 header：DATA_ICON_RESPONSE 与 DATA_ICON_REQUEST 共用
    // PACKAGE_INFO 类型，只有 header 能区分请求/响应方向
    binary_codec::encode_data_frame(
        header,
        msg_type,
        local_uuid,
        local_pub_key,
        encrypted_payload,
    )
}

/// 编码发现请求（格式同UDP广播：uuid:name_b64:port:battery:device_type）
pub fn encode_discovery_request(
    uuid: &str,
    name_b64: &str,
    port: u16,
    battery: i32,
    device_type: &str,
) -> String {
    let battery_str = if battery >= 0 {
        format!("+{}", battery)
    } else {
        format!("{}", battery)
    };
    format!(
        "{}:{}:{}:{}:{}",
        uuid, name_b64, port, battery_str, device_type
    )
}

/// 解码发现请求
pub fn decode_discovery_request(line: &str) -> Option<(String, String, u16, i32, String)> {
    let parts: Vec<&str> = line.split(':').collect();
    if parts.len() < 5 {
        return None;
    }
    let uuid = parts[0].to_string();
    let name_b64 = parts[1].to_string();
    let port = parts[2].parse().ok()?;
    let battery = parts[3].parse().unwrap_or(0);
    let device_type = parts[4].to_string();
    Some((uuid, name_b64, port, battery, device_type))
}

/// 编码发现响应（格式同请求：uuid:name_b64:port:battery:device_type）
pub fn encode_discovery_response(
    uuid: &str,
    name_b64: &str,
    port: u16,
    battery: i32,
    device_type: &str,
) -> String {
    encode_discovery_request(uuid, name_b64, port, battery, device_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 帧负载（跳过 5 字节帧头）
    fn payload(frame: &[u8]) -> String {
        String::from_utf8_lossy(&frame[5..]).to_string()
    }

    #[test]
    fn data_frame_carries_version_in_plaintext() {
        let frame = encode_data_message("DATA_NOTIFICATION", "uuid-1", "", "enc");
        let text = payload(&frame);
        let parts: Vec<&str> = text.splitn(5, ':').collect();
        assert_eq!(parts.len(), 5, "DATA 帧应为 5 段: {}", text);
        assert_eq!(parts[0], "DATA_NOTIFICATION");
        assert_eq!(parts[1], "uuid-1");
        assert_eq!(parts[2], version::CORE_VERSION);
        assert_eq!(parts[3], "");
        assert_eq!(parts[4], "enc");
    }

    #[test]
    fn pairing_init_carries_version_as_second_field() {
        let frame = encode_pairing_init("uuid-a", "spake", "1.2.3.4", 50, "phone");
        let text = payload(&frame);
        assert_eq!(text.split(':').nth(1), Some(version::CORE_VERSION));
    }

    #[test]
    fn pairing_resp_carries_version_as_second_field() {
        let frame = encode_pairing_resp("uuid-b", "spake", "enc", "1.2.3.4", 50, "pc");
        let text = payload(&frame);
        assert_eq!(text.split(':').nth(1), Some(version::CORE_VERSION));
    }

    #[test]
    fn accept_carries_version_as_second_field() {
        let frame = encode_accept("uuid-a", "enc_lt", "", 0, "");
        let text = payload(&frame);
        assert_eq!(text.split(':').nth(1), Some(version::CORE_VERSION));
    }

    #[test]
    fn handshake_carries_core_version() {
        let frame = encode_handshake("uuid-1", "127.0.0.1", 50, "desktop");
        let text = payload(&frame);
        assert!(
            text.contains(&format!("\"coreVersion\":\"{}\"", version::CORE_VERSION)),
            "HANDSHAKE 必须携带 coreVersion: {}",
            text
        );
    }
}
