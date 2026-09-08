use super::binary_codec;
use crate::protocol::header::{FeatureFlag, MessageType};

pub const DEFAULT_TCP_PORT: u16 = 23333;

pub fn encode_pairing_init(
    uuid: &str,
    spake2_pub: &str,
    ip: &str,
    battery: i32,
    device_type: &str,
) -> Vec<u8> {
    let payload = if battery >= 0 {
        format!(
            "{}:{}:{}:{}+:{}",
            uuid, spake2_pub, ip, battery, device_type
        )
    } else {
        // 负数电量（放电）需保留负号：解析端按 i32 解析，abs() 会把 -1 变成 1
        format!("{}:{}:{}:{}:{}", uuid, spake2_pub, ip, battery, device_type)
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
    // uuid : spake2_pub : lt_pub : ip : battery : device_type
    let payload = if battery >= 0 {
        format!(
            "{}:{}:{}:{}:{}+:{}",
            uuid, spake2_pub, lt_pub, ip, battery, device_type
        )
    } else {
        // 同 encode_pairing_init：负数电量保留负号（abs() 会丢失符号）
        format!(
            "{}:{}:{}:{}:{}:{}",
            uuid, spake2_pub, lt_pub, ip, battery, device_type
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
    // 负载格式与配对消息帧一致：uuid:lt_pub_key（base64 不含冒号，splitn(2, ':') 安全）。
    let payload = format!("{}:{}", uuid, lt_pub_key);
    binary_codec::encode_pairing_frame(MessageType::ACCEPT, &payload)
}

pub fn encode_reject(uuid: &str) -> Vec<u8> {
    binary_codec::encode_control_frame(MessageType::REJECT, uuid)
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

/// 解码发现响应
pub fn decode_discovery_response(line: &str) -> Option<(String, String, u16, i32, String)> {
    decode_discovery_request(line)
}
