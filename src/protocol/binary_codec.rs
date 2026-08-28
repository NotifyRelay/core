use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};

use super::header::MessageType;

/// 二进制帧格式: type(1B) + length(4B LE) + payload(NB)
///
/// - type: 消息类型 (0-255)
/// - length: payload 长度，小端序
/// - payload: 明文控制消息体 或 加密的 DATA 消息体

/// 从 TCP 流读取一个完整帧
pub fn read_frame(reader: &mut impl Read) -> io::Result<(u8, Vec<u8>)> {
    let mut header = [0u8; 5];
    reader.read_exact(&mut header)?;
    let msg_type = header[0];
    let length = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if length > 16 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("帧长度过大: {} bytes", length),
        ));
    }
    let mut payload = vec![0u8; length];
    reader.read_exact(&mut payload)?;
    Ok((msg_type, payload))
}

/// 向 TCP 流写入一个完整帧
pub fn write_frame(writer: &mut impl Write, msg_type: u8, payload: &[u8]) -> io::Result<()> {
    let length = payload.len() as u32;
    let header = [
        msg_type,
        length.to_le_bytes()[0],
        length.to_le_bytes()[1],
        length.to_le_bytes()[2],
        length.to_le_bytes()[3],
    ];
    writer.write_all(&header)?;
    writer.write_all(payload)?;
    writer.flush()
}

/// DATA_ 前缀到消息类型的映射
pub fn data_header_to_type(header: &str) -> u8 {
    match header {
        "DATA_NOTIFICATION" => MessageType::NOTIFICATION,
        "DATA_MEDIAPLAY" => MessageType::MEDIA_SESSION,
        "DATA_SUPERISLAND" => MessageType::FEATURE_STATUS,
        "DATA_CLIPBOARD" => MessageType::CLIPBOARD,
        "DATA_ICON_REQUEST" | "DATA_ICON_RESPONSE" => MessageType::PACKAGE_INFO,
        "DATA_APP_LIST_REQUEST" => MessageType::SYNC_SEARCH_APP,
        "DATA_APP_LIST_RESPONSE" => MessageType::SYNC_SEARCH_APP_RESPONSE,
        "DATA_MEDIA_CONTROL" => MessageType::MEDIA_SESSION_CONTROL,
        "DATA_FTP" => MessageType::FTP,
        "DATA_STATUS" => MessageType::DEVICE_STATUS,
        "DATA_APP_LAUNCH" => MessageType::RELAY_APPLICATION,
        _ => 0xFF,
    }
}

/// 消息类型到 DATA_ 前缀的映射
pub fn type_to_data_header(msg_type: u8) -> &'static str {
    match msg_type {
        MessageType::NOTIFICATION => "DATA_NOTIFICATION",
        MessageType::MEDIA_SESSION => "DATA_MEDIAPLAY",
        MessageType::FEATURE_STATUS => "DATA_SUPERISLAND",
        MessageType::CLIPBOARD => "DATA_CLIPBOARD",
        MessageType::PACKAGE_INFO => "DATA_ICON_REQUEST",
        MessageType::SYNC_SEARCH_APP => "DATA_APP_LIST_REQUEST",
        MessageType::SYNC_SEARCH_APP_RESPONSE => "DATA_APP_LIST_RESPONSE",
        MessageType::MEDIA_SESSION_CONTROL => "DATA_MEDIA_CONTROL",
        MessageType::FTP => "DATA_FTP",
        MessageType::DEVICE_STATUS => "DATA_STATUS",
        MessageType::RELAY_APPLICATION => "DATA_APP_LAUNCH",
        _ => "DATA_UNKNOWN",
    }
}

// ==================== ProtoHandshake ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtoHandshake {
    #[serde(rename = "uuid")]
    pub uuid: String,
    #[serde(rename = "pubKey")]
    pub pub_key: String,
    #[serde(rename = "deviceName")]
    pub device_name: String,
    #[serde(rename = "deviceType")]
    pub device_type: String,
    #[serde(rename = "battery")]
    pub battery: i32,
    #[serde(rename = "featureFlag", skip_serializing_if = "Option::is_none")]
    pub feature_flag: Option<Vec<String>>,
}

/// 编码 ProtoHandshake 为二进制帧
pub fn encode_handshake_frame(
    uuid: &str,
    pub_key: &str,
    device_name: &str,
    device_type: &str,
    battery: i32,
    feature_flag: &[&str],
) -> Vec<u8> {
    let hs = ProtoHandshake {
        uuid: uuid.to_string(),
        pub_key: pub_key.to_string(),
        device_name: device_name.to_string(),
        device_type: device_type.to_string(),
        battery,
        feature_flag: Some(feature_flag.iter().map(|s| s.to_string()).collect()),
    };
    let json = serde_json::to_string(&hs).unwrap_or_default();
    // 构造帧: type(1) + length(4) + payload
    let mut frame = Vec::with_capacity(5 + json.len());
    frame.push(MessageType::HANDSHAKE);
    let len = json.len() as u32;
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(json.as_bytes());
    frame
}

/// 从二进制 payload 解码 ProtoHandshake
pub fn decode_handshake_frame(payload: &[u8]) -> Option<ProtoHandshake> {
    serde_json::from_slice(payload).ok()
}

// ==================== DATA 消息帧 ====================

/// 编码 DATA 消息为二进制帧（payload 已加密）
pub fn encode_data_frame(
    msg_type: u8,
    local_uuid: &str,
    local_pub_key: &str,
    encrypted_payload: &str,
) -> Vec<u8> {
    // DATA 消息的 payload 格式: DATA_TYPE:uuid:pub_key:encrypted_data
    let header = type_to_data_header(msg_type);
    let data_payload = format!(
        "{}:{}:{}:{}",
        header, local_uuid, local_pub_key, encrypted_payload
    );
    let mut frame = Vec::with_capacity(5 + data_payload.len());
    frame.push(msg_type);
    let len = data_payload.len() as u32;
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(data_payload.as_bytes());
    frame
}

// ==================== 心跳帧 ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatPayload {
    #[serde(rename = "uuid")]
    pub uuid: String,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "port")]
    pub port: u16,
    #[serde(rename = "battery")]
    pub battery: i32,
    #[serde(rename = "deviceType")]
    pub device_type: String,
}

/// 编码心跳为二进制帧
pub fn encode_heartbeat_frame(
    uuid: &str,
    name: &str,
    port: u16,
    battery: i32,
    device_type: &str,
) -> Vec<u8> {
    let hb = HeartbeatPayload {
        uuid: uuid.to_string(),
        name: name.to_string(),
        port,
        battery,
        device_type: device_type.to_string(),
    };
    let json = serde_json::to_string(&hb).unwrap_or_default();
    let mut frame = Vec::with_capacity(5 + json.len());
    frame.push(MessageType::HEARTBEAT);
    let len = json.len() as u32;
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(json.as_bytes());
    frame
}

/// 从二进制 payload 解码心跳
pub fn decode_heartbeat_frame(payload: &[u8]) -> Option<HeartbeatPayload> {
    serde_json::from_slice(payload).ok()
}

// ==================== 配对消息帧 ====================

/// 编码配对消息为二进制帧
pub fn encode_pairing_frame(msg_type: u8, payload: &str) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(msg_type);
    let len = payload.len() as u32;
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(payload.as_bytes());
    frame
}

/// 编码控制消息（ACCEPT/REJECT/ACK）为二进制帧
pub fn encode_control_frame(msg_type: u8, uuid: &str) -> Vec<u8> {
    let payload = uuid.as_bytes();
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(msg_type);
    let len = payload.len() as u32;
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(payload);
    frame
}
