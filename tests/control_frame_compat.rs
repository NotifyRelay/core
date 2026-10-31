//! 控制帧兼容性验证：QUIC 承载的明文载荷必须能被既有解码器接受。
//!
//! 关键前提：控制帧解码器（`decode_handshake_frame` / `decode_heartbeat_frame`）
//! 都是直接对 payload 做 `serde_json::from_slice`，配对类则按 ':' 切分纯文本。
//! 因此旧二进制帧的「5 字节帧头」只是传输层包裹，剥掉后明文语义不变。

use notify_relay_core::protocol::binary_codec;
use notify_relay_core::protocol::header::MessageType;

/// 从二进制帧中剥离 5 字节帧头，取出明文载荷（QUIC 侧应发送的内容）。
fn strip_header(frame: &[u8]) -> (u8, &[u8]) {
    let msg_type = frame[0];
    let len = u32::from_le_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize;
    (msg_type, &frame[5..5 + len])
}

#[test]
fn handshake_json_payload_survives_without_frame_header() {
    // 构造一个握手帧，再剥掉帧头 —— 这正是 QUIC 发送的内容
    let payload = r#"{"uuid":"dev-a","deviceName":"A","battery":80,"deviceType":"pc","coreVersion":"1.0.0","ip":"127.0.0.1","port":23333,"featureFlag":0}"#;
    let frame = binary_codec::encode_pairing_frame(MessageType::HANDSHAKE, payload);
    let (msg_type, body) = strip_header(&frame);
    assert_eq!(msg_type, MessageType::HANDSHAKE);
    assert_eq!(body, payload.as_bytes(), "剥离帧头后应得到原始 JSON");
}

#[test]
fn heartbeat_json_payload_survives_without_frame_header() {
    let frame = binary_codec::encode_heartbeat_frame("dev-a", "bkVsbG8=", 23333, 55, "phone");
    let (msg_type, body) = strip_header(&frame);
    assert_eq!(msg_type, MessageType::HEARTBEAT);
    // 心跳解码器直接吃 JSON
    let decoded = binary_codec::decode_heartbeat_frame(body).expect("心跳解码");
    assert_eq!(decoded.uuid, "dev-a");
    assert_eq!(decoded.port, 23333);
    assert_eq!(decoded.battery, 55);
}

#[test]
fn pairing_text_payload_survives_without_frame_header() {
    let payload = "dev-a:1.0.0:c3Bha2Uy:127.0.0.1:80:pc";
    let frame = binary_codec::encode_pairing_frame(MessageType::PAIRING_INIT, payload);
    let (msg_type, body) = strip_header(&frame);
    assert_eq!(msg_type, MessageType::PAIRING_INIT);
    assert_eq!(std::str::from_utf8(body).expect("UTF-8"), payload);
    // 解析端按 ':' 切分，与帧头无关
    let parts: Vec<&str> = std::str::from_utf8(body).unwrap().splitn(6, ':').collect();
    assert_eq!(parts[0], "dev-a");
    assert_eq!(parts.len(), 6);
}
