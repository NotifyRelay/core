//! 入站身份识别验证：设备表不得出现 IP:端口 形式的伪设备标识。
//!
//! 回归背景：早期实现把 `quic:{ip}:{port}` 当作 uuid 传给 on_conn，
//! 导致设备列表出现大量「quic ip 端口」格式的条目。

use std::sync::mpsc;
use std::time::Duration;

use notify_relay_core::crypto::{cert, ecdh};
use notify_relay_core::quic::QuicTransport;

const REAL_UUID: &str = "3f2b9c1e-4d5a-4b6c-8e7d-0123456789ab";

#[test]
fn inbound_uses_cert_uuid_not_ip_port() {
    let (secret_a, _) = ecdh::generate_keypair();
    let (secret_b, _) = ecdh::generate_keypair();
    // A 的证书写入真实 uuid
    let cert_a = cert::derive_cert(&secret_a, REAL_UUID).expect("A 证书");
    let cert_b = cert::derive_cert(&secret_b, "server-b").expect("B 证书");
    let fp_b = cert_b.fingerprint.clone();

    let server = QuicTransport::new().expect("创建服务端");
    let (tx, rx) = mpsc::channel::<(String, String)>();
    let port = server
        .start_server(
            0,
            cert_b,
            move |uuid, ip| {
                let _ = tx.send((uuid, ip));
            },
            |_, _, _| {},
        )
        .expect("启动服务端");

    let client = QuicTransport::new().expect("创建客户端");
    // 纯客户端也需出示证书以参与双向认证
    client.set_local_cert(cert_a);
    client
        .connect("server-b", "127.0.0.1", port, Some(&fp_b))
        .expect("连接");
    // 真实场景下连接建立后必有业务帧；此处发一帧以确保入站流被消费
    let _ = client.send(
        "server-b",
        "CTRL_HEARTBEAT",
        br#"{"uuid":"probe","name":"","port":23333,"battery":100,"device_type":"pc"}"#,
    );

    // 入站回调的 uuid 必须是证书里的真实设备标识
    let (uuid, ip) = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("服务端应收到入站连接");

    assert_eq!(uuid, REAL_UUID, "入站 uuid 必须来自对端证书");
    assert!(!uuid.starts_with("quic:"), "设备身份不得是连接标识: {uuid}");
    assert!(!uuid.contains(':'), "设备身份不得包含 IP:端口 形式: {uuid}");
    assert!(ip.contains("127.0.0.1"), "来源地址仍应记录: {ip}");

    client.shutdown();
    server.shutdown();
}

/// 对端证书必须可反解 uuid，且与派生时传入的一致。
#[test]
fn cert_roundtrip_yields_uuid() {
    let (secret, _) = ecdh::generate_keypair();
    let derived = cert::derive_cert(&secret, REAL_UUID).expect("派生证书");
    let uuid = cert::device_uuid_from_cert(&derived.cert_der).expect("解析 uuid");
    assert_eq!(uuid, REAL_UUID);
}
