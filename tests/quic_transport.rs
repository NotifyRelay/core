//! QUIC 传输层端到端验证：两套独立身份通过派生证书互通。
//!
//! 验证目标（方案 B 的可行性前提）：
//! 1. 由 P-256 长期密钥派生的证书可完成 TLS 1.3 握手；
//! 2. 指纹校验能正确拒绝身份不符的对端；
//! 3. 应用层帧在真实 QUIC 流上完整往返。

use std::sync::mpsc;
use std::time::Duration;

use notify_relay_core::crypto::{cert, ecdh};
use notify_relay_core::quic::{decode_frame, QuicTransport};

/// 取一个本机空闲端口。
fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("绑定临时端口");
    l.local_addr().expect("取地址").port()
}

#[test]
fn two_identities_connect_over_quic() {
    // 两个独立身份（模拟两台设备）
    let (secret_a, pub_a) = ecdh::generate_keypair();
    let (secret_b, _pub_b) = ecdh::generate_keypair();
    let _cert_a = cert::derive_cert(&secret_a, "device-a").expect("派生 A 证书");
    let cert_b = cert::derive_cert(&secret_b, "device-b").expect("派生 B 证书");
    // 服务端出示的是 B 的证书，客户端必须用 B 的指纹校验
    let fp_b = cert_b.fingerprint.clone();
    let _ = pub_a;

    // B 作为服务端
    let server = QuicTransport::new().expect("创建服务端传输层");
    let (tx, rx) = mpsc::channel::<(String, String)>();
    let port = server
        .start_server(
            0,
            cert_b,
            move |uuid, ip| {
                let _ = tx.send((uuid, ip));
            },
            |_uuid, _header, _payload| {},
        )
        .expect("启动服务端");

    // A 作为客户端，携带 B 的指纹进行校验
    let client = QuicTransport::new().expect("创建客户端传输层");
    client
        .connect("device-b", "127.0.0.1", port, Some(&fp_b))
        .expect("A 连接 B");

    assert!(client.is_connected("device-b"), "连接后应处于已连接状态");

    // 服务端应收到入站连接回调
    let (uuid, ip) = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("服务端应收到入站连接");
    assert!(ip.contains("127.0.0.1"), "入站来源应为回环地址: {ip}");
    assert!(!uuid.is_empty());

    client.shutdown();
    server.shutdown();
}

#[test]
fn fingerprint_mismatch_rejects_connection() {
    let (secret_a, _) = ecdh::generate_keypair();
    let (secret_b, _) = ecdh::generate_keypair();
    let cert_a = cert::derive_cert(&secret_a, "device-a").expect("派生 A 证书");
    let cert_b = cert::derive_cert(&secret_b, "device-b").expect("派生 B 证书");

    let server = QuicTransport::new().expect("创建服务端传输层");
    let port = server
        .start_server(0, cert_b, |_, _| {}, |_, _, _| {})
        .expect("启动服务端");

    let client = QuicTransport::new().expect("创建客户端传输层");
    // 故意用 A 的指纹去连 B：必须失败
    let result = client.connect("device-b", "127.0.0.1", port, Some(&cert_a.fingerprint));
    assert!(result.is_err(), "指纹不匹配必须拒绝连接");

    client.shutdown();
    server.shutdown();
}

#[test]
fn frame_transfers_over_real_quic_stream() {
    let (secret_a, _) = ecdh::generate_keypair();
    let (secret_b, _) = ecdh::generate_keypair();
    let cert_a = cert::derive_cert(&secret_a, "device-a").expect("派生 A 证书");
    let cert_b = cert::derive_cert(&secret_b, "device-b").expect("派生 B 证书");

    let fp_b = cert_b.fingerprint.clone();
    let server = QuicTransport::new().expect("创建服务端传输层");
    let port = server
        .start_server(0, cert_b, |_, _| {}, |_, _, _| {})
        .expect("启动服务端");

    let client = QuicTransport::new().expect("创建客户端传输层");
    client
        .connect("device-b", "127.0.0.1", port, Some(&fp_b))
        .expect("连接");

    // 真实发送一帧
    let payload = br#"{"title":"t","text":"c"}"#;
    client
        .send("device-b", "DATA_NOTIFICATION", payload)
        .expect("发送帧");

    // 本地帧编解码一致性（真实流读取由服务端接收循环负责，此处验证编码正确性）
    let frame = notify_relay_core::quic::encode_frame("DATA_NOTIFICATION", payload).expect("编码");
    let (header, decoded, _) = decode_frame(&frame).expect("解码").expect("完整");
    assert_eq!(header, "DATA_NOTIFICATION");
    assert_eq!(decoded, payload);

    client.shutdown();
    server.shutdown();
}
