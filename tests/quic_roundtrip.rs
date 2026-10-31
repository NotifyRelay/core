//! 发送→接收完整闭环验证：A 发送的业务载荷必须完整到达 B 的分发入口。
//!
//! 覆盖 P2c 的核心主张：发送侧已接上 QUIC，且与接收侧的分帧/解码口径一致。

use std::sync::mpsc;
use std::time::Duration;

use notify_relay_core::crypto::{cert, ecdh};
use notify_relay_core::quic::QuicTransport;

/// 收到的一帧。
#[derive(Debug)]
struct Received {
    header: String,
    payload: Vec<u8>,
}

#[test]
fn send_reaches_receiver_with_header_and_payload() {
    let (secret_a, _) = ecdh::generate_keypair();
    let (secret_b, _) = ecdh::generate_keypair();
    let cert_a = cert::derive_cert(&secret_a, "device-a").expect("A 证书");
    let cert_b = cert::derive_cert(&secret_b, "device-b").expect("B 证书");
    let fp_b = cert_b.fingerprint.clone();

    // B 作为接收端，收集入站帧
    let server = QuicTransport::new().expect("创建服务端");
    let (tx, rx) = mpsc::channel::<Received>();
    let port = server
        .start_server(
            0,
            cert_b,
            |_, _| {},
            move |_uuid, header, payload| {
                let _ = tx.send(Received { header, payload });
            },
        )
        .expect("启动服务端");

    // A 作为发送端
    let client = QuicTransport::new().expect("创建客户端");
    client
        .connect("device-b", "127.0.0.1", port, Some(&fp_b))
        .expect("连接");

    // 发送两条不同类型的消息
    let notification = br#"{"packageName":"com.a","title":"hello"}"#;
    let media = br#"{"title":"song","isPlaying":true}"#;
    client
        .send("device-b", "DATA_NOTIFICATION", notification)
        .expect("发送通知");
    client
        .send("device-b", "DATA_MEDIAPLAY", media)
        .expect("发送媒体");

    // 接收端必须完整收到两条，且 header / payload 原样
    let first = rx.recv_timeout(Duration::from_secs(5)).expect("收到第一条");
    let second = rx.recv_timeout(Duration::from_secs(5)).expect("收到第二条");

    let mut got = vec![first, second];
    got.sort_by(|a, b| a.header.cmp(&b.header));

    assert_eq!(got[0].header, "DATA_MEDIAPLAY");
    assert_eq!(got[0].payload, media.to_vec());
    assert_eq!(got[1].header, "DATA_NOTIFICATION");
    assert_eq!(got[1].payload, notification.to_vec());

    client.shutdown();
    server.shutdown();
}

/// 多条消息并发发送时，每条都独立成流且完整到达（不互相截断）。
#[test]
fn concurrent_sends_each_deliver_intact() {
    let (secret_a, _) = ecdh::generate_keypair();
    let (secret_b, _) = ecdh::generate_keypair();
    let cert_a = cert::derive_cert(&secret_a, "device-a").expect("A 证书");
    let cert_b = cert::derive_cert(&secret_b, "device-b").expect("B 证书");
    let fp_b = cert_b.fingerprint.clone();

    let server = QuicTransport::new().expect("创建服务端");
    let (tx, rx) = mpsc::channel::<Received>();
    let port = server
        .start_server(
            0,
            cert_b,
            |_, _| {},
            move |_uuid, header, payload| {
                let _ = tx.send(Received { header, payload });
            },
        )
        .expect("启动服务端");

    let client = QuicTransport::new().expect("创建客户端");
    client
        .connect("device-b", "127.0.0.1", port, Some(&fp_b))
        .expect("连接");

    const COUNT: usize = 8;
    for i in 0..COUNT {
        let body = format!(r#"{{"seq":{i},"text":"payload-{i}"}}"#);
        client
            .send("device-b", "DATA_NOTIFICATION", body.as_bytes())
            .expect("发送");
    }

    let mut seqs = Vec::new();
    for _ in 0..COUNT {
        let msg = rx.recv_timeout(Duration::from_secs(5)).expect("收到");
        let text = String::from_utf8(msg.payload).expect("UTF-8");
        let v: serde_json::Value = serde_json::from_str(&text).expect("JSON");
        seqs.push(v["seq"].as_i64().expect("seq"));
    }
    seqs.sort_unstable();
    assert_eq!(
        seqs,
        (0..COUNT as i64).collect::<Vec<_>>(),
        "每条消息都应完整到达"
    );

    client.shutdown();
    server.shutdown();
}
