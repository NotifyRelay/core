//! 回归：传输服务端派生的证书必须携带非空设备 uuid。
//!
//! 缺陷背景：`start_transport_server` 曾从 `broadcast_info` 取 uuid，
//! 而 `broadcast_info` 在其之后才由心跳调度器写入 → 证书 CN 为空
//! （`notifyrelay:`）→ 对端 `device_uuid_from_cert` 返回 None →
//! 入站帧被判「无法确定设备身份」而丢弃（媒体帧全丢）。

use notify_relay_core::crypto::{cert, ecdh};

/// 证书 CN 必须能反解出传入的 uuid。
#[test]
fn cert_cn_carries_uuid() {
    let (secret, _) = ecdh::generate_keypair();
    let uuid = "3d97367f-5d81-47c2-837d-10ec68e4bc4a";
    let derived = cert::derive_cert(&secret, uuid).expect("派生证书");
    let parsed = cert::device_uuid_from_cert(&derived.cert_der).expect("证书必须能反解 uuid");
    assert_eq!(parsed, uuid, "证书 CN 必须携带完整 uuid");
}

/// 空 uuid 派生的证书必须解析失败（而不是返回空串冒充有效身份）。
#[test]
fn empty_uuid_yields_no_identity() {
    let (secret, _) = ecdh::generate_keypair();
    let derived = cert::derive_cert(&secret, "").expect("空 uuid 仍可派生证书");
    assert!(
        cert::device_uuid_from_cert(&derived.cert_der).is_none(),
        "空 uuid 的证书不得被解析成有效设备身份"
    );
}

/// 两个不同设备派生出的身份互不相同。
#[test]
fn distinct_devices_distinct_identity() {
    let (s1, _) = ecdh::generate_keypair();
    let (s2, _) = ecdh::generate_keypair();
    let c1 = cert::derive_cert(&s1, "dev-1").expect("证书1");
    let c2 = cert::derive_cert(&s2, "dev-2").expect("证书2");
    assert_eq!(
        cert::device_uuid_from_cert(&c1.cert_der).as_deref(),
        Some("dev-1")
    );
    assert_eq!(
        cert::device_uuid_from_cert(&c2.cert_der).as_deref(),
        Some("dev-2")
    );
}
