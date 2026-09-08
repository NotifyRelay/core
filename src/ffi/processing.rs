use std::ffi::CString;

use base64::Engine;

use crate::{
    crypto::{aes, ecdh, hkdf, spake2},
    protocol::{binary_codec, codec, header::MessageType},
    SafeContext,
};

use super::send::do_send_via_network;

fn fire_pairing_cb(
    ctx: &SafeContext,
    uuid: &str,
    msg_type: &str,
    data: &str,
    int_value: i32,
    extra: &str,
) {
    let (cb, ud) = {
        let Ok(g) = ctx.lock() else {
            return;
        };
        (g.router.on_pairing, g.router.user_data)
    };
    if let Some(cb_fn) = cb {
        let uuid_c = CString::new(uuid).unwrap_or_default();
        let type_c = CString::new(msg_type).unwrap_or_default();
        let data_c = CString::new(data).unwrap_or_default();
        let extra_c = CString::new(extra).unwrap_or_default();
        cb_fn(
            uuid_c.as_ptr(),
            type_c.as_ptr(),
            data_c.as_ptr(),
            int_value,
            extra_c.as_ptr(),
            ud,
        );
    }
}

fn fire_data_cb(ctx: &SafeContext, uuid: &str, msg_type: &str, plaintext: &str) {
    let (cb, ud) = {
        let Ok(g) = ctx.lock() else {
            return;
        };
        (g.router.on_data, g.router.user_data)
    };
    if let Some(cb_fn) = cb {
        let uuid_c = CString::new(uuid).unwrap_or_default();
        let type_c = CString::new(msg_type).unwrap_or_default();
        let text_c = CString::new(plaintext).unwrap_or_default();
        cb_fn(uuid_c.as_ptr(), type_c.as_ptr(), text_c.as_ptr(), ud);
    }
}

/// 提取帧内声明的发送方 uuid；无法判定的控制帧（ACK / REJECT 负载为对端 uuid）返回 None
fn frame_sender_uuid(msg_type: u8, payload: &[u8]) -> Option<String> {
    match msg_type {
        MessageType::HANDSHAKE => binary_codec::decode_handshake_frame(payload).map(|h| h.uuid),
        MessageType::HEARTBEAT => binary_codec::decode_heartbeat_frame(payload).map(|h| h.uuid),
        t if t >= 10 && t <= 200 => std::str::from_utf8(payload)
            .ok()
            .and_then(|s| s.splitn(4, ':').nth(1).map(|v| v.to_string())),
        // 配对帧与 ACCEPT：首段即发送方 uuid
        MessageType::PAIRING_INIT | MessageType::PAIRING_RESP | MessageType::ACCEPT => {
            std::str::from_utf8(payload)
                .ok()
                .and_then(|s| s.splitn(2, ':').next().map(|v| v.trim().to_string()))
                .filter(|u| !u.is_empty())
        }
        _ => None,
    }
}

/// 处理二进制帧（硬切换，不再支持文本协议）
/// session_uuid：帧所属 TCP 会话的 uuid（oneshot 直连场景为 None）；
/// 非 None 时校验帧内声明的 uuid 与会话一致，防止跨会话冒用对端身份
pub(crate) fn process_frame(
    ctx: &SafeContext,
    session_uuid: Option<&str>,
    msg_type: u8,
    payload: &[u8],
) -> i32 {
    if let Some(session) = session_uuid {
        if let Some(frame_uuid) = frame_sender_uuid(msg_type, payload) {
            if frame_uuid != session {
                log::warn!(
                    "处理消息: 丢弃 uuid 与会话不一致的帧 session={}, frame={}, type={}",
                    session,
                    frame_uuid,
                    msg_type
                );
                return -1;
            }
        }
    }
    match msg_type {
        MessageType::HANDSHAKE => process_handshake(ctx, payload),
        MessageType::PAIRING_INIT => process_pairing_init(ctx, payload),
        MessageType::PAIRING_RESP => process_pairing_resp(ctx, payload),
        MessageType::ACCEPT => process_accept(ctx, payload),
        MessageType::REJECT => process_reject(ctx, payload),
        MessageType::HEARTBEAT => process_heartbeat(ctx, payload),
        MessageType::ACK => {
            log::debug!("处理消息: 收到 ACK");
            0
        }
        MessageType::RESYNC_REQUEST => process_data(ctx, msg_type, payload),
        t if t >= 10 && t <= 200 => process_data(ctx, t, payload),
        _ => {
            log::warn!("处理消息: 未知消息类型 type={}", msg_type);
            -1
        }
    }
}

fn process_handshake(ctx: &SafeContext, payload: &[u8]) -> i32 {
    let hs = match binary_codec::decode_handshake_frame(payload) {
        Some(h) => h,
        None => {
            log::error!("处理消息: HANDSHAKE 解码失败");
            return -1;
        }
    };

    let uuid_str = hs.uuid.clone();
    // 重连 HANDSHAKE 不再明文携带长期公钥；仅使用配对阶段锁定的 remote_pub_key 派生，
    // 使长期 ECDH 密钥严格绑定到经配对码(SPAKE2)认证的身份，杜绝链路劫持替换公钥。
    let (is_self, already_paired, local_key, locked_remote) = {
        let Ok(guard) = ctx.lock() else {
            return -1;
        };
        (
            guard
                .broadcast_info
                .as_ref()
                .map(|b| b.uuid == uuid_str)
                .unwrap_or(false),
            guard.crypto.device_keys.contains_key(&uuid_str),
            guard.crypto.local_key.clone(),
            guard
                .crypto
                .device_keys
                .get(&uuid_str)
                .map(|e| e.remote_pub_key.clone())
                .unwrap_or_default(),
        )
    };
    if is_self {
        return 0;
    }

    if already_paired {
        if locked_remote.is_empty() {
            log::warn!(
                "HANDSHAKE: 锁定 remote_pub_key 为空，跳过 ECDH 重派生(uuid={}，建议重新配对)",
                uuid_str
            );
        } else if let Some(ref key) = local_key {
            if let Ok(shared) = ecdh::compute_shared_secret(key, &locked_remote) {
                let aes_key = hkdf::derive_session_key(&shared);
                let b64 = base64::engine::general_purpose::STANDARD.encode(aes_key);
                {
                    let Ok(mut guard) = ctx.lock() else {
                        return -1;
                    };
                    guard.crypto.device_keys.insert(
                        uuid_str.clone(),
                        crate::crypto::DeviceKeyEntry {
                            remote_pub_key: locked_remote.clone(),
                            aes_key_b64: b64,
                            aes_key_bytes: Some(aes_key),
                        },
                    );
                }
            }
        }
    }

    let ip = {
        let Ok(guard) = ctx.lock() else {
            return -1;
        };
        let ip_from_ips = guard
            .device_ips
            .lock()
            .ok()
            .and_then(|ips| ips.get(uuid_str.as_str()).cloned())
            .unwrap_or_default();
        let ip = if hs.device_name.is_empty() {
            ip_from_ips.as_str()
        } else {
            &hs.device_name
        };
        guard.registry.upsert_no_seen(
            &uuid_str,
            "",
            ip,
            codec::DEFAULT_TCP_PORT,
            hs.battery,
            &hs.device_type,
        );
        ip.to_string()
    };

    let data = serde_json::json!({
        "uuid": hs.uuid,
        "pub_key": locked_remote,
        "device_name": hs.device_name,
        "battery": hs.battery,
        "device_type": hs.device_type,
        "feature_flag": hs.feature_flag,
        "auto_accept": already_paired,
    })
    .to_string();

    if already_paired {
        let (local_uuid, local_pub, local_battery, local_type, network) = {
            let Ok(guard) = ctx.lock() else {
                return -1;
            };
            guard.discovery.add_known_device(&uuid_str, &ip);
            let bi = guard.broadcast_info.as_ref();
            (
                bi.map(|b| b.uuid.clone()).unwrap_or_default(),
                guard.crypto.local_pub_key_b64.clone().unwrap_or_default(),
                bi.map(|b| b.battery).unwrap_or(0),
                bi.map(|b| b.device_type.clone()).unwrap_or_default(),
                guard.network.tcp.clone(),
            )
        };
        let local_ip = super::utils::get_local_ip_impl().unwrap_or_default();
        if !local_uuid.is_empty() && !local_pub.is_empty() {
            let accept = codec::encode_accept(
                &local_uuid,
                &local_pub,
                &local_ip,
                local_battery,
                &local_type,
            );
            do_send_via_network(&network, &uuid_str, &accept);
            log::info!("配对自动闭环: 已配对设备 {} 握手后自动 ACCEPT", uuid_str);
        }
    }

    fire_pairing_cb(
        ctx,
        &uuid_str,
        "HANDSHAKE",
        &data,
        hs.battery,
        &locked_remote,
    );
    0
}

fn process_pairing_init(ctx: &SafeContext, payload: &[u8]) -> i32 {
    let text = match std::str::from_utf8(payload) {
        Ok(s) => s,
        Err(_) => {
            log::error!("处理消息: PAIRING_INIT payload 非 UTF-8");
            return -1;
        }
    };
    // 配对消息 payload 格式: uuid:spake2_pub:ip:battery:device_type
    // 限定 5 段：device_type 允许包含冒号（对端传入，未做转义）
    let parts: Vec<&str> = text.splitn(5, ':').collect();
    if parts.len() < 5 {
        log::error!("处理消息: PAIRING_INIT 字段不足");
        return -1;
    }
    let uuid = parts[0];
    let spake2_pub = parts[1];
    let ip = parts[2];
    let battery: i32 = parts[3].trim_end_matches('+').parse().unwrap_or(0);
    let device_type = parts[4];

    {
        let Ok(mut guard) = ctx.lock() else {
            return -1;
        };
        // 配对会话按发起方 uuid 隔离：多个设备同时发起配对时互不覆盖
        let session = guard.pairing_session_mut(uuid);
        session.pairing_ctx = Some(crate::PairingContext {
            peer_uuid: uuid.to_string(),
            peer_spake2_pub: spake2_pub.to_string(),
            peer_lt_pub: None,
        });
    }
    let data = serde_json::json!({
        "uuid": uuid,
        "spake2_pub": spake2_pub,
        "ip": ip,
        "battery": battery,
        "device_type": device_type,
    })
    .to_string();
    fire_pairing_cb(ctx, uuid, "PAIRING_INIT", &data, battery, spake2_pub);
    0
}

fn process_pairing_resp(ctx: &SafeContext, payload: &[u8]) -> i32 {
    let text = match std::str::from_utf8(payload) {
        Ok(s) => s,
        Err(_) => {
            log::error!("处理消息: PAIRING_RESP payload 非 UTF-8");
            return -1;
        }
    };
    // 配对消息 payload 格式: uuid:spake2_pub:enc_lt_pub:ip:battery:device_type
    // enc_lt_pub 为接收方用 K_s 加密的本机长期公钥；此处用 K_s 解密
    // 限定 6 段：device_type 允许包含冒号（对端传入，未做转义）
    let parts: Vec<&str> = text.splitn(6, ':').collect();
    if parts.len() < 6 {
        log::error!("处理消息: PAIRING_RESP 字段不足");
        return -1;
    }
    let uuid = parts[0];
    let spake2_pub = parts[1];
    let enc_lt_pub = parts[2];
    let ip = parts[3];
    let battery: i32 = parts[4].trim_end_matches('+').parse().unwrap_or(0);
    let device_type = parts[5];

    // 发起方在此完成 SPAKE2 prover，得到会话密钥 K_s，并用其解密对端 lt_pub；
    // K_s 暂存供后续 ACCEPT 加密复用（两端推导出的 K_s 对称一致）
    //
    // 会话按对端 uuid 取用：平台端 PAIRING_RESP 携带的 uuid 语义不统一
    // （Android 传发起方 uuid、PC 传本机 uuid），未命中时退回唯一持有 prover 的会话。
    let (session_id, prover) = {
        let Ok(mut guard) = ctx.lock() else {
            return -1;
        };
        guard.prune_expired_pairing_sessions();
        let key = if guard.pairing_sessions.contains_key(uuid) {
            uuid.to_string()
        } else {
            let mut with_prover: Vec<String> = guard
                .pairing_sessions
                .iter()
                .filter(|(_, s)| s.prover.is_some())
                .map(|(k, _)| k.clone())
                .collect();
            if with_prover.len() == 1 {
                with_prover.pop().unwrap_or_default()
            } else {
                log::error!("处理 PAIRING_RESP: 缺少 SPAKE2 prover 会话");
                String::new()
            }
        };
        if key.is_empty() {
            (String::new(), None)
        } else if let Some(session) = guard.pairing_sessions.get_mut(&key) {
            (key, session.prover.take())
        } else {
            (String::new(), None)
        }
    };

    let (peer_lt_pub, mut ks) = match prover {
        Some(prover) => match spake2::prover_complete(prover, spake2_pub) {
            Ok(shared) => {
                let k = hkdf::derive_session_key(&shared);
                match aes::decrypt(&k, enc_lt_pub) {
                    Ok(bytes) => (Some(String::from_utf8_lossy(&bytes).to_string()), Some(k)),
                    Err(e) => {
                        log::error!("处理 PAIRING_RESP: 对端 lt_pub 解密失败: {}", e);
                        (None, Some(k))
                    }
                }
            }
            Err(e) => {
                log::error!("处理 PAIRING_RESP: SPAKE2 prover 完成失败: {}", e);
                (None, None)
            }
        },
        None => {
            log::error!("处理 PAIRING_RESP: 缺少 SPAKE2 prover 会话");
            (None, None)
        }
    };

    if !session_id.is_empty() {
        let Ok(mut guard) = ctx.lock() else {
            if let Some(key) = ks.as_mut() {
                crate::crypto::zeroize_key(key);
            }
            return -1;
        };
        if let Some(session) = guard.pairing_sessions.get_mut(&session_id) {
            if let Some(previous) = session.session_key.as_mut() {
                crate::crypto::zeroize_key(previous);
            }
            session.session_key = ks;
            session.pairing_ctx = Some(crate::PairingContext {
                peer_uuid: uuid.to_string(),
                peer_spake2_pub: spake2_pub.to_string(),
                peer_lt_pub: peer_lt_pub.clone(),
            });
            session.refresh_expiry();
        }
    }
    if let Some(key) = ks.as_mut() {
        crate::crypto::zeroize_key(key);
    }

    let data = serde_json::json!({
        "uuid": uuid,
        "spake2_pub": spake2_pub,
        "lt_pub": peer_lt_pub.clone().unwrap_or_default(),
        "ip": ip,
        "battery": battery,
        "device_type": device_type,
    })
    .to_string();
    fire_pairing_cb(
        ctx,
        uuid,
        "PAIRING_RESP",
        &data,
        battery,
        peer_lt_pub.as_deref().unwrap_or(""),
    );
    0
}

fn process_accept(ctx: &SafeContext, payload: &[u8]) -> i32 {
    // ACCEPT 负载格式：uuid:enc_lt_pub（enc_lt_pub 为 AES(K_s) 密文，与 encode_accept 对应）
    let (uuid, enc_lt) = match std::str::from_utf8(payload) {
        Ok(s) => {
            let s = s.trim();
            let parts: Vec<&str> = s.splitn(2, ':').collect();
            let u = parts.first().map(|p| p.to_string()).unwrap_or_default();
            let k = if parts.len() > 1 {
                parts[1].to_string()
            } else {
                String::new()
            };
            (u, k)
        }
        Err(_) => {
            log::error!("处理消息: ACCEPT payload 非 UTF-8");
            return -1;
        }
    };

    // 配对流程判定：接收方在 nrc_send_pairing_resp 已完成 verifier 并暂存 K_s。
    // K_s 按 ACCEPT 发送方 uuid 取用，确保命中同一对端的配对会话
    let ks = {
        let Ok(mut guard) = ctx.lock() else {
            return -1;
        };
        guard.prune_expired_pairing_sessions();
        guard
            .pairing_sessions
            .remove(&uuid)
            .and_then(|mut session| session.session_key.take())
    };

    let mut success = false;
    let mut pairing_flow = false;
    let mut cb_lt_pub = String::new();
    if let Some(mut aes_key) = ks {
        pairing_flow = true;
        match aes::decrypt(&aes_key, &enc_lt) {
            Ok(bytes) => {
                let remote_lt = String::from_utf8_lossy(&bytes).to_string();
                cb_lt_pub = remote_lt.clone();
                // 数据通道密钥由长期 ECDH 派生（与重连路径 process_handshake 一致），
                // K_s 仅用于本次长期公钥传输；派生失败时回落 K_s，保证两端对称
                let (b64, key_bytes) = {
                    let Ok(guard) = ctx.lock() else {
                        crate::crypto::zeroize_key(&mut aes_key);
                        return -1;
                    };
                    match guard.crypto.derive_session_key(&remote_lt) {
                        Some(k) => (base64::engine::general_purpose::STANDARD.encode(k), Some(k)),
                        None => {
                            log::error!("处理消息: ECDH 派生会话密钥失败，回落使用 K_s");
                            (
                                base64::engine::general_purpose::STANDARD.encode(aes_key),
                                None,
                            )
                        }
                    }
                };
                // K_s 使命完成，清零，避免长期驻留内存
                crate::crypto::zeroize_key(&mut aes_key);
                {
                    let Ok(mut guard) = ctx.lock() else {
                        return -1;
                    };
                    guard.crypto.device_keys.insert(
                        uuid.clone(),
                        crate::crypto::DeviceKeyEntry {
                            remote_pub_key: remote_lt.clone(),
                            aes_key_b64: b64,
                            aes_key_bytes: key_bytes,
                        },
                    );
                }
                success = true;
                let target_uuid = uuid.clone();
                {
                    // 与扫描回调、后台线程统一通过 lock() 取锁
                    if let Ok(g) = ctx.lock() {
                        g.discovery.add_known_device(&target_uuid, "");
                    }
                }
                let delay_pending = {
                    match ctx.lock() {
                        Ok(g) => g.applist_delay_pending.clone(),
                        // 取锁失败（极低概率）：按未挂起来处理，仍尝试触发一次应用列表拉取
                        Err(_) => std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                    }
                };
                if !delay_pending.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    let ctx_ptr = ctx as *const SafeContext as usize;
                    let _ = std::thread::Builder::new()
                        .name("auto-applist".to_string())
                        .spawn(move || {
                            std::thread::sleep(std::time::Duration::from_secs(3));
                            // 后台线程：通过 lock() 取锁，与 FFI/扫描回调共用同一把锁
                            let ctx = unsafe { &*(ctx_ptr as *const SafeContext) };
                            if let Ok(g) = ctx.lock() {
                                if g.sender_queue != 0 {
                                    let q = unsafe {
                                        &*(crate::ffi::handle::get(g.sender_queue)
                                            as *const crate::sender_queue::SenderQueue)
                                    };
                                    let now = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .map(|d| d.as_secs() as i64)
                                        .unwrap_or(0);
                                    let payload =
                                        crate::app_sync::build_applist_request("user", now);
                                    q.enqueue(crate::sender_queue::SendItem {
                                        device_uuid: target_uuid.clone(),
                                        header: "DATA_APP_LIST_REQUEST".to_string(),
                                        plaintext: payload,
                                        dedup_key: None,
                                        retries_left: 0,
                                        coalesce_key: None,
                                    });
                                }
                            }
                            delay_pending.store(false, std::sync::atomic::Ordering::SeqCst);
                        });
                }
            }
            Err(e) => {
                log::error!("处理消息: ACCEPT 中 lt_pub 解密失败: {}", e);
            }
        }
    } else {
        // 已配对设备重连走的是正常路径（密钥由 HANDSHAKE 重派生），
        // 这里仅为排查保留 debug 级日志，避免平台端日志桥接产生告警
        log::debug!("处理消息: ACCEPT 时 SPAKE2 会话密钥缺失(已配对设备重连场景，跳过密钥更新)");
        let Ok(g) = ctx.lock() else {
            return -1;
        };
        cb_lt_pub = g
            .crypto
            .device_keys
            .get(&uuid)
            .map(|e| e.remote_pub_key.clone())
            .unwrap_or_default();
    }

    let data = serde_json::json!({
        "uuid": uuid,
        "success": success,
        "lt_pub_key": cb_lt_pub,
    })
    .to_string();
    fire_pairing_cb(ctx, &uuid, "ACCEPT", &data, 0, "");

    if pairing_flow {
        fire_pairing_cb(ctx, &uuid, "RESULT", &serde_json::json!({"uuid": uuid, "success": success, "lt_pub_key": cb_lt_pub, "error": if success { "ok" } else { "spake2_failed" }}).to_string(), if success { 1 } else { 0 }, if success { "ok" } else { "spake2_failed" });
    }

    {
        let ack = codec::encode_ack(&uuid);
        let network = match ctx.lock() {
            Ok(guard) => guard.network.tcp.clone(),
            Err(_) => return -1,
        };
        do_send_via_network(&network, &uuid, &ack);
    }
    0
}

fn process_reject(ctx: &SafeContext, payload: &[u8]) -> i32 {
    let uuid = match std::str::from_utf8(payload) {
        Ok(s) => s.trim(),
        Err(_) => return -1,
    };
    let uuid = uuid.to_string();

    let network = match ctx.lock() {
        Ok(mut guard) => {
            guard.pairing_sessions.remove(&uuid);
            guard.network.tcp.clone()
        }
        Err(_) => return -1,
    };

    fire_pairing_cb(
        ctx,
        &uuid,
        "REJECT",
        &serde_json::json!({"uuid": uuid}).to_string(),
        0,
        "rejected",
    );
    fire_pairing_cb(
        ctx,
        &uuid,
        "RESULT",
        &serde_json::json!({"uuid": uuid, "success": false, "error": "rejected"}).to_string(),
        0,
        "rejected",
    );
    {
        let ack = codec::encode_ack(&uuid);
        do_send_via_network(&network, &uuid, &ack);
    }
    0
}

fn process_heartbeat(ctx: &SafeContext, payload: &[u8]) -> i32 {
    let hb = match binary_codec::decode_heartbeat_frame(payload) {
        Some(h) => h,
        None => {
            log::error!("处理消息: HEARTBEAT 解码失败");
            return -1;
        }
    };

    let Ok(mut guard) = ctx.lock() else {
        return -1;
    };
    guard.heartbeat.record(&hb.uuid);
    drop(guard);
    let name_decoded = String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(&hb.name)
            .unwrap_or_default(),
    )
    .unwrap_or(hb.name.clone());

    {
        let Ok(guard) = ctx.lock() else {
            return -1;
        };
        let ip = guard
            .device_ips
            .lock()
            .ok()
            .and_then(|ips| ips.get(hb.uuid.as_str()).cloned())
            .unwrap_or_default();
        guard.registry.upsert(
            &hb.uuid,
            &name_decoded,
            &ip,
            hb.port,
            hb.battery,
            &hb.device_type,
        );
    }

    let data = serde_json::json!({
        "uuid": hb.uuid,
        "name": name_decoded,
        "port": hb.port,
        "battery": hb.battery,
        "device_type": hb.device_type,
        "ip": "",
    })
    .to_string();
    fire_pairing_cb(
        ctx,
        &hb.uuid,
        "HEARTBEAT_TCP",
        &data,
        hb.battery,
        &name_decoded,
    );
    0
}

fn process_data(ctx: &SafeContext, msg_type: u8, payload: &[u8]) -> i32 {
    // DATA 消息 payload 格式: DATA_TYPE:uuid:pub_key:encrypted_data
    let text = match std::str::from_utf8(payload) {
        Ok(s) => s,
        Err(_) => {
            log::error!("处理消息: DATA payload 非 UTF-8");
            return -1;
        }
    };
    let parts: Vec<&str> = text.splitn(4, ':').collect();
    if parts.len() < 4 {
        log::error!("处理消息: DATA 字段不足");
        return -1;
    }
    // parts[0] 为 wire header（DATA_XXX），用于区分共用同一 msg_type 的请求/响应方向
    let wire_header = parts[0];
    let local_uuid = parts[1];
    let encrypted_payload = parts[3];

    let key_arr = {
        let Ok(guard) = ctx.lock() else {
            return -1;
        };
        guard.crypto.get_aes_key(local_uuid)
    };
    let key_arr = match key_arr {
        Some(k) => k,
        None => {
            log::warn!(
                "处理消息: 未找到密钥或密钥无效 uuid={}, msg_type={}",
                local_uuid,
                msg_type
            );
            return -1;
        }
    };

    let plain = match aes::decrypt(&key_arr, encrypted_payload) {
        Ok(p) => p,
        Err(_) => {
            log::error!(
                "处理消息: DATA 解密失败 msg_type={}, uuid={}",
                msg_type,
                local_uuid
            );
            return -1;
        }
    };
    let plaintext = String::from_utf8_lossy(&plain).to_string();
    // 以对端写入的 wire header 为准：DATA_ICON_REQUEST / DATA_ICON_RESPONSE
    // 共用 PACKAGE_INFO 类型，仅 header 能还原真实方向
    let data_header = if wire_header.is_empty() {
        binary_codec::type_to_data_header(msg_type)
    } else {
        wire_header
    };

    log::debug!(
        "处理消息: 解密 DATA header={}, uuid={}, 密文长度={}",
        data_header,
        local_uuid,
        encrypted_payload.len()
    );

    // 重同步请求：接收端缺失基线时主动请求发送方重发 FULL
    if msg_type == MessageType::RESYNC_REQUEST {
        match serde_json::from_str::<serde_json::Value>(&plaintext) {
            Ok(v) => {
                if let Some(fid) = v.get("feature").and_then(|x| x.as_str()) {
                    // local_uuid 为请求方（原接收端）；本机作为发送方标记对应会话重发 FULL
                    crate::state_merge::apply_resync_request(ctx, local_uuid, fid);
                }
            }
            Err(e) => {
                log::error!("处理消息: 重同步请求 JSON 解析失败: {}", e);
            }
        }
        return 0;
    }

    // 超级岛 / 媒体：交给状态合并引擎
    if msg_type == MessageType::MEDIA_SESSION || msg_type == MessageType::FEATURE_STATUS {
        let is_media = msg_type == MessageType::MEDIA_SESSION;
        crate::state_merge::handle_state_message(ctx, local_uuid, is_media, &plaintext);
        return 0;
    }

    let cb_type = match msg_type {
        MessageType::NOTIFICATION => "NOTIFICATION",
        MessageType::MEDIA_SESSION => "MEDIAPLAY",
        MessageType::PACKAGE_INFO => {
            if data_header == "DATA_ICON_RESPONSE" {
                "ICON_RESPONSE"
            } else {
                "ICON_REQUEST"
            }
        }
        MessageType::SYNC_SEARCH_APP => "APP_LIST_REQUEST",
        MessageType::SYNC_SEARCH_APP_RESPONSE => "APP_LIST_RESPONSE",
        MessageType::MEDIA_SESSION_CONTROL => "MEDIA_CONTROL",
        MessageType::FTP => "FTP",
        MessageType::CLIPBOARD => "CLIPBOARD",
        MessageType::DEVICE_STATUS => "STATUS",
        MessageType::RELAY_APPLICATION => "APP_LAUNCH",
        MessageType::FEATURE_STATUS => "SUPERISLAND",
        _ => "UNKNOWN",
    };

    let processed_text = match msg_type {
        MessageType::NOTIFICATION => {
            serde_json::from_str::<crate::models::Notification>(&plaintext)
                .ok()
                .and_then(|v| serde_json::to_string(&v).ok())
                .unwrap_or(plaintext.clone())
        }
        MessageType::MEDIA_SESSION | MessageType::FEATURE_STATUS => {
            serde_json::from_str::<crate::models::MediaPayload>(&plaintext)
                .ok()
                .and_then(|v| serde_json::to_string(&v).ok())
                .unwrap_or(plaintext.clone())
        }
        MessageType::PACKAGE_INFO => serde_json::from_str::<crate::models::IconRequest>(&plaintext)
            .ok()
            .and_then(|v| serde_json::to_string(&v).ok())
            .unwrap_or(plaintext.clone()),
        MessageType::SYNC_SEARCH_APP => {
            serde_json::from_str::<crate::models::AppListRequest>(&plaintext)
                .ok()
                .and_then(|v| serde_json::to_string(&v).ok())
                .unwrap_or(plaintext.clone())
        }
        MessageType::SYNC_SEARCH_APP_RESPONSE => {
            serde_json::from_str::<crate::models::AppListResponse>(&plaintext)
                .ok()
                .and_then(|v| serde_json::to_string(&v).ok())
                .unwrap_or(plaintext.clone())
        }
        MessageType::MEDIA_SESSION_CONTROL => {
            serde_json::from_str::<crate::models::MediaControl>(&plaintext)
                .ok()
                .and_then(|v| serde_json::to_string(&v).ok())
                .unwrap_or(plaintext.clone())
        }
        MessageType::FTP => serde_json::from_str::<crate::models::FtpMessage>(&plaintext)
            .ok()
            .and_then(|v| serde_json::to_string(&v).ok())
            .unwrap_or(plaintext.clone()),
        MessageType::CLIPBOARD => serde_json::from_str::<crate::models::ClipboardData>(&plaintext)
            .ok()
            .and_then(|v| serde_json::to_string(&v).ok())
            .unwrap_or(plaintext.clone()),
        MessageType::DEVICE_STATUS => {
            serde_json::from_str::<crate::models::StatusMessage>(&plaintext)
                .ok()
                .and_then(|v| serde_json::to_string(&v).ok())
                .unwrap_or(plaintext.clone())
        }
        MessageType::RELAY_APPLICATION => {
            serde_json::from_str::<crate::models::AppLaunch>(&plaintext)
                .ok()
                .and_then(|v| serde_json::to_string(&v).ok())
                .unwrap_or(plaintext.clone())
        }
        _ => plaintext.clone(),
    };

    fire_data_cb(ctx, local_uuid, cb_type, &processed_text);
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CoreContext, MAX_PAIRING_SESSIONS};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    #[test]
    fn incomplete_pairing_sessions_remain_bounded_under_many_requests() {
        let ctx = Mutex::new(CoreContext::new());

        for index in 0..(MAX_PAIRING_SESSIONS * 4) {
            let payload = format!("peer-{index}:spake:{index}:50:desktop");
            assert_eq!(process_pairing_init(&ctx, payload.as_bytes()), 0);
            assert!(ctx.lock().unwrap().pairing_sessions.len() <= MAX_PAIRING_SESSIONS);
        }

        let guard = ctx.lock().unwrap();
        assert_eq!(guard.pairing_sessions.len(), MAX_PAIRING_SESSIONS);
        assert!(guard
            .pairing_sessions
            .contains_key(&format!("peer-{}", MAX_PAIRING_SESSIONS * 4 - 1)));
    }

    #[test]
    fn expired_pairing_sessions_are_pruned_by_new_requests() {
        let ctx = Mutex::new(CoreContext::new());
        {
            let mut guard = ctx.lock().unwrap();
            guard.pairing_session_mut("expired").expires_at =
                Instant::now() - Duration::from_secs(1);
        }

        assert_eq!(
            process_pairing_init(&ctx, b"current:spake:127.0.0.1:50:desktop"),
            0
        );

        let guard = ctx.lock().unwrap();
        assert!(!guard.pairing_sessions.contains_key("expired"));
        assert!(guard.pairing_sessions.contains_key("current"));
    }

    #[test]
    fn reject_removes_the_matching_pairing_session() {
        let ctx = Mutex::new(CoreContext::new());
        ctx.lock().unwrap().pairing_session_mut("peer");

        assert_eq!(process_reject(&ctx, b"peer"), 0);
        assert!(!ctx.lock().unwrap().pairing_sessions.contains_key("peer"));
    }
}
