use std::ffi::CString;

use base64::Engine;

use crate::{
    crypto::{aes, ecdh, hkdf, spake2},
    protocol::{binary_codec, codec, header::MessageType},
    SafeContext,
};

use super::send::do_send;

fn fire_pairing_cb(
    ctx: &mut SafeContext,
    uuid: &str,
    msg_type: &str,
    data: &str,
    int_value: i32,
    extra: &str,
) {
    let (cb, ud) = {
        let g = ctx.get_mut().unwrap();
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

fn fire_data_cb(ctx: &mut SafeContext, uuid: &str, msg_type: &str, plaintext: &str) {
    let (cb, ud) = {
        let g = ctx.get_mut().unwrap();
        (g.router.on_data, g.router.user_data)
    };
    if let Some(cb_fn) = cb {
        let uuid_c = CString::new(uuid).unwrap_or_default();
        let type_c = CString::new(msg_type).unwrap_or_default();
        let text_c = CString::new(plaintext).unwrap_or_default();
        cb_fn(uuid_c.as_ptr(), type_c.as_ptr(), text_c.as_ptr(), ud);
    }
}

/// 处理二进制帧（硬切换，不再支持文本协议）
pub(crate) fn process_frame(ctx: &mut SafeContext, msg_type: u8, payload: &[u8]) -> i32 {
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
        t if t >= 10 && t <= 200 => process_data(ctx, t, payload),
        _ => {
            log::warn!("处理消息: 未知消息类型 type={}", msg_type);
            -1
        }
    }
}

fn process_handshake(ctx: &mut SafeContext, payload: &[u8]) -> i32 {
    let hs = match binary_codec::decode_handshake_frame(payload) {
        Some(h) => h,
        None => {
            log::error!("处理消息: HANDSHAKE 解码失败");
            return -1;
        }
    };

    let uuid_str = hs.uuid.clone();
    let is_self = ctx
        .get_mut()
        .unwrap()
        .broadcast_info
        .as_ref()
        .map(|b| b.uuid == uuid_str)
        .unwrap_or(false);
    if is_self {
        return 0;
    }

    let peer_pub_str = hs.pub_key.clone();
    let already_paired = ctx
        .get_mut()
        .unwrap()
        .crypto
        .device_keys
        .contains_key(&uuid_str);

    if already_paired {
        if let Some(ref key) = {
            let guard = ctx.get_mut().unwrap();
            guard.crypto.local_key.clone()
        } {
            if let Ok(shared) = ecdh::compute_shared_secret(key, &peer_pub_str) {
                let aes_key = hkdf::derive_session_key(&shared);
                let b64 = base64::engine::general_purpose::STANDARD.encode(aes_key);
                {
                    let guard = ctx.get_mut().unwrap();
                    guard.crypto.device_keys.insert(
                        uuid_str.clone(),
                        crate::crypto::DeviceKeyEntry {
                            remote_pub_key: peer_pub_str.clone(),
                            aes_key_b64: b64,
                            aes_key_bytes: Some(aes_key),
                        },
                    );
                }
            }
        }
    }

    let ip = {
        let guard = ctx.get_mut().unwrap();
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
        "pub_key": hs.pub_key,
        "device_name": hs.device_name,
        "battery": hs.battery,
        "device_type": hs.device_type,
        "feature_flag": hs.feature_flag,
        "auto_accept": already_paired,
    })
    .to_string();

    if already_paired {
        let _ = ctx
            .get_mut()
            .unwrap()
            .discovery
            .add_known_device(&uuid_str, &ip);
        let (local_uuid, local_pub, local_battery, local_type) = {
            let guard = ctx.get_mut().unwrap();
            let bi = guard.broadcast_info.as_ref();
            (
                bi.map(|b| b.uuid.clone()).unwrap_or_default(),
                guard.crypto.local_pub_key_b64.clone().unwrap_or_default(),
                bi.map(|b| b.battery).unwrap_or(0),
                bi.map(|b| b.device_type.clone()).unwrap_or_default(),
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
            do_send(&ctx.get_mut().unwrap(), &uuid_str, &accept);
            log::info!("配对自动闭环: 已配对设备 {} 握手后自动 ACCEPT", uuid_str);
        }
    }

    fire_pairing_cb(ctx, &uuid_str, "HANDSHAKE", &data, hs.battery, &hs.pub_key);
    0
}

fn process_pairing_init(ctx: &mut SafeContext, payload: &[u8]) -> i32 {
    let text = match std::str::from_utf8(payload) {
        Ok(s) => s,
        Err(_) => {
            log::error!("处理消息: PAIRING_INIT payload 非 UTF-8");
            return -1;
        }
    };
    // 配对消息 payload 格式: uuid:spake2_pub:ip:battery:device_type
    let parts: Vec<&str> = text.split(':').collect();
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
        let guard = ctx.get_mut().unwrap();
        guard.pairing_ctx = Some(crate::PairingContext {
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

fn process_pairing_resp(ctx: &mut SafeContext, payload: &[u8]) -> i32 {
    let text = match std::str::from_utf8(payload) {
        Ok(s) => s,
        Err(_) => {
            log::error!("处理消息: PAIRING_RESP payload 非 UTF-8");
            return -1;
        }
    };
    // 配对消息 payload 格式: uuid:spake2_pub:lt_pub:ip:battery:device_type
    let parts: Vec<&str> = text.split(':').collect();
    if parts.len() < 6 {
        log::error!("处理消息: PAIRING_RESP 字段不足");
        return -1;
    }
    let uuid = parts[0];
    let spake2_pub = parts[1];
    let lt_pub = parts[2];
    let ip = parts[3];
    let battery: i32 = parts[4].trim_end_matches('+').parse().unwrap_or(0);
    let device_type = parts[5];

    let peer_spake2 = spake2_pub.to_string();
    let peer_lt = lt_pub.to_string();
    {
        let guard = ctx.get_mut().unwrap();
        guard.pairing_ctx = Some(crate::PairingContext {
            peer_uuid: uuid.to_string(),
            peer_spake2_pub: peer_spake2.clone(),
            peer_lt_pub: Some(peer_lt.clone()),
        });
    }
    let data = serde_json::json!({
        "uuid": uuid,
        "spake2_pub": spake2_pub,
        "lt_pub": lt_pub,
        "ip": ip,
        "battery": battery,
        "device_type": device_type,
    })
    .to_string();
    fire_pairing_cb(ctx, uuid, "PAIRING_RESP", &data, battery, lt_pub);
    0
}

fn process_accept(ctx: &mut SafeContext, payload: &[u8]) -> i32 {
    let uuid = match std::str::from_utf8(payload) {
        Ok(s) => s.trim(),
        Err(_) => {
            log::error!("处理消息: ACCEPT payload 非 UTF-8");
            return -1;
        }
    };
    let uuid = uuid.to_string();

    let (verifier_session, peer_spake2_pub) = {
        let guard = ctx.get_mut().unwrap();
        (
            guard.spake2_verifier.take(),
            guard
                .pairing_ctx
                .as_ref()
                .map(|c| c.peer_spake2_pub.clone()),
        )
    };

    let mut success = false;
    let mut pairing_flow = false;
    if let (Some(session), Some(spake2_pub)) = (verifier_session, peer_spake2_pub) {
        pairing_flow = true;
        match spake2::verifier_complete(session, &spake2_pub) {
            Ok(shared_secret) => {
                let aes_key = hkdf::derive_session_key(&shared_secret);
                let b64 = base64::engine::general_purpose::STANDARD.encode(aes_key);
                {
                    let guard = ctx.get_mut().unwrap();
                    guard.crypto.device_keys.insert(
                        uuid.clone(),
                        crate::crypto::DeviceKeyEntry {
                            remote_pub_key: String::new(),
                            aes_key_b64: b64,
                            aes_key_bytes: Some(aes_key),
                        },
                    );
                    guard.spake2_prover = None;
                    guard.spake2_verifier = None;
                    guard.pairing_ctx = None;
                    guard.expected_pairing_code = None;
                }
                success = true;
                let target_uuid = uuid.clone();
                {
                    let g = ctx.get_mut().unwrap();
                    g.discovery.add_known_device(&target_uuid, "");
                }
                let delay_pending = {
                    let g = ctx.get_mut().unwrap();
                    g.applist_delay_pending.clone()
                };
                if !delay_pending.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    let ctx_ptr = ctx as *mut SafeContext as usize;
                    let _ = std::thread::Builder::new()
                        .name("auto-applist".to_string())
                        .spawn(move || {
                            std::thread::sleep(std::time::Duration::from_secs(3));
                            let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
                            if let Ok(g) = ctx.get_mut() {
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
                log::error!("处理消息: SPAKE2 verifier 完成失败: {}", e);
            }
        }
    } else {
        log::warn!("处理消息: ACCEPT 时 SPAKE2 会话或参数缺失(已配对设备重连场景，跳过)");
    }

    let data = serde_json::json!({
        "uuid": uuid,
        "success": success,
    })
    .to_string();
    fire_pairing_cb(ctx, &uuid, "ACCEPT", &data, 0, "");

    if pairing_flow {
        fire_pairing_cb(ctx, &uuid, "RESULT", &serde_json::json!({"uuid": uuid, "success": success, "error": if success { "ok" } else { "spake2_failed" }}).to_string(), if success { 1 } else { 0 }, if success { "ok" } else { "spake2_failed" });
    }

    {
        let ack = codec::encode_ack(&uuid);
        let guard = ctx.get_mut().unwrap();
        do_send(guard, &uuid, &ack);
    }
    0
}

fn process_reject(ctx: &mut SafeContext, payload: &[u8]) -> i32 {
    let uuid = match std::str::from_utf8(payload) {
        Ok(s) => s.trim(),
        Err(_) => return -1,
    };
    let uuid = uuid.to_string();

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
        let guard = ctx.get_mut().unwrap();
        do_send(guard, &uuid, &ack);
    }
    0
}

fn process_heartbeat(ctx: &mut SafeContext, payload: &[u8]) -> i32 {
    let hb = match binary_codec::decode_heartbeat_frame(payload) {
        Some(h) => h,
        None => {
            log::error!("处理消息: HEARTBEAT 解码失败");
            return -1;
        }
    };

    ctx.get_mut().unwrap().heartbeat.record(&hb.uuid);
    let name_decoded = String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(&hb.name)
            .unwrap_or_default(),
    )
    .unwrap_or(hb.name.clone());

    {
        let guard = ctx.get_mut().unwrap();
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

fn process_data(ctx: &mut SafeContext, msg_type: u8, payload: &[u8]) -> i32 {
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
    let local_uuid = parts[1];
    let encrypted_payload = parts[3];

    let key_arr = {
        let guard = ctx.get_mut().unwrap();
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
    let data_header = binary_codec::type_to_data_header(msg_type);

    log::debug!(
        "处理消息: 解密 DATA header={}, uuid={}, 密文长度={}",
        data_header,
        local_uuid,
        encrypted_payload.len()
    );

    // 超级岛 / 媒体：交给状态合并引擎
    if msg_type == MessageType::MEDIA_SESSION || msg_type == MessageType::FEATURE_STATUS {
        let is_media = msg_type == MessageType::MEDIA_SESSION;
        crate::state_merge::handle_state_message(&mut *ctx, local_uuid, is_media, &plaintext);
        return 0;
    }

    let cb_type = match msg_type {
        MessageType::NOTIFICATION => "NOTIFICATION",
        MessageType::MEDIA_SESSION => "MEDIAPLAY",
        MessageType::PACKAGE_INFO => "ICON_REQUEST",
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
