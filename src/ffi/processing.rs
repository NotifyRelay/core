use std::ffi::CString;

use base64::Engine;

use crate::{
    crypto::{aes, ecdh, hkdf, spake2},
    protocol::{codec, header::ProtocolHeader},
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

pub(crate) fn process_line(ctx: &mut SafeContext, line_str: &str) -> i32 {
    if line_str.is_empty() {
        log::error!("处理消息: 空行");
        return -1;
    }
    let header = ProtocolHeader::parse(line_str);
    match header {
        ProtocolHeader::Handshake => {
            if let Some(f) = codec::decode_handshake(line_str) {
                let uuid_str = f.uuid.to_string();
                // 忽略本机发起的握手（如重连线程误连本机 IP 导致的自我握手），避免登记本机设备
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
                let peer_pub_str = f.pub_key.to_string();
                // 判定是否已配对（处理前 device_keys 是否已有该设备密钥）
                let already_paired = ctx
                    .get_mut()
                    .unwrap()
                    .crypto
                    .device_keys
                    .contains_key(&uuid_str);
                // 仅对已配对设备刷新会话密钥；未配对设备不登记密钥，
                // 避免拒绝/黑名单设备凭首次握手残留的 key 在下次握手被自动 ACCEPT，
                // 新设备密钥由 ACCEPT/SPAKE2 流程或平台侧派生建立
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
                    // 握手：登记设备身份（不刷新 last_seen），IP 优先用报文携带值
                    let ip_from_ips = guard
                        .device_ips
                        .lock()
                        .ok()
                        .and_then(|ips| ips.get(uuid_str.as_str()).cloned())
                        .unwrap_or_default();
                    let ip = if f.ip.is_empty() {
                        ip_from_ips.as_str()
                    } else {
                        f.ip
                    };
                    guard.registry.upsert_no_seen(
                        &uuid_str,
                        "",
                        ip,
                        codec::DEFAULT_TCP_PORT,
                        f.battery,
                        f.device_type,
                    );
                    ip.to_string()
                };
                let data = serde_json::json!({
                    "uuid": f.uuid,
                    "pub_key": f.pub_key,
                    "ip": f.ip,
                    "battery": f.battery,
                    "device_type": f.device_type,
                    "auto_accept": already_paired,
                })
                .to_string();
                if already_paired {
                    // 已配对设备自动闭环：登记 known_device + 自动发送 ACCEPT，平台仅做持久化/通知
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
                fire_pairing_cb(ctx, &uuid_str, "HANDSHAKE", &data, f.battery, f.pub_key);
                0
            } else {
                log::error!("处理消息: HANDSHAKE 解析失败");
                -1
            }
        }
        ProtocolHeader::PairingInit => {
            if let Some(f) = codec::decode_pairing_init(line_str) {
                {
                    let guard = ctx.get_mut().unwrap();
                    guard.pairing_ctx = Some(crate::PairingContext {
                        peer_uuid: f.uuid.to_string(),
                        peer_spake2_pub: f.spake2_pub.to_string(),
                        peer_lt_pub: None,
                    });
                }
                let data = serde_json::json!({
                    "uuid": f.uuid,
                    "spake2_pub": f.spake2_pub,
                    "ip": f.ip,
                    "battery": f.battery,
                    "device_type": f.device_type,
                })
                .to_string();
                fire_pairing_cb(ctx, f.uuid, "PAIRING_INIT", &data, f.battery, f.spake2_pub);
                0
            } else {
                log::error!("处理消息: PAIRING_INIT 解析失败");
                -1
            }
        }
        ProtocolHeader::PairingResp => {
            if let Some(f) = codec::decode_pairing_resp(line_str) {
                let peer_spake2 = f.spake2_pub.to_string();
                let peer_lt = f.lt_pub.to_string();
                {
                    let guard = ctx.get_mut().unwrap();
                    guard.pairing_ctx = Some(crate::PairingContext {
                        peer_uuid: f.uuid.to_string(),
                        peer_spake2_pub: peer_spake2.clone(),
                        peer_lt_pub: Some(peer_lt.clone()),
                    });
                }
                let data = serde_json::json!({
                    "uuid": f.uuid,
                    "spake2_pub": f.spake2_pub,
                    "lt_pub": f.lt_pub,
                    "ip": f.ip,
                    "battery": f.battery,
                    "device_type": f.device_type,
                })
                .to_string();
                fire_pairing_cb(ctx, f.uuid, "PAIRING_RESP", &data, f.battery, f.lt_pub);
                0
            } else {
                log::error!("处理消息: PAIRING_RESP 解析失败");
                -1
            }
        }
        ProtocolHeader::Accept => {
            if let Some(f) = codec::decode_accept(line_str) {
                let uuid = f.uuid.to_string();
                let lt_pub = f.lt_pub_key.to_string();
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
                                        remote_pub_key: lt_pub.clone(),
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
                            // 配对成功自动闭环：登记 known_device + 记录对端 IP
                            let peer_ip = f.ip.to_string();
                            let target_uuid = uuid.clone();
                            {
                                let g = ctx.get_mut().unwrap();
                                g.discovery.add_known_device(&target_uuid, &peer_ip);
                                if !peer_ip.is_empty() {
                                    if let Ok(mut ips) = g.device_ips.lock() {
                                        ips.insert(target_uuid.clone(), peer_ip);
                                    }
                                }
                            }
                            // 自动延迟 3s 发送应用列表请求（下沉自平台 DelayedRequestAppList）
                            // 互斥标志防止短时间多次配对时线程堆叠
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
                                                    crate::app_sync::build_applist_request(
                                                        "user", now,
                                                    );
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
                                        delay_pending
                                            .store(false, std::sync::atomic::Ordering::SeqCst);
                                    });
                            }
                        }
                        Err(e) => {
                            log::error!("处理消息: SPAKE2 verifier 完成失败: {}", e);
                        }
                    }
                } else {
                    log::warn!(
                        "处理消息: ACCEPT 时 SPAKE2 会话或参数缺失(已配对设备重连场景，跳过)"
                    );
                }
                let data = serde_json::json!({
                    "uuid": f.uuid,
                    "lt_pub_key": f.lt_pub_key,
                    "ip": f.ip,
                    "battery": f.battery,
                    "device_type": f.device_type,
                })
                .to_string();
                fire_pairing_cb(ctx, &uuid, "ACCEPT", &data, f.battery, f.lt_pub_key);
                // 仅配对流程发送 RESULT 结果；已配对设备重连的 ACCEPT 由 ACCEPT 回调处理，
                // 不再误报 success=false（避免平台侧将成功的重连判为配对失败）
                if pairing_flow {
                    fire_pairing_cb(ctx, &uuid, "RESULT", &serde_json::json!({"uuid": uuid, "success": success, "error": if success { "ok" } else { "spake2_failed" }}).to_string(), if success { 1 } else { 0 }, if success { "ok" } else { "spake2_failed" });
                }
                {
                    let ack = codec::encode_ack(&uuid);
                    let guard = ctx.get_mut().unwrap();
                    do_send(guard, &uuid, &ack);
                }
                0
            } else {
                log::error!("处理消息: ACCEPT 解析失败");
                -1
            }
        }
        ProtocolHeader::Reject => {
            if let Some(payload) = line_str.strip_prefix("REJECT:") {
                fire_pairing_cb(
                    ctx,
                    payload,
                    "REJECT",
                    &serde_json::json!({"uuid": payload}).to_string(),
                    0,
                    "rejected",
                );
                fire_pairing_cb(
                    ctx,
                    payload,
                    "RESULT",
                    &serde_json::json!({"uuid": payload, "success": false, "error": "rejected"})
                        .to_string(),
                    0,
                    "rejected",
                );
                {
                    let ack = codec::encode_ack(payload);
                    let guard = ctx.get_mut().unwrap();
                    do_send(guard, payload, &ack);
                }
                0
            } else {
                log::error!("处理消息: REJECT 解析失败");
                -1
            }
        }
        ProtocolHeader::HeartbeatTcp => {
            if let Some(f) = codec::decode_heartbeat_tcp(line_str) {
                ctx.get_mut().unwrap().heartbeat.record(f.uuid);
                let name_decoded = String::from_utf8(
                    base64::engine::general_purpose::STANDARD
                        .decode(f.name)
                        .unwrap_or_default(),
                )
                .unwrap_or(f.name.to_string());
                {
                    let guard = ctx.get_mut().unwrap();
                    // IP 从 device_ips 取（TCP 连接来源 IP）
                    let ip = guard
                        .device_ips
                        .lock()
                        .ok()
                        .and_then(|ips| ips.get(f.uuid).cloned())
                        .unwrap_or_default();
                    guard.registry.upsert(
                        f.uuid,
                        &name_decoded,
                        &ip,
                        f.port,
                        f.battery,
                        f.device_type,
                    );
                }
                let data = serde_json::json!({
                    "uuid": f.uuid,
                    "name": name_decoded,
                    "port": f.port,
                    "battery": f.battery,
                    "device_type": f.device_type,
                    "ip": "",
                })
                .to_string();
                fire_pairing_cb(
                    ctx,
                    f.uuid,
                    "HEARTBEAT_TCP",
                    &data,
                    f.battery,
                    &name_decoded,
                );
                0
            } else {
                log::error!("处理消息: HEARTBEAT_TCP 解析失败");
                -1
            }
        }
        ProtocolHeader::Data(hdr) => {
            let fields = match codec::decode_data_message(line_str) {
                Some(f) => f,
                None => {
                    log::error!("处理消息: DATA 消息解析失败");
                    return -1;
                }
            };
            let key_arr = {
                let guard = ctx.get_mut().unwrap();
                let key = guard.crypto.get_aes_key(fields.local_uuid);
                let _ud = guard.router.user_data;
                key
            };
            let key_arr = match key_arr {
                Some(k) => k,
                None => {
                    log::warn!(
                        "处理消息: 未找到密钥或密钥无效 uuid={}, header={}",
                        fields.local_uuid,
                        hdr
                    );
                    return -1;
                }
            };
            let plain = match aes::decrypt(&key_arr, fields.encrypted_payload) {
                Ok(p) => p,
                Err(_) => {
                    log::error!(
                        "处理消息: DATA 解密失败 header={}, uuid={}",
                        hdr,
                        fields.local_uuid
                    );
                    return -1;
                }
            };
            let plaintext = String::from_utf8_lossy(&plain).to_string();
            let uuid_s = fields.local_uuid;
            log::debug!(
                "处理消息: 解密 DATA header={}, uuid={}, 密文长度={}",
                hdr,
                uuid_s,
                fields.encrypted_payload.len()
            );

            // 超级岛 / 媒体：交给状态合并引擎，Rust 内部合并为全量后通过全量回调交给平台。
            // 平台永远只见到全键值状态，差异合并仅在 Rust 内闭环。
            if hdr == "DATA_MEDIAPLAY" || hdr == "DATA_SUPERISLAND" {
                let is_media = hdr == "DATA_MEDIAPLAY";
                crate::state_merge::handle_state_message(&mut *ctx, uuid_s, is_media, &plaintext);
                return 0;
            }

            let msg_type = match hdr {
                "DATA_NOTIFICATION" => "NOTIFICATION",
                "DATA_MEDIAPLAY" => "MEDIAPLAY",
                "DATA_ICON_REQUEST" => "ICON_REQUEST",
                "DATA_ICON_RESPONSE" => "ICON_RESPONSE",
                "DATA_APP_LIST_REQUEST" => "APP_LIST_REQUEST",
                "DATA_APP_LIST_RESPONSE" => "APP_LIST_RESPONSE",
                "DATA_MEDIA_CONTROL" => "MEDIA_CONTROL",
                "DATA_FTP" => "FTP",
                "DATA_CLIPBOARD" => "CLIPBOARD",
                "DATA_STATUS" => "STATUS",
                "DATA_APP_LAUNCH" => "APP_LAUNCH",
                "DATA_SUPERISLAND" => "SUPERISLAND",
                _ => "UNKNOWN",
            };

            let processed_text = match hdr {
                "DATA_NOTIFICATION" => {
                    serde_json::from_str::<crate::models::Notification>(&plaintext)
                        .ok()
                        .and_then(|v| serde_json::to_string(&v).ok())
                        .unwrap_or(plaintext.clone())
                }
                "DATA_MEDIAPLAY" | "DATA_SUPERISLAND" => {
                    serde_json::from_str::<crate::models::MediaPayload>(&plaintext)
                        .ok()
                        .and_then(|v| serde_json::to_string(&v).ok())
                        .unwrap_or(plaintext.clone())
                }
                "DATA_ICON_REQUEST" => {
                    serde_json::from_str::<crate::models::IconRequest>(&plaintext)
                        .ok()
                        .and_then(|v| serde_json::to_string(&v).ok())
                        .unwrap_or(plaintext.clone())
                }
                "DATA_ICON_RESPONSE" => {
                    serde_json::from_str::<crate::models::IconResponse>(&plaintext)
                        .ok()
                        .and_then(|v| serde_json::to_string(&v).ok())
                        .unwrap_or(plaintext.clone())
                }
                "DATA_APP_LIST_REQUEST" => {
                    serde_json::from_str::<crate::models::AppListRequest>(&plaintext)
                        .ok()
                        .and_then(|v| serde_json::to_string(&v).ok())
                        .unwrap_or(plaintext.clone())
                }
                "DATA_APP_LIST_RESPONSE" => {
                    serde_json::from_str::<crate::models::AppListResponse>(&plaintext)
                        .ok()
                        .and_then(|v| serde_json::to_string(&v).ok())
                        .unwrap_or(plaintext.clone())
                }
                "DATA_MEDIA_CONTROL" => {
                    serde_json::from_str::<crate::models::MediaControl>(&plaintext)
                        .ok()
                        .and_then(|v| serde_json::to_string(&v).ok())
                        .unwrap_or(plaintext.clone())
                }
                "DATA_FTP" => serde_json::from_str::<crate::models::FtpMessage>(&plaintext)
                    .ok()
                    .and_then(|v| serde_json::to_string(&v).ok())
                    .unwrap_or(plaintext.clone()),
                "DATA_CLIPBOARD" => {
                    serde_json::from_str::<crate::models::ClipboardData>(&plaintext)
                        .ok()
                        .and_then(|v| serde_json::to_string(&v).ok())
                        .unwrap_or(plaintext.clone())
                }
                "DATA_STATUS" => serde_json::from_str::<crate::models::StatusMessage>(&plaintext)
                    .ok()
                    .and_then(|v| serde_json::to_string(&v).ok())
                    .unwrap_or(plaintext.clone()),
                "DATA_APP_LAUNCH" => serde_json::from_str::<crate::models::AppLaunch>(&plaintext)
                    .ok()
                    .and_then(|v| serde_json::to_string(&v).ok())
                    .unwrap_or(plaintext.clone()),
                _ => plaintext.clone(),
            };

            fire_data_cb(ctx, uuid_s, msg_type, &processed_text);
            0
        }
        ProtocolHeader::Ack => {
            log::debug!("处理消息: 收到 ACK");
            0
        }
        _ => {
            log::warn!("处理消息: 未知消息类型");
            -1
        }
    }
}
