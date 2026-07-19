use std::ffi::CString;
use std::os::raw::c_char;
use std::os::raw::c_void;

use base64::Engine;

use crate::{
    crypto::{aes, ecdh, hkdf, spake2},
    protocol::{codec, header::ProtocolHeader},
    SafeContext,
};

use super::common::{from_cstr};
use super::send::do_send;

fn fire_pairing_cb(ctx: &mut SafeContext, uuid: &str, msg_type: &str, data: &str, int_value: i32, extra: &str) {
    let (cb, ud) = match ctx.lock() {
        Ok(g) => (g.router.on_pairing, g.router.user_data),
        Err(_) => return,
    };
    if let Some(cb_fn) = cb {
        let uuid_c = CString::new(uuid).unwrap_or_default();
        let type_c = CString::new(msg_type).unwrap_or_default();
        let data_c = CString::new(data).unwrap_or_default();
        let extra_c = CString::new(extra).unwrap_or_default();
        cb_fn(uuid_c.as_ptr(), type_c.as_ptr(), data_c.as_ptr(), int_value, extra_c.as_ptr(), ud);
    }
}

fn fire_data_cb(ctx: &mut SafeContext, uuid: &str, msg_type: &str, plaintext: &str) {
    let (cb, ud) = match ctx.lock() {
        Ok(g) => (g.router.on_data, g.router.user_data),
        Err(_) => return,
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
                let peer_pub_str = f.pub_key.to_string();
                if let Some(ref key) = { let guard = match ctx.lock() { Ok(g) => g, Err(_) => return -1 }; guard.crypto.local_key.clone() } {
                    if let Ok(shared) = ecdh::compute_shared_secret(key, &peer_pub_str) {
                        let aes_key = hkdf::derive_session_key(&shared);
                        let b64 = base64::engine::general_purpose::STANDARD.encode(aes_key);
                        if let Ok(mut guard) = ctx.lock() {
                            guard.crypto.device_keys.insert(
                                uuid_str.clone(),
                                crate::crypto::DeviceKeyEntry { remote_pub_key: peer_pub_str.clone(), aes_key_b64: b64 },
                            );
                        }
                    }
                }
                let data = serde_json::json!({
                    "uuid": f.uuid,
                    "pub_key": f.pub_key,
                    "ip": f.ip,
                    "battery": f.battery,
                    "device_type": f.device_type,
                }).to_string();
                fire_pairing_cb(ctx, &uuid_str, "HANDSHAKE", &data, f.battery, &f.pub_key);
                 0
            } else {
                log::error!("处理消息: HANDSHAKE 解析失败");
                -1
            }
        }
        ProtocolHeader::PairingInit => {
            if let Some(f) = codec::decode_pairing_init(line_str) {
                let mut guard = match ctx.lock() { Ok(g) => g, Err(_) => return -1 };
                guard.pairing_ctx = Some(crate::PairingContext {
                    peer_uuid: f.uuid.to_string(),
                    peer_spake2_pub: f.spake2_pub.to_string(),
                    peer_lt_pub: None,
                });
                drop(guard);
                let data = serde_json::json!({
                    "uuid": f.uuid,
                    "spake2_pub": f.spake2_pub,
                    "ip": f.ip,
                    "battery": f.battery,
                    "device_type": f.device_type,
                }).to_string();
                fire_pairing_cb(ctx, &f.uuid, "PAIRING_INIT", &data, f.battery, &f.spake2_pub);
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
                if let Ok(mut guard) = ctx.lock() {
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
                }).to_string();
                fire_pairing_cb(ctx, &f.uuid, "PAIRING_RESP", &data, f.battery, &f.lt_pub);
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
                    let mut guard = match ctx.lock() { Ok(g) => g, Err(_) => return -1 };
                    (guard.spake2_verifier.take(), guard.pairing_ctx.as_ref().map(|c| c.peer_spake2_pub.clone()))
                };
                let mut success = false;
                if let (Some(session), Some(spake2_pub)) = (verifier_session, peer_spake2_pub) {
                    match spake2::verifier_complete(session, &spake2_pub) {
                        Ok(shared_secret) => {
                            let aes_key = hkdf::derive_session_key(&shared_secret);
                            let b64 = base64::engine::general_purpose::STANDARD.encode(aes_key);
                            if let Ok(mut guard) = ctx.lock() {
                                guard.crypto.device_keys.insert(
                                    uuid.clone(),
                                    crate::crypto::DeviceKeyEntry { remote_pub_key: lt_pub.clone(), aes_key_b64: b64 },
                                );
                                guard.spake2_prover = None;
                                guard.spake2_verifier = None;
                                guard.pairing_ctx = None;
                                guard.expected_pairing_code = None;
                            }
                            success = true;
                        }
                        Err(e) => {
                            log::error!("处理消息: SPAKE2 verifier 完成失败: {}", e);
                        }
                    }
                } else {
                    log::warn!("处理消息: ACCEPT 时 SPAKE2 会话或参数缺失");
                }
                let data = serde_json::json!({
                    "uuid": f.uuid,
                    "lt_pub_key": f.lt_pub_key,
                    "ip": f.ip,
                    "battery": f.battery,
                    "device_type": f.device_type,
                }).to_string();
                fire_pairing_cb(ctx, &uuid, "ACCEPT", &data, f.battery, &f.lt_pub_key);
                fire_pairing_cb(ctx, &uuid, "RESULT", &serde_json::json!({"uuid": uuid, "success": success, "error": if success { "ok" } else { "spake2_failed" }}).to_string(), if success { 1 } else { 0 }, if success { "ok" } else { "spake2_failed" });
                {
                    let ack = codec::encode_ack(&uuid);
                    match ctx.lock() {
                        Ok(ref guard) => { do_send(guard, &uuid, &ack); }
                        _ => {}
                    }
                }
                 0
            } else {
                log::error!("处理消息: ACCEPT 解析失败");
                -1
            }
        }
        ProtocolHeader::Reject => {
            if let Some(payload) = line_str.strip_prefix("REJECT:") {
                fire_pairing_cb(ctx, payload, "REJECT", &serde_json::json!({"uuid": payload}).to_string(), 0, "rejected");
                fire_pairing_cb(ctx, payload, "RESULT", &serde_json::json!({"uuid": payload, "success": false, "error": "rejected"}).to_string(), 0, "rejected");
                {
                    let ack = codec::encode_ack(payload);
                    match ctx.lock() {
                        Ok(ref guard) => { do_send(guard, payload, &ack); }
                        _ => {}
                    }
                }
                 0
            } else {
                log::error!("处理消息: REJECT 解析失败");
                -1
            }
        }
        ProtocolHeader::HeartbeatTcp => {
            if let Some(f) = codec::decode_heartbeat_tcp(line_str) {
                let mut guard = match ctx.lock() { Ok(g) => g, Err(_) => return -1 };
                guard.heartbeat.record(&f.uuid);
                let name_decoded = String::from_utf8(
                    base64::engine::general_purpose::STANDARD.decode(&f.name).unwrap_or_default()
                ).unwrap_or(f.name.to_string());
                drop(guard);
                let data = serde_json::json!({
                    "uuid": f.uuid,
                    "name": name_decoded,
                    "port": f.port,
                    "battery": f.battery,
                    "device_type": f.device_type,
                    "ip": "",
                }).to_string();
                fire_pairing_cb(ctx, &f.uuid, "HEARTBEAT_TCP", &data, f.battery, &name_decoded);
                 0
            } else {
                log::error!("处理消息: HEARTBEAT_TCP 解析失败");
                -1
            }
        }
        ProtocolHeader::Data(hdr) => {
            let fields = match codec::decode_data_message(line_str) {
                Some(f) => f, None => {
                    log::error!("处理消息: DATA 消息解析失败");
                    return -1;
                }
            };
            let guard = match ctx.lock() {
                Ok(g) => g, Err(_) => {
                    log::error!("处理消息: DATA 消息加锁失败");
                    return -1;
                }
            };
            let key_b64 = guard.crypto.device_keys.get(fields.local_uuid)
                .map(|k| k.aes_key_b64.clone());
            let _ud = guard.router.user_data;
            drop(guard);
            let key_b64 = match key_b64 {
                Some(k) => k, None => {
                    log::warn!("处理消息: 未找到密钥 uuid={}, header={}", fields.local_uuid, hdr);
                    return -1;
                }
            };
            let key_bytes = match base64::engine::general_purpose::STANDARD.decode(&key_b64) {
                Ok(b) if b.len() == 32 => b, _ => {
                    log::error!("处理消息: 密钥格式无效 uuid={}", fields.local_uuid);
                    return -1;
                }
            };
            let mut key_arr = [0u8; 32]; key_arr.copy_from_slice(&key_bytes);
            let plain = match aes::decrypt(&key_arr, fields.encrypted_payload) {
                Ok(p) => p, Err(_) => {
                    log::error!("处理消息: DATA 解密失败 header={}, uuid={}", hdr, fields.local_uuid);
                    return -1;
                }
            };
            let plaintext = String::from_utf8_lossy(&plain).to_string();
            let uuid_s = fields.local_uuid;
            log::debug!("处理消息: 解密 DATA header={}, uuid={}, 密文长度={}", hdr, uuid_s, fields.encrypted_payload.len());
            
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
                "DATA_NOTIFICATION" => serde_json::from_str::<crate::models::Notification>(&plaintext)
                    .ok().and_then(|v| serde_json::to_string(&v).ok()).unwrap_or(plaintext.clone()),
                "DATA_MEDIAPLAY" | "DATA_SUPERISLAND" => serde_json::from_str::<crate::models::MediaPayload>(&plaintext)
                    .ok().and_then(|v| serde_json::to_string(&v).ok()).unwrap_or(plaintext.clone()),
                "DATA_ICON_REQUEST" => serde_json::from_str::<crate::models::IconRequest>(&plaintext)
                    .ok().and_then(|v| serde_json::to_string(&v).ok()).unwrap_or(plaintext.clone()),
                "DATA_ICON_RESPONSE" => serde_json::from_str::<crate::models::IconResponse>(&plaintext)
                    .ok().and_then(|v| serde_json::to_string(&v).ok()).unwrap_or(plaintext.clone()),
                "DATA_APP_LIST_REQUEST" => serde_json::from_str::<crate::models::AppListRequest>(&plaintext)
                    .ok().and_then(|v| serde_json::to_string(&v).ok()).unwrap_or(plaintext.clone()),
                "DATA_APP_LIST_RESPONSE" => serde_json::from_str::<crate::models::AppListResponse>(&plaintext)
                    .ok().and_then(|v| serde_json::to_string(&v).ok()).unwrap_or(plaintext.clone()),
                "DATA_MEDIA_CONTROL" => serde_json::from_str::<crate::models::MediaControl>(&plaintext)
                    .ok().and_then(|v| serde_json::to_string(&v).ok()).unwrap_or(plaintext.clone()),
                "DATA_FTP" => serde_json::from_str::<crate::models::FtpMessage>(&plaintext)
                    .ok().and_then(|v| serde_json::to_string(&v).ok()).unwrap_or(plaintext.clone()),
                "DATA_CLIPBOARD" => serde_json::from_str::<crate::models::ClipboardData>(&plaintext)
                    .ok().and_then(|v| serde_json::to_string(&v).ok()).unwrap_or(plaintext.clone()),
                "DATA_STATUS" => serde_json::from_str::<crate::models::StatusMessage>(&plaintext)
                    .ok().and_then(|v| serde_json::to_string(&v).ok()).unwrap_or(plaintext.clone()),
                "DATA_APP_LAUNCH" => serde_json::from_str::<crate::models::AppLaunch>(&plaintext)
                    .ok().and_then(|v| serde_json::to_string(&v).ok()).unwrap_or(plaintext.clone()),
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

#[no_mangle]
pub extern "C" fn nrc_process_line(ctx_ptr: *mut c_void, line: *const c_char) -> i32 {
    if ctx_ptr.is_null() || line.is_null() {
        log::error!("处理消息: 空指针");
        return -1;
    }
    let line_str = unsafe { from_cstr(line) };
    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
    process_line(ctx, line_str)
}