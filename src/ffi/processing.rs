use std::ffi::CString;
use std::os::raw::c_char;
use std::os::raw::c_void;

use base64::Engine;

use crate::{
    crypto::{aes, ecdh, hkdf},
    protocol::{codec, header::ProtocolHeader},
    SafeContext,
};

use super::common::{from_cstr};

fn dispatch_data(cb: crate::router::OnDataCb, local_uuid: &str, plaintext: &str, ud: *mut c_void) {
    if let Some(cb) = cb {
        let uuid_c = CString::new(local_uuid).unwrap_or_default();
        let text_c = CString::new(plaintext).unwrap_or_default();
        cb(uuid_c.as_ptr(), text_c.as_ptr(), ud);
    } else {
        log::warn!("数据回调未注册: uuid={}", local_uuid);
    }
}

/// 内部消息处理函数，供 FFI 和 TCP 回调共用
pub(crate) fn process_line(ctx: &mut SafeContext, line_str: &str) -> i32 {
    if line_str.is_empty() {
        log::error!("处理消息: 空行");
        return -1;
    }
    let header = ProtocolHeader::parse(line_str);
    match header {
        ProtocolHeader::Handshake => {
            if let Some(f) = codec::decode_handshake(line_str) {
                let (cb, ud, priv_key) = {
                    let guard = match ctx.lock() { Ok(g) => g, Err(_) => return -1 };
                    (guard.router.on_handshake, guard.router.user_data, guard.crypto.local_key.clone())
                };
                let uuid_str = f.uuid.to_string();
                let peer_pub_str = f.pub_key.to_string();
                if let Some(ref key) = priv_key {
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
                if let Some(cb_fn) = cb {
                    let uuid_c = CString::new(f.uuid).unwrap_or_default();
                    let pk = CString::new(f.pub_key).unwrap_or_default();
                    let ip = CString::new(f.ip).unwrap_or_default();
                    let dt = CString::new(f.device_type).unwrap_or_default();
                    cb_fn(uuid_c.as_ptr(), pk.as_ptr(), ip.as_ptr(), f.battery, dt.as_ptr(), ud);
                } else {
                    log::warn!("处理消息: HANDSHAKE 回调未注册");
                }
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
                    peer_tmp_pub: f.tmp_pub_key.to_string(),
                    peer_lt_pub: None,
                    decrypted_code: None,
                });
                let cb = guard.router.on_pairing_init; let ud = guard.router.user_data;
                drop(guard);
                if let Some(cb) = cb {
                    let uuid = CString::new(f.uuid).unwrap_or_default();
                    let tmp = CString::new(f.tmp_pub_key).unwrap_or_default();
                    let ip = CString::new(f.ip).unwrap_or_default();
                    let dt = CString::new(f.device_type).unwrap_or_default();
                    cb(uuid.as_ptr(), tmp.as_ptr(), ip.as_ptr(), f.battery, dt.as_ptr(), ud);
                } else {
                    log::warn!("处理消息: PAIRING_INIT 回调未注册");
                }
                 0
            } else {
                log::error!("处理消息: PAIRING_INIT 解析失败");
                -1
            }
        }
        ProtocolHeader::PairingResp => {
            if let Some(f) = codec::decode_pairing_resp(line_str) {
                let (eph_key, cb, ud) = {
                    let guard = match ctx.lock() { Ok(g) => g, Err(_) => return -1 };
                    (guard.ephemeral_key.clone(), guard.router.on_pairing_resp, guard.router.user_data)
                };
                let peer_tmp = f.tmp_pub.to_string();
                let peer_lt = f.lt_pub.to_string();
                let enc_code = f.encrypted_code.to_string();
                if let Some(ref ek) = eph_key {
                    if let Ok(shared) = ecdh::compute_shared_secret(ek, &peer_tmp) {
                        let aes_key = hkdf::derive_pairing_key(&shared);
                        let decoded = aes::decrypt(&aes_key, &enc_code).ok()
                            .map(|p| String::from_utf8_lossy(&p).to_string());
                        if let Ok(mut guard) = ctx.lock() {
                            guard.pairing_key = Some(aes_key);
                            guard.pairing_ctx = Some(crate::PairingContext {
                                peer_uuid: f.uuid.to_string(),
                                peer_tmp_pub: peer_tmp.clone(),
                                peer_lt_pub: Some(peer_lt.clone()),
                                decrypted_code: decoded.clone(),
                            });
                        }
                    }
                }
                if let Some(cb_fn) = cb {
                    let uuid_c = CString::new(f.uuid).unwrap_or_default();
                    let tmp = CString::new(f.tmp_pub).unwrap_or_default();
                    let lt = CString::new(f.lt_pub).unwrap_or_default();
                    let enc = CString::new(f.encrypted_code).unwrap_or_default();
                    let ip = CString::new(f.ip).unwrap_or_default();
                    let dt = CString::new(f.device_type).unwrap_or_default();
                    cb_fn(uuid_c.as_ptr(), tmp.as_ptr(), lt.as_ptr(), enc.as_ptr(), ip.as_ptr(), f.battery, dt.as_ptr(), ud);
                } else {
                    log::warn!("处理消息: PAIRING_RESP 回调未注册");
                }
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
                let (cb, ud, priv_key, result_cb) = {
                    let guard = match ctx.lock() { Ok(g) => g, Err(_) => return -1 };
                    (guard.router.on_accept, guard.router.user_data,
                     guard.crypto.local_key.clone(), guard.router.on_pairing_result)
                };
                // 自动派生共享密钥
                if let Some(ref key) = priv_key {
                    if let Ok(shared) = ecdh::compute_shared_secret(key, &lt_pub) {
                        let aes_key = hkdf::derive_session_key(&shared);
                        let b64 = base64::engine::general_purpose::STANDARD.encode(aes_key);
                        if let Ok(mut guard) = ctx.lock() {
                            guard.crypto.device_keys.insert(
                                uuid.clone(),
                                crate::crypto::DeviceKeyEntry { remote_pub_key: lt_pub.clone(), aes_key_b64: b64 },
                            );
                        }
                        // 配对成功回调
                        if let Some(cb_r) = result_cb {
                            let uuid_c = CString::new(uuid.as_str()).unwrap_or_default();
                            let ok_c = CString::new("ok").unwrap_or_default();
                            cb_r(uuid_c.as_ptr(), 1, ok_c.as_ptr(), ud);
                        }
                    } else {
                        if let Some(cb_r) = result_cb {
                            let uuid_c = CString::new(uuid.as_str()).unwrap_or_default();
                            let err_c = CString::new("shared_secret_derivation_failed").unwrap_or_default();
                            cb_r(uuid_c.as_ptr(), 0, err_c.as_ptr(), ud);
                        }
                    }
                } else {
                    if let Some(cb_r) = result_cb {
                        let uuid_c = CString::new(uuid.as_str()).unwrap_or_default();
                        let err_c = CString::new("no_local_keypair").unwrap_or_default();
                        cb_r(uuid_c.as_ptr(), 0, err_c.as_ptr(), ud);
                    }
                }
                if let Some(cb) = cb {
                    let uuid_c = CString::new(f.uuid).unwrap_or_default();
                    let lt = CString::new(f.lt_pub_key).unwrap_or_default();
                    let ip = CString::new(f.ip).unwrap_or_default();
                    let dt = CString::new(f.device_type).unwrap_or_default();
                    cb(uuid_c.as_ptr(), lt.as_ptr(), ip.as_ptr(), f.battery, dt.as_ptr(), ud);
                } else {
                    log::warn!("处理消息: ACCEPT 回调未注册");
                }
                 0
            } else {
                log::error!("处理消息: ACCEPT 解析失败");
                -1
            }
        }
        ProtocolHeader::Reject => {
            if let Some(payload) = line_str.strip_prefix("REJECT:") {
                let (cb, ud, result_cb) = {
                    let guard = match ctx.lock() { Ok(g) => g, Err(_) => return -1 };
                    (guard.router.on_reject, guard.router.user_data, guard.router.on_pairing_result)
                };
                // 配对失败回调
                if let Some(cb_r) = result_cb {
                    let uuid_c = CString::new(payload).unwrap_or_default();
                    let err_c = CString::new("rejected").unwrap_or_default();
                    cb_r(uuid_c.as_ptr(), 0, err_c.as_ptr(), ud);
                }
                if let Some(cb) = cb {
                    let uuid_c = CString::new(payload).unwrap_or_default();
                    cb(uuid_c.as_ptr(), ud);
                } else {
                    log::warn!("处理消息: REJECT 回调未注册");
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
                let cb = guard.router.on_heartbeat_tcp; let ud = guard.router.user_data;
                drop(guard);
                if let Some(cb) = cb {
                    let uuid = CString::new(f.uuid).unwrap_or_default();
                    let name_decoded = String::from_utf8(
                        base64::engine::general_purpose::STANDARD.decode(&f.name).unwrap_or_default()
                    ).unwrap_or(f.name.to_string());
                    let name = CString::new(name_decoded).unwrap_or_default();
                    let dt = CString::new(f.device_type).unwrap_or_default();
                    let ip = CString::new("").unwrap_or_default();
                    cb(uuid.as_ptr(), name.as_ptr(), f.port, f.battery, dt.as_ptr(), ip.as_ptr(), ud);
                } else {
                    log::warn!("处理消息: HEARTBEAT_TCP 回调未注册");
                }
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
            let (cb_notif, cb_media, cb_icon_req, cb_icon_resp,
                 cb_app_req, cb_app_resp, cb_ctrl, cb_ftp,
                 cb_clip, cb_status, cb_launch, cb_super, cb_unk, ud) = {
                let r = &guard.router;
                (r.on_notification, r.on_media_play, r.on_icon_request, r.on_icon_response,
                 r.on_app_list_request, r.on_app_list_response, r.on_media_control, r.on_ftp,
                 r.on_clipboard, r.on_status, r.on_app_launch, r.on_superisland, r.on_unknown_data,
                 r.user_data)
            };
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
            match hdr {
                "DATA_NOTIFICATION" => {
                    let n = serde_json::from_str::<crate::models::Notification>(&plaintext)
                        .ok().and_then(|v| serde_json::to_string(&v).ok()).unwrap_or(plaintext.clone());
                    dispatch_data(cb_notif, uuid_s, &n, ud);
                }
                "DATA_MEDIAPLAY" | "DATA_SUPERISLAND" => {
                    let n = serde_json::from_str::<crate::models::MediaPayload>(&plaintext)
                        .ok().and_then(|v| serde_json::to_string(&v).ok()).unwrap_or(plaintext.clone());
                    let cb = if hdr == "DATA_MEDIAPLAY" { cb_media } else { cb_super };
                    dispatch_data(cb, uuid_s, &n, ud);
                }
                "DATA_ICON_REQUEST" => {
                    let n = serde_json::from_str::<crate::models::IconRequest>(&plaintext)
                        .ok().and_then(|v| serde_json::to_string(&v).ok()).unwrap_or(plaintext.clone());
                    dispatch_data(cb_icon_req, uuid_s, &n, ud);
                }
                "DATA_ICON_RESPONSE" => {
                    let n = serde_json::from_str::<crate::models::IconResponse>(&plaintext)
                        .ok().and_then(|v| serde_json::to_string(&v).ok()).unwrap_or(plaintext.clone());
                    dispatch_data(cb_icon_resp, uuid_s, &n, ud);
                }
                "DATA_APP_LIST_REQUEST" => {
                    let n = serde_json::from_str::<crate::models::AppListRequest>(&plaintext)
                        .ok().and_then(|v| serde_json::to_string(&v).ok()).unwrap_or(plaintext.clone());
                    dispatch_data(cb_app_req, uuid_s, &n, ud);
                }
                "DATA_APP_LIST_RESPONSE" => {
                    let n = serde_json::from_str::<crate::models::AppListResponse>(&plaintext)
                        .ok().and_then(|v| serde_json::to_string(&v).ok()).unwrap_or(plaintext.clone());
                    dispatch_data(cb_app_resp, uuid_s, &n, ud);
                }
                "DATA_MEDIA_CONTROL" => {
                    let n = serde_json::from_str::<crate::models::MediaControl>(&plaintext)
                        .ok().and_then(|v| serde_json::to_string(&v).ok()).unwrap_or(plaintext.clone());
                    dispatch_data(cb_ctrl, uuid_s, &n, ud);
                }
                "DATA_FTP" => {
                    let n = serde_json::from_str::<crate::models::FtpMessage>(&plaintext)
                        .ok().and_then(|v| serde_json::to_string(&v).ok()).unwrap_or(plaintext.clone());
                    dispatch_data(cb_ftp, uuid_s, &n, ud);
                }
                "DATA_CLIPBOARD" => {
                    let n = serde_json::from_str::<crate::models::ClipboardData>(&plaintext)
                        .ok().and_then(|v| serde_json::to_string(&v).ok()).unwrap_or(plaintext.clone());
                    dispatch_data(cb_clip, uuid_s, &n, ud);
                }
                "DATA_STATUS" => {
                    let n = serde_json::from_str::<crate::models::StatusMessage>(&plaintext)
                        .ok().and_then(|v| serde_json::to_string(&v).ok()).unwrap_or(plaintext.clone());
                    dispatch_data(cb_status, uuid_s, &n, ud);
                }
                "DATA_APP_LAUNCH" => {
                    let n = serde_json::from_str::<crate::models::AppLaunch>(&plaintext)
                        .ok().and_then(|v| serde_json::to_string(&v).ok()).unwrap_or(plaintext.clone());
                    dispatch_data(cb_launch, uuid_s, &n, ud);
                }
                _ => dispatch_data(cb_unk, uuid_s, &plaintext, ud),
            }
             0
        }
        _ => {
            log::warn!("处理消息: 未知消息类型");
            -1
        }
    }
}

/// FFI 入口：处理接收到的消息行
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


