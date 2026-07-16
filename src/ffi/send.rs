use std::ffi::CString;
use std::io::Write;
use std::os::raw::c_char;
use std::os::raw::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use base64::Engine;

use crate::{crypto::aes, protocol::codec, crypto::ecdh, crypto::hkdf, BroadcastHandle, BroadcastInfo, CoreContext, SafeContext};

use super::common::{encode_name_b64, from_cstr, with_ctx};

/// 通过已建立的 TCP 会话发送消息
fn do_send(ctx: &CoreContext, uuid: &str, line: &str) -> bool {
    let data = format!("{}\n", line);
    match ctx.network.tcp.lock() {
        Ok(mut tcp) => {
            if let Some(session) = tcp.sessions.get_mut(uuid) {
                if let Err(e) = session.stream.write_all(data.as_bytes()) {
                    log::error!("发送消息失败 uuid={}, error={}", uuid, e);
                    false
                } else {
                    true
                }
            } else {
                log::warn!("设备未连接 uuid={}", uuid);
                false
            }
        }
        Err(e) => {
            log::error!("加锁失败: {}", e);
            false
        }
    }
}

/// 通过 Oneshot TCP 发送，并处理响应
fn oneshot_send_and_process(
    ctx: &mut crate::SafeContext,
    ip: &str,
    port: u16,
    payload: &str,
) -> i32 {
    let resp = crate::network::oneshot_send_receive(payload, ip, port, 5000);
    match resp {
        Some(line) => {
            super::processing::process_line(ctx, &line);
            0
        }
        None => {
            log::error!("oneshot 发送/接收失败 ip={}, port={}", ip, port);
            -1
        }
    }
}

/// 发送 HANDSHAKE 并通过 oneshot 处理 ACCEPT 响应
#[no_mangle]
pub extern "C" fn nrc_send_handshake(
    ctx_ptr: *mut c_void,
    uuid: *const c_char,
    pub_key: *const c_char,
    ip: *const c_char,
    battery: i32,
    device_type: *const c_char,
) -> i32 {
    let u = unsafe { from_cstr(uuid).to_string() };
    let p = unsafe { from_cstr(pub_key).to_string() };
    let i = unsafe { from_cstr(ip).to_string() };
    let d = unsafe { from_cstr(device_type).to_string() };
    let port = crate::protocol::codec::DEFAULT_TCP_PORT;
    let msg = codec::encode_handshake(&u, &p, &i, battery, &d);

    // 尝试通过已有 TCP 会话发送
    let sent = with_ctx(ctx_ptr, |ctx| do_send(ctx, &u, &msg));
    if sent {
        return 0;
    }

    // 否则通过 oneshot 发送到 ip:port
    let ctx = unsafe { &mut *(ctx_ptr as *mut crate::SafeContext) };
    oneshot_send_and_process(ctx, &i, port, &msg)
}

/// 发送 PAIRING_INIT（发起方），自动完成完整配对流程
/// 内部：生成临时密钥 → 发送 → 接收 PAIRING_RESP → 验证配对码 → 发送 ACCEPT/REJECT
#[no_mangle]
pub extern "C" fn nrc_send_pairing_init(
    ctx_ptr: *mut c_void,
    uuid: *const c_char,
    expected_code: *const c_char,
    ip: *const c_char,
    battery: i32,
    device_type: *const c_char,
) -> i32 {
    let u = unsafe { from_cstr(uuid).to_string() };
    let code = unsafe { from_cstr(expected_code).to_string() };
    let i = unsafe { from_cstr(ip).to_string() };
    let d = unsafe { from_cstr(device_type).to_string() };
    let port = crate::protocol::codec::DEFAULT_TCP_PORT;

    let ctx = unsafe { &mut *(ctx_ptr as *mut crate::SafeContext) };
    let ctx_ref = match ctx.lock() {
        Ok(mut guard) => {
            guard.expected_pairing_code = Some(code.clone());
            // 生成临时密钥
            let (secret, b64) = ecdh::generate_keypair();
            guard.ephemeral_key = Some(secret);
            guard.ephemeral_pub_b64 = Some(b64.clone());
            let msg = codec::encode_pairing_init(&u, &b64, &i, battery, &d);
            drop(guard);
            msg
        }
        Err(_) => return -1,
    };

    // oneshot 发送 PAIRING_INIT 并接收 PAIRING_RESP
    let resp = crate::network::oneshot_send_receive(&ctx_ref, &i, port, 5000);
    let resp = match resp {
        Some(r) => r,
        None => {
            log::error!("配对发起: 未收到响应");
            return -1;
        }
    };

    // 处理 PAIRING_RESP（process_line 内部会解密配对码）
    super::processing::process_line(ctx, &resp);

    // 检查配对结果
    let (decrypted, _eph_key, local_key) = match ctx.lock() {
        Ok(g) => (
            g.pairing_ctx.as_ref().and_then(|c| c.decrypted_code.clone()),
            g.ephemeral_key.clone(),
            g.crypto.local_key.clone(),
        ),
        Err(_) => (None, None, None),
    };

    if let Some(ref decrypted_code) = decrypted {
        if decrypted_code == &code {
            log::info!("配对发起: 配对码验证成功，发送 ACCEPT");
            // 获取 peer_lt_pub 用于派生长期密钥
            let (peer_lt_pub, local_pub_b64) = match ctx.lock() {
                Ok(g) => (
                    g.pairing_ctx.as_ref().and_then(|c| c.peer_lt_pub.clone()),
                    g.crypto.local_pub_key_b64.clone().unwrap_or_default(),
                ),
                Err(_) => (None, String::new()),
            };
            // 派生长期共享密钥
            if let (Some(ref lt_pub), ref lk) = (&peer_lt_pub, &local_key) {
                if let Some(ref lk) = lk {
                    if let Ok(shared) = ecdh::compute_shared_secret(lk, lt_pub) {
                        let aes_key = hkdf::derive_session_key(&shared);
                        let b64 = base64::engine::general_purpose::STANDARD.encode(aes_key);
                        if let Ok(mut guard) = ctx.lock() {
                            guard.crypto.device_keys.insert(
                                u.clone(),
                                crate::crypto::DeviceKeyEntry {
                                    remote_pub_key: lt_pub.clone(),
                                    aes_key_b64: b64,
                                },
                            );
                        }
                    }
                }
            }
            // 清理配对状态
            if let Ok(mut guard) = ctx.lock() {
                guard.ephemeral_key = None;
                guard.ephemeral_pub_b64 = None;
                guard.pairing_ctx = None;
                guard.expected_pairing_code = None;
            }
            // 通过 oneshot 发送 ACCEPT（不等待响应）
            let accept_line = codec::encode_accept(&u, &local_pub_b64, &i, battery, &d);
            crate::network::oneshot_send_only(&accept_line, &i, port, 5000);
            // 配对成功回调
            let (cb, ud) = match ctx.lock() {
                Ok(g) => (g.router.on_pairing_result, g.router.user_data),
                Err(_) => (None, std::ptr::null_mut()),
            };
            if let Some(cb_fn) = cb {
                let uuid_c = CString::new(u.clone()).unwrap_or_default();
                let ok_c = CString::new("ok").unwrap_or_default();
                cb_fn(uuid_c.as_ptr(), 1, ok_c.as_ptr(), ud);
            }
            return 0;
        }
    }

    // 配对失败
    log::warn!("配对发起: 配对码验证失败");
    let (cb, ud) = match ctx.lock() {
        Ok(mut g) => {
            g.ephemeral_key = None;
            g.ephemeral_pub_b64 = None;
            g.pairing_ctx = None;
            g.expected_pairing_code = None;
            (g.router.on_pairing_result, g.router.user_data)
        }
        Err(_) => (None, std::ptr::null_mut()),
    };
    // 发送 REJECT
    let reject_msg = codec::encode_reject(&u);
    let _ = crate::network::oneshot_send_only(&reject_msg, &i, port, 5000);
    if let Some(cb_fn) = cb {
        let uuid_c = CString::new(u).unwrap_or_default();
        let err_c = CString::new("code_mismatch").unwrap_or_default();
        cb_fn(uuid_c.as_ptr(), 0, err_c.as_ptr(), ud);
    }
    0
}

/// 发送 PAIRING_RESP（接收方回复发起方的配对请求）
/// 通过已有 TCP 会话发送
#[no_mangle]
pub extern "C" fn nrc_send_pairing_resp(
    ctx_ptr: *mut c_void,
    uuid: *const c_char,
    lt_pub: *const c_char,
    pairing_code: *const c_char,
    ip: *const c_char,
    battery: i32,
    device_type: *const c_char,
) -> i32 {
    let u = unsafe { from_cstr(uuid).to_string() };
    let l = unsafe { from_cstr(lt_pub).to_string() };
    let code = unsafe { from_cstr(pairing_code).to_string() };
    let i = unsafe { from_cstr(ip).to_string() };
    let d = unsafe { from_cstr(device_type).to_string() };

    let ctx = unsafe { &mut *(ctx_ptr as *mut crate::SafeContext) };
    let msg = match ctx.lock() {
        Ok(mut guard) => {
            // 确保有临时密钥
            if guard.ephemeral_key.is_none() {
                let (secret, b64) = ecdh::generate_keypair();
                guard.ephemeral_key = Some(secret);
                guard.ephemeral_pub_b64 = Some(b64);
            }
            let tmp_pub = guard.ephemeral_pub_b64.clone().unwrap_or_default();
            // 派生配对密钥
            if let Some(ref eph_key) = guard.ephemeral_key.clone() {
                if let Some(ref peer_tmp) = guard.pairing_ctx.as_ref().map(|c| c.peer_tmp_pub.clone()) {
                    if let Ok(shared) = ecdh::compute_shared_secret(eph_key, peer_tmp) {
                        let aes_key = hkdf::derive_pairing_key(&shared);
                        guard.pairing_key = Some(aes_key);
                    }
                }
            }
            // 加密配对码
            let encrypted = guard.pairing_key
                .and_then(|key| aes::encrypt(&key, code.as_bytes()).ok())
                .unwrap_or_default();
            let msg = codec::encode_pairing_resp(&u, &tmp_pub, &l, &encrypted, &i, battery, &d);
            msg
        }
        Err(_) => return -1,
    };

    // 通过 TCP 会话发送
    with_ctx(ctx_ptr, |ctx| {
        do_send(ctx, &u, &msg);
    });
    0
}

#[no_mangle]
pub extern "C" fn nrc_send_accept(
    ctx_ptr: *mut c_void,
    uuid: *const c_char,
    lt_pub_key: *const c_char,
    ip: *const c_char,
    battery: i32,
    device_type: *const c_char,
) {
    let u = unsafe { from_cstr(uuid).to_string() };
    let l = unsafe { from_cstr(lt_pub_key).to_string() };
    let i = unsafe { from_cstr(ip).to_string() };
    let d = unsafe { from_cstr(device_type).to_string() };
    with_ctx(ctx_ptr, |ctx| {
        do_send(ctx, &u, &codec::encode_accept(&u, &l, &i, battery, &d));
    });
}

#[no_mangle]
pub extern "C" fn nrc_send_reject(ctx_ptr: *mut c_void, uuid: *const c_char) {
    let u = unsafe { from_cstr(uuid).to_string() };
    with_ctx(ctx_ptr, |ctx| {
        do_send(ctx, &u, &codec::encode_reject(&u));
    });
}

#[no_mangle]
pub extern "C" fn nrc_send_heartbeat_tcp(
    ctx_ptr: *mut c_void,
    uuid: *const c_char,
    name: *const c_char,
    port: u16,
    battery: i32,
    device_type: *const c_char,
) {
    let u = unsafe { from_cstr(uuid).to_string() };
    let n_b64 = encode_name_b64(unsafe { from_cstr(name) });
    let d = unsafe { from_cstr(device_type).to_string() };
    with_ctx(ctx_ptr, |ctx| {
        do_send(ctx, &u, &codec::encode_heartbeat_tcp(&u, &n_b64, port, battery, &d));
    });
}

#[no_mangle]
pub extern "C" fn nrc_send_heartbeat_udp(
    _ctx_ptr: *mut c_void,
    uuid: *const c_char,
    name: *const c_char,
    port: u16,
    battery: i32,
    device_type: *const c_char,
) {
    let u = unsafe { from_cstr(uuid).to_string() };
    let n_b64 = encode_name_b64(unsafe { from_cstr(name) });
    let d = unsafe { from_cstr(device_type).to_string() };
    crate::network::send_udp_broadcast(&codec::encode_udp_broadcast(&u, &n_b64, port, battery, &d)).ok();
}

#[no_mangle]
pub extern "C" fn nrc_send_discovery(
    _ctx_ptr: *mut c_void,
    uuid: *const c_char,
    name: *const c_char,
    port: u16,
    battery: i32,
    device_type: *const c_char,
) {
    let u = unsafe { from_cstr(uuid).to_string() };
    let n_b64 = encode_name_b64(unsafe { from_cstr(name) });
    let d = unsafe { from_cstr(device_type).to_string() };
    crate::network::send_udp_broadcast(&codec::encode_udp_broadcast(&u, &n_b64, port, battery, &d)).ok();
}

#[no_mangle]
pub extern "C" fn nrc_send_data_message(
    ctx_ptr: *mut c_void,
    header: *const c_char,
    local_uuid: *const c_char,
    local_pub_key: *const c_char,
    remote_uuid: *const c_char,
    plaintext: *const c_char,
) {
    let hdr = unsafe { from_cstr(header).to_string() };
    let uuid = unsafe { from_cstr(local_uuid).to_string() };
    let pub_key = unsafe { from_cstr(local_pub_key).to_string() };
    let remote = unsafe { from_cstr(remote_uuid).to_string() };
    let text = unsafe { from_cstr(plaintext).to_string() };
    with_ctx(ctx_ptr, |ctx| {
        let key_b64 = match ctx.crypto.device_keys.get(&remote) {
            Some(k) => k.aes_key_b64.clone(), None => return,
        };
        let key_bytes = match base64::engine::general_purpose::STANDARD.decode(&key_b64) {
            Ok(b) if b.len() == 32 => b, _ => return,
        };
        let mut key_arr = [0u8; 32]; key_arr.copy_from_slice(&key_bytes);
        if let Ok(encrypted) = aes::encrypt(&key_arr, text.as_bytes()) {
            let msg = codec::encode_data_message(&hdr, &uuid, &pub_key, &encrypted);
            do_send(ctx, &uuid, &msg);
        }
    });
}

const BROADCAST_INTERVAL_MS: u64 = 2000;

#[no_mangle]
pub extern "C" fn nrc_periodic_broadcast(
    ctx_ptr: *mut c_void,
    action: i32,
    uuid: *const c_char,
    name: *const c_char,
    battery: i32,
    device_type: *const c_char,
) -> i32 {
    if ctx_ptr.is_null() { return -1; }
    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };

    match action {
        0 => {
            let mut guard = match ctx.lock() { Ok(g) => g, Err(_) => return -1 };
            if let Some(handle) = guard.broadcast_handle.take() {
                handle.running.store(false, Ordering::Relaxed);
            }
            guard.broadcast_info = None;
            0
        }
        1 => {
            if uuid.is_null() || name.is_null() || device_type.is_null() || battery < 0 {
                return -1;
            }
            let u = unsafe { from_cstr(uuid).to_string() };
            let n_b64 = encode_name_b64(unsafe { from_cstr(name) });
            let d = unsafe { from_cstr(device_type).to_string() };

            let mut guard = match ctx.lock() { Ok(g) => g, Err(_) => return -1 };
            guard.broadcast_info = Some(BroadcastInfo {
                uuid: u,
                name_b64: n_b64,
                battery,
                device_type: d,
            });

            if guard.broadcast_handle.is_some() {
                return 0;
            }

            let running = Arc::new(AtomicBool::new(true));
            let r = running.clone();
            let ctx_usize = ctx_ptr as usize;

            match thread::Builder::new()
                .name("periodic-broadcast".to_string())
                .spawn(move || {
                    loop {
                        if !r.load(Ordering::Relaxed) { break; }

                        let msg = {
                            let ctx = unsafe { &mut *(ctx_usize as *mut SafeContext) };
                            let guard = match ctx.lock() { Ok(g) => g, Err(_) => break };
                            match &guard.broadcast_info {
                                Some(i) => codec::encode_udp_broadcast(
                                    &i.uuid, &i.name_b64, codec::DEFAULT_TCP_PORT, i.battery, &i.device_type,
                                ),
                                None => {
                                    drop(guard);
                                    thread::sleep(Duration::from_millis(500));
                                    continue;
                                }
                            }
                        };

                        let _ = crate::network::send_udp_broadcast(&msg);
                        thread::sleep(Duration::from_millis(BROADCAST_INTERVAL_MS));
                    }
                }) {
                Ok(_) => {
                    guard.broadcast_handle = Some(BroadcastHandle { running });
                    0
                }
                Err(e) => {
                    log::error!("启动广播线程失败: {}", e);
                    -1
                }
            }
        }
        2 => {
            let mut guard = match ctx.lock() { Ok(g) => g, Err(_) => return -1 };
            if let Some(ref mut info) = guard.broadcast_info {
                if !uuid.is_null() { info.uuid = unsafe { from_cstr(uuid).to_string() }; }
                if !name.is_null() { info.name_b64 = encode_name_b64(unsafe { from_cstr(name) }); }
                if battery >= 0 { info.battery = battery; }
                if !device_type.is_null() { info.device_type = unsafe { from_cstr(device_type).to_string() }; }
            }
            0
        }
        _ => -1,
    }
}
