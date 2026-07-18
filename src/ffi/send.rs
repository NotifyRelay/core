use std::ffi::CString;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::os::raw::c_char;
use std::os::raw::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use base64::Engine;

use crate::{crypto::aes, protocol::codec, crypto::hkdf, crypto::spake2, BroadcastHandle, BroadcastInfo, CoreContext, SafeContext};

use super::common::{encode_name_b64, from_cstr, with_ctx};

/// 通过已建立的 TCP 会话发送消息
pub(crate) fn do_send(ctx: &CoreContext, uuid: &str, line: &str) -> bool {
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
    local_ip: *const c_char,
    target_ip: *const c_char,
    battery: i32,
    device_type: *const c_char,
) -> i32 {
    let u = unsafe { from_cstr(uuid).to_string() };
    let p = unsafe { from_cstr(pub_key).to_string() };
    let li = unsafe { from_cstr(local_ip).to_string() };
    let ti = unsafe { from_cstr(target_ip).to_string() };
    let d = unsafe { from_cstr(device_type).to_string() };
    let port = crate::protocol::codec::DEFAULT_TCP_PORT;
    let msg = codec::encode_handshake(&u, &p, &li, battery, &d);

    // 尝试通过已有 TCP 会话发送
    let sent = with_ctx(ctx_ptr, |ctx| do_send(ctx, &u, &msg));
    if sent {
        return 0;
    }

    // 否则通过 oneshot 发送到 target_ip:port
    let ctx = unsafe { &mut *(ctx_ptr as *mut crate::SafeContext) };
    oneshot_send_and_process(ctx, &ti, port, &msg)
}

/// 发送配对结果回调并清理临时状态
fn fire_pairing_result(ctx: &mut SafeContext, target_uuid: &str, success: i32, error_msg: &str) {
    let (cb, ud) = match ctx.lock() {
        Ok(mut g) => {
            g.spake2_prover = None;
            g.spake2_verifier = None;
            g.pairing_ctx = None;
            g.expected_pairing_code = None;
            (g.router.on_pairing_result, g.router.user_data)
        }
        Err(_) => return,
    };
    if let Some(cb_fn) = cb {
        let uuid_c = CString::new(target_uuid).unwrap_or_default();
        let err_c = CString::new(error_msg).unwrap_or_default();
        cb_fn(uuid_c.as_ptr(), success, err_c.as_ptr(), ud);
    }
}

/// 发送 PAIRING_INIT（发起方），自动完成完整配对流程
/// 内部：SPAKE2 Prover → 发送 → 接收 PAIRING_RESP → 完成密钥协商 → 发送 ACCEPT → 等待 ACK → 回调
/// Rust 内部自动从 device_ips 映射表解析目标 IP，调用方只需传入 UUID
#[no_mangle]
pub extern "C" fn nrc_send_pairing_init(
    ctx_ptr: *mut c_void,
    local_uuid: *const c_char,
    target_uuid: *const c_char,
    expected_code: *const c_char,
    battery: i32,
    device_type: *const c_char,
) -> i32 {
    let lu = unsafe { from_cstr(local_uuid).to_string() };
    let tu = unsafe { from_cstr(target_uuid).to_string() };
    let code = unsafe { from_cstr(expected_code).to_string() };
    let dt = unsafe { from_cstr(device_type).to_string() };
    let port = crate::protocol::codec::DEFAULT_TCP_PORT;

    let local_ip = super::utils::get_local_ip_impl().unwrap_or_default();

    let ctx = unsafe { &mut *(ctx_ptr as *mut crate::SafeContext) };
    let (ctx_ref, target_ip) = match ctx.lock() {
        Ok(mut guard) => {
            guard.expected_pairing_code = Some(code.clone());
            let (session, spake2_pub) = spake2::generate_prover_session(&code);
            guard.spake2_prover = Some(session);
            let msg = codec::encode_pairing_init(&lu, &spake2_pub, &local_ip, battery, &dt);

            let target = guard.device_ips.lock()
                .ok()
                .and_then(|ips| ips.get(&tu).cloned())
                .filter(|ip| !ip.is_empty() && ip != "0.0.0.0")
                .unwrap_or_default();

            drop(guard);
            (msg, target)
        }
        Err(_) => return -1,
    };

    if target_ip.is_empty() {
        log::error!("配对发起: 无法获取目标设备IP, target_uuid={}", tu);
        fire_pairing_result(ctx, &tu, 0, "no_target_ip");
        return -1;
    }

    let addr = format!("{}:{}", target_ip, port);
    let sock_addr = match addr.parse::<std::net::SocketAddr>() {
        Ok(a) => a,
        Err(_) => {
            log::error!("配对发起: 地址解析失败 addr={}", addr);
            fire_pairing_result(ctx, &tu, 0, "address_parse_failed");
            return -1;
        }
    };
    let mut stream = match TcpStream::connect_timeout(&sock_addr, Duration::from_secs(5)) {
        Ok(s) => s,
        Err(e) => {
            log::error!("配对发起: 连接目标超时, err={}", e);
            fire_pairing_result(ctx, &tu, 0, "connection_timeout");
            return -1;
        }
    };

    stream.set_write_timeout(Some(Duration::from_secs(10))).ok();
    {
        let mut writer = &stream;
        if writer.write_all(format!("{}\n", ctx_ref).as_bytes()).is_err() {
            log::error!("配对发起: 发送 PAIRING_INIT 失败");
            fire_pairing_result(ctx, &tu, 0, "send_pairing_init_failed");
            return -1;
        }
        let _ = writer.flush();
    }

    stream.set_read_timeout(Some(Duration::from_secs(60))).ok();
    let resp = {
        let mut reader = BufReader::new(&stream);
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            log::error!("配对发起: 读取 PAIRING_RESP 失败或连接关闭");
            fire_pairing_result(ctx, &tu, 0, "pairing_resp_timeout");
            let reject_msg = codec::encode_reject(&lu);
            let _ = crate::network::oneshot_send_only(&reject_msg, &target_ip, port, 5000);
            return -1;
        }
        line.trim().to_string()
    };

    super::processing::process_line(ctx, &resp);

    let (prover_session, peer_lt_pub, peer_spake2_pub) = match ctx.lock() {
        Ok(mut g) => (
            g.spake2_prover.take(),
            g.pairing_ctx.as_ref().and_then(|c| c.peer_lt_pub.clone()),
            g.pairing_ctx.as_ref().map(|c| c.peer_spake2_pub.clone()),
        ),
        Err(_) => (None, None, None),
    };

    if let (Some(session), Some(lt_pub), Some(spake2_pub)) = (prover_session, peer_lt_pub, peer_spake2_pub) {
        match spake2::prover_complete(session, &spake2_pub) {
            Ok(shared_secret) => {
                log::info!("配对发起: SPAKE2 密钥协商成功，发送 ACCEPT");
                let aes_key = hkdf::derive_session_key(&shared_secret);
                let b64 = base64::engine::general_purpose::STANDARD.encode(aes_key);
                if let Ok(mut guard) = ctx.lock() {
                    guard.crypto.device_keys.insert(
                        tu.clone(),
                        crate::crypto::DeviceKeyEntry {
                            remote_pub_key: lt_pub.clone(),
                            aes_key_b64: b64,
                        },
                    );
                    guard.spake2_prover = None;
                    guard.spake2_verifier = None;
                    guard.pairing_ctx = None;
                    guard.expected_pairing_code = None;
                }
                let local_pub_b64 = match ctx.lock() {
                    Ok(g) => g.crypto.local_pub_key_b64.clone().unwrap_or_default(),
                    Err(_) => String::new(),
                };
                let accept_line = codec::encode_accept(&lu, &local_pub_b64, &local_ip, battery, &dt);
                let data = format!("{}\n", accept_line);
                stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
                if stream.write_all(data.as_bytes()).is_err() || stream.flush().is_err() {
                    log::warn!("配对发起: 发送 ACCEPT 失败");
                } else {
                    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
                    let mut ack_reader = BufReader::new(&stream);
                    let mut ack_line = String::new();
                    match ack_reader.read_line(&mut ack_line) {
                        Ok(n) if n > 0 => {
                            if ack_line.trim().starts_with("ACK:") {
                                log::info!("配对发起: 收到 ACK 确认: {}", ack_line.trim());
                            } else {
                                log::warn!("配对发起: 收到非 ACK 响应: {}", ack_line.trim());
                            }
                        }
                        _ => {
                            log::warn!("配对发起: 未收到 ACK 确认");
                        }
                    }
                }
                fire_pairing_result(ctx, &tu, 1, "ok");
                return 0;
            }
            Err(e) => {
                log::error!("配对发起: SPAKE2 密钥协商失败: {}", e);
                fire_pairing_result(ctx, &tu, 0, "spake2_failed");
                let reject_msg = codec::encode_reject(&lu);
                let _ = crate::network::oneshot_send_only(&reject_msg, &target_ip, port, 5000);
                return -1;
            }
        }
    }

    log::warn!("配对发起: SPAKE2 会话或参数缺失");
    let reject_msg = codec::encode_reject(&lu);
    let data = format!("{}\n", reject_msg);
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
    if stream.write_all(data.as_bytes()).is_ok() && stream.flush().is_ok() {
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let mut ack_reader = BufReader::new(&stream);
        let mut ack_line = String::new();
        ack_reader.read_line(&mut ack_line).ok();
    } else {
        let _ = crate::network::oneshot_send_only(&reject_msg, &target_ip, port, 5000);
    }
    fire_pairing_result(ctx, &tu, 0, "session_missing");
    0
}

/// 发送 PAIRING_RESP（接收方回复发起方的配对请求）
/// uuid 为接收方（本机）身份标识，用于编码到消息中
/// 会话通过 pairing_ctx.peer_uuid 查找
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
    let target_uuid = match ctx.lock() {
        Ok(guard) => match guard.pairing_ctx.as_ref() {
            Some(c) => Some(c.peer_uuid.clone()),
            None => {
                log::error!("发送 PAIRING_RESP: 无配对上下文");
                None
            }
        },
        Err(_) => {
            log::error!("发送 PAIRING_RESP: 加锁失败");
            None
        }
    };
    let target_uuid = match target_uuid {
        Some(u) => u,
        None => return -1,
    };

    let msg = match ctx.lock() {
        Ok(mut guard) => {
            let (session, spake2_pub) = spake2::generate_verifier_session(&code);
            guard.spake2_verifier = Some(session);
            let msg = codec::encode_pairing_resp(&u, &spake2_pub, &l, &i, battery, &d);
            msg
        }
        Err(_) => return -1,
    };

    with_ctx(ctx_ptr, |ctx| {
        do_send(ctx, &target_uuid, &msg);
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

/// 生成 6 位配对码，存储到 Rust 上下文中，返回码字符串。
/// ttl_secs: 配对码有效期（秒），0 表示使用默认 300 秒（5 分钟）
#[no_mangle]
pub extern "C" fn nrc_generate_pairing_code(ctx_ptr: *mut c_void, ttl_secs: u32) -> *mut c_char {
    use rand::Rng;
    let ttl = if ttl_secs == 0 { 300 } else { ttl_secs as u64 };
    let code: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Uniform::new(0u32, 10u32))
        .take(6)
        .map(|d| d.to_string())
        .collect();
    let result = super::common::to_cstr(&code);
    if !ctx_ptr.is_null() {
        let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
        if let Ok(mut guard) = ctx.lock() {
            guard.pairing_code = Some(code);
            guard.pairing_code_expiry = Some(std::time::Instant::now() + Duration::from_secs(ttl));
        }
    }
    result
}

/// 清除已存储的配对码
#[no_mangle]
pub extern "C" fn nrc_clear_pairing_code(ctx_ptr: *mut c_void) {
    if ctx_ptr.is_null() { return; }
    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
    if let Ok(mut guard) = ctx.lock() {
        guard.pairing_code = None;
        guard.pairing_code_expiry = None;
    }
}

/// 验证配对码：比对存储的配对码且检查是否过期
/// 返回 0 表示验证通过，-1 表示不匹配，-2 表示已过期
#[no_mangle]
pub extern "C" fn nrc_validate_pairing_code(ctx_ptr: *mut c_void, code: *const c_char) -> i32 {
    if ctx_ptr.is_null() || code.is_null() { return -1; }
    let input = unsafe { from_cstr(code) };
    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
    match ctx.lock() {
        Ok(guard) => {
            let stored = match &guard.pairing_code {
                Some(c) => c.clone(),
                None => return -1,
            };
            if stored != input {
                return -1;
            }
            if let Some(expiry) = guard.pairing_code_expiry {
                if std::time::Instant::now() > expiry {
                    return -2;
                }
            }
            0
        }
        Err(_) => -1,
    }
}
