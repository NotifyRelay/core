use std::ffi::CString;
use std::io::{BufReader, Write};
use std::net::TcpStream;
use std::os::raw::c_char;
use std::os::raw::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine;

use crate::{
    crypto::{aes, hkdf, spake2},
    protocol::codec,
    BroadcastHandle, BroadcastInfo, CoreContext, SafeContext,
};

use super::common::{encode_name_b64, from_cstr, with_ctx};

/// 通过已建立的 TCP 会话发送消息
pub(crate) fn do_send(ctx: &CoreContext, uuid: &str, data: &[u8]) -> bool {
    do_send_via_network(&ctx.network.tcp, uuid, data)
}

/// 仅持有 TCP 状态锁执行发送；调用方无需在网络 I/O 期间持有 CoreContext 锁。
pub(crate) fn do_send_via_network(
    network: &Arc<std::sync::Mutex<crate::network::TcpServerState>>,
    uuid: &str,
    data: &[u8],
) -> bool {
    match network.lock() {
        Ok(mut tcp) => {
            if let Some(session) = tcp.sessions.get_mut(uuid) {
                if let Err(e) = session.stream.write_all(data) {
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
fn oneshot_send_and_process(ctx: &crate::SafeContext, ip: &str, port: u16, payload: &[u8]) -> i32 {
    let resp = crate::network::oneshot_send_receive_bin(payload, ip, port, 5000);
    match resp {
        Some((msg_type, payload)) => {
            // oneshot 直连：无会话 uuid 可比对
            super::processing::process_frame(ctx, None, msg_type, &payload);
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
pub unsafe extern "C" fn nrc_send_handshake(
    ctx_ptr: *mut c_void,
    uuid: *const c_char,
    _pub_key: *const c_char,
    local_ip: *const c_char,
    target_ip: *const c_char,
    battery: i32,
    device_type: *const c_char,
) -> i32 {
    let u = unsafe { from_cstr(uuid).to_string() };
    let li = unsafe { from_cstr(local_ip).to_string() };
    let ti = unsafe { from_cstr(target_ip).to_string() };
    let d = unsafe { from_cstr(device_type).to_string() };
    let port = crate::protocol::codec::DEFAULT_TCP_PORT;
    let msg = codec::encode_handshake(&u, &li, battery, &d);

    // 尝试通过已有 TCP 会话发送
    let sent = with_ctx(ctx_ptr, |ctx| do_send(ctx, &u, &msg));
    if sent {
        return 0;
    }

    // 否则通过 oneshot 发送到 target_ip:port
    let ctx = unsafe { &*(ctx_ptr as *const crate::SafeContext) };
    oneshot_send_and_process(ctx, &ti, port, &msg)
}

/// 发送配对结果回调并清理临时状态
fn fire_pairing_result(ctx: &SafeContext, target_uuid: &str, success: i32, error_msg: &str) {
    let (cb, ud) = {
        let Ok(mut g) = ctx.lock() else {
            return;
        };
        // 只清理该对端的配对会话，不影响与其他设备的并发配对
        g.pairing_sessions.remove(target_uuid);
        (g.router.on_pairing, g.router.user_data)
    };
    if let Some(cb_fn) = cb {
        let uuid_c = CString::new(target_uuid).unwrap_or_default();
        let type_c = CString::new("RESULT").unwrap_or_default();
        let json_str =
            serde_json::json!({"uuid": target_uuid, "success": success != 0, "error": error_msg})
                .to_string();
        let data_c = CString::new(json_str).unwrap_or_default();
        let extra_c = CString::new(error_msg).unwrap_or_default();
        cb_fn(
            uuid_c.as_ptr(),
            type_c.as_ptr(),
            data_c.as_ptr(),
            success,
            extra_c.as_ptr(),
            ud,
        );
    }
}

/// 发送 PAIRING_INIT（发起方），自动完成完整配对流程
/// 内部：SPAKE2 Prover → 发送 → 接收 PAIRING_RESP → 完成密钥协商 → 发送 ACCEPT → 等待 ACK → 回调
/// Rust 内部自动从 device_ips 映射表解析目标 IP，调用方只需传入 UUID
#[no_mangle]
pub unsafe extern "C" fn nrc_send_pairing_init(
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
    let (prover, spake2_pub) = spake2::generate_prover_session(&code);
    let ctx_ref = codec::encode_pairing_init(&lu, &spake2_pub, &local_ip, battery, &dt);

    let ctx = unsafe { &*(ctx_ptr as *const crate::SafeContext) };
    let target_ip = {
        let Ok(mut guard) = ctx.lock() else {
            return -1;
        };
        // 配对会话按目标 uuid 隔离：prover 与期望配对码绑定到本次发起的对端
        let session = guard.pairing_session_mut(&tu);
        session.expected_code = Some(code.clone());
        session.prover = Some(prover);

        guard
            .device_ips
            .lock()
            .ok()
            .and_then(|ips| ips.get(&tu).cloned())
            .filter(|ip| !ip.is_empty() && ip != "0.0.0.0")
            .unwrap_or_default()
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
        if writer.write_all(&ctx_ref).is_err() {
            log::error!("配对发起: 发送 PAIRING_INIT 失败");
            fire_pairing_result(ctx, &tu, 0, "send_pairing_init_failed");
            return -1;
        }
        let _ = writer.flush();
    }

    stream.set_read_timeout(Some(Duration::from_secs(60))).ok();
    let resp = {
        let mut reader = BufReader::new(&stream);
        match crate::protocol::binary_codec::read_frame(&mut reader) {
            Ok((t, p)) => (t, p),
            Err(e) => {
                log::error!("配对发起: 读取 PAIRING_RESP 失败或连接关闭: {}", e);
                fire_pairing_result(ctx, &tu, 0, "pairing_resp_timeout");
                let reject_msg = codec::encode_reject(&lu);
                let _ = crate::network::oneshot_send_only(&reject_msg, &target_ip, port, 5000);
                return -1;
            }
        }
    };

    // 配对发起方在自己建立的连接上读取响应：无会话 uuid 可比对
    super::processing::process_frame(ctx, None, resp.0, &resp.1);

    let (ks, peer_lt_pub) = {
        let Ok(mut g) = ctx.lock() else {
            fire_pairing_result(ctx, &tu, 0, "context_lock_failed");
            return -1;
        };
        g.prune_expired_pairing_sessions();
        match g.pairing_sessions.get_mut(&tu) {
            Some(s) => (
                s.session_key.take(),
                s.pairing_ctx.as_ref().and_then(|c| c.peer_lt_pub.clone()),
            ),
            None => (None, None),
        }
    };

    if let (Some(mut aes_key), Some(lt_pub)) = (ks, peer_lt_pub) {
        log::info!("配对发起: SPAKE2 密钥协商成功，发送 ACCEPT");
        let (local_pub_b64, derived_key) = {
            let Ok(guard) = ctx.lock() else {
                crate::crypto::zeroize_key(&mut aes_key);
                fire_pairing_result(ctx, &tu, 0, "context_lock_failed");
                return -1;
            };
            (
                guard.crypto.local_pub_key_b64.clone().unwrap_or_default(),
                guard.crypto.derive_session_key(&lt_pub),
            )
        };
        // 用 K_s 加密本机 lt_pub，避免明文传输（K_s 仅用于本次公钥传输）
        let enc_lt = aes::encrypt(&aes_key, local_pub_b64.as_bytes()).unwrap_or_default();
        // 数据通道密钥由长期 ECDH 派生（与重连路径一致），K_s 不再作为会话密钥；
        // 派生失败（本机长期私钥缺失/对端公钥非法）时回落 K_s，保证两端仍对称可用
        let (b64, key_bytes) = match derived_key {
            Some(k) => (base64::engine::general_purpose::STANDARD.encode(k), Some(k)),
            None => {
                log::error!("配对发起: ECDH 派生会话密钥失败，回落使用 K_s");
                (
                    base64::engine::general_purpose::STANDARD.encode(aes_key),
                    None,
                )
            }
        };
        // K_s 使命完成，清零，避免长期驻留内存
        crate::crypto::zeroize_key(&mut aes_key);
        {
            let Ok(mut guard) = ctx.lock() else {
                fire_pairing_result(ctx, &tu, 0, "context_lock_failed");
                return -1;
            };
            guard.crypto.device_keys.insert(
                tu.clone(),
                crate::crypto::DeviceKeyEntry {
                    remote_pub_key: lt_pub.clone(),
                    aes_key_b64: b64,
                    aes_key_bytes: key_bytes,
                },
            );
            guard.pairing_sessions.remove(&tu);
        }
        let accept_line = codec::encode_accept(&lu, &enc_lt, &local_ip, battery, &dt);
        stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
        if stream.write_all(&accept_line).is_err() || stream.flush().is_err() {
            log::warn!("配对发起: 发送 ACCEPT 失败");
        } else {
            stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
            let mut ack_reader = BufReader::new(&stream);
            match crate::protocol::binary_codec::read_frame(&mut ack_reader) {
                Ok((t, _)) if t == crate::protocol::header::MessageType::ACK => {
                    log::info!("配对发起: 收到 ACK 确认");
                }
                Ok((t, _)) => {
                    log::warn!("配对发起: 收到非 ACK 响应 type={}", t);
                }
                Err(_) => {
                    log::warn!("配对发起: 未收到 ACK 确认");
                }
            }
        }
        fire_pairing_result(ctx, &tu, 1, "ok");
        return 0;
    }

    log::warn!("配对发起: SPAKE2 会话密钥或对方公钥缺失");
    let reject_msg = codec::encode_reject(&lu);
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
    if stream.write_all(&reject_msg).is_ok() && stream.flush().is_ok() {
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let mut ack_reader = BufReader::new(&stream);
        let _ = crate::protocol::binary_codec::read_frame(&mut ack_reader);
    } else {
        let _ = crate::network::oneshot_send_only(&reject_msg, &target_ip, port, 5000);
    }
    fire_pairing_result(ctx, &tu, 0, "session_missing");
    0
}

/// 解析 PAIRING_RESP 的目标对端 uuid。
///
/// 平台端传入的 `uuid` 语义不统一（Android 传对端 uuid、PC 传本机 uuid），
/// 故优先命中同名配对会话；未命中时退回唯一待处理（已收到 PAIRING_INIT）的会话。
/// 同时存在多个待处理会话时无法确定目标，返回 None 并由调用方报错。
fn resolve_pairing_resp_target(ctx: &CoreContext, uuid: &str) -> Option<String> {
    if ctx.pairing_sessions.contains_key(uuid) {
        return Some(uuid.to_string());
    }
    let mut pending: Vec<String> = ctx
        .pairing_sessions
        .iter()
        .filter(|(_, s)| s.pairing_ctx.is_some())
        .map(|(k, _)| k.clone())
        .collect();
    match pending.len() {
        1 => pending.pop(),
        0 => {
            log::error!("发送 PAIRING_RESP: 无配对上下文");
            None
        }
        n => {
            log::error!(
                "发送 PAIRING_RESP: 存在 {} 个待处理配对会话，无法确定目标",
                n
            );
            None
        }
    }
}

/// 发送 PAIRING_RESP（接收方回复发起方的配对请求）
/// uuid 为接收方（本机）身份标识，用于编码到消息中
/// 会话按目标对端 uuid 从 pairing_sessions 查找
#[no_mangle]
pub unsafe extern "C" fn nrc_send_pairing_resp(
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

    let ctx = unsafe { &*(ctx_ptr as *const crate::SafeContext) };
    let target_uuid = {
        let Ok(mut guard) = ctx.lock() else {
            return -1;
        };
        guard.prune_expired_pairing_sessions();
        resolve_pairing_resp_target(&guard, &u)
    };
    let target_uuid = match target_uuid {
        Some(u) => u,
        None => return -1,
    };

    // 响应方 IP 使用本机地址（与 nrc_send_pairing_init 对称），平台传入的 ip 仅作兜底
    let local_ip = super::utils::get_local_ip_impl().unwrap_or_else(|| i.clone());
    // 接收方在此完成 SPAKE2 verifier，得到会话密钥 K_s（与发起方对称），
    // 并用 K_s 加密本机 lt_pub，避免明文传输；K_s 暂存供后续 ACCEPT 解密复用。
    let peer_spake2_pub = {
        let Ok(mut guard) = ctx.lock() else {
            return -1;
        };
        let Some(session) = guard.pairing_sessions.get_mut(&target_uuid) else {
            return -1;
        };
        session
            .pairing_ctx
            .as_ref()
            .map(|c| c.peer_spake2_pub.clone())
            .unwrap_or_default()
    };
    let (verifier, spake2_pub) = spake2::generate_verifier_session(&code);
    let msg = match spake2::verifier_complete(verifier, &peer_spake2_pub) {
        Ok(shared) => {
            let mut ks = hkdf::derive_session_key(&shared);
            let enc_lt = aes::encrypt(&ks, l.as_bytes()).unwrap_or_default();
            let stored = match ctx.lock() {
                Ok(mut guard) => match guard.pairing_sessions.get_mut(&target_uuid) {
                    Some(session) => {
                        if let Some(mut previous) = session.session_key.replace(ks) {
                            crate::crypto::zeroize_key(&mut previous);
                        }
                        session.verifier = None;
                        session.refresh_expiry();
                        true
                    }
                    None => false,
                },
                Err(_) => false,
            };
            // session_key 中保留受控副本；清除本地 K_s 临时值。
            crate::crypto::zeroize_key(&mut ks);
            if !stored {
                return -1;
            }
            codec::encode_pairing_resp(&u, &spake2_pub, &enc_lt, &local_ip, battery, &d)
        }
        Err(e) => {
            log::error!("发送 PAIRING_RESP: SPAKE2 verifier 完成失败: {}", e);
            Vec::new()
        }
    };
    if msg.is_empty() {
        log::error!("发送 PAIRING_RESP: 密钥协商失败，放弃发送");
        return -1;
    }

    let network = match ctx.lock() {
        Ok(guard) => guard.network.tcp.clone(),
        Err(_) => return -1,
    };
    do_send_via_network(&network, &target_uuid, &msg);
    0
}

#[no_mangle]
pub unsafe extern "C" fn nrc_send_accept(
    ctx_ptr: *mut c_void,
    target_uuid: *const c_char,
    lt_pub_key: *const c_char,
    ip: *const c_char,
    battery: i32,
    device_type: *const c_char,
) {
    let t = unsafe { from_cstr(target_uuid).to_string() };
    let l = unsafe { from_cstr(lt_pub_key).to_string() };
    let i = unsafe { from_cstr(ip).to_string() };
    let d = unsafe { from_cstr(device_type).to_string() };
    with_ctx(ctx_ptr, |ctx| {
        let local_uuid = ctx
            .broadcast_info
            .as_ref()
            .map(|info| info.uuid.clone())
            .unwrap_or_default();
        if local_uuid.is_empty() {
            log::warn!("nrc_send_accept: 本机 uuid 未设置（broadcast_info 为空），跳过发送 ACCEPT");
            return;
        }
        do_send(
            ctx,
            &t,
            &codec::encode_accept(&local_uuid, &l, &i, battery, &d),
        );
    });
}

#[no_mangle]
pub unsafe extern "C" fn nrc_send_reject(ctx_ptr: *mut c_void, uuid: *const c_char) {
    let u = unsafe { from_cstr(uuid).to_string() };
    if ctx_ptr.is_null() {
        return;
    }
    let ctx = unsafe { &*(ctx_ptr as *const SafeContext) };
    let network = match ctx.lock() {
        Ok(mut guard) => {
            guard.pairing_sessions.remove(&u);
            guard.network.tcp.clone()
        }
        Err(_) => return,
    };
    do_send_via_network(&network, &u, &codec::encode_reject(&u));
}

/// UDP 广播发现周期：2秒。
///
/// 防回归说明：设备发现早期即为 UDP 广播（2s 周期）。曾因移动网络下对 /24 网段做
/// 254 个 IP 并发 TCP 全段扫描、持续抢占蜂窝空口与系统 conntrack 表项，导致同设备其他
/// 应用网络异常，才切换到 TCP 扫描；现恢复 UDP 广播。移动网络（蜂窝）下无局域网广播域，
/// UDP 广播不可达属预期行为，设备间连接仍由心跳 / known_device_scanner 等定向 TCP 通道
/// 负责，请勿为「移动网络下也能发现」改回全段 TCP 扫描（防回归）。
const BROADCAST_INTERVAL_MS: u64 = 2000;

/// 统一处理「发现到的设备」：登记注册表、记录 device_ips，并触发平台 on_device_discovered 回调。
/// UDP 广播发现路径与（保留的）TCP 发现请求应答路径共用同一消费链，保证发现结果上抛语义一致。
/// 仅在发现线程中调用，必须通过 ctx.lock() 取锁（不得用 get_mut() 绕过互斥）。
fn consume_discovered_device(
    ctx_ref: &SafeContext,
    uuid: &str,
    name_b64: &str,
    port: u16,
    battery: i32,
    device_type: &str,
    ip: &str,
) {
    let Ok(guard) = ctx_ref.lock() else {
        return;
    };
    // 跳过本机自身：UDP 广播可能回环到本机监听端口，避免自我登记为远程设备
    if guard
        .broadcast_info
        .as_ref()
        .map(|b| b.uuid == uuid)
        .unwrap_or(false)
    {
        return;
    }
    // 名称 base64 解码（与心跳路径一致），失败回退原串
    let name = String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(name_b64)
            .unwrap_or_default(),
    )
    .unwrap_or_else(|_| name_b64.to_string());
    // 设备状态统一由 core 维护：登记注册表并刷新 last_seen（在线判定唯一依据）
    guard
        .registry
        .upsert(uuid, &name, ip, port, battery, device_type);
    // 记录发现来源 IP 到内部映射：配对发起（nrc_send_pairing_init）等出站操作依赖该表解析目标 IP
    if let Ok(mut ips) = guard.device_ips.lock() {
        ips.insert(uuid.to_string(), ip.to_string());
    }
    let (cb, user_data) = (guard.router.on_device_discovered, guard.router.user_data);
    // 回调前释放锁：平台端回调内可能再次调用 core 接口（如拉取设备快照）
    drop(guard);
    if let Some(f) = cb {
        let c_uuid = CString::new(uuid).unwrap_or_default();
        let c_name = CString::new(name).unwrap_or_default();
        let c_type = CString::new(device_type).unwrap_or_default();
        let c_ip = CString::new(ip).unwrap_or_default();
        f(
            c_uuid.as_ptr(),
            c_name.as_ptr(),
            port,
            battery,
            c_type.as_ptr(),
            c_ip.as_ptr(),
            user_data,
        );
    }
}

#[no_mangle]
pub unsafe extern "C" fn nrc_periodic_broadcast(
    ctx_ptr: *mut c_void,
    action: i32,
    uuid: *const c_char,
    name: *const c_char,
    battery: i32,
    device_type: *const c_char,
) -> i32 {
    if ctx_ptr.is_null() {
        return -1;
    }
    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };

    match action {
        0 => {
            let guard = ctx.get_mut().unwrap();
            if let Some(handle) = guard.broadcast_handle.take() {
                handle.running.store(false, Ordering::Relaxed);
            }
            // 注意：不清空 broadcast_info，心跳调度器/重连/发现等组件依赖它获取本机身份
            // （锁屏切换 TCP 备用心跳时若本机信息为空，心跳调度器将停摆不工作）
            0
        }
        1 => {
            if uuid.is_null() || name.is_null() || device_type.is_null() || battery.abs() > 100 {
                return -1;
            }
            let u = unsafe { from_cstr(uuid).to_string() };
            let n_b64 = encode_name_b64(unsafe { from_cstr(name) });
            let d = unsafe { from_cstr(device_type).to_string() };

            let guard = ctx.get_mut().unwrap();
            let local_uuid = u.clone();
            guard.broadcast_info = Some(BroadcastInfo {
                uuid: u,
                name_b64: n_b64,
                battery,
                device_type: d,
            });
            // 同步广播信息到 TCP 层（供发现请求响应使用）
            crate::network::set_broadcast_info(
                guard.network.tcp.clone(),
                guard.broadcast_info.clone(),
            );
            // 同步本机 uuid 到持久化与 TCP 层状态（防御平台端 StartTcpServer 早于广播启动的情况）
            // 仅库值缺失时采用平台传入值：uuid 已由 Rust 生成持有，空值或与库值冲突时均不得覆盖库值
            if !local_uuid.is_empty() {
                guard.ensure_persistence_loaded();
                if guard.local_uuid.is_empty() {
                    guard.local_uuid = local_uuid.clone();
                    guard.mark_persistence_dirty();
                }
                guard.persistence_activated = true;
            }
            crate::network::set_local_uuid(guard.network.tcp.clone(), &local_uuid);

            if guard.broadcast_handle.is_some() {
                return 0;
            }

            let running = Arc::new(AtomicBool::new(true));
            let r = running.clone();
            let ctx_usize = ctx_ptr as usize;

            match thread::Builder::new()
                .name("periodic-discovery".to_string())
                .spawn(move || {
                    // UDP 广播发现线程：
                    // - 以 BROADCAST_INTERVAL_MS 为周期广播本机发现信息（发送 socket）；
                    // - 其余时间分片监听 UDP 广播端口，收到对端广播即解析并走统一消费链
                    //   （registry 登记 / device_ips 记录 / on_device_discovered 回调）。
                    // 移动网络（蜂窝）下无局域网广播域，广播不可达属预期，勿改回全段 TCP 扫描。
                    let sender = match crate::network::create_udp_broadcast_socket() {
                        Ok(s) => Some(s),
                        Err(e) => {
                            log::warn!("UDP 广播发现: 创建发送 socket 失败: {}", e);
                            None
                        }
                    };
                    // 监听 socket 绑定失败（如端口被其他实例占用）时不阻塞广播发送，退化为仅发送
                    let listener = match crate::network::bind_udp_discovery_listener() {
                        Ok(s) => Some(s),
                        Err(e) => {
                            log::warn!("UDP 广播发现: 绑定监听端口失败（退化为仅发送）: {}", e);
                            None
                        }
                    };
                    if sender.is_none() && listener.is_none() {
                        return;
                    }

                    // 首次进入循环即广播一次，缩短平台开启发现后的首个发现周期
                    let mut last_broadcast = Instant::now()
                        .checked_sub(Duration::from_millis(BROADCAST_INTERVAL_MS))
                        .unwrap_or_else(Instant::now);
                    let mut buf = [0u8; 2048];

                    loop {
                        if !r.load(Ordering::Relaxed) {
                            break;
                        }

                        // 1) 到点广播本机发现信息
                        if let Some(sock) = sender.as_ref() {
                            if last_broadcast.elapsed()
                                >= Duration::from_millis(BROADCAST_INTERVAL_MS)
                            {
                                let msg = {
                                    // 后台线程统一走 lock() 取锁，避免裸指针 + get_mut()
                                    // 绕过互斥导致 CoreContext 数据竞争
                                    let ctx = unsafe { &*(ctx_usize as *const SafeContext) };
                                    let Ok(guard) = ctx.lock() else {
                                        continue;
                                    };
                                    match &guard.broadcast_info {
                                        Some(i) => codec::encode_discovery_request(
                                            &i.uuid,
                                            &i.name_b64,
                                            codec::DEFAULT_TCP_PORT,
                                            i.battery,
                                            &i.device_type,
                                        ),
                                        None => String::new(),
                                    }
                                };
                                if !msg.is_empty() {
                                    if let Err(e) =
                                        crate::network::send_udp_discovery_broadcast(sock, &msg)
                                    {
                                        log::debug!("UDP 广播发现: 发送失败: {}", e);
                                    }
                                }
                                last_broadcast = Instant::now();
                            }
                        }

                        // 2) 分片监听对端广播（读超时 100ms，兼顾定时广播的及时性）
                        if let Some(sock) = listener.as_ref() {
                            match sock.recv_from(&mut buf) {
                                Ok((n, src)) => {
                                    let line = match std::str::from_utf8(&buf[..n]) {
                                        Ok(s) => s.trim().to_string(),
                                        Err(_) => continue,
                                    };
                                    if line.is_empty() {
                                        continue;
                                    }
                                    if let Some((uuid, name_b64, port, battery, device_type)) =
                                        codec::decode_discovery_request(&line)
                                    {
                                        if !uuid.is_empty() {
                                            let ctx_ref =
                                                unsafe { &*(ctx_usize as *const SafeContext) };
                                            consume_discovered_device(
                                                ctx_ref,
                                                &uuid,
                                                &name_b64,
                                                port,
                                                battery,
                                                &device_type,
                                                &src.ip().to_string(),
                                            );
                                        }
                                    }
                                }
                                Err(e)
                                    if e.kind() == std::io::ErrorKind::WouldBlock
                                        || e.kind() == std::io::ErrorKind::TimedOut
                                        || e.kind() == std::io::ErrorKind::Interrupted => {}
                                Err(e) => {
                                    log::debug!("UDP 广播发现: 接收错误: {}", e);
                                }
                            }
                        } else {
                            // 无监听 socket 时退避，避免忙等
                            thread::sleep(Duration::from_millis(100));
                        }
                    }
                }) {
                Ok(_) => {
                    guard.broadcast_handle = Some(BroadcastHandle { running });
                    0
                }
                Err(e) => {
                    log::error!("启动发现线程失败: {}", e);
                    -1
                }
            }
        }
        2 => {
            let guard = ctx.get_mut().unwrap();
            if let Some(ref mut info) = guard.broadcast_info {
                if !uuid.is_null() {
                    info.uuid = unsafe { from_cstr(uuid).to_string() };
                }
                if !name.is_null() {
                    info.name_b64 = encode_name_b64(unsafe { from_cstr(name) });
                }
                if battery >= 0 {
                    info.battery = battery;
                }
                if !device_type.is_null() {
                    info.device_type = unsafe { from_cstr(device_type).to_string() };
                }
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
    let code_clone = code.clone();
    with_ctx(ctx_ptr, |ctx| {
        ctx.pairing_code = Some(code_clone);
        ctx.pairing_code_expiry = Some(std::time::Instant::now() + Duration::from_secs(ttl));
    });
    result
}

/// 清除已存储的配对码
#[no_mangle]
pub extern "C" fn nrc_clear_pairing_code(ctx_ptr: *mut c_void) {
    with_ctx(ctx_ptr, |ctx| {
        ctx.pairing_code = None;
        ctx.pairing_code_expiry = None;
    });
}

/// 高层连接接口：对已配对设备发起 HANDSHAKE 并等待对端 ACCEPT/REJECT。
/// 内部按「最多 3 次、每次 5s 超时、间隔 1s」重试（与平台端原有握手重试策略一致），
/// 通过 oneshot 新连接同步读取响应，无需平台端维护 deferred 等待器。
/// 返回 0 表示收到 ACCEPT（连接成功），-1 表示被拒绝或重试耗尽。
#[no_mangle]
pub unsafe extern "C" fn nrc_connect_device(
    ctx_ptr: *mut c_void,
    uuid: *const c_char,
    target_ip: *const c_char,
    battery: i32,
    device_type: *const c_char,
) -> i32 {
    const MAX_RETRIES: u32 = 3;
    const TIMEOUT_MS: u32 = 5000;
    const RETRY_DELAY_MS: u64 = 1000;
    const PORT: u16 = crate::protocol::codec::DEFAULT_TCP_PORT;

    if ctx_ptr.is_null() {
        return -1;
    }
    let tu = unsafe { from_cstr(uuid).to_string() };
    let ti = unsafe { from_cstr(target_ip).to_string() };
    let dt = unsafe { from_cstr(device_type).to_string() };

    let ctx = unsafe { &mut *(ctx_ptr as *mut crate::SafeContext) };
    let (local_uuid, local_ip) = {
        let guard = ctx.get_mut().unwrap();
        (
            guard
                .broadcast_info
                .as_ref()
                .map(|b| b.uuid.clone())
                .unwrap_or_default(),
            super::utils::get_local_ip_impl().unwrap_or_default(),
        )
    };
    if local_uuid.is_empty() {
        log::error!("连接设备: 本机身份未初始化 uuid={}", tu);
        return -1;
    }

    let msg = codec::encode_handshake(&local_uuid, &local_ip, battery, &dt);

    for attempt in 0..MAX_RETRIES {
        let resp = crate::network::oneshot_send_receive_bin(&msg, &ti, PORT, TIMEOUT_MS);
        match resp {
            Some((msg_type, payload)) => {
                if msg_type == crate::protocol::header::MessageType::ACCEPT {
                    log::info!("连接设备: 握手成功 uuid={}, 第 {} 次尝试", tu, attempt + 1);
                    super::processing::process_frame(ctx, None, msg_type, &payload);
                    return 0;
                }
                if msg_type == crate::protocol::header::MessageType::REJECT {
                    log::warn!("连接设备: 对端拒绝 uuid={}", tu);
                    super::processing::process_frame(ctx, None, msg_type, &payload);
                    return -1;
                }
                log::warn!(
                    "连接设备: 收到非预期响应(type={}) uuid={}, 重试",
                    msg_type,
                    tu
                );
                super::processing::process_frame(ctx, None, msg_type, &payload);
            }
            None => {
                log::warn!(
                    "连接设备: 握手超时 uuid={}, 第 {}/{} 次",
                    tu,
                    attempt + 1,
                    MAX_RETRIES
                );
            }
        }
        if attempt + 1 < MAX_RETRIES {
            std::thread::sleep(Duration::from_millis(RETRY_DELAY_MS));
        }
    }

    log::warn!("连接设备: 重试耗尽 uuid={}", tu);
    -1
}
