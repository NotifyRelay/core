//! 发链路：握手、配对、ACCEPT/REJECT、广播发现、配对码与主动连接。
//!
//! 全部为领域实现，入参/出参均为 Rust 类型；C ABI 与 UniFFI 的适配分别由
//! `ffi::send` 与 `api` 完成。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;

use crate::utils::encode_name_b64;
use crate::{
    crypto::{aes, hkdf, spake2},
    protocol::{codec, header::MessageType},
    quic, BroadcastHandle, BroadcastInfo, CoreContext, SafeContext,
};

/// 取传输层句柄。
///
/// 传输层句柄以 `Arc` 共享，锁内只做一次克隆；调用方必须在**释放上下文锁之后**
/// 才发起收发。发送与拨号都会阻塞在 tokio 运行时上，持锁进行会让同一把锁上的
/// 其他线程（含 tokio 工作线程触发的入站回调）永久等待，形成全局死锁。
pub(crate) fn transport_handle(ctx: &SafeContext) -> Option<Arc<quic::QuicTransport>> {
    ctx.lock().ok().and_then(|guard| guard.quic.clone())
}

/// 通过已建立的会话发送一条「header + 明文」消息（QUIC 承载，加密由 TLS 1.3 负责）。
///
/// 这是全仓唯一的出站入口：旧 TCP 帧（含 AES-GCM 密文）已随传输层切换废弃。
pub(crate) fn send_via_quic(ctx: &SafeContext, uuid: &str, header: &str, plaintext: &str) -> bool {
    let Some(transport) = transport_handle(ctx) else {
        log::warn!(
            "发送失败: QUIC 传输层未启动 uuid={}, header={}",
            uuid,
            header
        );
        return false;
    };
    match transport.send(uuid, header, plaintext.as_bytes()) {
        Ok(()) => true,
        Err(e) => {
            log::warn!("发送失败 uuid={}, header={}, error={}", uuid, header, e);
            false
        }
    }
}

/// 通过已建立的会话发送一条控制帧（header + 明文）。
///
/// 调用方须持有传输层句柄而非上下文锁。
pub(crate) fn send_control_via(
    transport: &Arc<quic::QuicTransport>,
    uuid: &str,
    header: &str,
    payload: &str,
) -> bool {
    match transport.send(uuid, header, payload.as_bytes()) {
        Ok(()) => true,
        Err(e) => {
            log::warn!("发送失败 uuid={}, header={}, error={}", uuid, header, e);
            false
        }
    }
}

/// 向指定地址发起一次性请求并处理响应（QUIC 双向流）。
fn oneshot_send_and_process(
    ctx: &SafeContext,
    uuid: &str,
    ip: &str,
    port: u16,
    header: &str,
    payload: &str,
) -> i32 {
    let ctx_ptr = ctx as *const SafeContext as usize;
    let resp =
        crate::network::request_response_over_quic(ctx_ptr, uuid, ip, port, header, payload, 5000);
    match resp {
        Some((resp_header, resp_payload)) => {
            // 一次性直连：无会话 uuid 可比对
            crate::processing::process_header_frame(ctx, None, &resp_header, &resp_payload);
            0
        }
        None => {
            log::error!("一次性请求失败 ip={}, port={}", ip, port);
            -1
        }
    }
}

/// 发送 HANDSHAKE 并通过 oneshot 处理 ACCEPT 响应。
///
/// 优先走已建立会话；无会话时向 `target_ip` 做 oneshot 连接。
pub fn send_handshake(
    ctx: &SafeContext,
    uuid: &str,
    local_ip: &str,
    target_ip: &str,
    battery: i32,
    device_type: &str,
) -> i32 {
    let port = crate::protocol::codec::DEFAULT_TCP_PORT;
    let payload = codec::handshake_payload(uuid, local_ip, battery, device_type);

    // 优先走已建立会话（句柄在锁内取，发送在锁外进行）
    let sent = match transport_handle(ctx) {
        Some(transport) => send_control_via(
            &transport,
            uuid,
            crate::processing::CTRL_HANDSHAKE,
            &payload,
        ),
        None => false,
    };
    if sent {
        return 0;
    }

    // 否则在长连接上开流请求（首次会按 target_ip 建连）
    oneshot_send_and_process(
        ctx,
        uuid,
        target_ip,
        port,
        crate::processing::CTRL_HANDSHAKE,
        &payload,
    )
}

/// 发送配对结果回调并清理临时状态
fn fire_pairing_result(ctx: &SafeContext, target_uuid: &str, success: i32, error_msg: &str) {
    let cb = {
        let Ok(mut g) = ctx.lock() else {
            return;
        };
        // 只清理该对端的配对会话，不影响与其他设备的并发配对
        g.pairing_sessions.remove(target_uuid);
        g.router.on_pairing.clone()
    };
    if let Some(cb_fn) = cb.as_ref() {
        let json_str =
            serde_json::json!({"uuid": target_uuid, "success": success != 0, "error": error_msg})
                .to_string();
        cb_fn(target_uuid, "RESULT", &json_str, success, error_msg);
    }
}

/// 发起配对（发起方），自动完成完整配对流程。
///
/// 内部：SPAKE2 Prover → 发送 → 接收 PAIRING_RESP → 完成密钥协商 → 发送 ACCEPT → 等待 ACK → 回调。
/// 目标 IP 由 core 内部的 `device_ips` 映射表解析。
pub fn send_pairing_init(
    ctx: &SafeContext,
    local_uuid: &str,
    target_uuid: &str,
    expected_code: &str,
    battery: i32,
    device_type: &str,
) -> i32 {
    let port = crate::protocol::codec::DEFAULT_TCP_PORT;

    let local_ip = crate::utils::get_local_ip();
    let (prover, spake2_pub) = spake2::generate_prover_session(expected_code);

    let target_ip = {
        let Ok(mut guard) = ctx.lock() else {
            return -1;
        };
        // 配对会话按目标 uuid 隔离：prover 与期望配对码绑定到本次发起的对端
        let session = guard.pairing_session_mut(target_uuid);
        session.expected_code = Some(expected_code.to_string());
        session.prover = Some(prover);

        guard
            .device_ips
            .lock()
            .ok()
            .and_then(|ips| ips.get(target_uuid).cloned())
            .filter(|ip| !ip.is_empty() && ip != "0.0.0.0")
            .unwrap_or_default()
    };

    if target_ip.is_empty() {
        log::error!("配对发起: 无法获取目标设备IP, target_uuid={}", target_uuid);
        fire_pairing_result(ctx, target_uuid, 0, "no_target_ip");
        return -1;
    }

    // 配对走 QUIC：发 PAIRING_INIT 并等待同流回复的 PAIRING_RESP
    let init_payload =
        codec::pairing_init_payload(local_uuid, &spake2_pub, &local_ip, battery, device_type);
    let ctx_ptr = ctx as *const SafeContext as usize;
    let resp = match crate::network::request_response_over_quic(
        ctx_ptr,
        target_uuid,
        &target_ip,
        port,
        crate::processing::CTRL_PAIRING_INIT,
        &init_payload,
        60_000,
    ) {
        Some(r) => r,
        None => {
            log::error!("配对发起: 等待 PAIRING_RESP 失败或超时");
            fire_pairing_result(ctx, target_uuid, 0, "pairing_resp_timeout");
            let reject = codec::reject_payload(local_uuid);
            let _ = crate::network::send_once_over_quic(
                ctx_ptr,
                target_uuid,
                &target_ip,
                port,
                crate::processing::CTRL_REJECT,
                &reject,
            );
            return -1;
        }
    };

    // 配对发起方读到的响应无会话 uuid 可比对
    crate::processing::process_frame(ctx, None, MessageType::PAIRING_RESP, &resp.1);

    let (ks, peer_lt_pub) = {
        let Ok(mut g) = ctx.lock() else {
            fire_pairing_result(ctx, target_uuid, 0, "context_lock_failed");
            return -1;
        };
        g.prune_expired_pairing_sessions();
        match g.pairing_sessions.get_mut(target_uuid) {
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
                fire_pairing_result(ctx, target_uuid, 0, "context_lock_failed");
                return -1;
            };
            (
                guard.crypto.local_pub_key_b64.clone().unwrap_or_default(),
                guard.crypto.derive_session_key(&lt_pub),
            )
        };
        // 用 K_s 加密本机 lt_pub，避免明文传输（K_s 仅用于本次公钥传输）
        let enc_lt = aes::encrypt(&aes_key, local_pub_b64.as_bytes()).unwrap_or_default();
        // 数据通道密钥由长期 ECDH 派生（与重连路径一致），K_s 不再作为会话密钥
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
        crate::crypto::zeroize_key(&mut aes_key);
        {
            let Ok(mut guard) = ctx.lock() else {
                fire_pairing_result(ctx, target_uuid, 0, "context_lock_failed");
                return -1;
            };
            guard.crypto.device_keys.insert(
                target_uuid.to_string(),
                crate::crypto::DeviceKeyEntry {
                    remote_pub_key: lt_pub.clone(),
                    aes_key_b64: b64,
                    aes_key_bytes: key_bytes,
                },
            );
            guard.pairing_sessions.remove(target_uuid);
        }

        // 发送 ACCEPT 并等待 ACK
        let accept = codec::accept_payload(local_uuid, &enc_lt);
        let acked = crate::network::request_response_over_quic(
            ctx_ptr,
            target_uuid,
            &target_ip,
            port,
            crate::processing::CTRL_ACCEPT,
            &accept,
            10_000,
        );
        match acked {
            Some(_) => log::info!("配对发起: 收到 ACK 确认"),
            None => log::warn!("配对发起: 未收到 ACK 确认"),
        }
        fire_pairing_result(ctx, target_uuid, 1, "ok");
        return 0;
    }

    log::warn!("配对发起: SPAKE2 会话密钥或对方公钥缺失");
    let reject = codec::reject_payload(local_uuid);
    let _ = crate::network::send_once_over_quic(
        ctx_ptr,
        target_uuid,
        &target_ip,
        port,
        crate::processing::CTRL_REJECT,
        &reject,
    );
    fire_pairing_result(ctx, target_uuid, 0, "session_missing");
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

/// 发送 PAIRING_RESP（接收方回复发起方的配对请求）。
///
/// `uuid` 为接收方（本机）身份标识，用于编码到消息中；
/// 会话按目标对端 uuid 从 `pairing_sessions` 查找。
pub fn send_pairing_resp(
    ctx: &SafeContext,
    uuid: &str,
    lt_pub: &str,
    pairing_code: &str,
    ip: &str,
    battery: i32,
    device_type: &str,
) -> i32 {
    let target_uuid = {
        let Ok(mut guard) = ctx.lock() else {
            return -1;
        };
        guard.prune_expired_pairing_sessions();
        resolve_pairing_resp_target(&guard, uuid)
    };
    let target_uuid = match target_uuid {
        Some(u) => u,
        None => return -1,
    };

    // 响应方 IP 使用本机地址（与 send_pairing_init 对称），平台传入的 ip 仅作兜底
    let local_ip = {
        let local = crate::utils::get_local_ip();
        if local.is_empty() {
            ip.to_string()
        } else {
            local
        }
    };
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
    let (verifier, spake2_pub) = spake2::generate_verifier_session(pairing_code);
    let msg = match spake2::verifier_complete(verifier, &peer_spake2_pub) {
        Ok(shared) => {
            let mut ks = hkdf::derive_session_key(&shared);
            let enc_lt = aes::encrypt(&ks, lt_pub.as_bytes()).unwrap_or_default();
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
            codec::pairing_resp_payload(uuid, &spake2_pub, &enc_lt, &local_ip, battery, device_type)
        }
        Err(e) => {
            log::error!("发送 PAIRING_RESP: SPAKE2 verifier 完成失败: {}", e);
            String::new()
        }
    };
    if msg.is_empty() {
        log::error!("发送 PAIRING_RESP: 密钥协商失败，放弃发送");
        return -1;
    }

    let sent = match transport_handle(ctx) {
        Some(transport) => send_control_via(
            &transport,
            &target_uuid,
            crate::processing::CTRL_PAIRING_RESP,
            &msg,
        ),
        None => false,
    };
    if !sent {
        log::warn!("发送 PAIRING_RESP 失败 target={}", target_uuid);
    }
    0
}

/// 发送 ACCEPT。
pub fn send_accept(
    ctx: &SafeContext,
    target_uuid: &str,
    lt_pub_key: &str,
    _ip: &str,
    _battery: i32,
    _device_type: &str,
) {
    let (local_uuid, transport) = {
        let Ok(guard) = ctx.lock() else {
            return;
        };
        (
            guard
                .broadcast_info
                .as_ref()
                .map(|info| info.uuid.clone())
                .unwrap_or_default(),
            guard.quic.clone(),
        )
    };
    if local_uuid.is_empty() {
        log::warn!("send_accept: 本机 uuid 未设置（broadcast_info 为空），跳过发送 ACCEPT");
        return;
    }
    let Some(transport) = transport else {
        log::warn!("send_accept: QUIC 传输层未就绪，跳过发送 ACCEPT");
        return;
    };
    let payload = codec::accept_payload(&local_uuid, lt_pub_key);
    let sent = send_control_via(
        &transport,
        target_uuid,
        crate::processing::CTRL_ACCEPT,
        &payload,
    );
    if !sent {
        log::warn!("send_accept: 发送 ACCEPT 失败 target={}", target_uuid);
    }
}

/// 发送 REJECT 并清理该对端的配对会话。
pub fn send_reject(ctx: &SafeContext, uuid: &str) {
    let payload = codec::reject_payload(uuid);
    let transport = match ctx.lock() {
        Ok(mut guard) => {
            guard.pairing_sessions.remove(uuid);
            guard.quic.clone()
        }
        Err(_) => None,
    };
    let sent = match transport {
        Some(transport) => {
            send_control_via(&transport, uuid, crate::processing::CTRL_REJECT, &payload)
        }
        None => false,
    };
    if !sent {
        log::warn!("send_reject: 发送 REJECT 失败 uuid={}", uuid);
    }
}

/// UDP 广播发现周期：2 秒。
///
/// 防回归说明：设备发现早期即为 UDP 广播（2s 周期）。曾因移动网络下对 /24 网段做
/// 254 个 IP 并发 TCP 全段扫描、持续抢占蜂窝空口与系统 conntrack 表项，导致同设备其他
/// 应用网络异常，才切换到 TCP 扫描；现恢复 UDP 广播。移动网络（蜂窝）下无局域网广播域，
/// UDP 广播不可达属预期行为，设备间连接仍由心跳 / known_device_scanner 等定向 TCP 通道
/// 负责，请勿为「移动网络下也能发现」改回全段 TCP 扫描（防回归）。
#[allow(dead_code)]
pub(crate) const BROADCAST_INTERVAL_MS: u64 = 2000;

/// 统一处理「发现到的设备」：登记注册表、记录 device_ips，并触发平台 on_device_discovered 回调。
/// UDP 广播发现路径与（保留的）TCP 发现请求应答路径共用同一消费链，保证发现结果上抛语义一致。
/// 仅在发现线程中调用，必须通过 ctx.lock() 取锁（不得用 get_mut() 绕过互斥）。
pub(crate) fn consume_discovered_device(
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
    // 跳过本机自身：mDNS 组播会回环到本机监听 socket，
    // 若不拦截会把本机登记成「远程设备」，污染设备表并占掉发现配额。
    //
    // 身份必须优先用持久化的 local_uuid：broadcast_info 由心跳调度器稍后写入，
    // 发现线程首次回调时可能仍为空，仅用它判断会漏过自我过滤。
    let is_self = if !guard.local_uuid.is_empty() {
        guard.local_uuid == uuid
    } else {
        guard
            .broadcast_info
            .as_ref()
            .map(|b| b.uuid == uuid)
            .unwrap_or(false)
    };
    if is_self {
        log::debug!("忽略自身 mDNS 通告 uuid={}", uuid);
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
    // 记录发现来源 IP：已锁定的地址优先保留，避免多地址反复覆盖。
    // mDNS 侧已实现「锁定地址仍在候选集中就沿用」，故这里只在无记录时写入；
    // 锁定地址失效时 mDNS 会传入新地址，需要覆盖时由该路径显式刷新。
    if let Ok(mut ips) = guard.device_ips.lock() {
        if !ips.contains_key(uuid) || ips.get(uuid).is_some_and(|v| v == ip) {
            ips.insert(uuid.to_string(), ip.to_string());
        }
    }
    // 关键：登记到 known_devices，否则心跳调度器不会为它启动心跳，
    // 该设备永远停留在「已发现但离线」状态（多设备场景下表现为随机一台掉线）。
    guard.discovery.add_known_device(uuid, ip);
    let cb = guard.router.on_device_discovered.clone();
    // 回调前释放锁：平台端回调内可能再次调用 core 接口（如拉取设备快照）
    drop(guard);
    if let Some(f) = cb.as_ref() {
        f(uuid, &name, port, battery, device_type, ip);
    }
}

/// 供集成测试驱动的发现消费入口。
///
/// 发现机制已迁移到 mDNS，consume_discovered_device 是唯一的消费链入口；
/// 集成测试无法构造 mdns_sd::ResolvedService，故由此转调，验证语义保持一致。
#[doc(hidden)]
pub fn consume_discovered_device_for_test(
    ctx: &SafeContext,
    uuid: &str,
    name_b64: &str,
    port: u16,
    battery: i32,
    device_type: &str,
    ip: &str,
) {
    consume_discovered_device(ctx, uuid, name_b64, port, battery, device_type, ip);
}

/// 周期广播控制：0=停止，1=启动，2=仅更新参数。
pub fn periodic_broadcast(
    ctx_ptr: usize,
    action: i32,
    uuid: Option<&str>,
    name: Option<&str>,
    battery: i32,
    device_type: Option<&str>,
) -> i32 {
    if ctx_ptr == 0 {
        return -1;
    }
    let ctx = unsafe { &*(ctx_ptr as *const SafeContext) };

    match action {
        0 => {
            let Ok(mut guard) = ctx.lock() else {
                return -1;
            };
            if let Some(handle) = guard.broadcast_handle.take() {
                handle.running.store(false, Ordering::Relaxed);
            }
            // 注意：不清空 broadcast_info，心跳调度器/重连/发现等组件依赖它获取本机身份
            // （锁屏切换 TCP 备用心跳时若本机信息为空，心跳调度器将停摆不工作）
            0
        }
        1 => {
            let (Some(uuid), Some(name), Some(device_type)) = (uuid, name, device_type) else {
                return -1;
            };
            if battery.abs() > 100 {
                return -1;
            }
            let u = uuid.to_string();
            let n_b64 = encode_name_b64(name);
            let d = device_type.to_string();

            let running = Arc::new(AtomicBool::new(true));

            let Ok(mut guard) = ctx.lock() else {
                return -1;
            };
            let local_uuid = u.clone();
            guard.broadcast_info = Some(BroadcastInfo {
                uuid: u.clone(),
                name_b64: n_b64,
                battery,
                device_type: d.clone(),
            });
            // 同步广播信息到 TCP 层（供发现请求响应使用）
            crate::network::set_broadcast_info(
                guard.network.transport.clone(),
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
            crate::network::set_local_uuid(guard.network.transport.clone(), &local_uuid);

            if guard.broadcast_handle.is_some() {
                return 0;
            }
            drop(guard);

            // mDNS 发现：注册本机服务 + 订阅同类型服务事件（替代 UDP 广播）
            let port = {
                let Ok(guard) = ctx.lock() else {
                    return -1;
                };
                guard.network.port
            };
            let discovery_port = if port == 0 {
                crate::protocol::codec::DEFAULT_TCP_PORT
            } else {
                port
            };
            let result = crate::discovery::mdns::MdnsDiscovery::start(
                ctx_ptr,
                &u,
                name,
                discovery_port,
                battery,
                &d,
            );
            match result {
                Ok(handle) => {
                    if let Ok(mut guard) = ctx.lock() {
                        guard.broadcast_handle = Some(BroadcastHandle {
                            running,
                            mdns: Some(std::sync::Arc::new(std::sync::Mutex::new(handle))),
                        });
                    }
                    0
                }
                Err(e) => {
                    log::error!("启动 mDNS 发现失败: {}", e);
                    running.store(false, Ordering::Relaxed);
                    -1
                }
            }
        }
        2 => {
            let mdns_target = {
                let Ok(mut guard) = ctx.lock() else {
                    return -1;
                };
                if let Some(ref mut info) = guard.broadcast_info {
                    if let Some(uuid) = uuid {
                        info.uuid = uuid.to_string();
                    }
                    if let Some(name) = name {
                        info.name_b64 = encode_name_b64(name);
                    }
                    // 负数表示放电，是有效状态；仅超出 [-100,100] 才视为未知
                    if battery.abs() <= 100 {
                        info.battery = battery;
                    }
                    if let Some(device_type) = device_type {
                        info.device_type = device_type.to_string();
                    }
                }
                guard.mdns_battery_target()
            };
            // 电量/名称/类型变化同步到 mDNS TXT 记录（锁外，避免阻塞 daemon 拖住上下文锁）
            if let Some((mdns, battery)) = mdns_target {
                if let Ok(mut guard) = mdns.lock() {
                    guard.update_battery(battery);
                }
            }
            0
        }
        _ => -1,
    }
}

/// 生成 6 位配对码并写入上下文，返回码字符串。
///
/// `ttl_secs` 为有效期（秒），0 表示使用默认 300 秒。
pub fn generate_pairing_code(ctx: &SafeContext, ttl_secs: u32) -> String {
    use rand::Rng;
    let ttl = if ttl_secs == 0 { 300 } else { ttl_secs as u64 };
    let code: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Uniform::new(0u32, 10u32))
        .take(6)
        .map(|d| d.to_string())
        .collect();
    if let Ok(mut guard) = ctx.lock() {
        guard.pairing_code = Some(code.clone());
        guard.pairing_code_expiry = Some(Instant::now() + Duration::from_secs(ttl));
    }
    code
}

/// 清除已存储的配对码。
pub fn clear_pairing_code(ctx: &SafeContext) {
    if let Ok(mut guard) = ctx.lock() {
        guard.pairing_code = None;
        guard.pairing_code_expiry = None;
    }
}

/// 对已配对设备发起 HANDSHAKE 并等待对端 ACCEPT/REJECT。
///
/// 内部按「最多 3 次、每次 5s 超时、间隔 1s」重试（与平台端原有握手重试策略一致），
/// 通过 oneshot 新连接同步读取响应，无需平台端维护 deferred 等待器。
/// 返回 0 表示收到 ACCEPT（连接成功），-1 表示被拒绝或重试耗尽。
pub fn connect_device(
    ctx: &SafeContext,
    target_uuid: &str,
    target_ip: &str,
    battery: i32,
    device_type: &str,
) -> i32 {
    const MAX_RETRIES: u32 = 3;
    const TIMEOUT_MS: u32 = 5000;
    const RETRY_DELAY_MS: u64 = 1000;
    const PORT: u16 = crate::protocol::codec::DEFAULT_TCP_PORT;

    let (local_uuid, local_ip) = {
        let Ok(guard) = ctx.lock() else {
            return -1;
        };
        (
            guard
                .broadcast_info
                .as_ref()
                .map(|b| b.uuid.clone())
                .unwrap_or_default(),
            crate::utils::get_local_ip(),
        )
    };
    if local_uuid.is_empty() {
        log::error!("连接设备: 本机身份未初始化 uuid={}", target_uuid);
        return -1;
    }

    let payload = codec::handshake_payload(&local_uuid, &local_ip, battery, device_type);

    let ptr = ctx as *const SafeContext as usize;
    for attempt in 0..MAX_RETRIES {
        let resp = crate::network::request_response_over_quic(
            ptr,
            target_uuid,
            target_ip,
            PORT,
            crate::processing::CTRL_HANDSHAKE,
            &payload,
            TIMEOUT_MS,
        );
        match resp {
            Some((resp_header, resp_payload)) => {
                if resp_header == crate::processing::CTRL_ACCEPT {
                    log::info!(
                        "连接设备: 握手成功 uuid={}, 第 {} 次尝试",
                        target_uuid,
                        attempt + 1
                    );
                    crate::processing::process_header_frame(ctx, None, &resp_header, &resp_payload);
                    return 0;
                }
                if resp_header == crate::processing::CTRL_REJECT {
                    log::warn!("连接设备: 对端拒绝 uuid={}", target_uuid);
                    crate::processing::process_header_frame(ctx, None, &resp_header, &resp_payload);
                    return -1;
                }
                log::warn!(
                    "连接设备: 收到非预期响应(header={}) uuid={}, 重试",
                    resp_header,
                    target_uuid
                );
                crate::processing::process_header_frame(ctx, None, &resp_header, &resp_payload);
            }
            None => {
                log::warn!(
                    "连接设备: 握手超时 uuid={}, 第 {}/{} 次",
                    target_uuid,
                    attempt + 1,
                    MAX_RETRIES
                );
            }
        }
        if attempt + 1 < MAX_RETRIES {
            std::thread::sleep(Duration::from_millis(RETRY_DELAY_MS));
        }
    }

    log::warn!("连接设备: 重试耗尽 uuid={}", target_uuid);
    -1
}
