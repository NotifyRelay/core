use std::sync::{Arc, Mutex};

/// 传输层状态：QUIC 承载全部数据与控制帧。
///
/// 连接与会话由 `quic:`Transport` 持有；本结构只保留跨模块共享的小字段，
/// 以及供旧调用点查询的在线设备视图。
pub struct TransportState {
    /// 传输服务端是否运行中
    pub running: bool,
    /// 传输服务端监听端口（0 表示未启动）
    pub port: u16,
    /// 本机 uuid（运行期动态更新）
    pub local_uuid: String,
    /// 广播信息副本（供发现应答使用）
    pub broadcast_info: Option<crate::BroadcastInfo>,
    /// QUIC 传输层共享句柄（发送路径经此转发，避免持锁做 I/O）
    pub transport: Option<Arc<crate::quic::QuicTransport>>,
}

impl TransportState {
    pub fn new() -> Self {
        Self {
            running: false,
            port: 0,
            local_uuid: String::new(),
            broadcast_info: None,
            transport: None,
        }
    }

    /// 在线设备数量（委托 QUIC）。
    pub fn connected_count(&self) -> i32 {
        self.transport
            .as_ref()
            .map(|t| t.connected_count() as i32)
            .unwrap_or(0)
    }

    /// 指定设备是否在线（委托 QUIC）。
    pub fn is_connected(&self, uuid: &str) -> bool {
        self.transport
            .as_ref()
            .is_some_and(|t| t.is_connected(uuid))
    }

    /// 移除设备连接（委托 QUIC）。
    pub fn remove_session(&mut self, uuid: &str) {
        if let Some(t) = self.transport.as_ref() {
            t.disconnect(uuid);
        }
    }
}

/// 网络状态（QUIC 传输）
pub struct NetworkState {
    /// 传输层共享状态（供 `set_local_uuid` / `set_broadcast_info` 等接口更新）
    pub transport: Arc<Mutex<TransportState>>,
    /// 本机证书公钥指纹（配对期交换给对端，连接期校验）
    pub local_fingerprint: Option<String>,
    /// 传输服务端监听端口（0 表示未启动）
    pub port: u16,
    /// 传输服务端是否运行中
    pub running: bool,
    /// 本机 uuid 副本
    pub local_uuid: String,
}

impl NetworkState {
    pub fn new() -> Self {
        Self {
            transport: Arc::new(Mutex::new(TransportState::new())),
            local_fingerprint: None,
            port: 0,
            running: false,
            local_uuid: String::new(),
        }
    }
}

/// 更新本机 uuid（运行期由 FFI 层同步，保证 TCP 层自我连接拒绝始终有效）
pub fn set_local_uuid(state: Arc<Mutex<TransportState>>, uuid: &str) {
    if let Ok(mut state) = state.lock() {
        state.local_uuid = uuid.to_string();
    }
}

/// 同步广播信息到 TCP 服务器状态（供发现请求响应使用）
pub fn set_broadcast_info(state: Arc<Mutex<TransportState>>, info: Option<crate::BroadcastInfo>) {
    if let Ok(mut s) = state.lock() {
        s.broadcast_info = info;
    }
}

/// 移除设备会话（FFI 用）
pub fn remove_device_connection(state: Arc<Mutex<TransportState>>, uuid: &str) {
    if let Ok(mut state) = state.lock() {
        state.remove_session(uuid);
    }
}

/// 取常驻传输层（不存在时按需创建并挂本机证书）。
///
/// 关键：**不再为每次探测新建传输层**。临时传输层用完即 shutdown，
/// 而发现扫描/重连是秒级循环，会表现为「连接反复建立又关闭」，
/// 且每次关闭都会把对端刚建立的连接一并断掉。
fn resident_transport(ctx: &crate::SafeContext) -> Option<Arc<crate::quic::QuicTransport>> {
    {
        let guard = ctx.lock().ok()?;
        if let Some(t) = guard.quic.as_ref() {
            return Some(t.clone());
        }
    }
    // 尚未启动服务端：创建一台并挂证书后回填，后续复用同一实例
    let (secret, uuid) = {
        let guard = ctx.lock().ok()?;
        (guard.crypto.local_key.clone()?, guard.local_uuid.clone())
    };
    if uuid.is_empty() {
        return None;
    }
    let cert = crate::crypto::cert::derive_cert(&secret, &uuid).ok()?;
    let transport = Arc::new(crate::quic::QuicTransport::new().ok()?);
    transport.set_local_cert(cert);
    let mut guard = ctx.lock().ok()?;
    if let Some(existing) = guard.quic.as_ref() {
        return Some(existing.clone());
    }
    guard.quic = Some(transport.clone());
    Some(transport)
}

/// 请求-响应：在**已建立的长连接**上开一条流，发帧并等待同流回复。
///
/// 语义修正（此前是短连接模型，错误）：
/// - 连接由 `ensure_link` 保证存在，本函数**从不主动拨号**；
/// - 同一条 QUIC 连接可并发承载多条流，探测/心跳/业务各自开流、互不阻塞；
/// - 返回 `None` 表示连接不可用或超时，调用方据此判定对端不可达。
pub fn request_response_over_quic(
    ctx_ptr: usize,
    uuid: &str,
    ip: &str,
    port: u16,
    header: &str,
    payload: &str,
    timeout_ms: u32,
) -> Option<(String, Vec<u8>)> {
    let ctx = unsafe { &*(ctx_ptr as *const crate::SafeContext) };
    let transport = ensure_link(ctx, uuid, ip, port)?;
    transport
        .request(uuid, header, payload.as_bytes(), u64::from(timeout_ms))
        .ok()?
}

/// 单向发送：在长连接上开一条流发送一帧（不等待回复）。
pub fn send_once_over_quic(
    ctx_ptr: usize,
    uuid: &str,
    ip: &str,
    port: u16,
    header: &str,
    payload: &str,
) -> bool {
    let ctx = unsafe { &*(ctx_ptr as *const crate::SafeContext) };
    let Some(transport) = ensure_link(ctx, uuid, ip, port) else {
        return false;
    };
    transport.send(uuid, header, payload.as_bytes()).is_ok()
}

/// 确保到该设备存在长连接（幂等）。
///
/// 多地址策略：同一设备可能有多个地址（mDNS 通告、已知设备表、连接来源 IP），
/// 其中部分不可达。此处**汇总全部来源、去重后逐个尝试**，任一成功即建立长连接：
/// 1. 已连接 → 直接返回；
/// 2. 候选 = mDNS 通告 ∪ device_ips ∪ known_devices ∪ 调用方传入 ip；
/// 3. 失败过的地址排最后（仍参与尝试，网络环境可能已变）。
///
/// 这是全仓唯一的建连入口，避免「每条消息一次拨号」的短连接行为。
///
/// 对 `crate` 内公开：心跳发送同样必须走多地址回退，
/// 否则单一地址不可达时该设备会持续被判离线。
pub(crate) fn ensure_link(
    ctx: &crate::SafeContext,
    uuid: &str,
    ip: &str,
    port: u16,
) -> Option<Arc<crate::quic::QuicTransport>> {
    let transport = resident_transport(ctx)?;
    if transport.is_connected(uuid) {
        return Some(transport);
    }

    // 汇总全部已知地址来源：任何单一来源都可能过期或不完整
    // （曾因只看 mDNS 表，把蜂窝地址当成唯一候选而永久连不上局域网对端）。
    let mut candidates: Vec<String> = Vec::new();
    let push = |addr: String, list: &mut Vec<String>| {
        let a = crate::utils::normalize_ip(&addr);
        if !a.is_empty() && a != "0.0.0.0" && !list.contains(&a) {
            list.push(a);
        }
    };
    {
        let Ok(guard) = ctx.lock() else {
            return None;
        };
        if let Ok(m) = guard.device_addrs.lock() {
            if let Some(list) = m.get(uuid) {
                for a in list {
                    push(a.clone(), &mut candidates);
                }
            }
        }
        if let Ok(m) = guard.device_ips.lock() {
            if let Some(a) = m.get(uuid) {
                push(a.clone(), &mut candidates);
            }
        }
        if let Some(a) = guard.discovery.get_known_devices().get(uuid) {
            push(a.clone(), &mut candidates);
        }
    }
    push(ip.to_string(), &mut candidates);

    if candidates.is_empty() {
        log::debug!("建连失败: 无候选地址 uuid={}", uuid);
        return None;
    }

    // 失败过的地址排到最后，仍参与尝试（网络环境可能已变化）
    let failed: std::collections::HashSet<String> = ctx
        .lock()
        .ok()
        .and_then(|g| g.failed_ips.lock().ok().and_then(|m| m.get(uuid).cloned()))
        .unwrap_or_default();
    candidates.sort_by_key(|addr| failed.contains(addr));

    for addr in &candidates {
        if transport.connect(uuid, addr, port, None).is_ok() {
            if let Ok(guard) = ctx.lock() {
                if let Ok(mut f) = guard.failed_ips.lock() {
                    f.remove(uuid);
                }
                // 记录本次可用地址，供后续优先复用
                if let Ok(mut ips) = guard.device_ips.lock() {
                    ips.insert(uuid.to_string(), addr.clone());
                }
            }
            return Some(transport);
        }
        log::debug!("建连失败: 地址不可达 uuid={}, addr={}:{}", uuid, addr, port);
        if let Ok(guard) = ctx.lock() {
            if let Ok(mut f) = guard.failed_ips.lock() {
                f.entry(uuid.to_string()).or_default().insert(addr.clone());
            }
        }
    }
    log::debug!(
        "建连失败: 全部地址均不可达 uuid={}, tried={:?}",
        uuid,
        candidates
    );
    None
}

// ===== 上下文级网络入口 =====

use crate::SafeContext;

/// 启动传输服务端（QUIC）。返回 0 表示成功。
///
/// 函数名沿用历史命名以保持调用方不变；实现已切换为 QUIC：
/// - 证书由本机长期 P-256 私钥派生（`crypto::cert`），历史配对无需重来；
/// - 入站帧解码后交给 `processing::process_frame`，与旧 TCP 路径语义一致；
/// - 无可用证书（尚未生成密钥对）时直接失败，由平台端先 `nrc_ecdh_generate_keypair`。
pub fn start_transport_server(ctx_ptr: usize, port: u16) -> i32 {
    if ctx_ptr == 0 {
        log::error!("启动传输服务端: 空上下文");
        return -1;
    }
    let ctx = unsafe { &*(ctx_ptr as *const SafeContext) };

    // 取出本机长期私钥与 uuid（缺失则无法派生证书，启动失败）
    let (secret, local_uuid, on_connected, on_disconnected, on_tcp_error) = {
        let Ok(guard) = ctx.lock() else {
            return -1;
        };
        let Some(secret) = guard.crypto.local_key.clone() else {
            log::error!("启动传输服务端: 本机长期密钥未生成，无法派生证书");
            return -1;
        };
        (
            secret,
            // 身份来源必须是持久化的 local_uuid：broadcast_info 在本函数之后才写入，
            // 用它会导致证书 CN 为空，对端解析不出设备身份。
            guard.local_uuid.clone(),
            guard.router.on_device_connected.clone(),
            guard.router.on_device_disconnected.clone(),
            guard.router.on_tcp_error.clone(),
        )
    };

    if local_uuid.is_empty() {
        log::error!("启动传输服务端: 本机 uuid 未就绪，无法派生身份证书");
        return -1;
    }

    // 派生证书（CN 携带本机 uuid，供对端在握手期识别身份）
    let cert = match crate::crypto::cert::derive_cert(&secret, &local_uuid) {
        Ok(c) => c,
        Err(e) => {
            log::error!("启动传输服务端: 派生证书失败: {}", e);
            return -1;
        }
    };
    let fingerprint = cert.fingerprint.clone();

    // 传输层惰性创建并保存到上下文
    let transport = match crate::quic::QuicTransport::new() {
        Ok(t) => t,
        Err(e) => {
            log::error!("启动传输服务端: 创建传输层失败: {}", e);
            return -1;
        }
    };

    let on_connected_cb = Arc::new(move |uuid: String, peer: String| {
        // 入站回调给出的是 SocketAddr（ip:port）；device_ips 必须只存纯 IP，
        // 否则后续拼成 "ip:port:23333" 建连必然失败。
        let ip = crate::utils::normalize_ip(&peer);
        if let Ok(guard) = unsafe { &*(ctx_ptr as *const SafeContext) }.lock() {
            if let Ok(mut ips) = guard.device_ips.lock() {
                ips.insert(uuid.clone(), ip.clone());
            }
            guard.registry.mark_connected(&uuid, &ip);
        }
        if let Some(cb) = on_connected.as_ref() {
            cb(&uuid, &ip);
        }
    });

    let _on_disconnected_cb = Arc::new(move |uuid: String| {
        if let Ok(mut guard) = unsafe { &*(ctx_ptr as *const SafeContext) }.lock() {
            guard.registry.mark_disconnected(&uuid);
            guard.pairing_sessions.remove(&uuid);
        }
        if let Some(cb) = on_disconnected.as_ref() {
            cb(&uuid);
        }
    });

    // 入站帧：直接交给既有的帧处理入口，保持与旧 TCP 路径一致
    let on_frame_cb = Arc::new(move |uuid: String, header: String, payload: Vec<u8>| {
        let ctx = unsafe { &*(ctx_ptr as *const SafeContext) };
        crate::processing::process_header_frame(ctx, Some(&uuid), &header, &payload);
    });

    let bind_port = port;
    let started = {
        let on_connected_cb = on_connected_cb.clone();
        let on_frame_cb = on_frame_cb.clone();
        transport.start_server(
            bind_port,
            cert,
            move |uuid, ip| on_connected_cb(uuid, ip),
            move |uuid, header, payload| on_frame_cb(uuid, header, payload),
        )
    };

    let bound = match started {
        Ok(p) => p,
        Err(e) => {
            log::error!("启动传输服务端失败: {}", e);
            if let Some(cb) = on_tcp_error.as_ref() {
                cb(&format!("启动传输服务端失败: {e}"));
            }
            return -1;
        }
    };

    // 保存传输层与证书指纹
    if let Ok(mut guard) = ctx.lock() {
        let shared = Arc::new(transport);
        guard.quic = Some(shared.clone());
        guard.network.transport.lock().ok().map(|mut t| {
            t.transport = Some(shared);
        });
        guard.network.local_fingerprint = Some(fingerprint);
        guard.network.port = bound;
        guard.network.running = true;
        guard.network.local_uuid = local_uuid.clone();
    }
    log::info!("QUIC 传输服务端已启动，端口: {}", bound);
    0
}

/// 移除设备 TCP 会话。
pub fn remove_session(ctx: &mut crate::CoreContext, uuid: &str) -> i32 {
    let network_state = ctx.network.transport.clone();
    remove_device_connection(network_state, uuid);
    0
}

/// 网络变化通知（WiFi 切换、网络恢复等）；`local_ip` 为空表示由 core 自行获取。
pub fn notify_network_changed(ctx_ptr: usize, local_ip: Option<&str>) {
    if ctx_ptr == 0 {
        return;
    }
    log::info!("网络变化通知: ip={:?}", local_ip);
    // 自动启动已知设备扫描（用于网络恢复后自动重连）
    crate::discovery::start_known_device_scanner_for(ctx_ptr);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_transport_state_reports_no_connections() {
        let state = TransportState::new();
        // 未挂载传输层时，在线视图必须为空且不 panic
        assert_eq!(state.connected_count(), 0);
        assert!(!state.is_connected("test-uuid"));
        assert!(!state.running);
        assert_eq!(state.port, 0);
    }

    #[test]
    fn remove_session_without_transport_is_noop() {
        let mut state = TransportState::new();
        // 无传输层时移除会话应为无害空操作
        state.remove_session("test-uuid");
        assert_eq!(state.connected_count(), 0);
    }

    #[test]
    fn test_remove_device_connection_not_exists() {
        let state = Arc::new(Mutex::new(TransportState::new()));
        remove_device_connection(state.clone(), "test-uuid");
    }

    /// mDNS 服务类型必须是标准 DNS-SD 形式（供外部工具核对）。
    #[test]
    fn mdns_service_type_is_dns_sd() {
        let ty = crate::discovery::mdns::SERVICE_TYPE;
        assert!(ty.starts_with('_'), "服务类型应以下划线开头: {ty}");
        assert!(ty.ends_with(".local."), "服务类型应为 .local. 域: {ty}");
        assert!(ty.contains("._udp."), "应声明 UDP 传输: {ty}");
    }
}
