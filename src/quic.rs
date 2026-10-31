//! QUIC 传输层（方案 B 的传输实现）。
//!
//! 设计要点：
//! - **对外仍是同步 API**：`QuicTransport` 的公开方法全部阻塞返回，
//!   内部通过独立 tokio 运行时 + `block_on` 桥接，现有 `nrc_*` 调用方零改动。
//! - **每条数据通道一条 QUIC 流**：不同 header（通知 / 媒体 / 超级岛 / 控制）
//!   走独立 stream，天然消除「单连接多线程并发处理」导致的乱序下发。
//! - **身份由既有长期密钥承担**：TLS 证书由 `crypto::cert` 从 P-256 长期私钥派生，
//!   配对流程（SPAKE2）与历史密钥均不变。
//! - 应用层分帧：`[u16 header_len][header][u32 payload_len][payload]`，
//!   与旧 TCP 帧语义对齐，便于上层处理逻辑复用。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use quinn::{ClientConfig, Connection, Endpoint, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::runtime::Runtime;

use crate::crypto::cert::DerivedCert;

/// QUIC 应用层 ALPN（协议不兼容时握手即失败，与版本绑定同义）。
pub const ALPN: &[u8] = b"notifyrelay/1";

/// 单帧最大载荷（与旧 `binary_codec` 的 16MB 上限对齐）。
const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

/// 单条 QUIC 流最大读取字节数（一条流承载一个或多个完整帧）。
const MAX_STREAM_LEN: usize = 32 * 1024 * 1024;

/// 连接级错误。
#[derive(Debug)]
pub enum QuicError {
    /// 对端未连接
    NotConnected(String),
    /// 连接建立失败
    Connect(String),
    /// 收发失败
    Io(String),
    /// 帧格式非法
    Frame(String),
    /// 未初始化
    NotReady,
}

impl std::fmt::Display for QuicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuicError::NotConnected(u) => write!(f, "设备未连接: {u}"),
            QuicError::Connect(e) => write!(f, "QUIC 连接失败: {e}"),
            QuicError::Io(e) => write!(f, "QUIC 收发失败: {e}"),
            QuicError::Frame(e) => write!(f, "QUIC 帧非法: {e}"),
            QuicError::NotReady => write!(f, "QUIC 传输未初始化"),
        }
    }
}

/// 传输句柄：持有运行时与 endpoint，供 `CoreContext` 存放。
pub struct QuicTransport {
    rt: Runtime,
    /// 服务端 endpoint（监听入站）
    server: Mutex<Option<Endpoint>>,
    /// 客户端 endpoint（发起出站；与 server 分离，避免绑定同一端口）
    client: Mutex<Option<Endpoint>>,
    /// 已建立连接：uuid → Connection
    conns: Arc<Mutex<HashMap<String, Connection>>>,
    /// 本机证书（供入站握手与指纹比对）
    cert: Mutex<Option<DerivedCert>>,
    /// 监听端口（0 表示未启动）
    port: Mutex<u16>,
}

impl QuicTransport {
    /// 创建传输层（不启动监听）。
    pub fn new() -> Result<Self, QuicError> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("quic-rt")
            .build()
            .map_err(|e| QuicError::Connect(format!("创建 tokio 运行时失败: {e}")))?;
        Ok(Self {
            rt,
            server: Mutex::new(None),
            client: Mutex::new(None),
            conns: Arc::new(Mutex::new(HashMap::new())),
            cert: Mutex::new(None),
            port: Mutex::new(0),
        })
    }

    /// 当前监听端口（未启动为 0）。
    pub fn port(&self) -> u16 {
        *self.port.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// 是否已启动。
    pub fn is_running(&self) -> bool {
        self.port() != 0
    }

    /// 设置本机证书（双向认证必需）。
    ///
    /// 证书生命周期独立于监听：纯客户端场景（只需发起连接）也必须先设置，
    /// 否则无法在 mTLS 握手中出示身份。
    pub fn set_local_cert(&self, cert: DerivedCert) {
        *self.cert.lock().unwrap_or_else(|e| e.into_inner()) = Some(cert);
    }

    /// 启动服务端监听。
    ///
    /// `on_conn` 在**新入站连接**建立时回调（参数：对端 uuid、对端地址），
    /// `on_frame` 在收到完整应用层帧时回调（参数：对端 uuid、header、payload）。
    /// 回调在 tokio 工作线程上执行，不得阻塞。
    pub fn start_server<F, G>(
        &self,
        port: u16,
        cert: DerivedCert,
        on_conn: F,
        on_frame: G,
    ) -> Result<u16, QuicError>
    where
        F: Fn(String, String) + Send + Sync + 'static,
        G: Fn(String, String, Vec<u8>) + Send + Sync + 'static,
    {
        // 先落本机证书：connect() 需要它做双向认证
        self.set_local_cert(DerivedCert {
            cert_der: cert.cert_der.clone(),
            key_der: cert.key_der.clone(),
            fingerprint: cert.fingerprint.clone(),
        });
        let server_config = build_server_config(&cert)?;
        let addr: SocketAddr = format!("0.0.0.0:{port}")
            .parse()
            .map_err(|e| QuicError::Connect(format!("监听地址非法: {e}")))?;

        let endpoint = self
            .rt
            .block_on(async { Endpoint::server(server_config, addr) })
            .map_err(|e| QuicError::Connect(format!("创建 QUIC 监听失败: {e}")))?;

        let bound = endpoint
            .local_addr()
            .map_err(|e| QuicError::Connect(format!("读取监听地址失败: {e}")))?
            .port();

        // 保存证书供客户端握手时校验
        *self.cert.lock().unwrap_or_else(|e| e.into_inner()) = Some(cert);

        // 入站连接接受循环
        let endpoint_clone = endpoint.clone();
        let conns = self.conns.clone();
        let on_conn = Arc::new(on_conn);
        let on_frame = Arc::new(on_frame);
        self.rt.spawn(async move {
            while let Some(incoming) = endpoint_clone.accept().await {
                let conns = conns.clone();
                let on_conn = on_conn.clone();
                let on_frame = on_frame.clone();
                tokio::spawn(async move {
                    let Ok(conn) = incoming.await else {
                        log::warn!("QUIC 入站握手失败");
                        return;
                    };
                    let peer = conn.remote_address().to_string();

                    // 身份来源优先级：对端证书 CN 中的 uuid > 首帧自报 uuid。
                    // 绝不使用 IP:端口 作为设备身份，避免污染设备表。
                    let mut resolved_uuid = peer_cert_uuid(&conn);
                    if resolved_uuid.is_none() {
                        log::warn!(
                            "QUIC 入站连接无有效身份证书 peer={}（对端可能未携带 uuid 证书）",
                            peer
                        );
                    }
                    if let Some(uuid) = resolved_uuid.clone() {
                        // 仅在无可用连接时登记：出站连接可能已存在，
                        // 覆盖会让正在使用的那条连接被替换，造成发送失败。
                        if let Ok(mut map) = conns.lock() {
                            let occupied =
                                map.get(&uuid).is_some_and(|c| c.close_reason().is_none());
                            if !occupied {
                                map.insert(uuid.clone(), conn.clone());
                            }
                        }
                        log::info!("QUIC 入站连接已建立: uuid={}, peer={}", uuid, peer);
                        // 同样投递到独立线程：on_conn 下游会登记设备并回调平台，
                        // 平台回调可能再次进入 core（含 send），在运行时线程上会 panic。
                        let on_conn = on_conn.clone();
                        let peer_clone = peer.clone();
                        std::thread::Builder::new()
                            .name("quic-onconn".to_string())
                            .spawn(move || {
                                on_conn(uuid, peer_clone);
                            })
                            .ok();
                    }

                    // 持续接受对端打开的流，逐流解码应用层帧
                    loop {
                        match conn.accept_bi().await {
                            Ok((_send, mut recv)) => {
                                let mut buf = Vec::new();
                                if let Ok(data) = recv.read_to_end(MAX_STREAM_LEN).await {
                                    buf.extend_from_slice(&data);
                                }
                                let mut offset = 0usize;
                                while let Ok(Some((header, payload, used))) =
                                    decode_frame(&buf[offset..])
                                {
                                    offset += used;
                                    // 首帧尚未解析出身份时，尝试从载荷中提取并对齐
                                    if resolved_uuid.is_none() {
                                        if let Some(uuid) = uuid_from_payload(&header, &payload) {
                                            if let Ok(mut map) = conns.lock() {
                                                map.insert(uuid.clone(), conn.clone());
                                            }
                                            log::info!(
                                                "QUIC 入站身份已确认: uuid={}, peer={}",
                                                uuid,
                                                peer
                                            );
                                            on_conn(uuid.clone(), peer.clone());
                                            resolved_uuid = Some(uuid);
                                        }
                                    }
                                    if let Some(uuid) = resolved_uuid.as_ref() {
                                        // 关键：on_frame 的下游可能同步调用 send()，
                                        // 而 send() 内部走 block_on。若在 tokio 工作线程上直接执行，
                                        // 会触发 "Cannot start a runtime from within a runtime" 而 panic。
                                        // 故投递到独立线程，运行时线程只负责收发字节。
                                        let on_frame = on_frame.clone();
                                        let uuid = uuid.clone();
                                        std::thread::Builder::new()
                                            .name("quic-dispatch".to_string())
                                            .spawn(move || {
                                                on_frame(uuid, header, payload);
                                            })
                                            .ok();
                                    } else {
                                        log::warn!(
                                            "QUIC 入站帧无法确定设备身份, 已丢弃: header={}",
                                            header
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                log::debug!("QUIC 入站流接受结束: {}", e);
                                break;
                            }
                        }
                    }
                });
            }
        });

        *self.server.lock().unwrap_or_else(|e| e.into_inner()) = Some(endpoint);
        *self.port.lock().unwrap_or_else(|e| e.into_inner()) = bound;
        log::info!("QUIC 服务端已启动，端口 {}", bound);
        Ok(bound)
    }

    /// 主动连接到对端。
    ///
    /// `expected_fingerprint` 非空时校验对端证书公钥指纹（配对期交换的值）。
    pub fn connect(
        &self,
        uuid: &str,
        ip: &str,
        port: u16,
        expected_fingerprint: Option<&str>,
    ) -> Result<(), QuicError> {
        let addr: SocketAddr = format!("{ip}:{port}")
            .parse()
            .map_err(|e| QuicError::Connect(format!("目标地址非法 {ip}:{port}: {e}")))?;

        // 取本机证书用于双向认证；未启动服务端时无证书，无法参与 mTLS
        let local_cert = {
            let guard = self.cert.lock().unwrap_or_else(|e| e.into_inner());
            guard.as_ref().map(|c| DerivedCert {
                cert_der: c.cert_der.clone(),
                key_der: c.key_der.clone(),
                fingerprint: c.fingerprint.clone(),
            })
        };
        let Some(local_cert) = local_cert else {
            return Err(QuicError::Connect(
                "本机证书未就绪，无法发起双向认证连接".to_string(),
            ));
        };
        let client_config = build_client_config(expected_fingerprint, &local_cert)?;
        let endpoint = {
            let mut guard = self.client.lock().unwrap_or_else(|e| e.into_inner());
            if guard.is_none() {
                let bind: SocketAddr = "0.0.0.0:0".parse().expect("通配地址恒定合法");
                let mut ep = self
                    .rt
                    .block_on(async { Endpoint::client(bind) })
                    .map_err(|e| QuicError::Connect(format!("创建 QUIC 客户端失败: {e}")))?;
                ep.set_default_client_config(client_config);
                *guard = Some(ep);
            }
            guard.as_ref().expect("刚插入").clone()
        };

        let conn = self.rt.block_on(async {
            let connecting = endpoint
                .connect(addr, "notifyrelay")
                .map_err(|e| QuicError::Connect(format!("发起连接失败: {e}")))?;
            connecting
                .await
                .map_err(|e| QuicError::Connect(format!("QUIC 握手失败: {e}")))
        })?;

        // 连接建立后按「对端证书 uuid」与「调用方键」双重登记。
        //
        // 为什么要双键：探测阶段调用方只知道地址（addr:ip:port），
        // 业务阶段只知道 uuid。若各建一条连接，同一对端会存在两条，
        // 表现为「连接反复建立又关闭」，且随机一条被对端超时判定离线。
        let peer_uuid = peer_cert_uuid(&conn);
        let reused = {
            let mut map = match self.conns.lock() {
                Ok(m) => m,
                Err(_) => return Err(QuicError::NotReady),
            };
            // 已有可用连接则直接复用，新连接立即关闭
            let occupied = map
                .iter()
                .any(|(_, c)| c.close_reason().is_none() && std::ptr::eq(c, &conn));
            let existing_alive = match peer_uuid.as_deref() {
                Some(p) => map.get(p).is_some_and(|c| c.close_reason().is_none()),
                None => false,
            };
            let key_alive = map.get(uuid).is_some_and(|c| c.close_reason().is_none());
            if existing_alive || key_alive {
                true
            } else {
                map.insert(uuid.to_string(), conn.clone());
                if let Some(p) = peer_uuid.as_deref() {
                    map.insert(p.to_string(), conn.clone());
                }
                let _ = occupied;
                false
            }
        };
        if reused {
            conn.close(0u32.into(), b"duplicate");
            log::debug!("QUIC 已有可用连接，复用而不新建 uuid={}", uuid);
            return Ok(());
        }
        log::info!("QUIC 已连接 {} ({}:{})", uuid, ip, port);
        Ok(())
    }

    /// 是否已连接指定设备。
    pub fn is_connected(&self, uuid: &str) -> bool {
        self.conns
            .lock()
            .map(|m| m.get(uuid).is_some_and(|c| c.close_reason().is_none()))
            .unwrap_or(false)
    }

    /// 已连接设备数。
    pub fn connected_count(&self) -> usize {
        self.conns
            .lock()
            .map(|m| m.values().filter(|c| c.close_reason().is_none()).count())
            .unwrap_or(0)
    }

    /// 已连接设备 uuid 列表。
    pub fn connected_uuids(&self) -> Vec<String> {
        self.conns
            .lock()
            .map(|m| {
                m.iter()
                    .filter(|(_, c)| c.close_reason().is_none())
                    .map(|(k, _)| k.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// 断开指定设备。
    pub fn disconnect(&self, uuid: &str) {
        let conn = self.conns.lock().ok().and_then(|mut m| m.remove(uuid));
        if let Some(conn) = conn {
            conn.close(0u32.into(), b"disconnect");
        }
    }

    /// 断开全部连接。
    pub fn disconnect_all(&self) {
        let drained: Vec<Connection> = self
            .conns
            .lock()
            .map(|mut m| m.drain().map(|(_, c)| c).collect())
            .unwrap_or_default();
        for conn in drained {
            conn.close(0u32.into(), b"shutdown");
        }
    }

    /// 发送一条消息：为本次发送开一条新 QUIC 流。
    ///
    /// 独立流意味着不同消息互不阻塞、各自有序，
    /// 从结构上消除旧实现「单连接并发处理导致乱序」的可能。
    pub fn send(&self, uuid: &str, header: &str, payload: &[u8]) -> Result<(), QuicError> {
        let conn = {
            let map = self.conns.lock().map_err(|_| QuicError::NotReady)?;
            map.get(uuid)
                .cloned()
                .ok_or_else(|| QuicError::NotConnected(uuid.to_string()))?
        };
        if conn.close_reason().is_some() {
            return Err(QuicError::NotConnected(uuid.to_string()));
        }

        let frame = encode_frame(header, payload)?;
        self.rt.block_on(async {
            let (mut send, _recv) = conn
                .open_bi()
                .await
                .map_err(|e| QuicError::Io(format!("打开流失败: {e}")))?;
            send.write_all(&frame)
                .await
                .map_err(|e| QuicError::Io(format!("写入流失败: {e}")))?;
            send.finish()
                .map_err(|e| QuicError::Io(format!("关闭发送侧失败: {e}")))?;
            Ok(())
        })
    }

    /// 请求-响应：打开一条双向流，写入帧后等待对端在同一流上回复一帧。
    ///
    /// 用于握手探测等「发一帧收一帧」场景，语义等价于旧 oneshot 短连接。
    pub fn request(
        &self,
        uuid: &str,
        header: &str,
        payload: &[u8],
        timeout_ms: u64,
    ) -> Result<Option<(String, Vec<u8>)>, QuicError> {
        let conn = {
            let map = self.conns.lock().map_err(|_| QuicError::NotReady)?;
            map.get(uuid)
                .cloned()
                .ok_or_else(|| QuicError::NotConnected(uuid.to_string()))?
        };
        let frame = encode_frame(header, payload)?;
        let deadline = std::time::Duration::from_millis(timeout_ms);
        self.rt.block_on(async move {
            let (mut send, mut recv) = conn
                .open_bi()
                .await
                .map_err(|e| QuicError::Io(format!("打开双向流失败: {e}")))?;
            send.write_all(&frame)
                .await
                .map_err(|e| QuicError::Io(format!("写入失败: {e}")))?;
            send.finish()
                .map_err(|e| QuicError::Io(format!("关闭发送侧失败: {e}")))?;
            let data = match tokio::time::timeout(deadline, recv.read_to_end(MAX_STREAM_LEN)).await
            {
                Ok(Ok(d)) => d,
                Ok(Err(e)) => return Err(QuicError::Io(format!("读取失败: {e}"))),
                Err(_) => return Ok(None),
            };
            match decode_frame(&data)? {
                Some((h, p, _)) => Ok(Some((h, p))),
                None => Ok(None),
            }
        })
    }

    /// 关闭传输层（停止监听、断开全部连接）。
    pub fn shutdown(&self) {
        self.disconnect_all();
        if let Some(ep) = self.server.lock().unwrap_or_else(|e| e.into_inner()).take() {
            ep.close(0u32.into(), b"shutdown");
        }
        if let Some(ep) = self.client.lock().unwrap_or_else(|e| e.into_inner()).take() {
            ep.close(0u32.into(), b"shutdown");
        }
        *self.port.lock().unwrap_or_else(|e| e.into_inner()) = 0;
        log::info!("QUIC 传输层已关闭");
    }
}

impl Drop for QuicTransport {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// 从入站 QUIC 连接的对端证书中解析设备 uuid。
///
/// quinn 在握手完成前不给 `peer_identity`；入站场景下取首条连接的身份。
fn peer_cert_uuid(conn: &Connection) -> Option<String> {
    let identity = conn.peer_identity()?;
    let certs = identity.downcast::<Vec<CertificateDer<'static>>>().ok()?;
    let first = certs.first()?;
    crate::crypto::cert::device_uuid_from_cert(first.as_ref())
}

/// 从应用层载荷中尝试提取设备 uuid（首帧自报身份兜底路径）。
///
/// 握手/心跳/配对帧都携带 uuid 字段：JSON 载荷取 `uuid` 字段，
/// 文本载荷取首个冒号前的段。
fn uuid_from_payload(header: &str, payload: &[u8]) -> Option<String> {
    // 仅控制帧参与身份推断，业务帧必须已有身份
    if crate::processing::control_header_to_type(header).is_none() {
        return None;
    }
    let text = std::str::from_utf8(payload).ok()?;
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
        if let Some(uuid) = v.get("uuid").and_then(|x| x.as_str()) {
            return (!uuid.is_empty()).then(|| uuid.to_string());
        }
    }
    let first = text.split(':').next().unwrap_or("");
    // 裸文本首段必须像设备标识（含连字符或足够长），避免把无意义片段当 uuid
    (first.len() >= 8 && first.is_ascii()).then(|| first.to_string())
}

/// 编码应用层帧：`[u16 header_len][header][u32 payload_len][payload]`。
pub fn encode_frame(header: &str, payload: &[u8]) -> Result<Vec<u8>, QuicError> {
    let hb = header.as_bytes();
    if hb.len() > u16::MAX as usize {
        return Err(QuicError::Frame("header 过长".into()));
    }
    if payload.len() > MAX_FRAME_LEN {
        return Err(QuicError::Frame(format!(
            "payload 过长: {} > {}",
            payload.len(),
            MAX_FRAME_LEN
        )));
    }
    let mut out = Vec::with_capacity(2 + hb.len() + 4 + payload.len());
    out.extend_from_slice(&(hb.len() as u16).to_le_bytes());
    out.extend_from_slice(hb);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// 解码应用层帧，返回 `(header, payload)` 与剩余字节。
pub fn decode_frame(buf: &[u8]) -> Result<Option<(String, Vec<u8>, usize)>, QuicError> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let hlen = u16::from_le_bytes([buf[0], buf[1]]) as usize;
    if buf.len() < 2 + hlen + 4 {
        return Ok(None);
    }
    let header = std::str::from_utf8(&buf[2..2 + hlen])
        .map_err(|e| QuicError::Frame(format!("header 非 UTF-8: {e}")))?
        .to_string();
    let plen =
        u32::from_le_bytes([buf[2 + hlen], buf[3 + hlen], buf[4 + hlen], buf[5 + hlen]]) as usize;
    if plen > MAX_FRAME_LEN {
        return Err(QuicError::Frame(format!("payload 过长: {plen}")));
    }
    let start = 2 + hlen + 4;
    if buf.len() < start + plen {
        return Ok(None);
    }
    Ok(Some((
        header,
        buf[start..start + plen].to_vec(),
        start + plen,
    )))
}

/// 构造服务端 TLS 配置（**双向认证**）。
///
/// 服务端同样要求客户端出示证书，这样才能从证书 CN 直接得到对端设备 uuid，
/// 无需依赖首帧自报身份（自报值可伪造，且会把连接标识误导成设备）。
fn build_server_config(cert: &DerivedCert) -> Result<ServerConfig, QuicError> {
    let certs = vec![CertificateDer::from(cert.cert_der.clone())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_der.clone()));

    let mut crypto = rustls::ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(AcceptAnyClientCert))
        .with_single_cert(certs, key)
        .map_err(|e| QuicError::Connect(format!("服务端 TLS 配置失败: {e}")))?;
    crypto.alpn_protocols = vec![ALPN.to_vec()];

    Ok(ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
            .map_err(|e| QuicError::Connect(format!("QUIC 服务端配置失败: {e}")))?,
    )))
}

/// 构造客户端 TLS 配置。
///
/// 提供 `expected_fingerprint` 时启用「指纹固定」校验：只接受公钥哈希匹配的证书；
/// 未提供时接受任意自签证书（首次配对前的引导阶段，身份由 SPAKE2 配对码保证）。
fn build_client_config(
    expected_fingerprint: Option<&str>,
    local_cert: &DerivedCert,
) -> Result<ClientConfig, QuicError> {
    let expected = expected_fingerprint.map(|s| s.to_string());

    // 客户端同样出示本机证书（双向认证），让服务端能识别来源设备
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(FingerprintVerifier { expected }))
        .with_client_auth_cert(
            vec![CertificateDer::from(local_cert.cert_der.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(local_cert.key_der.clone())),
        )
        .map_err(|e| QuicError::Connect(format!("客户端证书配置失败: {e}")))?;
    crypto.alpn_protocols = vec![ALPN.to_vec()];

    Ok(ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .map_err(|e| QuicError::Connect(format!("QUIC 客户端配置失败: {e}")))?,
    )))
}

/// 服务端接受任意客户端证书。
///
/// 客户端身份的可信度由配对阶段（SPAKE2 配对码 + 长期公钥比对）建立；
/// TLS 层只负责「让对方出示承载 uuid 的证书」，不做 PKI 链校验。
#[derive(Debug)]
struct AcceptAnyClientCert;

impl rustls::server::danger::ClientCertVerifier for AcceptAnyClientCert {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

/// 基于证书公钥指纹的校验器。
#[derive(Debug)]
struct FingerprintVerifier {
    /// 期望的长期公钥 SHA-256（小写 hex）；None 表示接受任意自签证书
    expected: Option<String>,
}

impl rustls::client::danger::ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        match &self.expected {
            None => Ok(rustls::client::danger::ServerCertVerified::assertion()),
            Some(want) => {
                let got = public_key_fingerprint(end_entity.as_ref());
                if got == *want {
                    Ok(rustls::client::danger::ServerCertVerified::assertion())
                } else {
                    Err(rustls::Error::General(format!(
                        "对端身份指纹不匹配: 期望 {want}, 实际 {got}"
                    )))
                }
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

/// 从证书 DER 中取出 **SubjectPublicKeyInfo 的 SHA-256 指纹**。
///
/// 必须与配对期交换的 `DerivedCert::fingerprint`（长期公钥哈希）同口径：
/// 证书内的公钥即长期公钥，故解析出 SPKI 后哈希即可与配对值直接比对。
fn public_key_fingerprint(cert_der: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    // 解析失败时退回证书整体哈希（至少保持「不同证书不同值」，不会误放行）
    match x509_parser::parse_x509_certificate(cert_der) {
        // 证书内 SPKI 的比特串即未压缩 EC 点（与 EncodedPoint 同字节），
        // 直接哈希才能与 DerivedCert::fingerprint 同口径
        Ok((_, cert)) => Sha256::digest(cert.public_key().subject_public_key.data.as_ref())
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect(),
        Err(_) => Sha256::digest(cert_der)
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let frame = encode_frame("DATA_NOTIFICATION", b"{\"a\":1}").expect("编码");
        let (header, payload, used) = decode_frame(&frame).expect("解码").expect("完整帧");
        assert_eq!(header, "DATA_NOTIFICATION");
        assert_eq!(payload, b"{\"a\":1}");
        assert_eq!(used, frame.len());
    }

    #[test]
    fn partial_frame_returns_none() {
        let frame = encode_frame("DATA_X", b"payload").expect("编码");
        // 截断到一半：应判定为「数据不足」而非错误
        assert!(decode_frame(&frame[..frame.len() / 2])
            .expect("解码")
            .is_none());
        assert!(decode_frame(&[]).expect("解码").is_none());
    }

    #[test]
    fn invalid_utf8_header_is_error() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&1u16.to_le_bytes());
        frame.push(0xFF);
        frame.extend_from_slice(&0u32.to_le_bytes());
        assert!(decode_frame(&frame).is_err());
    }

    #[test]
    fn oversized_payload_rejected() {
        let huge = vec![0u8; MAX_FRAME_LEN + 1];
        assert!(encode_frame("DATA_X", &huge).is_err());
    }

    /// 传输层可创建并正常关闭（不启动监听）。
    #[test]
    fn transport_lifecycle() {
        let t = QuicTransport::new().expect("创建传输层");
        assert!(!t.is_running());
        assert_eq!(t.connected_count(), 0);
        t.shutdown();
    }
}
