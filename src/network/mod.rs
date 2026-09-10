use std::collections::HashMap;
use std::io::BufReader;
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use threadpool::ThreadPool;

use crate::protocol::binary_codec;
use crate::protocol::header::MessageType;

/// 回调类型
type ConnectedCallback = Arc<dyn Fn(String, String) + Send + Sync>;
type DisconnectedCallback = Arc<dyn Fn(String) + Send + Sync>;
/// 消息回调: (uuid, msg_type, payload)
type MessageCallback = Arc<dyn Fn(String, u8, Vec<u8>) + Send + Sync>;
type ErrorCallback = Arc<dyn Fn(String) + Send + Sync>;

/// TCP 会话状态
pub struct TcpSession {
    pub stream: TcpStream,
    pub uuid: String,
    pub ip: String,
    /// 所属连接标识：同一 uuid 重连后旧连接退出时，
    /// 据此判断会话是否已属于新连接（避免误删新会话/误报断开）
    pub conn_id: u64,
}

/// 连接标识自增序列（每个 TCP 连接唯一）
static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);

/// TCP 服务器状态
pub struct TcpServerState {
    pub listener: Option<TcpListener>,
    pub sessions: HashMap<String, TcpSession>,
    pub running: bool,
    pub port: u16,
    /// 本机 uuid（运行期动态更新，用于 TCP 层拒绝自我连接）
    pub local_uuid: String,
    /// 广播信息副本（供发现请求响应使用）
    pub broadcast_info: Option<crate::BroadcastInfo>,
}

impl TcpServerState {
    pub fn new() -> Self {
        Self {
            listener: None,
            sessions: HashMap::new(),
            running: false,
            port: 0,
            local_uuid: String::new(),
            broadcast_info: None,
        }
    }

    /// 向指定设备发送二进制帧
    pub fn send_to_device(&mut self, uuid: &str, data: &[u8]) -> bool {
        if let Some(session) = self.sessions.get_mut(uuid) {
            match binary_codec::write_frame(&mut session.stream, data[0], &data[5..]) {
                Ok(_) => true,
                Err(e) => {
                    log::error!("发送消息失败 uuid={}, error={}", uuid, e);
                    false
                }
            }
        } else {
            log::warn!("设备未连接 uuid={}", uuid);
            false
        }
    }

    /// 通过已有 TCP 会话发送二进制帧（优先复用连接）
    /// 返回 Ok(true) 表示通过已有会话发送，Ok(false) 表示会话不存在（需 fallback）
    pub fn send_through_session(&mut self, uuid: &str, data: &[u8]) -> Result<bool, ()> {
        if let Some(session) = self.sessions.get_mut(uuid) {
            match binary_codec::write_frame(&mut session.stream, data[0], &data[5..]) {
                Ok(_) => Ok(true),
                Err(e) => {
                    log::warn!("通过已有会话发送失败 uuid={}, error={}, 移除会话", uuid, e);
                    self.sessions.remove(uuid);
                    Err(())
                }
            }
        } else {
            Ok(false)
        }
    }

    /// 广播二进制帧到所有连接的设备
    pub fn broadcast(&mut self, data: &[u8]) {
        let uuids: Vec<String> = self.sessions.keys().cloned().collect();
        for uuid in uuids {
            if let Some(session) = self.sessions.get_mut(&uuid) {
                if let Err(e) = binary_codec::write_frame(&mut session.stream, data[0], &data[5..])
                {
                    log::error!("广播消息失败 uuid={}, error={}", uuid, e);
                }
            }
        }
    }

    /// 获取在线设备数量
    pub fn connected_count(&self) -> i32 {
        self.sessions.len() as i32
    }

    /// 检查设备是否连接
    pub fn is_connected(&self, uuid: &str) -> bool {
        self.sessions.contains_key(uuid)
    }

    /// 移除设备会话
    pub fn remove_session(&mut self, uuid: &str) {
        self.sessions.remove(uuid);
    }
}

/// 网络状态（包含 TCP 服务器）
pub struct NetworkState {
    pub tcp: Arc<Mutex<TcpServerState>>,
}

impl NetworkState {
    pub fn new() -> Self {
        Self {
            tcp: Arc::new(Mutex::new(TcpServerState::new())),
        }
    }
}

/// 启动 TCP 服务器
pub fn start_tcp_server(
    state: Arc<Mutex<TcpServerState>>,
    port: u16,
    local_uuid: String,
    on_device_connected: Option<ConnectedCallback>,
    on_device_disconnected: Option<DisconnectedCallback>,
    on_message_received: Option<MessageCallback>,
    on_error: Option<ErrorCallback>,
) -> Result<(), String> {
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).map_err(|e| format!("绑定端口失败: {}", e))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("设置非阻塞失败: {}", e))?;

    {
        let mut state = state.lock().map_err(|e| format!("加锁失败: {}", e))?;
        state.listener = Some(listener);
        state.running = true;
        state.port = port;
        if !local_uuid.is_empty() {
            state.local_uuid = local_uuid;
        }
    }

    let pool_size = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let pool = Arc::new(ThreadPool::new(pool_size.max(2)));

    let state_clone = state.clone();
    let pool_clone = pool.clone();
    let on_connected = on_device_connected;
    let on_disconnected = on_device_disconnected;
    let on_message = on_message_received;
    let on_err = on_error;

    thread::spawn(move || {
        accept_loop(
            state_clone,
            pool_clone,
            on_connected,
            on_disconnected,
            on_message,
            on_err,
        );
    });

    log::info!(
        "TCP 服务器已启动，监听端口 {}，线程池大小 {}",
        port,
        pool_size
    );
    Ok(())
}

/// 更新本机 uuid（运行期由 FFI 层同步，保证 TCP 层自我连接拒绝始终有效）
pub fn set_local_uuid(state: Arc<Mutex<TcpServerState>>, uuid: &str) {
    if let Ok(mut state) = state.lock() {
        state.local_uuid = uuid.to_string();
    }
}

/// 同步广播信息到 TCP 服务器状态（供发现请求响应使用）
pub fn set_broadcast_info(state: Arc<Mutex<TcpServerState>>, info: Option<crate::BroadcastInfo>) {
    if let Ok(mut s) = state.lock() {
        s.broadcast_info = info;
    }
}

/// 接受连接循环
fn accept_loop(
    state: Arc<Mutex<TcpServerState>>,
    pool: Arc<ThreadPool>,
    on_connected: Option<ConnectedCallback>,
    on_disconnected: Option<DisconnectedCallback>,
    on_message: Option<MessageCallback>,
    on_error: Option<ErrorCallback>,
) {
    loop {
        let should_continue = {
            let state = state.lock().unwrap();
            state.running && state.listener.is_some()
        };

        if !should_continue {
            break;
        }

        let incoming = {
            let state = state.lock().unwrap();
            state.listener.as_ref().and_then(|l| l.accept().ok())
        };

        match incoming {
            Some((stream, addr)) => {
                let state_clone = state.clone();
                let on_connected = on_connected.clone();
                let on_disconnected = on_disconnected.clone();
                let on_message = on_message.clone();
                let on_err = on_error.clone();

                pool.execute(move || {
                    handle_connection(
                        stream,
                        addr,
                        state_clone,
                        on_connected,
                        on_disconnected,
                        on_message,
                        on_err,
                    );
                });
            }
            None => {
                thread::sleep(Duration::from_millis(5));
            }
        }
    }
}

/// 处理单个连接（二进制帧协议）
fn handle_connection(
    mut stream: TcpStream,
    addr: SocketAddr,
    state: Arc<Mutex<TcpServerState>>,
    on_connected: Option<ConnectedCallback>,
    on_disconnected: Option<DisconnectedCallback>,
    on_message: Option<MessageCallback>,
    on_error: Option<ErrorCallback>,
) {
    let ip = addr.ip().to_string();

    stream.set_nonblocking(false).expect("设置阻塞模式失败");

    let reader_stream = stream.try_clone().expect("克隆流失败");
    let mut reader = BufReader::new(reader_stream);

    // 读取第一帧（允许任意类型：HANDSHAKE / DATA / 配对 / 心跳 / 发现请求）
    let (first_type, first_payload) = match binary_codec::read_frame(&mut reader) {
        Ok(f) => f,
        Err(e) => {
            log::error!("读取第一帧失败: {}", e);
            if let Some(ref cb) = on_error {
                cb(format!("读取失败: {}", e));
            }
            return;
        }
    };

    // 发现请求：解析请求并回复本机发现响应，然后关闭连接
    if first_type == MessageType::DISCOVERY_REQUEST {
        let request_text = match std::str::from_utf8(&first_payload) {
            Ok(s) => s.trim(),
            Err(_) => {
                log::warn!("DISCOVERY_REQUEST payload 非 UTF-8");
                return;
            }
        };
        // 从请求中解析发送方信息，记录IP映射
        if let Some((peer_uuid, _name_b64, _port, _battery, _device_type)) =
            crate::protocol::codec::decode_discovery_request(request_text)
        {
            if !peer_uuid.is_empty() && !ip.is_empty() {
                log::debug!("收到 TCP 发现请求: uuid={}, ip={}", peer_uuid, ip);
            }
        }
        // 生成本机发现响应
        if let Ok(s) = state.lock() {
            if let Some(ref info) = s.broadcast_info {
                let response = crate::protocol::codec::encode_discovery_response(
                    &info.uuid,
                    &info.name_b64,
                    crate::protocol::codec::DEFAULT_TCP_PORT,
                    info.battery,
                    &info.device_type,
                );
                let resp_frame =
                    binary_codec::encode_pairing_frame(MessageType::DISCOVERY_RESPONSE, &response);
                use std::io::Write;
                let _ = stream.write_all(&resp_frame);
                let _ = stream.flush();
            }
        }
        return;
    }

    // 根据消息类型提取 UUID
    let uuid = match first_type {
        MessageType::HANDSHAKE => match binary_codec::decode_handshake_frame(&first_payload) {
            Some(h) => h.uuid,
            None => {
                log::warn!("HANDSHAKE 帧解码失败");
                return;
            }
        },
        MessageType::HEARTBEAT => match binary_codec::decode_heartbeat_frame(&first_payload) {
            Some(h) => h.uuid,
            None => {
                log::warn!("HEARTBEAT 帧解码失败");
                return;
            }
        },
        t if t >= 10 && t <= 200 => {
            // DATA 帧: DATA_TYPE:uuid:pub_key:encrypted_data
            match std::str::from_utf8(&first_payload) {
                Ok(s) => {
                    let parts: Vec<&str> = s.splitn(4, ':').collect();
                    if parts.len() >= 2 {
                        parts[1].to_string()
                    } else {
                        log::warn!("DATA 帧 payload 格式错误");
                        return;
                    }
                }
                Err(_) => {
                    log::warn!("DATA 帧 payload 非 UTF-8");
                    return;
                }
            }
        }
        MessageType::PAIRING_INIT | MessageType::PAIRING_RESP => {
            // 配对帧: uuid:...
            match std::str::from_utf8(&first_payload) {
                Ok(s) => {
                    let parts: Vec<&str> = s.splitn(2, ':').collect();
                    if !parts[0].is_empty() {
                        parts[0].to_string()
                    } else {
                        log::warn!("配对帧 UUID 为空");
                        return;
                    }
                }
                Err(_) => {
                    log::warn!("配对帧 payload 非 UTF-8");
                    return;
                }
            }
        }
        MessageType::ACCEPT | MessageType::REJECT => {
            // 控制帧: payload 就是 UUID
            match std::str::from_utf8(&first_payload) {
                Ok(s) => {
                    let uuid = s.trim().to_string();
                    if uuid.is_empty() {
                        log::warn!("控制帧 UUID 为空");
                        return;
                    }
                    uuid
                }
                Err(_) => {
                    log::warn!("控制帧 payload 非 UTF-8");
                    return;
                }
            }
        }
        _ => {
            log::warn!("第一帧类型不支持: type={}", first_type);
            return;
        }
    };

    // 拒绝本机发起的自我连接
    let local_uuid = state
        .lock()
        .map(|s| s.local_uuid.clone())
        .unwrap_or_default();
    if !local_uuid.is_empty() && uuid == local_uuid {
        return;
    }

    // 注册会话（带本连接唯一标识，供退出时判定归属）
    let conn_id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
    {
        let mut state = state.lock().unwrap();
        state.sessions.insert(
            uuid.clone(),
            TcpSession {
                stream: stream.try_clone().expect("克隆流失败"),
                uuid: uuid.clone(),
                ip: ip.clone(),
                conn_id,
            },
        );
    }

    if let Some(ref cb) = on_connected {
        cb(uuid.clone(), ip.clone());
    }

    // 回调第一帧
    if let Some(ref cb) = on_message {
        cb(uuid.clone(), first_type, first_payload);
    }

    // 持续读取二进制帧
    loop {
        match binary_codec::read_frame(&mut reader) {
            Ok((msg_type, payload)) => {
                if let Some(ref cb) = on_message {
                    cb(uuid.clone(), msg_type, payload);
                }
            }
            Err(e) => {
                if e.kind() != std::io::ErrorKind::UnexpectedEof {
                    log::error!("读取数据失败 uuid={}, error={}", uuid, e);
                    if let Some(ref cb) = on_error {
                        cb(format!("读取失败: {}", e));
                    }
                }
                break;
            }
        }
    }

    // 仅当会话仍属于本连接时才移除并上报断开：
    // 对端重连后新连接已覆盖同 uuid 会话，旧连接退出不得摘掉新会话
    let still_owner = {
        let mut state = state.lock().unwrap();
        let owned = state
            .sessions
            .get(&uuid)
            .map(|s| s.conn_id == conn_id)
            .unwrap_or(false);
        if owned {
            state.sessions.remove(&uuid);
        }
        owned
    };

    if still_owner {
        if let Some(ref cb) = on_disconnected {
            cb(uuid);
        }
    }
}

/// 移除设备会话（FFI 用）
pub fn remove_device_session(state: Arc<Mutex<TcpServerState>>, uuid: &str) {
    if let Ok(mut state) = state.lock() {
        state.remove_session(uuid);
    }
}

/// Oneshot TCP 发送二进制帧并接收二进制帧响应
pub fn oneshot_send_receive_bin(
    payload: &[u8],
    ip: &str,
    port: u16,
    timeout_ms: u32,
) -> Option<(u8, Vec<u8>)> {
    let addr = format!("{}:{}", ip, port);
    let sock_addr = addr.parse::<std::net::SocketAddr>().ok()?;
    let stream =
        TcpStream::connect_timeout(&sock_addr, Duration::from_millis(timeout_ms as u64)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(timeout_ms as u64)))
        .ok()?;
    stream
        .set_write_timeout(Some(Duration::from_millis(timeout_ms as u64)))
        .ok()?;
    binary_codec::write_frame(&mut &stream, payload[0], &payload[5..]).ok()?;
    let mut reader = BufReader::new(&stream);
    binary_codec::read_frame(&mut reader).ok()
}

/// Oneshot TCP 发送二进制帧（不等待响应）
pub fn oneshot_send_only(payload: &[u8], ip: &str, port: u16, timeout_ms: u32) -> bool {
    let addr = format!("{}:{}", ip, port);
    let sock_addr = match addr.parse::<std::net::SocketAddr>() {
        Ok(a) => a,
        Err(_) => {
            log::warn!("oneshot_send_only: 地址解析失败 addr={}", addr);
            return false;
        }
    };
    let stream =
        match TcpStream::connect_timeout(&sock_addr, Duration::from_millis(timeout_ms as u64)) {
            Ok(s) => s,
            Err(e) => {
                log::debug!("oneshot_send_only: 连接失败 addr={}, err={}", addr, e);
                return false;
            }
        };
    stream
        .set_write_timeout(Some(Duration::from_millis(timeout_ms as u64)))
        .ok();
    let mut writer = &stream;
    if binary_codec::write_frame(&mut writer, payload[0], &payload[5..]).is_err() {
        log::debug!("oneshot_send_only: 写入失败 addr={}", addr);
        return false;
    }
    true
}

/// UDP 广播发现端口（与 TCP 数据端口 codec::DEFAULT_TCP_PORT=23333 并存）。
/// 所有设备均监听该端口，并周期向该端口广播自身发现信息。
pub const UDP_BROADCAST_PORT: u16 = 23334;

/// 创建 UDP 广播发送 socket（绑定临时端口并开启广播）。
/// 与监听 socket 分离，避免向广播地址发送的包回环到自身监听路径。
pub fn create_udp_broadcast_socket() -> Result<UdpSocket, String> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| format!("创建 UDP 广播发送 socket 失败: {}", e))?;
    socket
        .set_broadcast(true)
        .map_err(|e| format!("设置 UDP 广播失败: {}", e))?;
    Ok(socket)
}

/// 创建 UDP 广播发现监听 socket（绑定 UDP_BROADCAST_PORT，接收其他设备的广播）。
/// 设置 100ms 读超时，使发现线程可在「定时广播」与「持续监听」之间及时切换。
///
/// 显式开启 SO_REUSEADDR：网络变化时平台会 stopDiscovery→startDiscovery 立刻重启发现线程，
/// 旧线程的监听 socket 可能尚未释放，若不允许地址复用，新线程绑定会失败并永久退化为
/// 「仅发送」（此后收不到任何对端广播，表现为对端全部离线）。
pub fn bind_udp_discovery_listener() -> Result<UdpSocket, String> {
    let addr = format!("0.0.0.0:{}", UDP_BROADCAST_PORT)
        .parse::<SocketAddr>()
        .map_err(|e| format!("解析 UDP 发现监听地址失败: {}", e))?;

    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .map_err(|e| format!("创建 UDP 发现监听 socket 失败: {}", e))?;
    socket
        .set_reuse_address(true)
        .map_err(|e| format!("设置 UDP 监听地址复用失败: {}", e))?;
    socket
        .bind(&addr.into())
        .map_err(|e| format!("绑定 UDP 发现监听端口 {} 失败: {}", UDP_BROADCAST_PORT, e))?;

    let socket: UdpSocket = socket.into();
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .map_err(|e| format!("设置 UDP 监听读超时失败: {}", e))?;
    Ok(socket)
}

/// 发送 UDP 广播发现消息：
/// 1. 先向 255.255.255.255 有限广播；
/// 2. 再向各非回环 IPv4 网卡的子网广播地址各发一次
///    （部分 Android ROM 与多网卡 Windows 会忽略有限广播，仅走默认路由那个接口）。
///
/// 两类广播相互独立：有限广播失败（Android 上默认路由为蜂窝/存在多网卡时返回
/// `Network is unreachable` 属常见情况）不得短路子网定向广播，否则设备将一条发现
/// 报文都发不出，对端永久看不到本机。
pub fn send_udp_discovery_broadcast(socket: &UdpSocket, message: &str) -> Result<(), String> {
    let data = message.as_bytes();
    let limited = socket
        .send_to(data, format!("255.255.255.255:{}", UDP_BROADCAST_PORT))
        .map(|_| ())
        .map_err(|e| format!("UDP 有限广播失败: {}", e));

    if let Err(e) = &limited {
        log::debug!("UDP 广播发现: 有限广播失败，改由子网定向广播兜底: {}", e);
    }
    send_to_all_subnets(socket, data)
}

/// 向所有非回环 IPv4 网卡的子网广播地址各发一次（PC 与 Android 共用同一份跨平台实现）。
/// 部分 Android ROM 与多网卡 Windows 会忽略 255.255.255.255 有限广播，仅走默认路由接口，
/// 补发子网定向广播可覆盖其余网卡。
fn send_to_all_subnets(socket: &UdpSocket, data: &[u8]) -> Result<(), String> {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr as StdSocketAddr};

    let interfaces =
        local_ip_address::list_afinet_netifas().map_err(|e| format!("枚举本机网卡失败: {}", e))?;

    for (_name, ip) in interfaces {
        let ip = match ip {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => continue,
        };
        if ip.is_loopback() || ip.is_unspecified() {
            continue;
        }

        let ip_bytes = ip.octets();
        let broadcast = Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], 255);
        let broadcast_addr = StdSocketAddr::new(IpAddr::V4(broadcast), UDP_BROADCAST_PORT);

        if let Err(e) = socket.send_to(data, broadcast_addr) {
            log::warn!("向子网 {} 广播失败: {}", broadcast, e);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send_to_device_not_connected() {
        let mut state = TcpServerState::new();
        // 构造一个最小二进制帧: type=0xFF, length=0
        let frame = vec![0xFF, 0, 0, 0, 0];
        let result = state.send_to_device("test-uuid", &frame);
        assert!(!result);
    }

    #[test]
    fn test_remove_device_session_not_exists() {
        let state = Arc::new(Mutex::new(TcpServerState::new()));
        remove_device_session(state.clone(), "test-uuid");
    }
}
