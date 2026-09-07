use std::collections::HashMap;
use std::io::BufReader;
use std::net::{SocketAddr, TcpListener, TcpStream};
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
}

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
                log::debug!("TCP扫描发现: uuid={}, ip={}", peer_uuid, ip);
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

    // 注册会话
    {
        let mut state = state.lock().unwrap();
        state.sessions.insert(
            uuid.clone(),
            TcpSession {
                stream: stream.try_clone().expect("克隆流失败"),
                uuid: uuid.clone(),
                ip: ip.clone(),
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

    {
        let mut state = state.lock().unwrap();
        state.sessions.remove(&uuid);
    }

    if let Some(ref cb) = on_disconnected {
        cb(uuid);
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

/// 获取本机局域网IP段的所有IP地址
pub fn get_local_subnet_ips() -> Vec<String> {
    use std::net::Ipv4Addr;

    let mut ips = Vec::new();

    // 获取本机IP地址
    if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if socket.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = socket.local_addr() {
                if let std::net::IpAddr::V4(ip) = addr.ip() {
                    let octets = ip.octets();
                    // 生成同子网的所有IP（/24子网）
                    for i in 1..=254 {
                        let subnet_ip = Ipv4Addr::new(octets[0], octets[1], octets[2], i);
                        ips.push(subnet_ip.to_string());
                    }
                }
            }
        }
    }

    // 如果无法获取本机IP，返回默认的C类网络
    if ips.is_empty() {
        for i in 1..=254 {
            ips.push(format!("192.168.1.{}", i));
        }
    }

    ips
}

/// TCP扫描发现：向指定IP发送发现请求并解析响应
/// 返回 (uuid, name_b64, port, battery, device_type)
pub fn tcp_scan_discover_single(
    ip: &str,
    discovery_request: &str,
    timeout_ms: u32,
) -> Option<(String, String, u16, i32, String)> {
    use crate::protocol::{binary_codec, header::MessageType};

    let addr = format!("{}:{}", ip, crate::protocol::codec::DEFAULT_TCP_PORT);
    let sock_addr = addr.parse::<std::net::SocketAddr>().ok()?;

    // 尝试TCP连接
    let stream =
        TcpStream::connect_timeout(&sock_addr, Duration::from_millis(timeout_ms as u64)).ok()?;

    stream
        .set_read_timeout(Some(Duration::from_millis(timeout_ms as u64)))
        .ok()?;
    stream
        .set_write_timeout(Some(Duration::from_millis(timeout_ms as u64)))
        .ok()?;

    // 发送发现请求（二进制帧格式）
    let frame =
        binary_codec::encode_pairing_frame(MessageType::DISCOVERY_REQUEST, discovery_request);
    {
        let mut writer = &stream;
        use std::io::Write;
        writer.write_all(&frame).ok()?;
        writer.flush().ok()?;
    }

    // 读取响应（二进制帧格式）
    let mut reader = BufReader::new(&stream);
    let (_msg_type, payload) = binary_codec::read_frame(&mut reader).ok()?;

    // 解析响应
    let response_text = std::str::from_utf8(&payload).ok()?;
    let trimmed = response_text.trim();
    if trimmed.is_empty() {
        return None;
    }

    crate::protocol::codec::decode_discovery_response(trimmed)
}

/// TCP扫描发现：并发扫描局域网IP段
pub fn tcp_scan_discover_all(
    discovery_request: &str,
    on_device_discovered: Option<
        Arc<dyn Fn(String, String, u16, i32, String, String) + Send + Sync>,
    >,
) {
    let ips = get_local_subnet_ips();
    let pool_size = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(20); // 限制最大并发数

    let pool = threadpool::ThreadPool::new(pool_size);
    let on_discovered = on_device_discovered;

    for ip in ips {
        let request = discovery_request.to_string();
        let cb = on_discovered.clone();

        pool.execute(move || {
            if let Some((uuid, name_b64, port, battery, device_type)) =
                tcp_scan_discover_single(&ip, &request, 3000)
            {
                if let Some(ref cb) = cb {
                    cb(uuid, name_b64, port, battery, device_type, ip);
                }
            }
        });
    }

    // 等待所有扫描完成
    pool.join();
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
