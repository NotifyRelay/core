use std::collections::HashMap;
use std::io::BufReader;
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use threadpool::ThreadPool;

use crate::heartbeat;
use crate::protocol::binary_codec;
use crate::protocol::header::MessageType;

/// 回调类型
type ConnectedCallback = Arc<dyn Fn(String, String) + Send + Sync>;
type DisconnectedCallback = Arc<dyn Fn(String) + Send + Sync>;
/// 消息回调: (uuid, msg_type, payload)
type MessageCallback = Arc<dyn Fn(String, u8, Vec<u8>) + Send + Sync>;
type ErrorCallback = Arc<dyn Fn(String) + Send + Sync>;

/// UDP 心跳回调（新增 String 参数为源 IP）
type UdpHeartbeatCallback = Arc<dyn Fn(String, String, u16, i32, String, String) + Send + Sync>;

/// TCP 会话状态
pub struct TcpSession {
    pub stream: TcpStream,
    pub uuid: String,
    pub ip: String,
}

/// UDP 监听器状态
pub struct UdpListenerHandle {
    pub running: Arc<Mutex<bool>>,
}

/// TCP 服务器状态
pub struct TcpServerState {
    pub listener: Option<TcpListener>,
    pub sessions: HashMap<String, TcpSession>,
    pub running: bool,
    pub port: u16,
    pub udp_handle: Option<UdpListenerHandle>,
    /// 本机 uuid（运行期动态更新，用于 TCP 层拒绝自我连接）
    pub local_uuid: String,
}

impl TcpServerState {
    pub fn new() -> Self {
        Self {
            listener: None,
            sessions: HashMap::new(),
            running: false,
            port: 0,
            udp_handle: None,
            local_uuid: String::new(),
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
    stream: TcpStream,
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

    // 读取第一帧（允许任意类型：HANDSHAKE / DATA / 配对 / 心跳）
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

/// UDP 广播端口
const UDP_BROADCAST_PORT: u16 = 23334;

/// 发送 UDP 广播消息（支持多子网）
pub fn send_udp_broadcast(message: &str) -> Result<(), String> {
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("绑定 UDP 失败: {}", e))?;
    socket
        .set_broadcast(true)
        .map_err(|e| format!("设置广播失败: {}", e))?;

    let data = message.as_bytes();

    socket
        .send_to(data, format!("255.255.255.255:{}", UDP_BROADCAST_PORT))
        .map_err(|e| format!("有限广播失败: {}", e))?;

    #[cfg(target_os = "android")]
    {
        send_to_all_subnets(&socket, data)?;
    }

    Ok(())
}

/// 向所有子网发送定向广播（Android/Linux）
#[cfg(target_os = "android")]
fn send_to_all_subnets(socket: &UdpSocket, data: &[u8]) -> Result<(), String> {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    unsafe {
        let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifaddrs) != 0 {
            return Err("getifaddrs 失败".to_string());
        }

        let mut ptr = ifaddrs;
        while !ptr.is_null() {
            let entry = &*ptr;

            if !entry.ifa_addr.is_null() {
                let addr = entry.ifa_addr;
                if (*addr).sa_family == libc::AF_INET as libc::sa_family_t {
                    let sockaddr = &*(addr as *const libc::sockaddr_in);
                    let ip = Ipv4Addr::from(sin_addr_to_bytes(sockaddr.sin_addr));

                    if !ip.is_loopback() && !ip.is_unspecified() {
                        let ip_bytes = ip.octets();
                        let broadcast = Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], 255);
                        let broadcast_addr =
                            SocketAddr::new(IpAddr::V4(broadcast), UDP_BROADCAST_PORT);

                        if let Err(e) = socket.send_to(data, broadcast_addr) {
                            log::warn!("向子网 {} 广播失败: {}", broadcast, e);
                        }
                    }
                }
            }

            ptr = (*entry).ifa_next;
        }

        libc::freeifaddrs(ifaddrs);
    }

    Ok(())
}

#[cfg(target_os = "android")]
unsafe fn sin_addr_to_bytes(addr: libc::in_addr) -> [u8; 4] {
    let s_addr = addr.s_addr;
    [
        (s_addr & 0xFF) as u8,
        ((s_addr >> 8) & 0xFF) as u8,
        ((s_addr >> 16) & 0xFF) as u8,
        ((s_addr >> 24) & 0xFF) as u8,
    ]
}

/// 启动 UDP 监听器，绑定到指定端口接收心跳广播
pub fn start_udp_listener(
    port: u16,
    on_heartbeat: Option<UdpHeartbeatCallback>,
    on_error: Option<ErrorCallback>,
) -> Result<Arc<Mutex<bool>>, String> {
    let addr = format!("0.0.0.0:{}", port);
    let socket =
        UdpSocket::bind(&addr).map_err(|e| format!("绑定 UDP 监听端口 {} 失败: {}", port, e))?;
    socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .map_err(|e| format!("设置 UDP 超时失败: {}", e))?;

    let running = Arc::new(Mutex::new(true));
    let running_clone = running.clone();

    thread::spawn(move || {
        let mut buf = [0u8; 2048];
        loop {
            let should_run = match running_clone.lock() {
                Ok(r) => *r,
                Err(_) => break,
            };
            if !should_run {
                break;
            }

            match socket.recv_from(&mut buf) {
                Ok((n, src)) => {
                    let src_ip = src.ip().to_string();
                    let line = match String::from_utf8_lossy(&buf[..n]).trim().to_string() {
                        s if s.is_empty() => continue,
                        s => s,
                    };
                    if let Some(ref cb) = on_heartbeat {
                        if let Some((uuid, name_b64, hb_port, battery, device_type)) =
                            heartbeat::parse_udp_heartbeat(&line)
                        {
                            cb(uuid, name_b64, hb_port, battery, device_type, src_ip);
                        }
                    }
                }
                Err(e) => {
                    // 超时和 EINTR(锁屏等信号中断)是正常的，继续循环
                    if e.kind() != std::io::ErrorKind::WouldBlock
                        && e.kind() != std::io::ErrorKind::TimedOut
                        && e.kind() != std::io::ErrorKind::Interrupted
                    {
                        log::debug!("UDP 接收错误: {}", e);
                        if let Some(ref cb) = on_error {
                            cb(format!("UDP 接收错误: {}", e));
                        }
                    }
                }
            }
        }
        log::debug!("UDP 监听线程已退出");
    });

    log::info!("UDP 监听器已启动，端口 {}", port);
    Ok(running)
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
