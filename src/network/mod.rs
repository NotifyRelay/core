use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream, SocketAddr};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::protocol::codec;

/// 回调类型
type ConnectedCallback = Arc<dyn Fn(String, String) + Send + Sync>;
type DisconnectedCallback = Arc<dyn Fn(String) + Send + Sync>;
type MessageCallback = Arc<dyn Fn(String, String) + Send + Sync>;
type ErrorCallback = Arc<dyn Fn(String) + Send + Sync>;

/// TCP 会话状态
pub struct TcpSession {
    pub stream: TcpStream,
    pub uuid: String,
    pub ip: String,
    pub buffer: String,
}

/// TCP 服务器状态
pub struct TcpServerState {
    pub listener: Option<TcpListener>,
    pub sessions: HashMap<String, TcpSession>,
    pub running: bool,
    pub port: u16,
}

impl TcpServerState {
    pub fn new() -> Self {
        Self {
            listener: None,
            sessions: HashMap::new(),
            running: false,
            port: 0,
        }
    }

    /// 向指定设备发送消息
    pub fn send_to_device(&mut self, uuid: &str, message: &str) -> bool {
        if let Some(session) = self.sessions.get_mut(uuid) {
            let data = format!("{}\n", message);
            match session.stream.write_all(data.as_bytes()) {
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

    /// 广播消息到所有连接的设备
    pub fn broadcast(&mut self, message: &str) {
        let data = format!("{}\n", message);
        let uuids: Vec<String> = self.sessions.keys().cloned().collect();
        for uuid in uuids {
            if let Some(session) = self.sessions.get_mut(&uuid) {
                if let Err(e) = session.stream.write_all(data.as_bytes()) {
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
    on_device_connected: Option<ConnectedCallback>,
    on_device_disconnected: Option<DisconnectedCallback>,
    on_message_received: Option<MessageCallback>,
    on_error: Option<ErrorCallback>,
) -> Result<(), String> {
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).map_err(|e| format!("绑定端口失败: {}", e))?;
    listener.set_nonblocking(true).map_err(|e| format!("设置非阻塞失败: {}", e))?;

    {
        let mut state = state.lock().map_err(|e| format!("加锁失败: {}", e))?;
        state.listener = Some(listener);
        state.running = true;
        state.port = port;
    }

    let state_clone = state.clone();
    let on_connected = on_device_connected;
    let on_disconnected = on_device_disconnected;
    let on_message = on_message_received;
    let on_err = on_error;

    thread::spawn(move || {
        accept_loop(state_clone, on_connected, on_disconnected, on_message, on_err);
    });

    log::info!("TCP 服务器已启动，监听端口 {}", port);
    Ok(())
}

/// 停止 TCP 服务器
pub fn stop_tcp_server(state: Arc<Mutex<TcpServerState>>) -> Result<(), String> {
    let mut state = state.lock().map_err(|e| format!("加锁失败: {}", e))?;
    state.running = false;
    state.listener = None;
    state.sessions.clear();
    log::info!("TCP 服务器已停止");
    Ok(())
}

/// 接受连接循环
fn accept_loop(
    state: Arc<Mutex<TcpServerState>>,
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
                log::info!("接受新连接: {}", addr);
                let state_clone = state.clone();
                let on_connected = on_connected.clone();
                let on_disconnected = on_disconnected.clone();
                let on_message = on_message.clone();
                let on_err = on_error.clone();

                thread::spawn(move || {
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
                thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }
}

/// 处理单个连接
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

    // 将 accepted socket 设回阻塞模式
    stream.set_nonblocking(false).expect("设置阻塞模式失败");

    let reader_stream = stream.try_clone().expect("克隆流失败");
    let mut reader = BufReader::new(reader_stream);
    let mut buffer = String::new();
    let mut uuid = String::new();

    // 读取第一行获取设备 UUID
    match reader.read_line(&mut buffer) {
        Ok(0) => {
            log::info!("连接立即关闭: {}", addr);
            return;
        }
        Ok(_) => {
            let line = buffer.trim().to_string();
            buffer.clear();

            // 从任意消息中提取 UUID（第二字段）
            // 格式: HEADER:uuid:... 或 HANDSHAKE:uuid:...
            if let Some(f) = codec::decode_handshake(&line) {
                uuid = f.uuid.to_string();
            } else if let Some(pos) = line.find(':') {
                let rest = &line[pos + 1..];
                if let Some(end) = rest.find(':') {
                    uuid = rest[..end].to_string();
                } else if !rest.is_empty() {
                    uuid = rest.to_string();
                }
            }

            if uuid.is_empty() {
                log::warn!("无法从消息中提取 UUID: {}", &line[..line.len().min(80)]);
                return;
            }

            log::info!("设备已连接: uuid={}, ip={}, 第一行={}", uuid, ip, &line[..line.len().min(40)]);

            // 添加到会话
            {
                let mut state = state.lock().unwrap();
                state.sessions.insert(uuid.clone(), TcpSession {
                    stream: stream.try_clone().expect("克隆流失败"),
                    uuid: uuid.clone(),
                    ip: ip.clone(),
                    buffer: String::new(),
                });
            }

            // 通知设备连接
            if let Some(ref cb) = on_connected {
                cb(uuid.clone(), ip.clone());
            }

            // 处理第一行消息
            if let Some(ref cb) = on_message {
                cb(uuid.clone(), line);
            }
        }
        Err(e) => {
            log::error!("读取第一行失败: {}", e);
            if let Some(ref cb) = on_error {
                cb(format!("读取失败: {}", e));
            }
            return;
        }
    }

    // 继续读取后续消息
    loop {
        buffer.clear();
        match reader.read_line(&mut buffer) {
            Ok(0) => {
                log::info!("连接关闭: uuid={}, ip={}", uuid, ip);
                break;
            }
            Ok(_) => {
                let line = buffer.trim().to_string();
                if !line.is_empty() {
                    if let Some(ref cb) = on_message {
                        cb(uuid.clone(), line);
                    }
                }
            }
            Err(e) => {
                log::error!("读取数据失败 uuid={}, error={}", uuid, e);
                if let Some(ref cb) = on_error {
                    cb(format!("读取失败: {}", e));
                }
                break;
            }
        }
    }

    // 清理会话
    {
        let mut state = state.lock().unwrap();
        state.sessions.remove(&uuid);
    }

    // 通知设备断开
    if let Some(ref cb) = on_disconnected {
        cb(uuid);
    }
}

/// 发送消息到指定设备（FFI 用）
pub fn send_to_device(state: Arc<Mutex<TcpServerState>>, uuid: &str, message: &str) -> bool {
    match state.lock() {
        Ok(mut state) => state.send_to_device(uuid, message),
        Err(e) => {
            log::error!("加锁失败: {}", e);
            false
        }
    }
}

/// 广播消息（FFI 用）
pub fn broadcast_message(state: Arc<Mutex<TcpServerState>>, message: &str) {
    if let Ok(mut state) = state.lock() {
        state.broadcast(message);
    }
}

/// 获取在线设备数量（FFI 用）
pub fn get_connected_count(state: Arc<Mutex<TcpServerState>>) -> i32 {
    match state.lock() {
        Ok(state) => state.connected_count(),
        Err(_) => 0,
    }
}

/// 检查设备是否连接（FFI 用）
pub fn is_device_connected(state: Arc<Mutex<TcpServerState>>, uuid: &str) -> bool {
    match state.lock() {
        Ok(state) => state.is_connected(uuid),
        Err(_) => false,
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
    use std::net::UdpSocket;

    let socket = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| format!("绑定 UDP 失败: {}", e))?;
    socket.set_broadcast(true)
        .map_err(|e| format!("设置广播失败: {}", e))?;

    let data = message.as_bytes();

    // 发送有限广播作为兜底
    socket.send_to(data, format!("255.255.255.255:{}", UDP_BROADCAST_PORT))
        .map_err(|e| format!("有限广播失败: {}", e))?;

    // Android/Linux: 使用 getifaddrs 枚举网络接口，发送定向广播
    #[cfg(target_os = "android")]
    {
        send_to_all_subnets(&socket, data)?;
    }

    Ok(())
}

/// 向所有子网发送定向广播（Android/Linux）
#[cfg(target_os = "android")]
fn send_to_all_subnets(socket: &std::net::UdpSocket, data: &[u8]) -> Result<(), String> {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    unsafe {
        let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifaddrs) != 0 {
            return Err("getifaddrs 失败".to_string());
        }

        let mut ptr = ifaddrs;
        while !ptr.is_null() {
            let entry = &*ptr;

            // 只处理 IPv4 地址
            if !entry.ifa_addr.is_null() {
                let addr = entry.ifa_addr;
                if (*addr).sa_family == libc::AF_INET as libc::sa_family_t {
                    let sockaddr = &*(addr as *const libc::sockaddr_in);
                    let ip = Ipv4Addr::from(sin_addr_to_bytes(sockaddr.sin_addr));

                    // 跳过回环地址和 0.0.0.0
                    if !ip.is_loopback() && !ip.is_unspecified() {
                        // 计算子网广播地址（假设 /24 子网）
                        let ip_bytes = ip.octets();
                        let broadcast = Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], 255);
                        let broadcast_addr = SocketAddr::new(IpAddr::V4(broadcast), UDP_BROADCAST_PORT);

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

/// 将 sin_addr 转换为字节数组
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

use std::time::Duration;

pub fn oneshot_send_receive(ip: &str, port: u16, payload: &str, connect_timeout_ms: u32, read_timeout_ms: u32) -> Option<String> {
    let addr = format!("{}:{}", ip, port);
    let stream = TcpStream::connect_timeout(&addr.parse().ok()?, Duration::from_millis(connect_timeout_ms as u64)).ok()?;
    stream.set_read_timeout(Some(Duration::from_millis(read_timeout_ms as u64))).ok()?;
    let mut writer = &stream;
    writer.write_all(format!("{}\n", payload).as_bytes()).ok()?;
    writer.flush().ok()?;
    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let trimmed = line.trim().to_string();
    if trimmed.is_empty() { None } else { Some(trimmed) }
}

pub fn oneshot_send_only(ip: &str, port: u16, payload: &str, connect_timeout_ms: u32) -> bool {
    let addr = format!("{}:{}", ip, port);
    let stream = match TcpStream::connect_timeout(&addr.parse().ok().unwrap(), Duration::from_millis(connect_timeout_ms as u64)) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let mut writer = &stream;
    writer.write_all(format!("{}\n", payload).as_bytes()).is_ok() && writer.flush().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_server_start_stop() {
        let state = Arc::new(Mutex::new(TcpServerState::new()));
        let port = 12345;

        // 启动服务器
        let result = start_tcp_server(
            state.clone(),
            port,
            None,
            None,
            None,
            None,
        );
        assert!(result.is_ok());

        // 验证服务器已启动
        {
            let state = state.lock().unwrap();
            assert!(state.running);
            assert_eq!(state.port, port);
        }

        // 停止服务器
        let result = stop_tcp_server(state.clone());
        assert!(result.is_ok());

        // 验证服务器已停止
        {
            let state = state.lock().unwrap();
            assert!(!state.running);
        }
    }

    #[test]
    fn test_send_to_device_not_connected() {
        let state = Arc::new(Mutex::new(TcpServerState::new()));

        // 尝试向未连接的设备发送消息
        let result = send_to_device(state.clone(), "test-uuid", "test message");
        assert!(!result);
    }

    #[test]
    fn test_broadcast_message_empty() {
        let state = Arc::new(Mutex::new(TcpServerState::new()));

        // 广播消息到空的设备列表
        broadcast_message(state.clone(), "test broadcast");
        // 不应崩溃
    }

    #[test]
    fn test_get_connected_count_empty() {
        let state = Arc::new(Mutex::new(TcpServerState::new()));

        // 获取在线设备数量
        let count = get_connected_count(state.clone());
        assert_eq!(count, 0);
    }

    #[test]
    fn test_is_device_connected_false() {
        let state = Arc::new(Mutex::new(TcpServerState::new()));

        // 检查设备是否连接
        let connected = is_device_connected(state.clone(), "test-uuid");
        assert!(!connected);
    }

    #[test]
    fn test_remove_device_session_not_exists() {
        let state = Arc::new(Mutex::new(TcpServerState::new()));

        // 移除不存在的设备会话
        remove_device_session(state.clone(), "test-uuid");
        // 不应崩溃
    }
}
