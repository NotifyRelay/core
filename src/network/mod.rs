use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::protocol::codec;
use crate::heartbeat;

/// 回调类型
type ConnectedCallback = Arc<dyn Fn(String, String) + Send + Sync>;
type DisconnectedCallback = Arc<dyn Fn(String) + Send + Sync>;
type MessageCallback = Arc<dyn Fn(String, String) + Send + Sync>;
type ErrorCallback = Arc<dyn Fn(String) + Send + Sync>;

/// UDP 心跳回调（新增 String 参数为源 IP）
type UdpHeartbeatCallback = Arc<dyn Fn(String, String, u16, i32, String, String) + Send + Sync>;

/// TCP 会话状态
pub struct TcpSession {
    pub stream: TcpStream,
    pub uuid: String,
    pub ip: String,
    pub buffer: String,
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
}

impl TcpServerState {
    pub fn new() -> Self {
        Self {
            listener: None,
            sessions: HashMap::new(),
            running: false,
            port: 0,
            udp_handle: None,
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
    // 停止 UDP 监听
    if let Some(handle) = state.udp_handle.take() {
        if let Ok(mut running) = handle.running.lock() {
            *running = false;
        }
    }
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
                thread::sleep(Duration::from_millis(10));
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

    stream.set_nonblocking(false).expect("设置阻塞模式失败");

    let reader_stream = stream.try_clone().expect("克隆流失败");
    let mut reader = BufReader::new(reader_stream);
    let mut buffer = String::new();
    let mut uuid = String::new();

    match reader.read_line(&mut buffer) {
        Ok(0) => return,
        Ok(_) => {
            let line = buffer.trim().to_string();
            buffer.clear();

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

            log::info!("TCP连接已建立 uuid={}, ip={}", uuid, ip);

            {
                let mut state = state.lock().unwrap();
                state.sessions.insert(uuid.clone(), TcpSession {
                    stream: stream.try_clone().expect("克隆流失败"),
                    uuid: uuid.clone(),
                    ip: ip.clone(),
                    buffer: String::new(),
                });
            }

            if let Some(ref cb) = on_connected {
                cb(uuid.clone(), ip.clone());
            }

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

    loop {
        buffer.clear();
        match reader.read_line(&mut buffer) {
            Ok(0) => break,
            Ok(_) => {
                let line = buffer.trim().to_string();
                if !line.is_empty() {
                    if let Some(data) = codec::decode_data_message(&line) {
                        log::info!("收到 TCP DATA: local_uuid={}, payload_len={}, from={}", 
                            data.local_uuid, data.encrypted_payload.len(), addr);
                    }
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

    {
        let mut state = state.lock().unwrap();
        state.sessions.remove(&uuid);
    }

    log::info!("TCP连接已断开 uuid={}", uuid);

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
    let socket = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| format!("绑定 UDP 失败: {}", e))?;
    socket.set_broadcast(true)
        .map_err(|e| format!("设置广播失败: {}", e))?;

    let data = message.as_bytes();

    socket.send_to(data, format!("255.255.255.255:{}", UDP_BROADCAST_PORT))
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
    let socket = UdpSocket::bind(&addr)
        .map_err(|e| format!("绑定 UDP 监听端口 {} 失败: {}", port, e))?;
    socket.set_read_timeout(Some(Duration::from_secs(1)))
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
                    // 超时是正常的，继续循环
                    if e.kind() != std::io::ErrorKind::WouldBlock
                        && e.kind() != std::io::ErrorKind::TimedOut
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

/// Oneshot TCP 发送并接收响应，内部通过 process_line 处理响应
pub fn oneshot_send_receive(
    payload: &str,
    ip: &str,
    port: u16,
    timeout_ms: u32,
) -> Option<String> {
    let addr = format!("{}:{}", ip, port);
    let sock_addr = addr.parse::<std::net::SocketAddr>().ok()?;
    let stream = TcpStream::connect_timeout(&sock_addr, Duration::from_millis(timeout_ms as u64)).ok()?;
    stream.set_read_timeout(Some(Duration::from_millis(timeout_ms as u64))).ok()?;
    stream.set_write_timeout(Some(Duration::from_millis(timeout_ms as u64))).ok()?;
    let mut writer = &stream;
    writer.write_all(format!("{}\n", payload).as_bytes()).ok()?;
    writer.flush().ok()?;
    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let trimmed = line.trim().to_string();
    if trimmed.is_empty() { None } else { Some(trimmed) }
}

/// Oneshot TCP 发送（不等待响应）
pub fn oneshot_send_only(payload: &str, ip: &str, port: u16, timeout_ms: u32) -> bool {
    let addr = format!("{}:{}", ip, port);
    let sock_addr = match addr.parse::<std::net::SocketAddr>() {
        Ok(a) => a,
        Err(_) => {
            log::warn!("oneshot_send_only: 地址解析失败 addr={}", addr);
            return false;
        }
    };
    let stream = match TcpStream::connect_timeout(&sock_addr, Duration::from_millis(timeout_ms as u64)) {
        Ok(s) => s,
        Err(e) => {
            log::debug!("oneshot_send_only: 连接失败 addr={}, err={}", addr, e);
            return false;
        }
    };
    stream.set_write_timeout(Some(Duration::from_millis(timeout_ms as u64))).ok();
    let data = format!("{}\n", payload);
    let mut writer = &stream;
    if writer.write_all(data.as_bytes()).is_err() || writer.flush().is_err() {
        log::debug!("oneshot_send_only: 写入失败 addr={}", addr);
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_server_start_stop() {
        let state = Arc::new(Mutex::new(TcpServerState::new()));
        let port = 12345;

        let result = start_tcp_server(
            state.clone(),
            port,
            None,
            None,
            None,
            None,
        );
        assert!(result.is_ok());

        {
            let state = state.lock().unwrap();
            assert!(state.running);
            assert_eq!(state.port, port);
        }

        let result = stop_tcp_server(state.clone());
        assert!(result.is_ok());

        {
            let state = state.lock().unwrap();
            assert!(!state.running);
        }
    }

    #[test]
    fn test_send_to_device_not_connected() {
        let state = Arc::new(Mutex::new(TcpServerState::new()));
        let result = send_to_device(state.clone(), "test-uuid", "test message");
        assert!(!result);
    }

    #[test]
    fn test_broadcast_message_empty() {
        let state = Arc::new(Mutex::new(TcpServerState::new()));
        broadcast_message(state.clone(), "test broadcast");
    }

    #[test]
    fn test_get_connected_count_empty() {
        let state = Arc::new(Mutex::new(TcpServerState::new()));
        let count = get_connected_count(state.clone());
        assert_eq!(count, 0);
    }

    #[test]
    fn test_is_device_connected_false() {
        let state = Arc::new(Mutex::new(TcpServerState::new()));
        let connected = is_device_connected(state.clone(), "test-uuid");
        assert!(!connected);
    }

    #[test]
    fn test_remove_device_session_not_exists() {
        let state = Arc::new(Mutex::new(TcpServerState::new()));
        remove_device_session(state.clone(), "test-uuid");
    }
}
