#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

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
