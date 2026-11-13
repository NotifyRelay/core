//! 平台回调集合。
//!
//! 内部以 `Arc<dyn Fn>` 闭包持有，注册方（UniFFI 导出层或 C ABI 委托层）负责把
//! 平台对象包装成闭包；内部调用点只传 Rust 类型，不再涉及 C 字符串与 `user_data`。

use std::sync::Arc;

/// 配对/握手过程消息。
///
/// 参数：`(device_uuid, message_type, data, int_value, extra)`。
/// `message_type` 取值："HANDSHAKE" / "PAIRING_INIT" / "PAIRING_RESP" / "ACCEPT" /
/// "REJECT" / "HEARTBEAT_TCP" / "RESULT"。
pub type OnPairing = Arc<dyn Fn(&str, &str, &str, i32, &str) + Send + Sync>;

/// 入站数据报文；`message_type` 如 "NOTIFICATION" / "MEDIAPLAY" / "ICON_REQUEST"。
pub type OnData = Arc<dyn Fn(&str, &str, &str) + Send + Sync>;

/// 状态查询（心跳线程锁外调用）。
///
/// 返回 0=该会话在平台不存在（引擎应移除会话）、1=存在且无变更、2=存在且有变更。
pub type OnStateQuery = Arc<dyn Fn(&str, &str, bool) -> i32 + Send + Sync>;

/// 设备超时（离线）。
pub type OnDeviceTimeout = Arc<dyn Fn(&str) + Send + Sync>;

/// 设备已连接。
pub type OnDeviceConnected = Arc<dyn Fn(&str, &str) + Send + Sync>;

/// 设备已断开。
pub type OnDeviceDisconnected = Arc<dyn Fn(&str) + Send + Sync>;

/// TCP 层错误。
pub type OnTcpError = Arc<dyn Fn(&str) + Send + Sync>;

/// 发现新设备；`name_b64` 为设备名的 base64 编码。
pub type OnDeviceDiscovered = Arc<dyn Fn(&str, &str, u16, i32, &str, &str) + Send + Sync>;

pub struct Router {
    pub on_pairing: Option<OnPairing>,
    pub on_data: Option<OnData>,
    pub on_state_query: Option<OnStateQuery>,

    pub on_device_discovered: Option<OnDeviceDiscovered>,
    pub on_device_timeout: Option<OnDeviceTimeout>,
    pub on_device_connected: Option<OnDeviceConnected>,
    pub on_device_disconnected: Option<OnDeviceDisconnected>,
    pub on_tcp_error: Option<OnTcpError>,
}

impl Router {
    pub fn new() -> Self {
        Self {
            on_pairing: None,
            on_data: None,
            on_state_query: None,
            on_device_discovered: None,
            on_device_timeout: None,
            on_device_connected: None,
            on_device_disconnected: None,
            on_tcp_error: None,
        }
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}
