use std::os::raw::c_char;
use std::os::raw::c_void;

pub type OnHandshakeCb =
    Option<extern "C" fn(*const c_char, *const c_char, *const c_char, i32, *const c_char, *mut c_void)>;
pub type OnPairingInitCb =
    Option<extern "C" fn(*const c_char, *const c_char, *const c_char, i32, *const c_char, *mut c_void)>;
pub type OnPairingRespCb = Option<
    extern "C" fn(
        *const c_char,
        *const c_char,
        *const c_char,
        *const c_char,
        *const c_char,
        i32,
        *const c_char,
        *mut c_void,
    ),
>;
pub type OnAcceptCb =
    Option<extern "C" fn(*const c_char, *const c_char, *const c_char, i32, *const c_char, *mut c_void)>;
pub type OnRejectCb = Option<extern "C" fn(*const c_char, *mut c_void)>;
pub type OnHeartbeatTcpCb = Option<
    extern "C" fn(
        *const c_char,
        *const c_char,
        u16,
        i32,
        *const c_char,
        *const c_char,
        *mut c_void,
    ),
>;
pub type OnDataCb = Option<extern "C" fn(*const c_char, *const c_char, *mut c_void)>;

pub type OnHeartbeatUdpCb = Option<
    extern "C" fn(
        *const c_char,
        *const c_char,
        u16,
        i32,
        *const c_char,
        *mut c_void,
    ),
>;

pub type OnDeviceTimeoutCb = Option<extern "C" fn(*const c_char, *mut c_void)>;

// 网络层回调类型
pub type OnDeviceConnectedCb = Option<extern "C" fn(*const c_char, *const c_char, *mut c_void)>;
pub type OnDeviceDisconnectedCb = Option<extern "C" fn(*const c_char, *mut c_void)>;
pub type OnTcpErrorCb = Option<extern "C" fn(*const c_char, *mut c_void)>;

/// 配对结果回调：success=1 成功, 0 失败
pub type OnPairingResultCb = Option<extern "C" fn(*const c_char, i32, *const c_char, *mut c_void)>;

pub struct Router {
    pub user_data: *mut c_void,
    pub on_handshake: OnHandshakeCb,
    pub on_pairing_init: OnPairingInitCb,
    pub on_pairing_resp: OnPairingRespCb,
    pub on_accept: OnAcceptCb,
    pub on_reject: OnRejectCb,
    pub on_heartbeat_tcp: OnHeartbeatTcpCb,
    pub on_notification: OnDataCb,
    pub on_media_play: OnDataCb,
    pub on_icon_request: OnDataCb,
    pub on_icon_response: OnDataCb,
    pub on_app_list_request: OnDataCb,
    pub on_app_list_response: OnDataCb,
    pub on_media_control: OnDataCb,
    pub on_ftp: OnDataCb,
    pub on_clipboard: OnDataCb,
    pub on_status: OnDataCb,
    pub on_app_launch: OnDataCb,
    pub on_superisland: OnDataCb,
    pub on_unknown_data: OnDataCb,

    pub on_heartbeat_udp: OnHeartbeatUdpCb,
    pub on_device_timeout: OnDeviceTimeoutCb,
    // 网络层回调
    pub on_device_connected: OnDeviceConnectedCb,
    pub on_device_disconnected: OnDeviceDisconnectedCb,
    pub on_tcp_error: OnTcpErrorCb,
    /// 配对完成回调
    pub on_pairing_result: OnPairingResultCb,
}

impl Router {
    pub fn new() -> Self {
        Self {
            user_data: std::ptr::null_mut(),
            on_handshake: None,
            on_pairing_init: None,
            on_pairing_resp: None,
            on_accept: None,
            on_reject: None,
            on_heartbeat_tcp: None,
            on_notification: None,
            on_media_play: None,
            on_icon_request: None,
            on_icon_response: None,
            on_app_list_request: None,
            on_app_list_response: None,
            on_media_control: None,
            on_ftp: None,
            on_clipboard: None,
            on_status: None,
            on_app_launch: None,
            on_superisland: None,
            on_unknown_data: None,

            on_heartbeat_udp: None,
            on_device_timeout: None,
            on_device_connected: None,
            on_device_disconnected: None,
            on_tcp_error: None,
            on_pairing_result: None,
        }
    }
}
