use std::os::raw::c_char;
use std::os::raw::c_void;

pub type OnPairingCb = Option<extern "C" fn(
    *const c_char,      // device_uuid
    *const c_char,      // message_type: "HANDSHAKE", "PAIRING_INIT", "PAIRING_RESP", "ACCEPT", "REJECT", "HEARTBEAT_TCP", "RESULT"
    *const c_char,      // data (JSON格式，包含所有字段)
    i32,                // int_value (battery, success等)
    *const c_char,      // extra (pub_key, ip等)
    *mut c_void,        // user_data
)>;

pub type OnDataCb = Option<extern "C" fn(
    *const c_char,      // device_uuid
    *const c_char,      // message_type: "NOTIFICATION", "MEDIAPLAY", "ICON_REQUEST", ...
    *const c_char,      // plaintext
    *mut c_void,        // user_data
)>;

pub type OnHeartbeatUdpCb = Option<
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

pub type OnMdnsDiscoveredCb = Option<
    extern "C" fn(
        *const c_char,
        *const c_char,
        *const c_char,
        u16,
        *const c_char,
        *mut c_void,
    ),
>;

pub type OnDeviceTimeoutCb = Option<extern "C" fn(*const c_char, *mut c_void)>;

pub type OnDeviceConnectedCb = Option<extern "C" fn(*const c_char, *const c_char, *mut c_void)>;
pub type OnDeviceDisconnectedCb = Option<extern "C" fn(*const c_char, *mut c_void)>;
pub type OnTcpErrorCb = Option<extern "C" fn(*const c_char, *mut c_void)>;

pub struct Router {
    pub user_data: *mut c_void,
    pub on_pairing: OnPairingCb,
    pub on_data: OnDataCb,

    pub on_heartbeat_udp: OnHeartbeatUdpCb,
    pub on_mdns_discovered: OnMdnsDiscoveredCb,
    pub on_device_timeout: OnDeviceTimeoutCb,
    pub on_device_connected: OnDeviceConnectedCb,
    pub on_device_disconnected: OnDeviceDisconnectedCb,
    pub on_tcp_error: OnTcpErrorCb,
}

impl Router {
    pub fn new() -> Self {
        Self {
            user_data: std::ptr::null_mut(),
            on_pairing: None,
            on_data: None,
            on_heartbeat_udp: None,
            on_mdns_discovered: None,
            on_device_timeout: None,
            on_device_connected: None,
            on_device_disconnected: None,
            on_tcp_error: None,
        }
    }
}