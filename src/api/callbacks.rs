//! 回调接口：把 11 个裸函数指针注册合并为一个 [`CoreCallbacks`] trait。
//!
//! 实现方式：trait 对象存入全局 `OnceLock`，再向既有 `router` / `audio_state`
//! 安装 C 风格蹦床函数指针，内部调用点无需改动。

use std::ffi::CStr;
use std::os::raw::{c_char, c_void};
use std::sync::{Arc, OnceLock};

use super::Core;

/// 平台侧回调实现。
///
/// 所有 `on_*` 可能在 JNA 附加线程、心跳线程或网络线程触发。
#[uniffi::export(callback_interface)]
pub trait CoreCallbacks: Send + Sync {
    /// 配对/握手过程消息。`message_type` 取值：
    /// "HANDSHAKE" / "PAIRING_INIT" / "PAIRING_RESP" / "ACCEPT" / "REJECT" /
    /// "HEARTBEAT_TCP" / "RESULT"。
    fn on_pairing(
        &self,
        device_uuid: String,
        message_type: String,
        data: String,
        int_value: i32,
        extra: String,
    );

    /// 入站数据报文；`message_type` 如 "NOTIFICATION" / "MEDIAPLAY" / "ICON_REQUEST"。
    fn on_data(&self, device_uuid: String, message_type: String, plaintext: String);

    /// 状态查询（心跳线程锁外调用）。
    ///
    /// 返回 0=该会话在平台不存在（引擎应移除会话）、1=存在且无变更、2=存在且有变更。
    fn on_state_query(&self, device_uuid: String, feature_id: String, is_media: bool) -> i32;

    /// 设备超时（离线）。
    fn on_device_timeout(&self, device_uuid: String);

    /// 设备已连接。
    fn on_device_connected(&self, device_uuid: String, ip: String);

    /// 设备已断开。
    fn on_device_disconnected(&self, device_uuid: String);

    /// TCP 层错误。
    fn on_tcp_error(&self, error: String);

    /// 发现新设备；`name_b64` 为设备名的 base64 编码。
    fn on_device_discovered(
        &self,
        device_uuid: String,
        name_b64: String,
        port: u16,
        battery: i32,
        device_type: String,
        ip: String,
    );

    /// 音频数据帧（PCM，16 位小端）。
    fn on_audio_data(&self, device_uuid: String, pcm: Vec<u8>, sample_rate: i32, channels: i32);

    /// 音频事件。
    fn on_audio_event(&self, device_uuid: String, event: String, data: String);

    /// 日志输出。
    fn on_log(&self, level: i32, message: String);
}

static CALLBACKS: OnceLock<Arc<dyn CoreCallbacks>> = OnceLock::new();

fn callbacks() -> Option<&'static Arc<dyn CoreCallbacks>> {
    CALLBACKS.get()
}

/// 读取 C 字符串指针；空指针转为空串。
unsafe fn read(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}

extern "C" fn trampoline_pairing(
    uuid: *const c_char,
    message_type: *const c_char,
    data: *const c_char,
    int_value: i32,
    extra: *const c_char,
    _ud: *mut c_void,
) {
    if let Some(cb) = callbacks() {
        cb.on_pairing(
            unsafe { read(uuid) },
            unsafe { read(message_type) },
            unsafe { read(data) },
            int_value,
            unsafe { read(extra) },
        );
    }
}

extern "C" fn trampoline_data(
    uuid: *const c_char,
    message_type: *const c_char,
    plaintext: *const c_char,
    _ud: *mut c_void,
) {
    if let Some(cb) = callbacks() {
        cb.on_data(
            unsafe { read(uuid) },
            unsafe { read(message_type) },
            unsafe { read(plaintext) },
        );
    }
}

extern "C" fn trampoline_state_query(
    uuid: *const c_char,
    feature_id: *const c_char,
    is_media: i32,
    _ud: *mut c_void,
) -> i32 {
    match callbacks() {
        Some(cb) => cb.on_state_query(
            unsafe { read(uuid) },
            unsafe { read(feature_id) },
            is_media != 0,
        ),
        None => 0,
    }
}

extern "C" fn trampoline_device_timeout(uuid: *const c_char, _ud: *mut c_void) {
    if let Some(cb) = callbacks() {
        cb.on_device_timeout(unsafe { read(uuid) });
    }
}

extern "C" fn trampoline_device_connected(
    uuid: *const c_char,
    ip: *const c_char,
    _ud: *mut c_void,
) {
    if let Some(cb) = callbacks() {
        cb.on_device_connected(unsafe { read(uuid) }, unsafe { read(ip) });
    }
}

extern "C" fn trampoline_device_disconnected(uuid: *const c_char, _ud: *mut c_void) {
    if let Some(cb) = callbacks() {
        cb.on_device_disconnected(unsafe { read(uuid) });
    }
}

extern "C" fn trampoline_tcp_error(error: *const c_char, _ud: *mut c_void) {
    if let Some(cb) = callbacks() {
        cb.on_tcp_error(unsafe { read(error) });
    }
}

extern "C" fn trampoline_device_discovered(
    uuid: *const c_char,
    name_b64: *const c_char,
    port: u16,
    battery: i32,
    device_type: *const c_char,
    ip: *const c_char,
    _ud: *mut c_void,
) {
    if let Some(cb) = callbacks() {
        cb.on_device_discovered(
            unsafe { read(uuid) },
            unsafe { read(name_b64) },
            port,
            battery,
            unsafe { read(device_type) },
            unsafe { read(ip) },
        );
    }
}

extern "C" fn trampoline_audio_data(
    uuid: *const c_char,
    data: *const u8,
    len: i32,
    sample_rate: i32,
    channels: i32,
    _ud: *mut c_void,
) {
    if let Some(cb) = callbacks() {
        let pcm = if data.is_null() || len <= 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(data, len as usize) }.to_vec()
        };
        cb.on_audio_data(unsafe { read(uuid) }, pcm, sample_rate, channels);
    }
}

extern "C" fn trampoline_audio_event(
    uuid: *const c_char,
    event: *const c_char,
    data: *const c_char,
    _ud: *mut c_void,
) {
    if let Some(cb) = callbacks() {
        cb.on_audio_event(unsafe { read(uuid) }, unsafe { read(event) }, unsafe {
            read(data)
        });
    }
}

#[uniffi::export]
impl Core {
    /// 注册平台回调集合，并装配 router 与音频回调蹦床。
    pub fn set_callbacks(&self, callbacks: Box<dyn CoreCallbacks>) {
        let _ = CALLBACKS.set(Arc::from(callbacks));

        install_log_forwarder();

        if let Ok(mut guard) = self.ctx().lock() {
            guard.router.on_pairing = Some(trampoline_pairing);
            guard.router.on_data = Some(trampoline_data);
            guard.router.on_state_query = Some(trampoline_state_query);
            guard.router.on_device_timeout = Some(trampoline_device_timeout);
            guard.router.on_device_connected = Some(trampoline_device_connected);
            guard.router.on_device_disconnected = Some(trampoline_device_disconnected);
            guard.router.on_tcp_error = Some(trampoline_tcp_error);
            guard.router.on_device_discovered = Some(trampoline_device_discovered);

            if let Ok(mut audio) = guard.audio.lock() {
                audio.on_data = Some(trampoline_audio_data);
                audio.on_event = Some(trampoline_audio_event);
            }
        }
    }
}

/// 仅注册日志回调（早期日志输出用，不装配业务回调）。
#[uniffi::export]
pub fn set_log_callback(callbacks: Box<dyn CoreCallbacks>) {
    let _ = CALLBACKS.set(Arc::from(callbacks));
    install_log_forwarder();
}

/// 把既有日志桥的输出转发到 [`CoreCallbacks::on_log`]。
///
/// `log` 全局 logger 只能安装一次，且已由 `ffi::common::init_log_bridge` 在
/// 上下文创建时装好；此处仅把该桥的回调指针指向本层的转发函数，
/// 避免两条路径争用同一全局 logger。
fn install_log_forwarder() {
    crate::ffi::common::set_log_callback_internal(Some(forward_log));
}

extern "C" fn forward_log(level: i32, message: *const std::os::raw::c_char) {
    if let Some(cb) = callbacks() {
        let msg = if message.is_null() {
            String::new()
        } else {
            unsafe { CStr::from_ptr(message) }
                .to_string_lossy()
                .into_owned()
        };
        cb.on_log(level, msg);
    }
}
