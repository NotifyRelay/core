//! 回调接口：平台侧实现 [`CoreCallbacks`]，本层把它装配成内部闭包。
//!
//! 实现方式：trait 对象存入全局 `OnceLock`，再为 `router` / `audio_stream`
//! 安装闭包；内部调用点无需改动。

use std::sync::{Arc, OnceLock};

use super::Core;

/// 平台侧回调实现。
///
/// 所有 `on_*` 可能在心跳线程、网络线程或音频线程触发。
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

#[uniffi::export]
impl Core {
    /// 注册平台回调集合，并装配 `router` 与音频回调。
    pub fn set_callbacks(&self, callbacks: Box<dyn CoreCallbacks>) {
        let _ = CALLBACKS.set(Arc::from(callbacks));

        install_log_forwarder();
        self.install_router_callbacks();
        self.install_audio_callbacks();
    }
}

impl Core {
    fn install_router_callbacks(&self) {
        let Ok(mut guard) = self.ctx().lock() else {
            return;
        };
        guard.router.on_pairing = Some(Arc::new(
            |device_uuid: &str, message_type: &str, data: &str, int_value: i32, extra: &str| {
                if let Some(cb) = callbacks() {
                    cb.on_pairing(
                        device_uuid.to_string(),
                        message_type.to_string(),
                        data.to_string(),
                        int_value,
                        extra.to_string(),
                    );
                }
            },
        ));
        guard.router.on_data = Some(Arc::new(
            |device_uuid: &str, message_type: &str, plaintext: &str| {
                if let Some(cb) = callbacks() {
                    cb.on_data(
                        device_uuid.to_string(),
                        message_type.to_string(),
                        plaintext.to_string(),
                    );
                }
            },
        ));
        guard.router.on_state_query = Some(Arc::new(
            |device_uuid: &str, feature_id: &str, is_media: bool| -> i32 {
                match callbacks() {
                    Some(cb) => {
                        cb.on_state_query(device_uuid.to_string(), feature_id.to_string(), is_media)
                    }
                    None => 0,
                }
            },
        ));
        guard.router.on_device_timeout = Some(Arc::new(|device_uuid: &str| {
            if let Some(cb) = callbacks() {
                cb.on_device_timeout(device_uuid.to_string());
            }
        }));
        guard.router.on_device_connected = Some(Arc::new(|device_uuid: &str, ip: &str| {
            if let Some(cb) = callbacks() {
                cb.on_device_connected(device_uuid.to_string(), ip.to_string());
            }
        }));
        guard.router.on_device_disconnected = Some(Arc::new(|device_uuid: &str| {
            if let Some(cb) = callbacks() {
                cb.on_device_disconnected(device_uuid.to_string());
            }
        }));
        guard.router.on_tcp_error = Some(Arc::new(|error: &str| {
            if let Some(cb) = callbacks() {
                cb.on_tcp_error(error.to_string());
            }
        }));
        guard.router.on_device_discovered = Some(Arc::new(
            |device_uuid: &str,
             name_b64: &str,
             port: u16,
             battery: i32,
             device_type: &str,
             ip: &str| {
                if let Some(cb) = callbacks() {
                    cb.on_device_discovered(
                        device_uuid.to_string(),
                        name_b64.to_string(),
                        port,
                        battery,
                        device_type.to_string(),
                        ip.to_string(),
                    );
                }
            },
        ));
    }

    fn install_audio_callbacks(&self) {
        let Ok(guard) = self.ctx().lock() else {
            return;
        };
        let data_cb = Arc::new(
            |device_uuid: &str, pcm: &[u8], sample_rate: i32, channels: i32| {
                if let Some(cb) = callbacks() {
                    cb.on_audio_data(device_uuid.to_string(), pcm.to_vec(), sample_rate, channels);
                }
            },
        );
        let event_cb = Arc::new(|device_uuid: &str, event: &str, data: &str| {
            if let Some(cb) = callbacks() {
                cb.on_audio_event(device_uuid.to_string(), event.to_string(), data.to_string());
            }
        });
        let audio_result = guard.audio.lock();
        if let Ok(mut audio) = audio_result {
            audio.on_data = Some(data_cb);
            audio.on_event = Some(event_cb);
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
/// `log` 全局 logger 只能安装一次，且已由 [`crate::log_bridge::init`] 在
/// 上下文创建时装好；此处仅把该桥的回调指针指向本层的转发函数，
/// 避免两条路径争用同一全局 logger。
fn install_log_forwarder() {
    crate::log_bridge::set_callback(Some(forward_log));
}

extern "C" fn forward_log(level: i32, message: *const std::os::raw::c_char) {
    if let Some(cb) = callbacks() {
        let msg = if message.is_null() {
            String::new()
        } else {
            unsafe { std::ffi::CStr::from_ptr(message) }
                .to_string_lossy()
                .into_owned()
        };
        cb.on_log(level, msg);
    }
}
