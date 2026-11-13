//! 音频流 C ABI 委托。

use std::os::raw::{c_char, c_void};

use super::common::from_cstr;

/// 启动音频流。`direction` 为 "send" 或 "recv"。
///
/// # Safety
/// 字符串指针须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_audio_start(
    ctx_ptr: *mut c_void,
    direction: *const c_char,
    port: i32,
    sample_rate: i32,
    channels: i32,
    remote_uuid: *const c_char,
) -> i32 {
    if ctx_ptr.is_null() {
        return -1;
    }
    let direction = unsafe { from_cstr(direction) };
    let remote_uuid = unsafe { from_cstr(remote_uuid) };
    crate::audio_stream::start(
        unsafe { &*(ctx_ptr as *const crate::SafeContext) },
        direction,
        port,
        sample_rate,
        channels,
        remote_uuid,
    )
}

/// 写入一帧 PCM 数据。
///
/// # Safety
/// `pcm_data` 须指向 `pcm_len` 字节可读内存。
#[no_mangle]
pub unsafe extern "C" fn nrc_audio_write_frame(
    ctx_ptr: *mut c_void,
    pcm_data: *const u8,
    pcm_len: i32,
) -> i32 {
    if pcm_len <= 0 || pcm_data.is_null() || ctx_ptr.is_null() {
        return -1;
    }
    let pcm = unsafe { std::slice::from_raw_parts(pcm_data, pcm_len as usize) };
    crate::audio_stream::write_pcm_frame(unsafe { &*(ctx_ptr as *const crate::SafeContext) }, pcm)
}

#[no_mangle]
pub extern "C" fn nrc_audio_stop(ctx_ptr: *mut c_void) -> i32 {
    if ctx_ptr.is_null() {
        return -1;
    }
    crate::audio_stream::stop_stream(unsafe { &*(ctx_ptr as *const crate::SafeContext) })
}

#[no_mangle]
pub extern "C" fn nrc_audio_is_active(ctx_ptr: *mut c_void) -> i32 {
    if ctx_ptr.is_null() {
        return 0;
    }
    if crate::audio_stream::is_active(unsafe { &*(ctx_ptr as *const crate::SafeContext) }) {
        1
    } else {
        0
    }
}

/// 注册音频数据回调：把 C 函数指针包成内部闭包。
///
/// # Safety
/// `cb` 须为空或指向签名匹配的有效函数。
#[no_mangle]
pub unsafe extern "C" fn nrc_register_audio_data_cb(
    ctx_ptr: *mut c_void,
    cb: Option<extern "C" fn(*const c_char, *const u8, i32, i32, i32, *mut c_void)>,
) {
    if ctx_ptr.is_null() {
        return;
    }
    let Some(cb) = cb else {
        return;
    };
    let wrapped: crate::audio_stream::AudioDataCb = std::sync::Arc::new(
        move |uuid: &str, pcm: &[u8], sample_rate: i32, channels: i32| {
            let Ok(uuid_c) = std::ffi::CString::new(uuid) else {
                return;
            };
            cb(
                uuid_c.as_ptr(),
                pcm.as_ptr(),
                pcm.len() as i32,
                sample_rate,
                channels,
                std::ptr::null_mut(),
            );
        },
    );
    crate::audio_stream::register_data_cb(
        unsafe { &*(ctx_ptr as *const crate::SafeContext) },
        wrapped,
    );
}

/// 注册音频事件回调：把 C 函数指针包成内部闭包。
///
/// # Safety
/// `cb` 须为空或指向签名匹配的有效函数。
#[no_mangle]
pub unsafe extern "C" fn nrc_register_audio_event_cb(
    ctx_ptr: *mut c_void,
    cb: Option<extern "C" fn(*const c_char, *const c_char, *const c_char, *mut c_void)>,
) {
    if ctx_ptr.is_null() {
        return;
    }
    let Some(cb) = cb else {
        return;
    };
    let wrapped: crate::audio_stream::AudioEventCb =
        std::sync::Arc::new(move |uuid: &str, event: &str, data: &str| {
            let (Ok(uuid_c), Ok(event_c), Ok(data_c)) = (
                std::ffi::CString::new(uuid),
                std::ffi::CString::new(event),
                std::ffi::CString::new(data),
            ) else {
                return;
            };
            cb(
                uuid_c.as_ptr(),
                event_c.as_ptr(),
                data_c.as_ptr(),
                std::ptr::null_mut(),
            );
        });
    crate::audio_stream::register_event_cb(
        unsafe { &*(ctx_ptr as *const crate::SafeContext) },
        wrapped,
    );
}
