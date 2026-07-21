use std::os::raw::{c_char, c_void};

use crate::audio_stream;
use super::common::{from_cstr, with_ctx};

#[no_mangle]
pub extern "C" fn nrc_audio_start(
    ctx_ptr: *mut c_void,
    direction: *const c_char,
    device_ip: *const c_char,
    port: i32,
    sample_rate: i32,
    channels: i32,
) -> i32 {
    let dir = unsafe { from_cstr(direction).to_string() };
    let ip = unsafe { from_cstr(device_ip).to_string() };
    let p = port as u16;

    with_ctx(ctx_ptr, |ctx| {
        let state = &mut ctx.audio;
        match dir.as_str() {
            "send" => {
                if audio_stream::start_sender(state, &ip, p, sample_rate, channels) { 0 } else { -1 }
            }
            "recv" => {
                if audio_stream::start_receiver(state, p, sample_rate, channels) {
                    audio_stream::start_accept_thread(state);
                    0
                } else {
                    -1
                }
            }
            _ => { log::error!("audio_stream FFI: unknown direction {dir}"); -1 }
        }
    })
}

#[no_mangle]
pub extern "C" fn nrc_audio_write_frame(
    ctx_ptr: *mut c_void,
    pcm_data: *const u8,
    pcm_len: i32,
) -> i32 {
    if pcm_len <= 0 || pcm_data.is_null() { return -1; }
    let pcm = unsafe { std::slice::from_raw_parts(pcm_data, pcm_len as usize) };
    with_ctx(ctx_ptr, |ctx| {
        if audio_stream::write_frame(&ctx.audio, pcm) { 0 } else { -1 }
    })
}

#[no_mangle]
pub extern "C" fn nrc_audio_stop(ctx_ptr: *mut c_void) -> i32 {
    with_ctx(ctx_ptr, |ctx| {
        audio_stream::stop(&mut ctx.audio);
    });
    0
}

#[no_mangle]
pub extern "C" fn nrc_audio_is_active(ctx_ptr: *mut c_void) -> i32 {
    with_ctx(ctx_ptr, |ctx| {
        if ctx.audio.active.load(std::sync::atomic::Ordering::SeqCst) { 1 } else { 0 }
    })
}

#[no_mangle]
pub extern "C" fn nrc_register_audio_data_cb(
    ctx_ptr: *mut c_void,
    cb: crate::audio_stream::AudioDataCb,
) {
    with_ctx(ctx_ptr, |ctx| { ctx.audio.on_data = cb; });
}

#[no_mangle]
pub extern "C" fn nrc_register_audio_event_cb(
    ctx_ptr: *mut c_void,
    cb: crate::audio_stream::AudioEventCb,
) {
    with_ctx(ctx_ptr, |ctx| { ctx.audio.on_event = cb; });
}
