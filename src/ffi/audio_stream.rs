use std::os::raw::{c_char, c_void};

use base64::Engine;
use crate::{audio_stream, crypto::aes, protocol::codec};
use crate::ffi::send::do_send;
use super::common::{from_cstr, with_ctx};

/// 通过加密通道发送 DATA_MEDIA_CONTROL 消息
fn send_control(ctx: &crate::CoreContext, remote_uuid: &str, action: &str, sample_rate: i32, channels: i32) {
    let payload = if action == "audioStart" {
        format!(r#"{{"type":"MEDIA_CONTROL","action":"{}","sampleRate":{},"channels":{}}}"#, action, sample_rate, channels)
    } else {
        format!(r#"{{"type":"MEDIA_CONTROL","action":"{}"}}"#, action)
    };

    // 获取对端 AES 密钥
    let key_b64 = match ctx.crypto.device_keys.get(remote_uuid) {
        Some(k) => k.aes_key_b64.clone(),
        None => {
            log::warn!("audio_stream: 未找到对端密钥 uuid={}", remote_uuid);
            return;
        }
    };
    let key_bytes = match base64::engine::general_purpose::STANDARD.decode(&key_b64) {
        Ok(b) if b.len() == 32 => b,
        _ => { log::warn!("audio_stream: 密钥格式无效"); return; }
    };
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_bytes);

    // 获取本端 UUID 和公钥
    let local_uuid = ctx.broadcast_info.as_ref().map(|i| i.uuid.clone()).unwrap_or_default();
    let local_pub_key = ctx.crypto.local_pub_key_b64.as_deref().unwrap_or_default();

    // 加密并发送
    if let Ok(encrypted) = aes::encrypt(&key_arr, payload.as_bytes()) {
        let msg = codec::encode_data_message("DATA_MEDIA_CONTROL", &local_uuid, &local_pub_key, &encrypted);
        if do_send(ctx, remote_uuid, &msg) {
            log::info!("audio_stream: 已发送控制消息 action={}", action);
        } else {
            log::warn!("audio_stream: 发送控制消息失败 action={}", action);
        }
    } else {
        log::error!("audio_stream: 加密控制消息失败");
    }
}

#[no_mangle]
pub extern "C" fn nrc_audio_start(
    ctx_ptr: *mut c_void,
    direction: *const c_char,
    device_ip: *const c_char,
    port: i32,
    sample_rate: i32,
    channels: i32,
    remote_uuid: *const c_char,
) -> i32 {
    let dir = unsafe { from_cstr(direction).to_string() };
    let ip = unsafe { from_cstr(device_ip).to_string() };
    let ruuid = unsafe { from_cstr(remote_uuid).to_string() };
    let p = port as u16;

    let start_ok = with_ctx(ctx_ptr, |ctx| -> bool {
        let state = &mut ctx.audio;
        state.remote_uuid = ruuid.clone();
        match dir.as_str() {
            "send" => {
                let ok = audio_stream::start_receiver(state, p, sample_rate, channels);
                if ok { audio_stream::start_accept_thread(state); }
                ok
            }
            "recv" => audio_stream::start_sender(state, &ip, p, sample_rate, channels),
            _ => { log::error!("audio_stream FFI: unknown direction {dir}"); false }
        }
    });

    // 启动成功后发控制消息
    if start_ok && dir == "send" {
        with_ctx(ctx_ptr, |ctx| {
            send_control(ctx, &ruuid, "audioStart", sample_rate, channels);
        });
    }

    if start_ok { 0 } else { -1 }
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
        let ruuid = ctx.audio.remote_uuid.clone();
        if !ruuid.is_empty() {
            send_control(ctx, &ruuid, "audioStop", 0, 0);
        }
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
