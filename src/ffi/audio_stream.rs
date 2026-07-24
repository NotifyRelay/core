use std::os::raw::{c_char, c_void};

use super::common::{from_cstr, with_ctx};
use crate::{audio_stream, crypto::aes, network, protocol::codec, SafeContext};
use base64::Engine;

fn send_control(
    ctx: &crate::CoreContext,
    remote_uuid: &str,
    action: &str,
    sample_rate: i32,
    channels: i32,
) {
    log::info!(
        "音频流: send_control 开始 action={}, 远端UUID={}",
        action,
        remote_uuid
    );
    let payload = if action == "audioStart" {
        format!(
            r#"{{"type":"MEDIA_CONTROL","action":"{}","sampleRate":{},"channels":{},"codec":"opus"}}"#,
            action, sample_rate, channels
        )
    } else {
        format!(r#"{{"type":"MEDIA_CONTROL","action":"{}"}}"#, action)
    };

    let key_b64 = match ctx.crypto.device_keys.get(remote_uuid) {
        Some(k) => k.aes_key_b64.clone(),
        None => {
            log::warn!("音频流: 未找到对端密钥 uuid={}", remote_uuid);
            return;
        }
    };
    let key_bytes = match base64::engine::general_purpose::STANDARD.decode(&key_b64) {
        Ok(b) if b.len() == 32 => b,
        _ => {
            log::warn!("音频流: 密钥格式无效");
            return;
        }
    };
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_bytes);

    let local_uuid = ctx
        .broadcast_info
        .as_ref()
        .map(|i| i.uuid.clone())
        .unwrap_or_default();

    if let Ok(encrypted) = aes::encrypt(&key_arr, payload.as_bytes()) {
        let msg = codec::encode_data_message("DATA_MEDIA_CONTROL", &local_uuid, "", &encrypted);
        let ip = ctx.audio.lock().unwrap().peer_ip.clone();

        if !ip.is_empty() && ip != "0.0.0.0" {
            if network::oneshot_send_only(&msg, &ip, codec::DEFAULT_TCP_PORT, 3000) {
                log::info!("音频流: 已发送控制消息 action={}", action);
            } else {
                log::warn!("音频流: oneshot 发送控制消息失败 action={}", action);
            }
        } else {
            log::warn!("音频流: 无有效IP发送控制消息 uuid={}", remote_uuid);
        }
    } else {
        log::error!("音频流: 加密控制消息失败");
    }
}

#[no_mangle]
pub unsafe extern "C" fn nrc_audio_start(
    ctx_ptr: *mut c_void,
    direction: *const c_char,
    device_ip: *const c_char,
    port: i32,
    sample_rate: i32,
    channels: i32,
    remote_uuid: *const c_char,
) -> i32 {
    let dir = from_cstr(direction).to_string();
    let ip = from_cstr(device_ip).to_string();
    let ruuid = from_cstr(remote_uuid).to_string();
    let p = port as u16;

    log::info!(
        "音频流: nrc_audio_start 方向={}, 对端IP={}, 端口={}, 采样率={}, 声道数={}, 远端UUID={}",
        dir,
        ip,
        port,
        sample_rate,
        channels,
        ruuid
    );

    let mut start_ok = false;

    if !ctx_ptr.is_null() {
        let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
        if let Ok(guard) = ctx.lock() {
            let mut audio_state = guard.audio.lock().unwrap();
            audio_state.remote_uuid = ruuid.clone();
            audio_state.peer_ip = ip.clone();
            start_ok = match dir.as_str() {
                "send" => audio_stream::start_sender(&mut audio_state, &ip, p, sample_rate, channels),
                "recv" => audio_stream::start_receiver(&mut audio_state, p, sample_rate, channels),
                _ => {
                    log::error!("音频流 FFI: 未知方向 {dir}");
                    false
                }
            };
        }
    }

    if start_ok {
        log::info!("音频流: nrc_audio_start 成功");
        if dir == "send" {
            with_ctx(ctx_ptr, |ctx| {
                send_control(ctx, &ruuid, "audioStart", sample_rate, channels);
            });
        }
        0
    } else {
        log::error!("音频流: nrc_audio_start 失败");
        -1
    }
}

#[no_mangle]
pub unsafe extern "C" fn nrc_audio_write_frame(
    ctx_ptr: *mut c_void,
    pcm_data: *const u8,
    pcm_len: i32,
) -> i32 {
    if pcm_len <= 0 || pcm_data.is_null() {
        return -1;
    }
    let pcm = std::slice::from_raw_parts(pcm_data, pcm_len as usize);
    if ctx_ptr.is_null() {
        return -1;
    }
    let ctx = &mut *(ctx_ptr as *mut SafeContext);
    if let Ok(guard) = ctx.lock() {
        if let Ok(audio_state) = guard.audio.try_lock() {
            if audio_stream::write_frame(&audio_state, pcm) {
                return 0;
            }
        }
    }
    -1
}

#[no_mangle]
pub extern "C" fn nrc_audio_stop(ctx_ptr: *mut c_void) -> i32 {
    log::info!("音频流: nrc_audio_stop 开始停止");

    let _ruuid = with_ctx(ctx_ptr, |ctx| {
        let uuid = ctx.audio.lock().unwrap().remote_uuid.clone();
        if !uuid.is_empty() {
            log::info!("音频流: 发送 audioStop 控制消息到 uuid={}", uuid);
            send_control(ctx, &uuid, "audioStop", 0, 0);
        }
        uuid
    });

    let thread_handles = if !ctx_ptr.is_null() {
        let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
        if let Ok(guard) = ctx.lock() {
            let audio_state = &mut guard.audio.lock().unwrap();
            audio_stream::stop(audio_state)
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    for h in thread_handles {
        log::info!("音频流: 等待线程退出");
        h.join().ok();
        log::info!("音频流: 线程已退出");
    }

    with_ctx(ctx_ptr, |ctx| {
        let mut audio_state = ctx.audio.lock().unwrap();
        let _ = audio_state.encoder.lock().map(|mut g| *g = None);
        let _ = audio_state.decoder.lock().map(|mut g| *g = None);
        let _ = audio_state.jitter.lock().map(|mut g| *g = None);
        let _ = audio_state.stats.lock().map(|mut g| *g = crate::audio_stream::AudioStats::new());
        let _ = audio_state.pcm_queue.lock().map(|mut g| g.clear());
        let _ = audio_state.pcm_buffer.lock().map(|mut g| g.clear());
    });

    log::info!("音频流: nrc_audio_stop 完成");
    0
}

#[no_mangle]
pub extern "C" fn nrc_audio_is_active(ctx_ptr: *mut c_void) -> i32 {
    if ctx_ptr.is_null() {
        return 0;
    }
    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
    if let Ok(guard) = ctx.lock() {
        if let Ok(audio_state) = guard.audio.try_lock() {
            let active = audio_state.active.load(std::sync::atomic::Ordering::SeqCst);
            log::debug!("音频流: 查询活跃状态={}", active);
            return if active { 1 } else { 0 };
        }
    }
    0
}

#[no_mangle]
pub extern "C" fn nrc_register_audio_data_cb(
    ctx_ptr: *mut c_void,
    cb: crate::audio_stream::AudioDataCb,
) {
    if ctx_ptr.is_null() {
        return;
    }
    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
    if let Ok(guard) = ctx.lock() {
        let mut audio_state = guard.audio.lock().unwrap();
        audio_state.on_data = cb;
    }
}

#[no_mangle]
pub extern "C" fn nrc_set_audio_user_data(
    ctx_ptr: *mut c_void,
    user_data: *mut c_void,
) {
    if ctx_ptr.is_null() {
        return;
    }
    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
    if let Ok(guard) = ctx.lock() {
        let mut audio_state = guard.audio.lock().unwrap();
        audio_state.user_data = user_data;
    }
}

#[no_mangle]
pub extern "C" fn nrc_register_audio_event_cb(
    ctx_ptr: *mut c_void,
    cb: crate::audio_stream::AudioEventCb,
) {
    if ctx_ptr.is_null() {
        return;
    }
    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
    if let Ok(guard) = ctx.lock() {
        if let Ok(mut audio_state) = guard.audio.try_lock() {
            audio_state.on_event = cb;
        }
    }
}
