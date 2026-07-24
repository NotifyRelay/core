use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use notify_relay_core::{ffi, CoreContext, SafeContext, BroadcastInfo};

fn init_logger() {
    let _ = env_logger::builder().filter_level(log::LevelFilter::Info).try_init();
}

static PORT_COUNTER: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(23336);

fn get_test_port() -> u16 {
    PORT_COUNTER.fetch_add(10, std::sync::atomic::Ordering::SeqCst)
}

type FrameStorage = Arc<Mutex<Vec<Vec<i16>>>>;

extern "C" fn recv_callback(
    _device_uuid: *const std::os::raw::c_char,
    pcm_data: *const u8,
    pcm_len: i32,
    _sample_rate: i32,
    _channels: i32,
    user_data: *mut std::os::raw::c_void,
) {
    if pcm_data.is_null() || pcm_len <= 0 || user_data.is_null() {
        return;
    }
    let data = unsafe { std::slice::from_raw_parts(pcm_data, pcm_len as usize) };
    let pcm: Vec<i16> = data.chunks_exact(2).map(|c| i16::from_le_bytes([c[0], c[1]])).collect();
    let frames = unsafe { &mut *(user_data as *mut FrameStorage) };
    if let Ok(mut guard) = frames.lock() {
        guard.push(pcm);
    }
}

fn create_context(uuid: &str) -> SafeContext {
    let mut ctx = CoreContext::new();
    ctx.broadcast_info = Some(BroadcastInfo {
        uuid: uuid.to_string(),
        name_b64: ffi::common::encode_name_b64("test-device"),
        battery: 100,
        device_type: "test".to_string(),
    });
    std::sync::Mutex::new(ctx)
}

fn set_temp_key(ctx: &mut SafeContext, remote_uuid: &str) {
    let temp_key = [0u8; 32];
    let ctx_ptr = ctx as *mut SafeContext as *mut std::os::raw::c_void;
    let uuid_cstr = std::ffi::CString::new(remote_uuid).unwrap();
    unsafe {
        ffi::key_management::nrc_migrate_shared_secret(ctx_ptr, uuid_cstr.as_ptr(), temp_key.as_ptr(), temp_key.len() as u32);
    }
}

fn sine_frame() -> Vec<u8> {
    let sample_rate = 48000;
    let frame_samples = (sample_rate * 20) / 1000;
    let mut pcm = Vec::with_capacity(frame_samples * 2);
    for i in 0..frame_samples {
        let t = i as f64 / sample_rate as f64;
        let val = (std::f64::consts::PI * 2.0 * 440.0 * t).sin() * 8000.0;
        let s = val as i16;
        pcm.extend_from_slice(&s.to_le_bytes());
    }
    pcm
}

fn rms(data: &[i16]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let sum_sq: f64 = data.iter().map(|&x| (x as f64).powi(2)).sum();
    (sum_sq / data.len() as f64).sqrt()
}

fn wait_for_frames(frames: &FrameStorage, min_count: usize, timeout: Duration) -> bool {
    let start = Instant::now();
    loop {
        if start.elapsed() >= timeout {
            return false;
        }
        if let Ok(guard) = frames.lock() {
            if guard.len() >= min_count {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn test_audio_loopback() {
    init_logger();
    let port = get_test_port();

    let frames: FrameStorage = Arc::new(Mutex::new(Vec::new()));
    let frames_ptr = (&frames as *const FrameStorage) as *mut std::os::raw::c_void;

    let mut ctx_a = create_context("sender-uuid");
    let mut ctx_b = create_context("receiver-uuid");

    set_temp_key(&mut ctx_a, "remote-uuid");
    set_temp_key(&mut ctx_b, "remote-uuid");

    let ctx_a_ptr = &mut ctx_a as *mut SafeContext as *mut std::os::raw::c_void;
    let ctx_b_ptr = &mut ctx_b as *mut SafeContext as *mut std::os::raw::c_void;

    let dir_recv = std::ffi::CString::new("recv").unwrap();
    let dir_send = std::ffi::CString::new("send").unwrap();
    let ip_recv = std::ffi::CString::new("0.0.0.0").unwrap();
    let ip_send = std::ffi::CString::new("127.0.0.1").unwrap();
    let uuid = std::ffi::CString::new("remote-uuid").unwrap();

    unsafe {
        ffi::audio_stream::nrc_register_audio_data_cb(ctx_b_ptr, Some(recv_callback));
        ffi::audio_stream::nrc_set_audio_user_data(ctx_b_ptr, frames_ptr);
        ffi::audio_stream::nrc_audio_start(ctx_b_ptr, dir_recv.as_ptr(), ip_recv.as_ptr(), port as i32, 48000, 1, uuid.as_ptr());
        ffi::audio_stream::nrc_audio_start(ctx_a_ptr, dir_send.as_ptr(), ip_send.as_ptr(), port as i32, 48000, 1, uuid.as_ptr());
    }

    std::thread::sleep(Duration::from_millis(200));

    let frame = sine_frame();
    for _ in 0..20 {
        unsafe {
            ffi::audio_stream::nrc_audio_write_frame(ctx_a_ptr, frame.as_ptr(), frame.len() as i32);
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    assert!(wait_for_frames(&frames, 1, Duration::from_secs(5)), "no frames received");

    unsafe {
        ffi::audio_stream::nrc_audio_stop(ctx_a_ptr);
        ffi::audio_stream::nrc_audio_stop(ctx_b_ptr);
    }

    let captured_frames = frames.lock().unwrap().clone();
    assert!(!captured_frames.is_empty(), "no frames captured");
    let energy = rms(&captured_frames[0]);
    assert!(energy > 4000.0, "RMS too low: {:.1}", energy);
}

#[test]
fn test_stop_start_idempotent() {
    init_logger();
    let port = get_test_port();

    let mut ctx_a = create_context("sender-uuid");
    let mut ctx_b = create_context("receiver-uuid");

    set_temp_key(&mut ctx_a, "remote-uuid");
    set_temp_key(&mut ctx_b, "remote-uuid");

    let ctx_a_ptr = &mut ctx_a as *mut SafeContext as *mut std::os::raw::c_void;
    let ctx_b_ptr = &mut ctx_b as *mut SafeContext as *mut std::os::raw::c_void;

    let dir_recv = std::ffi::CString::new("recv").unwrap();
    let dir_send = std::ffi::CString::new("send").unwrap();
    let ip_recv = std::ffi::CString::new("0.0.0.0").unwrap();
    let ip_send = std::ffi::CString::new("127.0.0.1").unwrap();
    let uuid = std::ffi::CString::new("remote-uuid").unwrap();

    for round in 0..2 {
        let frames: FrameStorage = Arc::new(Mutex::new(Vec::new()));
        let frames_ptr = (&frames as *const FrameStorage) as *mut std::os::raw::c_void;

        unsafe {
            ffi::audio_stream::nrc_register_audio_data_cb(ctx_b_ptr, Some(recv_callback));
            ffi::audio_stream::nrc_set_audio_user_data(ctx_b_ptr, frames_ptr);
            ffi::audio_stream::nrc_audio_start(ctx_b_ptr, dir_recv.as_ptr(), ip_recv.as_ptr(), port as i32, 48000, 1, uuid.as_ptr());
            ffi::audio_stream::nrc_audio_start(ctx_a_ptr, dir_send.as_ptr(), ip_send.as_ptr(), port as i32, 48000, 1, uuid.as_ptr());
        }

        std::thread::sleep(Duration::from_millis(200));

        let frame = sine_frame();
        for _ in 0..10 {
            unsafe {
                ffi::audio_stream::nrc_audio_write_frame(ctx_a_ptr, frame.as_ptr(), frame.len() as i32);
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        assert!(wait_for_frames(&frames, 1, Duration::from_secs(5)), "round {}: no frames received", round);

        unsafe {
            ffi::audio_stream::nrc_audio_stop(ctx_a_ptr);
            ffi::audio_stream::nrc_audio_stop(ctx_b_ptr);
        }

        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
fn test_reconnect_send() {
    init_logger();
    let port = get_test_port();

    let mut ctx_a = create_context("sender-uuid");
    let mut ctx_b = create_context("receiver-uuid");

    set_temp_key(&mut ctx_a, "remote-uuid");
    set_temp_key(&mut ctx_b, "remote-uuid");

    let ctx_a_ptr = &mut ctx_a as *mut SafeContext as *mut std::os::raw::c_void;
    let ctx_b_ptr = &mut ctx_b as *mut SafeContext as *mut std::os::raw::c_void;

    let dir_recv = std::ffi::CString::new("recv").unwrap();
    let dir_send = std::ffi::CString::new("send").unwrap();
    let ip_recv = std::ffi::CString::new("0.0.0.0").unwrap();
    let ip_send = std::ffi::CString::new("127.0.0.1").unwrap();
    let uuid = std::ffi::CString::new("remote-uuid").unwrap();

    for round in 0..3 {
        let frames: FrameStorage = Arc::new(Mutex::new(Vec::new()));
        let frames_ptr = (&frames as *const FrameStorage) as *mut std::os::raw::c_void;

        unsafe {
            ffi::audio_stream::nrc_register_audio_data_cb(ctx_b_ptr, Some(recv_callback));
            ffi::audio_stream::nrc_set_audio_user_data(ctx_b_ptr, frames_ptr);
            ffi::audio_stream::nrc_audio_start(ctx_b_ptr, dir_recv.as_ptr(), ip_recv.as_ptr(), port as i32, 48000, 1, uuid.as_ptr());
            ffi::audio_stream::nrc_audio_start(ctx_a_ptr, dir_send.as_ptr(), ip_send.as_ptr(), port as i32, 48000, 1, uuid.as_ptr());
        }

        std::thread::sleep(Duration::from_millis(200));

        let frame = sine_frame();
        for _ in 0..10 {
            unsafe {
                ffi::audio_stream::nrc_audio_write_frame(ctx_a_ptr, frame.as_ptr(), frame.len() as i32);
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        assert!(wait_for_frames(&frames, 5, Duration::from_secs(5)), "round {}: not enough frames", round);

        let captured_frames = frames.lock().unwrap().clone();
        let avg_rms: f64 = captured_frames.iter().map(|x| rms(x)).sum::<f64>() / captured_frames.len() as f64;
        assert!(avg_rms > 4000.0, "round {}: average RMS too low: {:.1}", round, avg_rms);

        unsafe {
            ffi::audio_stream::nrc_audio_stop(ctx_a_ptr);
            ffi::audio_stream::nrc_audio_stop(ctx_b_ptr);
        }

        std::thread::sleep(Duration::from_millis(200));
    }
}