use std::ffi::CString;
use std::io::Read;
use std::os::raw::{c_char, c_void};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use notify_relay_core::{ffi, BroadcastInfo, CoreContext, SafeContext};

fn init_logger() {
    let _ = env_logger::builder().filter_level(log::LevelFilter::Info).try_init();
}

static PORT_COUNTER: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(23336);

fn get_test_port() -> u16 {
    PORT_COUNTER.fetch_add(10, std::sync::atomic::Ordering::SeqCst)
}

extern "C" fn recv_callback(
    _device_uuid: *const c_char,
    pcm_data: *const u8,
    pcm_len: i32,
    _sample_rate: i32,
    _channels: i32,
    user_data: *mut c_void,
) {
    if pcm_data.is_null() || pcm_len <= 0 || user_data.is_null() {
        return;
    }
    let data = unsafe { std::slice::from_raw_parts(pcm_data, pcm_len as usize) };
    let pcm: Vec<i16> = data.chunks_exact(2).map(|c| i16::from_le_bytes([c[0], c[1]])).collect();
    let frames = unsafe { &*(user_data as *const Mutex<Vec<Vec<i16>>>) };
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
    Mutex::new(ctx)
}

fn set_temp_key(ctx: &mut SafeContext, remote_uuid: &str) {
    let temp_key = [0u8; 32];
    let ctx_ptr = ctx as *mut SafeContext as *mut c_void;
    let uuid_cstr = CString::new(remote_uuid).unwrap();
    unsafe {
        ffi::key_management::nrc_migrate_shared_secret(
            ctx_ptr, uuid_cstr.as_ptr(), temp_key.as_ptr(), temp_key.len() as u32,
        );
    }
}

fn set_device_ip(ctx: &mut SafeContext, uuid: &str, ip: &str) {
    let guard = ctx.lock().unwrap();
    guard.device_ips.lock().unwrap().insert(uuid.to_string(), ip.to_string());
}

fn ensure_tcp_listener() {
    static LISTENER: OnceLock<std::thread::JoinHandle<()>> = OnceLock::new();
    LISTENER.get_or_init(|| {
        let listener = std::net::TcpListener::bind("127.0.0.1:23333")
            .expect("无法绑定哑TCP监听器到127.0.0.1:23333");
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if let Ok(mut s) = stream {
                    let mut buf = [0u8; 4096];
                    let _ = s.set_read_timeout(Some(Duration::from_secs(1)));
                    let _ = s.read(&mut buf);
                }
            }
        })
    });
}

fn sine_frame() -> Vec<u8> {
    let sample_rate = 48000;
    let frame_samples = (sample_rate * 20) / 1000;
    let mut pcm = Vec::with_capacity(frame_samples * 2 * 2);
    for i in 0..frame_samples {
        let t = i as f64 / sample_rate as f64;
        let val = ((std::f64::consts::PI * 2.0 * 440.0 * t).sin() * 8000.0) as i16;
        pcm.extend_from_slice(&val.to_le_bytes());
        pcm.extend_from_slice(&val.to_le_bytes());
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

fn wait_for_frames(frames: &Mutex<Vec<Vec<i16>>>, min_count: usize, timeout: Duration) -> bool {
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
fn test_audio_basic_loopback() {
    init_logger();
    ensure_tcp_listener();
    let port = get_test_port();

    let mut ctx_a = create_context("sender-uuid");
    let mut ctx_b = create_context("receiver-uuid");

    set_temp_key(&mut ctx_a, "remote-uuid");
    set_temp_key(&mut ctx_b, "remote-uuid");
    set_device_ip(&mut ctx_a, "remote-uuid", "127.0.0.1");

    let ctx_a_ptr = &mut ctx_a as *mut SafeContext as *mut c_void;
    let ctx_b_ptr = &mut ctx_b as *mut SafeContext as *mut c_void;

    let dir_recv = CString::new("recv").unwrap();
    let dir_send = CString::new("send").unwrap();
    let uuid = CString::new("remote-uuid").unwrap();

    let frames = Box::new(Mutex::new(Vec::<Vec<i16>>::new()));
    let frames_ptr = Box::into_raw(frames) as *mut c_void;

    unsafe {
        let guard = &mut *(ctx_b_ptr as *mut SafeContext);
        let core_guard = guard.lock().unwrap();
        let mut audio_state = core_guard.audio.lock().unwrap();
        audio_state.user_data = frames_ptr;
    }
    ffi::audio_stream::nrc_register_audio_data_cb(ctx_b_ptr, Some(recv_callback));
    unsafe {
        ffi::audio_stream::nrc_audio_start(ctx_b_ptr, dir_recv.as_ptr(), port as i32, 48000, 2, uuid.as_ptr());
        ffi::audio_stream::nrc_audio_start(ctx_a_ptr, dir_send.as_ptr(), port as i32, 48000, 2, uuid.as_ptr());
    }

    let frame = sine_frame();
    for _ in 0..20 {
        unsafe {
            ffi::audio_stream::nrc_audio_write_frame(ctx_a_ptr, frame.as_ptr(), frame.len() as i32);
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    let frames = unsafe { &*frames_ptr.cast::<Mutex<Vec<Vec<i16>>>>() };
    assert!(wait_for_frames(frames, 1, Duration::from_secs(5)), "未收到音频帧");

    ffi::audio_stream::nrc_audio_stop(ctx_a_ptr);
    ffi::audio_stream::nrc_audio_stop(ctx_b_ptr);

    let captured = frames.lock().unwrap();
    assert!(!captured.is_empty(), "未捕获到音频帧");
    let energy = rms(&captured[0]);
    assert!(energy > 4000.0, "RMS 过低: {:.1}", energy);
}

#[test]
fn test_audio_stop_start_idempotent() {
    init_logger();
    ensure_tcp_listener();
    let port = get_test_port();

    let mut ctx_a = create_context("sender-uuid");
    let mut ctx_b = create_context("receiver-uuid");

    set_temp_key(&mut ctx_a, "remote-uuid");
    set_temp_key(&mut ctx_b, "remote-uuid");
    set_device_ip(&mut ctx_a, "remote-uuid", "127.0.0.1");

    let ctx_a_ptr = &mut ctx_a as *mut SafeContext as *mut c_void;
    let ctx_b_ptr = &mut ctx_b as *mut SafeContext as *mut c_void;

    let dir_recv = CString::new("recv").unwrap();
    let dir_send = CString::new("send").unwrap();
    let uuid = CString::new("remote-uuid").unwrap();

    for round in 0..2 {
        let frames = Box::new(Mutex::new(Vec::<Vec<i16>>::new()));
        let frames_ptr = Box::into_raw(frames) as *mut c_void;

        unsafe {
            let guard = &mut *(ctx_b_ptr as *mut SafeContext);
            let core_guard = guard.lock().unwrap();
            let mut audio_state = core_guard.audio.lock().unwrap();
            audio_state.user_data = frames_ptr;
        }
        ffi::audio_stream::nrc_register_audio_data_cb(ctx_b_ptr, Some(recv_callback));
        unsafe {
            ffi::audio_stream::nrc_audio_start(ctx_b_ptr, dir_recv.as_ptr(), port as i32, 48000, 2, uuid.as_ptr());
            ffi::audio_stream::nrc_audio_start(ctx_a_ptr, dir_send.as_ptr(), port as i32, 48000, 2, uuid.as_ptr());
        }

        let frame = sine_frame();
        for _ in 0..10 {
            unsafe {
                ffi::audio_stream::nrc_audio_write_frame(ctx_a_ptr, frame.as_ptr(), frame.len() as i32);
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        let frames = unsafe { &*frames_ptr.cast::<Mutex<Vec<Vec<i16>>>>() };
        assert!(
            wait_for_frames(frames, 1, Duration::from_secs(5)),
            "第 {} 轮: 未收到音频帧",
            round
        );

        ffi::audio_stream::nrc_audio_stop(ctx_a_ptr);
        ffi::audio_stream::nrc_audio_stop(ctx_b_ptr);

        unsafe { drop(Box::from_raw(frames_ptr.cast::<Mutex<Vec<Vec<i16>>>>())); }

        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
fn test_audio_reconnect_multiple() {
    init_logger();
    ensure_tcp_listener();
    let port = get_test_port();

    let mut ctx_a = create_context("sender-uuid");
    let mut ctx_b = create_context("receiver-uuid");

    set_temp_key(&mut ctx_a, "remote-uuid");
    set_temp_key(&mut ctx_b, "remote-uuid");
    set_device_ip(&mut ctx_a, "remote-uuid", "127.0.0.1");

    let ctx_a_ptr = &mut ctx_a as *mut SafeContext as *mut c_void;
    let ctx_b_ptr = &mut ctx_b as *mut SafeContext as *mut c_void;

    let dir_recv = CString::new("recv").unwrap();
    let dir_send = CString::new("send").unwrap();
    let uuid = CString::new("remote-uuid").unwrap();

    for round in 0..3 {
        let frames = Box::new(Mutex::new(Vec::<Vec<i16>>::new()));
        let frames_ptr = Box::into_raw(frames) as *mut c_void;

        unsafe {
            let guard = &mut *(ctx_b_ptr as *mut SafeContext);
            let core_guard = guard.lock().unwrap();
            let mut audio_state = core_guard.audio.lock().unwrap();
            audio_state.user_data = frames_ptr;
        }
        ffi::audio_stream::nrc_register_audio_data_cb(ctx_b_ptr, Some(recv_callback));
        unsafe {
            ffi::audio_stream::nrc_audio_start(ctx_b_ptr, dir_recv.as_ptr(), port as i32, 48000, 2, uuid.as_ptr());
            ffi::audio_stream::nrc_audio_start(ctx_a_ptr, dir_send.as_ptr(), port as i32, 48000, 2, uuid.as_ptr());
        }

        std::thread::sleep(Duration::from_millis(200));

        let frame = sine_frame();
        for _ in 0..10 {
            unsafe {
                ffi::audio_stream::nrc_audio_write_frame(ctx_a_ptr, frame.as_ptr(), frame.len() as i32);
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        let frames = unsafe { &*frames_ptr.cast::<Mutex<Vec<Vec<i16>>>>() };
        assert!(
            wait_for_frames(frames, 5, Duration::from_secs(5)),
            "第 {} 轮: 帧数不足",
            round
        );

        let captured = frames.lock().unwrap().clone();
        let avg_rms: f64 = captured.iter().map(|x| rms(x)).sum::<f64>() / captured.len() as f64;
        assert!(avg_rms > 4000.0, "第 {} 轮: 平均 RMS 过低: {:.1}", round, avg_rms);

        ffi::audio_stream::nrc_audio_stop(ctx_a_ptr);
        ffi::audio_stream::nrc_audio_stop(ctx_b_ptr);

        unsafe { drop(Box::from_raw(frames_ptr.cast::<Mutex<Vec<Vec<i16>>>>())); }

        std::thread::sleep(Duration::from_millis(200));
    }
}
