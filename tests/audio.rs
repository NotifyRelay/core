use std::ffi::CString;
use std::io::Read;
use std::os::raw::{c_char, c_void};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use notify_relay_core::{ffi, BroadcastInfo, CoreContext, SafeContext};

fn init_logger() {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .try_init();
}

/// 上下文序号：保证每个测试上下文使用独立的临时数据库。
static CTX_SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

static PORT_COUNTER: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(23336);

fn get_test_port() -> u16 {
    PORT_COUNTER.fetch_add(10, std::sync::atomic::Ordering::SeqCst)
}

/// 收到的音频帧容器（进程级）：C 回调无 user_data 通道，测试经此静态容器收集。
static RECEIVED_FRAMES: Mutex<Vec<Vec<i16>>> = Mutex::new(Vec::new());

extern "C" fn recv_callback(
    _device_uuid: *const c_char,
    pcm_data: *const u8,
    pcm_len: i32,
    _sample_rate: i32,
    _channels: i32,
    _user_data: *mut c_void,
) {
    if pcm_data.is_null() || pcm_len <= 0 {
        return;
    }
    let data = unsafe { std::slice::from_raw_parts(pcm_data, pcm_len as usize) };
    let pcm: Vec<i16> = data
        .chunks_exact(2)
        .map(|c| i16::from_le_bytes([c[0], c[1]]))
        .collect();
    if let Ok(mut guard) = RECEIVED_FRAMES.lock() {
        guard.push(pcm);
    }
}

/// 进程内已创建的临时库目录；进程退出时统一清理。
static CTX_DIRS: Mutex<Vec<std::path::PathBuf>> = Mutex::new(Vec::new());

/// 清理本进程及历史遗留的测试临时库目录。
fn prune_temp_dirs() {
    if let Ok(mut dirs) = CTX_DIRS.lock() {
        for dir in dirs.drain(..) {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
    let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.starts_with("nrc_audio_") {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// 注册进程退出清理（只注册一次）。
fn register_cleanup_once() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        extern "C" fn on_exit() {
            prune_temp_dirs();
        }
        // SAFETY: 回调只做文件删除，不访问其他全局状态
        unsafe { libc::atexit(on_exit) };
    });
}

fn create_context(uuid: &str) -> SafeContext {
    // 每个上下文使用独立临时库，避免写入平台默认路径（%LOCALAPPDATA% / 应用私有目录）
    let seq = CTX_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("nrc_audio_{}_{}", std::process::id(), seq));
    if let Ok(mut dirs) = CTX_DIRS.lock() {
        dirs.push(dir.clone());
    }
    register_cleanup_once();
    let mut ctx = CoreContext::with_db_override(dir.join("rust_core.db"));
    ctx.broadcast_info = Some(BroadcastInfo {
        uuid: uuid.to_string(),
        name_b64: notify_relay_core::utils::encode_name_b64("test-device"),
        battery: 100,
        device_type: "test".to_string(),
    });
    Mutex::new(ctx)
}

fn reset_frames() {
    RECEIVED_FRAMES.lock().unwrap().clear();
}

fn set_temp_key(ctx: &mut SafeContext, remote_uuid: &str) {
    let temp_key = [0u8; 32];
    let ctx_ptr = ctx as *mut SafeContext as *mut c_void;
    let uuid_cstr = CString::new(remote_uuid).unwrap();
    unsafe {
        ffi::key_management::nrc_migrate_shared_secret(
            ctx_ptr,
            uuid_cstr.as_ptr(),
            temp_key.as_ptr(),
            temp_key.len() as u32,
        );
    }
}

fn set_device_ip(ctx: &mut SafeContext, uuid: &str, ip: &str) {
    let guard = ctx.get_mut().unwrap();
    guard
        .device_ips
        .lock()
        .unwrap()
        .insert(uuid.to_string(), ip.to_string());
}

fn ensure_tcp_listener() {
    static LISTENER: OnceLock<std::thread::JoinHandle<()>> = OnceLock::new();
    LISTENER.get_or_init(|| {
        let listener = std::net::TcpListener::bind("127.0.0.1:23333")
            .expect("无法绑定哑TCP监听器到127.0.0.1:23333");
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else {
                    continue;
                };
                let mut buf = [0u8; 4096];
                let _ = s.set_read_timeout(Some(Duration::from_secs(1)));
                let _ = s.read(&mut buf);
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

fn wait_for_frames(min_count: usize, timeout: Duration) -> bool {
    let start = Instant::now();
    loop {
        if start.elapsed() >= timeout {
            return false;
        }
        if let Ok(guard) = RECEIVED_FRAMES.lock() {
            if guard.len() >= min_count {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// 测试串行锁：帧容器为进程级静态，并行执行会互相串扰。
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

#[test]
fn test_audio_basic_loopback() {
    let _serial = serial();
    init_logger();
    ensure_tcp_listener();
    reset_frames();
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

    unsafe { ffi::audio_stream::nrc_register_audio_data_cb(ctx_b_ptr, Some(recv_callback)) };
    unsafe {
        ffi::audio_stream::nrc_audio_start(
            ctx_b_ptr,
            dir_recv.as_ptr(),
            port as i32,
            48000,
            2,
            uuid.as_ptr(),
        );
        ffi::audio_stream::nrc_audio_start(
            ctx_a_ptr,
            dir_send.as_ptr(),
            port as i32,
            48000,
            2,
            uuid.as_ptr(),
        );
    }

    let frame = sine_frame();
    for _ in 0..20 {
        unsafe {
            ffi::audio_stream::nrc_audio_write_frame(ctx_a_ptr, frame.as_ptr(), frame.len() as i32);
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    assert!(wait_for_frames(1, Duration::from_secs(5)), "未收到音频帧");

    ffi::audio_stream::nrc_audio_stop(ctx_a_ptr);
    ffi::audio_stream::nrc_audio_stop(ctx_b_ptr);

    let captured = RECEIVED_FRAMES.lock().unwrap();
    assert!(!captured.is_empty(), "未捕获到音频帧");
    let energy = rms(&captured[0]);
    assert!(energy > 4000.0, "RMS 过低: {:.1}", energy);
}

#[test]
fn test_audio_stop_start_idempotent() {
    let _serial = serial();
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
        reset_frames();

        unsafe { ffi::audio_stream::nrc_register_audio_data_cb(ctx_b_ptr, Some(recv_callback)) };
        unsafe {
            ffi::audio_stream::nrc_audio_start(
                ctx_b_ptr,
                dir_recv.as_ptr(),
                port as i32,
                48000,
                2,
                uuid.as_ptr(),
            );
            ffi::audio_stream::nrc_audio_start(
                ctx_a_ptr,
                dir_send.as_ptr(),
                port as i32,
                48000,
                2,
                uuid.as_ptr(),
            );
        }

        let frame = sine_frame();
        for _ in 0..10 {
            unsafe {
                ffi::audio_stream::nrc_audio_write_frame(
                    ctx_a_ptr,
                    frame.as_ptr(),
                    frame.len() as i32,
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        assert!(
            wait_for_frames(1, Duration::from_secs(5)),
            "第 {} 轮: 未收到音频帧",
            round
        );

        ffi::audio_stream::nrc_audio_stop(ctx_a_ptr);
        ffi::audio_stream::nrc_audio_stop(ctx_b_ptr);

        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
fn test_audio_reconnect_multiple() {
    let _serial = serial();
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
        reset_frames();

        unsafe { ffi::audio_stream::nrc_register_audio_data_cb(ctx_b_ptr, Some(recv_callback)) };
        unsafe {
            ffi::audio_stream::nrc_audio_start(
                ctx_b_ptr,
                dir_recv.as_ptr(),
                port as i32,
                48000,
                2,
                uuid.as_ptr(),
            );
            ffi::audio_stream::nrc_audio_start(
                ctx_a_ptr,
                dir_send.as_ptr(),
                port as i32,
                48000,
                2,
                uuid.as_ptr(),
            );
        }

        std::thread::sleep(Duration::from_millis(200));

        let frame = sine_frame();
        for _ in 0..10 {
            unsafe {
                ffi::audio_stream::nrc_audio_write_frame(
                    ctx_a_ptr,
                    frame.as_ptr(),
                    frame.len() as i32,
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        assert!(
            wait_for_frames(5, Duration::from_secs(5)),
            "第 {} 轮: 帧数不足",
            round
        );

        let captured = RECEIVED_FRAMES.lock().unwrap().clone();
        let avg_rms: f64 = captured.iter().map(|x| rms(x)).sum::<f64>() / captured.len() as f64;
        assert!(
            avg_rms > 4000.0,
            "第 {} 轮: 平均 RMS 过低: {:.1}",
            round,
            avg_rms
        );

        ffi::audio_stream::nrc_audio_stop(ctx_a_ptr);
        ffi::audio_stream::nrc_audio_stop(ctx_b_ptr);

        std::thread::sleep(Duration::from_millis(200));
    }
}
