use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::raw::{c_char, c_void};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

pub type AudioDataCb = Option<extern "C" fn(*const c_char, *const u8, i32, i32, i32, *mut c_void)>;
pub type AudioEventCb =
    Option<extern "C" fn(*const c_char, *const c_char, *const c_char, *mut c_void)>;

pub struct AudioStreamState {
    pub listener: Option<TcpListener>,
    pub stream_slot: Arc<Mutex<Option<TcpStream>>>,
    pub active: Arc<AtomicBool>,
    pub sample_rate: i32,
    pub channels: i32,
    pub thread_handle: Option<thread::JoinHandle<()>>,
    pub on_data: AudioDataCb,
    pub on_event: AudioEventCb,
    pub user_data: *mut c_void,
    pub remote_uuid: String,
}

impl AudioStreamState {
    pub fn new() -> Self {
        Self {
            listener: None,
            stream_slot: Arc::new(Mutex::new(None)),
            active: Arc::new(AtomicBool::new(false)),
            sample_rate: 0,
            channels: 0,
            thread_handle: None,
            on_data: None,
            on_event: None,
            user_data: std::ptr::null_mut(),
            remote_uuid: String::new(),
        }
    }
}

/// 连接接收端 :23335（用于推流或读取）
pub(crate) fn start_sender(
    state: &mut AudioStreamState,
    ip: &str,
    port: u16,
    sample_rate: i32,
    channels: i32,
) -> bool {
    if state.active.load(Ordering::SeqCst) {
        log::warn!("音频流: 已在运行，无法重复启动发送端");
        return false;
    }
    let addr = format!("{}:{}", ip, port);
    let stream = match TcpStream::connect(&addr) {
        Ok(s) => s,
        Err(e) => {
            log::error!("音频流: 连接对端 {addr} 失败: {e}");
            return false;
        }
    };
    state.sample_rate = sample_rate;
    state.channels = channels;
    let cloned = stream.try_clone().unwrap();
    *state.stream_slot.lock().unwrap() = Some(cloned);
    state.active.store(true, Ordering::SeqCst);
    log::info!("音频流: 发送端已连接到 {addr}");

    // 启动读取循环（接收端连接后也要读数据）
    start_read_thread(state, stream);
    true
}

/// 在独立线程中读取 PCM 数据并回调
fn start_read_thread(state: &mut AudioStreamState, stream: TcpStream) {
    let active = state.active.clone();
    let sample_rate = state.sample_rate;
    let channels = state.channels;
    let on_data = state.on_data;
    let ud = state.user_data as usize;

    let handle = thread::spawn(move || {
        let ud_ptr = ud as *mut c_void;
        log::info!("音频流: 读取线程已启动");
        read_loop(stream, active, sample_rate, channels, on_data, ud_ptr);
        log::info!("音频流: 读取线程已结束");
    });
    state.thread_handle = Some(handle);
}

/// 接收端：监听 :23335，等待发送端连接
pub(crate) fn start_receiver(
    state: &mut AudioStreamState,
    port: u16,
    sample_rate: i32,
    channels: i32,
) -> bool {
    if state.active.load(Ordering::SeqCst) {
        log::warn!("音频流: 已在运行，无法重复启动接收端");
        return false;
    }
    let listener = match TcpListener::bind(format!("0.0.0.0:{}", port)) {
        Ok(l) => l,
        Err(e) => {
            log::error!("音频流: 绑定端口 :{port} 失败: {e}");
            return false;
        }
    };
    state.sample_rate = sample_rate;
    state.channels = channels;
    state.listener = Some(listener);
    state.active.store(true, Ordering::SeqCst);
    log::info!("音频流: 正在监听端口 :{port}");
    true
}

/// 独立线程等待连接 → 连接后仅存储 stream（发送方写数据用）
pub(crate) fn start_accept_thread(state: &mut AudioStreamState) {
    let listener = match state.listener.as_ref() {
        Some(l) => l.try_clone().unwrap(),
        None => return,
    };
    let stream_slot = state.stream_slot.clone();

    let handle = thread::spawn(move || {
        log::info!("音频流: 等待对端连接...");
        match listener.accept() {
            Ok((stream, addr)) => {
                log::info!("音频流: 对端已连接 {addr}");
                if let Ok(cloned) = stream.try_clone() {
                    *stream_slot.lock().unwrap() = Some(cloned);
                }
            }
            Err(e) => log::error!("音频流: 接受连接失败: {e}"),
        }
    });
    state.thread_handle = Some(handle);
}

/// 读取循环：读帧长(4B BE)→读PCM→回调
fn read_loop(
    mut stream: TcpStream,
    active: Arc<AtomicBool>,
    sample_rate: i32,
    channels: i32,
    on_data: AudioDataCb,
    user_data: *mut c_void,
) {
    let mut len_buf = [0u8; 4];
    loop {
        if !active.load(Ordering::SeqCst) {
            break;
        }
        if stream.read_exact(&mut len_buf).is_err() {
            break;
        }
        let frame_len = u32::from_be_bytes(len_buf) as usize;
        let mut pcm = vec![0u8; frame_len];
        if stream.read_exact(&mut pcm).is_err() {
            break;
        }
        if let Some(cb) = on_data {
            let dev = std::ffi::CString::new("").unwrap();
            cb(
                dev.as_ptr(),
                pcm.as_ptr(),
                frame_len as i32,
                sample_rate,
                channels,
                user_data,
            );
        }
    }
    active.store(false, Ordering::SeqCst);
    log::info!("音频流: 读取循环已退出");
}

/// 写入一帧 PCM（发送端调用）
pub(crate) fn write_frame(state: &AudioStreamState, pcm_data: &[u8]) -> bool {
    if !state.active.load(Ordering::SeqCst) {
        return false;
    }
    let mut guard = match state.stream_slot.lock() {
        Ok(g) => g,
        Err(_) => return false,
    };
    let stream = match guard.as_mut() {
        Some(s) => s,
        None => return false,
    };
    let len_be = (pcm_data.len() as u32).to_be_bytes();
    if stream.write_all(&len_be).is_err() {
        return false;
    }
    if stream.write_all(pcm_data).is_err() {
        return false;
    }
    true
}

/// 停止
pub(crate) fn stop(state: &mut AudioStreamState) {
    state.active.store(false, Ordering::SeqCst);
    if let Ok(mut guard) = state.stream_slot.lock() {
        if let Some(stream) = guard.take() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }
    state.listener.take();
    state.thread_handle.take().map(|h| h.join());
    log::info!("音频流: 已停止");
}
