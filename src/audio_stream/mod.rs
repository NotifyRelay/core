use std::collections::VecDeque;
use std::net::{SocketAddr, UdpSocket};
use std::os::raw::{c_char, c_void};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use bytes::Bytes;
use rtp::header::Header;
use rtp::packet::Packet;
use webrtc_util::marshal::{Marshal, MarshalSize, Unmarshal};

use crate::audio_codec::{JitterBuffer, OpusDecoder, OpusEncoder};

pub type AudioDataCb = Option<extern "C" fn(*const c_char, *const u8, i32, i32, i32, *mut c_void)>;
pub type AudioEventCb =
    Option<extern "C" fn(*const c_char, *const c_char, *const c_char, *mut c_void)>;

pub struct AudioStats {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub packets_lost: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub opus_bytes_sent: u64,
    pub start_time: Instant,
}

impl AudioStats {
    pub fn new() -> Self {
        Self {
            packets_sent: 0,
            packets_received: 0,
            packets_lost: 0,
            bytes_sent: 0,
            bytes_received: 0,
            opus_bytes_sent: 0,
            start_time: Instant::now(),
        }
    }
}

pub struct AudioStreamState {
    pub active: Arc<AtomicBool>,
    pub sample_rate: i32,
    pub channels: i32,
    pub thread_handle: Option<thread::JoinHandle<()>>,
    pub playback_handle: Option<thread::JoinHandle<()>>,
    pub on_data: AudioDataCb,
    pub on_event: AudioEventCb,
    pub user_data: *mut c_void,
    pub remote_uuid: String,
    pub peer_ip: String,
    pub peer_port: u16,

    pub udp_socket: Option<UdpSocket>,
    pub encoder: Arc<Mutex<Option<OpusEncoder>>>,
    pub decoder: Arc<Mutex<Option<OpusDecoder>>>,
    pub jitter: Arc<Mutex<Option<JitterBuffer>>>,
    pub rtp_seq: Arc<Mutex<u16>>,
    pub rtp_ts: Arc<Mutex<u32>>,
    pub ssrc: u32,
    pub stats: Arc<Mutex<AudioStats>>,
    pub pcm_queue: Arc<Mutex<VecDeque<Vec<i16>>>>,
}

impl AudioStreamState {
    pub fn new() -> Self {
        Self {
            active: Arc::new(AtomicBool::new(false)),
            sample_rate: 0,
            channels: 0,
            thread_handle: None,
            playback_handle: None,
            on_data: None,
            on_event: None,
            user_data: std::ptr::null_mut(),
            remote_uuid: String::new(),
            peer_ip: String::new(),
            peer_port: 0,
            udp_socket: None,
            encoder: Arc::new(Mutex::new(None)),
            decoder: Arc::new(Mutex::new(None)),
            jitter: Arc::new(Mutex::new(None)),
            rtp_seq: Arc::new(Mutex::new(0)),
            rtp_ts: Arc::new(Mutex::new(0)),
            ssrc: rand::random(),
            stats: Arc::new(Mutex::new(AudioStats::new())),
            pcm_queue: Arc::new(Mutex::new(VecDeque::new())),
        }
    }
}

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

    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            log::error!("音频流: 创建 UDP socket 失败: {e}");
            return false;
        }
    };

    let encoder = match OpusEncoder::new(sample_rate, channels) {
        Ok(e) => e,
        Err(e) => {
            log::error!("音频流: 创建 Opus 编码器失败: {e}");
            return false;
        }
    };

    state.sample_rate = sample_rate;
    state.channels = channels;
    state.peer_ip = ip.to_string();
    state.peer_port = port;
    state.udp_socket = Some(socket);
    *state.encoder.lock().unwrap() = Some(encoder);
    state.active.store(true, Ordering::SeqCst);

    let mut stats = state.stats.lock().unwrap();
    *stats = AudioStats::new();

    log::info!("音频流: 发送端已启动，对端 {ip}:{port}");
    true
}

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

    let addr: SocketAddr = match format!("0.0.0.0:{}", port).parse() {
        Ok(a) => a,
        Err(e) => {
            log::error!("音频流: 地址解析失败: {e}");
            return false;
        }
    };

    let socket = match UdpSocket::bind(&addr) {
        Ok(s) => s,
        Err(e) => {
            log::error!("音频流: 绑定端口 :{port} 失败: {e}");
            return false;
        }
    };

    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .ok();

    let decoder = match OpusDecoder::new(sample_rate, channels) {
        Ok(d) => d,
        Err(e) => {
            log::error!("音频流: 创建 Opus 解码器失败: {e}");
            return false;
        }
    };

    state.sample_rate = sample_rate;
    state.channels = channels;
    state.udp_socket = Some(socket);
    *state.decoder.lock().unwrap() = Some(decoder);
    *state.jitter.lock().unwrap() = Some(JitterBuffer::new());
    state.active.store(true, Ordering::SeqCst);

    {
        let mut stats = state.stats.lock().unwrap();
        *stats = AudioStats::new();
    }

    log::info!("音频流: 接收端已启动，监听 :{port}");

    start_read_thread(state);
    true
}

fn start_read_thread(state: &mut AudioStreamState) {
    let socket = match state.udp_socket.as_ref() {
        Some(s) => s.try_clone().unwrap(),
        None => return,
    };
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .ok();

    let active = state.active.clone();
    let sample_rate = state.sample_rate;
    let channels = state.channels;
    let on_data = state.on_data;
    let ud = state.user_data as usize;

    let decoder = Arc::clone(&state.decoder);
    let jitter = Arc::clone(&state.jitter);
    let stats = Arc::clone(&state.stats);
    let pcm_queue = Arc::clone(&state.pcm_queue);

    let active_clone = Arc::clone(&active);
    let pcm_queue_clone = Arc::clone(&pcm_queue);
    let handle = thread::spawn(move || {
        log::info!("音频流: 读取线程已启动");
        read_loop(
            socket,
            active_clone,
            sample_rate,
            channels,
            decoder,
            jitter,
            stats,
            pcm_queue_clone,
        );
        log::info!("音频流: 读取线程已结束");
    });
    state.thread_handle = Some(handle);

    let playback_handle = thread::spawn(move || {
        let ud_ptr = ud as *mut c_void;
        log::info!("音频流: 播放线程已启动");
        playback_loop(active, on_data, ud_ptr, sample_rate, channels, pcm_queue);
        log::info!("音频流: 播放线程已结束");
    });
    state.playback_handle = Some(playback_handle);
}

fn read_loop(
    socket: UdpSocket,
    active: Arc<AtomicBool>,
    _sample_rate: i32,
    _channels: i32,
    decoder: Arc<Mutex<Option<OpusDecoder>>>,
    jitter: Arc<Mutex<Option<JitterBuffer>>>,
    stats: Arc<Mutex<AudioStats>>,
    pcm_queue: Arc<Mutex<VecDeque<Vec<i16>>>>,
) {
    let mut buf = [0u8; 2048];

    loop {
        if !active.load(Ordering::SeqCst) {
            break;
        }

        match socket.recv_from(&mut buf) {
            Ok((n, _src)) => {
                let mut data = &buf[..n];
                let pkt = match Packet::unmarshal(&mut data) {
                    Ok(p) => p,
                    Err(e) => {
                        log::debug!("音频流: RTP 解包失败: {e}");
                        continue;
                    }
                };

                let seq = pkt.header.sequence_number;
                let payload = pkt.payload.to_vec();

                {
                    let mut jitter_guard = jitter.lock().unwrap();
                    let jitter_buf = jitter_guard.as_mut().unwrap();
                    jitter_buf.push(seq, payload);
                }

                {
                    let mut stats_guard = stats.lock().unwrap();
                    stats_guard.packets_received += 1;
                    stats_guard.bytes_received += n as u64;
                }

                loop {
                    if !active.load(Ordering::SeqCst) {
                        break;
                    }

                    let (opus_data, lost_count) = {
                        let mut jitter_guard = jitter.lock().unwrap();
                        let jitter_buf = jitter_guard.as_mut().unwrap();
                        jitter_buf.pop_with_gap()
                    };

                    if lost_count > 0 {
                        let mut stats_guard = stats.lock().unwrap();
                        stats_guard.packets_lost += lost_count;

                        for _ in 0..lost_count {
                            let pcm = {
                                let mut decoder_guard = decoder.lock().unwrap();
                                let dec = decoder_guard.as_mut().unwrap();
                                match dec.decode_loss() {
                                    Ok(p) => p,
                                    Err(e) => {
                                        log::warn!("音频流: Opus PLC 失败: {e}");
                                        continue;
                                    }
                                }
                            };

                            {
                                let mut queue_guard = pcm_queue.lock().unwrap();
                                queue_guard.push_back(pcm);
                                if queue_guard.len() > 50 {
                                    queue_guard.pop_front();
                                }
                            }
                        }
                    }

                    match opus_data {
                        Some(data) => {
                            let pcm = {
                                let mut decoder_guard = decoder.lock().unwrap();
                                let dec = decoder_guard.as_mut().unwrap();
                                match dec.decode(&data) {
                                    Ok(p) => p,
                                    Err(e) => {
                                        log::warn!("音频流: Opus 解码失败: {e}");
                                        continue;
                                    }
                                }
                            };

                            {
                                let mut queue_guard = pcm_queue.lock().unwrap();
                                queue_guard.push_back(pcm);
                                if queue_guard.len() > 50 {
                                    queue_guard.pop_front();
                                }
                            }
                        }
                        None => break,
                    }
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => {
                log::error!("音频流: UDP 接收失败: {e}");
                break;
            }
        }
    }
    active.store(false, Ordering::SeqCst);
    log::info!("音频流: 读取循环已退出");
}

fn playback_loop(
    active: Arc<AtomicBool>,
    on_data: AudioDataCb,
    user_data: *mut c_void,
    sample_rate: i32,
    channels: i32,
    pcm_queue: Arc<Mutex<VecDeque<Vec<i16>>>>,
) {
    loop {
        if !active.load(Ordering::SeqCst) {
            break;
        }

        let pcm = {
            let mut queue_guard = pcm_queue.lock().unwrap();
            queue_guard.pop_front()
        };

        match pcm {
            Some(data) => {
                if let Some(cb) = on_data {
                    let pcm_bytes = unsafe {
                        std::slice::from_raw_parts(
                            data.as_ptr() as *const u8,
                            data.len() * std::mem::size_of::<i16>(),
                        )
                    };
                    let dev = std::ffi::CString::new("").unwrap();
                    cb(
                        dev.as_ptr(),
                        pcm_bytes.as_ptr(),
                        pcm_bytes.len() as i32,
                        sample_rate,
                        channels,
                        user_data,
                    );
                }
            }
            None => {
                thread::sleep(Duration::from_millis(1));
                continue;
            }
        }
    }
}

pub(crate) fn write_frame(state: &AudioStreamState, pcm_data: &[u8]) -> bool {
    if !state.active.load(Ordering::SeqCst) {
        return false;
    }

    let pcm: Vec<i16> = pcm_data
        .chunks_exact(2)
        .map(|c| i16::from_le_bytes([c[0], c[1]]))
        .collect();

    let mut encoder_guard = match state.encoder.try_lock() {
        Ok(g) => g,
        Err(_) => return false,
    };
    let encoder = match encoder_guard.as_mut() {
        Some(e) => e,
        None => return false,
    };

    let opus_data = match encoder.encode(&pcm) {
        Ok(d) => d,
        Err(e) => {
            log::warn!("音频流: Opus 编码失败: {e}");
            return false;
        }
    };

    let socket = match state.udp_socket.as_ref() {
        Some(s) => s,
        None => return false,
    };

    let peer_addr = SocketAddr::new(
        match state.peer_ip.parse() {
            Ok(ip) => ip,
            Err(_) => return false,
        },
        state.peer_port,
    );

    let mut seq_guard = match state.rtp_seq.try_lock() {
        Ok(g) => g,
        Err(_) => return false,
    };
    let seq = *seq_guard;
    *seq_guard = seq.wrapping_add(1);

    let mut ts_guard = match state.rtp_ts.try_lock() {
        Ok(g) => g,
        Err(_) => return false,
    };
    let ts = *ts_guard;
    *ts_guard += encoder.frame_size() as u32;

    let ssrc = state.ssrc;

    let pkt = Packet {
        header: Header {
            version: 2,
            marker: false,
            payload_type: 97,
            sequence_number: seq,
            timestamp: ts,
            ssrc,
            csrc: vec![],
            padding: false,
            extension: false,
            extension_profile: 0,
            extensions: vec![],
            extensions_padding: 0,
        },
        payload: Bytes::from(opus_data.clone()),
    };

    let mut rtp_buf = vec![0u8; pkt.marshal_size()];
    if pkt.marshal_to(&mut rtp_buf).is_err() {
        log::warn!("音频流: RTP 打包失败");
        return false;
    }

    match socket.send_to(&rtp_buf, &peer_addr) {
        Ok(n) => {
            if let Ok(mut stats) = state.stats.try_lock() {
                stats.packets_sent += 1;
                stats.bytes_sent += n as u64;
                stats.opus_bytes_sent += opus_data.len() as u64;
            }
            true
        }
        Err(e) => {
            log::warn!("音频流: UDP 发送失败: {e}");
            false
        }
    }
}

pub(crate) fn stop(state: &mut AudioStreamState) -> Vec<std::thread::JoinHandle<()>> {
    state.active.store(false, Ordering::SeqCst);

    drop(state.udp_socket.take());

    let mut handles = Vec::new();
    if let Some(h) = state.thread_handle.take() {
        handles.push(h);
    }
    if let Some(h) = state.playback_handle.take() {
        handles.push(h);
    }

    if let Ok(stats) = state.stats.try_lock() {
        let elapsed = stats.start_time.elapsed().as_secs_f64();
        let pcm_bytes = stats.packets_sent * 960 * 2 * 2;
        let compression_ratio = if pcm_bytes > 0 {
            pcm_bytes as f64 / stats.opus_bytes_sent as f64
        } else {
            0.0
        };
        let actual_bitrate = if elapsed > 0.0 {
            (stats.opus_bytes_sent * 8) as f64 / elapsed / 1000.0
        } else {
            0.0
        };
        let loss_rate = if stats.packets_received > 0 {
            (stats.packets_lost as f64 / stats.packets_received as f64) * 100.0
        } else {
            0.0
        };

        log::info!(
            "[音频流] 会话统计: 发送 {} 包, 接收 {} 包, 丢包 {} ({:.2}%), 原始 PCM {:.1} MB → Opus {:.1} MB (压缩比 {:.1}:1), 实际比特率 {:.1} kbps, 帧大小 960, 持续时间 {:.1}s",
            stats.packets_sent,
            stats.packets_received,
            stats.packets_lost,
            loss_rate,
            pcm_bytes as f64 / 1024.0 / 1024.0,
            stats.opus_bytes_sent as f64 / 1024.0 / 1024.0,
            compression_ratio,
            actual_bitrate,
            elapsed,
        );
    }

    let _ = state.encoder.try_lock().map(|mut g| *g = None);
    let _ = state.decoder.try_lock().map(|mut g| *g = None);
    let _ = state.jitter.try_lock().map(|mut g| *g = None);
    let _ = state.stats.try_lock().map(|mut g| *g = AudioStats::new());
    let _ = state.pcm_queue.try_lock().map(|mut g| g.clear());

    state.on_data = None;
    state.on_event = None;
    state.remote_uuid.clear();
    state.peer_ip.clear();
    state.peer_port = 0;
    log::info!("音频流: 已停止");

    handles
}
