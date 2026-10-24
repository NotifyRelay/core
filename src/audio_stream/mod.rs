use std::collections::VecDeque;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use bytes::Bytes;
use parking_lot::Mutex;
use rtp::header::Header;
use rtp::packet::Packet;
use webrtc_util::marshal::{Marshal, MarshalSize, Unmarshal};

use crate::audio_codec::{JitterBuffer, OpusDecoder, OpusEncoder};

/// 音频 PCM 数据回调：`(device_uuid, pcm, sample_rate, channels)`。
pub type AudioDataCb = Arc<dyn Fn(&str, &[u8], i32, i32) + Send + Sync>;
/// 音频事件回调：`(device_uuid, event, data)`。
pub type AudioEventCb = Arc<dyn Fn(&str, &str, &str) + Send + Sync>;

pub struct AudioStats {
    pub packets_sent: AtomicU64,
    pub packets_received: AtomicU64,
    pub packets_lost: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub opus_bytes_sent: AtomicU64,
    pub opus_bytes_received: AtomicU64,
    pub sent_frames: AtomicU64,
    pub sent_silence_frames: AtomicU64,
    pub recv_played_frames: AtomicU64,
    pub recv_silence_frames: AtomicU64,
    pub no_data_ms: AtomicU64,
    pub start_time: parking_lot::Mutex<Instant>,
}

impl AudioStats {
    pub fn new() -> Self {
        Self {
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            packets_lost: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            opus_bytes_sent: AtomicU64::new(0),
            opus_bytes_received: AtomicU64::new(0),
            sent_frames: AtomicU64::new(0),
            sent_silence_frames: AtomicU64::new(0),
            recv_played_frames: AtomicU64::new(0),
            recv_silence_frames: AtomicU64::new(0),
            no_data_ms: AtomicU64::new(0),
            start_time: parking_lot::Mutex::new(Instant::now()),
        }
    }

    pub fn reset(&self) {
        self.packets_sent.store(0, Ordering::Relaxed);
        self.packets_received.store(0, Ordering::Relaxed);
        self.packets_lost.store(0, Ordering::Relaxed);
        self.bytes_sent.store(0, Ordering::Relaxed);
        self.bytes_received.store(0, Ordering::Relaxed);
        self.opus_bytes_sent.store(0, Ordering::Relaxed);
        self.opus_bytes_received.store(0, Ordering::Relaxed);
        self.sent_frames.store(0, Ordering::Relaxed);
        self.sent_silence_frames.store(0, Ordering::Relaxed);
        self.recv_played_frames.store(0, Ordering::Relaxed);
        self.recv_silence_frames.store(0, Ordering::Relaxed);
        self.no_data_ms.store(0, Ordering::Relaxed);
        *self.start_time.lock() = Instant::now();
    }
}

impl Default for AudioStats {
    fn default() -> Self {
        Self::new()
    }
}

fn is_silent_frame(pcm: &[i16], threshold: i16) -> bool {
    pcm.iter().all(|&s| s.abs() <= threshold)
}

pub struct AudioStreamState {
    pub active: Arc<AtomicBool>,
    pub sample_rate: i32,
    pub channels: i32,
    pub thread_handle: Option<thread::JoinHandle<()>>,
    pub playback_handle: Option<thread::JoinHandle<()>>,
    pub on_data: Option<AudioDataCb>,
    pub on_event: Option<AudioEventCb>,
    pub remote_uuid: String,
    pub peer_ip: String,
    pub peer_port: u16,

    pub udp_socket: Option<UdpSocket>,
    pub encoder: Arc<Mutex<Option<OpusEncoder>>>,
    pub decoder: Arc<Mutex<Option<OpusDecoder>>>,
    pub jitter: Arc<Mutex<Option<JitterBuffer>>>,
    pub rtp_seq: AtomicU16,
    pub rtp_ts: AtomicU32,
    pub ssrc: u32,
    pub stats: Arc<AudioStats>,
    pub pcm_queue: Arc<Mutex<VecDeque<Vec<i16>>>>,
    pub pcm_buffer: Arc<Mutex<Vec<i16>>>,
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
            remote_uuid: String::new(),
            peer_ip: String::new(),
            peer_port: 0,
            udp_socket: None,
            encoder: Arc::new(Mutex::new(None)),
            decoder: Arc::new(Mutex::new(None)),
            jitter: Arc::new(Mutex::new(None)),
            rtp_seq: AtomicU16::new(0),
            rtp_ts: AtomicU32::new(0),
            ssrc: rand::random(),
            stats: Arc::new(AudioStats::new()),
            pcm_queue: Arc::new(Mutex::new(VecDeque::new())),
            pcm_buffer: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl Default for AudioStreamState {
    fn default() -> Self {
        Self::new()
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

    let socket = match socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    ) {
        Ok(s) => s,
        Err(e) => {
            log::error!("音频流: 创建 UDP socket 失败: {e}");
            return false;
        }
    };

    if let Err(e) = socket.set_reuse_address(true) {
        log::warn!("音频流: 设置 SO_REUSEADDR 失败: {e}");
    }

    if let Err(e) = socket.set_send_buffer_size(256 * 1024) {
        log::warn!("音频流: 设置 SO_SNDBUF 失败: {e}");
    }

    let addr: std::net::SocketAddr = "0.0.0.0:0".parse().unwrap();
    let sock_addr: socket2::SockAddr = addr.into();
    if let Err(e) = socket.bind(&sock_addr) {
        log::error!("音频流: 绑定 UDP socket 失败: {e}");
        return false;
    }

    let socket = UdpSocket::from(socket);

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
    *state.encoder.lock() = Some(encoder);
    state.active.store(true, Ordering::SeqCst);

    state.stats.reset();
    *state.stats.start_time.lock() = Instant::now();

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

    let socket = match socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    ) {
        Ok(s) => s,
        Err(e) => {
            log::error!("音频流: 创建 UDP socket 失败: {e}");
            return false;
        }
    };

    if let Err(e) = socket.set_reuse_address(true) {
        log::warn!("音频流: 设置 SO_REUSEADDR 失败: {e}");
    }

    if let Err(e) = socket.set_recv_buffer_size(256 * 1024) {
        log::warn!("音频流: 设置 SO_RCVBUF 失败: {e}");
    }

    let sock_addr: socket2::SockAddr = addr.into();
    if let Err(e) = socket.bind(&sock_addr) {
        log::error!("音频流: 绑定端口 :{port} 失败: {e}");
        return false;
    }

    let socket = UdpSocket::from(socket);

    socket
        .set_read_timeout(Some(Duration::from_millis(10)))
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
    *state.decoder.lock() = Some(decoder);
    *state.jitter.lock() = Some(JitterBuffer::new());
    state.active.store(true, Ordering::SeqCst);

    state.stats.reset();
    *state.stats.start_time.lock() = Instant::now();

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
        .set_read_timeout(Some(Duration::from_millis(10)))
        .ok();

    let active = state.active.clone();
    let sample_rate = state.sample_rate;
    let channels = state.channels;
    let on_data = state.on_data.clone();

    let decoder = Arc::clone(&state.decoder);
    let jitter = Arc::clone(&state.jitter);
    let stats = Arc::clone(&state.stats);
    let pcm_queue = Arc::clone(&state.pcm_queue);

    let active_clone = Arc::clone(&active);
    let pcm_queue_clone = Arc::clone(&pcm_queue);
    let playback_stats = Arc::clone(&state.stats);
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
        let mut wait_count = 0;
        while active.load(Ordering::SeqCst) {
            if pcm_queue.lock().len() >= 3 {
                break;
            }
            wait_count += 1;
            thread::sleep(Duration::from_millis(5));
            if wait_count > 200 {
                log::warn!("音频流: 等待预填充超时，直接启动播放");
                break;
            }
        }

        log::info!("音频流: 播放线程已启动");
        playback_loop(
            active,
            on_data,
            sample_rate,
            channels,
            pcm_queue,
            playback_stats,
        );
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
    stats: Arc<AudioStats>,
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
                        log::warn!(
                            "音频流: RTP 解包失败: {e}, 原始数据前16字节: {:02x?}",
                            &buf[..std::cmp::min(16, n)]
                        );
                        continue;
                    }
                };

                let seq = pkt.header.sequence_number;
                let payload = pkt.payload.to_vec();

                {
                    let mut jitter_guard = jitter.lock();
                    if let Some(jitter_buf) = jitter_guard.as_mut() {
                        jitter_buf.push(seq, payload);
                    }
                }

                stats.packets_received.fetch_add(1, Ordering::Relaxed);
                stats.bytes_received.fetch_add(n as u64, Ordering::Relaxed);

                loop {
                    if !active.load(Ordering::SeqCst) {
                        break;
                    }

                    let (opus_data, lost_count) = {
                        let mut jitter_guard = jitter.lock();
                        match jitter_guard.as_mut() {
                            Some(jitter_buf) => jitter_buf.pop_with_gap(),
                            None => break,
                        }
                    };

                    if lost_count > 0 {
                        stats.packets_lost.fetch_add(lost_count, Ordering::Relaxed);

                        for _ in 0..lost_count {
                            let pcm = {
                                let mut decoder_guard = decoder.lock();
                                match decoder_guard.as_mut() {
                                    Some(dec) => match dec.decode_loss() {
                                        Ok(p) => p,
                                        Err(e) => {
                                            log::warn!("音频流: Opus PLC 失败: {e}");
                                            continue;
                                        }
                                    },
                                    None => break,
                                }
                            };

                            {
                                let mut queue_guard = pcm_queue.lock();
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
                                let mut decoder_guard = decoder.lock();
                                match decoder_guard.as_mut() {
                                    Some(dec) => match dec.decode(&data) {
                                        Ok(p) => p,
                                        Err(e) => {
                                            log::warn!("音频流: Opus 解码失败: {e}");
                                            continue;
                                        }
                                    },
                                    None => break,
                                }
                            };

                            stats
                                .opus_bytes_received
                                .fetch_add(data.len() as u64, Ordering::Relaxed);

                            {
                                let mut queue_guard = pcm_queue.lock();
                                queue_guard.push_back(pcm);
                                if queue_guard.len() > 50 {
                                    queue_guard.pop_front();
                                }
                            }
                        }
                        None => {
                            break;
                        }
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
                log::warn!("音频流: UDP 接收临时错误: {e}，继续监听");
                continue;
            }
        }
    }
    active.store(false, Ordering::SeqCst);
    log::info!("音频流: 读取循环已退出");
}

fn playback_loop(
    active: Arc<AtomicBool>,
    on_data: Option<AudioDataCb>,
    sample_rate: i32,
    channels: i32,
    pcm_queue: Arc<Mutex<VecDeque<Vec<i16>>>>,
    stats: Arc<AudioStats>,
) {
    let frame_samples = (sample_rate * 20) / 1000;
    let frame_duration_us = (frame_samples as u64 * 1_000_000) / sample_rate as u64;
    let mut frame_count: u64 = 0;
    let mut start_time = Instant::now();

    loop {
        if !active.load(Ordering::SeqCst) {
            break;
        }

        let pcm = {
            let mut queue_guard = pcm_queue.lock();
            queue_guard.pop_front()
        };

        match pcm {
            Some(data) => {
                stats.recv_played_frames.fetch_add(1, Ordering::Relaxed);
                if is_silent_frame(&data, 50) {
                    stats.recv_silence_frames.fetch_add(1, Ordering::Relaxed);
                }
                if let Some(ref cb) = on_data {
                    let pcm_bytes = unsafe {
                        std::slice::from_raw_parts(
                            data.as_ptr() as *const u8,
                            data.len() * std::mem::size_of::<i16>(),
                        )
                    };
                    cb("", pcm_bytes, sample_rate, channels);
                }

                frame_count += 1;
                let target_time =
                    start_time + Duration::from_micros(frame_duration_us * frame_count);
                let now = Instant::now();

                let lag_us = now.duration_since(target_time).as_micros() as i64;
                if lag_us > 50_000 {
                    start_time = now;
                    frame_count = 1;
                } else if now < target_time {
                    thread::sleep(target_time - now);
                }
            }
            None => {
                stats.no_data_ms.fetch_add(1, Ordering::Relaxed);
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

    let frame_samples = {
        let encoder_guard = match state.encoder.try_lock() {
            Some(g) => g,
            None => return false,
        };
        match encoder_guard.as_ref() {
            Some(e) => e.frame_size() as usize * e.channels() as usize,
            None => return false,
        }
    };

    let mut buffer_guard = match state.pcm_buffer.try_lock() {
        Some(g) => g,
        None => return false,
    };
    buffer_guard.extend_from_slice(&pcm);

    let mut result = true;
    while buffer_guard.len() >= frame_samples {
        let frame_data = buffer_guard.drain(..frame_samples).collect::<Vec<_>>();
        drop(buffer_guard);

        state.stats.sent_frames.fetch_add(1, Ordering::Relaxed);
        if is_silent_frame(&frame_data, 50) {
            state
                .stats
                .sent_silence_frames
                .fetch_add(1, Ordering::Relaxed);
        }

        let mut encoder_guard = match state.encoder.try_lock() {
            Some(g) => g,
            None => return false,
        };
        let encoder = match encoder_guard.as_mut() {
            Some(e) => e,
            None => return false,
        };

        let opus_data = match encoder.encode(&frame_data) {
            Ok(d) => d,
            Err(e) => {
                log::warn!("音频流: Opus 编码失败: {e}");
                result = false;
                break;
            }
        };

        let socket = match state.udp_socket.as_ref() {
            Some(s) => s,
            None => {
                result = false;
                break;
            }
        };

        let peer_addr = SocketAddr::new(
            match state.peer_ip.parse() {
                Ok(ip) => ip,
                Err(_) => {
                    result = false;
                    break;
                }
            },
            state.peer_port,
        );

        let seq = state.rtp_seq.fetch_add(1, Ordering::SeqCst);
        let ts = state
            .rtp_ts
            .fetch_add(encoder.frame_size() as u32, Ordering::SeqCst);
        let ssrc = state.ssrc;

        let opus_len = opus_data.len() as u64;
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
            payload: Bytes::from(opus_data),
        };

        let mut rtp_buf = vec![0u8; pkt.marshal_size()];
        if pkt.marshal_to(&mut rtp_buf).is_err() {
            log::warn!("音频流: RTP 打包失败");
            result = false;
            break;
        }

        match socket.send_to(&rtp_buf, peer_addr) {
            Ok(n) => {
                state.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
                state
                    .stats
                    .bytes_sent
                    .fetch_add(n as u64, Ordering::Relaxed);
                state
                    .stats
                    .opus_bytes_sent
                    .fetch_add(opus_len, Ordering::Relaxed);
            }
            Err(e) => {
                log::warn!("音频流: UDP 发送失败: {e}");
                result = false;
                break;
            }
        }

        buffer_guard = match state.pcm_buffer.try_lock() {
            Some(g) => g,
            None => return result,
        };
    }

    result
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

    let frame_size = match state.encoder.lock().as_ref() {
        Some(e) => e.frame_size(),
        None => match state.decoder.lock().as_ref() {
            Some(d) => d.frame_size(),
            None => 960,
        },
    };

    let elapsed = state.stats.start_time.lock().elapsed().as_secs_f64();
    let packets_sent = state.stats.packets_sent.load(Ordering::Relaxed);
    let packets_received = state.stats.packets_received.load(Ordering::Relaxed);
    let packets_lost = state.stats.packets_lost.load(Ordering::Relaxed);
    let opus_bytes_sent = state.stats.opus_bytes_sent.load(Ordering::Relaxed);
    let opus_bytes_received = state.stats.opus_bytes_received.load(Ordering::Relaxed);

    let pcm_bytes_sent = packets_sent * frame_size as u64 * 2 * 2;
    let _pcm_bytes_received = packets_received * frame_size as u64 * 2 * 2;
    let compression_ratio = if pcm_bytes_sent > 0 {
        pcm_bytes_sent as f64 / opus_bytes_sent as f64
    } else {
        0.0
    };
    let send_bitrate = if elapsed > 0.0 {
        (opus_bytes_sent * 8) as f64 / elapsed / 1000.0
    } else {
        0.0
    };
    let recv_bitrate = if elapsed > 0.0 {
        (opus_bytes_received * 8) as f64 / elapsed / 1000.0
    } else {
        0.0
    };
    let loss_rate = if packets_received > 0 {
        (packets_lost as f64 / packets_received as f64) * 100.0
    } else {
        0.0
    };

    log::info!(
        "[音频流] 会话统计: 发送 {} 包/{} KB, 接收 {} 包/{} KB, 丢包 {} ({:.2}%), 原始 PCM {:.1} MB → Opus {:.1} MB (压缩比 {:.1}:1), 发送比特率 {:.1} kbps, 接收比特率 {:.1} kbps, 帧大小 {}, 持续时间 {:.1}s",
        packets_sent,
        opus_bytes_sent / 1024,
        packets_received,
        opus_bytes_received / 1024,
        packets_lost,
        loss_rate,
        pcm_bytes_sent as f64 / 1024.0 / 1024.0,
        opus_bytes_sent as f64 / 1024.0 / 1024.0,
        compression_ratio,
        send_bitrate,
        recv_bitrate,
        frame_size,
        elapsed,
    );

    let sent_frames = state.stats.sent_frames.load(Ordering::Relaxed);
    let sent_silence_frames = state.stats.sent_silence_frames.load(Ordering::Relaxed);
    let recv_played_frames = state.stats.recv_played_frames.load(Ordering::Relaxed);
    let recv_silence_frames = state.stats.recv_silence_frames.load(Ordering::Relaxed);
    let no_data_ms = state.stats.no_data_ms.load(Ordering::Relaxed);

    if state.encoder.lock().is_some() && sent_frames > 0 {
        log::info!(
            "音频流: 发送端无声占比 {:.2}% (静默 {} / 总帧 {})",
            sent_silence_frames as f64 / sent_frames as f64 * 100.0,
            sent_silence_frames,
            sent_frames
        );
    }
    if state.decoder.lock().is_some() && recv_played_frames > 0 {
        let no_data_pct = if elapsed > 0.0 {
            no_data_ms as f64 / (elapsed * 1000.0) * 100.0
        } else {
            0.0
        };
        log::info!(
            "音频流: 接收端无声占比 {:.2}% (静默 {} / 播放 {}), 无数据时段 {} ms (占 {:.2}%)",
            recv_silence_frames as f64 / recv_played_frames as f64 * 100.0,
            recv_silence_frames,
            recv_played_frames,
            no_data_ms,
            no_data_pct
        );
    }

    state.remote_uuid.clear();
    state.peer_ip.clear();
    state.peer_port = 0;
    log::info!("音频流: 已停止");

    handles
}

// ===== 上下文级音频入口 =====

use crate::SafeContext;

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

    let key_arr = match ctx.crypto.get_aes_key(remote_uuid) {
        Some(k) => k,
        None => {
            log::warn!("音频流: 未找到对端密钥或密钥无效 uuid={}", remote_uuid);
            return;
        }
    };

    let local_uuid = ctx
        .broadcast_info
        .as_ref()
        .map(|i| i.uuid.clone())
        .unwrap_or_default();

    // DATA 通道加密统一绑定 core 版本 AAD（与 sender_queue / process_data 一致）
    if let Ok(encrypted) = crate::crypto::aes::encrypt_with_aad(
        &key_arr,
        payload.as_bytes(),
        &crate::protocol::version::data_aad(),
    ) {
        let msg = crate::protocol::codec::encode_data_message(
            "DATA_MEDIA_CONTROL",
            &local_uuid,
            "",
            &encrypted,
        );
        let ip = ctx.audio.lock().unwrap().peer_ip.clone();

        if !ip.is_empty() && ip != "0.0.0.0" {
            if crate::network::oneshot_send_only(
                &msg,
                &ip,
                crate::protocol::codec::DEFAULT_TCP_PORT,
                3000,
            ) {
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

/// 启动音频流。`direction` 为 "send" 或 "recv"；返回 0 表示成功。
pub fn start(
    ctx: &SafeContext,
    direction: &str,
    port: i32,
    sample_rate: i32,
    channels: i32,
    remote_uuid: &str,
) -> i32 {
    let p = port as u16;
    log::info!(
        "音频流: 启动 方向={}, 端口={}, 采样率={}, 声道数={}, 远端UUID={}",
        direction,
        port,
        sample_rate,
        channels,
        remote_uuid
    );

    let start_ok = {
        let Ok(guard) = ctx.lock() else {
            return -1;
        };
        let mut audio_state = guard.audio.lock().unwrap();
        audio_state.remote_uuid = remote_uuid.to_string();

        match direction {
            "send" => {
                let resolved_ip = guard
                    .device_ips
                    .lock()
                    .ok()
                    .and_then(|m| m.get(remote_uuid).cloned())
                    .filter(|ip| !ip.is_empty() && ip != "0.0.0.0")
                    .unwrap_or_else(|| {
                        log::error!("音频流: 无法解析对端IP uuid={}", remote_uuid);
                        String::new()
                    });
                if resolved_ip.is_empty() {
                    false
                } else {
                    audio_state.peer_ip = resolved_ip.clone();
                    start_sender(&mut audio_state, &resolved_ip, p, sample_rate, channels)
                }
            }
            "recv" => {
                audio_state.peer_ip = String::new();
                start_receiver(&mut audio_state, p, sample_rate, channels)
            }
            _ => {
                log::error!("音频流: 未知方向 {}", direction);
                false
            }
        }
    };

    if start_ok {
        log::info!("音频流: 启动成功");
        if direction == "send" {
            if let Ok(guard) = ctx.lock() {
                send_control(&guard, remote_uuid, "audioStart", sample_rate, channels);
            }
        }
        0
    } else {
        log::error!("音频流: 启动失败");
        -1
    }
}

/// 写入一帧 PCM 数据（16 位小端）。
pub fn write_pcm_frame(ctx: &SafeContext, pcm_data: &[u8]) -> i32 {
    if pcm_data.is_empty() {
        return -1;
    }
    let Ok(guard) = ctx.lock() else {
        return -1;
    };
    if let Ok(audio_state) = guard.audio.try_lock() {
        if write_frame(&audio_state, pcm_data) {
            return 0;
        }
    }
    -1
}

/// 停止音频流。
pub fn stop_stream(ctx: &SafeContext) -> i32 {
    log::info!("音频流: 停止开始");

    let uuid = {
        let Ok(guard) = ctx.lock() else {
            return -1;
        };
        let uuid = guard.audio.lock().unwrap().remote_uuid.clone();
        if !uuid.is_empty() {
            log::info!("音频流: 发送 audioStop 控制消息到 uuid={}", uuid);
            send_control(&guard, &uuid, "audioStop", 0, 0);
        }
        uuid
    };
    let _ = uuid;

    let thread_handles = {
        let Ok(guard) = ctx.lock() else {
            return -1;
        };
        let mut audio_state = guard.audio.lock().unwrap();
        stop(&mut audio_state)
    };

    for h in thread_handles {
        log::info!("音频流: 等待线程退出");
        h.join().ok();
        log::info!("音频流: 线程已退出");
    }

    if let Ok(guard) = ctx.lock() {
        let audio_state = guard.audio.lock().unwrap();
        *audio_state.encoder.lock() = None;
        *audio_state.decoder.lock() = None;
        *audio_state.jitter.lock() = None;
        audio_state.stats.reset();
        audio_state.pcm_queue.lock().clear();
        audio_state.pcm_buffer.lock().clear();
    }

    log::info!("音频流: 停止完成");
    0
}

/// 音频流是否活跃。
pub fn is_active(ctx: &SafeContext) -> bool {
    let Ok(guard) = ctx.lock() else {
        return false;
    };
    let active = match guard.audio.try_lock() {
        Ok(audio_state) => {
            let active = audio_state.active.load(Ordering::SeqCst);
            log::debug!("音频流: 查询活跃状态={}", active);
            active
        }
        Err(_) => false,
    };
    active
}

/// 注册音频数据回调。
pub fn register_data_cb(ctx: &SafeContext, cb: AudioDataCb) {
    let Ok(guard) = ctx.lock() else {
        return;
    };
    let data_result = guard.audio.lock();
    if let Ok(mut audio_state) = data_result {
        audio_state.on_data = Some(cb);
    }
}

/// 注册音频事件回调。
pub fn register_event_cb(ctx: &SafeContext, cb: AudioEventCb) {
    let Ok(guard) = ctx.lock() else {
        return;
    };
    let event_result = guard.audio.try_lock();
    if let Ok(mut audio_state) = event_result {
        audio_state.on_event = Some(cb);
    }
}
