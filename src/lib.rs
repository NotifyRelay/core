mod protocol;
mod crypto;
mod router;
mod heartbeat;
mod discovery;
pub mod audio_stream;
mod network;
mod dedup;
mod models;
mod filter;
pub mod diff;
pub mod sender_queue;
pub mod reconnect;
pub mod ffi;

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub struct DeviceState {
    pub peer_lt_pub: Option<String>,
}

pub struct CoreContext {
    pub crypto: crypto::CryptoState,
    pub router: router::Router,
    pub heartbeat: heartbeat::HeartbeatState,
    pub discovery: discovery::DiscoveryState,
    pub audio: audio_stream::AudioStreamState,
    pub network: network::NetworkState,
    pub dedup: dedup::DedupState,
    pub filter: ffi::filter::FilterState,
    pub spake2_prover: Option<crypto::spake2::Spake2ProverSession>,
    pub spake2_verifier: Option<crypto::spake2::Spake2VerifierSession>,
    pub pairing_ctx: Option<PairingContext>,
    pub expected_pairing_code: Option<String>,
    /// 配对码生成（接收端/初始生成端）
    pub pairing_code: Option<String>,
    /// 配对码过期时间
    pub pairing_code_expiry: Option<Instant>,
    pub broadcast_info: Option<BroadcastInfo>,
    pub broadcast_handle: Option<BroadcastHandle>,
    /// UUID → IP 映射（从 UDP 心跳源地址、TCP 连接等收集）
    pub device_ips: Mutex<HashMap<String, String>>,
    // 新增字段
    pub heartbeat_handle: i64,
    pub offline_detector_handle: i64,
    pub sender_queue: i64,
    pub reconnect_state: i64,
}

pub struct PairingContext {
    pub peer_uuid: String,
    pub peer_spake2_pub: String,
    pub peer_lt_pub: Option<String>,
}

pub struct BroadcastInfo {
    pub uuid: String,
    pub name_b64: String,
    pub battery: i32,
    pub device_type: String,
}

pub struct BroadcastHandle {
    pub running: Arc<AtomicBool>,
}

impl CoreContext {
    pub fn new() -> Self {
        Self {
            crypto: crypto::CryptoState::new(),
            router: router::Router::new(),
            heartbeat: heartbeat::HeartbeatState::new(),
            discovery: discovery::DiscoveryState::new(),
            audio: audio_stream::AudioStreamState::new(),
            network: network::NetworkState::new(),
            dedup: dedup::DedupState::new(),
            filter: ffi::filter::FilterState::new(),
            device_ips: Mutex::new(HashMap::new()),
            spake2_prover: None,
            spake2_verifier: None,
            pairing_ctx: None,
            expected_pairing_code: None,
            pairing_code: None,
            pairing_code_expiry: None,
            broadcast_info: None,
            broadcast_handle: None,
            heartbeat_handle: 0,
            offline_detector_handle: 0,
            sender_queue: 0,
            reconnect_state: 0,
        }
    }
}

pub type SafeContext = Mutex<CoreContext>;
