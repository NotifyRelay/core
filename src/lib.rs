#![allow(clippy::missing_safety_doc)]

mod app_sync;
pub mod audio_codec;
pub mod audio_stream;
mod clipboard;
mod crypto;
mod dedup;
pub mod device_registry;
pub mod diff;
mod discovery;
pub mod ffi;
mod filter;
mod heartbeat;
mod mdns;
mod models;
mod network;
mod protocol;
pub mod reconnect;
mod router;
pub mod sender_queue;
mod state_merge;

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
    pub audio: Arc<Mutex<audio_stream::AudioStreamState>>,
    pub network: network::NetworkState,
    pub mdns: mdns::MdnsState,
    pub dedup: dedup::DedupState,
    pub clipboard: clipboard::ClipboardState,
    pub app_sync: app_sync::AppSyncState,
    pub filter: ffi::filter::FilterState,
    /// 设备运行时状态统一注册表
    pub registry: device_registry::DeviceRegistry,
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
    /// 统一心跳调度器句柄（扫描 known_devices 自动启停每设备心跳，AUTO 模式）
    pub heartbeat_scheduler: i64,
    /// 调度器持有的每设备 HeartbeatHandle（跨轮次持久，由调度线程维护）
    pub heartbeat_scheduler_handles: HashMap<String, heartbeat::HeartbeatHandle>,
    pub offline_detector_handle: i64,
    pub sender_queue: i64,
    pub reconnect_state: i64,
    /// 超级岛 / 媒体 状态合并引擎（diff/merge/ACK/心跳全部在此闭环）
    pub state_merge: state_merge::StateMerge,
    /// 配对成功后延迟应用列表请求互斥标志（防止多次配对时线程堆叠）
    pub applist_delay_pending: Arc<AtomicBool>,
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
            audio: Arc::new(Mutex::new(audio_stream::AudioStreamState::new())),
            network: network::NetworkState::new(),
            mdns: mdns::MdnsState::new(),
            dedup: dedup::DedupState::new(),
            clipboard: clipboard::ClipboardState::new(),
            app_sync: app_sync::AppSyncState::new(),
            filter: ffi::filter::FilterState::new(),
            registry: device_registry::DeviceRegistry::new(),
            device_ips: Mutex::new(HashMap::new()),
            spake2_prover: None,
            spake2_verifier: None,
            pairing_ctx: None,
            expected_pairing_code: None,
            pairing_code: None,
            pairing_code_expiry: None,
            broadcast_info: None,
            broadcast_handle: None,
            heartbeat_scheduler: 0,
            heartbeat_scheduler_handles: HashMap::new(),
            offline_detector_handle: 0,
            sender_queue: 0,
            reconnect_state: 0,
            state_merge: state_merge::StateMerge::new(),
            applist_delay_pending: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl Default for CoreContext {
    fn default() -> Self {
        Self::new()
    }
}

pub type SafeContext = Mutex<CoreContext>;
