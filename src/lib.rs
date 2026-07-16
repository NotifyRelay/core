mod protocol;
mod crypto;
mod router;
mod heartbeat;
mod discovery;
mod network;
mod dedup;
mod models;
mod filter;
pub mod ffi;

use p256::SecretKey;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

pub struct DeviceState {
    pub peer_tmp_pub: Option<String>,
    pub peer_lt_pub: Option<String>,
    pub decrypted_code: Option<String>,
}

pub struct CoreContext {
    pub crypto: crypto::CryptoState,
    pub router: router::Router,
    pub heartbeat: heartbeat::HeartbeatState,
    pub discovery: discovery::DiscoveryState,
    pub network: network::NetworkState,
    pub dedup: dedup::DedupState,
    pub filter: ffi::filter::FilterState,
    pub ephemeral_key: Option<SecretKey>,
    pub ephemeral_pub_b64: Option<String>,
    pub pairing_key: Option<[u8; 32]>,
    pub pairing_ctx: Option<PairingContext>,
    /// 预期配对码（发起方设置，用于自动验证）
    pub expected_pairing_code: Option<String>,
    pub broadcast_info: Option<BroadcastInfo>,
    pub broadcast_handle: Option<BroadcastHandle>,
}

pub struct PairingContext {
    pub peer_tmp_pub: String,
    pub peer_lt_pub: Option<String>,
    pub decrypted_code: Option<String>,
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
            network: network::NetworkState::new(),
            dedup: dedup::DedupState::new(),
            filter: ffi::filter::FilterState::new(),
            ephemeral_key: None,
            ephemeral_pub_b64: None,
            pairing_key: None,
            pairing_ctx: None,
            expected_pairing_code: None,
            broadcast_info: None,
            broadcast_handle: None,
        }
    }
}

pub type SafeContext = Mutex<CoreContext>;
