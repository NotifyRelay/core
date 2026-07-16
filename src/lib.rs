mod protocol;
mod crypto;
mod router;
mod heartbeat;
mod discovery;
mod network;
mod dedup;
mod models;
pub mod ffi;

use p256::SecretKey;
use std::sync::Mutex;

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
    pub ephemeral_key: Option<SecretKey>,
    pub ephemeral_pub_b64: Option<String>,
    pub pairing_key: Option<[u8; 32]>,
    pub pairing_ctx: Option<PairingContext>,
}

pub struct PairingContext {
    pub peer_tmp_pub: String,
    pub peer_lt_pub: Option<String>,
    pub decrypted_code: Option<String>,
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
            ephemeral_key: None,
            ephemeral_pub_b64: None,
            pairing_key: None,
            pairing_ctx: None,
        }
    }
}

pub type SafeContext = Mutex<CoreContext>;
