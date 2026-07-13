mod protocol;
mod crypto;
mod router;
mod heartbeat;
mod discovery;
mod models;
pub mod ffi;

use p256::SecretKey;
use std::sync::Mutex;

pub struct CoreContext {
    pub crypto: crypto::CryptoState,
    pub router: router::Router,
    pub heartbeat: heartbeat::HeartbeatState,
    pub discovery: discovery::DiscoveryState,
    pub ephemeral_key: Option<SecretKey>,
    pub ephemeral_pub_b64: Option<String>,
    pub pairing_key: Option<[u8; 32]>,
}

impl CoreContext {
    pub fn new() -> Self {
        Self {
            crypto: crypto::CryptoState::new(),
            router: router::Router::new(),
            heartbeat: heartbeat::HeartbeatState::new(),
            discovery: discovery::DiscoveryState::new(),
            ephemeral_key: None,
            ephemeral_pub_b64: None,
            pairing_key: None,
        }
    }
}

pub type SafeContext = Mutex<CoreContext>;
