#![allow(dead_code)]

mod protocol;
mod crypto;
mod router;
mod heartbeat;
mod discovery;
mod models;
pub mod ffi;

use std::sync::Mutex;

pub struct CoreContext {
    pub crypto: crypto::CryptoState,
    pub router: router::Router,
    pub heartbeat: heartbeat::HeartbeatState,
    pub discovery: discovery::DiscoveryState,
}

impl CoreContext {
    pub fn new() -> Self {
        Self {
            crypto: crypto::CryptoState::new(),
            router: router::Router::new(),
            heartbeat: heartbeat::HeartbeatState::new(),
            discovery: discovery::DiscoveryState::new(),
        }
    }
}

pub type SafeContext = Mutex<CoreContext>;
