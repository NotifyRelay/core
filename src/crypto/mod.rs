pub mod aes;
pub mod ecdh;
pub mod hkdf;
pub mod spake2;

use p256::SecretKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Serialize, Deserialize)]
pub struct DeviceKeyEntry {
    pub remote_pub_key: String,
    pub aes_key_b64: String,
}

#[derive(Serialize, Deserialize)]
pub struct KeyStoreData {
    pub local_private_key_pem: Option<String>,
    pub local_public_key_b64: Option<String>,
    pub devices: HashMap<String, DeviceKeyEntry>,
}

pub struct CryptoState {
    pub local_key: Option<SecretKey>,
    pub local_pub_key_b64: Option<String>,
    pub device_keys: HashMap<String, DeviceKeyEntry>,
}

impl CryptoState {
    pub fn new() -> Self {
        Self {
            local_key: None,
            local_pub_key_b64: None,
            device_keys: HashMap::new(),
        }
    }
}
