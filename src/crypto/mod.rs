pub mod aes;
pub mod ecdh;
pub mod hkdf;
pub mod spake2;

use base64::Engine;
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

    /// 获取指定对端的 AES-256 密钥
    pub fn get_aes_key(&self, remote_uuid: &str) -> Option<[u8; 32]> {
        let key_b64 = self.device_keys.get(remote_uuid)?.aes_key_b64.clone();
        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(&key_b64)
            .ok()?;
        if key_bytes.len() != 32 {
            return None;
        }
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&key_bytes);
        Some(key_arr)
    }
}
