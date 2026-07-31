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
    #[serde(skip)]
    pub aes_key_bytes: Option<[u8; 32]>,
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
        let entry = self.device_keys.get(remote_uuid)?;
        if let Some(cached) = entry.aes_key_bytes {
            return Some(cached);
        }
        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(&entry.aes_key_b64)
            .ok()?;
        if key_bytes.len() != 32 {
            return None;
        }
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&key_bytes);
        Some(key_arr)
    }

    /// 存储设备密钥并预解码 AES key
    pub fn set_device_key(&mut self, uuid: String, remote_pub_key: String, aes_key_b64: String) {
        let aes_key_bytes = base64::engine::general_purpose::STANDARD
            .decode(&aes_key_b64)
            .ok()
            .and_then(|bytes| {
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    Some(arr)
                } else {
                    None
                }
            });
        self.device_keys.insert(
            uuid,
            DeviceKeyEntry {
                remote_pub_key,
                aes_key_b64,
                aes_key_bytes,
            },
        );
    }
}
