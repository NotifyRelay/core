//! 密钥、状态与设备管理的导出实现。

use super::Core;

#[uniffi::export]
impl Core {
    // ===== ECDH =====

    /// 生成本机 ECDH 密钥对。
    pub fn ecdh_generate_keypair(&self) -> bool {
        let Ok(mut guard) = self.ctx().lock() else {
            return false;
        };
        crate::crypto::ops::generate_keypair(&mut guard);
        true
    }

    /// 读取本机长期 ECDH 公钥（Base64）；未生成时为 `None`。
    pub fn ecdh_get_public_key(&self) -> Option<String> {
        let Ok(mut guard) = self.ctx().lock() else {
            return None;
        };
        crate::crypto::ops::public_key(&mut guard)
    }

    /// 本机是否已持有 ECDH 密钥对。
    pub fn ecdh_has_keypair(&self) -> bool {
        let Ok(mut guard) = self.ctx().lock() else {
            return false;
        };
        crate::crypto::ops::has_keypair(&mut guard)
    }

    /// 由对端公钥派生共享密钥并登记设备密钥。
    pub fn ecdh_derive_shared_secret(&self, peer_uuid: String, peer_pub_key_b64: String) -> bool {
        let Ok(mut guard) = self.ctx().lock() else {
            return false;
        };
        crate::crypto::ops::derive_shared_secret(&mut guard, &peer_uuid, &peer_pub_key_b64)
    }

    // ===== 密钥管理 =====

    /// 迁移导入共享密钥（32 字节 AES 密钥）。
    pub fn migrate_shared_secret(&self, device_uuid: String, aes_key: Vec<u8>) -> bool {
        let Ok(mut guard) = self.ctx().lock() else {
            return false;
        };
        crate::crypto::ops::migrate_shared_secret(&mut guard, &device_uuid, &aes_key)
    }

    /// 移除设备（内存态、注册表与持久化行原子删除）。
    pub fn remove_device(&self, device_uuid: String) -> bool {
        let Ok(mut guard) = self.ctx().lock() else {
            return false;
        };
        crate::crypto::ops::remove_device(&mut guard, &device_uuid)
    }

    /// 读取指定设备的密钥材料。
    pub fn export_device_key(&self, device_uuid: String) -> Option<String> {
        let Ok(mut guard) = self.ctx().lock() else {
            return None;
        };
        crate::crypto::ops::export_device_key_json(&mut guard, &device_uuid)
    }

    /// 导出完整密钥状态 JSON。
    pub fn export_state(&self) -> Option<String> {
        let Ok(mut guard) = self.ctx().lock() else {
            return None;
        };
        crate::crypto::ops::export_state(&mut guard)
    }

    /// 导入密钥状态 JSON。
    pub fn import_state(&self, json: String) -> bool {
        let Ok(mut guard) = self.ctx().lock() else {
            return false;
        };
        crate::crypto::ops::import_state(&mut guard, &json)
    }

    /// 用设备 UUID 派生的本地状态密钥加密明文。
    pub fn encrypt_local_state(&self, plaintext: String, device_uuid: String) -> Option<String> {
        let Ok(mut guard) = self.ctx().lock() else {
            return None;
        };
        crate::crypto::ops::encrypt_local_state(&mut guard, &plaintext, &device_uuid)
    }

    /// 用设备 UUID 派生的本地状态密钥解密密文。
    pub fn decrypt_local_state(
        &self,
        encrypted_b64: String,
        device_uuid: String,
    ) -> Option<String> {
        let Ok(mut guard) = self.ctx().lock() else {
            return None;
        };
        crate::crypto::ops::decrypt_local_state(&mut guard, &encrypted_b64, &device_uuid)
    }

    /// 本地状态序列化聚合入口。
    pub fn serialize_local_state(&self, device_uuid: String, encrypt: bool) -> Option<String> {
        let Ok(mut guard) = self.ctx().lock() else {
            return None;
        };
        crate::crypto::ops::serialize_local_state(&mut guard, &device_uuid, encrypt)
    }

    /// 本地状态反序列化聚合入口：按需解密后导入。
    pub fn deserialize_local_state(
        &self,
        payload: String,
        device_uuid: String,
        encrypted: bool,
    ) -> String {
        let Ok(mut guard) = self.ctx().lock() else {
            return r#"{"ok":false}"#.to_string();
        };
        crate::crypto::ops::deserialize_local_state(&mut guard, &payload, &device_uuid, encrypted)
    }

    // ===== 设备状态 =====

    /// 获取设备列表 JSON。
    pub fn get_device_list(
        &self,
        authed_timeout_ms: i64,
        unauthed_timeout_ms: i64,
    ) -> Option<String> {
        let Ok(mut guard) = self.ctx().lock() else {
            return None;
        };
        Some(crate::device_registry::device_list_json(
            &mut guard,
            authed_timeout_ms,
            unauthed_timeout_ms,
        ))
    }

    /// 读取本机 UUID（不存在时由 core 生成并落盘）。
    pub fn get_local_uuid(&self) -> Option<String> {
        let Ok(mut guard) = self.ctx().lock() else {
            return None;
        };
        crate::persistence::local_uuid(&mut guard)
    }

    /// 重命名设备。
    pub fn rename_device(&self, device_uuid: String, name: String) -> bool {
        let Ok(mut guard) = self.ctx().lock() else {
            return false;
        };
        crate::persistence::rename_device(&mut guard, &device_uuid, &name)
    }
}
