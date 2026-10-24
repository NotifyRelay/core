//! 密钥、状态与设备管理的委托实现。

use std::os::raw::c_char;

use super::conv::{cs, take_cstr, take_cstr_or_empty};
use super::Core;

#[uniffi::export]
impl Core {
    // ===== ECDH =====

    /// 生成本机 ECDH 密钥对。
    pub fn ecdh_generate_keypair(&self) -> bool {
        crate::ffi::ecdh::nrc_ecdh_generate_keypair(self.ctx_ptr()) == 0
    }

    /// 读取本机长期 ECDH 公钥（Base64）；未生成时为 `None`。
    pub fn ecdh_get_public_key(&self) -> Option<String> {
        unsafe { take_cstr(crate::ffi::ecdh::nrc_ecdh_get_public_key(self.ctx_ptr())) }
    }

    /// 本机是否已持有 ECDH 密钥对。
    pub fn ecdh_has_keypair(&self) -> bool {
        crate::ffi::ecdh::nrc_ecdh_has_keypair(self.ctx_ptr()) != 0
    }

    /// 由对端公钥派生共享密钥并登记设备密钥。
    pub fn ecdh_derive_shared_secret(&self, peer_uuid: String, peer_pub_key_b64: String) -> bool {
        let uuid = cs(&peer_uuid);
        let pk = cs(&peer_pub_key_b64);
        unsafe {
            crate::ffi::ecdh::nrc_ecdh_derive_shared_secret(
                self.ctx_ptr(),
                uuid.as_ptr(),
                pk.as_ptr(),
            ) == 0
        }
    }

    // ===== 密钥管理 =====

    /// 迁移导入共享密钥（32 字节 AES 密钥）。
    pub fn migrate_shared_secret(&self, device_uuid: String, aes_key: Vec<u8>) -> bool {
        if aes_key.len() != 32 {
            return false;
        }
        let uuid = cs(&device_uuid);
        unsafe {
            crate::ffi::key_management::nrc_migrate_shared_secret(
                self.ctx_ptr(),
                uuid.as_ptr(),
                aes_key.as_ptr(),
                aes_key.len() as u32,
            ) == 0
        }
    }

    /// 移除设备（内存态、注册表与持久化行原子删除）。
    pub fn remove_device(&self, device_uuid: String) -> bool {
        let uuid = cs(&device_uuid);
        unsafe { crate::ffi::key_management::nrc_remove_device(self.ctx_ptr(), uuid.as_ptr()) == 0 }
    }

    /// 读取指定设备的密钥材料。
    pub fn export_device_key(&self, device_uuid: String) -> Option<String> {
        let uuid = cs(&device_uuid);
        unsafe {
            take_cstr(crate::ffi::key_management::nrc_export_device_key(
                self.ctx_ptr(),
                uuid.as_ptr(),
            ))
        }
    }

    /// 导出完整密钥状态 JSON。
    pub fn export_state(&self) -> Option<String> {
        unsafe { take_cstr(crate::ffi::key_management::nrc_export_state(self.ctx_ptr())) }
    }

    /// 导入密钥状态 JSON。
    pub fn import_state(&self, json: String) -> bool {
        let j = cs(&json);
        unsafe { crate::ffi::key_management::nrc_import_state(self.ctx_ptr(), j.as_ptr()) == 0 }
    }

    /// 用设备 UUID 派生的本地状态密钥加密明文。
    pub fn encrypt_local_state(&self, plaintext: String, device_uuid: String) -> Option<String> {
        let p = cs(&plaintext);
        let u = cs(&device_uuid);
        unsafe {
            take_cstr(crate::ffi::key_management::nrc_encrypt_local_state(
                self.ctx_ptr(),
                p.as_ptr(),
                u.as_ptr(),
            ))
        }
    }

    /// 用设备 UUID 派生的本地状态密钥解密密文。
    pub fn decrypt_local_state(
        &self,
        encrypted_b64: String,
        device_uuid: String,
    ) -> Option<String> {
        let e = cs(&encrypted_b64);
        let u = cs(&device_uuid);
        unsafe {
            take_cstr(crate::ffi::key_management::nrc_decrypt_local_state(
                self.ctx_ptr(),
                e.as_ptr(),
                u.as_ptr(),
            ))
        }
    }

    /// 本地状态序列化聚合入口。
    pub fn serialize_local_state(&self, device_uuid: String, encrypt: bool) -> Option<String> {
        let u = cs(&device_uuid);
        unsafe {
            take_cstr(crate::ffi::key_management::nrc_serialize_local_state(
                self.ctx_ptr(),
                u.as_ptr(),
                if encrypt { 1 } else { 0 },
            ))
        }
    }

    /// 本地状态反序列化聚合入口：按需解密后导入。
    pub fn deserialize_local_state(
        &self,
        payload: String,
        device_uuid: String,
        encrypted: bool,
    ) -> String {
        let p = cs(&payload);
        let u = cs(&device_uuid);
        unsafe {
            take_cstr_or_empty(crate::ffi::key_management::nrc_deserialize_local_state(
                self.ctx_ptr(),
                p.as_ptr(),
                u.as_ptr(),
                if encrypted { 1 } else { 0 },
            ))
        }
    }

    // ===== 设备状态 =====

    /// 获取设备列表 JSON。
    pub fn get_device_list(
        &self,
        authed_timeout_ms: i64,
        unauthed_timeout_ms: i64,
    ) -> Option<String> {
        unsafe {
            take_cstr(crate::ffi::device_state::nrc_get_device_list(
                self.ctx_ptr(),
                authed_timeout_ms,
                unauthed_timeout_ms,
            ))
        }
    }

    /// 读取本机 UUID（不存在时由 core 生成并落盘）。
    pub fn get_local_uuid(&self) -> Option<String> {
        unsafe { take_cstr(crate::ffi::persistence::nrc_get_local_uuid(self.ctx_ptr())) }
    }

    /// 重命名设备。
    pub fn rename_device(&self, device_uuid: String, name: String) -> bool {
        let u = cs(&device_uuid);
        let n = cs(&name);
        unsafe {
            crate::ffi::persistence::nrc_rename_device(self.ctx_ptr(), u.as_ptr(), n.as_ptr()) == 0
        }
    }
}

/// 便于需要裸指针的调用点复用。
#[allow(dead_code)]
pub(crate) fn cstr_ptr(s: &str) -> (*const c_char, std::ffi::CString) {
    let c = cs(s);
    (c.as_ptr(), c)
}
