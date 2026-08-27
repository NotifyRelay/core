use std::os::raw::c_char;
use std::os::raw::c_void;

use base64::Engine;

use crate::crypto::{self, aes, ecdh, hkdf};

use super::common::{from_cstr, to_cstr, with_ctx};

#[no_mangle]
pub unsafe extern "C" fn nrc_migrate_shared_secret(
    ctx_ptr: *mut c_void,
    device_uuid: *const c_char,
    aes_key: *const u8,
    len: u32,
) -> i32 {
    if aes_key.is_null() || len == 0 {
        return -1;
    }
    let uuid = from_cstr(device_uuid);
    let key_bytes = std::slice::from_raw_parts(aes_key, len as usize);
    if key_bytes.len() != 32 {
        return -1;
    }
    with_ctx(ctx_ptr, |ctx| {
        ctx.ensure_persistence_loaded();
        let b64 = base64::engine::general_purpose::STANDARD.encode(key_bytes);
        ctx.crypto
            .set_device_key(uuid.to_string(), String::new(), b64);
        // 迁移导入的密钥：立即落库
        ctx.mark_persistence_dirty();
        ctx.persist_device_row_now(&uuid);
        0
    })
}

#[no_mangle]
pub unsafe extern "C" fn nrc_remove_device(
    ctx_ptr: *mut c_void,
    device_uuid: *const c_char,
) -> i32 {
    let uuid = from_cstr(device_uuid);
    with_ctx(ctx_ptr, |ctx| {
        ctx.ensure_persistence_loaded();
        // 先持久化删除：失败则保持内存状态并返回失败，避免「内存已删但库行残留」
        // 在重启后 load_all 回灌密钥导致设备复活（墓碑删不掉的根因之一）
        if let Some(p) = ctx.persistence.as_ref() {
            if let Err(e) = p.delete_device(uuid) {
                log::error!("从持久化库删除设备失败 {}: {}", uuid, e);
                return -1;
            }
        }
        ctx.crypto.device_keys.remove(uuid);
        ctx.registry.remove(uuid);
        ctx.persisted_devices.remove(uuid);
        ctx.mark_persistence_dirty();
        // 立即重写密钥状态：删除后进程被杀/重启时，旧 state 中的密钥
        // 会把设备从库中“复活”，必须同步落盘（未激活时由下次读取前 flush 兜底）
        let _ = ctx.flush_persistence();
        0
    })
}

#[no_mangle]
pub unsafe extern "C" fn nrc_export_device_key(
    ctx_ptr: *mut c_void,
    device_uuid: *const c_char,
) -> *mut c_char {
    let uuid = from_cstr(device_uuid);
    with_ctx(ctx_ptr, |ctx| {
        ctx.crypto
            .device_keys
            .get(uuid)
            .map(|k| {
                let json = serde_json::json!({
                    "aes_key_b64": k.aes_key_b64,
                    "remote_pub_key": k.remote_pub_key,
                });
                to_cstr(&json.to_string())
            })
            .unwrap_or(std::ptr::null_mut())
    })
}

#[no_mangle]
pub extern "C" fn nrc_export_state(ctx_ptr: *mut c_void) -> *mut c_char {
    with_ctx(ctx_ptr, |ctx| {
        let local_priv_pem = ctx
            .crypto
            .local_key
            .as_ref()
            .and_then(|k| ecdh::secret_to_pem(k).ok());
        let data = crypto::KeyStoreData {
            local_private_key_pem: local_priv_pem,
            local_public_key_b64: ctx.crypto.local_pub_key_b64.clone(),
            devices: ctx.crypto.device_keys.clone(),
        };
        match serde_json::to_string(&data) {
            Ok(json) => to_cstr(&json),
            Err(_) => std::ptr::null_mut(),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn nrc_import_state(ctx_ptr: *mut c_void, json: *const c_char) -> i32 {
    let json_str = from_cstr(json);
    with_ctx(ctx_ptr, |ctx| {
        ctx.ensure_persistence_loaded();
        match serde_json::from_str::<crypto::KeyStoreData>(json_str) {
            Ok(data) => {
                crate::persistence::apply_keystore_data(&mut ctx.crypto, &data);
                ctx.mark_persistence_dirty();
                0
            }
            Err(e) => {
                log::error!("导入状态解析失败: {}", e);
                -1
            }
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn nrc_encrypt_local_state(
    ctx_ptr: *mut c_void,
    plaintext: *const c_char,
    device_uuid: *const c_char,
) -> *mut c_char {
    let text = from_cstr(plaintext);
    let uuid = from_cstr(device_uuid);
    with_ctx(ctx_ptr, |_ctx| {
        let key = hkdf::derive_local_state_key(uuid);
        match aes::encrypt(&key, text.as_bytes()) {
            Ok(enc) => to_cstr(&enc),
            Err(_) => std::ptr::null_mut(),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn nrc_decrypt_local_state(
    ctx_ptr: *mut c_void,
    encrypted_b64: *const c_char,
    device_uuid: *const c_char,
) -> *mut c_char {
    let enc = from_cstr(encrypted_b64);
    let uuid = from_cstr(device_uuid);
    with_ctx(ctx_ptr, |_ctx| {
        let key = hkdf::derive_local_state_key(uuid);
        match aes::decrypt(&key, enc) {
            Ok(plain) => {
                let s = String::from_utf8_lossy(&plain).to_string();
                to_cstr(&s)
            }
            Err(_) => std::ptr::null_mut(),
        }
    })
}
