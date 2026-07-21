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
        let b64 = base64::engine::general_purpose::STANDARD.encode(key_bytes);
        ctx.crypto.device_keys.insert(
            uuid.to_string(),
            crypto::DeviceKeyEntry {
                remote_pub_key: String::new(),
                aes_key_b64: b64,
            },
        );
        0
    })
}

#[no_mangle]
pub unsafe extern "C" fn nrc_remove_device(ctx_ptr: *mut c_void, device_uuid: *const c_char) -> i32 {
    let uuid = from_cstr(device_uuid);
    with_ctx(ctx_ptr, |ctx| {
        ctx.crypto.device_keys.remove(uuid);
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
pub extern "C" fn nrc_export_local_keypair(ctx_ptr: *mut c_void) -> *mut c_char {
    with_ctx(ctx_ptr, |ctx| {
        let local_priv_pem = ctx
            .crypto
            .local_key
            .as_ref()
            .and_then(|k| ecdh::secret_to_pem(k).ok());
        let json = serde_json::json!({
            "private_key_pem": local_priv_pem,
            "public_key_b64": ctx.crypto.local_pub_key_b64,
        });
        to_cstr(&json.to_string())
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
        match serde_json::from_str::<crypto::KeyStoreData>(json_str) {
            Ok(data) => {
                if let Some(ref pem) = data.local_private_key_pem {
                    ctx.crypto.local_key = ecdh::secret_from_pem(pem).ok();
                }
                ctx.crypto.local_pub_key_b64 = data.local_public_key_b64;
                ctx.crypto.device_keys = data.devices;
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
