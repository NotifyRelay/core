use std::os::raw::c_char;
use std::os::raw::c_void;

use base64::Engine;

use crate::crypto::{self, aes, ecdh, hkdf};

use super::common::{from_cstr, to_cstr, with_ctx};

#[no_mangle]
pub extern "C" fn nrc_ecdh_generate_keypair(ctx_ptr: *mut c_void) -> i32 {
    with_ctx(ctx_ptr, |ctx| {
        let (secret, b64) = ecdh::generate_keypair();
        ctx.crypto.local_key = Some(secret);
        ctx.crypto.local_pub_key_b64 = Some(b64);
        0
    })
}

#[no_mangle]
pub extern "C" fn nrc_ecdh_get_public_key(ctx_ptr: *mut c_void) -> *mut c_char {
    with_ctx(ctx_ptr, |ctx| {
        ctx.crypto
            .local_pub_key_b64
            .as_deref()
            .map(to_cstr)
            .unwrap_or(std::ptr::null_mut())
    })
}

#[no_mangle]
pub extern "C" fn nrc_ecdh_has_keypair(ctx_ptr: *mut c_void) -> i32 {
    with_ctx(ctx_ptr, |ctx| {
        if ctx.crypto.local_key.is_some() { 1 } else { 0 }
    })
}

#[no_mangle]
pub extern "C" fn nrc_ecdh_derive_shared_secret(
    ctx_ptr: *mut c_void,
    peer_uuid: *const c_char,
    peer_pub_key_b64: *const c_char,
) -> i32 {
    let uuid = unsafe { from_cstr(peer_uuid).to_string() };
    let peer = unsafe { from_cstr(peer_pub_key_b64).to_string() };
    with_ctx(ctx_ptr, |ctx| {
        if let Some(ref priv_key) = ctx.crypto.local_key {
            match ecdh::compute_shared_secret(priv_key, &peer) {
                Ok(shared) => {
                    let aes_key = hkdf::derive_session_key(&shared);
                    let b64 = base64::engine::general_purpose::STANDARD.encode(aes_key);
                    ctx.crypto.device_keys.insert(
                        uuid,
                        crypto::DeviceKeyEntry {
                            remote_pub_key: peer.clone(),
                            aes_key_b64: b64,
                        },
                    );
                    0
                }
                Err(_) => -1,
            }
        } else {
            -1
        }
    })
}

#[no_mangle]
pub extern "C" fn nrc_ecdh_generate_ephemeral_keypair(ctx_ptr: *mut c_void) -> i32 {
    with_ctx(ctx_ptr, |ctx| {
        let (secret, b64) = ecdh::generate_keypair();
        ctx.ephemeral_key = Some(secret);
        ctx.ephemeral_pub_b64 = Some(b64);
        0
    })
}

#[no_mangle]
pub extern "C" fn nrc_ecdh_get_ephemeral_public_key(ctx_ptr: *mut c_void) -> *mut c_char {
    with_ctx(ctx_ptr, |ctx| {
        ctx.ephemeral_pub_b64
            .as_deref()
            .map(to_cstr)
            .unwrap_or(std::ptr::null_mut())
    })
}

#[no_mangle]
pub extern "C" fn nrc_ecdh_has_ephemeral_keypair(ctx_ptr: *mut c_void) -> i32 {
    with_ctx(ctx_ptr, |ctx| {
        if ctx.ephemeral_key.is_some() { 1 } else { 0 }
    })
}

#[no_mangle]
pub extern "C" fn nrc_ecdh_clear_ephemeral_keypair(ctx_ptr: *mut c_void) {
    with_ctx(ctx_ptr, |ctx| {
        ctx.ephemeral_key = None;
        ctx.ephemeral_pub_b64 = None;
        ctx.pairing_key = None;
    });
}

#[no_mangle]
pub extern "C" fn nrc_ecdh_derive_pairing_key(
    ctx_ptr: *mut c_void,
    peer_eph_pub_b64: *const c_char,
) -> i32 {
    let peer = unsafe { from_cstr(peer_eph_pub_b64) };
    with_ctx(ctx_ptr, |ctx| {
        let eph_key = match ctx.ephemeral_key {
            Some(ref k) => k,
            None => return -1,
        };
        match ecdh::compute_shared_secret(eph_key, peer) {
            Ok(shared) => {
                let aes_key = hkdf::derive_pairing_key(&shared);
                ctx.pairing_key = Some(aes_key);
                0
            }
            Err(_) => -1,
        }
    })
}

#[no_mangle]
pub extern "C" fn nrc_ecdh_encrypt_pairing_code(
    ctx_ptr: *mut c_void,
    code: *const c_char,
) -> *mut c_char {
    let code_str = unsafe { from_cstr(code) };
    with_ctx(ctx_ptr, |ctx| {
        let key = match ctx.pairing_key {
            Some(k) => k,
            None => return std::ptr::null_mut(),
        };
        match aes::encrypt(&key, code_str.as_bytes()) {
            Ok(encrypted) => to_cstr(&encrypted),
            Err(_) => std::ptr::null_mut(),
        }
    })
}

#[no_mangle]
pub extern "C" fn nrc_ecdh_decrypt_pairing_code(
    ctx_ptr: *mut c_void,
    encrypted_b64: *const c_char,
) -> *mut c_char {
    let encrypted = unsafe { from_cstr(encrypted_b64) };
    with_ctx(ctx_ptr, |ctx| {
        let key = match ctx.pairing_key {
            Some(k) => k,
            None => return std::ptr::null_mut(),
        };
        match aes::decrypt(&key, encrypted) {
            Ok(plain) => {
                let s = String::from_utf8_lossy(&plain).to_string();
                to_cstr(&s)
            }
            Err(_) => std::ptr::null_mut(),
        }
    })
}

#[no_mangle]
pub extern "C" fn nrc_ecdh_derive_long_term_key(
    ctx_ptr: *mut c_void,
    peer_uuid: *const c_char,
    peer_lt_pub_b64: *const c_char,
) -> i32 {
    nrc_ecdh_derive_shared_secret(ctx_ptr, peer_uuid, peer_lt_pub_b64)
}