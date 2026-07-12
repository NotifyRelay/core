use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use base64::Engine;

use crate::{
    crypto::{self, aes, ecdh, hkdf},
    SafeContext,
};

type NrcMessageCallback = extern "C" fn(*const c_char, *const c_char, *mut std::ffi::c_void);
type NrcPairingCallback = extern "C" fn(*const c_char, *const c_char, *const c_char, *mut std::ffi::c_void);

fn to_cstr(s: &str) -> *mut c_char {
    CString::new(s).unwrap_or_default().into_raw()
}

unsafe fn from_cstr<'a>(ptr: *const c_char) -> &'a str {
    if ptr.is_null() {
        return "";
    }
    CStr::from_ptr(ptr).to_str().unwrap_or("")
}

fn with_ctx<F, R>(ctx_ptr: *mut std::ffi::c_void, f: F) -> R
where
    F: FnOnce(&mut crate::CoreContext) -> R,
    R: Default,
{
    if ctx_ptr.is_null() {
        return R::default();
    }
    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
    match ctx.lock() {
        Ok(mut guard) => f(&mut guard),
        Err(_) => R::default(),
    }
}

#[no_mangle]
pub extern "C" fn nrc_init() -> *mut std::ffi::c_void {
    let ctx = Box::new(std::sync::Mutex::new(crate::CoreContext::new()));
    Box::into_raw(ctx) as *mut std::ffi::c_void
}

#[no_mangle]
pub extern "C" fn nrc_destroy(ctx_ptr: *mut std::ffi::c_void) {
    if !ctx_ptr.is_null() {
        let ctx = unsafe { Box::from_raw(ctx_ptr as *mut SafeContext) };
        drop(ctx);
    }
}

#[no_mangle]
pub extern "C" fn nrc_ecdh_generate_keypair(ctx_ptr: *mut std::ffi::c_void) -> i32 {
    with_ctx(ctx_ptr, |ctx| {
        let (secret, b64) = ecdh::generate_keypair();
        ctx.crypto.local_key = Some(secret);
        ctx.crypto.local_pub_key_b64 = Some(b64);
        0
    })
}

#[no_mangle]
pub extern "C" fn nrc_ecdh_get_public_key(ctx_ptr: *mut std::ffi::c_void) -> *mut c_char {
    with_ctx(ctx_ptr, |ctx| {
        ctx.crypto
            .local_pub_key_b64
            .as_deref()
            .map(to_cstr)
            .unwrap_or(std::ptr::null_mut())
    })
}

#[no_mangle]
pub extern "C" fn nrc_ecdh_has_keypair(ctx_ptr: *mut std::ffi::c_void) -> i32 {
    with_ctx(ctx_ptr, |ctx| {
        if ctx.crypto.local_key.is_some() {
            1
        } else {
            0
        }
    })
}

#[no_mangle]
pub extern "C" fn nrc_ecdh_derive_shared_secret(
    ctx_ptr: *mut std::ffi::c_void,
    peer_pub_key_b64: *const c_char,
) -> i32 {
    let peer = unsafe { from_cstr(peer_pub_key_b64).to_string() };
    with_ctx(ctx_ptr, |ctx| {
        if let Some(ref priv_key) = ctx.crypto.local_key {
            match ecdh::compute_shared_secret(priv_key, &peer) {
                Ok(shared) => {
                    let aes_key = hkdf::derive_session_key(&shared);
                    let b64 = base64::engine::general_purpose::STANDARD.encode(aes_key);
                    let device_id = uuid::Uuid::new_v4().to_string();
                    ctx.crypto.device_keys.insert(
                        device_id,
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
pub extern "C" fn nrc_migrate_shared_secret(
    ctx_ptr: *mut std::ffi::c_void,
    secret: *const u8,
    len: u32,
) -> i32 {
    if secret.is_null() || len == 0 {
        return -1;
    }
    let secret_bytes = unsafe { std::slice::from_raw_parts(secret, len as usize) };
    with_ctx(ctx_ptr, |ctx| {
        let aes_key = hkdf::derive_session_key(secret_bytes);
        let b64 = base64::engine::general_purpose::STANDARD.encode(aes_key);
        let device_id = uuid::Uuid::new_v4().to_string();
        ctx.crypto.device_keys.insert(
            device_id,
            crypto::DeviceKeyEntry {
                remote_pub_key: String::new(),
                aes_key_b64: b64,
            },
        );
        0
    })
}

#[no_mangle]
pub extern "C" fn nrc_encrypt_message(
    ctx_ptr: *mut std::ffi::c_void,
    header_prefix: *const c_char,
    local_uuid: *const c_char,
    local_pub_key: *const c_char,
    plaintext: *const c_char,
) -> *mut c_char {
    let header = unsafe { from_cstr(header_prefix) };
    let uuid = unsafe { from_cstr(local_uuid) };
    let pub_key = unsafe { from_cstr(local_pub_key) };
    let text = unsafe { from_cstr(plaintext) };

    with_ctx(ctx_ptr, |ctx| {
        let default_key = match ctx.crypto.device_keys.values().next() {
            Some(k) => k.aes_key_b64.clone(),
            None => return std::ptr::null_mut(),
        };
        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(&default_key)
            .ok();
        let key_arr: [u8; 32] = match key_bytes {
            Some(b) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                arr
            }
            _ => return std::ptr::null_mut(),
        };
        match aes::encrypt(&key_arr, text.as_bytes()) {
            Ok(encrypted) => {
                let msg = crate::protocol::codec::encode_data_message(
                    header, uuid, pub_key, &encrypted,
                );
                to_cstr(&msg)
            }
            Err(_) => std::ptr::null_mut(),
        }
    })
}

#[no_mangle]
pub extern "C" fn nrc_decrypt_message(
    ctx_ptr: *mut std::ffi::c_void,
    encrypted_line: *const c_char,
) -> *mut c_char {
    let line = unsafe { from_cstr(encrypted_line) };
    with_ctx(ctx_ptr, |ctx| {
        let fields = match crate::protocol::codec::decode_data_message(line) {
            Some(f) => f,
            None => return std::ptr::null_mut(),
        };
        let default_key = match ctx.crypto.device_keys.values().next() {
            Some(k) => k.aes_key_b64.clone(),
            None => return std::ptr::null_mut(),
        };
        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(&default_key)
            .ok();
        let key_arr: [u8; 32] = match key_bytes {
            Some(b) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                arr
            }
            _ => return std::ptr::null_mut(),
        };
        match aes::decrypt(&key_arr, fields.encrypted_payload) {
            Ok(plain) => {
                let s = String::from_utf8_lossy(&plain).to_string();
                to_cstr(&s)
            }
            Err(_) => std::ptr::null_mut(),
        }
    })
}

#[no_mangle]
pub extern "C" fn nrc_process_line(
    ctx_ptr: *mut std::ffi::c_void,
    line: *const c_char,
    on_message: Option<NrcMessageCallback>,
    on_pairing: Option<NrcPairingCallback>,
    user_data: *mut std::ffi::c_void,
) -> i32 {
    let line_str = unsafe { from_cstr(line) };
    if line_str.is_empty() {
        return -1;
    }
    with_ctx(ctx_ptr, |ctx| {
        let header = crate::protocol::header::ProtocolHeader::parse(line_str);
        let header_str = header.to_string();

        match header {
            crate::protocol::header::ProtocolHeader::Data(_) => {
                if let Some(ref cb) = on_message {
                    if let Some(fields) = crate::protocol::codec::decode_data_message(line_str) {
                        let h_cstr = CString::new(fields.header)
                            .unwrap_or_default();
                        let p_cstr = CString::new(fields.encrypted_payload)
                            .unwrap_or_default();
                        cb(h_cstr.as_ptr(), p_cstr.as_ptr(), user_data);
                    }
                }
                ctx.router.process_line(line_str);
                0
            }
            crate::protocol::header::ProtocolHeader::PairingInit
            | crate::protocol::header::ProtocolHeader::PairingResp
            | crate::protocol::header::ProtocolHeader::Accept
            | crate::protocol::header::ProtocolHeader::Handshake => {
                if let Some(ref cb) = on_pairing {
                    let parts: Vec<&str> = line_str.splitn(4, ':').collect();
                    let uuid = if parts.len() > 1 { parts[1] } else { "" };
                    let pub_key = if parts.len() > 2 { parts[2] } else { "" };
                    let h_cstr = CString::new(header_str).unwrap_or_default();
                    let u_cstr = CString::new(uuid).unwrap_or_default();
                    let p_cstr = CString::new(pub_key).unwrap_or_default();
                    cb(h_cstr.as_ptr(), u_cstr.as_ptr(), p_cstr.as_ptr(), user_data);
                }
                ctx.router.process_line(line_str);
                0
            }
            _ => {
                ctx.router.process_line(line_str);
                -1
            }
        }
    })
}

#[no_mangle]
pub extern "C" fn nrc_format_heartbeat(
    uuid: *const c_char,
    name: *const c_char,
    port: u16,
    battery: i32,
    device_type: *const c_char,
) -> *mut c_char {
    let u = unsafe { from_cstr(uuid) };
    let n = unsafe { from_cstr(name) };
    let dt = unsafe { from_cstr(device_type) };
    let result = crate::heartbeat::format_udp_heartbeat(u, n, port, battery, dt);
    to_cstr(&result)
}

#[no_mangle]
pub extern "C" fn nrc_parse_heartbeat(
    line: *const c_char,
) -> *mut c_char {
    let l = unsafe { from_cstr(line) };
    let result = crate::heartbeat::parse_udp_heartbeat(l)
        .map(|(u, n, p, b, d)| format!("{}:{}:{}:{:+}:{}", u, n, p, b, d))
        .unwrap_or_default();
    to_cstr(&result)
}

#[no_mangle]
pub extern "C" fn nrc_format_discovery(
    uuid: *const c_char,
    name: *const c_char,
    port: u16,
    battery: i32,
    device_type: *const c_char,
) -> *mut c_char {
    let u = unsafe { from_cstr(uuid) };
    let n = unsafe { from_cstr(name) };
    let dt = unsafe { from_cstr(device_type) };
    let result = crate::discovery::format_discovery_broadcast(u, n, port, battery, dt);
    to_cstr(&result)
}

#[no_mangle]
pub extern "C" fn nrc_export_state(ctx_ptr: *mut std::ffi::c_void) -> *mut c_char {
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
pub extern "C" fn nrc_import_state(
    ctx_ptr: *mut std::ffi::c_void,
    json: *const c_char,
) -> i32 {
    let json_str = unsafe { from_cstr(json) };
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
                log::error!("import_state parse error: {}", e);
                -1
            }
        }
    })
}

#[no_mangle]
pub extern "C" fn nrc_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}
