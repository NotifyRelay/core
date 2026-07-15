use std::os::raw::c_char;
use std::os::raw::c_void;

use base64::Engine;

use crate::crypto::aes;
use crate::protocol::{codec, header::ProtocolHeader};

use super::common::{from_cstr, to_cstr, with_ctx};

#[no_mangle]
pub extern "C" fn nrc_encrypt_message(
    ctx_ptr: *mut c_void, header_prefix: *const c_char,
    local_uuid: *const c_char, local_pub_key: *const c_char,
    remote_uuid: *const c_char, plaintext: *const c_char,
) -> *mut c_char {
    let header = unsafe { from_cstr(header_prefix) };
    let uuid = unsafe { from_cstr(local_uuid) };
    let pub_key = unsafe { from_cstr(local_pub_key) };
    let remote = unsafe { from_cstr(remote_uuid) };
    let text = unsafe { from_cstr(plaintext) };
    with_ctx(ctx_ptr, |ctx| {
        let key_b64 = match ctx.crypto.device_keys.get(remote) {
            Some(k) => k.aes_key_b64.clone(), None => return std::ptr::null_mut(),
        };
        let key_bytes = base64::engine::general_purpose::STANDARD.decode(&key_b64).ok();
        let key_arr: [u8; 32] = match key_bytes {
            Some(b) if b.len() == 32 => { let mut arr = [0u8; 32]; arr.copy_from_slice(&b); arr }
            _ => return std::ptr::null_mut(),
        };
        match aes::encrypt(&key_arr, text.as_bytes()) {
            Ok(encrypted) => {
                let msg = codec::encode_data_message(header, uuid, pub_key, &encrypted);
                to_cstr(&msg)
            }
            Err(_) => std::ptr::null_mut(),
        }
    })
}

#[no_mangle]
pub extern "C" fn nrc_decrypt_message(
    ctx_ptr: *mut c_void, encrypted_line: *const c_char,
) -> *mut c_char {
    let line = unsafe { from_cstr(encrypted_line) };
    with_ctx(ctx_ptr, |ctx| {
        let fields = match codec::decode_data_message(line) {
            Some(f) => f, None => return std::ptr::null_mut(),
        };
        let key_b64 = match ctx.crypto.device_keys.get(fields.local_uuid) {
            Some(k) => k.aes_key_b64.clone(), None => return std::ptr::null_mut(),
        };
        let key_bytes = base64::engine::general_purpose::STANDARD.decode(&key_b64).ok();
        let key_arr: [u8; 32] = match key_bytes {
            Some(b) if b.len() == 32 => { let mut arr = [0u8; 32]; arr.copy_from_slice(&b); arr }
            _ => return std::ptr::null_mut(),
        };
        match aes::decrypt(&key_arr, fields.encrypted_payload) {
            Ok(plain) => { let s = String::from_utf8_lossy(&plain).to_string(); to_cstr(&s) }
            Err(_) => std::ptr::null_mut(),
        }
    })
}

#[no_mangle]
pub extern "C" fn nrc_decode_line(ctx_ptr: *mut c_void, line: *const c_char) -> *mut c_char {
    let line_str = unsafe { from_cstr(line) };
    if line_str.is_empty() { return std::ptr::null_mut(); }
    let header = ProtocolHeader::parse(line_str);
    match header {
        ProtocolHeader::Data(hdr) => with_ctx(ctx_ptr, |ctx| {
            let fields = match codec::decode_data_message(line_str) {
                Some(f) => f, None => return std::ptr::null_mut(),
            };
            let key_b64 = match ctx.crypto.device_keys.get(fields.local_uuid) {
                Some(k) => k.aes_key_b64.clone(), None => return std::ptr::null_mut(),
            };
            let key_bytes = base64::engine::general_purpose::STANDARD.decode(&key_b64).ok();
            let key_arr: [u8; 32] = match key_bytes {
                Some(b) if b.len() == 32 => { let mut arr = [0u8; 32]; arr.copy_from_slice(&b); arr }
                _ => return std::ptr::null_mut(),
            };
            match aes::decrypt(&key_arr, fields.encrypted_payload) {
                Ok(plain) => {
                    let plaintext = String::from_utf8_lossy(&plain).to_string();
                    let json = serde_json::json!({
                        "header": hdr, "type": "data",
                        "local_uuid": fields.local_uuid, "plaintext": plaintext,
                    });
                    to_cstr(&json.to_string())
                }
                Err(_) => std::ptr::null_mut(),
            }
        }),
        ProtocolHeader::Handshake => match codec::decode_handshake(line_str) {
            Some(f) => to_cstr(&serde_json::json!({
                "header": "HANDSHAKE", "uuid": f.uuid, "pub_key": f.pub_key,
                "ip": f.ip, "battery": f.battery, "device_type": f.device_type,
            }).to_string()),
            None => std::ptr::null_mut(),
        },
        ProtocolHeader::PairingInit => match codec::decode_pairing_init(line_str) {
            Some(f) => to_cstr(&serde_json::json!({
                "header": "PAIRING_INIT", "uuid": f.uuid, "tmp_pub_key": f.tmp_pub_key,
                "ip": f.ip, "battery": f.battery, "device_type": f.device_type,
            }).to_string()),
            None => std::ptr::null_mut(),
        },
        ProtocolHeader::PairingResp => match codec::decode_pairing_resp(line_str) {
            Some(f) => to_cstr(&serde_json::json!({
                "header": "PAIRING_RESP", "uuid": f.uuid, "tmp_pub": f.tmp_pub,
                "lt_pub": f.lt_pub, "encrypted_code": f.encrypted_code,
                "ip": f.ip, "battery": f.battery, "device_type": f.device_type,
            }).to_string()),
            None => std::ptr::null_mut(),
        },
        ProtocolHeader::Accept => match codec::decode_accept(line_str) {
            Some(f) => to_cstr(&serde_json::json!({
                "header": "ACCEPT", "uuid": f.uuid, "lt_pub_key": f.lt_pub_key,
                "ip": f.ip, "battery": f.battery, "device_type": f.device_type,
            }).to_string()),
            None => std::ptr::null_mut(),
        },
        ProtocolHeader::HeartbeatTcp => match codec::decode_heartbeat_tcp(line_str) {
            Some(f) => to_cstr(&serde_json::json!({
                "header": "HEARTBEAT_TCP", "uuid": f.uuid, "name_b64": f.name,
                "port": f.port, "battery": f.battery, "device_type": f.device_type,
            }).to_string()),
            None => std::ptr::null_mut(),
        },
        _ => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn nrc_decrypt_payload(
    ctx_ptr: *mut c_void, local_uuid: *const c_char, encrypted_b64: *const c_char,
) -> *mut c_char {
    let uuid = unsafe { from_cstr(local_uuid) };
    let enc = unsafe { from_cstr(encrypted_b64) };
    with_ctx(ctx_ptr, |ctx| {
        let key_b64 = match ctx.crypto.device_keys.get(uuid) {
            Some(k) => k.aes_key_b64.clone(), None => return std::ptr::null_mut(),
        };
        let key_bytes = base64::engine::general_purpose::STANDARD.decode(&key_b64).ok();
        let key_arr: [u8; 32] = match key_bytes {
            Some(b) if b.len() == 32 => { let mut arr = [0u8; 32]; arr.copy_from_slice(&b); arr }
            _ => return std::ptr::null_mut(),
        };
        match aes::decrypt(&key_arr, enc) {
            Ok(plain) => { let s = String::from_utf8_lossy(&plain).to_string(); to_cstr(&s) }
            Err(_) => std::ptr::null_mut(),
        }
    })
}