use std::ffi::CString;
use std::os::raw::c_char;
use std::os::raw::c_void;

use base64::Engine;

use crate::{crypto::aes, protocol::codec, crypto::ecdh, crypto::hkdf, CoreContext};

use super::common::{encode_name_b64, from_cstr, with_ctx};

fn do_send(ctx: &CoreContext, line: &str) {
    if let Some(cb) = ctx.router.on_send {
        if let Ok(c_line) = CString::new(line) {
            cb(c_line.as_ptr(), ctx.router.user_data);
        }
    }
}

fn do_send_udp(ctx: &CoreContext, line: &str) {
    if let Some(cb) = ctx.router.on_send_udp {
        if let Ok(c_line) = CString::new(line) {
            cb(c_line.as_ptr(), ctx.router.user_data);
        }
    }
}

#[no_mangle]
pub extern "C" fn nrc_send_handshake(ctx_ptr: *mut c_void, uuid: *const c_char,
    pub_key: *const c_char, ip: *const c_char, battery: i32,
    device_type: *const c_char) {
    let u = unsafe { from_cstr(uuid).to_string() };
    let p = unsafe { from_cstr(pub_key).to_string() };
    let i = unsafe { from_cstr(ip).to_string() };
    let d = unsafe { from_cstr(device_type).to_string() };
    with_ctx(ctx_ptr, |ctx| {
        do_send(ctx, &codec::encode_handshake(&u, &p, &i, battery, &d));
    });
}

#[no_mangle]
pub extern "C" fn nrc_send_pairing_init(ctx_ptr: *mut c_void, uuid: *const c_char,
    ip: *const c_char, battery: i32, device_type: *const c_char) {
    let u = unsafe { from_cstr(uuid).to_string() };
    let i = unsafe { from_cstr(ip).to_string() };
    let d = unsafe { from_cstr(device_type).to_string() };
    with_ctx(ctx_ptr, |ctx| {
        let (secret, b64) = ecdh::generate_keypair();
        ctx.ephemeral_key = Some(secret);
        ctx.ephemeral_pub_b64 = Some(b64.clone());
        do_send(ctx, &codec::encode_pairing_init(&u, &b64, &i, battery, &d));
    });
}

#[no_mangle]
pub extern "C" fn nrc_send_pairing_resp(ctx_ptr: *mut c_void, uuid: *const c_char,
    lt_pub: *const c_char, pairing_code: *const c_char, ip: *const c_char,
    battery: i32, device_type: *const c_char) {
    let u = unsafe { from_cstr(uuid).to_string() };
    let l = unsafe { from_cstr(lt_pub).to_string() };
    let code = unsafe { from_cstr(pairing_code).to_string() };
    let i = unsafe { from_cstr(ip).to_string() };
    let d = unsafe { from_cstr(device_type).to_string() };
    with_ctx(ctx_ptr, |ctx| {
        if ctx.ephemeral_key.is_none() {
            let (secret, b64) = ecdh::generate_keypair();
            ctx.ephemeral_key = Some(secret);
            ctx.ephemeral_pub_b64 = Some(b64);
        }
        let tmp_pub = ctx.ephemeral_pub_b64.clone().unwrap_or_default();
        if let Some(ref eph_key) = ctx.ephemeral_key.clone() {
            if let Some(ref peer_tmp) = ctx.pairing_ctx.as_ref().map(|c| c.peer_tmp_pub.clone()) {
                if let Ok(shared) = ecdh::compute_shared_secret(eph_key, &peer_tmp) {
                    let aes_key = hkdf::derive_pairing_key(&shared);
                    ctx.pairing_key = Some(aes_key);
                }
            }
        }
        let encrypted = ctx.pairing_key.and_then(|key| {
            aes::encrypt(&key, code.as_bytes()).ok()
        }).unwrap_or_default();
        do_send(ctx, &codec::encode_pairing_resp(&u, &tmp_pub, &l, &encrypted, &i, battery, &d));
    });
}

#[no_mangle]
pub extern "C" fn nrc_send_accept(ctx_ptr: *mut c_void, uuid: *const c_char,
    lt_pub_key: *const c_char, ip: *const c_char, battery: i32,
    device_type: *const c_char) {
    let u = unsafe { from_cstr(uuid).to_string() };
    let l = unsafe { from_cstr(lt_pub_key).to_string() };
    let i = unsafe { from_cstr(ip).to_string() };
    let d = unsafe { from_cstr(device_type).to_string() };
    with_ctx(ctx_ptr, |ctx| {
        do_send(ctx, &codec::encode_accept(&u, &l, &i, battery, &d));
    });
}

#[no_mangle]
pub extern "C" fn nrc_send_reject(ctx_ptr: *mut c_void, uuid: *const c_char) {
    let u = unsafe { from_cstr(uuid).to_string() };
    with_ctx(ctx_ptr, |ctx| {
        do_send(ctx, &codec::encode_reject(&u));
    });
}

#[no_mangle]
pub extern "C" fn nrc_send_heartbeat_tcp(ctx_ptr: *mut c_void, uuid: *const c_char,
    name: *const c_char, port: u16, battery: i32, device_type: *const c_char) {
    let u = unsafe { from_cstr(uuid).to_string() };
    let n_b64 = encode_name_b64(unsafe { from_cstr(name) });
    let d = unsafe { from_cstr(device_type).to_string() };
    with_ctx(ctx_ptr, |ctx| {
        do_send(ctx, &codec::encode_heartbeat_tcp(&u, &n_b64, port, battery, &d));
    });
}

#[no_mangle]
pub extern "C" fn nrc_send_heartbeat_udp(ctx_ptr: *mut c_void, uuid: *const c_char,
    name: *const c_char, port: u16, battery: i32, device_type: *const c_char) {
    let u = unsafe { from_cstr(uuid).to_string() };
    let n_b64 = encode_name_b64(unsafe { from_cstr(name) });
    let d = unsafe { from_cstr(device_type).to_string() };
    with_ctx(ctx_ptr, |ctx| {
        do_send_udp(ctx, &codec::encode_udp_broadcast(&u, &n_b64, port, battery, &d));
    });
}

#[no_mangle]
pub extern "C" fn nrc_send_discovery(ctx_ptr: *mut c_void, uuid: *const c_char,
    name: *const c_char, port: u16, battery: i32, device_type: *const c_char) {
    let u = unsafe { from_cstr(uuid).to_string() };
    let n_b64 = encode_name_b64(unsafe { from_cstr(name) });
    let d = unsafe { from_cstr(device_type).to_string() };
    with_ctx(ctx_ptr, |ctx| {
        do_send_udp(ctx, &codec::encode_udp_broadcast(&u, &n_b64, port, battery, &d));
    });
}

#[no_mangle]
pub extern "C" fn nrc_send_data_message(ctx_ptr: *mut c_void, header: *const c_char,
    local_uuid: *const c_char, local_pub_key: *const c_char,
    remote_uuid: *const c_char, plaintext: *const c_char) {
    let hdr = unsafe { from_cstr(header).to_string() };
    let uuid = unsafe { from_cstr(local_uuid).to_string() };
    let pub_key = unsafe { from_cstr(local_pub_key).to_string() };
    let remote = unsafe { from_cstr(remote_uuid).to_string() };
    let text = unsafe { from_cstr(plaintext).to_string() };
    with_ctx(ctx_ptr, |ctx| {
        let key_b64 = match ctx.crypto.device_keys.get(&remote) {
            Some(k) => k.aes_key_b64.clone(), None => return,
        };
        let key_bytes = match base64::engine::general_purpose::STANDARD.decode(&key_b64) {
            Ok(b) if b.len() == 32 => b, _ => return,
        };
        let mut key_arr = [0u8; 32]; key_arr.copy_from_slice(&key_bytes);
        if let Ok(encrypted) = aes::encrypt(&key_arr, text.as_bytes()) {
            let msg = codec::encode_data_message(&hdr, &uuid, &pub_key, &encrypted);
            do_send(ctx, &msg);
        }
    });
}