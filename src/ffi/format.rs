use std::os::raw::c_char;

use crate::protocol::codec;

use super::common::{encode_name_b64, from_cstr, to_cstr};

#[no_mangle]
pub extern "C" fn nrc_format_handshake(uuid: *const c_char, pub_key: *const c_char,
    ip: *const c_char, battery: i32, device_type: *const c_char) -> *mut c_char {
    let u = unsafe { from_cstr(uuid) }; let p = unsafe { from_cstr(pub_key) };
    let i = unsafe { from_cstr(ip) }; let d = unsafe { from_cstr(device_type) };
    to_cstr(&codec::encode_handshake(u, p, i, battery, d))
}

#[no_mangle]
pub extern "C" fn nrc_format_pairing_init(uuid: *const c_char, tmp_pub_key: *const c_char,
    ip: *const c_char, battery: i32, device_type: *const c_char) -> *mut c_char {
    let u = unsafe { from_cstr(uuid) }; let t = unsafe { from_cstr(tmp_pub_key) };
    let i = unsafe { from_cstr(ip) }; let d = unsafe { from_cstr(device_type) };
    to_cstr(&codec::encode_pairing_init(u, t, i, battery, d))
}

#[no_mangle]
pub extern "C" fn nrc_format_pairing_resp(uuid: *const c_char, tmp_pub: *const c_char,
    lt_pub: *const c_char, encrypted_code: *const c_char, ip: *const c_char,
    battery: i32, device_type: *const c_char) -> *mut c_char {
    let u = unsafe { from_cstr(uuid) }; let t = unsafe { from_cstr(tmp_pub) };
    let l = unsafe { from_cstr(lt_pub) }; let e = unsafe { from_cstr(encrypted_code) };
    let i = unsafe { from_cstr(ip) }; let d = unsafe { from_cstr(device_type) };
    to_cstr(&codec::encode_pairing_resp(u, t, l, e, i, battery, d))
}

#[no_mangle]
pub extern "C" fn nrc_format_accept(uuid: *const c_char, lt_pub_key: *const c_char,
    ip: *const c_char, battery: i32, device_type: *const c_char) -> *mut c_char {
    let u = unsafe { from_cstr(uuid) }; let l = unsafe { from_cstr(lt_pub_key) };
    let i = unsafe { from_cstr(ip) }; let d = unsafe { from_cstr(device_type) };
    to_cstr(&codec::encode_accept(u, l, i, battery, d))
}

#[no_mangle]
pub extern "C" fn nrc_format_tcp_heartbeat(uuid: *const c_char, name: *const c_char,
    port: u16, battery: i32, device_type: *const c_char) -> *mut c_char {
    let u = unsafe { from_cstr(uuid) }; let n_b64 = encode_name_b64(unsafe { from_cstr(name) });
    let dt = unsafe { from_cstr(device_type) };
    to_cstr(&codec::encode_heartbeat_tcp(u, &n_b64, port, battery, dt))
}

#[no_mangle]
pub extern "C" fn nrc_format_heartbeat(uuid: *const c_char, name: *const c_char,
    port: u16, battery: i32, device_type: *const c_char) -> *mut c_char {
    let u = unsafe { from_cstr(uuid) }; let n_b64 = encode_name_b64(unsafe { from_cstr(name) });
    let dt = unsafe { from_cstr(device_type) };
    to_cstr(&codec::encode_udp_broadcast(u, &n_b64, port, battery, dt))
}

#[no_mangle]
pub extern "C" fn nrc_format_discovery(uuid: *const c_char, name: *const c_char,
    port: u16, battery: i32, device_type: *const c_char) -> *mut c_char {
    let u = unsafe { from_cstr(uuid) }; let n_b64 = encode_name_b64(unsafe { from_cstr(name) });
    let dt = unsafe { from_cstr(device_type) };
    to_cstr(&codec::encode_udp_broadcast(u, &n_b64, port, battery, dt))
}