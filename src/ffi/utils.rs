use std::ffi::CString;
use std::os::raw::c_char;
use std::os::raw::c_void;

use sha2::Digest;

use crate::heartbeat;
use crate::protocol::codec;

use super::common::{from_cstr, to_cstr};

#[no_mangle]
pub extern "C" fn nrc_verify_pairing_code(
    stored_code: *const c_char,
    input_code: *const c_char,
) -> i32 {
    let stored = unsafe { from_cstr(stored_code) };
    let input = unsafe { from_cstr(input_code) };
    if stored.is_empty() || input.is_empty() {
        return 0;
    }
    if stored == input { 1 } else { 0 }
}

#[no_mangle]
pub extern "C" fn nrc_compute_dedup_key(
    device_uuid: *const c_char,
    data: *const c_char,
) -> *mut c_char {
    let uuid = unsafe { from_cstr(device_uuid) };
    let d = unsafe { from_cstr(data) };
    let input = format!("{}|{}", uuid, d);
    let hash = sha2::Sha256::digest(input.as_bytes());
    let hex = hash.iter().map(|b| format!("{:02x}", b)).collect::<String>();
    to_cstr(&hex)
}

#[no_mangle]
pub extern "C" fn nrc_heartbeat_has_timed_out(
    last_heartbeat_sec: i64,
    now_sec: i64,
    timeout_sec: i64,
) -> i32 {
    if last_heartbeat_sec <= 0 { return 1; }
    if now_sec - last_heartbeat_sec > timeout_sec { 1 } else { 0 }
}

#[no_mangle]
pub extern "C" fn nrc_compute_feature_id(
    package_name: *const c_char,
    title: *const c_char,
    text: *const c_char,
) -> *mut c_char {
    let pkg = unsafe { from_cstr(package_name) };
    let t = unsafe { from_cstr(title) };
    let tx = unsafe { from_cstr(text) };
    let mut parts: Vec<&str> = Vec::new();
    if !pkg.is_empty() { parts.push(pkg); }
    if !t.is_empty() { parts.push(t); }
    if !tx.is_empty() { parts.push(tx); }
    let feature = parts.join("|");
    to_cstr(&feature)
}

#[no_mangle]
pub extern "C" fn nrc_parse_heartbeat_with_cb(
    line: *const c_char,
    cb: Option<extern "C" fn(*const c_char, *const c_char, u16, i32, *const c_char, *mut c_void)>,
    user_data: *mut c_void,
) -> i32 {
    let l = unsafe { from_cstr(line) };
    match heartbeat::parse_udp_heartbeat(l) {
        Some((uuid, name_b64, port, battery, device_type)) => {
            if let Some(cb_fn) = cb {
                let uuid_c = CString::new(uuid).unwrap_or_default();
                let name_c = CString::new(name_b64).unwrap_or_default();
                let dt_c = CString::new(device_type).unwrap_or_default();
                cb_fn(uuid_c.as_ptr(), name_c.as_ptr(), port, battery, dt_c.as_ptr(), user_data);
            }
            0
        }
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn nrc_parse_heartbeat_tcp_with_cb(
    line: *const c_char,
    cb: Option<extern "C" fn(*const c_char, *const c_char, u16, i32, *const c_char, *const c_char, *mut c_void)>,
    user_data: *mut c_void,
) -> i32 {
    let l = unsafe { from_cstr(line) };
    match codec::decode_heartbeat_tcp(l) {
        Some(f) => {
            if let Some(cb_fn) = cb {
                let uuid_c = CString::new(f.uuid).unwrap_or_default();
                let name_c = CString::new(f.name).unwrap_or_default();
                let dt_c = CString::new(f.device_type).unwrap_or_default();
                let ip_c = CString::new("").unwrap_or_default();
                cb_fn(uuid_c.as_ptr(), name_c.as_ptr(), f.port, f.battery, dt_c.as_ptr(), ip_c.as_ptr(), user_data);
            }
            0
        }
        None => -1,
    }
}