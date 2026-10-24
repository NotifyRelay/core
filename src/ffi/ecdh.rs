//! ECDH C ABI 委托。

use std::os::raw::{c_char, c_void};

use super::common::{from_cstr, to_cstr, with_ctx};

#[no_mangle]
pub extern "C" fn nrc_ecdh_generate_keypair(ctx_ptr: *mut c_void) -> i32 {
    with_ctx(ctx_ptr, |ctx| {
        crate::crypto::ops::generate_keypair(ctx);
        0
    })
}

#[no_mangle]
pub extern "C" fn nrc_ecdh_get_public_key(ctx_ptr: *mut c_void) -> *mut c_char {
    match with_ctx(ctx_ptr, crate::crypto::ops::public_key) {
        Some(b64) => to_cstr(&b64),
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn nrc_ecdh_has_keypair(ctx_ptr: *mut c_void) -> i32 {
    if with_ctx(ctx_ptr, crate::crypto::ops::has_keypair) {
        1
    } else {
        0
    }
}

/// # Safety
/// 字符串指针须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_ecdh_derive_shared_secret(
    ctx_ptr: *mut c_void,
    peer_uuid: *const c_char,
    peer_pub_key_b64: *const c_char,
) -> i32 {
    let uuid = unsafe { from_cstr(peer_uuid) }.to_string();
    let peer = unsafe { from_cstr(peer_pub_key_b64) }.to_string();
    let ok = with_ctx(ctx_ptr, |ctx| {
        crate::crypto::ops::derive_shared_secret(ctx, &uuid, &peer)
    });
    if ok {
        0
    } else {
        -1
    }
}
