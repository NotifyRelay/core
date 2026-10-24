//! 密钥与本地状态 C ABI 委托。

use std::os::raw::{c_char, c_void};

use super::common::{from_cstr, to_cstr, with_ctx, with_ctx_or};

/// # Safety
/// 字符串指针须为空或指向有效 NUL 结尾字符串；`aes_key` 须指向 `len` 字节可读内存。
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
    let uuid = unsafe { from_cstr(device_uuid) }.to_string();
    let key_bytes = unsafe { std::slice::from_raw_parts(aes_key, len as usize) };
    if key_bytes.len() != 32 {
        return -1;
    }
    let ok = with_ctx_or(ctx_ptr, false, |ctx| {
        crate::crypto::ops::migrate_shared_secret(ctx, &uuid, key_bytes)
    });
    if ok {
        0
    } else {
        -1
    }
}

/// # Safety
/// `ctx_ptr` 须为有效上下文指针，`device_uuid` 须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_remove_device(
    ctx_ptr: *mut c_void,
    device_uuid: *const c_char,
) -> i32 {
    let uuid = unsafe { from_cstr(device_uuid) }.to_string();
    let ok = with_ctx_or(ctx_ptr, false, |ctx| {
        crate::crypto::ops::remove_device(ctx, &uuid)
    });
    if ok {
        0
    } else {
        -1
    }
}

/// # Safety
/// 同 [`nrc_remove_device`]。
#[no_mangle]
pub unsafe extern "C" fn nrc_export_device_key(
    ctx_ptr: *mut c_void,
    device_uuid: *const c_char,
) -> *mut c_char {
    let uuid = unsafe { from_cstr(device_uuid) }.to_string();
    let json = with_ctx(ctx_ptr, |ctx| {
        crate::crypto::ops::export_device_key_json(ctx, &uuid)
    });
    match json {
        Some(json) => to_cstr(&json),
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn nrc_export_state(ctx_ptr: *mut c_void) -> *mut c_char {
    match with_ctx(ctx_ptr, crate::crypto::ops::export_state) {
        Some(json) => to_cstr(&json),
        None => std::ptr::null_mut(),
    }
}

/// # Safety
/// `json` 须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_import_state(ctx_ptr: *mut c_void, json: *const c_char) -> i32 {
    let json = unsafe { from_cstr(json) }.to_string();
    let ok = with_ctx(ctx_ptr, |ctx| crate::crypto::ops::import_state(ctx, &json));
    if ok {
        0
    } else {
        -1
    }
}

/// # Safety
/// 所有字符串指针须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_encrypt_local_state(
    ctx_ptr: *mut c_void,
    plaintext: *const c_char,
    device_uuid: *const c_char,
) -> *mut c_char {
    let text = unsafe { from_cstr(plaintext) }.to_string();
    let uuid = unsafe { from_cstr(device_uuid) }.to_string();
    match with_ctx(ctx_ptr, |ctx| {
        crate::crypto::ops::encrypt_local_state(ctx, &text, &uuid)
    }) {
        Some(enc) => to_cstr(&enc),
        None => std::ptr::null_mut(),
    }
}

/// # Safety
/// 所有字符串指针须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_decrypt_local_state(
    ctx_ptr: *mut c_void,
    encrypted_b64: *const c_char,
    device_uuid: *const c_char,
) -> *mut c_char {
    let enc = unsafe { from_cstr(encrypted_b64) }.to_string();
    let uuid = unsafe { from_cstr(device_uuid) }.to_string();
    match with_ctx(ctx_ptr, |ctx| {
        crate::crypto::ops::decrypt_local_state(ctx, &enc, &uuid)
    }) {
        Some(plain) => to_cstr(&plain),
        None => std::ptr::null_mut(),
    }
}

/// # Safety
/// 字符串指针须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_serialize_local_state(
    ctx_ptr: *mut c_void,
    device_uuid: *const c_char,
    encrypt: i32,
) -> *mut c_char {
    let uuid = unsafe { from_cstr(device_uuid) }.to_string();
    match with_ctx(ctx_ptr, |ctx| {
        crate::crypto::ops::serialize_local_state(ctx, &uuid, encrypt != 0)
    }) {
        Some(s) => to_cstr(&s),
        None => std::ptr::null_mut(),
    }
}

/// # Safety
/// 字符串指针须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_deserialize_local_state(
    ctx_ptr: *mut c_void,
    payload: *const c_char,
    device_uuid: *const c_char,
    encrypted: i32,
) -> *mut c_char {
    let text = unsafe { from_cstr(payload) }.to_string();
    let uuid = unsafe { from_cstr(device_uuid) }.to_string();
    let result = with_ctx_or(ctx_ptr, r#"{"ok":false}"#.to_string(), |ctx| {
        crate::crypto::ops::deserialize_local_state(ctx, &text, &uuid, encrypted != 0)
    });
    to_cstr(&result)
}
