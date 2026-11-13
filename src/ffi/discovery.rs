//! 设备发现 C ABI 委托。

use std::os::raw::{c_char, c_void};

use super::common::{from_cstr, with_ctx};

/// 添加已知设备（已配对的设备信息）。
///
/// # Safety
/// 字符串指针须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_add_known_device(
    ctx_ptr: *mut c_void,
    uuid: *const c_char,
    ip: *const c_char,
) {
    let uuid = unsafe { from_cstr(uuid) }.to_string();
    let ip = unsafe { from_cstr(ip) }.to_string();
    with_ctx(ctx_ptr, |ctx| {
        crate::discovery::add_known_device(ctx, &uuid, &ip);
    });
}

/// 移除已知设备。
///
/// # Safety
/// `uuid` 须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_remove_known_device(ctx_ptr: *mut c_void, uuid: *const c_char) {
    let uuid = unsafe { from_cstr(uuid) }.to_string();
    with_ctx(ctx_ptr, |ctx| {
        crate::discovery::remove_known_device(ctx, &uuid);
    });
}
