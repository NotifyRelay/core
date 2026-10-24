//! 重连 C ABI 委托。

use std::os::raw::{c_char, c_void};

use super::common::{from_cstr, with_ctx};

/// 添加重连目标。
///
/// # Safety
/// 字符串指针须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_reconnect_add_target(
    ctx_ptr: *mut c_void,
    uuid: *const c_char,
    ip: *const c_char,
) {
    let uuid = unsafe { from_cstr(uuid) }.to_string();
    let ip = unsafe { from_cstr(ip) }.to_string();
    with_ctx(ctx_ptr, |ctx| {
        crate::reconnect::add_target(ctx, &uuid, &ip);
    });
}

/// 移除重连目标。
///
/// # Safety
/// `uuid` 须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_reconnect_remove_target(ctx_ptr: *mut c_void, uuid: *const c_char) {
    let uuid = unsafe { from_cstr(uuid) }.to_string();
    with_ctx(ctx_ptr, |ctx| {
        crate::reconnect::remove_target(ctx, &uuid);
    });
}
