//! 本地持久化 C ABI 委托。

use std::os::raw::{c_char, c_void};

use super::common::{from_cstr, to_cstr, with_ctx_or};

/// 获取本机 UUID（库为准；库无记录则由 core 生成并落库）。
///
/// # Safety
/// `ctx_ptr` 须为有效上下文指针。
#[no_mangle]
pub unsafe extern "C" fn nrc_get_local_uuid(ctx_ptr: *mut c_void) -> *mut c_char {
    match with_ctx_or(ctx_ptr, None, crate::persistence::local_uuid) {
        Some(uuid) => to_cstr(&uuid),
        None => std::ptr::null_mut(),
    }
}

/// 更新设备显示名。
///
/// # Safety
/// 字符串指针须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_rename_device(
    ctx_ptr: *mut c_void,
    device_uuid: *const c_char,
    name: *const c_char,
) -> i32 {
    let uuid = unsafe { from_cstr(device_uuid) }.to_string();
    let name = unsafe { from_cstr(name) }.to_string();
    let ok = with_ctx_or(ctx_ptr, false, |ctx| {
        crate::persistence::rename_device(ctx, &uuid, &name)
    });
    if ok {
        0
    } else {
        -1
    }
}
