//! 过滤 C ABI 委托。

use std::os::raw::c_char;

use super::common::{from_cstr, to_cstr, with_ctx_or};

/// # Safety
/// 字符串指针须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_set_filter_config(
    ctx_ptr: *mut crate::SafeContext,
    config_json: *const c_char,
) -> i32 {
    if ctx_ptr.is_null() || config_json.is_null() {
        return -1;
    }
    let json = unsafe { from_cstr(config_json) }.to_string();
    let ok = with_ctx_or(ctx_ptr as *mut std::os::raw::c_void, false, |ctx| {
        crate::filter::set_config_json(&ctx.filter, &json)
    });
    if ok {
        0
    } else {
        -1
    }
}

/// # Safety
/// 同上。
#[no_mangle]
pub unsafe extern "C" fn nrc_map_local_package(
    ctx_ptr: *mut crate::SafeContext,
    remote_package: *const c_char,
) -> *mut c_char {
    if ctx_ptr.is_null() || remote_package.is_null() {
        return to_cstr("");
    }
    let pkg = unsafe { from_cstr(remote_package) }.to_string();
    let mapped = with_ctx_or(ctx_ptr as *mut std::os::raw::c_void, String::new(), |ctx| {
        crate::filter::map_local_package(&ctx.filter, &pkg)
    });
    to_cstr(&mapped)
}

/// 检查过滤模式（返回 1=通过, 0=被过滤）。
///
/// # Safety
/// 同上。
#[no_mangle]
pub unsafe extern "C" fn nrc_check_filter_mode(
    ctx_ptr: *mut crate::SafeContext,
    mapped_package: *const c_char,
    _original_package: *const c_char,
    title: *const c_char,
    text: *const c_char,
) -> i32 {
    if ctx_ptr.is_null() || mapped_package.is_null() {
        return 1;
    }
    let pkg = unsafe { from_cstr(mapped_package) }.to_string();
    let title = unsafe { from_cstr(title) }.to_string();
    let text = unsafe { from_cstr(text) }.to_string();
    let pass = with_ctx_or(ctx_ptr as *mut std::os::raw::c_void, true, |ctx| {
        crate::filter::check_mode(&ctx.filter, &pkg, &title, &text)
    });
    if pass {
        1
    } else {
        0
    }
}
