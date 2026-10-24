//! 应用同步 C ABI 委托。

use std::os::raw::c_char;

use super::common::{from_cstr, to_cstr};

/// 图标请求入参（C 侧原始参数的聚合）。
struct IconRequestArgs {
    packages_json: *const c_char,
    installed_json: *const c_char,
    cached_json: *const c_char,
    app_device_json: *const c_char,
    source_device_uuid: *const c_char,
    now_ms: i64,
}

unsafe fn request_icons(
    ctx_ptr: *mut std::os::raw::c_void,
    args: IconRequestArgs,
    release_pending: bool,
) -> *mut c_char {
    if ctx_ptr.is_null() {
        return to_cstr("{}");
    }
    let packages_json = unsafe { from_cstr(args.packages_json) };
    let installed_json = unsafe { from_cstr(args.installed_json) };
    let cached_json = unsafe { from_cstr(args.cached_json) };
    let app_device_json = unsafe { from_cstr(args.app_device_json) };
    let source = unsafe { from_cstr(args.source_device_uuid) };
    let result = crate::app_sync::request_icons_for(
        ctx_ptr as usize,
        packages_json,
        installed_json,
        cached_json,
        app_device_json,
        source,
        args.now_ms,
        release_pending,
    );
    to_cstr(&result)
}

/// # Safety
/// 字符串指针须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_app_sync_prepare_icon_request(
    ctx_ptr: *mut std::os::raw::c_void,
    packages_json: *const c_char,
    installed_json: *const c_char,
    cached_json: *const c_char,
    app_device_json: *const c_char,
    source_device_uuid: *const c_char,
    now_ms: i64,
) -> *mut c_char {
    request_icons(
        ctx_ptr,
        IconRequestArgs {
            packages_json,
            installed_json,
            cached_json,
            app_device_json,
            source_device_uuid,
            now_ms,
        },
        false,
    )
}

/// # Safety
/// 同上。
#[no_mangle]
pub unsafe extern "C" fn nrc_app_sync_request_icons(
    ctx_ptr: *mut std::os::raw::c_void,
    packages_json: *const c_char,
    installed_json: *const c_char,
    cached_json: *const c_char,
    app_device_json: *const c_char,
    source_device_uuid: *const c_char,
    now_ms: i64,
) -> *mut c_char {
    request_icons(
        ctx_ptr,
        IconRequestArgs {
            packages_json,
            installed_json,
            cached_json,
            app_device_json,
            source_device_uuid,
            now_ms,
        },
        true,
    )
}

/// # Safety
/// 字符串指针须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_app_sync_clear_icon_pending(
    ctx_ptr: *mut std::os::raw::c_void,
    packages_json: *const c_char,
) {
    if ctx_ptr.is_null() {
        return;
    }
    let packages_json = unsafe { from_cstr(packages_json) };
    crate::app_sync::clear_icon_pending_for(ctx_ptr as usize, packages_json);
}

/// # Safety
/// `payload_json` 须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_app_sync_parse_icon_response(
    payload_json: *const c_char,
) -> *mut c_char {
    let payload = unsafe { from_cstr(payload_json) };
    to_cstr(&crate::app_sync::parse_icon_response(payload))
}

/// # Safety
/// `scope` 须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_app_sync_build_applist_request(
    scope: *const c_char,
    now_ms: i64,
) -> *mut c_char {
    let scope = unsafe { from_cstr(scope) };
    to_cstr(&crate::app_sync::build_applist_request(scope, now_ms))
}

/// # Safety
/// `payload_json` 须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_app_sync_parse_applist_response(
    payload_json: *const c_char,
) -> *mut c_char {
    let payload = unsafe { from_cstr(payload_json) };
    to_cstr(&crate::app_sync::parse_applist_response(payload))
}
