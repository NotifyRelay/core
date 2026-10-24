//! 状态合并 C ABI 委托。

use std::os::raw::{c_char, c_void};

use super::common::{from_cstr, to_cstr};

/// 推送超级岛全量状态。
#[no_mangle]
pub extern "C" fn nrc_push_superisland_state(
    ctx_ptr: *mut c_void,
    queue_handle: u64,
    device_uuid: *const c_char,
    full_json: *const c_char,
    is_end: i32,
    is_query: i32,
) -> i32 {
    push_state_impl(
        ctx_ptr,
        queue_handle,
        device_uuid,
        full_json,
        is_end,
        is_query,
        false,
    )
}

/// 推送媒体全量状态。
#[no_mangle]
pub extern "C" fn nrc_push_media_state(
    ctx_ptr: *mut c_void,
    queue_handle: u64,
    device_uuid: *const c_char,
    full_json: *const c_char,
    is_end: i32,
    is_query: i32,
) -> i32 {
    push_state_impl(
        ctx_ptr,
        queue_handle,
        device_uuid,
        full_json,
        is_end,
        is_query,
        true,
    )
}

fn push_state_impl(
    ctx_ptr: *mut c_void,
    queue_handle: u64,
    device_uuid: *const c_char,
    full_json: *const c_char,
    is_end: i32,
    is_query: i32,
    is_media: bool,
) -> i32 {
    if ctx_ptr.is_null() || queue_handle == 0 || device_uuid.is_null() || full_json.is_null() {
        return -1;
    }
    // SAFETY: 上方已排除空指针；字符串由调用方保证以 NUL 结尾。
    let uuid = unsafe { from_cstr(device_uuid) };
    let full = unsafe { from_cstr(full_json) };
    crate::state_merge::push_state(
        ctx_ptr as usize,
        queue_handle,
        uuid,
        full,
        is_end != 0,
        is_query != 0,
        is_media,
    )
}

/// 解析超级岛入站报文，返回归一结构 JSON。
///
/// # Safety
/// 字符串指针须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_parse_superisland_inbound(
    device_uuid: *const c_char,
    pkg: *const c_char,
    full_json: *const c_char,
) -> *mut c_char {
    let uuid = unsafe { from_cstr(device_uuid) };
    let pkg = unsafe { from_cstr(pkg) };
    let full = unsafe { from_cstr(full_json) };
    let result = crate::state_merge::parse_superisland_inbound(uuid, pkg, full);
    to_cstr(&result.to_string())
}

/// 解析通知入站报文。
///
/// # Safety
/// `full_json` 须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_parse_notification_inbound(full_json: *const c_char) -> *mut c_char {
    let full = unsafe { from_cstr(full_json) };
    let result = crate::state_merge::parse_notification_inbound(full);
    to_cstr(&result.to_string())
}

/// 解析媒体入站报文。
///
/// # Safety
/// `full_json` 须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_parse_media_inbound(full_json: *const c_char) -> *mut c_char {
    let full = unsafe { from_cstr(full_json) };
    let result = crate::state_merge::parse_media_inbound(full);
    to_cstr(&result.to_string())
}
