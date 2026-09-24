//! 状态合并引擎的 FFI 接口
//!
//! 平台侧只需：
//! - 调用 `nrc_push_superisland_state` / `nrc_push_media_state` 传入全量状态；
//! - 接收端合并后的全量通过既有的 `nrc_set_on_data_cb`（`SUPERISLAND` / `MEDIAPLAY`）传出，
//!   无需注册新的输出回调。
//!   所有差异计算、合并、ACK 与心跳都在 Rust 内闭环。

use std::os::raw::c_char;
use std::os::raw::c_void;

use crate::ffi::common::{from_cstr, to_cstr};
use crate::sender_queue::SenderQueue;
use crate::SafeContext;

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
    let uuid = unsafe { from_cstr(device_uuid) };
    let full = unsafe { from_cstr(full_json) };
    let queue = unsafe { &*(crate::ffi::handle::get(queue_handle) as *mut SenderQueue) };
    let mut guard = match unsafe { &*(ctx_ptr as *mut SafeContext) }.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };
    if guard
        .state_merge
        .push_state(queue, uuid, is_media, full, is_end != 0, is_query != 0)
    {
        0
    } else {
        -1
    }
}

/// 超级岛入站解析 FFI：纯字符串输入/输出，无 ctx。
///
/// 平台传入 `device_uuid`（来自 on_data 回调，不在 wire 内）、`pkg`（已解析包名：
/// Android 传映射后 mappedPkg，Win 传原始 packageName）与 `full_json`（wire/全量 JSON），
/// 返回归一结构 JSON 字符串。调用方须用 `nrc_free_string` 释放返回的 char*。
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
