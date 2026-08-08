//! 状态合并引擎的 FFI 接口
//!
//! 平台侧只需：
//! - 调用 `nrc_push_superisland_state` / `nrc_push_media_state` 传入全量状态；
//! - 接收端合并后的全量通过既有的 `nrc_set_on_data_cb`（`SUPERISLAND` / `MEDIAPLAY`）传出，
//!   无需注册新的输出回调。
//!   所有差异计算、合并、ACK 与心跳都在 Rust 内闭环。

use std::os::raw::c_char;
use std::os::raw::c_void;

use crate::ffi::common::from_cstr;
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
