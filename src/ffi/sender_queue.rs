//! 发送队列 C ABI 委托。

use std::os::raw::c_char;

use super::common::from_cstr;

/// 入队消息（IP 由 core 内部管理；header 规范化、去重键推导与发送去重均在内部完成）。
///
/// 返回：1=已入队 0=命中去重丢弃（仅通知类） -1=参数无效或队列未初始化
///
/// # Safety
/// 字符串指针须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_enqueue_message(
    ctx_ptr: *mut std::os::raw::c_void,
    queue_handle: u64,
    device_uuid: *const c_char,
    header: *const c_char,
    plaintext: *const c_char,
) -> i32 {
    if ctx_ptr.is_null() || queue_handle == 0 {
        return -1;
    }
    let uuid = unsafe { from_cstr(device_uuid) };
    let hdr = unsafe { from_cstr(header) };
    let text = unsafe { from_cstr(plaintext) };
    crate::sender_queue::enqueue_message(ctx_ptr as usize, queue_handle, uuid, hdr, text)
}
