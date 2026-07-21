use std::os::raw::{c_char, c_void};

use crate::sender_queue::{SendItem, SenderQueue};
use crate::SafeContext;

use super::common::from_cstr;

/// 创建发送队列
#[no_mangle]
pub extern "C" fn nrc_create_sender_queue(ctx_ptr: *mut c_void) -> i64 {
    if ctx_ptr.is_null() {
        return -1;
    }
    let queue = Box::new(SenderQueue::new());
    let ptr = Box::into_raw(queue) as i64;

    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
    if let Ok(mut guard) = ctx.lock() {
        guard.sender_queue = ptr;
    }

    ptr
}

/// 启动发送队列后台工作者
#[no_mangle]
pub extern "C" fn nrc_start_sender_queue(ctx_ptr: *mut c_void, queue_ptr: i64) {
    if ctx_ptr.is_null() || queue_ptr == 0 {
        return;
    }
    let queue = unsafe { &*(queue_ptr as *const SenderQueue) };
    queue.start_worker(ctx_ptr as usize);
}

/// 入队消息（IP 由 Rust 内部管理，无需平台端传入）
#[no_mangle]
pub extern "C" fn nrc_enqueue_message(
    ctx_ptr: *mut c_void,
    queue_ptr: i64,
    device_uuid: *const c_char,
    header: *const c_char,
    plaintext: *const c_char,
    dedup_key: *const c_char,
) {
    if ctx_ptr.is_null() || queue_ptr == 0 {
        return;
    }
    let queue = unsafe { &*(queue_ptr as *const SenderQueue) };
    let uuid = unsafe { from_cstr(device_uuid) };
    let hdr = unsafe { from_cstr(header) };
    let text = unsafe { from_cstr(plaintext) };
    let dk = unsafe { from_cstr(dedup_key) };

    queue.enqueue(SendItem {
        device_uuid: uuid.to_string(),
        header: hdr.to_string(),
        plaintext: text.to_string(),
        dedup_key: if dk.is_empty() {
            None
        } else {
            Some(dk.to_string())
        },
        retries_left: 0,
    });
}

/// 停止发送队列
#[no_mangle]
pub extern "C" fn nrc_stop_sender_queue(ctx_ptr: *mut c_void, queue_ptr: i64) {
    if ctx_ptr.is_null() || queue_ptr == 0 {
        return;
    }
    let queue = unsafe { Box::from_raw(queue_ptr as *mut SenderQueue) };
    queue.stop();
    if let Ok(mut guard) = unsafe { &mut *(ctx_ptr as *mut SafeContext) }.lock() {
        guard.sender_queue = 0;
    }
}
