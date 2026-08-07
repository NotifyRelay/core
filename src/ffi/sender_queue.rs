use std::os::raw::{c_char, c_void};

use crate::sender_queue::{SendItem, SenderQueue};
use crate::SafeContext;

use super::common::from_cstr;

/// 发送去重 TTL（毫秒），与原平台端 SENT_KEY_TTL_MS 一致
const SENT_DEDUP_TTL_MS: i64 = 3000;

/// 创建发送队列
#[no_mangle]
pub extern "C" fn nrc_create_sender_queue(ctx_ptr: *mut c_void) -> i64 {
    if ctx_ptr.is_null() {
        return -1;
    }
    let queue = Box::new(SenderQueue::new());
    let ptr = Box::into_raw(queue) as i64;

    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
    ctx.get_mut().unwrap().sender_queue = ptr;

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
pub unsafe extern "C" fn nrc_enqueue_message(
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

    // 发送去重 TTL（与原平台端实现一致：3000ms）
    if !dk.is_empty() {
        let ctx = unsafe { &mut *(ctx_ptr as *mut crate::SafeContext) };
        let dedup_ok = ctx
            .get_mut()
            .map(|g| g.dedup.check_and_pend(&dk, SENT_DEDUP_TTL_MS))
            .unwrap_or(false);
        if !dedup_ok {
            return;
        }
    }

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
        coalesce_key: None,
    });
}
