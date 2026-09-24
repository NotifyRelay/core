use std::os::raw::{c_char, c_void};

use crate::sender_queue::{SendItem, SenderQueue};
use crate::SafeContext;

use super::common::from_cstr;

/// 发送去重 TTL（毫秒），与原平台端 SENT_KEY_TTL_MS 一致
const SENT_DEDUP_TTL_MS: i64 = 3000;

/// 创建发送队列（内部实现，供 nrc_start_core 调用）
/// 返回句柄（正整数，0 表示失败）
pub(crate) unsafe fn create_sender_queue_impl(ctx_ptr: *mut c_void) -> u64 {
    if ctx_ptr.is_null() {
        return 0;
    }
    let queue = Box::new(SenderQueue::new());
    let handle = super::handle::put(Box::into_raw(queue) as *mut c_void);

    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
    ctx.get_mut().unwrap().sender_queue = handle;

    handle
}

/// 启动发送队列后台工作者（内部实现，供 nrc_start_core 调用）
pub(crate) unsafe fn start_sender_queue_impl(ctx_ptr: *mut c_void, queue_handle: u64) {
    if ctx_ptr.is_null() || queue_handle == 0 {
        return;
    }
    let queue = unsafe { &*(super::handle::get(queue_handle) as *const SenderQueue) };
    queue.start_worker(ctx_ptr as usize);
}

/// 入队消息（IP 由 Rust 内部管理，无需平台端传入）
#[no_mangle]
pub unsafe extern "C" fn nrc_enqueue_message(
    ctx_ptr: *mut c_void,
    queue_handle: u64,
    device_uuid: *const c_char,
    header: *const c_char,
    plaintext: *const c_char,
    dedup_key: *const c_char,
) {
    if ctx_ptr.is_null() || queue_handle == 0 {
        return;
    }
    let queue = unsafe { &*(super::handle::get(queue_handle) as *const SenderQueue) };
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

    // 通知类消息只注入并记录生成时刻 `ts`，不做丢弃：
    // 断线期间的通知累积是有益的，恢复后应完整补收（实时状态的丢弃在 state_merge / sender_queue 内处理）。
    //
    // 仅对 DATA_NOTIFICATION 注入：其他通道（图标/应用列表/控制等）的模型未声明 `ts`，
    // 注入会触发 `normalize_or_keep` 的"往返丢字段"兜底并产生无谓告警，且这些通道无时效语义。
    let plaintext = if hdr == "DATA_NOTIFICATION" {
        crate::timestamp::inject_ts(text, crate::timestamp::now_ms())
    } else {
        text.to_string()
    };

    queue.enqueue(SendItem {
        device_uuid: uuid.to_string(),
        header: hdr.to_string(),
        plaintext,
        dedup_key: if dk.is_empty() {
            None
        } else {
            Some(dk.to_string())
        },
        retries_left: 0,
        coalesce_key: None,
    });
}
