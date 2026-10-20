use std::os::raw::{c_char, c_void};

use crate::dedup::compute_dedup_key;
use crate::sender_queue::{SendItem, SenderQueue};
use crate::SafeContext;

use super::common::from_cstr;

/// 发送去重 TTL（毫秒），与原平台端 SENT_KEY_TTL_MS 一致
const SENT_DEDUP_TTL_MS: i64 = 3000;

/// 参与发送去重的通知类 header（仅通知通道存在重复发送语义）
fn is_notification_header(header: &str) -> bool {
    header == "DATA_NOTIFICATION"
}

/// 规范化帧类型标识：非空且不以 DATA_ 开头时补前缀（接收端只识别 DATA_*）
pub(crate) fn normalize_header(header: &str) -> String {
    if !header.is_empty() && !header.starts_with("DATA_") {
        format!("DATA_{}", header)
    } else {
        header.to_string()
    }
}

/// 创建发送队列（内部实现，供 nrc_start_core 调用）
/// 返回句柄（正整数，0 表示失败）
pub(crate) unsafe fn create_sender_queue_impl(ctx_ptr: *mut c_void) -> u64 {
    if ctx_ptr.is_null() {
        return 0;
    }
    let queue = Box::new(SenderQueue::new());
    queue.set_ctx_ptr(ctx_ptr as usize);
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

/// 入队消息（IP 由 Rust 内部管理；header 规范化、去重键推导与发送去重均在内部完成）
///
/// 发送去重仅作用于通知类消息（`DATA_NOTIFICATION`）：其他通道无重复语义。
/// 返回：1=已入队 0=命中去重丢弃（仅通知类） -1=参数无效或队列未初始化
#[no_mangle]
pub unsafe extern "C" fn nrc_enqueue_message(
    ctx_ptr: *mut c_void,
    queue_handle: u64,
    device_uuid: *const c_char,
    header: *const c_char,
    plaintext: *const c_char,
) -> i32 {
    if ctx_ptr.is_null() || queue_handle == 0 {
        return -1;
    }
    let queue = unsafe { &*(super::handle::get(queue_handle) as *const SenderQueue) };
    let uuid = unsafe { from_cstr(device_uuid) };
    let hdr = normalize_header(unsafe { from_cstr(header) });
    let text = unsafe { from_cstr(plaintext) };

    let is_notification = is_notification_header(&hdr);

    let dedup_key = if is_notification {
        let key = compute_dedup_key(uuid, text);
        let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
        let dedup_ok = match ctx.get_mut() {
            Ok(g) => {
                g.dedup.maybe_cleanup();
                g.dedup.check_and_pend(&key, SENT_DEDUP_TTL_MS)
            }
            Err(_) => return -1,
        };
        if !dedup_ok {
            return 0;
        }
        Some(key)
    } else {
        None
    };

    // 通知类消息只注入并记录生成时刻 `ts`，不做丢弃：
    // 断线期间的通知累积是有益的，恢复后应完整补收（实时状态的丢弃在 state_merge / sender_queue 内处理）。
    //
    // 仅对 DATA_NOTIFICATION 注入：其他通道（图标/应用列表/控制等）的模型未声明 `ts`，
    // 注入会触发 `normalize_or_keep` 的"往返丢字段"兜底并产生无谓告警，且这些通道无时效语义。
    let plaintext = if is_notification {
        crate::timestamp::inject_ts(text, crate::timestamp::now_ms())
    } else {
        text.to_string()
    };

    queue.enqueue(SendItem {
        device_uuid: uuid.to_string(),
        header: hdr,
        plaintext,
        dedup_key,
        retries_left: 0,
        coalesce_key: None,
    });
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::sync::Mutex;

    fn create_ctx() -> Mutex<crate::CoreContext> {
        let p = std::env::temp_dir()
            .join(format!("nrsq_{}", std::process::id()))
            .join("rust_core.db");
        Mutex::new(crate::CoreContext::with_db_override(p))
    }

    #[test]
    fn normalize_header_cases() {
        assert_eq!(normalize_header("ICON_REQUEST"), "DATA_ICON_REQUEST");
        assert_eq!(normalize_header("DATA_JSON"), "DATA_JSON");
        assert_eq!(normalize_header("DATA_"), "DATA_");
        assert_eq!(normalize_header(""), "");
    }

    #[test]
    fn enqueue_message_params_and_dedup() {
        let ctx = create_ctx();
        let ptr = &ctx as *const Mutex<crate::CoreContext> as *mut c_void;

        // 空上下文 → -1
        assert_eq!(
            unsafe {
                nrc_enqueue_message(
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            -1
        );
        // 队列未初始化 → -1
        assert_eq!(
            unsafe {
                nrc_enqueue_message(ptr, 0, std::ptr::null(), std::ptr::null(), std::ptr::null())
            },
            -1
        );

        let queue_handle = unsafe { create_sender_queue_impl(ptr) };
        assert_ne!(queue_handle, 0);

        let uuid = CString::new("uuid-1").unwrap();
        let notification = CString::new("DATA_NOTIFICATION").unwrap();
        let icon = CString::new("ICON_REQUEST").unwrap();
        let body = CString::new(r#"{"a":1}"#).unwrap();
        let body2 = CString::new(r#"{"a":2}"#).unwrap();

        // 通知：首次入队 → 1
        assert_eq!(
            unsafe {
                nrc_enqueue_message(
                    ptr,
                    queue_handle,
                    uuid.as_ptr(),
                    notification.as_ptr(),
                    body.as_ptr(),
                )
            },
            1
        );
        // 通知：同一 (uuid, plaintext) 在 TTL 内重复 → 0
        assert_eq!(
            unsafe {
                nrc_enqueue_message(
                    ptr,
                    queue_handle,
                    uuid.as_ptr(),
                    notification.as_ptr(),
                    body.as_ptr(),
                )
            },
            0
        );
        // 通知：不同 plaintext → 1
        assert_eq!(
            unsafe {
                nrc_enqueue_message(
                    ptr,
                    queue_handle,
                    uuid.as_ptr(),
                    notification.as_ptr(),
                    body2.as_ptr(),
                )
            },
            1
        );
        // 非通知通道不去重：同一负载连续两次都入队
        assert_eq!(
            unsafe {
                nrc_enqueue_message(
                    ptr,
                    queue_handle,
                    uuid.as_ptr(),
                    icon.as_ptr(),
                    body.as_ptr(),
                )
            },
            1
        );
        assert_eq!(
            unsafe {
                nrc_enqueue_message(
                    ptr,
                    queue_handle,
                    uuid.as_ptr(),
                    icon.as_ptr(),
                    body.as_ptr(),
                )
            },
            1
        );

        let queue = unsafe { &*(super::super::handle::get(queue_handle) as *const SenderQueue) };
        assert_eq!(queue.pending_count(), 4);
    }
}
