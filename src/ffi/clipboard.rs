use std::os::raw::{c_char, c_void};

use crate::sender_queue::SenderQueue;

use super::common::{from_cstr, to_cstr};

/// 平台检测到剪贴板变化时调用。
/// Rust 内部完成类型归一化、内容去重、防循环、频率限制与 2MB 阈值判定，
/// 通过后直接构造 DATA_CLIPBOARD 报文按 targets 逐个入队发送（无需平台端再调用发送接口）。
///
/// 参数：
/// - targets_json: 目标设备 UUID 数组 JSON，如 ["uuid1","uuid2"]
/// - mime: 剪贴板 MIME 类型（如 text/plain、image/png）
/// - content: 剪贴板内容（文本原文 / 图片 base64 或 data URL）
/// - now_ms: 当前时间戳（毫秒）
/// - force: 1=手动同步模式（跳过前台/Fcitx 判定；内容未变/防循环/频率检查仍生效）
///
/// 返回 JSON：{"action": "sent"|"skipped"|"file_transfer", "reason": "..."}
#[no_mangle]
pub unsafe extern "C" fn nrc_clipboard_on_changed(
    ctx_ptr: *mut c_void,
    queue_ptr: i64,
    targets_json: *const c_char,
    mime: *const c_char,
    content: *const c_char,
    now_ms: i64,
    force: i32,
) -> *mut c_char {
    if ctx_ptr.is_null() || queue_ptr == 0 {
        return to_cstr(r#"{"action":"skipped","reason":"invalid ctx or queue"}"#);
    }
    let targets = from_cstr(targets_json);
    let mime_str = from_cstr(mime);
    let content_str = from_cstr(content);
    let targets: Vec<String> = serde_json::from_str::<Vec<String>>(targets)
        .unwrap_or_default()
        .into_iter()
        .filter(|u| !u.is_empty())
        .collect();
    if targets.is_empty() {
        return to_cstr(r#"{"action":"skipped","reason":"no targets"}"#);
    }

    let ctx = unsafe { &mut *(ctx_ptr as *mut crate::SafeContext) };
    let guard = match ctx.get_mut() {
        Ok(g) => g,
        Err(_) => return to_cstr(r#"{"action":"skipped","reason":"lock failed"}"#),
    };
    let queue = unsafe { &*(queue_ptr as *const SenderQueue) };
    let result = crate::clipboard::on_changed(
        &mut guard.clipboard,
        queue,
        &targets,
        mime_str,
        content_str,
        now_ms,
        force != 0,
    );
    to_cstr(&result)
}

/// 平台收到远程剪贴板报文（DATA_CLIPBOARD）时调用。
/// Rust 解析报文、归一化类型并登记防循环时间窗，返回内容供平台写入系统剪贴板。
///
/// 参数：
/// - payload_json: 收到的 DATA_CLIPBOARD 报文 JSON
/// - now_ms: 当前时间戳（毫秒）
///
/// 返回 JSON：{"type": "text"|"image", "content": "..."}
#[no_mangle]
pub unsafe extern "C" fn nrc_clipboard_on_received(
    ctx_ptr: *mut c_void,
    payload_json: *const c_char,
    now_ms: i64,
) -> *mut c_char {
    if ctx_ptr.is_null() {
        return to_cstr(r#"{"type":"text","content":""}"#);
    }
    let payload = from_cstr(payload_json);
    let ctx = unsafe { &mut *(ctx_ptr as *mut crate::SafeContext) };
    let guard = match ctx.get_mut() {
        Ok(g) => g,
        Err(_) => return to_cstr(r#"{"type":"text","content":""}"#),
    };
    let result = crate::clipboard::on_received(&mut guard.clipboard, payload, now_ms);
    to_cstr(&result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_cstr_test(s: &str) -> *const c_char {
        std::ffi::CString::new(s).unwrap().into_raw()
    }

    fn free_cstr(p: *const c_char) {
        unsafe {
            let _ = std::ffi::CString::from_raw(p as *mut c_char);
        }
    }

    #[test]
    fn test_clipboard_on_changed_no_targets() {
        let ctx = crate::SafeContext::new(crate::CoreContext::new());
        let ctx_ptr = &ctx as *const crate::SafeContext as *mut std::os::raw::c_void;
        let queue = crate::sender_queue::SenderQueue::new();
        let queue_ptr = &queue as *const _ as i64;

        let targets = to_cstr_test("[]");
        let mime = to_cstr_test("text/plain");
        let content = to_cstr_test("hello");
        let result = unsafe {
            nrc_clipboard_on_changed(ctx_ptr, queue_ptr, targets, mime, content, 1000, 0)
        };
        let s = unsafe { from_cstr(result).to_string() };
        assert!(s.contains("no targets"));
        free_cstr(result);
        free_cstr(targets);
        free_cstr(mime);
        free_cstr(content);
    }

    #[test]
    fn test_clipboard_on_received() {
        let ctx = crate::SafeContext::new(crate::CoreContext::new());
        let ctx_ptr = &ctx as *const crate::SafeContext as *mut std::os::raw::c_void;
        let payload = to_cstr_test(r#"{"clipboardType":"image/png","content":"AAA="}"#);
        let result = unsafe { nrc_clipboard_on_received(ctx_ptr, payload, 2000) };
        let s = unsafe { from_cstr(result).to_string() };
        assert!(s.contains("\"type\":\"image\""));
        free_cstr(result);
        free_cstr(payload);
    }
}
