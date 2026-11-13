//! 剪贴板 C ABI 委托。

use std::os::raw::c_char;

use super::common::{from_cstr, to_cstr};

/// 平台检测到剪贴板变化时调用。
///
/// 返回 JSON：`{"action": "sent"|"skipped"|"file_transfer", "reason": "..."}`
///
/// # Safety
/// 字符串指针须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_clipboard_on_changed(
    ctx_ptr: *mut std::os::raw::c_void,
    queue_handle: u64,
    targets_json: *const c_char,
    mime: *const c_char,
    content: *const c_char,
    now_ms: i64,
    force: i32,
) -> *mut c_char {
    if ctx_ptr.is_null() || queue_handle == 0 {
        return to_cstr(r#"{"action":"skipped","reason":"invalid ctx or queue"}"#);
    }
    let targets_json = unsafe { from_cstr(targets_json) };
    let mime = unsafe { from_cstr(mime) };
    let content = unsafe { from_cstr(content) };
    let result = crate::clipboard::on_changed_for(
        ctx_ptr as usize,
        queue_handle,
        targets_json,
        mime,
        content,
        now_ms,
        force != 0,
    );
    to_cstr(&result)
}

/// 平台收到远程剪贴板报文时调用。
///
/// 返回 JSON：`{"type": "text"|"image", "content": "..."}`
///
/// # Safety
/// 字符串指针须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_clipboard_on_received(
    ctx_ptr: *mut std::os::raw::c_void,
    payload_json: *const c_char,
    now_ms: i64,
) -> *mut c_char {
    if ctx_ptr.is_null() {
        return to_cstr(r#"{"type":"text","content":""}"#);
    }
    let payload = unsafe { from_cstr(payload_json) };
    let result = crate::clipboard::on_received_for(ctx_ptr as usize, payload, now_ms);
    to_cstr(&result)
}
