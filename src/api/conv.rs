//! C 字符串与本层类型之间的转换辅助。
//!
//! 本层是既有 `ffi` 实现的薄委托：入参转 C 字符串，出参读回后按原约定释放，
//! 业务逻辑一律留在原实现内。

use std::ffi::CString;
use std::os::raw::c_char;

/// 生成 C 字符串；含 NUL 时退化为空串（与既有 `to_cstr` 的 `unwrap_or_default` 一致）。
pub(crate) fn cs(s: &str) -> CString {
    CString::new(s).unwrap_or_default()
}

/// 读取既有实现返回的 `*mut c_char`：非空则转 String 并释放。
pub(crate) unsafe fn take_cstr(ptr: *mut c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let s = unsafe { std::ffi::CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned();
    unsafe { crate::ffi::lifecycle::nrc_free_string(ptr) };
    Some(s)
}

/// 读取并释放，空指针返回空串。
pub(crate) unsafe fn take_cstr_or_empty(ptr: *mut c_char) -> String {
    unsafe { take_cstr(ptr) }.unwrap_or_default()
}
