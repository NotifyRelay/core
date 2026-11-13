//! 生命周期 C ABI 委托。

use std::ffi::CString;
use std::os::raw::{c_char, c_void};

/// 创建核心上下文。
#[no_mangle]
pub extern "C" fn nrc_init() -> *mut c_void {
    crate::service::create_context()
}

#[no_mangle]
pub extern "C" fn nrc_get_git_hash() -> *mut c_char {
    CString::new(env!("NOTIFY_RELAY_GIT_HASH"))
        .unwrap_or_default()
        .into_raw()
}

/// # Safety
/// `s` 必须为空指针或由本库 `to_cstr` / `CString::into_raw` 产出的指针。
#[no_mangle]
pub unsafe extern "C" fn nrc_free_string(s: *mut c_char) {
    if !s.is_null() {
        let _ = unsafe { CString::from_raw(s) };
    }
}
