//! C ABI 通用辅助与日志桥委托。

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};

use crate::CoreContext;

/// 日志回调类型。
pub type LogCb = crate::log_bridge::LogCb;

pub fn to_cstr(s: &str) -> *mut c_char {
    CString::new(s).unwrap_or_default().into_raw()
}

/// 读取 C 字符串；空指针返回空串。
///
/// # Safety
/// 调用方保证 `ptr` 为空或指向以 NUL 结尾的有效 UTF-8 字符串。
pub unsafe fn from_cstr<'a>(ptr: *const c_char) -> &'a str {
    if ptr.is_null() {
        return "";
    }
    unsafe { CStr::from_ptr(ptr) }.to_str().unwrap_or("")
}

/// 在上下文锁内执行；失败（空上下文 / 锁中毒 / panic）时返回默认值。
///
/// panic 跨 `extern "C"` 边界会导致 SIGABRT，此处在边界内捕获并记录，
/// 返回值与「无效上下文」同语义。
pub fn with_ctx<F, R>(ctx_ptr: *mut c_void, f: F) -> R
where
    F: FnOnce(&mut CoreContext) -> R,
    R: Default,
{
    with_ctx_or(ctx_ptr, R::default(), f)
}

/// 与 [`with_ctx`] 相同，但失败时返回调用方指定的值。
///
/// 用于失败语义必须与成功区分的关键接口（如删除设备），避免默认值（0=成功）误导平台端。
pub fn with_ctx_or<F, R>(ctx_ptr: *mut c_void, or: R, f: F) -> R
where
    F: FnOnce(&mut CoreContext) -> R,
{
    if ctx_ptr.is_null() {
        return or;
    }
    let ctx = unsafe { &*(ctx_ptr as *mut crate::SafeContext) };
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match ctx.lock() {
        Ok(mut g) => Some(f(&mut g)),
        Err(_) => None,
    })) {
        Ok(Some(r)) => r,
        Ok(None) => or,
        Err(payload) => {
            let msg = payload
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| payload.downcast_ref::<String>().map(|s| s.as_str()))
                .unwrap_or("unknown panic payload");
            log::error!("FFI 调用发生 panic（已捕获，进程不崩溃）：{}", msg);
            or
        }
    }
}

#[no_mangle]
pub extern "C" fn nrc_set_log_callback(cb: Option<LogCb>) {
    crate::log_bridge::set_callback(cb);
}

/// 设备名 base64 编码（发现/心跳通道统一使用）。
pub fn encode_name_b64(name: &str) -> String {
    crate::utils::encode_name_b64(name)
}
