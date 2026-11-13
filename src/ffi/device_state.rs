//! 设备状态快照 C ABI 委托。

use std::os::raw::{c_char, c_void};

use super::common::{to_cstr, with_ctx};

/// 获取设备状态快照（JSON 数组）；语义见 [`crate::device_registry::device_list_json`]。
#[no_mangle]
pub unsafe extern "C" fn nrc_get_device_list(
    ctx_ptr: *mut c_void,
    authed_timeout_ms: i64,
    unauthed_timeout_ms: i64,
) -> *mut c_char {
    let json = with_ctx(ctx_ptr, |ctx| {
        crate::device_registry::device_list_json(ctx, authed_timeout_ms, unauthed_timeout_ms)
    });
    to_cstr(&json)
}
