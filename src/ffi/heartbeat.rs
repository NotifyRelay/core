//! 心跳与离线检测 C ABI 委托。

use std::os::raw::{c_char, c_void};

use super::common::from_cstr;

/// 更新心跳调度器本机参数（电量/名称/设备类型变化时调用）。
///
/// # Safety
/// 字符串指针须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_update_heartbeat_scheduler_params(
    ctx_ptr: *mut c_void,
    name: *const c_char,
    battery: i32,
    device_type: *const c_char,
) {
    if ctx_ptr.is_null() {
        return;
    }
    let name = unsafe { from_cstr(name) }.to_string();
    let device_type = unsafe { from_cstr(device_type) }.to_string();
    crate::heartbeat::update_scheduler_params(
        unsafe { &*(ctx_ptr as *const crate::SafeContext) },
        &name,
        battery,
        &device_type,
    );
}
