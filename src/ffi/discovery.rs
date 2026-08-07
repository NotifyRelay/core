use std::os::raw::{c_char, c_void};

use super::common::{from_cstr, with_ctx};

/// 添加已知设备（已配对的设备信息）
#[no_mangle]
pub unsafe extern "C" fn nrc_add_known_device(
    ctx_ptr: *mut c_void,
    uuid: *const c_char,
    ip: *const c_char,
) {
    let u = from_cstr(uuid).to_string();
    let i = from_cstr(ip).to_string();
    with_ctx(ctx_ptr, |ctx| {
        // 忽略本机自身，避免自我扫描连接
        let is_self = ctx
            .broadcast_info
            .as_ref()
            .map(|b| b.uuid == u)
            .unwrap_or(false);
        if is_self {
            return;
        }
        ctx.discovery.add_known_device(&u, &i);
    });
}

/// 移除已知设备
#[no_mangle]
pub unsafe extern "C" fn nrc_remove_known_device(ctx_ptr: *mut c_void, uuid: *const c_char) {
    let u = from_cstr(uuid).to_string();
    with_ctx(ctx_ptr, |ctx| {
        ctx.discovery.remove_known_device(&u);
    });
}

/// 启动已知设备自动扫描（网络变化后调用）
#[no_mangle]
pub unsafe extern "C" fn nrc_start_known_device_scanner(ctx_ptr: *mut c_void) {
    with_ctx(ctx_ptr, |ctx| {
        ctx.discovery.start_known_device_scanner(ctx_ptr as usize);
    });
}
