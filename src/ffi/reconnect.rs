use std::os::raw::{c_char, c_void};

use crate::reconnect::ReconnectState;
use crate::SafeContext;

use super::common::from_cstr;

/// 创建重连状态机（内部实现，供 nrc_start_core 调用）
/// 返回句柄（正整数，0 表示失败）
pub(crate) unsafe fn create_reconnect_state_impl(ctx_ptr: *mut c_void) -> u64 {
    if ctx_ptr.is_null() {
        return 0;
    }
    let state = Box::new(ReconnectState::new());
    let handle = super::handle::put(Box::into_raw(state) as *mut c_void);
    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
    crate::ctx_mut(ctx).reconnect_state = handle;
    handle
}

/// 添加重连目标（重连状态机由 nrc_start_core 统一创建，内部从 ctx 获取）
#[no_mangle]
pub unsafe extern "C" fn nrc_reconnect_add_target(
    ctx_ptr: *mut c_void,
    uuid: *const c_char,
    ip: *const c_char,
) {
    if ctx_ptr.is_null() {
        return;
    }
    let u = unsafe { from_cstr(uuid) };
    let i = unsafe { from_cstr(ip) };
    // 忽略本机自身，避免自我重连
    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) }
        .get_mut()
        .unwrap();
    let is_self = ctx
        .broadcast_info
        .as_ref()
        .map(|b| b.uuid == u)
        .unwrap_or(false);
    if is_self {
        return;
    }
    let state_handle = ctx.reconnect_state;
    if state_handle == 0 {
        return;
    }
    let state = unsafe { &*(super::handle::get(state_handle) as *const ReconnectState) };
    state.add_target(u, i);
}

/// 移除重连目标
#[no_mangle]
pub unsafe extern "C" fn nrc_reconnect_remove_target(ctx_ptr: *mut c_void, uuid: *const c_char) {
    if ctx_ptr.is_null() {
        return;
    }
    let u = unsafe { from_cstr(uuid) };
    let state_handle = unsafe { &mut *(ctx_ptr as *mut SafeContext) }
        .get_mut()
        .unwrap()
        .reconnect_state;
    if state_handle == 0 {
        return;
    }
    let state = unsafe { &*(super::handle::get(state_handle) as *const ReconnectState) };
    state.remove_target(u);
}

/// 启动重连检测（内部实现，供 nrc_start_core 调用）
pub(crate) unsafe fn reconnect_start_impl(
    ctx_ptr: *mut c_void,
    state_handle: u64,
    interval_secs: u64,
    max_retries: u32,
) {
    if ctx_ptr.is_null() || state_handle == 0 {
        return;
    }
    let state = unsafe { &*(super::handle::get(state_handle) as *const ReconnectState) };
    state.configure(interval_secs, max_retries);
    state.start(ctx_ptr as usize);
}
