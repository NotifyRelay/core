use std::os::raw::{c_char, c_void};

use crate::reconnect::ReconnectState;
use crate::SafeContext;

use super::common::from_cstr;

/// 创建重连状态机
#[no_mangle]
pub extern "C" fn nrc_create_reconnect_state(ctx_ptr: *mut c_void) -> i64 {
    if ctx_ptr.is_null() {
        return -1;
    }
    let state = Box::new(ReconnectState::new());
    let ptr = Box::into_raw(state) as i64;
    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
    ctx.get_mut().unwrap().reconnect_state = ptr;
    ptr
}

/// 添加重连目标
#[no_mangle]
pub unsafe extern "C" fn nrc_reconnect_add_target(
    ctx_ptr: *mut c_void,
    state_ptr: i64,
    uuid: *const c_char,
    ip: *const c_char,
) {
    if ctx_ptr.is_null() || state_ptr == 0 {
        return;
    }
    let u = unsafe { from_cstr(uuid) };
    let i = unsafe { from_cstr(ip) };
    // 忽略本机自身，避免自我重连
    let is_self = unsafe { &mut *(ctx_ptr as *mut SafeContext) }
        .get_mut()
        .unwrap()
        .broadcast_info
        .as_ref()
        .map(|b| b.uuid == u)
        .unwrap_or(false);
    if is_self {
        return;
    }
    let state = unsafe { &*(state_ptr as *const ReconnectState) };
    state.add_target(u, i);
}

/// 移除重连目标
#[no_mangle]
pub unsafe extern "C" fn nrc_reconnect_remove_target(
    ctx_ptr: *mut c_void,
    state_ptr: i64,
    uuid: *const c_char,
) {
    if ctx_ptr.is_null() || state_ptr == 0 {
        return;
    }
    let u = unsafe { from_cstr(uuid) };
    let state = unsafe { &*(state_ptr as *const ReconnectState) };
    state.remove_target(u);
}

/// 启动重连检测
#[no_mangle]
pub extern "C" fn nrc_reconnect_start(
    ctx_ptr: *mut c_void,
    state_ptr: i64,
    interval_secs: u64,
    max_retries: u32,
) {
    if ctx_ptr.is_null() || state_ptr == 0 {
        return;
    }
    let state = unsafe { &*(state_ptr as *const ReconnectState) };
    state.configure(interval_secs, max_retries);
    state.start(ctx_ptr as usize);
}
