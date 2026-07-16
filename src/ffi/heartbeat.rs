use std::os::raw::{c_char, c_void};

use crate::heartbeat::{self, HeartbeatHandle};
use crate::SafeContext;

use super::common::from_cstr;

/// 启动心跳发送器
/// mode: 0=UDP, 1=TCP, 2=Auto
#[no_mangle]
pub extern "C" fn nrc_start_heartbeat_sender(
    ctx_ptr: *mut c_void,
    uuid: *const c_char,
    name: *const c_char,
    battery: i32,
    device_type: *const c_char,
    ip: *const c_char,
    interval_ms: u64,
    mode: i32,
) -> i64 {
    if ctx_ptr.is_null() { return -1; }
    let u = unsafe { from_cstr(uuid) };
    let n = unsafe { from_cstr(name) };
    let d = unsafe { from_cstr(device_type) };
    let ip_str = unsafe { from_cstr(ip) };

    match HeartbeatHandle::start(ctx_ptr as usize, u, n, battery, d, &ip_str, interval_ms, mode) {
        Ok(handle) => {
            // 存储 handle 到 context
            let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
            if let Ok(mut guard) = ctx.lock() {
                let handle_box = Box::new(handle);
                let ptr = Box::into_raw(handle_box) as i64;
                guard.heartbeat_handle = ptr;
                ptr
            } else { -1 }
        }
        Err(_) => -1,
    }
}

/// 更新心跳发送器参数
#[no_mangle]
pub extern "C" fn nrc_update_heartbeat_params(
    ctx_ptr: *mut c_void,
    handle_ptr: i64,
    uuid: *const c_char,
    name: *const c_char,
    battery: i32,
    device_type: *const c_char,
) {
    if ctx_ptr.is_null() || handle_ptr == 0 { return; }
    let handle = unsafe { &*(handle_ptr as *const HeartbeatHandle) };
    let u = unsafe { from_cstr(uuid) };
    let n = unsafe { from_cstr(name) };
    let d = unsafe { from_cstr(device_type) };
    handle.update(u, n, battery, d);
}

/// 停止心跳发送器
#[no_mangle]
pub extern "C" fn nrc_stop_heartbeat_sender(ctx_ptr: *mut c_void, handle_ptr: i64) {
    if ctx_ptr.is_null() || handle_ptr == 0 { return; }
    let handle = unsafe { Box::from_raw(handle_ptr as *mut HeartbeatHandle) };
    handle.stop();
    // 清除 context 中的引用
    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
    if let Ok(mut guard) = ctx.lock() {
        guard.heartbeat_handle = 0;
    }
}

/// 启动离线检测
/// timeout_sec: 超时秒数（默认 12）
/// check_interval_ms: 检查间隔（默认 5000）
#[no_mangle]
pub extern "C" fn nrc_start_offline_detector(
    ctx_ptr: *mut c_void,
    timeout_sec: i64,
    check_interval_ms: u64,
) -> i64 {
    if ctx_ptr.is_null() { return -1; }
    match heartbeat::start_offline_detector(ctx_ptr as usize, check_interval_ms, timeout_sec) {
        Ok(running) => {
            let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
            if let Ok(mut guard) = ctx.lock() {
                let boxed = Box::new(running);
                let ptr = Box::into_raw(boxed) as i64;
                guard.offline_detector_handle = ptr;
                ptr
            } else { -1 }
        }
        Err(_) => -1,
    }
}

/// 停止离线检测
#[no_mangle]
pub extern "C" fn nrc_stop_offline_detector(ctx_ptr: *mut c_void) {
    if ctx_ptr.is_null() { return; }
    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
    if let Ok(mut guard) = ctx.lock() {
        if guard.offline_detector_handle != 0 {
            let boxed = unsafe { Box::from_raw(guard.offline_detector_handle as *mut std::sync::Arc<std::sync::atomic::AtomicBool>) };
            boxed.store(false, std::sync::atomic::Ordering::Relaxed);
            guard.offline_detector_handle = 0;
        }
    }
}
