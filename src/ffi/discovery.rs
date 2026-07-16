use std::os::raw::{c_char, c_void};

use crate::SafeContext;

use super::common::from_cstr;

/// 添加已知设备（已配对的设备信息）
#[no_mangle]
pub extern "C" fn nrc_add_known_device(
    ctx_ptr: *mut c_void,
    uuid: *const c_char,
    ip: *const c_char,
) {
    if ctx_ptr.is_null() { return; }
    let u = unsafe { from_cstr(uuid) };
    let i = unsafe { from_cstr(ip) };
    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
    if let Ok(guard) = ctx.lock() {
        guard.discovery.add_known_device(u, i);
    }
}

/// 移除已知设备
#[no_mangle]
pub extern "C" fn nrc_remove_known_device(
    ctx_ptr: *mut c_void,
    uuid: *const c_char,
) {
    if ctx_ptr.is_null() { return; }
    let u = unsafe { from_cstr(uuid) };
    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
    if let Ok(guard) = ctx.lock() {
        guard.discovery.remove_known_device(u);
    }
}

/// 记录发现的设备（由 UDP 心跳接收时调用）
#[no_mangle]
pub extern "C" fn nrc_record_discovered_device(
    ctx_ptr: *mut c_void,
    uuid: *const c_char,
    name: *const c_char,
    ip: *const c_char,
    port: u16,
    battery: i32,
    device_type: *const c_char,
) {
    if ctx_ptr.is_null() { return; }
    let u = unsafe { from_cstr(uuid) };
    let n = unsafe { from_cstr(name) };
    let i = unsafe { from_cstr(ip) };
    let d = unsafe { from_cstr(device_type) };
    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
    if let Ok(guard) = ctx.lock() {
        guard.discovery.record_device(u, n, i, port, battery, d);
    }
}

/// 获取发现的设备列表（JSON 格式）
#[no_mangle]
pub extern "C" fn nrc_get_discovered_devices(ctx_ptr: *mut c_void) -> *mut c_char {
    if ctx_ptr.is_null() { return super::common::to_cstr("[]"); }
    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
    let devices = match ctx.lock() {
        Ok(guard) => guard.discovery.get_devices(),
        Err(_) => Vec::new(),
    };
    let json: Vec<serde_json::Value> = devices.into_iter().map(|d| {
        serde_json::json!({
            "uuid": d.uuid,
            "name": d.name,
            "ip": d.ip,
            "port": d.port,
            "battery": d.battery,
            "deviceType": d.device_type,
        })
    }).collect();
    super::common::to_cstr(&serde_json::to_string(&json).unwrap_or_else(|_| "[]".to_string()))
}

/// 启动已知设备自动扫描（网络变化后调用）
#[no_mangle]
pub extern "C" fn nrc_start_known_device_scanner(ctx_ptr: *mut c_void) {
    if ctx_ptr.is_null() { return; }
    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
    if let Ok(guard) = ctx.lock() {
        guard.discovery.start_known_device_scanner(ctx_ptr as usize);
    }
}

/// 停止已知设备自动扫描
#[no_mangle]
pub extern "C" fn nrc_stop_known_device_scanner(ctx_ptr: *mut c_void) {
    if ctx_ptr.is_null() { return; }
    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
    if let Ok(guard) = ctx.lock() {
        guard.discovery.stop_scanner();
    }
}
