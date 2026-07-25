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

/// 记录发现的设备（由 UDP 心跳接收时调用）
#[no_mangle]
pub unsafe extern "C" fn nrc_record_discovered_device(
    ctx_ptr: *mut c_void,
    uuid: *const c_char,
    name: *const c_char,
    ip: *const c_char,
    port: u16,
    battery: i32,
    device_type: *const c_char,
) {
    let u = from_cstr(uuid).to_string();
    let n = from_cstr(name).to_string();
    let i = from_cstr(ip).to_string();
    let d = from_cstr(device_type).to_string();
    with_ctx(ctx_ptr, |ctx| {
        ctx.discovery.record_device(&u, &n, &i, port, battery, &d);
    });
}

/// 获取发现的设备列表（JSON 格式）
#[no_mangle]
pub unsafe extern "C" fn nrc_get_discovered_devices(ctx_ptr: *mut c_void) -> *mut c_char {
    let devices = with_ctx(ctx_ptr, |ctx| ctx.discovery.get_devices());
    let json: Vec<serde_json::Value> = devices
        .into_iter()
        .map(|d| {
            serde_json::json!({
                "uuid": d.uuid,
                "name": d.name,
                "ip": d.ip,
                "port": d.port,
                "battery": d.battery,
                "deviceType": d.device_type,
            })
        })
        .collect();
    super::common::to_cstr(&serde_json::to_string(&json).unwrap_or_else(|_| "[]".to_string()))
}

/// 启动已知设备自动扫描（网络变化后调用）
#[no_mangle]
pub unsafe extern "C" fn nrc_start_known_device_scanner(ctx_ptr: *mut c_void) {
    with_ctx(ctx_ptr, |ctx| {
        ctx.discovery
            .start_known_device_scanner(ctx_ptr as usize);
    });
}

/// 停止已知设备自动扫描
#[no_mangle]
pub unsafe extern "C" fn nrc_stop_known_device_scanner(ctx_ptr: *mut c_void) {
    with_ctx(ctx_ptr, |ctx| {
        ctx.discovery.stop_scanner();
    });
}
