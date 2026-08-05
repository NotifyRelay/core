use std::os::raw::{c_char, c_void};

use base64::Engine;

use crate::heartbeat::{self, HeartbeatHandle};
use crate::SafeContext;

use super::common::from_cstr;

/// 启动心跳发送器
/// mode: 0=UDP, 1=TCP, 2=Auto
#[no_mangle]
pub unsafe extern "C" fn nrc_start_heartbeat_sender(
    ctx_ptr: *mut c_void,
    uuid: *const c_char,
    name: *const c_char,
    battery: i32,
    device_type: *const c_char,
    ip: *const c_char,
    interval_ms: u64,
    mode: i32,
) -> i64 {
    if ctx_ptr.is_null() {
        return -1;
    }
    let u = from_cstr(uuid);
    let n = from_cstr(name);
    let d = from_cstr(device_type);
    let ip_str = from_cstr(ip);

    match HeartbeatHandle::start(
        ctx_ptr as usize,
        u,
        n,
        battery,
        d,
        ip_str,
        interval_ms,
        mode,
    ) {
        Ok(handle) => {
            let ctx = &mut *(ctx_ptr as *mut SafeContext);
            {
                let guard = ctx.get_mut().unwrap();
                let name_b64 = base64::engine::general_purpose::STANDARD.encode(n.as_bytes());
                guard.broadcast_info = Some(crate::BroadcastInfo {
                    uuid: u.to_string(),
                    name_b64,
                    battery,
                    device_type: d.to_string(),
                });
                let handle_box = Box::new(handle);
                let ptr = Box::into_raw(handle_box) as i64;
                guard.heartbeat_handle = ptr;
                ptr
            }
        }
        Err(_) => -1,
    }
}

/// 更新心跳发送器参数
#[no_mangle]
pub unsafe extern "C" fn nrc_update_heartbeat_params(
    ctx_ptr: *mut c_void,
    handle_ptr: i64,
    uuid: *const c_char,
    name: *const c_char,
    battery: i32,
    device_type: *const c_char,
) {
    if ctx_ptr.is_null() || handle_ptr == 0 {
        return;
    }
    let handle = &*(handle_ptr as *const HeartbeatHandle);
    let u = from_cstr(uuid);
    let n = from_cstr(name);
    let d = from_cstr(device_type);
    handle.update(u, n, battery, d);
}

/// 停止心跳发送器
#[no_mangle]
pub unsafe extern "C" fn nrc_stop_heartbeat_sender(ctx_ptr: *mut c_void, handle_ptr: i64) {
    if ctx_ptr.is_null() || handle_ptr == 0 {
        return;
    }
    let handle = Box::from_raw(handle_ptr as *mut HeartbeatHandle);
    handle.stop();
    let ctx = &mut *(ctx_ptr as *mut SafeContext);
    {
        let guard = ctx.get_mut().unwrap();
        guard.heartbeat_handle = 0;
    }
}

/// 启动离线检测
/// timeout_sec: 超时秒数（默认 30）
/// check_interval_ms: 检查间隔（默认 3000）
/// 注意参数顺序与平台端声明一致：timeout_sec 在前，check_interval_ms 在后
#[no_mangle]
pub unsafe extern "C" fn nrc_start_offline_detector(
    ctx_ptr: *mut c_void,
    timeout_sec: i64,
    check_interval_ms: u64,
) -> i64 {
    if ctx_ptr.is_null() {
        return -1;
    }
    match heartbeat::start_offline_detector(ctx_ptr as usize, check_interval_ms, timeout_sec) {
        Ok(running) => {
            let ctx = &mut *(ctx_ptr as *mut SafeContext);
            {
                let guard = ctx.get_mut().unwrap();
                let boxed = Box::new(running);
                let ptr = Box::into_raw(boxed) as i64;
                guard.offline_detector_handle = ptr;
                ptr
            }
        }
        Err(_) => -1,
    }
}

/// 停止离线检测
#[no_mangle]
pub unsafe extern "C" fn nrc_stop_offline_detector(ctx_ptr: *mut c_void) {
    if ctx_ptr.is_null() {
        return;
    }
    let ctx = &mut *(ctx_ptr as *mut SafeContext);
    {
        let guard = ctx.get_mut().unwrap();
        if guard.offline_detector_handle != 0 {
            let boxed = Box::from_raw(
                guard.offline_detector_handle as *mut std::sync::Arc<std::sync::atomic::AtomicBool>,
            );
            boxed.store(false, std::sync::atomic::Ordering::Relaxed);
            guard.offline_detector_handle = 0;
        }
    }
}

/// 启动统一心跳调度器
/// 内部扫描 known_devices：为已配对设备自动启动/停止每设备心跳（AUTO 模式，复用现有回退逻辑）
/// 本机身份参数（uuid/name/battery/device_type）写入 broadcast_info
#[no_mangle]
pub unsafe extern "C" fn nrc_start_heartbeat_scheduler(
    ctx_ptr: *mut c_void,
    uuid: *const c_char,
    name: *const c_char,
    battery: i32,
    device_type: *const c_char,
    interval_ms: u64,
) -> i64 {
    if ctx_ptr.is_null() {
        return -1;
    }
    let u = from_cstr(uuid).to_string();
    let n = from_cstr(name).to_string();
    let d = from_cstr(device_type).to_string();
    let name_b64 = base64::engine::general_purpose::STANDARD.encode(n.as_bytes());

    let ctx = &mut *(ctx_ptr as *mut SafeContext);
    let guard = ctx.get_mut().unwrap();
    // 重复启动时先停止旧调度器
    if guard.heartbeat_scheduler != 0 {
        let boxed =
            Box::from_raw(guard.heartbeat_scheduler as *mut crate::heartbeat::HeartbeatScheduler);
        boxed.stop();
        guard.heartbeat_scheduler = 0;
        for (_, h) in guard.heartbeat_scheduler_handles.drain() {
            h.stop();
        }
    }
    guard.broadcast_info = Some(crate::BroadcastInfo {
        uuid: u,
        name_b64,
        battery,
        device_type: d,
    });

    match crate::heartbeat::HeartbeatScheduler::start(ctx_ptr as usize, interval_ms) {
        Ok(scheduler) => {
            let boxed = Box::new(scheduler);
            let ptr = Box::into_raw(boxed) as i64;
            guard.heartbeat_scheduler = ptr;
            ptr
        }
        Err(e) => {
            log::error!("启动心跳调度器失败: {}", e);
            -1
        }
    }
}

/// 更新心跳调度器本机参数（更新 broadcast_info，全部 handle 由调度线程同步）
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
    let n = from_cstr(name).to_string();
    let d = from_cstr(device_type).to_string();
    let ctx = &mut *(ctx_ptr as *mut SafeContext);
    let guard = ctx.get_mut().unwrap();
    if let Some(ref mut b) = guard.broadcast_info {
        if !n.is_empty() {
            b.name_b64 = base64::engine::general_purpose::STANDARD.encode(n.as_bytes());
        }
        if battery.abs() <= 100 {
            b.battery = battery;
        }
        if !d.is_empty() {
            b.device_type = d;
        }
    }
    // 本机电量变化同步更新 mDNS 广告 TXT（广告同时承担发现与 UDP 信息源）
    guard.mdns.update_battery(battery);
}

/// 停止统一心跳调度器（停止线程并停止全部调度器维护的心跳）
#[no_mangle]
pub unsafe extern "C" fn nrc_stop_heartbeat_scheduler(ctx_ptr: *mut c_void) {
    if ctx_ptr.is_null() {
        return;
    }
    let ctx = &mut *(ctx_ptr as *mut SafeContext);
    let guard = ctx.get_mut().unwrap();
    if guard.heartbeat_scheduler != 0 {
        let boxed =
            Box::from_raw(guard.heartbeat_scheduler as *mut crate::heartbeat::HeartbeatScheduler);
        boxed.stop();
        guard.heartbeat_scheduler = 0;
    }
    for (_, h) in guard.heartbeat_scheduler_handles.drain() {
        h.stop();
    }
}
