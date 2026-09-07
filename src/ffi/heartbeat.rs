use std::os::raw::{c_char, c_void};

use base64::Engine;

use crate::heartbeat;
use crate::SafeContext;

use super::common::from_cstr;

/// 启动离线检测（内部实现，供 nrc_start_core 调用）
/// timeout_sec: 超时秒数（默认 30）
/// check_interval_ms: 检查间隔（默认 3000）
/// 注意参数顺序与平台端声明一致：timeout_sec 在前，check_interval_ms 在后
/// 返回句柄（正整数，0 表示失败）
pub(crate) unsafe fn start_offline_detector_impl(
    ctx_ptr: *mut c_void,
    timeout_sec: i64,
    check_interval_ms: u64,
) -> u64 {
    if ctx_ptr.is_null() {
        return 0;
    }
    match heartbeat::start_offline_detector(ctx_ptr as usize, check_interval_ms, timeout_sec) {
        Ok(running) => {
            let ctx = &mut *(ctx_ptr as *mut SafeContext);
            {
                let guard = ctx.get_mut().unwrap();
                let boxed = Box::new(running);
                let handle = super::handle::put(Box::into_raw(boxed) as *mut c_void);
                guard.offline_detector_handle = handle;
                handle
            }
        }
        Err(_) => 0,
    }
}

/// 启动统一心跳调度器（内部实现，供 nrc_start_core 调用）
/// 内部扫描 known_devices：为已配对设备自动启动/停止每设备心跳（AUTO 模式，复用现有回退逻辑）
/// 本机身份参数（uuid/name/battery/device_type）写入 broadcast_info
/// 返回句柄（正整数，0 表示失败）
pub(crate) unsafe fn start_heartbeat_scheduler_impl(
    ctx_ptr: *mut c_void,
    uuid: *const c_char,
    name: *const c_char,
    battery: i32,
    device_type: *const c_char,
    interval_ms: u64,
) -> u64 {
    if ctx_ptr.is_null() {
        return 0;
    }
    let u = from_cstr(uuid).to_string();
    let n = from_cstr(name).to_string();
    let d = from_cstr(device_type).to_string();
    let name_b64 = base64::engine::general_purpose::STANDARD.encode(n.as_bytes());

    let ctx = &mut *(ctx_ptr as *mut SafeContext);
    let guard = ctx.get_mut().unwrap();
    // 重复启动时先停止旧调度器
    if guard.heartbeat_scheduler != 0 {
        let boxed = Box::from_raw(super::handle::get(guard.heartbeat_scheduler)
            as *mut crate::heartbeat::HeartbeatScheduler);
        boxed.stop();
        guard.heartbeat_scheduler = 0;
        for (_, h) in guard.heartbeat_scheduler_handles.drain() {
            h.stop();
        }
    }
    let local_uuid = u.clone();
    guard.broadcast_info = Some(crate::BroadcastInfo {
        uuid: u,
        name_b64,
        battery,
        device_type: d,
    });
    // 同步广播信息到 TCP 层（供发现请求响应使用）
    crate::network::set_broadcast_info(guard.network.tcp.clone(), guard.broadcast_info.clone());
    // 同步本机 uuid 到持久化（读取接口前自动落盘）与 TCP 层状态（防御平台端 StartTcpServer 早于本函数调用的情况）
    // 仅库值缺失时采用平台传入值：uuid 已由 Rust 生成持有，空值或与库值冲突时均不得覆盖库值
    if !local_uuid.is_empty() {
        guard.ensure_persistence_loaded();
        if guard.local_uuid.is_empty() {
            guard.local_uuid = local_uuid.clone();
            guard.mark_persistence_dirty();
        }
        guard.persistence_activated = true;
    }
    crate::network::set_local_uuid(guard.network.tcp.clone(), &local_uuid);

    match crate::heartbeat::HeartbeatScheduler::start(ctx_ptr as usize, interval_ms) {
        Ok(scheduler) => {
            let boxed = Box::new(scheduler);
            let handle = super::handle::put(Box::into_raw(boxed) as *mut c_void);
            guard.heartbeat_scheduler = handle;
            handle
        }
        Err(e) => {
            log::error!("启动心跳调度器失败: {}", e);
            0
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
    // 本机名称/电量变化同步更新 mDNS 广告 TXT（广告同时承担发现与 UDP 信息源）
    guard.mdns.update_name_battery(&n, battery);
}
