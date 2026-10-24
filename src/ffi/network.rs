//! 网络 C ABI 委托。

use std::os::raw::{c_char, c_void};

use super::common::from_cstr;

/// 移除设备会话。
///
/// # Safety
/// `uuid` 须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_remove_device_session(
    ctx_ptr: *mut c_void,
    uuid: *const c_char,
) -> i32 {
    if ctx_ptr.is_null() || uuid.is_null() {
        return -1;
    }
    let uuid = unsafe { from_cstr(uuid) }.to_string();
    let ctx = unsafe { &*(ctx_ptr as *const crate::SafeContext) };
    let Ok(mut guard) = ctx.lock() else {
        return -1;
    };
    crate::network::remove_session(&mut guard, &uuid)
}

/// 网络变化通知；`local_ip` 为空表示由 core 自行获取。
///
/// # Safety
/// `local_ip` 须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_on_network_changed(ctx_ptr: *mut c_void, local_ip: *const c_char) {
    if ctx_ptr.is_null() {
        return;
    }
    let ip = unsafe { from_cstr(local_ip) };
    let ip = if ip.is_empty() { None } else { Some(ip) };
    crate::network::notify_network_changed(ctx_ptr as usize, ip);
}

/// 统一启动入口：一次完成 TCP、发送队列、心跳调度、离线检测、
/// 已知设备扫描、重连状态机的启动。
///
/// 返回发送队列句柄（正整数，供入队使用），失败返回 0。
///
/// # Safety
/// 字符串指针须为空或有效 C 字符串；`_pubkey` 当前未使用（长期公钥由 core 持有）。
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "C" fn nrc_start_core(
    ctx_ptr: *mut c_void,
    uuid: *const c_char,
    name: *const c_char,
    battery: i32,
    device_type: *const c_char,
    tcp_port: u16,
    _pubkey: *const c_char,
    heartbeat_interval_ms: u64,
    offline_timeout_sec: i64,
    offline_check_interval_ms: u64,
    reconnect_interval_secs: u64,
    reconnect_max_retries: u32,
) -> u64 {
    if ctx_ptr.is_null() {
        return 0;
    }
    let uuid = unsafe { from_cstr(uuid) };
    let name = unsafe { from_cstr(name) };
    let device_type = unsafe { from_cstr(device_type) };
    crate::service::start_core(
        ctx_ptr as usize,
        crate::service::StartCoreParams {
            uuid,
            name,
            battery,
            device_type,
            tcp_port,
            heartbeat_interval_ms,
            offline_timeout_sec,
            offline_check_interval_ms,
            reconnect_interval_secs,
            reconnect_max_retries,
        },
    )
}
