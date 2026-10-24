//! 发送链路 C ABI 委托。

use std::os::raw::{c_char, c_void};

use super::common::{from_cstr, to_cstr};

/// 发送 HANDSHAKE；优先走已建立会话，失败则 one-shot 连接。
///
/// # Safety
/// 字符串指针须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_send_handshake(
    ctx_ptr: *mut c_void,
    uuid: *const c_char,
    _pub_key: *const c_char,
    local_ip: *const c_char,
    target_ip: *const c_char,
    battery: i32,
    device_type: *const c_char,
) -> i32 {
    if ctx_ptr.is_null() {
        return -1;
    }
    let uuid = unsafe { from_cstr(uuid) }.to_string();
    let local_ip = unsafe { from_cstr(local_ip) }.to_string();
    let target_ip = unsafe { from_cstr(target_ip) }.to_string();
    let device_type = unsafe { from_cstr(device_type) }.to_string();
    let ctx = unsafe { &*(ctx_ptr as *const crate::SafeContext) };
    crate::send::send_handshake(ctx, &uuid, &local_ip, &target_ip, battery, &device_type)
}

/// 发起配对（客户端侧）。
///
/// # Safety
/// 字符串指针须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_send_pairing_init(
    ctx_ptr: *mut c_void,
    local_uuid: *const c_char,
    target_uuid: *const c_char,
    expected_code: *const c_char,
    battery: i32,
    device_type: *const c_char,
) -> i32 {
    if ctx_ptr.is_null() {
        return -1;
    }
    let local_uuid = unsafe { from_cstr(local_uuid) }.to_string();
    let target_uuid = unsafe { from_cstr(target_uuid) }.to_string();
    let expected_code = unsafe { from_cstr(expected_code) }.to_string();
    let device_type = unsafe { from_cstr(device_type) }.to_string();
    let ctx = unsafe { &*(ctx_ptr as *const crate::SafeContext) };
    crate::send::send_pairing_init(
        ctx,
        &local_uuid,
        &target_uuid,
        &expected_code,
        battery,
        &device_type,
    )
}

/// 回应配对（服务端侧）。
///
/// # Safety
/// 字符串指针须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_send_pairing_resp(
    ctx_ptr: *mut c_void,
    uuid: *const c_char,
    lt_pub: *const c_char,
    pairing_code: *const c_char,
    ip: *const c_char,
    battery: i32,
    device_type: *const c_char,
) -> i32 {
    if ctx_ptr.is_null() {
        return -1;
    }
    let uuid = unsafe { from_cstr(uuid) }.to_string();
    let lt_pub = unsafe { from_cstr(lt_pub) }.to_string();
    let pairing_code = unsafe { from_cstr(pairing_code) }.to_string();
    let ip = unsafe { from_cstr(ip) }.to_string();
    let device_type = unsafe { from_cstr(device_type) }.to_string();
    let ctx = unsafe { &*(ctx_ptr as *const crate::SafeContext) };
    crate::send::send_pairing_resp(
        ctx,
        &uuid,
        &lt_pub,
        &pairing_code,
        &ip,
        battery,
        &device_type,
    )
}

/// 发送 ACCEPT。
///
/// # Safety
/// 字符串指针须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_send_accept(
    ctx_ptr: *mut c_void,
    target_uuid: *const c_char,
    lt_pub_key: *const c_char,
    ip: *const c_char,
    battery: i32,
    device_type: *const c_char,
) {
    if ctx_ptr.is_null() {
        return;
    }
    let target_uuid = unsafe { from_cstr(target_uuid) }.to_string();
    let lt_pub_key = unsafe { from_cstr(lt_pub_key) }.to_string();
    let ip = unsafe { from_cstr(ip) }.to_string();
    let device_type = unsafe { from_cstr(device_type) }.to_string();
    let ctx = unsafe { &*(ctx_ptr as *const crate::SafeContext) };
    crate::send::send_accept(ctx, &target_uuid, &lt_pub_key, &ip, battery, &device_type);
}

/// 发送 REJECT。
///
/// # Safety
/// `uuid` 须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_send_reject(ctx_ptr: *mut c_void, uuid: *const c_char) {
    if ctx_ptr.is_null() {
        return;
    }
    let uuid = unsafe { from_cstr(uuid) }.to_string();
    let ctx = unsafe { &*(ctx_ptr as *const crate::SafeContext) };
    crate::send::send_reject(ctx, &uuid);
}

/// 主动连接设备（带重试）。
///
/// # Safety
/// 字符串指针须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_connect_device(
    ctx_ptr: *mut c_void,
    uuid: *const c_char,
    target_ip: *const c_char,
    battery: i32,
    device_type: *const c_char,
) -> i32 {
    if ctx_ptr.is_null() {
        return -1;
    }
    let uuid = unsafe { from_cstr(uuid) }.to_string();
    let target_ip = unsafe { from_cstr(target_ip) }.to_string();
    let device_type = unsafe { from_cstr(device_type) }.to_string();
    let ctx = unsafe { &*(ctx_ptr as *const crate::SafeContext) };
    crate::send::connect_device(ctx, &uuid, &target_ip, battery, &device_type)
}

/// 周期性 UDP 广播发现控制：0=停止，1=启动，2=仅更新参数。
///
/// # Safety
/// 字符串指针须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_periodic_broadcast(
    ctx_ptr: *mut c_void,
    action: i32,
    uuid: *const c_char,
    name: *const c_char,
    battery: i32,
    device_type: *const c_char,
) -> i32 {
    if ctx_ptr.is_null() {
        return -1;
    }
    let uuid = Some(unsafe { from_cstr(uuid) });
    let name = Some(unsafe { from_cstr(name) });
    let device_type = Some(unsafe { from_cstr(device_type) });
    crate::send::periodic_broadcast(ctx_ptr as usize, action, uuid, name, battery, device_type)
}

/// 生成 6 位配对码并设置有效期（秒；0 表示 300s）。
#[no_mangle]
pub extern "C" fn nrc_generate_pairing_code(ctx_ptr: *mut c_void, ttl_secs: u32) -> *mut c_char {
    if ctx_ptr.is_null() {
        return to_cstr("");
    }
    let ctx = unsafe { &*(ctx_ptr as *const crate::SafeContext) };
    to_cstr(&crate::send::generate_pairing_code(ctx, ttl_secs))
}

/// 清除配对码。
#[no_mangle]
pub extern "C" fn nrc_clear_pairing_code(ctx_ptr: *mut c_void) {
    if ctx_ptr.is_null() {
        return;
    }
    let ctx = unsafe { &*(ctx_ptr as *const crate::SafeContext) };
    crate::send::clear_pairing_code(ctx);
}
