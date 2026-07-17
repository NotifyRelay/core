use std::ffi::CString;
use std::os::raw::c_char;
use std::os::raw::c_void;
use std::sync::Arc;

use base64::Engine;

use crate::SafeContext;

use super::common::from_cstr;

/// 启动 TCP 服务器
#[no_mangle]
pub extern "C" fn nrc_start_tcp_server(ctx_ptr: *mut c_void, port: u16) -> i32 {
    if ctx_ptr.is_null() {
        log::error!("启动 TCP 服务器: 空指针");
        return -1;
    }

    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
    let guard = match ctx.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };

    // 获取回调
    let on_connected = guard.router.on_device_connected;
    let on_disconnected = guard.router.on_device_disconnected;
    let on_tcp_error = guard.router.on_tcp_error;
    let on_heartbeat_udp = guard.router.on_heartbeat_udp;
    let user_data = guard.router.user_data;

    // 获取网络状态
    let network_state = guard.network.tcp.clone();

    drop(guard);

    // 创建回调包装器
    let user_data_usize = user_data as usize;

    let on_connected_cb = if let Some(cb) = on_connected {
        Some(Arc::new(move |uuid: String, ip: String| {
            if let (Ok(uuid_c), Ok(ip_c)) = (CString::new(uuid.as_str()), CString::new(ip.as_str())) {
                let ud = user_data_usize as *mut c_void;
                cb(uuid_c.as_ptr(), ip_c.as_ptr(), ud);
            }
        }) as Arc<dyn Fn(String, String) + Send + Sync>)
    } else {
        None
    };

    let on_disconnected_cb = if let Some(cb) = on_disconnected {
        Some(Arc::new(move |uuid: String| {
            if let Ok(uuid_c) = CString::new(uuid.as_str()) {
                let ud = user_data_usize as *mut c_void;
                cb(uuid_c.as_ptr(), ud);
            }
        }) as Arc<dyn Fn(String) + Send + Sync>)
    } else {
        None
    };

    let on_message_cb = {
        let ctx_usize = ctx_ptr as usize;
        Some(Arc::new(move |_uuid: String, line: String| {
            let ctx_ptr = ctx_usize as *mut c_void;
            let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
            super::processing::process_line(ctx, &line);
        }) as Arc<dyn Fn(String, String) + Send + Sync>)
    };

    let on_error_cb = if let Some(cb) = on_tcp_error {
        Some(Arc::new(move |error: String| {
            if let Ok(err_c) = CString::new(error.as_str()) {
                let ud = user_data_usize as *mut c_void;
                cb(err_c.as_ptr(), ud);
            }
        }) as Arc<dyn Fn(String) + Send + Sync>)
    } else {
        None
    };

    match crate::network::start_tcp_server(
        network_state.clone(),
        port,
        on_connected_cb,
        on_disconnected_cb,
        on_message_cb,
        on_error_cb,
    ) {
        Ok(_) => {
            log::info!("TCP 服务器已启动，端口: {}", port);
        }
        Err(e) => {
            log::error!("启动 TCP 服务器失败: {}", e);
            return -1;
        }
    }

    // 同时启动 UDP 监听器（仅在未启动时）
    let udp_already_running = match network_state.lock() {
        Ok(state) => state.udp_handle.is_some(),
        Err(_) => false,
    };

    if !udp_already_running {
        let udp_port = 23334u16;
        let udp_user_data = user_data_usize;
        let udp_ctx = ctx_ptr as usize;
        let on_udp_cb = if let Some(cb) = on_heartbeat_udp {
            Some(Arc::new(move |uuid: String, name_b64: String, port: u16, battery: i32, device_type: String, src_ip: String| {
                let name = String::from_utf8(
                    base64::engine::general_purpose::STANDARD.decode(&name_b64).unwrap_or_default()
                ).unwrap_or(name_b64);
                // 记录源 IP 到内部映射
                if let Ok(guard) = unsafe { &*(udp_ctx as *mut crate::SafeContext) }.lock() {
                    if let Ok(mut ips) = guard.device_ips.lock() {
                        ips.insert(uuid.clone(), src_ip);
                    }
                }
                if let (Ok(uuid_c), Ok(name_c), Ok(dt_c)) = (
                    CString::new(uuid.as_str()),
                    CString::new(name.as_str()),
                    CString::new(device_type.as_str()),
                ) {
                    let ud = udp_user_data as *mut c_void;
                    cb(uuid_c.as_ptr(), name_c.as_ptr(), port, battery, dt_c.as_ptr(), ud);
                }
            }) as Arc<dyn Fn(String, String, u16, i32, String, String) + Send + Sync>)
        } else {
            None
        };
        let on_udp_err = if let Some(cb) = on_tcp_error {
            Some(Arc::new(move |error: String| {
                if let Ok(err_c) = CString::new(error.as_str()) {
                    let ud = user_data_usize as *mut c_void;
                    cb(err_c.as_ptr(), ud);
                }
            }) as Arc<dyn Fn(String) + Send + Sync>)
        } else {
            None
        };

        match crate::network::start_udp_listener(udp_port, on_udp_cb, on_udp_err) {
            Ok(running) => {
                if let Ok(mut state) = network_state.lock() {
                    state.udp_handle = Some(crate::network::UdpListenerHandle { running });
                }
                log::info!("UDP 监听器已启动，端口: {}", udp_port);
            }
            Err(e) => {
                log::warn!("启动 UDP 监听器失败: {}", e);
            }
        }
    } else {
        log::info!("UDP 监听器已在运行，跳过");
    }

    0
}

/// 停止 TCP 服务器
#[no_mangle]
pub extern "C" fn nrc_stop_tcp_server(ctx_ptr: *mut c_void) -> i32 {
    if ctx_ptr.is_null() {
        return -1;
    }

    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
    let guard = match ctx.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };

    let network_state = guard.network.tcp.clone();
    drop(guard);

    match crate::network::stop_tcp_server(network_state) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

/// 重启 UDP 监听器（网络变化后调用）
#[no_mangle]
pub extern "C" fn nrc_restart_udp_listener(ctx_ptr: *mut c_void) -> i32 {
    if ctx_ptr.is_null() { return -1; }
    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
    let guard = match ctx.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };
    let network_state = guard.network.tcp.clone();
    let on_heartbeat_udp = guard.router.on_heartbeat_udp;
    let on_tcp_error = guard.router.on_tcp_error;
    let user_data = guard.router.user_data;
    drop(guard);

    // 停止旧的 UDP 监听器
    if let Ok(mut state) = network_state.lock() {
        if let Some(handle) = state.udp_handle.take() {
            if let Ok(mut running) = handle.running.lock() {
                *running = false;
            }
        }
    }

    // 启动新的
    let udp_port = 23334u16;
    let udp_user_data = user_data as usize;
    let udp_ctx = ctx_ptr as usize;
    let on_udp_cb = if let Some(cb) = on_heartbeat_udp {
        Some(Arc::new(move |uuid: String, name_b64: String, port: u16, battery: i32, device_type: String, src_ip: String| {
            let name = String::from_utf8(
                base64::engine::general_purpose::STANDARD.decode(&name_b64).unwrap_or_default()
            ).unwrap_or(name_b64);
            if let Ok(guard) = unsafe { &*(udp_ctx as *mut crate::SafeContext) }.lock() {
                if let Ok(mut ips) = guard.device_ips.lock() {
                    ips.insert(uuid.clone(), src_ip);
                }
            }
            if let (Ok(uuid_c), Ok(name_c), Ok(dt_c)) = (
                CString::new(uuid.as_str()),
                CString::new(name.as_str()),
                CString::new(device_type.as_str()),
            ) {
                let ud = udp_user_data as *mut c_void;
                cb(uuid_c.as_ptr(), name_c.as_ptr(), port, battery, dt_c.as_ptr(), ud);
            }
        }) as Arc<dyn Fn(String, String, u16, i32, String, String) + Send + Sync>)
    } else {
        None
    };
    let on_udp_err = if let Some(cb) = on_tcp_error {
        Some(Arc::new(move |error: String| {
            if let Ok(err_c) = CString::new(error.as_str()) {
                let ud = udp_user_data as *mut c_void;
                cb(err_c.as_ptr(), ud);
            }
        }) as Arc<dyn Fn(String) + Send + Sync>)
    } else {
        None
    };

    match crate::network::start_udp_listener(udp_port, on_udp_cb, on_udp_err) {
        Ok(running) => {
            if let Ok(mut state) = network_state.lock() {
                state.udp_handle = Some(crate::network::UdpListenerHandle { running });
            }
            log::info!("UDP 监听器已重启，端口: {}", udp_port);
            0
        }
        Err(e) => {
            log::error!("重启 UDP 监听器失败: {}", e);
            -1
        }
    }
}

/// 发送消息到指定设备
#[no_mangle]
pub extern "C" fn nrc_send_to_device(ctx_ptr: *mut c_void, uuid: *const c_char, message: *const c_char) -> i32 {
    if ctx_ptr.is_null() || uuid.is_null() || message.is_null() {
        return -1;
    }

    let uuid_str = unsafe { from_cstr(uuid) };
    let message_str = unsafe { from_cstr(message) };

    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
    let guard = match ctx.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };

    let network_state = guard.network.tcp.clone();
    drop(guard);

    if crate::network::send_to_device(network_state, &uuid_str, &message_str) {
        0
    } else {
        -1
    }
}

/// 广播消息到所有连接的设备
#[no_mangle]
pub extern "C" fn nrc_broadcast_message(ctx_ptr: *mut c_void, message: *const c_char) -> i32 {
    if ctx_ptr.is_null() || message.is_null() {
        return -1;
    }

    let message_str = unsafe { from_cstr(message) };

    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
    let guard = match ctx.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };

    let network_state = guard.network.tcp.clone();
    drop(guard);

    crate::network::broadcast_message(network_state, &message_str);
    0
}

/// 获取在线设备数量
#[no_mangle]
pub extern "C" fn nrc_get_connected_device_count(ctx_ptr: *mut c_void) -> i32 {
    if ctx_ptr.is_null() {
        return 0;
    }

    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
    let guard = match ctx.lock() {
        Ok(g) => g,
        Err(_) => return 0,
    };

    let network_state = guard.network.tcp.clone();
    drop(guard);

    crate::network::get_connected_count(network_state)
}

/// 检查设备是否连接
#[no_mangle]
pub extern "C" fn nrc_is_device_connected(ctx_ptr: *mut c_void, uuid: *const c_char) -> i32 {
    if ctx_ptr.is_null() || uuid.is_null() {
        return 0;
    }

    let uuid_str = unsafe { from_cstr(uuid) };

    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
    let guard = match ctx.lock() {
        Ok(g) => g,
        Err(_) => return 0,
    };

    let network_state = guard.network.tcp.clone();
    drop(guard);

    if crate::network::is_device_connected(network_state, &uuid_str) {
        1
    } else {
        0
    }
}

/// 移除设备会话
#[no_mangle]
pub extern "C" fn nrc_remove_device_session(ctx_ptr: *mut c_void, uuid: *const c_char) -> i32 {
    if ctx_ptr.is_null() || uuid.is_null() {
        return -1;
    }

    let uuid_str = unsafe { from_cstr(uuid) };

    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
    let guard = match ctx.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };

    let network_state = guard.network.tcp.clone();
    drop(guard);

    crate::network::remove_device_session(network_state, &uuid_str);
    0
}

/// Oneshot TCP 发送+接收（新版：统一超时，返回状态码）
/// 返回 0=成功(响应已通过 process_line 处理), -1=失败
#[no_mangle]
pub extern "C" fn nrc_oneshot_send_receive(
    ctx_ptr: *mut c_void,
    ip: *const c_char,
    port: u16,
    payload: *const c_char,
    timeout_ms: u32,
) -> i32 {
    if ctx_ptr.is_null() || ip.is_null() || payload.is_null() { return -1; }
    let ip_str = unsafe { from_cstr(ip) };
    let payload_str = unsafe { from_cstr(payload) };
    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };

    match crate::network::oneshot_send_receive(payload_str, ip_str, port, timeout_ms) {
        Some(response) => {
            // 内部处理响应（触发回调）
            super::processing::process_line(ctx, &response);
            0
        }
        None => -1,
    }
}

/// Oneshot TCP 发送（不等待响应）
/// 返回 1=成功, 0=失败
#[no_mangle]
pub extern "C" fn nrc_oneshot_send_only(
    ctx_ptr: *mut c_void,
    ip: *const c_char,
    port: u16,
    payload: *const c_char,
    timeout_ms: u32,
) -> i32 {
    if ctx_ptr.is_null() || ip.is_null() || payload.is_null() { return 0; }
    let ip_str = unsafe { from_cstr(ip) };
    let payload_str = unsafe { from_cstr(payload) };
    if crate::network::oneshot_send_only(payload_str, ip_str, port, timeout_ms) { 1 } else { 0 }
}

/// 网络变化通知
/// 平台端在网络状态变化（WiFi 切换、网络恢复等）时调用此函数
/// local_ip: 新的本机 IP 地址（可为空，core 会自动获取）
#[no_mangle]
pub extern "C" fn nrc_on_network_changed(
    ctx_ptr: *mut c_void,
    local_ip: *const c_char,
) {
    if ctx_ptr.is_null() { return; }

    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };

    // 获取新 IP
    let new_ip = if !local_ip.is_null() {
        let ip = unsafe { from_cstr(local_ip) };
        if !ip.is_empty() { Some(ip.to_string()) } else { None }
    } else {
        None
    };

    log::info!("网络变化通知: ip={:?}", new_ip);

    // UDP 监听器使用 0.0.0.0:23334 监听所有接口，网络变化不影响其工作
    // 只有在监听器未运行时才启动，避免频繁重启导致端口占用竞争
    if let Ok(guard) = ctx.lock() {
        let udp_running = match guard.network.tcp.lock() {
            Ok(state) => state.udp_handle.is_some(),
            Err(_) => false,
        };

        if !udp_running {
            let on_heartbeat_udp = guard.router.on_heartbeat_udp;
            let on_tcp_error = guard.router.on_tcp_error;
            let user_data = guard.router.user_data;
            let network_state = guard.network.tcp.clone();
            drop(guard);

            let udp_port = 23334u16;
            let udp_ctx2 = ctx_ptr as usize;
            let udp_user_data = user_data as usize;
            let on_udp_cb = if let Some(cb) = on_heartbeat_udp {
                Some(Arc::new(move |uuid: String, name_b64: String, port: u16, battery: i32, device_type: String, src_ip: String| {
                    let name = String::from_utf8(
                        base64::engine::general_purpose::STANDARD.decode(&name_b64).unwrap_or_default()
                    ).unwrap_or(name_b64);
                    if let Ok(guard) = unsafe { &*(udp_ctx2 as *mut crate::SafeContext) }.lock() {
                        if let Ok(mut ips) = guard.device_ips.lock() {
                            ips.insert(uuid.clone(), src_ip);
                        }
                    }
                    if let (Ok(uuid_c), Ok(name_c), Ok(dt_c)) = (
                        std::ffi::CString::new(uuid.as_str()),
                        std::ffi::CString::new(name.as_str()),
                        std::ffi::CString::new(device_type.as_str()),
                    ) {
                        let ud = udp_user_data as *mut c_void;
                        cb(uuid_c.as_ptr(), name_c.as_ptr(), port, battery, dt_c.as_ptr(), ud);
                    }
                }) as Arc<dyn Fn(String, String, u16, i32, String, String) + Send + Sync>)
            } else {
                None
            };
            let udp_err_user_data = user_data as usize;
            let on_udp_err = if let Some(cb) = on_tcp_error {
                Some(Arc::new(move |error: String| {
                    if let Ok(err_c) = std::ffi::CString::new(error.as_str()) {
                        let ud = udp_err_user_data as *mut c_void;
                        cb(err_c.as_ptr(), ud);
                    }
                }) as Arc<dyn Fn(String) + Send + Sync>)
            } else {
                None
            };

            match crate::network::start_udp_listener(udp_port, on_udp_cb, on_udp_err) {
                Ok(running) => {
                    if let Ok(mut state) = network_state.lock() {
                        state.udp_handle = Some(crate::network::UdpListenerHandle { running });
                    }
                    log::info!("网络变化: UDP 监听器已启动");
                }
                Err(e) => {
                    log::warn!("网络变化: 启动 UDP 监听器失败: {}", e);
                }
            }
        } else {
            log::info!("网络变化: UDP 监听器已在运行，跳过");
        }
    }

    // 自动启动已知设备扫描（用于网络恢复后自动重连）
    if let Ok(guard) = ctx.lock() {
        guard.discovery.start_known_device_scanner(ctx_ptr as usize);
    }
}
