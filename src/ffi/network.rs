use std::ffi::CString;
use std::os::raw::c_char;
use std::os::raw::c_void;
use std::sync::Arc;

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
    let user_data = guard.router.user_data;

    // 获取网络状态
    let network_state = guard.network.tcp.clone();

    drop(guard);

    // 创建回调包装器
    // 将 *mut c_void 转换为 usize 以实现 Send + Sync
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

    let on_message_cb = None; // 消息处理由平台通过 processLine 完成

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
        network_state,
        port,
        on_connected_cb,
        on_disconnected_cb,
        on_message_cb,
        on_error_cb,
    ) {
        Ok(_) => {
            log::info!("TCP 服务器已启动，端口: {}", port);
            0
        }
        Err(e) => {
            log::error!("启动 TCP 服务器失败: {}", e);
            -1
        }
    }
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
