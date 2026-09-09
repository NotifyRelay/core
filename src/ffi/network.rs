use std::ffi::CString;
use std::os::raw::c_char;
use std::os::raw::c_void;
use std::sync::Arc;
use std::time::Duration;

use crate::SafeContext;

use super::common::from_cstr;

/// 启动 TCP 服务器（内部实现，供 nrc_start_core 调用）
pub(crate) fn start_tcp_server_impl(ctx_ptr: *mut c_void, port: u16) -> i32 {
    if ctx_ptr.is_null() {
        log::error!("启动 TCP 服务器: 空指针");
        return -1;
    }

    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
    let guard = ctx.get_mut().unwrap();

    // 获取回调
    let on_connected = guard.router.on_device_connected;
    let on_disconnected = guard.router.on_device_disconnected;
    let on_tcp_error = guard.router.on_tcp_error;
    let user_data = guard.router.user_data;

    // 获取网络状态
    let network_state = guard.network.tcp.clone();
    // 本机 uuid（用于 TCP 层拒绝自我连接）
    let local_uuid = guard
        .broadcast_info
        .as_ref()
        .map(|b| b.uuid.clone())
        .unwrap_or_default();

    // 创建回调包装器
    let user_data_usize = user_data as usize;

    let connected_ctx = ctx_ptr as usize;
    let on_connected_cb = Some(Arc::new(move |uuid: String, ip: String| {
        // 始终记录 TCP 连接来源 IP 到内部映射（供 oneshot 发送回退）
        if let Ok(guard) = unsafe { &*(connected_ctx as *mut crate::SafeContext) }.lock() {
            if let Ok(mut ips) = guard.device_ips.lock() {
                ips.insert(uuid.clone(), ip.clone());
            }
            guard.registry.mark_connected(&uuid, &ip);
        }
        if let Some(cb) = on_connected {
            if let (Ok(uuid_c), Ok(ip_c)) = (CString::new(uuid.as_str()), CString::new(ip.as_str()))
            {
                let ud = user_data_usize as *mut c_void;
                cb(uuid_c.as_ptr(), ip_c.as_ptr(), ud);
            }
        }
    }) as Arc<dyn Fn(String, String) + Send + Sync>);

    let on_disconnected_cb = {
        let ctx_usize = ctx_ptr as usize;
        Some(Arc::new(move |uuid: String| {
            // TCP 断开：登记断开状态，并清理该连接遗留的未完成配对会话。
            if let Ok(mut guard) = unsafe { &*(ctx_usize as *const crate::SafeContext) }.lock() {
                guard.registry.mark_disconnected(&uuid);
                guard.pairing_sessions.remove(&uuid);
            }
            if let Some(cb) = on_disconnected {
                if let Ok(uuid_c) = CString::new(uuid.as_str()) {
                    let ud = user_data_usize as *mut c_void;
                    cb(uuid_c.as_ptr(), ud);
                }
            }
        }) as Arc<dyn Fn(String) + Send + Sync>)
    };

    let on_message_cb = {
        let ctx_usize = ctx_ptr as usize;
        Some(
            Arc::new(move |uuid: String, msg_type: u8, payload: Vec<u8>| {
                let ctx_ptr = ctx_usize as *mut c_void;
                let ctx = unsafe { &*(ctx_ptr as *const SafeContext) };
                // 传入会话 uuid：帧内声明的发送方必须与之相同，否则丢弃
                super::processing::process_frame(ctx, Some(&uuid), msg_type, &payload);
            }) as Arc<dyn Fn(String, u8, Vec<u8>) + Send + Sync>,
        )
    };

    let on_error_cb = on_tcp_error.map(|cb| {
        Arc::new(move |error: String| {
            if let Ok(err_c) = CString::new(error.as_str()) {
                let ud = user_data_usize as *mut c_void;
                cb(err_c.as_ptr(), ud);
            }
        }) as Arc<dyn Fn(String) + Send + Sync>
    });

    // TCP 绑定失败时自动重试（覆盖旧进程退出导致端口延迟释放等场景），间隔递增
    let mut attempts = 0;
    let tcp_result = loop {
        match crate::network::start_tcp_server(
            network_state.clone(),
            port,
            local_uuid.clone(),
            on_connected_cb.clone(),
            on_disconnected_cb.clone(),
            on_message_cb.clone(),
            on_error_cb.clone(),
        ) {
            Ok(_) => break Ok(()),
            Err(e) => {
                attempts += 1;
                if attempts >= 5 {
                    break Err(e);
                }
                log::warn!("启动 TCP 服务器失败（第 {}/5 次）: {}", attempts, e);
                std::thread::sleep(Duration::from_secs(attempts as u64));
            }
        }
    };
    match tcp_result {
        Ok(_) => {
            log::info!("TCP 服务器已启动，端口: {}", port);
        }
        Err(e) => {
            log::error!("启动 TCP 服务器失败（已重试 5 次）: {}", e);
            return -1;
        }
    }

    0
}

/// 移除设备会话
#[no_mangle]
pub unsafe extern "C" fn nrc_remove_device_session(
    ctx_ptr: *mut c_void,
    uuid: *const c_char,
) -> i32 {
    if ctx_ptr.is_null() || uuid.is_null() {
        return -1;
    }

    let uuid_str = unsafe { from_cstr(uuid) };

    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
    let guard = ctx.get_mut().unwrap();

    let network_state = guard.network.tcp.clone();

    crate::network::remove_device_session(network_state, uuid_str);
    0
}

/// 网络变化通知
/// 平台端在网络状态变化（WiFi 切换、网络恢复等）时调用此函数
/// local_ip: 新的本机 IP 地址（可为空，core 会自动获取）
#[no_mangle]
pub unsafe extern "C" fn nrc_on_network_changed(ctx_ptr: *mut c_void, local_ip: *const c_char) {
    if ctx_ptr.is_null() {
        return;
    }

    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };

    // 获取新 IP
    let new_ip = if !local_ip.is_null() {
        let ip = unsafe { from_cstr(local_ip) };
        if !ip.is_empty() {
            Some(ip.to_string())
        } else {
            None
        }
    } else {
        None
    };

    log::info!("网络变化通知: ip={:?}", new_ip);

    // 自动启动已知设备扫描（用于网络恢复后自动重连）
    ctx.get_mut()
        .unwrap()
        .discovery
        .start_known_device_scanner(ctx_ptr as usize);
}

/// 高层统一启动接口：一次完成 TCP、发送队列、心跳调度、离线检测、
/// 已知设备扫描、重连状态机的启动。
/// 返回发送队列句柄（正整数，供入队使用），失败返回 0。
/// 注意：本机身份（uuid/name/battery/device_type）写入 broadcast_info；
/// 设备发现由 nrc_periodic_broadcast 启动的 UDP 广播负责。
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

    log::info!(
        "nrc_start_core 启动 (git: {}, version: {})",
        env!("NOTIFY_RELAY_GIT_HASH"),
        env!("CARGO_PKG_VERSION")
    );

    // 先启动 TCP/UDP（需在广播信息就绪前设置本机 uuid 用于自我连接拒绝）
    if start_tcp_server_impl(ctx_ptr, tcp_port) != 0 {
        // TCP 绑定失败不阻塞其他组件：发送队列/心跳照常启动，
        // 出站发送由发送队列 worker 独立负责，网络恢复后重连状态机会补建连接
        log::warn!("nrc_start_core: TCP 服务器启动失败，继续启动其他组件");
    }

    // 心跳调度（写入 broadcast_info + 启动调度线程）
    let hb = super::heartbeat::start_heartbeat_scheduler_impl(
        ctx_ptr,
        uuid,
        name,
        battery,
        device_type,
        heartbeat_interval_ms,
    );
    if hb == 0 {
        log::warn!("nrc_start_core: 心跳调度器启动失败");
    }

    // 离线检测
    super::heartbeat::start_offline_detector_impl(
        ctx_ptr,
        offline_timeout_sec,
        offline_check_interval_ms,
    );

    // 发送队列
    let queue_handle = super::sender_queue::create_sender_queue_impl(ctx_ptr);
    if queue_handle == 0 {
        return 0;
    }
    super::sender_queue::start_sender_queue_impl(ctx_ptr, queue_handle);

    // 已知设备扫描
    super::discovery::start_known_device_scanner_impl(ctx_ptr);

    // 重连状态机
    let reconnect_state = super::reconnect::create_reconnect_state_impl(ctx_ptr);
    if reconnect_state == 0 {
        log::warn!("nrc_start_core: 重连状态机创建失败");
    } else {
        super::reconnect::reconnect_start_impl(
            ctx_ptr,
            reconnect_state,
            reconnect_interval_secs,
            reconnect_max_retries,
        );
    }

    queue_handle
}
