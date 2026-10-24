//! 生命周期与统一启动编排。
//!
//! 由上下文创建（初始化日志桥、启动心跳线程）与统一启动入口（TCP、心跳调度、
//! 离线检测、发送队列、已知设备扫描、重连状态机）组成。

use std::os::raw::c_void;
use std::sync::Mutex;

use crate::CoreContext;

/// 创建核心上下文并启动后台心跳线程。
///
/// 返回上下文指针（进程生命周期内不释放）。重复调用会产生独立上下文。
pub fn create_context() -> *mut c_void {
    crate::log_bridge::init();
    log::info!(
        "NotifyRelay Core v{} (git: {})",
        env!("CARGO_PKG_VERSION"),
        env!("NOTIFY_RELAY_GIT_HASH")
    );
    let ctx = Box::new(Mutex::new(CoreContext::new()));
    let ptr = Box::into_raw(ctx) as *mut c_void;
    crate::state_merge::start_heartbeat_thread(ptr as usize);
    ptr
}

/// 统一启动参数。
pub struct StartCoreParams<'a> {
    pub uuid: &'a str,
    pub name: &'a str,
    pub battery: i32,
    pub device_type: &'a str,
    pub tcp_port: u16,
    pub heartbeat_interval_ms: u64,
    pub offline_timeout_sec: i64,
    pub offline_check_interval_ms: u64,
    pub reconnect_interval_secs: u64,
    pub reconnect_max_retries: u32,
}

/// 一次完成 TCP、心跳调度、离线检测、发送队列、已知设备扫描与重连状态机的启动。
///
/// 返回发送队列句柄（正整数，供入队使用），失败返回 0。
/// 本机身份（uuid/name/battery/device_type）写入 `broadcast_info`；
/// 设备发现由 `send::periodic_broadcast` 启动的 UDP 广播负责。
pub fn start_core(ctx_ptr: usize, params: StartCoreParams<'_>) -> u64 {
    if ctx_ptr == 0 {
        return 0;
    }

    log::info!(
        "start_core 启动 (git: {}, version: {})",
        env!("NOTIFY_RELAY_GIT_HASH"),
        env!("CARGO_PKG_VERSION")
    );

    // 先启动 TCP/UDP（需在广播信息就绪前设置本机 uuid 用于自我连接拒绝）
    if crate::network::start_tcp_server_for(ctx_ptr, params.tcp_port) != 0 {
        // TCP 绑定失败不阻塞其他组件：发送队列/心跳照常启动，
        // 出站发送由发送队列 worker 独立负责，网络恢复后重连状态机会补建连接
        log::warn!("start_core: TCP 服务器启动失败，继续启动其他组件");
    }

    // 心跳调度（写入 broadcast_info + 启动调度线程）
    let hb = crate::heartbeat::start_scheduler_for(
        ctx_ptr,
        params.uuid,
        params.name,
        params.battery,
        params.device_type,
        params.heartbeat_interval_ms,
    );
    if hb == 0 {
        log::warn!("start_core: 心跳调度器启动失败");
    }

    // 离线检测
    crate::heartbeat::start_offline_detector_for(
        ctx_ptr,
        params.offline_timeout_sec,
        params.offline_check_interval_ms,
    );

    // 发送队列
    let queue_handle = crate::sender_queue::create_with_ctx(ctx_ptr);
    if queue_handle == 0 {
        log::error!("start_core: 发送队列创建失败");
        return 0;
    }
    crate::sender_queue::start_worker_for(ctx_ptr, queue_handle);

    // 已知设备扫描
    crate::discovery::start_known_device_scanner_for(ctx_ptr);

    // 重连状态机
    let reconnect_state = crate::reconnect::create_state_for(ctx_ptr);
    crate::reconnect::start_for(
        ctx_ptr,
        reconnect_state,
        params.reconnect_interval_secs,
        params.reconnect_max_retries,
    );

    queue_handle
}
