//! FFI 心跳接口语义测试（nrc_update_heartbeat_scheduler_params）
//! 目的：保证 PC 与 Android 两个平台端共享的心跳配置接口契约不变

use notify_relay_core::ffi;

mod common;
use common::*;

#[test]
fn test_update_heartbeat_params_without_scheduler_is_safe() {
    let ctx = create_ctx();
    let ptr = ctx_ptr(&ctx);
    // 未启动调度器（broadcast_info 为 None）时调用不崩溃
    let name = cstr("新设备名");
    let d = cstr("phone");
    unsafe {
        ffi::heartbeat::nrc_update_heartbeat_scheduler_params(ptr, name, 85, d);
        free_cstr(name);
        free_cstr(d);
    }
    // null ctx 安全
    unsafe {
        ffi::heartbeat::nrc_update_heartbeat_scheduler_params(
            std::ptr::null_mut(),
            std::ptr::null(),
            85,
            std::ptr::null(),
        );
    }
}
