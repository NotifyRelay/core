//! FFI 心跳接口语义测试（nrc_set_heartbeat_tcp_backup / nrc_update_heartbeat_scheduler_params）
//! 目的：保证 PC 与 Android 两个平台端共享的心跳配置接口契约不变

use std::ffi::CString;
use std::os::raw::{c_char, c_void};
use std::sync::Mutex;

use notify_relay_core::{ffi, CoreContext, SafeContext};

static CTX_SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
fn create_ctx() -> SafeContext {
    let n = CTX_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let p = std::env::temp_dir()
        .join(format!("nrctx_{}_{}", std::process::id(), n))
        .join("rust_core.db");
    Mutex::new(CoreContext::with_db_override(p))
}

fn ctx_ptr(ctx: &SafeContext) -> *mut c_void {
    ctx as *const SafeContext as *mut c_void
}

fn cstr(s: &str) -> *const c_char {
    CString::new(s).unwrap().into_raw()
}

unsafe fn free_cstr(p: *const c_char) {
    if !p.is_null() {
        drop(CString::from_raw(p as *mut c_char));
    }
}

#[test]
fn test_set_heartbeat_tcp_backup_toggle() {
    let ctx = create_ctx();
    let ptr = ctx_ptr(&ctx);
    // 默认广播主用；开启 TCP 备用 → 0
    assert_eq!(
        unsafe { ffi::heartbeat::nrc_set_heartbeat_tcp_backup(ptr, 1) },
        0
    );
    // 重复开启（幂等）→ 0
    assert_eq!(
        unsafe { ffi::heartbeat::nrc_set_heartbeat_tcp_backup(ptr, 1) },
        0
    );
    // 关闭 → 0
    assert_eq!(
        unsafe { ffi::heartbeat::nrc_set_heartbeat_tcp_backup(ptr, 0) },
        0
    );
    // 任意非 0 视为开启 → 0
    assert_eq!(
        unsafe { ffi::heartbeat::nrc_set_heartbeat_tcp_backup(ptr, 2) },
        0
    );
}

#[test]
fn test_set_heartbeat_tcp_backup_null_ctx_fails() {
    assert_eq!(
        unsafe { ffi::heartbeat::nrc_set_heartbeat_tcp_backup(std::ptr::null_mut(), 1) },
        -1
    );
}

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
