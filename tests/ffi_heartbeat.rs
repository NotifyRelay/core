//! FFI 心跳接口语义测试（nrc_update_heartbeat_scheduler_params）
//! 目的：保证 PC 与 Android 两个平台端共享的心跳配置接口契约不变

use std::ffi::CString;
use std::os::raw::{c_char, c_void};
use std::sync::Mutex;

use notify_relay_core::{ffi, CoreContext, SafeContext};

static CTX_SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
/// 进程内已创建的临时库目录；进程退出时统一清理，避免在 TEMP 下堆积。
static CTX_DIRS: Mutex<Vec<std::path::PathBuf>> = Mutex::new(Vec::new());

/// 清理本进程及历史遗留的全部测试临时库目录。
fn prune_temp_dirs() {
    if let Ok(mut dirs) = CTX_DIRS.lock() {
        for dir in dirs.drain(..) {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
    let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.starts_with("nrctx_") {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// 注册进程退出清理（只注册一次）。
fn register_cleanup_once() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        extern "C" fn on_exit() {
            prune_temp_dirs();
        }
        // SAFETY: 回调只做文件删除，不访问其他全局状态
        unsafe { libc::atexit(on_exit) };
    });
}

fn create_ctx() -> SafeContext {
    let n = CTX_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("nrctx_{}_{}", std::process::id(), n));
    if let Ok(mut dirs) = CTX_DIRS.lock() {
        dirs.push(dir.clone());
    }
    register_cleanup_once();
    Mutex::new(CoreContext::with_db_override(dir.join("rust_core.db")))
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
