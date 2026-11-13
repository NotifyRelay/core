//! FFI 集成测试的共享脚手架。
//!
//! 每个 `tests/*.rs` 都是独立 crate，共享代码只能以模块形式引入：
//! 各测试文件写 `mod common;` 后即可使用本模块导出的上下文、C 字符串与队列句柄。
//!
//! 临时库目录统一以 `nrctx_` 开头，进程退出时按前缀回收，避免在 TEMP 下堆积。
//! 读取 FFI 返回字符串的各文件语义不同（有的自行释放、有的交给调用方），故不在此收敛。

#![allow(dead_code)]

use std::ffi::CString;
use std::os::raw::{c_char, c_void};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use notify_relay_core::{ffi, CoreContext, SafeContext};

static CTX_SEQ: AtomicUsize = AtomicUsize::new(0);
/// 进程内已创建的临时库目录；进程退出时统一清理，避免在 TEMP 下堆积。
static CTX_DIRS: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

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

/// 建立一套临时库上下文。
///
/// 每次调用分配独立的临时目录，测试之间互不共享库文件。
pub fn create_ctx() -> SafeContext {
    create_ctx_with_prefix("nrctx")
}

/// 建立一套临时库上下文，临时目录按给定前缀命名。
pub fn create_ctx_with_prefix(prefix: &str) -> SafeContext {
    create_ctx_configured(prefix, |_| {})
}

/// 把上下文按 FFI 的裸指针口径交出。
pub fn ctx_ptr(ctx: &SafeContext) -> *mut c_void {
    ctx as *const SafeContext as *mut c_void
}

/// 把上下文按 FFI 的可写指针口径交出。
pub fn ctx_mut(ctx: &SafeContext) -> *mut SafeContext {
    ctx as *const SafeContext as *mut SafeContext
}

/// 建立 C 字符串；调用方负责用 [free_cstr] 释放。
pub fn cstr(s: &str) -> *const c_char {
    CString::new(s).unwrap().into_raw()
}

/// 释放 [cstr] 建立的 C 字符串。
///
/// # Safety
///
/// 指针必须来自 [cstr]，且只释放一次。
pub unsafe fn free_cstr(p: *const c_char) {
    if !p.is_null() {
        drop(CString::from_raw(p as *mut c_char));
    }
}

/// 登记一个发送队列句柄，返回其句柄号。
pub fn make_queue_handle() -> u64 {
    let queue = Box::new(notify_relay_core::sender_queue::SenderQueue::new());
    ffi::handle::put(Box::into_raw(queue) as *mut c_void)
}
/// 读取 FFI 返回的 C 字符串，不释放指针。
///
/// # Safety
///
/// 指针必须指向合法的、以 NUL 结尾的字符串。
pub unsafe fn read_cstr(p: *const c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    std::ffi::CStr::from_ptr(p)
        .to_str()
        .unwrap_or("")
        .to_string()
}

/// 释放核心库分配的 C 字符串。
///
/// # Safety
///
/// 指针必须由核心库分配，且只释放一次。
pub unsafe fn free_str(p: *mut c_char) {
    if !p.is_null() {
        drop(CString::from_raw(p));
    }
}

/// 状态推送入口的 FFI 签名。
type PushStateFn =
    unsafe extern "C" fn(*mut c_void, u64, *const c_char, *const c_char, i32, i32) -> i32;

/// 以给定 FFI 入口推送一次全量状态；返回核心库的返回值。
fn push_state(
    push: PushStateFn,
    ctx: &SafeContext,
    queue_handle: u64,
    uuid: &str,
    full_json: &str,
    is_end: i32,
    is_query: i32,
) -> i32 {
    let u = cstr(uuid);
    let f = cstr(full_json);
    let r = unsafe { push(ctx_ptr(ctx), queue_handle, u, f, is_end, is_query) };
    unsafe {
        free_cstr(u);
        free_cstr(f);
    }
    r
}

/// 推送一次超级岛全量状态；返回核心库的返回值。
pub fn push_superisland(
    ctx: &SafeContext,
    queue_handle: u64,
    uuid: &str,
    full_json: &str,
    is_end: i32,
    is_query: i32,
) -> i32 {
    push_state(
        ffi::state_merge::nrc_push_superisland_state,
        ctx,
        queue_handle,
        uuid,
        full_json,
        is_end,
        is_query,
    )
}

/// 登记一台已知设备。
pub fn add_known(ctx: &SafeContext, uuid: &str, ip: &str) {
    let u = cstr(uuid);
    let i = cstr(ip);
    unsafe {
        ffi::discovery::nrc_add_known_device(ctx_ptr(ctx), u, i);
        free_cstr(u);
        free_cstr(i);
    }
}

/// 移除一台已知设备。
pub fn remove_known(ctx: &SafeContext, uuid: &str) {
    let u = cstr(uuid);
    unsafe {
        ffi::discovery::nrc_remove_known_device(ctx_ptr(ctx), u);
        free_cstr(u);
    }
}

/// 读取设备列表；返回解析后的 JSON。
pub fn device_list(ctx: &SafeContext, authed_ms: i64, unauthed_ms: i64) -> serde_json::Value {
    let r = unsafe { ffi::device_state::nrc_get_device_list(ctx_ptr(ctx), authed_ms, unauthed_ms) };
    let s = unsafe { read_cstr(r) };
    unsafe { free_str(r) };
    serde_json::from_str(&s).unwrap_or_else(|_| panic!("设备列表应为合法 JSON: {}", s))
}
/// 登记进程退出清理回调；同一回调只登记一次。
///
/// 各测试的临时目录前缀不同，清理逻辑由调用方以 `extern "C" fn` 传入，
/// 去重按回调地址进行，调用方无需各自维护 `Once`。
pub fn register_exit_cleanup_once(cleanup: extern "C" fn()) {
    static REGISTERED: std::sync::OnceLock<Mutex<std::collections::HashSet<usize>>> =
        std::sync::OnceLock::new();
    let registered = REGISTERED.get_or_init(|| Mutex::new(std::collections::HashSet::new()));
    let mut guard = registered
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if guard.insert(cleanup as usize) {
        // SAFETY: 回调只做文件删除，不访问其他全局状态
        unsafe { libc::atexit(cleanup) };
    }
}
/// 建立一套临时库上下文，交给调用方在包装前配置核心实例。
///
/// 临时目录仍以 `nrctx_` 开头，退出时由本模块统一回收。
pub fn create_ctx_configured(
    prefix: &str,
    configure: impl FnOnce(&mut CoreContext),
) -> SafeContext {
    let n = CTX_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("{}_{}_{}", prefix, std::process::id(), n));
    if let Ok(mut dirs) = CTX_DIRS.lock() {
        dirs.push(dir.clone());
    }
    register_cleanup_once();
    let mut ctx = CoreContext::with_db_override(dir.join("rust_core.db"));
    configure(&mut ctx);
    Mutex::new(ctx)
}

/// 推送一次媒体全量状态；返回核心库的返回值。
pub fn push_media(
    ctx: &SafeContext,
    queue_handle: u64,
    uuid: &str,
    full_json: &str,
    is_end: i32,
    is_query: i32,
) -> i32 {
    push_state(
        ffi::state_merge::nrc_push_media_state,
        ctx,
        queue_handle,
        uuid,
        full_json,
        is_end,
        is_query,
    )
}
