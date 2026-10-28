//! FFI 剪贴板接口语义测试（nrc_clipboard_on_changed / nrc_clipboard_on_received）
//! 目的：保证 PC 与 Android 两个平台端共享的剪贴板接口契约不变

use std::ffi::{CStr, CString};
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

unsafe fn read_cstr(p: *const c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    CStr::from_ptr(p).to_str().unwrap_or("").to_string()
}

unsafe fn free_str(p: *mut c_char) {
    if !p.is_null() {
        drop(CString::from_raw(p));
    }
}

unsafe fn free_cstr(p: *const c_char) {
    if !p.is_null() {
        drop(CString::from_raw(p as *mut c_char));
    }
}

fn on_changed(
    ctx: &SafeContext,
    queue_handle: u64,
    targets_json: &str,
    mime: &str,
    content: &str,
    now_ms: i64,
    force: i32,
) -> serde_json::Value {
    let t = cstr(targets_json);
    let m = cstr(mime);
    let c = cstr(content);
    let r = unsafe {
        ffi::clipboard::nrc_clipboard_on_changed(ctx_ptr(ctx), queue_handle, t, m, c, now_ms, force)
    };
    let s = unsafe { read_cstr(r) };
    unsafe {
        free_str(r);
        free_cstr(t);
        free_cstr(m);
        free_cstr(c);
    }
    serde_json::from_str(&s).unwrap_or_else(|_| panic!("应返回合法 JSON: {}", s))
}

fn on_received(ctx: &SafeContext, payload_json: &str, now_ms: i64) -> serde_json::Value {
    let p = cstr(payload_json);
    let r = unsafe { ffi::clipboard::nrc_clipboard_on_received(ctx_ptr(ctx), p, now_ms) };
    let s = unsafe { read_cstr(r) };
    unsafe {
        free_str(r);
        free_cstr(p);
    }
    serde_json::from_str(&s).unwrap_or_else(|_| panic!("应返回合法 JSON: {}", s))
}

fn make_queue_handle() -> u64 {
    let queue = Box::new(notify_relay_core::sender_queue::SenderQueue::new());
    ffi::handle::put(Box::into_raw(queue) as *mut c_void)
}

#[test]
fn test_on_changed_invalid_ctx_skipped() {
    let result = on_changed(
        &create_ctx(),
        0,
        r#"["dev-1"]"#,
        "text/plain",
        "hello",
        1000,
        0,
    );
    assert_eq!(result["action"], "skipped");
    assert!(result["reason"].as_str().unwrap().contains("queue"));
}

#[test]
fn test_on_changed_no_targets_skipped() {
    let ctx = create_ctx();
    let queue_handle = make_queue_handle();
    let result = on_changed(&ctx, queue_handle, "[]", "text/plain", "hello", 1000, 0);
    assert_eq!(result["action"], "skipped");
    assert!(result["reason"].as_str().unwrap().contains("no targets"));
}

#[test]
fn test_on_changed_sends_and_skips_unchanged() {
    let ctx = create_ctx();
    let queue_handle = make_queue_handle();
    // 首次发送
    let r1 = on_changed(
        &ctx,
        queue_handle,
        r#"["dev-1"]"#,
        "text/plain",
        "hello",
        1000,
        0,
    );
    assert_eq!(r1["action"], "sent");
    // 内容未变且非 force → skipped
    let r2 = on_changed(
        &ctx,
        queue_handle,
        r#"["dev-1"]"#,
        "text/plain",
        "hello",
        3000,
        0,
    );
    assert_eq!(r2["action"], "skipped");
    assert!(r2["reason"].as_str().unwrap().contains("未改"));
    // force=1 允许重发（now 已越过频率窗口）
    let r3 = on_changed(
        &ctx,
        queue_handle,
        r#"["dev-1"]"#,
        "text/plain",
        "hello",
        5000,
        1,
    );
    assert_eq!(r3["action"], "sent");
    // 新内容 → sent
    let r4 = on_changed(
        &ctx,
        queue_handle,
        r#"["dev-1"]"#,
        "text/plain",
        "hello-2",
        7000,
        0,
    );
    assert_eq!(r4["action"], "sent");
}

#[test]
fn test_on_changed_frequency_limit() {
    let ctx = create_ctx();
    let queue_handle = make_queue_handle();
    let r1 = on_changed(
        &ctx,
        queue_handle,
        r#"["dev-1"]"#,
        "text/plain",
        "c1",
        1000,
        0,
    );
    assert_eq!(r1["action"], "sent");
    // 200ms 内再次发送（内容不同）→ 频率限制 skipped
    let r2 = on_changed(
        &ctx,
        queue_handle,
        r#"["dev-1"]"#,
        "text/plain",
        "c2",
        1200,
        0,
    );
    assert_eq!(r2["action"], "skipped");
    assert!(r2["reason"].as_str().unwrap().contains("频繁"));
}

#[test]
fn test_on_changed_anti_loop() {
    let ctx = create_ctx();
    let queue_handle = make_queue_handle();
    // 收到远程内容（登记防循环窗）
    let recv = on_received(
        &ctx,
        r#"{"clipboardType":"text/plain","content":"loop-content"}"#,
        1000,
    );
    assert_eq!(recv["type"], "text");
    // 窗口内同内容本地上报 → 防循环跳过
    let r = on_changed(
        &ctx,
        queue_handle,
        r#"["dev-1"]"#,
        "text/plain",
        "loop-content",
        1500,
        0,
    );
    assert_eq!(r["action"], "skipped");
    assert!(r["reason"].as_str().unwrap().contains("远程"));
}

#[test]
fn test_on_changed_large_image_returns_file_transfer() {
    let ctx = create_ctx();
    let queue_handle = make_queue_handle();
    // 超过 2MB 阈值的 base64 图片（3MB 的 'A'）
    let big = "A".repeat(3 * 1024 * 1024);
    let r = on_changed(
        &ctx,
        queue_handle,
        r#"["dev-1"]"#,
        "image/png",
        &big,
        1000,
        0,
    );
    assert_eq!(r["action"], "file_transfer");
}

#[test]
fn test_on_received_normalizes_type() {
    let ctx = create_ctx();
    let r = on_received(
        &ctx,
        r#"{"clipboardType":"image/png","content":"AAA="}"#,
        1000,
    );
    assert_eq!(r["type"], "image");
    assert_eq!(r["content"], "AAA=");
}

#[test]
fn test_on_received_invalid_payload_returns_empty() {
    let ctx = create_ctx();
    let r = on_received(&ctx, "not-json", 1000);
    assert_eq!(r["type"], "text");
    assert_eq!(r["content"], "");
}

#[test]
fn test_on_received_null_ctx_returns_empty() {
    let p = cstr(r#"{"clipboardType":"text/plain","content":"x"}"#);
    let r = unsafe { ffi::clipboard::nrc_clipboard_on_received(std::ptr::null_mut(), p, 1000) };
    let v: serde_json::Value = serde_json::from_str(&unsafe { read_cstr(r) }).unwrap();
    assert_eq!(v["type"], "text");
    assert_eq!(v["content"], "");
    unsafe {
        free_str(r);
        free_cstr(p);
    }
}
