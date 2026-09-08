//! FFI 状态合并引擎接口语义测试（nrc_push_superisland_state / nrc_push_media_state）
//! 目的：保证 PC 与 Android 两个平台端共享的状态合并接口契约不变

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

fn make_queue_handle() -> u64 {
    let queue = Box::new(notify_relay_core::sender_queue::SenderQueue::new());
    ffi::handle::put(Box::into_raw(queue) as *mut c_void)
}

fn push_superisland(
    ctx: &SafeContext,
    queue_handle: u64,
    uuid: &str,
    full_json: &str,
    is_end: i32,
    is_query: i32,
) -> i32 {
    let u = cstr(uuid);
    let f = cstr(full_json);
    let r = ffi::state_merge::nrc_push_superisland_state(
        ctx_ptr(ctx),
        queue_handle,
        u,
        f,
        is_end,
        is_query,
    );
    unsafe {
        free_cstr(u);
        free_cstr(f);
    }
    r
}

fn push_media(
    ctx: &SafeContext,
    queue_handle: u64,
    uuid: &str,
    full_json: &str,
    is_end: i32,
    is_query: i32,
) -> i32 {
    let u = cstr(uuid);
    let f = cstr(full_json);
    let r =
        ffi::state_merge::nrc_push_media_state(ctx_ptr(ctx), queue_handle, u, f, is_end, is_query);
    unsafe {
        free_cstr(u);
        free_cstr(f);
    }
    r
}

const FULL_STATE: &str = r#"{"featureId":"f1","title":"t","text":"c"}"#;

#[test]
fn test_push_null_ctx_fails() {
    let queue_handle = make_queue_handle();
    let u = cstr("dev-1");
    let f = cstr(FULL_STATE);
    assert_eq!(
        ffi::state_merge::nrc_push_superisland_state(
            std::ptr::null_mut(),
            queue_handle,
            u,
            f,
            0,
            0,
        ),
        -1
    );
    unsafe {
        free_cstr(u);
        free_cstr(f);
    }
}

#[test]
fn test_push_invalid_queue_fails() {
    let ctx = create_ctx();
    assert_eq!(push_superisland(&ctx, 0, "dev-1", FULL_STATE, 0, 0), -1);
    assert_eq!(push_media(&ctx, 0, "dev-1", FULL_STATE, 0, 0), -1);
}

#[test]
fn test_push_superisland_state_success() {
    let ctx = create_ctx();
    let queue_handle = make_queue_handle();
    assert_eq!(
        push_superisland(&ctx, queue_handle, "dev-1", FULL_STATE, 0, 0),
        0
    );
}

#[test]
fn test_push_media_state_success() {
    let ctx = create_ctx();
    let queue_handle = make_queue_handle();
    assert_eq!(push_media(&ctx, queue_handle, "dev-1", FULL_STATE, 0, 0), 0);
}

#[test]
fn test_push_multiple_updates_success() {
    let ctx = create_ctx();
    let queue_handle = make_queue_handle();
    assert_eq!(
        push_superisland(&ctx, queue_handle, "dev-1", FULL_STATE, 0, 0),
        0
    );
    // 同设备连续推送（差量合并路径）不失败
    assert_eq!(
        push_superisland(&ctx, queue_handle, "dev-1", FULL_STATE, 0, 0),
        0
    );
    // 多设备并行会话
    assert_eq!(
        push_superisland(&ctx, queue_handle, "dev-2", FULL_STATE, 0, 0),
        0
    );
    assert_eq!(push_media(&ctx, queue_handle, "dev-1", FULL_STATE, 0, 0), 0);
}

#[test]
fn test_push_with_end_flag() {
    let ctx = create_ctx();
    let queue_handle = make_queue_handle();
    // is_end=1：结束标记（会话收尾）仍返回成功
    assert_eq!(
        push_superisland(&ctx, queue_handle, "dev-1", FULL_STATE, 1, 0),
        0
    );
    assert_eq!(push_media(&ctx, queue_handle, "dev-1", FULL_STATE, 1, 0), 0);
}

#[test]
fn test_push_query_flag() {
    let ctx = create_ctx();
    let queue_handle = make_queue_handle();
    // is_query=1：平台查询推送路径
    assert_eq!(
        push_superisland(&ctx, queue_handle, "dev-1", FULL_STATE, 0, 1),
        0
    );
    assert_eq!(push_media(&ctx, queue_handle, "dev-1", FULL_STATE, 0, 1), 0);
}

/// 媒体状态推送回归测试：FULL → 差量 → FULL 发送链路正常，
/// 且 force_full_next（重同步触发后）逻辑可经由此路径重发全量。
///
/// 注意：将 DELTA 注入"接收路径"并断言"远端下一帧为 FULL"的完整重同步验证，
/// 由 crate 内单元测试覆盖（`state_merge::tests::test_media_need_full_enqueues_resync_request`
/// 与 `test_resync_request_triggers_full_resend`），因集成测试作为外部 crate 无法访问
/// 私有 `handle_state_message`，也无法检查发送队列内部内容。
#[test]
fn test_media_resync_sender_path() {
    let ctx = create_ctx();
    let queue_handle = make_queue_handle();

    // 首次推送媒体状态（FULL，建立发送端基线）
    assert_eq!(push_media(&ctx, queue_handle, "dev-1", FULL_STATE, 0, 0), 0);

    // 推送变更（按差量发送）
    let changed = r#"{"featureIdOverride":"f1","title":"updated","text":"c"}"#;
    assert_eq!(push_media(&ctx, queue_handle, "dev-1", changed, 0, 0), 0);

    // 再次推送全量（接收端重同步请求后，发送端应经 force_full_next 重发 FULL 而非 delta）
    assert_eq!(push_media(&ctx, queue_handle, "dev-1", FULL_STATE, 0, 0), 0);
}
