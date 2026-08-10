//! FFI 状态合并引擎接口语义测试（nrc_push_superisland_state / nrc_push_media_state）
//! 目的：保证 PC 与 Android 两个平台端共享的状态合并接口契约不变

use std::ffi::CString;
use std::os::raw::{c_char, c_void};
use std::sync::Mutex;

use notify_relay_core::{ffi, CoreContext, SafeContext};

fn create_ctx() -> SafeContext {
    Mutex::new(CoreContext::new())
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
