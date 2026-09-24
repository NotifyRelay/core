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

// ===== nrc_parse_superisland_inbound 测试 =====

fn parse_superisland(uuid: &str, pkg: &str, full_json: &str) -> serde_json::Value {
    let u = cstr(uuid);
    let p = cstr(pkg);
    let f = cstr(full_json);
    let r = unsafe { ffi::state_merge::nrc_parse_superisland_inbound(u, p, f) };
    unsafe {
        free_cstr(u);
        free_cstr(p);
    }
    assert!(!r.is_null(), "返回指针不应为 null");
    let s = unsafe { CString::from_raw(r) }
        .to_str()
        .unwrap()
        .to_string();
    serde_json::from_str(&s).unwrap_or_else(|_| panic!("应返回合法 JSON: {}", s))
}

#[test]
fn test_parse_si_basic() {
    let wire = r#"{"packageName":"com.test","appName":"Test","title":"t1","text":"c1","param_v2_raw":"{\"k\":1}","featureKeyValue":"fid-abc","pics":{"icon":"base64data","empty":"","num":123},"type":"SUPERISLAND","hash":"x"}"#;
    let v = parse_superisland("uuid-1", "com.test", wire);
    assert_eq!(v["featureId"], "fid-abc");
    assert_eq!(v["packageName"], "com.test");
    assert_eq!(v["appName"], "Test");
    assert_eq!(v["title"], "t1");
    assert_eq!(v["text"], "c1");
    assert_eq!(v["paramV2Raw"], r#"{"k":1}"#);
    assert_eq!(v["isEnd"], false);
    assert_eq!(v["sourceKey"], "uuid-1|com.test|fid-abc");
    // pics：仅保留非空 string 值（"empty" 空串与 "num" 非字符串被过滤）
    assert_eq!(v["pics"]["icon"], "base64data");
    assert!(v["pics"].get("empty").is_none() || v["pics"]["empty"].is_null());
    assert!(v["pics"].get("num").is_none() || v["pics"]["num"].is_null());
}

#[test]
fn test_parse_si_is_end() {
    let wire = r#"{"featureKeyValue":"fid","terminateValue":"__END__"}"#;
    let v = parse_superisland("uuid-1", "com.test", wire);
    assert_eq!(v["isEnd"], true);
    assert_eq!(v["featureId"], "fid");
}

#[test]
fn test_parse_si_not_end() {
    let wire = r#"{"featureKeyValue":"fid","terminateValue":"other"}"#;
    let v = parse_superisland("uuid-1", "com.test", wire);
    assert_eq!(v["isEnd"], false);
}

#[test]
fn test_parse_si_feature_id_fallback() {
    // 无 featureKeyValue → 回退 compute_feature_id_impl（sha1 hex，40 字符）
    let wire = r#"{"packageName":"com.test","title":"t1","text":"c1"}"#;
    let v = parse_superisland("uuid-1", "com.test", wire);
    let fid = v["featureId"].as_str().expect("featureId 应为字符串");
    assert_eq!(fid.len(), 40, "sha1 hex 应为 40 字符");
    assert!(fid.chars().all(|c| c.is_ascii_hexdigit()), "应为 hex");
    // sourceKey 仍含三段
    assert_eq!(v["sourceKey"], format!("uuid-1|com.test|{}", fid));
}

#[test]
fn test_parse_si_feature_id_whitespace_falls_back() {
    // featureKeyValue 为纯空白 → 视为缺失，走回退（对齐 Android isNullOrBlank）
    let wire = r#"{"packageName":"com.test","featureKeyValue":"   "}"#;
    let v = parse_superisland("uuid-1", "com.test", wire);
    let fid = v["featureId"].as_str().expect("featureId 应为字符串");
    assert_eq!(fid.len(), 40, "空白 featureKeyValue 应走回退");
}

#[test]
fn test_parse_si_source_key_format() {
    let wire = r#"{"featureKeyValue":"fid"}"#;
    let v = parse_superisland("uuid-1", "com.mapped", wire);
    assert_eq!(v["sourceKey"], "uuid-1|com.mapped|fid");
}

#[test]
fn test_parse_si_null_fields_when_missing() {
    let wire = r#"{"packageName":"com.test"}"#;
    let v = parse_superisland("uuid-1", "com.test", wire);
    assert!(v["title"].is_null(), "缺失 title 应为 null");
    assert!(v["text"].is_null(), "缺失 text 应为 null");
    assert!(v["paramV2Raw"].is_null(), "缺失 paramV2Raw 应为 null");
    assert_eq!(v["appName"], "", "缺失 appName 应为空串");
}

#[test]
fn test_parse_si_param_v2_raw_blank_is_null() {
    let wire = r#"{"packageName":"com.test","param_v2_raw":"   "}"#;
    let v = parse_superisland("uuid-1", "com.test", wire);
    assert!(v["paramV2Raw"].is_null(), "纯空白 paramV2Raw 应为 null");
}

#[test]
fn test_parse_si_pics_empty_string_filtered() {
    let wire = r#"{"featureKeyValue":"fid","pics":{"keep":"val","drop":""}}"#;
    let v = parse_superisland("uuid-1", "com.test", wire);
    assert_eq!(v["pics"]["keep"], "val");
    assert!(v["pics"].get("drop").is_none() || v["pics"]["drop"].is_null());
}

#[test]
fn test_parse_si_invalid_json_returns_null() {
    let v = parse_superisland("uuid-1", "com.test", "not json");
    assert!(v.is_null(), "非法 JSON 应返回 null");
}
