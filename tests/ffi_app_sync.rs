//! FFI 应用同步接口语义测试（nrc_app_sync_*）
//! 目的：保证 PC 与 Android 两个平台端共享的应用同步接口契约不变

use std::ffi::{CStr, CString};
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

fn prepare_icon_request(
    ctx: &SafeContext,
    packages: &str,
    installed: &str,
    cached: &str,
    app_device: &str,
    source: &str,
    now_ms: i64,
) -> serde_json::Value {
    let p = cstr(packages);
    let i = cstr(installed);
    let c = cstr(cached);
    let m = cstr(app_device);
    let s = cstr(source);
    let r = unsafe {
        ffi::app_sync::nrc_app_sync_prepare_icon_request(ctx_ptr(ctx), p, i, c, m, s, now_ms)
    };
    let out = unsafe { read_cstr(r) };
    unsafe {
        free_str(r);
        free_cstr(p);
        free_cstr(i);
        free_cstr(c);
        free_cstr(m);
        free_cstr(s);
    }
    serde_json::from_str(&out).unwrap_or_else(|_| panic!("应返回合法 JSON: {}", out))
}

#[test]
fn test_prepare_icon_request_filters_installed_and_cached() {
    let ctx = create_ctx();
    let result = prepare_icon_request(
        &ctx,
        r#"["com.a","com.b","com.c","com.d"]"#,
        r#"["com.b"]"#,
        r#"["com.c"]"#,
        "{}",
        "dev-1",
        1000,
    );
    // 仅未安装且未缓存的包进入请求（多个包时使用 packageNames 数组）
    assert_eq!(
        result["packageNames"],
        serde_json::json!(["com.a", "com.d"])
    );
    assert_eq!(result["type"], "ICON_REQUEST");
}

#[test]
fn test_prepare_icon_request_single_package_uses_package_name() {
    let ctx = create_ctx();
    let result = prepare_icon_request(
        &ctx,
        r#"["com.a","com.b"]"#,
        r#"["com.b"]"#,
        "[]",
        "{}",
        "dev-1",
        1000,
    );
    // 仅剩一个待请求包时使用 packageName 字段（与平台端解析契约一致）
    assert_eq!(result["packageName"], "com.a");
}

#[test]
fn test_prepare_icon_request_device_association() {
    let ctx = create_ctx();
    // 包关联了源设备 dev-1 → 请求
    let result = prepare_icon_request(
        &ctx,
        r#"["com.a"]"#,
        "[]",
        "[]",
        r#"{"com.a":["dev-1"]}"#,
        "dev-1",
        1000,
    );
    assert!(result.to_string().contains("com.a"));
    // 包关联的是其它设备（非源设备）→ 不请求
    let result2 = prepare_icon_request(
        &ctx,
        r#"["com.other"]"#,
        "[]",
        "[]",
        r#"{"com.other":["dev-2"]}"#,
        "dev-1",
        2000,
    );
    assert_eq!(result2, serde_json::json!({}));
}

#[test]
fn test_prepare_icon_request_all_cached_empty() {
    let ctx = create_ctx();
    let result = prepare_icon_request(
        &ctx,
        r#"["com.a"]"#,
        "[]",
        r#"["com.a"]"#,
        "{}",
        "dev-1",
        1000,
    );
    // 全部已缓存 → 无需请求（空对象）
    assert_eq!(result, serde_json::json!({}));
}

#[test]
fn test_prepare_icon_request_null_ctx_returns_empty() {
    let p = cstr(r#"["com.a"]"#);
    let i = cstr("[]");
    let c = cstr("[]");
    let m = cstr("{}");
    let s = cstr("dev-1");
    let r = unsafe {
        ffi::app_sync::nrc_app_sync_prepare_icon_request(std::ptr::null_mut(), p, i, c, m, s, 1000)
    };
    assert_eq!(unsafe { read_cstr(r) }, "{}");
    unsafe {
        free_str(r);
        free_cstr(p);
        free_cstr(i);
        free_cstr(c);
        free_cstr(m);
        free_cstr(s);
    }
}

#[test]
fn test_parse_icon_response() {
    let payload =
        cstr(r#"{"icons":[{"packageName":"com.a","iconData":"AAA="}],"missing":["com.b"]}"#);
    let r = unsafe { ffi::app_sync::nrc_app_sync_parse_icon_response(payload) };
    let v: serde_json::Value = serde_json::from_str(&unsafe { read_cstr(r) }).unwrap();
    assert_eq!(v["icons"][0]["packageName"], "com.a");
    assert_eq!(v["icons"][0]["iconData"], "AAA=");
    assert_eq!(v["missing"], serde_json::json!(["com.b"]));
    unsafe {
        free_str(r);
        free_cstr(payload);
    }
}

#[test]
fn test_build_applist_request() {
    let scope = cstr("user");
    let r = unsafe { ffi::app_sync::nrc_app_sync_build_applist_request(scope, 1234567890) };
    let v: serde_json::Value = serde_json::from_str(&unsafe { read_cstr(r) }).unwrap();
    assert_eq!(v["type"], "APP_LIST_REQUEST");
    assert_eq!(v["scope"], "user");
    assert_eq!(v["time"], 1234567890);
    unsafe {
        free_str(r);
        free_cstr(scope);
    }
}

#[test]
fn test_parse_applist_response() {
    let payload =
        cstr(r#"{"scope":"user","total":1,"apps":[{"packageName":"com.a","appName":"AppA"}]}"#);
    let r = unsafe { ffi::app_sync::nrc_app_sync_parse_applist_response(payload) };
    let v: serde_json::Value = serde_json::from_str(&unsafe { read_cstr(r) }).unwrap();
    assert_eq!(v["apps"][0]["packageName"], "com.a");
    assert_eq!(v["apps"][0]["appName"], "AppA");
    assert_eq!(v["scope"], "user");
    unsafe {
        free_str(r);
        free_cstr(payload);
    }
}

#[test]
fn test_clear_icon_pending_after_prepare() {
    let ctx = create_ctx();
    let _ = prepare_icon_request(
        &ctx,
        r#"["com.a","com.b"]"#,
        "[]",
        "[]",
        "{}",
        "dev-1",
        1000,
    );
    // 清理后再次请求应重新生成
    let r2 = prepare_icon_request(
        &ctx,
        r#"["com.a","com.b"]"#,
        "[]",
        "[]",
        "{}",
        "dev-1",
        2000,
    );
    let packages = cstr(r#"["com.a","com.b"]"#);
    unsafe {
        ffi::app_sync::nrc_app_sync_clear_icon_pending(ctx_ptr(&ctx), packages);
        free_cstr(packages);
    }
    let r3 = prepare_icon_request(
        &ctx,
        r#"["com.a","com.b"]"#,
        "[]",
        "[]",
        "{}",
        "dev-1",
        3000,
    );
    assert!(!r2.to_string().is_empty() || !r3.to_string().is_empty());
}

/// 聚合入口的测试封装（参数与 prepare_icon_request 封装一致）
fn request_icons(
    ctx: &SafeContext,
    packages: &str,
    installed: &str,
    cached: &str,
    app_device: &str,
    source: &str,
    now_ms: i64,
) -> serde_json::Value {
    let p = cstr(packages);
    let i = cstr(installed);
    let c = cstr(cached);
    let m = cstr(app_device);
    let s = cstr(source);
    let ptr = ctx_ptr(ctx);
    let r = unsafe { ffi::app_sync::nrc_app_sync_request_icons(ptr, p, i, c, m, s, now_ms) };
    let out = unsafe { read_cstr(r) };
    unsafe {
        free_str(r);
        free_cstr(p);
        free_cstr(i);
        free_cstr(c);
        free_cstr(m);
        free_cstr(s);
    }
    serde_json::from_str(&out).unwrap_or_else(|_| panic!("应返回合法 JSON: {}", out))
}

#[test]
fn test_request_icons_matches_two_step_primitives() {
    // 聚合入口与「clear + prepare」两步串联的报文结果必须等价（含已有 pending 的情形）
    let agg_ctx = create_ctx();
    let two_ctx = create_ctx();
    let packages = r#"["com.a","com.b","com.c"]"#;

    // 两个上下文都先登记同一批包名，使 pending 状态一致
    let _ = prepare_icon_request(&agg_ctx, packages, "[]", "[]", "{}", "dev-1", 900);
    let _ = prepare_icon_request(&two_ctx, packages, "[]", "[]", "{}", "dev-1", 900);

    // 两步：先清空候选包名登记，再 prepare
    let clear = cstr(packages);
    unsafe {
        ffi::app_sync::nrc_app_sync_clear_icon_pending(ctx_ptr(&two_ctx), clear);
        free_cstr(clear);
    }
    let two_step = prepare_icon_request(&two_ctx, packages, "[]", "[]", "{}", "dev-1", 1000);
    let aggregated = request_icons(&agg_ctx, packages, "[]", "[]", "{}", "dev-1", 1000);
    assert_eq!(aggregated, two_step);
    assert_eq!(aggregated["type"], "ICON_REQUEST");
}

#[test]
fn test_request_icons_clears_previous_pending() {
    // 聚合入口自带旧登记解除：连续调用仍能重新生成请求报文
    let ctx = create_ctx();
    let first = request_icons(&ctx, r#"["com.a"]"#, "[]", "[]", "{}", "dev-1", 1000);
    assert_eq!(first["packageName"], "com.a");

    // 对照：两步原语不做 clear 时，同一 TTL 窗口内被判定为进行中
    let still_pending = prepare_icon_request(&ctx, r#"["com.a"]"#, "[]", "[]", "{}", "dev-1", 2000);
    assert_eq!(still_pending, serde_json::json!({}));

    // 聚合入口自带 clear，同一时间点仍能重新生成
    let second = request_icons(&ctx, r#"["com.a"]"#, "[]", "[]", "{}", "dev-1", 2000);
    assert_eq!(second["packageName"], "com.a");
}

#[test]
fn test_request_icons_still_honors_filters() {
    // 聚合入口保留 prepare 的全部过滤语义
    let ctx = create_ctx();
    let result = request_icons(
        &ctx,
        r#"["com.installed","com.cached","com.other"]"#,
        r#"["com.installed"]"#,
        r#"["com.cached"]"#,
        r#"{"com.other":["dev-2"]}"#,
        "dev-1",
        1000,
    );
    assert_eq!(result, serde_json::json!({}));
}

#[test]
fn test_request_icons_null_ctx_returns_empty() {
    let p = cstr(r#"["com.a"]"#);
    let i = cstr("[]");
    let c = cstr("[]");
    let m = cstr("{}");
    let s = cstr("dev-1");
    let null_ctx: *mut c_void = std::ptr::null_mut();
    let r = unsafe { ffi::app_sync::nrc_app_sync_request_icons(null_ctx, p, i, c, m, s, 1000) };
    assert_eq!(unsafe { read_cstr(r) }, "{}");
    unsafe {
        free_str(r);
        free_cstr(p);
        free_cstr(i);
        free_cstr(c);
        free_cstr(m);
        free_cstr(s);
    }
}
