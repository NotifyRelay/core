//! FFI 过滤接口语义测试（nrc_set_filter_config / nrc_map_local_package / nrc_check_filter_mode）
//! 目的：保证 PC 与 Android 两个平台端共享的过滤接口契约不变

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::Mutex;

use notify_relay_core::{ffi, CoreContext, SafeContext};

fn create_ctx() -> SafeContext {
    Mutex::new(CoreContext::new())
}

fn ctx_mut(ctx: &SafeContext) -> *mut SafeContext {
    ctx as *const SafeContext as *mut SafeContext
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

fn set_config(ctx: &SafeContext, json: &str) -> i32 {
    let j = cstr(json);
    let r = unsafe { ffi::filter::nrc_set_filter_config(ctx_mut(ctx), j) };
    unsafe { free_cstr(j) };
    r
}

fn check(ctx: &SafeContext, pkg: &str, title: &str, text: &str) -> i32 {
    let p = cstr(pkg);
    let t = cstr(title);
    let x = cstr(text);
    let e = cstr("");
    let r = unsafe { ffi::filter::nrc_check_filter_mode(ctx_mut(ctx), p, e, t, x) };
    unsafe {
        free_cstr(p);
        free_cstr(t);
        free_cstr(x);
        free_cstr(e);
    }
    r
}

#[test]
fn test_set_filter_config_invalid_json_fails() {
    let ctx = create_ctx();
    assert_eq!(set_config(&ctx, "not-json"), -1);
    // 非法 JSON 后配置保持默认（mode=0 不过滤）
    assert_eq!(check(&ctx, "com.any", "", ""), 1);
}

#[test]
fn test_set_filter_config_null_ctx_fails() {
    let j = cstr("{}");
    assert_eq!(
        unsafe { ffi::filter::nrc_set_filter_config(std::ptr::null_mut(), j) },
        -1
    );
    unsafe { free_cstr(j) };
}

#[test]
fn test_whitelist_mode_semantics() {
    let ctx = create_ctx();
    assert_eq!(
        set_config(
            &ctx,
            r#"{"filterMode":1,"filterList":["com.allowed","com.app|blocked"]}"#
        ),
        0
    );
    // 白名单：列表内通过
    assert_eq!(check(&ctx, "com.allowed", "", ""), 1);
    // 白名单：列表外拦截
    assert_eq!(check(&ctx, "com.blocked", "", ""), 0);
    // 关键词条目：标题含关键词才通过
    assert_eq!(check(&ctx, "com.app", "blocked content", ""), 1);
    assert_eq!(check(&ctx, "com.app", "normal", ""), 0);
}

#[test]
fn test_blacklist_mode_semantics() {
    let ctx = create_ctx();
    assert_eq!(
        set_config(&ctx, r#"{"filterMode":2,"filterList":["com.app|blocked"]}"#),
        0
    );
    // 黑名单：关键词命中拦截
    assert_eq!(check(&ctx, "com.app", "has blocked word", ""), 0);
    // 黑名单：关键词未命中放行
    assert_eq!(check(&ctx, "com.app", "normal", ""), 1);
    // 黑名单：其他包放行
    assert_eq!(check(&ctx, "com.other", "blocked", ""), 1);
}

#[test]
fn test_default_mode_never_filters() {
    let ctx = create_ctx();
    assert_eq!(check(&ctx, "com.any", "anything", "anything"), 1);
}

#[test]
fn test_package_group_mapping() {
    let ctx = create_ctx();
    // 未启用映射时返回原包名
    let pkg = cstr("com.whatsapp");
    let r = unsafe { ffi::filter::nrc_map_local_package(ctx_mut(&ctx), pkg) };
    assert_eq!(unsafe { read_cstr(r) }, "com.whatsapp");
    unsafe { free_str(r) };

    // 启用映射
    assert_eq!(
        set_config(
            &ctx,
            r#"{"enablePackageGroupMapping":true,"packageGroups":[{"groupName":"messaging","packages":["com.whatsapp","com.telegram"]}],"groupEnabled":{"messaging":true}}"#,
        ),
        0
    );
    let r2 = unsafe { ffi::filter::nrc_map_local_package(ctx_mut(&ctx), pkg) };
    assert_eq!(unsafe { read_cstr(r2) }, "messaging");
    // 不在组内的包返回原包名
    let pkg2 = cstr("com.unknown");
    let r3 = unsafe { ffi::filter::nrc_map_local_package(ctx_mut(&ctx), pkg2) };
    assert_eq!(unsafe { read_cstr(r3) }, "com.unknown");
    unsafe {
        free_str(r2);
        free_str(r3);
        free_cstr(pkg);
        free_cstr(pkg2);
    }
}

#[test]
fn test_package_group_mapping_disabled_group() {
    let ctx = create_ctx();
    assert_eq!(
        set_config(
            &ctx,
            r#"{"enablePackageGroupMapping":true,"packageGroups":[{"groupName":"messaging","packages":["com.whatsapp"]}],"groupEnabled":{"messaging":false}}"#,
        ),
        0
    );
    // 组被禁用时不映射
    let pkg = cstr("com.whatsapp");
    let r = unsafe { ffi::filter::nrc_map_local_package(ctx_mut(&ctx), pkg) };
    assert_eq!(unsafe { read_cstr(r) }, "com.whatsapp");
    unsafe {
        free_str(r);
        free_cstr(pkg);
    }
}

#[test]
fn test_filter_config_replace_semantics() {
    let ctx = create_ctx();
    assert_eq!(
        set_config(&ctx, r#"{"filterMode":1,"filterList":["com.a"]}"#),
        0
    );
    assert_eq!(check(&ctx, "com.a", "", ""), 1);
    // 重新设置配置应整体替换，而不是追加
    assert_eq!(
        set_config(&ctx, r#"{"filterMode":1,"filterList":["com.b"]}"#),
        0
    );
    assert_eq!(check(&ctx, "com.a", "", ""), 0);
    assert_eq!(check(&ctx, "com.b", "", ""), 1);
}
