//! FFI 设备列表接口语义测试（nrc_get_device_list / nrc_add_known_device / nrc_remove_known_device）
//! 目的：保证 PC 与 Android 两个平台端共享的设备列表契约不变

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

fn device_list(ctx: &SafeContext, authed_ms: i64, unauthed_ms: i64) -> serde_json::Value {
    let r = unsafe { ffi::device_state::nrc_get_device_list(ctx_ptr(ctx), authed_ms, unauthed_ms) };
    let s = unsafe { read_cstr(r) };
    unsafe { free_str(r) };
    serde_json::from_str(&s).unwrap_or_else(|_| panic!("设备列表应为合法 JSON: {}", s))
}

fn add_known(ctx: &SafeContext, uuid: &str, ip: &str) {
    let u = cstr(uuid);
    let i = cstr(ip);
    unsafe {
        ffi::discovery::nrc_add_known_device(ctx_ptr(ctx), u, i);
        free_cstr(u);
        free_cstr(i);
    }
}

fn remove_known(ctx: &SafeContext, uuid: &str) {
    let u = cstr(uuid);
    unsafe {
        ffi::discovery::nrc_remove_known_device(ctx_ptr(ctx), u);
        free_cstr(u);
    }
}

fn migrate_key(ctx: &SafeContext, uuid: &str) {
    let u = cstr(uuid);
    let key = [1u8; 32];
    unsafe {
        ffi::key_management::nrc_migrate_shared_secret(ctx_ptr(ctx), u, key.as_ptr(), 32);
        free_cstr(u);
    }
}

fn find_device<'a>(list: &'a serde_json::Value, uuid: &str) -> &'a serde_json::Value {
    list.as_array()
        .unwrap()
        .iter()
        .find(|d| d["uuid"] == uuid)
        .unwrap_or_else(|| panic!("列表应包含设备 {}", uuid))
}

#[test]
fn test_device_list_empty() {
    let ctx = create_ctx();
    let list = device_list(&ctx, 30000, 30000);
    assert_eq!(list.as_array().unwrap().len(), 0);
}

#[test]
fn test_device_list_known_device_offline_placeholder() {
    let ctx = create_ctx();
    add_known(&ctx, "dev-1", "192.168.1.5");
    let list = device_list(&ctx, 30000, 30000);
    let d = find_device(&list, "dev-1");
    assert_eq!(d["name"], "");
    assert_eq!(d["ip"], "192.168.1.5");
    assert_eq!(d["port"], 23333); // 默认 TCP 端口
    assert_eq!(d["battery"], -101); // 未知电量
    assert_eq!(d["connected"], false);
    assert_eq!(d["paired"], false);
    assert_eq!(d["online"], false); // lastSeen=0 视为离线
    assert_eq!(d["lastSeen"], 0);
    assert_eq!(d["deviceType"], "");
}

#[test]
fn test_device_list_paired_device_placeholder() {
    let ctx = create_ctx();
    // 已配对（有密钥）但从未有状态 → 以 paired=true 占位
    migrate_key(&ctx, "dev-paired");
    let list = device_list(&ctx, 30000, 30000);
    let d = find_device(&list, "dev-paired");
    assert_eq!(d["paired"], true);
    assert_eq!(d["ip"], "");
    assert_eq!(d["online"], false);
}

#[test]
fn test_device_list_paired_known_device() {
    let ctx = create_ctx();
    add_known(&ctx, "dev-1", "10.0.0.2");
    migrate_key(&ctx, "dev-1");
    let list = device_list(&ctx, 30000, 30000);
    let d = find_device(&list, "dev-1");
    assert_eq!(d["paired"], true);
    assert_eq!(d["ip"], "10.0.0.2");
}

#[test]
fn test_device_list_online_judgement() {
    let ctx = create_ctx();
    add_known(&ctx, "dev-1", "192.168.1.5");
    // lastSeen=0：离线占位。时间差(秒*1000) 超过常规阈值 → online=false
    let list = device_list(&ctx, 30000, 30000);
    assert_eq!(find_device(&list, "dev-1")["online"], false);
    // 阈值极大时在线判定公式成立（now - lastSeen <= threshold）
    let list2 = device_list(&ctx, i64::MAX / 2, i64::MAX / 2);
    assert_eq!(find_device(&list2, "dev-1")["online"], true);
    // threshold=0 时恒为离线
    let list3 = device_list(&ctx, 0, 0);
    assert_eq!(find_device(&list3, "dev-1")["online"], false);
}

#[test]
fn test_device_list_remove_known_device() {
    let ctx = create_ctx();
    add_known(&ctx, "dev-1", "192.168.1.5");
    assert_eq!(device_list(&ctx, 30000, 30000).as_array().unwrap().len(), 1);
    remove_known(&ctx, "dev-1");
    let list = device_list(&ctx, 30000, 30000);
    assert_eq!(list.as_array().unwrap().len(), 0);
}

#[test]
fn test_device_list_multiple_devices() {
    let ctx = create_ctx();
    add_known(&ctx, "dev-b", "1.1.1.1");
    add_known(&ctx, "dev-a", "2.2.2.2");
    let list = device_list(&ctx, 30000, 30000);
    let arr = list.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    let mut uuids: Vec<&str> = arr.iter().map(|d| d["uuid"].as_str().unwrap()).collect();
    uuids.sort_unstable();
    assert_eq!(uuids, vec!["dev-a", "dev-b"]);
}
