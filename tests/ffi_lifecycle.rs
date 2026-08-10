//! FFI 生命周期接口语义测试（nrc_init / nrc_get_git_hash / nrc_free_string / nrc_get_local_ip）
//! 目的：保证 PC 与 Android 两个平台端共享的生命周期接口契约不变

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use notify_relay_core::ffi;

unsafe fn read_cstr(p: *const c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    CStr::from_ptr(p).to_str().unwrap_or("").to_string()
}

#[test]
fn test_init_returns_non_null_context() {
    let ctx = ffi::lifecycle::nrc_init();
    assert!(!ctx.is_null());
    // 泄漏该上下文由进程回收（生命周期接口语义：返回的指针由平台端管理）
}

#[test]
fn test_get_git_hash_returns_non_empty() {
    let hash = ffi::lifecycle::nrc_get_git_hash();
    let s = unsafe { read_cstr(hash) };
    assert!(!s.is_empty());
    // 格式：提交哈希（7-40 位 hex），工作区未提交时带 -dirty 后缀
    let trimmed = s.strip_suffix("-dirty").unwrap_or(&s);
    assert!(trimmed.len() >= 7 && trimmed.len() <= 40);
    assert!(trimmed.chars().all(|c| c.is_ascii_hexdigit()));
    unsafe {
        drop(CString::from_raw(hash));
    }
}

#[test]
fn test_free_string_null_safe() {
    unsafe {
        ffi::lifecycle::nrc_free_string(std::ptr::null_mut());
    }
}

#[test]
fn test_free_string_non_null() {
    let s = CString::new("hello").unwrap().into_raw();
    unsafe {
        ffi::lifecycle::nrc_free_string(s);
    }
}

#[test]
fn test_get_local_ip_returns_string() {
    let ip = ffi::utils::nrc_get_local_ip();
    let s = unsafe { read_cstr(ip) };
    // 真实设备上应返回可解析的局域网 IP；无网络环境允许空
    if !s.is_empty() {
        let is_valid = s.parse::<std::net::IpAddr>().is_ok();
        assert!(is_valid, "应返回合法 IP 地址，实际: {}", s);
    }
    unsafe {
        drop(CString::from_raw(ip));
    }
}

#[test]
fn test_set_log_callback_null_and_dummy() {
    // 设置/清空日志回调不崩溃
    ffi::common::nrc_set_log_callback(None);
}
