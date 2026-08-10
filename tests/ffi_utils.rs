//! FFI 工具接口语义测试（feature_id / dedup_key / 去重判定 / FTP 凭据 / 密码 / nrc_dedup）
//! 目的：保证 PC 与 Android 两个平台端共享的工具接口契约不变

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

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

// ==================== feature_id ====================

#[test]
fn test_compute_feature_id_returns_40_hex() {
    let pkg = cstr("com.test.app");
    let param = cstr("");
    let title = cstr("Hello");
    let text = cstr("World");
    let iid = cstr("inst-123");
    let result = unsafe { ffi::utils::nrc_compute_feature_id(pkg, param, title, text, iid) };
    let s = unsafe { read_cstr(result) };
    assert_eq!(s.len(), 40);
    assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    unsafe {
        free_str(result);
        free_cstr(pkg);
        free_cstr(param);
        free_cstr(title);
        free_cstr(text);
        free_cstr(iid);
    }
}

#[test]
fn test_compute_feature_id_deterministic() {
    let pkg = cstr("com.test.app");
    let param = cstr(r#"{"chatInfo":{"title":"MyChat"}}"#);
    let title = cstr("");
    let text = cstr("");
    let iid = cstr("inst-123");
    let r1 = unsafe { ffi::utils::nrc_compute_feature_id(pkg, param, title, text, iid) };
    let r2 = unsafe { ffi::utils::nrc_compute_feature_id(pkg, param, title, text, iid) };
    assert_eq!(unsafe { read_cstr(r1) }, unsafe { read_cstr(r2) });
    unsafe {
        free_str(r1);
        free_str(r2);
        free_cstr(pkg);
        free_cstr(param);
        free_cstr(title);
        free_cstr(text);
        free_cstr(iid);
    }
}

#[test]
fn test_compute_feature_id_distinguishes_inputs() {
    let pkg = cstr("com.test.app");
    let title = cstr("");
    let text = cstr("");
    let iid = cstr("");

    let chat_a = cstr(r#"{"chatInfo":{"title":"ChatA"}}"#);
    let chat_b = cstr(r#"{"chatInfo":{"title":"ChatB"}}"#);
    let r1 = unsafe { ffi::utils::nrc_compute_feature_id(pkg, chat_a, title, text, iid) };
    let r2 = unsafe { ffi::utils::nrc_compute_feature_id(pkg, chat_b, title, text, iid) };
    assert_ne!(unsafe { read_cstr(r1) }, unsafe { read_cstr(r2) });

    let base = cstr(r#"{"baseInfo":{"title":"BaseT","content":"BaseC"}}"#);
    let r3 = unsafe { ffi::utils::nrc_compute_feature_id(pkg, base, title, text, iid) };
    assert_eq!(unsafe { read_cstr(r3) }.len(), 40);

    let highlight = cstr(r#"{"highlightInfo":{"title":"Highlight"}}"#);
    let r4 = unsafe { ffi::utils::nrc_compute_feature_id(pkg, highlight, title, text, iid) };
    assert_eq!(unsafe { read_cstr(r4) }.len(), 40);

    unsafe {
        free_str(r1);
        free_str(r2);
        free_str(r3);
        free_str(r4);
        free_cstr(pkg);
        free_cstr(title);
        free_cstr(text);
        free_cstr(iid);
        free_cstr(chat_a);
        free_cstr(chat_b);
        free_cstr(base);
        free_cstr(highlight);
    }
}

// ==================== dedup_key ====================

#[test]
fn test_compute_dedup_key() {
    let u = cstr("uuid-1");
    let d1 = cstr("data-1");
    let d2 = cstr("data-2");

    let r1 = unsafe { ffi::utils::nrc_compute_dedup_key(u, d1) };
    let r2 = unsafe { ffi::utils::nrc_compute_dedup_key(u, d1) };
    let r3 = unsafe { ffi::utils::nrc_compute_dedup_key(u, d2) };
    let s1 = unsafe { read_cstr(r1) };
    assert_eq!(s1, unsafe { read_cstr(r2) });
    assert_eq!(s1.len(), 64); // sha256 hex
    assert_ne!(s1, unsafe { read_cstr(r3) });

    // 不同设备相同数据 → 不同 key
    let u2 = cstr("uuid-2");
    let r4 = unsafe { ffi::utils::nrc_compute_dedup_key(u2, d1) };
    assert_ne!(s1, unsafe { read_cstr(r4) });

    unsafe {
        free_str(r1);
        free_str(r2);
        free_str(r3);
        free_str(r4);
        free_cstr(u);
        free_cstr(u2);
        free_cstr(d1);
        free_cstr(d2);
    }
}

// ==================== nrc_dedup ====================

#[test]
fn test_dedup_action_semantics() {
    let ctx = create_ctx();
    let ptr = ctx_ptr(&ctx);
    let key = cstr("dedup-key-1");

    // action=0 首次检查 → 1（应发送）
    assert_eq!(unsafe { ffi::utils::nrc_dedup(ptr, 0, key, 60000, 0) }, 1);
    // 重复（pending 中）→ 0
    assert_eq!(unsafe { ffi::utils::nrc_dedup(ptr, 0, key, 60000, 0) }, 0);
    // action=2 清除 pending → 0，之后可再次发送
    assert_eq!(unsafe { ffi::utils::nrc_dedup(ptr, 2, key, 0, 0) }, 0);
    assert_eq!(unsafe { ffi::utils::nrc_dedup(ptr, 0, key, 60000, 0) }, 1);
    // action=1 标记已发送 → 0，TTL 内重复 → 0
    assert_eq!(unsafe { ffi::utils::nrc_dedup(ptr, 1, key, 0, 0) }, 0);
    assert_eq!(unsafe { ffi::utils::nrc_dedup(ptr, 0, key, 60000, 0) }, 0);
    // action=3 清理过期（时间前进 70s，TTL 60s）→ 0，之后可再次发送
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    assert_eq!(
        unsafe { ffi::utils::nrc_dedup(ptr, 3, key, now + 70000, 60000) },
        0
    );
    assert_eq!(unsafe { ffi::utils::nrc_dedup(ptr, 0, key, 60000, 0) }, 1);

    unsafe { free_cstr(key) };
}

#[test]
fn test_dedup_edge_cases() {
    // null ctx → -1
    assert_eq!(
        unsafe { ffi::utils::nrc_dedup(std::ptr::null_mut(), 0, std::ptr::null(), 0, 0) },
        -1
    );
    // 无效 action → -1
    let ctx = create_ctx();
    let ptr = ctx_ptr(&ctx);
    let key = cstr("k");
    assert_eq!(unsafe { ffi::utils::nrc_dedup(ptr, 99, key, 0, 0) }, -1);
    // 空 key 且 action=0 → 0（不允许发送）
    assert_eq!(
        unsafe { ffi::utils::nrc_dedup(ptr, 0, std::ptr::null(), 0, 0) },
        0
    );
    unsafe { free_cstr(key) };
}

#[test]
fn test_dedup_keys_independent() {
    let ctx = create_ctx();
    let ptr = ctx_ptr(&ctx);
    let k1 = cstr("k1");
    let k2 = cstr("k2");
    assert_eq!(unsafe { ffi::utils::nrc_dedup(ptr, 0, k1, 60000, 0) }, 1);
    assert_eq!(unsafe { ffi::utils::nrc_dedup(ptr, 0, k2, 60000, 0) }, 1);
    assert_eq!(unsafe { ffi::utils::nrc_dedup(ptr, 0, k1, 60000, 0) }, 0);
    unsafe {
        free_cstr(k1);
        free_cstr(k2);
    }
}

// ==================== 通知去重判定 ====================

#[test]
fn test_should_deduplicate_identical_returns_1() {
    let nt = cstr("Hello");
    let ntx = cstr("World");
    let ot = cstr("Hello");
    let otx = cstr("World");
    assert_eq!(
        unsafe { ffi::utils::nrc_should_deduplicate(nt, ntx, ot, otx) },
        1
    );
    unsafe {
        free_cstr(nt);
        free_cstr(ntx);
        free_cstr(ot);
        free_cstr(otx);
    }
}

#[test]
fn test_should_deduplicate_completely_different_returns_0() {
    let nt = cstr("Completely different title");
    let ntx = cstr("Completely different text body that is very long");
    let ot = cstr("Something else entirely");
    let otx = cstr("Another message that shares no words with the other");
    assert_eq!(
        unsafe { ffi::utils::nrc_should_deduplicate(nt, ntx, ot, otx) },
        0
    );
    unsafe {
        free_cstr(nt);
        free_cstr(ntx);
        free_cstr(ot);
        free_cstr(otx);
    }
}

#[test]
fn test_should_deduplicate_empty_both_returns_1() {
    let e = cstr("");
    assert_eq!(unsafe { ffi::utils::nrc_should_deduplicate(e, e, e, e) }, 1);
    unsafe { free_cstr(e) };
}

// ==================== FTP 凭据 / 密码 ====================

#[test]
fn test_derive_ftp_credentials_structure() {
    let secret = cstr("dGVzdHNlY3JldA==");
    let result = unsafe { ffi::utils::nrc_derive_ftp_credentials(secret) };
    let v: serde_json::Value = serde_json::from_str(&unsafe { read_cstr(result) }).unwrap();
    let username = v["username"].as_str().unwrap();
    let password = v["password"].as_str().unwrap();
    assert!(username.starts_with("ftp_"));
    assert!(!password.is_empty());
    // 确定性：相同密钥 → 相同凭据
    let r2 = unsafe { ffi::utils::nrc_derive_ftp_credentials(secret) };
    assert_eq!(unsafe { read_cstr(result) }, unsafe { read_cstr(r2) });
    unsafe {
        free_str(result);
        free_str(r2);
        free_cstr(secret);
    }
}

#[test]
fn test_derive_ftp_credentials_invalid_secret_returns_empty() {
    let secret = cstr("!!!not-base64!!!");
    let result = unsafe { ffi::utils::nrc_derive_ftp_credentials(secret) };
    let v: serde_json::Value = serde_json::from_str(&unsafe { read_cstr(result) }).unwrap();
    assert_eq!(v["username"], "");
    assert_eq!(v["password"], "");
    unsafe {
        free_str(result);
        free_cstr(secret);
    }
}

#[test]
fn test_derive_password_hash_deterministic() {
    let pw = cstr("mypassword");
    let r1 = unsafe { ffi::utils::nrc_derive_password_hash(pw) };
    let r2 = unsafe { ffi::utils::nrc_derive_password_hash(pw) };
    let s1 = unsafe { read_cstr(r1) };
    assert_eq!(s1, unsafe { read_cstr(r2) });
    assert!(!s1.is_empty());
    unsafe {
        free_str(r1);
        free_str(r2);
        free_cstr(pw);
    }
}

#[test]
fn test_generate_random_password_format() {
    let r1 = ffi::utils::nrc_generate_random_password();
    let r2 = ffi::utils::nrc_generate_random_password();
    let s1 = unsafe { read_cstr(r1) };
    let s2 = unsafe { read_cstr(r2) };
    assert_eq!(s1.len(), 12);
    assert_eq!(s2.len(), 12);
    assert_ne!(s1, s2);
    unsafe {
        free_str(r1);
        free_str(r2);
    }
}
