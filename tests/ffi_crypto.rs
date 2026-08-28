//! FFI 加密接口语义测试（nrc_ecdh_* / nrc_migrate_shared_secret / nrc_export_* / nrc_import_state / nrc_*_local_state）
//! 目的：保证 PC 与 Android 两个平台端共享的加密接口契约不变

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::sync::Mutex;

use base64::Engine;
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

// ==================== ECDH ====================

#[test]
fn test_ecdh_keypair_lifecycle() {
    let ctx = create_ctx();
    let ptr = ctx_ptr(&ctx);
    // 初始无密钥对
    assert_eq!(ffi::ecdh::nrc_ecdh_has_keypair(ptr), 0);
    assert!(ffi::ecdh::nrc_ecdh_get_public_key(ptr).is_null());
    // 生成密钥对
    assert_eq!(ffi::ecdh::nrc_ecdh_generate_keypair(ptr), 0);
    assert_eq!(ffi::ecdh::nrc_ecdh_has_keypair(ptr), 1);
    let pub_key = ffi::ecdh::nrc_ecdh_get_public_key(ptr);
    assert!(!pub_key.is_null());
    assert!(!unsafe { read_cstr(pub_key) }.is_empty());
    unsafe { free_str(pub_key) };
}

#[test]
fn test_ecdh_null_ctx_returns_default() {
    // with_ctx 对 null 指针返回默认值，不崩溃
    assert_eq!(
        ffi::ecdh::nrc_ecdh_generate_keypair(std::ptr::null_mut()),
        0
    );
    assert_eq!(ffi::ecdh::nrc_ecdh_has_keypair(std::ptr::null_mut()), 0);
}

#[test]
fn test_ecdh_shared_secret_agreement() {
    let ctx_a = create_ctx();
    let ctx_b = create_ctx();
    let a = ctx_ptr(&ctx_a);
    let b = ctx_ptr(&ctx_b);
    assert_eq!(ffi::ecdh::nrc_ecdh_generate_keypair(a), 0);
    assert_eq!(ffi::ecdh::nrc_ecdh_generate_keypair(b), 0);

    let pub_a = ffi::ecdh::nrc_ecdh_get_public_key(a);
    let pub_b = ffi::ecdh::nrc_ecdh_get_public_key(b);
    let uuid_a = cstr("peer-b");
    let uuid_b = cstr("peer-a");

    assert_eq!(
        unsafe { ffi::ecdh::nrc_ecdh_derive_shared_secret(a, uuid_a, pub_b) },
        0
    );
    assert_eq!(
        unsafe { ffi::ecdh::nrc_ecdh_derive_shared_secret(b, uuid_b, pub_a) },
        0
    );

    // 双方各自导出的 AES key 必须一致（两平台端协商一致性的核心契约）
    let exp_a = unsafe { ffi::key_management::nrc_export_device_key(a, uuid_a) };
    let exp_b = unsafe { ffi::key_management::nrc_export_device_key(b, uuid_b) };
    let json_a: serde_json::Value = serde_json::from_str(&unsafe { read_cstr(exp_a) }).unwrap();
    let json_b: serde_json::Value = serde_json::from_str(&unsafe { read_cstr(exp_b) }).unwrap();
    assert_eq!(json_a["aes_key_b64"], json_b["aes_key_b64"]);
    // 远端公钥被记录
    assert_eq!(json_a["remote_pub_key"], unsafe { read_cstr(pub_b) });

    unsafe {
        free_str(exp_a);
        free_str(exp_b);
        free_str(pub_a);
        free_str(pub_b);
        free_cstr(uuid_a);
        free_cstr(uuid_b);
    }
}

#[test]
fn test_ecdh_derive_shared_secret_errors() {
    let ctx = create_ctx();
    let ptr = ctx_ptr(&ctx);
    let uuid = cstr("peer");
    let bad_pub = cstr("garbage-not-base64");

    // 无密钥对 → -1
    assert_eq!(
        unsafe { ffi::ecdh::nrc_ecdh_derive_shared_secret(ptr, uuid, bad_pub) },
        -1
    );

    // 有密钥对但公钥非法 base64 → -1
    assert_eq!(ffi::ecdh::nrc_ecdh_generate_keypair(ptr), 0);
    assert_eq!(
        unsafe { ffi::ecdh::nrc_ecdh_derive_shared_secret(ptr, uuid, bad_pub) },
        -1
    );

    // 合法 base64 但非有效 P-256 公钥 → -1
    let invalid_pub = cstr("AAAA");
    assert_eq!(
        unsafe { ffi::ecdh::nrc_ecdh_derive_shared_secret(ptr, uuid, invalid_pub) },
        -1
    );

    unsafe {
        free_cstr(uuid);
        free_cstr(bad_pub);
        free_cstr(invalid_pub);
    }
}

// ==================== 共享密钥迁移 ====================

#[test]
fn test_migrate_shared_secret() {
    let ctx = create_ctx();
    let ptr = ctx_ptr(&ctx);
    let uuid = cstr("device-1");
    let key = [9u8; 32];

    // 长度非 32 或为 0 → -1
    assert_eq!(
        unsafe { ffi::key_management::nrc_migrate_shared_secret(ptr, uuid, key.as_ptr(), 16) },
        -1
    );
    assert_eq!(
        unsafe { ffi::key_management::nrc_migrate_shared_secret(ptr, uuid, key.as_ptr(), 0) },
        -1
    );

    // 正确 32 字节 → 0，导出可验证
    assert_eq!(
        unsafe { ffi::key_management::nrc_migrate_shared_secret(ptr, uuid, key.as_ptr(), 32) },
        0
    );
    let exp = unsafe { ffi::key_management::nrc_export_device_key(ptr, uuid) };
    let json: serde_json::Value = serde_json::from_str(&unsafe { read_cstr(exp) }).unwrap();
    assert_eq!(
        json["aes_key_b64"],
        serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(key))
    );

    unsafe {
        free_str(exp);
        free_cstr(uuid);
    }
}

#[test]
fn test_export_device_key_unknown_returns_null() {
    let ctx = create_ctx();
    let ptr = ctx_ptr(&ctx);
    let uuid = cstr("unknown-device");
    assert!(unsafe { ffi::key_management::nrc_export_device_key(ptr, uuid) }.is_null());
    unsafe { free_cstr(uuid) };
}

#[test]
fn test_remove_device_clears_key() {
    let ctx = create_ctx();
    let ptr = ctx_ptr(&ctx);
    let uuid = cstr("device-1");
    let key = [3u8; 32];
    assert_eq!(
        unsafe { ffi::key_management::nrc_migrate_shared_secret(ptr, uuid, key.as_ptr(), 32) },
        0
    );
    assert!(!unsafe { ffi::key_management::nrc_export_device_key(ptr, uuid) }.is_null());
    assert_eq!(
        unsafe { ffi::key_management::nrc_remove_device(ptr, uuid) },
        0
    );
    assert!(unsafe { ffi::key_management::nrc_export_device_key(ptr, uuid) }.is_null());
    unsafe { free_cstr(uuid) };
}

// ==================== 状态导出 / 导入 ====================

#[test]
fn test_export_import_state_roundtrip() {
    let ctx_a = create_ctx();
    let ctx_b = create_ctx();
    let a = ctx_ptr(&ctx_a);
    let b = ctx_ptr(&ctx_b);

    // A：生成密钥对 + 迁移设备密钥
    assert_eq!(ffi::ecdh::nrc_ecdh_generate_keypair(a), 0);
    let uuid = cstr("device-1");
    let key = [7u8; 32];
    assert_eq!(
        unsafe { ffi::key_management::nrc_migrate_shared_secret(a, uuid, key.as_ptr(), 32) },
        0
    );

    // 导出状态 JSON
    let state = ffi::key_management::nrc_export_state(a);
    let json = unsafe { read_cstr(state) };
    assert!(json.contains("local_private_key_pem"));
    assert!(json.contains("local_public_key_b64"));
    unsafe { free_str(state) };

    // 导入到 B
    let json_c = CString::new(json).unwrap();
    assert_eq!(
        unsafe { ffi::key_management::nrc_import_state(b, json_c.as_ptr()) },
        0
    );
    assert_eq!(ffi::ecdh::nrc_ecdh_has_keypair(b), 1);

    // B 与 A 的本地公钥一致（私钥随状态迁移）
    let pub_a = ffi::ecdh::nrc_ecdh_get_public_key(a);
    let pub_b = ffi::ecdh::nrc_ecdh_get_public_key(b);
    assert_eq!(unsafe { read_cstr(pub_a) }, unsafe { read_cstr(pub_b) });

    // 设备密钥一致
    let exp_a = unsafe { ffi::key_management::nrc_export_device_key(a, uuid) };
    let exp_b = unsafe { ffi::key_management::nrc_export_device_key(b, uuid) };
    let ja: serde_json::Value = serde_json::from_str(&unsafe { read_cstr(exp_a) }).unwrap();
    let jb: serde_json::Value = serde_json::from_str(&unsafe { read_cstr(exp_b) }).unwrap();
    assert_eq!(ja["aes_key_b64"], jb["aes_key_b64"]);

    unsafe {
        free_str(pub_a);
        free_str(pub_b);
        free_str(exp_a);
        free_str(exp_b);
        free_cstr(uuid);
    }
}

#[test]
fn test_import_state_invalid_json_fails() {
    let ctx = create_ctx();
    let ptr = ctx_ptr(&ctx);
    let bad = cstr("not-json-at-all");
    assert_eq!(
        unsafe { ffi::key_management::nrc_import_state(ptr, bad) },
        -1
    );
    unsafe { free_cstr(bad) };
}

// ==================== 本地状态加密 ====================

#[test]
fn test_local_state_encrypt_decrypt_roundtrip() {
    let ctx = create_ctx();
    let ptr = ctx_ptr(&ctx);
    let uuid = cstr("device-1");
    let plain = cstr("hello-local-state-中文");

    let enc = unsafe { ffi::key_management::nrc_encrypt_local_state(ptr, plain, uuid) };
    assert!(!enc.is_null());
    let enc_c = CString::new(unsafe { read_cstr(enc) }).unwrap();
    unsafe { free_str(enc) };

    let dec = unsafe { ffi::key_management::nrc_decrypt_local_state(ptr, enc_c.as_ptr(), uuid) };
    assert_eq!(unsafe { read_cstr(dec) }, "hello-local-state-中文");
    unsafe { free_str(dec) };

    // 同一明文不同 nonce 加密，仍可解出相同明文
    let enc2 = unsafe { ffi::key_management::nrc_encrypt_local_state(ptr, plain, uuid) };
    let enc2_c = CString::new(unsafe { read_cstr(enc2) }).unwrap();
    unsafe { free_str(enc2) };
    let dec2 = unsafe { ffi::key_management::nrc_decrypt_local_state(ptr, enc2_c.as_ptr(), uuid) };
    assert_eq!(unsafe { read_cstr(dec2) }, "hello-local-state-中文");
    unsafe { free_str(dec2) };

    unsafe {
        free_cstr(uuid);
        free_cstr(plain);
    }
}

#[test]
fn test_decrypt_local_state_tampered_fails() {
    let ctx = create_ctx();
    let ptr = ctx_ptr(&ctx);
    let uuid = cstr("device-1");
    let plain = cstr("secret");

    let enc = unsafe { ffi::key_management::nrc_encrypt_local_state(ptr, plain, uuid) };
    let mut enc_bytes = unsafe { read_cstr(enc) }.into_bytes();
    unsafe { free_str(enc) };
    // 篡改 ciphertext 段（前 16 字符为 nonce 的 base64）
    enc_bytes[20] = if enc_bytes[20] == b'A' { b'B' } else { b'A' };
    let tampered = CString::new(enc_bytes).unwrap();
    assert!(
        unsafe { ffi::key_management::nrc_decrypt_local_state(ptr, tampered.as_ptr(), uuid) }
            .is_null()
    );

    unsafe {
        free_cstr(uuid);
        free_cstr(plain);
    }
}

#[test]
fn test_decrypt_local_state_invalid_ciphertext_fails() {
    let ctx = create_ctx();
    let ptr = ctx_ptr(&ctx);
    let uuid = cstr("device-1");
    let bad = cstr("AA");
    assert!(unsafe { ffi::key_management::nrc_decrypt_local_state(ptr, bad, uuid) }.is_null());
    unsafe {
        free_cstr(uuid);
        free_cstr(bad);
    }
}
