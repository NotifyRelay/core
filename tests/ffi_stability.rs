//! FFI 接口稳定性测试：反复调用、组合流程、多线程并发下的稳定工作（不崩溃、状态一致）
//! 目的：保证 PC 与 Android 两个平台端共享的接口不仅语义不变，且在真实调用场景下可靠运行

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::sync::Mutex;
use std::thread;

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

fn get_pub_key(ctx: &SafeContext) -> String {
    let p = ffi::ecdh::nrc_ecdh_get_public_key(ctx_ptr(ctx));
    let s = unsafe { read_cstr(p) };
    unsafe { free_str(p) };
    s
}

fn export_key_json(ctx: &SafeContext, uuid: &str) -> Option<serde_json::Value> {
    let u = cstr(uuid);
    let p = unsafe { ffi::key_management::nrc_export_device_key(ctx_ptr(ctx), u) };
    unsafe { free_cstr(u) };
    if p.is_null() {
        return None;
    }
    let v = serde_json::from_str(&unsafe { read_cstr(p) }).ok();
    unsafe { free_str(p) };
    v
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

fn device_list(ctx: &SafeContext, authed_ms: i64, unauthed_ms: i64) -> serde_json::Value {
    let r = unsafe { ffi::device_state::nrc_get_device_list(ctx_ptr(ctx), authed_ms, unauthed_ms) };
    let s = unsafe { read_cstr(r) };
    unsafe { free_str(r) };
    serde_json::from_str(&s).unwrap_or_else(|_| panic!("设备列表应为合法 JSON: {}", s))
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

// ==================== 反复调用稳定 ====================

#[test]
fn test_ecdh_repeated_generation_stable() {
    let ctx = create_ctx();
    let ptr = ctx_ptr(&ctx);
    for _ in 0..100 {
        assert_eq!(ffi::ecdh::nrc_ecdh_generate_keypair(ptr), 0);
        assert_eq!(ffi::ecdh::nrc_ecdh_has_keypair(ptr), 1);
        assert!(!get_pub_key(&ctx).is_empty());
    }
}

#[test]
fn test_ecdh_negotiation_rounds_stable() {
    // 多轮完整协商，双方密钥始终一致且为合法 32 字节 AES key
    for round in 0..5 {
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
        let exp_a = export_key_json(&ctx_a, "peer-b").unwrap();
        let exp_b = export_key_json(&ctx_b, "peer-a").unwrap();
        assert_eq!(
            exp_a["aes_key_b64"], exp_b["aes_key_b64"],
            "第 {} 轮协商密钥不一致",
            round
        );
        // 协商产物必须是合法 32 字节密钥（可直接用于 AES）
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(exp_a["aes_key_b64"].as_str().unwrap())
            .unwrap();
        assert_eq!(decoded.len(), 32);
        unsafe {
            free_str(pub_a);
            free_str(pub_b);
            free_cstr(uuid_a);
            free_cstr(uuid_b);
        }
    }
}

#[test]
fn test_key_lifecycle_loop_stable() {
    let ctx = create_ctx();
    let ptr = ctx_ptr(&ctx);
    let uuid = cstr("dev-loop");
    let key = [5u8; 32];
    for _ in 0..100 {
        assert_eq!(
            unsafe { ffi::key_management::nrc_migrate_shared_secret(ptr, uuid, key.as_ptr(), 32) },
            0
        );
        assert!(export_key_json(&ctx, "dev-loop").is_some());
    }
    // 最终可正常移除
    assert_eq!(
        unsafe { ffi::key_management::nrc_remove_device(ptr, uuid) },
        0
    );
    assert!(export_key_json(&ctx, "dev-loop").is_none());
    unsafe { free_cstr(uuid) };
}

#[test]
fn test_state_export_import_loop_stable() {
    let ctx_a = create_ctx();
    let ctx_b = create_ctx();
    let a = ctx_ptr(&ctx_a);
    let b = ctx_ptr(&ctx_b);
    let uuid = cstr("dev-1");
    let key = [7u8; 32];
    for _ in 0..20 {
        assert_eq!(ffi::ecdh::nrc_ecdh_generate_keypair(a), 0);
        assert_eq!(
            unsafe { ffi::key_management::nrc_migrate_shared_secret(a, uuid, key.as_ptr(), 32) },
            0
        );
        let state = ffi::key_management::nrc_export_state(a);
        let json = unsafe { read_cstr(state) };
        unsafe { free_str(state) };
        let json_c = CString::new(json).unwrap();
        assert_eq!(
            unsafe { ffi::key_management::nrc_import_state(b, json_c.as_ptr()) },
            0
        );
        // 导入后 B 的本地公钥与 A 一致（私钥随状态稳定迁移）
        assert_eq!(ffi::ecdh::nrc_ecdh_has_keypair(b), 1);
        let pub_a = ffi::ecdh::nrc_ecdh_get_public_key(a);
        let pub_b = ffi::ecdh::nrc_ecdh_get_public_key(b);
        assert_eq!(unsafe { read_cstr(pub_a) }, unsafe { read_cstr(pub_b) });
        unsafe {
            free_str(pub_a);
            free_str(pub_b);
        }
    }
    unsafe { free_cstr(uuid) };
}

#[test]
fn test_device_known_loop_stable() {
    let ctx = create_ctx();
    for i in 0..50 {
        add_known(&ctx, &format!("dev-{}", i % 5), "192.168.1.10");
    }
    // 去重后共 5 个设备
    let list = device_list(&ctx, 30000, 30000);
    assert_eq!(list.as_array().unwrap().len(), 5);
    // 连续查询结果幂等
    for _ in 0..20 {
        assert_eq!(device_list(&ctx, 30000, 30000), list);
    }
    // 全部移除后为空
    for i in 0..5 {
        remove_known(&ctx, &format!("dev-{}", i));
    }
    assert_eq!(device_list(&ctx, 30000, 30000).as_array().unwrap().len(), 0);
}

#[test]
fn test_dedup_high_frequency_stable() {
    let ctx = create_ctx();
    let ptr = ctx_ptr(&ctx);
    let key = cstr("hot-key");
    let mut sent_count = 0;
    for i in 0..1000 {
        if unsafe { ffi::utils::nrc_dedup(ptr, 0, key, 60000, 0) } == 1 {
            sent_count += 1;
        }
        if i % 2 == 1 {
            assert_eq!(unsafe { ffi::utils::nrc_dedup(ptr, 2, key, 0, 0) }, 0);
        }
    }
    // 每两轮至少一次可发送（偶数轮 check 成功、奇数轮被 pending 阻断后清除）
    assert_eq!(sent_count, 500);
    unsafe { free_cstr(key) };
}

#[test]
fn test_state_merge_continuous_push_stable() {
    let ctx = create_ctx();
    let queue_handle = make_queue_handle();
    for i in 0..50 {
        let state = format!(
            r#"{{"featureId":"f{}","title":"t{}","text":"c{}"}}"#,
            i, i, i
        );
        assert_eq!(
            push_superisland(&ctx, queue_handle, "dev-1", &state, 0, 0),
            0,
            "第 {} 次推送失败",
            i
        );
    }
    // is_end 交替收尾稳定
    let full = r#"{"featureId":"end","title":"t","text":"c"}"#;
    for i in 0..20 {
        assert_eq!(
            push_superisland(&ctx, queue_handle, "dev-1", full, i % 2, 0),
            0
        );
    }
}

// ==================== 多线程并发稳定 ====================

#[test]
fn test_concurrent_handle_put_take_stable() {
    // 句柄表为全局共享（ffi_handle.rs 已单独验证 count 语义），此处验证并发 put/get/take 正确性
    let handles: Vec<u64> = (0..8)
        .map(|_| {
            let dummy: u8 = 1;
            let ptr = (&dummy as *const u8 as *mut u8) as *mut c_void;
            ffi::handle::put(ptr)
        })
        .collect();
    let mut threads = Vec::new();
    for _ in 0..8 {
        threads.push(thread::spawn(|| {
            for _ in 0..200 {
                let dummy: u8 = 2;
                let ptr = (&dummy as *const u8 as *mut u8) as *mut c_void;
                let h = ffi::handle::put(ptr);
                assert!(!ffi::handle::get(h).is_null());
                ffi::handle::take(h);
            }
        }));
    }
    for t in threads {
        t.join().unwrap();
    }
    for h in handles {
        // 清理（指针指向已销毁的栈变量，仅 take 不 deref）
        assert!(!ffi::handle::take(h).is_null());
    }
}

#[test]
fn test_concurrent_dedup_distinct_keys_stable() {
    // 每线程独立 ctx（core 假定同一 ctx 的调用由调用方串行化，跨线程各自 ctx 并发）
    let mut threads = Vec::new();
    for t in 0..8 {
        threads.push(thread::spawn(move || {
            let ctx = create_ctx();
            let ptr = ctx_ptr(&ctx);
            let key = cstr(&format!("thread-key-{}", t));
            for _ in 0..100 {
                assert_eq!(unsafe { ffi::utils::nrc_dedup(ptr, 0, key, 60000, 0) }, 1);
                assert_eq!(unsafe { ffi::utils::nrc_dedup(ptr, 0, key, 60000, 0) }, 0);
                assert_eq!(unsafe { ffi::utils::nrc_dedup(ptr, 2, key, 0, 0) }, 0);
            }
            unsafe { free_cstr(key) };
        }));
    }
    for t in threads {
        t.join().unwrap();
    }
}

#[test]
fn test_concurrent_clipboard_received_stable() {
    let mut threads = Vec::new();
    for t in 0..8 {
        threads.push(thread::spawn(move || {
            let ctx = create_ctx();
            let ptr = ctx_ptr(&ctx);
            let payload = cstr(&format!(
                r#"{{"clipboardType":"text/plain","content":"c{}"}}"#,
                t
            ));
            for _ in 0..50 {
                let r = unsafe { ffi::clipboard::nrc_clipboard_on_received(ptr, payload, 1000) };
                let v: serde_json::Value = serde_json::from_str(&unsafe { read_cstr(r) }).unwrap();
                assert_eq!(v["type"], "text");
                assert_eq!(v["content"], format!("c{}", t));
                unsafe { free_str(r) };
            }
            unsafe { free_cstr(payload) };
        }));
    }
    for t in threads {
        t.join().unwrap();
    }
}

#[test]
fn test_concurrent_filter_check_stable() {
    let mut threads = Vec::new();
    for _ in 0..8 {
        threads.push(thread::spawn(move || {
            let ctx = create_ctx();
            let j = cstr(r#"{"filterMode":1,"filterList":["com.allowed"]}"#);
            assert_eq!(
                unsafe {
                    ffi::filter::nrc_set_filter_config(
                        &ctx as *const SafeContext as *mut SafeContext,
                        j,
                    )
                },
                0
            );
            unsafe { free_cstr(j) };
            let ptr = &ctx as *const SafeContext as *mut SafeContext;
            let pkg = cstr("com.allowed");
            let empty = cstr("");
            for _ in 0..100 {
                assert_eq!(
                    unsafe { ffi::filter::nrc_check_filter_mode(ptr, pkg, empty, empty, empty) },
                    1
                );
            }
            unsafe {
                free_cstr(pkg);
                free_cstr(empty);
            }
        }));
    }
    for t in threads {
        t.join().unwrap();
    }
}

#[test]
fn test_concurrent_migrate_distinct_devices_stable() {
    let mut threads = Vec::new();
    for t in 0..8 {
        threads.push(thread::spawn(move || {
            let ctx = create_ctx();
            let ptr = ctx_ptr(&ctx);
            let key = [t as u8; 32];
            let uuid = cstr(&format!("concurrent-dev-{}", t));
            for _ in 0..100 {
                assert_eq!(
                    unsafe {
                        ffi::key_management::nrc_migrate_shared_secret(ptr, uuid, key.as_ptr(), 32)
                    },
                    0
                );
            }
            // 各线程密钥保持各自值
            let exp = export_key_json(&ctx, &format!("concurrent-dev-{}", t)).unwrap();
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(exp["aes_key_b64"].as_str().unwrap())
                .unwrap();
            assert_eq!(decoded, vec![t as u8; 32]);
            unsafe { free_cstr(uuid) };
        }));
    }
    for t in threads {
        t.join().unwrap();
    }
}
