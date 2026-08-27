//! FFI 持久化语义测试（nrc_get_local_uuid / nrc_rename_device / get_device_list 数据源）
//! 目的：验证私有库自动定位（环境变量注入）、自动落盘、重启恢复语义
//!
//! 注意：单个 test 函数内端到端编排（环境变量为进程级，避免并发测试竞争）

use std::ffi::{CStr, CString};
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

fn db_path_env() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("nrc_persist_test_{}", std::process::id()))
}

fn cleanup(path: &std::path::Path) {
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(path.to_string_lossy().to_string() + suffix);
    }
}

#[test]
fn test_persistence_full_flow() {
    let dir = db_path_env();
    let db = dir.join("rust_core.db");
    // 清理历史残留（损坏库也一并处理）
    cleanup(&db);
    let _ = std::fs::remove_dir_all(&dir);

    // 注入测试库路径
    unsafe {
        std::env::set_var("NR_NOTIFY_CORE_DB_PATH", db.to_string_lossy().as_ref());
    }

    // ========== 首次启动（全新库）==========
    let ctx1 = create_ctx();
    let p1 = ctx_ptr(&ctx1);

    // 全新安装：库不存在 → 无密钥
    assert_eq!(ffi::nrc_ecdh_has_keypair(p1), 0);
    // 生成密钥对
    assert_eq!(ffi::nrc_ecdh_generate_keypair(p1), 0);
    assert_eq!(ffi::nrc_ecdh_has_keypair(p1), 1);
    let pub1 = ffi::nrc_ecdh_get_public_key(p1);
    let pub1_str = unsafe { read_cstr(pub1) };
    unsafe { free_str(pub1) };
    assert!(!pub1_str.is_empty());

    // 本机 UUID 由 Rust 生成/持有：无平台侧注入，读取即自动生成并落库
    let uuid = unsafe { ffi::nrc_get_local_uuid(p1) };
    let uuid1 = unsafe { read_cstr(uuid) };
    unsafe { free_str(uuid) };
    assert!(!uuid1.is_empty(), "Rust 应自动生成本机 UUID");

    // 对端设备（peer-1）：先有名字（rename），再派生密钥（模拟迁移顺序）
    assert_eq!(
        unsafe { ffi::nrc_rename_device(p1, cstr("peer-1"), cstr("小米手机")) },
        0
    );
    // peer-2 派生密钥（对端公钥：用另一 ctx 生成的真实公钥）
    let ctx_peer = create_ctx();
    ffi::nrc_ecdh_generate_keypair(ctx_ptr(&ctx_peer));
    let peer_pub = ffi::nrc_ecdh_get_public_key(ctx_ptr(&ctx_peer));
    let peer_pub_str = unsafe { read_cstr(peer_pub) };
    unsafe { free_str(peer_pub) };
    assert_eq!(
        unsafe { ffi::nrc_ecdh_derive_shared_secret(p1, cstr("peer-2"), cstr(&peer_pub_str)) },
        0
    );

    // get_device_list 读取（触发自动落盘）
    let list = unsafe { ffi::nrc_get_device_list(p1, 30_000, 10_000) };
    let list_json = unsafe { read_cstr(list) };
    unsafe { free_str(list) };
    let v: serde_json::Value = serde_json::from_str(&list_json).unwrap();
    let arr = v.as_array().unwrap();
    assert!(
        arr.iter()
            .any(|x| x["uuid"] == "peer-2" && x["paired"] == true),
        "派生密钥后设备应出现在列表: {}",
        list_json
    );
    assert!(
        arr.iter()
            .any(|x| x["uuid"] == "peer-1" && x["name"] == "小米手机"),
        "改名设备应带名称出现在列表: {}",
        list_json
    );

    // 读取幂等：再次获取的 UUID 与首次一致
    let uuid_dup = unsafe { ffi::nrc_get_local_uuid(p1) };
    assert_eq!(unsafe { read_cstr(uuid_dup) }, uuid1);
    unsafe { free_str(uuid_dup) };

    // 库文件确实存在
    assert!(db.exists(), "持久化库未创建: {:?}", db);

    // ========== 模拟重启（新 ctx 重新加载）==========
    let ctx2 = create_ctx();
    let p2 = ctx_ptr(&ctx2);
    assert_eq!(ffi::nrc_ecdh_has_keypair(p2), 1, "重启后应恢复本机密钥对");
    let uuid2 = unsafe { ffi::nrc_get_local_uuid(p2) };
    assert_eq!(unsafe { read_cstr(uuid2) }, uuid1, "重启后 UUID 应稳定");
    unsafe { free_str(uuid2) };
    let list2 = unsafe { ffi::nrc_get_device_list(p2, 30_000, 10_000) };
    let list2_json = unsafe { read_cstr(list2) };
    unsafe { free_str(list2) };
    let v2: serde_json::Value = serde_json::from_str(&list2_json).unwrap();
    let arr2 = v2.as_array().unwrap();
    assert!(
        arr2.iter()
            .any(|x| x["uuid"] == "peer-2" && x["paired"] == true),
        "重启后 peer-2 密钥应恢复: {}",
        list2_json
    );
    assert!(
        arr2.iter()
            .any(|x| x["uuid"] == "peer-1" && x["name"] == "小米手机"),
        "重启后 peer-1 名称应恢复: {}",
        list2_json
    );
    // 迁移通道：state 明文（等价于平台旧 blob 解密结果）可用并二次导入不丢失
    let exported = ffi::nrc_export_state(p2);
    let exported_str = unsafe { read_cstr(exported) };
    unsafe { free_str(exported) };
    assert!(!exported_str.is_empty());
    assert_eq!(unsafe { ffi::nrc_import_state(p2, cstr(&exported_str)) }, 0);

    // ========== 删除配对：内存/库/列表联动 ==========
    // remove 内部立即落盘（state 重写 + 行删除），此后不调用任何接口直接重启
    assert_eq!(unsafe { ffi::nrc_remove_device(p2, cstr("peer-2")) }, 0);
    let ctx3 = create_ctx();
    let p3 = ctx_ptr(&ctx3);
    let list3 = unsafe { ffi::nrc_get_device_list(p3, 30_000, 10_000) };
    let list3_json = unsafe { read_cstr(list3) };
    unsafe { free_str(list3) };
    let v3: serde_json::Value = serde_json::from_str(&list3_json).unwrap();
    let arr3 = v3.as_array().unwrap();
    assert!(
        !arr3.iter().any(|x| x["uuid"] == "peer-2"),
        "删除配对后（立即重启）peer-2 不应再出现: {}",
        list3_json
    );
    // peer-1 名称仍在（未删除）
    assert!(arr3.iter().any(|x| x["uuid"] == "peer-1"));

    // 删除设备行验证（库级）
    let ctx4 = create_ctx();
    unsafe { ffi::nrc_remove_device(ctx_ptr(&ctx4), cstr("peer-1")) };
    unsafe {
        ffi::nrc_get_local_uuid(ctx_ptr(&ctx4));
    }
    drop(ctx1);
    drop(ctx2);
    drop(ctx3);
    drop(ctx4);

    // ===== 专项：首次配对（库不存在）密钥即时落盘 =====
    // 全新库 + generate + derive 后不做任何 flush/读取，直接“重启”即恢复密钥
    cleanup(&db);
    let _ = std::fs::remove_dir_all(&dir);
    let ctx_a = create_ctx();
    assert_eq!(ffi::nrc_ecdh_generate_keypair(ctx_ptr(&ctx_a)), 0);
    let ctx_peer2 = create_ctx();
    ffi::nrc_ecdh_generate_keypair(ctx_ptr(&ctx_peer2));
    let peer_pub2 = ffi::nrc_ecdh_get_public_key(ctx_ptr(&ctx_peer2));
    let peer_pub2_str = unsafe { read_cstr(peer_pub2) };
    unsafe { free_str(peer_pub2) };
    assert_eq!(
        unsafe {
            ffi::nrc_ecdh_derive_shared_secret(
                ctx_ptr(&ctx_a),
                cstr("peer-fresh"),
                cstr(&peer_pub2_str),
            )
        },
        0
    );
    // 无任何中间调用：库不存在时配对行已直接落库
    assert!(db.exists(), "首次配对应即时创建持久化库");
    let ctx_b = create_ctx();
    let key_json = unsafe { ffi::nrc_export_device_key(ctx_ptr(&ctx_b), cstr("peer-fresh")) };
    let key_str = unsafe { read_cstr(key_json) };
    unsafe { free_str(key_json) };
    assert!(!key_str.is_empty(), "库不存在时配对密钥应即时落盘可恢复");
    let key_json: serde_json::Value = serde_json::from_str(&key_str).unwrap_or_default();
    let aes = key_json
        .get("aes_key_b64")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert!(
        !aes.is_empty(),
        "恢复的密钥行应包含有效 AES 密钥；(行 uuid=peer-fresh)"
    );
    drop(ctx_a);
    drop(ctx_b);
    drop(ctx_peer2);

    // 清理临时库
    cleanup(&db);
    let _ = std::fs::remove_dir_all(&dir);
    unsafe { std::env::remove_var("NR_NOTIFY_CORE_DB_PATH") };
}
