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

    // 本机信息（模拟 periodicBroadcast 写入本机 uuid/名称）
    assert_eq!(
        unsafe {
            ffi::nrc_periodic_broadcast(
                p1,
                1,
                cstr("local-test-uuid"),
                cstr("测试机"),
                -1,
                cstr("android"),
            )
        },
        0
    );

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

    // 本机 uuid 已落库（flush 时机已过）
    let uuid = unsafe { ffi::nrc_get_local_uuid(p1) };
    assert_eq!(unsafe { read_cstr(uuid) }, "local-test-uuid");
    unsafe { free_str(uuid) };

    // 库文件确实存在
    assert!(db.exists(), "持久化库未创建: {:?}", db);

    // ========== 模拟重启（新 ctx 重新加载）==========
    let ctx2 = create_ctx();
    let p2 = ctx_ptr(&ctx2);
    assert_eq!(ffi::nrc_ecdh_has_keypair(p2), 1, "重启后应恢复本机密钥对");
    let uuid2 = unsafe { ffi::nrc_get_local_uuid(p2) };
    assert_eq!(unsafe { read_cstr(uuid2) }, "local-test-uuid");
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
    assert_eq!(unsafe { ffi::nrc_remove_device(p2, cstr("peer-2")) }, 0);
    let uuid3 = unsafe { ffi::nrc_get_local_uuid(p2) };
    unsafe { free_str(uuid3) }; // 触发 flush（state 移除 peer-2、行删除）
    let ctx3 = create_ctx();
    let p3 = ctx_ptr(&ctx3);
    let list3 = unsafe { ffi::nrc_get_device_list(p3, 30_000, 10_000) };
    let list3_json = unsafe { read_cstr(list3) };
    unsafe { free_str(list3) };
    let v3: serde_json::Value = serde_json::from_str(&list3_json).unwrap();
    let arr3 = v3.as_array().unwrap();
    assert!(
        !arr3.iter().any(|x| x["uuid"] == "peer-2"),
        "删除配对后 peer-2 不应再出现: {}",
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

    // 清理临时库
    cleanup(&db);
    let _ = std::fs::remove_dir_all(&dir);
    unsafe { std::env::remove_var("NR_NOTIFY_CORE_DB_PATH") };
}
