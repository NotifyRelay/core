//! mDNS 发现专项语义测试（tests/ffi_mdns_discovery.rs）
//!
//! 发现机制已由 UDP 广播迁移到 mDNS（DNS-SD），本测试验证发现结果进入
//! 统一消费链后的语义，不依赖真实局域网组播，CI 可稳定执行：
//! 1. 消费链登记 registry（供设备列表读取）；
//! 2. 记录 device_ips（建连寻址来源）；
//! 3. 登记 known_devices（心跳调度器的目标来源）；
//! 4. 触发 on_device_discovered 平台回调。
//!
//! 自我过滤同属该链路：mDNS 组播会回环到本机，本机 uuid 的通告必须被忽略，
//! 否则会把自身登记为远程设备并占掉发现配额。

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::sync::Mutex;

use notify_relay_core::{ffi, CoreContext, SafeContext};

const LOCAL_UUID: &str = "local-mdns-self";
const PEER_UUID: &str = "peer-mdns-1";
const PEER_IP: &str = "192.168.31.200";
const PEER_PORT: u16 = 23333;

static CTX_SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// on_device_discovered 回调事件：(uuid, name, port, battery, device_type, ip)
type DiscoveredEvent = (String, String, u16, i32, String, String);

/// 记录 on_device_discovered 回调事件（回调为 extern "C"，无法捕获上下文）
static DISCOVERED: Mutex<Vec<DiscoveredEvent>> = Mutex::new(Vec::new());

/// 进程内已创建的临时库目录；进程退出时统一清理。
static CTX_DIRS: Mutex<Vec<std::path::PathBuf>> = Mutex::new(Vec::new());

/// 清理本进程及历史遗留的测试临时库目录。
fn prune_temp_dirs() {
    if let Ok(mut dirs) = CTX_DIRS.lock() {
        for dir in dirs.drain(..) {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
    let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.starts_with("nrctx_mdns_") {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// 注册进程退出清理（只注册一次）。
fn register_cleanup_once() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        extern "C" fn on_exit() {
            prune_temp_dirs();
        }
        // SAFETY: 回调只做文件删除，不访问其他全局状态
        unsafe { libc::atexit(on_exit) };
    });
}

fn create_ctx() -> SafeContext {
    let n = CTX_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("nrctx_mdns_{}_{}", std::process::id(), n));
    if let Ok(mut dirs) = CTX_DIRS.lock() {
        dirs.push(dir.clone());
    }
    register_cleanup_once();
    Mutex::new(CoreContext::with_db_override(dir.join("rust_core.db")))
}

fn ctx_ptr(ctx: &SafeContext) -> *mut c_void {
    ctx as *const SafeContext as *mut c_void
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

extern "C" fn on_device_discovered(
    uuid: *const c_char,
    name_b64: *const c_char,
    port: u16,
    battery: i32,
    device_type: *const c_char,
    ip: *const c_char,
    _user_data: *mut c_void,
) {
    DISCOVERED.lock().unwrap().push((
        unsafe { read_cstr(uuid) },
        unsafe { read_cstr(name_b64) },
        port,
        battery,
        unsafe { read_cstr(device_type) },
        unsafe { read_cstr(ip) },
    ));
}

fn device_list(ctx: &SafeContext, authed_ms: i64, unauthed_ms: i64) -> serde_json::Value {
    let r = unsafe { ffi::device_state::nrc_get_device_list(ctx_ptr(ctx), authed_ms, unauthed_ms) };
    let s = unsafe { read_cstr(r) };
    unsafe { free_str(r) };
    serde_json::from_str(&s).unwrap_or_else(|_| panic!("设备列表应为合法 JSON: {}", s))
}

/// 通过发现消费链登记一台对端，并断言 registry、device_ips、known_devices 与回调。
#[test]
fn mdns_discovery_registers_peer_through_consumer() {
    DISCOVERED.lock().unwrap().clear();

    let ctx = create_ctx();
    ffi::callbacks::nrc_set_on_device_discovered_cb(ctx_ptr(&ctx), Some(on_device_discovered));

    // 本机身份必须先就绪：消费链以 local_uuid 判定自我通告
    {
        let mut guard = ctx.lock().expect("取上下文锁");
        guard.local_uuid = LOCAL_UUID.to_string();
    }

    let name_b64 = {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        STANDARD.encode("Peer Device".as_bytes())
    };
    notify_relay_core::send::consume_discovered_device_for_test(
        &ctx, PEER_UUID, &name_b64, PEER_PORT, 66, "phone", PEER_IP,
    );

    // 1) registry 已登记且判定在线（发现即刷新 last_seen）
    let list = device_list(&ctx, 30000, 30000);
    let dev = list
        .as_array()
        .and_then(|arr| arr.iter().find(|d| d["uuid"] == PEER_UUID))
        .unwrap_or_else(|| panic!("发现结果应登记进设备列表: {}", list));
    assert_eq!(dev["ip"], PEER_IP);
    assert_eq!(dev["port"], PEER_PORT);
    assert_eq!(dev["deviceType"], "phone");
    assert_eq!(dev["online"], true, "刚发现的设备应判定在线");

    // 2) device_ips 与 known_devices 同步：前者供建连寻址，后者供心跳调度
    {
        let guard = ctx.lock().expect("取上下文锁");
        let ip = guard
            .device_ips
            .lock()
            .ok()
            .and_then(|m| m.get(PEER_UUID).cloned())
            .unwrap_or_default();
        assert_eq!(ip, PEER_IP, "device_ips 应记录发现来源地址");
        let known = guard.discovery.get_known_devices();
        assert!(
            known.contains_key(PEER_UUID),
            "known_devices 应包含新发现的设备，否则不会为它启动心跳"
        );
    }

    // 3) 平台回调已按统一语义上抛
    let evs = DISCOVERED.lock().unwrap();
    let ev = evs
        .iter()
        .find(|(u, _, _, _, _, _)| u == PEER_UUID)
        .unwrap_or_else(|| panic!("应收到 {} 的 on_device_discovered 回调", PEER_UUID));
    assert_eq!(ev.1, "Peer Device", "回调名称应为 base64 解码后的明文");
    assert_eq!(ev.2, PEER_PORT);
    assert_eq!(ev.3, 66);
    assert_eq!(ev.4, "phone");
    assert_eq!(ev.5, PEER_IP);
}

/// mDNS 组播会回环到本机，自身通告必须被忽略。
#[test]
fn mdns_discovery_ignores_self_announcement() {
    DISCOVERED.lock().unwrap().clear();

    let ctx = create_ctx();
    ffi::callbacks::nrc_set_on_device_discovered_cb(ctx_ptr(&ctx), Some(on_device_discovered));
    {
        let mut guard = ctx.lock().expect("取上下文锁");
        guard.local_uuid = LOCAL_UUID.to_string();
    }

    notify_relay_core::send::consume_discovered_device_for_test(
        &ctx, LOCAL_UUID, "", PEER_PORT, 80, "phone", PEER_IP,
    );

    assert!(
        DISCOVERED.lock().unwrap().is_empty(),
        "本机自身通告不得触发 on_device_discovered"
    );
    {
        let guard = ctx.lock().expect("取上下文锁");
        let known = guard.discovery.get_known_devices();
        assert!(
            !known.contains_key(LOCAL_UUID),
            "本机不得登记进 known_devices，否则会占掉发现配额"
        );
    }
}
