//! UDP 广播发现专项语义测试（tests/ffi_udp_discovery.rs）
//!
//! 目的：验证 `nrc_periodic_broadcast(action=1)` 启动的 UDP 广播发现线程能够
//! 1. 绑定 UDP 广播端口（UDP_BROADCAST_PORT = 23334）持续监听；
//! 2. 收到对端设备的「发现行」广播后走统一消费链：
//!    registry 登记 + device_ips 记录 + `on_device_discovered` 平台回调。
//!
//! 实现方式：通过向本机 127.0.0.1:23334 发送一条与 codec::encode_discovery_request
//! 相同格式的文本行来模拟对端设备广播，不依赖真实局域网广播域，CI 可稳定执行。
//! 本文件刻意只含一个 #[test]：监听端口为固定 23334，避免同进程并行测试互相抢占端口。

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::sync::Mutex;
use std::time::Duration;

use notify_relay_core::{ffi, CoreContext, SafeContext};

/// 与 src/network/mod.rs 的 UDP_BROADCAST_PORT 保持一致
const UDP_DISC_PORT: u16 = 23334;
const LOCAL_UUID: &str = "local-udp-self";
const PEER_UUID: &str = "peer-udp-1";

static CTX_SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// on_device_discovered 回调事件：(uuid, name_b64, port, battery, device_type, ip)
type DiscoveredEvent = (String, String, u16, i32, String, String);

/// 记录 on_device_discovered 回调事件的全局容器（回调为 extern "C"，无法捕获上下文）
static DISCOVERED: Mutex<Vec<DiscoveredEvent>> = Mutex::new(Vec::new());

fn create_ctx() -> SafeContext {
    let n = CTX_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let p = std::env::temp_dir()
        .join(format!("nrctx_udp_{}_{}", std::process::id(), n))
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

unsafe fn free_cstr(p: *const c_char) {
    if !p.is_null() {
        drop(CString::from_raw(p as *mut c_char));
    }
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

#[test]
fn test_udp_discovery_receives_peer_broadcast() {
    DISCOVERED.lock().unwrap().clear();

    let ctx = create_ctx();
    ffi::callbacks::nrc_set_on_device_discovered_cb(ctx_ptr(&ctx), Some(on_device_discovered));

    // 1) 以本机身份启动 UDP 广播发现（action=1：周期广播本机信息 + 监听对端广播）
    let u = cstr(LOCAL_UUID);
    let nm = cstr("LocalSelf");
    let ty = cstr("phone");
    let rc = unsafe { ffi::send::nrc_periodic_broadcast(ctx_ptr(&ctx), 1, u, nm, 80, ty) };
    unsafe {
        free_cstr(u);
        free_cstr(nm);
        free_cstr(ty);
    }
    assert_eq!(
        rc, 0,
        "nrc_periodic_broadcast(action=1) 应成功启动 UDP 广播发现线程"
    );

    // 2) 模拟对端设备：周期向本机 UDP 广播端口发送「发现行」
    //    （格式与 codec::encode_discovery_request 相同：uuid:name_b64:port:battery:device_type，
    //     此处 name_b64 置空等价于 base64("")）
    let peer_line = format!("{}::23333:80:phone", PEER_UUID);
    let sender = std::net::UdpSocket::bind("0.0.0.0:0").expect("绑定测试 UDP 发送 socket 失败");

    // 3) 轮询等待发现线程完成绑定并消费广播（上限 5s：绑定 + 首条广播 + 登记回调足够）
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut listed = false;
    while std::time::Instant::now() < deadline {
        let _ = sender.send_to(peer_line.as_bytes(), ("127.0.0.1", UDP_DISC_PORT));
        std::thread::sleep(Duration::from_millis(50));

        let list = device_list(&ctx, 30000, 30000);
        if let Some(dev) = list
            .as_array()
            .and_then(|arr| arr.iter().find(|d| d["uuid"] == PEER_UUID))
        {
            // 4) 断言登记结果：来源 IP 为环回地址、端口为载荷携带的 TCP 端口
            assert_eq!(
                dev["ip"], "127.0.0.1",
                "UDP 广播来源 IP 应为发送端 127.0.0.1"
            );
            assert_eq!(dev["port"], 23333, "应登记对端 TCP 数据端口");
            assert_eq!(dev["deviceType"], "phone");
            assert_eq!(dev["online"], true, "刚广播的对端应判定在线");
            listed = true;
            break;
        }
    }
    assert!(listed, "5s 内应通过 UDP 广播发现并登记设备 {}", PEER_UUID);

    // 5) 断言 on_device_discovered 平台回调已触发（走统一消费链）
    let evs = DISCOVERED.lock().unwrap();
    let ev = evs
        .iter()
        .find(|(u, _, _, _, _, _)| u == PEER_UUID)
        .unwrap_or_else(|| panic!("应收到 {} 的 on_device_discovered 回调", PEER_UUID));
    assert_eq!(ev.5, "127.0.0.1");
    assert_eq!(ev.2, 23333);
    assert_eq!(ev.4, "phone");
    drop(evs);

    // 6) 清理：停止发现线程（广播线程退出、UDP socket 关闭）
    let rc = unsafe {
        ffi::send::nrc_periodic_broadcast(
            ctx_ptr(&ctx),
            0,
            std::ptr::null(),
            std::ptr::null(),
            -1,
            std::ptr::null(),
        )
    };
    assert_eq!(rc, 0);
}
