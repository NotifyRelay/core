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

use std::os::raw::{c_char, c_void};
use std::sync::Mutex;

use notify_relay_core::ffi;

mod common;
use common::*;

const LOCAL_UUID: &str = "local-mdns-self";
const PEER_UUID: &str = "peer-mdns-1";
const PEER_IP: &str = "192.168.31.200";
const PEER_PORT: u16 = 23333;

/// on_device_discovered 回调事件：(uuid, name, port, battery, device_type, ip)
type DiscoveredEvent = (String, String, u16, i32, String, String);

/// 记录 on_device_discovered 回调事件（回调为 extern "C"，无法捕获上下文）
static DISCOVERED: Mutex<Vec<DiscoveredEvent>> = Mutex::new(Vec::new());

/// 发现态容器是进程级共享：使用它的测试必须串行执行，
/// 否则一个测试的 clear 会清掉另一个测试刚记录的事件。
static DISCOVERY_SERIAL: Mutex<()> = Mutex::new(());

/// 取得串行许可；前序测试 panic 导致的锁中毒不阻断后续测试。
fn serial_guard() -> std::sync::MutexGuard<'static, ()> {
    DISCOVERY_SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// 读取已记录事件；中毒时取回内部数据而非直接失败。
fn discovered() -> std::sync::MutexGuard<'static, Vec<DiscoveredEvent>> {
    DISCOVERED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
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
    discovered().push((
        unsafe { read_cstr(uuid) },
        unsafe { read_cstr(name_b64) },
        port,
        battery,
        unsafe { read_cstr(device_type) },
        unsafe { read_cstr(ip) },
    ));
}

/// 通过发现消费链登记一台对端，并断言 registry、device_ips、known_devices 与回调。
#[test]
fn mdns_discovery_registers_peer_through_consumer() {
    let _serial = serial_guard();
    discovered().clear();

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
    let evs = discovered();
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
    let _serial = serial_guard();
    discovered().clear();

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
        discovered().is_empty(),
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
/// 服务下线后必须清理发现态，否则设备永久挂在列表里并被反复重拨。
#[test]
fn mdns_service_removed_clears_discovery_state() {
    let _serial = serial_guard();
    discovered().clear();

    let ctx = create_ctx();
    {
        let mut guard = ctx.lock().expect("取上下文锁");
        guard.local_uuid = LOCAL_UUID.to_string();
    }

    // 先登记一台对端
    notify_relay_core::send::consume_discovered_device_for_test(
        &ctx, PEER_UUID, "", PEER_PORT, 66, "phone", PEER_IP,
    );
    {
        let guard = ctx.lock().expect("取上下文锁");
        assert!(guard.discovery.get_known_devices().contains_key(PEER_UUID));
    }

    // 模拟其 mDNS 服务下线（Goodbye）
    let fullname = format!("nr-{}._notifyrelay._udp.local.", PEER_UUID);
    notify_relay_core::discovery::mdns::handle_service_removed_for_test(
        ctx_ptr(&ctx) as usize,
        &fullname,
    );

    // 发现态必须被清空：known_devices 与 device_ips 都不再保留该设备
    let guard = ctx.lock().expect("取上下文锁");
    assert!(
        !guard.discovery.get_known_devices().contains_key(PEER_UUID),
        "服务下线后 known_devices 必须移除该设备，否则会持续重拨已下线地址"
    );
    let ip = guard
        .device_ips
        .lock()
        .ok()
        .and_then(|m| m.get(PEER_UUID).cloned())
        .unwrap_or_default();
    assert!(ip.is_empty(), "服务下线后 device_ips 必须一并清理");
}

/// 本机自身服务下线通知不得触发清理（避免误删自身状态）。
#[test]
fn mdns_service_removed_ignores_self() {
    let _serial = serial_guard();
    // 各测试使用独立的 local uuid，避免并行执行时共享 DISCOVERED 互相污染
    const SELF_UUID: &str = "self-removed-test";

    let ctx = create_ctx();
    {
        let mut guard = ctx.lock().expect("取上下文锁");
        guard.local_uuid = SELF_UUID.to_string();
        guard.discovery.add_known_device(SELF_UUID, "127.0.0.1");
    }

    let fullname = format!("nr-{}._notifyrelay._udp.local.", SELF_UUID);
    notify_relay_core::discovery::mdns::handle_service_removed_for_test(
        ctx_ptr(&ctx) as usize,
        &fullname,
    );

    // 自身 uuid 的下线通知被跳过，本机登记不应被清除
    let guard = ctx.lock().expect("取上下文锁");
    assert!(
        guard.discovery.get_known_devices().contains_key(SELF_UUID),
        "本机自身的下线通知不得清理发现态"
    );
}
