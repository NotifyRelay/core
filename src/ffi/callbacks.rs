//! 平台回调 C ABI 委托。
//!
//! 把 C 函数指针包装成内部 `Arc<dyn Fn>` 闭包后交给 `router`；
//! 内部调用点只处理 Rust 类型。

use std::os::raw::{c_char, c_void};

use crate::router::{
    OnData, OnDeviceConnected, OnDeviceDisconnected, OnDeviceDiscovered, OnDeviceTimeout,
    OnPairing, OnStateQuery, OnTcpError,
};

/// C 侧回调函数类型（与 `router` 的闭包签名一一对应）。
pub type PairingCbFn = Option<
    extern "C" fn(*const c_char, *const c_char, *const c_char, i32, *const c_char, *mut c_void),
>;
pub type DataCbFn = Option<extern "C" fn(*const c_char, *const c_char, *const c_char, *mut c_void)>;
pub type StateQueryCbFn =
    Option<extern "C" fn(*const c_char, *const c_char, i32, *mut c_void) -> i32>;
pub type UnitCbFn = Option<extern "C" fn(*const c_char, *mut c_void)>;
pub type ConnectedCbFn = Option<extern "C" fn(*const c_char, *const c_char, *mut c_void)>;
pub type DiscoveredCbFn = Option<
    extern "C" fn(
        *const c_char,
        *const c_char,
        u16,
        i32,
        *const c_char,
        *const c_char,
        *mut c_void,
    ),
>;

fn cstring(s: &str) -> std::ffi::CString {
    std::ffi::CString::new(s).unwrap_or_default()
}

/// 上下文锁内安装回调。
fn install<F>(ctx_ptr: *mut c_void, f: F)
where
    F: FnOnce(&mut crate::CoreContext),
{
    if ctx_ptr.is_null() {
        return;
    }
    let ctx = unsafe { &*(ctx_ptr as *const crate::SafeContext) };
    if let Ok(mut guard) = ctx.lock() {
        f(&mut guard);
    }
}

#[no_mangle]
pub extern "C" fn nrc_set_on_pairing_cb(ctx_ptr: *mut c_void, cb: PairingCbFn) {
    let wrapped: Option<OnPairing> = cb.map(|f| {
        std::sync::Arc::new(
            move |uuid: &str, msg_type: &str, data: &str, int_value: i32, extra: &str| {
                let (u, t, d, e) = (
                    cstring(uuid),
                    cstring(msg_type),
                    cstring(data),
                    cstring(extra),
                );
                f(
                    u.as_ptr(),
                    t.as_ptr(),
                    d.as_ptr(),
                    int_value,
                    e.as_ptr(),
                    std::ptr::null_mut(),
                );
            },
        ) as OnPairing
    });
    install(ctx_ptr, |ctx| ctx.router.on_pairing = wrapped);
}

#[no_mangle]
pub extern "C" fn nrc_set_on_data_cb(ctx_ptr: *mut c_void, cb: DataCbFn) {
    let wrapped: Option<OnData> = cb.map(|f| {
        std::sync::Arc::new(move |uuid: &str, msg_type: &str, plaintext: &str| {
            let (u, t, p) = (cstring(uuid), cstring(msg_type), cstring(plaintext));
            f(u.as_ptr(), t.as_ptr(), p.as_ptr(), std::ptr::null_mut());
        }) as OnData
    });
    install(ctx_ptr, |ctx| ctx.router.on_data = wrapped);
}

#[no_mangle]
pub extern "C" fn nrc_set_on_state_query_cb(ctx_ptr: *mut c_void, cb: StateQueryCbFn) {
    let wrapped: Option<OnStateQuery> = cb.map(|f| {
        std::sync::Arc::new(move |uuid: &str, feature_id: &str, is_media: bool| -> i32 {
            let (u, fid) = (cstring(uuid), cstring(feature_id));
            f(
                u.as_ptr(),
                fid.as_ptr(),
                i32::from(is_media),
                std::ptr::null_mut(),
            )
        }) as OnStateQuery
    });
    install(ctx_ptr, |ctx| ctx.router.on_state_query = wrapped);
}

#[no_mangle]
pub extern "C" fn nrc_set_on_device_timeout_cb(ctx_ptr: *mut c_void, cb: UnitCbFn) {
    let wrapped: Option<OnDeviceTimeout> = cb.map(|f| {
        std::sync::Arc::new(move |uuid: &str| {
            let u = cstring(uuid);
            f(u.as_ptr(), std::ptr::null_mut());
        }) as OnDeviceTimeout
    });
    install(ctx_ptr, |ctx| ctx.router.on_device_timeout = wrapped);
}

#[no_mangle]
pub extern "C" fn nrc_set_on_device_connected_cb(ctx_ptr: *mut c_void, cb: ConnectedCbFn) {
    let wrapped: Option<OnDeviceConnected> = cb.map(|f| {
        std::sync::Arc::new(move |uuid: &str, ip: &str| {
            let (u, i) = (cstring(uuid), cstring(ip));
            f(u.as_ptr(), i.as_ptr(), std::ptr::null_mut());
        }) as OnDeviceConnected
    });
    install(ctx_ptr, |ctx| ctx.router.on_device_connected = wrapped);
}

#[no_mangle]
pub extern "C" fn nrc_set_on_device_disconnected_cb(ctx_ptr: *mut c_void, cb: UnitCbFn) {
    let wrapped: Option<OnDeviceDisconnected> = cb.map(|f| {
        std::sync::Arc::new(move |uuid: &str| {
            let u = cstring(uuid);
            f(u.as_ptr(), std::ptr::null_mut());
        }) as OnDeviceDisconnected
    });
    install(ctx_ptr, |ctx| ctx.router.on_device_disconnected = wrapped);
}

#[no_mangle]
pub extern "C" fn nrc_set_on_tcp_error_cb(ctx_ptr: *mut c_void, cb: UnitCbFn) {
    let wrapped: Option<OnTcpError> = cb.map(|f| {
        std::sync::Arc::new(move |error: &str| {
            let e = cstring(error);
            f(e.as_ptr(), std::ptr::null_mut());
        }) as OnTcpError
    });
    install(ctx_ptr, |ctx| ctx.router.on_tcp_error = wrapped);
}

#[no_mangle]
pub extern "C" fn nrc_set_on_device_discovered_cb(ctx_ptr: *mut c_void, cb: DiscoveredCbFn) {
    let wrapped: Option<OnDeviceDiscovered> = cb.map(|f| {
        std::sync::Arc::new(
            move |uuid: &str,
                  name_b64: &str,
                  port: u16,
                  battery: i32,
                  device_type: &str,
                  ip: &str| {
                let (u, n, dt, i) = (
                    cstring(uuid),
                    cstring(name_b64),
                    cstring(device_type),
                    cstring(ip),
                );
                f(
                    u.as_ptr(),
                    n.as_ptr(),
                    port,
                    battery,
                    dt.as_ptr(),
                    i.as_ptr(),
                    std::ptr::null_mut(),
                );
            },
        ) as OnDeviceDiscovered
    });
    install(ctx_ptr, |ctx| ctx.router.on_device_discovered = wrapped);
}
