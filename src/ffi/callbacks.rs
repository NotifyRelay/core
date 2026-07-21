use std::os::raw::c_void;

use super::common::with_ctx;

#[no_mangle]
pub extern "C" fn nrc_set_on_pairing_cb(ctx_ptr: *mut c_void, cb: crate::router::OnPairingCb) {
    with_ctx(ctx_ptr, |ctx| {
        ctx.router.on_pairing = cb;
    });
}

#[no_mangle]
pub extern "C" fn nrc_set_on_data_cb(ctx_ptr: *mut c_void, cb: crate::router::OnDataCb) {
    with_ctx(ctx_ptr, |ctx| {
        ctx.router.on_data = cb;
    });
}

#[no_mangle]
pub extern "C" fn nrc_set_on_heartbeat_udp_cb(
    ctx_ptr: *mut c_void,
    cb: crate::router::OnHeartbeatUdpCb,
) {
    with_ctx(ctx_ptr, |ctx| {
        ctx.router.on_heartbeat_udp = cb;
    });
}

#[no_mangle]
pub extern "C" fn nrc_set_on_device_timeout_cb(
    ctx_ptr: *mut c_void,
    cb: crate::router::OnDeviceTimeoutCb,
) {
    with_ctx(ctx_ptr, |ctx| {
        ctx.router.on_device_timeout = cb;
    });
}

#[no_mangle]
pub extern "C" fn nrc_set_on_device_connected_cb(
    ctx_ptr: *mut c_void,
    cb: crate::router::OnDeviceConnectedCb,
) {
    with_ctx(ctx_ptr, |ctx| {
        ctx.router.on_device_connected = cb;
    });
}

#[no_mangle]
pub extern "C" fn nrc_set_on_device_disconnected_cb(
    ctx_ptr: *mut c_void,
    cb: crate::router::OnDeviceDisconnectedCb,
) {
    with_ctx(ctx_ptr, |ctx| {
        ctx.router.on_device_disconnected = cb;
    });
}

#[no_mangle]
pub extern "C" fn nrc_set_on_tcp_error_cb(ctx_ptr: *mut c_void, cb: crate::router::OnTcpErrorCb) {
    with_ctx(ctx_ptr, |ctx| {
        ctx.router.on_tcp_error = cb;
    });
}

#[no_mangle]
pub extern "C" fn nrc_set_on_mdns_discovered_cb(
    ctx_ptr: *mut c_void,
    cb: crate::router::OnMdnsDiscoveredCb,
) {
    with_ctx(ctx_ptr, |ctx| {
        ctx.router.on_mdns_discovered = cb;
    });
}

#[no_mangle]
pub extern "C" fn nrc_set_user_data(ctx_ptr: *mut c_void, user_data: *mut c_void) {
    with_ctx(ctx_ptr, |ctx| {
        ctx.router.user_data = user_data;
    });
}
