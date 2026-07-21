use std::os::raw::{c_char, c_void};

use super::common::from_cstr;

#[no_mangle]
pub extern "C" fn nrc_start_mdns_advertiser(
    ctx_ptr: *mut c_void,
    uuid: *const c_char,
    name: *const c_char,
    port: u16,
    pubkey: *const c_char,
    device_type: *const c_char,
) -> i32 {
    if ctx_ptr.is_null() || uuid.is_null() || name.is_null() || pubkey.is_null() || device_type.is_null() {
        return -1;
    }
    let u = unsafe { from_cstr(uuid).to_string() };
    let n = unsafe { from_cstr(name).to_string() };
    let pk = unsafe { from_cstr(pubkey).to_string() };
    let dt = unsafe { from_cstr(device_type).to_string() };

    let ctx = unsafe { &mut *(ctx_ptr as *mut crate::SafeContext) };
    let mut guard = match ctx.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };

    match guard.mdns.start_advertiser(&u, &n, port, &pk, &dt) {
        Ok(_) => 0,
        Err(e) => {
            log::error!("启动 mDNS 广告失败: {}", e);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn nrc_stop_mdns_advertiser(ctx_ptr: *mut c_void) -> i32 {
    if ctx_ptr.is_null() {
        return -1;
    }
    let ctx = unsafe { &mut *(ctx_ptr as *mut crate::SafeContext) };
    let mut guard = match ctx.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };
    guard.mdns.stop_advertiser();
    0
}

#[no_mangle]
pub extern "C" fn nrc_start_mdns_discovery(ctx_ptr: *mut c_void) -> i32 {
    if ctx_ptr.is_null() {
        return -1;
    }

    let ctx_ptr_usize = ctx_ptr as usize;
    let ctx = unsafe { &mut *(ctx_ptr as *mut crate::SafeContext) };
    let (on_mdns_discovered, user_data) = match ctx.lock() {
        Ok(guard) => (guard.router.on_mdns_discovered, guard.router.user_data),
        Err(_) => return -1,
    };

    let ctx = unsafe { &mut *(ctx_ptr as *mut crate::SafeContext) };
    let mut guard = match ctx.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };

    match guard.mdns.start_browser(ctx_ptr_usize, on_mdns_discovered, user_data) {
        Ok(_) => 0,
        Err(e) => {
            log::error!("启动 mDNS 发现失败: {}", e);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn nrc_stop_mdns_discovery(ctx_ptr: *mut c_void) -> i32 {
    if ctx_ptr.is_null() {
        return -1;
    }
    let ctx = unsafe { &mut *(ctx_ptr as *mut crate::SafeContext) };
    let mut guard = match ctx.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };
    guard.mdns.stop_browser();
    0
}
