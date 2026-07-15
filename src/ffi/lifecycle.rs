use std::ffi::CString;
use std::os::raw::c_char;
use std::os::raw::c_void;

use crate::{CoreContext, SafeContext};

use super::common::init_log_bridge;

#[no_mangle]
pub extern "C" fn nrc_init() -> *mut c_void {
    init_log_bridge();
    let ctx = Box::new(std::sync::Mutex::new(CoreContext::new()));
    Box::into_raw(ctx) as *mut c_void
}

#[no_mangle]
pub extern "C" fn nrc_destroy(ctx_ptr: *mut c_void) {
    if !ctx_ptr.is_null() {
        let ctx = unsafe { Box::from_raw(ctx_ptr as *mut SafeContext) };
        drop(ctx);
    }
}

#[no_mangle]
pub extern "C" fn nrc_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}