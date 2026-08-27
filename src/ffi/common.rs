use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::os::raw::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Once;

use base64::Engine;

type LogCb = extern "C" fn(i32, *const c_char);

static LOG_CB: AtomicUsize = AtomicUsize::new(0);
static LOG_INIT: Once = Once::new();

struct PlatformLogBridge;

impl log::Log for PlatformLogBridge {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }
    fn log(&self, record: &log::Record) {
        if record.target().starts_with("mdns_sd") {
            return;
        }
        let val = LOG_CB.load(Ordering::Relaxed);
        if val == 0 {
            return;
        }
        let cb: LogCb = unsafe { std::mem::transmute(val) };
        if let Ok(c_msg) = CString::new(format!("{}", record.args())) {
            cb(record.level() as i32, c_msg.as_ptr());
        }
    }
    fn flush(&self) {}
}

static LOG_BRIDGE: PlatformLogBridge = PlatformLogBridge;

pub fn init_log_bridge() {
    LOG_INIT.call_once(|| {
        log::set_logger(&LOG_BRIDGE).ok();
        log::set_max_level(log::LevelFilter::Debug);
    });
}

#[no_mangle]
pub extern "C" fn nrc_set_log_callback(cb: Option<LogCb>) {
    let val = match cb {
        Some(f) => f as usize,
        None => 0,
    };
    LOG_CB.store(val, Ordering::Release);
}

use crate::{CoreContext, SafeContext};

pub fn to_cstr(s: &str) -> *mut c_char {
    CString::new(s).unwrap_or_default().into_raw()
}

pub unsafe fn from_cstr<'a>(ptr: *const c_char) -> &'a str {
    if ptr.is_null() {
        return "";
    }
    CStr::from_ptr(ptr).to_str().unwrap_or("")
}

pub fn with_ctx<F, R>(ctx_ptr: *mut c_void, f: F) -> R
where
    F: FnOnce(&mut CoreContext) -> R,
    R: Default,
{
    if ctx_ptr.is_null() {
        return R::default();
    }
    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
    // panic 跨 extern "C" 边界会导致 SIGABRT（真机已证实：device list 刷新路径）。
    // 捕获并记录 panic 详情（消息/位置），不再终止进程；返回值与「无效上下文」同语义
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match ctx.get_mut() {
        Ok(g) => f(g),
        Err(_) => R::default(),
    })) {
        Ok(r) => r,
        Err(payload) => {
            let msg = payload
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| payload.downcast_ref::<String>().map(|s| s.as_str()))
                .unwrap_or("unknown panic payload");
            log::error!("FFI 调用发生 panic（已捕获，进程不崩溃）：{}", msg);
            R::default()
        }
    }
}

pub fn encode_name_b64(name: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(name)
}
