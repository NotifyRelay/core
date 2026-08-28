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
    with_ctx_or(ctx_ptr, R::default(), f)
}

/// 与 with_ctx 相同，但失败（空上下文/锁中毒/panic）时返回调用方指定的值。
/// 用于失败语义必须与成功区分的关键接口（如删除设备），避免默认值（0=成功）误导平台端
pub fn with_ctx_or<F, R>(ctx_ptr: *mut c_void, or: R, f: F) -> R
where
    F: FnOnce(&mut CoreContext) -> R,
{
    if ctx_ptr.is_null() {
        return or;
    }
    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
    // panic 跨 extern "C" 边界会导致 SIGABRT（真机已证实：device list 刷新路径）。
    // 捕获并记录 panic 详情（消息/位置），不再终止进程；返回值与「无效上下文」同语义
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match ctx.get_mut() {
        Ok(g) => Some(f(g)),
        Err(_) => None,
    })) {
        Ok(Some(r)) => r,
        Ok(None) => or,
        Err(payload) => {
            let msg = payload
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| payload.downcast_ref::<String>().map(|s| s.as_str()))
                .unwrap_or("unknown panic payload");
            log::error!("FFI 调用发生 panic（已捕获，进程不崩溃）：{}", msg);
            or
        }
    }
}

pub fn encode_name_b64(name: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(name)
}
