use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::os::raw::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Once;

use base64::Engine;

type LogCb = extern "C" fn(i32, *const c_char);

#[cfg(target_os = "android")]
const ANDROID_LOG_DEBUG: i32 = 3;
#[cfg(target_os = "android")]
const ANDROID_LOG_INFO: i32 = 4;
#[cfg(target_os = "android")]
const ANDROID_LOG_WARN: i32 = 5;
#[cfg(target_os = "android")]
const ANDROID_LOG_ERROR: i32 = 6;

#[cfg(target_os = "android")]
fn android_log_level(level: log::Level) -> i32 {
    match level {
        log::Level::Error => ANDROID_LOG_ERROR,
        log::Level::Warn => ANDROID_LOG_WARN,
        log::Level::Info => ANDROID_LOG_INFO,
        _ => ANDROID_LOG_DEBUG,
    }
}

#[cfg(target_os = "android")]
#[link(name = "log")]
extern "C" {
    fn __android_log_write(prio: i32, tag: *const libc::c_char, text: *const libc::c_char) -> i32;
}

static LOG_CB: AtomicUsize = AtomicUsize::new(0);
static LOG_INIT: Once = Once::new();

struct PlatformLogBridge;

impl log::Log for PlatformLogBridge {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        if metadata.target().starts_with("mdns_sd") && metadata.level() <= log::Level::Debug {
            return false;
        }
        true
    }
    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        #[cfg(target_os = "android")]
        {
            let tag = CString::new("NotifyRelayCore").unwrap();
            let msg = CString::new(format!("{}", record.args())).unwrap();
            unsafe {
                __android_log_write(android_log_level(record.level()), tag.as_ptr(), msg.as_ptr());
            }
        }
        #[cfg(not(target_os = "android"))]
        {
            let val = LOG_CB.load(Ordering::Relaxed);
            if val == 0 {
                return;
            }
            let cb: LogCb = unsafe { std::mem::transmute(val) };
            if let Ok(c_msg) = CString::new(format!("{}", record.args())) {
                cb(record.level() as i32, c_msg.as_ptr());
            }
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
    match ctx.lock() {
        Ok(mut guard) => f(&mut guard),
        Err(_) => R::default(),
    }
}

pub fn encode_name_b64(name: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(name)
}
