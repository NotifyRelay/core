//! 平台日志桥。
//!
//! `log` 全局 logger 只能安装一次；本模块持有唯一安装点，平台侧通过回调接收日志。
//! UniFFI 导出层与 C ABI 委托层共用同一回调槽位。

use std::ffi::CString;
use std::os::raw::c_char;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Once;

/// 日志回调签名：`(level, message)`，message 为以 NUL 结尾的 UTF-8 串。
pub type LogCb = extern "C" fn(i32, *const c_char);

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

/// 安装全局 logger（进程内只生效一次）。
pub fn init() {
    LOG_INIT.call_once(|| {
        log::set_logger(&LOG_BRIDGE).ok();
        log::set_max_level(log::LevelFilter::Debug);
    });
}

/// 安装/清除日志回调；`None` 表示停止转发。
pub fn set_callback(cb: Option<LogCb>) {
    let val = match cb {
        Some(f) => f as usize,
        None => 0,
    };
    LOG_CB.store(val, Ordering::Release);
}
