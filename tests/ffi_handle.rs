//! 句柄注册表契约测试（ffi::handle::put/get/take/count）
//! 目的：保证"句柄索引替代裸指针"重构的核心契约不变（0=无效、递增、取走即失效）

use std::os::raw::c_void;
use std::sync::{Mutex, MutexGuard};

use notify_relay_core::ffi;

// 句柄表为全局共享状态；同一测试二进制内的多个 #[test] 默认并行执行，
// 会并发 put/take 互相干扰（尤其依赖全局 count() 绝对基线的用例）。
// 用一把进程内互斥锁将本文件所有用例串行化，消除并发竞态。
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap()
}

#[test]
fn test_put_null_returns_zero() {
    let _g = serial();
    assert_eq!(ffi::handle::put(std::ptr::null_mut()), 0);
}

#[test]
fn test_get_zero_returns_null() {
    let _g = serial();
    assert!(ffi::handle::get(0).is_null());
}

#[test]
fn test_get_invalid_handle_returns_null() {
    let _g = serial();
    assert!(ffi::handle::get(999999).is_null());
}

#[test]
fn test_put_get_roundtrip() {
    let _g = serial();
    let dummy: u8 = 42;
    let ptr = (&dummy as *const u8 as *mut u8) as *mut c_void;
    let handle = ffi::handle::put(ptr);
    assert!(handle > 0);
    assert_eq!(ffi::handle::get(handle), ptr);
}

#[test]
fn test_put_returns_increasing_handles() {
    let _g = serial();
    let dummy: u8 = 1;
    let ptr = (&dummy as *const u8 as *mut u8) as *mut c_void;
    let h1 = ffi::handle::put(ptr);
    let h2 = ffi::handle::put(ptr);
    let h3 = ffi::handle::put(ptr);
    assert!(h1 < h2 && h2 < h3, "句柄应递增: {} < {} < {}", h1, h2, h3);
}

#[test]
fn test_take_removes_handle() {
    let _g = serial();
    let dummy: u8 = 7;
    let ptr = (&dummy as *const u8 as *mut u8) as *mut c_void;
    let handle = ffi::handle::put(ptr);
    assert_eq!(ffi::handle::get(handle), ptr);
    // take 返回原指针且使句柄失效
    assert_eq!(ffi::handle::take(handle), ptr);
    assert!(ffi::handle::get(handle).is_null());
    // 重复 take 返回 null
    assert!(ffi::handle::take(handle).is_null());
}

#[test]
fn test_take_zero_returns_null() {
    let _g = serial();
    assert!(ffi::handle::take(0).is_null());
}

#[test]
fn test_count_reflects_put_take() {
    let _g = serial();
    let dummy: u8 = 9;
    let ptr = (&dummy as *const u8 as *mut u8) as *mut c_void;
    let before = ffi::handle::count();
    let handle = ffi::handle::put(ptr);
    assert_eq!(ffi::handle::count(), before + 1);
    ffi::handle::take(handle);
    assert_eq!(ffi::handle::count(), before);
}
