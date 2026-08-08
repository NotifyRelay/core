//! 全局句柄注册表
//!
//! 替代裸指针直接跨 FFI 传递：平台端只持有递增正整数句柄（0 恒为无效值），
//! Rust 侧通过句柄查表还原真实指针。避免 ARM64 标签指针（高位为 1）在
//! 有符号 i64 解读下被误判为负数的隐患。

use std::collections::HashMap;
use std::os::raw::c_void;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

fn table() -> &'static Mutex<Option<HashMap<u64, usize>>> {
    static TABLE: Mutex<Option<HashMap<u64, usize>>> = Mutex::new(None);
    &TABLE
}

/// 注册指针，返回递增正整数句柄（0 表示无效，永不复用）
pub fn put(ptr: *mut c_void) -> u64 {
    if ptr.is_null() {
        return 0;
    }
    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut guard) = table().lock() {
        guard
            .get_or_insert_with(HashMap::new)
            .insert(handle, ptr as usize);
    }
    handle
}

/// 句柄还原为指针；无效句柄返回 null
pub fn get(handle: u64) -> *mut c_void {
    if handle == 0 {
        return std::ptr::null_mut();
    }
    if let Ok(guard) = table().lock() {
        guard
            .as_ref()
            .and_then(|m| m.get(&handle).copied())
            .map(|p| p as *mut c_void)
            .unwrap_or(std::ptr::null_mut())
    } else {
        std::ptr::null_mut()
    }
}

/// 取出句柄对应的指针并从表中移除（用于释放）；无效句柄返回 null
pub fn take(handle: u64) -> *mut c_void {
    if handle == 0 {
        return std::ptr::null_mut();
    }
    if let Ok(mut guard) = table().lock() {
        guard
            .as_mut()
            .and_then(|m| m.remove(&handle))
            .map(|p| p as *mut c_void)
            .unwrap_or(std::ptr::null_mut())
    } else {
        std::ptr::null_mut()
    }
}

/// 句柄总数（调试用）
#[allow(dead_code)]
pub fn count() -> usize {
    if let Ok(guard) = table().lock() {
        guard.as_ref().map(|m| m.len()).unwrap_or(0)
    } else {
        0
    }
}
