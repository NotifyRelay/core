//! UniFFI 导出层。
//!
//! Kotlin 绑定由 gobley-uniffi-bindgen 生成；本层只做类型映射，
//! 业务逻辑位于各领域模块（`crypto` / `filter` / `network` / `sender_queue` / …）。

use std::os::raw::c_void;
use std::sync::Arc;

use crate::SafeContext;

mod callbacks;
mod media;
mod send;
mod state;
mod util;

/// 核心上下文句柄。
///
/// 内部保存上下文地址（进程生命周期内不释放）：后台线程以裸指针访问同一上下文，
/// 故不可在 `Drop` 中释放。以 `usize` 保存，满足 UniFFI 对 Object 的 Send/Sync 要求。
#[derive(uniffi::Object)]
pub struct Core {
    ptr: usize,
}

unsafe impl Send for Core {}
unsafe impl Sync for Core {}

impl Core {
    /// 上下文裸指针。
    pub(crate) fn ctx_ptr(&self) -> *mut c_void {
        self.ptr as *mut c_void
    }

    /// 上下文引用。
    pub(crate) fn ctx(&self) -> &SafeContext {
        unsafe { &*(self.ptr as *const SafeContext) }
    }
}

#[uniffi::export]
impl Core {
    /// 创建核心上下文。
    ///
    /// 初始化日志桥并启动心跳线程。
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        let ptr = crate::service::create_context();
        Arc::new(Self { ptr: ptr as usize })
    }

    /// 构建版本（git 短哈希；工作区有改动时带 `-dirty`）。
    pub fn git_hash(&self) -> String {
        env!("NOTIFY_RELAY_GIT_HASH").to_string()
    }

    /// 核心库 crate 版本。
    pub fn crate_version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }
}

/// ABI 探针：返回核心库 crate 版本。
#[uniffi::export]
pub fn abi_probe() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
