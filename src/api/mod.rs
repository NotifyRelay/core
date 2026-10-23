//! UniFFI 导出层的顶层模块。
//!
//! 与 `ffi`（手写 C ABI）并列存在，迁移期由本模块逐个接管能力；
//! 全部迁移完成后 `ffi` 模块整体删除。

/// ABI 探针：返回核心库的 crate 版本。
///
/// 用途是验证 UniFFI + Gobley 生成链路可用（Kotlin 侧能调用并拿到预期值），
/// 不承担业务语义。
#[uniffi::export]
pub fn abi_probe() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
