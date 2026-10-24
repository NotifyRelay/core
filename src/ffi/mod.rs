//! C ABI 导出层。
//!
//! 本层是**纯委托**：只做 C 字符串 / 切片 / 整型 ↔ Rust 类型的转换，
//! 业务逻辑一律在领域模块（`crypto` / `filter` / `network` / `sender_queue` /
//! `state_merge` / …）中实现。新增能力先写领域模块，再在 `api` 导出；
//! 本层仅按需补 ABI 适配。

pub mod app_sync;
pub mod audio_stream;
pub mod callbacks;
pub mod clipboard;
pub mod common;
pub mod device_state;
pub mod discovery;
pub mod ecdh;
pub mod filter;
pub mod heartbeat;
pub mod key_management;
pub mod lifecycle;
pub mod network;
pub mod persistence;
pub mod reconnect;
pub mod send;
pub mod sender_queue;
pub mod state_merge;
pub mod utils;

pub use app_sync::*;
pub use audio_stream::*;
pub use callbacks::*;
pub use clipboard::*;
pub use common::*;
pub use device_state::*;
pub use discovery::*;
pub use ecdh::*;
pub use filter::*;
pub use heartbeat::*;
pub use key_management::*;
pub use lifecycle::*;
pub use network::*;
pub use persistence::*;
pub use reconnect::*;
pub use send::*;
pub use sender_queue::*;
pub use state_merge::*;
pub use utils::*;

/// 句柄注册表（`ffi::handle::*` 路径保持不变，实现位于 crate 根）。
pub use crate::handle;
