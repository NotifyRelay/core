//! 核心生命周期与全局关停信号。
//!
//! 上下文互斥锁可能因下层阻塞（网络收发、拨号握手）长时间不释放，
//! 此时任何依赖该锁的操作都会一起停摆。关停信号必须与上下文锁**完全解耦**：
//! 只操作原子量，保证在锁被占用时依然能立即置位并让后台线程退出。
//!
//! 恢复流程由平台侧重建核心实例完成；本模块只负责让旧实例的线程停下，
//! 不尝试解锁或强杀正在阻塞的调用。

use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

/// 全局关停信号。置位后所有后台循环应在下一轮退出。
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

/// 请求关停。返回 true 表示本次调用首次置位。
///
/// 不获取上下文锁，可在任意线程、任意时刻调用。
pub fn request_shutdown() -> bool {
    !SHUTDOWN_REQUESTED.swap(true, Ordering::SeqCst)
}

/// 是否已请求关停。
pub fn is_shutdown_requested() -> bool {
    SHUTDOWN_REQUESTED.load(Ordering::SeqCst)
}

/// 清除关停信号，供新实例接管前重置。
pub fn clear_shutdown() {
    SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);
}

/// 关停协调线程的轮询间隔。
const COORDINATOR_POLL: Duration = Duration::from_millis(200);

/// 协调线程等待上下文锁的上限：超时后放弃剩余清理，仅保留信号。
///
/// 锁在此期限内仍取不到说明阻塞方未返回，继续等待没有意义。
const COORDINATOR_LOCK_TIMEOUT: Duration = Duration::from_secs(3);

/// 启动关停协调线程。
///
/// 线程只做一件事：等待关停信号，然后在**有界等待**内释放仍可释放的资源。
/// 取锁失败不重试、不阻塞，保证该线程自身不会成为新的死锁参与者。
pub fn start_coordinator(ctx_ptr: usize) {
    if ctx_ptr == 0 {
        return;
    }
    thread::Builder::new()
        .name("core-shutdown".to_string())
        .spawn(move || {
            while !is_shutdown_requested() {
                thread::sleep(COORDINATOR_POLL);
            }
            log::warn!("核心: 收到关停请求，开始释放资源");
            let ctx = unsafe { &*(ctx_ptr as *const crate::SafeContext) };
            let deadline = std::time::Instant::now() + COORDINATOR_LOCK_TIMEOUT;
            loop {
                match ctx.try_lock() {
                    Ok(mut guard) => {
                        if let Some(handle) = guard.broadcast_handle.take() {
                            handle.running.store(false, Ordering::Relaxed);
                        }
                        if let Some(transport) = guard.quic.take() {
                            transport.shutdown();
                        }
                        guard.heartbeat_scheduler_handles.clear();
                        break;
                    }
                    Err(std::sync::TryLockError::Poisoned(_)) => break,
                    Err(std::sync::TryLockError::WouldBlock) => {
                        if std::time::Instant::now() >= deadline {
                            log::error!(
                                "核心: 关停期间上下文锁仍被占用，放弃后续清理（已置关停信号）"
                            );
                            return;
                        }
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            }
            log::warn!("核心: 资源释放完成，等待平台重建实例");
        })
        .ok();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_signal_is_global_and_idempotent() {
        clear_shutdown();
        assert!(!is_shutdown_requested());

        assert!(request_shutdown(), "首次置位应返回 true");
        assert!(is_shutdown_requested());
        assert!(!request_shutdown(), "重复置位应返回 false");

        clear_shutdown();
        assert!(!is_shutdown_requested());
    }
}
