use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// 去重指纹：SHA-256 全摘要，作为去重键的定长表示。
pub type Fingerprint = [u8; 32];

/// 入站内容去重窗口（毫秒）
pub const CONTENT_DEDUP_TTL_MS: i64 = 10_000;

/// 表超过该规模时触发惰性清理
const DEDUP_CLEANUP_THRESHOLD: usize = 1024;

/// 按 TTL 分域的去重表。
///
/// 每个条目保存自身过期时刻（登记时刻 + ttl），因此同一张表可以混存不同窗口的键
/// （出站 3s 与超级岛锁屏 300s 共用出站域）。清理按过期时刻判定，
/// 不再用单一窗口把长窗口键提前删除。
#[derive(Default)]
struct TtlMap {
    /// 已登记未确认的条目 → 过期时刻
    pending: HashMap<Fingerprint, i64>,
    /// 已确认的条目 → 过期时刻
    sent: HashMap<Fingerprint, i64>,
}

impl TtlMap {
    fn is_live(expire_at: i64, now: i64) -> bool {
        now <= expire_at
    }

    /// 登记 pending；窗口内已存在（pending 或 sent）时返回 false。
    fn check_and_pend(&mut self, fp: &Fingerprint, ttl_ms: i64) -> bool {
        let now = now_ms();
        if let Some(&expire_at) = self.pending.get(fp) {
            if Self::is_live(expire_at, now) {
                return false;
            }
            self.pending.remove(fp);
        }
        if let Some(&expire_at) = self.sent.get(fp) {
            if Self::is_live(expire_at, now) {
                return false;
            }
            self.sent.remove(fp);
        }
        self.pending.insert(*fp, now.saturating_add(ttl_ms));
        true
    }

    fn mark_sent(&mut self, fp: &Fingerprint, ttl_ms: i64) {
        self.pending.remove(fp);
        self.sent.insert(*fp, now_ms().saturating_add(ttl_ms));
    }

    fn clear_pending(&mut self, fp: &Fingerprint) {
        self.pending.remove(fp);
    }

    fn contains(&self, fp: &Fingerprint) -> bool {
        match self.sent.get(fp) {
            Some(&expire_at) => Self::is_live(expire_at, now_ms()),
            None => false,
        }
    }

    fn cleanup(&mut self, now: i64) {
        self.pending
            .retain(|_, &mut expire_at| Self::is_live(expire_at, now));
        self.sent
            .retain(|_, &mut expire_at| Self::is_live(expire_at, now));
    }

    fn maybe_cleanup(&mut self) {
        if self.pending.len() + self.sent.len() > DEDUP_CLEANUP_THRESHOLD {
            self.cleanup(now_ms());
        }
    }

    fn clear(&mut self) {
        self.pending.clear();
        self.sent.clear();
    }
}

/// 去重状态：出站发送域与入站内容域彼此隔离。
///
/// 分域的原因是两者存在「清除全部内容键」的需求（clear_content），
/// 键已是指纹、不再带前缀，无法按前缀区分归属；同时避免一方清理波及另一方。
pub struct DedupState {
    outbound: TtlMap,
    content: TtlMap,
}

impl Default for DedupState {
    fn default() -> Self {
        Self::new()
    }
}

impl DedupState {
    pub fn new() -> Self {
        Self {
            outbound: TtlMap::default(),
            content: TtlMap::default(),
        }
    }

    /// 出站检查：不在窗口内已发送或待发送时返回 true，并登记 pending。
    pub fn check_and_pend(&mut self, fp: &Fingerprint, ttl_ms: i64) -> bool {
        self.outbound.check_and_pend(fp, ttl_ms)
    }

    /// 出站确认：从 pending 移到 sent，窗口由 ttl_ms 起算。
    pub fn mark_sent(&mut self, fp: &Fingerprint, ttl_ms: i64) {
        self.outbound.mark_sent(fp, ttl_ms);
    }

    /// 出站撤销：发送失败时清除 pending，窗口未建立。
    pub fn clear_pending(&mut self, fp: &Fingerprint) {
        self.outbound.clear_pending(fp);
    }

    /// 两域按各条目自身过期时刻回收。
    pub fn cleanup(&mut self) {
        let now = now_ms();
        self.outbound.cleanup(now);
        self.content.cleanup(now);
    }

    /// 表规模超阈值时惰性清理。
    pub fn maybe_cleanup(&mut self) {
        self.outbound.maybe_cleanup();
        self.content.maybe_cleanup();
    }

    /// 入站内容纯查询：窗口内已见返回 true，不写状态。
    pub fn contains(&self, fp: &Fingerprint) -> bool {
        self.content.contains(fp)
    }

    /// 入站内容标记已见，窗口为 CONTENT_DEDUP_TTL_MS。
    pub fn mark_seen(&mut self, fp: &Fingerprint) {
        self.content.maybe_cleanup();
        self.content.mark_sent(fp, CONTENT_DEDUP_TTL_MS);
    }

    /// 清除全部入站内容键；出站域不受影响。
    pub fn clear_content(&mut self) {
        self.content.clear();
    }
}

/// 去重状态句柄类型。
pub type DedupHandle = std::sync::Arc<std::sync::Mutex<DedupState>>;

/// 从上下文取出未加锁的去重状态句柄；上下文不可用时返回 None。
///
/// 调用方在上下文锁内只取句柄，查重本身在锁外完成，避免短操作排在网络与持久化之后。
pub fn handle_of(ctx_ptr: usize) -> Option<DedupHandle> {
    if ctx_ptr == 0 {
        return None;
    }
    let ctx = unsafe { &*(ctx_ptr as *const crate::SafeContext) };
    match ctx.lock() {
        Ok(guard) => Some(guard.dedup.clone()),
        Err(_) => None,
    }
}

/// 在锁外执行一次去重动作：句柄取自上下文，动作与上下文锁不重叠。
pub fn with_handle<R>(ctx_ptr: usize, or: R, f: impl FnOnce(&mut DedupState) -> R) -> R {
    match handle_of(ctx_ptr) {
        Some(state) => match state.lock() {
            Ok(mut guard) => f(&mut guard),
            Err(_) => or,
        },
        None => or,
    }
}

/// 统一去重动作：0=check_and_pend / 1=mark_sent / 2=clear_pending / 3=cleanup。
///
/// 跨平台入口（C ABI 与 UniFFI）共用本函数，避免动作分发与返回语义在两处各写一遍。
/// action=0 返回 1=应发送、0=重复；其余 action 返回 0=成功；非法 action 返回 -1。
/// `arg1_ms` 是 action 0/1 的窗口长度。
pub fn apply_action(state: &mut DedupState, action: i32, raw_key: &str, arg1_ms: i64) -> i32 {
    let key = fingerprint(&[raw_key]);
    match action {
        0 => {
            if raw_key.is_empty() {
                return 0;
            }
            i32::from(state.check_and_pend(&key, arg1_ms))
        }
        1 => {
            if !raw_key.is_empty() {
                state.mark_sent(&key, arg1_ms);
            }
            0
        }
        2 => {
            if !raw_key.is_empty() {
                state.clear_pending(&key);
            }
            0
        }
        3 => {
            state.cleanup();
            0
        }
        _ => -1,
    }
}

/// 入站内容去重动作：0=纯查询 / 1=标记已见 / 2=清除全部内容键。
///
/// 查询返回 1=窗口内已见、0=未见；其余 action 返回 0；非法 action 返回 -1。
pub fn apply_content_action(state: &mut DedupState, action: i32, key: &Fingerprint) -> i32 {
    match action {
        0 => i32::from(state.contains(key)),
        1 => {
            state.mark_seen(key);
            0
        }
        2 => {
            state.clear_content();
            0
        }
        _ => -1,
    }
}

/// 由若干字段计算指纹：各字段先写长度前缀再写内容。
///
/// 长度前缀使字段边界参与哈希：`("a|b", "c")` 与 `("a", "b|c")` 不会得到同一指纹。
pub fn fingerprint(parts: &[&str]) -> Fingerprint {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part.as_bytes());
    }
    let mut fp = [0u8; 32];
    fp.copy_from_slice(&hasher.finalize());
    fp
}

/// 出站发送去重键：设备 UUID 与报文。
pub fn compute_dedup_key(device_uuid: &str, data: &str) -> Fingerprint {
    fingerprint(&[device_uuid, data])
}

/// 入站内容去重键：应用名、标题与正文。
pub fn content_key(app_name: &str, title: &str, text: &str) -> Fingerprint {
    fingerprint(&[app_name, title, text])
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contains_is_pure_query() {
        let mut d = DedupState::new();
        let k = fingerprint(&["k"]);
        assert!(!d.contains(&k));
        // 纯查询不写 pending：重复查询结果一致，且随后的 check_and_pend 仍可通过
        assert!(!d.contains(&k));
        assert!(d.check_and_pend(&k, CONTENT_DEDUP_TTL_MS));
    }

    #[test]
    fn contains_true_after_mark_and_cleanup_keeps_live_entry() {
        let mut d = DedupState::new();
        let key = content_key("app", "t", "x");
        d.mark_seen(&key);
        assert!(d.contains(&key));
        d.cleanup();
        // 未过期：清理不得移除窗口内条目
        assert!(d.contains(&key));
    }

    #[test]
    fn cleanup_drops_entry_past_its_own_window() {
        let mut d = DedupState::new();
        let key = content_key("app", "t", "x");
        d.mark_seen(&key);
        d.content.cleanup(now_ms() + CONTENT_DEDUP_TTL_MS + 1);
        assert!(!d.contains(&key));
    }

    #[test]
    fn long_window_survives_short_window_cleanup() {
        // 超级岛锁屏去重 300s 与出站 3s 共用出站域：
        // 按条目自身过期时刻清理，短窗口清理不得带走长窗口键。
        let mut d = DedupState::new();
        let island = fingerprint(&["island"]);
        assert!(d.check_and_pend(&island, 300_000));
        d.mark_sent(&island, 300_000);

        let base = now_ms();
        d.outbound.cleanup(base + 10_000);
        assert!(
            d.outbound.sent.contains_key(&island),
            "300s 窗口的键不应被 10s 时点的清理删除"
        );

        d.outbound.cleanup(base + 300_001);
        assert!(
            !d.outbound.sent.contains_key(&island),
            "超过自身窗口后应回收"
        );
    }

    #[test]
    fn fingerprint_distinguishes_field_boundaries() {
        assert_ne!(fingerprint(&["a|b", "c"]), fingerprint(&["a", "b|c"]));
        assert_eq!(fingerprint(&["a", "b"]), fingerprint(&["a", "b"]));
    }

    #[test]
    fn content_and_outbound_domains_are_isolated() {
        let mut d = DedupState::new();
        let outbound = compute_dedup_key("uuid-1", "data-1");
        let content = content_key("app", "title", "text");
        d.mark_sent(&outbound, 3000);
        d.mark_seen(&content);
        d.clear_content();
        assert!(!d.check_and_pend(&outbound, 3000), "出站键仍在窗口内");
        assert!(!d.contains(&content), "内容键应已清除");
    }

    #[test]
    fn expired_pending_entry_is_registrable_again() {
        let mut d = DedupState::new();
        let key = fingerprint(&["k"]);
        assert!(d.check_and_pend(&key, 3000));
        assert!(!d.check_and_pend(&key, 3000), "窗口内仍视为重复");
        d.outbound.pending.insert(key, now_ms() - 1);
        assert!(d.check_and_pend(&key, 3000), "过期 pending 应可重新登记");
    }

    #[test]
    fn maybe_cleanup_drops_expired_entries() {
        let mut d = DedupState::new();
        let stale = fingerprint(&["stale"]);
        d.outbound.sent.insert(stale, now_ms() - 1);
        for i in 0..DEDUP_CLEANUP_THRESHOLD + 1 {
            d.check_and_pend(&fingerprint(&[&format!("k{}", i)]), 3000);
        }
        d.maybe_cleanup();
        assert!(!d.outbound.sent.contains_key(&stale));
        assert!(d.outbound.pending.contains_key(&fingerprint(&["k0"])));
    }

    #[test]
    fn compute_dedup_key_is_deterministic_and_distinct() {
        let a = compute_dedup_key("uuid-1", "data");
        assert_eq!(a, compute_dedup_key("uuid-1", "data"));
        assert_eq!(a.len(), 32);
        assert_ne!(a, compute_dedup_key("uuid-2", "data"));
        assert_ne!(a, compute_dedup_key("uuid-1", "data2"));
    }
}
