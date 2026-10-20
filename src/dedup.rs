use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

/// 入站内容去重键前缀：与出站发送键（64 位 sha256 十六进制）区分
pub const CONTENT_KEY_PREFIX: &str = "content|";

/// 入站内容去重窗口（毫秒）
pub const CONTENT_DEDUP_TTL_MS: i64 = 10_000;

/// sent 表超过该规模时触发惰性清理
const DEDUP_CLEANUP_THRESHOLD: usize = 1024;

pub struct DedupState {
    pending: HashSet<String>,
    sent: HashMap<String, i64>,
}

impl DedupState {
    pub fn new() -> Self {
        Self {
            pending: HashSet::new(),
            sent: HashMap::new(),
        }
    }

    /// 检查是否应发送（不在已发送 TTL 内），并标记 pending
    /// 返回 true = 可以发送，false = 重复
    pub fn check_and_pend(&mut self, dedup_key: &str, ttl_ms: i64) -> bool {
        if self.pending.contains(dedup_key) {
            return false;
        }
        if let Some(&ts) = self.sent.get(dedup_key) {
            if now_ms() - ts <= ttl_ms {
                return false;
            }
        }
        self.pending.insert(dedup_key.to_string());
        true
    }

    /// 从 pending 移到 sent（发送成功时调用）
    pub fn mark_sent(&mut self, dedup_key: &str) {
        self.pending.remove(dedup_key);
        self.sent.insert(dedup_key.to_string(), now_ms());
    }

    /// 清除 pending（发送失败时调用）
    pub fn clear_pending(&mut self, dedup_key: &str) {
        self.pending.remove(dedup_key);
    }

    /// 清理过期 sent 记录
    pub fn cleanup(&mut self, now_ms: i64, ttl_ms: i64) {
        self.sent.retain(|_, &mut ts| now_ms - ts <= ttl_ms);
    }

    /// 纯查询：键是否在 TTL 窗口内已见（只读 sent，不写入 pending）
    pub fn contains(&self, dedup_key: &str, ttl_ms: i64) -> bool {
        match self.sent.get(dedup_key) {
            Some(&ts) => now_ms() - ts <= ttl_ms,
            None => false,
        }
    }

    /// 清除指定前缀的键（pending 与 sent 同时清理）
    pub fn clear_prefix(&mut self, prefix: &str) {
        self.pending.retain(|k| !k.starts_with(prefix));
        self.sent.retain(|k, _| !k.starts_with(prefix));
    }

    /// sent 表超过阈值时按最长窗口惰性清理（仅内存回收，不改变窗口语义）
    pub fn maybe_cleanup(&mut self) {
        if self.sent.len() > DEDUP_CLEANUP_THRESHOLD {
            self.cleanup(now_ms(), CONTENT_DEDUP_TTL_MS);
        }
    }
}

/// 出站发送去重键：sha256(device_uuid|data) 的 64 位十六进制
pub fn compute_dedup_key(device_uuid: &str, data: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(format!("{}|{}", device_uuid, data).as_bytes());
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

/// 入站内容去重键：前缀 + title|text
pub fn content_key(title: &str, text: &str) -> String {
    format!("{}{}|{}", CONTENT_KEY_PREFIX, title, text)
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
        assert!(!d.contains("k", CONTENT_DEDUP_TTL_MS));
        // 纯查询不写 pending：重复查询结果一致，且随后的 check_and_pend 仍可通过
        assert!(!d.contains("k", CONTENT_DEDUP_TTL_MS));
        assert!(d.check_and_pend("k", CONTENT_DEDUP_TTL_MS));
    }

    #[test]
    fn contains_true_after_mark_and_false_after_cleanup() {
        let mut d = DedupState::new();
        let key = content_key("t", "x");
        d.mark_sent(&key);
        assert!(d.contains(&key, CONTENT_DEDUP_TTL_MS));
        d.cleanup(now_ms() + CONTENT_DEDUP_TTL_MS + 1, CONTENT_DEDUP_TTL_MS);
        assert!(!d.contains(&key, CONTENT_DEDUP_TTL_MS));
    }

    #[test]
    fn clear_prefix_keeps_outbound_keys() {
        let mut d = DedupState::new();
        let outbound = compute_dedup_key("uuid-1", "data-1");
        let content = content_key("title", "text");
        d.mark_sent(&outbound);
        d.mark_sent(&content);
        d.clear_prefix(CONTENT_KEY_PREFIX);
        assert!(d.contains(&outbound, CONTENT_DEDUP_TTL_MS));
        assert!(!d.contains(&content, CONTENT_DEDUP_TTL_MS));
    }

    #[test]
    fn maybe_cleanup_drops_expired_entries() {
        let mut d = DedupState::new();
        d.sent
            .insert("stale".to_string(), now_ms() - CONTENT_DEDUP_TTL_MS - 1);
        for i in 0..DEDUP_CLEANUP_THRESHOLD + 1 {
            d.mark_sent(&format!("k{}", i));
        }
        d.maybe_cleanup();
        assert!(!d.contains("stale", CONTENT_DEDUP_TTL_MS));
        assert!(d.contains("k0", CONTENT_DEDUP_TTL_MS));
    }

    #[test]
    fn compute_dedup_key_is_deterministic_and_distinct() {
        let a = compute_dedup_key("uuid-1", "data");
        assert_eq!(a, compute_dedup_key("uuid-1", "data"));
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, compute_dedup_key("uuid-2", "data"));
        assert_ne!(a, compute_dedup_key("uuid-1", "data2"));
    }
}
