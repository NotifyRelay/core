use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct DedupState {
    pending: HashSet<String>,
    sent: HashMap<String, i64>,
}

impl DedupState {
    pub fn new() -> Self {
        Self { pending: HashSet::new(), sent: HashMap::new() }
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
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
