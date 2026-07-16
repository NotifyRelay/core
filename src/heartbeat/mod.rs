use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::protocol::codec;

pub struct HeartbeatState {
    /// 设备 UUID → 最后心跳 Unix 秒时间戳
    pub last_seen: HashMap<String, i64>,
}

impl HeartbeatState {
    pub fn new() -> Self {
        Self { last_seen: HashMap::new() }
    }

    /// 记录设备心跳时间
    pub fn record(&mut self, uuid: &str) {
        let now = now_sec();
        self.last_seen.insert(uuid.to_string(), now);
    }

    /// 检查超时设备，返回超时的 UUID 列表
    pub fn check_timeouts(&self, timeout_sec: i64) -> Vec<String> {
        let now = now_sec();
        self.last_seen.iter()
            .filter(|(_, &ts)| now - ts > timeout_sec)
            .map(|(uuid, _)| uuid.clone())
            .collect()
    }

    /// 移除设备跟踪
    pub fn remove(&mut self, uuid: &str) {
        self.last_seen.remove(uuid);
    }
}

fn now_sec() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub fn parse_udp_heartbeat(line: &str) -> Option<(String, String, u16, i32, String)> {
    let parts: Vec<&str> = line.split(':').collect();
    if parts.len() < 5 {
        return None;
    }
    Some((
        parts[0].to_string(),
        parts[1].to_string(),
        parts[2].parse().unwrap_or(codec::DEFAULT_TCP_PORT),
        parts[3].parse().unwrap_or(0),
        parts[4].to_string(),
    ))
}
