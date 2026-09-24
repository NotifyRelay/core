//! 消息时间戳系统。
//!
//! 背景：断线期间发送队列会持续累积实时状态（超级岛 / 媒体）消息，恢复连接后按序
//! 回放会造成"追逐"现象（过期的歌词/进度被快速逐条补放）。为此 core 在实时状态
//! 消息中注入生成时刻 `ts`（毫秒级 Unix 时间戳），两端据此丢弃过期数据：
//!
//! - **发送端**：入队/发送时丢弃队列中已超过 [`STATE_MAX_AGE_MS`] 的实时状态积压；
//! - **接收端**：丢弃超过 [`STATE_MAX_AGE_MS`] 的过期包，以及 `ts` 小于该会话已应用
//!   时间戳的乱序旧包。
//!
//! 通知类消息（非实时）只注入并记录 `ts`，**不做丢弃**：断线期间的通知累积是有益的，
//! 恢复后应完整补收。
//!
//! # 时钟假设
//!
//! 过期判定使用**绝对** Unix 时间戳，因此假定两端系统时钟大致同步（手机与 PC 均依赖
//! 系统 NTP 校时，偏差通常在秒级以内）。若接收端时钟**明显偏快**，可能把新鲜包误判过期
//! 而丢弃；为此 `ts <= 0`（未携带）一律不判过期，且 [`STATE_MAX_AGE_MS`] 留出 15s 余量，
//! 可吸收常规时钟偏差。两端时钟差异极大（如手动改系统时间）属异常场景，不在防护范围内。

use std::time::{SystemTime, UNIX_EPOCH};

/// 实时状态（超级岛 / 媒体）最大可接受时延（毫秒）。
///
/// 必须大于发送端保活间隔（超级岛 8s / 媒体 6s）与接收端卡片超时周期
/// （PC 普通岛 12s / Gamebar 10s / PC 媒体块 30s），否则正常保活包会被误判为过期，
/// 导致卡片"突然消失"；同时远小于断线累积量级（秒级），足以消除回放追逐。
pub const STATE_MAX_AGE_MS: i64 = 15_000;

/// 当前 Unix 毫秒时间戳（系统时钟异常时回落 0，调用方按"未携带"处理）。
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// 判断时间戳是否已过期（超过 [`STATE_MAX_AGE_MS`]）。
///
/// `ts <= 0` 表示未携带时间戳（旧版本/非实时通道），一律视为不过期，
/// 避免因字段缺失误丢数据。
pub fn is_stale(ts: i64, now: i64) -> bool {
    if ts <= 0 {
        return false;
    }
    now.saturating_sub(ts) > STATE_MAX_AGE_MS
}

/// 从 JSON 对象明文提取 `ts` 字段（非对象/缺失/非整数返回 None）。
pub fn extract_ts(plaintext: &str) -> Option<i64> {
    serde_json::from_str::<serde_json::Value>(plaintext)
        .ok()?
        .get("ts")
        .and_then(|v| v.as_i64())
}

/// 为 JSON 对象明文注入 `ts`（已存在时不覆盖），非对象原样返回。
///
/// 用于通知等由平台端构造、core 仅代为记录时间戳的通道。
pub fn inject_ts(plaintext: &str, ts: i64) -> String {
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(plaintext) else {
        return plaintext.to_string();
    };
    let Some(obj) = value.as_object_mut() else {
        return plaintext.to_string();
    };
    if !obj.contains_key("ts") {
        obj.insert("ts".to_string(), serde_json::json!(ts));
    }
    serde_json::to_string(&value).unwrap_or_else(|_| plaintext.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_ms_is_positive() {
        assert!(now_ms() > 0);
    }

    #[test]
    fn missing_timestamp_is_never_stale() {
        assert!(!is_stale(0, now_ms()));
        assert!(!is_stale(-1, now_ms()));
    }

    #[test]
    fn fresh_timestamp_is_not_stale() {
        let now = now_ms();
        assert!(!is_stale(now, now));
        assert!(!is_stale(now - STATE_MAX_AGE_MS, now));
    }

    #[test]
    fn old_timestamp_is_stale() {
        let now = now_ms();
        assert!(is_stale(now - STATE_MAX_AGE_MS - 1, now));
    }

    #[test]
    fn extract_and_inject_roundtrip() {
        let injected = inject_ts(r#"{"title":"t"}"#, 1234);
        assert_eq!(extract_ts(&injected), Some(1234));
        // 已存在 ts 不覆盖
        let kept = inject_ts(&injected, 9999);
        assert_eq!(extract_ts(&kept), Some(1234));
    }

    #[test]
    fn inject_ts_passes_through_non_object() {
        assert_eq!(inject_ts("not json", 1), "not json");
        assert_eq!(inject_ts("[1,2]", 1), "[1,2]");
        assert_eq!(extract_ts("not json"), None);
    }
}
