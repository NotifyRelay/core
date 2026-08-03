use crate::sender_queue::{SendItem, SenderQueue};

/// 防循环时间窗（毫秒）：写入剪贴板触发的回环在此窗口内被忽略
const ANTI_LOOP_DELAY_MS: i64 = 1000;
/// 频率限制（毫秒）：同一内容的最小发送间隔
const FREQ_LIMIT_MS: i64 = 1000;
/// 大内容阈值（字节）：超过后返回 file_transfer 动作交由平台文件通道处理
const LARGE_CONTENT_THRESHOLD: usize = 2 * 1024 * 1024;

/// 剪贴板同步状态（Rust 内部维护，平台端不再持有任何同步状态）
pub struct ClipboardState {
    pub last_content: String,
    pub last_type: String,
    pub last_sync_time: i64,
    pub last_received_content: String,
    pub last_received_type: String,
    pub last_received_time: i64,
}

impl ClipboardState {
    pub fn new() -> Self {
        Self {
            last_content: String::new(),
            last_type: String::new(),
            last_sync_time: 0,
            last_received_content: String::new(),
            last_received_type: String::new(),
            last_received_time: 0,
        }
    }
}

impl Default for ClipboardState {
    fn default() -> Self {
        Self::new()
    }
}

/// MIME 类型归一化为内部类型：text/xxx → text, image/xxx → image
fn normalize_type(mime: &str) -> &str {
    if mime.starts_with("text/") {
        "text"
    } else if mime.starts_with("image/") {
        "image"
    } else {
        mime
    }
}

/// 归一化内容：data URL（data:image/...;base64,xxx）提取纯 base64 部分
fn normalize_content(content: &str) -> String {
    let lower = content.to_lowercase();
    if lower.starts_with("data:image/") && content.contains(',') {
        content
            .split_once(',')
            .map(|(_, rest)| rest.to_string())
            .unwrap_or_else(|| content.to_string())
    } else {
        content.to_string()
    }
}

/// 估算 base64 解码后的字节长度
fn decoded_len(b64: &str) -> usize {
    let len = b64.len();
    (len * 3) / 4
}

/// 平台检测到剪贴板变化时调用。
/// Rust 内部完成类型归一化、内容未变跳过、防循环、频率限制与 2MB 阈值判定，
/// 通过后直接构造 DATA_CLIPBOARD 报文按 targets 逐个入队发送。
/// 返回 JSON：{"action": "sent"|"skipped"|"file_transfer", "reason": "..."}
pub fn on_changed(
    state: &mut ClipboardState,
    queue: &SenderQueue,
    targets: &[String],
    mime: &str,
    content: &str,
    now: i64,
    force: bool,
) -> String {
    let ctype = normalize_type(mime).to_string();
    let ccontent = normalize_content(content);

    if ccontent.is_empty() {
        return skipped("内容为空");
    }

    // 防循环：内容与最近一次从远程接收的一致且在窗口内
    if !state.last_received_content.is_empty()
        && state.last_received_type == ctype
        && state.last_received_content == ccontent
        && now - state.last_received_time < ANTI_LOOP_DELAY_MS
    {
        return skipped("内容来自远程，跳过发送");
    }

    // 内容未变（force 手动同步时允许重发）
    if !force
        && !state.last_content.is_empty()
        && state.last_content == ccontent
        && state.last_type == ctype
    {
        return skipped("内容未改变");
    }

    // 频率限制
    if state.last_sync_time > 0 && now - state.last_sync_time < FREQ_LIMIT_MS {
        return skipped("同步过于频繁");
    }

    // 大图片走文件传输通道（仅 image 类型判定阈值）
    if ctype == "image" && decoded_len(&ccontent) > LARGE_CONTENT_THRESHOLD {
        state.last_content = ccontent;
        state.last_type = ctype;
        state.last_sync_time = now;
        return r#"{"action":"file_transfer"}"#.to_string();
    }

    let payload = build_data_clipboard_json(&ctype, &ccontent, now);
    for uuid in targets {
        if uuid.is_empty() {
            continue;
        }
        queue.enqueue(SendItem {
            device_uuid: uuid.clone(),
            header: "DATA_CLIPBOARD".to_string(),
            plaintext: payload.clone(),
            dedup_key: None,
            retries_left: 0,
            coalesce_key: None,
        });
    }

    state.last_content = ccontent;
    state.last_type = ctype;
    state.last_sync_time = now;
    r#"{"action":"sent"}"#.to_string()
}

/// 平台收到远程剪贴板（DATA_CLIPBOARD 报文）时调用。
/// Rust 解析报文、归一化类型并登记防循环时间窗，返回内容供平台写入系统剪贴板。
/// 返回 JSON：{"type": "text"|"image", "content": "..."}
pub fn on_received(state: &mut ClipboardState, payload_json: &str, now: i64) -> String {
    let (ctype, content) = match serde_json::from_str::<serde_json::Value>(payload_json) {
        Ok(v) => {
            let mime = v
                .get("clipboardType")
                .and_then(|t| t.as_str())
                .unwrap_or("text");
            let c = v.get("content").and_then(|c| c.as_str()).unwrap_or("");
            (normalize_type(mime).to_string(), normalize_content(c))
        }
        Err(_) => return r#"{"type":"text","content":""}"#.to_string(),
    };

    state.last_received_content = content.clone();
    state.last_received_type = ctype.clone();
    state.last_received_time = now;

    serde_json::json!({ "type": ctype, "content": content }).to_string()
}

fn build_data_clipboard_json(ctype: &str, content: &str, now: i64) -> String {
    serde_json::json!({
        "type": "DATA_CLIPBOARD",
        "clipboardType": ctype,
        "content": content,
        "time": now,
    })
    .to_string()
}

fn skipped(reason: &str) -> String {
    serde_json::json!({ "action": "skipped", "reason": reason }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn queue() -> SenderQueue {
        SenderQueue::new()
    }

    #[test]
    fn test_normalize_type() {
        assert_eq!(normalize_type("text/plain"), "text");
        assert_eq!(normalize_type("text/html"), "text");
        assert_eq!(normalize_type("image/png"), "image");
        assert_eq!(normalize_type("application/pdf"), "application/pdf");
    }

    #[test]
    fn test_normalize_content_data_url() {
        assert_eq!(normalize_content("data:image/png;base64,ABC="), "ABC=");
        assert_eq!(normalize_content("hello"), "hello");
    }

    #[test]
    fn test_on_changed_sends_to_targets() {
        let mut state = ClipboardState::new();
        let q = queue();
        let targets = vec!["dev1".to_string(), "dev2".to_string()];
        let result = on_changed(&mut state, &q, &targets, "text/plain", "hello", 1000, false);
        assert_eq!(result, r#"{"action":"sent"}"#);
        assert_eq!(state.last_content, "hello");
        assert_eq!(q.pending_count(), 2);
    }

    #[test]
    fn test_on_changed_skips_unchanged() {
        let mut state = ClipboardState::new();
        let q = queue();
        let targets = vec!["dev1".to_string()];
        let _ = on_changed(&mut state, &q, &targets, "text/plain", "hello", 1000, false);
        let result = on_changed(&mut state, &q, &targets, "text/plain", "hello", 2000, false);
        assert!(result.contains("skipped"));
        assert_eq!(q.pending_count(), 1);
    }

    #[test]
    fn test_on_changed_force_resends() {
        let mut state = ClipboardState::new();
        let q = queue();
        let targets = vec!["dev1".to_string()];
        let _ = on_changed(&mut state, &q, &targets, "text/plain", "hello", 1000, false);
        let result = on_changed(&mut state, &q, &targets, "text/plain", "hello", 2000, true);
        assert_eq!(result, r#"{"action":"sent"}"#);
        assert_eq!(q.pending_count(), 2);
    }

    #[test]
    fn test_on_changed_skips_loop() {
        let mut state = ClipboardState::new();
        state.last_received_content = "hello".to_string();
        state.last_received_type = "text".to_string();
        state.last_received_time = 900;
        let q = queue();
        let targets = vec!["dev1".to_string()];
        let result = on_changed(&mut state, &q, &targets, "text/plain", "hello", 1000, true);
        assert!(result.contains("skipped"));
        assert_eq!(q.pending_count(), 0);
    }

    #[test]
    fn test_on_changed_frequency_limit() {
        let mut state = ClipboardState::new();
        let q = queue();
        let targets = vec!["dev1".to_string()];
        let _ = on_changed(&mut state, &q, &targets, "text/plain", "hello", 1000, false);
        let result = on_changed(&mut state, &q, &targets, "text/plain", "world", 1500, false);
        assert!(result.contains("skipped"));
    }

    #[test]
    fn test_on_changed_large_image_returns_file_transfer() {
        let mut state = ClipboardState::new();
        let q = queue();
        let targets = vec!["dev1".to_string()];
        let big = "A".repeat(LARGE_CONTENT_THRESHOLD * 4 / 3 + 100);
        let result = on_changed(&mut state, &q, &targets, "image/png", &big, 1000, false);
        assert_eq!(result, r#"{"action":"file_transfer"}"#);
        assert_eq!(q.pending_count(), 0);
    }

    #[test]
    fn test_on_received_normalizes() {
        let mut state = ClipboardState::new();
        let result = on_received(
            &mut state,
            r#"{"clipboardType":"image/png","content":"AAA=","time":1000}"#,
            2000,
        );
        assert!(result.contains("\"type\":\"image\""));
        assert!(result.contains("\"content\":\"AAA=\""));
        assert_eq!(state.last_received_content, "AAA=");
        assert_eq!(state.last_received_type, "image");
        assert_eq!(state.last_received_time, 2000);
    }
}
