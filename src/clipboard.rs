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

/// 归一化内容：data URL（data:image/...;base64,xxx）提取纯 base64 部分，换行统一为 LF。
///
/// 换行归一必须与平台写入系统剪贴板的形态同口径：防循环以内容相等为前提，
/// 平台回读的内容（已归一到 LF）才能与接收时登记的值比较。
fn normalize_content(content: &str) -> String {
    let lower = content.to_lowercase();
    let extracted = if lower.starts_with("data:image/") && content.contains(',') {
        content
            .split_once(',')
            .map(|(_, rest)| rest.to_string())
            .unwrap_or_else(|| content.to_string())
    } else {
        content.to_string()
    };
    extracted.replace("\r\n", "\n")
}

/// 估算 base64 解码后的字节长度
fn decoded_len(b64: &str) -> usize {
    let len = b64.len();
    (len * 3) / 4
}

/// 平台检测到剪贴板变化时调用。
/// Rust 内部完成类型归一化、内容未变跳过、防循环、频率限制与 2MB 阈值判定，
/// 通过后直接构造 DATA_CLIPBOARD 报文按 targets 逐个入队发送。
/// 平台不持有任何同步状态：本机复制与远端回灌的区分全部在此完成。
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

    // 防循环：最近一次从远程接收的内容在窗口内被平台写回剪贴板又回读出来。
    // 内容按归一化后的口径比较，不要求类型一致：安卓把接收到的图片以 data URL 文本写回剪贴板
    // （归一化去掉前缀），回读类型是 text 而登记类型是 image，限定类型会漏判。
    // 图片还有平台重编码的情形（剪贴板形态与线上 Base64 不同），内容不可比，退回类型与窗口判定。
    // 未接收过任何内容时 last_received_content 为空，内容分支不命中。
    let within_window = now - state.last_received_time < ANTI_LOOP_DELAY_MS;
    let same_content =
        !state.last_received_content.is_empty() && state.last_received_content == ccontent;
    let reencoded_image = state.last_received_type == "image" && ctype == "image";
    if within_window && (same_content || reencoded_image) {
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

// ===== 上下文级剪贴板入口 =====

/// 剪贴板内容变化入口（供 ABI / UniFFI 共用）。
///
/// 内部完成类型归一化、内容去重、防循环、频率限制与 2MB 阈值判定，
/// 通过后直接构造报文按 targets 逐个入队发送。
pub fn on_changed_for(
    ctx_ptr: usize,
    queue_handle: u64,
    targets_json: &str,
    mime: &str,
    content: &str,
    now_ms: i64,
    force: bool,
) -> String {
    // 目标列表由平台拼装：解析失败与"没有目标"是两回事，静默当成空列表会让发送
    // 永远不发生且不留线索（平台手拼 JSON 出错时就是这样）。
    let targets: Vec<String> = match serde_json::from_str::<Vec<String>>(targets_json) {
        Ok(list) => list.into_iter().filter(|u| !u.is_empty()).collect(),
        Err(e) => {
            log::warn!("剪贴板目标列表 JSON 无效: {e}");
            return skipped("目标列表解析失败");
        }
    };
    if targets.is_empty() {
        return skipped("no targets");
    }
    let ctx = unsafe { &*(ctx_ptr as *const crate::SafeContext) };
    let Ok(mut guard) = ctx.lock() else {
        return skipped("lock failed");
    };
    let queue = unsafe { &*(crate::handle::get(queue_handle) as *const SenderQueue) };
    on_changed(
        &mut guard.clipboard,
        queue,
        &targets,
        mime,
        content,
        now_ms,
        force,
    )
}

/// 收到远程剪贴板报文入口（供 ABI / UniFFI 共用）。
pub fn on_received_for(ctx_ptr: usize, payload_json: &str, now_ms: i64) -> String {
    let ctx = unsafe { &*(ctx_ptr as *const crate::SafeContext) };
    let Ok(mut guard) = ctx.lock() else {
        return r#"{"type":"text","content":""}"#.to_string();
    };
    on_received(&mut guard.clipboard, payload_json, now_ms)
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
    fn test_normalize_content_newlines() {
        assert_eq!(normalize_content("a\r\nb"), "a\nb");
        assert_eq!(normalize_content("a\rb"), "a\rb");
        assert_eq!(normalize_content("a\nb"), "a\nb");
    }

    #[test]
    fn test_on_received_canonicalizes_newlines() {
        let mut state = ClipboardState::new();
        let result = on_received(
            &mut state,
            r#"{"clipboardType":"text/plain","content":"a\r\nb","time":1000}"#,
            2000,
        );
        assert!(result.contains(r#""content":"a\nb""#));
        assert_eq!(state.last_received_content, "a\nb");
    }

    #[test]
    fn test_on_changed_skips_loop_for_crlf_receive() {
        let mut state = ClipboardState::new();
        let _ = on_received(
            &mut state,
            r#"{"clipboardType":"text/plain","content":"a\r\nb","time":1000}"#,
            1000,
        );
        let q = queue();
        let targets = vec!["dev1".to_string()];
        let result = on_changed(&mut state, &q, &targets, "text/plain", "a\nb", 1200, false);
        assert!(result.contains("skipped"));
        assert_eq!(q.pending_count(), 0);
    }

    #[test]
    fn test_on_changed_skips_image_loop_within_window() {
        let mut state = ClipboardState::new();
        state.last_received_content = "B0".to_string();
        state.last_received_type = "image".to_string();
        state.last_received_time = 900;
        let q = queue();
        let targets = vec!["dev1".to_string()];
        // 平台回读图片时重编码，内容与线上 Base64 不同
        let result = on_changed(&mut state, &q, &targets, "image/png", "B1", 1000, false);
        assert!(result.contains("内容来自远程"));
        assert_eq!(q.pending_count(), 0);
    }

    #[test]
    fn test_on_changed_for_reports_malformed_targets() {
        // 平台手拼 JSON 出错时必须留下可观察原因，而不是静默按"没有目标"处理
        let ctx = crate::SafeContext::new(crate::CoreContext::new());
        let ctx_ptr = &ctx as *const crate::SafeContext as usize;
        let q = queue();
        let queue_handle = crate::ffi::handle::put(&q as *const _ as *mut std::os::raw::c_void);
        let result = on_changed_for(
            ctx_ptr,
            queue_handle,
            "[ + it.uuid + ]",
            "text/plain",
            "hello",
            1000,
            false,
        );
        assert!(result.contains("目标列表解析失败"), "unexpected: {result}");
        assert_eq!(q.pending_count(), 0);
    }

    #[test]
    fn test_on_changed_skips_data_url_writeback_as_text() {
        // 安卓收到图片后把 data URL 文本写回剪贴板，Fcitx5 广播回来时类型已是 text
        let mut state = ClipboardState::new();
        let _ = on_received(
            &mut state,
            r#"{"clipboardType":"image/png","content":"AAA=","time":1000}"#,
            1000,
        );
        let q = queue();
        let targets = vec!["dev1".to_string()];
        let result = on_changed(
            &mut state,
            &q,
            &targets,
            "text/plain",
            "data:image/png;base64,AAA=",
            1200,
            false,
        );
        assert!(result.contains("内容来自远程"));
        assert_eq!(q.pending_count(), 0);
    }

    #[test]
    fn test_on_changed_skips_loop_for_same_content_across_types() {
        // 内容相等即判定为回灌，不再要求类型相等
        let mut state = ClipboardState::new();
        state.last_received_content = "hello".to_string();
        state.last_received_type = "text".to_string();
        state.last_received_time = 900;
        let q = queue();
        let targets = vec!["dev1".to_string()];
        let result = on_changed(&mut state, &q, &targets, "text/html", "hello", 1000, false);
        assert!(result.contains("内容来自远程"));
        assert_eq!(q.pending_count(), 0);
    }

    #[test]
    fn test_on_changed_sends_image_after_window() {
        let mut state = ClipboardState::new();
        state.last_received_content = "B0".to_string();
        state.last_received_type = "image".to_string();
        state.last_received_time = 1000;
        let q = queue();
        let targets = vec!["dev1".to_string()];
        let result = on_changed(&mut state, &q, &targets, "image/png", "B1", 2001, false);
        assert_eq!(result, r#"{"action":"sent"}"#);
        assert_eq!(q.pending_count(), 1);
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
