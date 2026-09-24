use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::crypto::aes;
use crate::protocol::codec;
use crate::SafeContext;

/// 消息发送项（IP 由 Rust 内部分配，不依赖平台端传入）
pub struct SendItem {
    pub device_uuid: String,
    pub header: String,
    pub plaintext: String,
    pub dedup_key: Option<String>,
    pub retries_left: u32,
    /// 队列内合并键（媒体类消息为 "device_uuid|header"）：
    /// 全量状态入队时移除队列中同键旧项，避免积压后爆发式回放
    pub coalesce_key: Option<String>,
}

pub struct SenderQueue {
    inner: Arc<Mutex<SenderQueueInner>>,
    running: Arc<AtomicBool>,
    /// 当前并发发送任务数
    active: Arc<AtomicUsize>,
}

struct SenderQueueInner {
    items: Vec<SendItem>,
    /// dedup_key -> 发送开始时间
    in_flight: HashMap<String, Instant>,
    /// device_uuid -> 发送开始时间（同设备串行发送，保证消息顺序）
    busy_devices: HashMap<String, Instant>,
    /// device_uuid -> 冷却截止时间（发送失败退避，避免反复烧满连接超时）
    device_cooldown: HashMap<String, Instant>,
    /// device_uuid -> 连续失败次数
    device_fail_streak: HashMap<String, u32>,
}

/// 发送任务完成/异常时清理并发状态（RAII，防止线程 panic 导致状态泄漏）
struct TaskGuard {
    inner: Arc<Mutex<SenderQueueInner>>,
    active: Arc<AtomicUsize>,
    device_uuid: String,
    dedup_key: Option<String>,
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
        if let Ok(mut guard) = self.inner.lock() {
            guard.busy_devices.remove(&self.device_uuid);
            if let Some(ref key) = self.dedup_key {
                if !key.is_empty() {
                    guard.in_flight.remove(key);
                }
            }
        }
    }
}

impl SenderQueue {
    const MAX_CONCURRENT: usize = 5;
    const MAX_RETRIES: u32 = 3;
    /// 媒体类消息连接超时（毫秒）：过期状态无重发价值，快速失败
    const MEDIA_TIMEOUT_MS: u32 = 800;
    /// 普通消息连接超时（毫秒）
    const DEFAULT_TIMEOUT_MS: u32 = 3000;
    /// 失败退避冷却上限（秒）
    const MAX_COOLDOWN_SECS: u64 = 5;

    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(SenderQueueInner {
                items: Vec::new(),
                in_flight: HashMap::new(),
                busy_devices: HashMap::new(),
                device_cooldown: HashMap::new(),
                device_fail_streak: HashMap::new(),
            })),
            running: Arc::new(AtomicBool::new(true)),
            active: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl Default for SenderQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl SenderQueue {
    /// 媒体类消息 header（高频全量状态，仅保留最新）
    fn is_media_header(header: &str) -> bool {
        matches!(header, "DATA_MEDIAPLAY" | "DATA_SUPERISLAND")
    }

    /// 是否为增量负载（含 changes 的差量消息依赖前序消息，不可替换旧项）
    fn is_delta_payload(plaintext: &str) -> bool {
        plaintext.contains("\"changes\"")
    }

    /// 是否为媒体/超级岛"结束包"（会话终止，对端需据此移除卡片/岛）：
    /// 平台端统一用 terminateValue=="__END__" 或 terminate:true 标识。
    /// 结束包丢失会导致对端残留过期媒体展示，故必须可靠重试。
    fn is_media_end_packet(plaintext: &str) -> bool {
        plaintext.contains("__END__") || plaintext.contains("\"terminate\":true")
    }

    /// 队列项是否属于「已过期的实时状态」：发送前与入队前的统一判定。
    ///
    /// 非实时 header（通知/图标/控制等）与结束包一律不判过期；
    /// 未携带 `ts` 的负载保守保留（旧格式/异常负载，不因字段缺失误丢）。
    fn is_stale_realtime_item(it: &SendItem) -> bool {
        if !Self::is_media_header(&it.header) || Self::is_media_end_packet(&it.plaintext) {
            return false;
        }
        match crate::timestamp::extract_ts(&it.plaintext) {
            Some(ts) => crate::timestamp::is_stale(ts, crate::timestamp::now_ms()),
            None => false,
        }
    }

    /// 清理指定设备 + header 下已过期的实时状态积压（FULL 与 DELTA 均适用）。
    ///
    /// 断线期间实时状态（超级岛 / 媒体）会持续入队，恢复后按序回放会造成"追逐"；
    /// 此处按注入的 `ts` 丢弃超过 `STATE_MAX_AGE_MS` 的旧项。结束包不丢弃
    /// （会话终止信号必须送达，否则对端卡片/岛残留）。
    ///
    /// 返回被丢弃条数：调用方据此把本次推送强制为 FULL，重建接收端基线
    /// （丢弃 DELTA 可能使 `pics` 等真差量字段在接收端缺失，FULL 可一次性纠正）。
    pub fn purge_stale_realtime(&self, device_uuid: &str, header: &str) -> usize {
        if !Self::is_media_header(header) {
            return 0;
        }
        let now = crate::timestamp::now_ms();
        let Ok(mut inner) = self.inner.lock() else {
            return 0;
        };
        let before = inner.items.len();
        inner.items.retain(|it| {
            if it.device_uuid != device_uuid || it.header != header {
                return true;
            }
            if Self::is_media_end_packet(&it.plaintext) {
                return true;
            }
            match crate::timestamp::extract_ts(&it.plaintext) {
                Some(ts) => !crate::timestamp::is_stale(ts, now),
                // 未携带 ts（旧格式/异常负载）：保守保留
                None => true,
            }
        });
        let dropped = before - inner.items.len();
        if dropped > 0 {
            log::debug!(
                "发送队列: 清理过期实时状态积压 uuid={} header={}, 丢弃 {} 条",
                device_uuid,
                header,
                dropped
            );
        }
        dropped
    }

    pub fn enqueue(&self, mut item: SendItem) {
        let is_media = Self::is_media_header(&item.header);
        let is_end = is_media && Self::is_media_end_packet(&item.plaintext);
        // 实时状态统一补齐生成时刻 `ts`：state_merge 的主动推送已注入，
        // 此处兜底覆盖保活/重发等旁路，保证接收端对所有实时包都能做时效判定。
        if is_media && crate::timestamp::extract_ts(&item.plaintext).is_none() {
            item.plaintext =
                crate::timestamp::inject_ts(&item.plaintext, crate::timestamp::now_ms());
        }
        // 媒体高频状态失败即弃（过期状态重发只会造成回放追赶）；
        // 但结束包必须可靠送达（否则对端媒体卡片/岛无法消失），与通知/控制一样重试。
        item.retries_left = if is_media && !is_end {
            1
        } else {
            Self::MAX_RETRIES
        };
        if is_media && item.coalesce_key.is_none() {
            item.coalesce_key = Some(format!("{}|{}", item.device_uuid, item.header));
        }
        if let Ok(mut inner) = self.inner.lock() {
            // 全量媒体状态入队时移除同键旧项（含未发出的增量），只保留最新，
            // 根除网络恢复后过期状态的爆发式回放
            if let Some(ref key) = item.coalesce_key {
                if !Self::is_delta_payload(&item.plaintext) {
                    let before = inner.items.len();
                    inner
                        .items
                        .retain(|it| it.coalesce_key.as_deref() != Some(key.as_str()));
                    let dropped = before - inner.items.len();
                    if dropped > 0 {
                        log::debug!(
                            "发送队列: 合并过期媒体状态 key={}, 丢弃 {} 条旧项",
                            key,
                            dropped
                        );
                    }
                }
            }
            inner.items.push(item);
        }
    }

    /// 启动后台调度线程（实际发送在并发任务线程中执行，同设备串行）
    pub fn start_worker(&self, ctx_ptr: usize) {
        let inner = self.inner.clone();
        let running = self.running.clone();
        let active = self.active.clone();

        thread::Builder::new()
            .name("sender-queue".to_string())
            .spawn(move || {
                loop {
                    if !running.load(Ordering::Relaxed) {
                        break;
                    }

                    if active.load(Ordering::Relaxed) >= Self::MAX_CONCURRENT {
                        thread::sleep(Duration::from_millis(20));
                        continue;
                    }

                    let item = {
                        let mut guard = match inner.lock() {
                            Ok(g) => g,
                            Err(_) => {
                                thread::sleep(Duration::from_millis(50));
                                continue;
                            }
                        };
                        let now = Instant::now();
                        // 清理超时状态（防异常泄漏）
                        guard
                            .in_flight
                            .retain(|_, &mut ts| now.duration_since(ts).as_secs() < 5);
                        guard
                            .busy_devices
                            .retain(|_, &mut ts| now.duration_since(ts).as_secs() < 30);
                        guard.device_cooldown.retain(|_, &mut until| until > now);

                        // 发送前丢弃已过期的实时状态：设备长时间离线时队列会持续积压
                        // 超级岛/媒体状态，恢复后即使没有新推送，worker 也会按序回放造成"追逐"。
                        // 此处按注入的 `ts` 丢弃过期项（结束包保留，会话终止信号必须送达）。
                        let before = guard.items.len();
                        guard.items.retain(|it| !Self::is_stale_realtime_item(it));
                        let dropped = before - guard.items.len();
                        if dropped > 0 {
                            log::debug!("发送队列: 发送前清理过期实时状态 {} 条", dropped);
                        }

                        // 选取可发送项：同 dedup_key 不并发、同设备串行、冷却中的设备跳过
                        let idx = guard.items.iter().position(|it| {
                            let key = it.dedup_key.as_deref().unwrap_or("");
                            (key.is_empty() || !guard.in_flight.contains_key(key))
                                && !guard.busy_devices.contains_key(&it.device_uuid)
                                && !guard.device_cooldown.contains_key(&it.device_uuid)
                        });
                        match idx {
                            Some(i) => {
                                let it = guard.items.remove(i);
                                if let Some(ref key) = it.dedup_key {
                                    if !key.is_empty() {
                                        guard.in_flight.insert(key.clone(), now);
                                    }
                                }
                                guard.busy_devices.insert(it.device_uuid.clone(), now);
                                Some(it)
                            }
                            None => None,
                        }
                    };

                    match item {
                        Some(item) => {
                            active.fetch_add(1, Ordering::Relaxed);
                            let task_guard = TaskGuard {
                                inner: inner.clone(),
                                active: active.clone(),
                                device_uuid: item.device_uuid.clone(),
                                dedup_key: item.dedup_key.clone(),
                            };
                            let task_inner = inner.clone();
                            let spawn_result = thread::Builder::new()
                                .name("sender-task".to_string())
                                .spawn(move || {
                                    let _guard = task_guard;
                                    Self::process_item(ctx_ptr, &item, &task_inner);
                                });
                            if let Err(e) = spawn_result {
                                // spawn 失败时闭包被丢弃，TaskGuard 的 Drop 已清理状态
                                log::warn!("发送队列: 派生发送任务失败: {}", e);
                                thread::sleep(Duration::from_millis(100));
                            }
                        }
                        None => {
                            thread::sleep(Duration::from_millis(50));
                        }
                    }
                }
            })
            .expect("启动发送队列线程失败");
    }

    fn process_item(ctx_ptr: usize, item: &SendItem, inner: &Arc<Mutex<SenderQueueInner>>) {
        let send_ok = match Self::try_send(ctx_ptr, item) {
            Ok(v) => v,
            Err(_) => return,
        };

        let ctx = unsafe { &*(ctx_ptr as *const SafeContext) };

        if send_ok {
            if let Some(ref key) = item.dedup_key {
                if !key.is_empty() {
                    // 后台线程：通过 lock() 取锁，与扫描回调、FFI 共用同一把锁
                    if let Ok(mut guard) = ctx.lock() {
                        guard.dedup.mark_sent(key);
                    }
                }
            }
            // 发送成功：清除该设备的失败退避状态
            if let Ok(mut guard) = inner.lock() {
                guard.device_fail_streak.remove(&item.device_uuid);
                guard.device_cooldown.remove(&item.device_uuid);
            }
            log::debug!(
                "发送队列: 已发送 uuid={}, header={}",
                item.device_uuid,
                item.header
            );
            return;
        }

        // 发送失败：设置递增冷却，避免对不可达设备反复握手占用并发槽位
        if let Ok(mut guard) = inner.lock() {
            let streak = {
                let entry = guard
                    .device_fail_streak
                    .entry(item.device_uuid.clone())
                    .or_insert(0);
                *entry = entry.saturating_add(1);
                *entry
            };
            let secs = u64::from(streak).min(Self::MAX_COOLDOWN_SECS);
            guard.device_cooldown.insert(
                item.device_uuid.clone(),
                Instant::now() + Duration::from_secs(secs),
            );
            log::debug!(
                "发送队列: 设备失败退避 uuid={}, 连续失败 {} 次, 冷却 {}s",
                item.device_uuid,
                streak,
                secs
            );
        }

        if item.retries_left > 1 {
            log::debug!(
                "发送队列: 重试第 {} 次 uuid={}, header={}",
                Self::MAX_RETRIES - item.retries_left + 1,
                item.device_uuid,
                item.header
            );
            if let Ok(mut guard) = inner.lock() {
                guard.items.push(SendItem {
                    device_uuid: item.device_uuid.clone(),
                    header: item.header.clone(),
                    plaintext: item.plaintext.clone(),
                    dedup_key: item.dedup_key.clone(),
                    retries_left: item.retries_left - 1,
                    coalesce_key: item.coalesce_key.clone(),
                });
            }
        } else {
            if let Some(ref key) = item.dedup_key {
                if !key.is_empty() {
                    if let Ok(mut guard) = ctx.lock() {
                        guard.dedup.clear_pending(key);
                    }
                }
            }
            if Self::is_media_header(&item.header) && !Self::is_media_end_packet(&item.plaintext) {
                log::debug!(
                    "发送队列: 媒体高频状态发送失败即弃 uuid={}, header={}",
                    item.device_uuid,
                    item.header
                );
            } else {
                log::warn!(
                    "发送队列: 发送失败已达最大重试 uuid={}, header={}",
                    item.device_uuid,
                    item.header
                );
            }
        }
    }

    fn try_send(ctx_ptr: usize, item: &SendItem) -> Result<bool, ()> {
        let ctx = unsafe { &*(ctx_ptr as *const SafeContext) };
        let (key_arr, local_uuid) = {
            // 后台线程：通过 lock() 取锁，与扫描回调、FFI 共用同一把锁
            let Ok(guard) = ctx.lock() else {
                return Err(());
            };
            let key = guard.crypto.get_aes_key(&item.device_uuid);
            let uuid = guard
                .broadcast_info
                .as_ref()
                .map(|i| i.uuid.clone())
                .unwrap_or_default();
            (key, uuid)
        };

        let key_arr = match key_arr {
            Some(k) => k,
            None => {
                log::warn!("发送队列: 未找到密钥 uuid={}", item.device_uuid);
                return Ok(false);
            }
        };

        if !local_uuid.is_empty() && item.device_uuid == local_uuid {
            log::warn!("发送队列: 跳过向自身发送 uuid={}", item.device_uuid);
            return Ok(false);
        }

        // DATA 通道统一使用绑定 core 版本的 AAD：跨 major.minor 时对端 AAD 不同，
        // GCM 认证必然失败，即便公钥与密钥完全一致也无法通信。
        let encrypted = match aes::encrypt_with_aad(
            &key_arr,
            item.plaintext.as_bytes(),
            &crate::protocol::version::data_aad(),
        ) {
            Ok(e) => e,
            Err(_) => return Ok(false),
        };
        let msg = codec::encode_data_message(&item.header, &local_uuid, "", &encrypted);

        // 始终使用 oneshot 新连接发送，不依赖可能即将关闭的 TCP session
        let ip = {
            let Ok(guard) = ctx.lock() else {
                return Ok(false);
            };
            guard
                .device_ips
                .lock()
                .ok()
                .and_then(|ips| ips.get(&item.device_uuid).cloned())
                .unwrap_or_default()
        };
        if !ip.is_empty() && ip != "0.0.0.0" {
            // 媒体类消息用短超时快速失败，避免长时间占用并发槽位
            let timeout_ms = if Self::is_media_header(&item.header) {
                Self::MEDIA_TIMEOUT_MS
            } else {
                Self::DEFAULT_TIMEOUT_MS
            };
            Ok(crate::network::oneshot_send_only(
                &msg,
                &ip,
                codec::DEFAULT_TCP_PORT,
                timeout_ms,
            ))
        } else {
            log::warn!("发送队列: 无有效IP uuid={}", item.device_uuid);
            Ok(false)
        }
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    /// 当前待发送项数量（供状态查询与测试使用）
    pub fn pending_count(&self) -> usize {
        self.inner.lock().map(|g| g.items.len()).unwrap_or(0)
    }

    /// 测试辅助：清空队列并返回全部明文（仅测试用）
    #[cfg(test)]
    pub fn test_drain_plaintexts(&self) -> Vec<String> {
        self.inner
            .lock()
            .map(|mut g| {
                let texts = g.items.iter().map(|i| i.plaintext.clone()).collect();
                g.items.clear();
                texts
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(uuid: &str, header: &str, text: &str) -> SendItem {
        SendItem {
            device_uuid: uuid.to_string(),
            header: header.to_string(),
            plaintext: text.to_string(),
            dedup_key: None,
            retries_left: 0,
            coalesce_key: None,
        }
    }

    #[test]
    fn test_media_full_coalesce_keeps_latest() {
        let q = SenderQueue::new();
        q.enqueue(item("dev1", "DATA_MEDIAPLAY", r#"{"title":"a"}"#));
        q.enqueue(item("dev1", "DATA_MEDIAPLAY", r#"{"title":"b"}"#));
        q.enqueue(item("dev1", "DATA_MEDIAPLAY", r#"{"title":"c"}"#));
        let inner = q.inner.lock().unwrap();
        assert_eq!(inner.items.len(), 1);
        assert!(inner.items[0].plaintext.contains("\"c\""));
    }

    #[test]
    fn test_media_retries_disabled() {
        let q = SenderQueue::new();
        q.enqueue(item("dev1", "DATA_MEDIAPLAY", r#"{"title":"a"}"#));
        q.enqueue(item("dev1", "DATA_NOTIFICATION", r#"{"title":"n"}"#));
        let inner = q.inner.lock().unwrap();
        assert_eq!(inner.items[0].retries_left, 1);
        assert_eq!(inner.items[1].retries_left, SenderQueue::MAX_RETRIES);
    }

    #[test]
    fn test_media_end_packet_retries_enabled() {
        let q = SenderQueue::new();
        // 结束包（terminateValue=__END__）必须可靠送达，需重试
        q.enqueue(item(
            "dev1",
            "DATA_MEDIAPLAY",
            r#"{"terminate":true,"terminateValue":"__END__"}"#,
        ));
        q.enqueue(item(
            "dev1",
            "DATA_SUPERISLAND",
            r#"{"terminateValue":"__END__"}"#,
        ));
        let inner = q.inner.lock().unwrap();
        assert_eq!(inner.items[0].retries_left, SenderQueue::MAX_RETRIES);
        assert_eq!(inner.items[1].retries_left, SenderQueue::MAX_RETRIES);
    }

    #[test]
    fn test_media_delta_not_replaced() {
        let q = SenderQueue::new();
        q.enqueue(item("dev1", "DATA_MEDIAPLAY", r#"{"title":"a"}"#));
        q.enqueue(item(
            "dev1",
            "DATA_MEDIAPLAY",
            r#"{"changes":{"title":"b"}}"#,
        ));
        let inner = q.inner.lock().unwrap();
        // 增量项不替换旧项，追加保持顺序
        assert_eq!(inner.items.len(), 2);
    }

    #[test]
    fn test_full_removes_pending_deltas() {
        let q = SenderQueue::new();
        q.enqueue(item("dev1", "DATA_MEDIAPLAY", r#"{"title":"a"}"#));
        q.enqueue(item(
            "dev1",
            "DATA_MEDIAPLAY",
            r#"{"changes":{"title":"b"}}"#,
        ));
        q.enqueue(item("dev1", "DATA_MEDIAPLAY", r#"{"title":"c"}"#));
        let inner = q.inner.lock().unwrap();
        // 全量状态覆盖此前未发出的全量与增量
        assert_eq!(inner.items.len(), 1);
        assert!(inner.items[0].plaintext.contains("\"c\""));
    }

    #[test]
    fn test_different_devices_and_headers_not_coalesced() {
        let q = SenderQueue::new();
        q.enqueue(item("dev1", "DATA_MEDIAPLAY", r#"{"title":"a"}"#));
        q.enqueue(item("dev2", "DATA_MEDIAPLAY", r#"{"title":"b"}"#));
        q.enqueue(item("dev1", "DATA_SUPERISLAND", r#"{"features":[]}"#));
        let inner = q.inner.lock().unwrap();
        assert_eq!(inner.items.len(), 3);
    }

    #[test]
    fn test_non_media_never_coalesced() {
        let q = SenderQueue::new();
        q.enqueue(item("dev1", "DATA_NOTIFICATION", r#"{"title":"a"}"#));
        q.enqueue(item("dev1", "DATA_NOTIFICATION", r#"{"title":"a"}"#));
        let inner = q.inner.lock().unwrap();
        assert_eq!(inner.items.len(), 2);
        assert!(inner.items[0].coalesce_key.is_none());
    }

    #[test]
    fn test_realtime_enqueue_injects_ts() {
        let q = SenderQueue::new();
        q.enqueue(item("dev1", "DATA_MEDIAPLAY", r#"{"title":"a"}"#));
        let inner = q.inner.lock().unwrap();
        let ts = crate::timestamp::extract_ts(&inner.items[0].plaintext);
        assert!(ts.is_some_and(|t| t > 0), "实时状态入队应注入 ts");
    }

    #[test]
    fn test_notification_enqueue_does_not_inject_ts() {
        // 通知的 ts 由 FFI 入队路径注入；SenderQueue 本身只处理实时 header，
        // 避免向图标/应用列表等严格模型通道注入未声明字段
        let q = SenderQueue::new();
        q.enqueue(item(
            "dev1",
            "DATA_ICON_REQUEST",
            r#"{"packageNames":["a"]}"#,
        ));
        let inner = q.inner.lock().unwrap();
        assert!(crate::timestamp::extract_ts(&inner.items[0].plaintext).is_none());
    }

    #[test]
    fn test_is_stale_realtime_item_classification() {
        let stale = crate::timestamp::now_ms() - crate::timestamp::STATE_MAX_AGE_MS - 1;
        let fresh = crate::timestamp::now_ms();
        // 过期实时状态 → 判为过期
        assert!(SenderQueue::is_stale_realtime_item(&item(
            "dev1",
            "DATA_MEDIAPLAY",
            &format!(r#"{{"title":"a","ts":{}}}"#, stale)
        )));
        // 新鲜实时状态 → 不过期
        assert!(!SenderQueue::is_stale_realtime_item(&item(
            "dev1",
            "DATA_MEDIAPLAY",
            &format!(r#"{{"title":"a","ts":{}}}"#, fresh)
        )));
        // 结束包即便 ts 过期也保留
        assert!(!SenderQueue::is_stale_realtime_item(&item(
            "dev1",
            "DATA_MEDIAPLAY",
            &format!(
                r#"{{"terminateValue":"__END__","terminate":true,"ts":{}}}"#,
                stale
            )
        )));
        // 非实时通道不判过期（通知的累积是有益的）
        assert!(!SenderQueue::is_stale_realtime_item(&item(
            "dev1",
            "DATA_NOTIFICATION",
            &format!(r#"{{"title":"a","ts":{}}}"#, stale)
        )));
        // 未携带 ts → 保守保留
        assert!(!SenderQueue::is_stale_realtime_item(&item(
            "dev1",
            "DATA_MEDIAPLAY",
            r#"{"title":"a"}"#
        )));
    }

    #[test]
    fn test_purge_stale_realtime_scoped_to_device_and_header() {
        let q = SenderQueue::new();
        let stale = crate::timestamp::now_ms() - crate::timestamp::STATE_MAX_AGE_MS - 1;
        // 过期：dev1 + DATA_MEDIAPLAY（应被清理）
        q.enqueue(item(
            "dev1",
            "DATA_MEDIAPLAY",
            &format!(r#"{{"changes":{{"title":"s"}},"ts":{}}}"#, stale),
        ));
        // 同 header 不同设备（不应被清理）
        q.enqueue(item(
            "dev2",
            "DATA_MEDIAPLAY",
            &format!(r#"{{"changes":{{"title":"s"}},"ts":{}}}"#, stale),
        ));
        // 同设备不同 header（不应被清理）
        q.enqueue(item(
            "dev1",
            "DATA_SUPERISLAND",
            &format!(r#"{{"changes":{{"title":"s"}},"ts":{}}}"#, stale),
        ));
        let dropped = q.purge_stale_realtime("dev1", "DATA_MEDIAPLAY");
        assert_eq!(dropped, 1, "仅应清理目标设备与 header 的过期项");
        assert_eq!(q.pending_count(), 2);
    }
}
