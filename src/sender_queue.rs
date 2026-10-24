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
    /// core 上下文指针：补清理未发送即被丢弃项的去重键时使用（0 表示未绑定）
    ctx_ptr: AtomicUsize,
    /// 待补清理的去重键：丢弃发生在可能已持有 ctx 锁的调用栈内，此处只登记
    orphan_keys: Arc<Mutex<Vec<String>>>,
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
    /// orphan_keys 上限（超出丢弃最旧记录，正常路径每轮 worker 即清空）
    const MAX_ORPHAN_KEYS: usize = 4096;

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
            ctx_ptr: AtomicUsize::new(0),
            orphan_keys: Arc::new(Mutex::new(Vec::new())),
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

    /// 绑定 core 上下文指针（队列创建时写入；0 表示未绑定）
    pub(crate) fn set_ctx_ptr(&self, ctx_ptr: usize) {
        self.ctx_ptr.store(ctx_ptr, Ordering::Relaxed);
    }

    /// 登记未发送即被丢弃项的去重键，等待未持 ctx 锁的一侧补清理。
    ///
    /// 键自身不随项存放：遗漏清理会让该键永久驻留 pending，
    /// 导致后续相同负载被误判为重复而静默丢弃。
    /// 丢弃可能发生在已持有 ctx 锁的调用栈内（状态推送 → enqueue/purge_stale_realtime），
    /// 而 SafeContext 是不可重入互斥锁，故此处只登记，不在原地加锁。
    fn defer_orphan_keys_at(orphan: &Arc<Mutex<Vec<String>>>, keys: &[String]) {
        if keys.is_empty() {
            return;
        }
        if let Ok(mut list) = orphan.lock() {
            let len = list.len();
            if len + keys.len() > Self::MAX_ORPHAN_KEYS {
                let overflow = len + keys.len() - Self::MAX_ORPHAN_KEYS;
                list.drain(0..overflow.min(len));
            }
            list.extend(keys.iter().filter(|k| !k.is_empty()).cloned());
        }
    }

    fn defer_orphan_keys(&self, keys: &[String]) {
        Self::defer_orphan_keys_at(&self.orphan_keys, keys);
    }

    /// 补清理延迟释放的键（worker 每轮与 FFI 入队路径调用，调用时未持有 ctx 锁）
    fn flush_orphan_keys_at(ctx_ptr: usize, orphan: &Arc<Mutex<Vec<String>>>) {
        if ctx_ptr == 0 {
            return;
        }
        let keys: Vec<String> = match orphan.lock() {
            Ok(mut list) => {
                if list.is_empty() {
                    return;
                }
                std::mem::take(&mut *list)
            }
            Err(_) => return,
        };
        let ctx = unsafe { &*(ctx_ptr as *const SafeContext) };
        match ctx.lock() {
            Ok(mut guard) => {
                for key in &keys {
                    guard.dedup.clear_pending(key);
                }
            }
            // 取锁失败：回填，留待下一次补清理
            Err(_) => Self::defer_orphan_keys_at(orphan, &keys),
        }
    }

    pub(crate) fn flush_orphan_keys(&self) {
        Self::flush_orphan_keys_at(self.ctx_ptr.load(Ordering::Relaxed), &self.orphan_keys);
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
        let mut dropped_keys: Vec<String> = Vec::new();
        inner.items.retain(|it| {
            if it.device_uuid != device_uuid || it.header != header {
                return true;
            }
            if Self::is_media_end_packet(&it.plaintext) {
                return true;
            }
            let keep = match crate::timestamp::extract_ts(&it.plaintext) {
                Some(ts) => !crate::timestamp::is_stale(ts, now),
                // 未携带 ts（旧格式/异常负载）：保守保留
                None => true,
            };
            if !keep {
                if let Some(ref key) = it.dedup_key {
                    dropped_keys.push(key.clone());
                }
            }
            keep
        });
        let dropped = before - inner.items.len();
        // 登记被丢弃项的去重键，交由未持 ctx 锁的一侧补清理
        self.defer_orphan_keys(&dropped_keys);
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
        let mut replaced_keys: Vec<String> = Vec::new();
        if let Ok(mut inner) = self.inner.lock() {
            // 全量媒体状态入队时移除同键旧项（含未发出的增量），只保留最新，
            // 根除网络恢复后过期状态的爆发式回放
            if let Some(ref key) = item.coalesce_key {
                if !Self::is_delta_payload(&item.plaintext) {
                    let before = inner.items.len();
                    inner.items.retain(|it| {
                        let replaced = it.coalesce_key.as_deref() == Some(key.as_str());
                        if replaced {
                            if let Some(ref k) = it.dedup_key {
                                replaced_keys.push(k.clone());
                            }
                        }
                        !replaced
                    });
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
        // 登记被替换旧项的去重键，交由未持 ctx 锁的一侧补清理
        self.defer_orphan_keys(&replaced_keys);
    }

    /// 启动后台调度线程（实际发送在并发任务线程中执行，同设备串行）
    pub fn start_worker(&self, ctx_ptr: usize) {
        let inner = self.inner.clone();
        let running = self.running.clone();
        let active = self.active.clone();
        let orphan = self.orphan_keys.clone();

        thread::Builder::new()
            .name("sender-queue".to_string())
            .spawn(move || {
                loop {
                    if !running.load(Ordering::Relaxed) {
                        break;
                    }

                    // 补清理延迟释放的去重键（此处未持 ctx 锁）
                    Self::flush_orphan_keys_at(ctx_ptr, &orphan);

                    if active.load(Ordering::Relaxed) >= Self::MAX_CONCURRENT {
                        thread::sleep(Duration::from_millis(20));
                        continue;
                    }

                    let mut stale_keys: Vec<String> = Vec::new();
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
                        guard.items.retain(|it| {
                            let stale = Self::is_stale_realtime_item(it);
                            if stale {
                                if let Some(ref key) = it.dedup_key {
                                    stale_keys.push(key.clone());
                                }
                            }
                            !stale
                        });
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
                    // 登记被丢弃项的去重键，交由补清理路径释放
                    Self::defer_orphan_keys_at(&orphan, &stale_keys);

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
                            let task_orphan = orphan.clone();
                            let orphan_key = item.dedup_key.clone();
                            let spawn_result = thread::Builder::new()
                                .name("sender-task".to_string())
                                .spawn(move || {
                                    let _guard = task_guard;
                                    Self::process_item(ctx_ptr, &item, &task_inner, &task_orphan);
                                });
                            if let Err(e) = spawn_result {
                                // spawn 失败时闭包被丢弃：TaskGuard 的 Drop 已清理并发状态，
                                // 该项不会发送，需同时登记其去重键待补清理
                                if let Some(ref key) = orphan_key {
                                    Self::defer_orphan_keys_at(&orphan, std::slice::from_ref(key));
                                }
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

    fn process_item(
        ctx_ptr: usize,
        item: &SendItem,
        inner: &Arc<Mutex<SenderQueueInner>>,
        orphan: &Arc<Mutex<Vec<String>>>,
    ) {
        let send_ok = match Self::try_send(ctx_ptr, item) {
            Ok(v) => v,
            Err(_) => {
                // 取锁失败使该项未发送即被丢弃：登记其去重键待补清理
                if let Some(ref key) = item.dedup_key {
                    Self::defer_orphan_keys_at(orphan, std::slice::from_ref(key));
                }
                return;
            }
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

    fn make_ctx(tag: &str) -> Mutex<crate::CoreContext> {
        let p = std::env::temp_dir()
            .join(format!("nrq_{}_{}", std::process::id(), tag))
            .join("rust_core.db");
        Mutex::new(crate::CoreContext::with_db_override(p))
    }

    fn item_with_key(uuid: &str, header: &str, text: &str, key: &str) -> SendItem {
        SendItem {
            device_uuid: uuid.to_string(),
            header: header.to_string(),
            plaintext: text.to_string(),
            dedup_key: Some(key.to_string()),
            retries_left: 0,
            coalesce_key: None,
        }
    }

    #[test]
    fn test_purge_stale_realtime_releases_dedup_key() {
        let ctx = make_ctx("purge");
        let ctx_ptr = &ctx as *const Mutex<crate::CoreContext> as usize;
        let q = SenderQueue::new();
        q.set_ctx_ptr(ctx_ptr);

        // 模拟入队时的去重键登记
        {
            let mut guard = ctx.lock().unwrap();
            assert!(guard.dedup.check_and_pend("k-purge", 3000));
            assert!(!guard.dedup.check_and_pend("k-purge", 3000));
        }

        let stale = crate::timestamp::now_ms() - crate::timestamp::STATE_MAX_AGE_MS - 1;
        let payload = format!(r#"{{"changes":{{"title":"s"}},"ts":{}}}"#, stale);
        q.enqueue(item_with_key("dev1", "DATA_MEDIAPLAY", &payload, "k-purge"));

        assert_eq!(q.purge_stale_realtime("dev1", "DATA_MEDIAPLAY"), 1);
        // 丢弃仅登记，由补清理路径释放
        q.flush_orphan_keys();
        // 丢弃项的去重键必须被释放，否则相同负载会被永久判为重复
        assert!(
            ctx.lock().unwrap().dedup.check_and_pend("k-purge", 3000),
            "被丢弃项的去重键应已释放"
        );
    }

    #[test]
    fn test_enqueue_while_ctx_locked_defers_release_without_deadlock() {
        let ctx = make_ctx("nested");
        let ctx_ptr = &ctx as *const Mutex<crate::CoreContext> as usize;
        let q = SenderQueue::new();
        q.set_ctx_ptr(ctx_ptr);

        {
            let mut guard = ctx.lock().unwrap();
            assert!(guard.dedup.check_and_pend("k-old", 3000));
        }

        // 模拟状态推送路径：持 ctx 锁调用 enqueue（第二次入队触发 coalesce 丢弃第一项）
        {
            let _guard = ctx.lock().unwrap();
            q.enqueue(item_with_key(
                "dev1",
                "DATA_MEDIAPLAY",
                r#"{"title":"a"}"#,
                "k-old",
            ));
            q.enqueue(item_with_key(
                "dev1",
                "DATA_MEDIAPLAY",
                r#"{"title":"b"}"#,
                "k-new",
            ));
        }

        q.flush_orphan_keys();
        assert!(
            ctx.lock().unwrap().dedup.check_and_pend("k-old", 3000),
            "持锁路径丢弃的键应由补清理释放"
        );
    }

    #[test]
    fn test_flush_orphan_keys_keeps_sent_window() {
        let ctx = make_ctx("flush-sent");
        let ctx_ptr = &ctx as *const Mutex<crate::CoreContext> as usize;
        let q = SenderQueue::new();
        q.set_ctx_ptr(ctx_ptr);

        {
            let mut guard = ctx.lock().unwrap();
            guard.dedup.mark_sent("k-sent");
        }
        q.defer_orphan_keys(&["k-sent".to_string()]);
        q.flush_orphan_keys();

        // 补清理只清 pending，不得影响已发送键的窗口
        assert!(
            !ctx.lock().unwrap().dedup.check_and_pend("k-sent", 3000),
            "已发送键的窗口不应被补清理影响"
        );
    }

    #[test]
    fn test_coalesce_replacement_releases_old_key() {
        let ctx = make_ctx("coalesce");
        let ctx_ptr = &ctx as *const Mutex<crate::CoreContext> as usize;
        let q = SenderQueue::new();
        q.set_ctx_ptr(ctx_ptr);

        {
            let mut guard = ctx.lock().unwrap();
            assert!(guard.dedup.check_and_pend("k-old", 3000));
            assert!(guard.dedup.check_and_pend("k-new", 3000));
        }

        q.enqueue(item_with_key(
            "dev1",
            "DATA_MEDIAPLAY",
            r#"{"title":"a"}"#,
            "k-old",
        ));
        q.enqueue(item_with_key(
            "dev1",
            "DATA_MEDIAPLAY",
            r#"{"title":"b"}"#,
            "k-new",
        ));
        q.flush_orphan_keys();

        let mut guard = ctx.lock().unwrap();
        assert!(
            guard.dedup.check_and_pend("k-old", 3000),
            "被替换旧项的去重键应已释放"
        );
        assert!(
            !guard.dedup.check_and_pend("k-new", 3000),
            "保留项的键仍在 pending"
        );
    }
}

// ===== 上下文级发送队列入口 =====

/// 发送去重 TTL（毫秒），与原平台端 SENT_KEY_TTL_MS 一致
const SENT_DEDUP_TTL_MS: i64 = 3000;

/// 参与发送去重的通知类 header（仅通知通道存在重复发送语义）
fn is_notification_header(header: &str) -> bool {
    header == "DATA_NOTIFICATION"
}

/// 规范化帧类型标识：非空且不以 DATA_ 开头时补前缀（接收端只识别 DATA_*）
pub fn normalize_header(header: &str) -> String {
    if !header.is_empty() && !header.starts_with("DATA_") {
        format!("DATA_{}", header)
    } else {
        header.to_string()
    }
}

/// 创建发送队列并登记句柄（供统一启动入口调用）。返回句柄，0 表示失败。
pub fn create_with_ctx(ctx_ptr: usize) -> u64 {
    if ctx_ptr == 0 {
        return 0;
    }
    let queue = Box::new(SenderQueue::new());
    queue.set_ctx_ptr(ctx_ptr);
    let handle = crate::handle::put(Box::into_raw(queue) as *mut std::os::raw::c_void);

    let ctx = unsafe { &*(ctx_ptr as *const crate::SafeContext) };
    if let Ok(mut guard) = ctx.lock() {
        guard.sender_queue = handle;
    }

    handle
}

/// 启动队列后台工作者（供统一启动入口调用）。
pub fn start_worker_for(ctx_ptr: usize, queue_handle: u64) {
    if ctx_ptr == 0 || queue_handle == 0 {
        return;
    }
    let queue = unsafe { &*(crate::handle::get(queue_handle) as *const SenderQueue) };
    queue.start_worker(ctx_ptr);
}

/// 写入一条待发送报文（header 规范化、去重键推导与发送去重均在此完成）。
///
/// 发送去重仅作用于通知类消息（`DATA_NOTIFICATION`）：其他通道无重复语义。
/// 返回：1=已入队 0=命中去重丢弃（仅通知类） -1=参数无效或队列未初始化。
pub fn enqueue_message(
    ctx_ptr: usize,
    queue_handle: u64,
    device_uuid: &str,
    header: &str,
    plaintext: &str,
) -> i32 {
    if ctx_ptr == 0 || queue_handle == 0 {
        return -1;
    }
    let queue = unsafe { &*(crate::handle::get(queue_handle) as *const SenderQueue) };
    let hdr = normalize_header(header);

    let is_notification = is_notification_header(&hdr);

    let dedup_key = if is_notification {
        let key = crate::dedup::compute_dedup_key(device_uuid, plaintext);
        let ctx = unsafe { &*(ctx_ptr as *const crate::SafeContext) };
        let dedup_ok = match ctx.lock() {
            Ok(mut g) => {
                g.dedup.maybe_cleanup();
                g.dedup.check_and_pend(&key, SENT_DEDUP_TTL_MS)
            }
            Err(_) => return -1,
        };
        if !dedup_ok {
            return 0;
        }
        Some(key)
    } else {
        None
    };

    // 通知类消息只注入并记录生成时刻 `ts`，不做丢弃：
    // 断线期间的通知累积是有益的，恢复后应完整补收（实时状态的丢弃在 state_merge / sender_queue 内处理）。
    //
    // 仅对 DATA_NOTIFICATION 注入：其他通道（图标/应用列表/控制等）的模型未声明 `ts`，
    // 注入会触发 `normalize_or_keep` 的"往返丢字段"兜底并产生无谓告警，且这些通道无时效语义。
    let plaintext = if is_notification {
        crate::timestamp::inject_ts(plaintext, crate::timestamp::now_ms())
    } else {
        plaintext.to_string()
    };

    queue.enqueue(SendItem {
        device_uuid: device_uuid.to_string(),
        header: hdr,
        plaintext,
        dedup_key,
        retries_left: 0,
        coalesce_key: None,
    });
    // 补清理队列丢弃项遗留的去重键（此处未持有 ctx 锁）
    queue.flush_orphan_keys();
    1
}

/// 读取上下文中的发送队列句柄（未启动时为 0）。
pub fn handle_of(ctx_ptr: usize) -> u64 {
    if ctx_ptr == 0 {
        return 0;
    }
    let ctx = unsafe { &*(ctx_ptr as *const crate::SafeContext) };
    match ctx.lock() {
        Ok(guard) => guard.sender_queue,
        Err(_) => 0,
    }
}

#[cfg(test)]
mod ctx_tests {
    use super::*;
    use std::sync::Mutex;

    fn create_ctx() -> Mutex<crate::CoreContext> {
        let p = std::env::temp_dir()
            .join(format!("nrsq_ctx_{}", std::process::id()))
            .join("rust_core.db");
        Mutex::new(crate::CoreContext::with_db_override(p))
    }

    #[test]
    fn normalize_header_cases() {
        assert_eq!(normalize_header("ICON_REQUEST"), "DATA_ICON_REQUEST");
        assert_eq!(normalize_header("DATA_JSON"), "DATA_JSON");
        assert_eq!(normalize_header("DATA_"), "DATA_");
        assert_eq!(normalize_header(""), "");
    }

    #[test]
    fn enqueue_message_params_and_dedup() {
        let ctx = create_ctx();
        let ptr = &ctx as *const Mutex<crate::CoreContext> as usize;

        // 空上下文 / 队列未初始化 → -1
        assert_eq!(enqueue_message(0, 0, "", "", ""), -1);
        assert_eq!(enqueue_message(ptr, 0, "", "", ""), -1);

        let queue_handle = create_with_ctx(ptr);
        assert_ne!(queue_handle, 0);

        let body = r#"{"a":1}"#;
        let body2 = r#"{"a":2}"#;

        // 通知：首次入队 → 1
        assert_eq!(
            enqueue_message(ptr, queue_handle, "uuid-1", "DATA_NOTIFICATION", body),
            1
        );
        // 通知：同一 (uuid, plaintext) 在 TTL 内重复 → 0
        assert_eq!(
            enqueue_message(ptr, queue_handle, "uuid-1", "DATA_NOTIFICATION", body),
            0
        );
        // 通知：不同 plaintext → 1
        assert_eq!(
            enqueue_message(ptr, queue_handle, "uuid-1", "DATA_NOTIFICATION", body2),
            1
        );
        // 非通知通道不去重：同一负载连续两次都入队
        assert_eq!(
            enqueue_message(ptr, queue_handle, "uuid-1", "ICON_REQUEST", body),
            1
        );
        assert_eq!(
            enqueue_message(ptr, queue_handle, "uuid-1", "ICON_REQUEST", body),
            1
        );

        let queue = unsafe { &*(crate::handle::get(queue_handle) as *const SenderQueue) };
        assert_eq!(queue.pending_count(), 4);
    }
}
