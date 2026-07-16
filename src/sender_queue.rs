use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine;

use crate::crypto::aes;
use crate::protocol::codec;
use crate::SafeContext;

/// 消息发送项
pub struct SendItem {
    pub device_uuid: String,
    pub device_ip: String,
    pub header: String,
    pub plaintext: String,
    pub dedup_key: Option<String>,
    pub retries_left: u32,
}

pub struct SenderQueue {
    inner: Arc<Mutex<SenderQueueInner>>,
    running: Arc<AtomicBool>,
}

struct SenderQueueInner {
    items: Vec<SendItem>,
    /// dedup_key -> 发送开始时间
    in_flight: HashMap<String, Instant>,
}

impl SenderQueue {
    const MAX_CONCURRENT: usize = 5;
    const MAX_RETRIES: u32 = 3;

    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(SenderQueueInner {
                items: Vec::new(),
                in_flight: HashMap::new(),
            })),
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn enqueue(&self, mut item: SendItem) {
        item.retries_left = Self::MAX_RETRIES;
        if let Ok(mut inner) = self.inner.lock() {
            inner.items.push(item);
        }
    }

    /// 启动后台处理线程
    pub fn start_worker(&self, ctx_ptr: usize) {
        let inner = self.inner.clone();
        let running = self.running.clone();

        thread::Builder::new()
            .name("sender-queue".to_string())
            .spawn(move || {
                loop {
                    if !running.load(Ordering::Relaxed) { break; }

                    let item = {
                        let mut guard = match inner.lock() {
                            Ok(g) => g,
                            Err(_) => { thread::sleep(Duration::from_millis(50)); continue; }
                        };
                        // 清理 5 秒超时的 in_flight
                        let now = Instant::now();
                        guard.in_flight.retain(|_, &mut ts| now.duration_since(ts).as_secs() < 5);
                        let available = Self::MAX_CONCURRENT.saturating_sub(guard.in_flight.len());
                        if available == 0 { thread::sleep(Duration::from_millis(50)); continue; }

                        let idx = guard.items.iter().position(|item| {
                            let key = item.dedup_key.as_deref().unwrap_or("");
                            key.is_empty() || !guard.in_flight.contains_key(key)
                        });
                        match idx {
                            Some(i) => {
                                let item = guard.items.remove(i);
                                if let Some(ref key) = item.dedup_key {
                                    if !key.is_empty() {
                                        guard.in_flight.insert(key.clone(), now);
                                    }
                                }
                                Some(item)
                            }
                            None => { thread::sleep(Duration::from_millis(50)); continue; }
                        }
                    };

                    if let Some(item) = item {
                        Self::process_item(ctx_ptr, &item, &inner);
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

        let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };

        if send_ok {
            if let Some(ref key) = item.dedup_key {
                if !key.is_empty() {
                    if let Ok(mut guard) = ctx.lock() {
                        guard.dedup.mark_sent(key);
                    }
                }
            }
            log::debug!("发送队列: 已发送 uuid={}, header={}", item.device_uuid, item.header);
        } else if item.retries_left > 1 {
            log::debug!("发送队列: 重试第 {} 次 uuid={}, header={}",
                Self::MAX_RETRIES - item.retries_left + 1, item.device_uuid, item.header);
            if let Ok(mut guard) = inner.lock() {
                guard.items.push(SendItem {
                    retries_left: item.retries_left - 1,
                    ..SendItem {
                        device_uuid: item.device_uuid.clone(),
                        device_ip: item.device_ip.clone(),
                        header: item.header.clone(),
                        plaintext: item.plaintext.clone(),
                        dedup_key: item.dedup_key.clone(),
                        retries_left: 0,
                    }
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
            log::warn!("发送队列: 发送失败已达最大重试 uuid={}, header={}", item.device_uuid, item.header);
        }

        // 清理 in_flight
        if let Some(ref key) = item.dedup_key {
            if !key.is_empty() {
                if let Ok(mut guard) = inner.lock() {
                    guard.in_flight.remove(key);
                }
            }
        }
    }

    fn try_send(ctx_ptr: usize, item: &SendItem) -> Result<bool, ()> {
        let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
        let (key_b64, has_tcp_session, local_uuid) = match ctx.lock() {
            Ok(guard) => {
                let key = guard.crypto.device_keys.get(&item.device_uuid)
                    .map(|k| k.aes_key_b64.clone());
                let has = guard.network.tcp.lock()
                    .map(|tcp| tcp.is_connected(&item.device_uuid))
                    .unwrap_or(false);
                let uuid = guard.broadcast_info.as_ref().map(|i| i.uuid.clone()).unwrap_or_default();
                (key, has, uuid)
            }
            Err(_) => return Err(()),
        };

        let key_b64 = match key_b64 {
            Some(k) => k,
            None => {
                log::warn!("发送队列: 未找到密钥 uuid={}", item.device_uuid);
                return Ok(false);
            }
        };

        let key_bytes = match base64::engine::general_purpose::STANDARD.decode(&key_b64) {
            Ok(b) if b.len() == 32 => b,
            _ => return Ok(false),
        };
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&key_bytes);

        let encrypted = match aes::encrypt(&key_arr, item.plaintext.as_bytes()) {
            Ok(e) => e,
            Err(_) => return Ok(false),
        };
        let msg = codec::encode_data_message(&item.header, &local_uuid, "", &encrypted);

        if has_tcp_session && !item.device_uuid.is_empty() {
            match ctx.lock() {
                Ok(guard) => {
                    match guard.network.tcp.lock() {
                        Ok(mut tcp) => Ok(tcp.send_to_device(&item.device_uuid, &msg)),
                        Err(_) => Ok(false),
                    }
                }
                Err(_) => Ok(false),
            }
        } else if !item.device_ip.is_empty() {
            Ok(crate::network::oneshot_send_only(&msg, &item.device_ip, codec::DEFAULT_TCP_PORT, 3000))
        } else {
            Ok(false)
        }
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}
