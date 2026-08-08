//! 状态合并引擎
//!
//! 作为超级岛 / 媒体跨设备同步的唯一真相源：
//! - 发送端：平台只传入「全键值」状态，引擎负责计算差异（FULL / DELTA / SKIP）、
//!   ACK 跟踪与定期全量心跳，所有 diff 逻辑仅在 Rust 内闭环。
//! - 接收端：解密收到 DELTA 后与本端存储的上次全量合并为全量，再**复用既有的
//!   `on_data` 回调**（message_type 为 `SUPERISLAND` / `MEDIAPLAY`）交给平台；
//!   平台永远只见到全量，不再做任何合并。不再新增独立的输出回调。
//!
//! 链路仍使用 DELTA 以节省流量（沿用 `sender_queue` 的 `"changes"` 启发式），
//! 但接收端 Rust 会把 DELTA 合并回全量再交给 App。

use std::collections::HashMap;
use std::ffi::CString;
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

use crate::sender_queue::{SendItem, SenderQueue};
use crate::SafeContext;

const SI_ACK_TIMEOUT_MS: u64 = 4000;
const SI_HEARTBEAT_MS: u64 = 30_000;
const MEDIA_HEARTBEAT_MS: u64 = 6_000;
const MEDIA_KEY: &str = "media_global";

fn sha256_hex(s: &str) -> String {
    use sha2::Digest;
    let h = sha2::Sha256::digest(s.as_bytes());
    h.iter().map(|b| format!("{:02x}", b)).collect()
}

#[derive(Clone)]
struct SenderState {
    device_uuid: String,
    feature_id: String,
    is_media: bool,
    last_full: String,
    last_hash: String,
    pending_ack: Option<(String, Instant)>,
    force_full_next: bool,
    /// 上次主动推送（含 is_query 推送）时间；心跳查询间隔据此跳过活跃会话
    last_push: Instant,
}

#[derive(Clone)]
struct ReceiverState {
    last_full: String,
}

pub struct StateMerge {
    senders: HashMap<String, SenderState>,
    receivers: HashMap<String, ReceiverState>,
}

impl StateMerge {
    pub fn new() -> Self {
        Self {
            senders: HashMap::new(),
            receivers: HashMap::new(),
        }
    }

    fn key(device_uuid: &str, feature_id: &str) -> String {
        format!("{}|{}", device_uuid, feature_id)
    }

    fn compute_feature_id(full: &Value) -> String {
        // 平台端必须注入稳定的 featureIdOverride（sbn.key），内容变化不再产生新会话；
        // 缺失时返回空串，不做内容哈希兜底
        full.get("featureIdOverride")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or_default()
            .to_string()
    }

    /// 平台传入全量状态（canonical 内容对象，包含 device 字段）。
    /// 引擎计算差异并据此入队 FULL / DELTA；无变化时发送空 DELTA 保活（接收端刷新时间戳）。
    /// `is_query` 表示本次推送是查询回调（`OnStateQueryCb` 返回 2 后）触发的响应推送，
    /// 与主动推送同样更新 `last_push`，仅用于心跳查询间隔判断。
    pub fn push_state(
        &mut self,
        queue: &SenderQueue,
        remote_uuid: &str,
        is_media: bool,
        full_json: &str,
        is_end: bool,
        is_query: bool,
    ) -> bool {
        let full: Value = match serde_json::from_str(full_json) {
            Ok(v) => v,
            Err(_) => return false,
        };
        if !full.is_object() {
            return false;
        }
        let feature_id = if is_media {
            MEDIA_KEY.to_string()
        } else {
            Self::compute_feature_id(&full)
        };
        let key = Self::key(remote_uuid, &feature_id);
        let canonical = serde_json::to_string(&full).unwrap_or_default();
        let hash = sha256_hex(&canonical);
        let now = Instant::now();
        if is_query {
            log::debug!(
                "[state_merge] 查询响应推送 uuid={} fid={} is_media={}",
                remote_uuid,
                feature_id,
                is_media
            );
        }

        let mut session = self
            .senders
            .get(&key)
            .cloned()
            .unwrap_or_else(|| SenderState {
                device_uuid: remote_uuid.to_string(),
                feature_id: feature_id.clone(),
                is_media,
                last_full: String::new(),
                last_hash: String::new(),
                pending_ack: None,
                force_full_next: true,
                last_push: now,
            });

        let first = session.last_full.is_empty();
        let force = session.force_full_next;

        let payload = if first || force || is_end {
            build_full_wire(&full, &feature_id, &hash, is_end)
        } else {
            // 无变化时发送空差量保活包：接收端据此刷新时间戳，避免卡片超时消失
            let delta = if session.last_full == canonical {
                json!({})
            } else {
                let old_val: Value =
                    serde_json::from_str(&session.last_full).unwrap_or(Value::Null);
                diff_island(&old_val, &full)
            };
            build_delta_wire(&delta, &feature_id, &hash)
        };

        let header = if is_media {
            "DATA_MEDIAPLAY"
        } else {
            "DATA_SUPERISLAND"
        };
        let item = SendItem {
            device_uuid: remote_uuid.to_string(),
            header: header.to_string(),
            plaintext: payload,
            dedup_key: None,
            retries_left: 0,
            coalesce_key: None,
        };
        queue.enqueue(item);

        session.last_full = canonical;
        session.last_hash = hash.clone();
        session.force_full_next = false;
        session.last_push = now;
        if is_media {
            session.pending_ack = None;
        } else {
            session.pending_ack = Some((hash.clone(), now));
        }

        if is_end {
            self.senders.remove(&key);
        } else {
            self.senders.insert(key, session);
        }
        true
    }

    /// 接收端：把解密后的明文（FULL 或 DELTA）合并为全量，返回 (feature_id, 全量json, is_end)。
    pub fn merge_incoming(
        &mut self,
        device_uuid: &str,
        is_media: bool,
        payload: &str,
    ) -> Option<(String, String, bool)> {
        let v: Value = serde_json::from_str(payload).ok()?;
        let feature_id = if is_media {
            MEDIA_KEY.to_string()
        } else {
            v.get("featureKeyValue")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string()
        };
        if feature_id.is_empty() {
            return None;
        }
        let key = Self::key(device_uuid, &feature_id);
        let is_end = v.get("terminateValue").and_then(|x| x.as_str()) == Some("__END__")
            || v.get("terminate").and_then(|x| x.as_bool()) == Some(true);

        let new_full = if v.get("type").and_then(|x| x.as_str()) == Some("delta") {
            let changes = v.get("changes").cloned().unwrap_or(Value::Null);
            let base = self.receivers.get(&key).map(|r| r.last_full.clone());
            let base_val: Value = base
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or(Value::Object(Map::new()));
            merge_island(&base_val, &changes)
        } else {
            strip_routing(&v)
        };

        if is_end {
            self.receivers.remove(&key);
        } else {
            self.receivers.insert(
                key.clone(),
                ReceiverState {
                    last_full: new_full.clone(),
                },
            );
        }
        Some((feature_id, new_full, is_end))
    }

    /// 处理来自接收端的 ACK，清除对应发送会话的 pending。
    pub fn handle_ack(&mut self, device_uuid: &str, feature_id: &str, hash: &str) {
        let key = Self::key(device_uuid, feature_id);
        if let Some(s) = self.senders.get_mut(&key) {
            if let Some((pending_hash, _)) = &s.pending_ack {
                if pending_hash == hash {
                    s.pending_ack = None;
                }
            }
        }
    }

    /// 定时器（心跳线程每秒调用，锁内）：不再重发全量包，改为收集需要查询的会话。
    /// - 主动推送间隔内（now - last_push < interval）的会话跳过查询；
    /// - 超级岛 ACK 超时仅标记 `force_full_next`，等待下次变更/推送时全量重发。
    ///
    /// 返回待查询的 (device_uuid, feature_id, is_media) 快照，回调必须在锁外调用。
    pub fn heartbeat_tick(&mut self, now: Instant) -> Vec<(String, String, bool)> {
        let mut to_query: Vec<(String, String, bool)> = Vec::new();
        for s in self.senders.values_mut() {
            if s.last_full.is_empty() {
                continue;
            }
            if let Some((_, ack_time)) = &s.pending_ack {
                if now.duration_since(*ack_time).as_millis() as u64 >= SI_ACK_TIMEOUT_MS {
                    s.force_full_next = true;
                    s.pending_ack = None;
                    log::warn!(
                        "[state_merge] ACK 超时,标记下次全量重发 uuid={} fid={}",
                        s.device_uuid,
                        s.feature_id
                    );
                }
            }
            let interval = if s.is_media {
                MEDIA_HEARTBEAT_MS
            } else {
                SI_HEARTBEAT_MS
            };
            let elapsed = now.duration_since(s.last_push).as_millis() as u64;
            if elapsed < interval {
                continue;
            }
            to_query.push((s.device_uuid.clone(), s.feature_id.clone(), s.is_media));
        }
        to_query
    }

    /// 处理查询回调结果（锁内）：
    /// - 0 = 平台上不存在 → 仅移除会话，不发任何包（接收端靠超时自然消失）
    /// - 1 = 存在无变更 → 保活（重置 last_push，延长查询间隔）
    /// - 2 = 存在有变更 → 平台已/将调用 push(is_query=1)，引擎无需动作
    pub fn apply_query_results(&mut self, results: Vec<(String, String, i32)>) {
        for (device_uuid, feature_id, code) in results {
            let key = Self::key(&device_uuid, &feature_id);
            match code {
                0 => {
                    log::warn!(
                        "[state_merge] 查询到会话不存在,移除 uuid={} fid={}",
                        device_uuid,
                        feature_id
                    );
                    self.senders.remove(&key);
                }
                1 => {
                    if let Some(s) = self.senders.get_mut(&key) {
                        s.last_push = Instant::now();
                    }
                }
                _ => {}
            }
        }
    }
}

// ===== 内部辅助 =====

fn build_full_wire(full: &Value, feature_id: &str, hash: &str, is_end: bool) -> String {
    let mut obj = full.clone();
    if let Value::Object(ref mut m) = obj {
        let is_media = feature_id == MEDIA_KEY;
        m.insert(
            "type".into(),
            json!(if is_media {
                "MEDIA_PLAY"
            } else {
                "SUPERISLAND"
            }),
        );
        m.insert("featureKeyValue".into(), json!(feature_id));
        m.insert("hash".into(), json!(hash));
        if is_end {
            m.insert("terminateValue".into(), json!("__END__"));
            m.insert("terminate".into(), json!(true));
        } else {
            m.remove("terminate");
        }
    }
    obj.to_string()
}

fn build_delta_wire(delta: &Value, feature_id: &str, hash: &str) -> String {
    json!({
        "type": "delta",
        "featureKeyValue": feature_id,
        "hash": hash,
        "changes": delta.clone(),
    })
    .to_string()
}

fn strip_routing(v: &Value) -> String {
    let mut obj = v.clone();
    if let Value::Object(ref mut m) = obj {
        m.remove("type");
        m.remove("featureKeyValue");
        m.remove("hash");
        m.remove("device");
    }
    serde_json::to_string(&obj).unwrap_or_default()
}

fn field_str(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(|x| x.as_str()).map(|s| s.to_string())
}

fn pics_map(v: &Value) -> Map<String, Value> {
    v.get("pics")
        .and_then(|x| x.as_object())
        .cloned()
        .unwrap_or_default()
}

/// 计算 island 状态差异（title/text/param_v2_raw/coverUrl/isPlaying/pics），返回 changes 对象。
fn diff_island(old: &Value, new: &Value) -> Value {
    let mut changes = Map::new();
    for k in ["title", "text", "param_v2_raw", "coverUrl"] {
        let o = field_str(old, k);
        let n = field_str(new, k);
        if o != n {
            changes.insert(k.to_string(), json!(n.unwrap_or_default()));
        }
    }
    // isPlaying 为布尔字段，单独比较：仅暂停/播放切换时生成 delta，接收端可正确合并
    let o_play = old.get("isPlaying").and_then(|x| x.as_bool());
    let n_play = new.get("isPlaying").and_then(|x| x.as_bool());
    if o_play != n_play {
        if let Some(v) = new.get("isPlaying") {
            changes.insert("isPlaying".to_string(), v.clone());
        }
    }
    let op = pics_map(old);
    let np = pics_map(new);
    let mut pics_changed = Map::new();
    for (k, v) in &np {
        if op.get(k) != Some(v) {
            pics_changed.insert(k.clone(), v.clone());
        }
    }
    let mut pics_removed: Vec<Value> = Vec::new();
    for k in op.keys() {
        if !np.contains_key(k) {
            pics_removed.push(json!(k.clone()));
        }
    }
    if !pics_changed.is_empty() {
        changes.insert("pics".to_string(), json!(pics_changed));
    }
    if !pics_removed.is_empty() {
        changes.insert("pics_removed".to_string(), json!(pics_removed));
    }
    json!(changes)
}

/// 把 delta 的 changes 合并进 base（上次全量），产出新的全量。
fn merge_island(base: &Value, changes: &Value) -> String {
    let mut merged = base.clone();
    if let Value::Object(ref mut m) = merged {
        for k in ["title", "text", "param_v2_raw", "coverUrl"] {
            if let Some(v) = changes.get(k) {
                if v.is_string() {
                    m.insert(k.to_string(), v.clone());
                } else if v.is_null() {
                    m.remove(k);
                } else {
                    m.insert(k.to_string(), v.clone());
                }
            }
        }
        // isPlaying 布尔字段合并（与 diff_island 对应）
        if let Some(v) = changes.get("isPlaying") {
            if v.is_boolean() {
                m.insert("isPlaying".to_string(), v.clone());
            } else if v.is_null() {
                m.remove("isPlaying");
            } else {
                m.insert("isPlaying".to_string(), v.clone());
            }
        }
        if let Some(pics_new) = changes.get("pics").and_then(|x| x.as_object()) {
            let pics = m
                .entry("pics")
                .or_insert_with(|| json!({}))
                .as_object_mut()
                .unwrap();
            for (k, v) in pics_new {
                if v.is_string() {
                    let s = v.as_str().unwrap();
                    if s.is_empty() {
                        pics.remove(k);
                    } else {
                        pics.insert(k.clone(), v.clone());
                    }
                } else if v.is_null() {
                    pics.remove(k);
                } else {
                    pics.insert(k.clone(), v.clone());
                }
            }
        }
        if let Some(removed) = changes.get("pics_removed").and_then(|x| x.as_array()) {
            if let Some(pics) = m.get_mut("pics").and_then(|x| x.as_object_mut()) {
                for r in removed {
                    if let Some(k) = r.as_str() {
                        pics.remove(k);
                    }
                }
            }
        }
    }
    serde_json::to_string(&merged).unwrap_or_default()
}

/// 在接收路径处理超级岛 / 媒体消息：合并为全量后通过既有 `on_data` 回调交给平台，
/// 并在需要时回 ACK。返回 true 表示该消息已被引擎消费（无需再走通用 on_data）。
pub fn handle_state_message(
    ctx: &mut SafeContext,
    uuid: &str,
    is_media: bool,
    plaintext: &str,
) -> bool {
    let v: Value = match serde_json::from_str(plaintext) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if v.get("type").and_then(|x| x.as_str()) == Some("SI_ACK") {
        let fid = v
            .get("featureKeyValue")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let hash = v
            .get("hash")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        {
            let g = ctx.get_mut().unwrap();
            g.state_merge.handle_ack(uuid, &fid, &hash);
        }
        return true;
    }
    let (fid, full, is_end) = {
        let g = ctx.get_mut().unwrap();
        match g.state_merge.merge_incoming(uuid, is_media, plaintext) {
            Some(r) => r,
            None => return false,
        }
    };
    // 合并后的全量经旧的 on_data 回调传出，platform 侧无需感知 delta。
    // 重新包装成与历史 FULL wire 一致的形态（含 featureKeyValue / terminateValue），
    // 使平台既有 SUPERISLAND / MEDIAPLAY 处理逻辑（按全量替换）保持不变。
    let wire_val: Value = serde_json::from_str(&full).unwrap_or(Value::Object(Map::new()));
    let wire_hash = sha256_hex(&full);
    let wire = build_full_wire(&wire_val, &fid, &wire_hash, is_end);
    let (cb, ud) = {
        let g = ctx.get_mut().unwrap();
        (g.router.on_data, g.router.user_data)
    };
    if let Some(cb_fn) = cb {
        let uuid_c = CString::new(uuid).unwrap_or_default();
        let mt_c =
            CString::new(if is_media { "MEDIAPLAY" } else { "SUPERISLAND" }).unwrap_or_default();
        let wire_c = CString::new(wire).unwrap_or_default();
        cb_fn(uuid_c.as_ptr(), mt_c.as_ptr(), wire_c.as_ptr(), ud);
    }
    // 超级岛需回 ACK（媒体不需要），用于发送端清除 pending / 超时强制全量
    if !is_media && !is_end {
        if let Some(hash) = v.get("hash").and_then(|x| x.as_str()) {
            let g = ctx.get_mut().unwrap();
            if g.sender_queue != 0 {
                let q = unsafe { &*(crate::ffi::handle::get(g.sender_queue) as *mut SenderQueue) };
                let ack = json!({
                    "type": "SI_ACK",
                    "device": uuid,
                    "featureKeyValue": fid,
                    "hash": hash,
                })
                .to_string();
                let item = SendItem {
                    device_uuid: uuid.to_string(),
                    header: "DATA_SUPERISLAND".to_string(),
                    plaintext: ack,
                    dedup_key: None,
                    retries_left: 0,
                    coalesce_key: None,
                };
                q.enqueue(item);
            }
        }
    }
    true
}

/// 启动后台心跳线程（在 nrc_init 中调用一次）。
/// 每秒 tick：锁内收集待查询会话快照 → 释放锁 → 调用平台查询回调（返回状态码）
/// → 重新加锁处理结果。回调必须在锁外执行，因为平台回调内可能直接调 `nrc_push_*`。
pub fn start_heartbeat_thread(ctx_ptr: usize) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(1));
        let ctx = unsafe { &*(ctx_ptr as *const SafeContext) };
        let now = Instant::now();
        let (cb, user_data, queries) = {
            let mut guard = match ctx.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            (
                guard.router.on_state_query,
                guard.router.user_data,
                guard.state_merge.heartbeat_tick(now),
            )
        };
        if queries.is_empty() {
            continue;
        }
        let Some(cb_fn) = cb else {
            // 平台未注册查询回调：跳过查询（会话保持，仅靠正常 is_end 结束）
            continue;
        };
        let mut results: Vec<(String, String, i32)> = Vec::with_capacity(queries.len());
        for (device_uuid, feature_id, is_media) in queries {
            let uuid_c = CString::new(device_uuid.clone()).unwrap_or_default();
            let fid_c = CString::new(feature_id.clone()).unwrap_or_default();
            let code = cb_fn(uuid_c.as_ptr(), fid_c.as_ptr(), is_media as i32, user_data);
            results.push((device_uuid, feature_id, code));
        }
        if let Ok(mut guard) = ctx.lock() {
            guard.state_merge.apply_query_results(results);
        }
    });
}

impl Default for StateMerge {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn si_full(title: &str, text: &str) -> String {
        json!({
            "packageName": "com.x",
            "appName": "App",
            "time": 1,
            "isLocked": false,
            "title": title,
            "text": text,
            "param_v2_raw": "",
            "featureIdOverride": "test-sbn-key",
            "pics": {},
        })
        .to_string()
    }

    #[test]
    fn test_diff_and_merge_roundtrip() {
        let q = SenderQueue::new();
        let mut sm = StateMerge::new();
        // 首次推送应为 FULL
        assert!(sm.push_state(&q, "devA", false, &si_full("t1", "c1"), false, false));
        // 相同内容 → 发送空差量保活包（不跳过），接收端据此刷新时间戳
        assert!(sm.push_state(&q, "devA", false, &si_full("t1", "c1"), false, false));
        let items = q.test_drain_plaintexts();
        assert_eq!(items.len(), 2);
        assert!(items[1].contains("\"type\":\"delta\""));
        assert!(items[1].contains("\"changes\":{}"));
        // 变化产生 delta（通过队列内容判断）
        // 这里只验证 merge 往返：模拟接收端
        let full1 = si_full("t1", "c1");
        let merged1 = {
            let mut r = StateMerge::new();
            let (_, f, _) = r
                .merge_incoming(
                    "devA",
                    false,
                    &build_full_wire(&serde_json::from_str(&full1).unwrap(), "fid", "h1", false),
                )
                .unwrap();
            f
        };
        assert_eq!(merged1, full1);
    }

    #[test]
    fn test_delta_merge_updates_fields() {
        let full_a =
            json!({"device":"self","title":"a","text":"x","param_v2_raw":"","pics":{"k":"v"}});
        let full_b = json!({"device":"self","title":"b","text":"x","param_v2_raw":"","pics":{"k":"v","k2":"v2"}});
        let delta = diff_island(&full_a, &full_b);
        let merged = merge_island(&full_a, &delta);
        let merged_v: Value = serde_json::from_str(&merged).unwrap();
        assert_eq!(merged_v["title"], json!("b"));
        assert_eq!(merged_v["pics"]["k2"], json!("v2"));
    }

    #[test]
    fn test_media_fields_diff_and_merge() {
        // 仅切换 isPlaying：FULL 之后产生非空 delta，接收端合并后状态正确
        let full_playing =
            json!({"device":"self","title":"t","text":"a","coverUrl":"url1","isPlaying":true});
        let full_paused =
            json!({"device":"self","title":"t","text":"a","coverUrl":"url1","isPlaying":false});
        let delta = diff_island(&full_playing, &full_paused);
        assert_ne!(delta, json!({}));
        assert_eq!(delta["isPlaying"], json!(false));
        let merged = merge_island(&full_playing, &delta);
        let merged_v: Value = serde_json::from_str(&merged).unwrap();
        assert_eq!(merged_v["isPlaying"], json!(false));
        assert_eq!(merged_v["coverUrl"], json!("url1"));
        // 无变化时 delta 为空
        let no_change = diff_island(&full_paused, &full_paused);
        assert_eq!(no_change, json!({}));

        // 仅更换 coverUrl：delta 非空且合并后封面正确
        let full_new_cover =
            json!({"device":"self","title":"t","text":"a","coverUrl":"url2","isPlaying":false});
        let delta2 = diff_island(&full_paused, &full_new_cover);
        assert_ne!(delta2, json!({}));
        assert_eq!(delta2["coverUrl"], json!("url2"));
        assert!(delta2.get("isPlaying").is_none());
        let merged2 = merge_island(&full_paused, &delta2);
        let merged2_v: Value = serde_json::from_str(&merged2).unwrap();
        assert_eq!(merged2_v["coverUrl"], json!("url2"));
        assert_eq!(merged2_v["isPlaying"], json!(false));
    }

    #[test]
    fn test_heartbeat_query_and_removal() {
        let q = SenderQueue::new();
        let mut sm = StateMerge::new();
        // 主动推送后心跳查询应跳过（活跃推送无查询开销）
        assert!(sm.push_state(&q, "devA", false, &si_full("t1", "c1"), false, false));
        assert!(sm.heartbeat_tick(Instant::now()).is_empty());
        // 超过查询间隔后收集快照
        let later = Instant::now() + Duration::from_secs(31);
        let queries = sm.heartbeat_tick(later);
        assert_eq!(queries.len(), 1);
        assert_eq!(queries[0].0, "devA");
        assert!(!queries[0].1.is_empty());
        // 查询不存在 → 仅移除会话，不再查询（不发任何包）
        sm.apply_query_results(vec![(queries[0].0.clone(), queries[0].1.clone(), 0)]);
        assert!(sm.heartbeat_tick(later + Duration::from_secs(1)).is_empty());
        // 会话移除后再次推送会重新创建
        assert!(sm.push_state(&q, "devA", false, &si_full("t2", "c2"), false, false));
        let queries2 = sm.heartbeat_tick(Instant::now() + Duration::from_secs(31));
        assert_eq!(queries2.len(), 1);
        // 存在无变更 → 保活，间隔内不再查询
        sm.apply_query_results(vec![(queries2[0].0.clone(), queries2[0].1.clone(), 1)]);
        assert!(sm
            .heartbeat_tick(Instant::now() + Duration::from_secs(29))
            .is_empty());
        // 存在有变更（2）→ 引擎等待平台随后的 push，不主动动作
        let queries3 = sm.heartbeat_tick(Instant::now() + Duration::from_secs(31));
        assert_eq!(queries3.len(), 1);
        sm.apply_query_results(vec![(queries3[0].0.clone(), queries3[0].1.clone(), 2)]);
    }

    #[test]
    fn test_is_end_removes_session() {
        let q = SenderQueue::new();
        let mut sm = StateMerge::new();
        assert!(sm.push_state(&q, "devA", false, &si_full("t1", "c1"), false, false));
        // 正常结束包照常发送并移除会话
        assert!(sm.push_state(&q, "devA", false, &si_full("t1", "c1"), true, false));
        assert!(sm
            .heartbeat_tick(Instant::now() + Duration::from_secs(31))
            .is_empty());
    }
}
