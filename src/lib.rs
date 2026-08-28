#![allow(clippy::missing_safety_doc)]

mod app_sync;
pub mod audio_codec;
pub mod audio_stream;
mod clipboard;
mod crypto;
mod dedup;
pub mod device_registry;
pub mod diff;
mod discovery;
pub mod ffi;
mod filter;
mod heartbeat;
mod mdns;
mod models;
mod network;
mod persistence;
mod protocol;
pub mod reconnect;
mod router;
pub mod sender_queue;
mod state_merge;

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub struct DeviceState {
    pub peer_lt_pub: Option<String>,
}

pub struct CoreContext {
    pub crypto: crypto::CryptoState,
    pub router: router::Router,
    pub heartbeat: heartbeat::HeartbeatState,
    pub discovery: discovery::DiscoveryState,
    pub audio: Arc<Mutex<audio_stream::AudioStreamState>>,
    pub network: network::NetworkState,
    pub mdns: mdns::MdnsState,
    pub dedup: dedup::DedupState,
    pub clipboard: clipboard::ClipboardState,
    pub app_sync: app_sync::AppSyncState,
    pub filter: ffi::filter::FilterState,
    /// 设备运行时状态统一注册表
    pub registry: device_registry::DeviceRegistry,
    pub spake2_prover: Option<crypto::spake2::Spake2ProverSession>,
    pub spake2_verifier: Option<crypto::spake2::Spake2VerifierSession>,
    pub pairing_ctx: Option<PairingContext>,
    pub expected_pairing_code: Option<String>,
    /// 配对码生成（接收端/初始生成端）
    pub pairing_code: Option<String>,
    /// 配对码过期时间
    pub pairing_code_expiry: Option<Instant>,
    pub broadcast_info: Option<BroadcastInfo>,
    pub broadcast_handle: Option<BroadcastHandle>,
    /// UUID → IP 映射（从 UDP 心跳源地址、TCP 连接等收集）
    pub device_ips: Mutex<HashMap<String, String>>,
    // 新增字段
    /// 统一心跳调度器句柄（扫描 known_devices 自动启停每设备心跳）
    pub heartbeat_scheduler: u64,
    /// 调度器持有的每设备 HeartbeatHandle（跨轮次持久，由调度线程维护）
    pub heartbeat_scheduler_handles: HashMap<String, heartbeat::HeartbeatHandle>,
    /// 心跳模式：false=广播主用（UDP 广播兼发现+心跳，不启动每设备心跳）；
    /// true=TCP 备用（锁屏/WLAN直连 时每设备 TCP 定向心跳）
    pub heartbeat_tcp_backup: AtomicBool,
    pub offline_detector_handle: u64,
    pub sender_queue: u64,
    pub reconnect_state: u64,
    /// 超级岛 / 媒体 状态合并引擎（diff/merge/ACK/心跳全部在此闭环）
    pub state_merge: state_merge::StateMerge,
    /// 配对成功后延迟应用列表请求互斥标志（防止多次配对时线程堆叠）
    pub applist_delay_pending: Arc<AtomicBool>,
    // ===== 私有持久化（uuid/密钥由 Rust 独自持有）=====
    /// core 私有 SQLite 库（惰性打开）
    pub persistence: Option<persistence::Persistence>,
    /// 已尝试过加载（防重复 open）
    pub persistence_loaded: bool,
    /// 内存状态与库不一致（读取接口前自动落盘）
    pub persistence_dirty: bool,
    /// 持久化已激活（平台端已确认身份来源：get_local_uuid / start_core / 广播）。
    /// 未激活时自动落盘跳过，避免测试等非应用进程在默认路径创建库
    pub persistence_activated: bool,
    /// 本机 UUID（库为准；平台 start_core/广播时同步）
    pub local_uuid: String,
    /// 库内设备行缓存（供 get_device_list 名称/IP 展示）
    pub persisted_devices: std::collections::HashMap<String, persistence::PersistedDevice>,
    /// 待删除设备 UUID（nrc_remove_device 加入，flush_all 事务内执行 DELETE，
    /// 保证 state 更新与行删除原子生效，避免 flush 失败后重启设备"复活"）
    pub pending_device_deletions: Vec<String>,
    /// 持久化库路径覆盖（测试隔离用：每个测试注入独立库文件；生产为 None）
    db_override: Option<std::path::PathBuf>,
}

pub struct PairingContext {
    pub peer_uuid: String,
    pub peer_spake2_pub: String,
    pub peer_lt_pub: Option<String>,
}

pub struct BroadcastInfo {
    pub uuid: String,
    pub name_b64: String,
    pub battery: i32,
    pub device_type: String,
}

pub struct BroadcastHandle {
    pub running: Arc<AtomicBool>,
}

impl CoreContext {
    pub fn new() -> Self {
        Self {
            crypto: crypto::CryptoState::new(),
            router: router::Router::new(),
            heartbeat: heartbeat::HeartbeatState::new(),
            discovery: discovery::DiscoveryState::new(),
            audio: Arc::new(Mutex::new(audio_stream::AudioStreamState::new())),
            network: network::NetworkState::new(),
            mdns: mdns::MdnsState::new(),
            dedup: dedup::DedupState::new(),
            clipboard: clipboard::ClipboardState::new(),
            app_sync: app_sync::AppSyncState::new(),
            filter: ffi::filter::FilterState::new(),
            registry: device_registry::DeviceRegistry::new(),
            device_ips: Mutex::new(HashMap::new()),
            spake2_prover: None,
            spake2_verifier: None,
            pairing_ctx: None,
            expected_pairing_code: None,
            pairing_code: None,
            pairing_code_expiry: None,
            broadcast_info: None,
            broadcast_handle: None,
            heartbeat_scheduler: 0,
            heartbeat_scheduler_handles: HashMap::new(),
            heartbeat_tcp_backup: AtomicBool::new(false),
            offline_detector_handle: 0,
            sender_queue: 0,
            reconnect_state: 0,
            state_merge: state_merge::StateMerge::new(),
            applist_delay_pending: Arc::new(AtomicBool::new(false)),
            persistence: None,
            persistence_loaded: false,
            persistence_dirty: false,
            persistence_activated: false,
            local_uuid: String::new(),
            persisted_devices: HashMap::new(),
            pending_device_deletions: Vec::new(),
            db_override: None,
        }
    }

    /// 指定持久化库路径构造（测试隔离用：每个测试注入独立库文件）
    pub fn with_db_override(path: std::path::PathBuf) -> Self {
        let mut c = Self::new();
        c.db_override = Some(path);
        c
    }

    fn open_persistence(&self) -> Option<persistence::Persistence> {
        if let Some(p) = self.db_override.as_ref() {
            return persistence::Persistence::open_at(p).ok();
        }
        persistence::Persistence::open().ok()
    }

    fn open_persistence_if_exists(&self) -> Option<persistence::Persistence> {
        if let Some(p) = self.db_override.as_ref() {
            if p.exists() {
                return persistence::Persistence::open_at(p).ok();
            }
            return None;
        }
        persistence::Persistence::open_if_exists().ok().flatten()
    }
}

impl CoreContext {
    /// 惰性加载：库文件已存在才 open+load；全新安装跳过
    /// 区分"文件不存在"（不重试）与"文件存在但打开失败"（保留重试机会）
    pub fn ensure_persistence_loaded(&mut self) {
        if self.persistence.is_some() || self.persistence_loaded {
            return;
        }
        // 先检查库文件是否已存在：不存在则标记已尝试（全新安装不创建库）
        let path_exists = if let Some(p) = self.db_override.as_ref() {
            p.exists()
        } else {
            persistence::Persistence::resolve_db_path()
                .map(|p| p.exists())
                .unwrap_or(false)
        };
        if !path_exists {
            self.persistence_loaded = true;
            log::info!("持久化库不存在（全新安装），跳过加载");
            return;
        }
        // 文件存在：尝试打开，失败不标记（下次重试，应对临时权限/锁问题）
        match self.open_persistence_if_exists() {
            Some(p) => {
                self.persistence_loaded = true;
                if let Err(e) = persistence::load_all(
                    &p,
                    &mut self.crypto,
                    &mut self.persisted_devices,
                    &mut self.local_uuid,
                ) {
                    log::error!("持久化加载失败: {}", e);
                } else {
                    log::info!("持久化加载完成 uuid={}", self.local_uuid);
                }
                self.persistence = Some(p);
            }
            None => {
                // 文件存在但打开失败：不标记 persistence_loaded，下次重试
                log::warn!("持久化库存在但打开失败，将在下次调用时重试");
            }
        }
    }

    pub fn mark_persistence_dirty(&mut self) {
        self.persistence_dirty = true;
    }

    /// 确保本机 UUID 就绪：库有则用库值；无则 Rust 生成 v4 UUID 并落库
    /// （平台端不再生成 UUID，仅读取，减少数据流动）
    pub fn ensure_local_uuid(&mut self) -> bool {
        if !self.local_uuid.is_empty() {
            return true;
        }
        let p = if self.persistence.is_some() {
            self.persistence.as_ref().unwrap()
        } else {
            match self.open_persistence() {
                Some(p) => {
                    self.persistence = Some(p);
                    self.persistence.as_ref().unwrap()
                }
                None => {
                    log::warn!("持久化打开失败: 无法生成本机 UUID");
                    return false;
                }
            }
        };
        match p.get_local_uuid() {
            Some(u) if !u.is_empty() => {
                self.local_uuid = u;
                true
            }
            _ => {
                let new_uuid = uuid::Uuid::new_v4().to_string();
                if let Err(e) = p.save_local_uuid(&new_uuid) {
                    log::error!("保存本机 UUID 失败: {}", e);
                    return false;
                }
                self.local_uuid = new_uuid;
                // 已生成新 uuid，状态加密密钥随之变化，需要重新落盘
                self.persistence_dirty = true;
                true
            }
        }
    }

    /// 组装库内设备行（密钥来自 crypto，名称/IP 来自库缓存与运行时注册表）
    fn build_device_row(&self, uuid: &str) -> persistence::PersistedDevice {
        let key = self.crypto.device_keys.get(uuid);
        let info = self.persisted_devices.get(uuid);
        let reg = self.registry.get(uuid);
        let now = crate::device_registry::now_sec();
        let created = info.map(|i| i.created_at).unwrap_or(now);
        let display_name = info
            .map(|i| i.display_name.clone())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                reg.as_ref()
                    .map(|r| r.name.clone())
                    .filter(|s| !s.is_empty())
            })
            .unwrap_or_default();
        let last_ip = reg
            .as_ref()
            .map(|r| r.ip.clone())
            .filter(|s| !s.is_empty() && s != "0.0.0.0")
            .or_else(|| info.map(|i| i.last_ip.clone()).filter(|s| !s.is_empty()))
            .unwrap_or_default();
        let last_port = reg
            .as_ref()
            .map(|r| r.port)
            .filter(|&p| p > 0)
            .or_else(|| info.map(|i| i.last_port))
            .unwrap_or(crate::protocol::codec::DEFAULT_TCP_PORT);
        persistence::PersistedDevice {
            uuid: uuid.to_string(),
            public_key: key.map(|k| k.remote_pub_key.clone()).unwrap_or_default(),
            shared_secret: key.map(|k| k.aes_key_b64.clone()).unwrap_or_default(),
            is_accepted: key.is_some() || info.map(|i| i.is_accepted).unwrap_or(false),
            display_name,
            last_ip,
            last_port,
            created_at: created,
            updated_at: now,
        }
    }

    /// 打开（创建）库并写入单个设备行（配对/改名等关键路径用）
    /// 库尚不存在时立即创建写入：配对密钥不依赖「库已预先存在」；
    /// 仅打开失败时为不阻塞配对流程降至 dirty（由后续读取前 flush 兜底）
    pub fn persist_device_row_now(&mut self, uuid: &str) {
        let p = if self.persistence.is_some() {
            self.persistence.as_ref().unwrap()
        } else {
            match self.open_persistence() {
                Some(p) => {
                    self.persistence = Some(p);
                    self.persistence.as_ref().unwrap()
                }
                None => {
                    log::warn!("持久化打开失败，标记 dirty 稍后重试");
                    self.mark_persistence_dirty();
                    return;
                }
            }
        };
        let dev = self.build_device_row(uuid);
        let has_key = self.crypto.device_keys.contains_key(uuid);
        if let Err(e) = p.upsert_device_row(&dev, has_key) {
            log::error!("持久化设备行失败 {}: {}", uuid, e);
            return;
        }
        // 同步库缓存
        if let Some(info) = self.persisted_devices.get_mut(uuid) {
            info.display_name = dev.display_name.clone();
            info.last_ip = dev.last_ip.clone();
            info.last_port = dev.last_port;
            info.public_key = dev.public_key.clone();
            info.shared_secret = dev.shared_secret.clone();
            info.is_accepted = dev.is_accepted;
            info.updated_at = dev.updated_at;
        }
    }

    /// 读取接口前的自动落盘：dirty 且持久化已激活时打开库并写入 uuid/state/设备行
    /// 本机 UUID 由 Rust 生成/持有（ensure_local_uuid），平台端仅读取
    pub fn flush_persistence(&mut self) -> bool {
        if !self.persistence_dirty {
            return true;
        }
        if !self.persistence_activated {
            log::debug!("持久化未激活（平台端身份未确认），跳过自动落盘");
            return true;
        }
        if !self.ensure_local_uuid() {
            log::warn!("本机 UUID 不可用，暂缓持久化落盘");
            return false;
        }
        if self.persistence.is_none() {
            match self.open_persistence() {
                Some(p) => self.persistence = Some(p),
                None => {
                    log::warn!("持久化打开失败，暂缓落盘");
                    return false;
                }
            }
        }
        // ——只读收集（不持有持久化可变借用）——
        let encrypted_state = persistence::encrypt_state(&self.crypto, &self.local_uuid)
            .map(Some)
            .unwrap_or_else(|e| {
                log::error!("加密密钥状态失败: {}", e);
                None
            });
        let mut uuids: Vec<String> = self.crypto.device_keys.keys().cloned().collect();
        uuids.extend(self.persisted_devices.keys().cloned());
        uuids.sort();
        uuids.dedup();
        let rows: Vec<(persistence::PersistedDevice, bool)> = uuids
            .iter()
            .map(|uuid| {
                (
                    self.build_device_row(uuid),
                    self.crypto.device_keys.contains_key(uuid),
                )
            })
            .collect();
        // 墓碑清理：库中残留但内存已无的设备行（删除未直删成功/异常时兜底，
        // 防止重启后 load_all 把行内密钥回灌导致设备“复活”）
        let tombstones: Vec<String> = {
            let p = self.persistence.as_ref().unwrap();
            p.load_device_rows()
                .ok()
                .map(|rows| {
                    rows.into_iter()
                        .filter(|row| {
                            !self.crypto.device_keys.contains_key(&row.uuid)
                                && !self.persisted_devices.contains_key(&row.uuid)
                        })
                        .map(|row| row.uuid)
                        .collect()
                })
                .unwrap_or_default()
        };
        // ——单事务原子写入：state 与设备行要么同时生效要么同时回滚，
        // 避免中间态导致重启后加载旧密钥而忽略更新的设备行——
        let p = self.persistence.as_mut().unwrap();
        match p.flush_all(
            Some(&self.local_uuid),
            encrypted_state.as_deref(),
            &rows,
            &tombstones,
            &self.pending_device_deletions,
        ) {
            Ok(()) => {
                self.persistence_dirty = false;
                self.pending_device_deletions.clear();
                true
            }
            Err(e) => {
                log::error!("持久化落盘失败（保留 dirty，等待重试）: {}", e);
                false
            }
        }
    }
}

impl Default for CoreContext {
    fn default() -> Self {
        Self::new()
    }
}

pub type SafeContext = Mutex<CoreContext>;
