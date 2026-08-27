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
        }
    }
}

impl CoreContext {
    /// 惰性加载：库文件已存在才 open+load；全新安装跳过
    pub fn ensure_persistence_loaded(&mut self) {
        if self.persistence.is_some() || self.persistence_loaded {
            return;
        }
        self.persistence_loaded = true;
        match persistence::Persistence::open_if_exists() {
            Ok(Some(p)) => {
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
            Ok(None) => {
                log::info!("持久化库不存在（全新安装），跳过加载");
            }
            Err(e) => {
                log::warn!("持久化打开失败: {}", e);
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
            match persistence::Persistence::open() {
                Ok(p) => {
                    self.persistence = Some(p);
                    self.persistence.as_ref().unwrap()
                }
                Err(e) => {
                    log::warn!("持久化打开失败: {}", e);
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
    /// 库尚不存在时仅置脏（由读取接口前 flush 创建库并落盘），避免测试/异常环境创建空库
    pub fn persist_device_row_now(&mut self, uuid: &str) {
        if self.persistence.is_none() {
            match persistence::Persistence::resolve_db_path() {
                Ok(path) if path.exists() => {}
                Ok(_) => {
                    self.mark_persistence_dirty();
                    return;
                }
                Err(_) => {
                    self.mark_persistence_dirty();
                    return;
                }
            }
        }
        let p = if self.persistence.is_some() {
            self.persistence.as_ref().unwrap()
        } else {
            match persistence::Persistence::open() {
                Ok(p) => {
                    self.persistence = Some(p);
                    self.persistence.as_ref().unwrap()
                }
                Err(e) => {
                    log::warn!("持久化打开失败: {}", e);
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
        let p = if self.persistence.is_some() {
            self.persistence.as_ref().unwrap()
        } else {
            match persistence::Persistence::open() {
                Ok(p) => {
                    self.persistence = Some(p);
                    self.persistence.as_ref().unwrap()
                }
                Err(e) => {
                    log::warn!("持久化打开失败: {}", e);
                    return false;
                }
            }
        };
        if !self.local_uuid.is_empty() {
            if let Err(e) = p.save_local_uuid(&self.local_uuid) {
                log::error!("保存本机 UUID 失败: {}", e);
            }
        }
        match persistence::encrypt_state(&self.crypto, &self.local_uuid) {
            Ok(enc) => {
                if let Err(e) = p.save_state_encrypted(&enc) {
                    log::error!("保存密钥状态失败: {}", e);
                }
            }
            Err(e) => log::error!("加密密钥状态失败: {}", e),
        }
        let mut uuids: Vec<String> = self.crypto.device_keys.keys().cloned().collect();
        uuids.extend(self.persisted_devices.keys().cloned());
        uuids.sort();
        uuids.dedup();
        for uuid in &uuids {
            let dev = self.build_device_row(uuid);
            let has_key = self.crypto.device_keys.contains_key(uuid);
            if let Err(e) = p.upsert_device_row(&dev, has_key) {
                log::error!("持久化设备行失败 {}: {}", uuid, e);
            }
        }
        self.persistence_dirty = false;
        true
    }
}

impl Default for CoreContext {
    fn default() -> Self {
        Self::new()
    }
}

pub type SafeContext = Mutex<CoreContext>;
