//! 私有持久化模块：本机 UUID、密钥状态、设备键由 Rust 独自持有
//!
//! 设计要点：
//! - 库路径由 core 自动定位（Android: /proc/self/cmdline 取包名 →
//!   /data/user/0/<pkg>/rust_core.db；Windows: %LOCALAPPDATA%\rust_core.db），
//!   环境变量 NR_NOTIFY_CORE_DB_PATH 可覆盖（测试/调试/部署护航）
//! - 惰性加载：库文件已存在才 open 并读入内存；不存在视为全新安装
//! - 脏标记 flush：状态变更标记 dirty，读取接口（get_local_uuid /
//!   get_device_list）前自动落盘，平台端无需任何入库接口；
//!   配对/删除/改名等关键路径直接写库

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use base64::Engine;
use rusqlite::Connection;

use crate::crypto::{self, aes, ecdh, hkdf};

const KEY_LOCAL_UUID: &str = "general_device_uuid";
const KEY_RUST_CORE_STATE: &str = "general_rust_core_state";
const DB_FILE_NAME: &str = "rust_core.db";

/// 库内设备行（密钥 + UI 元数据；给 get_device_list 展示用）
#[derive(Debug, Clone, Default)]
pub struct PersistedDevice {
    pub uuid: String,
    pub public_key: String,
    pub shared_secret: String,
    pub is_accepted: bool,
    pub display_name: String,
    pub last_ip: String,
    pub last_port: u16,
    pub created_at: i64,
    pub updated_at: i64,
}

impl PersistedDevice {
    pub fn from_row(
        uuid: String,
        public_key: String,
        shared_secret: String,
        is_accepted: bool,
        display_name: String,
        last_ip: String,
        last_port: i64,
        created_at: i64,
        updated_at: i64,
    ) -> Self {
        Self {
            uuid,
            public_key,
            shared_secret,
            is_accepted,
            display_name,
            last_ip,
            last_port: last_port.clamp(0, u16::MAX as i64) as u16,
            created_at,
            updated_at,
        }
    }
}

/// 持久化管理器（core 私有单库）
pub struct Persistence {
    db: Connection,
}

impl Persistence {
    fn ensure_parent(path: &Path) {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
    }

    /// 解析数据库路径：环境变量 > Android 包目录 > Windows 本地应用目录
    pub fn resolve_db_path() -> Result<PathBuf, String> {
        if let Ok(p) = std::env::var("NR_NOTIFY_CORE_DB_PATH") {
            if !p.is_empty() {
                return Ok(PathBuf::from(p));
            }
        }
        #[cfg(target_os = "android")]
        if let Some(dir) = Self::android_app_dir() {
            return Ok(dir.join(DB_FILE_NAME));
        }
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            if !local.is_empty() {
                return Ok(PathBuf::from(local).join(DB_FILE_NAME));
            }
        }
        if let Ok(user) = std::env::var("USERPROFILE") {
            if !user.is_empty() {
                return Ok(PathBuf::from(user)
                    .join("AppData")
                    .join("Local")
                    .join(DB_FILE_NAME));
            }
        }
        if let Ok(home) = std::env::var("HOME") {
            if !home.is_empty() {
                return Ok(PathBuf::from(home).join(DB_FILE_NAME));
            }
        }
        Err("无法定位持久化数据库路径".to_string())
    }

    /// Android 应用私有目录：/proc/self/cmdline 首字段为包名（子进程含 "pkg:process"）
    #[cfg(target_os = "android")]
    fn android_app_dir() -> Option<PathBuf> {
        if let Ok(raw) = std::fs::read("/proc/self/cmdline") {
            if let Some(first) = raw.split(|&b| b == 0).next() {
                if let Ok(s) = std::str::from_utf8(first) {
                    let pkg = s.split(':').next().unwrap_or(s);
                    if !pkg.is_empty() && pkg != "zygote" && !pkg.starts_with('[') {
                        return Some(PathBuf::from(format!("/data/user/0/{}", pkg)));
                    }
                }
            }
        }
        None
    }

    /// 打开（不存在则创建并建表）
    pub fn open() -> Result<Self, String> {
        let path = Self::resolve_db_path()?;
        Self::open_at(&path)
    }

    /// 库文件已存在才打开（惰性加载入口；全新安装时返回 None 不创建库）
    pub fn open_if_exists() -> Result<Option<Self>, String> {
        let path = Self::resolve_db_path()?;
        if !path.exists() {
            return Ok(None);
        }
        Self::open_at(&path).map(Some)
    }

    /// 在指定路径打开库（测试/故障排查用）
    fn open_at(path: &Path) -> Result<Self, String> {
        Self::ensure_parent(path);
        let conn = Connection::open(path)
            .map_err(|e| format!("打开数据库失败 {}: {}", path.display(), e))?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA busy_timeout=5000;",
        )
        .map_err(|e| format!("设置 WAL 模式失败: {}", e))?;
        Self::ensure_tables(&conn)?;
        Ok(Self { db: conn })
    }

    fn ensure_tables(conn: &Connection) -> Result<(), String> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS app_config (
                key TEXT PRIMARY KEY NOT NULL,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS devices (
                uuid TEXT PRIMARY KEY NOT NULL,
                publicKey TEXT NOT NULL,
                sharedSecret TEXT NOT NULL,
                isAccepted INTEGER NOT NULL,
                displayName TEXT NOT NULL,
                lastIp TEXT NOT NULL,
                lastPort INTEGER NOT NULL,
                createdAt INTEGER NOT NULL,
                updatedAt INTEGER NOT NULL
            );",
        )
        .map_err(|e| format!("创建表失败: {}", e))
    }

    // ============================================================
    //  本机信息
    // ============================================================

    pub fn get_local_uuid(&self) -> Option<String> {
        self.db
            .query_row(
                "SELECT value FROM app_config WHERE key = ?1",
                [KEY_LOCAL_UUID],
                |row| row.get(0),
            )
            .ok()
            .filter(|s: &String| !s.is_empty())
    }

    pub fn save_local_uuid(&self, uuid: &str) -> Result<(), String> {
        if uuid.is_empty() {
            return Ok(());
        }
        self.db
            .execute(
                "INSERT OR REPLACE INTO app_config (key, value) VALUES (?1, ?2)",
                rusqlite::params![KEY_LOCAL_UUID, uuid],
            )
            .map_err(|e| format!("保存本机 UUID 失败: {}", e))?;
        Ok(())
    }

    // ============================================================
    //  密钥状态（加密 KeyStoreData）
    // ============================================================

    pub fn get_state_encrypted(&self) -> Option<String> {
        self.db
            .query_row(
                "SELECT value FROM app_config WHERE key = ?1",
                [KEY_RUST_CORE_STATE],
                |row| row.get(0),
            )
            .ok()
            .filter(|s: &String| !s.is_empty())
    }

    pub fn save_state_encrypted(&self, encrypted: &str) -> Result<(), String> {
        self.db
            .execute(
                "INSERT OR REPLACE INTO app_config (key, value) VALUES (?1, ?2)",
                rusqlite::params![KEY_RUST_CORE_STATE, encrypted],
            )
            .map_err(|e| format!("保存密钥状态失败: {}", e))?;
        Ok(())
    }

    // ============================================================
    //  设备行
    // ============================================================

    pub fn load_device_rows(&self) -> Result<Vec<PersistedDevice>, String> {
        let mut stmt = self
            .db
            .prepare(
                "SELECT uuid, publicKey, sharedSecret, isAccepted, displayName, lastIp, lastPort, createdAt, updatedAt
                 FROM devices",
            )
            .map_err(|e| format!("准备设备查询失败: {}", e))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(PersistedDevice::from_row(
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get::<_, i32>(3)? != 0,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                ))
            })
            .map_err(|e| format!("查询设备失败: {}", e))?
            .filter_map(|r| r.ok())
            .collect::<Vec<_>>();
        Ok(rows)
    }

    /// 幂等 upsert：基础行 INSERT OR IGNORE，密钥列/元数据列分别补充
    pub fn upsert_device_row(&self, dev: &PersistedDevice, has_key: bool) -> Result<(), String> {
        self.db
            .execute(
                "INSERT OR IGNORE INTO devices (uuid, publicKey, sharedSecret, isAccepted, displayName, lastIp, lastPort, createdAt, updatedAt)
                 VALUES (?1, '', '', 0, '', '', 0, ?2, ?2)",
                rusqlite::params![dev.uuid, dev.updated_at],
            )
            .map_err(|e| format!("插入设备行失败: {}", e))?;
        if has_key && !dev.shared_secret.is_empty() {
            self.db
                .execute(
                    "UPDATE devices SET publicKey = ?1, sharedSecret = ?2, isAccepted = 1, updatedAt = ?3 WHERE uuid = ?4",
                    rusqlite::params![dev.public_key, dev.shared_secret, dev.updated_at, dev.uuid],
                )
                .map_err(|e| format!("更新设备密钥失败: {}", e))?;
        }
        if !dev.display_name.is_empty() || !dev.last_ip.is_empty() || dev.last_port > 0 {
            self.db
                .execute(
                    "UPDATE devices SET displayName = ?1, lastIp = ?2, lastPort = ?3, updatedAt = ?4 WHERE uuid = ?5",
                    rusqlite::params![
                        dev.display_name,
                        dev.last_ip,
                        dev.last_port as i64,
                        dev.updated_at,
                        dev.uuid
                    ],
                )
                .map_err(|e| format!("更新设备信息失败: {}", e))?;
        }
        Ok(())
    }

    pub fn delete_device(&self, uuid: &str) -> Result<(), String> {
        self.db
            .execute("DELETE FROM devices WHERE uuid = ?1", [uuid])
            .map_err(|e| format!("删除设备失败: {}", e))?;
        Ok(())
    }

    /// 单事务写入全部落盘内容（uuid/state/设备行/墓碑清理），失败整体回滚
    /// 保证 state 与设备密钥行要么同时生效要么都不生效，
    /// 避免「state 已写/行未写」或「行已写/state 未写」的中间态在重启时
    /// 加载旧密钥而忽略更新的设备行（load_all 以 state 优先）
    pub fn flush_all(
        &mut self,
        local_uuid: Option<&str>,
        encrypted_state: Option<&str>,
        rows: &[(PersistedDevice, bool)],
        tombstones: &[String],
    ) -> Result<(), String> {
        let tx = self
            .db
            .transaction()
            .map_err(|e| format!("开启事务失败: {}", e))?;
        if let Some(u) = local_uuid {
            if !u.is_empty() {
                tx.execute(
                    "INSERT OR REPLACE INTO app_config (key, value) VALUES (?1, ?2)",
                    rusqlite::params![KEY_LOCAL_UUID, u],
                )
                .map_err(|e| format!("保存本机 UUID 失败: {}", e))?;
            }
        }
        if let Some(enc) = encrypted_state {
            tx.execute(
                "INSERT OR REPLACE INTO app_config (key, value) VALUES (?1, ?2)",
                rusqlite::params![KEY_RUST_CORE_STATE, enc],
            )
            .map_err(|e| format!("保存密钥状态失败: {}", e))?;
        }
        for (dev, has_key) in rows {
            Self::upsert_device_row_tx(&tx, dev, *has_key)?;
        }
        for uuid in tombstones {
            tx.execute("DELETE FROM devices WHERE uuid = ?1", [uuid.as_str()])
                .map_err(|e| format!("删除残留设备行失败 {}: {}", uuid, e))?;
        }
        tx.commit().map_err(|e| format!("提交事务失败: {}", e))
    }

    fn upsert_device_row_tx(
        tx: &rusqlite::Transaction,
        dev: &PersistedDevice,
        has_key: bool,
    ) -> Result<(), String> {
        tx.execute(
            "INSERT OR IGNORE INTO devices (uuid, publicKey, sharedSecret, isAccepted, displayName, lastIp, lastPort, createdAt, updatedAt)
             VALUES (?1, '', '', 0, '', '', 0, ?2, ?2)",
            rusqlite::params![dev.uuid, dev.updated_at],
        )
        .map_err(|e| format!("插入设备行失败: {}", e))?;
        if has_key && !dev.shared_secret.is_empty() {
            tx.execute(
                "UPDATE devices SET publicKey = ?1, sharedSecret = ?2, isAccepted = 1, updatedAt = ?3 WHERE uuid = ?4",
                rusqlite::params![dev.public_key, dev.shared_secret, dev.updated_at, dev.uuid],
            )
            .map_err(|e| format!("更新设备密钥失败: {}", e))?;
        }
        if !dev.display_name.is_empty() || !dev.last_ip.is_empty() || dev.last_port > 0 {
            tx.execute(
                "UPDATE devices SET displayName = ?1, lastIp = ?2, lastPort = ?3, updatedAt = ?4 WHERE uuid = ?5",
                rusqlite::params![
                    dev.display_name,
                    dev.last_ip,
                    dev.last_port as i64,
                    dev.updated_at,
                    dev.uuid
                ],
            )
            .map_err(|e| format!("更新设备信息失败: {}", e))?;
        }
        Ok(())
    }
}

/// 加密密钥状态 → app_config（复用现有 encrypt_local_state 原语：hkdf(uuid) 派生密钥）
pub fn encrypt_state(crypto: &crypto::CryptoState, local_uuid: &str) -> Result<String, String> {
    let local_priv_pem = crypto
        .local_key
        .as_ref()
        .and_then(|k| ecdh::secret_to_pem(k).ok());
    let data = crypto::KeyStoreData {
        local_private_key_pem: local_priv_pem,
        local_public_key_b64: crypto.local_pub_key_b64.clone(),
        devices: crypto.device_keys.clone(),
    };
    let json = serde_json::to_string(&data).map_err(|e| format!("序列化状态失败: {}", e))?;
    let key = hkdf::derive_local_state_key(local_uuid);
    aes::encrypt(&key, json.as_bytes()).map_err(|e| format!("加密状态失败: {}", e))
}

/// app_config 加密状态 → KeyStoreData
pub fn decrypt_state(encrypted: &str, local_uuid: &str) -> Result<crypto::KeyStoreData, String> {
    let key = hkdf::derive_local_state_key(local_uuid);
    let plaintext = aes::decrypt(&key, encrypted).map_err(|e| format!("解密状态失败: {}", e))?;
    let json_str = String::from_utf8_lossy(&plaintext).to_string();
    serde_json::from_str(&json_str).map_err(|e| format!("解析状态 JSON 失败: {}", e))
}

/// 将 KeyStoreData 导入 CryptoState（与 import_state 对称，填充 aes_key_bytes）
pub fn apply_keystore_data(crypto: &mut crypto::CryptoState, data: &crypto::KeyStoreData) {
    if let Some(ref pem) = data.local_private_key_pem {
        crypto.local_key = ecdh::secret_from_pem(pem).ok();
    }
    crypto.local_pub_key_b64 = data.local_public_key_b64.clone();
    let mut device_keys = data.devices.clone();
    for entry in device_keys.values_mut() {
        if entry.aes_key_bytes.is_none() {
            if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&entry.aes_key_b64)
            {
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    entry.aes_key_bytes = Some(arr);
                }
            }
        }
    }
    crypto.device_keys = device_keys;
}

/// 从库中一次性加载到内存（uuid/密钥状态/设备行）
pub fn load_all(
    persistence: &Persistence,
    crypto: &mut crypto::CryptoState,
    devices_out: &mut HashMap<String, PersistedDevice>,
    local_uuid_out: &mut String,
) -> Result<(), String> {
    if let Some(uuid) = persistence.get_local_uuid() {
        *local_uuid_out = uuid.clone();
        // 解密密钥状态（uuid 已知才可能解密）
        if let Some(enc) = persistence.get_state_encrypted() {
            match decrypt_state(&enc, &uuid) {
                Ok(data) => apply_keystore_data(crypto, &data),
                Err(e) => log::warn!("解密密钥状态失败: {}", e),
            }
        }
    }
    for row in persistence.load_device_rows()? {
        // 密钥行补齐 crypto（state 未覆盖时）
        if !row.shared_secret.is_empty() && !crypto.device_keys.contains_key(&row.uuid) {
            let key_bytes = base64::engine::general_purpose::STANDARD
                .decode(&row.shared_secret)
                .ok()
                .filter(|b| b.len() == 32);
            if key_bytes.is_some() {
                crypto.set_device_key(
                    row.uuid.clone(),
                    row.public_key.clone(),
                    row.shared_secret.clone(),
                );
            }
        }
        devices_out.insert(row.uuid.clone(), row);
    }
    Ok(())
}
