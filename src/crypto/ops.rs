//! 密钥与本地状态的上下文级操作。
//!
//! 由 ECDH 密钥派生、设备密钥迁移/移除、密钥状态导入导出与本地状态加解密聚合入口组成。
//! 只做业务逻辑，不涉及任何 C 字符串或 FFI 类型。

use base64::Engine;

use crate::crypto::{self, aes, ecdh, hkdf};
use crate::CoreContext;

// ===== ECDH =====

/// 生成本机 ECDH 密钥对并写入上下文。
pub fn generate_keypair(ctx: &mut CoreContext) {
    ctx.ensure_persistence_loaded();
    let (secret, b64) = ecdh::generate_keypair();
    ctx.crypto.local_key = Some(secret);
    ctx.crypto.local_pub_key_b64 = Some(b64);
    ctx.mark_persistence_dirty();
}

/// 读取本机长期公钥（Base64）；未生成时为 `None`。
pub fn public_key(ctx: &mut CoreContext) -> Option<String> {
    ctx.ensure_persistence_loaded();
    ctx.crypto.local_pub_key_b64.clone()
}

/// 本机是否已持有密钥对。
pub fn has_keypair(ctx: &mut CoreContext) -> bool {
    ctx.ensure_persistence_loaded();
    ctx.crypto.local_key.is_some()
}

/// 由对端公钥派生共享密钥并登记为设备密钥。
///
/// 成功时立即落库该设备行（配对关键路径，防进程丢失）；派生失败返回 `false`。
pub fn derive_shared_secret(ctx: &mut CoreContext, peer_uuid: &str, peer_pub_b64: &str) -> bool {
    ctx.ensure_persistence_loaded();
    let Some(ref private_key) = ctx.crypto.local_key else {
        return false;
    };
    let Ok(shared) = ecdh::compute_shared_secret(private_key, peer_pub_b64) else {
        return false;
    };
    let aes_key = hkdf::derive_session_key(&shared);
    ctx.crypto.set_device_key(
        peer_uuid.to_string(),
        peer_pub_b64.to_string(),
        base64::engine::general_purpose::STANDARD.encode(aes_key),
    );
    ctx.mark_persistence_dirty();
    ctx.persist_device_row_now(peer_uuid);
    true
}

// ===== 设备密钥管理 =====

/// 迁移导入 32 字节共享密钥，并原子落盘。
pub fn migrate_shared_secret(ctx: &mut CoreContext, device_uuid: &str, aes_key: &[u8]) -> bool {
    if aes_key.len() != 32 {
        return false;
    }
    ctx.ensure_persistence_loaded();
    let b64 = base64::engine::general_purpose::STANDARD.encode(aes_key);
    ctx.crypto
        .set_device_key(device_uuid.to_string(), String::new(), b64);
    // 迁移导入的密钥：通过 flush_persistence 原子持久化（state + 设备行同一事务）
    ctx.mark_persistence_dirty();
    ctx.flush_persistence()
}

/// 移除设备：内存态、注册表、库缓存同步清理并原子落盘。
pub fn remove_device(ctx: &mut CoreContext, device_uuid: &str) -> bool {
    ctx.ensure_persistence_loaded();
    // 先从内存移除：保持内存与意图一致
    ctx.crypto.device_keys.remove(device_uuid);
    ctx.registry.remove(device_uuid);
    ctx.persisted_devices.remove(device_uuid);
    // 加入待删除队列：flush_all 事务内执行 DELETE，与 state 更新原子生效
    // 避免「行已删 / state 未写」导致重启后旧 state 密钥回灌使设备"复活"
    ctx.pending_device_deletions.push(device_uuid.to_string());
    ctx.mark_persistence_dirty();
    // 立即重写密钥状态：删除后进程被杀 / 重启时，旧 state 中的密钥
    // 会把设备从库中"复活"，必须同步落盘（未激活时由下次读取前 flush 兜底）
    if !ctx.flush_persistence() {
        log::error!(
            "删除设备后持久化落盘失败 {}: 将在下次读取前重试",
            device_uuid
        );
        return false;
    }
    true
}

/// 读取指定设备的密钥材料 JSON（`aes_key_b64` + `remote_pub_key`）。
pub fn export_device_key_json(ctx: &mut CoreContext, device_uuid: &str) -> Option<String> {
    ctx.ensure_persistence_loaded();
    ctx.crypto.device_keys.get(device_uuid).map(|k| {
        serde_json::json!({
            "aes_key_b64": k.aes_key_b64,
            "remote_pub_key": k.remote_pub_key,
        })
        .to_string()
    })
}

// ===== 密钥状态导入导出 =====

/// 构造密钥状态 JSON（导出前先加载持久化，保证内存态完整）。
pub fn build_state_json(ctx: &mut CoreContext) -> Option<String> {
    ctx.ensure_persistence_loaded();
    let local_priv_pem = ctx
        .crypto
        .local_key
        .as_ref()
        .and_then(|k| ecdh::secret_to_pem(k).ok());
    let data = crypto::KeyStoreData {
        local_private_key_pem: local_priv_pem,
        local_public_key_b64: ctx.crypto.local_pub_key_b64.clone(),
        devices: ctx.crypto.device_keys.clone(),
    };
    serde_json::to_string(&data).ok()
}

/// 解析密钥状态 JSON 并应用（成功后标记持久化待落盘）。
pub fn apply_state_json(ctx: &mut CoreContext, json: &str) -> bool {
    ctx.ensure_persistence_loaded();
    match serde_json::from_str::<crypto::KeyStoreData>(json) {
        Ok(data) => {
            crate::persistence::apply_keystore_data(&mut ctx.crypto, &data);
            ctx.mark_persistence_dirty();
            true
        }
        Err(e) => {
            log::error!("导入状态解析失败: {}", e);
            false
        }
    }
}

/// 导出完整密钥状态 JSON。
pub fn export_state(ctx: &mut CoreContext) -> Option<String> {
    build_state_json(ctx)
}

/// 导入密钥状态 JSON。
pub fn import_state(ctx: &mut CoreContext, json: &str) -> bool {
    apply_state_json(ctx, json)
}

// ===== 本地状态加解密 =====

/// 用设备 UUID 派生的本地状态密钥加密明文。
fn encrypt_state_text(device_uuid: &str, plaintext: &str) -> Option<String> {
    let key = hkdf::derive_local_state_key(device_uuid);
    aes::encrypt(&key, plaintext.as_bytes()).ok()
}

/// 用设备 UUID 派生的本地状态密钥解密密文。
fn decrypt_state_text(device_uuid: &str, encrypted_b64: &str) -> Option<String> {
    let key = hkdf::derive_local_state_key(device_uuid);
    aes::decrypt(&key, encrypted_b64)
        .ok()
        .map(|plain| String::from_utf8_lossy(&plain).to_string())
}

/// 反序列化成功标记
const DESERIALIZE_OK_JSON: &str = r#"{"ok":true}"#;
/// 反序列化失败标记
const DESERIALIZE_FAIL_JSON: &str = r#"{"ok":false}"#;

/// 加密明文；失败返回 `None`。
pub fn encrypt_local_state(
    _ctx: &mut CoreContext,
    plaintext: &str,
    device_uuid: &str,
) -> Option<String> {
    encrypt_state_text(device_uuid, plaintext)
}

/// 解密密文；失败返回 `None`。
pub fn decrypt_local_state(
    _ctx: &mut CoreContext,
    encrypted_b64: &str,
    device_uuid: &str,
) -> Option<String> {
    decrypt_state_text(device_uuid, encrypted_b64)
}

/// 本地状态序列化聚合入口：导出密钥状态，按 `encrypt` 决定是否加密。
pub fn serialize_local_state(
    ctx: &mut CoreContext,
    device_uuid: &str,
    encrypt: bool,
) -> Option<String> {
    let json = build_state_json(ctx)?;
    if !encrypt {
        return Some(json);
    }
    encrypt_state_text(device_uuid, &json)
}

/// 本地状态反序列化聚合入口：按 `encrypted` 决定是否解密，再导入密钥状态。
///
/// 返回 `{"ok":true}` 或 `{"ok":false}`。
pub fn deserialize_local_state(
    ctx: &mut CoreContext,
    payload: &str,
    device_uuid: &str,
    encrypted: bool,
) -> String {
    let plain = if encrypted {
        match decrypt_state_text(device_uuid, payload) {
            Some(p) => p,
            None => return DESERIALIZE_FAIL_JSON.to_string(),
        }
    } else {
        payload.to_string()
    };
    if !apply_state_json(ctx, &plain) {
        return DESERIALIZE_FAIL_JSON.to_string();
    }
    DESERIALIZE_OK_JSON.to_string()
}
