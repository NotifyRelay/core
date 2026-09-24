use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use base64::Engine;
use rand::Rng;

/// 无附加认证数据（AAD）加密：仅用于本地持久化/本地状态等非跨端通道。
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<String, String> {
    encrypt_with_aad(key, plaintext, &[])
}

/// 带附加认证数据（AAD）加密：AAD 参与 GCM 认证标签计算，
/// 两端 AAD 不一致时解密必然失败（用于绑定 core 协议版本）。
pub fn encrypt_with_aad(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<String, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("{:?}", e))?;
    let nonce_bytes: [u8; 12] = rand::thread_rng().gen();
    let nonce = Nonce::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| format!("encrypt failed: {:?}", e))?;
    let mut output = Vec::with_capacity(12 + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(base64::engine::general_purpose::STANDARD.encode(&output))
}

/// 无附加认证数据（AAD）解密：与 [`encrypt`] 对称。
pub fn decrypt(key: &[u8; 32], encrypted_b64: &str) -> Result<Vec<u8>, String> {
    decrypt_with_aad(key, encrypted_b64, &[])
}

/// 带附加认证数据（AAD）解密：AAD 不匹配时 GCM 认证失败，返回 Err。
pub fn decrypt_with_aad(
    key: &[u8; 32],
    encrypted_b64: &str,
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let data = base64::engine::general_purpose::STANDARD
        .decode(encrypted_b64)
        .map_err(|e| format!("base64 decode: {}", e))?;
    if data.len() < 12 {
        return Err("data too short".to_string());
    }
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce_arr: [u8; 12] = nonce_bytes
        .try_into()
        .map_err(|_| "nonce length mismatch".to_string())?;
    let nonce = Nonce::from(nonce_arr);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("{:?}", e))?;
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|e| format!("decrypt failed: {:?}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [9u8; 32];

    #[test]
    fn aad_roundtrip_with_matching_aad() {
        let enc = encrypt_with_aad(&KEY, b"hello", b"aad-v0.2").unwrap();
        let dec = decrypt_with_aad(&KEY, &enc, b"aad-v0.2").unwrap();
        assert_eq!(dec, b"hello");
    }

    #[test]
    fn mismatched_aad_fails_decryption() {
        let enc = encrypt_with_aad(&KEY, b"hello", b"aad-v0.2").unwrap();
        // AAD 不同 → GCM 认证失败，即便密钥完全一致
        assert!(decrypt_with_aad(&KEY, &enc, b"aad-v0.3").is_err());
        // 无 AAD 解密同样失败（AAD 已绑定进标签）
        assert!(decrypt(&KEY, &enc).is_err());
    }

    #[test]
    fn aad_encrypted_payload_is_not_plaintext() {
        let enc = encrypt_with_aad(&KEY, b"secret", b"aad").unwrap();
        assert_ne!(enc, "secret");
    }
}
