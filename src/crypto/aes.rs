use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::Engine;
use rand::Rng;

pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<String, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("{:?}", e))?;
    let nonce_bytes: [u8; 12] = rand::thread_rng().gen();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("encrypt failed: {:?}", e))?;
    let mut output = Vec::with_capacity(12 + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(base64::engine::general_purpose::STANDARD.encode(&output))
}

pub fn decrypt(key: &[u8; 32], encrypted_b64: &str) -> Result<Vec<u8>, String> {
    let data = base64::engine::general_purpose::STANDARD
        .decode(encrypted_b64)
        .map_err(|e| format!("base64 decode: {}", e))?;
    if data.len() < 12 {
        return Err("data too short".to_string());
    }
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("{:?}", e))?;
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("decrypt failed: {:?}", e))
}
