use base64::Engine;
use p256::{ecdh::diffie_hellman, EncodedPoint, PublicKey, SecretKey};
use rand::rngs::OsRng;

pub fn generate_keypair() -> (SecretKey, String) {
    let secret = SecretKey::random(&mut OsRng);
    let public = secret.public_key();
    let encoded = EncodedPoint::from(public);
    let b64 = base64::engine::general_purpose::STANDARD.encode(encoded.as_bytes());
    (secret, b64)
}

pub fn secret_from_pem(pem: &str) -> Result<SecretKey, String> {
    SecretKey::from_sec1_pem(pem).map_err(|e| format!("{:?}", e))
}

pub fn secret_to_pem(key: &SecretKey) -> Result<String, String> {
    key.to_sec1_pem(Default::default())
        .map_err(|e| format!("{:?}", e))
        .map(|z| z.to_string())
}

pub fn compute_shared_secret(private: &SecretKey, peer_pub_b64: &str) -> Result<Vec<u8>, String> {
    let peer_bytes = base64::engine::general_purpose::STANDARD
        .decode(peer_pub_b64)
        .map_err(|e| format!("base64 decode: {}", e))?;
    let peer_pub = PublicKey::from_sec1_bytes(&peer_bytes)
        .map_err(|e| format!("invalid public key: {:?}", e))?;
    let shared = diffie_hellman(private.to_nonzero_scalar(), peer_pub.as_affine());
    Ok(shared.raw_secret_bytes().to_vec())
}
