use hkdf::Hkdf;
use sha2::Sha256;

pub const PAIRING_CODE_INFO: &[u8] = b"pairing-code-encryption";
pub const SESSION_KEY_INFO: &[u8] = b"NotifyRelay-ECDH-v1";

fn derive_key(ikm: &[u8], info: &[u8], salt: Option<&[u8]>) -> [u8; 32] {
    let default_salt = [0u8; 32];
    let salt = salt.unwrap_or(&default_salt);
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("32 bytes HKDF expand should never fail");
    okm
}

pub fn derive_pairing_key(shared_secret: &[u8]) -> [u8; 32] {
    derive_key(shared_secret, PAIRING_CODE_INFO, None)
}

pub fn derive_session_key(shared_secret: &[u8]) -> [u8; 32] {
    derive_key(shared_secret, SESSION_KEY_INFO, None)
}
