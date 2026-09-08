use base64::Engine;
use spake2::{Ed25519Group, Identity, Password, Spake2};

pub type Spake2ProverSession = Spake2<Ed25519Group>;
pub type Spake2VerifierSession = Spake2<Ed25519Group>;

pub fn generate_prover_session(pin: &str) -> (Spake2ProverSession, String) {
    let (session, pub_msg) = Spake2::<Ed25519Group>::start_a(
        &Password::new(pin.as_bytes()),
        &Identity::new(b"prover"),
        &Identity::new(b"verifier"),
    );
    let b64 = base64::engine::general_purpose::STANDARD.encode(&pub_msg);
    (session, b64)
}

pub fn generate_verifier_session(pin: &str) -> (Spake2VerifierSession, String) {
    let (session, pub_msg) = Spake2::<Ed25519Group>::start_b(
        &Password::new(pin.as_bytes()),
        &Identity::new(b"prover"),
        &Identity::new(b"verifier"),
    );
    let b64 = base64::engine::general_purpose::STANDARD.encode(&pub_msg);
    (session, b64)
}

pub fn prover_complete(
    session: Spake2ProverSession,
    verifier_pub_b64: &str,
) -> Result<Vec<u8>, String> {
    let verifier_pub_bytes = base64::engine::general_purpose::STANDARD
        .decode(verifier_pub_b64)
        .map_err(|e| format!("base64 decode: {}", e))?;
    session
        .finish(&verifier_pub_bytes)
        .map_err(|e| format!("prover finish failed: {:?}", e))
}

pub fn verifier_complete(
    session: Spake2VerifierSession,
    prover_pub_b64: &str,
) -> Result<Vec<u8>, String> {
    let prover_pub_bytes = base64::engine::general_purpose::STANDARD
        .decode(prover_pub_b64)
        .map_err(|e| format!("base64 decode: {}", e))?;
    session
        .finish(&prover_pub_bytes)
        .map_err(|e| format!("verifier finish failed: {:?}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{aes, hkdf};

    const SAMPLE_LT_PUB: &str = "BASE64_LT_PUB_KEY_SAMPLE_VALUE_AAAA";

    /// 验证设计意图：SPAKE2（配对码）协商出的 K_s 两端一致，
    /// 且 lt_pub 经 K_s 加密后绝非明文、对端可用同一 K_s 解密还原。
    #[test]
    fn spake2_ks_symmetric_and_ltpub_encrypted_not_plaintext() {
        let code = "123456";
        let (prover, prover_pub) = generate_prover_session(code);
        let (verifier, verifier_pub) = generate_verifier_session(code);

        let shared_p = prover_complete(prover, &verifier_pub).expect("prover 完成失败");
        let shared_v = verifier_complete(verifier, &prover_pub).expect("verifier 完成失败");
        assert_eq!(shared_p, shared_v, "两端 SPAKE2 共享秘密必须一致");

        let ks_p = hkdf::derive_session_key(&shared_p);
        let ks_v = hkdf::derive_session_key(&shared_v);
        assert_eq!(ks_p, ks_v, "两端派生的会话密钥 K_s 必须一致");

        let enc = aes::encrypt(&ks_v, SAMPLE_LT_PUB.as_bytes()).expect("加密 lt_pub 失败");
        assert_ne!(
            enc, SAMPLE_LT_PUB,
            "PAIRING_RESP/ACCEPT 中的 lt_pub 不得明文传输"
        );
        let dec = aes::decrypt(&ks_p, &enc).expect("解密 lt_pub 失败");
        assert_eq!(dec, SAMPLE_LT_PUB.as_bytes(), "K_s 解密应能还原对端 lt_pub");
    }
}
