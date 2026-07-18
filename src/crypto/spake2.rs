use spake2::{Ed25519Group, Identity, Password, Spake2};
use base64::Engine;

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