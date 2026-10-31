//! 由既有长期密钥派生 QUIC/TLS 所需的自签证书。
//!
//! 设计约束：
//! - **不得引入新的身份根**：证书由 `local_private_key_pem`（P-256 长期私钥）派生，
//!   历史配对无需重新建立。
//! - **身份绑定值必须是确定性的**：ECDSA 签名本身随机（同一输入每次签名不同），
//!   因此证书 DER 每次派生都不同；绑定值改用**长期公钥的 SHA-256**，
//!   它只取决于私钥，可稳定复现，也直接对应设备身份。
//! - 私钥不出进程：只把 DER 交给 rustls，不落盘。

use p256::pkcs8::EncodePrivateKey;
use p256::{EncodedPoint, SecretKey};
use rcgen::{CertificateParams, DnType, KeyPair, SanType};
use sha2::{Digest, Sha256};

/// 派生出的证书材料。
pub struct DerivedCert {
    /// 证书 DER（交给 rustls 的 `CertificateDer`）
    pub cert_der: Vec<u8>,
    /// 私钥 DER（PKCS#8，交给 rustls 的 `PrivateKeyDer`）
    pub key_der: Vec<u8>,
    /// 长期公钥 SHA-256（小写 hex）：确定性身份绑定值
    pub fingerprint: String,
}

/// 由长期 P-256 私钥派生自签证书。
///
/// `device_uuid` 进入证书 CN 与 SAN，使证书文本可读；
/// 但**绑定值只取长期公钥哈希**，与 uuid、签名随机性均无关。
pub fn derive_cert(secret: &SecretKey, device_uuid: &str) -> Result<DerivedCert, String> {
    // 1. 身份绑定值：长期公钥的 SHA-256（确定性，可复现）
    let public = secret.public_key();
    let encoded = EncodedPoint::from(public);
    let fingerprint = Sha256::digest(encoded.as_bytes())
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    // 2. 把 P-256 私钥转成 PKCS#8 DER，供 rcgen 复用（不生成新密钥）
    let key_der = secret
        .to_pkcs8_der()
        .map_err(|e| format!("导出 PKCS#8 私钥失败: {:?}", e))?
        .as_bytes()
        .to_vec();

    let pkcs8 = rustls_pki_types::PrivatePkcs8KeyDer::from(key_der.clone());
    let key_pair = KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| format!("rcgen 载入私钥失败: {:?}", e))?;

    // 3. 证书参数：主体名与 SAN 携带设备标识，便于对端在握手期核对
    let san_name = format!("{}.milink.local", sanitize(device_uuid));
    let mut params = CertificateParams::new(vec![san_name.clone()])
        .map_err(|e| format!("构造证书参数失败: {:?}", e))?;
    params
        .distinguished_name
        .push(DnType::CommonName, format!("notifyrelay:{device_uuid}"));
    params.subject_alt_names.push(SanType::DnsName(
        san_name
            .try_into()
            .map_err(|_| "SAN 名称非法".to_string())?,
    ));

    // 4. 自签
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| format!("自签证书失败: {:?}", e))?;

    Ok(DerivedCert {
        cert_der: cert.der().to_vec(),
        key_der,
        fingerprint,
    })
}

/// 设备 uuid 可能含非法 DNS 字符，仅保留字母数字，其余替换为连字符。
fn sanitize(uuid: &str) -> String {
    let cleaned: String = uuid
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    if cleaned.is_empty() {
        "device".to_string()
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ecdh;
    use base64::Engine as _;

    /// 同一私钥必须得到同一身份绑定值（历史密钥可复用的前提）。
    #[test]
    fn same_key_yields_same_fingerprint() {
        let (secret, _pub_b64) = ecdh::generate_keypair();
        let a = derive_cert(&secret, "device-1").expect("派生证书");
        let b = derive_cert(&secret, "device-1").expect("派生证书");
        assert_eq!(a.fingerprint, b.fingerprint, "同私钥绑定值必须稳定");
        assert_eq!(a.fingerprint.len(), 64, "SHA-256 指纹应为 64 位 hex");
    }

    /// PEM 往返后仍得到同一绑定值（模拟「历史库读出的私钥」路径）。
    #[test]
    fn pem_roundtrip_keeps_identity() {
        let (secret, _) = ecdh::generate_keypair();
        let pem = ecdh::secret_to_pem(&secret).expect("导出 PEM");
        let restored = ecdh::secret_from_pem(&pem).expect("导入 PEM");
        let a = derive_cert(&secret, "device-1").expect("派生证书");
        let b = derive_cert(&restored, "device-1").expect("派生证书");
        assert_eq!(a.fingerprint, b.fingerprint, "PEM 往返后身份不得变化");
    }

    /// 绑定值等于长期公钥哈希，与 uuid 无关（uuid 只影响证书文本）。
    #[test]
    fn fingerprint_matches_public_key_hash() {
        let (secret, pub_b64) = ecdh::generate_keypair();
        let derived = derive_cert(&secret, "device-1").expect("派生证书");
        let expected = Sha256::digest(
            base64::engine::general_purpose::STANDARD
                .decode(&pub_b64)
                .expect("解码公钥"),
        )
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
        assert_eq!(derived.fingerprint, expected);
        let other = derive_cert(&secret, "device-2").expect("派生证书");
        assert_eq!(
            derived.fingerprint, other.fingerprint,
            "uuid 不参与绑定值计算"
        );
    }

    /// 不同私钥必须产生不同绑定值。
    #[test]
    fn different_key_changes_fingerprint() {
        let (a_key, _) = ecdh::generate_keypair();
        let (b_key, _) = ecdh::generate_keypair();
        let a = derive_cert(&a_key, "device-1").expect("派生证书");
        let b = derive_cert(&b_key, "device-1").expect("派生证书");
        assert_ne!(a.fingerprint, b.fingerprint);
    }
}
