//! core 版本号与协议版本绑定。
//!
//! 版本号参与全链路（配对帧 / HANDSHAKE / DATA 帧）校验，并作为 DATA 通道
//! AES-GCM 的 AAD（附加认证数据）参与加密：即便双方公钥与密钥完全一致，
//! 版本不兼容时也无法解密，从而在密码学层面阻断跨版本通信。
//!
//! 兼容规则（标准语义化版本）：仅比较 `major.minor`，`patch` 不参与兼容判定，
//! 便于补丁级修复（如 0.2.0 ↔ 0.2.1）保持互通。

/// 当前 core 版本（取自 Cargo.toml，语义化版本 `major.minor.patch`）
pub const CORE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// 解析版本串的 `(major, minor)`；缺失 minor 视为 0，非法输入返回 None。
pub fn major_minor(version: &str) -> Option<(u32, u32)> {
    let trimmed = version.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut parts = trimmed.split('.');
    let major = parts.next()?.trim().parse::<u32>().ok()?;
    let minor = match parts.next() {
        Some(s) => s.trim().parse::<u32>().ok()?,
        None => 0,
    };
    Some((major, minor))
}

/// 判断对端版本是否与本机兼容（仅比较 major.minor）。
pub fn is_compatible(remote: &str) -> bool {
    match (major_minor(CORE_VERSION), major_minor(remote)) {
        (Some(local), Some(peer)) => local == peer,
        _ => false,
    }
}

/// DATA 通道 AAD：绑定 `major.minor`，patch 差异仍可互通。
///
/// 两端在同一 `major.minor` 下派生出相同的 AAD，因此 AES-GCM 认证通过；
/// 跨 `major.minor` 时 AAD 不同，解密必然失败（GCM 认证标签不匹配）。
pub fn data_aad() -> Vec<u8> {
    let (major, minor) = major_minor(CORE_VERSION).unwrap_or((0, 0));
    format!("NotifyRelay-Data-v{}.{}", major, minor).into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_version_is_semver() {
        assert!(major_minor(CORE_VERSION).is_some());
        assert_eq!(major_minor(CORE_VERSION), Some((0, 2)));
    }

    #[test]
    fn patch_difference_is_compatible() {
        let (major, minor) = major_minor(CORE_VERSION).unwrap();
        assert!(is_compatible(&format!("{}.{}.99", major, minor)));
        assert!(is_compatible(&format!("{}.{}", major, minor)));
    }

    #[test]
    fn major_or_minor_difference_is_incompatible() {
        let (major, minor) = major_minor(CORE_VERSION).unwrap();
        assert!(!is_compatible(&format!("{}.{}", major + 1, minor)));
        assert!(!is_compatible(&format!("{}.{}", major, minor + 1)));
    }

    #[test]
    fn invalid_version_is_incompatible() {
        assert!(!is_compatible(""));
        assert!(!is_compatible("abc"));
        assert!(!is_compatible("1.x.0"));
    }

    #[test]
    fn aad_only_binds_major_minor() {
        let (major, minor) = major_minor(CORE_VERSION).unwrap();
        let expected = format!("NotifyRelay-Data-v{}.{}", major, minor);
        assert_eq!(String::from_utf8(data_aad()).unwrap(), expected);
    }
}
