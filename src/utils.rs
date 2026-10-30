//! 无状态工具函数。
//!
//! 特征 ID 推导、文本相似度、FTP 凭据派生、密码哈希与随机密码、本机 IP、设备名编码。

use base64::Engine;
use sha2::Digest;

/// 计算「岛」的特征 ID（与平台侧实现对齐）。
///
/// 优先取 `param` 内的 `chatInfo.title` / `baseInfo.title|content` / `highlightInfo.title`；
/// 均不可用时回落到标题与正文；`instance_id` 非空时追加。
pub fn compute_feature_id(pkg: &str, param: &str, title: &str, text: &str, iid: &str) -> String {
    let mut key_parts: Vec<String> = Vec::new();
    key_parts.push(pkg.to_string());
    if !param.is_empty() {
        if let Ok(root) = serde_json::from_str::<serde_json::Value>(param) {
            if let Some(chat_info) = root.get("chatInfo").and_then(|v| v.as_object()) {
                if let Some(title_val) = chat_info.get("title").and_then(|v| v.as_str()) {
                    if !title_val.is_empty() {
                        key_parts.push(format!("chat:{}", title_val));
                    }
                }
            } else if let Some(base_info) = root.get("baseInfo").and_then(|v| v.as_object()) {
                let bt = base_info
                    .get("title")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let bc = base_info
                    .get("content")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if !bt.is_empty() {
                    key_parts.push(format!("baseT:{}", bt));
                }
                if !bc.is_empty() {
                    key_parts.push(format!("baseC:{}", bc));
                }
            } else if let Some(highlight) = root.get("highlightInfo").and_then(|v| v.as_object()) {
                if let Some(ht) = highlight.get("title").and_then(|v| v.as_str()) {
                    if !ht.is_empty() {
                        key_parts.push(format!("hi:{}", ht));
                    }
                }
            }
        }
    }
    if key_parts.len() <= 1 {
        if !title.is_empty() {
            key_parts.push(format!("t:{}", title));
        }
        if !text.is_empty() {
            key_parts.push(format!("c:{}", text));
        }
    }
    if !iid.is_empty() {
        key_parts.push(format!("id:{}", iid));
    }
    let raw = key_parts.join("|");
    let hash = sha1::Sha1::digest(raw.as_bytes());
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

/// 单段文本相似度（0.0 ~ 1.0）。
fn text_similarity(a: &str, b: &str) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let a_lower = a.trim().to_lowercase();
    let b_lower = b.trim().to_lowercase();
    if a_lower == b_lower {
        return 1.0;
    }
    if a_lower.contains(&b_lower) || b_lower.contains(&a_lower) {
        return 0.9;
    }
    strsim::sorensen_dice(&a_lower, &b_lower)
}

/// 标题与正文的合并相似度：一侧为空时只比较另一侧。
fn combined_similarity(new_title: &str, new_text: &str, old_title: &str, old_text: &str) -> f64 {
    let title_empty = new_title.is_empty() && old_title.is_empty();
    let text_empty = new_text.is_empty() && old_text.is_empty();
    if title_empty && text_empty {
        return 1.0;
    }
    if title_empty {
        return text_similarity(new_text, old_text);
    }
    if text_empty {
        return text_similarity(new_title, old_title);
    }
    let title_sim = text_similarity(new_title, old_title);
    let text_sim = text_similarity(new_text, old_text);
    (title_sim + text_sim) / 2.0
}

/// 应用名是否指向同一应用：归一化后相等或互相包含。
///
/// 两侧均为空时视为同一应用。
pub fn same_app(new_app_name: &str, old_app_name: &str) -> bool {
    let a = new_app_name.trim().to_lowercase();
    let b = old_app_name.trim().to_lowercase();
    if a.is_empty() && b.is_empty() {
        return true;
    }
    if a.is_empty() || b.is_empty() {
        return false;
    }
    a == b || a.contains(&b) || b.contains(&a)
}

/// 相似度是否达到去重阈值（0.8）：应用名须指向同一应用，标题与正文按加权相似度判定。
pub fn should_deduplicate(
    new_app_name: &str,
    new_title: &str,
    new_text: &str,
    old_app_name: &str,
    old_title: &str,
    old_text: &str,
) -> bool {
    if !same_app(new_app_name, old_app_name) {
        return false;
    }
    combined_similarity(new_title, new_text, old_title, old_text) >= 0.8
}

/// 由共享密钥派生 FTP 凭据，返回 `{"username":..,"password":..}` JSON。
pub fn derive_ftp_credentials(shared_secret_b64: &str) -> String {
    use sha2::{Digest, Sha256};
    let secret_bytes = match base64::engine::general_purpose::STANDARD.decode(shared_secret_b64) {
        Ok(b) => b,
        Err(_) => return r#"{"username":"","password":""}"#.to_string(),
    };
    let derived = Sha256::digest(&secret_bytes);
    let username_bytes = &derived[..8];
    let username = base64::engine::general_purpose::STANDARD
        .encode(username_bytes)
        .replace('+', "-")
        .replace('/', "_")
        .replace('=', "");
    let username: String = username
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    let username = format!("ftp_{}", &username[..username.len().min(16)]);
    let password_bytes = &derived[..32];
    let password = base64::engine::general_purpose::STANDARD
        .encode(password_bytes)
        .replace('+', "-")
        .replace('/', "_")
        .replace('=', "");
    let password: String = password
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    serde_json::json!({"username": username, "password": password}).to_string()
}

/// 密码哈希（MD5 的 base64）。
pub fn derive_password_hash(password: &str) -> String {
    let hash = md5::compute(password.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(hash.0)
}

/// 生成 12 位随机密码。
pub fn generate_random_password() -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    let mut rng = rand::thread_rng();
    (0..12)
        .map(|_| {
            let idx = rng.gen_range(0..CHARS.len());
            CHARS[idx] as char
        })
        .collect()
}

/// 本机局域网 IP；无可用接口时返回空串。
pub fn get_local_ip() -> String {
    local_ip_address::local_ip()
        .ok()
        .map(|ip| ip.to_string())
        .unwrap_or_default()
}

/// 设备名 base64 编码（发现/心跳通道统一使用）。
pub fn encode_name_b64(name: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_feature_id_with_instance_id() {
        let s = compute_feature_id("com.test.app", "", "Hello", "World", "inst-123");
        assert!(!s.is_empty());
        assert_eq!(s.len(), 40);
    }

    #[test]
    fn test_compute_feature_id_chat_info() {
        let s = compute_feature_id(
            "com.test.app",
            r#"{"chatInfo":{"title":"MyChat"}}"#,
            "",
            "",
            "",
        );
        assert_eq!(s.len(), 40);
    }

    #[test]
    fn test_compute_feature_id_base_info() {
        let s = compute_feature_id(
            "com.test.app",
            r#"{"baseInfo":{"title":"BaseT","content":"BaseC"}}"#,
            "",
            "",
            "",
        );
        assert_eq!(s.len(), 40);
    }

    #[test]
    fn test_compute_feature_id_highlight_info() {
        let s = compute_feature_id(
            "com.test.app",
            r#"{"highlightInfo":{"title":"Highlight"}}"#,
            "",
            "",
            "",
        );
        assert_eq!(s.len(), 40);
    }

    #[test]
    fn test_should_deduplicate() {
        assert!(should_deduplicate(
            "QQ", "Hello", "World", "QQ", "Hello", "World"
        ));
        assert!(!should_deduplicate(
            "QQ",
            "Completely different title",
            "Completely different text body that is very long",
            "QQ",
            "Something else entirely",
            "Another message that shares no words with the other",
        ));
    }

    #[test]
    fn test_should_deduplicate_requires_same_app() {
        assert!(!should_deduplicate(
            "QQ", "Hello", "World", "WeChat", "Hello", "World"
        ));
    }

    #[test]
    fn test_same_app_normalizes_and_accepts_containment() {
        assert!(same_app("QQ", "qq"));
        assert!(same_app("  QQ  ", "QQ"));
        assert!(same_app("QQ", "QQ音乐"));
        assert!(same_app("", ""));
        assert!(!same_app("", "QQ"));
        assert!(!same_app("QQ", "WeChat"));
    }

    #[test]
    fn test_should_deduplicate_accepts_subset_text() {
        // 一方为另一方的子集时按 0.9 计，超过阈值
        assert!(should_deduplicate(
            "QQ",
            "张三",
            "在吗",
            "QQ",
            "张三",
            "在吗？我刚看到你的消息"
        ));
    }

    #[test]
    fn test_derive_ftp_credentials() {
        let s = derive_ftp_credentials("dGVzdHNlY3JldA==");
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(v["username"].as_str().unwrap().starts_with("ftp_"));
        assert!(!v["password"].as_str().unwrap().is_empty());
    }

    #[test]
    fn test_derive_password_hash() {
        assert!(!derive_password_hash("mypassword").is_empty());
    }

    #[test]
    fn test_generate_random_password() {
        assert_eq!(generate_random_password().len(), 12);
    }
}
