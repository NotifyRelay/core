use std::net::UdpSocket;
use std::os::raw::c_char;
use std::os::raw::c_void;

use sha2::Digest;

use super::common::{from_cstr, to_cstr};

#[no_mangle]
pub extern "C" fn nrc_compute_dedup_key(
    device_uuid: *const c_char,
    data: *const c_char,
) -> *mut c_char {
    let uuid = unsafe { from_cstr(device_uuid) };
    let d = unsafe { from_cstr(data) };
    let input = format!("{}|{}", uuid, d);
    let hash = sha2::Sha256::digest(input.as_bytes());
    let hex = hash
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    to_cstr(&hex)
}

#[no_mangle]
pub extern "C" fn nrc_compute_feature_id(
    super_pkg: *const c_char,
    param_v2_raw: *const c_char,
    title: *const c_char,
    text: *const c_char,
    instance_id: *const c_char,
) -> *mut c_char {
    let pkg = unsafe { from_cstr(super_pkg) };
    let param = unsafe { from_cstr(param_v2_raw) };
    let t = unsafe { from_cstr(title) };
    let tx = unsafe { from_cstr(text) };
    let iid = unsafe { from_cstr(instance_id) };
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
        if !t.is_empty() {
            key_parts.push(format!("t:{}", t));
        }
        if !tx.is_empty() {
            key_parts.push(format!("c:{}", tx));
        }
    }
    if !iid.is_empty() {
        key_parts.push(format!("id:{}", iid));
    }
    let raw = key_parts.join("|");
    let hash = sha1::Sha1::digest(raw.as_bytes());
    let hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
    to_cstr(&hex)
}

#[no_mangle]
pub extern "C" fn nrc_compute_feature_id_simple(
    package_name: *const c_char,
    title: *const c_char,
    text: *const c_char,
) -> *mut c_char {
    let pkg = unsafe { from_cstr(package_name) };
    let t = unsafe { from_cstr(title) };
    let tx = unsafe { from_cstr(text) };
    let mut parts: Vec<&str> = Vec::new();
    if !pkg.is_empty() {
        parts.push(pkg);
    }
    if !t.is_empty() {
        parts.push(t);
    }
    if !tx.is_empty() {
        parts.push(tx);
    }
    let feature = parts.join("|");
    to_cstr(&feature)
}

/// 统一去重接口
/// action: 0=check_and_pend, 1=mark_sent, 2=clear_pending, 3=cleanup
/// action=0 时返回 1=应发送, 0=重复
/// action=1/2/3 时返回 0=成功, -1=失败
#[no_mangle]
pub extern "C" fn nrc_dedup(
    ctx_ptr: *mut c_void,
    action: i32,
    dedup_key: *const c_char,
    arg1_ms: i64,
    arg2_ms: i64,
) -> i32 {
    if ctx_ptr.is_null() {
        return -1;
    }
    let key = if !dedup_key.is_null() {
        unsafe { from_cstr(dedup_key) }
    } else {
        ""
    };
    let ctx = unsafe { &mut *(ctx_ptr as *mut crate::SafeContext) };
    let mut guard = match ctx.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };

    match action {
        0 => {
            if key.is_empty() {
                return 0;
            }
            if guard.dedup.check_and_pend(key, arg1_ms) {
                1
            } else {
                0
            }
        }
        1 => {
            if !key.is_empty() {
                guard.dedup.mark_sent(key);
            }
            0
        }
        2 => {
            if !key.is_empty() {
                guard.dedup.clear_pending(key);
            }
            0
        }
        3 => {
            guard.dedup.cleanup(arg1_ms, arg2_ms);
            0
        }
        _ => -1,
    }
}

use base64::Engine;

fn text_similarity_impl(a: &str, b: &str) -> f64 {
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
    let set_a: std::collections::HashSet<char> = a_lower.chars().collect();
    let set_b: std::collections::HashSet<char> = b_lower.chars().collect();
    if set_a.is_empty() && set_b.is_empty() {
        return 1.0;
    }
    let intersection = set_a.intersection(&set_b).count();
    let union = set_a.union(&set_b).count();
    let jaccard = if union > 0 {
        intersection as f64 / union as f64
    } else {
        0.0
    };
    let len_ratio =
        a_lower.len().min(b_lower.len()) as f64 / a_lower.len().max(b_lower.len()) as f64;
    jaccard * 0.7 + len_ratio * 0.3
}

fn combined_similarity_impl(
    new_title: &str,
    new_text: &str,
    old_title: &str,
    old_text: &str,
) -> f64 {
    let title_empty = new_title.is_empty() && old_title.is_empty();
    let text_empty = new_text.is_empty() && old_text.is_empty();
    if title_empty && text_empty {
        return 1.0;
    }
    if title_empty {
        return text_similarity_impl(new_text, old_text);
    }
    if text_empty {
        return text_similarity_impl(new_title, old_title);
    }
    let title_sim = text_similarity_impl(new_title, old_title);
    let text_sim = text_similarity_impl(new_text, old_text);
    (title_sim + text_sim) / 2.0
}

#[no_mangle]
pub extern "C" fn nrc_text_similarity(a: *const c_char, b: *const c_char) -> f64 {
    let a_str = unsafe { from_cstr(a) };
    let b_str = unsafe { from_cstr(b) };
    text_similarity_impl(a_str, b_str)
}

#[no_mangle]
pub extern "C" fn nrc_should_deduplicate(
    new_title: *const c_char,
    new_text: *const c_char,
    old_title: *const c_char,
    old_text: *const c_char,
) -> i32 {
    let nt = unsafe { from_cstr(new_title) };
    let ntx = unsafe { from_cstr(new_text) };
    let ot = unsafe { from_cstr(old_title) };
    let otx = unsafe { from_cstr(old_text) };
    let sim = combined_similarity_impl(nt, ntx, ot, otx);
    if sim >= 0.8 {
        1
    } else {
        0
    }
}

fn derive_ftp_credentials_impl(shared_secret_b64: &str) -> String {
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

#[no_mangle]
pub extern "C" fn nrc_derive_ftp_credentials(shared_secret_b64: *const c_char) -> *mut c_char {
    let secret = unsafe { from_cstr(shared_secret_b64) };
    let result = derive_ftp_credentials_impl(secret);
    to_cstr(&result)
}

#[no_mangle]
pub extern "C" fn nrc_derive_password_hash(password: *const c_char) -> *mut c_char {
    let pw = unsafe { from_cstr(password) };
    let hash = md5::compute(pw.as_bytes());
    let b64 = base64::engine::general_purpose::STANDARD.encode(hash.0);
    to_cstr(&b64)
}

#[no_mangle]
pub extern "C" fn nrc_generate_random_password() -> *mut c_char {
    use rand::Rng;
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    let mut rng = rand::thread_rng();
    let password: String = (0..12)
        .map(|_| {
            let idx = rng.gen_range(0..CHARS.len());
            CHARS[idx] as char
        })
        .collect();
    to_cstr(&password)
}

/// 获取本机局域网 IP 地址
/// 通过 UDP 连接到外部地址来确定实际出站接口
#[no_mangle]
pub extern "C" fn nrc_get_local_ip() -> *mut c_char {
    let ip = get_local_ip_impl().unwrap_or_default();
    to_cstr(&ip)
}

pub(crate) fn get_local_ip_impl() -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    // 连接 Google DNS 以确定本地接口，不实际发送数据
    socket.connect("8.8.8.8:53").ok()?;
    let local_addr = socket.local_addr().ok()?;
    Some(local_addr.ip().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_feature_id_with_instance_id() {
        let pkg = to_cstr("com.test.app");
        let param = to_cstr("");
        let title = to_cstr("Hello");
        let text = to_cstr("World");
        let iid = to_cstr("inst-123");
        let result = unsafe { nrc_compute_feature_id(pkg, param, title, text, iid) };
        let s = unsafe { from_cstr(result).to_string() };
        assert!(!s.is_empty());
        assert_eq!(s.len(), 40);
    }

    #[test]
    fn test_compute_feature_id_chat_info() {
        let pkg = to_cstr("com.test.app");
        let param = to_cstr(r#"{"chatInfo":{"title":"MyChat"}}"#);
        let title = to_cstr("");
        let text = to_cstr("");
        let iid = to_cstr("");
        let result = unsafe { nrc_compute_feature_id(pkg, param, title, text, iid) };
        let s = unsafe { from_cstr(result).to_string() };
        assert_eq!(s.len(), 40);
    }

    #[test]
    fn test_compute_feature_id_base_info() {
        let pkg = to_cstr("com.test.app");
        let param = to_cstr(r#"{"baseInfo":{"title":"BaseT","content":"BaseC"}}"#);
        let title = to_cstr("");
        let text = to_cstr("");
        let iid = to_cstr("");
        let result = unsafe { nrc_compute_feature_id(pkg, param, title, text, iid) };
        let s = unsafe { from_cstr(result).to_string() };
        assert_eq!(s.len(), 40);
    }

    #[test]
    fn test_compute_feature_id_highlight_info() {
        let pkg = to_cstr("com.test.app");
        let param = to_cstr(r#"{"highlightInfo":{"title":"Highlight"}}"#);
        let title = to_cstr("");
        let text = to_cstr("");
        let iid = to_cstr("");
        let result = unsafe { nrc_compute_feature_id(pkg, param, title, text, iid) };
        let s = unsafe { from_cstr(result).to_string() };
        assert_eq!(s.len(), 40);
    }

    #[test]
    fn test_text_similarity() {
        let a = to_cstr("hello world");
        let b = to_cstr("hello world");
        let result = unsafe { nrc_text_similarity(a, b) };
        assert_eq!(result, 1.0);

        let c = to_cstr("hello");
        let d = to_cstr("world");
        let result2 = unsafe { nrc_text_similarity(c, d) };
        assert!(result2 < 1.0);
    }

    #[test]
    fn test_should_deduplicate() {
        let nt = to_cstr("Hello");
        let ntx = to_cstr("World");
        let ot = to_cstr("Hello");
        let otx = to_cstr("World");
        let result = unsafe { nrc_should_deduplicate(nt, ntx, ot, otx) };
        assert_eq!(result, 1);

        let nt2 = to_cstr("Completely different title");
        let ntx2 = to_cstr("Completely different text body that is very long");
        let ot2 = to_cstr("Something else entirely");
        let otx2 = to_cstr("Another message that shares no words with the other");
        let result2 = unsafe { nrc_should_deduplicate(nt2, ntx2, ot2, otx2) };
        assert_eq!(result2, 0);
    }

    #[test]
    fn test_derive_ftp_credentials() {
        let secret = to_cstr("dGVzdHNlY3JldA==");
        let result = unsafe { nrc_derive_ftp_credentials(secret) };
        let s = unsafe { from_cstr(result).to_string() };
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(v["username"].as_str().unwrap().starts_with("ftp_"));
        assert!(!v["password"].as_str().unwrap().is_empty());
    }

    #[test]
    fn test_derive_password_hash() {
        let pw = to_cstr("mypassword");
        let result = unsafe { nrc_derive_password_hash(pw) };
        let s = unsafe { from_cstr(result).to_string() };
        assert!(!s.is_empty());
    }

    #[test]
    fn test_generate_random_password() {
        let result = unsafe { nrc_generate_random_password() };
        let s = unsafe { from_cstr(result).to_string() };
        assert_eq!(s.len(), 12);
    }
}
