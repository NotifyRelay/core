//! 无状态工具、入站解析与应用同步的委托实现（顶层函数，无上下文）。

use super::conv::{cs, take_cstr, take_cstr_or_empty};

/// 计算「岛」的特征 ID。
#[uniffi::export]
pub fn compute_feature_id(
    super_pkg: String,
    param_v2_raw: String,
    title: String,
    text: String,
    instance_id: String,
) -> String {
    let a = cs(&super_pkg);
    let b = cs(&param_v2_raw);
    let c = cs(&title);
    let d = cs(&text);
    let e = cs(&instance_id);
    unsafe {
        take_cstr_or_empty(crate::ffi::utils::nrc_compute_feature_id(
            a.as_ptr(),
            b.as_ptr(),
            c.as_ptr(),
            d.as_ptr(),
            e.as_ptr(),
        ))
    }
}

/// 相似度是否达到去重阈值。
#[uniffi::export]
pub fn should_deduplicate(
    new_title: String,
    new_text: String,
    old_title: String,
    old_text: String,
) -> bool {
    let a = cs(&new_title);
    let b = cs(&new_text);
    let c = cs(&old_title);
    let d = cs(&old_text);
    unsafe {
        crate::ffi::utils::nrc_should_deduplicate(a.as_ptr(), b.as_ptr(), c.as_ptr(), d.as_ptr())
            != 0
    }
}

/// 由共享密钥派生 FTP 凭据。
#[uniffi::export]
pub fn derive_ftp_credentials(shared_secret_b64: String) -> String {
    let s = cs(&shared_secret_b64);
    unsafe { take_cstr_or_empty(crate::ffi::utils::nrc_derive_ftp_credentials(s.as_ptr())) }
}

/// 计算密码哈希。
#[uniffi::export]
pub fn derive_password_hash(password: String) -> String {
    let p = cs(&password);
    unsafe { take_cstr_or_empty(crate::ffi::utils::nrc_derive_password_hash(p.as_ptr())) }
}

/// 生成 12 位随机密码。
#[uniffi::export]
pub fn generate_random_password() -> String {
    unsafe { take_cstr_or_empty(crate::ffi::utils::nrc_generate_random_password()) }
}

/// 本机局域网 IP；无可用接口时返回空串。
#[uniffi::export]
pub fn get_local_ip() -> String {
    unsafe { take_cstr_or_empty(crate::ffi::utils::nrc_get_local_ip()) }
}

/// 解析超级岛入站报文，返回归一结构 JSON。
#[uniffi::export]
pub fn parse_superisland_inbound(device_uuid: String, pkg: String, full_json: String) -> String {
    let u = cs(&device_uuid);
    let p = cs(&pkg);
    let f = cs(&full_json);
    unsafe {
        take_cstr_or_empty(crate::ffi::state_merge::nrc_parse_superisland_inbound(
            u.as_ptr(),
            p.as_ptr(),
            f.as_ptr(),
        ))
    }
}

/// 解析通知入站报文。
#[uniffi::export]
pub fn parse_notification_inbound(full_json: String) -> String {
    let f = cs(&full_json);
    unsafe {
        take_cstr_or_empty(crate::ffi::state_merge::nrc_parse_notification_inbound(
            f.as_ptr(),
        ))
    }
}

/// 解析媒体入站报文。
#[uniffi::export]
pub fn parse_media_inbound(full_json: String) -> String {
    let f = cs(&full_json);
    unsafe { take_cstr_or_empty(crate::ffi::state_merge::nrc_parse_media_inbound(f.as_ptr())) }
}

/// 解析图标响应报文。
#[uniffi::export]
pub fn app_sync_parse_icon_response(payload_json: String) -> Option<String> {
    let p = cs(&payload_json);
    unsafe {
        take_cstr(crate::ffi::app_sync::nrc_app_sync_parse_icon_response(
            p.as_ptr(),
        ))
    }
}

/// 构造应用列表请求报文。
#[uniffi::export]
pub fn app_sync_build_applist_request(scope: String, now_ms: i64) -> Option<String> {
    let s = cs(&scope);
    unsafe {
        take_cstr(crate::ffi::app_sync::nrc_app_sync_build_applist_request(
            s.as_ptr(),
            now_ms,
        ))
    }
}

/// 解析应用列表响应报文。
#[uniffi::export]
pub fn app_sync_parse_applist_response(payload_json: String) -> Option<String> {
    let p = cs(&payload_json);
    unsafe {
        take_cstr(crate::ffi::app_sync::nrc_app_sync_parse_applist_response(
            p.as_ptr(),
        ))
    }
}
