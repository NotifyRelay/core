//! 无状态工具、入站解析与应用同步的导出实现（顶层函数，无上下文）。

/// 计算「岛」的特征 ID。
#[uniffi::export]
pub fn compute_feature_id(
    super_pkg: String,
    param_v2_raw: String,
    title: String,
    text: String,
    instance_id: String,
) -> String {
    crate::utils::compute_feature_id(&super_pkg, &param_v2_raw, &title, &text, &instance_id)
}

/// 相似度是否达到去重阈值：应用名须指向同一应用。
#[uniffi::export]
pub fn should_deduplicate(
    new_app_name: String,
    new_title: String,
    new_text: String,
    old_app_name: String,
    old_title: String,
    old_text: String,
) -> bool {
    crate::utils::should_deduplicate(
        &new_app_name,
        &new_title,
        &new_text,
        &old_app_name,
        &old_title,
        &old_text,
    )
}

/// 由共享密钥派生 FTP 凭据。
#[uniffi::export]
pub fn derive_ftp_credentials(shared_secret_b64: String) -> String {
    crate::utils::derive_ftp_credentials(&shared_secret_b64)
}

/// 计算密码哈希。
#[uniffi::export]
pub fn derive_password_hash(password: String) -> String {
    crate::utils::derive_password_hash(&password)
}

/// 生成 12 位随机密码。
#[uniffi::export]
pub fn generate_random_password() -> String {
    crate::utils::generate_random_password()
}

/// 本机局域网 IP；无可用接口时返回空串。
#[uniffi::export]
pub fn get_local_ip() -> String {
    crate::utils::get_local_ip()
}

/// 解析超级岛入站报文，返回归一结构 JSON。
#[uniffi::export]
pub fn parse_superisland_inbound(device_uuid: String, pkg: String, full_json: String) -> String {
    crate::state_merge::parse_superisland_inbound_json(&device_uuid, &pkg, &full_json)
}

/// 解析通知入站报文。
#[uniffi::export]
pub fn parse_notification_inbound(full_json: String) -> String {
    crate::state_merge::parse_notification_inbound_json(&full_json)
}

/// 解析媒体入站报文。
#[uniffi::export]
pub fn parse_media_inbound(full_json: String) -> String {
    crate::state_merge::parse_media_inbound_json(&full_json)
}

/// 解析图标响应报文。
#[uniffi::export]
pub fn app_sync_parse_icon_response(payload_json: String) -> Option<String> {
    Some(crate::app_sync::parse_icon_response(&payload_json))
}

/// 构造应用列表请求报文。
#[uniffi::export]
pub fn app_sync_build_applist_request(scope: String, now_ms: i64) -> Option<String> {
    Some(crate::app_sync::build_applist_request(&scope, now_ms))
}

/// 解析应用列表响应报文。
#[uniffi::export]
pub fn app_sync_parse_applist_response(payload_json: String) -> Option<String> {
    Some(crate::app_sync::parse_applist_response(&payload_json))
}
