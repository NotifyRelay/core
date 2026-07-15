use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ==================== DATA_NOTIFICATION ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Notification {
    pub package_name: String,
    pub app_name: String,
    pub title: String,
    pub text: String,
    pub time: i64,
    pub is_locked: bool,
}

// ==================== DATA_MEDIAPLAY / DATA_SUPERISLAND ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaPayload {
    pub package_name: String,
    pub app_name: String,
    pub title: Option<String>,
    pub text: Option<String>,
    pub time: i64,
    pub is_locked: bool,
    pub media_type: String,
    pub cover_url: Option<String>,
    pub terminate_value: Option<String>,
    pub feature_key_name: Option<String>,
    pub feature_key_value: Option<String>,
    pub pics: Option<HashMap<String, String>>,
    pub hash: Option<String>,
    pub param_v2_raw: Option<String>,
    pub changes: Option<MediaPayloadChanges>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaPayloadChanges {
    pub title: Option<String>,
    pub text: Option<String>,
    pub param_v2_raw: Option<String>,
    pub pics: Option<HashMap<String, String>>,
    pub pics_removed: Option<Vec<String>>,
}

// ==================== DATA_MEDIA_CONTROL ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaControl {
    pub action: String,
    pub result: Option<String>,
}

// ==================== DATA_CLIPBOARD ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClipboardData {
    pub clipboard_type: String,
    pub content: String,
    pub time: i64,
}

// ==================== DATA_ICON_REQUEST / DATA_ICON_RESPONSE ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IconRequest {
    pub package_name: Option<String>,
    pub package_names: Option<Vec<String>>,
    pub time: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IconResponse {
    pub package_name: Option<String>,
    pub icon_data: Option<String>,
    pub icons: Option<Vec<IconItem>>,
    pub missing: Option<serde_json::Value>,
    pub time: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IconItem {
    pub package_name: String,
    pub icon_data: String,
}

// ==================== DATA_APP_LIST_REQUEST / DATA_APP_LIST_RESPONSE ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppListRequest {
    pub scope: String,
    pub time: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppListResponse {
    pub scope: String,
    pub total: i32,
    pub apps: Vec<AppInfo>,
    pub time: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    pub package_name: String,
    pub app_name: String,
}

// ==================== DATA_FTP ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FtpMessage {
    pub action: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub ip_address: Option<String>,
    pub port: Option<u16>,
}

// ==================== DATA_STATUS ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusMessage {
    pub original_header: String,
    pub result: String,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub request_id: Option<String>,
    pub action: Option<String>,
    pub hash: Option<String>,
    pub feature_key_value: Option<String>,
}

// ==================== DATA_APP_LAUNCH ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppLaunch {
    pub action: String,
    pub package_name: String,
    pub display_id: Option<i32>,
}
