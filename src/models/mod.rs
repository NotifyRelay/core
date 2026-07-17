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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    pub time: i64,
    pub is_locked: bool,
    pub media_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cover_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminate_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feature_key_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feature_key_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pics: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub param_v2_raw: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changes: Option<MediaPayloadChanges>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaPayloadChanges {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub param_v2_raw: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pics: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pics_removed: Option<Vec<String>>,
}

// ==================== DATA_MEDIA_CONTROL ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaControl {
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
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
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_names: Option<Vec<String>>,
    pub time: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IconResponse {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icons: Option<Vec<IconItem>>,
    #[serde(skip_serializing_if = "Option::is_none")]
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
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<String>,
    pub scope: String,
    pub time: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppListResponse {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

// ==================== DATA_STATUS ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusMessage {
    pub original_header: String,
    pub result: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feature_key_value: Option<String>,
}

// ==================== DATA_APP_LAUNCH ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppLaunch {
    pub action: String,
    pub package_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_id: Option<i32>,
}
