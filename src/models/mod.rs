use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub app_name: String,
    pub package_name: String,
    pub title: String,
    pub body: String,
    pub icon_url: Option<String>,
    pub device_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaInfo {
    pub title: String,
    pub artist: String,
    pub cover_url: Option<String>,
    pub is_playing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MediaControl {
    PlayPause,
    Next,
    Previous,
    AudioRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipboardData {
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub uuid: String,
    pub name: String,
    pub device_type: String,
    pub ip: String,
    pub port: u16,
    pub battery: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppInfo {
    pub package_name: String,
    pub app_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FtpRequest {
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub status: String,
    pub message: Option<String>,
}
