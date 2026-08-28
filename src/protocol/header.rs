use std::fmt;

/// 二进制协议消息类型常量（对齐反编译文档 ProtocolV1）
pub struct MessageType;

impl MessageType {
    pub const HEARTBEAT: u8 = 0;
    pub const HANDSHAKE: u8 = 1;
    pub const NOTIFICATION: u8 = 10;
    pub const CLIPBOARD: u8 = 13;
    pub const DEVICE_STATUS: u8 = 15;
    pub const SYNC_SEARCH_APP: u8 = 19;
    pub const SYNC_SEARCH_APP_RESPONSE: u8 = 20;
    pub const RELAY_APPLICATION: u8 = 22;
    pub const PACKAGE_INFO: u8 = 42;
    pub const MEDIA_SESSION: u8 = 51;
    pub const MEDIA_SESSION_CONTROL: u8 = 52;
    pub const FEATURE_STATUS: u8 = 66;
    pub const FTP: u8 = 200;
    pub const PAIRING_INIT: u8 = 240;
    pub const PAIRING_RESP: u8 = 241;
    pub const ACCEPT: u8 = 244;
    pub const REJECT: u8 = 245;
    pub const ACK: u8 = 246;
}

/// 设备类型枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[allow(dead_code)]
pub enum DeviceType {
    Phone = 0,
    Pad = 1,
    Tv = 2,
    Laptop = 3,
    Desktop = 4,
    Speaker = 5,
    Watch = 6,
    Unknown = 255,
}

impl DeviceType {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "phone" | "手机" => Self::Phone,
            "pad" | "tablet" | "平板" => Self::Pad,
            "tv" | "电视" => Self::Tv,
            "laptop" | "笔记本" => Self::Laptop,
            "desktop" | "台式机" | "pc" => Self::Desktop,
            "speaker" | "音箱" => Self::Speaker,
            "watch" | "手表" => Self::Watch,
            _ => Self::Unknown,
        }
    }

    pub fn to_str(self) -> &'static str {
        match self {
            Self::Phone => "Phone",
            Self::Pad => "Pad",
            Self::Tv => "Tv",
            Self::Laptop => "Laptop",
            Self::Desktop => "Desktop",
            Self::Speaker => "Speaker",
            Self::Watch => "Watch",
            Self::Unknown => "Unknown",
        }
    }
}

/// 功能标志常量（用于 ProtoHandshake 的 featureFlag 字段）
pub struct FeatureFlag;

impl FeatureFlag {
    pub const NOTIFICATION: &'static str = "NOTIFICATION";
    pub const MEDIA_SESSION: &'static str = "MEDIA_SESSION";
    pub const CLIPBOARD: &'static str = "CLIPBOARD";
    pub const SUPERISLAND: &'static str = "SUPERISLAND";
    pub const PACKAGE_INFO: &'static str = "PACKAGE_INFO";
    pub const APP_LIST: &'static str = "APP_LIST";
    pub const MEDIA_CONTROL: &'static str = "MEDIA_CONTROL";
    pub const FTP: &'static str = "FTP";
    pub const APP_LAUNCH: &'static str = "APP_LAUNCH";

    /// 当前 core 支持的完整功能列表
    pub fn supported() -> Vec<&'static str> {
        vec![
            Self::NOTIFICATION,
            Self::MEDIA_SESSION,
            Self::CLIPBOARD,
            Self::SUPERISLAND,
            Self::PACKAGE_INFO,
            Self::APP_LIST,
            Self::MEDIA_CONTROL,
            Self::FTP,
            Self::APP_LAUNCH,
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ProtocolHeader<'a> {
    PairingInit,
    PairingResp,
    Accept,
    Reject,
    Ack,
    Handshake,
    Data(&'a str),
    HeartbeatTcp,
    Unknown(&'a str),
}

impl<'a> ProtocolHeader<'a> {
    pub fn parse(line: &'a str) -> Self {
        if let Some(pos) = line.find(':') {
            let prefix = &line[..pos];
            match prefix {
                "PAIRING_INIT" => Self::PairingInit,
                "PAIRING_RESP" => Self::PairingResp,
                "ACCEPT" => Self::Accept,
                "REJECT" => Self::Reject,
                "ACK" => Self::Ack,
                "HANDSHAKE" => Self::Handshake,
                "HEARTBEAT_TCP" => Self::HeartbeatTcp,
                _ if prefix.starts_with("DATA") => Self::Data(prefix),
                _ => Self::Unknown(prefix),
            }
        } else {
            Self::Unknown(line)
        }
    }

    pub fn is_data(&self) -> bool {
        matches!(self, Self::Data(_))
    }
}

impl fmt::Display for ProtocolHeader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PairingInit => write!(f, "PAIRING_INIT"),
            Self::PairingResp => write!(f, "PAIRING_RESP"),
            Self::Accept => write!(f, "ACCEPT"),
            Self::Reject => write!(f, "REJECT"),
            Self::Ack => write!(f, "ACK"),
            Self::Handshake => write!(f, "HANDSHAKE"),
            Self::HeartbeatTcp => write!(f, "HEARTBEAT_TCP"),
            Self::Data(h) => write!(f, "{}", h),
            Self::Unknown(h) => write!(f, "{}", h),
        }
    }
}
