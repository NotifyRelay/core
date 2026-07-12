use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolHeader<'a> {
    PairingInit,
    PairingResp,
    Accept,
    Reject,
    Handshake,
    Data(&'a str),
    HeartbeatTcp,
    DiscoverManual,
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
                "HANDSHAKE" => Self::Handshake,
                "HEARTBEAT_TCP" => Self::HeartbeatTcp,
                "NOTIFYRELAY_DISCOVER_MANUAL" => Self::DiscoverManual,
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
            Self::Handshake => write!(f, "HANDSHAKE"),
            Self::HeartbeatTcp => write!(f, "HEARTBEAT_TCP"),
            Self::DiscoverManual => write!(f, "NOTIFYRELAY_DISCOVER_MANUAL"),
            Self::Data(h) => write!(f, "{}", h),
            Self::Unknown(h) => write!(f, "{}", h),
        }
    }
}
