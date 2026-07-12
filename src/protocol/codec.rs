use crate::protocol::header::ProtocolHeader;

pub const DEFAULT_TCP_PORT: u16 = 23333;
pub const DEFAULT_UDP_PORT: u16 = 23334;

pub fn encode_pairing_init(
    uuid: &str,
    tmp_pub_key: &str,
    ip: &str,
    battery: i32,
    device_type: &str,
) -> String {
    format!(
        "PAIRING_INIT:{}:{}:{}:{:+}:{}",
        uuid, tmp_pub_key, ip, battery, device_type
    )
}

pub fn encode_pairing_resp(
    uuid: &str,
    tmp_pub: &str,
    lt_pub: &str,
    encrypted_code: &str,
    ip: &str,
    battery: i32,
    device_type: &str,
) -> String {
    format!(
        "PAIRING_RESP:{}:{}:{}:{}:{}:{:+}:{}",
        uuid, tmp_pub, lt_pub, encrypted_code, ip, battery, device_type
    )
}

pub fn encode_accept(
    code: &str,
    uuid: &str,
    lt_pub_key: &str,
    ip: &str,
    battery: i32,
    device_type: &str,
) -> String {
    format!(
        "ACCEPT:{}:{}:{}:{}:{:+}:{}",
        code, uuid, lt_pub_key, ip, battery, device_type
    )
}

pub fn encode_reject(uuid: &str) -> String {
    format!("REJECT:{}", uuid)
}

pub fn encode_handshake(
    uuid: &str,
    pub_key: &str,
    ip: &str,
    battery: i32,
    device_type: &str,
) -> String {
    format!(
        "HANDSHAKE:{}:{}:{}:{:+}:{}",
        uuid, pub_key, ip, battery, device_type
    )
}

pub fn encode_heartbeat_tcp(
    uuid: &str,
    name: &str,
    port: u16,
    battery: i32,
) -> String {
    format!(
        "HEARTBEAT_TCP:{}:{}:{}:{:+}",
        uuid, name, port, battery
    )
}

pub fn encode_data_message(
    header: &str,
    local_uuid: &str,
    local_pub_key: &str,
    encrypted_payload: &str,
) -> String {
    format!(
        "{}:{}:{}:{}",
        header, local_uuid, local_pub_key, encrypted_payload
    )
}

pub fn encode_discovery_manual(
    uuid: &str,
    name_b64: &str,
    port: u16,
    battery: i32,
    device_type: &str,
) -> String {
    format!(
        "NOTIFYRELAY_DISCOVER_MANUAL:{}:{}:{}:{:+}:{}",
        uuid, name_b64, port, battery, device_type
    )
}

#[derive(Debug)]
pub struct PairingInitFields<'a> {
    pub uuid: &'a str,
    pub tmp_pub_key: &'a str,
    pub ip: &'a str,
    pub battery: i32,
    pub device_type: &'a str,
}

#[derive(Debug)]
pub struct PairingRespFields<'a> {
    pub uuid: &'a str,
    pub tmp_pub: &'a str,
    pub lt_pub: &'a str,
    pub encrypted_code: &'a str,
    pub ip: &'a str,
    pub battery: i32,
    pub device_type: &'a str,
}

#[derive(Debug)]
pub struct AcceptFields<'a> {
    pub code: &'a str,
    pub uuid: &'a str,
    pub lt_pub_key: &'a str,
    pub ip: &'a str,
    pub battery: i32,
    pub device_type: &'a str,
}

#[derive(Debug)]
pub struct HandshakeFields<'a> {
    pub uuid: &'a str,
    pub pub_key: &'a str,
    pub ip: &'a str,
    pub battery: i32,
    pub device_type: &'a str,
}

#[derive(Debug)]
pub struct DataMessageFields<'a> {
    pub header: &'a str,
    pub local_uuid: &'a str,
    pub local_pub_key: &'a str,
    pub encrypted_payload: &'a str,
}

#[derive(Debug)]
pub struct HeartbeatTcpFields<'a> {
    pub uuid: &'a str,
    pub name: &'a str,
    pub port: u16,
    pub battery: i32,
}

pub fn decode_pairing_init(line: &str) -> Option<PairingInitFields<'_>> {
    let h = ProtocolHeader::parse(line);
    if !matches!(h, ProtocolHeader::PairingInit) {
        return None;
    }
    let parts: Vec<&str> = line.split(':').collect();
    if parts.len() < 6 {
        return None;
    }
    Some(PairingInitFields {
        uuid: parts[1],
        tmp_pub_key: parts[2],
        ip: parts[3],
        battery: parts[4].parse().unwrap_or(0),
        device_type: parts[5],
    })
}

pub fn decode_pairing_resp(line: &str) -> Option<PairingRespFields<'_>> {
    let h = ProtocolHeader::parse(line);
    if !matches!(h, ProtocolHeader::PairingResp) {
        return None;
    }
    let parts: Vec<&str> = line.split(':').collect();
    if parts.len() < 8 {
        return None;
    }
    Some(PairingRespFields {
        uuid: parts[1],
        tmp_pub: parts[2],
        lt_pub: parts[3],
        encrypted_code: parts[4],
        ip: parts[5],
        battery: parts[6].parse().unwrap_or(0),
        device_type: parts[7],
    })
}

pub fn decode_accept(line: &str) -> Option<AcceptFields<'_>> {
    let h = ProtocolHeader::parse(line);
    if !matches!(h, ProtocolHeader::Accept) {
        return None;
    }
    let parts: Vec<&str> = line.split(':').collect();
    if parts.len() < 7 {
        return None;
    }
    Some(AcceptFields {
        code: parts[1],
        uuid: parts[2],
        lt_pub_key: parts[3],
        ip: parts[4],
        battery: parts[5].parse().unwrap_or(0),
        device_type: parts[6],
    })
}

pub fn decode_handshake(line: &str) -> Option<HandshakeFields<'_>> {
    let h = ProtocolHeader::parse(line);
    if !matches!(h, ProtocolHeader::Handshake) {
        return None;
    }
    let parts: Vec<&str> = line.split(':').collect();
    if parts.len() < 6 {
        return None;
    }
    Some(HandshakeFields {
        uuid: parts[1],
        pub_key: parts[2],
        ip: parts[3],
        battery: parts[4].parse().unwrap_or(0),
        device_type: parts[5],
    })
}

pub fn decode_data_message(line: &str) -> Option<DataMessageFields<'_>> {
    let h = ProtocolHeader::parse(line);
    if !h.is_data() {
        return None;
    }
    let parts: Vec<&str> = line.splitn(4, ':').collect();
    if parts.len() < 4 {
        return None;
    }
    Some(DataMessageFields {
        header: parts[0],
        local_uuid: parts[1],
        local_pub_key: parts[2],
        encrypted_payload: parts[3],
    })
}

pub fn decode_heartbeat_tcp(line: &str) -> Option<HeartbeatTcpFields<'_>> {
    let h = ProtocolHeader::parse(line);
    if !matches!(h, ProtocolHeader::HeartbeatTcp) {
        return None;
    }
    let parts: Vec<&str> = line.split(':').collect();
    if parts.len() < 5 {
        return None;
    }
    Some(HeartbeatTcpFields {
        uuid: parts[1],
        name: parts[2],
        port: parts[3].parse().unwrap_or(DEFAULT_TCP_PORT),
        battery: parts[4].parse().unwrap_or(0),
    })
}

#[derive(Debug)]
pub struct DiscoveryFields<'a> {
    pub uuid: &'a str,
    pub name_b64: &'a str,
    pub port: u16,
    pub battery: i32,
    pub device_type: &'a str,
}

pub fn decode_discovery_line(line: &str) -> Option<DiscoveryFields<'_>> {
    let parts: Vec<&str> = line.split(':').collect();
    if parts.len() < 5 {
        return None;
    }
    Some(DiscoveryFields {
        uuid: parts[0],
        name_b64: parts[1],
        port: parts[2].parse().unwrap_or(DEFAULT_TCP_PORT),
        battery: parts[3].parse().unwrap_or(0),
        device_type: parts[4],
    })
}
