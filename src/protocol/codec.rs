use crate::protocol::header::ProtocolHeader;

pub const DEFAULT_TCP_PORT: u16 = 23333;

fn battery_pairing(battery: i32) -> String {
    if battery >= 0 {
        format!("{}+", battery)
    } else {
        format!("{}", battery.abs())
    }
}

fn parse_battery_pairing(raw: &str) -> i32 {
    if raw.ends_with('+') {
        raw.trim_end_matches('+').parse().unwrap_or(0)
    } else {
        -raw.parse::<i32>().unwrap_or(0)
    }
}

fn battery_hb(battery: i32) -> String {
    if battery >= 0 {
        format!("+{}", battery)
    } else {
        format!("{}", battery)
    }
}

fn parse_battery_hb(raw: &str) -> i32 {
    raw.parse().unwrap_or(0)
}

pub fn encode_pairing_init(
    uuid: &str,
    spake2_pub: &str,
    ip: &str,
    battery: i32,
    device_type: &str,
) -> String {
    format!(
        "PAIRING_INIT:{}:{}:{}:{}:{}",
        uuid,
        spake2_pub,
        ip,
        battery_pairing(battery),
        device_type
    )
}

pub fn encode_pairing_resp(
    uuid: &str,
    spake2_pub: &str,
    lt_pub: &str,
    ip: &str,
    battery: i32,
    device_type: &str,
) -> String {
    format!(
        "PAIRING_RESP:{}:{}:{}:{}:{}:{}",
        uuid,
        spake2_pub,
        lt_pub,
        ip,
        battery_pairing(battery),
        device_type
    )
}

pub fn encode_accept(
    uuid: &str,
    lt_pub_key: &str,
    ip: &str,
    battery: i32,
    device_type: &str,
) -> String {
    format!(
        "ACCEPT:{}:{}:{}:{}:{}",
        uuid,
        lt_pub_key,
        ip,
        battery_pairing(battery),
        device_type
    )
}

pub fn encode_reject(uuid: &str) -> String {
    format!("REJECT:{}", uuid)
}

pub fn encode_ack(uuid: &str) -> String {
    format!("ACK:{}", uuid)
}

pub fn encode_handshake(
    uuid: &str,
    pub_key: &str,
    ip: &str,
    battery: i32,
    device_type: &str,
) -> String {
    format!(
        "HANDSHAKE:{}:{}:{}:{}:{}",
        uuid,
        pub_key,
        ip,
        battery_pairing(battery),
        device_type
    )
}

pub fn encode_heartbeat_tcp(
    uuid: &str,
    name: &str,
    port: u16,
    battery: i32,
    device_type: &str,
) -> String {
    format!(
        "HEARTBEAT_TCP:{}:{}:{}:{}:{}",
        uuid,
        name,
        port,
        battery_hb(battery),
        device_type
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

pub fn encode_udp_broadcast(
    uuid: &str,
    name_b64: &str,
    port: u16,
    battery: i32,
    device_type: &str,
) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        uuid,
        name_b64,
        port,
        battery_hb(battery),
        device_type
    )
}

#[derive(Debug)]
pub struct PairingInitFields<'a> {
    pub uuid: &'a str,
    pub spake2_pub: &'a str,
    pub ip: &'a str,
    pub battery: i32,
    pub device_type: &'a str,
}

#[derive(Debug)]
pub struct PairingRespFields<'a> {
    pub uuid: &'a str,
    pub spake2_pub: &'a str,
    pub lt_pub: &'a str,
    pub ip: &'a str,
    pub battery: i32,
    pub device_type: &'a str,
}

#[derive(Debug)]
pub struct AcceptFields<'a> {
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
    pub local_uuid: &'a str,
    pub encrypted_payload: &'a str,
}

#[derive(Debug)]
pub struct HeartbeatTcpFields<'a> {
    pub uuid: &'a str,
    pub name: &'a str,
    pub port: u16,
    pub battery: i32,
    pub device_type: &'a str,
}

fn split_parts<'a>(line: &'a str, prefix: &str) -> Vec<&'a str> {
    if let Some(payload) = line.strip_prefix(prefix) {
        payload.split(':').collect()
    } else {
        line.split(':').collect()
    }
}

pub fn decode_pairing_init(line: &str) -> Option<PairingInitFields<'_>> {
    let h = ProtocolHeader::parse(line);
    if !matches!(h, ProtocolHeader::PairingInit) {
        return None;
    }
    let parts = split_parts(line, "PAIRING_INIT:");
    if parts.len() < 5 {
        return None;
    }
    Some(PairingInitFields {
        uuid: parts[0],
        spake2_pub: parts[1],
        ip: parts[2],
        battery: parse_battery_pairing(parts[3]),
        device_type: parts[4],
    })
}

pub fn decode_pairing_resp(line: &str) -> Option<PairingRespFields<'_>> {
    let h = ProtocolHeader::parse(line);
    if !matches!(h, ProtocolHeader::PairingResp) {
        return None;
    }
    let parts = split_parts(line, "PAIRING_RESP:");
    if parts.len() < 6 {
        return None;
    }
    Some(PairingRespFields {
        uuid: parts[0],
        spake2_pub: parts[1],
        lt_pub: parts[2],
        ip: parts[3],
        battery: parse_battery_pairing(parts[4]),
        device_type: parts[5],
    })
}

pub fn decode_accept(line: &str) -> Option<AcceptFields<'_>> {
    let h = ProtocolHeader::parse(line);
    if !matches!(h, ProtocolHeader::Accept) {
        return None;
    }
    let parts = split_parts(line, "ACCEPT:");
    if parts.len() < 5 {
        return None;
    }
    Some(AcceptFields {
        uuid: parts[0],
        lt_pub_key: parts[1],
        ip: parts[2],
        battery: parse_battery_pairing(parts[3]),
        device_type: parts[4],
    })
}

pub fn decode_handshake(line: &str) -> Option<HandshakeFields<'_>> {
    let h = ProtocolHeader::parse(line);
    if !matches!(h, ProtocolHeader::Handshake) {
        return None;
    }
    let parts = split_parts(line, "HANDSHAKE:");
    if parts.len() < 5 {
        return None;
    }
    Some(HandshakeFields {
        uuid: parts[0],
        pub_key: parts[1],
        ip: parts[2],
        battery: parse_battery_pairing(parts[3]),
        device_type: parts[4],
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
        local_uuid: parts[1],
        encrypted_payload: parts[3],
    })
}

pub fn decode_heartbeat_tcp(line: &str) -> Option<HeartbeatTcpFields<'_>> {
    let h = ProtocolHeader::parse(line);
    if !matches!(h, ProtocolHeader::HeartbeatTcp) {
        return None;
    }
    let parts = split_parts(line, "HEARTBEAT_TCP:");
    if parts.len() < 5 {
        return None;
    }
    Some(HeartbeatTcpFields {
        uuid: parts[0],
        name: parts[1],
        port: parts[2].parse().unwrap_or(DEFAULT_TCP_PORT),
        battery: parse_battery_hb(parts[3]),
        device_type: parts[4],
    })
}
