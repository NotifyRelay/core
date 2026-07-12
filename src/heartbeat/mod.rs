pub struct HeartbeatState;

impl HeartbeatState {
    pub fn new() -> Self {
        Self
    }
}

pub fn format_udp_heartbeat(
    uuid: &str,
    name_b64: &str,
    port: u16,
    battery: i32,
    device_type: &str,
) -> String {
    format!("{}:{}:{}:{:+}:{}", uuid, name_b64, port, battery, device_type)
}

pub fn format_tcp_heartbeat(
    uuid: &str,
    name_b64: &str,
    port: u16,
    battery: i32,
) -> String {
    format!("HEARTBEAT_TCP:{}:{}:{}:{:+}", uuid, name_b64, port, battery)
}

pub fn parse_udp_heartbeat(line: &str) -> Option<(String, String, u16, i32, String)> {
    let parts: Vec<&str> = line.split(':').collect();
    if parts.len() < 5 {
        return None;
    }
    Some((
        parts[0].to_string(),
        parts[1].to_string(),
        parts[2].parse().unwrap_or(23333),
        parts[3].parse().unwrap_or(0),
        parts[4].to_string(),
    ))
}
