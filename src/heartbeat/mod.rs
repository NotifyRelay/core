use crate::protocol::codec;

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
    codec::encode_udp_broadcast(uuid, name_b64, port, battery, device_type)
}

pub fn format_tcp_heartbeat(
    uuid: &str,
    name_b64: &str,
    port: u16,
    battery: i32,
    device_type: &str,
) -> String {
    codec::encode_heartbeat_tcp(uuid, name_b64, port, battery, device_type)
}

pub fn parse_udp_heartbeat(line: &str) -> Option<(String, String, u16, i32, String)> {
    codec::decode_discovery_line(line).map(|f| {
        (
            f.uuid.to_string(),
            f.name_b64.to_string(),
            f.port,
            f.battery,
            f.device_type.to_string(),
        )
    })
}
