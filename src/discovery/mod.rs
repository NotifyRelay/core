use crate::protocol::codec;

pub struct DiscoveryState;

impl DiscoveryState {
    pub fn new() -> Self {
        Self
    }
}

pub fn format_discovery_broadcast(
    uuid: &str,
    name_b64: &str,
    port: u16,
    battery: i32,
    device_type: &str,
) -> String {
    codec::encode_udp_broadcast(uuid, name_b64, port, battery, device_type)
}
