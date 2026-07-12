use crate::protocol::{
    codec,
    header::ProtocolHeader,
};

pub type MessageCallback = Box<dyn Fn(&str, &str) + Send + 'static>;
pub type PairingCallback = Box<dyn Fn(&str, &str, &str) + Send + 'static>;

pub struct Router {
    pub on_message: Option<MessageCallback>,
    pub on_pairing: Option<PairingCallback>,
}

impl Router {
    pub fn new() -> Self {
        Self {
            on_message: None,
            on_pairing: None,
        }
    }

    pub fn set_callbacks(
        &mut self,
        on_msg: Option<MessageCallback>,
        on_pairing: Option<PairingCallback>,
    ) {
        self.on_message = on_msg;
        self.on_pairing = on_pairing;
    }

    pub fn process_line(&self, line: &str) {
        let header = ProtocolHeader::parse(line);
        match header {
            ProtocolHeader::PairingInit => {
                if let Some(fields) = codec::decode_pairing_init(line) {
                    if let Some(ref cb) = self.on_pairing {
                        cb("PAIRING_INIT", fields.uuid, fields.tmp_pub_key);
                    }
                }
            }
            ProtocolHeader::PairingResp => {
                if let Some(fields) = codec::decode_pairing_resp(line) {
                    if let Some(ref cb) = self.on_pairing {
                        cb("PAIRING_RESP", fields.uuid, fields.encrypted_code);
                    }
                }
            }
            ProtocolHeader::Accept => {
                if let Some(fields) = codec::decode_accept(line) {
                    if let Some(ref cb) = self.on_pairing {
                        cb("ACCEPT", fields.uuid, fields.lt_pub_key);
                    }
                }
            }
            ProtocolHeader::Handshake => {
                if let Some(fields) = codec::decode_handshake(line) {
                    if let Some(ref cb) = self.on_pairing {
                        cb("HANDSHAKE", fields.uuid, fields.pub_key);
                    }
                }
            }
            ProtocolHeader::Data(_) => {
                if let Some(fields) = codec::decode_data_message(line) {
                    if let Some(ref cb) = self.on_message {
                        cb(fields.header, fields.encrypted_payload);
                    }
                }
            }
            _ => {
                log::debug!("unhandled protocol line: {}", line);
            }
        }
    }
}
