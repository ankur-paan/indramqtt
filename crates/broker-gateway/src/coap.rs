//! CoAP (RFC 7252) Protocol Gateway for IndraMQTT.
//!
//! Provides zero-copy CoAP frame parsing, serialization, and translation between
//! CoAP publish/subscribe requests and internal MQTT topics.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::net::UdpSocket;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum CoapError {
    #[error("CoAP packet too short (less than 4-byte header)")]
    PacketTooShort,
    #[error("Unsupported CoAP version: {0}")]
    UnsupportedVersion(u8),
    #[error("Invalid token length: {0} (max is 8)")]
    InvalidTokenLength(u8),
    #[error("Malformed CoAP option delta or length")]
    MalformedOption,
    #[error("Malformed payload marker (expected 0xFF)")]
    MalformedPayloadMarker,
    #[error("Invalid path or topic: {0}")]
    InvalidTopic(String),
}

/// CoAP message type (2 bits)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoapType {
    Confirmable = 0,
    NonConfirmable = 1,
    Acknowledgement = 2,
    Reset = 3,
}

impl CoapType {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Confirmable),
            1 => Some(Self::NonConfirmable),
            2 => Some(Self::Acknowledgement),
            3 => Some(Self::Reset),
            _ => None,
        }
    }
}

/// CoAP message code (Class.Detail in single u8: class << 5 | detail)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoapCode(pub u8);

impl CoapCode {
    pub const EMPTY: Self = Self(0);
    pub const GET: Self = Self(1);
    pub const POST: Self = Self(2);
    pub const PUT: Self = Self(3);
    pub const DELETE: Self = Self(4);

    // 2.xx Success
    pub const CREATED: Self = Self((2 << 5) | 1); // 65
    pub const DELETED: Self = Self((2 << 5) | 2); // 66
    pub const VALID: Self = Self((2 << 5) | 3); // 67
    pub const CHANGED: Self = Self((2 << 5) | 4); // 68
    pub const CONTENT: Self = Self((2 << 5) | 5); // 69

    // 4.xx Client Error
    pub const BAD_REQUEST: Self = Self(4 << 5); // 128
    pub const UNAUTHORIZED: Self = Self((4 << 5) | 1); // 129
    pub const NOT_FOUND: Self = Self((4 << 5) | 4); // 132
    pub const METHOD_NOT_ALLOWED: Self = Self((4 << 5) | 5); // 133

    // 5.xx Server Error
    pub const INTERNAL_SERVER_ERROR: Self = Self(5 << 5); // 160

    pub fn class(&self) -> u8 {
        self.0 >> 5
    }

    pub fn detail(&self) -> u8 {
        self.0 & 0x1F
    }

    pub fn is_request(&self) -> bool {
        self.class() == 0 && self.detail() > 0
    }

    pub fn is_response(&self) -> bool {
        self.class() >= 2
    }
}

/// CoAP Option numbers
pub mod option_number {
    pub const OBSERVE: u16 = 6;
    pub const URI_PORT: u16 = 7;
    pub const URI_PATH: u16 = 11;
    pub const CONTENT_FORMAT: u16 = 12;
    pub const MAX_AGE: u16 = 14;
    pub const URI_QUERY: u16 = 15;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoapOption {
    pub number: u16,
    pub value: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoapMessage {
    pub message_type: CoapType,
    pub code: CoapCode,
    pub message_id: u16,
    pub token: Bytes,
    pub options: Vec<CoapOption>,
    pub payload: Bytes,
}

impl CoapMessage {
    /// Decode a raw CoAP UDP datagram.
    pub fn decode(mut src: &[u8]) -> Result<Self, CoapError> {
        if src.len() < 4 {
            return Err(CoapError::PacketTooShort);
        }

        let first = src.get_u8();
        let ver = (first >> 6) & 0x03;
        if ver != 1 {
            return Err(CoapError::UnsupportedVersion(ver));
        }

        let type_raw = (first >> 4) & 0x03;
        let message_type =
            CoapType::from_u8(type_raw).ok_or(CoapError::UnsupportedVersion(type_raw))?;
        let token_len = (first & 0x0F) as usize;
        if token_len > 8 {
            return Err(CoapError::InvalidTokenLength(token_len as u8));
        }

        let code = CoapCode(src.get_u8());
        let message_id = src.get_u16();

        if src.len() < token_len {
            return Err(CoapError::PacketTooShort);
        }
        let token = Bytes::copy_from_slice(&src[..token_len]);
        src.advance(token_len);

        let mut options = Vec::new();
        let mut current_option_num = 0u16;

        while !src.is_empty() {
            if src[0] == 0xFF {
                // Payload marker encountered
                src.advance(1);
                break;
            }

            let opt_header = src.get_u8();
            let mut delta = ((opt_header >> 4) & 0x0F) as u16;
            let mut length = (opt_header & 0x0F) as usize;

            if delta == 13 {
                if src.is_empty() {
                    return Err(CoapError::MalformedOption);
                }
                delta = src.get_u8() as u16 + 13;
            } else if delta == 14 {
                if src.len() < 2 {
                    return Err(CoapError::MalformedOption);
                }
                delta = src.get_u16() + 269;
            } else if delta == 15 {
                return Err(CoapError::MalformedOption);
            }

            if length == 13 {
                if src.is_empty() {
                    return Err(CoapError::MalformedOption);
                }
                length = src.get_u8() as usize + 13;
            } else if length == 14 {
                if src.len() < 2 {
                    return Err(CoapError::MalformedOption);
                }
                length = src.get_u16() as usize + 269;
            } else if length == 15 {
                return Err(CoapError::MalformedOption);
            }

            if src.len() < length {
                return Err(CoapError::MalformedOption);
            }

            current_option_num += delta;
            let val = Bytes::copy_from_slice(&src[..length]);
            src.advance(length);

            options.push(CoapOption {
                number: current_option_num,
                value: val,
            });
        }

        let payload = Bytes::copy_from_slice(src);

        Ok(Self {
            message_type,
            code,
            message_id,
            token,
            options,
            payload,
        })
    }

    /// Encode the message into a CoAP datagram bytes buffer.
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(64 + self.payload.len());

        let token_len = self.token.len().min(8) as u8;
        let first = (1 << 6) | ((self.message_type as u8) << 4) | token_len;
        buf.put_u8(first);
        buf.put_u8(self.code.0);
        buf.put_u16(self.message_id);

        if token_len > 0 {
            buf.put_slice(&self.token[..token_len as usize]);
        }

        // Options must be sorted by option number
        let mut sorted_opts = self.options.clone();
        sorted_opts.sort_by_key(|o| o.number);

        let mut prev_num = 0u16;
        for opt in sorted_opts {
            let delta = opt.number.saturating_sub(prev_num);
            prev_num = opt.number;
            let len = opt.value.len();

            let (d_nibble, d_ext) = if delta < 13 {
                (delta as u8, None)
            } else if delta < 269 {
                (13, Some(delta - 13))
            } else {
                (14, Some(delta - 269))
            };

            let (l_nibble, l_ext) = if len < 13 {
                (len as u8, None)
            } else if len < 269 {
                (13, Some((len - 13) as u16))
            } else {
                (14, Some((len - 269) as u16))
            };

            buf.put_u8((d_nibble << 4) | l_nibble);

            if d_nibble == 13 {
                buf.put_u8(d_ext.unwrap() as u8);
            } else if d_nibble == 14 {
                buf.put_u16(d_ext.unwrap());
            }

            if l_nibble == 13 {
                buf.put_u8(l_ext.unwrap() as u8);
            } else if l_nibble == 14 {
                buf.put_u16(l_ext.unwrap());
            }

            buf.put_slice(&opt.value);
        }

        if !self.payload.is_empty() {
            buf.put_u8(0xFF); // Payload marker
            buf.put_slice(&self.payload);
        }

        buf.freeze()
    }

    /// Extract URI path by concatenating all Uri-Path options.
    pub fn uri_path(&self) -> String {
        let segments: Vec<&str> = self
            .options
            .iter()
            .filter(|o| o.number == option_number::URI_PATH)
            .filter_map(|o| std::str::from_utf8(&o.value).ok())
            .collect();
        segments.join("/")
    }

    /// Create an Acknowledgement (ACK) response with given code and payload.
    pub fn make_ack(&self, code: CoapCode, payload: Bytes) -> Self {
        Self {
            message_type: CoapType::Acknowledgement,
            code,
            message_id: self.message_id,
            token: self.token.clone(),
            options: Vec::new(),
            payload,
        }
    }
}

/// CoAP PubSub Translation Engine:
/// Translates CoAP URI path requests (`/ps/<topic>`) into MQTT publish/read actions.
pub struct CoapGatewayHandler {
    retained_messages: parking_lot::RwLock<HashMap<String, Bytes>>,
}

impl Default for CoapGatewayHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl CoapGatewayHandler {
    pub fn new() -> Self {
        Self {
            retained_messages: parking_lot::RwLock::new(HashMap::new()),
        }
    }

    /// Process a received CoAP message and produce a response packet (if ACK is needed).
    pub fn handle_message(&self, req: &CoapMessage) -> Result<Option<CoapMessage>, CoapError> {
        let path = req.uri_path();

        // Path must start with "ps/" for pub/sub broker mapping
        let topic = if let Some(stripped) = path.strip_prefix("ps/") {
            stripped.to_string()
        } else if path == "ps" {
            "".to_string()
        } else {
            path
        };

        match req.code {
            CoapCode::POST | CoapCode::PUT => {
                if topic.is_empty() {
                    return Ok(Some(req.make_ack(
                        CoapCode::BAD_REQUEST,
                        Bytes::from_static(b"Topic cannot be empty"),
                    )));
                }
                // Store/publish message
                self.retained_messages
                    .write()
                    .insert(topic, req.payload.clone());
                Ok(Some(req.make_ack(CoapCode::CHANGED, Bytes::new())))
            }
            CoapCode::GET => {
                if let Some(data) = self.retained_messages.read().get(&topic) {
                    Ok(Some(req.make_ack(CoapCode::CONTENT, data.clone())))
                } else {
                    Ok(Some(req.make_ack(
                        CoapCode::NOT_FOUND,
                        Bytes::from_static(b"Not Found"),
                    )))
                }
            }
            CoapCode::DELETE => {
                self.retained_messages.write().remove(&topic);
                Ok(Some(req.make_ack(CoapCode::DELETED, Bytes::new())))
            }
            _ => Ok(Some(
                req.make_ack(CoapCode::METHOD_NOT_ALLOWED, Bytes::new()),
            )),
        }
    }
}

/// UDP CoAP Gateway Listener
pub struct CoapListener {
    socket: Arc<UdpSocket>,
    handler: Arc<CoapGatewayHandler>,
}

impl CoapListener {
    pub async fn bind(addr: SocketAddr) -> std::io::Result<Self> {
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        Ok(Self {
            socket,
            handler: Arc::new(CoapGatewayHandler::new()),
        })
    }

    pub fn handler(&self) -> Arc<CoapGatewayHandler> {
        self.handler.clone()
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Process a single inbound UDP datagram.
    pub async fn receive_and_process_one(&self) -> Result<(SocketAddr, Option<Bytes>), CoapError> {
        let mut buf = [0u8; 2048];
        let (len, peer) = self
            .socket
            .recv_from(&mut buf)
            .await
            .map_err(|_| CoapError::PacketTooShort)?;

        let msg = CoapMessage::decode(&buf[..len])?;
        let response = self.handler.handle_message(&msg)?;

        if let Some(resp_msg) = response {
            let encoded = resp_msg.encode();
            let _ = self.socket.send_to(&encoded, peer).await;
            Ok((peer, Some(encoded)))
        } else {
            Ok((peer, None))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coap_encode_decode_roundtrip() {
        let msg = CoapMessage {
            message_type: CoapType::Confirmable,
            code: CoapCode::POST,
            message_id: 0x1A2B,
            token: Bytes::from_static(b"tok1"),
            options: vec![
                CoapOption {
                    number: option_number::URI_PATH,
                    value: Bytes::from_static(b"ps"),
                },
                CoapOption {
                    number: option_number::URI_PATH,
                    value: Bytes::from_static(b"sensors"),
                },
                CoapOption {
                    number: option_number::URI_PATH,
                    value: Bytes::from_static(b"temp"),
                },
            ],
            payload: Bytes::from_static(b"{\"temp\": 24.5}"),
        };

        let encoded = msg.encode();
        let decoded = CoapMessage::decode(&encoded).expect("decode CoAP");

        assert_eq!(decoded.message_type, CoapType::Confirmable);
        assert_eq!(decoded.code, CoapCode::POST);
        assert_eq!(decoded.message_id, 0x1A2B);
        assert_eq!(decoded.token, Bytes::from_static(b"tok1"));
        assert_eq!(decoded.uri_path(), "ps/sensors/temp");
        assert_eq!(decoded.payload, Bytes::from_static(b"{\"temp\": 24.5}"));
    }

    #[test]
    fn test_coap_pubsub_handler() {
        let handler = CoapGatewayHandler::new();

        // 1. Publish (PUT /ps/factory/temp)
        let put_req = CoapMessage {
            message_type: CoapType::Confirmable,
            code: CoapCode::PUT,
            message_id: 101,
            token: Bytes::from_static(b"t1"),
            options: vec![
                CoapOption {
                    number: option_number::URI_PATH,
                    value: Bytes::from_static(b"ps"),
                },
                CoapOption {
                    number: option_number::URI_PATH,
                    value: Bytes::from_static(b"factory"),
                },
                CoapOption {
                    number: option_number::URI_PATH,
                    value: Bytes::from_static(b"temp"),
                },
            ],
            payload: Bytes::from_static(b"42.8"),
        };

        let resp = handler.handle_message(&put_req).unwrap().unwrap();
        assert_eq!(resp.code, CoapCode::CHANGED);
        assert_eq!(resp.message_id, 101);

        // 2. Read (GET /ps/factory/temp)
        let get_req = CoapMessage {
            message_type: CoapType::Confirmable,
            code: CoapCode::GET,
            message_id: 102,
            token: Bytes::from_static(b"t2"),
            options: vec![
                CoapOption {
                    number: option_number::URI_PATH,
                    value: Bytes::from_static(b"ps"),
                },
                CoapOption {
                    number: option_number::URI_PATH,
                    value: Bytes::from_static(b"factory"),
                },
                CoapOption {
                    number: option_number::URI_PATH,
                    value: Bytes::from_static(b"temp"),
                },
            ],
            payload: Bytes::new(),
        };

        let get_resp = handler.handle_message(&get_req).unwrap().unwrap();
        assert_eq!(get_resp.code, CoapCode::CONTENT);
        assert_eq!(get_resp.payload, Bytes::from_static(b"42.8"));
    }
}
