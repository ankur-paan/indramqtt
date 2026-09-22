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
///
/// The handler is stateless with respect to message payloads: retained
/// reads and writes live in the kernel (`broker-storage` retained store)
/// and fan-out goes through the kernel router, so every CoAP publish
/// reaches ordinary MQTT subscribers. This handler only validates the
/// `/ps/<topic>` mapping and tracks CoAP observe registrations (bounded
/// below). The previous in-crate `retained_messages` map has been
/// deleted; a GET served without the kernel always answers NOT FOUND and
/// the kernel replaces it with CONTENT when retained state exists.
pub struct CoapGatewayHandler {
    observers: parking_lot::RwLock<HashMap<String, Vec<CoapObserver>>>,
    observe_seq: std::sync::atomic::AtomicU32,
}

/// One CoAP observer waiting for notifications on a topic.
///
/// Bounded by [`MAX_OBSERVERS_PER_TOPIC`] per topic and
/// [`MAX_OBSERVED_TOPICS`] topics: both caps are checked on registration,
/// so the table cannot grow without bound on the message path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoapObserver {
    pub peer: SocketAddr,
    pub token: Bytes,
}

/// Maximum observers kept per observed topic.
///
/// 32 observers cover constrained-device fan-out while keeping per-publish
/// notify work to at most 32 small UDP datagrams, spawned off the hot
/// path by the kernel.
pub const MAX_OBSERVERS_PER_TOPIC: usize = 32;

/// Maximum distinct topics with at least one observer.
///
/// 2048 topics bound the table to at most
/// `2048 * 32` observer entries (each under 100 bytes), well within the
/// 12 GB test-host budget and never on the fan-out fast path.
pub const MAX_OBSERVED_TOPICS: usize = 2048;

impl Default for CoapGatewayHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl CoapGatewayHandler {
    pub fn new() -> Self {
        Self {
            observers: parking_lot::RwLock::new(HashMap::new()),
            observe_seq: std::sync::atomic::AtomicU32::new(0),
        }
    }

    /// Extract the MQTT topic for a `/ps/<topic>` request.
    ///
    /// Returns `Some(topic)` only when the URI path is exactly
    /// `ps/<topic>` with a non-empty `<topic>`; any other path
    /// (including bare `ps`) yields `None` so the caller answers
    /// BAD REQUEST instead of routing a malformed topic.
    pub fn coap_topic(req: &CoapMessage) -> Option<String> {
        let path = req.uri_path();
        path.strip_prefix("ps/")
            .filter(|stripped| !stripped.is_empty())
            .map(str::to_string)
    }

    /// Whether this GET registers a CoAP observe relationship (RFC 7641).
    ///
    /// True when an Observe option (number 6) is present with an empty
    /// value or a zero value, the registration encoding used by
    /// constrained clients. Cancellation (Observe: 1) is not tracked:
    /// it is treated as a plain GET.
    pub fn is_observe_register(req: &CoapMessage) -> bool {
        req.options
            .iter()
            .filter(|o| o.number == option_number::OBSERVE)
            .any(|o| o.value.is_empty() || o.value.iter().all(|b| *b == 0))
    }

    /// Minimal big-endian encoding of an observe sequence number.
    fn encode_observe_seq(seq: u32) -> Bytes {
        let seq = seq & 0x00FF_FFFF;
        if seq < 256 {
            Bytes::copy_from_slice(&[seq as u8])
        } else if seq < 65536 {
            Bytes::copy_from_slice(&[(seq >> 8) as u8, seq as u8])
        } else {
            Bytes::copy_from_slice(&[(seq >> 16) as u8, (seq >> 8) as u8, seq as u8])
        }
    }

    /// Next observe sequence number (wraps at 24 bits per RFC 7641).
    pub fn next_observe_seq(&self) -> u32 {
        self.observe_seq
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            & 0x00FF_FFFF
    }

    /// Register `peer`/`token` as an observer of `topic`.
    ///
    /// Bounded: false when the per-topic cap or the distinct-topic cap
    /// is hit, or when `topic` is empty. Duplicate `(peer, token)` pairs
    /// refresh in place instead of growing the list. Short write lock
    /// only on the registration path, never on fan-out.
    pub fn register_observer(&self, topic: &str, peer: SocketAddr, token: Bytes) -> bool {
        if topic.is_empty() || token.len() > 8 {
            return false;
        }
        let mut table = self.observers.write();
        if let Some(list) = table.get_mut(topic) {
            if list.iter().any(|o| o.peer == peer && o.token == token) {
                return true;
            }
            if list.len() >= MAX_OBSERVERS_PER_TOPIC {
                return false;
            }
            list.push(CoapObserver { peer, token });
            return true;
        }
        if table.len() >= MAX_OBSERVED_TOPICS {
            return false;
        }
        table.insert(topic.to_string(), vec![CoapObserver { peer, token }]);
        true
    }

    /// Snapshot the observers of one topic for a notify round.
    pub fn observers_for(&self, topic: &str) -> Vec<CoapObserver> {
        self.observers
            .read()
            .get(topic)
            .cloned()
            .unwrap_or_default()
    }

    /// Cheap empty check for the publish hot path: one read lock that
    /// returns after a length check when nobody observes anything.
    pub fn has_observers(&self) -> bool {
        !self.observers.read().is_empty()
    }

    /// Total observer entries (for tests and observability).
    pub fn observer_count(&self) -> usize {
        self.observers.read().values().map(Vec::len).sum()
    }

    /// Build the ACK for an observe registration carrying `payload`.
    pub fn make_observe_response(
        &self,
        req: &CoapMessage,
        payload: Bytes,
        seq: u32,
    ) -> CoapMessage {
        CoapMessage {
            message_type: CoapType::Acknowledgement,
            code: CoapCode::CONTENT,
            message_id: req.message_id,
            token: req.token.clone(),
            options: vec![CoapOption {
                number: option_number::OBSERVE,
                value: Self::encode_observe_seq(seq),
            }],
            payload,
        }
    }

    /// Build one NON notification for `observer` carrying `payload`.
    pub fn build_notify(&self, observer: &CoapObserver, payload: Bytes, seq: u32) -> CoapMessage {
        CoapMessage {
            message_type: CoapType::NonConfirmable,
            code: CoapCode::CONTENT,
            message_id: (seq & 0xFFFF) as u16,
            token: observer.token.clone(),
            options: vec![CoapOption {
                number: option_number::OBSERVE,
                value: Self::encode_observe_seq(seq),
            }],
            payload,
        }
    }

    /// Encode every observer notification for `topic` (pure, for tests).
    pub fn notify_encodings(
        &self,
        topic: &str,
        payload: &Bytes,
        seq: u32,
    ) -> Vec<(SocketAddr, Bytes)> {
        self.observers_for(topic)
            .iter()
            .map(|o| {
                let msg = self.build_notify(o, payload.clone(), seq);
                (o.peer, msg.encode())
            })
            .collect()
    }

    /// Validate a received CoAP message and produce the immediate response.
    ///
    /// POST/PUT with a valid `/ps/<topic>` answers CHANGED (the kernel
    /// publishes the payload through the router and retained store);
    /// POST/PUT without one answers BAD REQUEST. DELETE answers DELETED
    /// (the kernel clears retained state). GET answers NOT FOUND here:
    /// the kernel replaces it with CONTENT plus an Observe option when
    /// retained state exists, registering the observer first when this
    /// is an observe GET.
    pub fn handle_message(&self, req: &CoapMessage) -> Result<Option<CoapMessage>, CoapError> {
        match req.code {
            CoapCode::POST | CoapCode::PUT => {
                if Self::coap_topic(req).is_none() {
                    return Ok(Some(req.make_ack(
                        CoapCode::BAD_REQUEST,
                        Bytes::from_static(b"Topic cannot be empty"),
                    )));
                }
                Ok(Some(req.make_ack(CoapCode::CHANGED, Bytes::new())))
            }
            CoapCode::GET => Ok(Some(
                req.make_ack(CoapCode::NOT_FOUND, Bytes::from_static(b"Not Found")),
            )),
            CoapCode::DELETE => Ok(Some(req.make_ack(CoapCode::DELETED, Bytes::new()))),
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
    ///
    /// Stateless with respect to payloads (retained state lives in the
    /// kernel); observe GETs register the sender before answering so a
    /// standalone listener still tracks observers. The kernel listener
    /// replaces the GET answer with retained CONTENT when it exists.
    pub async fn receive_and_process_one(&self) -> Result<(SocketAddr, Option<Bytes>), CoapError> {
        let mut buf = [0u8; 2048];
        let (len, peer) = self
            .socket
            .recv_from(&mut buf)
            .await
            .map_err(|_| CoapError::PacketTooShort)?;

        let msg = CoapMessage::decode(&buf[..len])?;
        if msg.code == CoapCode::GET && CoapGatewayHandler::is_observe_register(&msg) {
            if let Some(topic) = CoapGatewayHandler::coap_topic(&msg) {
                self.handler
                    .register_observer(&topic, peer, msg.token.clone());
            }
        }
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
    fn test_coap_pubsub_handler_is_stateless() {
        let handler = CoapGatewayHandler::new();

        // 1. Publish (PUT /ps/factory/temp) validates and answers CHANGED
        // without storing: retained lives in the kernel.
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

        assert_eq!(
            CoapGatewayHandler::coap_topic(&put_req).as_deref(),
            Some("factory/temp")
        );
        let resp = handler.handle_message(&put_req).unwrap().unwrap();
        assert_eq!(resp.code, CoapCode::CHANGED);
        assert_eq!(resp.message_id, 101);

        // 2. Empty topic is BAD REQUEST, never routed.
        let bad_req = CoapMessage {
            message_type: CoapType::Confirmable,
            code: CoapCode::PUT,
            message_id: 103,
            token: Bytes::from_static(b"t3"),
            options: vec![CoapOption {
                number: option_number::URI_PATH,
                value: Bytes::from_static(b"ps"),
            }],
            payload: Bytes::from_static(b"42.8"),
        };
        assert_eq!(CoapGatewayHandler::coap_topic(&bad_req), None);
        let bad_resp = handler.handle_message(&bad_req).unwrap().unwrap();
        assert_eq!(bad_resp.code, CoapCode::BAD_REQUEST);

        // 3. Read (GET /ps/factory/temp) answers NOT FOUND here: the
        // kernel replaces it with CONTENT when retained state exists.
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
        assert_eq!(get_resp.code, CoapCode::NOT_FOUND);
        assert!(!CoapGatewayHandler::is_observe_register(&get_req));
    }

    #[test]
    fn test_coap_observe_registers_and_notifies() {
        let handler = CoapGatewayHandler::new();
        assert!(!handler.has_observers());
        let peer: SocketAddr = "127.0.0.1:5683".parse().unwrap();

        let observe_req = CoapMessage {
            message_type: CoapType::Confirmable,
            code: CoapCode::GET,
            message_id: 201,
            token: Bytes::from_static(b"obs1"),
            options: vec![
                CoapOption {
                    number: option_number::URI_PATH,
                    value: Bytes::from_static(b"ps"),
                },
                CoapOption {
                    number: option_number::URI_PATH,
                    value: Bytes::from_static(b"sensors/temp"),
                },
                CoapOption {
                    number: option_number::OBSERVE,
                    value: Bytes::from_static(b"\x00"),
                },
            ],
            payload: Bytes::new(),
        };
        assert!(CoapGatewayHandler::is_observe_register(&observe_req));
        assert_eq!(
            CoapGatewayHandler::coap_topic(&observe_req).as_deref(),
            Some("sensors/temp")
        );
        assert!(handler.register_observer("sensors/temp", peer, Bytes::from_static(b"obs1")));
        assert!(handler.has_observers());
        assert_eq!(handler.observer_count(), 1);

        // Duplicate registration refreshes instead of growing.
        assert!(handler.register_observer("sensors/temp", peer, Bytes::from_static(b"obs1")));
        assert_eq!(handler.observer_count(), 1);

        let payload = Bytes::from_static(b"21.5");
        let seq = handler.next_observe_seq();
        let encodings = handler.notify_encodings("sensors/temp", &payload, seq);
        assert_eq!(encodings.len(), 1);
        assert_eq!(encodings[0].0, peer);
        let decoded = CoapMessage::decode(&encodings[0].1).expect("decode notify");
        assert_eq!(decoded.code, CoapCode::CONTENT);
        assert_eq!(decoded.token, Bytes::from_static(b"obs1"));
        assert_eq!(decoded.payload, payload);
        assert!(
            decoded
                .options
                .iter()
                .any(|o| o.number == option_number::OBSERVE),
            "notify must carry the Observe option"
        );

        // Unrelated topics notify nobody.
        assert!(handler
            .notify_encodings("other/topic", &payload, seq)
            .is_empty());
    }

    #[test]
    fn test_coap_observer_table_is_bounded() {
        let handler = CoapGatewayHandler::new();
        let base: SocketAddr = "127.0.0.1:5683".parse().unwrap();
        // Per-topic cap holds.
        for i in 0..(MAX_OBSERVERS_PER_TOPIC + 8) {
            let peer = SocketAddr::new(base.ip(), base.port().wrapping_add(i as u16).max(1024));
            let token = Bytes::copy_from_slice(format!("t{i:04}").as_bytes());
            let ok = handler.register_observer("bounded/topic", peer, token);
            if i < MAX_OBSERVERS_PER_TOPIC {
                assert!(ok, "first {MAX_OBSERVERS_PER_TOPIC} registrations fit");
            } else {
                assert!(!ok, "registrations past the per-topic cap refuse");
            }
        }
        assert_eq!(handler.observer_count(), MAX_OBSERVERS_PER_TOPIC);
    }
}
