//! MQTT wire codec for protocol levels 4 (3.1.1) and 5.
//!
//! The kernel uses this codec for the connections that it owns. The
//! decoders borrow from the input where that is possible, and the
//! encoders append to a caller buffer, thus one publish does not need
//! an allocation for its topic or its payload.
//!
//! Bounds: a property section holds at most [`MAX_USER_PROPS`] user
//! properties, and each key or value has at most [`MAX_PROP_STRING`]
//! bytes. These are the same bounds that the edge codec uses.

use std::fmt;

/// Largest remaining length that the fixed header can carry.
pub const MAX_REMAINING: usize = 268_435_455;
/// Largest number of user properties in one property section.
pub const MAX_USER_PROPS: usize = 16;
/// Largest key or value of a user property, in bytes.
pub const MAX_PROP_STRING: usize = 1024;
/// Largest subscription identifier (variable byte integer maximum).
pub const MAX_SUB_ID: u32 = 268_435_455;

/// Packet types (the high four bits of the first byte).
pub mod kind {
    pub const CONNECT: u8 = 1;
    pub const CONNACK: u8 = 2;
    pub const PUBLISH: u8 = 3;
    pub const PUBACK: u8 = 4;
    pub const PUBREC: u8 = 5;
    pub const PUBREL: u8 = 6;
    pub const PUBCOMP: u8 = 7;
    pub const SUBSCRIBE: u8 = 8;
    pub const SUBACK: u8 = 9;
    pub const UNSUBSCRIBE: u8 = 10;
    pub const UNSUBACK: u8 = 11;
    pub const PINGREQ: u8 = 12;
    pub const PINGRESP: u8 = 13;
    pub const DISCONNECT: u8 = 14;
    pub const AUTH: u8 = 15;
}

/// Property identifiers used by this codec.
pub mod prop {
    pub const PAYLOAD_FORMAT: u32 = 1;
    pub const MESSAGE_EXPIRY: u32 = 2;
    pub const SUBSCRIPTION_ID: u32 = 11;
    pub const SESSION_EXPIRY: u32 = 17;
    pub const ASSIGNED_CLIENT_ID: u32 = 18;
    pub const AUTH_METHOD: u32 = 21;
    pub const REQUEST_PROBLEM_INFO: u32 = 23;
    pub const REQUEST_RESPONSE_INFO: u32 = 25;
    pub const REASON_STRING: u32 = 28;
    pub const RECEIVE_MAXIMUM: u32 = 33;
    pub const TOPIC_ALIAS_MAXIMUM: u32 = 34;
    pub const TOPIC_ALIAS: u32 = 35;
    pub const USER_PROPERTY: u32 = 38;
    pub const MAXIMUM_PACKET_SIZE: u32 = 39;
}

/// A packet that the codec cannot accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// The bytes do not agree with the specification.
    Malformed(&'static str),
    /// The packet is correct, but this broker does not accept it.
    Unsupported(&'static str),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::Malformed(what) => write!(f, "malformed packet: {what}"),
            WireError::Unsupported(what) => write!(f, "unsupported packet: {what}"),
        }
    }
}

impl std::error::Error for WireError {}

type Result<T> = std::result::Result<T, WireError>;

/// Decodes a variable byte integer. `Ok(None)` means that more bytes
/// are necessary.
pub fn decode_varint(buf: &[u8]) -> Result<Option<(u32, usize)>> {
    let mut value: u32 = 0;
    for (index, byte) in buf.iter().enumerate().take(4) {
        value |= u32::from(byte & 0x7F) << (7 * index);
        if byte & 0x80 == 0 {
            return Ok(Some((value, index + 1)));
        }
    }
    if buf.len() >= 4 {
        return Err(WireError::Malformed("variable byte integer is too long"));
    }
    Ok(None)
}

/// Appends a variable byte integer. The value must not be larger than
/// [`MAX_REMAINING`].
pub fn encode_varint(mut value: u32, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// The fixed header of one packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedHeader {
    pub kind: u8,
    pub flags: u8,
    /// Length of the fixed header in bytes.
    pub header_len: usize,
    /// Length of the packet body in bytes.
    pub remaining: usize,
}

impl FixedHeader {
    /// Length of the full packet in bytes.
    pub fn packet_len(&self) -> usize {
        self.header_len + self.remaining
    }
}

/// Reads the fixed header at the start of `buf`. `Ok(None)` means that
/// more bytes are necessary. The flags of each packet type other than
/// PUBLISH are examined here.
pub fn fixed_header(buf: &[u8]) -> Result<Option<FixedHeader>> {
    let Some(&first) = buf.first() else {
        return Ok(None);
    };
    let Some((remaining, used)) = decode_varint(&buf[1..])? else {
        return Ok(None);
    };
    let kind = first >> 4;
    let flags = first & 0x0F;
    let expected = match kind {
        kind::PUBLISH => flags,
        kind::PUBREL | kind::SUBSCRIBE | kind::UNSUBSCRIBE => 0x02,
        kind::CONNECT
        | kind::CONNACK
        | kind::PUBACK
        | kind::PUBREC
        | kind::PUBCOMP
        | kind::SUBACK
        | kind::UNSUBACK
        | kind::PINGREQ
        | kind::PINGRESP
        | kind::DISCONNECT
        | kind::AUTH => 0x00,
        _ => return Err(WireError::Malformed("packet type 0 is reserved")),
    };
    if flags != expected {
        return Err(WireError::Malformed("incorrect fixed header flags"));
    }
    Ok(Some(FixedHeader {
        kind,
        flags,
        header_len: 1 + used,
        remaining: remaining as usize,
    }))
}

/// A cursor on a packet body.
struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        if self.buf.len() < len {
            return Err(WireError::Malformed("packet is truncated"));
        }
        let (head, tail) = self.buf.split_at(len);
        self.buf = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn varint(&mut self) -> Result<u32> {
        match decode_varint(self.buf)? {
            Some((value, used)) => {
                self.buf = &self.buf[used..];
                Ok(value)
            }
            None => Err(WireError::Malformed("packet is truncated")),
        }
    }

    fn binary(&mut self) -> Result<&'a [u8]> {
        let len = self.u16()? as usize;
        self.take(len)
    }

    fn utf8(&mut self) -> Result<&'a str> {
        let bytes = self.binary()?;
        let text =
            std::str::from_utf8(bytes).map_err(|_| WireError::Malformed("string is not UTF-8"))?;
        if text.contains('\0') {
            return Err(WireError::Malformed("string contains a null character"));
        }
        Ok(text)
    }

    /// Takes one property section: a variable byte integer length and
    /// that number of bytes.
    fn properties(&mut self) -> Result<&'a [u8]> {
        let len = self.varint()? as usize;
        self.take(len)
    }
}

/// One property value.
enum PropValue<'a> {
    Byte(u8),
    U16(u16),
    U32(u32),
    Varint(u32),
    Text(&'a str),
    /// Binary data. No caller reads the bytes.
    Binary,
    Pair(&'a str, &'a str),
}

/// Calls `visit` for each property of one section. An identifier that
/// the specification does not define is an error. The number and the
/// size of the user properties have a limit.
fn walk_properties<'a>(
    section: &'a [u8],
    mut visit: impl FnMut(u32, PropValue<'a>) -> Result<()>,
) -> Result<()> {
    let mut reader = Reader::new(section);
    let mut users = 0usize;
    while !reader.is_empty() {
        let id = reader.varint()?;
        let value = match id {
            1 | 23 | 25 | 36 | 37 | 40 | 41 | 42 => PropValue::Byte(reader.u8()?),
            19 | 33 | 34 | 35 => PropValue::U16(reader.u16()?),
            2 | 17 | 24 | 39 => PropValue::U32(reader.u32()?),
            11 => PropValue::Varint(reader.varint()?),
            3 | 8 | 18 | 21 | 26 | 28 | 31 => PropValue::Text(reader.utf8()?),
            9 | 22 => {
                reader.binary()?;
                PropValue::Binary
            }
            38 => {
                let key = reader.utf8()?;
                let value = reader.utf8()?;
                users += 1;
                if users > MAX_USER_PROPS {
                    return Err(WireError::Unsupported("too many user properties"));
                }
                if key.len() > MAX_PROP_STRING || value.len() > MAX_PROP_STRING {
                    return Err(WireError::Unsupported("user property is too large"));
                }
                PropValue::Pair(key, value)
            }
            _ => return Err(WireError::Malformed("unknown property identifier")),
        };
        visit(id, value)?;
    }
    Ok(())
}

/// Sets `slot` one time. A property that is not a user property must
/// not be in a section two times.
fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<()> {
    if slot.is_some() {
        return Err(WireError::Malformed("property is in the section two times"));
    }
    *slot = Some(value);
    Ok(())
}

/// The will of a CONNECT packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Will {
    pub topic: String,
    pub payload: Vec<u8>,
    pub qos: u8,
    pub retain: bool,
}

/// The properties of an MQTT 5 CONNECT packet. `None` means that the
/// client did not send the property.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectProperties {
    pub session_expiry: Option<u32>,
    pub receive_maximum: Option<u16>,
    pub maximum_packet_size: Option<u32>,
    pub topic_alias_maximum: Option<u16>,
    pub request_response_info: Option<u8>,
    pub request_problem_info: Option<u8>,
    pub auth_method: Option<String>,
    pub user_properties: Vec<(String, String)>,
}

/// A decoded CONNECT packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connect {
    /// Protocol level: 3 (3.1), 4 (3.1.1) or 5.
    pub level: u8,
    pub clean_start: bool,
    pub keepalive: u16,
    pub client_id: String,
    pub will: Option<Will>,
    pub username: Option<String>,
    pub password: Option<Vec<u8>>,
    /// `Some` only for protocol level 5.
    pub properties: Option<ConnectProperties>,
}

/// Decodes the body of a CONNECT packet.
pub fn decode_connect(body: &[u8]) -> Result<Connect> {
    let mut reader = Reader::new(body);
    let name = reader.binary()?;
    let level = reader.u8()?;
    match (name, level) {
        (b"MQTT", 4) | (b"MQTT", 5) | (b"MQIsdp", 3) => {}
        (b"MQTT", _) | (b"MQIsdp", _) => {
            return Err(WireError::Unsupported("protocol level"));
        }
        _ => return Err(WireError::Malformed("protocol name")),
    }
    let flags = reader.u8()?;
    if flags & 0x01 != 0 {
        return Err(WireError::Malformed("reserved connect flag is set"));
    }
    let clean_start = flags & 0x02 != 0;
    let will_flag = flags & 0x04 != 0;
    let will_qos = (flags >> 3) & 0x03;
    let will_retain = flags & 0x20 != 0;
    let has_password = flags & 0x40 != 0;
    let has_username = flags & 0x80 != 0;
    if will_qos > 2 || (!will_flag && (will_qos != 0 || will_retain)) {
        return Err(WireError::Malformed("will flags"));
    }
    if level < 5 && has_password && !has_username {
        return Err(WireError::Malformed("password without a user name"));
    }
    let keepalive = reader.u16()?;
    let properties = if level == 5 {
        let section = reader.properties()?;
        let mut props = ConnectProperties::default();
        let mut auth_data = false;
        walk_properties(section, |id, value| match (id, value) {
            (prop::SESSION_EXPIRY, PropValue::U32(v)) => set_once(&mut props.session_expiry, v),
            (prop::RECEIVE_MAXIMUM, PropValue::U16(v)) => {
                if v == 0 {
                    return Err(WireError::Malformed("receive maximum is 0"));
                }
                set_once(&mut props.receive_maximum, v)
            }
            (prop::MAXIMUM_PACKET_SIZE, PropValue::U32(v)) => {
                if v == 0 {
                    return Err(WireError::Malformed("maximum packet size is 0"));
                }
                set_once(&mut props.maximum_packet_size, v)
            }
            (prop::TOPIC_ALIAS_MAXIMUM, PropValue::U16(v)) => {
                set_once(&mut props.topic_alias_maximum, v)
            }
            (prop::REQUEST_RESPONSE_INFO, PropValue::Byte(v)) if v <= 1 => {
                set_once(&mut props.request_response_info, v)
            }
            (prop::REQUEST_PROBLEM_INFO, PropValue::Byte(v)) if v <= 1 => {
                set_once(&mut props.request_problem_info, v)
            }
            (prop::AUTH_METHOD, PropValue::Text(v)) => {
                set_once(&mut props.auth_method, v.to_string())
            }
            (22, PropValue::Binary) => {
                if auth_data {
                    return Err(WireError::Malformed("property is in the section two times"));
                }
                auth_data = true;
                Ok(())
            }
            (prop::USER_PROPERTY, PropValue::Pair(k, v)) => {
                props.user_properties.push((k.to_string(), v.to_string()));
                Ok(())
            }
            _ => Err(WireError::Malformed("property is not permitted in CONNECT")),
        })?;
        Some(props)
    } else {
        None
    };
    let client_id = reader.utf8()?.to_string();
    let will = if will_flag {
        if level == 5 {
            // Will properties: examined, then not used.
            let section = reader.properties()?;
            walk_properties(section, |_, _| Ok(()))?;
        }
        let topic = reader.utf8()?.to_string();
        let payload = reader.binary()?.to_vec();
        Some(Will {
            topic,
            payload,
            qos: will_qos,
            retain: will_retain,
        })
    } else {
        None
    };
    let username = if has_username {
        Some(reader.utf8()?.to_string())
    } else {
        None
    };
    let password = if has_password {
        Some(reader.binary()?.to_vec())
    } else {
        None
    };
    if !reader.is_empty() {
        return Err(WireError::Malformed("bytes after the CONNECT payload"));
    }
    Ok(Connect {
        level,
        clean_start,
        keepalive,
        client_id,
        will,
        username,
        password,
        properties,
    })
}

/// A decoded PUBLISH packet. The topic and the payload borrow from the
/// input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publish<'a> {
    pub dup: bool,
    pub qos: u8,
    pub retain: bool,
    /// Empty only when `alias` is `Some` (MQTT 5 alias by reference).
    pub topic: &'a str,
    /// 0 for QoS 0.
    pub packet_id: u16,
    /// The Topic Alias property. `Some(0)` is an error that the caller
    /// reports with reason code 0x94.
    pub alias: Option<u16>,
    /// Payload Format Indicator (0 when absent).
    pub payload_format: u8,
    /// Message Expiry Interval in seconds (0 when absent).
    pub message_expiry: u32,
    pub user_properties: Vec<(&'a str, &'a str)>,
    pub payload: &'a [u8],
}

/// Decodes the body of a PUBLISH packet. `flags` are the low four bits
/// of the first byte.
pub fn decode_publish(flags: u8, body: &[u8], level: u8) -> Result<Publish<'_>> {
    let dup = flags & 0x08 != 0;
    let qos = (flags >> 1) & 0x03;
    let retain = flags & 0x01 != 0;
    if qos > 2 {
        return Err(WireError::Malformed("QoS 3"));
    }
    if qos == 0 && dup {
        return Err(WireError::Malformed("DUP with QoS 0"));
    }
    let mut reader = Reader::new(body);
    let topic = reader.utf8()?;
    let packet_id = if qos > 0 {
        let id = reader.u16()?;
        if id == 0 {
            return Err(WireError::Malformed("packet identifier is 0"));
        }
        id
    } else {
        0
    };
    let mut alias = None;
    let mut format = None;
    let mut expiry = None;
    let mut users = Vec::new();
    if level == 5 {
        let section = reader.properties()?;
        walk_properties(section, |id, value| match (id, value) {
            (prop::TOPIC_ALIAS, PropValue::U16(v)) => set_once(&mut alias, v),
            (prop::PAYLOAD_FORMAT, PropValue::Byte(v)) if v <= 1 => set_once(&mut format, v),
            (prop::MESSAGE_EXPIRY, PropValue::U32(v)) => set_once(&mut expiry, v),
            (prop::USER_PROPERTY, PropValue::Pair(k, v)) => {
                users.push((k, v));
                Ok(())
            }
            // A client must not send a subscription identifier.
            (prop::SUBSCRIPTION_ID, _) => Err(WireError::Malformed(
                "subscription identifier from a client",
            )),
            // Content type, response topic and correlation data are
            // correct in a PUBLISH. This broker does not forward them.
            (3, PropValue::Text(_)) | (8, PropValue::Text(_)) | (9, PropValue::Binary) => Ok(()),
            _ => Err(WireError::Malformed("property is not permitted in PUBLISH")),
        })?;
    }
    if topic.is_empty() && alias.is_none() {
        return Err(WireError::Malformed("empty topic without an alias"));
    }
    if topic.contains(['+', '#']) {
        return Err(WireError::Malformed("wildcard in a topic name"));
    }
    Ok(Publish {
        dup,
        qos,
        retain,
        topic,
        packet_id,
        alias,
        payload_format: format.unwrap_or(0),
        message_expiry: expiry.unwrap_or(0),
        user_properties: users,
        payload: reader.buf,
    })
}

/// A decoded SUBSCRIBE packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscribe<'a> {
    pub packet_id: u16,
    /// Subscription identifier of the packet (0 when absent).
    pub subscription_id: u32,
    /// Each filter with its raw options byte. For protocol level 4 the
    /// byte is the requested QoS. The kernel examines the options, and
    /// an incorrect options byte fails only its filter.
    pub filters: Vec<(&'a str, u8)>,
}

/// Decodes the body of a SUBSCRIBE packet.
pub fn decode_subscribe(body: &[u8], level: u8) -> Result<Subscribe<'_>> {
    let mut reader = Reader::new(body);
    let packet_id = reader.u16()?;
    if packet_id == 0 {
        return Err(WireError::Malformed("packet identifier is 0"));
    }
    let mut subscription_id = None;
    if level == 5 {
        let section = reader.properties()?;
        walk_properties(section, |id, value| match (id, value) {
            (prop::SUBSCRIPTION_ID, PropValue::Varint(v)) => {
                if v == 0 {
                    return Err(WireError::Malformed("subscription identifier is 0"));
                }
                set_once(&mut subscription_id, v)
            }
            (prop::USER_PROPERTY, PropValue::Pair(_, _)) => Ok(()),
            _ => Err(WireError::Malformed(
                "property is not permitted in SUBSCRIBE",
            )),
        })?;
    }
    let mut filters = Vec::new();
    while !reader.is_empty() {
        let bytes = reader.binary()?;
        if bytes.is_empty() {
            return Err(WireError::Malformed("empty topic filter"));
        }
        let filter =
            std::str::from_utf8(bytes).map_err(|_| WireError::Malformed("string is not UTF-8"))?;
        let options = reader.u8()?;
        filters.push((filter, options));
    }
    if filters.is_empty() {
        return Err(WireError::Malformed("SUBSCRIBE without a topic filter"));
    }
    Ok(Subscribe {
        packet_id,
        subscription_id: subscription_id.unwrap_or(0),
        filters,
    })
}

/// A decoded UNSUBSCRIBE packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsubscribe<'a> {
    pub packet_id: u16,
    pub filters: Vec<&'a str>,
}

/// Decodes the body of an UNSUBSCRIBE packet.
pub fn decode_unsubscribe(body: &[u8], level: u8) -> Result<Unsubscribe<'_>> {
    let mut reader = Reader::new(body);
    let packet_id = reader.u16()?;
    if packet_id == 0 {
        return Err(WireError::Malformed("packet identifier is 0"));
    }
    if level == 5 {
        let section = reader.properties()?;
        walk_properties(section, |id, value| match (id, value) {
            (prop::USER_PROPERTY, PropValue::Pair(_, _)) => Ok(()),
            _ => Err(WireError::Malformed(
                "property is not permitted in UNSUBSCRIBE",
            )),
        })?;
    }
    let mut filters = Vec::new();
    while !reader.is_empty() {
        let filter = reader.utf8()?;
        if filter.is_empty() {
            return Err(WireError::Malformed("empty topic filter"));
        }
        filters.push(filter);
    }
    if filters.is_empty() {
        return Err(WireError::Malformed("UNSUBSCRIBE without a topic filter"));
    }
    Ok(Unsubscribe { packet_id, filters })
}

/// Decodes the body of PUBACK, PUBREC, PUBREL or PUBCOMP into the
/// packet identifier and the reason code. The reason code is 0 when the
/// packet does not carry one.
pub fn decode_ack(body: &[u8], level: u8) -> Result<(u16, u8)> {
    let mut reader = Reader::new(body);
    let packet_id = reader.u16()?;
    if packet_id == 0 {
        return Err(WireError::Malformed("packet identifier is 0"));
    }
    if reader.is_empty() {
        return Ok((packet_id, 0));
    }
    if level != 5 {
        return Err(WireError::Malformed("bytes after the packet identifier"));
    }
    let reason = reader.u8()?;
    if !reader.is_empty() {
        let section = reader.properties()?;
        walk_properties(section, |id, value| match (id, value) {
            (prop::REASON_STRING, PropValue::Text(_)) => Ok(()),
            (prop::USER_PROPERTY, PropValue::Pair(_, _)) => Ok(()),
            _ => Err(WireError::Malformed(
                "property is not permitted in an acknowledgement",
            )),
        })?;
        if !reader.is_empty() {
            return Err(WireError::Malformed("bytes after the properties"));
        }
    }
    Ok((packet_id, reason))
}

/// Decodes the body of a DISCONNECT packet into its reason code. For
/// protocol level 4 the body must be empty.
pub fn decode_disconnect(body: &[u8], level: u8) -> Result<u8> {
    if body.is_empty() {
        return Ok(0);
    }
    if level != 5 {
        return Err(WireError::Malformed("DISCONNECT with a body"));
    }
    let mut reader = Reader::new(body);
    let reason = reader.u8()?;
    if !reader.is_empty() {
        let section = reader.properties()?;
        walk_properties(section, |id, value| match (id, value) {
            (prop::SESSION_EXPIRY, PropValue::U32(_)) => Ok(()),
            (prop::REASON_STRING, PropValue::Text(_)) => Ok(()),
            (prop::USER_PROPERTY, PropValue::Pair(_, _)) => Ok(()),
            // Server Reference: correct, not used.
            (31, PropValue::Text(_)) => Ok(()),
            _ => Err(WireError::Malformed(
                "property is not permitted in DISCONNECT",
            )),
        })?;
        if !reader.is_empty() {
            return Err(WireError::Malformed("bytes after the properties"));
        }
    }
    Ok(reason)
}

fn put_fixed_header(first: u8, remaining: usize, out: &mut Vec<u8>) {
    debug_assert!(remaining <= MAX_REMAINING);
    out.push(first);
    encode_varint(remaining as u32, out);
}

fn varint_len(value: usize) -> usize {
    match value {
        0..=127 => 1,
        128..=16_383 => 2,
        16_384..=2_097_151 => 3,
        _ => 4,
    }
}

fn put_binary(bytes: &[u8], out: &mut Vec<u8>) {
    debug_assert!(bytes.len() <= usize::from(u16::MAX));
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Appends a CONNACK for protocol level 3 or 4.
pub fn encode_connack(session_present: bool, return_code: u8, out: &mut Vec<u8>) {
    out.extend_from_slice(&[0x20, 0x02, u8::from(session_present), return_code]);
}

/// The properties that the broker can put in an MQTT 5 CONNACK. `None`
/// means that the property is not sent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnackProperties<'a> {
    pub session_expiry: Option<u32>,
    pub receive_maximum: Option<u16>,
    pub maximum_packet_size: Option<u32>,
    pub topic_alias_maximum: Option<u16>,
    pub assigned_client_id: Option<&'a str>,
    pub reason_string: Option<&'a str>,
    pub user_properties: &'a [(String, String)],
}

/// Appends an MQTT 5 CONNACK.
pub fn encode_connack_v5(
    session_present: bool,
    reason: u8,
    props: &ConnackProperties<'_>,
    out: &mut Vec<u8>,
) {
    let mut section = Vec::new();
    if let Some(v) = props.session_expiry {
        section.push(prop::SESSION_EXPIRY as u8);
        section.extend_from_slice(&v.to_be_bytes());
    }
    if let Some(v) = props.receive_maximum {
        section.push(prop::RECEIVE_MAXIMUM as u8);
        section.extend_from_slice(&v.to_be_bytes());
    }
    if let Some(v) = props.maximum_packet_size {
        section.push(prop::MAXIMUM_PACKET_SIZE as u8);
        section.extend_from_slice(&v.to_be_bytes());
    }
    if let Some(v) = props.topic_alias_maximum {
        section.push(prop::TOPIC_ALIAS_MAXIMUM as u8);
        section.extend_from_slice(&v.to_be_bytes());
    }
    if let Some(v) = props.assigned_client_id {
        section.push(prop::ASSIGNED_CLIENT_ID as u8);
        put_binary(v.as_bytes(), &mut section);
    }
    if let Some(v) = props.reason_string {
        section.push(prop::REASON_STRING as u8);
        put_binary(v.as_bytes(), &mut section);
    }
    for (key, value) in props.user_properties {
        section.push(prop::USER_PROPERTY as u8);
        put_binary(key.as_bytes(), &mut section);
        put_binary(value.as_bytes(), &mut section);
    }
    put_fixed_header(0x20, 2 + varint_len(section.len()) + section.len(), out);
    out.push(u8::from(session_present));
    out.push(reason);
    encode_varint(section.len() as u32, out);
    out.extend_from_slice(&section);
}

/// One PUBLISH to send to a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishOut<'a> {
    pub dup: bool,
    pub qos: u8,
    pub retain: bool,
    pub topic: &'a str,
    /// Used only when `qos` is 1 or 2.
    pub packet_id: u16,
    /// Topic alias (0 = none). Sent only for protocol level 5.
    pub alias: u16,
    /// Subscription identifier (0 = none). Sent only for protocol level 5.
    pub subscription_id: u32,
    /// Payload Format Indicator (0 = not sent).
    pub payload_format: u8,
    /// Message Expiry Interval (0 = not sent).
    pub message_expiry: u32,
    /// User properties as raw UTF-8 pairs. Sent only for protocol level 5.
    pub user_properties: &'a [(Vec<u8>, Vec<u8>)],
    pub payload: &'a [u8],
}

/// Appends a PUBLISH. For protocol level 5 the packet always has the
/// property length, also when there are no properties.
pub fn encode_publish(publish: &PublishOut<'_>, level: u8, out: &mut Vec<u8>) {
    let first = 0x30
        | (u8::from(publish.dup) << 3)
        | ((publish.qos & 0x03) << 1)
        | u8::from(publish.retain);
    let id_len = if publish.qos > 0 { 2 } else { 0 };
    let mut section_len = 0usize;
    if level == 5 {
        if publish.alias != 0 {
            section_len += 3;
        }
        if publish.subscription_id != 0 {
            section_len += 1 + varint_len(publish.subscription_id as usize);
        }
        if publish.payload_format != 0 {
            section_len += 2;
        }
        if publish.message_expiry != 0 {
            section_len += 5;
        }
        for (key, value) in publish.user_properties {
            section_len += 1 + 2 + key.len() + 2 + value.len();
        }
    }
    let props_len = if level == 5 {
        varint_len(section_len) + section_len
    } else {
        0
    };
    let remaining = 2 + publish.topic.len() + id_len + props_len + publish.payload.len();
    out.reserve(1 + 4 + remaining);
    put_fixed_header(first, remaining, out);
    put_binary(publish.topic.as_bytes(), out);
    if publish.qos > 0 {
        out.extend_from_slice(&publish.packet_id.to_be_bytes());
    }
    if level == 5 {
        encode_varint(section_len as u32, out);
        if publish.alias != 0 {
            out.push(prop::TOPIC_ALIAS as u8);
            out.extend_from_slice(&publish.alias.to_be_bytes());
        }
        if publish.subscription_id != 0 {
            out.push(prop::SUBSCRIPTION_ID as u8);
            encode_varint(publish.subscription_id, out);
        }
        if publish.payload_format != 0 {
            out.push(prop::PAYLOAD_FORMAT as u8);
            out.push(publish.payload_format);
        }
        if publish.message_expiry != 0 {
            out.push(prop::MESSAGE_EXPIRY as u8);
            out.extend_from_slice(&publish.message_expiry.to_be_bytes());
        }
        for (key, value) in publish.user_properties {
            out.push(prop::USER_PROPERTY as u8);
            put_binary(key, out);
            put_binary(value, out);
        }
    }
    out.extend_from_slice(publish.payload);
}

/// Appends a SUBACK. `codes` has one byte for each filter.
pub fn encode_suback(packet_id: u16, codes: &[u8], level: u8, out: &mut Vec<u8>) {
    let props_len = usize::from(level == 5);
    put_fixed_header(0x90, 2 + props_len + codes.len(), out);
    out.extend_from_slice(&packet_id.to_be_bytes());
    if level == 5 {
        out.push(0);
    }
    out.extend_from_slice(codes);
}

/// Appends an UNSUBACK. For protocol level 5, `codes` has one reason
/// code for each filter. Protocol level 4 has no codes.
pub fn encode_unsuback(packet_id: u16, codes: &[u8], level: u8, out: &mut Vec<u8>) {
    if level == 5 {
        put_fixed_header(0xB0, 2 + 1 + codes.len(), out);
        out.extend_from_slice(&packet_id.to_be_bytes());
        out.push(0);
        out.extend_from_slice(codes);
    } else {
        out.extend_from_slice(&[0xB0, 0x02]);
        out.extend_from_slice(&packet_id.to_be_bytes());
    }
}

/// Appends PUBACK, PUBREC, PUBREL or PUBCOMP. `packet_kind` is one of
/// the constants in [`kind`]. A reason code other than 0 is sent only
/// for protocol level 5.
pub fn encode_ack(packet_kind: u8, packet_id: u16, reason: u8, level: u8, out: &mut Vec<u8>) {
    let flags = if packet_kind == kind::PUBREL {
        0x02
    } else {
        0x00
    };
    let first = (packet_kind << 4) | flags;
    if level == 5 && reason != 0 {
        out.extend_from_slice(&[first, 0x03]);
        out.extend_from_slice(&packet_id.to_be_bytes());
        out.push(reason);
    } else {
        out.extend_from_slice(&[first, 0x02]);
        out.extend_from_slice(&packet_id.to_be_bytes());
    }
}

/// Appends a PINGRESP.
pub fn encode_pingresp(out: &mut Vec<u8>) {
    out.extend_from_slice(&[0xD0, 0x00]);
}

/// Appends an MQTT 5 DISCONNECT with a reason code and no properties.
pub fn encode_disconnect_v5(reason: u8, out: &mut Vec<u8>) {
    if reason == 0 {
        out.extend_from_slice(&[0xE0, 0x00]);
    } else {
        out.extend_from_slice(&[0xE0, 0x01, reason]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body_of(packet: &[u8]) -> (FixedHeader, &[u8]) {
        let header = fixed_header(packet).unwrap().unwrap();
        assert_eq!(header.packet_len(), packet.len());
        (header, &packet[header.header_len..])
    }

    /// A small generator of test bytes (xorshift). The sequence is the
    /// same in each run.
    struct TestBytes(u64);

    impl TestBytes {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn bytes(&mut self, max_len: usize) -> Vec<u8> {
            let len = (self.next() as usize) % (max_len + 1);
            (0..len).map(|_| self.next() as u8).collect()
        }
    }

    fn decode_all(first: u8, body: &[u8]) {
        for level in [3u8, 4, 5] {
            let _ = decode_connect(body);
            let _ = decode_publish(first & 0x0F, body, level);
            let _ = decode_subscribe(body, level);
            let _ = decode_unsubscribe(body, level);
            let _ = decode_ack(body, level);
            let _ = decode_disconnect(body, level);
        }
    }

    #[test]
    fn random_bytes_do_not_panic() {
        let mut source = TestBytes(0x2545_F491_4F6C_DD1D);
        for _ in 0..300_000 {
            let packet = source.bytes(96);
            let _ = fixed_header(&packet);
            let _ = decode_varint(&packet);
            let first = packet.first().copied().unwrap_or(0);
            decode_all(first, &packet);
        }
    }

    #[test]
    fn changed_and_cut_packets_do_not_panic() {
        // Correct bodies. Each is cut at each length, and each byte is
        // changed to some other values.
        let connect_v5: Vec<u8> = {
            let mut body = vec![0, 4, b'M', b'Q', b'T', b'T', 5, 0xEE, 0, 30];
            let props = [
                17, 0, 0, 0, 9, 33, 0, 10, 34, 0, 5, 38, 0, 1, b'k', 0, 1, b'v',
            ];
            body.push(props.len() as u8);
            body.extend_from_slice(&props);
            body.extend_from_slice(&[0, 2, b'c', b'1', 0, 0, 1, b'w', 0, 2, b'h', b'i']);
            body.extend_from_slice(&[0, 1, b'u', 0, 1, b'p']);
            body
        };
        let publish_v5 = vec![
            0, 1, b't', 0, 7, 11, 35, 0, 2, 1, 1, 38, 0, 1, b'a', 0, 0, b'x',
        ];
        let subscribe_v5 = vec![0, 2, 2, 11, 42, 0, 3, b'a', b'/', b'#', 0x2D, 0, 1, b'b', 1];
        let ack_v5 = vec![0, 7, 0x10, 4, 31, 0, 1, b'r'];
        let mut source = TestBytes(0xD6E8_FEB8_6659_FD93);
        for body in [connect_v5, publish_v5, subscribe_v5, ack_v5] {
            for cut in 0..=body.len() {
                decode_all(0x32, &body[..cut]);
            }
            for index in 0..body.len() {
                for _ in 0..64 {
                    let mut changed = body.clone();
                    changed[index] = source.next() as u8;
                    decode_all(0x32, &changed);
                    decode_all(0x30, &changed);
                }
            }
        }
    }

    #[test]
    fn varint_round_trip_and_limits() {
        for value in [
            0u32,
            1,
            127,
            128,
            16_383,
            16_384,
            2_097_151,
            2_097_152,
            268_435_455,
        ] {
            let mut out = Vec::new();
            encode_varint(value, &mut out);
            assert_eq!(out.len(), varint_len(value as usize));
            assert_eq!(decode_varint(&out).unwrap(), Some((value, out.len())));
        }
        assert_eq!(decode_varint(&[0x80]).unwrap(), None);
        assert!(decode_varint(&[0x80, 0x80, 0x80, 0x80, 0x01]).is_err());
    }

    #[test]
    fn fixed_header_examines_the_flags() {
        assert_eq!(fixed_header(&[]).unwrap(), None);
        assert_eq!(fixed_header(&[0x30]).unwrap(), None);
        assert!(
            fixed_header(&[0x80, 0x00]).is_err(),
            "SUBSCRIBE needs flags 0010"
        );
        assert!(fixed_header(&[0x00, 0x00]).is_err());
        let header = fixed_header(&[0x82, 0x05]).unwrap().unwrap();
        assert_eq!(
            (header.kind, header.header_len, header.remaining),
            (8, 2, 5)
        );
    }

    #[test]
    fn connect_v4_with_will_and_credentials() {
        let mut body = vec![0, 4, b'M', b'Q', b'T', b'T', 4, 0xEE, 0, 60];
        body.extend_from_slice(&[0, 2, b'c', b'1']);
        body.extend_from_slice(&[0, 1, b'w', 0, 2, b'h', b'i']);
        body.extend_from_slice(&[0, 1, b'u', 0, 1, b'p']);
        let connect = decode_connect(&body).unwrap();
        assert_eq!(connect.level, 4);
        assert!(connect.clean_start);
        assert_eq!(connect.keepalive, 60);
        assert_eq!(connect.client_id, "c1");
        assert_eq!(
            connect.will,
            Some(Will {
                topic: "w".into(),
                payload: b"hi".to_vec(),
                qos: 1,
                retain: true
            })
        );
        assert_eq!(connect.username.as_deref(), Some("u"));
        assert_eq!(connect.password.as_deref(), Some(&b"p"[..]));
        assert!(connect.properties.is_none());
    }

    #[test]
    fn connect_v5_properties() {
        let mut body = vec![0, 4, b'M', b'Q', b'T', b'T', 5, 0x02, 0, 30];
        let props = [
            17, 0, 0, 0x0E, 0x10, // session expiry 3600
            33, 0, 10, // receive maximum 10
            34, 0, 5, // topic alias maximum 5
            38, 0, 1, b'k', 0, 1, b'v',
        ];
        body.push(props.len() as u8);
        body.extend_from_slice(&props);
        body.extend_from_slice(&[0, 0]);
        let connect = decode_connect(&body).unwrap();
        let p = connect.properties.unwrap();
        assert_eq!(p.session_expiry, Some(3600));
        assert_eq!(p.receive_maximum, Some(10));
        assert_eq!(p.topic_alias_maximum, Some(5));
        assert_eq!(p.maximum_packet_size, None);
        assert_eq!(p.user_properties, vec![("k".to_string(), "v".to_string())]);
        assert_eq!(connect.client_id, "");
    }

    #[test]
    fn connect_refuses_incorrect_input() {
        // Reserved flag.
        assert!(decode_connect(&[0, 4, b'M', b'Q', b'T', b'T', 4, 0x03, 0, 0, 0, 0]).is_err());
        // Unknown protocol level.
        assert_eq!(
            decode_connect(&[0, 4, b'M', b'Q', b'T', b'T', 6, 0x02, 0, 0, 0, 0]),
            Err(WireError::Unsupported("protocol level"))
        );
        // Receive maximum 0.
        let body = [
            0, 4, b'M', b'Q', b'T', b'T', 5, 0x02, 0, 0, 3, 33, 0, 0, 0, 0,
        ];
        assert!(decode_connect(&body).is_err());
        // A property two times.
        let body = [
            0, 4, b'M', b'Q', b'T', b'T', 5, 0x02, 0, 0, 6, 33, 0, 1, 33, 0, 1, 0, 0,
        ];
        assert!(decode_connect(&body).is_err());
        // Bytes after the payload.
        assert!(decode_connect(&[0, 4, b'M', b'Q', b'T', b'T', 4, 0x02, 0, 0, 0, 0, 9]).is_err());
    }

    #[test]
    fn publish_v4_round_trip() {
        let mut out = Vec::new();
        encode_publish(
            &PublishOut {
                dup: false,
                qos: 1,
                retain: true,
                topic: "a/b",
                packet_id: 7,
                alias: 0,
                subscription_id: 0,
                payload_format: 0,
                message_expiry: 0,
                user_properties: &[],
                payload: b"hello",
            },
            4,
            &mut out,
        );
        assert_eq!(
            out,
            [0x33, 12, 0, 3, b'a', b'/', b'b', 0, 7, b'h', b'e', b'l', b'l', b'o']
        );
        let (header, body) = body_of(&out);
        let publish = decode_publish(header.flags, body, 4).unwrap();
        assert_eq!(publish.topic, "a/b");
        assert_eq!(publish.packet_id, 7);
        assert_eq!(publish.qos, 1);
        assert!(publish.retain);
        assert_eq!(publish.payload, b"hello");
    }

    #[test]
    fn publish_v5_always_has_the_property_length() {
        let base = PublishOut {
            dup: false,
            qos: 0,
            retain: false,
            topic: "t",
            packet_id: 0,
            alias: 0,
            subscription_id: 0,
            payload_format: 0,
            message_expiry: 0,
            user_properties: &[],
            payload: b"hi",
        };
        let mut out = Vec::new();
        encode_publish(&base, 5, &mut out);
        assert_eq!(out, [0x30, 6, 0, 1, b't', 0, b'h', b'i']);

        let users = vec![(b"k".to_vec(), b"v".to_vec())];
        let mut out = Vec::new();
        encode_publish(
            &PublishOut {
                qos: 1,
                packet_id: 9,
                alias: 3,
                subscription_id: 200,
                payload_format: 1,
                message_expiry: 60,
                user_properties: &users,
                ..base.clone()
            },
            5,
            &mut out,
        );
        let (header, body) = body_of(&out);
        assert_eq!(header.flags, 0x02);
        // Topic, packet identifier, then the property section.
        assert_eq!(&body[..5], &[0, 1, b't', 0, 9]);
        let section_len = body[5] as usize;
        let section = &body[6..6 + section_len];
        assert_eq!(
            section,
            &[35, 0, 3, 11, 0xC8, 0x01, 1, 1, 2, 0, 0, 0, 60, 38, 0, 1, b'k', 0, 1, b'v']
        );
        assert_eq!(&body[6 + section_len..], b"hi");
    }

    #[test]
    fn publish_v5_decode_reads_the_properties() {
        // Topic "t", then 11 property bytes: alias 2, format 1 and one
        // user property with key "a" and an empty value. Payload "x".
        let body = [0, 1, b't', 11, 35, 0, 2, 1, 1, 38, 0, 1, b'a', 0, 0, b'x'];
        let publish = decode_publish(0, &body, 5).unwrap();
        assert_eq!(publish.topic, "t");
        assert_eq!(publish.alias, Some(2));
        assert_eq!(publish.payload_format, 1);
        assert_eq!(publish.message_expiry, 0);
        assert_eq!(publish.user_properties, vec![("a", "")]);
        assert_eq!(publish.payload, b"x");
    }

    #[test]
    fn publish_refuses_incorrect_input() {
        // QoS 3.
        assert!(decode_publish(0x06, &[0, 1, b't', 0, 1], 4).is_err());
        // Packet identifier 0.
        assert!(decode_publish(0x02, &[0, 1, b't', 0, 0], 4).is_err());
        // Wildcard in the topic name.
        assert!(decode_publish(0, &[0, 1, b'#'], 4).is_err());
        // Empty topic without an alias.
        assert!(decode_publish(0, &[0, 0, 0], 5).is_err());
        // A subscription identifier from a client.
        assert!(decode_publish(0, &[0, 1, b't', 2, 11, 42, b'h'], 5).is_err());
        // An empty topic with an alias is correct.
        let publish = decode_publish(0, &[0, 0, 3, 35, 0, 4, b'p'], 5).unwrap();
        assert_eq!(
            (publish.topic, publish.alias, publish.payload),
            ("", Some(4), &b"p"[..])
        );
    }

    #[test]
    fn subscribe_v4_and_v5() {
        let body = [0, 9, 0, 3, b'a', b'/', b'#', 1, 0, 1, b'b', 0];
        let sub = decode_subscribe(&body, 4).unwrap();
        assert_eq!(sub.packet_id, 9);
        assert_eq!(sub.subscription_id, 0);
        assert_eq!(sub.filters, vec![("a/#", 1), ("b", 0)]);

        let body = [0, 2, 2, 11, 42, 0, 1, b't', 0x2D];
        let sub = decode_subscribe(&body, 5).unwrap();
        assert_eq!(sub.subscription_id, 42);
        assert_eq!(sub.filters, vec![("t", 0x2D)]);

        assert!(decode_subscribe(&[0, 1], 4).is_err(), "no filter");
        assert!(
            decode_subscribe(&[0, 0, 0, 1, b't', 0], 4).is_err(),
            "identifier 0"
        );
        assert!(decode_subscribe(&[0, 2, 2, 11, 0, 0, 1, b't', 0], 5).is_err());
    }

    #[test]
    fn unsubscribe_and_unsuback() {
        let unsub = decode_unsubscribe(&[0, 5, 0, 1, b'a', 0, 1, b'b'], 4).unwrap();
        assert_eq!(unsub.packet_id, 5);
        assert_eq!(unsub.filters, vec!["a", "b"]);
        let unsub = decode_unsubscribe(&[0, 5, 0, 0, 1, b'a'], 5).unwrap();
        assert_eq!(unsub.filters, vec!["a"]);
        let mut out = Vec::new();
        encode_unsuback(5, &[0, 17], 4, &mut out);
        assert_eq!(out, [0xB0, 2, 0, 5]);
        let mut out = Vec::new();
        encode_unsuback(5, &[0, 17], 5, &mut out);
        assert_eq!(out, [0xB0, 5, 0, 5, 0, 0, 17]);
    }

    #[test]
    fn acknowledgements() {
        assert_eq!(decode_ack(&[0, 7], 4).unwrap(), (7, 0));
        assert_eq!(decode_ack(&[0, 7, 0x10], 5).unwrap(), (7, 0x10));
        assert_eq!(decode_ack(&[0, 7, 0x10, 0], 5).unwrap(), (7, 0x10));
        assert!(decode_ack(&[0, 7, 0], 4).is_err());
        assert!(decode_ack(&[0, 0], 4).is_err());
        let mut out = Vec::new();
        encode_ack(kind::PUBACK, 7, 0, 4, &mut out);
        encode_ack(kind::PUBREL, 7, 0, 5, &mut out);
        encode_ack(kind::PUBREC, 7, 0x97, 5, &mut out);
        encode_ack(kind::PUBREC, 7, 0x97, 4, &mut out);
        assert_eq!(
            out,
            [0x40, 2, 0, 7, 0x62, 2, 0, 7, 0x50, 3, 0, 7, 0x97, 0x50, 2, 0, 7]
        );
    }

    #[test]
    fn connack_suback_ping_disconnect() {
        let mut out = Vec::new();
        encode_connack(true, 0, &mut out);
        assert_eq!(out, [0x20, 2, 1, 0]);

        let users = vec![("k".to_string(), "v".to_string())];
        let mut out = Vec::new();
        encode_connack_v5(
            false,
            0,
            &ConnackProperties {
                topic_alias_maximum: Some(8),
                user_properties: &users,
                ..ConnackProperties::default()
            },
            &mut out,
        );
        assert_eq!(
            out,
            [0x20, 13, 0, 0, 10, 34, 0, 8, 38, 0, 1, b'k', 0, 1, b'v']
        );

        let mut out = Vec::new();
        encode_suback(3, &[0, 0x80], 4, &mut out);
        encode_suback(3, &[1, 0x8F], 5, &mut out);
        assert_eq!(out, [0x90, 4, 0, 3, 0, 0x80, 0x90, 5, 0, 3, 0, 1, 0x8F]);

        let mut out = Vec::new();
        encode_pingresp(&mut out);
        encode_disconnect_v5(0x94, &mut out);
        encode_disconnect_v5(0, &mut out);
        assert_eq!(out, [0xD0, 0, 0xE0, 1, 0x94, 0xE0, 0]);

        assert_eq!(decode_disconnect(&[], 4).unwrap(), 0);
        assert_eq!(decode_disconnect(&[4], 5).unwrap(), 4);
        assert_eq!(decode_disconnect(&[4, 0], 5).unwrap(), 4);
        assert!(decode_disconnect(&[4], 4).is_err());
    }
}
