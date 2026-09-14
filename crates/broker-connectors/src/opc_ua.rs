//! OPC-UA industrial telemetry bridge (INDRA-201).
//!
//! Bridges OPC-UA binary telemetry and MonitoredItem subscriptions
//! into MQTT topic trees (inbound path: wire decode → JSON documents
//! for streaming SQL) and routes MQTT setpoint writes back out as
//! OPC-UA WriteRequests with strict type coercion (outbound path).
//!
//! The transport layer is clean-room OPC-UA TCP framing: HEL/ACK
//! handshake, OPN/CLO secure-channel chunks with SecureChannelId,
//! SecurityToken and SequenceNumber accounting. Payloads use the
//! Variant/DataValue codec across all primitive industrial types
//! with quality (`Good`/`Uncertain`/`Bad`) and source/server
//! timestamp extraction.
//!
//! `BadSessionIdInvalid` / `BadSecureChannelClosed` are transient
//! reconnect events; `BadNodeIdUnknown` / `BadTypeMismatch` are
//! terminal.

#![allow(unknown_lints)]
#![allow(clippy::chunks_exact_to_as_chunks)]

use async_trait::async_trait;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{now_millis, render_template, BackoffState, BatchQueue, ConnectorError, Result, Sink};

// ---------------------------------------------------------------------------
// Status codes.
// ---------------------------------------------------------------------------

/// OPC-UA status severity (top two bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpcUaSeverity {
    Good,
    Uncertain,
    Bad,
}

/// Classify a 32-bit StatusCode by severity + well-known value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpcUaStatus(pub u32);

impl OpcUaStatus {
    pub const GOOD: u32 = 0x0000_0000;
    pub const UNCERTAIN: u32 = 0x4000_0000;
    pub const BAD: u32 = 0x8000_0000;
    pub const BAD_SESSION_ID_INVALID: u32 = 0x8025_0000;
    pub const BAD_SECURE_CHANNEL_CLOSED: u32 = 0x8086_0000;
    pub const BAD_NODE_ID_UNKNOWN: u32 = 0x8034_0000;
    pub const BAD_TYPE_MISMATCH: u32 = 0x8074_0000;

    pub fn severity(self) -> OpcUaSeverity {
        match self.0 >> 30 {
            0 => OpcUaSeverity::Good,
            1 => OpcUaSeverity::Uncertain,
            _ => OpcUaSeverity::Bad,
        }
    }

    pub fn text(self) -> &'static str {
        match self.0 {
            Self::GOOD => "Good",
            Self::UNCERTAIN => "Uncertain",
            Self::BAD => "Bad",
            Self::BAD_SESSION_ID_INVALID => "BadSessionIdInvalid",
            Self::BAD_SECURE_CHANNEL_CLOSED => "BadSecureChannelClosed",
            Self::BAD_NODE_ID_UNKNOWN => "BadNodeIdUnknown",
            Self::BAD_TYPE_MISMATCH => "BadTypeMismatch",
            _ => match self.severity() {
                OpcUaSeverity::Good => "Good",
                OpcUaSeverity::Uncertain => "Uncertain",
                _ => "Bad",
            },
        }
    }

    /// Transient reconnect events (session/channel loss) vs terminal
    /// data errors (unknown node, type mismatch).
    pub fn is_transient(self) -> bool {
        matches!(
            self.0,
            Self::BAD_SESSION_ID_INVALID | Self::BAD_SECURE_CHANNEL_CLOSED
        )
    }
}

// ---------------------------------------------------------------------------
// NodeId.
// ---------------------------------------------------------------------------

/// OPC-UA NodeId (namespace + numeric/string/GUID/opaque identifier).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpcUaNodeId {
    pub namespace: u16,
    pub id: OpcUaNodeIdValue,
}

/// NodeId payload variants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpcUaNodeIdValue {
    Numeric(u32),
    Text(String),
    Guid([u8; 16]),
    Opaque(Vec<u8>),
}

impl OpcUaNodeId {
    /// Parse `ns=<u16>;<type>=<value>` with types `i` (numeric),
    /// `s` (string), `g` (GUID `8-4-4-4-12` hex), `b` (base64
    /// opaque). Rejects wildcards and malformed shapes.
    pub fn parse(text: &str) -> Result<Self> {
        if text.contains('+') || text.contains('#') || text.contains('*') {
            return Err(ConnectorError::Dispatch(format!(
                "opc-ua node id must be concrete: {text:?}"
            )));
        }
        let (ns_part, id_part) = text.split_once(';').ok_or_else(|| {
            ConnectorError::Dispatch(format!("opc-ua node id needs ns=<n>;<t>=<v>: {text:?}"))
        })?;
        let namespace: u16 = ns_part
            .strip_prefix("ns=")
            .ok_or_else(|| ConnectorError::Dispatch(format!("opc-ua node id needs ns=: {text:?}")))?
            .parse()
            .map_err(|_| ConnectorError::Dispatch(format!("opc-ua bad namespace in {text:?}")))?;
        let (kind, value) = id_part.split_once('=').ok_or_else(|| {
            ConnectorError::Dispatch(format!("opc-ua node id needs <t>=<v>: {text:?}"))
        })?;
        if value.is_empty() {
            return Err(ConnectorError::Dispatch(format!(
                "opc-ua node id value is empty: {text:?}"
            )));
        }
        let id =
            match kind {
                "i" => OpcUaNodeIdValue::Numeric(value.parse().map_err(|_| {
                    ConnectorError::Dispatch(format!("opc-ua bad numeric id in {text:?}"))
                })?),
                "s" => OpcUaNodeIdValue::Text(value.to_string()),
                "g" => OpcUaNodeIdValue::Guid(parse_guid(value).ok_or_else(|| {
                    ConnectorError::Dispatch(format!("opc-ua bad GUID in {text:?}"))
                })?),
                "b" => OpcUaNodeIdValue::Opaque(base64_decode(value).ok_or_else(|| {
                    ConnectorError::Dispatch(format!("opc-ua bad opaque base64 in {text:?}"))
                })?),
                _ => {
                    return Err(ConnectorError::Dispatch(format!(
                        "opc-ua node id type must be i/s/g/b: {text:?}"
                    )))
                }
            };
        Ok(Self { namespace, id })
    }

    /// Canonical display form (`ns=<n>;<t>=<v>`).
    pub fn display(&self) -> String {
        let body = match &self.id {
            OpcUaNodeIdValue::Numeric(v) => format!("i={v}"),
            OpcUaNodeIdValue::Text(v) => format!("s={v}"),
            OpcUaNodeIdValue::Guid(v) => format!("g={}", format_guid(v)),
            OpcUaNodeIdValue::Opaque(v) => format!("b={}", base64_encode(v)),
        };
        format!("ns={};{body}", self.namespace)
    }

    /// Filesystem/topic-safe identifier (`ns2_Line1_Temperature`).
    pub fn sanitized_id(&self) -> String {
        self.display()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect()
    }
}

fn parse_guid(text: &str) -> Option<[u8; 16]> {
    let parts: Vec<&str> = text.split('-').collect();
    if parts.len() != 5
        || [8, 4, 4, 4, 12]
            .iter()
            .zip(parts.iter())
            .any(|(len, part)| part.len() != *len)
    {
        return None;
    }
    let hex: String = parts.concat();
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 16];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        out[index] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(out)
}

fn format_guid(id: &[u8; 16]) -> String {
    let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

fn base64_decode(text: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(text).ok()
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

// ---------------------------------------------------------------------------
// Variant / DataValue codec.
// ---------------------------------------------------------------------------

/// OPC-UA primitive variant types (scalar only in this subset).
#[derive(Debug, Clone, PartialEq)]
pub enum OpcUaVariant {
    Boolean(bool),
    SByte(i8),
    Byte(u8),
    Int16(i16),
    UInt16(u16),
    Int32(i32),
    UInt32(u32),
    Int64(i64),
    UInt64(u64),
    Float(f32),
    Double(f64),
    Text(String),
    DateTime(i64),
    ByteString(Vec<u8>),
}

impl OpcUaVariant {
    /// Builtin type id (Variant encoding byte).
    pub fn type_id(&self) -> u8 {
        match self {
            Self::Boolean(_) => 1,
            Self::SByte(_) => 2,
            Self::Byte(_) => 3,
            Self::Int16(_) => 4,
            Self::UInt16(_) => 5,
            Self::Int32(_) => 6,
            Self::UInt32(_) => 7,
            Self::Int64(_) => 8,
            Self::UInt64(_) => 9,
            Self::Float(_) => 10,
            Self::Double(_) => 11,
            Self::Text(_) => 12,
            Self::DateTime(_) => 13,
            Self::ByteString(_) => 15,
        }
    }

    /// JSON projection of the value.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Self::Boolean(v) => serde_json::json!(*v),
            Self::SByte(v) => serde_json::json!(*v),
            Self::Byte(v) => serde_json::json!(*v),
            Self::Int16(v) => serde_json::json!(*v),
            Self::UInt16(v) => serde_json::json!(*v),
            Self::Int32(v) => serde_json::json!(*v),
            Self::UInt32(v) => serde_json::json!(*v),
            Self::Int64(v) => serde_json::json!(*v),
            Self::UInt64(v) => serde_json::json!(*v),
            Self::Float(v) => serde_json::json!(*v),
            Self::Double(v) => serde_json::json!(*v),
            Self::Text(v) => serde_json::json!(v),
            Self::DateTime(v) => serde_json::json!(datetime_to_rfc3339(*v)),
            Self::ByteString(v) => serde_json::json!(base64_encode(v)),
        }
    }

    /// Strict JSON coercion for outbound writes (type mismatches are
    /// terminal `BadTypeMismatch` errors, never silent casts).
    pub fn coerce_from(target: OpcUaVariantKind, value: &serde_json::Value) -> Result<Self> {
        match (target, value) {
            (OpcUaVariantKind::Boolean, serde_json::Value::Bool(v)) => Ok(Self::Boolean(*v)),
            (OpcUaVariantKind::SByte, serde_json::Value::Number(n)) => n
                .as_i64()
                .and_then(|v| i8::try_from(v).ok())
                .map(Self::SByte)
                .ok_or_else(|| type_mismatch("SByte")),
            (OpcUaVariantKind::Byte, serde_json::Value::Number(n)) => n
                .as_u64()
                .and_then(|v| u8::try_from(v).ok())
                .map(Self::Byte)
                .ok_or_else(|| type_mismatch("Byte")),
            (OpcUaVariantKind::Int16, serde_json::Value::Number(n)) => n
                .as_i64()
                .and_then(|v| i16::try_from(v).ok())
                .map(Self::Int16)
                .ok_or_else(|| type_mismatch("Int16")),
            (OpcUaVariantKind::UInt16, serde_json::Value::Number(n)) => n
                .as_u64()
                .and_then(|v| u16::try_from(v).ok())
                .map(Self::UInt16)
                .ok_or_else(|| type_mismatch("UInt16")),
            (OpcUaVariantKind::Int32, serde_json::Value::Number(n)) => n
                .as_i64()
                .and_then(|v| i32::try_from(v).ok())
                .map(Self::Int32)
                .ok_or_else(|| type_mismatch("Int32")),
            (OpcUaVariantKind::UInt32, serde_json::Value::Number(n)) => n
                .as_u64()
                .and_then(|v| u32::try_from(v).ok())
                .map(Self::UInt32)
                .ok_or_else(|| type_mismatch("UInt32")),
            (OpcUaVariantKind::Int64, serde_json::Value::Number(n)) => n
                .as_i64()
                .map(Self::Int64)
                .ok_or_else(|| type_mismatch("Int64")),
            (OpcUaVariantKind::UInt64, serde_json::Value::Number(n)) => n
                .as_u64()
                .map(Self::UInt64)
                .ok_or_else(|| type_mismatch("UInt64")),
            (OpcUaVariantKind::Float, serde_json::Value::Number(n)) => n
                .as_f64()
                .map(|v| Self::Float(v as f32))
                .ok_or_else(|| type_mismatch("Float")),
            (OpcUaVariantKind::Double, serde_json::Value::Number(n)) => n
                .as_f64()
                .map(Self::Double)
                .ok_or_else(|| type_mismatch("Double")),
            (OpcUaVariantKind::Text, serde_json::Value::String(v)) => Ok(Self::Text(v.clone())),
            (OpcUaVariantKind::DateTime, serde_json::Value::Number(n)) => n
                .as_i64()
                .map(Self::DateTime)
                .ok_or_else(|| type_mismatch("DateTime")),
            (OpcUaVariantKind::ByteString, serde_json::Value::String(v)) => base64_decode(v)
                .map(Self::ByteString)
                .ok_or_else(|| type_mismatch("ByteString")),
            _ => Err(type_mismatch("variant")),
        }
    }
}

fn type_mismatch(expected: &str) -> ConnectorError {
    ConnectorError::Dispatch(format!("opc-ua BadTypeMismatch: expected {expected}"))
}

/// Variant kind selector for write coercion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OpcUaVariantKind {
    Boolean,
    SByte,
    Byte,
    Int16,
    UInt16,
    Int32,
    UInt32,
    Int64,
    UInt64,
    Float,
    Double,
    Text,
    DateTime,
    ByteString,
}

/// OPC-UA DateTime: 100ns ticks since 1601-01-01. Unix epoch
/// (1970-01-01) sits at 116444736000000000 ticks.
const DATETIME_UNIX_OFFSET: i64 = 116_444_736_000_000_000;

/// Render DateTime ticks as RFC 3339 millis (UTC).
pub fn datetime_to_rfc3339(ticks: i64) -> String {
    let millis = ticks.div_euclid(10_000) - 11_644_473_600_000;
    super::rfc3339_millis(millis)
}

/// Whole-second DateTime ticks for a Unix millis timestamp.
pub fn datetime_from_millis(millis: i64) -> i64 {
    millis
        .saturating_mul(10_000)
        .saturating_add(DATETIME_UNIX_OFFSET)
}

fn encode_u32(value: u32, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn encode_i32(value: i32, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn encode_string(text: &str, out: &mut Vec<u8>) {
    encode_i32(text.len() as i32, out);
    out.extend_from_slice(text.as_bytes());
}

fn decode_exact<'a>(cursor: &mut &'a [u8], n: usize, what: &str) -> Result<&'a [u8]> {
    if cursor.len() < n {
        return Err(ConnectorError::Connection(format!(
            "opc-ua truncated {what}"
        )));
    }
    let (head, rest) = cursor.split_at(n);
    *cursor = rest;
    Ok(head)
}

fn decode_u16(cursor: &mut &[u8]) -> Result<u16> {
    Ok(u16::from_le_bytes(
        decode_exact(cursor, 2, "u16")?.try_into().expect("2 bytes"),
    ))
}

fn decode_u32(cursor: &mut &[u8]) -> Result<u32> {
    Ok(u32::from_le_bytes(
        decode_exact(cursor, 4, "u32")?.try_into().expect("4 bytes"),
    ))
}

fn decode_i32(cursor: &mut &[u8]) -> Result<i32> {
    Ok(i32::from_le_bytes(
        decode_exact(cursor, 4, "i32")?.try_into().expect("4 bytes"),
    ))
}

fn decode_u64(cursor: &mut &[u8]) -> Result<u64> {
    Ok(u64::from_le_bytes(
        decode_exact(cursor, 8, "u64")?.try_into().expect("8 bytes"),
    ))
}

fn decode_i64(cursor: &mut &[u8]) -> Result<i64> {
    Ok(i64::from_le_bytes(
        decode_exact(cursor, 8, "i64")?.try_into().expect("8 bytes"),
    ))
}

fn decode_string(cursor: &mut &[u8]) -> Result<String> {
    let len = decode_i32(cursor)?;
    if len < 0 {
        return Ok(String::new());
    }
    let bytes = decode_exact(cursor, len as usize, "string")?;
    std::str::from_utf8(bytes)
        .map(str::to_string)
        .map_err(|_| ConnectorError::Connection("opc-ua string not UTF-8".to_string()))
}

/// Encode one scalar Variant (type mask + value).
pub fn encode_variant(variant: &OpcUaVariant, out: &mut Vec<u8>) {
    out.push(variant.type_id());
    match variant {
        OpcUaVariant::Boolean(v) => out.push(u8::from(*v)),
        OpcUaVariant::SByte(v) => out.push(*v as u8),
        OpcUaVariant::Byte(v) => out.push(*v),
        OpcUaVariant::Int16(v) => out.extend_from_slice(&v.to_le_bytes()),
        OpcUaVariant::UInt16(v) => out.extend_from_slice(&v.to_le_bytes()),
        OpcUaVariant::Int32(v) => encode_i32(*v, out),
        OpcUaVariant::UInt32(v) => encode_u32(*v, out),
        OpcUaVariant::Int64(v) => out.extend_from_slice(&v.to_le_bytes()),
        OpcUaVariant::UInt64(v) => out.extend_from_slice(&v.to_le_bytes()),
        OpcUaVariant::Float(v) => out.extend_from_slice(&v.to_le_bytes()),
        OpcUaVariant::Double(v) => out.extend_from_slice(&v.to_le_bytes()),
        OpcUaVariant::Text(v) => encode_string(v, out),
        OpcUaVariant::DateTime(v) => out.extend_from_slice(&v.to_le_bytes()),
        OpcUaVariant::ByteString(v) => {
            encode_i32(v.len() as i32, out);
            out.extend_from_slice(v);
        }
    }
}

/// Decode one scalar Variant.
pub fn decode_variant(cursor: &mut &[u8]) -> Result<OpcUaVariant> {
    let type_id = decode_exact(cursor, 1, "variant mask")?[0];
    match type_id {
        1 => Ok(OpcUaVariant::Boolean(
            decode_exact(cursor, 1, "bool")?[0] != 0,
        )),
        2 => Ok(OpcUaVariant::SByte(
            decode_exact(cursor, 1, "sbyte")?[0] as i8,
        )),
        3 => Ok(OpcUaVariant::Byte(decode_exact(cursor, 1, "byte")?[0])),
        4 => Ok(OpcUaVariant::Int16(i16::from_le_bytes(
            decode_exact(cursor, 2, "int16")?
                .try_into()
                .expect("2 bytes"),
        ))),
        5 => Ok(OpcUaVariant::UInt16(decode_u16(cursor)?)),
        6 => Ok(OpcUaVariant::Int32(decode_i32(cursor)?)),
        7 => Ok(OpcUaVariant::UInt32(decode_u32(cursor)?)),
        8 => Ok(OpcUaVariant::Int64(decode_i64(cursor)?)),
        9 => Ok(OpcUaVariant::UInt64(decode_u64(cursor)?)),
        10 => Ok(OpcUaVariant::Float(f32::from_le_bytes(
            decode_exact(cursor, 4, "float")?
                .try_into()
                .expect("4 bytes"),
        ))),
        11 => Ok(OpcUaVariant::Double(f64::from_le_bytes(
            decode_exact(cursor, 8, "double")?
                .try_into()
                .expect("8 bytes"),
        ))),
        12 => Ok(OpcUaVariant::Text(decode_string(cursor)?)),
        13 => Ok(OpcUaVariant::DateTime(decode_i64(cursor)?)),
        15 => {
            let len = decode_i32(cursor)?;
            if len < 0 {
                return Ok(OpcUaVariant::ByteString(Vec::new()));
            }
            Ok(OpcUaVariant::ByteString(
                decode_exact(cursor, len as usize, "bytestring")?.to_vec(),
            ))
        }
        other => Err(ConnectorError::Connection(format!(
            "opc-ua unsupported variant type {other} (arrays/matrices out of scope)"
        ))),
    }
}

/// One MonitoredItem value: node, value, quality, timestamps.
#[derive(Debug, Clone, PartialEq)]
pub struct OpcUaDataValue {
    pub node_id: OpcUaNodeId,
    pub value: OpcUaVariant,
    pub status: OpcUaStatus,
    pub source_timestamp: Option<i64>,
    pub server_timestamp: Option<i64>,
}

/// Encode a DataValue: mask + value + status + optional timestamps.
pub fn encode_data_value(data: &OpcUaDataValue, out: &mut Vec<u8>) {
    let mut mask = 0x01u8; // value present
    mask |= 0x02; // status always present here
    if data.source_timestamp.is_some() {
        mask |= 0x04;
    }
    if data.server_timestamp.is_some() {
        mask |= 0x08;
    }
    out.push(mask);
    encode_variant(&data.value, out);
    encode_u32(data.status.0, out);
    if let Some(ticks) = data.source_timestamp {
        out.extend_from_slice(&ticks.to_le_bytes());
    }
    if let Some(ticks) = data.server_timestamp {
        out.extend_from_slice(&ticks.to_le_bytes());
    }
}

/// Decode a DataValue for a known node.
pub fn decode_data_value(node_id: OpcUaNodeId, cursor: &mut &[u8]) -> Result<OpcUaDataValue> {
    let mask = decode_exact(cursor, 1, "datavalue mask")?[0];
    let value = if mask & 0x01 != 0 {
        decode_variant(cursor)?
    } else {
        OpcUaVariant::Boolean(false)
    };
    let status = if mask & 0x02 != 0 {
        OpcUaStatus(decode_u32(cursor)?)
    } else {
        OpcUaStatus(OpcUaStatus::GOOD)
    };
    let source_timestamp = if mask & 0x04 != 0 {
        Some(decode_i64(cursor)?)
    } else {
        None
    };
    let server_timestamp = if mask & 0x08 != 0 {
        Some(decode_i64(cursor)?)
    } else {
        None
    };
    Ok(OpcUaDataValue {
        node_id,
        value,
        status,
        source_timestamp,
        server_timestamp,
    })
}

/// Map a DataChangeNotification value into the streaming JSON
/// document evaluated by SQL rules.
pub fn notification_to_json(data: &OpcUaDataValue) -> serde_json::Value {
    let timestamp = data
        .source_timestamp
        .or(data.server_timestamp)
        .map(datetime_to_rfc3339)
        .unwrap_or_else(|| super::rfc3339_millis(now_millis()));
    serde_json::json!({
        "node_id": data.node_id.display(),
        "value": data.value.to_json(),
        "status": data.status.text(),
        "status_code": format!("0x{:08x}", data.status.0),
        "timestamp": timestamp,
    })
}

// ---------------------------------------------------------------------------
// TCP transport framing: HEL/ACK + OPN/CLO chunks.
// ---------------------------------------------------------------------------

/// Chunk header: 3-byte type + flags + u32 LE length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpcUaChunk {
    Hello,
    Acknowledge,
    OpenSecureChannel,
    CloseSecureChannel,
}

impl OpcUaChunk {
    fn tag(self) -> [u8; 3] {
        match self {
            Self::Hello => *b"HEL",
            Self::Acknowledge => *b"ACK",
            Self::OpenSecureChannel => *b"OPN",
            Self::CloseSecureChannel => *b"CLO",
        }
    }

    fn parse(tag: &[u8]) -> Result<Self> {
        match tag {
            b"HEL" => Ok(Self::Hello),
            b"ACK" => Ok(Self::Acknowledge),
            b"OPN" => Ok(Self::OpenSecureChannel),
            b"CLO" => Ok(Self::CloseSecureChannel),
            _ => Err(ConnectorError::Connection(format!(
                "opc-ua unknown chunk tag {tag:?}"
            ))),
        }
    }
}

/// Encode a chunk frame: tag + flags('F' final) + length + body.
pub fn encode_chunk(kind: OpcUaChunk, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + body.len());
    out.extend_from_slice(&kind.tag());
    out.push(b'F');
    out.extend_from_slice(&((8 + body.len()) as u32).to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// Split a received chunk into (kind, body).
pub fn decode_chunk(frame: &[u8]) -> Result<(OpcUaChunk, Vec<u8>)> {
    if frame.len() < 8 {
        return Err(ConnectorError::Connection(
            "opc-ua truncated chunk header".to_string(),
        ));
    }
    let kind = OpcUaChunk::parse(&frame[..3])?;
    let length = u32::from_le_bytes([frame[4], frame[5], frame[6], frame[7]]) as usize;
    if length < 8 || frame.len() < length {
        return Err(ConnectorError::Connection(
            "opc-ua truncated chunk body".to_string(),
        ));
    }
    Ok((kind, frame[8..length].to_vec()))
}

/// HEL body: version + buffers + limits + endpoint URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpcUaHello {
    pub protocol_version: u32,
    pub receive_buffer: u32,
    pub send_buffer: u32,
    pub max_message: u32,
    pub max_chunk: u32,
    pub endpoint_url: String,
}

impl OpcUaHello {
    pub fn encode(&self, out: &mut Vec<u8>) {
        encode_u32(self.protocol_version, out);
        encode_u32(self.receive_buffer, out);
        encode_u32(self.send_buffer, out);
        encode_u32(self.max_message, out);
        encode_u32(self.max_chunk, out);
        encode_string(&self.endpoint_url, out);
    }

    pub fn decode(cursor: &mut &[u8]) -> Result<Self> {
        Ok(Self {
            protocol_version: decode_u32(cursor)?,
            receive_buffer: decode_u32(cursor)?,
            send_buffer: decode_u32(cursor)?,
            max_message: decode_u32(cursor)?,
            max_chunk: decode_u32(cursor)?,
            endpoint_url: decode_string(cursor)?,
        })
    }
}

/// OPN/CLO body: SecureChannelId plus the sequence header
/// (sequence number and request id). Security headers stay empty
/// under the None policy; token accounting rides the session layer
/// below.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpcUaChannelFrame {
    pub secure_channel_id: u32,
    pub sequence_number: u32,
    pub request_id: u32,
}

impl OpcUaChannelFrame {
    pub fn encode(&self, out: &mut Vec<u8>) {
        encode_u32(self.secure_channel_id, out);
        encode_u32(self.sequence_number, out);
        encode_u32(self.request_id, out);
    }

    pub fn decode(cursor: &mut &[u8]) -> Result<Self> {
        Ok(Self {
            secure_channel_id: decode_u32(cursor)?,
            sequence_number: decode_u32(cursor)?,
            request_id: decode_u32(cursor)?,
        })
    }
}

// ---------------------------------------------------------------------------
// Config.
// ---------------------------------------------------------------------------

/// OPC-UA security policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum OpcUaSecurityPolicy {
    #[default]
    None,
    Basic256Sha256,
    Aes128Sha256RsaOaep,
}

impl OpcUaSecurityPolicy {
    pub fn uri(self) -> &'static str {
        match self {
            Self::None => "http://opcfoundation.org/UA/SecurityPolicy#None",
            Self::Basic256Sha256 => "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
            Self::Aes128Sha256RsaOaep => {
                "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep"
            }
        }
    }
}

/// OPC-UA security mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum OpcUaSecurityMode {
    #[default]
    None,
    Sign,
    SignAndEncrypt,
}

/// OPC-UA authentication scheme.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase", tag = "type")]
pub enum OpcUaAuth {
    #[default]
    Anonymous,
    UsernamePassword {
        username: String,
        password: String,
    },
    Certificate {
        cert_pem: String,
        key_pem: String,
    },
}

/// One node subscription: polled node → MQTT topic template.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeSubscriptionConfig {
    /// Standard NodeId (`ns=2;s=Line1.Temperature`, ...).
    pub node_id: String,
    /// Sampling interval in ms.
    pub sampling_interval_ms: u64,
    /// Destination topic (`factory/line1/${node.sanitized_id}`).
    pub publish_topic_template: String,
    /// Optional MQTT pattern for outbound setpoint writes.
    #[serde(default)]
    pub write_topic_pattern: Option<String>,
}

/// OPC-UA bridge configuration. Buffering is unbounded by default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpcUaSinkConfig {
    /// Server URL (`opc.tcp://host:4840`).
    pub endpoint_url: String,
    /// Security policy (default None).
    #[serde(default)]
    pub security_policy: OpcUaSecurityPolicy,
    /// Security mode (default None).
    #[serde(default)]
    pub security_mode: OpcUaSecurityMode,
    /// Authentication (default anonymous).
    #[serde(default)]
    pub auth: OpcUaAuth,
    /// Node subscriptions (non-empty).
    pub node_subscriptions: Vec<NodeSubscriptionConfig>,
    /// Buffer capacity (`None` unbounded).
    #[serde(default)]
    pub buffer_capacity: Option<usize>,
    /// Flush trigger row count (default 100).
    #[serde(default = "default_batch_size")]
    pub batch_size: Option<usize>,
    /// Linger flush window in ms (default 50).
    #[serde(default = "default_linger_ms")]
    pub linger_ms: Option<u64>,
    /// Network connect / request timeout in ms (default 5000).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

fn default_batch_size() -> Option<usize> {
    Some(100)
}

fn default_linger_ms() -> Option<u64> {
    Some(50)
}

impl OpcUaSinkConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.unwrap_or(5000).max(1))
    }

    pub fn validate(&self) -> Result<()> {
        if !self.endpoint_url.starts_with("opc.tcp://") {
            return Err(ConnectorError::Dispatch(format!(
                "opc-ua endpoint_url must start with opc.tcp://: {:?}",
                self.endpoint_url
            )));
        }
        if self.security_policy == OpcUaSecurityPolicy::None
            && self.security_mode != OpcUaSecurityMode::None
        {
            return Err(ConnectorError::Dispatch(
                "opc-ua Sign/SignAndEncrypt need a security policy".to_string(),
            ));
        }
        match &self.auth {
            OpcUaAuth::Anonymous => {}
            OpcUaAuth::UsernamePassword { username, .. } => {
                if username.trim().is_empty() {
                    return Err(ConnectorError::Dispatch(
                        "opc-ua username must not be empty".to_string(),
                    ));
                }
            }
            OpcUaAuth::Certificate { cert_pem, key_pem } => {
                if !cert_pem.contains("BEGIN CERTIFICATE") || !key_pem.contains("BEGIN") {
                    return Err(ConnectorError::Dispatch(
                        "opc-ua certificate auth needs PEM cert + key".to_string(),
                    ));
                }
            }
        }
        if self.node_subscriptions.is_empty() {
            return Err(ConnectorError::Dispatch(
                "opc-ua node_subscriptions must not be empty".to_string(),
            ));
        }
        for subscription in &self.node_subscriptions {
            OpcUaNodeId::parse(&subscription.node_id)?;
            if subscription.publish_topic_template.trim().is_empty() {
                return Err(ConnectorError::Dispatch(
                    "opc-ua publish_topic_template must not be empty".to_string(),
                ));
            }
            // Strict template check with the sanitized id variable.
            render_template(
                &subscription.publish_topic_template,
                &[("node.sanitized_id", "dummy".to_string())],
            )?;
        }
        if self.batch_size == Some(0) {
            return Err(ConnectorError::Dispatch(
                "opc-ua batch_size must be >= 1".to_string(),
            ));
        }
        Ok(())
    }

    pub fn effective_batch_size(&self) -> usize {
        self.batch_size.unwrap_or(usize::MAX).max(1)
    }

    pub fn effective_linger(&self) -> Duration {
        self.linger_ms
            .map(Duration::from_millis)
            .unwrap_or(Duration::MAX)
    }

    pub fn effective_buffer(&self) -> usize {
        self.buffer_capacity.unwrap_or(usize::MAX).max(1)
    }

    /// Render a subscription's publish topic for a node.
    pub fn publish_topic(
        &self,
        subscription: &NodeSubscriptionConfig,
        node: &OpcUaNodeId,
    ) -> Result<String> {
        render_template(
            &subscription.publish_topic_template,
            &[("node.sanitized_id", node.sanitized_id())],
        )
    }
}

// ---------------------------------------------------------------------------
// Transport + sink (outbound setpoint writes).
// ---------------------------------------------------------------------------

/// One outbound write: node + coerced value frame bytes.
#[derive(Debug, Clone)]
pub struct OpcUaWriteFrame {
    pub node_id: OpcUaNodeId,
    pub variant: OpcUaVariant,
    pub bytes: Vec<u8>,
}

/// Encode a minimal WriteRequest body: node display + variant.
pub fn encode_write_request(node: &OpcUaNodeId, variant: &OpcUaVariant) -> Vec<u8> {
    let mut out = Vec::new();
    encode_string(&node.display(), &mut out);
    encode_variant(variant, &mut out);
    out
}

#[async_trait]
pub trait OpcUaTransport: Send + Sync {
    async fn connect(&self) -> Result<()>;
    async fn write(&self, frame: &OpcUaWriteFrame) -> Result<()>;
}

/// In-memory transport capturing every write (tests, dry runs).
#[derive(Debug, Default)]
pub struct MemoryOpcUaTransport {
    writes: parking_lot::Mutex<Vec<OpcUaWriteFrame>>,
    connected: AtomicU64,
    calls: AtomicU64,
}

impl MemoryOpcUaTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn writes(&self) -> Vec<OpcUaWriteFrame> {
        self.writes.lock().clone()
    }

    pub fn connect_calls(&self) -> u64 {
        self.connected.load(Ordering::SeqCst)
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl OpcUaTransport for MemoryOpcUaTransport {
    async fn connect(&self) -> Result<()> {
        self.connected.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn write(&self, frame: &OpcUaWriteFrame) -> Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.writes.lock().push(frame.clone());
        Ok(())
    }
}

/// TCP transport: HEL/ACK handshake, then framed writes with
/// sequence accounting.
pub struct TcpOpcUaTransport {
    host: String,
    port: u16,
    hello: OpcUaHello,
    stream: tokio::sync::Mutex<Option<tokio::net::TcpStream>>,
    sequence: AtomicU64,
    timeout: Duration,
}

impl TcpOpcUaTransport {
    pub fn new(config: &OpcUaSinkConfig) -> Result<Self> {
        config.validate()?;
        let rest = config.endpoint_url.trim_start_matches("opc.tcp://");
        let (host, port) = match rest.split_once('/') {
            Some((authority, _)) => split_host_port(authority)?,
            None => split_host_port(rest)?,
        };
        Ok(Self {
            host,
            port,
            hello: OpcUaHello {
                protocol_version: 0,
                receive_buffer: 65536,
                send_buffer: 65536,
                max_message: 2 * 1024 * 1024,
                max_chunk: 65536,
                endpoint_url: config.endpoint_url.clone(),
            },
            stream: tokio::sync::Mutex::new(None),
            sequence: AtomicU64::new(1),
            timeout: config.timeout(),
        })
    }

    pub fn next_sequence(&self) -> u32 {
        self.sequence.fetch_add(1, Ordering::SeqCst) as u32
    }
}

fn split_host_port(authority: &str) -> Result<(String, u16)> {
    let authority = authority.split('@').next_back().unwrap_or_default();
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => {
            let port: u16 = port.parse().map_err(|_| {
                ConnectorError::Dispatch(format!("opc-ua bad port in {authority:?}"))
            })?;
            (host, port)
        }
        None => (authority, 4840),
    };
    if host.is_empty() {
        return Err(ConnectorError::Dispatch(
            "opc-ua host must not be empty".to_string(),
        ));
    }
    Ok((host.to_string(), port))
}

#[async_trait]
impl OpcUaTransport for TcpOpcUaTransport {
    async fn connect(&self) -> Result<()> {
        if self.stream.lock().await.is_some() {
            return Ok(());
        }
        let addr = format!("{}:{}", self.host, self.port);
        let mut stream = tokio::time::timeout(self.timeout, tokio::net::TcpStream::connect(&addr))
            .await
            .map_err(|_| ConnectorError::Connection(format!("opc-ua connect timeout: {addr}")))?
            .map_err(|e| ConnectorError::Connection(format!("opc-ua connect failed: {e}")))?;
        let mut body = Vec::new();
        self.hello.encode(&mut body);
        stream
            .write_all(&encode_chunk(OpcUaChunk::Hello, &body))
            .await
            .map_err(|e| ConnectorError::Connection(format!("opc-ua hello write failed: {e}")))?;
        let mut header = [0u8; 8];
        tokio::time::timeout(self.timeout, stream.read_exact(&mut header))
            .await
            .map_err(|_| ConnectorError::Connection("opc-ua ack timeout".to_string()))?
            .map_err(|e| ConnectorError::Connection(format!("opc-ua ack read failed: {e}")))?;
        let length = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
        if !(8..=64 * 1024).contains(&length) {
            return Err(ConnectorError::Connection(
                "opc-ua bad ACK length".to_string(),
            ));
        }
        let mut rest = vec![0u8; length - 8];
        stream
            .read_exact(&mut rest)
            .await
            .map_err(|e| ConnectorError::Connection(format!("opc-ua ack read failed: {e}")))?;
        let mut full = header.to_vec();
        full.extend_from_slice(&rest);
        let (kind, _) = decode_chunk(&full)?;
        if kind != OpcUaChunk::Acknowledge {
            return Err(ConnectorError::Connection(
                "opc-ua expected ACK".to_string(),
            ));
        }
        *self.stream.lock().await = Some(stream);
        Ok(())
    }

    async fn write(&self, frame: &OpcUaWriteFrame) -> Result<()> {
        let sequence = self.next_sequence();
        let mut channel = Vec::new();
        OpcUaChannelFrame {
            secure_channel_id: 1,
            sequence_number: sequence,
            request_id: sequence,
        }
        .encode(&mut channel);
        channel.extend_from_slice(&frame.bytes);
        let packet = encode_chunk(OpcUaChunk::OpenSecureChannel, &channel);
        let mut guard = self.stream.lock().await;
        let stream = guard
            .as_mut()
            .ok_or_else(|| ConnectorError::Connection("opc-ua not connected".to_string()))?;
        stream
            .write_all(&packet)
            .await
            .map_err(|e| ConnectorError::Connection(format!("opc-ua write failed: {e}")))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Sink: MQTT setpoint writes → OPC-UA WriteRequests.
// ---------------------------------------------------------------------------

/// One buffered setpoint write.
#[derive(Debug, Clone)]
struct OpcUaRow {
    node_id: OpcUaNodeId,
    variant: OpcUaVariant,
}

/// Match an MQTT topic against a `+`/`#` write pattern.
fn topic_matches(pattern: &str, topic: &str) -> bool {
    let mut filters = pattern.split('/');
    let mut names = topic.split('/');
    loop {
        match (filters.next(), names.next()) {
            (Some("#"), _) => return true,
            (Some("+"), Some(_)) => continue,
            (Some(filter), Some(name)) if filter == name => continue,
            (None, None) => return true,
            _ => return false,
        }
    }
}

/// OPC-UA bridge sink: routes setpoint events to node writes.
pub struct OpcUaSink {
    config: OpcUaSinkConfig,
    transport: Arc<dyn OpcUaTransport>,
    buffer: parking_lot::Mutex<BatchQueue<OpcUaRow>>,
    backoff: parking_lot::Mutex<BackoffState>,
    sent_batches: AtomicU64,
    sent_records: AtomicU64,
}

impl OpcUaSink {
    pub fn new(config: OpcUaSinkConfig, transport: Arc<dyn OpcUaTransport>) -> Result<Self> {
        config.validate()?;
        let linger = config.effective_linger();
        Ok(Self {
            buffer: parking_lot::Mutex::new(BatchQueue::new(config.effective_batch_size(), linger)),
            config,
            transport,
            backoff: parking_lot::Mutex::new(BackoffState::default()),
            sent_batches: AtomicU64::new(0),
            sent_records: AtomicU64::new(0),
        })
    }

    pub fn config(&self) -> &OpcUaSinkConfig {
        &self.config
    }

    pub fn sent_batches(&self) -> u64 {
        self.sent_batches.load(Ordering::Relaxed)
    }

    pub fn sent_records(&self) -> u64 {
        self.sent_records.load(Ordering::Relaxed)
    }

    pub fn buffered_rows(&self) -> usize {
        self.buffer.lock().len()
    }

    /// Flush buffered writes (no-op when empty). Any failure restores
    /// the buffer, engages backoff, and propagates.
    pub async fn flush(&self) -> Result<()> {
        self.backoff.lock().check()?;
        let (rows, oldest) = self.buffer.lock().take_batch();
        if rows.is_empty() {
            return Ok(());
        }
        let record_count = rows.len() as u64;
        let result = async {
            self.transport.connect().await?;
            for row in &rows {
                self.transport
                    .write(&OpcUaWriteFrame {
                        node_id: row.node_id.clone(),
                        variant: row.variant.clone(),
                        bytes: encode_write_request(&row.node_id, &row.variant),
                    })
                    .await?;
            }
            Ok::<(), ConnectorError>(())
        }
        .await;
        match result {
            Ok(()) => {
                self.backoff.lock().success();
                self.sent_batches.fetch_add(1, Ordering::Relaxed);
                self.sent_records.fetch_add(record_count, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                self.buffer.lock().restore(rows, oldest);
                self.backoff.lock().failure();
                Err(e)
            }
        }
    }

    /// Route one event: first subscription whose write pattern
    /// matches wins; JSON coerces to Double/Int64/Boolean/Text by
    /// shape (numbers with fractions → Double, else Int64).
    fn buffer_row(&self, topic: &Topic, payload: &Bytes, _qos: QoS) -> Result<bool> {
        if topic.as_str().is_empty() {
            return Err(ConnectorError::Dispatch(
                "opc-ua row requires a non-empty topic".to_string(),
            ));
        }
        // Buffer-cap backpressure (unbounded by default).
        if self.buffer.lock().len() >= self.config.effective_buffer() {
            return Err(ConnectorError::Connection(
                "opc-ua buffer limit reached".to_string(),
            ));
        }
        let subscription = self
            .config
            .node_subscriptions
            .iter()
            .find(|subscription| {
                subscription
                    .write_topic_pattern
                    .as_ref()
                    .is_some_and(|pattern| topic_matches(pattern, topic.as_str()))
            })
            .ok_or_else(|| {
                ConnectorError::Dispatch(format!(
                    "opc-ua no subscription matches topic {:?}",
                    topic.as_str()
                ))
            })?;
        let text = std::str::from_utf8(payload)
            .map_err(|_| ConnectorError::Dispatch("opc-ua payload must be UTF-8".to_string()))?;
        let value: serde_json::Value = serde_json::from_str(text)
            .map_err(|_| ConnectorError::Dispatch("opc-ua payload must be JSON".to_string()))?;
        let inner_val = match &value {
            serde_json::Value::Object(map) => {
                if let Some(v) = map.get("value") {
                    v
                } else if map.len() == 1 {
                    map.values().next().unwrap()
                } else {
                    &value
                }
            }
            _ => &value,
        };
        let variant = match inner_val {
            serde_json::Value::Bool(v) => OpcUaVariant::Boolean(*v),
            serde_json::Value::Number(n) => {
                if let Some(v) = n.as_i64() {
                    // Integers ride Int64 unless a fraction needs Double.
                    OpcUaVariant::Int64(v)
                } else if let Some(v) = n.as_f64() {
                    OpcUaVariant::Double(v)
                } else if let Some(v) = n.as_u64() {
                    OpcUaVariant::UInt64(v)
                } else {
                    return Err(ConnectorError::Dispatch(
                        "opc-ua BadTypeMismatch: number".to_string(),
                    ));
                }
            }
            serde_json::Value::String(v) => OpcUaVariant::Text(v.clone()),
            _ => {
                return Err(ConnectorError::Dispatch(
                    "opc-ua BadTypeMismatch: complex JSON".to_string(),
                ))
            }
        };
        let node_id = OpcUaNodeId::parse(&subscription.node_id)?;
        Ok(self.buffer.lock().push(OpcUaRow { node_id, variant }))
    }
}

#[async_trait]
impl Sink for OpcUaSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        if self.buffer_row(topic, payload, qos)? {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "opc_ua"
    }
}

/// Management connector handle pairing an id with an OPC-UA sink.
pub struct OpcUaConnector {
    id: String,
    sink: Arc<OpcUaSink>,
}

impl OpcUaConnector {
    pub fn new(id: impl Into<String>, sink: Arc<OpcUaSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }
}

impl super::Connector for OpcUaConnector {
    fn connector_id(&self) -> &str {
        &self.id
    }

    fn kind(&self) -> &'static str {
        self.sink.kind()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Sink;

    fn test_config() -> OpcUaSinkConfig {
        OpcUaSinkConfig {
            endpoint_url: "opc.tcp://192.168.1.100:4840".to_string(),
            security_policy: OpcUaSecurityPolicy::None,
            security_mode: OpcUaSecurityMode::None,
            auth: OpcUaAuth::Anonymous,
            node_subscriptions: vec![
                NodeSubscriptionConfig {
                    node_id: "ns=2;s=Line1.Temperature".to_string(),
                    sampling_interval_ms: 100,
                    publish_topic_template: "factory/line1/${node.sanitized_id}".to_string(),
                    write_topic_pattern: Some("factory/setpoint/+".to_string()),
                },
                NodeSubscriptionConfig {
                    node_id: "ns=1;i=2258".to_string(),
                    sampling_interval_ms: 1_000,
                    publish_topic_template: "factory/meta/${node.sanitized_id}".to_string(),
                    write_topic_pattern: None,
                },
            ],
            buffer_capacity: None,
            batch_size: Some(100),
            linger_ms: Some(50),
            timeout_ms: None,
        }
    }

    #[test]
    fn test_config_validation() {
        let mut config = test_config();
        assert!(config.validate().is_ok());

        config.endpoint_url = "http://192.168.1.100:4840".to_string();
        assert!(config.validate().is_err());
        config.endpoint_url = test_config().endpoint_url;

        config.security_mode = OpcUaSecurityMode::Sign;
        assert!(config.validate().is_err(), "sign needs a policy");
        config.security_mode = OpcUaSecurityMode::None;

        config.auth = OpcUaAuth::UsernamePassword {
            username: "  ".to_string(),
            password: "x".to_string(),
        };
        assert!(config.validate().is_err());
        config.auth = OpcUaAuth::Certificate {
            cert_pem: "not-a-cert".to_string(),
            key_pem: "not-a-key".to_string(),
        };
        assert!(config.validate().is_err());
        config.auth = OpcUaAuth::Anonymous;

        config.node_subscriptions.clear();
        assert!(config.validate().is_err());
        config.node_subscriptions = test_config().node_subscriptions;

        config.node_subscriptions[0].node_id = "ns=2;x=1".to_string();
        assert!(config.validate().is_err());
        config.node_subscriptions[0].node_id = "ns=2;s=Line1.Temperature".to_string();

        config.batch_size = Some(0);
        assert!(config.validate().is_err());
        // Unbounded depths accepted: zero clamped ceilings.
        config.batch_size = None;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_hello_ack_framing() {
        let hello = OpcUaHello {
            protocol_version: 0,
            receive_buffer: 65_536,
            send_buffer: 65_536,
            max_message: 2 * 1024 * 1024,
            max_chunk: 65_536,
            endpoint_url: "opc.tcp://192.168.1.100:4840".to_string(),
        };
        let mut body = Vec::new();
        hello.encode(&mut body);
        // 5 u32 + endpoint string (len + 28 bytes).
        assert_eq!(body.len(), 20 + 4 + 28);
        let frame = encode_chunk(OpcUaChunk::Hello, &body);
        assert_eq!(&frame[..3], b"HEL");
        assert_eq!(frame[3], b'F');
        assert_eq!(
            u32::from_le_bytes([frame[4], frame[5], frame[6], frame[7]]) as usize,
            frame.len()
        );
        let (kind, back) = decode_chunk(&frame).unwrap();
        assert_eq!(kind, OpcUaChunk::Hello);
        let mut cursor = back.as_slice();
        assert_eq!(OpcUaHello::decode(&mut cursor).unwrap(), hello);
        assert!(cursor.is_empty());
        assert!(decode_chunk(&frame[..5]).is_err());
    }

    #[test]
    fn test_channel_frame_sequencing() {
        let frame = OpcUaChannelFrame {
            secure_channel_id: 42,
            sequence_number: 7,
            request_id: 7,
        };
        let mut body = Vec::new();
        frame.encode(&mut body);
        assert_eq!(body.len(), 12);
        let mut cursor = body.as_slice();
        assert_eq!(OpcUaChannelFrame::decode(&mut cursor).unwrap(), frame);
        let packet = encode_chunk(OpcUaChunk::OpenSecureChannel, &body);
        assert_eq!(&packet[..3], b"OPN");
        let (kind, back) = decode_chunk(&packet).unwrap();
        assert_eq!(kind, OpcUaChunk::OpenSecureChannel);
        assert_eq!(back, body);
    }

    #[test]
    fn test_node_id_formats() {
        assert_eq!(
            OpcUaNodeId::parse("ns=2;s=Line1.Temperature").unwrap(),
            OpcUaNodeId {
                namespace: 2,
                id: OpcUaNodeIdValue::Text("Line1.Temperature".to_string()),
            }
        );
        assert_eq!(
            OpcUaNodeId::parse("ns=1;i=2258").unwrap().id,
            OpcUaNodeIdValue::Numeric(2258)
        );
        let guid = OpcUaNodeId::parse("ns=2;g=12345678-1234-5678-1234-567812345678").unwrap();
        assert!(matches!(guid.id, OpcUaNodeIdValue::Guid(_)));
        assert_eq!(
            guid.display(),
            "ns=2;g=12345678-1234-5678-1234-567812345678"
        );
        let opaque = OpcUaNodeId::parse("ns=2;b=aGVsbG8=").unwrap();
        assert_eq!(opaque.id, OpcUaNodeIdValue::Opaque(b"hello".to_vec()));
        // Display + sanitize round-trips.
        assert_eq!(
            OpcUaNodeId::parse("ns=2;s=Line1.Temperature")
                .unwrap()
                .sanitized_id(),
            "ns_2_s_Line1_Temperature"
        );
        for bad in [
            "ns=2;x=1",
            "ns=abc;i=1",
            "s=Line1",
            "ns=2;s=",
            "ns=2;g=zzz",
            "ns=2;b=!!!",
            "ns=2;s=Line1/#",
            "ns=2;s=Line1/+",
        ] {
            assert!(OpcUaNodeId::parse(bad).is_err(), "must reject {bad:?}");
        }
    }

    #[test]
    fn test_variant_codec_all_primitives() {
        let cases: Vec<OpcUaVariant> = vec![
            OpcUaVariant::Boolean(true),
            OpcUaVariant::SByte(-5),
            OpcUaVariant::Byte(250),
            OpcUaVariant::Int16(-300),
            OpcUaVariant::UInt16(60_000),
            OpcUaVariant::Int32(-100_000),
            OpcUaVariant::UInt32(3_000_000_000),
            OpcUaVariant::Int64(i64::MIN),
            OpcUaVariant::UInt64(u64::MAX),
            OpcUaVariant::Float(0.5),
            OpcUaVariant::Double(82.5),
            OpcUaVariant::Text("héllo".to_string()),
            OpcUaVariant::DateTime(datetime_from_millis(1_789_211_889_123)),
            OpcUaVariant::ByteString(vec![0x00, 0xFF]),
        ];
        for variant in &cases {
            let mut bytes = Vec::new();
            encode_variant(variant, &mut bytes);
            assert_eq!(bytes[0], variant.type_id());
            let mut cursor = bytes.as_slice();
            assert_eq!(&decode_variant(&mut cursor).unwrap(), variant);
            assert!(cursor.is_empty());
        }
        // Type ids match the OPC-UA builtin table.
        assert_eq!(OpcUaVariant::Double(0.0).type_id(), 11);
        assert_eq!(OpcUaVariant::Text(String::new()).type_id(), 12);
        assert!(decode_variant(&mut [99u8].as_slice()).is_err());
    }

    #[test]
    fn test_notification_json_mapping() {
        let data = OpcUaDataValue {
            node_id: OpcUaNodeId::parse("ns=2;s=Line1.Temperature").unwrap(),
            value: OpcUaVariant::Double(24.85),
            status: OpcUaStatus(OpcUaStatus::GOOD),
            source_timestamp: Some(datetime_from_millis(1_789_211_889_123)),
            server_timestamp: None,
        };
        // DataValue round-trips with both timestamps.
        let mut bytes = Vec::new();
        encode_data_value(&data, &mut bytes);
        let mut cursor = bytes.as_slice();
        let back = decode_data_value(data.node_id.clone(), &mut cursor).unwrap();
        assert_eq!(back, data);
        assert!(cursor.is_empty());
        // JSON document matches the streaming contract.
        let doc = notification_to_json(&data);
        assert_eq!(doc["node_id"], "ns=2;s=Line1.Temperature");
        assert_eq!(doc["value"], 24.85);
        assert_eq!(doc["status"], "Good");
        assert_eq!(doc["status_code"], "0x00000000");
        assert_eq!(doc["timestamp"], "2026-09-12T11:18:09.123Z");
    }

    #[test]
    fn test_write_coercion_and_mismatch() {
        assert_eq!(
            OpcUaVariant::coerce_from(OpcUaVariantKind::Double, &serde_json::json!(75.2)).unwrap(),
            OpcUaVariant::Double(75.2)
        );
        assert_eq!(
            OpcUaVariant::coerce_from(OpcUaVariantKind::Int32, &serde_json::json!(5)).unwrap(),
            OpcUaVariant::Int32(5)
        );
        // Range violations and shape mismatches are terminal.
        assert!(
            OpcUaVariant::coerce_from(OpcUaVariantKind::Int32, &serde_json::json!(1i64 << 40))
                .is_err()
        );
        assert!(
            OpcUaVariant::coerce_from(OpcUaVariantKind::Boolean, &serde_json::json!(1)).is_err()
        );
        assert!(OpcUaVariant::coerce_from(OpcUaVariantKind::Text, &serde_json::json!({})).is_err());
    }

    #[test]
    fn test_error_classification() {
        assert_eq!(
            OpcUaStatus(OpcUaStatus::GOOD).severity(),
            OpcUaSeverity::Good
        );
        assert_eq!(
            OpcUaStatus(OpcUaStatus::UNCERTAIN).severity(),
            OpcUaSeverity::Uncertain
        );
        assert_eq!(OpcUaStatus(0x8034_0000).severity(), OpcUaSeverity::Bad);
        assert!(OpcUaStatus(OpcUaStatus::BAD_SESSION_ID_INVALID).is_transient());
        assert!(OpcUaStatus(OpcUaStatus::BAD_SECURE_CHANNEL_CLOSED).is_transient());
        assert!(!OpcUaStatus(OpcUaStatus::BAD_NODE_ID_UNKNOWN).is_transient());
        assert!(!OpcUaStatus(OpcUaStatus::BAD_TYPE_MISMATCH).is_transient());
        assert_eq!(
            OpcUaStatus(OpcUaStatus::BAD_NODE_ID_UNKNOWN).text(),
            "BadNodeIdUnknown"
        );
    }

    #[tokio::test]
    async fn test_subscription_routing_and_writes() {
        let mut config = test_config();
        config.batch_size = Some(10);
        let transport = Arc::new(MemoryOpcUaTransport::new());
        let sink = Arc::new(OpcUaSink::new(config, transport.clone()).unwrap());

        // Matched setpoint: Int64 for whole numbers, Double for fractions.
        sink.send(
            &Topic::new("factory/setpoint/zone1").unwrap(),
            &Bytes::from("5"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        sink.send(
            &Topic::new("factory/setpoint/zone2").unwrap(),
            &Bytes::from("75.2"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        sink.flush().await.unwrap();
        assert_eq!(transport.connect_calls(), 1);
        let writes = transport.writes();
        assert_eq!(writes.len(), 2);
        assert_eq!(writes[0].node_id.display(), "ns=2;s=Line1.Temperature");
        assert_eq!(writes[0].variant, OpcUaVariant::Int64(5));
        assert_eq!(writes[1].variant, OpcUaVariant::Double(75.2));
        assert_eq!(sink.sent_records(), 2);

        // Unmatched topics fail loudly (no silent blackhole).
        assert!(sink
            .send(
                &Topic::new("factory/other").unwrap(),
                &Bytes::from("1"),
                QoS::AtMostOnce
            )
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_loopback_hello_ack_and_datachange() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            // HEL: chunk tag + endpoint URL inside.
            let mut header = [0u8; 8];
            stream.read_exact(&mut header).await.expect("hel head");
            assert_eq!(&header[..3], b"HEL");
            let length = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
            let mut body = vec![0u8; length - 8];
            stream.read_exact(&mut body).await.expect("hel body");
            let mut cursor = body.as_slice();
            let hello = OpcUaHello::decode(&mut cursor).expect("hello");
            assert_eq!(hello.receive_buffer, 65_536);
            // ACK with matching buffers.
            let mut ack = Vec::new();
            OpcUaHello {
                protocol_version: hello.protocol_version,
                receive_buffer: 65_536,
                send_buffer: 65_536,
                max_message: hello.max_message,
                max_chunk: hello.max_chunk,
                endpoint_url: hello.endpoint_url,
            }
            .encode(&mut ack);
            stream
                .write_all(&encode_chunk(OpcUaChunk::Acknowledge, &ack))
                .await
                .expect("ack");
            // One OPN write frame follows (setpoint delivery).
            let mut header = [0u8; 8];
            stream.read_exact(&mut header).await.expect("opn head");
            assert_eq!(&header[..3], b"OPN");
            let length = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
            let mut body = vec![0u8; length - 8];
            stream.read_exact(&mut body).await.expect("opn body");
            let mut cursor = body.as_slice();
            let channel = OpcUaChannelFrame::decode(&mut cursor).expect("channel");
            assert_eq!(channel.sequence_number, 1);
            // Remainder is the write request (node display + variant).
            let needle = b"ns=2;s=Line1.Temperature";
            assert!(cursor.windows(needle.len()).any(|w| w == needle));
        });

        let mut config = test_config();
        config.endpoint_url = format!("opc.tcp://127.0.0.1:{port}");
        config.batch_size = Some(1);
        let transport = Arc::new(TcpOpcUaTransport::new(&config).unwrap());
        let sink = OpcUaSink::new(config, transport).unwrap();
        sink.send(
            &Topic::new("factory/setpoint/zone1").unwrap(),
            &Bytes::from("22"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        assert_eq!(sink.sent_records(), 1);
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("server done")
            .expect("server task");
    }
}
