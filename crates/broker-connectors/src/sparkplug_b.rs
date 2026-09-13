//! Eclipse Tahu Sparkplug B codec, state machine and sink (INDRA-202).
//!
//! Industrial IoT (SCADA/PLC/MES) support: Sparkplug namespace parsing
//! (`spBv1.0/<group>/<type>/<edge>[/<device>]`), a clean-room Protobuf
//! wire codec for Payload/Metric messages, bidirectional translation to
//! normalized JSON documents (so Rekuiper SQL rules run directly on
//! Sparkplug telemetry), and an edge/node state machine tracking
//! online status, birth alias caches and cyclical sequence health.
//!
//! Tier classification: Sparkplug processing is an Enterprise
//! capability, gated under `RuleTier::Enterprise` in broker-rules
//! (see [`SPARKPLUG_TIER`]); Community deployments must not register
//! `sparkplug_b` connectors.
//!
//! Protobuf field mapping (Tahu-compatible subset):
//! Payload: `timestamp = 1` (varint), `metrics = 2` (repeated LEN),
//! `seq = 3` (varint), `uuid = 4` (string), `body = 5` (bytes).
//! Metric: `name = 1`, `alias = 2` (varint), `timestamp = 3` (varint),
//! `datatype = 4` (varint enum), values `int = 10` (varint, two's
//! complement), `uint = 11` (varint), `float = 12` (fixed32),
//! `double = 13` (fixed64), `boolean = 14` (varint), `string = 15`
//! (LEN), `bytes = 16` (LEN).

use async_trait::async_trait;
use base64::Engine;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use super::{BatchQueue, ConnectorError, Result, Sink};
use std::time::Duration;

/// Tier gate for Sparkplug processing: Enterprise only.
pub const SPARKPLUG_TIER: &str = "enterprise";

/// Enterprise tier marker for Sparkplug components.
pub fn tier() -> &'static str {
    SPARKPLUG_TIER
}

// ---------------------------------------------------------------------------
// Namespace.
// ---------------------------------------------------------------------------

/// Sparkplug B message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SparkplugMessageType {
    NBirth,
    NDeath,
    NData,
    NCmd,
    DBirth,
    DDeath,
    DData,
    DCmd,
    State,
}

impl SparkplugMessageType {
    fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "NBIRTH" => Self::NBirth,
            "NDEATH" => Self::NDeath,
            "NDATA" => Self::NData,
            "NCMD" => Self::NCmd,
            "DBIRTH" => Self::DBirth,
            "DDEATH" => Self::DDeath,
            "DDATA" => Self::DData,
            "DCMD" => Self::DCmd,
            "STATE" => Self::State,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::NBirth => "NBIRTH",
            Self::NDeath => "NDEATH",
            Self::NData => "NDATA",
            Self::NCmd => "NCMD",
            Self::DBirth => "DBIRTH",
            Self::DDeath => "DDEATH",
            Self::DData => "DDATA",
            Self::DCmd => "DCMD",
            Self::State => "STATE",
        }
    }

    /// True for device-scoped types (require a device id).
    pub fn is_device(self) -> bool {
        matches!(self, Self::DBirth | Self::DDeath | Self::DData | Self::DCmd)
    }

    /// True for birth messages (populate alias caches).
    pub fn is_birth(self) -> bool {
        matches!(self, Self::NBirth | Self::DBirth)
    }

    /// True for death messages (invalidate state).
    pub fn is_death(self) -> bool {
        matches!(self, Self::NDeath | Self::DDeath)
    }

    /// True for data messages (alias resolution applies).
    pub fn is_data(self) -> bool {
        matches!(self, Self::NData | Self::DData)
    }
}

/// Parsed Sparkplug B topic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparkplugTopic {
    pub group_id: String,
    /// Edge node id, or the host id for `STATE` messages.
    pub edge_node_id: String,
    pub device_id: Option<String>,
    pub message_type: SparkplugMessageType,
}

impl SparkplugTopic {
    /// Parse and validate: `spBv1.0/<group>/<type>/<edge>[/<device>]`
    /// (STATE uses `spBv1.0/STATE/<host>`). Rejects wildcards, wrong
    /// namespaces, unknown types and device/arity mismatches.
    pub fn parse(topic: &str) -> Result<Self> {
        if topic.contains('+') || topic.contains('#') {
            return Err(ConnectorError::Dispatch(format!(
                "sparkplug topic must be concrete: {topic:?}"
            )));
        }
        let parts: Vec<&str> = topic.split('/').collect();
        if parts.len() < 3 || parts[0] != "spBv1.0" {
            return Err(ConnectorError::Dispatch(format!(
                "sparkplug topic must start with spBv1.0: {topic:?}"
            )));
        }
        if parts.iter().any(|part| part.is_empty()) {
            return Err(ConnectorError::Dispatch(format!(
                "sparkplug topic has empty components: {topic:?}"
            )));
        }
        // Host state: exactly spBv1.0/STATE/<host_id>.
        if parts[1] == "STATE" {
            if parts.len() != 3 {
                return Err(ConnectorError::Dispatch(format!(
                    "sparkplug STATE must be spBv1.0/STATE/<host_id>: {topic:?}"
                )));
            }
            return Ok(Self {
                group_id: "STATE".to_string(),
                edge_node_id: parts[2].to_string(),
                device_id: None,
                message_type: SparkplugMessageType::State,
            });
        }
        let message_type = SparkplugMessageType::parse(parts[2]).ok_or_else(|| {
            ConnectorError::Dispatch(format!("sparkplug unknown message type in {topic:?}"))
        })?;
        if message_type == SparkplugMessageType::State {
            return Err(ConnectorError::Dispatch(format!(
                "sparkplug STATE must be spBv1.0/STATE/<host_id>: {topic:?}"
            )));
        }
        match (message_type.is_device(), parts.len()) {
            (false, 4) => Ok(Self {
                group_id: parts[1].to_string(),
                edge_node_id: parts[3].to_string(),
                device_id: None,
                message_type,
            }),
            (true, 5) => Ok(Self {
                group_id: parts[1].to_string(),
                edge_node_id: parts[3].to_string(),
                device_id: Some(parts[4].to_string()),
                message_type,
            }),
            (false, _) => Err(ConnectorError::Dispatch(format!(
                "sparkplug {} takes no device id: {topic:?}",
                message_type.as_str()
            ))),
            (true, _) => Err(ConnectorError::Dispatch(format!(
                "sparkplug {} requires a device id: {topic:?}",
                message_type.as_str()
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// Protobuf wire codec (clean-room).
// ---------------------------------------------------------------------------

const WIRE_VARINT: u32 = 0;
const WIRE_FIXED64: u32 = 1;
const WIRE_LEN: u32 = 2;
const WIRE_FIXED32: u32 = 5;

/// Append a varint-encoded u64.
pub fn encode_varint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Decode a varint, returning (value, bytes used).
pub fn decode_varint(buf: &[u8]) -> Result<(u64, usize)> {
    let mut value = 0u64;
    for (index, byte) in buf.iter().take(10).enumerate() {
        let bits = (byte & 0x7F) as u64;
        if index == 9 && bits > 1 {
            return Err(ConnectorError::Dispatch(
                "sparkplug varint overflow".to_string(),
            ));
        }
        value |= bits << (7 * index);
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
    }
    Err(ConnectorError::Dispatch(
        "sparkplug truncated varint".to_string(),
    ))
}

fn encode_tag(field: u32, wire: u32, out: &mut Vec<u8>) {
    encode_varint((u64::from(field) << 3) | u64::from(wire), out);
}

fn decode_tag(buf: &[u8]) -> Result<((u32, u32), usize)> {
    let (tag, used) = decode_varint(buf)?;
    Ok((((tag >> 3) as u32, (tag & 0x07) as u32), used))
}

/// Skip one field of `wire` type, returning bytes consumed.
fn skip_field(buf: &[u8], wire: u32) -> Result<usize> {
    match wire {
        WIRE_VARINT => Ok(decode_varint(buf)?.1),
        WIRE_FIXED64 => {
            if buf.len() < 8 {
                return Err(ConnectorError::Dispatch(
                    "sparkplug truncated fixed64".to_string(),
                ));
            }
            Ok(8)
        }
        WIRE_LEN => {
            let (len, used) = decode_varint(buf)?;
            let len = len as usize;
            if buf.len() < used + len {
                return Err(ConnectorError::Dispatch(
                    "sparkplug truncated length-delimited".to_string(),
                ));
            }
            Ok(used + len)
        }
        WIRE_FIXED32 => {
            if buf.len() < 4 {
                return Err(ConnectorError::Dispatch(
                    "sparkplug truncated fixed32".to_string(),
                ));
            }
            Ok(4)
        }
        _ => Err(ConnectorError::Dispatch(format!(
            "sparkplug unsupported wire type {wire}"
        ))),
    }
}

fn read_len(buf: &[u8]) -> Result<(&[u8], usize)> {
    let (len, used) = decode_varint(buf)?;
    let len = len as usize;
    if buf.len() < used + len {
        return Err(ConnectorError::Dispatch(
            "sparkplug truncated length-delimited".to_string(),
        ));
    }
    Ok((&buf[used..used + len], used + len))
}

/// Sparkplug metric datatypes (Tahu subset).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[repr(u32)]
pub enum SpbDataType {
    #[default]
    Unknown = 0,
    Int8 = 1,
    Int16 = 2,
    Int32 = 3,
    Int64 = 4,
    UInt8 = 5,
    UInt16 = 6,
    UInt32 = 7,
    UInt64 = 8,
    Float = 9,
    Double = 10,
    Boolean = 11,
    String = 12,
    Bytes = 17,
}

impl SpbDataType {
    fn from_u32(value: u32) -> Self {
        match value {
            1 => Self::Int8,
            2 => Self::Int16,
            3 => Self::Int32,
            4 => Self::Int64,
            5 => Self::UInt8,
            6 => Self::UInt16,
            7 => Self::UInt32,
            8 => Self::UInt64,
            9 => Self::Float,
            10 => Self::Double,
            11 => Self::Boolean,
            12 => Self::String,
            17 => Self::Bytes,
            _ => Self::Unknown,
        }
    }

    /// Bit width for integer truncation (None for non-integers).
    fn int_width(self) -> Option<u32> {
        match self {
            Self::Int8 | Self::UInt8 => Some(8),
            Self::Int16 | Self::UInt16 => Some(16),
            Self::Int32 | Self::UInt32 => Some(32),
            Self::Int64 | Self::UInt64 => Some(64),
            _ => None,
        }
    }

    fn is_signed(self) -> bool {
        matches!(self, Self::Int8 | Self::Int16 | Self::Int32 | Self::Int64)
    }
}

/// Typed metric value.
#[derive(Debug, Clone, PartialEq)]
pub enum SpbValue {
    Int(i64),
    UInt(u64),
    Float(f32),
    Double(f64),
    Bool(bool),
    Text(String),
    Bytes(Vec<u8>),
    Null,
}

impl SpbValue {
    /// JSON projection of the value (bytes ride base64).
    fn to_json(&self) -> serde_json::Value {
        match self {
            Self::Int(v) => serde_json::json!(*v),
            Self::UInt(v) => serde_json::json!(*v),
            Self::Float(v) => serde_json::json!(*v),
            Self::Double(v) => serde_json::json!(*v),
            Self::Bool(v) => serde_json::json!(*v),
            Self::Text(v) => serde_json::json!(v),
            Self::Bytes(v) => {
                serde_json::json!(base64::engine::general_purpose::STANDARD.encode(v))
            }
            Self::Null => serde_json::Value::Null,
        }
    }

    /// Infer (datatype, value) from a JSON value for normalized encoding.
    fn from_json(value: &serde_json::Value) -> (SpbDataType, SpbValue) {
        match value {
            serde_json::Value::Number(n) => {
                if let Some(v) = n.as_i64() {
                    (SpbDataType::Int64, SpbValue::Int(v))
                } else if let Some(v) = n.as_u64() {
                    (SpbDataType::UInt64, SpbValue::UInt(v))
                } else if let Some(v) = n.as_f64() {
                    (SpbDataType::Double, SpbValue::Double(v))
                } else {
                    (SpbDataType::Unknown, SpbValue::Null)
                }
            }
            serde_json::Value::Bool(v) => (SpbDataType::Boolean, SpbValue::Bool(*v)),
            serde_json::Value::String(v) => (SpbDataType::String, SpbValue::Text(v.clone())),
            serde_json::Value::Null => (SpbDataType::Unknown, SpbValue::Null),
            other => (SpbDataType::String, SpbValue::Text(other.to_string())),
        }
    }
}

/// One Sparkplug metric.
#[derive(Debug, Clone, PartialEq)]
pub struct SpbMetric {
    pub name: Option<String>,
    pub alias: Option<u64>,
    pub timestamp: Option<u64>,
    pub datatype: SpbDataType,
    pub value: SpbValue,
}

/// One Sparkplug payload.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SpbPayload {
    pub timestamp: Option<u64>,
    pub metrics: Vec<SpbMetric>,
    pub seq: Option<u64>,
    pub uuid: Option<String>,
    pub body: Option<Vec<u8>>,
}

/// Encode one metric into `out`.
pub fn encode_metric(metric: &SpbMetric, out: &mut Vec<u8>) {
    if let Some(name) = &metric.name {
        encode_tag(1, WIRE_LEN, out);
        encode_varint(name.len() as u64, out);
        out.extend_from_slice(name.as_bytes());
    }
    if let Some(alias) = metric.alias {
        encode_tag(2, WIRE_VARINT, out);
        encode_varint(alias, out);
    }
    if let Some(timestamp) = metric.timestamp {
        encode_tag(3, WIRE_VARINT, out);
        encode_varint(timestamp, out);
    }
    encode_tag(4, WIRE_VARINT, out);
    encode_varint(metric.datatype as u64, out);
    match &metric.value {
        SpbValue::Int(v) => {
            encode_tag(10, WIRE_VARINT, out);
            encode_varint(*v as u64, out);
        }
        SpbValue::UInt(v) => {
            encode_tag(11, WIRE_VARINT, out);
            encode_varint(*v, out);
        }
        SpbValue::Float(v) => {
            encode_tag(12, WIRE_FIXED32, out);
            out.extend_from_slice(&v.to_le_bytes());
        }
        SpbValue::Double(v) => {
            encode_tag(13, WIRE_FIXED64, out);
            out.extend_from_slice(&v.to_le_bytes());
        }
        SpbValue::Bool(v) => {
            encode_tag(14, WIRE_VARINT, out);
            encode_varint(u64::from(*v), out);
        }
        SpbValue::Text(v) => {
            encode_tag(15, WIRE_LEN, out);
            encode_varint(v.len() as u64, out);
            out.extend_from_slice(v.as_bytes());
        }
        SpbValue::Bytes(v) => {
            encode_tag(16, WIRE_LEN, out);
            encode_varint(v.len() as u64, out);
            out.extend_from_slice(v);
        }
        SpbValue::Null => {}
    }
}

/// Raw value fields seen while decoding one metric.
#[derive(Default)]
struct RawMetricValue {
    int: Option<u64>,
    uint: Option<u64>,
    float_bits: Option<u32>,
    double_bits: Option<u64>,
    boolean: Option<u64>,
    text: Option<Vec<u8>>,
    bytes: Option<Vec<u8>>,
}

/// Decode one metric from `buf`, returning (metric, bytes used).
pub fn decode_metric(buf: &[u8]) -> Result<(SpbMetric, usize)> {
    let mut cursor = buf;
    let mut name = None;
    let mut alias = None;
    let mut timestamp = None;
    let mut datatype = SpbDataType::Unknown;
    let mut raw = RawMetricValue::default();
    while !cursor.is_empty() {
        let ((field, wire), used) = decode_tag(cursor)?;
        cursor = &cursor[used..];
        match (field, wire) {
            (1, WIRE_LEN) => {
                let (bytes, used) = read_len(cursor)?;
                name = Some(
                    std::str::from_utf8(bytes)
                        .map_err(|_| {
                            ConnectorError::Dispatch("sparkplug metric name not UTF-8".to_string())
                        })?
                        .to_string(),
                );
                cursor = &cursor[used..];
            }
            (2, WIRE_VARINT) => {
                let (value, used) = decode_varint(cursor)?;
                alias = Some(value);
                cursor = &cursor[used..];
            }
            (3, WIRE_VARINT) => {
                let (value, used) = decode_varint(cursor)?;
                timestamp = Some(value);
                cursor = &cursor[used..];
            }
            (4, WIRE_VARINT) => {
                let (value, used) = decode_varint(cursor)?;
                datatype = SpbDataType::from_u32(value as u32);
                cursor = &cursor[used..];
            }
            (10, WIRE_VARINT) => {
                let (value, used) = decode_varint(cursor)?;
                raw.int = Some(value);
                cursor = &cursor[used..];
            }
            (11, WIRE_VARINT) => {
                let (value, used) = decode_varint(cursor)?;
                raw.uint = Some(value);
                cursor = &cursor[used..];
            }
            (12, WIRE_FIXED32) => {
                if cursor.len() < 4 {
                    return Err(ConnectorError::Dispatch(
                        "sparkplug truncated float".to_string(),
                    ));
                }
                raw.float_bits = Some(u32::from_le_bytes([
                    cursor[0], cursor[1], cursor[2], cursor[3],
                ]));
                cursor = &cursor[4..];
            }
            (13, WIRE_FIXED64) => {
                if cursor.len() < 8 {
                    return Err(ConnectorError::Dispatch(
                        "sparkplug truncated double".to_string(),
                    ));
                }
                raw.double_bits = Some(u64::from_le_bytes([
                    cursor[0], cursor[1], cursor[2], cursor[3], cursor[4], cursor[5], cursor[6],
                    cursor[7],
                ]));
                cursor = &cursor[8..];
            }
            (14, WIRE_VARINT) => {
                let (value, used) = decode_varint(cursor)?;
                raw.boolean = Some(value);
                cursor = &cursor[used..];
            }
            (15, WIRE_LEN) => {
                let (bytes, used) = read_len(cursor)?;
                raw.text = Some(bytes.to_vec());
                cursor = &cursor[used..];
            }
            (16, WIRE_LEN) => {
                let (bytes, used) = read_len(cursor)?;
                raw.bytes = Some(bytes.to_vec());
                cursor = &cursor[used..];
            }
            _ => {
                let used = skip_field(cursor, wire)?;
                cursor = &cursor[used..];
            }
        }
    }
    let consumed = buf.len() - cursor.len();
    Ok((
        SpbMetric {
            name,
            alias,
            timestamp,
            datatype,
            value: resolve_value(datatype, &raw)?,
        },
        consumed,
    ))
}

/// Resolve the typed value from the datatype, falling back to any
/// value field actually present.
fn resolve_value(datatype: SpbDataType, raw: &RawMetricValue) -> Result<SpbValue> {
    let truncate = |value: u64| -> u64 {
        match datatype.int_width() {
            Some(64) | None => value,
            Some(width) => value & (u64::MAX >> (64 - width)),
        }
    };
    if datatype.is_signed() || matches!(datatype, SpbDataType::Unknown) {
        if let Some(value) = raw.int {
            let width = datatype.int_width().unwrap_or(64);
            let truncated = truncate(value);
            let signed = if width == 64 {
                truncated as i64
            } else {
                ((truncated << (64 - width)) as i64) >> (64 - width)
            };
            return Ok(SpbValue::Int(signed));
        }
    }
    if matches!(
        datatype,
        SpbDataType::UInt8
            | SpbDataType::UInt16
            | SpbDataType::UInt32
            | SpbDataType::UInt64
            | SpbDataType::Unknown
    ) {
        if let Some(value) = raw.uint {
            return Ok(SpbValue::UInt(truncate(value)));
        }
    }
    match datatype {
        SpbDataType::Float => {
            if let Some(bits) = raw.float_bits {
                return Ok(SpbValue::Float(f32::from_bits(bits)));
            }
        }
        SpbDataType::Double => {
            if let Some(bits) = raw.double_bits {
                return Ok(SpbValue::Double(f64::from_bits(bits)));
            }
        }
        SpbDataType::Boolean => {
            if let Some(value) = raw.boolean {
                return Ok(SpbValue::Bool(value != 0));
            }
        }
        SpbDataType::String => {
            if let Some(bytes) = &raw.text {
                return Ok(SpbValue::Text(
                    std::str::from_utf8(bytes)
                        .map_err(|_| {
                            ConnectorError::Dispatch("sparkplug string not UTF-8".to_string())
                        })?
                        .to_string(),
                ));
            }
        }
        SpbDataType::Bytes => {
            if let Some(bytes) = &raw.bytes {
                return Ok(SpbValue::Bytes(bytes.clone()));
            }
        }
        _ => {}
    }
    // Fallback: any value field present, best effort.
    if let Some(value) = raw.int {
        return Ok(SpbValue::Int(value as i64));
    }
    if let Some(value) = raw.uint {
        return Ok(SpbValue::UInt(value));
    }
    if let Some(bits) = raw.float_bits {
        return Ok(SpbValue::Float(f32::from_bits(bits)));
    }
    if let Some(bits) = raw.double_bits {
        return Ok(SpbValue::Double(f64::from_bits(bits)));
    }
    if let Some(value) = raw.boolean {
        return Ok(SpbValue::Bool(value != 0));
    }
    if let Some(bytes) = &raw.text {
        return Ok(SpbValue::Text(String::from_utf8_lossy(bytes).into_owned()));
    }
    if let Some(bytes) = &raw.bytes {
        return Ok(SpbValue::Bytes(bytes.clone()));
    }
    Ok(SpbValue::Null)
}

/// Encode one payload to Protobuf binary.
pub fn encode_payload(payload: &SpbPayload) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(timestamp) = payload.timestamp {
        encode_tag(1, WIRE_VARINT, &mut out);
        encode_varint(timestamp, &mut out);
    }
    for metric in &payload.metrics {
        let mut nested = Vec::new();
        encode_metric(metric, &mut nested);
        encode_tag(2, WIRE_LEN, &mut out);
        encode_varint(nested.len() as u64, &mut out);
        out.extend_from_slice(&nested);
    }
    if let Some(seq) = payload.seq {
        encode_tag(3, WIRE_VARINT, &mut out);
        encode_varint(seq, &mut out);
    }
    if let Some(uuid) = &payload.uuid {
        encode_tag(4, WIRE_LEN, &mut out);
        encode_varint(uuid.len() as u64, &mut out);
        out.extend_from_slice(uuid.as_bytes());
    }
    if let Some(body) = &payload.body {
        encode_tag(5, WIRE_LEN, &mut out);
        encode_varint(body.len() as u64, &mut out);
        out.extend_from_slice(body);
    }
    out
}

/// Decode Protobuf binary into a payload (empty input decodes to a
/// default payload so bare DDEATH frames still process).
pub fn decode_payload(buf: &[u8]) -> Result<SpbPayload> {
    let mut payload = SpbPayload::default();
    let mut cursor = buf;
    while !cursor.is_empty() {
        let ((field, wire), used) = decode_tag(cursor)?;
        cursor = &cursor[used..];
        match (field, wire) {
            (1, WIRE_VARINT) => {
                let (value, used) = decode_varint(cursor)?;
                payload.timestamp = Some(value);
                cursor = &cursor[used..];
            }
            (2, WIRE_LEN) => {
                let (nested, used) = read_len(cursor)?;
                let (metric, _) = decode_metric(nested)?;
                payload.metrics.push(metric);
                cursor = &cursor[used..];
            }
            (3, WIRE_VARINT) => {
                let (value, used) = decode_varint(cursor)?;
                payload.seq = Some(value);
                cursor = &cursor[used..];
            }
            (4, WIRE_LEN) => {
                let (bytes, used) = read_len(cursor)?;
                payload.uuid = Some(
                    std::str::from_utf8(bytes)
                        .map_err(|_| {
                            ConnectorError::Dispatch("sparkplug uuid not UTF-8".to_string())
                        })?
                        .to_string(),
                );
                cursor = &cursor[used..];
            }
            (5, WIRE_LEN) => {
                let (bytes, used) = read_len(cursor)?;
                payload.body = Some(bytes.to_vec());
                cursor = &cursor[used..];
            }
            _ => {
                let used = skip_field(cursor, wire)?;
                cursor = &cursor[used..];
            }
        }
    }
    Ok(payload)
}

// ---------------------------------------------------------------------------
// Normalized JSON translation.
// ---------------------------------------------------------------------------

/// Decodeed metric key: the name, else `alias:<n>` for resolution by
/// the state machine or downstream rules.
fn metric_key(metric: &SpbMetric) -> String {
    match &metric.name {
        Some(name) => name.clone(),
        None => match metric.alias {
            Some(alias) => format!("alias:{alias}"),
            None => "metric:?".to_string(),
        },
    }
}

/// Translate a decoded payload into the normalized JSON document that
/// Rekuiper SQL rules evaluate (`metrics.<Name>` paths).
pub fn payload_to_json(topic: &SparkplugTopic, payload: &SpbPayload) -> serde_json::Value {
    let mut metrics = serde_json::Map::new();
    for metric in &payload.metrics {
        metrics.insert(metric_key(metric), metric.value.to_json());
    }
    let mut doc = serde_json::Map::new();
    doc.insert("group_id".to_string(), serde_json::json!(topic.group_id));
    doc.insert(
        "edge_node_id".to_string(),
        serde_json::json!(topic.edge_node_id),
    );
    if let Some(device) = &topic.device_id {
        doc.insert("device_id".to_string(), serde_json::json!(device));
    }
    doc.insert(
        "msg_type".to_string(),
        serde_json::json!(topic.message_type.as_str()),
    );
    doc.insert(
        "timestamp".to_string(),
        serde_json::json!(payload.timestamp.unwrap_or(0)),
    );
    doc.insert(
        "seq".to_string(),
        serde_json::json!(payload.seq.unwrap_or(0)),
    );
    doc.insert("metrics".to_string(), serde_json::Value::Object(metrics));
    if let Some(uuid) = &payload.uuid {
        doc.insert("uuid".to_string(), serde_json::json!(uuid));
    }
    if let Some(body) = &payload.body {
        doc.insert(
            "body_b64".to_string(),
            serde_json::json!(base64::engine::general_purpose::STANDARD.encode(body)),
        );
    }
    serde_json::Value::Object(doc)
}

/// Encode a normalized JSON document back into Protobuf binary.
/// Metrics infer datatypes from JSON values; timestamps/seq/uuid pass
/// through when present.
pub fn payload_from_json(doc: &serde_json::Value) -> Result<SpbPayload> {
    let get_u64 = |key: &str| doc.get(key).and_then(|v| v.as_u64());
    let mut payload = SpbPayload {
        timestamp: get_u64("timestamp"),
        seq: get_u64("seq"),
        uuid: doc.get("uuid").and_then(|v| v.as_str()).map(str::to_string),
        body: doc
            .get("body_b64")
            .and_then(|v| v.as_str())
            .and_then(|text| base64::engine::general_purpose::STANDARD.decode(text).ok()),
        metrics: Vec::new(),
    };
    let metrics = doc
        .get("metrics")
        .and_then(|v| v.as_object())
        .ok_or_else(|| {
            ConnectorError::Dispatch("sparkplug document needs a metrics object".to_string())
        })?;
    let stamp = payload.timestamp;
    for (name, value) in metrics {
        let (datatype, typed) = SpbValue::from_json(value);
        payload.metrics.push(SpbMetric {
            name: Some(name.clone()),
            alias: None,
            timestamp: stamp,
            datatype,
            value: typed,
        });
    }
    Ok(payload)
}

// ---------------------------------------------------------------------------
// Edge/node state machine.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct NodeKey {
    group: String,
    edge: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DeviceKey {
    group: String,
    edge: String,
    device: String,
}

/// Online state plus birth alias cache for one node or device.
#[derive(Debug, Clone, Default)]
pub struct EndpointState {
    pub online: bool,
    pub last_seq: Option<u64>,
    pub aliases: HashMap<u64, String>,
    pub records_seen: u64,
}

/// Sequence/presence anomalies flagged while ingesting (accepted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpbAnomaly {
    /// Expected `(last + 1) % 256`, got something else (gap or replay).
    SequenceGap { expected: u64, got: u64 },
    /// Sequence number outside 0..=255.
    SequenceOutOfRange { got: u64 },
    /// Data arrived while the endpoint reads offline.
    OfflineData,
    /// Aliased metric with no cached birth definition.
    UnknownAlias { alias: u64 },
}

/// Outcome of ingesting one Sparkplug message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpbIngestOutcome {
    pub topic: SparkplugTopic,
    pub online: bool,
    pub anomalies: Vec<SpbAnomaly>,
    pub metrics: usize,
}

/// Tracks online/offline status, alias caches and sequence health per
/// node and device (Enterprise tier; see [`SPARKPLUG_TIER`]).
#[derive(Debug, Default)]
pub struct SparkplugStateMachine {
    nodes: HashMap<NodeKey, EndpointState>,
    devices: HashMap<DeviceKey, EndpointState>,
    hosts: HashMap<String, bool>,
}

impl SparkplugStateMachine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn node_state(&self, group: &str, edge: &str) -> Option<&EndpointState> {
        self.nodes.get(&NodeKey {
            group: group.to_string(),
            edge: edge.to_string(),
        })
    }

    pub fn device_state(&self, group: &str, edge: &str, device: &str) -> Option<&EndpointState> {
        self.devices.get(&DeviceKey {
            group: group.to_string(),
            edge: edge.to_string(),
            device: device.to_string(),
        })
    }

    pub fn host_online(&self, host: &str) -> Option<bool> {
        self.hosts.get(host).copied()
    }

    /// Ingest one message: parse the topic, decode the payload, update
    /// state, resolve aliases for data messages, and flag anomalies.
    pub fn ingest(&mut self, topic: &str, payload: &[u8]) -> Result<SpbIngestOutcome> {
        let parsed = SparkplugTopic::parse(topic)?;
        let decoded = decode_payload(payload)?;
        if parsed.message_type == SparkplugMessageType::State {
            // Host births carry ONLINE state; OFFLINE arrives either as
            // the body or as an `offline=true` metric.
            let body_offline = matches!(decoded.body.as_deref(), Some(b"OFFLINE"));
            let metric_offline = decoded.metrics.iter().any(|metric| {
                metric.name.as_deref() == Some("offline") && metric.value == SpbValue::Bool(true)
            });
            let online = !(body_offline || metric_offline);
            self.hosts.insert(parsed.edge_node_id.clone(), online);
            return Ok(SpbIngestOutcome {
                online,
                topic: parsed,
                anomalies: Vec::new(),
                metrics: decoded.metrics.len(),
            });
        }
        // Birth/death/data/command resolve to a node or device endpoint.
        let device = parsed.device_id.clone();
        if device.is_some() {
            // Tahu ordering: a device birth requires a live node birth.
            if parsed.message_type.is_birth() && !self.node_online(&parsed) {
                return Err(ConnectorError::Dispatch(format!(
                    "sparkplug device birth without an online node: {topic:?}"
                )));
            }
            let key = DeviceKey {
                group: parsed.group_id.clone(),
                edge: parsed.edge_node_id.clone(),
                device: device.clone().unwrap_or_default(),
            };
            let state = self.devices.entry(key).or_default();
            Self::apply(state, &parsed, &decoded)
        } else {
            let key = NodeKey {
                group: parsed.group_id.clone(),
                edge: parsed.edge_node_id.clone(),
            };
            let state = self.nodes.entry(key).or_default();
            Self::apply(state, &parsed, &decoded)
        }
    }

    fn node_online(&self, topic: &SparkplugTopic) -> bool {
        self.node_state(&topic.group_id, &topic.edge_node_id)
            .is_some_and(|state| state.online)
    }

    /// Fold one decoded payload into endpoint state.
    fn apply(
        state: &mut EndpointState,
        topic: &SparkplugTopic,
        payload: &SpbPayload,
    ) -> Result<SpbIngestOutcome> {
        let mut anomalies = Vec::new();
        // A birth (re)starts the session: the sequence tracker resets
        // before the health check so the birth sequence seeds it.
        if topic.message_type.is_birth() {
            state.last_seq = None;
        }
        // Sequence health first (birth sequence seeds the tracker).
        if let Some(seq) = payload.seq {
            if seq > 255 {
                anomalies.push(SpbAnomaly::SequenceOutOfRange { got: seq });
            } else if let Some(last) = state.last_seq {
                let expected = (last + 1) % 256;
                if seq != expected {
                    anomalies.push(SpbAnomaly::SequenceGap { expected, got: seq });
                }
            }
            state.last_seq = Some(seq);
        }
        state.records_seen += 1;
        if topic.message_type.is_birth() {
            state.online = true;
            state.aliases.clear();
            for metric in &payload.metrics {
                if let (Some(alias), Some(name)) = (metric.alias, metric.name.clone()) {
                    state.aliases.insert(alias, name);
                }
            }
        } else if topic.message_type.is_death() {
            state.online = false;
            state.aliases.clear();
        } else {
            // Data/command on an offline endpoint is anomalous but kept.
            if !state.online && topic.message_type.is_data() {
                anomalies.push(SpbAnomaly::OfflineData);
            }
            if topic.message_type.is_data() {
                for metric in &payload.metrics {
                    if metric.name.is_none() {
                        if let Some(alias) = metric.alias {
                            if !state.aliases.contains_key(&alias) {
                                anomalies.push(SpbAnomaly::UnknownAlias { alias });
                            }
                        }
                    }
                }
            }
        }
        let online = state.online;
        Ok(SpbIngestOutcome {
            topic: topic.clone(),
            online,
            anomalies,
            metrics: payload.metrics.len(),
        })
    }

    /// Resolve one metric display name via the endpoint alias cache.
    pub fn resolve_metric_name(
        &self,
        topic: &SparkplugTopic,
        metric: &SpbMetric,
    ) -> Option<String> {
        if let Some(name) = &metric.name {
            return Some(name.clone());
        }
        let alias = metric.alias?;
        let cached = match &topic.device_id {
            Some(device) => self
                .device_state(&topic.group_id, &topic.edge_node_id, device)?
                .aliases
                .get(&alias)
                .cloned(),
            None => self
                .node_state(&topic.group_id, &topic.edge_node_id)?
                .aliases
                .get(&alias)
                .cloned(),
        };
        cached.or_else(|| Some(format!("alias:{alias}")))
    }
}

// ---------------------------------------------------------------------------
// Sink: normalized JSON in, Sparkplug Protobuf frames out.
// ---------------------------------------------------------------------------

/// Sparkplug frame delivered to the transport.
#[derive(Debug, Clone)]
pub struct SparkplugFrame {
    pub topic: String,
    pub payload: Vec<u8>,
}

#[async_trait]
pub trait SparkplugTransport: Send + Sync {
    async fn publish(&self, frame: &SparkplugFrame) -> Result<()>;
}

/// In-memory transport capturing every frame (tests, dry runs).
#[derive(Debug, Default)]
pub struct MemorySparkplugTransport {
    frames: parking_lot::Mutex<Vec<SparkplugFrame>>,
    calls: AtomicU64,
}

impl MemorySparkplugTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn frames(&self) -> Vec<SparkplugFrame> {
        self.frames.lock().clone()
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl SparkplugTransport for MemorySparkplugTransport {
    async fn publish(&self, frame: &SparkplugFrame) -> Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.frames.lock().push(frame.clone());
        Ok(())
    }
}

/// Sparkplug sink configuration (Enterprise tier only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparkplugSinkConfig {
    /// Optional namespace guard, e.g. `spBv1.0/plant1`: accepted
    /// topics must live under it.
    #[serde(default)]
    pub topic_prefix: Option<String>,
    /// License tier gate: must be `"enterprise"`.
    #[serde(default = "default_tier")]
    pub tier: String,
    /// Flush trigger record count (default 100, `None` unbounded).
    #[serde(default = "default_batch_size")]
    pub batch_size: Option<usize>,
    /// Linger flush window in ms (default 50, `None` disables).
    #[serde(default = "default_linger_ms")]
    pub linger_ms: Option<u64>,
}

fn default_tier() -> String {
    SPARKPLUG_TIER.to_string()
}

fn default_batch_size() -> Option<usize> {
    Some(100)
}

fn default_linger_ms() -> Option<u64> {
    Some(50)
}

impl SparkplugSinkConfig {
    pub fn validate(&self) -> Result<()> {
        if self.tier != SPARKPLUG_TIER {
            return Err(ConnectorError::Dispatch(format!(
                "sparkplug_b requires the enterprise tier (got {:?}); see INDRA_ENTERPRISE_LICENSE",
                self.tier
            )));
        }
        if let Some(prefix) = &self.topic_prefix {
            if prefix.contains('+') || prefix.contains('#') {
                return Err(ConnectorError::Dispatch(format!(
                    "sparkplug topic_prefix must be concrete: {prefix:?}"
                )));
            }
            let parts: Vec<&str> = prefix.split('/').collect();
            if parts.first() != Some(&"spBv1.0") || parts.iter().any(|part| part.is_empty()) {
                return Err(ConnectorError::Dispatch(format!(
                    "sparkplug topic_prefix must start with spBv1.0/: {prefix:?}"
                )));
            }
        }
        if self.batch_size == Some(0) {
            return Err(ConnectorError::Dispatch(
                "sparkplug batch_size must be >= 1".to_string(),
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
}

/// Sparkplug B sink: validates namespace topics, encodes normalized
/// JSON documents to Protobuf frames, publishes in batches.
pub struct SparkplugBSink {
    config: SparkplugSinkConfig,
    transport: Arc<dyn SparkplugTransport>,
    buffer: parking_lot::Mutex<BatchQueue<(String, Vec<u8>)>>,
    backoff: parking_lot::Mutex<super::BackoffState>,
    sent_batches: AtomicU64,
    sent_records: AtomicU64,
}

impl SparkplugBSink {
    pub fn new(
        config: SparkplugSinkConfig,
        transport: Arc<dyn SparkplugTransport>,
    ) -> Result<Self> {
        config.validate()?;
        let linger = config.effective_linger();
        Ok(Self {
            buffer: parking_lot::Mutex::new(BatchQueue::new(config.effective_batch_size(), linger)),
            config,
            transport,
            backoff: parking_lot::Mutex::new(super::BackoffState::default()),
            sent_batches: AtomicU64::new(0),
            sent_records: AtomicU64::new(0),
        })
    }

    pub fn config(&self) -> &SparkplugSinkConfig {
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

    /// Flush buffered frames (no-op when empty). Failures restore the
    /// buffer, engage backoff, and propagate.
    pub async fn flush(&self) -> Result<()> {
        self.backoff.lock().check()?;
        let (rows, oldest) = self.buffer.lock().take_batch();
        if rows.is_empty() {
            return Ok(());
        }
        let record_count = rows.len() as u64;
        let mut failed: Option<ConnectorError> = None;
        for (topic, payload) in &rows {
            match self
                .transport
                .publish(&SparkplugFrame {
                    topic: topic.clone(),
                    payload: payload.clone(),
                })
                .await
            {
                Ok(()) => {}
                Err(e) => {
                    failed = Some(e);
                    break;
                }
            }
        }
        match failed {
            None => {
                self.backoff.lock().success();
                self.sent_batches.fetch_add(1, Ordering::Relaxed);
                self.sent_records.fetch_add(record_count, Ordering::Relaxed);
                Ok(())
            }
            Some(e) => {
                // All-or-nothing like the sibling sinks: the whole batch
                // is restored (at-least-once on retry).
                self.buffer.lock().restore(rows, oldest);
                self.backoff.lock().failure();
                Err(e)
            }
        }
    }

    /// Validate + buffer one event: the topic must parse as Sparkplug
    /// (under the prefix when set) and the payload must be a
    /// normalized JSON document with a metrics object.
    fn buffer_row(&self, topic: &Topic, payload: &Bytes, _qos: QoS) -> Result<bool> {
        let parsed = SparkplugTopic::parse(topic.as_str())?;
        if let Some(prefix) = &self.config.topic_prefix {
            if topic.as_str() != prefix && !topic.as_str().starts_with(&format!("{prefix}/")) {
                return Err(ConnectorError::Dispatch(format!(
                    "sparkplug topic outside prefix {prefix:?}: {:?}",
                    topic.as_str()
                )));
            }
        }
        let text = std::str::from_utf8(payload).map_err(|_| {
            ConnectorError::Dispatch("sparkplug payload must be UTF-8 JSON".to_string())
        })?;
        let doc: serde_json::Value = serde_json::from_str(text).map_err(|_| {
            ConnectorError::Dispatch("sparkplug payload must be a JSON document".to_string())
        })?;
        let encoded = encode_payload(&payload_from_json(&doc)?);
        let _ = parsed;
        Ok(self
            .buffer
            .lock()
            .push((topic.as_str().to_string(), encoded)))
    }
}

#[async_trait]
impl Sink for SparkplugBSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        if self.buffer_row(topic, payload, qos)? {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "sparkplug_b"
    }
}

/// Management connector handle pairing an id with a Sparkplug sink.
pub struct SparkplugBConnector {
    id: String,
    sink: Arc<SparkplugBSink>,
}

impl SparkplugBConnector {
    pub fn new(id: impl Into<String>, sink: Arc<SparkplugBSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }
}

impl super::Connector for SparkplugBConnector {
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

    fn birth_payload(seq: u64) -> Vec<u8> {
        encode_payload(&SpbPayload {
            timestamp: Some(1_726_145_890_000),
            seq: Some(seq),
            uuid: None,
            body: None,
            metrics: vec![
                SpbMetric {
                    name: Some("Temperature".to_string()),
                    alias: Some(1),
                    timestamp: Some(1_726_145_890_000),
                    datatype: SpbDataType::Double,
                    value: SpbValue::Double(82.5),
                },
                SpbMetric {
                    name: Some("Running".to_string()),
                    alias: Some(2),
                    timestamp: Some(1_726_145_890_000),
                    datatype: SpbDataType::Boolean,
                    value: SpbValue::Bool(true),
                },
            ],
        })
    }

    #[test]
    fn test_namespace_parsing() {
        let node = SparkplugTopic::parse("spBv1.0/plant1/NDATA/edge7").unwrap();
        assert_eq!(node.group_id, "plant1");
        assert_eq!(node.edge_node_id, "edge7");
        assert_eq!(node.device_id, None);
        assert_eq!(node.message_type, SparkplugMessageType::NData);

        let device = SparkplugTopic::parse("spBv1.0/plant1/DDATA/edge7/plc3").unwrap();
        assert_eq!(device.device_id.as_deref(), Some("plc3"));
        assert_eq!(device.message_type, SparkplugMessageType::DData);

        let state = SparkplugTopic::parse("spBv1.0/STATE/host-app").unwrap();
        assert_eq!(state.message_type, SparkplugMessageType::State);
        assert_eq!(state.edge_node_id, "host-app");

        for bad in [
            "spBv1.0/plant1/DDATA/edge7",      // device type, no device
            "spBv1.0/plant1/NDATA/edge7/plc3", // node type with device
            "spBv1.0/plant1/BOGUS/edge7",      // unknown type
            "spBv1.0/STATE",                   // short STATE
            "spBv1.0/STATE/a/b",               // long STATE
            "mqtt/plant1/NDATA/edge7",         // wrong namespace
            "spBv1.0/plant1/NDATA/+",          // wildcard
            "spBv1.0//NDATA/edge7",            // empty group
            "spBv1.0/plant1/NDATA/",           // trailing slash
        ] {
            assert!(SparkplugTopic::parse(bad).is_err(), "must reject {bad:?}");
        }
    }

    #[test]
    fn test_varint_edges() {
        for (value, bytes) in [
            (0u64, vec![0x00]),
            (127, vec![0x7F]),
            (128, vec![0x80, 0x01]),
            (300, vec![0xAC, 0x02]),
        ] {
            let mut out = Vec::new();
            encode_varint(value, &mut out);
            assert_eq!(out, bytes);
            assert_eq!(decode_varint(&out).unwrap(), (value, bytes.len()));
        }
        let mut max = Vec::new();
        encode_varint(u64::MAX, &mut max);
        assert_eq!(max.len(), 10);
        assert_eq!(decode_varint(&max).unwrap().0, u64::MAX);
        assert!(decode_varint(&[]).is_err());
        assert!(decode_varint(&[0x80; 10]).is_err());
    }

    #[test]
    fn test_protobuf_roundtrip_all_types() {
        let payload = SpbPayload {
            timestamp: Some(1_726_145_890_000),
            seq: Some(14),
            uuid: Some("uuid-1".to_string()),
            body: Some(b"raw".to_vec()),
            metrics: vec![
                SpbMetric {
                    name: Some("i8".into()),
                    alias: None,
                    timestamp: None,
                    datatype: SpbDataType::Int8,
                    value: SpbValue::Int(-5),
                },
                SpbMetric {
                    name: Some("i64".into()),
                    alias: None,
                    timestamp: None,
                    datatype: SpbDataType::Int64,
                    value: SpbValue::Int(i64::MIN),
                },
                SpbMetric {
                    name: Some("u64".into()),
                    alias: None,
                    timestamp: None,
                    datatype: SpbDataType::UInt64,
                    value: SpbValue::UInt(u64::MAX),
                },
                SpbMetric {
                    name: Some("f".into()),
                    alias: None,
                    timestamp: None,
                    datatype: SpbDataType::Float,
                    value: SpbValue::Float(0.5),
                },
                SpbMetric {
                    name: Some("d".into()),
                    alias: None,
                    timestamp: None,
                    datatype: SpbDataType::Double,
                    value: SpbValue::Double(101.3),
                },
                SpbMetric {
                    name: Some("b".into()),
                    alias: None,
                    timestamp: None,
                    datatype: SpbDataType::Boolean,
                    value: SpbValue::Bool(true),
                },
                SpbMetric {
                    name: Some("s".into()),
                    alias: None,
                    timestamp: None,
                    datatype: SpbDataType::String,
                    value: SpbValue::Text("héllo".to_string()),
                },
                SpbMetric {
                    name: Some("by".into()),
                    alias: None,
                    timestamp: None,
                    datatype: SpbDataType::Bytes,
                    value: SpbValue::Bytes(vec![0x00, 0xFF]),
                },
                SpbMetric {
                    name: Some("n".into()),
                    alias: None,
                    timestamp: None,
                    datatype: SpbDataType::Unknown,
                    value: SpbValue::Null,
                },
            ],
        };
        let bytes = encode_payload(&payload);
        let back = decode_payload(&bytes).unwrap();
        assert_eq!(back.timestamp, payload.timestamp);
        assert_eq!(back.seq, payload.seq);
        assert_eq!(back.uuid, payload.uuid);
        assert_eq!(back.body, payload.body);
        assert_eq!(back.metrics.len(), 9);
        assert_eq!(back.metrics[0].value, SpbValue::Int(-5));
        assert_eq!(back.metrics[1].value, SpbValue::Int(i64::MIN));
        assert_eq!(back.metrics[2].value, SpbValue::UInt(u64::MAX));
        assert_eq!(back.metrics[3].value, SpbValue::Float(0.5));
        assert_eq!(back.metrics[4].value, SpbValue::Double(101.3));
        assert_eq!(back.metrics[5].value, SpbValue::Bool(true));
        assert_eq!(back.metrics[6].value, SpbValue::Text("héllo".to_string()));
        assert_eq!(back.metrics[7].value, SpbValue::Bytes(vec![0x00, 0xFF]));
        assert_eq!(back.metrics[8].value, SpbValue::Null);
        // Bare deaths (empty body) still decode.
        assert_eq!(decode_payload(&[]).unwrap().metrics.len(), 0);
    }

    #[test]
    fn test_json_translation() {
        let topic = SparkplugTopic::parse("spBv1.0/plant1/DDATA/edge7/plc3").unwrap();
        let payload = decode_payload(&birth_payload(14)).unwrap();
        let doc = payload_to_json(&topic, &payload);
        assert_eq!(doc["group_id"], "plant1");
        assert_eq!(doc["edge_node_id"], "edge7");
        assert_eq!(doc["device_id"], "plc3");
        assert_eq!(doc["msg_type"], "DDATA");
        assert_eq!(doc["timestamp"], 1_726_145_890_000u64);
        assert_eq!(doc["seq"], 14u64);
        assert_eq!(doc["metrics"]["Temperature"], 82.5);
        assert_eq!(doc["metrics"]["Running"], true);

        // Back to binary: values survive the round trip.
        let reencoded = encode_payload(&payload_from_json(&doc).unwrap());
        let back = decode_payload(&reencoded).unwrap();
        let metrics: HashMap<String, SpbValue> = back
            .metrics
            .into_iter()
            .map(|metric| (metric.name.clone().unwrap(), metric.value))
            .collect();
        assert_eq!(metrics["Temperature"], SpbValue::Double(82.5));
        assert_eq!(metrics["Running"], SpbValue::Bool(true));
    }

    #[test]
    fn test_state_machine_lifecycle() {
        let mut machine = SparkplugStateMachine::new();
        // Data before birth is anomalous but kept.
        let data = encode_payload(&SpbPayload {
            timestamp: Some(1),
            seq: Some(0),
            uuid: None,
            body: None,
            metrics: vec![SpbMetric {
                name: None,
                alias: Some(1),
                timestamp: None,
                datatype: SpbDataType::Double,
                value: SpbValue::Double(1.0),
            }],
        });
        let outcome = machine.ingest("spBv1.0/g1/NDATA/e1", &data).unwrap();
        assert!(!outcome.online);
        assert!(outcome.anomalies.contains(&SpbAnomaly::OfflineData));
        assert!(outcome
            .anomalies
            .contains(&SpbAnomaly::UnknownAlias { alias: 1 }));

        // Birth brings the node online and caches aliases.
        let outcome = machine
            .ingest("spBv1.0/g1/NBIRTH/e1", &birth_payload(0))
            .unwrap();
        assert!(outcome.online);
        assert!(outcome.anomalies.is_empty());
        let state = machine.node_state("g1", "e1").unwrap();
        assert!(state.online);
        assert_eq!(
            state.aliases.get(&1).map(String::as_str),
            Some("Temperature")
        );

        // Aliased data now resolves without anomalies.
        let data_seq1 = encode_payload(&SpbPayload {
            timestamp: Some(1),
            seq: Some(1),
            uuid: None,
            body: None,
            metrics: vec![SpbMetric {
                name: None,
                alias: Some(1),
                timestamp: None,
                datatype: SpbDataType::Double,
                value: SpbValue::Double(1.0),
            }],
        });
        let outcome = machine.ingest("spBv1.0/g1/NDATA/e1", &data_seq1).unwrap();
        assert!(outcome.online);
        assert!(outcome.anomalies.is_empty());
        let topic = SparkplugTopic::parse("spBv1.0/g1/NDATA/e1").unwrap();
        let decoded = decode_payload(&data_seq1).unwrap();
        assert_eq!(
            machine
                .resolve_metric_name(&topic, &decoded.metrics[0])
                .as_deref(),
            Some("Temperature")
        );

        // Death takes the node offline and invalidates the cache.
        let outcome = machine.ingest("spBv1.0/g1/NDEATH/e1", &[]).unwrap();
        assert!(!outcome.online);
        let state = machine.node_state("g1", "e1").unwrap();
        assert!(!state.online);
        assert!(state.aliases.is_empty());
    }

    #[test]
    fn test_state_machine_device_ordering_and_sequences() {
        let mut machine = SparkplugStateMachine::new();
        // Device birth without a live node birth is rejected.
        let err = machine
            .ingest("spBv1.0/g1/DBIRTH/e1/d1", &birth_payload(0))
            .expect_err("device birth needs a node");
        assert!(matches!(err, ConnectorError::Dispatch(_)));

        machine
            .ingest("spBv1.0/g1/NBIRTH/e1", &birth_payload(0))
            .unwrap();
        let outcome = machine
            .ingest("spBv1.0/g1/DBIRTH/e1/d1", &birth_payload(0))
            .unwrap();
        assert!(outcome.online);
        assert!(machine.device_state("g1", "e1", "d1").unwrap().online);

        // In-order seq is quiet; a jump flags a gap; 255->0 wraps clean.
        let data_with_seq = |seq: u64| {
            encode_payload(&SpbPayload {
                timestamp: Some(1),
                seq: Some(seq),
                uuid: None,
                body: None,
                metrics: vec![],
            })
        };
        let outcome = machine
            .ingest("spBv1.0/g1/DDATA/e1/d1", &data_with_seq(1))
            .unwrap();
        assert!(outcome.anomalies.is_empty());
        let outcome = machine
            .ingest("spBv1.0/g1/DDATA/e1/d1", &data_with_seq(4))
            .unwrap();
        assert_eq!(
            outcome.anomalies,
            vec![SpbAnomaly::SequenceGap {
                expected: 2,
                got: 4
            }]
        );
        let outcome = machine
            .ingest("spBv1.0/g1/DDATA/e1/d1", &data_with_seq(300))
            .unwrap();
        assert!(outcome
            .anomalies
            .contains(&SpbAnomaly::SequenceOutOfRange { got: 300 }));

        // Wrap: drive to 255 then 0.
        machine
            .ingest("spBv1.0/g1/DDATA/e1/d1", &data_with_seq(255))
            .unwrap();
        let outcome = machine
            .ingest("spBv1.0/g1/DDATA/e1/d1", &data_with_seq(0))
            .unwrap();
        assert!(!outcome
            .anomalies
            .iter()
            .any(|anomaly| matches!(anomaly, SpbAnomaly::SequenceGap { expected: 0, .. })));
    }

    #[test]
    fn test_tier_gate() {
        assert_eq!(tier(), "enterprise");
        assert_eq!(SPARKPLUG_TIER, "enterprise");
        let mut config = SparkplugSinkConfig {
            topic_prefix: None,
            tier: "community".to_string(),
            batch_size: Some(100),
            linger_ms: Some(50),
        };
        assert!(config.validate().is_err());
        config.tier = "enterprise".to_string();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_sink_config_validation() {
        let mut config = SparkplugSinkConfig {
            topic_prefix: Some("spBv1.0/plant1".to_string()),
            tier: "enterprise".to_string(),
            batch_size: Some(100),
            linger_ms: Some(50),
        };
        assert!(config.validate().is_ok());
        config.topic_prefix = Some("spBv1.0/plant1/+".to_string());
        assert!(config.validate().is_err());
        config.topic_prefix = Some("mqtt/plant1".to_string());
        assert!(config.validate().is_err());
        config.topic_prefix = None;
        config.batch_size = Some(0);
        assert!(config.validate().is_err());
        config.batch_size = None;
        assert!(config.validate().is_ok());
    }

    #[tokio::test]
    async fn test_sink_encodes_normalized_documents() {
        let transport = Arc::new(MemorySparkplugTransport::new());
        let sink = SparkplugBSink::new(
            SparkplugSinkConfig {
                topic_prefix: Some("spBv1.0/plant1".to_string()),
                tier: "enterprise".to_string(),
                batch_size: Some(10),
                linger_ms: Some(50),
            },
            transport.clone(),
        )
        .unwrap();
        let doc = serde_json::json!({
            "timestamp": 1_726_145_890_000u64,
            "seq": 14u64,
            "metrics": {"Temperature": 82.5, "Pressure": 101.3},
        });
        sink.send(
            &Topic::new("spBv1.0/plant1/DDATA/edge7/plc3").unwrap(),
            &Bytes::from(serde_json::to_vec(&doc).unwrap()),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        sink.flush().await.unwrap();
        assert_eq!(sink.sent_records(), 1);
        let frames = transport.frames();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].topic, "spBv1.0/plant1/DDATA/edge7/plc3");
        let back = decode_payload(&frames[0].payload).unwrap();
        assert_eq!(back.seq, Some(14));
        let metrics: HashMap<String, SpbValue> = back
            .metrics
            .into_iter()
            .map(|metric| (metric.name.clone().unwrap(), metric.value))
            .collect();
        assert_eq!(metrics["Temperature"], SpbValue::Double(82.5));
        assert_eq!(metrics["Pressure"], SpbValue::Double(101.3));

        // Non-Sparkplug topics and non-JSON payloads are rejected.
        assert!(sink
            .send(
                &Topic::new("sensors/t1").unwrap(),
                &Bytes::from("{}"),
                QoS::AtMostOnce
            )
            .await
            .is_err());
        assert!(sink
            .send(
                &Topic::new("spBv1.0/plant1/DDATA/edge7/plc3").unwrap(),
                &Bytes::from("nope"),
                QoS::AtMostOnce
            )
            .await
            .is_err());
        // Outside the configured prefix is rejected.
        assert!(sink
            .send(
                &Topic::new("spBv1.0/other/DDATA/edge7/plc3").unwrap(),
                &Bytes::from("{}"),
                QoS::AtMostOnce
            )
            .await
            .is_err());
    }
}
