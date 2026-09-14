//! MongoDB / DocumentDB / Cosmos DB document sink (INDRA-164).
//!
//! Buffers MQTT events as BSON documents (payload fields merged with
//! an injected `_mqtt` metadata subdocument) and writes them with
//! `insert` / `update` bulk commands grouped by resolved collection.
//! The native transport speaks the OP_MSG wire protocol over TCP with
//! SCRAM-SHA-256 authentication — a clean-room implementation reusing
//! the shared HMAC-SHA256 core, so no driver dependency is needed and
//! every byte stays in-memory testable.
//!
//! Transient failures (pool timeouts, network errors, non-duplicate
//! server write errors) retry with jittered backoff; duplicate-key
//! (11000) and validation (121) write errors are terminal.

use async_trait::async_trait;
use base64::Engine;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{now_millis, render_template, BackoffState, BatchQueue, ConnectorError, Result, Sink};

// ---------------------------------------------------------------------------
// BSON model + codec (subset: the types the sink emits and reads).
// ---------------------------------------------------------------------------

/// BSON value subset.
#[derive(Debug, Clone, PartialEq)]
pub enum BsonValue {
    Double(f64),
    String(String),
    Document(BsonDocument),
    Array(Vec<BsonValue>),
    Binary(Vec<u8>),
    ObjectId([u8; 12]),
    Bool(bool),
    DateTime(i64),
    Null,
    Int32(i32),
    Int64(i64),
}

/// Ordered BSON document.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct BsonDocument {
    pub fields: Vec<(String, BsonValue)>,
}

impl BsonDocument {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, key: &str) -> Option<&BsonValue> {
        self.fields.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        let mut body = Vec::new();
        for (key, value) in &self.fields {
            encode_element(key, value, &mut body);
        }
        body.push(0x00);
        out.extend_from_slice(&((body.len() + 4) as i32).to_le_bytes());
        out.extend_from_slice(&body);
    }

    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    /// Decode from wire bytes (trailing bytes are not consumed here;
    /// callers slice the documented length first).
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < 5 {
            return Err(ConnectorError::Connection(
                "mongo truncated BSON document".to_string(),
            ));
        }
        let len = i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if len < 5 || buf.len() < len || buf[len - 1] != 0x00 {
            return Err(ConnectorError::Connection(
                "mongo bad BSON length".to_string(),
            ));
        }
        let mut doc = BsonDocument::new();
        let mut cursor = &buf[4..len - 1];
        while !cursor.is_empty() {
            let element = cursor[0];
            cursor = &cursor[1..];
            let key_end = cursor.iter().position(|&b| b == 0).ok_or_else(|| {
                ConnectorError::Connection("mongo truncated BSON key".to_string())
            })?;
            let key = std::str::from_utf8(&cursor[..key_end])
                .map_err(|_| ConnectorError::Connection("mongo BSON key not UTF-8".to_string()))?
                .to_string();
            cursor = &cursor[key_end + 1..];
            let (value, used) = decode_value(element, cursor)?;
            cursor = &cursor[used..];
            doc.fields.push((key, value));
        }
        Ok(doc)
    }
}

fn encode_cstring(out: &mut Vec<u8>, text: &str) {
    out.extend_from_slice(text.as_bytes());
    out.push(0x00);
}

fn encode_bson_string(out: &mut Vec<u8>, text: &str) {
    out.extend_from_slice(&((text.len() + 1) as i32).to_le_bytes());
    out.extend_from_slice(text.as_bytes());
    out.push(0x00);
}

fn encode_element(key: &str, value: &BsonValue, out: &mut Vec<u8>) {
    match value {
        BsonValue::Double(v) => {
            out.push(0x01);
            encode_cstring(out, key);
            out.extend_from_slice(&v.to_le_bytes());
        }
        BsonValue::String(v) => {
            out.push(0x02);
            encode_cstring(out, key);
            encode_bson_string(out, v);
        }
        BsonValue::Document(doc) => {
            out.push(0x03);
            encode_cstring(out, key);
            doc.encode_into(out);
        }
        BsonValue::Array(items) => {
            out.push(0x04);
            encode_cstring(out, key);
            let array = BsonDocument {
                fields: items
                    .iter()
                    .enumerate()
                    .map(|(index, item)| (index.to_string(), item.clone()))
                    .collect(),
            };
            array.encode_into(out);
        }
        BsonValue::Binary(v) => {
            out.push(0x05);
            encode_cstring(out, key);
            out.extend_from_slice(&(v.len() as i32).to_le_bytes());
            out.push(0x00);
            out.extend_from_slice(v);
        }
        BsonValue::ObjectId(id) => {
            out.push(0x07);
            encode_cstring(out, key);
            out.extend_from_slice(id);
        }
        BsonValue::Bool(v) => {
            out.push(0x08);
            encode_cstring(out, key);
            out.push(u8::from(*v));
        }
        BsonValue::DateTime(v) => {
            out.push(0x09);
            encode_cstring(out, key);
            out.extend_from_slice(&v.to_le_bytes());
        }
        BsonValue::Null => {
            out.push(0x0A);
            encode_cstring(out, key);
        }
        BsonValue::Int32(v) => {
            out.push(0x10);
            encode_cstring(out, key);
            out.extend_from_slice(&v.to_le_bytes());
        }
        BsonValue::Int64(v) => {
            out.push(0x12);
            encode_cstring(out, key);
            out.extend_from_slice(&v.to_le_bytes());
        }
    }
}

fn read_exact<'a>(cursor: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    if cursor.len() < n {
        return Err(ConnectorError::Connection(
            "mongo truncated BSON value".to_string(),
        ));
    }
    let (head, rest) = cursor.split_at(n);
    *cursor = rest;
    Ok(head)
}

fn read_bson_string<'a>(cursor: &mut &'a [u8]) -> Result<&'a str> {
    let len = i32::from_le_bytes(read_exact(cursor, 4)?.try_into().expect("4 bytes")) as usize;
    if len == 0 || cursor.len() < len || cursor[len - 1] != 0x00 {
        return Err(ConnectorError::Connection(
            "mongo bad BSON string".to_string(),
        ));
    }
    let text = std::str::from_utf8(&cursor[..len - 1])
        .map_err(|_| ConnectorError::Connection("mongo BSON string not UTF-8".to_string()))?;
    *cursor = &cursor[len..];
    Ok(text)
}

fn decode_value(element: u8, cursor: &[u8]) -> Result<(BsonValue, usize)> {
    let mut rest = cursor;
    let value = match element {
        0x01 => {
            let raw = read_exact(&mut rest, 8)?;
            BsonValue::Double(f64::from_le_bytes(raw.try_into().expect("8 bytes")))
        }
        0x02 => BsonValue::String(read_bson_string(&mut rest)?.to_string()),
        0x03 | 0x04 => {
            // Embedded document/array: peek the length prefix, slice
            // the full value bytes (prefix included) and decode.
            if cursor.len() < 4 {
                return Err(ConnectorError::Connection(
                    "mongo truncated BSON document".to_string(),
                ));
            }
            let total = i32::from_le_bytes(cursor[..4].try_into().expect("4 bytes")) as usize;
            if total < 5 || cursor.len() < total {
                return Err(ConnectorError::Connection(
                    "mongo bad nested BSON length".to_string(),
                ));
            }
            let doc = BsonDocument::decode(&cursor[..total])?;
            rest = &cursor[total..];
            if element == 0x03 {
                BsonValue::Document(doc)
            } else {
                let mut items = Vec::with_capacity(doc.fields.len());
                for (index, (key, item)) in doc.fields.iter().enumerate() {
                    if *key != index.to_string() {
                        return Err(ConnectorError::Connection(
                            "mongo array keys out of order".to_string(),
                        ));
                    }
                    items.push(item.clone());
                }
                BsonValue::Array(items)
            }
        }
        0x05 => {
            let len =
                i32::from_le_bytes(read_exact(&mut rest, 4)?.try_into().expect("4 bytes")) as usize;
            let _subtype = read_exact(&mut rest, 1)?[0];
            BsonValue::Binary(read_exact(&mut rest, len)?.to_vec())
        }
        0x07 => {
            let raw = read_exact(&mut rest, 12)?;
            let mut id = [0u8; 12];
            id.copy_from_slice(raw);
            BsonValue::ObjectId(id)
        }
        0x08 => BsonValue::Bool(read_exact(&mut rest, 1)?[0] != 0),
        0x09 => {
            let raw = read_exact(&mut rest, 8)?;
            BsonValue::DateTime(i64::from_le_bytes(raw.try_into().expect("8 bytes")))
        }
        0x0A => BsonValue::Null,
        0x10 => {
            let raw = read_exact(&mut rest, 4)?;
            BsonValue::Int32(i32::from_le_bytes(raw.try_into().expect("4 bytes")))
        }
        0x12 => {
            let raw = read_exact(&mut rest, 8)?;
            BsonValue::Int64(i64::from_le_bytes(raw.try_into().expect("8 bytes")))
        }
        other => {
            return Err(ConnectorError::Connection(format!(
                "mongo unsupported BSON type 0x{other:02x}"
            )))
        }
    };
    Ok((value, cursor.len() - rest.len()))
}

/// Generate an ObjectId: big-endian epoch seconds + process-unique
/// counter tail (unique per process, time-ordered prefix).
pub fn generate_object_id() -> [u8; 12] {
    static COUNTER: AtomicU32 = AtomicU32::new(0x5eed42);
    let mut id = [0u8; 12];
    let secs = (now_millis().max(0) / 1_000) as u32;
    id[..4].copy_from_slice(&secs.to_be_bytes());
    let count = COUNTER.fetch_add(1, Ordering::SeqCst);
    id[4..8].copy_from_slice(&std::process::id().to_be_bytes());
    id[8..12].copy_from_slice(&count.to_be_bytes());
    id
}

/// Map a JSON value onto BSON (integers prefer Int32, big u64s that
/// overflow i64 become Doubles, objects/arrays recurse).
pub fn json_to_bson(value: &serde_json::Value) -> BsonValue {
    match value {
        serde_json::Value::Null => BsonValue::Null,
        serde_json::Value::Bool(v) => BsonValue::Bool(*v),
        serde_json::Value::Number(n) => {
            if let Some(v) = n.as_i64() {
                if i32::try_from(v).is_ok() {
                    BsonValue::Int32(v as i32)
                } else {
                    BsonValue::Int64(v)
                }
            } else if let Some(v) = n.as_u64() {
                if let Ok(v) = i64::try_from(v) {
                    if i32::try_from(v).is_ok() {
                        BsonValue::Int32(v as i32)
                    } else {
                        BsonValue::Int64(v)
                    }
                } else {
                    BsonValue::Double(v as f64)
                }
            } else if let Some(v) = n.as_f64() {
                BsonValue::Double(v)
            } else {
                BsonValue::Null
            }
        }
        serde_json::Value::String(v) => BsonValue::String(v.clone()),
        serde_json::Value::Array(items) => {
            BsonValue::Array(items.iter().map(json_to_bson).collect())
        }
        serde_json::Value::Object(map) => BsonValue::Document(BsonDocument {
            fields: map
                .iter()
                .map(|(k, v)| (k.clone(), json_to_bson(v)))
                .collect(),
        }),
    }
}

// ---------------------------------------------------------------------------
// OP_MSG framing + SCRAM-SHA-256.
// ---------------------------------------------------------------------------

const OP_MSG: i32 = 2013;

/// Encode an OP_MSG with a single kind-0 body document.
pub fn encode_op_msg(body: &BsonDocument, request_id: i32) -> Vec<u8> {
    let encoded = body.encode();
    let mut frame = Vec::with_capacity(16 + 4 + 1 + encoded.len());
    let total = (16 + 4 + 1 + encoded.len()) as i32;
    frame.extend_from_slice(&total.to_le_bytes());
    frame.extend_from_slice(&request_id.to_le_bytes());
    frame.extend_from_slice(&0i32.to_le_bytes());
    frame.extend_from_slice(&OP_MSG.to_le_bytes());
    frame.extend_from_slice(&0u32.to_le_bytes()); // flagBits
    frame.push(0x00); // section kind 0
    frame.extend_from_slice(&encoded);
    frame
}

/// Split a received OP_MSG into (request_id, body document).
pub fn decode_op_msg(frame: &[u8]) -> Result<(i32, BsonDocument)> {
    if frame.len() < 16 + 4 + 1 + 5 {
        return Err(ConnectorError::Connection(
            "mongo truncated OP_MSG".to_string(),
        ));
    }
    let total = i32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    if frame.len() < total {
        return Err(ConnectorError::Connection(
            "mongo truncated OP_MSG body".to_string(),
        ));
    }
    let request_id = i32::from_le_bytes([frame[4], frame[5], frame[6], frame[7]]);
    let opcode = i32::from_le_bytes([frame[12], frame[13], frame[14], frame[15]]);
    if opcode != OP_MSG {
        return Err(ConnectorError::Connection(format!(
            "mongo expected OP_MSG, got opcode {opcode}"
        )));
    }
    if frame[20] != 0x00 {
        return Err(ConnectorError::Connection(
            "mongo only kind-0 sections supported".to_string(),
        ));
    }
    Ok((request_id, BsonDocument::decode(&frame[21..total])?))
}

/// PBKDF2-HMAC-SHA256 (RFC 5802 Hi function).
fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
    let mut block = Vec::with_capacity(salt.len() + 4);
    block.extend_from_slice(salt);
    block.extend_from_slice(&1u32.to_be_bytes());
    let mut result = super::hmac_sha256(password, &block);
    let mut previous = result.clone();
    for _ in 1..iterations.max(1) {
        previous = super::hmac_sha256(password, &previous);
        for (byte, prev) in result.iter_mut().zip(previous.iter()) {
            *byte ^= *prev;
        }
    }
    result
}

/// SCRAM-SHA-256 client proof + expected server signature for fixed
/// nonces (the transport generates fresh nonces per connection).
pub fn scram_client_proof(
    username: &str,
    password: &[u8],
    client_nonce: &str,
    server_first: &str,
) -> Result<(String, String)> {
    let mut parts: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
    for field in server_first.split(',') {
        if field.len() < 3 || field.as_bytes()[1] != b'=' {
            return Err(ConnectorError::Connection(
                "mongo bad SCRAM server-first".to_string(),
            ));
        }
        parts.insert(&field[..1], &field[2..]);
    }
    let full_nonce = parts.get("r").copied().unwrap_or_default();
    let salt_b64 = parts.get("s").copied().unwrap_or_default();
    let iterations: u32 = parts
        .get("i")
        .copied()
        .unwrap_or("4096")
        .parse()
        .map_err(|_| ConnectorError::Connection("mongo bad SCRAM iteration count".to_string()))?;
    if !full_nonce.starts_with(client_nonce) {
        return Err(ConnectorError::Connection(
            "mongo SCRAM nonce mismatch".to_string(),
        ));
    }
    let salt = base64::engine::general_purpose::STANDARD
        .decode(salt_b64)
        .map_err(|_| ConnectorError::Connection("mongo bad SCRAM salt".to_string()))?;
    let client_first_bare = format!("n={username},r={client_nonce}");
    let client_final_wo_proof = format!("c=biws,r={full_nonce}");
    let auth_message = format!("{client_first_bare},{server_first},{client_final_wo_proof}");
    let salted = pbkdf2_sha256(password, &salt, iterations);
    let client_key = super::hmac_sha256(&salted, b"Client Key");
    let stored_key = {
        use sha2::Digest;
        sha2::Sha256::digest(&client_key).to_vec()
    };
    let client_sig = super::hmac_sha256(&stored_key, auth_message.as_bytes());
    let proof: Vec<u8> = client_key
        .iter()
        .zip(client_sig.iter())
        .map(|(a, b)| a ^ b)
        .collect();
    let server_key = super::hmac_sha256(&salted, b"Server Key");
    let server_sig = super::hmac_sha256(&server_key, auth_message.as_bytes());
    Ok((
        base64::engine::general_purpose::STANDARD.encode(proof),
        base64::engine::general_purpose::STANDARD.encode(server_sig),
    ))
}

// ---------------------------------------------------------------------------
// Config.
// ---------------------------------------------------------------------------

/// Write operation for a bulk batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase", tag = "type")]
pub enum MongoOperation {
    /// Direct append with automatic `_id` generation.
    #[default]
    #[serde(alias = "insert_one")]
    InsertOne,
    /// Parametrized filter with `$set` payload.
    #[serde(alias = "update_one")]
    UpdateOne {
        filter_template: String,
        upsert: bool,
    },
    /// Parametrized filter with replacement payload.
    #[serde(alias = "replace_one")]
    ReplaceOne {
        filter_template: String,
        upsert: bool,
    },
}

fn default_batch_size() -> Option<usize> {
    Some(500)
}

fn default_batch_bytes() -> Option<usize> {
    Some(4_194_304)
}

fn default_linger_ms() -> Option<u64> {
    Some(20)
}

fn default_max_retries() -> Option<usize> {
    Some(4)
}

fn default_initial_backoff_ms() -> Option<u64> {
    Some(100)
}

fn default_max_backoff_ms() -> Option<u64> {
    Some(3_000)
}

/// MongoDB sink configuration. All depths are optional (`None` =
/// unbounded) with zero clamped ceilings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MongoDbSinkConfig {
    /// Connection URI (`mongodb://...` or `mongodb+srv://...`).
    pub connection_string: String,
    /// Target database name.
    pub database: String,
    /// Collection template (`${topic}`, `${client_id}`, ...).
    pub collection_template: String,
    /// Write operation (default insert).
    #[serde(default)]
    pub operation: MongoOperation,
    /// Documents per bulk batch (default 500).
    #[serde(default = "default_batch_size")]
    pub batch_size: Option<usize>,
    /// Batch byte limit over BSON (default 4 MiB).
    #[serde(default = "default_batch_bytes")]
    pub batch_bytes: Option<usize>,
    /// Linger flush window in ms (default 20).
    #[serde(default = "default_linger_ms")]
    pub linger_ms: Option<u64>,
    /// Retries on transient failures (default 4, `None` unbounded).
    #[serde(default = "default_max_retries")]
    pub max_retries: Option<usize>,
    /// First retry delay in ms (default 100).
    #[serde(default = "default_initial_backoff_ms")]
    pub initial_backoff_ms: Option<u64>,
    /// Retry delay ceiling in ms (default 3000).
    #[serde(default = "default_max_backoff_ms")]
    pub max_backoff_ms: Option<u64>,
    /// Socket / request timeout in ms (default 5000).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

impl MongoDbSinkConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.unwrap_or(5_000).max(1))
    }

    pub fn validate(&self) -> Result<()> {
        parse_connection_string(&self.connection_string)?;
        if self.database.trim().is_empty() || self.database.contains(['/', ' ', '\0']) {
            return Err(ConnectorError::Dispatch(format!(
                "mongodb database must be a bare name: {:?}",
                self.database
            )));
        }
        if self.collection_template.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "mongodb collection_template must not be empty".to_string(),
            ));
        }
        // Strict template checks with dummy values.
        self.resolve_collection("dummy/topic", b"{}", QoS::AtMostOnce, 0)?;
        match &self.operation {
            MongoOperation::InsertOne => {}
            MongoOperation::UpdateOne {
                filter_template, ..
            }
            | MongoOperation::ReplaceOne {
                filter_template, ..
            } => {
                let rendered =
                    self.event_vars("dummy", b"{}", QoS::AtMostOnce, 0, filter_template)?;
                serde_json::from_str::<serde_json::Value>(&rendered).map_err(|e| {
                    ConnectorError::Dispatch(format!(
                        "mongodb filter_template must render JSON: {e}"
                    ))
                })?;
            }
        }
        if self.batch_size == Some(0) {
            return Err(ConnectorError::Dispatch(
                "mongodb batch_size must be >= 1".to_string(),
            ));
        }
        if self.batch_bytes == Some(0) {
            return Err(ConnectorError::Dispatch(
                "mongodb batch_bytes must be >= 1".to_string(),
            ));
        }
        Ok(())
    }

    pub fn effective_batch_size(&self) -> usize {
        self.batch_size.unwrap_or(usize::MAX).max(1)
    }

    pub fn effective_batch_bytes(&self) -> usize {
        self.batch_bytes.unwrap_or(usize::MAX).max(1)
    }

    pub fn effective_linger(&self) -> Duration {
        self.linger_ms
            .map(Duration::from_millis)
            .unwrap_or(Duration::MAX)
    }

    /// Template variables for one event.
    fn template_vars(topic: &str, payload: &[u8], qos: QoS, millis: i64) -> Vec<(String, String)> {
        let doc: serde_json::Value = serde_json::from_slice(payload).unwrap_or_default();
        let field = |name: &str| match doc.get(name) {
            Some(serde_json::Value::String(text)) => text.clone(),
            Some(scalar) if scalar.is_number() || scalar.is_boolean() => scalar.to_string(),
            _ => String::new(),
        };
        vec![
            ("topic".to_string(), topic.to_string()),
            ("client_id".to_string(), field("client_id")),
            ("qos".to_string(), u8::from(qos).to_string()),
            ("timestamp".to_string(), millis.to_string()),
        ]
    }

    fn event_vars(
        &self,
        topic: &str,
        payload: &[u8],
        qos: QoS,
        millis: i64,
        template: &str,
    ) -> Result<String> {
        let mut vars = Self::template_vars(topic, payload, qos, millis);
        // `${payload.<field>}` JSON extraction on top.
        let doc: serde_json::Value = serde_json::from_slice(payload).unwrap_or_default();
        let mut rest = template;
        while let Some(start) = rest.find("${payload.") {
            let after = &rest[start + "${payload.".len()..];
            if let Some(close) = after.find('}') {
                let name = &after[..close];
                let value = match doc.get(name) {
                    Some(serde_json::Value::String(text)) => text.clone(),
                    Some(scalar) if scalar.is_number() || scalar.is_boolean() => scalar.to_string(),
                    _ => String::new(),
                };
                vars.push((format!("payload.{name}"), value));
                rest = &after[close + 1..];
            } else {
                break;
            }
        }
        let borrowed: Vec<(&str, String)> =
            vars.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
        render_template(template, &borrowed)
    }

    /// Resolve + validate the collection for one event.
    pub fn resolve_collection(
        &self,
        topic: &str,
        payload: &[u8],
        qos: QoS,
        millis: i64,
    ) -> Result<String> {
        let vars = Self::template_vars(topic, payload, qos, millis);
        let borrowed: Vec<(&str, String)> =
            vars.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
        let collection = render_template(&self.collection_template, &borrowed)?;
        if collection.trim().is_empty()
            || collection.contains('\0')
            || collection.starts_with("system.")
        {
            return Err(ConnectorError::Dispatch(format!(
                "mongodb collection resolved invalid: {collection:?}"
            )));
        }
        Ok(collection)
    }
}

/// Parsed connection endpoint (first seed host wins for the native
/// transport; replica-set failover beyond the seed list is out of
/// scope for the edge bridge).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MongoEndpoint {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub auth_source: String,
    pub srv: bool,
}

pub fn parse_connection_string(uri: &str) -> Result<MongoEndpoint> {
    let uri = uri.trim();
    let (srv, rest) = match uri.split_once("://") {
        Some(("mongodb", rest)) => (false, rest),
        Some(("mongodb+srv", rest)) => (true, rest),
        _ => {
            return Err(ConnectorError::Dispatch(format!(
                "mongodb connection string must start with mongodb:// or mongodb+srv://: {uri:?}"
            )));
        }
    };
    // Split credentials, hosts, and path/options.
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, ""),
    };
    let (credentials, hosts) = match authority.rfind('@') {
        Some(index) => (&authority[..index], &authority[index + 1..]),
        None => ("", authority),
    };
    let (username, password) = match credentials.split_once(':') {
        Some((user, pass)) => (Some(user.to_string()), Some(pass.to_string())),
        None if credentials.is_empty() => (None, None),
        None => (Some(credentials.to_string()), None),
    };
    let first_host = hosts.split(',').next().unwrap_or_default();
    let (host, port) = match first_host.rsplit_once(':') {
        Some((host, port)) => {
            let port: u16 = port
                .parse()
                .map_err(|_| ConnectorError::Dispatch(format!("mongodb bad port in {uri:?}")))?;
            (host, port)
        }
        None => (first_host, 27017),
    };
    if host.is_empty() {
        return Err(ConnectorError::Dispatch(format!(
            "mongodb host must not be empty in {uri:?}"
        )));
    }
    // ?authSource=X query option (default "admin").
    let mut auth_source = "admin".to_string();
    if let Some(query) = path.split_once('?').map(|(_, query)| query) {
        for pair in query.split('&') {
            if let Some(("authSource", value)) = pair.split_once('=') {
                if !value.is_empty() {
                    auth_source = value.to_string();
                }
            }
        }
    }
    Ok(MongoEndpoint {
        host: host.to_string(),
        port,
        username,
        password,
        auth_source,
        srv,
    })
}

// ---------------------------------------------------------------------------
// Transport.
// ---------------------------------------------------------------------------

/// One document operation inside a bulk batch.
#[derive(Debug, Clone, PartialEq)]
pub struct MongoDbDocumentItem {
    pub operation: MongoOperation,
    /// Filter for update/replace (None for inserts).
    pub filter: Option<BsonDocument>,
    /// Full document (insert/replace) or `$set` content (update).
    pub document: BsonDocument,
    pub upsert: bool,
    pub encoded_bytes: usize,
}

/// Scripted write outcome for the mock transport.
#[derive(Debug, Clone)]
pub enum MockMongoOutcome {
    /// Success.
    Ok,
    /// Transient failure (retries in-loop): pool timeouts, network.
    ConnectionError(String),
    /// Server write error with a code (11000/121 terminal, rest retry).
    WriteError { code: i32, message: String },
}

/// One captured bulk call.
#[derive(Debug, Clone)]
pub struct CapturedMongoBulk {
    pub db: String,
    pub collection: String,
    pub docs: Vec<MongoDbDocumentItem>,
}

#[async_trait]
pub trait MongoDbTransport: Send + Sync {
    async fn execute_bulk(
        &self,
        db: &str,
        collection: &str,
        docs: Vec<MongoDbDocumentItem>,
    ) -> Result<()>;
}

/// In-memory transport with scripted outcomes (tests, dry runs).
#[derive(Debug, Default)]
pub struct MockMongoDbTransport {
    scripted: parking_lot::Mutex<std::collections::VecDeque<MockMongoOutcome>>,
    captured: parking_lot::Mutex<Vec<CapturedMongoBulk>>,
    calls: AtomicU64,
}

impl MockMongoDbTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue outcomes consumed in order (default: success).
    pub fn script_outcomes(&self, outcomes: Vec<MockMongoOutcome>) {
        *self.scripted.lock() = outcomes.into_iter().collect();
    }

    pub fn captured(&self) -> Vec<CapturedMongoBulk> {
        self.captured.lock().clone()
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl MongoDbTransport for MockMongoDbTransport {
    async fn execute_bulk(
        &self,
        db: &str,
        collection: &str,
        docs: Vec<MongoDbDocumentItem>,
    ) -> Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.captured.lock().push(CapturedMongoBulk {
            db: db.to_string(),
            collection: collection.to_string(),
            docs: docs.clone(),
        });
        match self.scripted.lock().pop_front() {
            None | Some(MockMongoOutcome::Ok) => Ok(()),
            Some(MockMongoOutcome::ConnectionError(message)) => {
                Err(ConnectorError::Connection(message))
            }
            Some(MockMongoOutcome::WriteError { code, message }) => Err(match code {
                11_000 | 11_001 | 12_582 | 121 => {
                    ConnectorError::Dispatch(format!("mock mongo write error {code}: {message}"))
                }
                _ => {
                    ConnectorError::Connection(format!("mock mongo write error {code}: {message}"))
                }
            }),
        }
    }
}

/// Native transport: OP_MSG over TCP with SCRAM-SHA-256.
pub struct NativeMongoDbTransport {
    endpoint: MongoEndpoint,
    stream: tokio::sync::Mutex<Option<tokio::net::TcpStream>>,
    request_id: AtomicU32,
    timeout: Duration,
}

impl NativeMongoDbTransport {
    pub fn new(config: &MongoDbSinkConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            endpoint: parse_connection_string(&config.connection_string)?,
            stream: tokio::sync::Mutex::new(None),
            request_id: AtomicU32::new(1),
            timeout: config.timeout(),
        })
    }

    async fn roundtrip(&self, body: &BsonDocument) -> Result<BsonDocument> {
        let request_id = self.request_id.fetch_add(1, Ordering::SeqCst) as i32;
        let frame = encode_op_msg(body, request_id);
        let mut guard = self.stream.lock().await;
        let stream = guard
            .as_mut()
            .ok_or_else(|| ConnectorError::Connection("mongodb not connected".to_string()))?;
        stream
            .write_all(&frame)
            .await
            .map_err(|e| ConnectorError::Connection(format!("mongodb write failed: {e}")))?;
        let mut head = [0u8; 4];
        tokio::time::timeout(self.timeout.saturating_mul(2), stream.read_exact(&mut head))
            .await
            .map_err(|_| ConnectorError::Connection("mongodb read timeout".to_string()))?
            .map_err(|e| ConnectorError::Connection(format!("mongodb read failed: {e}")))?;
        let total = i32::from_le_bytes(head) as usize;
        if total > 48 * 1024 * 1024 {
            return Err(ConnectorError::Connection(
                "mongodb frame too large".to_string(),
            ));
        }
        let mut rest = vec![0u8; total - 4];
        stream
            .read_exact(&mut rest)
            .await
            .map_err(|e| ConnectorError::Connection(format!("mongodb read failed: {e}")))?;
        let mut full = head.to_vec();
        full.extend_from_slice(&rest);
        let (_, reply) = decode_op_msg(&full)?;
        Ok(reply)
    }

    /// Dial, say hello, and SCRAM-authenticate when configured.
    pub async fn connect(&self) -> Result<()> {
        if self.stream.lock().await.is_some() {
            return Ok(());
        }
        if self.endpoint.srv {
            return Err(ConnectorError::Dispatch(
                "mongodb+srv needs DNS SRV resolution; use mongodb:// with explicit hosts"
                    .to_string(),
            ));
        }
        let addr = format!("{}:{}", self.endpoint.host, self.endpoint.port);
        let stream = tokio::time::timeout(self.timeout, tokio::net::TcpStream::connect(&addr))
            .await
            .map_err(|_| ConnectorError::Connection(format!("mongodb connect timeout: {addr}")))?
            .map_err(|e| ConnectorError::Connection(format!("mongodb connect failed: {e}")))?;
        *self.stream.lock().await = Some(stream);
        // Hello (maxWireVersion selects the command surface).
        let mut hello = BsonDocument::new();
        hello
            .fields
            .push(("hello".to_string(), BsonValue::Int32(1)));
        let reply = self.roundtrip(&hello).await?;
        check_ok(&reply, "hello")?;
        // SCRAM-SHA-256 when credentials are configured.
        if let (Some(username), Some(password)) = (
            self.endpoint.username.clone(),
            self.endpoint.password.clone(),
        ) {
            self.scram_auth(&username, password.as_bytes()).await?;
        }
        Ok(())
    }

    async fn scram_auth(&self, username: &str, password: &[u8]) -> Result<()> {
        // Fixed-shape but unique-per-connection client nonce.
        let client_nonce = format!(
            "indra{:x}{:x}",
            now_millis().max(0) as u64,
            self.request_id.load(Ordering::SeqCst)
        );
        let first_bare = format!("n={username},r={client_nonce}");
        let mut start = BsonDocument::new();
        start
            .fields
            .push(("saslStart".to_string(), BsonValue::Int32(1)));
        start.fields.push((
            "mechanism".to_string(),
            BsonValue::String("SCRAM-SHA-256".to_string()),
        ));
        start.fields.push((
            "payload".to_string(),
            BsonValue::Binary(format!("n,,{first_bare}").into_bytes()),
        ));
        start.fields.push((
            "$db".to_string(),
            BsonValue::String(self.endpoint.auth_source.clone()),
        ));
        let reply = self.roundtrip(&start).await?;
        check_ok(&reply, "saslStart")?;
        let conversation = match reply.get("conversationId") {
            Some(BsonValue::Int32(v)) => *v,
            Some(BsonValue::Int64(v)) => *v as i32,
            _ => {
                return Err(ConnectorError::Connection(
                    "mongodb saslStart lacks conversationId".to_string(),
                ))
            }
        };
        let server_first = match reply.get("payload") {
            Some(BsonValue::Binary(v)) => String::from_utf8(v.clone()).map_err(|_| {
                ConnectorError::Connection("mongo SCRAM payload not UTF-8".to_string())
            })?,
            _ => {
                return Err(ConnectorError::Connection(
                    "mongodb saslStart lacks payload".to_string(),
                ))
            }
        };
        let (proof_b64, expected_server_sig) =
            scram_client_proof(username, password, &client_nonce, &server_first)?;
        let mut cont = BsonDocument::new();
        cont.fields
            .push(("saslContinue".to_string(), BsonValue::Int32(1)));
        cont.fields
            .push(("conversationId".to_string(), BsonValue::Int32(conversation)));
        cont.fields.push((
            "payload".to_string(),
            BsonValue::Binary(
                format!(
                    "c=biws,r={},p={}",
                    server_first
                        .split(',')
                        .find(|field| field.starts_with("r="))
                        .unwrap_or_default()
                        .trim_start_matches("r="),
                    proof_b64
                )
                .into_bytes(),
            ),
        ));
        cont.fields.push((
            "$db".to_string(),
            BsonValue::String(self.endpoint.auth_source.clone()),
        ));
        let reply = self.roundtrip(&cont).await?;
        check_ok(&reply, "saslContinue")?;
        let server_sig = match reply.get("payload") {
            Some(BsonValue::Binary(v)) => String::from_utf8(v.clone()).map_err(|_| {
                ConnectorError::Connection("mongo SCRAM payload not UTF-8".to_string())
            })?,
            _ => {
                return Err(ConnectorError::Connection(
                    "mongodb saslContinue lacks payload".to_string(),
                ))
            }
        };
        let presented = server_sig.strip_prefix("v=").unwrap_or_default();
        if presented != expected_server_sig {
            return Err(ConnectorError::Connection(
                "mongodb SCRAM server signature mismatch".to_string(),
            ));
        }
        Ok(())
    }
}

/// Require `"ok": 1.0` in a command reply.
fn check_ok(reply: &BsonDocument, command: &str) -> Result<()> {
    match reply.get("ok") {
        Some(BsonValue::Double(v)) if *v == 1.0 => Ok(()),
        Some(BsonValue::Int32(1)) | Some(BsonValue::Int64(1)) | Some(BsonValue::Bool(true)) => {
            Ok(())
        }
        _ => Err(ConnectorError::Connection(format!(
            "mongodb {command} not ok: {reply:?}"
        ))),
    }
}

/// Classify a server write error code: duplicate-key and validation
/// failures are terminal, everything else is transient.
fn classify_write_error(code: i32) -> bool {
    // Returns true when terminal.
    matches!(code, 11_000 | 11_001 | 12_582 | 121)
}

#[async_trait]
impl MongoDbTransport for NativeMongoDbTransport {
    async fn execute_bulk(
        &self,
        db: &str,
        collection: &str,
        docs: Vec<MongoDbDocumentItem>,
    ) -> Result<()> {
        if docs.is_empty() {
            return Ok(());
        }
        self.connect().await?;
        // All items in one call share the config operation.
        let operation = &docs[0].operation;
        let mut body = BsonDocument::new();
        match operation {
            MongoOperation::InsertOne => {
                body.fields.push((
                    "insert".to_string(),
                    BsonValue::String(collection.to_string()),
                ));
                let documents: Vec<BsonValue> = docs
                    .iter()
                    .map(|item| BsonValue::Document(item.document.clone()))
                    .collect();
                body.fields
                    .push(("documents".to_string(), BsonValue::Array(documents)));
                body.fields
                    .push(("ordered".to_string(), BsonValue::Bool(true)));
            }
            MongoOperation::UpdateOne { .. } | MongoOperation::ReplaceOne { .. } => {
                body.fields.push((
                    "update".to_string(),
                    BsonValue::String(collection.to_string()),
                ));
                let updates: Vec<BsonValue> = docs
                    .iter()
                    .map(|item| {
                        let filter = item.filter.clone().unwrap_or_default();
                        let update_doc = match operation {
                            MongoOperation::UpdateOne { .. } => BsonDocument {
                                fields: vec![(
                                    "$set".to_string(),
                                    BsonValue::Document(item.document.clone()),
                                )],
                            },
                            _ => item.document.clone(),
                        };
                        BsonValue::Document(BsonDocument {
                            fields: vec![
                                ("q".to_string(), BsonValue::Document(filter)),
                                ("u".to_string(), BsonValue::Document(update_doc)),
                                ("upsert".to_string(), BsonValue::Bool(item.upsert)),
                            ],
                        })
                    })
                    .collect();
                body.fields
                    .push(("updates".to_string(), BsonValue::Array(updates)));
                body.fields
                    .push(("ordered".to_string(), BsonValue::Bool(true)));
            }
        }
        body.fields
            .push(("$db".to_string(), BsonValue::String(db.to_string())));
        let reply = self.roundtrip(&body).await?;
        check_ok(&reply, "bulk write")?;
        if let Some(BsonValue::Array(errors)) = reply.get("writeErrors") {
            if let Some(BsonValue::Document(detail)) = errors.first() {
                let code = match detail.get("code") {
                    Some(BsonValue::Int32(v)) => *v,
                    Some(BsonValue::Int64(v)) => *v as i32,
                    _ => -1,
                };
                let message = match detail.get("errmsg") {
                    Some(BsonValue::String(text)) => text.clone(),
                    _ => "bulk write error".to_string(),
                };
                if classify_write_error(code) {
                    return Err(ConnectorError::Dispatch(format!(
                        "mongodb write error {code}: {message}"
                    )));
                }
                return Err(ConnectorError::Connection(format!(
                    "mongodb write error {code}: {message}"
                )));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Sink.
// ---------------------------------------------------------------------------

/// One buffered row: resolved collection, operation item, byte size.
#[derive(Debug, Clone)]
struct MongoRow {
    collection: String,
    item: MongoDbDocumentItem,
}

struct MongoBuffer {
    queue: BatchQueue<MongoRow>,
    bytes: usize,
}

/// MongoDB sink: buffers documents, bulk-writes grouped by collection.
pub struct MongoDbSink {
    config: MongoDbSinkConfig,
    transport: Arc<dyn MongoDbTransport>,
    buffer: parking_lot::Mutex<MongoBuffer>,
    backoff: parking_lot::Mutex<BackoffState>,
    sent_batches: AtomicU64,
    sent_records: AtomicU64,
}

impl MongoDbSink {
    pub fn new(config: MongoDbSinkConfig, transport: Arc<dyn MongoDbTransport>) -> Result<Self> {
        config.validate()?;
        let linger = config.effective_linger();
        Ok(Self {
            buffer: parking_lot::Mutex::new(MongoBuffer {
                queue: BatchQueue::new(config.effective_batch_size(), linger),
                bytes: 0,
            }),
            config,
            transport,
            backoff: parking_lot::Mutex::new(BackoffState::default()),
            sent_batches: AtomicU64::new(0),
            sent_records: AtomicU64::new(0),
        })
    }

    pub fn config(&self) -> &MongoDbSinkConfig {
        &self.config
    }

    pub fn sent_batches(&self) -> u64 {
        self.sent_batches.load(Ordering::Relaxed)
    }

    pub fn sent_records(&self) -> u64 {
        self.sent_records.load(Ordering::Relaxed)
    }

    pub fn buffered_rows(&self) -> usize {
        self.buffer.lock().queue.len()
    }

    /// Build the document for one event: payload object fields merged
    /// with the `_mqtt` metadata subdocument (non-object payloads ride
    /// under `value`; insert mode auto-generates `_id`).
    fn build_document(
        operation: &MongoOperation,
        topic: &Topic,
        payload: &Bytes,
        qos: QoS,
        millis: i64,
    ) -> Result<(Option<BsonDocument>, BsonDocument, bool)> {
        let text = std::str::from_utf8(payload)
            .map_err(|_| ConnectorError::Dispatch("mongodb payload must be UTF-8".to_string()))?;
        let value: serde_json::Value = serde_json::from_str(text)
            .map_err(|_| ConnectorError::Dispatch("mongodb payload must be JSON".to_string()))?;
        let client_id = value
            .get("client_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let mut meta = BsonDocument::new();
        meta.fields.push((
            "topic".to_string(),
            BsonValue::String(topic.as_str().to_string()),
        ));
        meta.fields.push((
            "client_id".to_string(),
            BsonValue::String(client_id.clone()),
        ));
        meta.fields
            .push(("qos".to_string(), BsonValue::Int32(u8::from(qos) as i32)));
        meta.fields
            .push(("timestamp".to_string(), BsonValue::Int64(millis)));
        let mut document = match &value {
            serde_json::Value::Object(map) => BsonDocument {
                fields: map
                    .iter()
                    .map(|(k, v)| (k.clone(), json_to_bson(v)))
                    .collect(),
            },
            other => BsonDocument {
                fields: vec![("value".to_string(), json_to_bson(other))],
            },
        };
        document
            .fields
            .push(("_mqtt".to_string(), BsonValue::Document(meta)));
        let has_id = document.get("_id").is_some();
        match operation {
            MongoOperation::InsertOne => {
                if !has_id {
                    document.fields.insert(
                        0,
                        ("_id".to_string(), BsonValue::ObjectId(generate_object_id())),
                    );
                }
                Ok((None, document, false))
            }
            MongoOperation::UpdateOne {
                filter_template,
                upsert,
            }
            | MongoOperation::ReplaceOne {
                filter_template,
                upsert,
            } => {
                // Filter templates render over the raw payload text.
                let rendered = render_template(
                    filter_template,
                    &[
                        ("topic", topic.as_str().to_string()),
                        ("client_id", client_id),
                        ("qos", u8::from(qos).to_string()),
                        ("timestamp", millis.to_string()),
                    ]
                    .iter()
                    .map(|(k, v)| (*k, v.clone()))
                    .collect::<Vec<_>>(),
                )?;
                let filter_json: serde_json::Value =
                    serde_json::from_str(&rendered).map_err(|e| {
                        ConnectorError::Dispatch(format!("mongodb filter must be JSON: {e}"))
                    })?;
                let filter = match json_to_bson(&filter_json) {
                    BsonValue::Document(doc) => doc,
                    _ => {
                        return Err(ConnectorError::Dispatch(
                            "mongodb filter must be a JSON object".to_string(),
                        ))
                    }
                };
                Ok((Some(filter), document, *upsert))
            }
        }
    }

    /// Flush buffered rows grouped by collection (no-op when empty).
    /// Transient failures retry in place; terminal write errors and
    /// exhaustion restore the buffer, engage backoff, and propagate.
    pub async fn flush(&self) -> Result<()> {
        self.backoff.lock().check()?;
        let (rows, oldest, taken_bytes) = {
            let mut buffer = self.buffer.lock();
            let (rows, oldest) = buffer.queue.take_batch();
            let taken = std::mem::replace(&mut buffer.bytes, 0);
            (rows, oldest, taken)
        };
        if rows.is_empty() {
            return Ok(());
        }
        // Group by collection, preserving first-seen order.
        let mut groups: Vec<(String, Vec<MongoDbDocumentItem>)> = Vec::new();
        for row in &rows {
            match groups
                .iter_mut()
                .find(|(collection, _)| collection == &row.collection)
            {
                Some((_, items)) => items.push(row.item.clone()),
                None => groups.push((row.collection.clone(), vec![row.item.clone()])),
            }
        }
        let record_count = rows.len() as u64;
        let max_retries = self.config.max_retries.unwrap_or(usize::MAX);
        let mut attempt = 0usize;
        loop {
            let mut outcome: Result<()> = Ok(());
            for (collection, items) in &groups {
                if let Err(e) = self
                    .transport
                    .execute_bulk(&self.config.database, collection, items.clone())
                    .await
                {
                    outcome = Err(e);
                    break;
                }
            }
            match outcome {
                Ok(()) => {
                    self.backoff.lock().success();
                    self.sent_batches
                        .fetch_add(groups.len() as u64, Ordering::Relaxed);
                    self.sent_records.fetch_add(record_count, Ordering::Relaxed);
                    return Ok(());
                }
                Err(ConnectorError::Connection(message)) => {
                    if attempt >= max_retries {
                        return self.restore_err(
                            rows,
                            oldest,
                            taken_bytes,
                            ConnectorError::Connection(message),
                        );
                    }
                    attempt += 1;
                    tokio::time::sleep(self.backoff_delay(attempt)).await;
                }
                Err(e) => {
                    return self.restore_err(rows, oldest, taken_bytes, e);
                }
            }
        }
    }

    fn backoff_delay(&self, attempt: usize) -> Duration {
        let initial = self.config.initial_backoff_ms.unwrap_or(100).max(1);
        let max = self.config.max_backoff_ms.unwrap_or(3_000).max(1);
        let grown = initial
            .saturating_mul(2u64.saturating_pow(attempt.min(10) as u32))
            .min(max);
        let jitter = (now_millis().max(0) as u64) % (grown / 2 + 1);
        Duration::from_millis(grown.saturating_add(jitter).min(max.saturating_mul(2)))
    }

    fn restore_err(
        &self,
        rows: Vec<MongoRow>,
        oldest: Option<std::time::Instant>,
        bytes: usize,
        error: ConnectorError,
    ) -> Result<()> {
        let mut buffer = self.buffer.lock();
        buffer.queue.restore(rows, oldest);
        buffer.bytes = buffer.bytes.saturating_add(bytes);
        self.backoff.lock().failure();
        Err(error)
    }

    /// Validate + buffer one event. Returns true when the batch is
    /// full, stale, or over the byte limit (caller flushes).
    fn buffer_row(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<bool> {
        if topic.as_str().is_empty() {
            return Err(ConnectorError::Dispatch(
                "mongodb row requires a non-empty topic".to_string(),
            ));
        }
        let millis = now_millis();
        let collection = self
            .config
            .resolve_collection(topic.as_str(), payload, qos, millis)?;
        let (filter, document, upsert) =
            Self::build_document(&self.config.operation, topic, payload, qos, millis)?;
        let encoded_bytes = document.encode().len();
        let item = MongoDbDocumentItem {
            operation: self.config.operation.clone(),
            filter,
            document,
            upsert,
            encoded_bytes,
        };
        let mut buffer = self.buffer.lock();
        let full = buffer.queue.push(MongoRow { collection, item });
        buffer.bytes = buffer.bytes.saturating_add(encoded_bytes);
        Ok(full || buffer.bytes >= self.config.effective_batch_bytes())
    }
}

#[async_trait]
impl Sink for MongoDbSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        if self.buffer_row(topic, payload, qos)? {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "mongodb"
    }
}

/// Management connector handle pairing an id with a MongoDB sink.
pub struct MongoDbConnector {
    id: String,
    sink: Arc<MongoDbSink>,
}

impl MongoDbConnector {
    pub fn new(id: impl Into<String>, sink: Arc<MongoDbSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }
}

impl super::Connector for MongoDbConnector {
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

    fn test_config() -> MongoDbSinkConfig {
        MongoDbSinkConfig {
            connection_string: "mongodb://user:pass@127.0.0.1:27017".to_string(),
            database: "telemetry".to_string(),
            collection_template: "telemetry_${topic}".to_string(),
            operation: MongoOperation::InsertOne,
            batch_size: Some(500),
            batch_bytes: Some(4_194_304),
            linger_ms: Some(20),
            max_retries: Some(4),
            initial_backoff_ms: Some(100),
            max_backoff_ms: Some(3_000),
            timeout_ms: None,
        }
    }

    fn test_sink(config: MongoDbSinkConfig) -> (Arc<MongoDbSink>, Arc<MockMongoDbTransport>) {
        let transport = Arc::new(MockMongoDbTransport::new());
        let sink = Arc::new(MongoDbSink::new(config, transport.clone()).unwrap());
        (sink, transport)
    }

    #[test]
    fn test_config_validation() {
        let mut config = test_config();
        assert!(config.validate().is_ok());

        config.connection_string = "http://127.0.0.1:27017".to_string();
        assert!(config.validate().is_err());
        config.connection_string = "mongodb+srv://cluster.example.net".to_string();
        assert!(config.validate().is_ok());
        config.connection_string = test_config().connection_string;

        config.database = "has space".to_string();
        assert!(config.validate().is_err());
        config.database = "telemetry".to_string();

        config.collection_template = "x/${nope}".to_string();
        assert!(config.validate().is_err());
        config.collection_template = test_config().collection_template;

        config.operation = MongoOperation::UpdateOne {
            filter_template: "not json".to_string(),
            upsert: true,
        };
        assert!(config.validate().is_err());
        config.operation = MongoOperation::UpdateOne {
            filter_template: "{\"device_id\": \"${client_id}\"}".to_string(),
            upsert: true,
        };
        assert!(config.validate().is_ok());
        config.operation = MongoOperation::InsertOne;

        config.batch_size = Some(0);
        assert!(config.validate().is_err());
        // Unbounded + huge depths accepted: zero clamped ceilings.
        config.batch_size = None;
        config.batch_bytes = Some(10_000_000);
        config.max_retries = None;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_connection_string_parsing() {
        let endpoint =
            parse_connection_string("mongodb://user:pass@127.0.0.1:27017/admin?authSource=ops")
                .unwrap();
        assert_eq!(endpoint.host, "127.0.0.1");
        assert_eq!(endpoint.port, 27017);
        assert_eq!(endpoint.username.as_deref(), Some("user"));
        assert_eq!(endpoint.password.as_deref(), Some("pass"));
        assert_eq!(endpoint.auth_source, "ops");
        assert!(!endpoint.srv);

        let endpoint = parse_connection_string("mongodb://seed1:27017,seed2:27018/db").unwrap();
        assert_eq!(endpoint.host, "seed1");
        assert_eq!(endpoint.port, 27017);
        assert_eq!(endpoint.username, None);
        assert_eq!(endpoint.auth_source, "admin");

        let endpoint = parse_connection_string("mongodb+srv://cluster.example.net").unwrap();
        assert!(endpoint.srv);
        assert_eq!(endpoint.port, 27017);

        assert!(parse_connection_string("").is_err());
        assert!(parse_connection_string("http://h:27017").is_err());
        assert!(parse_connection_string("mongodb://:27017").is_err());
        assert!(parse_connection_string("mongodb://h:notaport").is_err());
    }

    #[test]
    fn test_bson_roundtrip_and_layout() {
        let mut doc = BsonDocument::new();
        doc.fields
            .push(("n".to_string(), BsonValue::Int32(0x01020304)));
        doc.fields
            .push(("s".to_string(), BsonValue::String("hi".to_string())));
        doc.fields.push(("b".to_string(), BsonValue::Bool(true)));
        doc.fields.push(("d".to_string(), BsonValue::Double(1.5)));
        doc.fields.push(("nil".to_string(), BsonValue::Null));
        doc.fields.push((
            "sub".to_string(),
            BsonValue::Document(BsonDocument {
                fields: vec![("x".to_string(), BsonValue::Int64(-7))],
            }),
        ));
        let bytes = doc.encode();
        // Length prefix covers the whole document; NUL trailer ends it.
        assert_eq!(
            i32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize,
            bytes.len()
        );
        assert_eq!(bytes[bytes.len() - 1], 0x00);
        // First element: Int32 tag + "n" cstring + LE value bytes.
        assert_eq!(&bytes[4..7], &[0x10, b'n', 0x00]);
        assert_eq!(&bytes[7..11], &[0x04, 0x03, 0x02, 0x01]);
        assert_eq!(bytes[11], 0x02); // next tag: String
        let back = BsonDocument::decode(&bytes).unwrap();
        assert_eq!(back, doc);
        // Truncations and bad lengths fail loudly.
        assert!(BsonDocument::decode(&bytes[..bytes.len() - 1]).is_err());
        assert!(BsonDocument::decode(&[0x02, 0x00, 0x00, 0x00, 0x00]).is_err());
    }

    #[test]
    fn test_object_id_shape() {
        let first = generate_object_id();
        let second = generate_object_id();
        assert_ne!(first, second);
        // Big-endian epoch seconds prefix, non-decreasing.
        assert!(
            u32::from_be_bytes(first[..4].try_into().unwrap())
                <= u32::from_be_bytes(second[..4].try_into().unwrap())
        );
    }

    #[test]
    fn test_json_mapping_and_mqtt_injection() {
        let (sink, _) = test_sink(test_config());
        let _ = sink;
        let (filter, document, upsert) = MongoDbSink::build_document(
            &MongoOperation::InsertOne,
            &Topic::new("factory/line1/temp").unwrap(),
            &Bytes::from_static(br#"{"client_id":"sensor-101","temperature":78.4}"#),
            QoS::AtLeastOnce,
            1_726_160_000_000,
        )
        .unwrap();
        assert!(filter.is_none());
        assert!(!upsert);
        // Auto _id first, payload merged, _mqtt injected.
        assert!(matches!(document.get("_id"), Some(BsonValue::ObjectId(_))));
        assert_eq!(document.get("temperature"), Some(&BsonValue::Double(78.4)));
        let meta = match document.get("_mqtt") {
            Some(BsonValue::Document(meta)) => meta,
            other => panic!("_mqtt missing: {other:?}"),
        };
        assert_eq!(
            meta.get("topic"),
            Some(&BsonValue::String("factory/line1/temp".to_string()))
        );
        assert_eq!(
            meta.get("client_id"),
            Some(&BsonValue::String("sensor-101".to_string()))
        );
        assert_eq!(meta.get("qos"), Some(&BsonValue::Int32(1)));
        assert_eq!(
            meta.get("timestamp"),
            Some(&BsonValue::Int64(1_726_160_000_000))
        );

        // Non-object payloads ride under "value".
        let (_, document, _) = MongoDbSink::build_document(
            &MongoOperation::InsertOne,
            &Topic::new("t").unwrap(),
            &Bytes::from_static(b"42"),
            QoS::AtMostOnce,
            0,
        )
        .unwrap();
        assert_eq!(document.get("value"), Some(&BsonValue::Int32(42)));

        // Update mode renders the filter template + $set shape.
        let (filter, document, upsert) = MongoDbSink::build_document(
            &MongoOperation::UpdateOne {
                filter_template: "{\"device_id\": \"${client_id}\"}".to_string(),
                upsert: true,
            },
            &Topic::new("t").unwrap(),
            &Bytes::from_static(br#"{"client_id":"d7","v":1}"#),
            QoS::AtMostOnce,
            0,
        )
        .unwrap();
        assert!(upsert);
        assert_eq!(
            filter.unwrap().get("device_id"),
            Some(&BsonValue::String("d7".to_string()))
        );
        assert!(document.get("_mqtt").is_some());
    }

    #[test]
    fn test_op_msg_framing() {
        let mut body = BsonDocument::new();
        body.fields.push(("hello".to_string(), BsonValue::Int32(1)));
        let frame = encode_op_msg(&body, 7);
        let total = i32::from_le_bytes(frame[..4].try_into().unwrap()) as usize;
        assert_eq!(total, frame.len());
        assert_eq!(i32::from_le_bytes(frame[12..16].try_into().unwrap()), 2013);
        assert_eq!(frame[20], 0x00);
        let (request_id, back) = decode_op_msg(&frame).unwrap();
        assert_eq!(request_id, 7);
        assert_eq!(back, body);
        assert!(decode_op_msg(&frame[..10]).is_err());
    }

    #[test]
    fn test_scram_known_answer() {
        // Independent Python (hashlib/hmac/pbkdf2) vector: user indra,
        // fixed nonces, salt "saltysalt12345678", 4096 iterations.
        let server_first =
            "r=rOprNGfwEbeRWgbNEkqOcfhoK3k5e8m8r8c8,s=c2FsdHlzYWx0MTIzNDU2Nzg=,i=4096";
        let (proof_b64, server_sig) = scram_client_proof(
            "indra",
            b"s3cret-pass",
            "rOprNGfwEbeRWgbNEkqO",
            server_first,
        )
        .unwrap();
        assert_eq!(proof_b64, "/WeXeORFtAeaIMRl9KPSqCYOybXyIOdvwCTvSFAj8l4=");
        assert_eq!(server_sig, "FpANZr9jy3MU4R1Lli8Wu/fOH6w6mXz9BTpOnQU4GQQ=");
        // Nonce mismatch and bad iteration counts fail loudly.
        assert!(scram_client_proof("indra", b"s3cret-pass", "other", server_first).is_err());
        assert!(scram_client_proof(
            "indra",
            b"s3cret-pass",
            "rOprNGfwEbeRWgbNEkqO",
            "r=x,s=!!,i=1"
        )
        .is_err());
    }

    #[tokio::test]
    async fn test_grouping_by_collection() {
        let mut config = test_config();
        config.collection_template = "telemetry_${topic}".to_string();
        config.batch_size = Some(10);
        let (sink, transport) = test_sink(config);
        // Slashes ride into collection names verbatim here (template
        // has no sanitizer by design: operators own the template).
        sink.send(
            &Topic::new("a").unwrap(),
            &Bytes::from("{\"v\":1}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        sink.send(
            &Topic::new("b").unwrap(),
            &Bytes::from("{\"v\":2}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        sink.flush().await.unwrap();
        let captured = transport.captured();
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[0].collection, "telemetry_a");
        assert_eq!(captured[1].collection, "telemetry_b");
        assert_eq!(captured[0].db, "telemetry");
        // BSON fidelity: stored value survives the model.
        assert_eq!(
            captured[0].docs[0].document.get("v"),
            Some(&BsonValue::Int32(1))
        );
        assert!(matches!(
            captured[0].docs[0].document.get("_id"),
            Some(BsonValue::ObjectId(_))
        ));
        assert_eq!(sink.sent_records(), 2);
    }

    #[tokio::test]
    async fn test_retry_then_fail_fast() {
        let mut config = test_config();
        config.batch_size = Some(10);
        config.initial_backoff_ms = Some(1);
        config.max_backoff_ms = Some(2);
        let (sink, transport) = test_sink(config);
        transport.script_outcomes(vec![
            MockMongoOutcome::ConnectionError("pool timeout".to_string()),
            MockMongoOutcome::Ok,
        ]);

        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from("{}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        sink.flush().await.unwrap();
        assert_eq!(transport.calls(), 2);
        assert_eq!(sink.sent_records(), 1);
        assert_eq!(sink.buffered_rows(), 0);
    }

    #[tokio::test]
    async fn test_duplicate_key_is_terminal() {
        let mut config = test_config();
        config.batch_size = Some(10);
        config.max_retries = Some(5);
        let (sink, transport) = test_sink(config);
        transport.script_outcomes(vec![
            MockMongoOutcome::WriteError {
                code: 11_000,
                message: "dup key".to_string(),
            },
            MockMongoOutcome::Ok,
        ]);

        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from("{}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        let err = sink.flush().await.expect_err("duplicate key must fail");
        assert!(matches!(err, ConnectorError::Dispatch(_)));
        // No retry consumed the queued success; buffer retained.
        assert_eq!(transport.calls(), 1);
        assert_eq!(sink.buffered_rows(), 1);
    }
}
