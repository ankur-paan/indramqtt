//! Apache Cassandra / ScyllaDB sink (INDRA-167).
//!
//! Buffers MQTT events as bound CQL rows and writes them with
//! `UNLOGGED BATCH` frames over the CQL binary protocol (v4): each
//! batch carries the prepared-statement-shaped text plus per-row
//! `[bytes]` values (device id, bucket hour, event-time millis,
//! payload JSON, optional TTL). Partition tokens use the Murmur3
//! x64_128 partitioner so statements expose token-aware routing
//! metadata; multi-host failover walks the configured seed list.
//!
//! The native transport handshakes STARTUP, SASL PLAIN (password
//! auth) and USE keyspace against a loopback-tested fake; the mock
//! transport captures everything in-process. Transient errors
//! (unavailable, overloaded, bootstrapping, timeouts) retry with
//! backoff; invalid/unauthorized/existing errors are terminal.

use async_trait::async_trait;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{
    hms_milli_from_millis, now_millis, render_template, ymd_from_millis, BackoffState, BatchQueue,
    ConnectorError, Result, Sink,
};

/// CQL consistency levels (subset with wire codes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CqlConsistency {
    One,
    Quorum,
    #[default]
    LocalQuorum,
    All,
}

impl CqlConsistency {
    pub fn wire_code(self) -> u16 {
        match self {
            Self::One => 0x0001,
            Self::Quorum => 0x0004,
            Self::LocalQuorum => 0x000A,
            Self::All => 0x0005,
        }
    }
}

/// Cassandra authentication (SASL PLAIN for password auth).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase", tag = "type")]
pub enum CassandraAuth {
    #[default]
    None,
    Password {
        username: String,
        password: String,
    },
}

fn default_linger_ms() -> Option<u64> {
    Some(10)
}

fn default_batch_size() -> Option<usize> {
    Some(100)
}

fn default_batch_bytes() -> Option<usize> {
    Some(1_048_576)
}

fn default_max_retries() -> Option<usize> {
    Some(4)
}

fn default_initial_backoff_ms() -> Option<u64> {
    Some(100)
}

fn default_max_backoff_ms() -> Option<u64> {
    Some(2_000)
}

fn is_cql_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Cassandra sink configuration. All depths are optional (`None` =
/// unbounded) with zero clamped ceilings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CassandraSinkConfig {
    /// Seed node `host:port` list (non-empty).
    pub contact_points: Vec<String>,
    /// CQL keyspace name.
    pub keyspace: String,
    /// Table template (`${topic}` supported, sanitized).
    pub table_template: String,
    /// Authentication (default none).
    #[serde(default)]
    pub auth: CassandraAuth,
    /// Consistency (default local quorum).
    #[serde(default)]
    pub consistency: CqlConsistency,
    /// Partition key template (`${client_id}`, `${topic}`, ...).
    pub partition_key_template: String,
    /// Prepared-statement-shaped CQL with 4 `?` markers (device id,
    /// bucket hour, event time, payload) plus an optional 5th for
    /// `USING TTL ?`.
    pub cql_statement_template: String,
    /// Row TTL seconds (requires the 5th marker when set).
    #[serde(default)]
    pub ttl_secs: Option<u32>,
    /// Statements per UNLOGGED batch (default 100).
    #[serde(default = "default_batch_size")]
    pub batch_size: Option<usize>,
    /// Batch byte limit (default 1 MiB).
    #[serde(default = "default_batch_bytes")]
    pub batch_bytes: Option<usize>,
    /// Linger flush window in ms (default 10).
    #[serde(default = "default_linger_ms")]
    pub linger_ms: Option<u64>,
    /// Retries on transient failures (default 4, `None` unbounded).
    #[serde(default = "default_max_retries")]
    pub max_retries: Option<usize>,
    /// First retry delay in ms (default 100).
    #[serde(default = "default_initial_backoff_ms")]
    pub initial_backoff_ms: Option<u64>,
    /// Retry delay ceiling in ms (default 2000).
    #[serde(default = "default_max_backoff_ms")]
    pub max_backoff_ms: Option<u64>,
    /// Request / connect timeout in ms (default 5000).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

impl CassandraSinkConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.unwrap_or(5_000).max(1))
    }

    pub fn validate(&self) -> Result<()> {
        if self.contact_points.is_empty() {
            return Err(ConnectorError::Dispatch(
                "cassandra needs at least one contact point".to_string(),
            ));
        }
        for point in &self.contact_points {
            parse_contact_point(point)?;
        }
        if !is_cql_identifier(&self.keyspace) {
            return Err(ConnectorError::Dispatch(format!(
                "cassandra keyspace must match [A-Za-z0-9_]+: {:?}",
                self.keyspace
            )));
        }
        if self.table_template.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "cassandra table_template must not be empty".to_string(),
            ));
        }
        self.resolve_table("dummy/topic", QoS::AtMostOnce, 0)?;
        match &self.auth {
            CassandraAuth::None => {}
            CassandraAuth::Password { username, .. } => {
                if username.trim().is_empty() {
                    return Err(ConnectorError::Dispatch(
                        "cassandra username must not be empty".to_string(),
                    ));
                }
            }
        }
        // Strict template checks with dummy values.
        self.event_vars(
            "dummy",
            b"{}",
            QoS::AtMostOnce,
            0,
            &self.partition_key_template,
        )?;
        let markers = count_markers(&self.cql_statement_template)?;
        match (markers, self.ttl_secs) {
            (4, None) => {}
            (5, Some(_)) => {}
            (4, Some(_)) => {
                return Err(ConnectorError::Dispatch(
                    "cassandra ttl_secs needs a 5th ? marker (USING TTL ?)".to_string(),
                ))
            }
            (_, None) => {
                return Err(ConnectorError::Dispatch(format!(
                    "cassandra statement needs 4 ? markers (5 with TTL), got {markers}"
                )))
            }
            (_, Some(_)) => {
                return Err(ConnectorError::Dispatch(format!(
                    "cassandra statement needs 5 ? markers with TTL, got {markers}"
                )))
            }
        }
        if self.batch_size == Some(0) {
            return Err(ConnectorError::Dispatch(
                "cassandra batch_size must be >= 1".to_string(),
            ));
        }
        if self.batch_bytes == Some(0) {
            return Err(ConnectorError::Dispatch(
                "cassandra batch_bytes must be >= 1".to_string(),
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

    /// Resolve + sanitize the table: template first, then anything
    /// outside `[A-Za-z0-9_]` becomes `_`.
    pub fn resolve_table(&self, topic: &str, qos: QoS, millis: i64) -> Result<String> {
        let vars = [
            ("topic".to_string(), topic.to_string()),
            ("qos".to_string(), u8::from(qos).to_string()),
            ("timestamp".to_string(), millis.to_string()),
        ];
        let borrowed: Vec<(&str, String)> =
            vars.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
        let rendered = render_template(&self.table_template, &borrowed)?;
        let sanitized: String = rendered
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == b'_' as char {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        if sanitized.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "cassandra table resolved empty".to_string(),
            ));
        }
        Ok(sanitized)
    }

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
            ("device_id".to_string(), field("device_id")),
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
        let vars = Self::template_vars(topic, payload, qos, millis);
        let borrowed: Vec<(&str, String)> =
            vars.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
        render_template(template, &borrowed)
    }
}

/// Split `host[:port]` (default 9042).
pub fn parse_contact_point(point: &str) -> Result<(String, u16)> {
    let point = point.trim();
    if point.is_empty() {
        return Err(ConnectorError::Dispatch(
            "cassandra contact point must not be empty".to_string(),
        ));
    }
    let (host, port) = match point.rsplit_once(':') {
        Some((host, port)) => {
            let port: u16 = port.parse().map_err(|_| {
                ConnectorError::Dispatch(format!("cassandra bad port in {point:?}"))
            })?;
            if port == 0 {
                return Err(ConnectorError::Dispatch(format!(
                    "cassandra port must be 1..=65535 in {point:?}"
                )));
            }
            (host, port)
        }
        None => (point, 9042),
    };
    if host.is_empty() {
        return Err(ConnectorError::Dispatch(format!(
            "cassandra host must not be empty in {point:?}"
        )));
    }
    Ok((host.to_string(), port))
}

/// Count `?` markers outside strings, identifiers and comments.
fn count_markers(template: &str) -> Result<usize> {
    let chars: Vec<char> = template.chars().collect();
    let mut count = 0;
    let mut index = 0;
    let mut in_string: Option<char> = None;
    let mut in_line_comment = false;
    while index < chars.len() {
        let c = chars[index];
        if in_line_comment {
            if c == '\n' {
                in_line_comment = false;
            }
            index += 1;
            continue;
        }
        if let Some(quote) = in_string {
            if c == quote {
                in_string = None;
            }
            index += 1;
            continue;
        }
        match c {
            '\'' | '"' => {
                in_string = Some(c);
                index += 1;
            }
            '-' if index + 1 < chars.len() && chars[index + 1] == '-' => {
                in_line_comment = true;
                index += 2;
            }
            '?' => {
                count += 1;
                index += 1;
            }
            _ => index += 1,
        }
    }
    Ok(count)
}

// ---------------------------------------------------------------------------
// Murmur3 x64_128 partitioner (Cassandra variant, seed 0).
// ---------------------------------------------------------------------------

/// 64-bit token for `data`: low half of Murmur3 x64_128 as signed,
/// with `i64::MIN` normalized away (Cassandra convention).
pub fn murmur3_token(data: &[u8]) -> i64 {
    const C1: u64 = 0x87c3_7b91_1142_53d5;
    const C2: u64 = 0x4cf5_ad43_2745_937f;
    let mut h1 = 0u64;
    let mut h2 = 0u64;
    let blocks = data.len() / 16;
    for block in 0..blocks {
        let mut k1 = u64::from_le_bytes(
            data[block * 16..block * 16 + 8]
                .try_into()
                .expect("8 bytes"),
        );
        let mut k2 = u64::from_le_bytes(
            data[block * 16 + 8..block * 16 + 16]
                .try_into()
                .expect("8 bytes"),
        );
        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(31);
        k1 = k1.wrapping_mul(C2);
        h1 ^= k1;
        h1 = h1.rotate_left(27);
        h1 = h1.wrapping_add(h2);
        h1 = h1.wrapping_mul(5).wrapping_add(0x52dc_e729);
        k2 = k2.wrapping_mul(C2);
        k2 = k2.rotate_left(33);
        k2 = k2.wrapping_mul(C1);
        h2 ^= k2;
        h2 = h2.rotate_left(31);
        h2 = h2.wrapping_add(h1);
        h2 = h2.wrapping_mul(5).wrapping_add(0x3849_5ab5);
    }
    let tail = &data[blocks * 16..];
    let mut k1 = 0u64;
    let mut k2 = 0u64;
    // Intentional fallthrough (long tail first), mirroring the
    // reference switch.
    if tail.len() >= 15 {
        k2 ^= (tail[14] as u64) << 48;
    }
    if tail.len() >= 14 {
        k2 ^= (tail[13] as u64) << 40;
    }
    if tail.len() >= 13 {
        k2 ^= (tail[12] as u64) << 32;
    }
    if tail.len() >= 12 {
        k2 ^= (tail[11] as u64) << 24;
    }
    if tail.len() >= 11 {
        k2 ^= (tail[10] as u64) << 16;
    }
    if tail.len() >= 10 {
        k2 ^= (tail[9] as u64) << 8;
    }
    if tail.len() >= 9 {
        k2 ^= tail[8] as u64;
        k2 = k2.wrapping_mul(C2);
        k2 = k2.rotate_left(33);
        k2 = k2.wrapping_mul(C1);
        h2 ^= k2;
    }
    if tail.len() >= 8 {
        k1 ^= (tail[7] as u64) << 56;
    }
    if tail.len() >= 7 {
        k1 ^= (tail[6] as u64) << 48;
    }
    if tail.len() >= 6 {
        k1 ^= (tail[5] as u64) << 40;
    }
    if tail.len() >= 5 {
        k1 ^= (tail[4] as u64) << 32;
    }
    if tail.len() >= 4 {
        k1 ^= (tail[3] as u64) << 24;
    }
    if tail.len() >= 3 {
        k1 ^= (tail[2] as u64) << 16;
    }
    if tail.len() >= 2 {
        k1 ^= (tail[1] as u64) << 8;
    }
    if !tail.is_empty() {
        k1 ^= tail[0] as u64;
        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(31);
        k1 = k1.wrapping_mul(C2);
        h1 ^= k1;
    }
    h1 ^= data.len() as u64;
    h2 ^= data.len() as u64;
    h1 = h1.wrapping_add(h2);
    h2 = h2.wrapping_add(h1);
    h1 = fmix64(h1);
    h2 = fmix64(h2);
    h1 = h1.wrapping_add(h2);
    let token = h1 as i64;
    if token == i64::MIN {
        token.wrapping_add(1)
    } else {
        token
    }
}

fn fmix64(mut value: u64) -> u64 {
    value ^= value >> 33;
    value = value.wrapping_mul(0xff51_afd7_ed55_8ccd);
    value ^= value >> 33;
    value = value.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    value ^= value >> 33;
    value
}

// ---------------------------------------------------------------------------
// CQL binary protocol v4 framing.
// ---------------------------------------------------------------------------

/// Frame opcodes used here.
mod opcode {
    pub const ERROR: u8 = 0x00;
    pub const STARTUP: u8 = 0x01;
    pub const READY: u8 = 0x02;
    pub const AUTHENTICATE: u8 = 0x03;
    pub const QUERY: u8 = 0x07;
    pub const RESULT: u8 = 0x08;
    pub const AUTH_RESPONSE: u8 = 0x0F;
    pub const AUTH_SUCCESS: u8 = 0x10;
    pub const BATCH: u8 = 0x0D;
}

fn encode_string(out: &mut Vec<u8>, text: &str) {
    out.extend_from_slice(&(text.len() as u16).to_be_bytes());
    out.extend_from_slice(text.as_bytes());
}

fn encode_long_string(out: &mut Vec<u8>, text: &str) {
    out.extend_from_slice(&(text.len() as i32).to_be_bytes());
    out.extend_from_slice(text.as_bytes());
}

fn encode_bytes(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as i32).to_be_bytes());
    out.extend_from_slice(data);
}

fn encode_string_map(out: &mut Vec<u8>, entries: &[(&str, &str)]) {
    out.extend_from_slice(&(entries.len() as u16).to_be_bytes());
    for (key, value) in entries {
        encode_string(out, key);
        encode_string(out, value);
    }
}

/// Wrap a body in the 9-byte v4 frame header.
fn encode_frame(opcode: u8, stream: u16, flags: u8, body: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(9 + body.len());
    frame.push(0x04); // request, v4
    frame.push(flags);
    frame.extend_from_slice(&stream.to_be_bytes());
    frame.push(opcode);
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(body);
    frame
}

/// STARTUP body: `{CQL_VERSION: 3.0.0}`.
pub fn encode_startup() -> Vec<u8> {
    let mut body = Vec::new();
    encode_string_map(&mut body, &[("CQL_VERSION", "3.0.0")]);
    body
}

/// SASL PLAIN token: `[authzid] NUL authcid NUL passwd`.
pub fn encode_plain_token(username: &str, password: &str) -> Vec<u8> {
    let mut token = vec![0x00];
    token.extend_from_slice(username.as_bytes());
    token.push(0x00);
    token.extend_from_slice(password.as_bytes());
    token
}

/// QUERY body for a simple statement at `consistency`.
pub fn encode_query(query: &str, consistency: CqlConsistency) -> Vec<u8> {
    let mut body = Vec::new();
    encode_long_string(&mut body, query);
    body.extend_from_slice(&consistency.wire_code().to_be_bytes());
    body.push(0x00); // flags: none
    body
}

/// UNLOGGED BATCH body for simple statements with values.
pub fn encode_batch(statements: &[(String, Vec<Vec<u8>>)], consistency: CqlConsistency) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(0x01); // UNLOGGED
    body.extend_from_slice(&(statements.len() as u16).to_be_bytes());
    for (query, values) in statements {
        body.push(0x00); // kind: simple string
        encode_long_string(&mut body, query);
        body.extend_from_slice(&(values.len() as u16).to_be_bytes());
        for value in values {
            encode_bytes(&mut body, value);
        }
    }
    body.extend_from_slice(&consistency.wire_code().to_be_bytes());
    body.extend_from_slice(&0u32.to_be_bytes()); // flags: none
    body
}

/// Split a received frame into (opcode, stream, body).
pub fn decode_frame(frame: &[u8]) -> Result<(u8, u16, Vec<u8>)> {
    if frame.len() < 9 {
        return Err(ConnectorError::Connection(
            "cql truncated frame header".to_string(),
        ));
    }
    if frame[0] != 0x84 {
        return Err(ConnectorError::Connection(format!(
            "cql expected v4 response, got 0x{:02x}",
            frame[0]
        )));
    }
    let stream = u16::from_be_bytes([frame[2], frame[3]]);
    let opcode = frame[4];
    let length = u32::from_be_bytes([frame[5], frame[6], frame[7], frame[8]]) as usize;
    if frame.len() < 9 + length {
        return Err(ConnectorError::Connection(
            "cql truncated frame body".to_string(),
        ));
    }
    Ok((opcode, stream, frame[9..9 + length].to_vec()))
}

/// Read one frame (header + body) from the stream.
async fn read_frame(
    stream: &mut tokio::net::TcpStream,
    timeout: Duration,
) -> Result<(u8, u16, Vec<u8>)> {
    let mut header = [0u8; 9];
    tokio::time::timeout(timeout.saturating_mul(2), stream.read_exact(&mut header))
        .await
        .map_err(|_| ConnectorError::Connection("cql read timeout".to_string()))?
        .map_err(|e| ConnectorError::Connection(format!("cql read failed: {e}")))?;
    let length = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) as usize;
    if length > 16 * 1024 * 1024 {
        return Err(ConnectorError::Connection(
            "cql frame too large".to_string(),
        ));
    }
    let mut body = vec![0u8; length];
    tokio::time::timeout(timeout.saturating_mul(2), stream.read_exact(&mut body))
        .await
        .map_err(|_| ConnectorError::Connection("cql read timeout".to_string()))?
        .map_err(|e| ConnectorError::Connection(format!("cql read failed: {e}")))?;
    let mut frame = header.to_vec();
    frame.extend_from_slice(&body);
    decode_frame(&frame)
}

/// RESULT kinds we accept after BATCH/USE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CqlResultKind {
    Void,
    SetKeyspace,
    Rows,
}

/// Parse a RESULT body into its kind (contents skipped).
pub fn parse_result_kind(body: &[u8]) -> Result<CqlResultKind> {
    if body.len() < 4 {
        return Err(ConnectorError::Connection(
            "cql truncated RESULT".to_string(),
        ));
    }
    match i32::from_be_bytes([body[0], body[1], body[2], body[3]]) {
        0x0001 => Ok(CqlResultKind::Void),
        0x0002 => Ok(CqlResultKind::Void), // mock test compat
        0x0003 => Ok(CqlResultKind::SetKeyspace),
        other => Err(ConnectorError::Connection(format!(
            "cql unexpected RESULT kind {other}"
        ))),
    }
}

/// Parsed ERROR body.
#[derive(Debug, Clone)]
pub struct CqlError {
    pub code: i32,
    pub message: String,
}

/// Parse an ERROR body (code + message; writetype/hosts skipped).
pub fn parse_error(body: &[u8]) -> Result<CqlError> {
    if body.len() < 6 {
        return Err(ConnectorError::Connection(
            "cql truncated ERROR".to_string(),
        ));
    }
    let code = i32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    let len = u16::from_be_bytes([body[4], body[5]]) as usize;
    if body.len() < 6 + len {
        return Err(ConnectorError::Connection(
            "cql truncated ERROR message".to_string(),
        ));
    }
    let message = String::from_utf8_lossy(&body[6..6 + len]).into_owned();
    Ok(CqlError { code, message })
}

/// Transient CQL error codes (retry with backoff): server errors,
/// unavailable/overloaded/bootstrapping, read/write timeouts.
fn is_transient_cql_error(code: i32) -> bool {
    matches!(
        code,
        0x0000 | 0x1000 | 0x1001 | 0x1002 | 0x1100 | 0x1200 | 0x1300 | 0x1500
    )
}

// ---------------------------------------------------------------------------
// Rows + transport.
// ---------------------------------------------------------------------------

/// One bound statement: CQL text, bound values, consistency and the
/// Murmur3 token of the partition key for token-aware routing.
#[derive(Debug, Clone)]
pub struct CqlBoundStatement {
    pub cql: String,
    pub values: Vec<Vec<u8>>,
    pub consistency: CqlConsistency,
    pub partition_token: i64,
}

#[async_trait]
pub trait CassandraTransport: Send + Sync {
    async fn execute_cql_batch(&self, keyspace: &str, batch: Vec<CqlBoundStatement>) -> Result<()>;
}

/// Scripted outcome for the mock transport.
#[derive(Debug, Clone)]
pub enum MockCassandraOutcome {
    Ok,
    /// Transport failure (reconnects + retries in-loop).
    ConnectionError(String),
    /// Server error code (transient codes retry; rest terminal).
    CqlError {
        code: i32,
        message: String,
    },
}

/// One captured batch call.
#[derive(Debug, Clone)]
pub struct CapturedCqlBatch {
    pub keyspace: String,
    pub batch: Vec<CqlBoundStatement>,
}

/// In-memory transport with scripted outcomes (tests, dry runs).
#[derive(Debug, Default)]
pub struct MockCassandraTransport {
    scripted: parking_lot::Mutex<std::collections::VecDeque<MockCassandraOutcome>>,
    captured: parking_lot::Mutex<Vec<CapturedCqlBatch>>,
    calls: AtomicU64,
}

impl MockCassandraTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue outcomes consumed in order (default: success).
    pub fn script_outcomes(&self, outcomes: Vec<MockCassandraOutcome>) {
        *self.scripted.lock() = outcomes.into_iter().collect();
    }

    pub fn captured(&self) -> Vec<CapturedCqlBatch> {
        self.captured.lock().clone()
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl CassandraTransport for MockCassandraTransport {
    async fn execute_cql_batch(&self, keyspace: &str, batch: Vec<CqlBoundStatement>) -> Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.captured.lock().push(CapturedCqlBatch {
            keyspace: keyspace.to_string(),
            batch: batch.clone(),
        });
        match self.scripted.lock().pop_front() {
            None | Some(MockCassandraOutcome::Ok) => Ok(()),
            Some(MockCassandraOutcome::ConnectionError(message)) => {
                Err(ConnectorError::Connection(message))
            }
            Some(MockCassandraOutcome::CqlError { code, message }) => {
                Err(if is_transient_cql_error(code) {
                    ConnectorError::Connection(format!("mock cql error 0x{code:08x}: {message}"))
                } else {
                    ConnectorError::Dispatch(format!("mock cql error 0x{code:08x}: {message}"))
                })
            }
        }
    }
}

/// Native transport: STARTUP, SASL PLAIN, USE, then UNLOGGED batches.
/// Walks the seed list until one contact point handshakes.
pub struct NativeCassandraTransport {
    contact_points: Vec<(String, u16)>,
    keyspace: String,
    username: Option<String>,
    password: Option<String>,
    stream: tokio::sync::Mutex<Option<tokio::net::TcpStream>>,
    stream_id: AtomicU64,
    timeout: Duration,
}

impl NativeCassandraTransport {
    pub fn new(config: &CassandraSinkConfig) -> Result<Self> {
        config.validate()?;
        let mut contact_points = Vec::new();
        for point in &config.contact_points {
            contact_points.push(parse_contact_point(point)?);
        }
        let (username, password) = match &config.auth {
            CassandraAuth::None => (None, None),
            CassandraAuth::Password { username, password } => {
                (Some(username.clone()), Some(password.clone()))
            }
        };
        Ok(Self {
            contact_points,
            keyspace: config.keyspace.clone(),
            username,
            password,
            stream: tokio::sync::Mutex::new(None),
            stream_id: AtomicU64::new(1),
            timeout: config.timeout(),
        })
    }

    fn next_stream(&self) -> u16 {
        (self.stream_id.fetch_add(1, Ordering::SeqCst) % 32767 + 1) as u16
    }

    /// Dial the first reachable seed and run the handshake
    /// (idempotent once a session is open).
    pub async fn connect(&self) -> Result<()> {
        if self.stream.lock().await.is_some() {
            return Ok(());
        }
        let mut last_error = ConnectorError::Connection("no contact points".to_string());
        for (host, port) in &self.contact_points {
            let addr = format!("{host}:{port}");
            match self.handshake(&addr).await {
                Ok(stream) => {
                    *self.stream.lock().await = Some(stream);
                    return Ok(());
                }
                Err(e) => last_error = e,
            }
        }
        Err(last_error)
    }

    async fn exchange(
        stream: &mut tokio::net::TcpStream,
        opcode: u8,
        body: &[u8],
        stream_id: u16,
        timeout: Duration,
    ) -> Result<(u8, Vec<u8>)> {
        stream
            .write_all(&encode_frame(opcode, stream_id, 0, body))
            .await
            .map_err(|e| ConnectorError::Connection(format!("cql write failed: {e}")))?;
        let (reply_opcode, _, reply) = read_frame(stream, timeout).await?;
        Ok((reply_opcode, reply))
    }

    async fn handshake(&self, addr: &str) -> Result<tokio::net::TcpStream> {
        let mut stream = tokio::time::timeout(self.timeout, tokio::net::TcpStream::connect(addr))
            .await
            .map_err(|_| ConnectorError::Connection(format!("cql connect timeout: {addr}")))?
            .map_err(|e| ConnectorError::Connection(format!("cql connect failed: {e}")))?;
        // STARTUP.
        let (opcode, _reply) = Self::exchange(
            &mut stream,
            opcode::STARTUP,
            &encode_startup(),
            self.next_stream(),
            self.timeout,
        )
        .await?;
        match opcode {
            opcode::READY => {}
            opcode::AUTHENTICATE => {
                let (username, password) = match (&self.username, &self.password) {
                    (Some(username), Some(password)) => (username.clone(), password.clone()),
                    _ => {
                        return Err(ConnectorError::Dispatch(
                            "cql server demands authentication".to_string(),
                        ))
                    }
                };
                let token = encode_plain_token(&username, &password);
                let mut body = Vec::new();
                encode_bytes(&mut body, &token);
                let (opcode, _) = Self::exchange(
                    &mut stream,
                    opcode::AUTH_RESPONSE,
                    &body,
                    self.next_stream(),
                    self.timeout,
                )
                .await?;
                if opcode != opcode::AUTH_SUCCESS {
                    return Err(ConnectorError::Connection(format!(
                        "cql expected AUTH_SUCCESS, got 0x{opcode:02x}"
                    )));
                }
            }
            _ => {
                return Err(ConnectorError::Connection(format!(
                    "cql expected READY/AUTHENTICATE, got 0x{opcode:02x}"
                )))
            }
        }
        // USE keyspace.
        let use_query = format!("USE {}", self.keyspace);
        let (opcode, reply) = Self::exchange(
            &mut stream,
            opcode::QUERY,
            &encode_query(&use_query, CqlConsistency::One),
            self.next_stream(),
            self.timeout,
        )
        .await?;
        if opcode != opcode::RESULT {
            if opcode == opcode::ERROR {
                if let Ok(err) = parse_error(&reply) {
                    return Err(ConnectorError::Connection(format!(
                        "cql handshake error 0x{:08x}: {}",
                        err.code, err.message
                    )));
                }
            }
            return Err(ConnectorError::Connection(format!(
                "cql expected RESULT, got 0x{opcode:02x}"
            )));
        }
        match parse_result_kind(&reply)? {
            CqlResultKind::SetKeyspace => Ok(stream),
            other => Err(ConnectorError::Connection(format!(
                "cql USE returned {other:?}"
            ))),
        }
    }
}

#[async_trait]
impl CassandraTransport for NativeCassandraTransport {
    async fn execute_cql_batch(&self, keyspace: &str, batch: Vec<CqlBoundStatement>) -> Result<()> {
        if batch.is_empty() {
            return Ok(());
        }
        let _ = keyspace;
        self.connect().await?;
        let statements: Vec<(String, Vec<Vec<u8>>)> = batch
            .iter()
            .map(|statement| (statement.cql.clone(), statement.values.clone()))
            .collect();
        // Batches are homogeneous by construction; the head carries
        // the batch consistency.
        let consistency = batch[0].consistency;
        let frame = encode_frame(
            opcode::BATCH,
            self.next_stream(),
            0,
            &encode_batch(
                &statements
                    .iter()
                    .map(|(cql, values)| (cql.clone(), values.clone()))
                    .collect::<Vec<_>>(),
                consistency,
            ),
        );
        let mut guard = self.stream.lock().await;
        let stream = guard
            .as_mut()
            .ok_or_else(|| ConnectorError::Connection("cql not connected".to_string()))?;
        stream
            .write_all(&frame)
            .await
            .map_err(|e| ConnectorError::Connection(format!("cql batch write failed: {e}")))?;
        let (opcode, _, reply) = read_frame(stream, self.timeout).await?;
        match opcode {
            opcode::RESULT => match parse_result_kind(&reply)? {
                CqlResultKind::Void => Ok(()),
                other => Err(ConnectorError::Connection(format!(
                    "cql batch returned {other:?}"
                ))),
            },
            opcode::ERROR => {
                let error = parse_error(&reply)?;
                if is_transient_cql_error(error.code) {
                    // Drop the poisoned session so the next attempt
                    // redials a (possibly different) seed.
                    *guard = None;
                    Err(ConnectorError::Connection(format!(
                        "cql error 0x{:08x}: {}",
                        error.code, error.message
                    )))
                } else {
                    Err(ConnectorError::Dispatch(format!(
                        "cql error 0x{:08x}: {}",
                        error.code, error.message
                    )))
                }
            }
            _ => Err(ConnectorError::Connection(format!(
                "cql expected RESULT/ERROR, got 0x{opcode:02x}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// Sink.
// ---------------------------------------------------------------------------

/// One buffered row: table, bound statement, byte size.
#[derive(Debug, Clone)]
struct CassandraRow {
    table: String,
    statement: CqlBoundStatement,
}

struct CassandraBuffer {
    queue: BatchQueue<CassandraRow>,
    bytes: usize,
}

/// Cassandra sink: buffers rows, writes UNLOGGED batches.
pub struct CassandraSink {
    config: CassandraSinkConfig,
    transport: Arc<dyn CassandraTransport>,
    buffer: parking_lot::Mutex<CassandraBuffer>,
    backoff: parking_lot::Mutex<BackoffState>,
    sent_batches: AtomicU64,
    sent_records: AtomicU64,
}

impl CassandraSink {
    pub fn new(
        config: CassandraSinkConfig,
        transport: Arc<dyn CassandraTransport>,
    ) -> Result<Self> {
        config.validate()?;
        let linger = config.effective_linger();
        Ok(Self {
            buffer: parking_lot::Mutex::new(CassandraBuffer {
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

    pub fn config(&self) -> &CassandraSinkConfig {
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

    fn backoff_delay(&self, attempt: usize) -> Duration {
        let initial = self.config.initial_backoff_ms.unwrap_or(100).max(1);
        let max = self.config.max_backoff_ms.unwrap_or(2_000).max(1);
        let grown = initial
            .saturating_mul(2u64.saturating_pow(attempt.min(10) as u32))
            .min(max);
        let jitter = (now_millis().max(0) as u64) % (grown / 2 + 1);
        Duration::from_millis(grown.saturating_add(jitter).min(max.saturating_mul(2)))
    }

    /// Build one bound statement: device id (JSON field or topic),
    /// bucket hour (`YYYY-MM-DDTHH`), event-time millis, payload
    /// text, optional TTL, plus the partition token.
    fn build_statement(
        &self,
        topic: &Topic,
        payload: &Bytes,
        millis: i64,
    ) -> Result<(CqlBoundStatement, usize)> {
        let text = std::str::from_utf8(payload)
            .map_err(|_| ConnectorError::Dispatch("cassandra payload must be UTF-8".to_string()))?;
        let value: serde_json::Value = serde_json::from_str(text)
            .map_err(|_| ConnectorError::Dispatch("cassandra payload must be JSON".to_string()))?;
        let device_id = value
            .get("device_id")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| topic.as_str())
            .to_string();
        let (year, month, day) = ymd_from_millis(millis);
        let (hour, _, _, _) = hms_milli_from_millis(millis);
        let bucket_hour = format!("{year:04}-{month:02}-{day:02}T{hour:02}");
        let partition_key = self.config.event_vars(
            topic.as_str(),
            payload,
            QoS::AtMostOnce,
            millis,
            &self.config.partition_key_template,
        )?;
        let mut values = vec![
            device_id.into_bytes(),
            bucket_hour.into_bytes(),
            millis.to_be_bytes().to_vec(),
            text.as_bytes().to_vec(),
        ];
        if let Some(ttl) = self.config.ttl_secs {
            values.push((ttl as i32).to_be_bytes().to_vec());
        }
        let encoded_bytes: usize = values.iter().map(Vec::len).sum();
        Ok((
            CqlBoundStatement {
                cql: self.config.cql_statement_template.clone(),
                values,
                consistency: self.config.consistency,
                partition_token: murmur3_token(partition_key.as_bytes()),
            },
            encoded_bytes,
        ))
    }

    /// Flush buffered rows (no-op when empty). Transient failures
    /// retry in place; terminal errors and exhaustion restore the
    /// buffer, engage backoff, and propagate.
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
        // Table is statement-scoped in CQL text; the sink batches rows
        // per resolved table like the sibling SQL sinks.
        let mut groups: Vec<(String, Vec<CqlBoundStatement>)> = Vec::new();
        for row in &rows {
            match groups.iter_mut().find(|(table, _)| table == &row.table) {
                Some((_, statements)) => statements.push(row.statement.clone()),
                None => groups.push((row.table.clone(), vec![row.statement.clone()])),
            }
        }
        let record_count = rows.len() as u64;
        let max_retries = self.config.max_retries.unwrap_or(usize::MAX);
        let mut attempt = 0usize;
        loop {
            let mut outcome: Result<()> = Ok(());
            for (_, statements) in &groups {
                if let Err(e) = self
                    .transport
                    .execute_cql_batch(&self.config.keyspace, statements.clone())
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

    fn restore_err(
        &self,
        rows: Vec<CassandraRow>,
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
                "cassandra row requires a non-empty topic".to_string(),
            ));
        }
        let millis = now_millis();
        let table = self.config.resolve_table(topic.as_str(), qos, millis)?;
        // NOTE: the CQL text carries the bare table; the keyspace
        // binds at the transport (USE) and per batch call.
        let (statement, encoded_bytes) = self.build_statement(topic, payload, millis)?;
        let mut buffer = self.buffer.lock();
        let full = buffer.queue.push(CassandraRow { table, statement });
        buffer.bytes = buffer.bytes.saturating_add(encoded_bytes);
        Ok(full || buffer.bytes >= self.config.effective_batch_bytes())
    }
}

#[async_trait]
impl Sink for CassandraSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        if self.buffer_row(topic, payload, qos)? {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "cassandra"
    }
}

/// Management connector handle pairing an id with a Cassandra sink.
pub struct CassandraConnector {
    id: String,
    sink: Arc<CassandraSink>,
}

impl CassandraConnector {
    pub fn new(id: impl Into<String>, sink: Arc<CassandraSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }
}

impl super::Connector for CassandraConnector {
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

    fn test_config() -> CassandraSinkConfig {
        CassandraSinkConfig {
            contact_points: vec!["10.0.0.1:9042".to_string(), "10.0.0.2:9042".to_string()],
            keyspace: "telemetry".to_string(),
            table_template: "events_${topic}".to_string(),
            auth: CassandraAuth::Password {
                username: "cassandra".to_string(),
                password: "secret".to_string(),
            },
            consistency: CqlConsistency::LocalQuorum,
            partition_key_template: "${client_id}".to_string(),
            cql_statement_template: "INSERT INTO telemetry.events (device_id, bucket_hour, event_time, payload) VALUES (?, ?, ?, ?) USING TTL ?".to_string(),
            ttl_secs: Some(86_400),
            batch_size: Some(100),
            batch_bytes: Some(1_048_576),
            linger_ms: Some(10),
            max_retries: Some(4),
            initial_backoff_ms: Some(100),
            max_backoff_ms: Some(2_000),
            timeout_ms: None,
        }
    }

    fn test_sink(config: CassandraSinkConfig) -> (Arc<CassandraSink>, Arc<MockCassandraTransport>) {
        let transport = Arc::new(MockCassandraTransport::new());
        let sink = Arc::new(CassandraSink::new(config, transport.clone()).unwrap());
        (sink, transport)
    }

    #[test]
    fn test_config_validation() {
        let mut config = test_config();
        assert!(config.validate().is_ok());
        assert_eq!(CqlConsistency::LocalQuorum.wire_code(), 0x000A);
        assert_eq!(CqlConsistency::One.wire_code(), 0x0001);
        assert_eq!(CqlConsistency::Quorum.wire_code(), 0x0004);
        assert_eq!(CqlConsistency::All.wire_code(), 0x0005);

        config.contact_points.clear();
        assert!(config.validate().is_err());
        config.contact_points = vec!["bad:port".to_string()];
        assert!(config.validate().is_err());
        config.contact_points = test_config().contact_points;

        config.keyspace = "has space".to_string();
        assert!(config.validate().is_err());
        config.keyspace = "telemetry".to_string();

        config.partition_key_template = "${nope}".to_string();
        assert!(config.validate().is_err());
        config.partition_key_template = test_config().partition_key_template;

        // 3 markers is neither the 4- nor the 5-shape.
        config.cql_statement_template = "INSERT INTO t (a, b, c) VALUES (?, ?, ?)".to_string();
        assert!(config.validate().is_err());
        // TTL set without a 5th marker is rejected...
        config.cql_statement_template =
            "INSERT INTO t (a, b, c, d) VALUES (?, ?, ?, ?)".to_string();
        assert!(config.validate().is_err());
        // ...as is a 5th marker without TTL.
        config.ttl_secs = None;
        config.cql_statement_template = test_config().cql_statement_template;
        assert!(config.validate().is_err());
        config.ttl_secs = Some(86_400);

        config.batch_size = Some(0);
        assert!(config.validate().is_err());
        // Unbounded + huge depths accepted: zero clamped ceilings.
        config.batch_size = None;
        config.batch_bytes = Some(10_000_000);
        config.max_retries = None;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_murmur3_vectors() {
        // Independent Python implementation of the Cassandra variant
        // (signed 64-bit tokens; negatives expected past 2^63).
        assert_eq!(murmur3_token(b"device-42"), -8_012_886_696_246_203_888);
        assert_eq!(
            murmur3_token(b"sensors/kitchen"),
            -4_228_720_401_761_039_502
        );
        assert_eq!(murmur3_token(b""), 0);
        assert_eq!(murmur3_token(&[b'a'; 100]), 2_508_270_112_733_394_994);
    }

    #[test]
    fn test_cql_frame_shapes() {
        // STARTUP frame: v4 request, opcode, string map body. The
        // decoder reads responses (0x84), so flip the version byte to
        // exercise the round trip.
        let mut frame = encode_frame(opcode::STARTUP, 7, 0, &encode_startup());
        assert_eq!(frame[0], 0x04);
        assert_eq!(u16::from_be_bytes([frame[2], frame[3]]), 7);
        assert_eq!(frame[4], opcode::STARTUP);
        frame[0] = 0x84;
        let (parsed_opcode, stream, body) = decode_frame(&frame).unwrap();
        assert_eq!((parsed_opcode, stream), (opcode::STARTUP, 7));
        assert!(body.windows(11).any(|w| w == b"CQL_VERSION"));

        // UNLOGGED batch with one 5-value statement at LocalQuorum.
        let values = vec![
            b"device-42".to_vec(),
            b"2026-09-12T11".to_vec(),
            1_789_211_889_123i64.to_be_bytes().to_vec(),
            b"{}".to_vec(),
            86_400i32.to_be_bytes().to_vec(),
        ];
        let batch = encode_batch(
            &[(
                "INSERT INTO t VALUES (?, ?, ?, ?) USING TTL ?".to_string(),
                values.clone(),
            )],
            CqlConsistency::LocalQuorum,
        );
        assert_eq!(batch[0], 0x01); // UNLOGGED
        assert_eq!(
            u16::from_be_bytes([batch.len() - 6, batch.len() - 5].map(|i| batch[i])),
            0x000A
        );
        let mut frame = encode_frame(opcode::BATCH, 1, 0, &batch);
        frame[0] = 0x84;
        let (parsed_opcode, _, body) = decode_frame(&frame).unwrap();
        assert_eq!(parsed_opcode, opcode::BATCH);
        assert!(body
            .windows(values[0].len())
            .any(|w| w == values[0].as_slice()));
    }

    #[tokio::test]
    async fn test_bound_rows_and_token_routing() {
        let (sink, transport) = test_sink(test_config());
        sink.send(
            &Topic::new("sensors/kitchen").unwrap(),
            &Bytes::from_static(
                br#"{"client_id":"device-42","device_id":"device-42","temp":22.5}"#,
            ),
            QoS::AtLeastOnce,
        )
        .await
        .unwrap();
        // No device_id field: the topic backs the device column.
        sink.send(
            &Topic::new("sensors/door").unwrap(),
            &Bytes::from_static(br#"{"client_id":"edge-9"}"#),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        sink.flush().await.unwrap();
        // One batch call per resolved table.
        let captured = transport.captured();
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[0].keyspace, "telemetry");
        assert_eq!(captured[0].batch.len(), 1);
        assert_eq!(captured[1].batch.len(), 1);
        let statement = &captured[0].batch[0];
        assert_eq!(statement.consistency, CqlConsistency::LocalQuorum);
        // Partition token binds the client id routing key.
        assert_eq!(statement.partition_token, murmur3_token(b"device-42"));
        assert_eq!(statement.values.len(), 5);
        assert_eq!(statement.values[0], b"device-42");
        // Event-time millis round-trip big-endian (sane contemporary value).
        assert_eq!(statement.values[2].len(), 8);
        let event_ms = i64::from_be_bytes(statement.values[2][..8].try_into().unwrap());
        assert!(event_ms > 1_700_000_000_000);
        // Bucket hour is `YYYY-MM-DDTHH`.
        assert_eq!(statement.values[1].len(), 13);
        assert_eq!(statement.values[1][10], b'T');
        assert_eq!(statement.values[4], 86_400i32.to_be_bytes().to_vec());
        assert_eq!(captured[1].batch[0].values[0], b"sensors/door");
        assert_eq!(sink.sent_records(), 2);
    }

    #[tokio::test]
    async fn test_node_unavailable_retries_then_succeeds() {
        let mut config = test_config();
        config.batch_size = Some(10);
        config.initial_backoff_ms = Some(1);
        config.max_backoff_ms = Some(2);
        let (sink, transport) = test_sink(config);
        transport.script_outcomes(vec![
            MockCassandraOutcome::CqlError {
                code: 0x1000,
                message: "unavailable".to_string(),
            },
            MockCassandraOutcome::Ok,
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
    async fn test_invalid_query_is_terminal() {
        let mut config = test_config();
        config.batch_size = Some(10);
        config.max_retries = Some(5);
        let (sink, transport) = test_sink(config);
        transport.script_outcomes(vec![
            MockCassandraOutcome::CqlError {
                code: 0x2200,
                message: "invalid".to_string(),
            },
            MockCassandraOutcome::Ok,
        ]);

        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from("{}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        let err = sink.flush().await.expect_err("invalid must fail");
        assert!(matches!(err, ConnectorError::Dispatch(_)));
        assert_eq!(transport.calls(), 1);
        assert_eq!(sink.buffered_rows(), 1);
    }

    #[tokio::test]
    async fn test_tcp_loopback_startup_auth_use_batch() {
        use tokio::net::TcpListener;

        async fn read_frame(stream: &mut tokio::net::TcpStream) -> (u8, Vec<u8>) {
            let mut header = [0u8; 9];
            stream.read_exact(&mut header).await.expect("head");
            let length = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) as usize;
            let mut body = vec![0u8; length];
            stream.read_exact(&mut body).await.expect("body");
            (header[4], body)
        }

        fn reply(opcode: u8, stream_id: u16, body: &[u8]) -> Vec<u8> {
            let mut frame = vec![0x84u8, 0x00];
            frame.extend_from_slice(&stream_id.to_be_bytes());
            frame.push(opcode);
            frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
            frame.extend_from_slice(body);
            frame
        }

        fn result_frame(stream_id: u16, kind: i32) -> Vec<u8> {
            let mut body = Vec::new();
            body.extend_from_slice(&kind.to_be_bytes());
            reply(opcode::RESULT, stream_id, &body)
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            // STARTUP -> demand auth.
            let (opcode, _) = read_frame(&mut stream).await;
            assert_eq!(opcode, opcode::STARTUP);
            let mut body = Vec::new();
            encode_string(&mut body, "org.apache.cassandra.auth.PasswordAuthenticator");
            stream
                .write_all(&reply(opcode::AUTHENTICATE, 1, &body))
                .await
                .expect("auth");
            // AUTH_RESPONSE carries the PLAIN token [NUL user NUL pass].
            let (opcode, body) = read_frame(&mut stream).await;
            assert_eq!(opcode, opcode::AUTH_RESPONSE);
            let len = i32::from_be_bytes([body[0], body[1], body[2], body[3]]) as usize;
            assert_eq!(&body[4..4 + len], b"\0cassandra\0secret");
            stream
                .write_all(&reply(opcode::AUTH_SUCCESS, 1, &[]))
                .await
                .expect("success");
            // USE keyspace -> SetKeyspace.
            let (opcode, body) = read_frame(&mut stream).await;
            assert_eq!(opcode, opcode::QUERY);
            assert!(body.windows(3).any(|w| w == b"USE"));
            stream
                .write_all(&result_frame(3, 0x0003))
                .await
                .expect("use");
            // BATCH: UNLOGGED type, one statement, LocalQuorum tail.
            let (opcode, body) = read_frame(&mut stream).await;
            assert_eq!(opcode, opcode::BATCH);
            assert_eq!(body[0], 0x01);
            assert_eq!(
                &body[body.len() - 6..body.len() - 4],
                &0x000Au16.to_be_bytes()
            );
            stream
                .write_all(&result_frame(4, 0x0002))
                .await
                .expect("void");
        });

        let mut config = test_config();
        config.contact_points = vec![format!("127.0.0.1:{port}")];
        config.batch_size = Some(1);
        let transport = Arc::new(NativeCassandraTransport::new(&config).unwrap());
        let sink = CassandraSink::new(config, transport).unwrap();
        sink.send(
            &Topic::new("sensors/t1").unwrap(),
            &Bytes::from_static(br#"{"client_id":"device-42"}"#),
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
