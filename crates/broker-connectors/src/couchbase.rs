//! Couchbase Server / Capella sink (INDRA-168).
//!
//! Buffers MQTT events as JSON documents (payload fields merged with
//! an injected `_mqtt` metadata object) and writes them with the
//! maintained official `couchbase` driver
//! ([`DriverCouchbaseTransport`] below): `Upsert` → upsert,
//! `Insert` → insert (fails when the key exists), `Replace` →
//! replace (fails when the key is missing), with scope/collection
//! targeting and per-document expiry. The hand-written KV binary
//! path ([`NativeCouchbaseTransport`]: SET/ADD/REPLACE opcodes +
//! SASL PLAIN, pipelined by opaque) is retained for offline unit
//! tests only; production wiring uses the driver.
//!
//! Driver errors that are backpressure or transport failures retry
//! with backoff; document-exists (on insert) and document-missing
//! (on replace) are terminal.

use async_trait::async_trait;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{now_millis, render_template, BackoffState, BatchQueue, ConnectorError, Result, Sink};

/// KV opcodes used here.
mod opcode {
    pub const SET: u8 = 0x01;
    pub const ADD: u8 = 0x02;
    pub const REPLACE: u8 = 0x03;
    pub const SASL_AUTH: u8 = 0x21;
}

/// KV response statuses.
mod status {
    pub const SUCCESS: u16 = 0x0000;
    pub const NOT_FOUND: u16 = 0x0001;
    pub const EXISTS: u16 = 0x0002;
    pub const BUSY: u16 = 0x0085;
    pub const TEMPORARY_FAILURE: u16 = 0x0086;
}

/// Write operation mapping onto KV opcodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CouchbaseOperation {
    /// SET: insert or overwrite.
    #[default]
    Upsert,
    /// ADD: fails with Exists when the key is present.
    Insert,
    /// REPLACE: fails with NotFound when the key is absent.
    Replace,
}

impl CouchbaseOperation {
    fn opcode(self) -> u8 {
        match self {
            Self::Upsert => opcode::SET,
            Self::Insert => opcode::ADD,
            Self::Replace => opcode::REPLACE,
        }
    }
}

/// Couchbase authentication (SASL PLAIN).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CouchbaseAuth {
    pub username: String,
    pub password: String,
}

fn default_scope() -> Option<String> {
    None
}

fn default_collection() -> Option<String> {
    None
}

// Finite defaults with reasons (RULEBOOK §2: every bound has a finite
// default and its reason next to it; the sink's send path runs behind
// the rule engine's bounded queue, so no benchmark numbers are needed).
// `None` remains an explicit operator opt-in to unbounded; the code
// never chooses it.
fn default_batch_size() -> Option<usize> {
    // 100 docs: one KV batch stays well under the 16 MiB response cap
    // with typical sub-KB telemetry documents.
    Some(100)
}

fn default_batch_bytes() -> Option<usize> {
    // 2 MiB: matches the bulk sinks and keeps one batch far below the
    // driver's per-request limits.
    Some(2_097_152)
}

fn default_linger_ms() -> Option<u64> {
    // 10 ms: flushes interactive telemetry promptly without turning
    // every message into its own round trip.
    Some(10)
}

fn default_max_retries() -> Option<usize> {
    // 3 retries: absorbs transient backpressure without wedging the
    // rule worker behind a wedged cluster.
    Some(3)
}

fn default_initial_backoff_ms() -> Option<u64> {
    // 100 ms first delay: longer than a single scheduler quanta so a
    // hot server gets breathing room.
    Some(100)
}

fn default_max_backoff_ms() -> Option<u64> {
    // 2 s ceiling: bounds the worst-case stall per batch while still
    // backing off across a short node restart.
    Some(2_000)
}

/// Couchbase sink configuration. All depths are optional: `None` is
/// an explicit operator opt-in to unbounded, never the code's choice;
/// zero clamps the ceiling. Finite defaults above carry their reasons.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CouchbaseSinkConfig {
    /// Bootstrap string (`couchbase://host`, `couchbases://...`).
    pub connection_string: String,
    /// Bucket name.
    pub bucket: String,
    /// Scope (default `_default`).
    #[serde(default = "default_scope")]
    pub scope: Option<String>,
    /// Collection (default `_default`).
    #[serde(default = "default_collection")]
    pub collection: Option<String>,
    pub auth: CouchbaseAuth,
    /// Document key template (`${client_id}::${timestamp}`, ...).
    pub doc_id_template: String,
    /// Write operation (default upsert).
    #[serde(default)]
    pub operation: CouchbaseOperation,
    /// Document TTL seconds (`None`/0 = no expiry).
    #[serde(default)]
    pub expiry_secs: Option<u32>,
    /// Items per batch (default 100).
    #[serde(default = "default_batch_size")]
    pub batch_size: Option<usize>,
    /// Batch byte limit (default 2 MiB).
    #[serde(default = "default_batch_bytes")]
    pub batch_bytes: Option<usize>,
    /// Linger flush window in ms (default 10).
    #[serde(default = "default_linger_ms")]
    pub linger_ms: Option<u64>,
    /// Retries on backpressure (default 3, `None` unbounded, 0 none).
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

impl CouchbaseSinkConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.unwrap_or(5000).max(1))
    }

    pub fn validate(&self) -> Result<()> {
        parse_connection_string(&self.connection_string)?;
        if self.bucket.trim().is_empty() || self.bucket.contains(['/', ' ', '\0']) {
            return Err(ConnectorError::Dispatch(format!(
                "couchbase bucket must be a bare name: {:?}",
                self.bucket
            )));
        }
        if self.auth.username.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "couchbase username must not be empty".to_string(),
            ));
        }
        if self.doc_id_template.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "couchbase doc_id_template must not be empty".to_string(),
            ));
        }
        // Strict template check with dummy values (a dummy client id
        // satisfies the non-empty routing rule at validation time).
        self.resolve_doc_id("dummy", br#"{"client_id":"dummy"}"#, QoS::AtMostOnce, 0, 0)?;
        if self.batch_size == Some(0) {
            return Err(ConnectorError::Dispatch(
                "couchbase batch_size must be >= 1".to_string(),
            ));
        }
        if self.batch_bytes == Some(0) {
            return Err(ConnectorError::Dispatch(
                "couchbase batch_bytes must be >= 1".to_string(),
            ));
        }
        Ok(())
    }

    pub fn scope_or_default(&self) -> &str {
        self.scope.as_deref().unwrap_or("_default")
    }

    pub fn collection_or_default(&self) -> &str {
        self.collection.as_deref().unwrap_or("_default")
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

    pub fn effective_expiry(&self) -> u32 {
        self.expiry_secs.unwrap_or(0)
    }

    /// Template variables for one event.
    fn template_vars(
        topic: &str,
        payload: &[u8],
        qos: QoS,
        millis: i64,
        seq: u64,
    ) -> Vec<(String, String)> {
        let doc: serde_json::Value = serde_json::from_slice(payload).unwrap_or_default();
        let field = |name: &str| match doc.get(name) {
            Some(serde_json::Value::String(text)) => text.clone(),
            Some(scalar) if scalar.is_number() || scalar.is_boolean() => scalar.to_string(),
            _ => String::new(),
        };
        let mut client_id = field("client_id");
        if client_id.is_empty() {
            client_id = field("clientid");
        }
        if client_id.is_empty() {
            client_id = field("device_id");
        }
        vec![
            ("topic".to_string(), topic.to_string()),
            ("client_id".to_string(), client_id),
            ("qos".to_string(), u8::from(qos).to_string()),
            ("timestamp".to_string(), millis.to_string()),
            ("seq".to_string(), seq.to_string()),
        ]
    }

    /// Render the document key (rejects empty results). Routing
    /// variables (`${client_id}`, `${payload.<field>}`) must resolve
    /// non-empty: silent empty keys would collide across devices.
    pub fn resolve_doc_id(
        &self,
        topic: &str,
        payload: &[u8],
        qos: QoS,
        millis: i64,
        seq: u64,
    ) -> Result<String> {
        // `${payload.<field>}` extraction on top of base variables.
        let mut vars = Self::template_vars(topic, payload, qos, millis, seq);
        let doc: serde_json::Value = serde_json::from_slice(payload).unwrap_or_default();
        let field = |name: &str| match doc.get(name) {
            Some(serde_json::Value::String(text)) => text.clone(),
            Some(scalar) if scalar.is_number() || scalar.is_boolean() => scalar.to_string(),
            _ => String::new(),
        };
        let mut client_id = field("client_id");
        if client_id.is_empty() {
            client_id = field("clientid");
        }
        if client_id.is_empty() {
            client_id = field("device_id");
        }
        if self.doc_id_template.contains("${client_id}") && client_id.is_empty() {
            return Err(ConnectorError::Dispatch(
                "couchbase doc id needs a non-empty client_id".to_string(),
            ));
        }
        let mut rest = self.doc_id_template.as_str();
        while let Some(start) = rest.find("${payload.") {
            let after = &rest[start + "${payload.".len()..];
            if let Some(close) = after.find('}') {
                let name = &after[..close];
                let value = field(name);
                if value.is_empty() {
                    return Err(ConnectorError::Dispatch(format!(
                        "couchbase doc id needs a non-empty payload field {name:?}"
                    )));
                }
                vars.push((format!("payload.{name}"), value));
                rest = &after[close + 1..];
            } else {
                break;
            }
        }
        let borrowed: Vec<(&str, String)> =
            vars.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
        let key = render_template(&self.doc_id_template, &borrowed)?;
        if key.trim().is_empty() || key.contains('\0') {
            return Err(ConnectorError::Dispatch(
                "couchbase doc id resolved empty".to_string(),
            ));
        }
        Ok(key)
    }
}

/// Parsed bootstrap endpoint (first host wins; cluster map beyond
/// the seed is out of scope for the edge bridge).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CouchbaseEndpoint {
    pub host: String,
    pub port: u16,
    pub tls: bool,
}

pub fn parse_connection_string(uri: &str) -> Result<CouchbaseEndpoint> {
    let uri = uri.trim();
    let (tls, rest) = match uri.split_once("://") {
        Some(("couchbase", rest)) => (false, rest),
        Some(("couchbases", rest)) => (true, rest),
        _ => {
            return Err(ConnectorError::Dispatch(format!(
                "couchbase connection string must start with couchbase:// or couchbases://: {uri:?}"
            )));
        }
    };
    let host_port = rest.split(',').next().unwrap_or_default();
    let host_port = host_port.split('/').next().unwrap_or_default();
    let (host, port) = match host_port.rsplit_once(':') {
        Some((host, port)) => {
            let port: u16 = port
                .parse()
                .map_err(|_| ConnectorError::Dispatch(format!("couchbase bad port in {uri:?}")))?;
            if port == 0 {
                return Err(ConnectorError::Dispatch(format!(
                    "couchbase port must be 1..=65535 in {uri:?}"
                )));
            }
            (host, port)
        }
        None => (host_port, 11_210),
    };
    if host.is_empty() {
        return Err(ConnectorError::Dispatch(format!(
            "couchbase host must not be empty in {uri:?}"
        )));
    }
    Ok(CouchbaseEndpoint {
        host: host.to_string(),
        port,
        tls,
    })
}

// ---------------------------------------------------------------------------
// KV binary protocol framing.
// ---------------------------------------------------------------------------

/// Encode a request packet (magic 0x80).
pub fn encode_request(opcode: u8, key: &[u8], extras: &[u8], value: &[u8], opaque: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + extras.len() + key.len() + value.len());
    out.push(0x80);
    out.push(opcode);
    out.extend_from_slice(&(key.len() as u16).to_be_bytes());
    out.push(extras.len() as u8);
    out.push(0x00); // datatype: raw
    out.extend_from_slice(&0u16.to_be_bytes()); // vbucket
    out.extend_from_slice(&((extras.len() + key.len() + value.len()) as u32).to_be_bytes());
    out.extend_from_slice(&opaque.to_be_bytes());
    out.extend_from_slice(&0u64.to_be_bytes()); // CAS
    out.extend_from_slice(extras);
    out.extend_from_slice(key);
    out.extend_from_slice(value);
    out
}

/// Encode a SET/ADD/REPLACE mutation with flags + expiry extras.
pub fn encode_mutation(
    operation: CouchbaseOperation,
    key: &str,
    value: &[u8],
    expiry_secs: u32,
    opaque: u32,
) -> Vec<u8> {
    let mut extras = Vec::with_capacity(8);
    extras.extend_from_slice(&0u32.to_be_bytes()); // flags
    extras.extend_from_slice(&expiry_secs.to_be_bytes());
    encode_request(operation.opcode(), key.as_bytes(), &extras, value, opaque)
}

/// SASL PLAIN token: NUL + username + NUL + password.
pub fn encode_plain_token(username: &str, password: &str) -> Vec<u8> {
    let mut token = vec![0x00];
    token.extend_from_slice(username.as_bytes());
    token.push(0x00);
    token.extend_from_slice(password.as_bytes());
    token
}

/// Decoded response packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KvResponse {
    pub opcode: u8,
    pub status: u16,
    pub opaque: u32,
    pub body: Vec<u8>,
}

/// Decode one response packet (magic 0x81).
pub fn decode_response(frame: &[u8]) -> Result<KvResponse> {
    if frame.len() < 24 {
        return Err(ConnectorError::Connection(
            "couchbase truncated response".to_string(),
        ));
    }
    if frame[0] != 0x81 {
        return Err(ConnectorError::Connection(format!(
            "couchbase bad response magic 0x{:02x}",
            frame[0]
        )));
    }
    let key_len = u16::from_be_bytes([frame[2], frame[3]]) as usize;
    let ext_len = frame[4] as usize;
    let status = u16::from_be_bytes([frame[6], frame[7]]);
    let total = u32::from_be_bytes([frame[8], frame[9], frame[10], frame[11]]) as usize;
    let opaque = u32::from_be_bytes([frame[12], frame[13], frame[14], frame[15]]);
    if frame.len() < 24 + total {
        return Err(ConnectorError::Connection(
            "couchbase truncated response body".to_string(),
        ));
    }
    Ok(KvResponse {
        opcode: frame[1],
        status,
        opaque,
        body: frame[24 + ext_len + key_len..24 + total].to_vec(),
    })
}

/// Read one response packet from the stream.
async fn read_response(
    stream: &mut tokio::net::TcpStream,
    timeout: Duration,
) -> Result<KvResponse> {
    let mut header = [0u8; 24];
    tokio::time::timeout(timeout, stream.read_exact(&mut header))
        .await
        .map_err(|_| ConnectorError::Connection("couchbase read timeout".to_string()))?
        .map_err(|e| ConnectorError::Connection(format!("couchbase read failed: {e}")))?;
    let total = u32::from_be_bytes([header[8], header[9], header[10], header[11]]) as usize;
    if total > 16 * 1024 * 1024 {
        return Err(ConnectorError::Connection(
            "couchbase response too large".to_string(),
        ));
    }
    let mut body = vec![0u8; total];
    tokio::time::timeout(timeout, stream.read_exact(&mut body))
        .await
        .map_err(|_| ConnectorError::Connection("couchbase read timeout".to_string()))?
        .map_err(|e| ConnectorError::Connection(format!("couchbase read failed: {e}")))?;
    let mut frame = header.to_vec();
    frame.extend_from_slice(&body);
    decode_response(&frame)
}

/// Build a success response (fakes + tests).
pub fn encode_success_response(opcode: u8, opaque: u32) -> Vec<u8> {
    encode_status_response(opcode, opaque, status::SUCCESS)
}

/// Build an error response with an explicit status (fakes + tests):
/// the loopback fake answers SASL PLAIN failures this way so the
/// transport fails closed instead of panicking on a bad credential.
pub fn encode_status_response(opcode: u8, opaque: u32, status: u16) -> Vec<u8> {
    let mut out = vec![0x81, opcode];
    out.extend_from_slice(&0u16.to_be_bytes());
    out.push(0x00);
    out.push(0x00);
    out.extend_from_slice(&status.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&opaque.to_be_bytes());
    out.extend_from_slice(&0u64.to_be_bytes());
    out
}

/// SASL AUTH failure status answered for bad credentials (0x20,
/// the memcached AUTH_ERROR value): any non-zero status makes
/// [`NativeCouchbaseTransport::connect`] fail closed.
pub const SASL_AUTH_ERROR: u16 = 0x20;

/// Classify a status: retryable backpressure, terminal conflicts, or
/// success. Returns `Ok(true)` to retry, `Ok(false)` when done.
pub fn classify_status(operation: CouchbaseOperation, status: u16) -> Result<bool> {
    match status {
        status::SUCCESS => Ok(false),
        status::BUSY | status::TEMPORARY_FAILURE => Ok(true),
        status::EXISTS if operation == CouchbaseOperation::Insert => Err(ConnectorError::Dispatch(
            "couchbase insert: document exists".to_string(),
        )),
        status::NOT_FOUND if operation == CouchbaseOperation::Replace => Err(
            ConnectorError::Dispatch("couchbase replace: document missing".to_string()),
        ),
        other => Err(ConnectorError::Dispatch(format!(
            "couchbase error status 0x{other:04x}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Rows + transport.
// ---------------------------------------------------------------------------

/// One document operation in a batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CouchbaseDocItem {
    pub key: String,
    pub body: Vec<u8>,
    pub expiry_secs: u32,
}

#[async_trait]
pub trait CouchbaseTransport: Send + Sync {
    async fn execute_batch(
        &self,
        bucket: &str,
        scope: &str,
        coll: &str,
        items: Vec<CouchbaseDocItem>,
    ) -> Result<()>;
}

/// Scripted outcome for the mock transport.
#[derive(Debug, Clone)]
pub enum MockCouchbaseOutcome {
    Ok,
    /// Transport failure (retries in-loop).
    ConnectionError(String),
    /// Server status for every item (backpressure retries; conflicts terminal).
    StatusError {
        status: u16,
    },
}

/// One captured batch call.
#[derive(Debug, Clone)]
pub struct CapturedCouchbaseBatch {
    pub bucket: String,
    pub scope: String,
    pub collection: String,
    pub items: Vec<CouchbaseDocItem>,
}

/// In-memory transport with scripted outcomes (tests, dry runs).
/// Scripted statuses resolve against the configured operation tag
/// (0 = Upsert, 1 = Insert, 2 = Replace); test harnesses set it to
/// match the sink under test.
#[derive(Debug, Default)]
pub struct MockCouchbaseTransport {
    scripted: parking_lot::Mutex<std::collections::VecDeque<MockCouchbaseOutcome>>,
    captured: parking_lot::Mutex<Vec<CapturedCouchbaseBatch>>,
    calls: AtomicU64,
    operation: AtomicU8,
}

impl MockCouchbaseTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Operation tag for status mapping (0 Upsert, 1 Insert, 2 Replace).
    pub fn set_operation_tag(&self, tag: u8) {
        self.operation.store(tag.min(2), Ordering::SeqCst);
    }

    /// Queue outcomes consumed in order (default: success).
    pub fn script_outcomes(&self, outcomes: Vec<MockCouchbaseOutcome>) {
        *self.scripted.lock() = outcomes.into_iter().collect();
    }

    pub fn captured(&self) -> Vec<CapturedCouchbaseBatch> {
        self.captured.lock().clone()
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl CouchbaseTransport for MockCouchbaseTransport {
    async fn execute_batch(
        &self,
        bucket: &str,
        scope: &str,
        coll: &str,
        items: Vec<CouchbaseDocItem>,
    ) -> Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let operation = self.operation.load(Ordering::SeqCst);
        self.captured.lock().push(CapturedCouchbaseBatch {
            bucket: bucket.to_string(),
            scope: scope.to_string(),
            collection: coll.to_string(),
            items: items.clone(),
        });
        match self.scripted.lock().pop_front() {
            None | Some(MockCouchbaseOutcome::Ok) => Ok(()),
            Some(MockCouchbaseOutcome::ConnectionError(message)) => {
                Err(ConnectorError::Connection(message))
            }
            Some(MockCouchbaseOutcome::StatusError { status }) => {
                let operation = match operation {
                    0 => CouchbaseOperation::Upsert,
                    1 => CouchbaseOperation::Insert,
                    _ => CouchbaseOperation::Replace,
                };
                match classify_status(operation, status) {
                    Ok(true) => Err(ConnectorError::Connection(format!(
                        "mock couchbase backpressure 0x{status:04x}"
                    ))),
                    Ok(false) => Ok(()),
                    Err(e) => Err(e),
                }
            }
        }
    }
}

/// Native transport: SASL PLAIN once, then pipelined mutation batches
/// matched by opaque.
pub struct NativeCouchbaseTransport {
    endpoint: CouchbaseEndpoint,
    username: String,
    password: String,
    operation: CouchbaseOperation,
    stream: tokio::sync::Mutex<Option<tokio::net::TcpStream>>,
    opaque: AtomicU64,
    timeout: Duration,
}

impl NativeCouchbaseTransport {
    pub fn new(config: &CouchbaseSinkConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            endpoint: parse_connection_string(&config.connection_string)?,
            username: config.auth.username.clone(),
            password: config.auth.password.clone(),
            operation: config.operation,
            stream: tokio::sync::Mutex::new(None),
            opaque: AtomicU64::new(1),
            timeout: config.timeout(),
        })
    }

    /// Dial + SASL PLAIN authenticate (idempotent once open).
    pub async fn connect(&self) -> Result<()> {
        if self.stream.lock().await.is_some() {
            return Ok(());
        }
        if self.endpoint.tls {
            return Err(ConnectorError::Dispatch(
                "couchbases TLS transport not enabled in this build; use couchbase:// \
                 or terminate TLS in a sidecar proxy"
                    .to_string(),
            ));
        }
        let addr = format!("{}:{}", self.endpoint.host, self.endpoint.port);
        let mut stream = tokio::time::timeout(self.timeout, tokio::net::TcpStream::connect(&addr))
            .await
            .map_err(|_| ConnectorError::Connection(format!("couchbase connect timeout: {addr}")))?
            .map_err(|e| ConnectorError::Connection(format!("couchbase connect failed: {e}")))?;
        let token = encode_plain_token(&self.username, &self.password);
        let opaque = self.opaque.fetch_add(1, Ordering::SeqCst) as u32;
        let auth = encode_request(opcode::SASL_AUTH, b"PLAIN", &[], &token, opaque);
        stream
            .write_all(&auth)
            .await
            .map_err(|e| ConnectorError::Connection(format!("couchbase auth write failed: {e}")))?;
        let reply = read_response(&mut stream, self.timeout).await?;
        if reply.opaque != opaque || reply.status != status::SUCCESS {
            return Err(ConnectorError::Connection(format!(
                "couchbase auth failed with 0x{:04x}",
                reply.status
            )));
        }
        *self.stream.lock().await = Some(stream);
        Ok(())
    }
}

#[async_trait]
impl CouchbaseTransport for NativeCouchbaseTransport {
    async fn execute_batch(
        &self,
        bucket: &str,
        scope: &str,
        coll: &str,
        items: Vec<CouchbaseDocItem>,
    ) -> Result<()> {
        if items.is_empty() {
            return Ok(());
        }
        let _ = (bucket, scope, coll);
        self.connect().await?;
        // Pipeline: one opaque per item, single write, ordered reads.
        let mut opaques = Vec::with_capacity(items.len());
        let mut out = Vec::new();
        for item in &items {
            let opaque = self.opaque.fetch_add(1, Ordering::SeqCst) as u32;
            opaques.push(opaque);
            out.extend_from_slice(&encode_mutation(
                self.operation,
                &item.key,
                &item.body,
                item.expiry_secs,
                opaque,
            ));
        }
        let mut guard = self.stream.lock().await;
        let stream = guard
            .as_mut()
            .ok_or_else(|| ConnectorError::Connection("couchbase not connected".to_string()))?;
        stream.write_all(&out).await.map_err(|e| {
            ConnectorError::Connection(format!("couchbase batch write failed: {e}"))
        })?;
        for (item, opaque) in items.iter().zip(opaques.iter()) {
            let reply = read_response(stream, self.timeout).await?;
            if reply.opaque != *opaque || reply.opcode != self.operation.opcode() {
                return Err(ConnectorError::Connection(
                    "couchbase opaque/opcode mismatch".to_string(),
                ));
            }
            if classify_status(self.operation, reply.status)? {
                return Err(ConnectorError::Connection(format!(
                    "couchbase backpressure 0x{:04x} on {:?}",
                    reply.status, item.key
                )));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Official driver transport (production).
// ---------------------------------------------------------------------------

/// Map a driver error onto the sink's retry contract: document-exists
/// (insert) and document-missing (replace) are terminal dispatch
/// errors; everything else (transport loss, backpressure, timeouts,
/// failover) is a connection error so the sink retries with backoff.
fn map_driver_error(
    operation: CouchbaseOperation,
    error: couchbase::error::Error,
) -> ConnectorError {
    use couchbase::error::ErrorKind as Kind;
    match error.kind() {
        Kind::DocumentExists if operation == CouchbaseOperation::Insert => {
            ConnectorError::Dispatch(format!("couchbase insert: document exists: {error}"))
        }
        Kind::DocumentNotFound if operation == CouchbaseOperation::Replace => {
            ConnectorError::Dispatch(format!("couchbase replace: document missing: {error}"))
        }
        // Upserts never hit these, but if they do the write did not
        // happen: still terminal rather than silently retried forever.
        Kind::DocumentExists | Kind::DocumentNotFound => {
            ConnectorError::Dispatch(format!("couchbase driver conflict: {error}"))
        }
        _ => ConnectorError::Connection(format!("couchbase driver: {error}")),
    }
}

/// Production transport on the maintained official `couchbase` driver.
///
/// Holds the validated config and lazily connects: `new` is sync (so
/// management wiring stays sync like the other driver transports)
/// and the first batch opens the `Cluster`, waits for the bucket,
/// and caches it. Later batches reuse the cluster and derive the
/// target collection from the call's bucket/scope/collection, so the
/// sink's configured target is honoured per batch.
pub struct DriverCouchbaseTransport {
    config: CouchbaseSinkConfig,
    cluster: tokio::sync::RwLock<Option<couchbase::cluster::Cluster>>,
    timeout: Duration,
}

impl DriverCouchbaseTransport {
    pub fn new(config: &CouchbaseSinkConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config: config.clone(),
            cluster: tokio::sync::RwLock::new(None),
            timeout: config.timeout(),
        })
    }

    async fn cluster_handle(&self) -> Result<couchbase::cluster::Cluster> {
        if let Some(cluster) = self.cluster.read().await.clone() {
            return Ok(cluster);
        }
        let mut guard = self.cluster.write().await;
        if let Some(cluster) = guard.clone() {
            return Ok(cluster);
        }
        let authenticator = couchbase::authenticator::PasswordAuthenticator::new(
            self.config.auth.username.clone(),
            self.config.auth.password.clone(),
        );
        let options =
            couchbase::options::cluster_options::ClusterOptions::new(authenticator.into());
        let connection_string = self.config.connection_string.clone();
        let timeout = self.timeout;
        let cluster = tokio::time::timeout(
            timeout,
            couchbase::cluster::Cluster::connect(connection_string.clone(), options),
        )
        .await
        .map_err(|_| {
            ConnectorError::Connection(format!(
                "couchbase driver connect timed out: {connection_string}"
            ))
        })?
        .map_err(|e| ConnectorError::Connection(format!("couchbase driver connect: {e}")))?;
        let bucket = cluster.bucket(self.config.bucket.clone());
        tokio::time::timeout(timeout, bucket.wait_until_ready(None))
            .await
            .map_err(|_| {
                ConnectorError::Connection(format!(
                    "couchbase bucket timed out: {}",
                    self.config.bucket
                ))
            })?
            .map_err(|e| ConnectorError::Connection(format!("couchbase bucket ready: {e}")))?;
        *guard = Some(cluster.clone());
        Ok(cluster)
    }

    async fn write_one(
        collection: &couchbase::collection::Collection,
        operation: CouchbaseOperation,
        item: &CouchbaseDocItem,
        timeout: Duration,
    ) -> Result<()> {
        let document: serde_json::Value = serde_json::from_slice(&item.body).map_err(|e| {
            ConnectorError::Dispatch(format!("couchbase document must be JSON: {e}"))
        })?;
        let expiry = if item.expiry_secs == 0 {
            None
        } else {
            Some(Duration::from_secs(u64::from(item.expiry_secs)))
        };
        let outcome = match operation {
            CouchbaseOperation::Upsert => {
                let options = expiry.map(|expiry| {
                    couchbase::options::kv_options::UpsertOptions::new().expiry(expiry)
                });
                tokio::time::timeout(timeout, collection.upsert(&item.key, document, options))
                    .await
                    .map_err(|_| {
                        ConnectorError::Connection(format!(
                            "couchbase driver timed out on {:?}",
                            item.key
                        ))
                    })?
                    .map(|_| ())
                    .map_err(|e| map_driver_error(operation, e))
            }
            CouchbaseOperation::Insert => {
                let options = expiry.map(|expiry| {
                    couchbase::options::kv_options::InsertOptions::new().expiry(expiry)
                });
                tokio::time::timeout(timeout, collection.insert(&item.key, document, options))
                    .await
                    .map_err(|_| {
                        ConnectorError::Connection(format!(
                            "couchbase driver timed out on {:?}",
                            item.key
                        ))
                    })?
                    .map(|_| ())
                    .map_err(|e| map_driver_error(operation, e))
            }
            CouchbaseOperation::Replace => {
                let options = expiry.map(|expiry| {
                    couchbase::options::kv_options::ReplaceOptions::new().expiry(expiry)
                });
                tokio::time::timeout(timeout, collection.replace(&item.key, document, options))
                    .await
                    .map_err(|_| {
                        ConnectorError::Connection(format!(
                            "couchbase driver timed out on {:?}",
                            item.key
                        ))
                    })?
                    .map(|_| ())
                    .map_err(|e| map_driver_error(operation, e))
            }
        };
        outcome
    }
}

#[async_trait]
impl CouchbaseTransport for DriverCouchbaseTransport {
    async fn execute_batch(
        &self,
        bucket: &str,
        scope: &str,
        coll: &str,
        items: Vec<CouchbaseDocItem>,
    ) -> Result<()> {
        if items.is_empty() {
            return Ok(());
        }
        let cluster = self.cluster_handle().await?;
        let collection = cluster.bucket(bucket).scope(scope).collection(coll);
        for item in &items {
            Self::write_one(&collection, self.config.operation, item, self.timeout).await?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Sink.
// ---------------------------------------------------------------------------

/// One buffered row: document key, JSON body, expiry.
#[derive(Debug, Clone)]
struct CouchbaseRow {
    key: String,
    body: Vec<u8>,
}

struct CouchbaseBuffer {
    queue: BatchQueue<CouchbaseRow>,
    bytes: usize,
}

/// Couchbase sink: buffers documents, writes pipelined batches.
pub struct CouchbaseSink {
    config: CouchbaseSinkConfig,
    transport: Arc<dyn CouchbaseTransport>,
    buffer: parking_lot::Mutex<CouchbaseBuffer>,
    backoff: parking_lot::Mutex<BackoffState>,
    seq: AtomicU64,
    sent_batches: AtomicU64,
    sent_records: AtomicU64,
}

impl CouchbaseSink {
    pub fn new(
        config: CouchbaseSinkConfig,
        transport: Arc<dyn CouchbaseTransport>,
    ) -> Result<Self> {
        config.validate()?;
        let linger = config.effective_linger();
        Ok(Self {
            buffer: parking_lot::Mutex::new(CouchbaseBuffer {
                queue: BatchQueue::new(config.effective_batch_size(), linger),
                bytes: 0,
            }),
            config,
            transport,
            backoff: parking_lot::Mutex::new(BackoffState::default()),
            seq: AtomicU64::new(0),
            sent_batches: AtomicU64::new(0),
            sent_records: AtomicU64::new(0),
        })
    }

    pub fn config(&self) -> &CouchbaseSinkConfig {
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

    /// Build the JSON body: payload object merged with `_mqtt`, or
    /// `{"value": ...}` for scalar payloads.
    fn build_body(topic: &Topic, payload: &Bytes, qos: QoS, millis: i64) -> Result<Vec<u8>> {
        let text = std::str::from_utf8(payload)
            .map_err(|_| ConnectorError::Dispatch("couchbase payload must be UTF-8".to_string()))?;
        let value: serde_json::Value = serde_json::from_str(text)
            .map_err(|_| ConnectorError::Dispatch("couchbase payload must be JSON".to_string()))?;
        let client_id = value
            .get("client_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let mut document = match value {
            serde_json::Value::Object(map) => serde_json::Value::Object(map),
            other => serde_json::json!({"value": other}),
        };
        if let serde_json::Value::Object(map) = &mut document {
            map.insert(
                "_mqtt".to_string(),
                serde_json::json!({
                    "topic": topic.as_str(),
                    "client_id": client_id,
                    "qos": u8::from(qos),
                    "timestamp": millis,
                }),
            );
        }
        serde_json::to_vec(&document)
            .map_err(|e| ConnectorError::Dispatch(format!("couchbase encode failed: {e}")))
    }

    /// Flush buffered rows (no-op when empty). Backpressure retries
    /// in place; terminal conflicts and exhaustion restore the
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
        let items: Vec<CouchbaseDocItem> = rows
            .iter()
            .map(|row| CouchbaseDocItem {
                key: row.key.clone(),
                body: row.body.clone(),
                expiry_secs: self.config.effective_expiry(),
            })
            .collect();
        let record_count = rows.len() as u64;
        let max_retries = self.config.max_retries.unwrap_or(usize::MAX);
        let mut attempt = 0usize;
        loop {
            match self
                .transport
                .execute_batch(
                    &self.config.bucket,
                    self.config.scope_or_default(),
                    self.config.collection_or_default(),
                    items.clone(),
                )
                .await
            {
                Ok(()) => {
                    self.backoff.lock().success();
                    self.sent_batches.fetch_add(1, Ordering::Relaxed);
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
        rows: Vec<CouchbaseRow>,
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
                "couchbase row requires a non-empty topic".to_string(),
            ));
        }
        let millis = now_millis();
        let seq = self.seq.fetch_add(1, Ordering::SeqCst);
        let key = self
            .config
            .resolve_doc_id(topic.as_str(), payload, qos, millis, seq)?;
        let body = Self::build_body(topic, payload, qos, millis)?;
        let added = key.len() + body.len();
        let mut buffer = self.buffer.lock();
        let full = buffer.queue.push(CouchbaseRow { key, body });
        buffer.bytes = buffer.bytes.saturating_add(added);
        Ok(full || buffer.bytes >= self.config.effective_batch_bytes())
    }
}

#[async_trait]
impl Sink for CouchbaseSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        if self.buffer_row(topic, payload, qos)? {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "couchbase"
    }
}

/// Management connector handle pairing an id with a Couchbase sink.
pub struct CouchbaseConnector {
    id: String,
    sink: Arc<CouchbaseSink>,
}

impl CouchbaseConnector {
    pub fn new(id: impl Into<String>, sink: Arc<CouchbaseSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }
}

impl super::Connector for CouchbaseConnector {
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

    fn test_config() -> CouchbaseSinkConfig {
        CouchbaseSinkConfig {
            connection_string: "couchbase://127.0.0.1".to_string(),
            bucket: "telemetry".to_string(),
            scope: Some("edge".to_string()),
            collection: Some("events".to_string()),
            auth: CouchbaseAuth {
                username: "Administrator".to_string(),
                password: "secret".to_string(),
            },
            doc_id_template: "${client_id}::${timestamp}".to_string(),
            operation: CouchbaseOperation::Upsert,
            expiry_secs: Some(3_600),
            batch_size: Some(100),
            batch_bytes: Some(2_097_152),
            linger_ms: Some(10),
            max_retries: Some(3),
            initial_backoff_ms: Some(100),
            max_backoff_ms: Some(2_000),
            timeout_ms: None,
        }
    }

    fn test_sink(config: CouchbaseSinkConfig) -> (Arc<CouchbaseSink>, Arc<MockCouchbaseTransport>) {
        let transport = Arc::new(MockCouchbaseTransport::new());
        // Scripted statuses assume the sink operation; mirror it here.
        transport.set_operation_tag(operation_tag(&config.operation));
        let sink = Arc::new(CouchbaseSink::new(config, transport.clone()).unwrap());
        (sink, transport)
    }

    fn operation_tag(operation: &CouchbaseOperation) -> u8 {
        match operation {
            CouchbaseOperation::Upsert => 0,
            CouchbaseOperation::Insert => 1,
            CouchbaseOperation::Replace => 2,
        }
    }

    #[test]
    fn test_config_validation() {
        let mut config = test_config();
        assert!(config.validate().is_ok());
        assert_eq!(config.scope_or_default(), "edge");
        assert_eq!(config.collection_or_default(), "events");

        config.connection_string = "http://127.0.0.1".to_string();
        assert!(config.validate().is_err());
        config.connection_string = "couchbases://cb.example.com".to_string();
        assert!(config.validate().is_ok());
        let endpoint = parse_connection_string("couchbases://cb.example.com:11207").unwrap();
        assert!(endpoint.tls);
        assert_eq!(endpoint.port, 11207);
        assert_eq!(
            parse_connection_string("couchbase://127.0.0.1")
                .unwrap()
                .port,
            11_210
        );
        config.connection_string = test_config().connection_string;

        config.bucket = "has space".to_string();
        assert!(config.validate().is_err());
        config.bucket = "telemetry".to_string();

        config.auth.username.clear();
        assert!(config.validate().is_err());
        config.auth.username = "Administrator".to_string();

        config.doc_id_template.clear();
        assert!(config.validate().is_err());
        config.doc_id_template = test_config().doc_id_template;

        config.batch_size = Some(0);
        assert!(config.validate().is_err());
        // Unbounded + huge depths accepted: zero clamped ceilings.
        config.batch_size = None;
        config.batch_bytes = Some(10_000_000);
        config.max_retries = None;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_doc_id_and_body() {
        let config = test_config();
        let key = config
            .resolve_doc_id(
                "sensors/t1",
                br#"{"client_id":"edge-7"}"#,
                QoS::AtMostOnce,
                1_789_211_889_123,
                9,
            )
            .unwrap();
        assert_eq!(key, "edge-7::1789211889123");
        // Payload-field template variables work too.
        let mut uuid_config = test_config();
        uuid_config.doc_id_template = "${payload.uuid}".to_string();
        assert_eq!(
            uuid_config
                .resolve_doc_id("t", br#"{"uuid":"abc-123"}"#, QoS::AtMostOnce, 0, 0)
                .unwrap(),
            "abc-123"
        );
        assert!(config
            .resolve_doc_id("t", b"{}", QoS::AtMostOnce, 0, 0)
            .is_err());

        let body = CouchbaseSink::build_body(
            &Topic::new("sensors/t1").unwrap(),
            &Bytes::from_static(br#"{"client_id":"edge-7","v":1}"#),
            QoS::AtLeastOnce,
            1_789_211_889_123,
        )
        .unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(doc["v"], 1);
        assert_eq!(doc["_mqtt"]["topic"], "sensors/t1");
        assert_eq!(doc["_mqtt"]["client_id"], "edge-7");
        assert_eq!(doc["_mqtt"]["qos"], 1);
        assert_eq!(doc["_mqtt"]["timestamp"], 1_789_211_889_123i64);
    }

    #[test]
    fn test_kv_framing_shapes() {
        // SET with expiry: header + extras + key + value.
        let frame = encode_mutation(CouchbaseOperation::Upsert, "k1", b"v1", 3_600, 41);
        assert_eq!(frame[0], 0x80);
        assert_eq!(frame[1], opcode::SET);
        assert_eq!(u16::from_be_bytes([frame[2], frame[3]]), 2);
        assert_eq!(frame[4], 8);
        assert_eq!(
            u32::from_be_bytes([frame[12], frame[13], frame[14], frame[15]]),
            41
        );
        // Extras: flags 0 + expiry 3600 BE.
        assert_eq!(
            &frame[24..32],
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0E, 0x10]
        );
        assert_eq!(&frame[32..34], b"k1");
        assert_eq!(&frame[34..36], b"v1");

        // ADD and REPLACE opcodes differ; SASL PLAIN token shape holds.
        assert_eq!(
            encode_mutation(CouchbaseOperation::Insert, "k", b"", 0, 0)[1],
            opcode::ADD
        );
        assert_eq!(
            encode_mutation(CouchbaseOperation::Replace, "k", b"", 0, 0)[1],
            opcode::REPLACE
        );
        assert_eq!(encode_plain_token("u", "p"), b"\0u\0p".to_vec());

        // Success response decodes with its opaque.
        let reply = encode_success_response(opcode::SET, 41);
        let decoded = decode_response(&reply).unwrap();
        assert_eq!(decoded.opcode, opcode::SET);
        assert_eq!(decoded.status, status::SUCCESS);
        assert_eq!(decoded.opaque, 41);
        assert!(decoded.body.is_empty());
        assert!(decode_response(&reply[..10]).is_err());
    }

    #[tokio::test]
    async fn test_batch_targets_scope_collection() {
        let (sink, transport) = test_sink(test_config());
        sink.send(
            &Topic::new("sensors/t1").unwrap(),
            &Bytes::from_static(br#"{"client_id":"edge-7"}"#),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        sink.flush().await.unwrap();
        let captured = transport.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].bucket, "telemetry");
        assert_eq!(captured[0].scope, "edge");
        assert_eq!(captured[0].collection, "events");
        assert_eq!(captured[0].items.len(), 1);
        assert!(captured[0].items[0].key.starts_with("edge-7::"));
        assert_eq!(captured[0].items[0].expiry_secs, 3_600);
        let doc: serde_json::Value = serde_json::from_slice(&captured[0].items[0].body).unwrap();
        assert_eq!(doc["_mqtt"]["topic"], "sensors/t1");
        assert_eq!(sink.sent_records(), 1);
    }

    #[tokio::test]
    async fn test_insert_conflict_is_terminal() {
        // Insert mode + Exists: terminal, single attempt, retained.
        let mut config = test_config();
        config.operation = CouchbaseOperation::Insert;
        config.batch_size = Some(10);
        config.max_retries = Some(5);
        let (sink, transport) = test_sink(config);
        transport.script_outcomes(vec![MockCouchbaseOutcome::StatusError {
            status: status::EXISTS,
        }]);

        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from_static(br#"{"client_id":"d7"}"#),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        let err = sink.flush().await.expect_err("exists must fail");
        assert!(matches!(err, ConnectorError::Dispatch(_)));
        assert_eq!(transport.calls(), 1);
        assert_eq!(sink.buffered_rows(), 1);
    }

    #[tokio::test]
    async fn test_backpressure_retries_then_succeeds() {
        let mut config = test_config();
        config.batch_size = Some(10);
        config.initial_backoff_ms = Some(1);
        config.max_backoff_ms = Some(2);
        let (sink, transport) = test_sink(config);
        transport.script_outcomes(vec![
            MockCouchbaseOutcome::StatusError {
                status: status::TEMPORARY_FAILURE,
            },
            MockCouchbaseOutcome::Ok,
        ]);

        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from_static(br#"{"client_id":"d7"}"#),
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
    async fn test_tcp_loopback_sasl_and_pipelined_batch() {
        use tokio::net::TcpListener;

        async fn read_request(
            stream: &mut tokio::net::TcpStream,
        ) -> (u8, Vec<u8>, Vec<u8>, Vec<u8>, u32) {
            let mut header = [0u8; 24];
            stream.read_exact(&mut header).await.expect("head");
            assert_eq!(header[0], 0x80);
            let key_len = u16::from_be_bytes([header[2], header[3]]) as usize;
            let ext_len = header[4] as usize;
            let total = u32::from_be_bytes([header[8], header[9], header[10], header[11]]) as usize;
            let mut rest = vec![0u8; total];
            stream.read_exact(&mut rest).await.expect("body");
            let opaque = u32::from_be_bytes([header[12], header[13], header[14], header[15]]);
            (
                header[1],
                rest[..ext_len].to_vec(),
                rest[ext_len..ext_len + key_len].to_vec(),
                rest[ext_len + key_len..].to_vec(),
                opaque,
            )
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            // SASL PLAIN auth first. The fake verifies the credential it
            // receives and fails closed: a bad token gets AUTH_ERROR
            // instead of an anonymous pass.
            let (opcode, _, key, value, opaque) = read_request(&mut stream).await;
            assert_eq!(opcode, opcode::SASL_AUTH);
            assert_eq!(key, b"PLAIN");
            if value != b"\0Administrator\0secret" {
                stream
                    .write_all(&encode_status_response(
                        opcode::SASL_AUTH,
                        opaque,
                        SASL_AUTH_ERROR,
                    ))
                    .await
                    .expect("auth fail");
                return;
            }
            stream
                .write_all(&encode_success_response(opcode::SASL_AUTH, opaque))
                .await
                .expect("auth ok");
            // Two pipelined SETs arrive back to back with distinct opaques.
            let mut seen = Vec::new();
            for _ in 0..2 {
                let (opcode, extras, key, value, opaque) = read_request(&mut stream).await;
                assert_eq!(opcode, opcode::SET);
                assert_eq!(&extras[4..8], &3_600u32.to_be_bytes());
                seen.push((key, value, opaque));
            }
            assert_ne!(seen[0].2, seen[1].2);
            assert_eq!(seen[0].0, b"edge-7::1");
            for (_, _, opaque) in &seen {
                stream
                    .write_all(&encode_success_response(opcode::SET, *opaque))
                    .await
                    .expect("ok");
            }
        });

        let mut config = test_config();
        config.connection_string = format!("couchbase://127.0.0.1:{port}");
        config.doc_id_template = "${client_id}::1".to_string();
        config.batch_size = Some(10);
        let transport = Arc::new(NativeCouchbaseTransport::new(&config).unwrap());
        let sink = CouchbaseSink::new(config, transport).unwrap();
        for _ in 0..2 {
            sink.send(
                &Topic::new("sensors/t1").unwrap(),
                &Bytes::from_static(br#"{"client_id":"edge-7"}"#),
                QoS::AtMostOnce,
            )
            .await
            .unwrap();
        }
        sink.flush().await.unwrap();
        assert_eq!(sink.sent_records(), 2);
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("server done")
            .expect("server task");

        // Wrong password fails closed at connect: a second fake with
        // the same verifier answers AUTH_ERROR and the transport
        // surfaces a connection error.
        let bad_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let bad_port = bad_listener.local_addr().expect("addr").port();
        let bad_server = tokio::spawn(async move {
            let (mut stream, _) = bad_listener.accept().await.expect("accept");
            let (opcode, _, key, value, opaque) = read_request(&mut stream).await;
            assert_eq!(opcode, opcode::SASL_AUTH);
            assert_eq!(key, b"PLAIN");
            if value != b"\0Administrator\0secret" {
                stream
                    .write_all(&encode_status_response(
                        opcode::SASL_AUTH,
                        opaque,
                        SASL_AUTH_ERROR,
                    ))
                    .await
                    .expect("auth fail");
                return;
            }
            stream
                .write_all(&encode_success_response(opcode::SASL_AUTH, opaque))
                .await
                .expect("auth ok");
        });
        let mut bad_config = test_config();
        bad_config.connection_string = format!("couchbase://127.0.0.1:{bad_port}");
        bad_config.auth.password = "wrong".to_string();
        let bad_transport = NativeCouchbaseTransport::new(&bad_config).unwrap();
        let err = bad_transport
            .connect()
            .await
            .expect_err("bad password must fail");
        assert!(
            matches!(err, ConnectorError::Connection(_)),
            "bad credential must fail closed, got {err:?}"
        );
        tokio::time::timeout(Duration::from_secs(5), bad_server)
            .await
            .expect("bad server done")
            .expect("bad server task");
    }

    fn qual_env(name: &str) -> Option<String> {
        std::env::var(name).ok().filter(|v| !v.trim().is_empty())
    }

    /// Qualification against a real Couchbase Server via the official
    /// `couchbase` driver.
    ///
    /// Run with e.g.:
    /// `COUCHBASE_URL=couchbase://127.0.0.1 COUCHBASE_USERNAME=qual \
    ///  COUCHBASE_PASSWORD=qualpass1 COUCHBASE_BUCKET=qual \
    ///  cargo test -p broker-connectors --lib couchbase::tests::test_qualify_driver_write_path -- --ignored --nocapture --test-threads=1`
    ///
    /// The bucket is created by the qualification setup; the test
    /// creates the scope and collection itself through the driver's
    /// management API. 1000 messages drive through the broker's rule
    /// path (`ConnectorManager::register` the way `register_live_sink`
    /// does, then `manager.send`, which is exactly what the rule
    /// engine's `ForwardConnector` action calls; never `sink.send`
    /// directly), then every document is read back by key with a
    /// non-zero CAS. A 2 s expiry probe is gone after 5 s. After the
    /// first 300 messages the test requests a server restart by
    /// creating `$QUAL_FAULT_FILE` and waits for the host to delete
    /// it, proving the sink retries until every document lands.
    /// Cleans up the scope it created.
    #[tokio::test]
    #[ignore = "needs a real Couchbase server (see COUCHBASE_* env)"]
    async fn test_qualify_driver_write_path() {
        use crate::ConnectorManager;

        let url = qual_env("COUCHBASE_URL").unwrap_or_else(|| {
            panic!(
                "COUCHBASE_URL must point at a real Couchbase server for qualification; \
                 failing closed instead of passing vacuously \
                 (e.g. COUCHBASE_URL=couchbase://127.0.0.1)"
            )
        });
        let username = qual_env("COUCHBASE_USERNAME").unwrap_or_else(|| {
            panic!("COUCHBASE_USERNAME must be set for qualification; failing closed")
        });
        let password = qual_env("COUCHBASE_PASSWORD").unwrap_or_else(|| {
            panic!("COUCHBASE_PASSWORD must be set for qualification; failing closed")
        });
        let bucket_name = qual_env("COUCHBASE_BUCKET").unwrap_or_else(|| {
            panic!("COUCHBASE_BUCKET must be set for qualification; failing closed")
        });
        let scope_name =
            qual_env("COUCHBASE_SCOPE").unwrap_or_else(|| "qual_b311_scope".to_string());
        let collection_name =
            qual_env("COUCHBASE_COLLECTION").unwrap_or_else(|| "qual_b311_docs".to_string());

        let authenticator = couchbase::authenticator::PasswordAuthenticator::new(
            username.clone(),
            password.clone(),
        );
        let options =
            couchbase::options::cluster_options::ClusterOptions::new(authenticator.into());
        let cluster = tokio::time::timeout(
            Duration::from_secs(60),
            couchbase::cluster::Cluster::connect(url.clone(), options),
        )
        .await
        .expect("qual connect timed out")
        .expect("qual connect");
        let bucket = cluster.bucket(bucket_name.clone());
        tokio::time::timeout(Duration::from_secs(60), bucket.wait_until_ready(None))
            .await
            .expect("qual bucket timed out")
            .expect("qual bucket ready");

        // Server version for the report: pools endpoint first, driver
        // diagnostics second; if neither gives it, omit it (never a
        // constant standing in for a measurement).
        let mut version_printed = String::new();
        {
            let mgmt_host = url
                .split("://")
                .last()
                .unwrap_or(url.as_str())
                .split(',')
                .next()
                .unwrap_or(url.as_str())
                .split('/')
                .next()
                .unwrap_or(url.as_str())
                .rsplit_once(':')
                .map(|(host, port)| {
                    if port.chars().all(|c| c.is_ascii_digit()) {
                        host.to_string()
                    } else {
                        format!("{host}:{port}")
                    }
                })
                .unwrap_or_else(|| url.clone());
            let pools_url = format!("http://{mgmt_host}:8091/pools");
            match reqwest::Client::new()
                .get(pools_url.clone())
                .basic_auth(username.clone(), Some(password.clone()))
                .timeout(Duration::from_secs(10))
                .send()
                .await
            {
                Ok(response) => match response.json::<serde_json::Value>().await {
                    Ok(pools) => {
                        if let Some(version) =
                            pools.get("implementationVersion").and_then(|v| v.as_str())
                        {
                            version_printed = version.to_string();
                            eprintln!(
                                "qual server: version={version} url={url} bucket={bucket_name}"
                            );
                        } else {
                            eprintln!("qual server: pools={pools} url={url}");
                        }
                    }
                    Err(e) => eprintln!("qual server: pools parse failed: {e} url={url}"),
                },
                Err(e) => eprintln!("qual server: pools unreachable ({pools_url}): {e}"),
            }
        }
        match cluster.diagnostics(None).await {
            Ok(diagnostics) => {
                eprintln!("qual diagnostics: {diagnostics:?}");
                if version_printed.is_empty() {
                    eprintln!("qual server: version unavailable (pools gave none)");
                }
            }
            Err(e) => eprintln!("qual diagnostics unavailable: {e}"),
        }

        // Fresh scope/collection through the driver's management API
        // (drop stale, then create; exists-races are fine).
        let collections = bucket.collections();
        let _ = collections.drop_scope(&scope_name, None).await;
        match collections.create_scope(&scope_name, None).await {
            Ok(()) => {}
            Err(e) => match e.kind() {
                couchbase::error::ErrorKind::ScopeExists => {}
                _ => panic!("qual create scope: {e}"),
            },
        }
        let collection_settings =
            couchbase::management::collections::collection_settings::CreateCollectionSettings::new(
            );
        match collections
            .create_collection(&scope_name, &collection_name, collection_settings, None)
            .await
        {
            Ok(()) => {}
            Err(e) => match e.kind() {
                couchbase::error::ErrorKind::CollectionExists => {}
                couchbase::error::ErrorKind::ScopeNotFound => {
                    panic!("qual create collection: scope missing: {e}")
                }
                _ => panic!("qual create collection: {e}"),
            },
        }
        let collection = cluster
            .bucket(bucket_name.clone())
            .scope(scope_name.clone())
            .collection(collection_name.clone());
        // Wait for the collection to accept writes.
        tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                match collection
                    .upsert(
                        "qual-b311-ready-probe",
                        serde_json::json!({"probe": true}),
                        None,
                    )
                    .await
                {
                    Ok(_) => break,
                    Err(_) => tokio::time::sleep(Duration::from_millis(500)).await,
                }
            }
        })
        .await
        .expect("qual collection never became writable");
        let _ = collection.remove("qual-b311-ready-probe", None).await;

        let config = CouchbaseSinkConfig {
            connection_string: url.clone(),
            bucket: bucket_name.clone(),
            scope: Some(scope_name.clone()),
            collection: Some(collection_name.clone()),
            auth: CouchbaseAuth {
                username: username.clone(),
                password: password.clone(),
            },
            doc_id_template: "${client_id}".to_string(),
            operation: CouchbaseOperation::Upsert,
            expiry_secs: None,
            batch_size: Some(100),
            batch_bytes: Some(2_097_152),
            linger_ms: Some(10),
            // High enough to ride out the mid-batch server restart
            // below without wedging the rule worker.
            max_retries: Some(200),
            initial_backoff_ms: Some(100),
            max_backoff_ms: Some(1_000),
            timeout_ms: Some(15_000),
        };
        config.validate().expect("qual config validates");
        let transport = Arc::new(DriverCouchbaseTransport::new(&config).expect("qual transport"));
        let sink = Arc::new(CouchbaseSink::new(config, transport).expect("qual sink"));
        assert_eq!(sink.kind(), "couchbase");
        // The broker's path: rule actions deliver through the shared
        // connector manager (this is what `register_live_sink` fills
        // and what `ForwardConnector` sends through), so the
        // qualification sends through it and never `sink.send`.
        let manager = ConnectorManager::new();
        manager.register("qual-cb", sink.clone());
        manager.register("couchbase:qual-cb", sink.clone());

        // TODO(parity): multi-node failover qualification.
        let fault_file = qual_env("QUAL_FAULT_FILE");
        let topic = Topic::new("sensors/qual").unwrap();
        for seq in 0..1000u32 {
            let device = format!("qual-{seq:06}");
            let payload = Bytes::from(format!(
                r#"{{"client_id":"{device}","seq":{seq},"temperature":{:.2}}}"#,
                20.0 + f64::from(seq) * 0.01
            ));
            manager
                .send("qual-cb", &topic, &payload, QoS::AtLeastOnce)
                .await
                .expect("qual send");
            if seq == 300 {
                if let Some(path) = fault_file.clone() {
                    eprintln!("qual fault: requesting server restart via {path}");
                    std::fs::write(&path, b"restart").expect("qual fault file write");
                    tokio::time::timeout(Duration::from_secs(600), async {
                        while std::path::Path::new(&path).exists() {
                            tokio::time::sleep(Duration::from_millis(500)).await;
                        }
                    })
                    .await
                    .expect("qual server never came back after restart");
                    eprintln!("qual fault: server back, continuing writes");
                }
            }
        }
        sink.flush().await.expect("qual flush");
        assert_eq!(sink.sent_records(), 1000);
        eprintln!("qual rows sent: records=1000 scope={scope_name}");

        // Exactly 1000 documents asserted back by key (upserts by key
        // are idempotent, so a retry cannot create extras and any loss
        // is a defect): every key present, every CAS non-zero.
        for seq in 0..1000u32 {
            let device = format!("qual-{seq:06}");
            let got = collection
                .get(&device, None)
                .await
                .unwrap_or_else(|e| panic!("qual missing {device}: {e}"));
            assert_ne!(got.cas(), 0, "qual CAS must be non-zero for {device}");
        }
        eprintln!("qual rows asserted: count=1000 each with non-zero CAS");

        // Expiry through the sink path: one document with a 2 s TTL,
        // present immediately, gone after 5 s.
        let expiry_config = CouchbaseSinkConfig {
            connection_string: url.clone(),
            bucket: bucket_name.clone(),
            scope: Some(scope_name.clone()),
            collection: Some(collection_name.clone()),
            auth: CouchbaseAuth {
                username: username.clone(),
                password: password.clone(),
            },
            doc_id_template: "${client_id}".to_string(),
            operation: CouchbaseOperation::Upsert,
            expiry_secs: Some(2),
            batch_size: Some(1),
            batch_bytes: Some(2_097_152),
            linger_ms: Some(10),
            max_retries: Some(200),
            initial_backoff_ms: Some(100),
            max_backoff_ms: Some(1_000),
            timeout_ms: Some(15_000),
        };
        expiry_config.validate().expect("qual expiry config");
        let expiry_transport =
            Arc::new(DriverCouchbaseTransport::new(&expiry_config).expect("qual expiry transport"));
        let expiry_sink = Arc::new(
            CouchbaseSink::new(expiry_config, expiry_transport).expect("qual expiry sink"),
        );
        manager.register("qual-cb-expiry", expiry_sink.clone());
        manager
            .send(
                "qual-cb-expiry",
                &topic,
                &Bytes::from_static(br#"{"client_id":"qual-expiry-probe","seq":-1}"#),
                QoS::AtLeastOnce,
            )
            .await
            .expect("qual expiry send");
        expiry_sink.flush().await.expect("qual expiry flush");
        let probe = collection
            .get("qual-expiry-probe", None)
            .await
            .expect("qual expiry doc must exist immediately");
        assert_ne!(probe.cas(), 0);
        tokio::time::sleep(Duration::from_secs(5)).await;
        match collection.get("qual-expiry-probe", None).await {
            Ok(_) => panic!("qual expiry doc must be gone after 5 s"),
            Err(e) => match e.kind() {
                couchbase::error::ErrorKind::DocumentNotFound => {}
                _ => panic!("qual expiry get must be NotFound, got {e}"),
            },
        }
        eprintln!("qual expiry asserted: 2 s TTL gone after 5 s");

        // Cleanup the scope created for this run (collections go with
        // it); a failure is fatal so a stale scope never leaks into
        // the next run silently.
        collections
            .drop_scope(&scope_name, None)
            .await
            .expect("qual cleanup scope");
        eprintln!("qual cleanup: dropped scope {scope_name} in bucket {bucket_name}");
    }
}
