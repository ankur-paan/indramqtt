//! Apache RocketMQ 5.0 streaming producer sink (INDRA-154).
//!
//! MQTT events become RocketMQ 5.0 `SendMessage` envelopes sent to a
//! proxy endpoint over TCP with a length-prefixed JSON envelope frame:
//!
//! ```text
//! [version:1 = 0x01][body_len:4 BE][JSON envelope]
//! ```
//!
//! The envelope carries request headers (`x-mq-client-id`,
//! `x-mq-date-time`, `x-mq-authorization`), per-message
//! `SystemProperties` (tag, keys, FIFO message group, born
//! timestamp) and the raw body bytes (base64). Request signing is
//! clean-room HMAC-SHA1 (`MQ {access_key}:{signature}`).
//! Authentication is optional: without credentials the authorization
//! header is omitted (plain proxy testing).
//!
//! Response handling classifies `Status.Code`: `OK` commits,
//! `TOO_MANY_REQUESTS` / `MASTER_NOT_AVAILABLE` retry with backoff,
//! `ILLEGAL_TOPIC` / `ACCESS_DENIED` abort terminally. Batching,
//! restore-on-failure and backoff reuse the shared
//! [`super::BatchQueue`] / [`super::BackoffState`] helpers.

use async_trait::async_trait;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex as AsyncMutex;

use super::{
    hmac_sha1, now_millis, rfc3339_millis, BackoffState, BatchQueue, ConnectorError, Result, Sink,
};

/// Envelope wire version.
pub const ENVELOPE_VERSION: u8 = 0x01;

/// RocketMQ 5.0 sink configuration. Every depth is user-configurable
/// with no clamped ceiling (`None` = unbounded).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RocketMqSinkConfig {
    /// Proxy / nameserver endpoints, e.g. `["127.0.0.1:8081"]`.
    pub endpoints: Vec<String>,
    /// Target RocketMQ topic string.
    pub topic: String,
    /// Message tag template, e.g. `${topic_segment_2}`.
    #[serde(default)]
    pub tag_template: Option<String>,
    /// Business message keys template, e.g.
    /// `${client_id}-${message_id}` (`${message_id}` = per-event seq).
    #[serde(default)]
    pub keys_template: Option<String>,
    /// FIFO message group template for ordered delivery.
    #[serde(default)]
    pub message_group_template: Option<String>,
    /// ACL access key (both keys required for signing).
    #[serde(default)]
    pub access_key: Option<String>,
    /// ACL secret key for HMAC-SHA1 request signing.
    #[serde(default)]
    pub secret_key: Option<String>,
    /// Flush trigger record count (default 128).
    #[serde(default = "default_batch_size")]
    pub batch_size: Option<usize>,
    /// Buffer capacity (`None` = unbounded).
    #[serde(default)]
    pub buffer_capacity: Option<usize>,
    /// Linger flush window in ms (default 100).
    #[serde(default = "default_linger_ms")]
    pub linger_ms: Option<u64>,
    /// Network request / connect timeout in ms (default 5000).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

fn default_batch_size() -> Option<usize> {
    Some(128)
}

fn default_linger_ms() -> Option<u64> {
    Some(100)
}

impl RocketMqSinkConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.unwrap_or(5000).max(1))
    }

    pub fn validate(&self) -> Result<()> {
        if self.endpoints.is_empty() || self.endpoints.iter().any(|e| e.trim().is_empty()) {
            return Err(ConnectorError::Dispatch(
                "rocketmq endpoints must not be empty".to_string(),
            ));
        }
        if self.topic.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "rocketmq topic must not be empty".to_string(),
            ));
        }
        if self.topic.contains([' ', '\0']) {
            return Err(ConnectorError::Dispatch(format!(
                "rocketmq topic must not contain whitespace: {:?}",
                self.topic
            )));
        }
        match (&self.access_key, &self.secret_key) {
            (Some(ak), Some(sk)) => {
                if ak.trim().is_empty() || sk.is_empty() {
                    return Err(ConnectorError::Dispatch(
                        "rocketmq access_key/secret_key must not be empty".to_string(),
                    ));
                }
            }
            (None, None) => {}
            _ => {
                return Err(ConnectorError::Dispatch(
                    "rocketmq access_key and secret_key must be set together".to_string(),
                ))
            }
        }
        // Strict template checks with dummy values.
        if let Some(template) = &self.tag_template {
            resolve_system_field(template, "dummy/t", "dummy", 0)?;
        }
        if let Some(template) = &self.keys_template {
            resolve_system_field(template, "dummy/t", "dummy", 0)?;
        }
        if let Some(template) = &self.message_group_template {
            resolve_system_field(template, "dummy/t", "dummy", 0)?;
        }
        if self.batch_size == Some(0) {
            return Err(ConnectorError::Dispatch(
                "rocketmq batch_size must be >= 1".to_string(),
            ));
        }
        Ok(())
    }

    pub fn signing_enabled(&self) -> bool {
        self.access_key.is_some() && self.secret_key.is_some()
    }

    pub(crate) fn effective_batch_size(&self) -> usize {
        self.batch_size.unwrap_or(usize::MAX)
    }

    pub(crate) fn effective_buffer(&self) -> usize {
        self.buffer_capacity.unwrap_or(usize::MAX)
    }

    pub(crate) fn linger(&self) -> Duration {
        Duration::from_millis(self.linger_ms.unwrap_or(100).max(1))
    }
}

// ---------------------------------------------------------------------------
// SystemProperties templates.
// ---------------------------------------------------------------------------

/// Resolve a system field template: `${topic}`, `${topic_segment_N}`
/// (1-based), `${client_id}`, `${message_id}` (per-event sequence).
/// Anything else is a dispatch error so typos fail loudly.
pub fn resolve_system_field(
    template: &str,
    topic: &str,
    client_id: &str,
    message_id: u64,
) -> Result<String> {
    let segments: Vec<&str> = topic.split('/').collect();
    let mut vars = vec![
        ("topic".to_string(), topic.to_string()),
        ("client_id".to_string(), client_id.to_string()),
        ("message_id".to_string(), message_id.to_string()),
    ];
    for (index, segment) in segments.iter().enumerate() {
        vars.push((format!("topic_segment_{}", index + 1), segment.to_string()));
    }
    let mut out = String::with_capacity(template.len() + 16);
    let bytes = template.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            let start = i + 2;
            let mut end = start;
            while end < bytes.len() && bytes[end] != b'}' {
                end += 1;
            }
            if end >= bytes.len() {
                return Err(ConnectorError::Dispatch(format!(
                    "unclosed template variable in {template:?}"
                )));
            }
            let name = &template[start..end];
            if name.is_empty() {
                return Err(ConnectorError::Dispatch(format!(
                    "empty template variable in {template:?}"
                )));
            }
            match vars.iter().find(|(key, _)| key == name) {
                Some((_, value)) => out.push_str(value),
                None => {
                    return Err(ConnectorError::Dispatch(format!(
                        "unknown template variable {name:?} in {template:?}"
                    )))
                }
            }
            i = end + 1;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    Ok(out)
}

/// Per-message system properties for the SendMessage envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RocketMqSystemProperties {
    pub tag: Option<String>,
    pub keys: Vec<String>,
    pub message_group: Option<String>,
    pub born_timestamp_ms: i64,
}

/// Build [`RocketMqSystemProperties`] for one event: empty renders
/// become absent (no empty tags/keys/groups on the wire).
pub fn build_system_properties(
    config: &RocketMqSinkConfig,
    topic: &str,
    client_id: &str,
    message_id: u64,
    millis: i64,
) -> Result<RocketMqSystemProperties> {
    let tag = match &config.tag_template {
        Some(template) => {
            let rendered = resolve_system_field(template, topic, client_id, message_id)?;
            if rendered.is_empty() {
                None
            } else {
                Some(rendered)
            }
        }
        None => None,
    };
    let keys = match &config.keys_template {
        Some(template) => {
            let rendered = resolve_system_field(template, topic, client_id, message_id)?;
            if rendered.is_empty() {
                Vec::new()
            } else {
                rendered.split_whitespace().map(str::to_string).collect()
            }
        }
        None => Vec::new(),
    };
    let message_group = match &config.message_group_template {
        Some(template) => {
            let rendered = resolve_system_field(template, topic, client_id, message_id)?;
            if rendered.is_empty() {
                None
            } else {
                Some(rendered)
            }
        }
        None => None,
    };
    Ok(RocketMqSystemProperties {
        tag,
        keys,
        message_group,
        born_timestamp_ms: millis,
    })
}

// ---------------------------------------------------------------------------
// HMAC-SHA1 request signing (clean-room).
// ---------------------------------------------------------------------------

/// Build the signing string: client id, RFC 3339 datetime, topic and
/// the hex MD5 of the envelope body, LF-joined.
pub fn signing_string(client_id: &str, datetime: &str, topic: &str, body_md5_hex: &str) -> String {
    format!("{client_id}\n{datetime}\n{topic}\n{body_md5_hex}")
}

/// Lowercase hex MD5 of `data`.
pub fn md5_hex(data: &[u8]) -> String {
    use md5::Digest;
    let mut digest = md5::Md5::new();
    digest.update(data);
    format!("{:x}", digest.finalize())
}

/// `x-mq-authorization: MQ {access_key}:{Base64(HMAC_SHA1(secret, sts))}`.
pub fn authorization_header(access_key: &str, secret_key: &str, signing_string: &str) -> String {
    use base64::Engine;
    let signature = base64::engine::general_purpose::STANDARD
        .encode(hmac_sha1(secret_key.as_bytes(), signing_string.as_bytes()));
    format!("MQ {access_key}:{signature}")
}

// ---------------------------------------------------------------------------
// Envelope framing.
// ---------------------------------------------------------------------------

/// One message inside a SendMessage envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RocketMqEnvelopeMessage {
    pub system_properties: RocketMqSystemProperties,
    /// Raw payload bytes (base64).
    pub body_b64: String,
}

/// Full SendMessage envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RocketMqEnvelope {
    pub topic: String,
    pub client_id: String,
    pub datetime: String,
    pub authorization: Option<String>,
    pub messages: Vec<RocketMqEnvelopeMessage>,
}

/// Encode the envelope frame: version byte + BE length + JSON body.
pub fn encode_envelope(envelope: &RocketMqEnvelope) -> Result<Vec<u8>> {
    let body = serde_json::to_vec(envelope).map_err(|e| {
        ConnectorError::Dispatch(format!("rocketmq envelope is not JSON-encodable: {e}"))
    })?;
    let mut frame = Vec::with_capacity(5 + body.len());
    frame.push(ENVELOPE_VERSION);
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Decode one envelope frame back (length-checked).
pub fn decode_envelope(frame: &[u8]) -> Result<RocketMqEnvelope> {
    if frame.len() < 5 {
        return Err(ConnectorError::Dispatch(
            "rocketmq frame shorter than the 5-byte prefix".to_string(),
        ));
    }
    if frame[0] != ENVELOPE_VERSION {
        return Err(ConnectorError::Dispatch(format!(
            "rocketmq frame has bad version byte {:#04x}",
            frame[0]
        )));
    }
    let len = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize;
    if frame.len() - 5 != len {
        return Err(ConnectorError::Dispatch(format!(
            "rocketmq frame length mismatch: header says {len}, got {}",
            frame.len() - 5
        )));
    }
    serde_json::from_slice(&frame[5..])
        .map_err(|e| ConnectorError::Dispatch(format!("rocketmq envelope body is not JSON: {e}")))
}

// ---------------------------------------------------------------------------
// Status classification + FIFO hashing.
// ---------------------------------------------------------------------------

/// RocketMQ 5.0 `Status.Code` relevant to producers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RocketMqStatus {
    Ok,
    TooManyRequests,
    MasterNotAvailable,
    IllegalTopic,
    AccessDenied,
    MessageBodyTooLarge,
    Unknown(i32),
}

impl RocketMqStatus {
    /// Toy-protocol status codes for the JSON acknowledgement frame
    /// (`{"code":N}`): 0 OK, 1 TOO_MANY_REQUESTS, 2
    /// MASTER_NOT_AVAILABLE, 3 ILLEGAL_TOPIC, 4 ACCESS_DENIED, 5
    /// MESSAGE_BODY_TOO_LARGE.
    pub fn from_code(code: i32) -> Self {
        match code {
            0 => RocketMqStatus::Ok,
            1 => RocketMqStatus::TooManyRequests,
            2 => RocketMqStatus::MasterNotAvailable,
            3 => RocketMqStatus::IllegalTopic,
            4 => RocketMqStatus::AccessDenied,
            5 => RocketMqStatus::MessageBodyTooLarge,
            other => RocketMqStatus::Unknown(other),
        }
    }
}

/// Classified send outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RocketMqOutcome {
    Success,
    Retryable,
    Terminal,
}

/// `OK` commits; `TOO_MANY_REQUESTS` / `MASTER_NOT_AVAILABLE` retry
/// with backoff; `ILLEGAL_TOPIC` / `ACCESS_DENIED` (and oversized
/// bodies) abort terminally; unknown codes retry conservatively.
pub fn classify_status(status: RocketMqStatus) -> RocketMqOutcome {
    match status {
        RocketMqStatus::Ok => RocketMqOutcome::Success,
        RocketMqStatus::TooManyRequests | RocketMqStatus::MasterNotAvailable => {
            RocketMqOutcome::Retryable
        }
        RocketMqStatus::IllegalTopic
        | RocketMqStatus::AccessDenied
        | RocketMqStatus::MessageBodyTooLarge => RocketMqOutcome::Terminal,
        RocketMqStatus::Unknown(_) => RocketMqOutcome::Retryable,
    }
}

/// FNV-1a 32-bit hash for FIFO message-group queue selection.
pub fn fnv1a_32(data: &[u8]) -> u32 {
    let mut hash = 0x811c9dc5u32;
    for &byte in data {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

/// Queue index for a FIFO group (`None` group = queue 0, unordered).
pub fn fifo_partition(message_group: Option<&str>, queue_count: u32) -> u32 {
    let queues = queue_count.max(1);
    match message_group {
        Some(group) => fnv1a_32(group.as_bytes()) % queues,
        None => 0,
    }
}

// ---------------------------------------------------------------------------
// Transport.
// ---------------------------------------------------------------------------

/// One queued message: envelope properties + raw body.
#[derive(Debug, Clone)]
pub struct RocketMqMessage {
    pub properties: RocketMqSystemProperties,
    pub body: Vec<u8>,
}

#[async_trait]
pub trait RocketMqTransport: Send + Sync {
    async fn send_messages(
        &self,
        topic: &str,
        client_id: &str,
        datetime: &str,
        authorization: Option<&str>,
        messages: Vec<RocketMqMessage>,
    ) -> Result<()>;
}

/// In-memory transport recording every envelope (tests, dry runs).
#[derive(Debug, Default)]
pub struct MockRocketMqTransport {
    envelopes: parking_lot::Mutex<Vec<RocketMqEnvelope>>,
    failures_left: parking_lot::Mutex<usize>,
    calls: AtomicU64,
}

impl MockRocketMqTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fail the next `n` sends with a transport error (backoff tests).
    pub fn fail_next(&self, n: usize) {
        *self.failures_left.lock() = n;
    }

    pub fn envelopes(&self) -> Vec<RocketMqEnvelope> {
        self.envelopes.lock().clone()
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl RocketMqTransport for MockRocketMqTransport {
    async fn send_messages(
        &self,
        topic: &str,
        client_id: &str,
        datetime: &str,
        authorization: Option<&str>,
        messages: Vec<RocketMqMessage>,
    ) -> Result<()> {
        use base64::Engine;
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut failures = self.failures_left.lock();
        if *failures > 0 {
            *failures -= 1;
            return Err(ConnectorError::Connection("mock rocketmq down".to_string()));
        }
        self.envelopes.lock().push(RocketMqEnvelope {
            topic: topic.to_string(),
            client_id: client_id.to_string(),
            datetime: datetime.to_string(),
            authorization: authorization.map(str::to_string),
            messages: messages
                .into_iter()
                .map(|message| RocketMqEnvelopeMessage {
                    system_properties: message.properties,
                    body_b64: base64::engine::general_purpose::STANDARD.encode(&message.body),
                })
                .collect(),
        });
        Ok(())
    }
}

/// TCP transport: one envelope frame per flush, one JSON
/// acknowledgement frame (`{"code":N}`) per reply. One in-flight
/// exchange at a time; dropped connections redial once.
pub struct TcpRocketMqTransport {
    endpoint: String,
    timeout: Duration,
    conn: AsyncMutex<Option<TcpStream>>,
}

impl TcpRocketMqTransport {
    pub fn new(config: &RocketMqSinkConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            endpoint: config.endpoints[0].clone(),
            timeout: config.timeout(),
            conn: AsyncMutex::new(None),
        })
    }

    async fn roundtrip(&self, frame: Vec<u8>) -> Result<Vec<u8>> {
        let mut guard = self.conn.lock().await;
        for attempt in 0..2 {
            if guard.is_none() {
                let stream = tokio::time::timeout(
                    self.timeout,
                    TcpStream::connect(&self.endpoint),
                )
                .await
                .map_err(|_| {
                    ConnectorError::Connection(format!(
                        "rocketmq connect timeout: {}",
                        self.endpoint
                    ))
                })?
                .map_err(|e| {
                    ConnectorError::Connection(format!(
                        "rocketmq connect to {} failed: {e}",
                        self.endpoint
                    ))
                })?;
                *guard = Some(stream);
            }
            let stream = guard.as_mut().expect("connected");
            let exchange = async {
                stream.write_all(&frame).await?;
                let mut len_buf = [0u8; 4];
                stream.read_exact(&mut len_buf).await?;
                let len = u32::from_be_bytes(len_buf) as usize;
                if len > 8 * 1024 * 1024 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "rocketmq ack frame too large",
                    ));
                }
                let mut body = vec![0u8; len];
                stream.read_exact(&mut body).await?;
                Ok::<Vec<u8>, std::io::Error>(body)
            };
            match tokio::time::timeout(self.timeout, exchange).await {
                Ok(Ok(body)) => return Ok(body),
                Ok(Err(_)) | Err(_) if attempt == 0 => {
                    *guard = None;
                    continue;
                }
                Ok(Err(e)) => {
                    *guard = None;
                    return Err(ConnectorError::Connection(format!(
                        "rocketmq exchange failed: {e}"
                    )));
                }
                Err(_) => {
                    *guard = None;
                    return Err(ConnectorError::Connection(
                        "rocketmq exchange timed out".to_string(),
                    ));
                }
            }
        }
        Err(ConnectorError::Connection(
            "rocketmq exchange failed".to_string(),
        ))
    }
}

#[async_trait]
impl RocketMqTransport for TcpRocketMqTransport {
    async fn send_messages(
        &self,
        topic: &str,
        client_id: &str,
        datetime: &str,
        authorization: Option<&str>,
        messages: Vec<RocketMqMessage>,
    ) -> Result<()> {
        use base64::Engine;
        let frame = encode_envelope(&RocketMqEnvelope {
            topic: topic.to_string(),
            client_id: client_id.to_string(),
            datetime: datetime.to_string(),
            authorization: authorization.map(str::to_string),
            messages: messages
                .into_iter()
                .map(|message| RocketMqEnvelopeMessage {
                    system_properties: message.properties,
                    body_b64: base64::engine::general_purpose::STANDARD.encode(&message.body),
                })
                .collect(),
        })?;
        // Envelope frames carry their own 5-byte prefix; the ack
        // framing is a bare BE length + JSON `{"code":N}` body.
        let reply = self.roundtrip(frame).await?;
        let ack: serde_json::Value = serde_json::from_slice(&reply)
            .map_err(|e| ConnectorError::Connection(format!("rocketmq ack is not JSON: {e}")))?;
        let code = ack.get("code").and_then(|code| code.as_i64()).unwrap_or(-1) as i32;
        match classify_status(RocketMqStatus::from_code(code)) {
            RocketMqOutcome::Success => Ok(()),
            RocketMqOutcome::Retryable => Err(ConnectorError::Connection(format!(
                "rocketmq {topic} answered retryable code {code}"
            ))),
            RocketMqOutcome::Terminal => Err(ConnectorError::Dispatch(format!(
                "rocketmq {topic} answered terminal code {code}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// Sink.
// ---------------------------------------------------------------------------

/// One buffered event: raw topic/payload plus per-event sequence.
#[derive(Debug, Clone)]
struct RocketMqRow {
    topic: String,
    payload: Bytes,
    message_id: u64,
}

/// RocketMQ sink: buffers events, sends one envelope per flush with
/// fresh timestamps + signatures per attempt.
pub struct RocketMqSink {
    config: RocketMqSinkConfig,
    transport: Arc<dyn RocketMqTransport>,
    buffer: parking_lot::Mutex<BatchQueue<RocketMqRow>>,
    backoff: parking_lot::Mutex<BackoffState>,
    client_id: String,
    message_seq: AtomicU64,
    sent_batches: AtomicU64,
    sent_records: AtomicU64,
}

impl RocketMqSink {
    pub fn new(config: RocketMqSinkConfig, transport: Arc<dyn RocketMqTransport>) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            client_id: format!("indra-rmq-{}", uuid::Uuid::new_v4()),
            buffer: parking_lot::Mutex::new(BatchQueue::new(
                config.effective_batch_size(),
                config.linger(),
            )),
            config,
            transport,
            backoff: parking_lot::Mutex::new(BackoffState::default()),
            message_seq: AtomicU64::new(0),
            sent_batches: AtomicU64::new(0),
            sent_records: AtomicU64::new(0),
        })
    }

    pub fn config(&self) -> &RocketMqSinkConfig {
        &self.config
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
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

    /// Build transport messages for the pending rows (fresh per attempt
    /// so replays never reuse stale born timestamps... note the born
    /// timestamp rides the flush clock, shared across attempts of one
    /// flush like a broker-side born time).
    fn build_messages(&self, rows: &[RocketMqRow], millis: i64) -> Result<Vec<RocketMqMessage>> {
        let mut messages = Vec::with_capacity(rows.len());
        for row in rows {
            let text = std::str::from_utf8(&row.payload).map_err(|_| {
                ConnectorError::Dispatch("rocketmq payload must be UTF-8".to_string())
            })?;
            let parsed: serde_json::Value =
                serde_json::from_str(text).unwrap_or(serde_json::Value::Null);
            let client_id = parsed
                .get("client_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            messages.push(RocketMqMessage {
                properties: build_system_properties(
                    &self.config,
                    &row.topic,
                    client_id,
                    row.message_id,
                    millis,
                )?,
                body: row.payload.to_vec(),
            });
        }
        Ok(messages)
    }

    /// Flush buffered rows as one envelope (no-op when empty). The
    /// datetime + signature are fresh per flush; any failure restores
    /// the pending rows, engages backoff and propagates.
    pub async fn flush(&self) -> Result<()> {
        self.backoff.lock().check()?;
        let (rows, oldest) = {
            let mut buffer = self.buffer.lock();
            buffer.take_batch()
        };
        if rows.is_empty() {
            return Ok(());
        }
        let total = rows.len() as u64;
        let pending: Vec<RocketMqRow> = rows;
        // Single attempt per flush: the datetime + signature are fresh,
        // and any failure restores the rows, engages backoff and
        // propagates (the next flush retries after the backoff window).
        let millis = now_millis();
        let datetime = rfc3339_millis(millis);
        let messages = self.build_messages(&pending, millis)?;
        let body_md5 =
            md5_hex(&serde_json::to_vec(&messages_md5_input(&messages)).unwrap_or_default());
        let authorization = match (&self.config.access_key, &self.config.secret_key) {
            (Some(ak), Some(sk)) => Some(authorization_header(
                ak,
                sk,
                &signing_string(&self.client_id, &datetime, &self.config.topic, &body_md5),
            )),
            _ => None,
        };
        match self
            .transport
            .send_messages(
                &self.config.topic,
                &self.client_id,
                &datetime,
                authorization.as_deref(),
                messages,
            )
            .await
        {
            Ok(()) => {
                self.backoff.lock().success();
                self.sent_batches.fetch_add(1, Ordering::Relaxed);
                self.sent_records.fetch_add(total, Ordering::Relaxed);
                Ok(())
            }
            Err(ConnectorError::Connection(message)) => {
                let mut buffer = self.buffer.lock();
                buffer.restore(pending, oldest);
                self.backoff.lock().failure();
                Err(ConnectorError::Connection(message))
            }
            Err(e) => {
                let mut buffer = self.buffer.lock();
                buffer.restore(pending, oldest);
                self.backoff.lock().failure();
                Err(e)
            }
        }
    }

    /// Validate + buffer one event. Returns true when the batch is
    /// full or stale (caller flushes).
    fn buffer_row(&self, topic: &Topic, payload: &Bytes, _qos: QoS) -> Result<bool> {
        if topic.as_str().is_empty() {
            return Err(ConnectorError::Dispatch(
                "rocketmq row requires a non-empty topic".to_string(),
            ));
        }
        if self.buffer.lock().len() >= self.config.effective_buffer() {
            return Err(ConnectorError::Connection(
                "rocketmq buffer limit reached".to_string(),
            ));
        }
        let message_id = self.message_seq.fetch_add(1, Ordering::SeqCst);
        let mut buffer = self.buffer.lock();
        Ok(buffer.push(RocketMqRow {
            topic: topic.as_str().to_string(),
            payload: payload.clone(),
            message_id,
        }))
    }
}

/// Deterministic signing input for a batch of messages (JSON array of
/// base64 bodies).
fn messages_md5_input(messages: &[RocketMqMessage]) -> Vec<String> {
    use base64::Engine;
    messages
        .iter()
        .map(|m| base64::engine::general_purpose::STANDARD.encode(&m.body))
        .collect()
}

#[async_trait]
impl Sink for RocketMqSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        if self.buffer_row(topic, payload, qos)? {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "rocketmq"
    }
}

/// Management connector handle pairing an id with a RocketMQ sink.
pub struct RocketMqConnector {
    id: String,
    sink: Arc<RocketMqSink>,
}

impl RocketMqConnector {
    pub fn new(id: impl Into<String>, sink: Arc<RocketMqSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }
}

impl super::Connector for RocketMqConnector {
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

    fn test_config() -> RocketMqSinkConfig {
        RocketMqSinkConfig {
            endpoints: vec!["127.0.0.1:8081".to_string()],
            topic: "rocket-telemetry".to_string(),
            tag_template: Some("${topic_segment_2}".to_string()),
            keys_template: Some("${client_id}-${message_id}".to_string()),
            message_group_template: Some("group-${client_id}".to_string()),
            access_key: Some("rocket-key".to_string()),
            secret_key: Some("rocket-secret".to_string()),
            batch_size: Some(128),
            buffer_capacity: None,
            linger_ms: Some(100),
            timeout_ms: None,
        }
    }

    #[test]
    fn test_config_validation() {
        let mut config = test_config();
        assert!(config.validate().is_ok());

        config.endpoints.clear();
        assert!(config.validate().is_err());
        config.endpoints = vec!["  ".to_string()];
        assert!(config.validate().is_err());
        config.endpoints = test_config().endpoints;

        config.topic = "has space".to_string();
        assert!(config.validate().is_err());
        config.topic = String::new();
        assert!(config.validate().is_err());
        config.topic = test_config().topic;

        config.secret_key = None;
        assert!(config.validate().is_err(), "half credentials must fail");
        config.access_key = None;
        assert!(
            config.validate().is_ok(),
            "anonymous proxy testing is allowed"
        );
        config.access_key = Some("rocket-key".to_string());
        config.secret_key = Some(String::new());
        assert!(config.validate().is_err());
        config.secret_key = test_config().secret_key;

        config.tag_template = Some("${bogus}".to_string());
        assert!(config.validate().is_err());
        config.tag_template = test_config().tag_template;

        config.batch_size = Some(0);
        assert!(config.validate().is_err());
        config.batch_size = Some(10_000_000);

        // Zero clamped ceilings: huge depths are accepted.
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_authorization_known_answer() {
        // Independent Python (hmac/hashlib) vector.
        let sts = signing_string(
            "test-client-id",
            "2026-09-12T11:18:09.123Z",
            "rocket-telemetry",
            "5d41402abc4b2a76b9719d911017c592",
        );
        assert_eq!(
            sts,
            "test-client-id\n2026-09-12T11:18:09.123Z\nrocket-telemetry\n5d41402abc4b2a76b9719d911017c592"
        );
        assert_eq!(
            authorization_header("rocket-key", "rocket-secret", &sts),
            "MQ rocket-key:QQN6h/kBpUCyFPOPZ60kUDksydc="
        );
    }

    #[test]
    fn test_system_properties_builder() {
        let config = test_config();
        let props =
            build_system_properties(&config, "sensors/kitchen", "d7", 41, 1_789_211_889_123)
                .unwrap();
        assert_eq!(
            props,
            RocketMqSystemProperties {
                tag: Some("kitchen".to_string()),
                keys: vec!["d7-41".to_string()],
                message_group: Some("group-d7".to_string()),
                born_timestamp_ms: 1_789_211_889_123,
            }
        );
        // Empty renders vanish instead of riding the wire.
        let mut blank = test_config();
        blank.tag_template = Some("static".to_string());
        blank.keys_template = None;
        blank.message_group_template = None;
        let props = build_system_properties(&blank, "t", "d", 0, 0).unwrap();
        assert_eq!(props.tag.as_deref(), Some("static"));
        assert!(props.keys.is_empty());
        assert!(props.message_group.is_none());

        assert!(resolve_system_field("${bogus}", "a", "b", 0).is_err());
        assert!(resolve_system_field("${topic", "a", "b", 0).is_err());
        assert!(resolve_system_field("${}", "a", "b", 0).is_err());
    }

    #[test]
    fn test_envelope_framing_round_trip() {
        let envelope = RocketMqEnvelope {
            topic: "rocket-telemetry".to_string(),
            client_id: "test-client".to_string(),
            datetime: "2026-09-12T11:18:09.123Z".to_string(),
            authorization: Some("MQ k:s".to_string()),
            messages: vec![RocketMqEnvelopeMessage {
                system_properties: RocketMqSystemProperties {
                    tag: Some("kitchen".to_string()),
                    keys: vec!["d7-41".to_string()],
                    message_group: Some("group-d7".to_string()),
                    born_timestamp_ms: 1_789_211_889_123,
                },
                body_b64: "aGk=".to_string(),
            }],
        };
        let frame = encode_envelope(&envelope).unwrap();
        assert_eq!(frame[0], 0x01);
        let len = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize;
        assert_eq!(5 + len, frame.len());
        let back = decode_envelope(&frame).unwrap();
        assert_eq!(back.topic, "rocket-telemetry");
        assert_eq!(back.messages.len(), 1);
        assert_eq!(back.messages[0].body_b64, "aGk=");

        assert!(decode_envelope(&[0x01, 0x00]).is_err());
        assert!(decode_envelope(&[0x02, 0x00, 0x00, 0x00, 0x00]).is_err());
        let mut bad_len = frame.clone();
        bad_len[4] ^= 0xFF;
        assert!(decode_envelope(&bad_len).is_err());
    }

    #[test]
    fn test_status_classification_and_fifo_hashing() {
        assert_eq!(
            classify_status(RocketMqStatus::from_code(0)),
            RocketMqOutcome::Success
        );
        assert_eq!(
            classify_status(RocketMqStatus::from_code(1)),
            RocketMqOutcome::Retryable
        );
        assert_eq!(
            classify_status(RocketMqStatus::from_code(2)),
            RocketMqOutcome::Retryable
        );
        assert_eq!(
            classify_status(RocketMqStatus::from_code(3)),
            RocketMqOutcome::Terminal
        );
        assert_eq!(
            classify_status(RocketMqStatus::from_code(4)),
            RocketMqOutcome::Terminal
        );
        assert_eq!(
            classify_status(RocketMqStatus::from_code(5)),
            RocketMqOutcome::Terminal
        );
        assert_eq!(
            classify_status(RocketMqStatus::from_code(99)),
            RocketMqOutcome::Retryable
        );

        // FNV-1a 32 reference values (independent Python check).
        assert_eq!(fnv1a_32(b""), 0x811c9dc5);
        assert_eq!(fnv1a_32(b"a"), 0xe40c292c);
        assert_eq!(fnv1a_32(b"foobar"), 0xbf9cf968);
        assert_eq!(fnv1a_32(b"fifo-group-7"), 0xa7bf4ac9);
        // FIFO groups pin to one queue; unordered lands on 0.
        assert_eq!(fifo_partition(Some("fifo-group-7"), 8), 0xa7bf4ac9 % 8);
        assert_eq!(fifo_partition(None, 8), 0);
        assert_eq!(fifo_partition(Some("g"), 4), fnv1a_32(b"g") % 4);
    }

    #[tokio::test]
    async fn test_send_flow_and_backoff() {
        let transport = Arc::new(MockRocketMqTransport::new());
        let mut config = test_config();
        config.batch_size = Some(2);
        let sink = RocketMqSink::new(config, transport.clone()).unwrap();

        let topic = Topic::new("sensors/kitchen").unwrap();
        sink.send(
            &topic,
            &Bytes::from(r#"{"client_id":"d7"}"#),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        sink.send(
            &topic,
            &Bytes::from(r#"{"client_id":"d8"}"#),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        assert_eq!(sink.sent_batches(), 1);
        assert_eq!(sink.sent_records(), 2);

        let envelopes = transport.envelopes();
        assert_eq!(envelopes.len(), 1);
        assert_eq!(envelopes[0].topic, "rocket-telemetry");
        assert_eq!(envelopes[0].messages.len(), 2);
        assert_eq!(
            envelopes[0].messages[0].system_properties.tag.as_deref(),
            Some("kitchen")
        );
        assert_eq!(
            envelopes[0].messages[0].system_properties.keys,
            vec!["d7-0".to_string()]
        );
        assert_eq!(
            envelopes[0].messages[0]
                .system_properties
                .message_group
                .as_deref(),
            Some("group-d7")
        );
        use base64::Engine;
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(&envelopes[0].messages[0].body_b64)
                .unwrap(),
            br#"{"client_id":"d7"}"#.to_vec()
        );
        assert!(envelopes[0]
            .authorization
            .as_deref()
            .unwrap()
            .starts_with("MQ rocket-key:"));

        // Transport failures restore the buffer and engage backoff.
        transport.fail_next(10);
        sink.send(
            &topic,
            &Bytes::from(r#"{"client_id":"dx"}"#),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        let err = sink.flush().await.expect_err("mock down must fail");
        assert!(matches!(err, ConnectorError::Connection(_)));
        assert_eq!(sink.buffered_rows(), 1);
        assert_eq!(transport.calls(), 2);
    }

    /// Fake RocketMQ proxy: reads one envelope frame, checks the auth
    /// header + topics, and acks `{"code":0}`.
    #[tokio::test]
    async fn test_tcp_loopback_envelope() {
        use std::sync::Mutex as StdMutex;

        let seen_auth = Arc::new(StdMutex::new(Vec::<String>::new()));
        let seen_auth_rx = seen_auth.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            // Envelope frame: version + BE length + JSON.
            let mut prefix = [0u8; 5];
            stream.read_exact(&mut prefix).await.expect("prefix");
            assert_eq!(prefix[0], 0x01);
            let len = u32::from_be_bytes([prefix[1], prefix[2], prefix[3], prefix[4]]) as usize;
            let mut body = vec![0u8; len];
            stream.read_exact(&mut body).await.expect("body");
            let envelope: RocketMqEnvelope = serde_json::from_slice(&body).expect("envelope");
            assert_eq!(envelope.topic, "rocket-telemetry");
            assert_eq!(envelope.messages.len(), 1);
            assert_eq!(
                envelope.messages[0].system_properties.tag.as_deref(),
                Some("kitchen")
            );
            seen_auth_rx
                .lock()
                .unwrap()
                .push(envelope.authorization.clone().expect("signed when keyed"));
            // Ack frame: BE length + {"code":0}.
            let ack = br#"{"code":0}"#;
            let mut framed = (ack.len() as u32).to_be_bytes().to_vec();
            framed.extend_from_slice(ack);
            stream.write_all(&framed).await.expect("ack");
        });

        let mut config = test_config();
        config.endpoints = vec![format!("127.0.0.1:{port}")];
        config.batch_size = Some(1);
        let sink = RocketMqSink::new(config, Arc::new(MockRocketMqTransport::new())).unwrap();
        // Drive the TCP transport directly (unit scope: framing on wire).
        let transport = TcpRocketMqTransport::new(&test_config_with_port(port)).unwrap();
        let messages = sink
            .build_messages(
                &[RocketMqRow {
                    topic: "sensors/kitchen".to_string(),
                    payload: Bytes::from_static(br#"{"client_id":"d7"}"#),
                    message_id: 0,
                }],
                1_789_211_889_123,
            )
            .unwrap();
        transport
            .send_messages(
                "rocket-telemetry",
                sink.client_id(),
                "2026-09-12T11:18:09.123Z",
                Some("MQ rocket-key:test"),
                messages,
            )
            .await
            .expect("loopback send succeeds");

        let mut finished = false;
        for _ in 0..500 {
            if server.is_finished() {
                finished = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(finished, "fake proxy never consumed the envelope");
        server.await.expect("fake proxy task");
        assert_eq!(
            *seen_auth.lock().unwrap(),
            vec!["MQ rocket-key:test".to_string()]
        );
    }

    fn test_config_with_port(port: u16) -> RocketMqSinkConfig {
        let mut config = test_config();
        config.endpoints = vec![format!("127.0.0.1:{port}")];
        config
    }
}
