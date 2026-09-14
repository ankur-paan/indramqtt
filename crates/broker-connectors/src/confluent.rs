//! Confluent Cloud managed Kafka sink (INDRA-152).
//!
//! MQTT events become Kafka records on Confluent Cloud: the destination
//! topic renders from `topic_template` (`${topic}`,
//! `${topic_segment_N}`), the partition key derives from
//! `partition_key_template` (`${client_id}`, `${payload.<path>}`) with
//! murmur2 partitioning, and values optionally carry the Confluent
//! Schema Registry wire header (magic `0x00` + big-endian schema id).
//!
//! Authentication covers SASL/PLAIN (handshake + authenticate over TCP)
//! and SASL/SCRAM-SHA-256/512 (full clean-room client conversation:
//! client-first, proof via PBKDF2, mutual server-signature check).
//! RecordBatch-v2 encoding, Produce framing and the ApiVersions probe
//! reuse the shared Kafka framing in [`super::kafka`]; error codes
//! classify per the task contract (58 terminal, 7/19 retryable).

use async_trait::async_trait;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Mutex as AsyncMutex;

use super::kafka::{
    decode_api_versions_response, encode_api_versions_request, encode_produce_request,
    encode_request_header, parse_acks, read_response, send_frame, KafkaRecord,
};
use super::{now_millis, BackoffState, ConnectorError, Result, Sink};

/// SASL mechanism for Confluent Cloud.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SaslMechanism {
    /// `PLAIN` (`\0key\0secret`), the Confluent Cloud default.
    #[default]
    Plain,
    /// `SCRAM-SHA-256`.
    #[serde(rename = "scramsha256")]
    ScramSha256,
    /// `SCRAM-SHA-512`.
    #[serde(rename = "scramsha512")]
    ScramSha512,
}

impl SaslMechanism {
    pub fn kafka_name(self) -> &'static str {
        match self {
            SaslMechanism::Plain => "PLAIN",
            SaslMechanism::ScramSha256 => "SCRAM-SHA-256",
            SaslMechanism::ScramSha512 => "SCRAM-SHA-512",
        }
    }
}

/// Confluent Schema Registry attachment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfluentSchemaRegistryConfig {
    /// Registry URL, e.g. `https://psrc-xxxx.us-east-1.aws.confluent.cloud`.
    pub endpoint: String,
    /// Registry API key (Basic auth).
    pub api_key: String,
    /// Registry API secret (Basic auth).
    pub api_secret: String,
    /// Registered schema id framed ahead of every value.
    pub schema_id: u32,
}

fn default_batch_size() -> Option<usize> {
    Some(500)
}

fn default_partitions() -> u32 {
    12
}

/// Confluent Cloud Kafka sink configuration. Every depth is
/// user-configurable with no clamped ceiling (`None` = unbounded).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfluentKafkaConfig {
    /// Confluent Cloud broker endpoints, e.g.
    /// `["pkc-xxxx.us-east-1.aws.confluent.cloud:9092"]`.
    pub bootstrap_servers: Vec<String>,
    /// Confluent Cloud API key (SASL username).
    pub api_key: String,
    /// Confluent Cloud API secret (SASL password).
    pub api_secret: String,
    /// SASL mechanism (default PLAIN).
    #[serde(default)]
    pub auth_mechanism: SaslMechanism,
    /// Destination topic template, e.g. `telemetry-${topic_segment_1}`.
    pub topic_template: String,
    /// Message key derivation template (default none = null keys).
    #[serde(default)]
    pub partition_key_template: Option<String>,
    /// Optional Schema Registry framing.
    #[serde(default)]
    pub schema_registry: Option<ConfluentSchemaRegistryConfig>,
    /// Partition count for murmur2 routing (default 12).
    #[serde(default = "default_partitions")]
    pub partitions: u32,
    /// Flush trigger record count (default 500).
    #[serde(default = "default_batch_size")]
    pub batch_size: Option<usize>,
    /// Buffer capacity (`None` = unbounded).
    #[serde(default)]
    pub buffer_capacity: Option<usize>,
    /// Network request / connect timeout in ms (default 5000).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

impl ConfluentKafkaConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.unwrap_or(5000).max(1))
    }

    pub fn validate(&self) -> Result<()> {
        if self.bootstrap_servers.is_empty()
            || self.bootstrap_servers.iter().any(|s| s.trim().is_empty())
        {
            return Err(ConnectorError::Dispatch(
                "confluent bootstrap_servers must not be empty".to_string(),
            ));
        }
        if self.api_key.trim().is_empty() || self.api_secret.is_empty() {
            return Err(ConnectorError::Dispatch(
                "confluent api_key/api_secret must not be empty".to_string(),
            ));
        }
        if self.topic_template.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "confluent topic_template must not be empty".to_string(),
            ));
        }
        // Strict template check with dummy values (segments 1..=4).
        resolve_topic(&self.topic_template, "dummy/seg2/seg3")?;
        if let Some(template) = &self.partition_key_template {
            resolve_key(
                template,
                "dummy/seg2",
                "dummy-client",
                &serde_json::json!({}),
            )?;
        }
        if let Some(registry) = &self.schema_registry {
            if !registry.endpoint.starts_with("http://")
                && !registry.endpoint.starts_with("https://")
            {
                return Err(ConnectorError::Dispatch(format!(
                    "confluent schema registry endpoint must be http(s): {:?}",
                    registry.endpoint
                )));
            }
            if registry.api_key.trim().is_empty() || registry.api_secret.is_empty() {
                return Err(ConnectorError::Dispatch(
                    "confluent schema registry api_key/api_secret must not be empty".to_string(),
                ));
            }
        }
        if self.partitions == 0 {
            return Err(ConnectorError::Dispatch(
                "confluent partitions must be >= 1".to_string(),
            ));
        }
        if self.batch_size == Some(0) {
            return Err(ConnectorError::Dispatch(
                "confluent batch_size must be >= 1".to_string(),
            ));
        }
        Ok(())
    }

    pub(crate) fn effective_batch_size(&self) -> usize {
        self.batch_size.unwrap_or(usize::MAX)
    }

    pub(crate) fn effective_buffer(&self) -> usize {
        self.buffer_capacity.unwrap_or(usize::MAX)
    }
}

// ---------------------------------------------------------------------------
// Topic / key templates.
// ---------------------------------------------------------------------------

/// Template variables for one event: `${topic}`, `${topic_segment_N}`
/// (1-based MQTT levels), `${client_id}` and `${payload.<dotted>}`.
/// Unknown variables are dispatch errors (strict, like the shared
/// renderer).
fn template_vars(topic: &str, client_id: &str) -> Vec<(String, String)> {
    let mut vars = vec![
        ("topic".to_string(), topic.to_string()),
        ("client_id".to_string(), client_id.to_string()),
    ];
    for (index, segment) in topic.split('/').enumerate() {
        vars.push((format!("topic_segment_{}", index + 1), segment.to_string()));
    }
    vars
}

fn payload_leaf(payload: &serde_json::Value, path: &str) -> Option<String> {
    let mut current = payload;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    match current {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Render a template with the event variables plus payload leaves.
/// Implemented on top of manual scanning so `${payload.*}` leaves
/// resolve without polluting the strict shared renderer.
pub fn resolve_template(
    template: &str,
    topic: &str,
    client_id: &str,
    payload: &serde_json::Value,
) -> Result<String> {
    let vars = template_vars(topic, client_id);
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
            let value = if let Some(leaf) = name.strip_prefix("payload.") {
                payload_leaf(payload, leaf)
            } else {
                vars.iter()
                    .find(|(key, _)| key == name)
                    .map(|(_, v)| v.clone())
            };
            match value {
                Some(value) => out.push_str(&value),
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

/// Render the destination topic for one event.
pub fn resolve_topic(template: &str, topic: &str) -> Result<String> {
    let rendered = resolve_template(template, topic, "", &serde_json::Value::Null)?;
    if rendered.trim().is_empty() {
        return Err(ConnectorError::Dispatch(
            "confluent topic_template rendered empty".to_string(),
        ));
    }
    Ok(rendered)
}

/// Derive the message key for one event (`None` = null key).
pub fn resolve_key(
    template: &str,
    topic: &str,
    client_id: &str,
    payload: &serde_json::Value,
) -> Result<Option<Vec<u8>>> {
    let rendered = resolve_template(template, topic, client_id, payload)?;
    if rendered.is_empty() {
        Ok(None)
    } else {
        Ok(Some(rendered.into_bytes()))
    }
}

// ---------------------------------------------------------------------------
// Schema Registry wire format + auth.
// ---------------------------------------------------------------------------

/// Confluent Schema Registry wire framing: magic `0x00`, big-endian
/// schema id, then the payload body.
pub fn frame_schema_registry(schema_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(0x00);
    out.extend_from_slice(&schema_id.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Split a framed value back into (schema_id, body).
pub fn split_schema_registry(frame: &[u8]) -> Result<(u32, &[u8])> {
    if frame.len() < 5 {
        return Err(ConnectorError::Dispatch(
            "confluent frame shorter than the 5-byte prefix".to_string(),
        ));
    }
    if frame[0] != 0x00 {
        return Err(ConnectorError::Dispatch(format!(
            "confluent frame has bad magic byte {:#04x}",
            frame[0]
        )));
    }
    Ok((
        u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]),
        &frame[5..],
    ))
}

/// `Authorization: Basic {Base64(api_key:api_secret)}` for the Schema
/// Registry client.
pub fn schema_registry_basic_auth(api_key: &str, api_secret: &str) -> String {
    use base64::Engine;
    let credentials = format!("{api_key}:{api_secret}");
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes())
    )
}

/// SASL/PLAIN client payload: `\0{api_key}\0{api_secret}`.
pub fn sasl_plain_payload(api_key: &str, api_secret: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(api_key.len() + api_secret.len() + 2);
    out.push(0x00);
    out.extend_from_slice(api_key.as_bytes());
    out.push(0x00);
    out.extend_from_slice(api_secret.as_bytes());
    out
}

// ---------------------------------------------------------------------------
// SCRAM-SHA-256 / SCRAM-SHA-512 client (RFC 5802, clean-room).
// ---------------------------------------------------------------------------

/// SCRAM hash function selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScramHash {
    Sha256,
    Sha512,
}

fn hmac_with(hash: ScramHash, key: &[u8], message: &[u8]) -> Vec<u8> {
    match hash {
        ScramHash::Sha256 => super::hmac_sha256(key, message),
        ScramHash::Sha512 => {
            const BLOCK: usize = 128;
            let mut key_block = [0u8; BLOCK];
            if key.len() > BLOCK {
                let digest = sha2::Sha512::digest(key);
                key_block[..digest.len()].copy_from_slice(&digest);
            } else {
                key_block[..key.len()].copy_from_slice(key);
            }
            let mut ipad = [0x36u8; BLOCK];
            let mut opad = [0x5cu8; BLOCK];
            for i in 0..BLOCK {
                ipad[i] ^= key_block[i];
                opad[i] ^= key_block[i];
            }
            use sha2::Digest;
            let mut inner = sha2::Sha512::new();
            inner.update(ipad);
            inner.update(message);
            let inner_digest = inner.finalize();
            let mut outer = sha2::Sha512::new();
            outer.update(opad);
            outer.update(inner_digest);
            outer.finalize().to_vec()
        }
    }
}

fn hash_with(hash: ScramHash, data: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    match hash {
        ScramHash::Sha256 => sha2::Sha256::digest(data).to_vec(),
        ScramHash::Sha512 => sha2::Sha512::digest(data).to_vec(),
    }
}

/// PBKDF2 `Hi` (RFC 5802 §2.2): `U1 ^ U2 ^ ... ^ Ui`.
pub fn scram_hi(hash: ScramHash, password: &[u8], salt: &[u8], iterations: u32) -> Result<Vec<u8>> {
    if iterations == 0 {
        return Err(ConnectorError::Dispatch(
            "confluent scram iterations must be >= 1".to_string(),
        ));
    }
    let mut block = Vec::with_capacity(salt.len() + 4);
    block.extend_from_slice(salt);
    block.extend_from_slice(&1u32.to_be_bytes());
    let mut u = hmac_with(hash, password, &block);
    let mut hi = u.clone();
    for _ in 1..iterations {
        u = hmac_with(hash, password, &u);
        for (h, b) in hi.iter_mut().zip(u.iter()) {
            *h ^= *b;
        }
    }
    Ok(hi)
}

/// `n,,n={username},r={nonce}` (gs2 header `n,,` = no channel binding).
pub fn scram_client_first_message(username: &str, nonce: &str) -> String {
    format!("n,,n={username},r={nonce}")
}

/// Generate a printable SASL nonce (18 random bytes, base64).
pub fn scram_nonce() -> String {
    use base64::Engine;
    use rand::RngCore;
    let mut bytes = [0u8; 18];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Parsed SCRAM server-first message (`r=...,s=...,i=...`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScramServerFirst {
    pub nonce: String,
    pub salt_b64: String,
    pub iterations: u32,
}

pub fn parse_scram_server_first(message: &str) -> Result<ScramServerFirst> {
    let mut nonce = None;
    let mut salt_b64 = None;
    let mut iterations = None;
    for part in message.split(',') {
        if let Some(value) = part.strip_prefix("r=") {
            nonce = Some(value.to_string());
        } else if let Some(value) = part.strip_prefix("s=") {
            salt_b64 = Some(value.to_string());
        } else if let Some(value) = part.strip_prefix("i=") {
            iterations = Some(value.parse::<u32>().map_err(|_| {
                ConnectorError::Dispatch(format!(
                    "confluent scram server-first has a bad iteration count: {message:?}"
                ))
            })?);
        }
    }
    match (nonce, salt_b64, iterations) {
        (Some(nonce), Some(salt_b64), Some(iterations)) => Ok(ScramServerFirst {
            nonce,
            salt_b64,
            iterations,
        }),
        _ => Err(ConnectorError::Dispatch(format!(
            "confluent scram server-first is malformed: {message:?}"
        ))),
    }
}

/// Compute the base64 client proof for the full SCRAM `AuthMessage`
/// (`client-first-bare,server-first,client-final-without-proof`).
pub fn scram_client_proof(
    hash: ScramHash,
    password: &[u8],
    salt_b64: &str,
    iterations: u32,
    auth_message: &[u8],
) -> Result<String> {
    use base64::Engine;
    let salt = base64::engine::general_purpose::STANDARD
        .decode(salt_b64)
        .map_err(|e| {
            ConnectorError::Dispatch(format!("confluent scram salt is not base64: {e}"))
        })?;
    let salted = scram_hi(hash, password, &salt, iterations)?;
    let client_key = hmac_with(hash, &salted, b"Client Key");
    let stored_key = hash_with(hash, &client_key);
    let signature = hmac_with(hash, &stored_key, auth_message);
    let proof: Vec<u8> = client_key
        .iter()
        .zip(signature.iter())
        .map(|(a, b)| a ^ b)
        .collect();
    Ok(base64::engine::general_purpose::STANDARD.encode(proof))
}

/// Expected base64 server signature (`v=...`) for mutual
/// authentication of the server-final message.
pub fn scram_server_signature(
    hash: ScramHash,
    password: &[u8],
    salt_b64: &str,
    iterations: u32,
    auth_message: &[u8],
) -> Result<String> {
    use base64::Engine;
    let salt = base64::engine::general_purpose::STANDARD
        .decode(salt_b64)
        .map_err(|e| {
            ConnectorError::Dispatch(format!("confluent scram salt is not base64: {e}"))
        })?;
    let salted = scram_hi(hash, password, &salt, iterations)?;
    let server_key = hmac_with(hash, &salted, b"Server Key");
    Ok(
        base64::engine::general_purpose::STANDARD.encode(hmac_with(
            hash,
            &server_key,
            auth_message,
        )),
    )
}

// ---------------------------------------------------------------------------
// Produce error classification.
// ---------------------------------------------------------------------------

/// Classified Produce partition error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfluentOutcome {
    Success,
    Retryable,
    Terminal,
}

/// `SASL_AUTHENTICATION_FAILED` (58) is terminal; `REQUEST_TIMED_OUT`
/// (7) and `NOT_ENOUGH_REPLICAS` (19) are retryable with backoff;
/// unknown codes retry conservatively (terminal is reserved for
/// authentication: retries with backoff never corrupt data).
pub fn classify_kafka_error(code: i16) -> ConfluentOutcome {
    match code {
        0 => ConfluentOutcome::Success,
        58 => ConfluentOutcome::Terminal,
        7 | 19 => ConfluentOutcome::Retryable,
        _ => ConfluentOutcome::Retryable,
    }
}

// ---------------------------------------------------------------------------
// Transport.
// ---------------------------------------------------------------------------

/// One produced record: topic, partition, key, framed value, headers.
#[derive(Debug, Clone)]
pub struct ConfluentRecord {
    pub topic: String,
    pub partition: i32,
    pub key: Option<Bytes>,
    pub value: Bytes,
    pub headers: Vec<(String, Bytes)>,
}

#[async_trait]
pub trait ConfluentTransport: Send + Sync {
    async fn publish(&self, records: &[ConfluentRecord]) -> Result<()>;
}

/// In-memory transport recording every flushed batch (tests, dry runs).
#[derive(Debug, Default)]
pub struct MemoryConfluentTransport {
    batches: parking_lot::Mutex<Vec<Vec<ConfluentRecord>>>,
    failures_left: parking_lot::Mutex<usize>,
    calls: AtomicU64,
}

impl MemoryConfluentTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fail the next `n` publishes with a transport error (backoff tests).
    pub fn fail_next(&self, n: usize) {
        *self.failures_left.lock() = n;
    }

    pub fn batches(&self) -> Vec<Vec<ConfluentRecord>> {
        self.batches.lock().clone()
    }

    pub fn records_flat(&self) -> Vec<ConfluentRecord> {
        self.batches.lock().iter().flatten().cloned().collect()
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ConfluentTransport for MemoryConfluentTransport {
    async fn publish(&self, records: &[ConfluentRecord]) -> Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut failures = self.failures_left.lock();
        if *failures > 0 {
            *failures -= 1;
            return Err(ConnectorError::Connection(
                "mock confluent down".to_string(),
            ));
        }
        self.batches.lock().push(records.to_vec());
        Ok(())
    }
}

/// TCP transport: SASL handshake (PLAIN or full SCRAM conversation)
/// after the ApiVersions probe, then Produce v3 with RecordBatch-v2.
/// One in-flight exchange at a time; dropped connections redial once.
pub struct TcpConfluentTransport {
    endpoint: String,
    client_id: String,
    acks: i16,
    mechanism: SaslMechanism,
    username: String,
    password: String,
    timeout: Duration,
    conn: AsyncMutex<Option<TcpConfluentConn>>,
}

struct TcpConfluentConn {
    stream: TcpStream,
    correlation: i32,
}

impl TcpConfluentTransport {
    pub fn new(config: &ConfluentKafkaConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            endpoint: config.bootstrap_servers[0].clone(),
            client_id: format!("indra-confluent-{}", config.api_key),
            acks: parse_acks("all")?,
            mechanism: config.auth_mechanism,
            username: config.api_key.clone(),
            password: config.api_secret.clone(),
            timeout: config.timeout(),
            conn: AsyncMutex::new(None),
        })
    }

    async fn roundtrip(&self, api_key: i16, api_version: i16, body: Vec<u8>) -> Result<Vec<u8>> {
        let mut guard = self.conn.lock().await;
        for attempt in 0..2 {
            if guard.is_none() {
                *guard = Some(self.dial().await?);
            }
            let conn = guard.as_mut().expect("connected");
            let correlation = conn.correlation;
            conn.correlation = conn.correlation.wrapping_add(1);
            let mut frame =
                encode_request_header(api_key, api_version, correlation, &self.client_id);
            frame.extend_from_slice(&body);
            let exchange = async {
                send_frame(&mut conn.stream, frame).await?;
                read_response(&mut conn.stream).await
            };
            match tokio::time::timeout(self.timeout, exchange).await {
                Ok(Ok(mut response)) => {
                    if response.len() < 4 {
                        *guard = None;
                        if attempt == 0 {
                            continue;
                        }
                        return Err(ConnectorError::Connection(
                            "truncated confluent response".to_string(),
                        ));
                    }
                    let echoed =
                        i32::from_be_bytes([response[0], response[1], response[2], response[3]]);
                    if echoed != correlation {
                        *guard = None;
                        if attempt == 0 {
                            continue;
                        }
                        return Err(ConnectorError::Connection(format!(
                            "confluent correlation mismatch: {echoed} != {correlation}"
                        )));
                    }
                    response.drain(..4);
                    return Ok(response);
                }
                Ok(Err(_)) | Err(_) if attempt == 0 => {
                    *guard = None;
                    continue;
                }
                Ok(Err(e)) => {
                    *guard = None;
                    return Err(e);
                }
                Err(_) => {
                    *guard = None;
                    return Err(ConnectorError::Connection(
                        "confluent exchange timed out".to_string(),
                    ));
                }
            }
        }
        Err(ConnectorError::Connection(
            "confluent exchange failed".to_string(),
        ))
    }

    async fn dial(&self) -> Result<TcpConfluentConn> {
        let stream =
            tokio::time::timeout(self.timeout, TcpStream::connect(&self.endpoint))
                .await
                .map_err(|_| {
                    ConnectorError::Connection(format!(
                        "confluent connect timeout: {}",
                        self.endpoint
                    ))
                })?
                .map_err(|e| {
                    ConnectorError::Connection(format!(
                        "confluent connect to {} failed: {e}",
                        self.endpoint
                    ))
                })?;
        let mut conn = TcpConfluentConn {
            stream,
            correlation: 1,
        };
        // Prove framing before authenticating.
        let frame = encode_api_versions_request(0, &self.client_id);
        send_frame(&mut conn.stream, frame).await?;
        let response = read_response(&mut conn.stream).await?;
        decode_api_versions_response(&response, 0)?;
        self.sasl_authenticate(&mut conn).await?;
        conn.correlation = 1;
        Ok(conn)
    }

    async fn sasl_authenticate(&self, conn: &mut TcpConfluentConn) -> Result<()> {
        // SaslHandshake v1: mechanism STRING.
        let mut body = Vec::new();
        encode_kafka_string(self.mechanism.kafka_name(), &mut body);
        let correlation = conn.correlation;
        conn.correlation = conn.correlation.wrapping_add(1);
        let mut frame = encode_request_header(17, 1, correlation, &self.client_id);
        frame.extend_from_slice(&body);
        send_frame(&mut conn.stream, frame).await?;
        let response = read_response(&mut conn.stream).await?;
        let error = read_response_error(&response, correlation)?;
        if error != 0 {
            return Err(ConnectorError::Dispatch(format!(
                "confluent sasl handshake for {} failed with error {error}",
                self.mechanism.kafka_name()
            )));
        }
        match self.mechanism {
            SaslMechanism::Plain => self
                .sasl_authenticate_bytes(conn, &sasl_plain_payload(&self.username, &self.password))
                .await
                .map(|_| ()),
            SaslMechanism::ScramSha256 => self.scram_conversation(conn, ScramHash::Sha256).await,
            SaslMechanism::ScramSha512 => self.scram_conversation(conn, ScramHash::Sha512).await,
        }
    }

    /// One SaslAuthenticate v1 exchange; returns the server bytes.
    async fn sasl_authenticate_bytes(
        &self,
        conn: &mut TcpConfluentConn,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        body.extend_from_slice(&(payload.len() as i32).to_be_bytes());
        body.extend_from_slice(payload);
        let correlation = conn.correlation;
        conn.correlation = conn.correlation.wrapping_add(1);
        let mut frame = encode_request_header(36, 1, correlation, &self.client_id);
        frame.extend_from_slice(&body);
        send_frame(&mut conn.stream, frame).await?;
        let response = read_response(&mut conn.stream).await?;
        let error = read_response_error(&response, correlation)?;
        if error != 0 {
            let code = if error == 58 {
                "SASL_AUTHENTICATION_FAILED"
            } else {
                "sasl"
            };
            return Err(ConnectorError::Dispatch(format!(
                "confluent sasl authenticate failed ({code}) with error {error}"
            )));
        }
        // Response: error(2) + message(NULLABLE_STRING) + lifetime(8) +
        // sasl_auth_bytes(BYTES). Skip to the trailing bytes.
        let mut cursor = &response[4..];
        let message_len = read_i16(&mut cursor)?;
        if message_len > 0 {
            if cursor.len() < message_len as usize {
                return Err(ConnectorError::Connection(
                    "truncated confluent sasl response".to_string(),
                ));
            }
            cursor = &cursor[message_len as usize..];
        }
        if cursor.len() < 8 {
            return Err(ConnectorError::Connection(
                "truncated confluent sasl response".to_string(),
            ));
        }
        cursor = &cursor[8..];
        if cursor.len() < 4 {
            return Err(ConnectorError::Connection(
                "truncated confluent sasl response".to_string(),
            ));
        }
        let bytes_len = i32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]);
        if bytes_len < 0 || cursor.len() < 4 + bytes_len as usize {
            return Err(ConnectorError::Connection(
                "truncated confluent sasl response".to_string(),
            ));
        }
        Ok(cursor[4..4 + bytes_len as usize].to_vec())
    }

    /// Full SCRAM client conversation: client-first, server-first
    /// proof, mutual server-signature check.
    async fn scram_conversation(&self, conn: &mut TcpConfluentConn, hash: ScramHash) -> Result<()> {
        let nonce = scram_nonce();
        let client_first_bare = format!("n={},r={}", self.username, nonce);
        let client_first = format!("n,,{client_first_bare}");
        let server_first = String::from_utf8(
            self.sasl_authenticate_bytes(conn, client_first.as_bytes())
                .await?,
        )
        .map_err(|_| {
            ConnectorError::Connection("confluent scram server-first is not UTF-8".to_string())
        })?;
        let parsed = parse_scram_server_first(&server_first)?;
        if !parsed.nonce.starts_with(&nonce) {
            return Err(ConnectorError::Dispatch(
                "confluent scram server nonce does not extend the client nonce".to_string(),
            ));
        }
        let client_final_wo = format!("c=biws,r={}", parsed.nonce);
        let auth_message = format!("{client_first_bare},{server_first},{client_final_wo}");
        let proof = scram_client_proof(
            hash,
            self.password.as_bytes(),
            &parsed.salt_b64,
            parsed.iterations,
            auth_message.as_bytes(),
        )?;
        let client_final = format!("{client_final_wo},p={proof}");
        let server_final = String::from_utf8(
            self.sasl_authenticate_bytes(conn, client_final.as_bytes())
                .await?,
        )
        .map_err(|_| {
            ConnectorError::Connection("confluent scram server-final is not UTF-8".to_string())
        })?;
        let signature = server_final.strip_prefix("v=").ok_or_else(|| {
            ConnectorError::Dispatch(format!(
                "confluent scram server-final is malformed: {server_final:?}"
            ))
        })?;
        let expected = scram_server_signature(
            hash,
            self.password.as_bytes(),
            &parsed.salt_b64,
            parsed.iterations,
            auth_message.as_bytes(),
        )?;
        if signature != expected {
            return Err(ConnectorError::Dispatch(
                "confluent scram server signature mismatch".to_string(),
            ));
        }
        Ok(())
    }

    async fn produce_grouped(
        &self,
        grouped: &BTreeMap<(String, i32), Vec<KafkaRecord>>,
    ) -> Result<()> {
        if grouped.is_empty() {
            return Ok(());
        }
        let framed = encode_produce_request(0, &self.client_id, self.acks, grouped);
        // encode_produce_request frames header+body; the shared
        // roundtrip re-adds its own header, so strip to the body.
        let header_len = 2 + 2 + 4 + 2 + self.client_id.len();
        let body = framed[header_len..].to_vec();
        let response = self.roundtrip(0, 3, body).await?;
        let mut cursor = response.as_slice();
        let topics = read_i32(&mut cursor)?;
        for _ in 0..topics {
            let name_len = read_i16(&mut cursor)? as usize;
            if cursor.len() < name_len {
                return Err(ConnectorError::Connection(
                    "truncated confluent produce response".to_string(),
                ));
            }
            let name = String::from_utf8_lossy(&cursor[..name_len]).to_string();
            cursor = &cursor[name_len..];
            let partitions = read_i32(&mut cursor)?;
            for _ in 0..partitions {
                let index = read_i32(&mut cursor)?;
                let error = read_i16(&mut cursor)?;
                match classify_kafka_error(error) {
                    ConfluentOutcome::Success => {}
                    ConfluentOutcome::Retryable => {
                        return Err(ConnectorError::Connection(format!(
                            "confluent produce to {name}[{index}] failed retryably with error {error}"
                        )))
                    }
                    ConfluentOutcome::Terminal => {
                        return Err(ConnectorError::Dispatch(format!(
                            "confluent produce to {name}[{index}] failed terminally with error {error}"
                        )))
                    }
                }
                if cursor.len() < 8 + 8 + 8 + 4 {
                    return Err(ConnectorError::Connection(
                        "truncated confluent produce response".to_string(),
                    ));
                }
                cursor = &cursor[8 + 8 + 8 + 4..];
            }
        }
        Ok(())
    }
}

fn encode_kafka_string(s: &str, out: &mut Vec<u8>) {
    out.extend_from_slice(&(s.len() as i16).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn read_i16(cursor: &mut &[u8]) -> Result<i16> {
    if cursor.len() < 2 {
        return Err(ConnectorError::Connection(
            "truncated confluent response".to_string(),
        ));
    }
    let value = i16::from_be_bytes([cursor[0], cursor[1]]);
    *cursor = &cursor[2..];
    Ok(value)
}

fn read_i32(cursor: &mut &[u8]) -> Result<i32> {
    if cursor.len() < 4 {
        return Err(ConnectorError::Connection(
            "truncated confluent response".to_string(),
        ));
    }
    let value = i32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]);
    *cursor = &cursor[4..];
    Ok(value)
}

/// Check the echoed correlation and return the error code that opens
/// SaslHandshake / SaslAuthenticate v1 responses.
fn read_response_error(response: &[u8], correlation: i32) -> Result<i16> {
    if response.len() < 6 {
        return Err(ConnectorError::Connection(
            "truncated confluent sasl response".to_string(),
        ));
    }
    let echoed = i32::from_be_bytes([response[0], response[1], response[2], response[3]]);
    if echoed != correlation {
        return Err(ConnectorError::Connection(format!(
            "confluent correlation mismatch: {echoed} != {correlation}"
        )));
    }
    Ok(i16::from_be_bytes([response[4], response[5]]))
}

#[async_trait]
impl ConfluentTransport for TcpConfluentTransport {
    async fn publish(&self, records: &[ConfluentRecord]) -> Result<()> {
        let mut grouped: BTreeMap<(String, i32), Vec<KafkaRecord>> = BTreeMap::new();
        for record in records {
            grouped
                .entry((record.topic.clone(), record.partition))
                .or_default()
                .push(KafkaRecord {
                    topic: record.topic.clone(),
                    partition: record.partition,
                    key: record.key.clone(),
                    value: record.value.clone(),
                    headers: record.headers.clone(),
                    timestamp_ms: super::now_millis(),
                });
        }
        self.produce_grouped(&grouped).await
    }
}

// ---------------------------------------------------------------------------
// Sink.
// ---------------------------------------------------------------------------

struct ConfluentBuffer {
    records: Vec<ConfluentRecord>,
    bytes: usize,
}

/// Confluent Cloud sink: renders topics/keys, frames Schema Registry
/// values, batches records and dispatches through the transport with
/// restore-on-retryable-failure and backoff.
pub struct ConfluentKafkaSink {
    config: ConfluentKafkaConfig,
    transport: Arc<dyn ConfluentTransport>,
    buffer: parking_lot::Mutex<ConfluentBuffer>,
    backoff: parking_lot::Mutex<BackoffState>,
    sent_batches: AtomicU64,
    sent_records: AtomicU64,
}

impl ConfluentKafkaSink {
    pub fn new(
        config: ConfluentKafkaConfig,
        transport: Arc<dyn ConfluentTransport>,
    ) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            transport,
            buffer: parking_lot::Mutex::new(ConfluentBuffer {
                records: Vec::new(),
                bytes: 0,
            }),
            backoff: parking_lot::Mutex::new(BackoffState::default()),
            sent_batches: AtomicU64::new(0),
            sent_records: AtomicU64::new(0),
        })
    }

    pub fn config(&self) -> &ConfluentKafkaConfig {
        &self.config
    }

    pub fn sent_batches(&self) -> u64 {
        self.sent_batches.load(Ordering::Relaxed)
    }

    pub fn sent_records(&self) -> u64 {
        self.sent_records.load(Ordering::Relaxed)
    }

    pub fn buffered_records(&self) -> usize {
        self.buffer.lock().records.len()
    }

    fn build_record(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<ConfluentRecord> {
        let parsed: serde_json::Value =
            serde_json::from_slice(payload).unwrap_or(serde_json::Value::Null);
        let client_id = parsed
            .get("client_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let rendered_topic = resolve_topic(&self.config.topic_template, topic.as_str())?;
        let key = match &self.config.partition_key_template {
            Some(template) => {
                resolve_key(template, topic.as_str(), client_id, &parsed)?.map(Bytes::from)
            }
            None => None,
        };
        let mut value = payload.clone();
        if let Some(registry) = &self.config.schema_registry {
            value = Bytes::from(frame_schema_registry(registry.schema_id, payload));
        }
        let partition = super::kafka::partition_for_key(key.as_deref(), self.config.partitions);
        Ok(ConfluentRecord {
            topic: rendered_topic,
            partition,
            key,
            value,
            headers: vec![
                (
                    "mqtt.topic".to_string(),
                    Bytes::from(topic.as_str().to_string()),
                ),
                (
                    "mqtt.qos".to_string(),
                    Bytes::from(u8::from(qos).to_string()),
                ),
                (
                    "mqtt.timestamp".to_string(),
                    Bytes::from(now_millis().to_string()),
                ),
            ],
        })
    }

    /// Flush buffered records (no-op when empty). Retryable failures
    /// restore the batch at the front, engage backoff and propagate.
    pub async fn flush(&self) -> Result<()> {
        self.backoff.lock().check()?;
        let batch = {
            let mut buffer = self.buffer.lock();
            buffer.bytes = 0;
            std::mem::take(&mut buffer.records)
        };
        if batch.is_empty() {
            return Ok(());
        }
        let count = batch.len() as u64;
        match self.transport.publish(&batch).await {
            Ok(()) => {
                self.backoff.lock().success();
                self.sent_batches.fetch_add(1, Ordering::Relaxed);
                self.sent_records.fetch_add(count, Ordering::Relaxed);
                Ok(())
            }
            Err(ConnectorError::Connection(message)) => {
                // Restore the failed batch at the front, preserving
                // order, and engage backoff.
                let mut buffer = self.buffer.lock();
                let mut restored = batch;
                restored.append(&mut buffer.records);
                buffer.records = restored;
                buffer.bytes = buffer
                    .records
                    .iter()
                    .map(|r| r.value.len() + r.key.as_ref().map(|k| k.len()).unwrap_or(0))
                    .sum();
                self.backoff.lock().failure();
                Err(ConnectorError::Connection(message))
            }
            Err(e) => {
                self.backoff.lock().failure();
                Err(e)
            }
        }
    }

    /// Buffer one event. Returns true when the batch is full (caller
    /// flushes).
    fn buffer_row(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<bool> {
        if topic.as_str().is_empty() {
            return Err(ConnectorError::Dispatch(
                "confluent row requires a non-empty topic".to_string(),
            ));
        }
        if self.buffer.lock().records.len() >= self.config.effective_buffer() {
            return Err(ConnectorError::Connection(
                "confluent buffer limit reached".to_string(),
            ));
        }
        let record = self.build_record(topic, payload, qos)?;
        let mut buffer = self.buffer.lock();
        buffer.bytes += record.value.len() + record.key.as_ref().map(|k| k.len()).unwrap_or(0);
        buffer.records.push(record);
        Ok(buffer.records.len() >= self.config.effective_batch_size())
    }
}

#[async_trait]
impl Sink for ConfluentKafkaSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        if self.buffer_row(topic, payload, qos)? {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "confluent"
    }
}

/// Management connector handle pairing an id with a Confluent sink.
pub struct ConfluentKafkaConnector {
    id: String,
    sink: Arc<ConfluentKafkaSink>,
}

impl ConfluentKafkaConnector {
    pub fn new(id: impl Into<String>, sink: Arc<ConfluentKafkaSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }
}

impl super::Connector for ConfluentKafkaConnector {
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn test_config() -> ConfluentKafkaConfig {
        ConfluentKafkaConfig {
            bootstrap_servers: vec!["pkc-test.us-east-1.aws.confluent.cloud:9092".to_string()],
            api_key: "confluent-key".to_string(),
            api_secret: "confluent-secret".to_string(),
            auth_mechanism: SaslMechanism::Plain,
            topic_template: "telemetry-${topic_segment_1}".to_string(),
            partition_key_template: Some("${client_id}".to_string()),
            schema_registry: Some(ConfluentSchemaRegistryConfig {
                endpoint: "https://psrc-test.us-east-1.aws.confluent.cloud".to_string(),
                api_key: "registry-key".to_string(),
                api_secret: "registry-secret".to_string(),
                schema_id: 1001,
            }),
            partitions: 12,
            batch_size: Some(500),
            buffer_capacity: None,
            timeout_ms: None,
        }
    }

    #[test]
    fn test_config_validation() {
        let mut config = test_config();
        assert!(config.validate().is_ok());

        config.bootstrap_servers.clear();
        assert!(config.validate().is_err());
        config.bootstrap_servers = vec!["  ".to_string()];
        assert!(config.validate().is_err());
        config.bootstrap_servers = test_config().bootstrap_servers;

        config.topic_template = "t-${nope}".to_string();
        assert!(config.validate().is_err());
        config.topic_template = "t-${topic".to_string();
        assert!(config.validate().is_err());
        config.topic_template = test_config().topic_template;

        config.partitions = 0;
        assert!(config.validate().is_err());
        config.partitions = 12;

        config.batch_size = Some(0);
        assert!(config.validate().is_err());
        config.batch_size = Some(10_000_000);

        config.schema_registry.as_mut().unwrap().endpoint = "psrc-test".to_string();
        assert!(config.validate().is_err());

        // Zero clamped ceilings: huge depths are accepted.
        assert!(test_config().validate().is_ok());
    }

    #[test]
    fn test_wire_format_prefix() {
        let framed = frame_schema_registry(1001, b"hello");
        assert_eq!(&framed[..5], &[0x00, 0x00, 0x00, 0x03, 0xE9]);
        assert_eq!(&framed[5..], b"hello");
        let (id, body) = split_schema_registry(&framed).unwrap();
        assert_eq!(id, 1001);
        assert_eq!(body, b"hello");
        assert!(split_schema_registry(&[0x00, 0x01]).is_err());
        assert!(split_schema_registry(&[0x01, 0x00, 0x00, 0x00, 0x01]).is_err());
    }

    #[test]
    fn test_sasl_plain_payload() {
        assert_eq!(
            sasl_plain_payload("confluent-key", "confluent-secret"),
            b"\0confluent-key\0confluent-secret".to_vec()
        );
    }

    #[test]
    fn test_scram_sha256_exchange_vector() {
        // Full SCRAM exchange shape (client-first, server-first with
        // salt/iterations, channel-binding `biws`): the proof and the
        // mutual server signature below are the independent Python
        // (hashlib.pbkdf2_hmac/hmac) values for password "pencil".
        let client_first = scram_client_first_message("user", "fyko+d2lbbFgONRv9qkxdawU");
        assert_eq!(client_first, "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawU");
        let server_first = "r=fyko+d2lbbFgONRv9qkxdawU3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096";
        let parsed = parse_scram_server_first(server_first).unwrap();
        assert_eq!(parsed.iterations, 4096);
        let client_final_wo = "c=biws,r=fyko+d2lbbFgONRv9qkxdawU3rfcNHYJY1ZVvWVs7j";
        let auth_message =
            format!("n=user,r=fyko+d2lbbFgONRv9qkxdawU,{server_first},{client_final_wo}");
        let proof = scram_client_proof(
            ScramHash::Sha256,
            b"pencil",
            "QSXCR+Q6sek8bf92",
            4096,
            auth_message.as_bytes(),
        )
        .unwrap();
        assert_eq!(proof, "3uDt9BgJfPo0D/HJXhOiKkpNRc9C404y+qtd4VAsjqk=");
        // Mutual auth: the server signature verifies.
        let server_sig = scram_server_signature(
            ScramHash::Sha256,
            b"pencil",
            "QSXCR+Q6sek8bf92",
            4096,
            auth_message.as_bytes(),
        )
        .unwrap();
        assert_eq!(server_sig, "XUGiWvCdv6rmpBam6tzoioopDmHgyUkUaINh93MRI9c=");
        assert!(parse_scram_server_first("r=only").is_err());
        assert!(scram_hi(ScramHash::Sha256, b"p", &[0u8; 8], 0).is_err());
    }

    #[test]
    fn test_scram_sha512_proof_vector() {
        // Same exchange shape under SHA-512 (independent Python vector).
        let auth_message = "n=user,r=fyko+d2lbbFgONRv9qkxdawU,\
             r=fyko+d2lbbFgONRv9qkxdawU3rfcNHYJY1ZVvWVs7j,\
             s=QSXCR+Q6sek8bf92,i=4096,\
             c=biws,r=fyko+d2lbbFgONRv9qkxdawU3rfcNHYJY1ZVvWVs7j";
        let proof = scram_client_proof(
            ScramHash::Sha512,
            b"pencil",
            "QSXCR+Q6sek8bf92",
            4096,
            auth_message.as_bytes(),
        )
        .unwrap();
        assert_eq!(
            proof,
            "D1Hi1GzCebi+OTXKG+c/MCn91FFkgfRNFSJ1XVu/k4D0Tj98eZKcrtAwRtKlwPWe5LUq2sqinfnb30AhwWSVoQ=="
        );
    }

    #[test]
    fn test_topic_and_key_templates() {
        assert_eq!(
            resolve_topic("telemetry-${topic_segment_1}", "sensors/kitchen").unwrap(),
            "telemetry-sensors"
        );
        assert_eq!(resolve_topic("all-${topic}", "a/b/c").unwrap(), "all-a/b/c");
        assert_eq!(
            resolve_template(
                "k-${topic_segment_3}",
                "a/b/c",
                "",
                &serde_json::Value::Null
            )
            .unwrap(),
            "k-c"
        );
        let payload = serde_json::json!({"client_id": "d7", "device": {"id": "x1"}});
        assert_eq!(
            resolve_template("${client_id}-${payload.device.id}", "t", "d7", &payload).unwrap(),
            "d7-x1"
        );
        assert!(resolve_topic("t-${nope}", "a").is_err());
        assert!(resolve_topic("t-${topic", "a").is_err());
        assert!(resolve_topic("  ", "a").is_err());
        assert_eq!(
            resolve_key("${client_id}", "t", "d7", &payload).unwrap(),
            Some(b"d7".to_vec())
        );
    }

    #[test]
    fn test_schema_registry_basic_auth() {
        use base64::Engine;
        let header = schema_registry_basic_auth("registry-key", "registry-secret");
        let encoded = header.strip_prefix("Basic ").unwrap();
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .unwrap(),
            b"registry-key:registry-secret"
        );
    }

    #[test]
    fn test_error_code_classification() {
        assert_eq!(classify_kafka_error(0), ConfluentOutcome::Success);
        assert_eq!(classify_kafka_error(58), ConfluentOutcome::Terminal);
        assert_eq!(classify_kafka_error(7), ConfluentOutcome::Retryable);
        assert_eq!(classify_kafka_error(19), ConfluentOutcome::Retryable);
    }

    #[tokio::test]
    async fn test_record_batch_framing_and_flow() {
        use super::super::kafka::{encode_record_batch_v2, partition_for_key};

        let transport = Arc::new(MemoryConfluentTransport::new());
        let mut config = test_config();
        config.batch_size = Some(2);
        let sink = ConfluentKafkaSink::new(config, transport.clone()).unwrap();

        let topic = Topic::new("sensors/kitchen").unwrap();
        let payload = Bytes::from_static(br#"{ "client_id": "d7", "v": 1 }"#);
        sink.send(&topic, &payload, QoS::AtMostOnce).await.unwrap();
        sink.send(&topic, &payload, QoS::AtMostOnce).await.unwrap();
        assert_eq!(sink.sent_batches(), 1);
        assert_eq!(sink.sent_records(), 2);

        let records = transport.records_flat();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].topic, "telemetry-sensors");
        assert_eq!(records[0].key, Some(Bytes::from_static(b"d7")));
        assert_eq!(records[0].partition, partition_for_key(Some(b"d7"), 12));
        // Registry framing wraps the raw payload.
        let (id, body) = split_schema_registry(&records[0].value).unwrap();
        assert_eq!(id, 1001);
        assert_eq!(body, payload.as_ref());

        // Shared RecordBatch-v2 framing carries the batch with CRC-32C.
        let kafka_records: Vec<KafkaRecord> = records
            .iter()
            .map(|r| KafkaRecord {
                topic: r.topic.clone(),
                partition: r.partition,
                key: r.key.clone(),
                value: r.value.clone(),
                headers: r.headers.clone(),
                timestamp_ms: r
                    .headers
                    .iter()
                    .find(|(k, _)| k == "mqtt.timestamp")
                    .map(|(_, v)| String::from_utf8_lossy(v).parse::<i64>().unwrap_or(0))
                    .unwrap_or(0),
            })
            .collect();
        let batch = encode_record_batch_v2(&kafka_records);
        assert!(batch.len() > 8 + 4 + 4 + 1 + 4);
        let batch_len = i32::from_be_bytes([batch[8], batch[9], batch[10], batch[11]]) as usize;
        assert_eq!(8 + 4 + batch_len, batch.len());
        assert_eq!(batch[8 + 4 + 4], 2u8, "magic must be 2");

        // Retryable failures propagate as connection errors.
        transport.fail_next(10);
        sink.send(&topic, &payload, QoS::AtMostOnce).await.unwrap();
        sink.flush().await.expect_err("mock down must fail");
    }

    /// Fake Confluent broker: ApiVersions + SASL/PLAIN handshake +
    /// authenticate + Produce v3 over raw TCP, capturing the produce.
    #[tokio::test]
    async fn test_tcp_plain_produce_against_fake_broker() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let captured = Arc::new(parking_lot::Mutex::new(Vec::<u8>::new()));
        let captured_rx = captured.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            // 1) ApiVersions v0 -> success.
            let frame = read_tcp_frame(&mut stream).await;
            assert_eq!(&frame[..6], &[0, 18, 0, 0, 0, 0]);
            write_tcp_frame(&mut stream, &[0, 0, 0, 0, 0, 0, 0, 0]).await;
            // 2) SaslHandshake v1 PLAIN -> success, no mechanisms listed.
            let frame = read_tcp_frame(&mut stream).await;
            assert_eq!(&frame[..4], &[0, 17, 0, 1]);
            let client_len = i16::from_be_bytes([frame[8], frame[9]]) as usize;
            let mechanism = read_kafka_string(&frame[8 + 2 + client_len..]);
            assert_eq!(mechanism, "PLAIN");
            let mut response = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            response[0..4].copy_from_slice(&frame[4..8]);
            write_tcp_frame(&mut stream, &response).await;
            // 3) SaslAuthenticate v1 -> check the PLAIN payload, success.
            let frame = read_tcp_frame(&mut stream).await;
            assert_eq!(&frame[..4], &[0, 36, 0, 1]);
            let client_len = i16::from_be_bytes([frame[8], frame[9]]) as usize;
            let body = &frame[8 + 2 + client_len..];
            let auth_len = i32::from_be_bytes([body[0], body[1], body[2], body[3]]) as usize;
            assert_eq!(&body[4..4 + auth_len], b"\0confluent-key\0confluent-secret");
            let mut response = vec![0u8; 4 + 2 + 2 + 8 + 4];
            response[0..4].copy_from_slice(&frame[4..8]);
            write_tcp_frame(&mut stream, &response).await;
            // 4) Produce v3 -> capture, canned success.
            let frame = read_tcp_frame(&mut stream).await;
            assert_eq!(&frame[..4], &[0, 0, 0, 3]);
            captured_rx.lock().extend_from_slice(&frame);
            let mut response = vec![0, 0, 0, 0];
            response.extend_from_slice(&[0, 0, 0, 1]);
            response.extend_from_slice(&[0, 4]);
            response.extend_from_slice(b"test");
            response.extend_from_slice(&[0, 0, 0, 1]);
            response.extend_from_slice(&[0, 0, 0, 0]);
            response.extend_from_slice(&[0, 0]);
            response.extend_from_slice(&[0u8; 8 + 8 + 8]);
            response.extend_from_slice(&[0, 0, 0, 0]);
            response[0..4].copy_from_slice(&frame[4..8]);
            write_tcp_frame(&mut stream, &response).await;
        });

        let mut config = test_config();
        config.bootstrap_servers = vec![format!("127.0.0.1:{port}")];
        config.batch_size = Some(1);
        let sink = ConfluentKafkaSink::new(
            config,
            Arc::new(TcpConfluentTransport::new(&test_config_with_port(port)).unwrap()),
        )
        .expect("valid sink");

        let topic = Topic::new("sensors/temp").unwrap();
        sink.send(
            &topic,
            &Bytes::from_static(br#"{ "client_id": "d7" }"#),
            QoS::AtMostOnce,
        )
        .await
        .expect("produce over TCP");
        assert_eq!(sink.sent_batches(), 1);

        let mut finished = false;
        for _ in 0..500 {
            if server.is_finished() {
                finished = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(finished, "fake broker never consumed the produce");
        server.await.expect("fake broker task");
        let wire = captured.lock().clone();
        let topic_bytes = b"telemetry-sensors";
        assert!(
            wire.windows(topic_bytes.len()).any(|w| w == topic_bytes),
            "topic on the wire"
        );
        assert!(wire.windows(2).any(|w| w == b"d7"), "key on the wire");
        // Schema-registry magic + id ride inside the record value.
        assert!(
            wire.windows(5)
                .any(|w| *w == [0x00, 0x00, 0x00, 0x03, 0xE9]),
            "registry prefix on the wire"
        );
    }

    fn test_config_with_port(port: u16) -> ConfluentKafkaConfig {
        let mut config = test_config();
        config.bootstrap_servers = vec![format!("127.0.0.1:{port}")];
        config
    }

    async fn read_tcp_frame(stream: &mut TcpStream) -> Vec<u8> {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await.expect("read len");
        let len = i32::from_be_bytes(len_buf) as usize;
        let mut frame = vec![0u8; len];
        stream.read_exact(&mut frame).await.expect("read frame");
        frame
    }

    async fn write_tcp_frame(stream: &mut TcpStream, body: &[u8]) {
        let mut prefixed = (body.len() as i32).to_be_bytes().to_vec();
        prefixed.extend_from_slice(body);
        stream.write_all(&prefixed).await.expect("write frame");
    }

    fn read_kafka_string(frame: &[u8]) -> String {
        let len = i16::from_be_bytes([frame[0], frame[1]]) as usize;
        String::from_utf8_lossy(&frame[2..2 + len]).to_string()
    }
}
