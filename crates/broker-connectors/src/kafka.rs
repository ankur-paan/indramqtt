//! Apache Kafka producer sink.
//!
//! MQTT events become Kafka records: the destination topic renders from
//! `topic_template` (`${topic}`), the partition key extracts from a JSON
//! payload field (Kafka murmur2 partitioning), and MQTT topic, QoS, and
//! timestamp travel as record headers. Records batch in memory and flush
//! on size limits or explicitly.
//!
//! The production write path runs on the maintained `rdkafka` driver
//! ([`RdkafkaKafkaTransport`] below): Kafka Produce protocol (RecordBatch
//! v2 framing, murmur2 partitioning, acks, idempotence where configured)
//! through `FutureProducer` futures. The hand-written
//! [`TcpKafkaTransport`] (Produce/ApiVersions framing over TCP) is
//! retained for offline unit tests only; production wiring uses the
//! driver transport.
//!
//! The [`KafkaTransport`] boundary keeps unit tests broker-free
//! ([`MemoryKafkaTransport`]); [`TcpKafkaTransport`] speaks the legacy
//! framing over TCP.

use super::{BackoffState, ConnectorError, Result, Sink};
use async_trait::async_trait;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::RwLock as AsyncRwLock;

fn default_partitions() -> u32 {
    1
}

fn default_batch_max_records() -> usize {
    500
}

fn default_batch_max_bytes() -> usize {
    256 * 1024
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KafkaSinkConfig {
    pub bootstrap_servers: String,
    pub topic_template: String,
    pub partition_key_field: Option<String>,
    #[serde(default = "default_partitions")]
    pub partitions: u32,
    pub client_id: String,
    pub acks: String,
    #[serde(default = "default_batch_max_records")]
    pub batch_max_records: usize,
    #[serde(default = "default_batch_max_bytes")]
    pub batch_max_bytes: usize,
}

impl KafkaSinkConfig {
    pub fn validate(&self) -> Result<()> {
        if self.bootstrap_servers.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "kafka bootstrap_servers must not be empty".to_string(),
            ));
        }
        if self.topic_template.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "kafka topic_template must not be empty".to_string(),
            ));
        }
        if self.partitions == 0 {
            return Err(ConnectorError::Dispatch(
                "kafka partitions must be >= 1".to_string(),
            ));
        }
        match self.acks.as_str() {
            "all" | "-1" | "1" | "0" => {}
            other => {
                return Err(ConnectorError::Dispatch(format!(
                    "kafka acks must be one of all/-1/1/0, got {other:?}"
                )))
            }
        }
        if self.batch_max_records == 0 || self.batch_max_bytes == 0 {
            return Err(ConnectorError::Dispatch(
                "kafka batch limits must be >= 1".to_string(),
            ));
        }
        Ok(())
    }
}

/// Render `${topic}` placeholders against the MQTT topic. Unknown
/// `${...}` sequences pass through literally, then the whole rendered
/// string is sanitised to a valid Kafka topic name: `/` becomes `.`,
/// every other character outside `[A-Za-z0-9._-]` becomes `_`, the
/// result is truncated to 249 characters, and an empty result or the
/// reserved names `.` and `..` become `indramqtt-invalid-topic`.
pub fn render_topic_template(template: &str, topic: &str) -> String {
    const MAX_TOPIC_LEN: usize = 249;
    const INVALID_TOPIC_FALLBACK: &str = "indramqtt-invalid-topic";
    let rendered = template.replace("${topic}", topic);
    let mut sanitized = String::with_capacity(rendered.len());
    for ch in rendered.chars() {
        if ch == '/' {
            sanitized.push('.');
        } else if ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' || ch == '-' {
            sanitized.push(ch);
        } else {
            sanitized.push('_');
        }
    }
    let truncated: String = sanitized.chars().take(MAX_TOPIC_LEN).collect();
    if truncated.is_empty() || truncated == "." || truncated == ".." {
        INVALID_TOPIC_FALLBACK.to_string()
    } else {
        truncated
    }
}

/// Kafka's murmur2 (seed 0x9747b28c): hash-compatible partitioning with
/// Java producers for the same key bytes.
#[allow(unknown_lints, clippy::chunks_exact_to_as_chunks)]
pub fn murmur2(data: &[u8]) -> u32 {
    const SEED: u32 = 0x9747b28c;
    const M: u32 = 0x5bd1e995;
    const R: u32 = 24;
    let mut h = SEED ^ data.len() as u32;
    let mut chunks = data.chunks_exact(4);
    for chunk in &mut chunks {
        let mut k = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        k = k.wrapping_mul(M);
        k ^= k >> R;
        k = k.wrapping_mul(M);
        h = h.wrapping_mul(M);
        h ^= k;
    }
    match *chunks.remainder() {
        [a, b, c] => {
            h ^= (c as u32) << 16;
            h ^= (b as u32) << 8;
            h ^= a as u32;
            h = h.wrapping_mul(M);
        }
        [a, b] => {
            h ^= (b as u32) << 8;
            h ^= a as u32;
            h = h.wrapping_mul(M);
        }
        [a] => {
            h ^= a as u32;
            h = h.wrapping_mul(M);
        }
        _ => {}
    }
    h ^= h >> 13;
    h = h.wrapping_mul(M);
    h ^= h >> 15;
    h
}

/// Kafka `toPositive(murmur2(key)) % partitions`. Null keys land on
/// partition 0 deterministically (documented; Kafka uses sticky-random,
/// which would defeat test determinism).
pub fn partition_for_key(key: Option<&[u8]>, partitions: u32) -> i32 {
    assert!(partitions >= 1, "partitions must be >= 1");
    match key {
        Some(key) => ((murmur2(key) & 0x7fffffff) % partitions) as i32,
        None => 0,
    }
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// One Kafka record ready for a v2 batch.
#[derive(Debug, Clone)]
pub struct KafkaRecord {
    pub topic: String,
    pub partition: i32,
    pub key: Option<Bytes>,
    pub value: Bytes,
    pub headers: Vec<(String, Bytes)>,
    pub timestamp_ms: i64,
}

// ---------------------------------------------------------------------------
// RecordBatch v2 binary encoding (KIP-32 layout).
// ---------------------------------------------------------------------------

fn encode_unsigned_varint(mut value: u64, out: &mut Vec<u8>) {
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

fn encode_zigzag_i64(value: i64, out: &mut Vec<u8>) {
    encode_unsigned_varint(((value << 1) ^ (value >> 63)) as u64, out);
}

fn encode_varbytes(data: Option<&[u8]>, out: &mut Vec<u8>) {
    match data {
        Some(bytes) => {
            encode_unsigned_varint(bytes.len() as u64, out);
            out.extend_from_slice(bytes);
        }
        None => out.push(0x01), // zigzag(-1)
    }
}

fn crc32c_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    for i in 0..256 {
        let mut crc = i as u32;
        for _ in 0..8 {
            if crc & 1 == 1 {
                crc = (crc >> 1) ^ 0x1EDC6F41;
            } else {
                crc >>= 1;
            }
        }
        table[i as usize] = crc;
    }
    table
}

fn crc32c(data: &[u8]) -> u32 {
    let table = crc32c_table();
    let mut crc = 0xFFFFFFFFu32;
    for &byte in data {
        crc = table[((crc ^ byte as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFFFFFF
}

/// Encode records as one RecordBatch v2 (magic 2, CRC-32C). All records in
/// `records` must share topic+partition (the sink groups before calling).
pub fn encode_record_batch_v2(records: &[KafkaRecord]) -> Vec<u8> {
    let mut batch = Vec::new();
    batch.extend_from_slice(&0i64.to_be_bytes()); // baseOffset
    let len_pos = batch.len();
    batch.extend_from_slice(&0i32.to_be_bytes()); // batchLength (patched)
    batch.extend_from_slice(&(-1i32).to_be_bytes()); // partitionLeaderEpoch
    batch.push(2u8); // magic
    let crc_pos = batch.len();
    batch.extend_from_slice(&0u32.to_be_bytes()); // crc (patched)

    let body_start = batch.len();
    batch.extend_from_slice(&0i16.to_be_bytes()); // attributes: none
    let last_delta = records.len().saturating_sub(1) as i32;
    batch.extend_from_slice(&last_delta.to_be_bytes());
    let first_ts = records.first().map(|r| r.timestamp_ms).unwrap_or(0);
    let max_ts = records.iter().map(|r| r.timestamp_ms).max().unwrap_or(0);
    batch.extend_from_slice(&first_ts.to_be_bytes());
    batch.extend_from_slice(&max_ts.to_be_bytes());
    batch.extend_from_slice(&(-1i64).to_be_bytes()); // producerId
    batch.extend_from_slice(&(-1i16).to_be_bytes()); // producerEpoch
    batch.extend_from_slice(&(-1i32).to_be_bytes()); // baseSequence
    batch.extend_from_slice(&(records.len() as i32).to_be_bytes());

    for (offset_delta, record) in records.iter().enumerate() {
        let mut rec = Vec::new();
        rec.push(0u8); // attributes
        encode_zigzag_i64(record.timestamp_ms - first_ts, &mut rec);
        encode_unsigned_varint(offset_delta as u64, &mut rec);
        encode_varbytes(record.key.as_deref(), &mut rec);
        encode_varbytes(Some(&record.value), &mut rec);
        encode_unsigned_varint(record.headers.len() as u64, &mut rec);
        for (key, value) in &record.headers {
            encode_unsigned_varint(key.len() as u64, &mut rec);
            rec.extend_from_slice(key.as_bytes());
            encode_varbytes(Some(value), &mut rec);
        }
        encode_unsigned_varint(rec.len() as u64, &mut batch);
        batch.extend_from_slice(&rec);
    }

    let crc = crc32c(&batch[body_start..]);
    batch[crc_pos..crc_pos + 4].copy_from_slice(&crc.to_be_bytes());
    let batch_len = (batch.len() - len_pos - 4) as i32;
    batch[len_pos..len_pos + 4].copy_from_slice(&batch_len.to_be_bytes());
    batch
}

// ---------------------------------------------------------------------------
// Transports.
// ---------------------------------------------------------------------------

#[async_trait]
pub trait KafkaTransport: Send + Sync {
    async fn publish(&self, records: Vec<KafkaRecord>) -> Result<()>;
}

/// In-memory transport recording every flushed batch (tests, dry runs).
#[derive(Debug, Default)]
pub struct MemoryKafkaTransport {
    batches: parking_lot::Mutex<Vec<Vec<KafkaRecord>>>,
}

impl MemoryKafkaTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn batches(&self) -> Vec<Vec<KafkaRecord>> {
        self.batches.lock().clone()
    }

    pub fn records_flat(&self) -> Vec<KafkaRecord> {
        self.batches.lock().iter().flatten().cloned().collect()
    }
}

#[async_trait]
impl KafkaTransport for MemoryKafkaTransport {
    async fn publish(&self, records: Vec<KafkaRecord>) -> Result<()> {
        self.batches.lock().push(records);
        Ok(())
    }
}

pub(crate) fn encode_request_header(
    api_key: i16,
    api_version: i16,
    correlation: i32,
    client_id: &str,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&api_key.to_be_bytes());
    out.extend_from_slice(&api_version.to_be_bytes());
    out.extend_from_slice(&correlation.to_be_bytes());
    out.extend_from_slice(&(client_id.len() as i16).to_be_bytes());
    out.extend_from_slice(client_id.as_bytes());
    out
}

fn encode_string(s: &str, out: &mut Vec<u8>) {
    out.extend_from_slice(&(s.len() as i16).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

pub(crate) async fn read_response(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| ConnectorError::Connection("kafka response timeout".to_string()))?
        .map_err(|e| ConnectorError::Connection(format!("kafka read failed: {e}")))?;
    let len = i32::from_be_bytes(len_buf) as usize;
    if len > 8 * 1024 * 1024 {
        return Err(ConnectorError::Connection(format!(
            "kafka response too large: {len}"
        )));
    }
    let mut body = vec![0u8; len];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut body))
        .await
        .map_err(|_| ConnectorError::Connection("kafka response timeout".to_string()))?
        .map_err(|e| ConnectorError::Connection(format!("kafka read failed: {e}")))?;
    Ok(body)
}

pub(crate) async fn send_frame(stream: &mut TcpStream, mut frame: Vec<u8>) -> Result<()> {
    let mut prefixed = (frame.len() as i32).to_be_bytes().to_vec();
    prefixed.append(&mut frame);
    stream
        .write_all(&prefixed)
        .await
        .map_err(|e| ConnectorError::Connection(format!("kafka write failed: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| ConnectorError::Connection(format!("kafka flush failed: {e}")))?;
    Ok(())
}

/// Minimal ApiVersions v0 exchange: proves the peer speaks Kafka and
/// surfaces broker-side errors early.
pub(crate) fn encode_api_versions_request(correlation: i32, client_id: &str) -> Vec<u8> {
    encode_request_header(18, 0, correlation, client_id)
}

pub(crate) fn decode_api_versions_response(body: &[u8], correlation: i32) -> Result<()> {
    if body.len() < 6 {
        return Err(ConnectorError::Connection(
            "truncated ApiVersions response".to_string(),
        ));
    }
    let echoed = i32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    if echoed != correlation {
        return Err(ConnectorError::Connection(format!(
            "ApiVersions correlation mismatch: {echoed} != {correlation}"
        )));
    }
    let error = i16::from_be_bytes([body[4], body[5]]);
    if error != 0 {
        return Err(ConnectorError::Connection(format!(
            "ApiVersions broker error {error}"
        )));
    }
    Ok(())
}

pub(crate) fn encode_produce_body(
    acks: i16,
    grouped: &BTreeMap<(String, i32), Vec<KafkaRecord>>,
) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&(-1i16).to_be_bytes()); // transactional_id = null
    frame.extend_from_slice(&acks.to_be_bytes());
    frame.extend_from_slice(&30_000i32.to_be_bytes()); // timeout ms
    frame.extend_from_slice(&(grouped.len() as i32).to_be_bytes());
    for ((topic, partition), records) in grouped {
        encode_string(topic, &mut frame);
        frame.extend_from_slice(&1i32.to_be_bytes()); // one partition entry
        frame.extend_from_slice(&partition.to_be_bytes());
        let batch = encode_record_batch_v2(records);
        frame.extend_from_slice(&(batch.len() as i32).to_be_bytes());
        frame.extend_from_slice(&batch);
    }
    frame
}

/// Produce v3 request for pre-grouped `(topic, partition) -> records`.
pub(crate) fn encode_produce_request(
    correlation: i32,
    client_id: &str,
    acks: i16,
    grouped: &BTreeMap<(String, i32), Vec<KafkaRecord>>,
) -> Vec<u8> {
    let mut frame = encode_request_header(0, 3, correlation, client_id);
    frame.extend_from_slice(&encode_produce_body(acks, grouped));
    frame
}

pub(crate) fn parse_acks(acks: &str) -> Result<i16> {
    match acks {
        "all" | "-1" => Ok(-1),
        "1" => Ok(1),
        "0" => Ok(0),
        other => Err(ConnectorError::Dispatch(format!(
            "kafka acks must be one of all/-1/1/0, got {other:?}"
        ))),
    }
}

/// TCP transport speaking real Produce/ApiVersions framing. Connects
/// lazily on first use; reconnects once per failed request.
pub struct TcpKafkaTransport {
    endpoint: String,
    client_id: String,
    acks: i16,
    conn: AsyncMutex<Option<TcpKafkaConn>>,
}

struct TcpKafkaConn {
    stream: TcpStream,
    correlation: i32,
}

impl TcpKafkaTransport {
    pub fn new(
        endpoint: impl Into<String>,
        client_id: impl Into<String>,
        acks: &str,
    ) -> Result<Self> {
        Ok(Self {
            endpoint: endpoint.into(),
            client_id: client_id.into(),
            acks: parse_acks(acks)?,
            conn: AsyncMutex::new(None),
        })
    }

    async fn roundtrip(&self, api_key: i16, api_version: i16, body: Vec<u8>) -> Result<Vec<u8>> {
        // Serialize requests: one in-flight exchange at a time.
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
            match exchange.await {
                Ok(mut response) => {
                    if response.len() < 4 {
                        *guard = None;
                        if attempt == 0 {
                            continue;
                        }
                        return Err(ConnectorError::Connection(
                            "truncated kafka response".to_string(),
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
                            "kafka correlation mismatch: {echoed} != {correlation}"
                        )));
                    }
                    response.drain(..4);
                    return Ok(response);
                }
                Err(_) if attempt == 0 => {
                    *guard = None;
                    continue;
                }
                Err(e) => {
                    *guard = None;
                    return Err(e);
                }
            }
        }
        Err(ConnectorError::Connection(
            "kafka exchange failed".to_string(),
        ))
    }

    async fn dial(&self) -> Result<TcpKafkaConn> {
        let stream =
            tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&self.endpoint))
                .await
                .map_err(|_| {
                    ConnectorError::Connection(format!("kafka connect timeout: {}", self.endpoint))
                })?
                .map_err(|e| {
                    ConnectorError::Connection(format!(
                        "kafka connect to {} failed: {e}",
                        self.endpoint
                    ))
                })?;
        let mut conn = TcpKafkaConn {
            stream,
            correlation: 1,
        };
        // Prove framing against the broker before producing.
        let frame = encode_api_versions_request(0, &self.client_id);
        send_frame(&mut conn.stream, frame).await?;
        let response = read_response(&mut conn.stream).await?;
        decode_api_versions_response(&response, 0)?;
        conn.correlation = 1;
        Ok(conn)
    }

    async fn produce_grouped(
        &self,
        grouped: &BTreeMap<(String, i32), Vec<KafkaRecord>>,
    ) -> Result<()> {
        if grouped.is_empty() {
            return Ok(());
        }
        let body = encode_produce_body(self.acks, grouped);
        let response = self.roundtrip(0, 3, body).await?;
        // Response: [topics]: name, [partitions]: index, error, base_offset,
        // log_append_time, log_start_offset, throttle.
        let mut cursor = response.as_slice();
        let topics = read_i32(&mut cursor)?;
        for _ in 0..topics {
            let name_len = read_i16(&mut cursor)? as usize;
            if cursor.len() < name_len {
                return Err(ConnectorError::Connection(
                    "truncated produce response".to_string(),
                ));
            }
            let name = String::from_utf8_lossy(&cursor[..name_len]).to_string();
            cursor = &cursor[name_len..];
            let partitions = read_i32(&mut cursor)?;
            for _ in 0..partitions {
                let _index = read_i32(&mut cursor)?;
                let error = read_i16(&mut cursor)?;
                if error != 0 {
                    return Err(ConnectorError::Dispatch(format!(
                        "kafka produce to {name} failed with error {error}"
                    )));
                }
                if cursor.len() < 8 + 8 + 8 + 4 {
                    return Err(ConnectorError::Connection(
                        "truncated produce response".to_string(),
                    ));
                }
                cursor = &cursor[8 + 8 + 8 + 4..];
            }
        }
        Ok(())
    }
}

fn read_i16(cursor: &mut &[u8]) -> Result<i16> {
    if cursor.len() < 2 {
        return Err(ConnectorError::Connection(
            "truncated kafka response".to_string(),
        ));
    }
    let value = i16::from_be_bytes([cursor[0], cursor[1]]);
    *cursor = &cursor[2..];
    Ok(value)
}

fn read_i32(cursor: &mut &[u8]) -> Result<i32> {
    if cursor.len() < 4 {
        return Err(ConnectorError::Connection(
            "truncated kafka response".to_string(),
        ));
    }
    let value = i32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]);
    *cursor = &cursor[4..];
    Ok(value)
}

#[async_trait]
impl KafkaTransport for TcpKafkaTransport {
    async fn publish(&self, records: Vec<KafkaRecord>) -> Result<()> {
        let mut grouped: BTreeMap<(String, i32), Vec<KafkaRecord>> = BTreeMap::new();
        for record in records {
            grouped
                .entry((record.topic.clone(), record.partition))
                .or_default()
                .push(record);
        }
        self.produce_grouped(&grouped).await
    }
}

// ---------------------------------------------------------------------------
// Maintained driver transport (`rdkafka`).
// ---------------------------------------------------------------------------

/// Build the maintained `rdkafka` client configuration for plain Apache
/// Kafka endpoints: the configured bootstrap servers and client id, the
/// configured acks as `request.required.acks`, and a 30 s
/// `message.timeout.ms` (covers a single-broker KRaft restart window
/// while keeping each delivery future bounded; the Kafka default of
/// 5 min would hold rule-path futures far past the sink's retry
/// window). Idempotence turns on exactly when acks requests a quorum
/// (`all`/`-1`, the Kafka requirement for `enable.idempotence=true`);
/// otherwise it stays off so `acks=1`/`acks=0` keep their documented
/// throughput semantics.
///
/// Building the config opens no socket and spawns no thread; the
/// driver connects lazily on first publish (see
/// [`RdkafkaKafkaTransport`]). Management-plane validation therefore
/// stays offline-safe: creating the sink never touches the network.
pub fn rdkafka_client_config(config: &KafkaSinkConfig) -> rdkafka::config::ClientConfig {
    let mut client = rdkafka::config::ClientConfig::new();
    client
        .set("bootstrap.servers", config.bootstrap_servers.clone())
        .set("client.id", config.client_id.clone())
        .set(
            "request.required.acks",
            match config.acks.as_str() {
                "all" | "-1" => "all",
                "1" => "1",
                _ => "0",
            },
        )
        // 30 s: single-broker restart window (see QUAL fault test);
        // the Kafka default (300 s) would pin rule-path futures.
        .set("message.timeout.ms", "30000")
        .set("socket.timeout.ms", "30000")
        .set(
            "enable.idempotence",
            match config.acks.as_str() {
                "all" | "-1" => "true",
                _ => "false",
            },
        );
    client
}

/// Whether a driver failure message is terminal (`true`) or retryable
/// (`false`). Authentication/authorisation failures and oversize
/// records can never succeed on retry, so they are terminal; timeouts,
/// transport loss, unknown topics and queue pressure retry with
/// backoff through the sink.
///
/// TODO(parity): librdkafka reports a wider taxonomy than these
/// substrings; which further codes must be terminal versus retryable
/// for exactly-once accounting on plain Kafka?
pub fn is_terminal_driver_message(message: &str) -> bool {
    let text = message.to_lowercase();
    text.contains("sasl")
        || text.contains("auth")
        || text.contains("ssl")
        || text.contains("message too large")
        || text.contains("msg_size_too_large")
}

/// Classify a driver delivery failure into the sink's error contract:
/// terminal failures become `Dispatch` (drop, never retry), everything
/// else becomes `Connection` (restore the batch, back off, retry).
pub fn classify_driver_error(error: &rdkafka::error::KafkaError) -> ConnectorError {
    if is_terminal_driver_message(&format!("{error:?}")) {
        ConnectorError::Dispatch(format!("kafka driver delivery failed terminally: {error}"))
    } else {
        ConnectorError::Connection(format!("kafka driver delivery failed retryably: {error}"))
    }
}

/// Production transport on the maintained `rdkafka` driver.
///
/// The `FutureProducer` is created lazily on first publish and cached;
/// creation validates the librdkafka keys without opening any socket,
/// and the driver dials on first delivery. Records publish
/// sequentially, one delivery future at a time, so the driver queue
/// holds at most one flush in flight: no new unbounded buffer on the
/// publish path, no lock held across I/O (the producer handle is
/// cloned under a short read lock, then used lock-free). The sink's
/// in-memory batch (bounded by `batch_max_records`/`batch_max_bytes`,
/// defaults 500 records / 256 KiB because a rule worker must stay
/// small) is the only queue ahead of it.
pub struct RdkafkaKafkaTransport {
    config: KafkaSinkConfig,
    producer: AsyncRwLock<Option<rdkafka::producer::FutureProducer>>,
}

impl RdkafkaKafkaTransport {
    pub fn new(config: &KafkaSinkConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config: config.clone(),
            producer: AsyncRwLock::new(None),
        })
    }

    pub fn config(&self) -> &KafkaSinkConfig {
        &self.config
    }

    async fn producer(&self) -> Result<rdkafka::producer::FutureProducer> {
        if let Some(producer) = self.producer.read().await.clone() {
            return Ok(producer);
        }
        let mut guard = self.producer.write().await;
        if let Some(producer) = guard.clone() {
            return Ok(producer);
        }
        // PERF(parity): one driver producer per transport, created once
        // and shared by every flush. A pooled producer set would be the
        // fast version under very high partition fan-out; kept singular
        // so a kernel restart never inherits half-open broker sessions.
        // Hot-path numbers (per publish of R records): before (legacy
        // TCP): R framed copies into one Produce body + 1 socket write;
        // after (driver): R queue copies + R delivery futures, no new
        // locks (the handle clones under a short read lock, then runs
        // lock-free) and at most one flush in flight.
        let producer: rdkafka::producer::FutureProducer = rdkafka_client_config(&self.config)
            .create()
            .map_err(|error: rdkafka::error::KafkaError| {
                ConnectorError::Dispatch(format!("kafka driver config rejected: {error}"))
            })?;
        *guard = Some(producer.clone());
        Ok(producer)
    }

    /// Drop the cached driver producer so the next publish redials with
    /// the current configuration. Used by qualification to prove the
    /// driver recovers after a server restart.
    pub async fn reconnect(&self) -> Result<()> {
        *self.producer.write().await = None;
        self.producer().await.map(|_| ())
    }
}

#[async_trait]
impl KafkaTransport for RdkafkaKafkaTransport {
    async fn publish(&self, records: Vec<KafkaRecord>) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        let producer = self.producer().await?;
        // 30 s per record: matches `message.timeout.ms` above so a
        // delivery future never outlives the driver's own deadline.
        let timeout = Duration::from_secs(30);
        for record in &records {
            let payload: &[u8] = record.value.as_ref();
            let mut headers = rdkafka::message::OwnedHeaders::new();
            for (name, value) in &record.headers {
                let content: &[u8] = value.as_ref();
                headers = headers.insert(rdkafka::message::Header {
                    key: name.as_str(),
                    value: Some(content),
                });
            }
            let mut wire: rdkafka::producer::FutureRecord<'_, [u8], [u8]> =
                rdkafka::producer::FutureRecord::to(record.topic.as_str())
                    .partition(record.partition)
                    .payload(payload)
                    .headers(headers);
            if let Some(key) = record.key.as_ref() {
                let key_bytes: &[u8] = key.as_ref();
                wire = wire.key(key_bytes);
            }
            producer
                .send(wire, rdkafka::util::Timeout::After(timeout))
                .await
                .map_err(|(error, _)| classify_driver_error(&error))?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Sink.
// ---------------------------------------------------------------------------

/// Kafka producer sink: renders topics, extracts partition keys, batches
/// records, and dispatches through the configured transport.
pub struct KafkaSink {
    config: KafkaSinkConfig,
    transport: Arc<dyn KafkaTransport>,
    buffer: parking_lot::Mutex<BatchBuffer>,
    backoff: parking_lot::Mutex<BackoffState>,
    sent_batches: AtomicU64,
    sent_records: AtomicU64,
}

#[derive(Default)]
struct BatchBuffer {
    records: Vec<KafkaRecord>,
    bytes: usize,
}

impl KafkaSink {
    pub fn new(config: KafkaSinkConfig, transport: Arc<dyn KafkaTransport>) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            transport,
            buffer: parking_lot::Mutex::new(BatchBuffer::default()),
            backoff: parking_lot::Mutex::new(BackoffState::default()),
            sent_batches: AtomicU64::new(0),
            sent_records: AtomicU64::new(0),
        })
    }

    pub fn config(&self) -> &KafkaSinkConfig {
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

    fn build_record(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> KafkaRecord {
        let rendered = render_topic_template(&self.config.topic_template, topic.as_str());
        let key = self
            .config
            .partition_key_field
            .as_deref()
            .and_then(|field| extract_json_field(payload, field))
            .map(Bytes::from);
        let partition = partition_for_key(key.as_deref(), self.config.partitions);
        KafkaRecord {
            topic: rendered,
            partition,
            key,
            value: payload.clone(),
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
            timestamp_ms: now_millis(),
        }
    }

    /// Flush buffered records (no-op when empty). Retryable driver
    /// failures retry in place with backoff so a mid-batch single-broker
    /// restart still lands every key (at-least-once: duplicates possible,
    /// loss is a defect); terminal failures restore the batch and
    /// propagate. At most 200 attempts with 100 ms to 1 s backoff (about
    /// 100 s window: covers a KRaft single-broker restart while keeping
    /// the rule worker bounded).
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
        // 200 attempts: single-broker restart window for the
        // qualification fault test; each sleep is 100 ms doubling to
        // 1 s, so the window is about 100 s without wedging the rule
        // worker past the driver's own 30 s deadline per record.
        let mut attempt = 0usize;
        loop {
            match self.transport.publish(batch.clone()).await {
                Ok(()) => {
                    self.backoff.lock().success();
                    self.sent_batches.fetch_add(1, Ordering::Relaxed);
                    self.sent_records.fetch_add(count, Ordering::Relaxed);
                    return Ok(());
                }
                Err(ConnectorError::Connection(message)) => {
                    attempt += 1;
                    if attempt >= 200 {
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
                        return Err(ConnectorError::Connection(message));
                    }
                    let delay_ms = 100u64
                        .saturating_mul(2u64.saturating_pow((attempt.min(4)) as u32))
                        .min(1_000);
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
                Err(e) => {
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
                    return Err(e);
                }
            }
        }
    }
}

/// Extract a top-level JSON field as key bytes: strings raw, scalars via
/// their JSON spelling, containers re-serialized. Missing fields and
/// non-JSON payloads yield `None` (null-key partitioning).
fn extract_json_field(payload: &[u8], field: &str) -> Option<Vec<u8>> {
    let value: serde_json::Value = serde_json::from_slice(payload).ok()?;
    match value.get(field) {
        Some(serde_json::Value::String(text)) => Some(text.as_bytes().to_vec()),
        Some(scalar) if scalar.is_number() || scalar.is_boolean() => {
            Some(scalar.to_string().into_bytes())
        }
        Some(other) => serde_json::to_vec(other).ok(),
        None => None,
    }
}

#[async_trait]
impl Sink for KafkaSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> super::Result<()> {
        let record = self.build_record(topic, payload, qos);
        let should_flush = {
            let mut buffer = self.buffer.lock();
            buffer.bytes += record.value.len() + record.key.as_ref().map(|k| k.len()).unwrap_or(0);
            buffer.records.push(record);
            buffer.records.len() >= self.config.batch_max_records
                || buffer.bytes >= self.config.batch_max_bytes
        };
        if should_flush {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "kafka"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn test_config() -> KafkaSinkConfig {
        KafkaSinkConfig {
            bootstrap_servers: "127.0.0.1:9092".to_string(),
            topic_template: "kafka-telemetry-${topic}".to_string(),
            partition_key_field: Some("device_id".to_string()),
            partitions: 12,
            client_id: "indra-test".to_string(),
            acks: "all".to_string(),
            batch_max_records: 500,
            batch_max_bytes: 256 * 1024,
        }
    }

    #[test]
    fn test_config_validation() {
        let mut config = test_config();
        assert!(config.validate().is_ok());

        config.bootstrap_servers = "  ".to_string();
        assert!(config.validate().is_err());
        config.bootstrap_servers = "x:9092".to_string();

        config.topic_template.clear();
        assert!(config.validate().is_err());
        config.topic_template = "t-${topic}".to_string();

        for bad in ["2", "quorum", ""] {
            config.acks = bad.to_string();
            assert!(config.validate().is_err(), "acks {bad:?} must fail");
        }
        for good in ["all", "-1", "1", "0"] {
            config.acks = good.to_string();
            assert!(config.validate().is_ok(), "acks {good:?} must pass");
        }

        config.partitions = 0;
        assert!(config.validate().is_err());
        config.partitions = 12;

        config.batch_max_records = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_topic_template_rendering() {
        assert_eq!(
            render_topic_template("kafka-telemetry-${topic}", "sensors/temp"),
            "kafka-telemetry-sensors.temp"
        );
        assert_eq!(render_topic_template("plain", "a/b"), "plain");
        // Unknown placeholders pass through literally.
        assert_eq!(render_topic_template("x-${nope}-y", "a"), "x-__nope_-y");
    }

    #[test]
    fn test_topic_template_sanitises_illegal_kafka_characters() {
        assert_eq!(
            render_topic_template("t-${topic}", "a+b#c d:e/f"),
            "t-a_b_c_d_e.f"
        );
        assert_eq!(
            render_topic_template("t-${topic}", "sensors/tempé"),
            "t-sensors.temp_"
        );
        assert_eq!(render_topic_template("x-${nope}-y", "a"), "x-__nope_-y");
    }

    #[test]
    fn test_topic_template_enforces_kafka_length_and_reserved_names() {
        let long_topic = "a".repeat(300);
        let rendered = render_topic_template("${topic}", &long_topic);
        assert_eq!(rendered.len(), 249);
        assert_eq!(rendered, "a".repeat(249));
        let rendered = render_topic_template("prefix-${topic}", &long_topic);
        assert_eq!(rendered.len(), 249);
        assert_eq!(
            rendered,
            format!("prefix-{}", "a".repeat(249 - "prefix-".len()))
        );
        assert_eq!(
            render_topic_template("${topic}", ""),
            "indramqtt-invalid-topic"
        );
        assert_eq!(
            render_topic_template("${topic}", "."),
            "indramqtt-invalid-topic"
        );
        assert_eq!(
            render_topic_template("${topic}", ".."),
            "indramqtt-invalid-topic"
        );
        assert_eq!(render_topic_template(".", "a/b"), "indramqtt-invalid-topic");
        assert_eq!(render_topic_template("..", "a"), "indramqtt-invalid-topic");
    }

    #[test]
    fn test_partition_key_extraction_and_hashing() {
        // Same key always lands on the same partition, in range.
        let p1 = partition_for_key(Some(b"device-7"), 12);
        assert_eq!(p1, partition_for_key(Some(b"device-7"), 12));
        assert!((0..12).contains(&p1));
        // Null keys pin to partition 0 deterministically.
        assert_eq!(partition_for_key(None, 12), 0);
        // A sample of keys spreads across partitions (no single hotspot).
        let mut seen = std::collections::HashSet::new();
        for i in 0..50 {
            seen.insert(partition_for_key(
                Some(format!("device-{i}").as_bytes()),
                12,
            ));
        }
        assert!(seen.len() >= 6, "keys must spread, got {seen:?}");

        // Field extraction shapes.
        assert_eq!(
            extract_json_field(br#"{ "device_id": "d7", "v": 1 }"#, "device_id"),
            Some(b"d7".to_vec())
        );
        assert_eq!(
            extract_json_field(br#"{ "device_id": 42 }"#, "device_id"),
            Some(b"42".to_vec())
        );
        assert_eq!(extract_json_field(br#"{ "v": 1 }"#, "device_id"), None);
        assert_eq!(extract_json_field(b"not json", "device_id"), None);
    }

    #[test]
    fn test_record_headers_and_serialization() {
        let transport = Arc::new(MemoryKafkaTransport::new());
        // Batching raised so nothing auto-flushes before the explicit call.
        let mut config = test_config();
        config.batch_max_records = 100;
        let sink = KafkaSink::new(config, transport.clone()).expect("valid sink");
        let topic = Topic::new("sensors/temp").unwrap();
        let payload = Bytes::from_static(br#"{ "device_id": "d7", "temperature": 21.5 }"#);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            sink.send(&topic, &payload, QoS::AtLeastOnce).await.unwrap();
            sink.send(&topic, &payload, QoS::AtLeastOnce).await.unwrap();
            assert_eq!(sink.buffered_records(), 2);
            assert!(transport.batches().is_empty());
            sink.flush().await.unwrap();
        });

        let batches = transport.batches();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].len(), 2);
        let record = &batches[0][0];
        assert_eq!(record.topic, "kafka-telemetry-sensors.temp");
        assert_eq!(record.key, Some(Bytes::from_static(b"d7")));
        assert!((0..12).contains(&record.partition));
        assert_eq!(record.value, payload);
        let header_map: std::collections::HashMap<&str, &Bytes> = record
            .headers
            .iter()
            .map(|(k, v)| (k.as_str(), v))
            .collect();
        assert_eq!(
            header_map.get("mqtt.topic"),
            Some(&&Bytes::from_static(b"sensors/temp"))
        );
        assert_eq!(header_map.get("mqtt.qos"), Some(&&Bytes::from_static(b"1")));
        assert!(header_map.contains_key("mqtt.timestamp"));

        // RecordBatch v2 framing: length prefix consistency + magic + content.
        let batch = encode_record_batch_v2(&batches[0]);
        assert!(batch.len() > 8 + 4 + 4 + 1 + 4);
        let batch_len = i32::from_be_bytes([batch[8], batch[9], batch[10], batch[11]]) as usize;
        assert_eq!(8 + 4 + batch_len, batch.len());
        assert_eq!(batch[8 + 4 + 4], 2u8, "magic must be 2");
        assert!(
            batch.windows(b"d7".len()).any(|w| w == b"d7"),
            "key bytes embedded"
        );
        assert!(
            batch
                .windows(b"mqtt.topic".len())
                .any(|w| w == b"mqtt.topic"),
            "header key embedded"
        );
        assert_eq!(sink.sent_batches(), 1);
    }

    #[test]
    fn test_batch_auto_flush_on_record_limit() {
        let transport = Arc::new(MemoryKafkaTransport::new());
        let mut config = test_config();
        config.batch_max_records = 3;
        let sink = KafkaSink::new(config, transport.clone()).expect("valid sink");
        let topic = Topic::new("t").unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            for _ in 0..3 {
                sink.send(&topic, &Bytes::from_static(b"{}"), QoS::AtMostOnce)
                    .await
                    .unwrap();
            }
        });
        assert_eq!(transport.batches().len(), 1);
        assert_eq!(transport.batches()[0].len(), 3);
        assert_eq!(sink.buffered_records(), 0);
        assert_eq!(sink.sent_batches(), 1);
    }

    /// In-process fake Kafka broker: scripted ApiVersions + Produce
    /// exchange over raw TCP, capturing the produced bytes.
    #[tokio::test]
    async fn test_tcp_transport_produce_against_fake_broker() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let captured = Arc::new(parking_lot::Mutex::new(Vec::<u8>::new()));
        let captured_rx = captured.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            // 1) ApiVersions v0 request -> canned success, no APIs listed.
            let frame = read_frame(&mut stream).await;
            assert_eq!(&frame[..6], &[0, 18, 0, 0, 0, 0]);
            write_frame(&mut stream, &[0, 0, 0, 0, 0, 0, 0, 0]).await;
            // 2) Produce request -> capture, canned v3 success.
            let frame = read_frame(&mut stream).await;
            // api_key 0 (Produce), version 3.
            assert_eq!(&frame[..4], &[0, 0, 0, 3]);
            captured_rx.lock().extend_from_slice(&frame);
            // ProduceResponse v3: [topics=1][name][partitions=1][index,
            // error, base_offset, log_append_time, log_start_offset,
            // throttle], echoing the request correlation id.
            let mut response = vec![0, 0, 0, 0];
            response.extend_from_slice(&[0, 0, 0, 1]); // topics
            response.extend_from_slice(&[0, 4]); // name len
            response.extend_from_slice(b"test");
            response.extend_from_slice(&[0, 0, 0, 1]); // partitions
            response.extend_from_slice(&[0, 0, 0, 0]); // index
            response.extend_from_slice(&[0, 0]); // error = 0
            response.extend_from_slice(&[0u8; 8 + 8 + 8]); // offsets/times
            response.extend_from_slice(&[0, 0, 0, 0]); // throttle
            response[0..4].copy_from_slice(&frame[4..8]);
            write_frame(&mut stream, &response).await;
        });

        // Batch of one: every send flushes straight through TCP.
        let mut config = test_config();
        config.batch_max_records = 1;
        let sink = KafkaSink::new(
            config,
            Arc::new(
                TcpKafkaTransport::new(format!("127.0.0.1:{port}"), "indra-fake-test", "all")
                    .expect("valid transport"),
            ),
        )
        .expect("valid sink");

        let topic = Topic::new("sensors/temp").unwrap();
        sink.send(
            &topic,
            &Bytes::from_static(br#"{ "device_id": "d7" }"#),
            QoS::AtMostOnce,
        )
        .await
        .expect("produce over TCP");
        assert_eq!(sink.sent_batches(), 1);

        // The transport returns once bytes hit the kernel; poll until the
        // fake broker has consumed the produce request.
        let mut finished = false;
        for _ in 0..500 {
            if server.is_finished() {
                finished = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(finished, "fake broker never consumed the produce");
        server.await.expect("fake broker task");
        let wire = captured.lock().clone();
        assert!(wire.windows(4).any(|w| w == b"test"), "topic on the wire");
        assert!(wire.windows(2).any(|w| w == b"d7"), "key on the wire");
        assert!(
            wire.windows(10).any(|w| w == b"mqtt.topic"),
            "headers on the wire"
        );
        assert!(
            wire.windows(br#"{ "device_id": "d7" }"#.len())
                .any(|w| w == br#"{ "device_id": "d7" }"#),
            "payload on the wire"
        );
    }

    async fn read_frame(stream: &mut TcpStream) -> Vec<u8> {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await.expect("read len");
        let len = i32::from_be_bytes(len_buf) as usize;
        let mut frame = vec![0u8; len];
        stream.read_exact(&mut frame).await.expect("read frame");
        frame
    }

    async fn write_frame(stream: &mut TcpStream, body: &[u8]) {
        let mut prefixed = (body.len() as i32).to_be_bytes().to_vec();
        prefixed.extend_from_slice(body);
        stream.write_all(&prefixed).await.expect("write frame");
    }

    #[test]
    fn test_driver_config_mapping() {
        // The driver config must accept every acks mode we advertise:
        // `create` validates the librdkafka keys without opening any
        // socket, so this stays offline.
        for acks in ["all", "-1", "1", "0"] {
            let mut config = test_config();
            config.acks = acks.to_string();
            let client = rdkafka_client_config(&config);
            let producer: std::result::Result<
                rdkafka::producer::FutureProducer,
                rdkafka::error::KafkaError,
            > = client.create();
            assert!(
                producer.is_ok(),
                "driver must accept acks {acks:?} without I/O"
            );
        }
        // Idempotence follows the Kafka requirement: on exactly when a
        // quorum ack is requested.
        let mut all = test_config();
        all.acks = "all".to_string();
        let _ = rdkafka_client_config(&all);
        let mut one = test_config();
        one.acks = "1".to_string();
        let _ = rdkafka_client_config(&one);
    }

    #[test]
    fn test_driver_error_classification() {
        // Terminal: authentication/authorisation and oversize records.
        for message in [
            "SASL authentication failed: bad credentials",
            "SaslAuthFailedError: invalid username",
            "ssl handshake failed: certificate verify",
            "Message production error: MessageTooLarge (MSG_SIZE_TOO_LARGE)",
            "msg_size_too_large: record exceeds the limit",
        ] {
            assert!(
                is_terminal_driver_message(message),
                "{message:?} must be terminal"
            );
        }
        // Retryable: timeouts, transport loss, unknown topics, pressure.
        for message in [
            "Message timed out (MSG_TIMED_OUT)",
            "Broker transport failure: connection reset",
            "Unknown topic or partition",
            "Queue full: would block",
            "success",
        ] {
            assert!(
                !is_terminal_driver_message(message),
                "{message:?} must be retryable"
            );
        }
    }

    #[tokio::test]
    async fn test_driver_transport_validates_without_io() {
        // `new` validates our config only; `reconnect` builds (and
        // caches) the driver producer, which dials lazily, so neither
        // touches the network.
        let transport = RdkafkaKafkaTransport::new(&test_config()).expect("valid driver transport");
        transport
            .reconnect()
            .await
            .expect("reconnect builds the producer offline");
        let mut bad = test_config();
        bad.bootstrap_servers.clear();
        assert!(RdkafkaKafkaTransport::new(&bad).is_err());
    }

    fn qual_env(name: &str) -> Option<String> {
        std::env::var(name).ok().filter(|v| !v.trim().is_empty())
    }

    /// Qualification against a real Apache Kafka server via the
    /// maintained `rdkafka` driver.
    ///
    /// Run with e.g.:
    /// `KAFKA_BOOTSTRAP_SERVERS=127.0.0.1:9092 KAFKA_TOPIC=qual-b324 \
    ///  cargo test -p broker-connectors --lib kafka::tests::test_qualify_driver_write_path -- --ignored --nocapture --test-threads=1`
    ///
    /// Creates the topic (`<topic>`, 6 partitions) when missing, streams
    /// 5000 keyed records through [`KafkaSink`] on
    /// [`RdkafkaKafkaTransport`] via the shared [`crate::ConnectorManager`]
    /// path the broker uses, restarts the server mid-batch through
    /// `$QUAL_FAULT_FILE` when set, then reads all 5000 back with a
    /// driver consumer asserting exact distinct counts, murmur2
    /// placement and per-partition ordering. Deletes the topic
    /// afterwards.
    ///
    /// TODO(parity): multi-broker leader failover qualification needs a
    /// second broker; single-broker restart is the only fault covered
    /// here.
    #[tokio::test]
    #[ignore = "needs a real Apache Kafka server (see KAFKA_* env)"]
    async fn test_qualify_driver_write_path() {
        use crate::ConnectorManager;
        use rdkafka::consumer::Consumer as _;
        use rdkafka::message::Message as _;
        use std::collections::{HashMap, HashSet};

        const RECORDS: u32 = 5000;
        const PARTITIONS: u32 = 6;

        let bootstrap = qual_env("KAFKA_BOOTSTRAP_SERVERS").unwrap_or_else(|| {
            panic!(
                "KAFKA_BOOTSTRAP_SERVERS must point at a real Apache Kafka server for qualification; \
                 failing closed instead of passing vacuously \
                 (e.g. KAFKA_BOOTSTRAP_SERVERS=127.0.0.1:9092)"
            )
        });
        let topic = qual_env("KAFKA_TOPIC")
            .unwrap_or_else(|| panic!("KAFKA_TOPIC must be set for qualification; failing closed"));
        // Server version for the report comes from the qualification
        // image the gates start (apache/kafka:3.8.0); the driver exposes
        // no broker-version RPC here, so the bootstrap/topic line below
        // is the measured endpoint, never a substitute version string.
        eprintln!("qual server: image apache/kafka:3.8.0 bootstrap={bootstrap} topic={topic}");
        let fault_file = qual_env("QUAL_FAULT_FILE");

        // Ensure the topic exists (idempotent: already-exists is fine).
        let admin_config = KafkaSinkConfig {
            bootstrap_servers: bootstrap.clone(),
            topic_template: topic.clone(),
            partition_key_field: Some("device_id".to_string()),
            partitions: PARTITIONS,
            client_id: "indra-qual-b324-admin".to_string(),
            acks: "all".to_string(),
            batch_max_records: 500,
            batch_max_bytes: 256 * 1024,
        };
        let admin: rdkafka::admin::AdminClient<rdkafka::client::DefaultClientContext> =
            rdkafka_client_config(&admin_config)
                .create()
                .expect("qual admin client");
        let new_topic = rdkafka::admin::NewTopic::new(
            topic.as_str(),
            PARTITIONS as i32,
            rdkafka::admin::TopicReplication::Fixed(1),
        );
        let created = admin
            .create_topics(
                [&new_topic],
                &rdkafka::admin::AdminOptions::new().operation_timeout(Some(
                    rdkafka::util::Timeout::After(Duration::from_secs(120)),
                )),
            )
            .await
            .expect("qual create topic rpc");
        for result in created {
            if let Err(error) = result {
                let text = format!("{error:?}");
                if !text.contains("AlreadyExists")
                    && !text.contains("already exists")
                    && !text.contains("ALREADY_EXISTS")
                {
                    panic!("qual create topic failed: {error:?}");
                }
            }
        }

        let config = KafkaSinkConfig {
            bootstrap_servers: bootstrap.clone(),
            topic_template: topic.clone(),
            partition_key_field: Some("device_id".to_string()),
            partitions: PARTITIONS,
            client_id: "indra-qual-b324".to_string(),
            acks: "all".to_string(),
            batch_max_records: 500,
            batch_max_bytes: 256 * 1024,
        };
        config.validate().expect("qual config validates");
        let transport = Arc::new(RdkafkaKafkaTransport::new(&config).expect("qual transport"));
        let sink = Arc::new(KafkaSink::new(config, transport.clone()).expect("qual sink"));
        assert_eq!(sink.kind(), "kafka");
        // The broker's path: rule actions deliver through the shared
        // connector manager, so the qualification sends through it and
        // never `sink.send` directly.
        let manager = ConnectorManager::new();
        manager.register("qual-kafka", sink.clone());
        manager.register("kafka:qual-kafka", sink.clone());

        let mqtt_topic = Topic::new("sensors/qual").expect("qual topic");
        for seq in 0..RECORDS {
            let device = format!("qual-{seq:06}");
            let payload = Bytes::from(format!(
                r#"{{"device_id":"{device}","seq":{seq},"temperature":{:.2}}}"#,
                20.0 + f64::from(seq) * 0.01
            ));
            // Retry transient connection failures per record so a
            // mid-batch server restart never loses a sequence number;
            // terminal failures panic immediately (fail closed).
            let mut attempts = 0usize;
            loop {
                match manager
                    .send("qual-kafka", &mqtt_topic, &payload, QoS::AtLeastOnce)
                    .await
                {
                    Ok(()) => break,
                    Err(ConnectorError::Connection(message)) => {
                        attempts += 1;
                        if attempts >= 240 {
                            panic!("qual send seq={seq} never recovered: {message}");
                        }
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                    Err(error) => panic!("qual send seq={seq} terminal: {error:?}"),
                }
            }
            if seq == 2500 {
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
        // Flush with an outer retry so a restart that outlasts one
        // inner window still lands every record.
        let mut flushed = false;
        for _ in 0..10 {
            match sink.flush().await {
                Ok(()) => {
                    flushed = true;
                    break;
                }
                Err(ConnectorError::Connection(message)) => {
                    eprintln!("qual flush retryable: {message}");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                Err(error) => panic!("qual flush terminal: {error:?}"),
            }
        }
        assert!(flushed, "qual flush never recovered after restart");
        assert_eq!(sink.sent_records(), u64::from(RECORDS));
        eprintln!(
            "qual rows sent: records={} batches={}",
            sink.sent_records(),
            sink.sent_batches()
        );

        // Read everything back: exact distinct counts (at-least-once
        // permits duplicates, never loss), murmur2 placement and
        // per-partition ordering.
        let mut consumer_config = rdkafka::config::ClientConfig::new();
        consumer_config
            .set("bootstrap.servers", bootstrap.clone())
            .set(
                "group.id",
                format!("indra-qual-b324-{}", super::super::now_millis()),
            )
            .set("enable.auto.commit", "false")
            .set("auto.offset.reset", "earliest");
        let consumer: rdkafka::consumer::StreamConsumer =
            consumer_config.create().expect("qual consumer");
        consumer
            .subscribe(&[topic.as_str()])
            .expect("qual subscribe");
        let mut seen: HashSet<String> = HashSet::new();
        let mut seq_by_key: HashMap<String, u32> = HashMap::new();
        let mut last_seq_by_partition: HashMap<i32, u32> = HashMap::new();
        let mut total = 0usize;
        let mut duplicates = 0usize;
        while seen.len() < RECORDS as usize {
            let message = tokio::time::timeout(Duration::from_secs(180), consumer.recv())
                .await
                .expect("qual recv timeout")
                .expect("qual recv");
            let key_bytes = message.key().expect("qual records are keyed");
            let payload_bytes = message.payload().expect("qual payload");
            let partition = message.partition();
            let value: serde_json::Value =
                serde_json::from_slice(payload_bytes).expect("qual payload is JSON");
            let device = value
                .get("device_id")
                .and_then(|v| v.as_str())
                .expect("qual payload carries device_id");
            let seq = value
                .get("seq")
                .and_then(|v| v.as_u64())
                .expect("qual payload carries seq") as u32;
            assert_eq!(
                key_bytes,
                device.as_bytes(),
                "key bytes must be the device id"
            );
            assert_eq!(
                partition,
                partition_for_key(Some(key_bytes), PARTITIONS),
                "murmur2 placement must match for key {device}"
            );
            total += 1;
            if !seen.insert(device.to_string()) {
                duplicates += 1;
                assert_eq!(
                    seq_by_key.get(device),
                    Some(&seq),
                    "duplicate delivery must carry the same seq for {device}"
                );
                continue;
            }
            seq_by_key.insert(device.to_string(), seq);
            if let Some(last) = last_seq_by_partition.get(&partition) {
                assert!(
                    seq > *last,
                    "ordering per partition violated on partition {partition}: seq={seq} after {last}"
                );
            }
            last_seq_by_partition.insert(partition, seq);
            if total.is_multiple_of(1000) || seen.len() == RECORDS as usize {
                eprintln!(
                    "qual progress: distinct={} total={} duplicates={}",
                    seen.len(),
                    total,
                    duplicates
                );
            }
        }
        assert_eq!(seen.len(), RECORDS as usize);
        for seq in 0..RECORDS {
            let device = format!("qual-{seq:06}");
            assert!(seen.contains(&device), "qual missing key {device}");
            assert_eq!(seq_by_key.get(&device), Some(&seq));
        }
        eprintln!(
            "qual rows asserted: distinct={} total={} duplicates={} partitions={}",
            seen.len(),
            total,
            duplicates,
            last_seq_by_partition.len()
        );
        assert_eq!(
            last_seq_by_partition.len(),
            PARTITIONS as usize,
            "keys must spread across all {PARTITIONS} partitions"
        );

        // Cleanup: delete the topic; a failure is logged, never silent.
        match admin
            .delete_topics(
                &[topic.as_str()],
                &rdkafka::admin::AdminOptions::new().operation_timeout(Some(
                    rdkafka::util::Timeout::After(Duration::from_secs(120)),
                )),
            )
            .await
        {
            Ok(results) => {
                for result in results {
                    if let Err(error) = result {
                        eprintln!("qual delete topic note: {error:?}");
                    }
                }
            }
            Err(error) => eprintln!("qual delete topic rpc failed: {error}"),
        }
        eprintln!("qual cleanup: deleted topic {topic}");
    }
}
