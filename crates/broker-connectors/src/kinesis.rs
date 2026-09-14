//! Amazon Kinesis Data Streams sink (INDRA-197).
//!
//! Buffers MQTT events and ingests them with the `PutRecords` batch
//! API (`Kinesis_20131202.PutRecords` over HTTP POST,
//! `application/x-amz-json-1.1`), signed with AWS Signature Version 4
//! for service `kinesis` via the shared signer in `super`
//! (temp-session `x-amz-security-token` included when configured).
//!
//! Partial failures retry per record: a response with
//! `FailedRecordCount > 0` requeues only the entries carrying an
//! `ErrorCode` (e.g. `ProvisionedThroughputExceededException`,
//! `InternalFailure`) with jittered backoff; clean entries are never
//! resent. HTTP 429/500..=504 retry the whole batch; other non-2xx
//! statuses are terminal dispatch failures.

use async_trait::async_trait;
use base64::Engine;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use md5::Md5;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::{now_millis, render_template, BackoffState, BatchQueue, ConnectorError, Result, Sink};

pub const KINESIS_TARGET: &str = "Kinesis_20131202.PutRecords";
pub const KINESIS_CONTENT_TYPE: &str = "application/x-amz-json-1.1";

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
    Some(5)
}

fn default_initial_backoff_ms() -> Option<u64> {
    Some(100)
}

fn default_max_backoff_ms() -> Option<u64> {
    Some(3_000)
}

/// Kinesis sink configuration. All depths are optional (`None` =
/// unbounded) with zero clamped ceilings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KinesisSinkConfig {
    /// Target stream, e.g. `telemetry-stream`.
    pub stream_name: String,
    /// AWS region, e.g. `us-east-1`.
    pub region: String,
    /// Custom endpoint (LocalStack/testing); defaults to
    /// `https://kinesis.{region}.amazonaws.com`.
    #[serde(default)]
    pub endpoint: Option<String>,
    pub access_key_id: String,
    pub secret_access_key: String,
    /// STS session token for temporary credentials.
    #[serde(default)]
    pub session_token: Option<String>,
    /// Partition key template (`${client_id}`, `${topic}`,
    /// `${payload.<field>}`, `${timestamp}`, `${seq}`); falls back to
    /// the MD5 hex of the topic when absent or empty.
    #[serde(default)]
    pub partition_key_template: Option<String>,
    /// Explicit 128-bit hash key for shard targeting.
    #[serde(default)]
    pub explicit_hash_key: Option<String>,
    /// Records per `PutRecords` call (default 500, Kinesis cap).
    #[serde(default = "default_batch_size")]
    pub batch_size: Option<usize>,
    /// Batch byte limit over base64 payloads (default 4 MiB).
    #[serde(default = "default_batch_bytes")]
    pub batch_bytes: Option<usize>,
    /// Linger flush window in ms (default 20).
    #[serde(default = "default_linger_ms")]
    pub linger_ms: Option<u64>,
    /// Retries on throttles/partial failures (default 5, `None`
    /// unbounded, 0 none).
    #[serde(default = "default_max_retries")]
    pub max_retries: Option<usize>,
    /// First retry delay in ms (default 100).
    #[serde(default = "default_initial_backoff_ms")]
    pub initial_backoff_ms: Option<u64>,
    /// Retry delay ceiling in ms (default 3000).
    #[serde(default = "default_max_backoff_ms")]
    pub max_backoff_ms: Option<u64>,
    /// Request timeout in ms (default 5000).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

impl KinesisSinkConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.unwrap_or(5000).max(1))
    }

    pub fn validate(&self) -> Result<()> {
        if self.stream_name.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "kinesis stream_name must not be empty".to_string(),
            ));
        }
        if self.stream_name.len() > 128 {
            return Err(ConnectorError::Dispatch(
                "kinesis stream_name must be <= 128 chars".to_string(),
            ));
        }
        if self.region.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "kinesis region must not be empty".to_string(),
            ));
        }
        if let Some(endpoint) = &self.endpoint {
            if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
                return Err(ConnectorError::Dispatch(format!(
                    "kinesis endpoint must be http(s): {endpoint:?}"
                )));
            }
        }
        if self.access_key_id.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "kinesis access_key_id must not be empty".to_string(),
            ));
        }
        if self.secret_access_key.is_empty() {
            return Err(ConnectorError::Dispatch(
                "kinesis secret_access_key must not be empty".to_string(),
            ));
        }
        if let Some(template) = &self.partition_key_template {
            // Strict check with dummy values (empty template itself is
            // allowed: it selects the MD5 fallback).
            if !template.trim().is_empty() {
                self.resolve_partition_key(template, "dummy", b"{}", 0)?;
            }
        }
        if let Some(hash_key) = &self.explicit_hash_key {
            if hash_key.parse::<u128>().is_err() {
                return Err(ConnectorError::Dispatch(format!(
                    "kinesis explicit_hash_key must be a 128-bit integer string: {hash_key:?}"
                )));
            }
        }
        if self.batch_size == Some(0) {
            return Err(ConnectorError::Dispatch(
                "kinesis batch_size must be >= 1".to_string(),
            ));
        }
        if self.batch_bytes == Some(0) {
            return Err(ConnectorError::Dispatch(
                "kinesis batch_bytes must be >= 1".to_string(),
            ));
        }
        Ok(())
    }

    pub fn endpoint_url(&self) -> String {
        match &self.endpoint {
            Some(endpoint) => endpoint.trim_end_matches('/').to_string(),
            None => format!("https://kinesis.{}.amazonaws.com", self.region),
        }
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

    /// Derive the partition key: template substitution over
    /// `${client_id}` (JSON field, else empty), `${topic}`,
    /// `${payload.<field>}` (JSON extraction), `${timestamp}` and
    /// `${seq}`; MD5 hex of the topic when no template is configured
    /// or the template renders empty.
    pub fn resolve_partition_key(
        &self,
        template: &str,
        topic: &str,
        payload: &[u8],
        seq: u64,
    ) -> Result<String> {
        let millis = now_millis();
        let doc: serde_json::Value = serde_json::from_slice(payload).unwrap_or_default();
        let field = |name: &str| match doc.get(name) {
            Some(serde_json::Value::String(text)) => text.clone(),
            Some(scalar) if scalar.is_number() || scalar.is_boolean() => scalar.to_string(),
            _ => String::new(),
        };
        let mut extra: Vec<(String, String)> = Vec::new();
        extra.push(("client_id".to_string(), field("client_id")));
        let mut rest = template;
        while let Some(start) = rest.find("${payload.") {
            let after = &rest[start + "${payload.".len()..];
            if let Some(close) = after.find('}') {
                let name = &after[..close];
                extra.push((format!("payload.{name}"), field(name)));
                rest = &after[close + 1..];
            } else {
                break;
            }
        }
        let mut vars = vec![
            ("topic", topic.to_string()),
            ("timestamp", millis.to_string()),
            ("seq", seq.to_string()),
        ];
        for (key, value) in &extra {
            vars.push((key.as_str(), value.clone()));
        }
        let borrowed: Vec<(&str, String)> = vars.iter().map(|(k, v)| (*k, v.clone())).collect();
        let key = render_template(template, &borrowed)?;
        if key.trim().is_empty() {
            return Ok(md5_hex(topic.as_bytes()));
        }
        Ok(key)
    }

    /// Partition key for one event under this config (template or
    /// MD5 fallback).
    pub fn partition_key_for(&self, topic: &str, payload: &[u8], seq: u64) -> Result<String> {
        match &self.partition_key_template {
            Some(template) if !template.trim().is_empty() => {
                self.resolve_partition_key(template, topic, payload, seq)
            }
            _ => Ok(md5_hex(topic.as_bytes())),
        }
    }
}

fn md5_hex(data: &[u8]) -> String {
    let mut digest = Md5::new();
    digest.update(data);
    digest
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

// ---------------------------------------------------------------------------
// Wire framing: PutRecords JSON + SigV4.
// ---------------------------------------------------------------------------

/// One buffered record with its sequence number.
#[derive(Debug, Clone)]
struct KinesisRow {
    topic: String,
    payload: Vec<u8>,
    seq: u64,
}

/// One `PutRecords` entry on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KinesisRecordEntry {
    /// Base64-encoded payload.
    pub data_b64: String,
    pub partition_key: String,
    pub explicit_hash_key: Option<String>,
}

/// One `PutRecords` call.
#[derive(Debug, Clone)]
pub struct KinesisPutRecordsRequest {
    pub stream_name: String,
    pub records: Vec<KinesisRecordEntry>,
}

/// Per-record result inside a `PutRecords` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KinesisRecordResult {
    pub ok: bool,
    pub error_code: Option<String>,
    pub sequence_number: Option<String>,
}

/// Parsed `PutRecords` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KinesisPutRecordsResponse {
    pub failed_count: usize,
    pub results: Vec<KinesisRecordResult>,
}

impl KinesisPutRecordsResponse {
    /// Indices of the failed records, in order.
    pub fn failed_indices(&self) -> Vec<usize> {
        self.results
            .iter()
            .enumerate()
            .filter(|(_, result)| !result.ok)
            .map(|(index, _)| index)
            .collect()
    }
}

/// Render the `PutRecords` JSON body for entries.
pub fn render_put_records_body(stream: &str, records: &[KinesisRecordEntry]) -> Vec<u8> {
    let mut body = String::from("{\"StreamName\":");
    body.push_str(&serde_json::to_string(stream).unwrap_or_default());
    body.push_str(",\"Records\":[");
    for (index, record) in records.iter().enumerate() {
        if index > 0 {
            body.push(',');
        }
        body.push_str("{\"Data\":");
        body.push_str(&serde_json::to_string(&record.data_b64).unwrap_or_default());
        body.push_str(",\"PartitionKey\":");
        body.push_str(&serde_json::to_string(&record.partition_key).unwrap_or_default());
        if let Some(hash_key) = &record.explicit_hash_key {
            body.push_str(",\"ExplicitHashKey\":");
            body.push_str(&serde_json::to_string(hash_key).unwrap_or_default());
        }
        body.push('}');
    }
    body.push_str("]}");
    body.into_bytes()
}

/// Parse a `PutRecords` JSON response body.
pub fn parse_put_records_response(body: &[u8]) -> Result<KinesisPutRecordsResponse> {
    let doc: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| ConnectorError::Connection(format!("kinesis bad response JSON: {e}")))?;
    let failed_count = doc
        .get("FailedRecordCount")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    let mut results = Vec::new();
    if let Some(records) = doc.get("Records").and_then(|v| v.as_array()) {
        for record in records {
            let error_code = record
                .get("ErrorCode")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            results.push(KinesisRecordResult {
                ok: error_code.is_none(),
                error_code,
                sequence_number: record
                    .get("SequenceNumber")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
            });
        }
    }
    Ok(KinesisPutRecordsResponse {
        failed_count,
        results,
    })
}

/// Sign a `PutRecords` POST with SigV4 (service `kinesis`), returning
/// the `Authorization` value plus the `x-amz-date` stamp.
pub fn sign_put_records(
    access_key_id: &str,
    secret_access_key: &str,
    session_token: Option<&str>,
    region: &str,
    host: &str,
    body: &[u8],
    millis: i64,
) -> (String, String) {
    let payload_hash = super::sha256_hex(body);
    let date = super::amz_date(millis);
    let mut headers = vec![
        ("content-type".to_string(), KINESIS_CONTENT_TYPE.to_string()),
        ("host".to_string(), host.to_string()),
        ("x-amz-date".to_string(), date.clone()),
        ("x-amz-target".to_string(), KINESIS_TARGET.to_string()),
    ];
    if let Some(token) = session_token {
        headers.push(("x-amz-security-token".to_string(), token.to_string()));
    }
    let auth = super::sigv4_authorization(&super::SigV4Signing {
        method: "POST",
        canonical_uri: "/".to_string(),
        canonical_query: String::new(),
        headers,
        payload_hash,
        access_key_id,
        secret_access_key,
        region,
        service: "kinesis",
        millis,
    });
    (auth, date)
}

// ---------------------------------------------------------------------------
// Transport.
// ---------------------------------------------------------------------------

#[async_trait]
pub trait KinesisTransport: Send + Sync {
    async fn put_records(
        &self,
        req: &KinesisPutRecordsRequest,
    ) -> Result<KinesisPutRecordsResponse>;
}

/// Scripted per-call outcome for the mock transport.
#[derive(Debug, Clone)]
pub enum MockKinesisOutcome {
    /// HTTP-level failure (status; 429/500..=504 retry the batch).
    HttpStatus(u16),
    /// 200 with per-record results (`None` entry = clean record).
    Records(Vec<Option<String>>),
}

/// In-memory transport with scripted outcomes (tests, dry runs).
#[derive(Debug, Default)]
pub struct MockKinesisTransport {
    scripted: parking_lot::Mutex<std::collections::VecDeque<MockKinesisOutcome>>,
    captured: parking_lot::Mutex<Vec<KinesisPutRecordsRequest>>,
    calls: AtomicU64,
}

impl MockKinesisTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue outcomes consumed in order (default: all records clean).
    pub fn script_outcomes(&self, outcomes: Vec<MockKinesisOutcome>) {
        *self.scripted.lock() = outcomes.into_iter().collect();
    }

    pub fn captured(&self) -> Vec<KinesisPutRecordsRequest> {
        self.captured.lock().clone()
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl KinesisTransport for MockKinesisTransport {
    async fn put_records(
        &self,
        req: &KinesisPutRecordsRequest,
    ) -> Result<KinesisPutRecordsResponse> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.captured.lock().push(KinesisPutRecordsRequest {
            stream_name: req.stream_name.clone(),
            records: req.records.clone(),
        });
        match self.scripted.lock().pop_front() {
            None => Ok(KinesisPutRecordsResponse {
                failed_count: 0,
                results: req
                    .records
                    .iter()
                    .map(|_| KinesisRecordResult {
                        ok: true,
                        error_code: None,
                        sequence_number: Some("seq-1".to_string()),
                    })
                    .collect(),
            }),
            Some(MockKinesisOutcome::HttpStatus(status)) => Err(match status {
                429 | 500..=504 => {
                    ConnectorError::Connection(format!("mock kinesis throttled with {status}"))
                }
                _ => ConnectorError::Dispatch(format!("mock kinesis failed with {status}")),
            }),
            Some(MockKinesisOutcome::Records(errors)) => {
                let mut results = Vec::new();
                let mut failed_count = 0;
                for error in errors {
                    match error {
                        None => results.push(KinesisRecordResult {
                            ok: true,
                            error_code: None,
                            sequence_number: Some("seq-1".to_string()),
                        }),
                        Some(code) => {
                            failed_count += 1;
                            results.push(KinesisRecordResult {
                                ok: false,
                                error_code: Some(code),
                                sequence_number: None,
                            });
                        }
                    }
                }
                Ok(KinesisPutRecordsResponse {
                    failed_count,
                    results,
                })
            }
        }
    }
}

/// Production transport: signed `POST {endpoint}/` with the JSON body.
pub struct HttpKinesisTransport {
    endpoint: String,
    host: String,
    region: String,
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
    client: reqwest::Client,
}

impl HttpKinesisTransport {
    pub fn new(config: &KinesisSinkConfig, client: reqwest::Client) -> Result<Self> {
        config.validate()?;
        let endpoint = config.endpoint_url();
        let host = endpoint
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or_default()
            .to_string();
        Ok(Self {
            endpoint,
            host,
            region: config.region.clone(),
            access_key_id: config.access_key_id.clone(),
            secret_access_key: config.secret_access_key.clone(),
            session_token: config.session_token.clone(),
            client,
        })
    }
}

#[async_trait]
impl KinesisTransport for HttpKinesisTransport {
    async fn put_records(
        &self,
        req: &KinesisPutRecordsRequest,
    ) -> Result<KinesisPutRecordsResponse> {
        let body = render_put_records_body(&req.stream_name, &req.records);
        let millis = now_millis();
        let (auth, date) = sign_put_records(
            &self.access_key_id,
            &self.secret_access_key,
            self.session_token.as_deref(),
            &self.region,
            &self.host,
            &body,
            millis,
        );
        let mut request = self
            .client
            .post(&self.endpoint)
            .header(reqwest::header::CONTENT_TYPE, KINESIS_CONTENT_TYPE)
            .header("X-Amz-Target", KINESIS_TARGET)
            .header("X-Amz-Date", date)
            .header(reqwest::header::AUTHORIZATION, auth)
            .body(body);
        if let Some(token) = &self.session_token {
            request = request.header("X-Amz-Security-Token", token.as_str());
        }
        let response = request
            .send()
            .await
            .map_err(|e| ConnectorError::Connection(format!("kinesis put_records failed: {e}")))?;
        let status = response.status().as_u16();
        if status == 429 || (500..=504).contains(&status) {
            return Err(ConnectorError::Connection(format!(
                "kinesis throttled with {status}"
            )));
        }
        if !(200..=299).contains(&status) {
            return Err(ConnectorError::Dispatch(format!(
                "kinesis put_records failed with {status}"
            )));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|e| ConnectorError::Connection(format!("kinesis read failed: {e}")))?;
        parse_put_records_response(&bytes)
    }
}

// ---------------------------------------------------------------------------
// Sink.
// ---------------------------------------------------------------------------

struct KinesisBuffer {
    queue: BatchQueue<KinesisRow>,
    bytes: usize,
}

/// Kinesis sink: buffers events, ingests `PutRecords` batches with
/// per-record partial-failure retry.
pub struct KinesisSink {
    config: KinesisSinkConfig,
    transport: Arc<dyn KinesisTransport>,
    buffer: parking_lot::Mutex<KinesisBuffer>,
    backoff: parking_lot::Mutex<BackoffState>,
    seq: AtomicU64,
    sent_batches: AtomicU64,
    sent_records: AtomicU64,
}

impl KinesisSink {
    pub fn new(config: KinesisSinkConfig, transport: Arc<dyn KinesisTransport>) -> Result<Self> {
        config.validate()?;
        let linger = config.effective_linger();
        Ok(Self {
            buffer: parking_lot::Mutex::new(KinesisBuffer {
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

    pub fn config(&self) -> &KinesisSinkConfig {
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
        let max = self.config.max_backoff_ms.unwrap_or(3_000).max(1);
        let grown = initial
            .saturating_mul(2u64.saturating_pow(attempt.min(10) as u32))
            .min(max);
        let jitter = (now_millis().max(0) as u64) % (grown / 2 + 1);
        Duration::from_millis(grown.saturating_add(jitter).min(max.saturating_mul(2)))
    }

    /// Flush buffered rows (no-op when empty). Failed records requeue
    /// by themselves; whole-batch throttles retry everything. Any
    /// terminal outcome restores the pending set, engages backoff, and
    /// propagates.
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
        let max_retries = self.config.max_retries.unwrap_or(usize::MAX);
        let mut pending: Vec<KinesisRow> = rows;
        let mut attempt = 0usize;
        let total = pending.len() as u64;
        loop {
            let entries = self.entries_for(&pending)?;
            let request = KinesisPutRecordsRequest {
                stream_name: self.config.stream_name.clone(),
                records: entries,
            };
            match self.transport.put_records(&request).await {
                Ok(response) => {
                    let failed = response.failed_indices();
                    if failed.is_empty() {
                        self.backoff.lock().success();
                        self.sent_batches.fetch_add(1, Ordering::Relaxed);
                        self.sent_records.fetch_add(total, Ordering::Relaxed);
                        return Ok(());
                    }
                    if attempt >= max_retries {
                        return self.restore_err(
                            pending,
                            oldest,
                            taken_bytes,
                            ConnectorError::Connection(format!(
                                "kinesis {} partial failures after {attempt} retries",
                                response.failed_count
                            )),
                        );
                    }
                    attempt += 1;
                    tokio::time::sleep(self.backoff_delay(attempt)).await;
                    pending = failed
                        .into_iter()
                        .map(|index| pending[index].clone())
                        .collect();
                }
                Err(ConnectorError::Connection(message)) => {
                    if attempt >= max_retries {
                        return self.restore_err(
                            pending,
                            oldest,
                            taken_bytes,
                            ConnectorError::Connection(message),
                        );
                    }
                    attempt += 1;
                    tokio::time::sleep(self.backoff_delay(attempt)).await;
                }
                Err(e) => {
                    return self.restore_err(pending, oldest, taken_bytes, e);
                }
            }
        }
    }

    fn restore_err(
        &self,
        rows: Vec<KinesisRow>,
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

    /// Build wire entries for rows (base64 payloads + keys).
    fn entries_for(&self, rows: &[KinesisRow]) -> Result<Vec<KinesisRecordEntry>> {
        rows.iter()
            .map(|row| {
                Ok(KinesisRecordEntry {
                    data_b64: base64::engine::general_purpose::STANDARD.encode(&row.payload),
                    partition_key: self.config.partition_key_for(
                        &row.topic,
                        &row.payload,
                        row.seq,
                    )?,
                    explicit_hash_key: self.config.explicit_hash_key.clone(),
                })
            })
            .collect()
    }

    /// Validate + buffer one event. Returns true when the batch is
    /// full, stale, or over the byte limit (caller flushes).
    fn buffer_row(&self, topic: &Topic, payload: &Bytes, _qos: QoS) -> Result<bool> {
        if topic.as_str().is_empty() {
            return Err(ConnectorError::Dispatch(
                "kinesis row requires a non-empty topic".to_string(),
            ));
        }
        // Kinesis data blobs are binary-safe; UTF-8 is not required.
        // QoS rides inside the projected payload, not its own field.
        let row = KinesisRow {
            topic: topic.as_str().to_string(),
            payload: payload.to_vec(),
            seq: self.seq.fetch_add(1, Ordering::SeqCst),
        };
        // Base64 inflates ~4/3: account the wire size up front.
        let added = row.payload.len() * 4 / 3 + 64;
        let mut buffer = self.buffer.lock();
        let full = buffer.queue.push(row);
        buffer.bytes = buffer.bytes.saturating_add(added);
        Ok(full || buffer.bytes >= self.config.effective_batch_bytes())
    }
}

#[async_trait]
impl Sink for KinesisSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        if self.buffer_row(topic, payload, qos)? {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "kinesis"
    }
}

/// Management connector handle pairing an id with a Kinesis sink.
pub struct KinesisConnector {
    id: String,
    sink: Arc<KinesisSink>,
}

impl KinesisConnector {
    pub fn new(id: impl Into<String>, sink: Arc<KinesisSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }
}

impl super::Connector for KinesisConnector {
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

    fn test_config() -> KinesisSinkConfig {
        KinesisSinkConfig {
            stream_name: "telemetry-stream".to_string(),
            region: "us-east-1".to_string(),
            endpoint: None,
            access_key_id: "AKIDEXAMPLE".to_string(),
            secret_access_key: "secret".to_string(),
            session_token: None,
            partition_key_template: Some("${topic}".to_string()),
            explicit_hash_key: None,
            batch_size: Some(500),
            batch_bytes: Some(4_194_304),
            linger_ms: Some(20),
            max_retries: Some(5),
            initial_backoff_ms: Some(100),
            max_backoff_ms: Some(3_000),
        }
    }

    fn test_sink(config: KinesisSinkConfig) -> (Arc<KinesisSink>, Arc<MockKinesisTransport>) {
        let transport = Arc::new(MockKinesisTransport::new());
        let sink = Arc::new(KinesisSink::new(config, transport.clone()).unwrap());
        (sink, transport)
    }

    #[test]
    fn test_config_validation() {
        let mut config = test_config();
        assert!(config.validate().is_ok());
        assert_eq!(
            config.endpoint_url(),
            "https://kinesis.us-east-1.amazonaws.com"
        );

        config.stream_name.clear();
        assert!(config.validate().is_err());
        config.stream_name = "telemetry-stream".to_string();

        config.region.clear();
        assert!(config.validate().is_err());
        config.region = "eu-west-1".to_string();
        assert_eq!(
            config.endpoint_url(),
            "https://kinesis.eu-west-1.amazonaws.com"
        );
        config.region = "us-east-1".to_string();

        config.endpoint = Some("kinesis:4566".to_string());
        assert!(config.validate().is_err());
        config.endpoint = Some("http://127.0.0.1:4566/".to_string());
        assert!(config.validate().is_ok());
        assert_eq!(config.endpoint_url(), "http://127.0.0.1:4566");
        config.endpoint = None;

        config.partition_key_template = Some("${nope}".to_string());
        assert!(config.validate().is_err());
        config.partition_key_template = None;

        config.explicit_hash_key = Some("not-a-number".to_string());
        assert!(config.validate().is_err());
        config.explicit_hash_key = Some("123456789".to_string());
        assert!(config.validate().is_ok());
        config.explicit_hash_key = None;

        config.batch_size = Some(0);
        assert!(config.validate().is_err());
        // Unbounded + huge depths accepted: zero clamped ceilings.
        config.batch_size = None;
        config.batch_bytes = Some(10_000_000);
        config.max_retries = None;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_partition_key_templates_and_fallback() {
        let config = test_config();
        // ${topic} template.
        assert_eq!(
            config.partition_key_for("sensors/t1", b"{}", 0).unwrap(),
            "sensors/t1"
        );
        // ${payload.device_id} extraction.
        assert_eq!(
            config
                .resolve_partition_key("${payload.device_id}", "t", br#"{"device_id":"d42"}"#, 0)
                .unwrap(),
            "d42"
        );
        // Empty render falls back to MD5(topic).
        assert_eq!(
            config
                .resolve_partition_key("${client_id}", "sensors/t1", b"{}", 0)
                .unwrap(),
            md5_hex(b"sensors/t1")
        );
        // No template at all: MD5 fallback (32 lowercase hex).
        let mut fallback = test_config();
        fallback.partition_key_template = None;
        let key = fallback.partition_key_for("sensors/t1", b"{}", 0).unwrap();
        assert_eq!(key.len(), 32);
        assert!(key.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(key, md5_hex(b"sensors/t1"));
    }

    #[test]
    fn test_request_framing() {
        let entries = vec![KinesisRecordEntry {
            data_b64: "aGk=".to_string(),
            partition_key: "sensor-device-42".to_string(),
            explicit_hash_key: None,
        }];
        let body = render_put_records_body("telemetry-stream", &entries);
        assert_eq!(
            String::from_utf8(body).unwrap(),
            r#"{"StreamName":"telemetry-stream","Records":[{"Data":"aGk=","PartitionKey":"sensor-device-42"}]}"#
        );

        let hashed = KinesisRecordEntry {
            explicit_hash_key: Some("123".to_string()),
            ..entries[0].clone()
        };
        let body = String::from_utf8(render_put_records_body("s", &[hashed])).unwrap();
        assert!(body.contains("\"ExplicitHashKey\":\"123\""));

        // Response parsing: mixed clean/failed records.
        let response = parse_put_records_response(
            br#"{"FailedRecordCount":1,"Records":[{"SequenceNumber":"s1","ShardId":"shard-0"},{"ErrorCode":"ProvisionedThroughputExceededException","ErrorMessage":"slow down"}]}"#,
        )
        .unwrap();
        assert_eq!(response.failed_count, 1);
        assert_eq!(response.failed_indices(), vec![1]);
        assert_eq!(
            response.results[1].error_code.as_deref(),
            Some("ProvisionedThroughputExceededException")
        );
    }

    #[test]
    fn test_sigv4_known_answer() {
        // Independent Python (hmac/hashlib) vector: PutRecords of one
        // record to telemetry-stream at 2026-09-12T11:18:09Z.
        let body = br#"{"StreamName":"telemetry-stream","Records":[{"Data":"aGk=","PartitionKey":"sensor-device-42"}]}"#;
        let (auth, date) = sign_put_records(
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            None,
            "us-east-1",
            "kinesis.us-east-1.amazonaws.com",
            body,
            1_789_211_889_000,
        );
        assert_eq!(date, "20260912T111809Z");
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260912/us-east-1/kinesis/aws4_request, \
             SignedHeaders=content-type;host;x-amz-date;x-amz-target, \
             Signature=0f90b256e1b52143b6ddc33f5898810ef931460cf93e2e7ed793576e0dedd6db"
        );
    }

    #[tokio::test]
    async fn test_partial_failure_retries_only_failed() {
        let mut config = test_config();
        config.batch_size = Some(10);
        config.initial_backoff_ms = Some(1);
        config.max_backoff_ms = Some(2);
        let (sink, transport) = test_sink(config);
        // First pass: record 0 throttled, record 1 clean. Second pass:
        // the single requeued record succeeds.
        transport.script_outcomes(vec![
            MockKinesisOutcome::Records(vec![
                Some("ProvisionedThroughputExceededException".to_string()),
                None,
            ]),
            MockKinesisOutcome::Records(vec![None]),
        ]);

        let topic = Topic::new("t").unwrap();
        sink.send(&topic, &Bytes::from("a"), QoS::AtMostOnce)
            .await
            .unwrap();
        sink.send(&topic, &Bytes::from("b"), QoS::AtMostOnce)
            .await
            .unwrap();
        sink.flush().await.unwrap();

        assert_eq!(transport.calls(), 2);
        let captured = transport.captured();
        assert_eq!(captured.len(), 2);
        // First attempt carried both records...
        assert_eq!(captured[0].records.len(), 2);
        assert_eq!(captured[0].stream_name, "telemetry-stream");
        // ...the retry only the failed one (payload "a").
        assert_eq!(captured[1].records.len(), 1);
        let payload = base64::engine::general_purpose::STANDARD
            .decode(&captured[1].records[0].data_b64)
            .unwrap();
        assert_eq!(payload, b"a");
        assert_eq!(sink.sent_records(), 2);
        assert_eq!(sink.buffered_rows(), 0);
    }

    #[tokio::test]
    async fn test_retry_exhaustion_restores_everything() {
        let mut config = test_config();
        config.batch_size = Some(10);
        config.max_retries = Some(1);
        config.initial_backoff_ms = Some(1);
        config.max_backoff_ms = Some(2);
        let (sink, transport) = test_sink(config);
        transport.script_outcomes(vec![
            MockKinesisOutcome::Records(vec![Some("InternalFailure".to_string())]),
            MockKinesisOutcome::Records(vec![Some("InternalFailure".to_string())]),
        ]);

        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from("a"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        let err = sink.flush().await.expect_err("failures must exhaust");
        assert!(matches!(err, ConnectorError::Connection(_)));
        assert_eq!(transport.calls(), 2);
        assert_eq!(sink.buffered_rows(), 1);
        // Backoff engaged: immediate retry fails fast, no new call.
        assert!(sink.flush().await.is_err());
        assert_eq!(transport.calls(), 2);
    }

    #[test]
    fn test_session_token_changes_signature() {
        let body = br#"{"StreamName":"s","Records":[]}"#;
        let (plain, _) = sign_put_records(
            "AKID",
            "secret",
            None,
            "us-east-1",
            "kinesis.us-east-1.amazonaws.com",
            body,
            1_789_211_889_000,
        );
        let (with_token, _) = sign_put_records(
            "AKID",
            "secret",
            Some("session-token"),
            "us-east-1",
            "kinesis.us-east-1.amazonaws.com",
            body,
            1_789_211_889_000,
        );
        // STS tokens join the signed headers, so the signature must
        // differ; signing is deterministic per input.
        assert_ne!(plain, with_token);
        assert!(with_token.contains("/us-east-1/kinesis/aws4_request"));
        let (repeat, _) = sign_put_records(
            "AKID",
            "secret",
            Some("session-token"),
            "us-east-1",
            "kinesis.us-east-1.amazonaws.com",
            body,
            1_789_211_889_000,
        );
        assert_eq!(with_token, repeat);
    }

    #[tokio::test]
    async fn test_terminal_status_aborts() {
        let mut config = test_config();
        config.batch_size = Some(10);
        config.max_retries = Some(5);
        let (sink, transport) = test_sink(config);
        transport.script_outcomes(vec![MockKinesisOutcome::HttpStatus(400)]);

        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from("a"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        let err = sink.flush().await.expect_err("400 must fail");
        assert!(matches!(err, ConnectorError::Dispatch(_)));
        assert_eq!(transport.calls(), 1);
        assert_eq!(sink.buffered_rows(), 1);
    }
}
