//! Amazon S3 / MinIO / Ceph / R2 object-storage sink (INDRA-188).
//!
//! Buffers MQTT events as newline-delimited JSON (ndjson) micro-batches
//! and uploads one object per flush with HTTP `PUT /<bucket>/<key>`.
//! Object keys come from a partitioned [`S3SinkConfig::key_template`]
//! (`${topic}`, `${YYYY}`, `${MM}`, `${DD}`, `${seq}`). Payloads can
//! optionally ride gzip (`Content-Encoding: gzip`).
//!
//! Authentication uses AWS Signature Version 4 over the payload hash;
//! empty credentials mean anonymous access (local MinIO testing).
//! Batching, restore-on-failure and backoff reuse the shared
//! [`super::BatchQueue`] / [`super::BackoffState`] helpers, so failed
//! flushes keep the buffer, engage backoff, and propagate the error.

use async_trait::async_trait;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use flate2::write::GzEncoder;
use flate2::Compression as GzCompression;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::{
    now_millis, render_template, ymd_from_millis, BackoffState, BatchQueue, ConnectorError, Result,
    Sink,
};

/// Object body compression.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum S3Compression {
    /// Raw ndjson bytes.
    #[default]
    None,
    /// RFC 1952 gzip member (`Content-Encoding: gzip`).
    Gzip,
}

fn default_region() -> String {
    "us-east-1".to_string()
}

fn default_batch_size() -> usize {
    1_000
}

fn default_batch_bytes() -> usize {
    5 * 1024 * 1024
}

fn default_batch_timeout_ms() -> u64 {
    60_000
}

/// S3 sink configuration. Every depth is user-configurable with no
/// clamped ceiling, so batches scale to millions of events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct S3SinkConfig {
    /// Base endpoint, e.g. `https://s3.us-east-1.amazonaws.com` or
    /// `http://127.0.0.1:9000` (MinIO).
    pub endpoint: String,
    /// Target bucket (DNS-compatible S3 name).
    pub bucket: String,
    /// AWS region used for SigV4 scope (default `us-east-1`).
    #[serde(default = "default_region")]
    pub region: String,
    /// Access key id; empty means anonymous access.
    #[serde(default)]
    pub access_key_id: String,
    /// Secret access key; empty means anonymous access.
    #[serde(default)]
    pub secret_access_key: String,
    /// Partitioned key template, e.g.
    /// `telemetry/year=${YYYY}/month=${MM}/day=${DD}/${topic}_${seq}.ndjson`.
    pub key_template: String,
    /// Body compression (default none).
    #[serde(default)]
    pub compression: S3Compression,
    /// Flush trigger record count (default 1,000).
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    /// Flush trigger byte limit over buffered ndjson (default 5 MiB).
    #[serde(default = "default_batch_bytes")]
    pub batch_bytes: usize,
    /// Linger flush window (default 60,000 ms).
    #[serde(default = "default_batch_timeout_ms")]
    pub batch_timeout_ms: u64,
    /// Request timeout in ms (default 5000).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

impl S3SinkConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.unwrap_or(5000).max(1))
    }

    pub fn validate(&self) -> Result<()> {
        if !self.endpoint.starts_with("http://") && !self.endpoint.starts_with("https://") {
            return Err(ConnectorError::Dispatch(format!(
                "s3 endpoint must be http(s): {:?}",
                self.endpoint
            )));
        }
        validate_bucket(&self.bucket)?;
        if self.region.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "s3 region must not be empty".to_string(),
            ));
        }
        if self.key_template.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "s3 key_template must not be empty".to_string(),
            ));
        }
        // Strict template check with dummy values: unknown or unclosed
        // variables fail here, not on the hot path.
        self.resolve_key("dummy/topic", 0, 0)?;
        if self.batch_size == 0 {
            return Err(ConnectorError::Dispatch(
                "s3 batch_size must be >= 1".to_string(),
            ));
        }
        if self.batch_bytes == 0 {
            return Err(ConnectorError::Dispatch(
                "s3 batch_bytes must be >= 1".to_string(),
            ));
        }
        Ok(())
    }

    /// Render the object key for one flush: `${topic}` is sanitized to
    /// path-safe characters, `${YYYY}`/`${MM}`/`${DD}` come from
    /// `millis` (UTC), `${seq}` is the flush sequence number and
    /// `${uuid}` a fresh v4 id (restart-safe uniqueness on top of the
    /// monotonic-per-process `${seq}`).
    pub fn resolve_key(&self, topic: &str, seq: u64, millis: i64) -> Result<String> {
        if topic.is_empty() {
            return Err(ConnectorError::Dispatch(
                "s3 key requires a non-empty topic".to_string(),
            ));
        }
        let (year, month, day) = ymd_from_millis(millis);
        let vars = [
            ("topic", sanitize_topic(topic)),
            ("YYYY", format!("{year:04}")),
            ("MM", format!("{month:02}")),
            ("DD", format!("{day:02}")),
            ("seq", seq.to_string()),
            ("uuid", uuid::Uuid::new_v4().to_string()),
        ];
        let key = render_template(&self.key_template, &vars)?;
        if key.is_empty() || key.starts_with('/') {
            return Err(ConnectorError::Dispatch(format!(
                "s3 key_template resolved to an invalid key: {key:?}"
            )));
        }
        Ok(key)
    }
}

fn validate_bucket(bucket: &str) -> Result<()> {
    let bytes = bucket.as_bytes();
    if bytes.len() < 3 || bytes.len() > 63 {
        return Err(ConnectorError::Dispatch(format!(
            "s3 bucket must be 3..=63 chars: {bucket:?}"
        )));
    }
    let edge_ok = |b: u8| b.is_ascii_alphanumeric();
    if !edge_ok(bytes[0]) || !edge_ok(bytes[bytes.len() - 1]) {
        return Err(ConnectorError::Dispatch(format!(
            "s3 bucket must start/end alphanumeric: {bucket:?}"
        )));
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'.' || *b == b'-')
    {
        return Err(ConnectorError::Dispatch(format!(
            "s3 bucket must match [a-z0-9.-]: {bucket:?}"
        )));
    }
    Ok(())
}

/// Keep hierarchy separators; everything outside `[A-Za-z0-9._-/]`
/// becomes `_` so keys stay path/URI-safe.
fn sanitize_topic(topic: &str) -> String {
    topic
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// One buffered ndjson line plus the topic it arrived on (the flush
/// key is resolved per row and rows sharing a key share one object).
#[derive(Debug, Clone)]
struct S3Row {
    topic: String,
    line: String,
}

fn render_row(topic: &Topic, payload: &Bytes, qos: QoS, millis: i64) -> Result<S3Row> {
    let text = std::str::from_utf8(payload)
        .map_err(|_| ConnectorError::Dispatch("s3 payload must be UTF-8".to_string()))?;
    let value: serde_json::Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(_) => serde_json::Value::String(text.to_string()),
    };
    let line = serde_json::json!({
        "topic": topic.as_str(),
        "qos": u8::from(qos),
        "payload": value,
        "timestamp": super::rfc3339_millis(millis),
    })
    .to_string();
    Ok(S3Row {
        topic: topic.as_str().to_string(),
        line,
    })
}

fn gzip_bytes(raw: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), GzCompression::default());
    encoder
        .write_all(raw)
        .map_err(|e| ConnectorError::Dispatch(format!("s3 gzip failed: {e}")))?;
    encoder
        .finish()
        .map_err(|e| ConnectorError::Dispatch(format!("s3 gzip failed: {e}")))
}

// ---------------------------------------------------------------------------
// AWS Signature Version 4 (PUT, unsigned query, signed payload).
// ---------------------------------------------------------------------------

/// Inputs to [`sigv4_authorization`]: `PUT /<bucket>/<key>` with a
/// signed payload hash at `millis` (UTC).
pub struct SigV4Request<'a> {
    pub access_key_id: &'a str,
    pub secret_access_key: &'a str,
    pub region: &'a str,
    pub host: &'a str,
    pub bucket: &'a str,
    pub key: &'a str,
    pub payload_sha256_hex: &'a str,
    pub millis: i64,
}

/// Build the `Authorization` header value for `PUT /<bucket>/<key>`.
/// Public for the known-answer test; the transport calls it per flush.
/// Delegates to the shared SigV4 core in `super`.
pub fn sigv4_authorization(request: &SigV4Request<'_>) -> String {
    super::sigv4_authorization(&super::SigV4Signing {
        method: "PUT",
        canonical_uri: super::aws_encode_path(&format!("/{}/{}", request.bucket, request.key)),
        canonical_query: String::new(),
        headers: vec![
            ("host".to_string(), request.host.to_string()),
            (
                "x-amz-content-sha256".to_string(),
                request.payload_sha256_hex.to_string(),
            ),
            ("x-amz-date".to_string(), super::amz_date(request.millis)),
        ],
        payload_hash: request.payload_sha256_hex.to_string(),
        access_key_id: request.access_key_id,
        secret_access_key: request.secret_access_key,
        region: request.region,
        service: "s3",
        millis: request.millis,
    })
}

// ---------------------------------------------------------------------------
// Transport.
// ---------------------------------------------------------------------------

/// One object upload: bucket, key, body and content headers.
#[derive(Debug, Clone)]
pub struct S3Put {
    pub bucket: String,
    pub key: String,
    pub body: Vec<u8>,
    pub content_type: &'static str,
    pub content_encoding: Option<&'static str>,
}

#[async_trait]
pub trait S3Transport: Send + Sync {
    async fn put_object(&self, put: &S3Put) -> Result<()>;
}

/// In-memory transport recording every upload (tests, dry runs).
#[derive(Debug, Default)]
pub struct MockS3Transport {
    puts: parking_lot::Mutex<Vec<S3Put>>,
    failures_left: parking_lot::Mutex<usize>,
    calls: AtomicU64,
}

impl MockS3Transport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fail the next `n` uploads with a transport error (backoff tests).
    pub fn fail_next(&self, n: usize) {
        *self.failures_left.lock() = n;
    }

    pub fn puts(&self) -> Vec<S3Put> {
        self.puts.lock().clone()
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl S3Transport for MockS3Transport {
    async fn put_object(&self, put: &S3Put) -> Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut failures = self.failures_left.lock();
        if *failures > 0 {
            *failures -= 1;
            return Err(ConnectorError::Connection("mock s3 down".to_string()));
        }
        self.puts.lock().push(put.clone());
        Ok(())
    }
}

/// HTTP transport: `PUT {endpoint}/{bucket}/{key}` with SigV4 unless
/// the credentials are empty (anonymous MinIO testing).
pub struct HttpS3Transport {
    endpoint: String,
    region: String,
    access_key_id: String,
    secret_access_key: String,
    client: reqwest::Client,
}

impl HttpS3Transport {
    pub fn new(config: &S3SinkConfig, client: reqwest::Client) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            endpoint: config.endpoint.trim_end_matches('/').to_string(),
            region: config.region.clone(),
            access_key_id: config.access_key_id.clone(),
            secret_access_key: config.secret_access_key.clone(),
            client,
        })
    }
}

#[async_trait]
impl S3Transport for HttpS3Transport {
    async fn put_object(&self, put: &S3Put) -> Result<()> {
        let url = format!("{}/{}/{}", self.endpoint, put.bucket, put.key);
        let payload_hash = super::sha256_hex(&put.body);
        let mut request = self
            .client
            .put(&url)
            .header(reqwest::header::CONTENT_TYPE, put.content_type)
            .header("x-amz-content-sha256", &payload_hash)
            .body(put.body.clone());
        if let Some(encoding) = put.content_encoding {
            request = request.header(reqwest::header::CONTENT_ENCODING, encoding);
        }
        if !self.access_key_id.is_empty() {
            let host = self
                .endpoint
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .split('/')
                .next()
                .unwrap_or_default();
            let millis = now_millis();
            let date = super::amz_date(millis);
            let auth = sigv4_authorization(&SigV4Request {
                access_key_id: &self.access_key_id,
                secret_access_key: &self.secret_access_key,
                region: &self.region,
                host,
                bucket: &put.bucket,
                key: &put.key,
                payload_sha256_hex: &payload_hash,
                millis,
            });
            request = request
                .header("x-amz-date", date)
                .header(reqwest::header::AUTHORIZATION, auth);
        }
        let response = request
            .send()
            .await
            .map_err(|e| ConnectorError::Connection(format!("s3 put failed: {e}")))?;
        if !response.status().is_success() {
            return Err(ConnectorError::Dispatch(format!(
                "s3 {} answered {}",
                put.key,
                response.status()
            )));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Sink.
// ---------------------------------------------------------------------------

struct S3Buffer {
    queue: BatchQueue<S3Row>,
    bytes: usize,
}

/// S3 sink: buffers ndjson rows, uploads one object per flush.
pub struct S3Sink {
    config: S3SinkConfig,
    transport: Arc<dyn S3Transport>,
    buffer: parking_lot::Mutex<S3Buffer>,
    backoff: parking_lot::Mutex<BackoffState>,
    key_seq: AtomicU64,
    sent_objects: AtomicU64,
    sent_records: AtomicU64,
}

impl S3Sink {
    pub fn new(config: S3SinkConfig, transport: Arc<dyn S3Transport>) -> Result<Self> {
        config.validate()?;
        let linger = Duration::from_millis(config.batch_timeout_ms);
        Ok(Self {
            buffer: parking_lot::Mutex::new(S3Buffer {
                queue: BatchQueue::new(config.batch_size, linger),
                bytes: 0,
            }),
            config,
            transport,
            backoff: parking_lot::Mutex::new(BackoffState::default()),
            key_seq: AtomicU64::new(0),
            sent_objects: AtomicU64::new(0),
            sent_records: AtomicU64::new(0),
        })
    }

    pub fn config(&self) -> &S3SinkConfig {
        &self.config
    }

    pub fn sent_objects(&self) -> u64 {
        self.sent_objects.load(Ordering::Relaxed)
    }

    pub fn sent_records(&self) -> u64 {
        self.sent_records.load(Ordering::Relaxed)
    }

    pub fn buffered_rows(&self) -> usize {
        self.buffer.lock().queue.len()
    }

    pub fn buffered_bytes(&self) -> usize {
        self.buffer.lock().bytes
    }

    /// Flush buffered rows as one object per key group (no-op when
    /// empty). Rows share an object only when their key renders
    /// identically under the same `key_seq`/`now`. While backing off,
    /// fails fast without touching the transport. Any failure restores
    /// the failed group plus every unsent group, engages backoff,
    /// propagates.
    pub async fn flush(&self) -> Result<()> {
        self.backoff.lock().check()?;
        let (rows, oldest) = {
            let mut buffer = self.buffer.lock();
            let (rows, oldest) = buffer.queue.take_batch();
            buffer.bytes = 0;
            (rows, oldest)
        };
        if rows.is_empty() {
            return Ok(());
        }
        let key_seq = self.key_seq.fetch_add(1, Ordering::SeqCst);
        let now = now_millis();
        // Group by the key rendered with the same `key_seq`/`now`,
        // keeping first-seen group order. Rows whose key fails to
        // resolve share one `unkeyed/{key_seq}.ndjson` group so no row
        // overwrites another; one warn per flush names the count.
        let unkeyed_key = format!("unkeyed/{key_seq}.ndjson");
        let mut group_keys: Vec<String> = Vec::new();
        let mut group_index: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        let mut row_group: Vec<usize> = Vec::with_capacity(rows.len());
        let mut unkeyed_count = 0usize;
        let mut first_unkeyed_error: Option<String> = None;
        for row in &rows {
            match self.config.resolve_key(&row.topic, key_seq, now) {
                Ok(key) => {
                    if let Some(&gi) = group_index.get(&key) {
                        row_group.push(gi);
                    } else {
                        let gi = group_keys.len();
                        group_keys.push(key.clone());
                        group_index.insert(key, gi);
                        row_group.push(gi);
                    }
                }
                Err(e) => {
                    unkeyed_count += 1;
                    if first_unkeyed_error.is_none() {
                        first_unkeyed_error = Some(e.to_string());
                    }
                    if let Some(&gi) = group_index.get(&unkeyed_key) {
                        row_group.push(gi);
                    } else {
                        let gi = group_keys.len();
                        group_keys.push(unkeyed_key.clone());
                        group_index.insert(unkeyed_key.clone(), gi);
                        row_group.push(gi);
                    }
                }
            }
        }
        if unkeyed_count > 0 {
            tracing::warn!(
                unkeyed_count,
                error = %first_unkeyed_error.unwrap_or_default(),
                "s3 key resolution failed; using unkeyed fallback"
            );
        }
        let mut members: Vec<Vec<usize>> = vec![Vec::new(); group_keys.len()];
        for (ri, gi) in row_group.iter().enumerate() {
            members[*gi].push(ri);
        }
        for (gi, key) in group_keys.iter().enumerate() {
            let mut raw = String::new();
            for &ri in &members[gi] {
                raw.push_str(&rows[ri].line);
                raw.push('\n');
            }
            let (body, content_encoding) = match self.config.compression {
                S3Compression::None => (raw.into_bytes(), None),
                S3Compression::Gzip => match gzip_bytes(raw.as_bytes()) {
                    Ok(body) => (body, Some("gzip")),
                    Err(e) => {
                        let mut unsent = Vec::new();
                        let mut unsent_bytes = 0usize;
                        for (ri, row) in rows.into_iter().enumerate() {
                            if row_group[ri] >= gi {
                                unsent_bytes = unsent_bytes.saturating_add(row.line.len() + 1);
                                unsent.push(row);
                            }
                        }
                        let mut buffer = self.buffer.lock();
                        buffer.queue.restore(unsent, oldest);
                        buffer.bytes = buffer.bytes.saturating_add(unsent_bytes);
                        self.backoff.lock().failure();
                        return Err(e);
                    }
                },
            };
            let put = S3Put {
                bucket: self.config.bucket.clone(),
                key: key.clone(),
                body,
                content_type: "application/x-ndjson",
                content_encoding,
            };
            let record_count = members[gi].len() as u64;
            match self.transport.put_object(&put).await {
                Ok(()) => {
                    self.sent_objects.fetch_add(1, Ordering::Relaxed);
                    self.sent_records.fetch_add(record_count, Ordering::Relaxed);
                }
                Err(e) => {
                    let mut unsent = Vec::new();
                    let mut unsent_bytes = 0usize;
                    for (ri, row) in rows.into_iter().enumerate() {
                        if row_group[ri] >= gi {
                            unsent_bytes = unsent_bytes.saturating_add(row.line.len() + 1);
                            unsent.push(row);
                        }
                    }
                    let mut buffer = self.buffer.lock();
                    buffer.queue.restore(unsent, oldest);
                    buffer.bytes = buffer.bytes.saturating_add(unsent_bytes);
                    self.backoff.lock().failure();
                    return Err(e);
                }
            }
        }
        self.backoff.lock().success();
        Ok(())
    }

    /// Validate + buffer one event. Returns true when the batch is
    /// full, stale, or over the byte limit (caller flushes).
    fn buffer_row(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<bool> {
        if topic.as_str().is_empty() {
            return Err(ConnectorError::Dispatch(
                "s3 row requires a non-empty topic".to_string(),
            ));
        }
        let row = render_row(topic, payload, qos, now_millis())?;
        let added = row.line.len() + 1; // line plus its newline
        let mut buffer = self.buffer.lock();
        let full = buffer.queue.push(row);
        buffer.bytes = buffer.bytes.saturating_add(added);
        Ok(full || buffer.bytes >= self.config.batch_bytes)
    }
}

#[async_trait]
impl Sink for S3Sink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        if self.buffer_row(topic, payload, qos)? {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "s3"
    }
}

/// Management connector handle pairing an id with an S3 sink.
pub struct S3Connector {
    id: String,
    sink: Arc<S3Sink>,
}

impl S3Connector {
    pub fn new(id: impl Into<String>, sink: Arc<S3Sink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }
}

impl super::Connector for S3Connector {
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
    use flate2::read::GzDecoder;
    use std::io::Read;

    fn test_config() -> S3SinkConfig {
        S3SinkConfig {
            endpoint: "http://127.0.0.1:9000".to_string(),
            bucket: "telemetry-cold-store".to_string(),
            region: "us-east-1".to_string(),
            access_key_id: String::new(),
            secret_access_key: String::new(),
            key_template: "telemetry/year=${YYYY}/month=${MM}/day=${DD}/${topic}_${seq}.ndjson"
                .to_string(),
            compression: S3Compression::None,
            batch_size: 1_000,
            batch_bytes: 5 * 1024 * 1024,
            batch_timeout_ms: 60_000,
            timeout_ms: None,
        }
    }

    #[test]
    fn test_config_validation() {
        let mut config = test_config();
        assert!(config.validate().is_ok());

        config.endpoint = "127.0.0.1:9000".to_string();
        assert!(config.validate().is_err());
        config.endpoint = "http://127.0.0.1:9000".to_string();

        for bad in [
            "UPPER",
            "ab",
            "no_underscores",
            "-lead",
            "trail-",
            "has space",
        ] {
            config.bucket = bad.to_string();
            assert!(config.validate().is_err(), "bucket {bad:?} must fail");
        }
        config.bucket = "telemetry-cold-store".to_string();

        config.key_template = "telemetry/${nope}.ndjson".to_string();
        assert!(config.validate().is_err());
        config.key_template = "telemetry/${topic".to_string();
        assert!(config.validate().is_err());
        config.key_template = test_config().key_template;

        config.batch_size = 0;
        assert!(config.validate().is_err());
        config.batch_size = 1_000;

        config.batch_bytes = 0;
        assert!(config.validate().is_err());

        // Zero clamped ceilings: huge depths are accepted.
        config.batch_bytes = 1024;
        config.batch_size = 10_000_000;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_key_template_resolution() {
        let config = test_config();
        // 2026-09-12T11:18:09.123Z.
        let key = config
            .resolve_key("sensors/t1", 7, 1_789_211_889_123)
            .unwrap();
        assert_eq!(
            key,
            "telemetry/year=2026/month=09/day=12/sensors/t1_7.ndjson"
        );

        // Illegal path characters in topics are sanitized; hierarchy kept.
        let key = config.resolve_key("a/b+c d?e#f", 0, 0).unwrap();
        assert_eq!(
            key,
            "telemetry/year=1970/month=01/day=01/a/b_c_d_e_f_0.ndjson"
        );

        // `${uuid}` renders a unique v4 id per call.
        let mut uuid_config = test_config();
        uuid_config.key_template = "telemetry/${uuid}.ndjson".to_string();
        let first = uuid_config.resolve_key("t", 0, 0).unwrap();
        let second = uuid_config.resolve_key("t", 0, 0).unwrap();
        assert_ne!(first, second);
        let id = first
            .strip_prefix("telemetry/")
            .unwrap()
            .strip_suffix(".ndjson")
            .unwrap();
        assert_eq!(id.len(), 36);
        assert!(uuid::Uuid::parse_str(id).is_ok());

        assert!(config.resolve_key("", 0, 0).is_err());
    }

    #[tokio::test]
    async fn test_ndjson_framing() {
        let transport = Arc::new(MockS3Transport::new());
        let mut config = test_config();
        config.batch_size = 2;
        let sink = S3Sink::new(config, transport.clone()).unwrap();

        let topic = Topic::new("sensors/t1").unwrap();
        sink.send(&topic, &Bytes::from(r#"{"v":1}"#), QoS::AtMostOnce)
            .await
            .unwrap();
        assert_eq!(sink.buffered_rows(), 1);
        sink.flush().await.unwrap();
        let puts = transport.puts();
        assert_eq!(puts.len(), 1);
        assert_eq!(puts[0].bucket, "telemetry-cold-store");
        assert!(puts[0].key.ends_with("sensors/t1_0.ndjson"));
        assert_eq!(puts[0].content_type, "application/x-ndjson");
        assert_eq!(puts[0].content_encoding, None);

        let body = String::from_utf8(puts[0].body.clone()).unwrap();
        assert!(body.ends_with('\n'));
        assert_eq!(body.lines().count(), 1);
        let row: serde_json::Value = serde_json::from_str(body.trim_end()).unwrap();
        assert_eq!(row["topic"], "sensors/t1");
        assert_eq!(row["qos"], 0);
        assert_eq!(row["payload"], serde_json::json!({"v": 1}));
        let ts = row["timestamp"].as_str().unwrap();
        assert_eq!(ts.len(), 24);
        assert!(ts.ends_with('Z'));
    }

    #[test]
    fn test_gzip_framing_round_trip() {
        let raw = b"{\"a\":1}\n{\"b\":2}\n";
        let gz = gzip_bytes(raw).unwrap();
        assert_eq!(&gz[..2], &[0x1f, 0x8b], "gzip magic");
        let mut decoder = GzDecoder::new(&gz[..]);
        let mut back = Vec::new();
        decoder.read_to_end(&mut back).unwrap();
        assert_eq!(back, raw);
    }

    #[tokio::test]
    async fn test_batch_triggers_count_and_bytes() {
        // Count trigger.
        let transport = Arc::new(MockS3Transport::new());
        let mut config = test_config();
        config.batch_size = 2;
        let sink = S3Sink::new(config, transport.clone()).unwrap();
        let topic = Topic::new("t").unwrap();
        sink.send(&topic, &Bytes::from("{}"), QoS::AtMostOnce)
            .await
            .unwrap();
        assert_eq!(sink.sent_objects(), 0);
        sink.send(&topic, &Bytes::from("{}"), QoS::AtMostOnce)
            .await
            .unwrap();
        assert_eq!(sink.sent_objects(), 1);
        assert_eq!(sink.sent_records(), 2);

        // Byte trigger below one row: every row flushes.
        let transport = Arc::new(MockS3Transport::new());
        let mut config = test_config();
        config.batch_size = 1_000_000;
        config.batch_bytes = 10;
        let sink = S3Sink::new(config, transport.clone()).unwrap();
        sink.send(&topic, &Bytes::from("{}"), QoS::AtMostOnce)
            .await
            .unwrap();
        assert_eq!(sink.sent_objects(), 1);
        assert_eq!(sink.buffered_bytes(), 0);
    }

    #[tokio::test]
    async fn test_failure_retains_buffer_and_backs_off() {
        let transport = Arc::new(MockS3Transport::new());
        transport.fail_next(100);
        let mut config = test_config();
        config.batch_size = 10;
        let sink = S3Sink::new(config, transport.clone()).unwrap();
        let topic = Topic::new("t").unwrap();
        sink.send(&topic, &Bytes::from("{}"), QoS::AtMostOnce)
            .await
            .unwrap();
        let bytes = sink.buffered_bytes();
        assert!(bytes > 0);
        let err = sink.flush().await.expect_err("mock down must fail");
        assert!(matches!(err, ConnectorError::Connection(_)));
        // Rows + byte count retained; backoff fails fast without a call.
        assert_eq!(sink.buffered_rows(), 1);
        assert_eq!(sink.buffered_bytes(), bytes);
        let calls = transport.calls();
        assert!(sink.flush().await.is_err());
        assert_eq!(transport.calls(), calls);
        assert_eq!(sink.sent_objects(), 0);
    }

    #[test]
    fn test_sigv4_known_answer() {
        // Independent Python (hmac/hashlib) vector: PUT of
        // b'{"topic":"s/t"}\n' to telemetry-cold-store with AKIDEXAMPLE
        // at 2026-09-12T11:18:09Z (1_789_211_889_000 ms).
        let payload_hash = "c0c225274b3d9e370140ebc07626ce52cb6907569b47f793bfc3c7dff8cf233b";
        let auth = sigv4_authorization(&SigV4Request {
            access_key_id: "AKIDEXAMPLE",
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            region: "us-east-1",
            host: "s3.us-east-1.amazonaws.com",
            bucket: "telemetry-cold-store",
            key: "telemetry/year=2026/month=09/day=12/sensors_7.ndjson",
            payload_sha256_hex: payload_hash,
            millis: 1_789_211_889_000,
        });
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260912/us-east-1/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
             Signature=54b9cbdbd7a85d624f7dfa9adad6e1ba873e991b117d420451f1cc4dac8e5331"
        );
    }

    /// Test-only transport failing exactly one call number (1-indexed).
    struct FailNthTransport {
        puts: parking_lot::Mutex<Vec<S3Put>>,
        calls: AtomicU64,
        fail_on_call: u64,
    }

    impl FailNthTransport {
        fn new(fail_on_call: u64) -> Self {
            Self {
                puts: parking_lot::Mutex::new(Vec::new()),
                calls: AtomicU64::new(0),
                fail_on_call,
            }
        }

        fn puts(&self) -> Vec<S3Put> {
            self.puts.lock().clone()
        }
    }

    #[async_trait]
    impl S3Transport for FailNthTransport {
        async fn put_object(&self, put: &S3Put) -> Result<()> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if call == self.fail_on_call {
                return Err(ConnectorError::Connection("mock s3 down".to_string()));
            }
            self.puts.lock().push(put.clone());
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_mixed_topics_write_one_object_per_topic() {
        let transport = Arc::new(MockS3Transport::new());
        let mut config = test_config();
        config.key_template = "keys/${topic}-${seq}.ndjson".to_string();
        config.batch_size = 1_000;
        let sink = S3Sink::new(config, transport.clone()).unwrap();

        for topic in ["a/x", "b/y", "a/x"] {
            sink.send(
                &Topic::new(topic).unwrap(),
                &Bytes::from("{}"),
                QoS::AtMostOnce,
            )
            .await
            .unwrap();
        }
        assert_eq!(sink.buffered_rows(), 3);
        sink.flush().await.unwrap();

        let puts = transport.puts();
        assert_eq!(puts.len(), 2, "one object per topic, got {puts:?}");
        assert_eq!(puts[0].key, "keys/a/x-0.ndjson");
        assert_eq!(puts[1].key, "keys/b/y-0.ndjson");
        let first_body = String::from_utf8(puts[0].body.clone()).unwrap();
        let second_body = String::from_utf8(puts[1].body.clone()).unwrap();
        assert_eq!(first_body.lines().count(), 2);
        assert_eq!(second_body.lines().count(), 1);
        for line in first_body.lines() {
            let row: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(row["topic"], "a/x");
        }
        let row: serde_json::Value =
            serde_json::from_str(second_body.lines().next().unwrap()).unwrap();
        assert_eq!(row["topic"], "b/y");
        assert_eq!(sink.sent_objects(), 2);
        assert_eq!(sink.sent_records(), 3);
        assert_eq!(sink.buffered_rows(), 0);
    }

    #[tokio::test]
    async fn test_failed_second_object_restores_only_unsent() {
        let transport = Arc::new(FailNthTransport::new(2));
        let mut config = test_config();
        config.key_template = "keys/${topic}-${seq}.ndjson".to_string();
        config.batch_size = 1_000;
        let sink = S3Sink::new(config, transport.clone()).unwrap();

        sink.send(
            &Topic::new("a/x").unwrap(),
            &Bytes::from("{}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        sink.send(
            &Topic::new("b/y").unwrap(),
            &Bytes::from("{}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        let err = sink.flush().await.expect_err("second put must fail");
        assert!(matches!(err, ConnectorError::Connection(_)));
        // First group uploaded, second group restored.
        assert_eq!(sink.sent_objects(), 1);
        assert_eq!(sink.sent_records(), 1);
        assert_eq!(sink.buffered_rows(), 1);
        let puts = transport.puts();
        assert_eq!(puts.len(), 1);
        assert_eq!(puts[0].key, "keys/a/x-0.ndjson");
        assert!(sink.buffered_bytes() > 0);
    }

    #[tokio::test]
    async fn test_unkeyed_rows_share_one_object() {
        // `resolve_key` fails when the sanitized topic leaves a key
        // starting with '/': template `${topic}-${seq}.ndjson` with a
        // leading-slash topic such as `/a` renders `/a-0.ndjson`.
        let transport = Arc::new(MockS3Transport::new());
        let mut config = test_config();
        config.key_template = "${topic}-${seq}.ndjson".to_string();
        config.batch_size = 1_000;
        let sink = S3Sink::new(config, transport.clone()).unwrap();

        for topic in ["/a", "/b", "ok/topic"] {
            sink.send(
                &Topic::new(topic).unwrap(),
                &Bytes::from("{}"),
                QoS::AtMostOnce,
            )
            .await
            .unwrap();
        }
        assert_eq!(sink.buffered_rows(), 3);
        sink.flush().await.unwrap();

        let puts = transport.puts();
        assert_eq!(
            puts.len(),
            2,
            "one unkeyed object + one normal, got {puts:?}"
        );
        let unkeyed: Vec<&S3Put> = puts
            .iter()
            .filter(|put| put.key.starts_with("unkeyed/"))
            .collect();
        assert_eq!(unkeyed.len(), 1, "unkeyed rows must share one object");
        assert_eq!(unkeyed[0].key, "unkeyed/0.ndjson");
        let body = String::from_utf8(unkeyed[0].body.clone()).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2, "both unkeyed rows in one body");
        let mut topics: Vec<String> = lines
            .iter()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).unwrap()["topic"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        topics.sort();
        assert_eq!(topics, vec!["/a".to_string(), "/b".to_string()]);
        let normal: Vec<&S3Put> = puts
            .iter()
            .filter(|put| !put.key.starts_with("unkeyed/"))
            .collect();
        assert_eq!(normal.len(), 1);
        let normal_body = String::from_utf8(normal[0].body.clone()).unwrap();
        assert_eq!(normal_body.lines().count(), 1);
        let row: serde_json::Value =
            serde_json::from_str(normal_body.lines().next().unwrap()).unwrap();
        assert_eq!(row["topic"], "ok/topic");
        assert_eq!(sink.sent_objects(), 2);
        assert_eq!(sink.sent_records(), 3);
        assert_eq!(sink.buffered_rows(), 0);
    }
}
