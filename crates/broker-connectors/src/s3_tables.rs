//! Amazon S3 Tables / Apache Iceberg lakehouse sink (INDRA-191).
//!
//! Buffers MQTT events as ndjson micro-batches and uploads one
//! gzip data file per flush over the S3 REST API with SigV4, using
//! Iceberg / S3 Tables layout conventions:
//!
//! ```text
//! data/${partition_path}/${uuid}.data.gz
//! ```
//!
//! e.g. `data/date_day=2026-09-12/device_id=sensor-42/98a7….data.gz`.
//! Partition directories derive from the record timestamp through the
//! Year, Month, Day and Hour transforms, plus Identity dimension
//! fields. A JSON snapshot document with the schema, a manifest
//! pointer and a partition summary frames every commit for catalog
//! readers.
//! Batching, restore-on-failure and backoff reuse the shared
//! [`super::BatchQueue`] / [`super::BackoffState`] helpers.

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
    hms_milli_from_millis, now_millis, ymd_from_millis, BackoffState, BatchQueue, ConnectorError,
    Result, Sink,
};

/// Iceberg partition transform over a source column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IcebergTransform {
    /// Raw dimension value (`device_id=sensor-42`).
    Identity,
    /// `date_year=2026` from the record timestamp.
    Year,
    /// `date_month=2026-09` from the record timestamp.
    Month,
    /// `date_day=2026-09-12` from the record timestamp.
    Day,
    /// `date_hour=2026-09-12-11` from the record timestamp.
    Hour,
}

/// One Iceberg partition field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IcebergPartitionField {
    /// Source column: `date` (record timestamp) or a dimension name
    /// (`device_id`, `client_id`, `topic`).
    pub source_name: String,
    /// Transform applied to the source column.
    pub transform: IcebergTransform,
}

/// Data-file payload codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum S3TablesFormat {
    /// Gzip-compressed ndjson (`*.data.gz`, today's workhorse).
    #[default]
    NdjsonCompressed,
    /// Reserved marker for a future columnar writer; currently
    /// encodes ndjson with a `.parquet` suffix so catalogs can stage
    /// the layout before the encoder lands.
    ParquetPlaceholder,
}

fn default_batch_size() -> Option<usize> {
    Some(1_000)
}

fn default_linger_ms() -> Option<u64> {
    Some(1_000)
}

/// S3 Tables sink configuration. Every depth is user-configurable
/// with no clamped ceiling (`None` = unbounded).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct S3TablesSinkConfig {
    /// S3 Tables bucket ARN, e.g.
    /// `arn:aws:s3tables:us-east-1:123456789012:bucket/telemetry-bucket`.
    pub table_bucket_arn: String,
    /// Iceberg namespace / database name, e.g. `production_iot`.
    pub namespace: String,
    /// Target table name, e.g. `device_events`.
    pub table_name: String,
    /// AWS region string, e.g. `us-east-1`.
    pub region: String,
    /// AWS Access Key ID.
    pub access_key_id: String,
    /// AWS Secret Access Key.
    pub secret_access_key: String,
    /// Temporary STS session token.
    #[serde(default)]
    pub session_token: Option<String>,
    /// Custom endpoint (LocalStack / MinIO testing).
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Iceberg partition spec (order = directory order).
    #[serde(default)]
    pub partition_spec: Vec<IcebergPartitionField>,
    /// Data-file payload codec (default gzip ndjson).
    #[serde(default)]
    pub target_format: S3TablesFormat,
    /// Flush trigger record count (default 1,000).
    #[serde(default = "default_batch_size")]
    pub batch_size: Option<usize>,
    /// Buffer capacity (`None` = unbounded).
    #[serde(default)]
    pub buffer_capacity: Option<usize>,
    /// Linger flush window in ms (default 1,000).
    #[serde(default = "default_linger_ms")]
    pub linger_ms: Option<u64>,
    /// Request timeout in ms (default 5000).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

impl S3TablesSinkConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.unwrap_or(5000).max(1))
    }

    pub fn validate(&self) -> Result<()> {
        parse_table_bucket_arn(&self.table_bucket_arn)
            .map_err(|e| ConnectorError::Dispatch(format!("s3_tables table_bucket_arn: {e}")))?;
        if self.namespace.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "s3_tables namespace must not be empty".to_string(),
            ));
        }
        if self.table_name.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "s3_tables table_name must not be empty".to_string(),
            ));
        }
        if self.region.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "s3_tables region must not be empty".to_string(),
            ));
        }
        if self.access_key_id.trim().is_empty() || self.secret_access_key.is_empty() {
            return Err(ConnectorError::Dispatch(
                "s3_tables access_key_id/secret_access_key must not be empty".to_string(),
            ));
        }
        for field in &self.partition_spec {
            if field.source_name.trim().is_empty() {
                return Err(ConnectorError::Dispatch(
                    "s3_tables partition source_name must not be empty".to_string(),
                ));
            }
        }
        if self.batch_size == Some(0) {
            return Err(ConnectorError::Dispatch(
                "s3_tables batch_size must be >= 1".to_string(),
            ));
        }
        Ok(())
    }

    /// Service endpoint host for SigV4 (`s3tables.{region}.amazonaws.com`
    /// unless overridden for LocalStack / MinIO testing).
    pub fn endpoint_host(&self) -> String {
        match &self.endpoint {
            Some(custom) => custom
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .trim_end_matches('/')
                .to_string(),
            None => format!("s3tables.{}.amazonaws.com", self.region),
        }
    }

    /// Request scheme: custom endpoints keep their own scheme,
    /// production S3 Tables is always https.
    pub fn endpoint_scheme(&self) -> &'static str {
        match &self.endpoint {
            Some(custom) if custom.starts_with("http://") => "http",
            _ => "https",
        }
    }

    /// SigV4 service name: `s3tables` in production, `s3` against a
    /// custom S3-compatible endpoint.
    pub fn sigv4_service(&self) -> &'static str {
        if self.endpoint.is_some() {
            "s3"
        } else {
            "s3tables"
        }
    }

    pub(crate) fn effective_batch_size(&self) -> usize {
        self.batch_size.unwrap_or(usize::MAX)
    }

    pub(crate) fn effective_buffer(&self) -> usize {
        self.buffer_capacity.unwrap_or(usize::MAX)
    }

    pub(crate) fn linger(&self) -> Duration {
        Duration::from_millis(self.linger_ms.unwrap_or(1_000).max(1))
    }
}

/// Parsed S3 Tables bucket ARN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableBucketArn {
    pub region: String,
    pub account_id: String,
    pub bucket: String,
}

/// Parse `arn:aws:s3tables:{region}:{account}:bucket/{bucket}`.
/// Anything else is a dispatch error naming the offending ARN.
pub fn parse_table_bucket_arn(arn: &str) -> std::result::Result<TableBucketArn, String> {
    let parts: Vec<&str> = arn.splitn(6, ':').collect();
    if parts.len() != 6
        || parts[0] != "arn"
        || parts[1] != "aws"
        || parts[2] != "s3tables"
        || parts[3].is_empty()
        || parts[4].is_empty()
    {
        return Err(format!("not an s3tables bucket ARN: {arn:?}"));
    }
    if !parts[4].bytes().all(|b| b.is_ascii_digit()) || parts[4].len() != 12 {
        return Err(format!("s3tables ARN needs a 12-digit account id: {arn:?}"));
    }
    match parts[5].strip_prefix("bucket/") {
        Some(bucket) if !bucket.is_empty() && !bucket.contains('/') => Ok(TableBucketArn {
            region: parts[3].to_string(),
            account_id: parts[4].to_string(),
            bucket: bucket.to_string(),
        }),
        _ => Err(format!(
            "s3tables ARN needs resource bucket/<name>: {arn:?}"
        )),
    }
}

// ---------------------------------------------------------------------------
// Partitioning.
// ---------------------------------------------------------------------------

/// Apply one partition transform: time transforms render from
/// `millis` (UTC), identity passes the dimension value through after
/// sanitizing it to path-safe characters.
pub fn apply_partition_transform(
    transform: IcebergTransform,
    source_name: &str,
    dimension: &str,
    millis: i64,
) -> String {
    let field = match source_name {
        "date" => "date".to_string(),
        other => other.to_string(),
    };
    match transform {
        IcebergTransform::Identity => {
            format!("{field}={}", sanitize_segment(dimension))
        }
        IcebergTransform::Year => {
            let (year, _, _) = ymd_from_millis(millis);
            format!("{field}_year={year:04}")
        }
        IcebergTransform::Month => {
            let (year, month, _) = ymd_from_millis(millis);
            format!("{field}_month={year:04}-{month:02}")
        }
        IcebergTransform::Day => {
            let (year, month, day) = ymd_from_millis(millis);
            format!("{field}_day={year:04}-{month:02}-{day:02}")
        }
        IcebergTransform::Hour => {
            let (year, month, day) = ymd_from_millis(millis);
            let (hour, _, _, _) = hms_milli_from_millis(millis);
            format!("{field}_hour={year:04}-{month:02}-{day:02}-{hour:02}")
        }
    }
}

/// Keep `[A-Za-z0-9._-]`; everything else becomes `_` so partition
/// directories stay URI-safe. Empty values become `__null__` (Hive
/// convention) instead of vanishing.
fn sanitize_segment(value: &str) -> String {
    if value.is_empty() {
        return "__null__".to_string();
    }
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '=') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Build the partition directory for one record: spec order, joined
/// with `/` (`date_day=2026-09-12/device_id=sensor-42`). The `date`
/// source renders from the record timestamp; any other source reads
/// from `dims` (missing = `__null__`).
pub fn partition_path(
    spec: &[IcebergPartitionField],
    dims: &[(&str, String)],
    millis: i64,
) -> String {
    spec.iter()
        .map(|field| {
            let dimension = if field.source_name == "date" {
                String::new()
            } else {
                dims.iter()
                    .find(|(name, _)| *name == field.source_name)
                    .map(|(_, value)| value.clone())
                    .unwrap_or_default()
            };
            apply_partition_transform(field.transform, &field.source_name, &dimension, millis)
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Data-file object key: `data/${partition_path}/${uuid}.data.gz`
/// (or `.data.parquet` for the placeholder codec).
pub fn data_file_path(partition: &str, format: S3TablesFormat) -> String {
    let suffix = match format {
        S3TablesFormat::NdjsonCompressed => "data.gz",
        S3TablesFormat::ParquetPlaceholder => "data.parquet",
    };
    let uuid = uuid::Uuid::new_v4();
    if partition.is_empty() {
        format!("data/{uuid}.{suffix}")
    } else {
        format!("data/{partition}/{uuid}.{suffix}")
    }
}

// ---------------------------------------------------------------------------
// Snapshot metadata framing.
// ---------------------------------------------------------------------------

/// One committed data file referenced by a snapshot.
#[derive(Debug, Clone)]
pub struct SnapshotFile {
    pub path: String,
    pub record_count: u64,
    pub size_bytes: u64,
    pub partition: String,
}

/// Build the JSON snapshot document for one commit: schema, manifest
/// pointer, file list and per-partition record summary.
pub fn render_snapshot(
    namespace: &str,
    table: &str,
    snapshot_id: u64,
    millis: i64,
    files: &[SnapshotFile],
) -> Vec<u8> {
    let mut summary: std::collections::BTreeMap<String, u64> = Default::default();
    let mut total_records = 0u64;
    for file in files {
        *summary.entry(file.partition.clone()).or_default() += file.record_count;
        total_records += file.record_count;
    }
    serde_json::json!({
        "format_version": 2,
        "snapshot_id": snapshot_id,
        "timestamp_ms": millis,
        "table": format!("{namespace}.{table}"),
        "schema": {
            "fields": [
                {"name": "topic", "type": "string", "id": 1},
                {"name": "qos", "type": "int", "id": 2},
                {"name": "payload", "type": "string", "id": 3},
                {"name": "timestamp", "type": "timestamptz", "id": 4},
            ]
        },
        "manifest": {
            "path": format!("metadata/snap-{snapshot_id}.avro"),
            "partition_summary": summary,
            "total_records": total_records,
        },
        "data_files": files.iter().map(|file| {
            serde_json::json!({
                "path": file.path,
                "partition": file.partition,
                "record_count": file.record_count,
                "size_bytes": file.size_bytes,
            })
        }).collect::<Vec<_>>(),
    })
    .to_string()
    .into_bytes()
}

// ---------------------------------------------------------------------------
// SigV4 for S3 Tables endpoints (shared core).
// ---------------------------------------------------------------------------

/// Inputs to [`s3tables_authorization`]: `PUT /{key}` with a signed
/// payload hash at `millis` (UTC).
pub struct S3TablesSigning<'a> {
    pub access_key_id: &'a str,
    pub secret_access_key: &'a str,
    pub session_token: Option<&'a str>,
    pub region: &'a str,
    pub service: &'a str,
    pub host: &'a str,
    pub key: &'a str,
    pub payload_sha256_hex: &'a str,
    pub millis: i64,
}

/// Build the `Authorization` header value for `PUT /{key}` plus the
/// `x-amz-date` value. Delegates to the shared SigV4 core in `super`.
/// Public for the known-answer test; the transport calls it per flush.
pub fn s3tables_authorization(signing: &S3TablesSigning<'_>) -> (String, String) {
    let mut headers = vec![
        ("host".to_string(), signing.host.to_string()),
        (
            "x-amz-content-sha256".to_string(),
            signing.payload_sha256_hex.to_string(),
        ),
        ("x-amz-date".to_string(), super::amz_date(signing.millis)),
    ];
    if let Some(token) = signing.session_token {
        headers.push(("x-amz-security-token".to_string(), token.to_string()));
    }
    let auth = super::sigv4_authorization(&super::SigV4Signing {
        method: "PUT",
        canonical_uri: super::aws_encode_path(&format!("/{}", signing.key)),
        canonical_query: String::new(),
        headers,
        payload_hash: signing.payload_sha256_hex.to_string(),
        access_key_id: signing.access_key_id,
        secret_access_key: signing.secret_access_key,
        region: signing.region,
        service: signing.service,
        millis: signing.millis,
    });
    (auth, super::amz_date(signing.millis))
}

// ---------------------------------------------------------------------------
// Transport.
// ---------------------------------------------------------------------------

/// One data-file upload: object key, body and content headers.
#[derive(Debug, Clone)]
pub struct S3TablesPut {
    pub key: String,
    pub body: Vec<u8>,
    pub content_type: &'static str,
    pub content_encoding: Option<&'static str>,
}

/// Classified PUT outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S3TablesOutcome {
    Success,
    Retryable,
    Terminal,
}

/// 403 is terminal (bad credentials / policy); 500/503 (and 429)
/// retry with backoff; other 2xx succeed; other 4xx are terminal
/// dispatch errors; other 5xx are retryable.
pub fn classify_put_status(status: u16) -> S3TablesOutcome {
    match status {
        200..=299 => S3TablesOutcome::Success,
        403 => S3TablesOutcome::Terminal,
        429 | 500 | 503 => S3TablesOutcome::Retryable,
        400..=499 => S3TablesOutcome::Terminal,
        _ => S3TablesOutcome::Retryable,
    }
}

#[async_trait]
pub trait S3TablesTransport: Send + Sync {
    async fn put_object(&self, put: &S3TablesPut, date: &str, authorization: &str) -> Result<()>;
}

/// In-memory transport recording every upload (tests, dry runs).
#[derive(Debug, Default)]
pub struct MockS3TablesTransport {
    puts: parking_lot::Mutex<Vec<S3TablesPut>>,
    failures_left: parking_lot::Mutex<usize>,
    calls: AtomicU64,
    pub last_authorization: parking_lot::Mutex<Option<String>>,
}

impl MockS3TablesTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fail the next `n` uploads with a transport error (backoff tests).
    pub fn fail_next(&self, n: usize) {
        *self.failures_left.lock() = n;
    }

    pub fn puts(&self) -> Vec<S3TablesPut> {
        self.puts.lock().clone()
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl S3TablesTransport for MockS3TablesTransport {
    async fn put_object(&self, put: &S3TablesPut, _date: &str, authorization: &str) -> Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.last_authorization.lock() = Some(authorization.to_string());
        let mut failures = self.failures_left.lock();
        if *failures > 0 {
            *failures -= 1;
            return Err(ConnectorError::Connection("mock s3tables down".to_string()));
        }
        self.puts.lock().push(put.clone());
        Ok(())
    }
}

/// HTTP transport: `PUT {scheme}://{host}/{key}` with the SigV4
/// `Authorization` + `x-amz-date` headers (plus the session token when
/// temporary STS credentials are configured).
pub struct HttpS3TablesTransport {
    config: S3TablesSinkConfig,
    client: reqwest::Client,
}

impl HttpS3TablesTransport {
    pub fn new(config: &S3TablesSinkConfig, client: reqwest::Client) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config: config.clone(),
            client,
        })
    }
}

#[async_trait]
impl S3TablesTransport for HttpS3TablesTransport {
    async fn put_object(&self, put: &S3TablesPut, date: &str, authorization: &str) -> Result<()> {
        let url = format!(
            "{}://{}/{}",
            self.config.endpoint_scheme(),
            self.config.endpoint_host(),
            put.key.trim_start_matches('/')
        );
        let mut request = self
            .client
            .put(&url)
            .header("x-amz-date", date)
            .header(reqwest::header::AUTHORIZATION, authorization)
            .header(reqwest::header::CONTENT_TYPE, put.content_type)
            .body(put.body.clone());
        if let Some(encoding) = put.content_encoding {
            request = request.header(reqwest::header::CONTENT_ENCODING, encoding);
        }
        if let Some(token) = &self.config.session_token {
            request = request.header("x-amz-security-token", token);
        }
        let response = request
            .send()
            .await
            .map_err(|e| ConnectorError::Connection(format!("s3_tables put failed: {e}")))?;
        match classify_put_status(response.status().as_u16()) {
            S3TablesOutcome::Success => Ok(()),
            S3TablesOutcome::Retryable => Err(ConnectorError::Connection(format!(
                "s3_tables {} answered {}",
                put.key,
                response.status()
            ))),
            S3TablesOutcome::Terminal => Err(ConnectorError::Dispatch(format!(
                "s3_tables {} answered {}",
                put.key,
                response.status()
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// Sink.
// ---------------------------------------------------------------------------

/// One buffered record: ndjson line, dimensions, timestamp.
#[derive(Debug, Clone)]
struct S3TablesRow {
    line: String,
    device_id: String,
    client_id: String,
    topic: String,
    millis: i64,
}

fn render_row(topic: &Topic, payload: &Bytes, qos: QoS, millis: i64) -> Result<S3TablesRow> {
    let text = std::str::from_utf8(payload)
        .map_err(|_| ConnectorError::Dispatch("s3_tables payload must be UTF-8".to_string()))?;
    let value: serde_json::Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(_) => serde_json::Value::String(text.to_string()),
    };
    let string_field = |name: &str| {
        value
            .get(name)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string()
    };
    let line = serde_json::json!({
        "topic": topic.as_str(),
        "qos": u8::from(qos),
        "payload": value,
        "timestamp": super::rfc3339_millis(millis),
    })
    .to_string();
    Ok(S3TablesRow {
        line,
        device_id: string_field("device_id"),
        client_id: string_field("client_id"),
        topic: topic.as_str().to_string(),
        millis,
    })
}

fn gzip_bytes(raw: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), GzCompression::default());
    encoder
        .write_all(raw)
        .map_err(|e| ConnectorError::Dispatch(format!("s3_tables gzip failed: {e}")))?;
    encoder
        .finish()
        .map_err(|e| ConnectorError::Dispatch(format!("s3_tables gzip failed: {e}")))
}

struct S3TablesBuffer {
    queue: BatchQueue<S3TablesRow>,
}

/// S3 Tables sink: buffers records, uploads one gzip data file per
/// flush and frames a JSON snapshot for the commit.
pub struct S3TablesSink {
    config: S3TablesSinkConfig,
    transport: Arc<dyn S3TablesTransport>,
    buffer: parking_lot::Mutex<S3TablesBuffer>,
    backoff: parking_lot::Mutex<BackoffState>,
    snapshot_seq: AtomicU64,
    sent_files: AtomicU64,
    sent_records: AtomicU64,
    pub last_snapshot: parking_lot::Mutex<Vec<u8>>,
}

impl S3TablesSink {
    pub fn new(config: S3TablesSinkConfig, transport: Arc<dyn S3TablesTransport>) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            buffer: parking_lot::Mutex::new(S3TablesBuffer {
                queue: BatchQueue::new(config.effective_batch_size(), config.linger()),
            }),
            config,
            transport,
            backoff: parking_lot::Mutex::new(BackoffState::default()),
            snapshot_seq: AtomicU64::new(0),
            sent_files: AtomicU64::new(0),
            sent_records: AtomicU64::new(0),
            last_snapshot: parking_lot::Mutex::new(Vec::new()),
        })
    }

    pub fn config(&self) -> &S3TablesSinkConfig {
        &self.config
    }

    pub fn sent_files(&self) -> u64 {
        self.sent_files.load(Ordering::Relaxed)
    }

    pub fn sent_records(&self) -> u64 {
        self.sent_records.load(Ordering::Relaxed)
    }

    pub fn buffered_rows(&self) -> usize {
        self.buffer.lock().queue.len()
    }

    /// Flush buffered records as one data file (no-op when empty).
    /// While backing off, fails fast without touching the transport.
    /// Any failure restores rows, engages backoff, propagates.
    pub async fn flush(&self) -> Result<()> {
        self.backoff.lock().check()?;
        let (rows, oldest) = {
            let mut buffer = self.buffer.lock();
            buffer.queue.take_batch()
        };
        if rows.is_empty() {
            return Ok(());
        }
        // Partition on the first row (micro-batches group one slice).
        let first = &rows[0];
        let dims = [
            ("device_id", first.device_id.clone()),
            ("client_id", first.client_id.clone()),
            ("topic", first.topic.clone()),
        ];
        let partition = partition_path(&self.config.partition_spec, &dims, first.millis);
        let key = data_file_path(&partition, self.config.target_format);
        let mut raw = String::new();
        for row in &rows {
            raw.push_str(&row.line);
            raw.push('\n');
        }
        let (body, content_encoding, content_type) = match self.config.target_format {
            S3TablesFormat::NdjsonCompressed => (
                gzip_bytes(raw.as_bytes())?,
                Some("gzip"),
                "application/x-ndjson",
            ),
            S3TablesFormat::ParquetPlaceholder => {
                (raw.into_bytes(), None, "application/octet-stream")
            }
        };
        let millis = now_millis();
        let payload_hash = super::sha256_hex(&body);
        let host = self.config.endpoint_host();
        let (authorization, date) = s3tables_authorization(&S3TablesSigning {
            access_key_id: &self.config.access_key_id,
            secret_access_key: &self.config.secret_access_key,
            session_token: self.config.session_token.as_deref(),
            region: &self.config.region,
            service: self.config.sigv4_service(),
            host: &host,
            key: &key,
            payload_sha256_hex: &payload_hash,
            millis,
        });
        let put = S3TablesPut {
            key: key.clone(),
            body: body.clone(),
            content_type,
            content_encoding,
        };
        let record_count = rows.len() as u64;
        match self.transport.put_object(&put, &date, &authorization).await {
            Ok(()) => {
                let snapshot_id = self.snapshot_seq.fetch_add(1, Ordering::SeqCst);
                *self.last_snapshot.lock() = render_snapshot(
                    &self.config.namespace,
                    &self.config.table_name,
                    snapshot_id,
                    millis,
                    &[SnapshotFile {
                        path: key,
                        record_count,
                        size_bytes: body.len() as u64,
                        partition,
                    }],
                );
                self.backoff.lock().success();
                self.sent_files.fetch_add(1, Ordering::Relaxed);
                self.sent_records.fetch_add(record_count, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                self.buffer.lock().queue.restore(rows, oldest);
                self.backoff.lock().failure();
                Err(e)
            }
        }
    }

    /// Validate + buffer one event. Returns true when the batch is
    /// full or stale (caller flushes).
    fn buffer_row(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<bool> {
        if topic.as_str().is_empty() {
            return Err(ConnectorError::Dispatch(
                "s3_tables row requires a non-empty topic".to_string(),
            ));
        }
        if self.buffer.lock().queue.len() >= self.config.effective_buffer() {
            return Err(ConnectorError::Connection(
                "s3_tables buffer limit reached".to_string(),
            ));
        }
        let row = render_row(topic, payload, qos, now_millis())?;
        let mut buffer = self.buffer.lock();
        Ok(buffer.queue.push(row))
    }
}

#[async_trait]
impl Sink for S3TablesSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        if self.buffer_row(topic, payload, qos)? {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "s3_tables"
    }
}

/// Management connector handle pairing an id with an S3 Tables sink.
pub struct S3TablesConnector {
    id: String,
    sink: Arc<S3TablesSink>,
}

impl S3TablesConnector {
    pub fn new(id: impl Into<String>, sink: Arc<S3TablesSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }
}

impl super::Connector for S3TablesConnector {
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

    fn test_config() -> S3TablesSinkConfig {
        S3TablesSinkConfig {
            table_bucket_arn: "arn:aws:s3tables:us-east-1:123456789012:bucket/telemetry-bucket"
                .to_string(),
            namespace: "production_iot".to_string(),
            table_name: "device_events".to_string(),
            region: "us-east-1".to_string(),
            access_key_id: "AKIDEXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: None,
            endpoint: None,
            partition_spec: vec![
                IcebergPartitionField {
                    source_name: "date".to_string(),
                    transform: IcebergTransform::Day,
                },
                IcebergPartitionField {
                    source_name: "device_id".to_string(),
                    transform: IcebergTransform::Identity,
                },
            ],
            target_format: S3TablesFormat::NdjsonCompressed,
            batch_size: Some(1_000),
            buffer_capacity: None,
            linger_ms: Some(1_000),
        }
    }

    #[test]
    fn test_config_validation() {
        let mut config = test_config();
        assert!(config.validate().is_ok());

        config.table_bucket_arn = "arn:aws:s3:::plain-bucket".to_string();
        assert!(config.validate().is_err());
        config.table_bucket_arn = "arn:aws:s3tables:us-east-1:123:bucket/b".to_string();
        assert!(config.validate().is_err(), "short account id must fail");
        config.table_bucket_arn = test_config().table_bucket_arn;

        config.namespace = String::new();
        assert!(config.validate().is_err());
        config.namespace = "production_iot".to_string();

        config.partition_spec[0].source_name = String::new();
        assert!(config.validate().is_err());
        config.partition_spec = test_config().partition_spec;

        config.batch_size = Some(0);
        assert!(config.validate().is_err());
        config.batch_size = Some(10_000_000);

        // Zero clamped ceilings: huge depths are accepted.
        assert!(config.validate().is_ok());
        assert_eq!(config.sigv4_service(), "s3tables");
        assert_eq!(config.endpoint_host(), "s3tables.us-east-1.amazonaws.com");
    }

    #[test]
    fn test_arn_parser() {
        let parsed = parse_table_bucket_arn(
            "arn:aws:s3tables:us-east-1:123456789012:bucket/telemetry-bucket",
        )
        .unwrap();
        assert_eq!(
            parsed,
            TableBucketArn {
                region: "us-east-1".to_string(),
                account_id: "123456789012".to_string(),
                bucket: "telemetry-bucket".to_string(),
            }
        );
        for bad in [
            "arn:aws:s3:::bucket",
            "arn:aws:s3tables:us-east-1:123456789012:table/t",
            "arn:aws:s3tables::123456789012:bucket/b",
            "arn:aws:s3tables:us-east-1:12345678901:bucket/b",
            "arn:aws:s3tables:us-east-1:123456789012:bucket/",
            "not-an-arn",
        ] {
            assert!(parse_table_bucket_arn(bad).is_err(), "{bad:?} must fail");
        }
    }

    #[test]
    fn test_partition_transforms() {
        // 2026-09-12T11:18:09.123Z.
        let millis = 1_789_211_889_123;
        assert_eq!(
            apply_partition_transform(IcebergTransform::Day, "date", "", millis),
            "date_day=2026-09-12"
        );
        assert_eq!(
            apply_partition_transform(IcebergTransform::Hour, "date", "", millis),
            "date_hour=2026-09-12-11"
        );
        assert_eq!(
            apply_partition_transform(IcebergTransform::Month, "date", "", millis),
            "date_month=2026-09"
        );
        assert_eq!(
            apply_partition_transform(IcebergTransform::Year, "date", "", millis),
            "date_year=2026"
        );
        assert_eq!(
            apply_partition_transform(IcebergTransform::Identity, "device_id", "sensor-42", millis),
            "device_id=sensor-42"
        );
        assert_eq!(
            apply_partition_transform(IcebergTransform::Identity, "device_id", "", millis),
            "device_id=__null__"
        );
        assert_eq!(
            apply_partition_transform(IcebergTransform::Identity, "device_id", "a/b c", millis),
            "device_id=a_b_c"
        );
        // Leap day renders (2024-02-29T00:00:00Z).
        assert_eq!(
            apply_partition_transform(IcebergTransform::Day, "date", "", 1_709_164_800_000),
            "date_day=2024-02-29"
        );

        // Full directory honours spec order; missing dims are null.
        let spec = vec![
            IcebergPartitionField {
                source_name: "date".to_string(),
                transform: IcebergTransform::Day,
            },
            IcebergPartitionField {
                source_name: "device_id".to_string(),
                transform: IcebergTransform::Identity,
            },
        ];
        let dims = [("device_id", "sensor-42".to_string())];
        assert_eq!(
            partition_path(&spec, &dims, millis),
            "date_day=2026-09-12/device_id=sensor-42"
        );
        assert_eq!(
            partition_path(&spec, &[], millis),
            "date_day=2026-09-12/device_id=__null__"
        );
        assert_eq!(partition_path(&[], &dims, millis), "");
    }

    #[test]
    fn test_data_file_path_and_snapshot() {
        let key = data_file_path(
            "date_day=2026-09-12/device_id=sensor-42",
            S3TablesFormat::NdjsonCompressed,
        );
        assert!(key.starts_with("data/date_day=2026-09-12/device_id=sensor-42/"));
        assert!(key.ends_with(".data.gz"));
        let id = key
            .rsplit('/')
            .next()
            .unwrap()
            .strip_suffix(".data.gz")
            .unwrap();
        assert!(uuid::Uuid::parse_str(id).is_ok());
        assert!(data_file_path("", S3TablesFormat::NdjsonCompressed).starts_with("data/"));

        let snapshot = render_snapshot(
            "production_iot",
            "device_events",
            7,
            1_789_211_889_123,
            &[SnapshotFile {
                path: "data/date_day=2026-09-12/f.data.gz".to_string(),
                record_count: 3,
                size_bytes: 128,
                partition: "date_day=2026-09-12".to_string(),
            }],
        );
        let parsed: serde_json::Value = serde_json::from_slice(&snapshot).unwrap();
        assert_eq!(parsed["format_version"], 2);
        assert_eq!(parsed["snapshot_id"], 7);
        assert_eq!(parsed["table"], "production_iot.device_events");
        assert_eq!(parsed["schema"]["fields"].as_array().unwrap().len(), 4);
        assert_eq!(parsed["manifest"]["path"], "metadata/snap-7.avro");
        assert_eq!(
            parsed["manifest"]["partition_summary"]["date_day=2026-09-12"],
            3
        );
        assert_eq!(parsed["data_files"][0]["record_count"], 3);
    }

    #[test]
    fn test_sigv4_s3tables_known_answer() {
        // Independent Python (hmac/hashlib) vector: PUT of b'{"a":1}\n'
        // to the s3tables.us-east-1 host at 20260912T111809Z. The shared
        // core percent-encodes `=` in the canonical URI (`%3D`).
        let payload_hash = "e346432021b04179518d9614f3560ccd71354a4ee101ddcb893d6959a9d6301c";
        let (auth, date) = s3tables_authorization(&S3TablesSigning {
            access_key_id: "AKIDEXAMPLE",
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            session_token: None,
            region: "us-east-1",
            service: "s3tables",
            host: "s3tables.us-east-1.amazonaws.com",
            key: "data/date_day=2026-09-12/f.data.gz",
            payload_sha256_hex: payload_hash,
            millis: 1_789_211_889_000,
        });
        assert_eq!(date, "20260912T111809Z");
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260912/us-east-1/s3tables/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
             Signature=1fb4966a8e9fa4053979f48cfc9c827031ccc12ecedb322773b5c4d1e62a4029"
        );
    }

    #[test]
    fn test_status_classification() {
        assert_eq!(classify_put_status(200), S3TablesOutcome::Success);
        assert_eq!(classify_put_status(403), S3TablesOutcome::Terminal);
        assert_eq!(classify_put_status(400), S3TablesOutcome::Terminal);
        assert_eq!(classify_put_status(500), S3TablesOutcome::Retryable);
        assert_eq!(classify_put_status(503), S3TablesOutcome::Retryable);
        assert_eq!(classify_put_status(429), S3TablesOutcome::Retryable);
    }

    #[tokio::test]
    async fn test_flush_flow_and_snapshot() {
        let transport = Arc::new(MockS3TablesTransport::new());
        let mut config = test_config();
        config.batch_size = Some(2);
        let sink = S3TablesSink::new(config, transport.clone()).unwrap();

        let topic = Topic::new("sensors/t1").unwrap();
        sink.send(
            &topic,
            &Bytes::from(r#"{"device_id":"sensor-42","v":1}"#),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        sink.send(
            &topic,
            &Bytes::from(r#"{"device_id":"sensor-42","v":2}"#),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        assert_eq!(sink.sent_files(), 1);
        assert_eq!(sink.sent_records(), 2);

        let puts = transport.puts();
        assert_eq!(puts.len(), 1);
        assert!(
            puts[0].key.contains("device_id=sensor-42/"),
            "got {:?}",
            puts[0].key
        );
        assert!(puts[0].key.ends_with(".data.gz"));
        assert_eq!(puts[0].content_encoding, Some("gzip"));
        // Gzip body holds both ndjson rows.
        let mut decoder = GzDecoder::new(&puts[0].body[..]);
        let mut raw = Vec::new();
        decoder.read_to_end(&mut raw).unwrap();
        assert_eq!(String::from_utf8(raw).unwrap().lines().count(), 2);
        // SigV4 proof ran against the s3tables service.
        let auth = transport.last_authorization.lock().clone().unwrap();
        assert!(auth.contains("/us-east-1/s3tables/aws4_request"));

        // Snapshot frames the commit for catalog readers.
        let snapshot: serde_json::Value =
            serde_json::from_slice(&sink.last_snapshot.lock()).unwrap();
        assert_eq!(snapshot["table"], "production_iot.device_events");
        assert_eq!(snapshot["manifest"]["total_records"], 2);

        // Transport failures restore the buffer and engage backoff.
        transport.fail_next(10);
        sink.send(&topic, &Bytes::from("{}"), QoS::AtMostOnce)
            .await
            .unwrap();
        let err = sink.flush().await.expect_err("mock down must fail");
        assert!(matches!(err, ConnectorError::Connection(_)));
        assert_eq!(sink.buffered_rows(), 1);
    }

    #[tokio::test]
    async fn test_loopback_put_signed() {
        use axum::{http::StatusCode, routing::put, Router};

        #[derive(Debug, Default)]
        struct Captured {
            inner: parking_lot::Mutex<Vec<CapturedPut>>,
        }
        #[derive(Debug)]
        struct CapturedPut {
            path: String,
            date: Option<String>,
            auth: Option<String>,
            content_type: Option<String>,
            body: Vec<u8>,
        }

        let captured = Arc::new(Captured::default());
        let app = Router::new().fallback(put({
            let captured = captured.clone();
            move |uri: axum::http::Uri, headers: axum::http::HeaderMap, body: Bytes| {
                let captured = captured.clone();
                async move {
                    let get = |name: &str| {
                        headers
                            .get(name)
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_string)
                    };
                    captured.inner.lock().push(CapturedPut {
                        path: uri.path().to_string(),
                        date: get("x-amz-date"),
                        auth: get("authorization"),
                        content_type: get("content-type"),
                        body: body.to_vec(),
                    });
                    StatusCode::OK
                }
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        let mut config = test_config();
        config.endpoint = Some(format!("http://127.0.0.1:{port}"));
        config.batch_size = Some(1);
        let transport =
            Arc::new(HttpS3TablesTransport::new(&config, reqwest::Client::new()).unwrap());
        let sink = S3TablesSink::new(config, transport).unwrap();
        sink.send(
            &Topic::new("sensors/t1").unwrap(),
            &Bytes::from(r#"{"device_id":"sensor-42"}"#),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        assert_eq!(sink.sent_files(), 1);

        let puts = captured.inner.lock();
        assert_eq!(puts.len(), 1);
        assert!(puts[0].path.starts_with("/data/date_day="));
        assert!(puts[0].path.ends_with(".data.gz"));
        assert_eq!(
            puts[0].content_type.as_deref(),
            Some("application/x-ndjson")
        );
        // Custom endpoint signs the `s3` service.
        assert!(puts[0]
            .auth
            .as_deref()
            .unwrap()
            .contains("/us-east-1/s3/aws4_request"));
        assert_eq!(puts[0].date.as_deref().unwrap().len(), 16);
        // The uploaded body gunzips to the single ndjson row.
        assert_eq!(&puts[0].body[..2], &[0x1f, 0x8b], "gzip magic");
        server.abort();
    }
}
