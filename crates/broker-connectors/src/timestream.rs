//! Amazon Timestream sink (INDRA-178).
//!
//! Buffers MQTT events as multi-measure records and ingests them
//! with `WriteRecords` (`Timestream_20181101.WriteRecords` over HTTP
//! POST, `application/x-amz-json-1.0`), signed with AWS Signature
//! Version 4 for service `timestream` via the shared signer in
//! `super`. Dimensions sort by name so request bodies (and therefore
//! signatures) are deterministic.
//!
//! Partial failures requeue by record: a `RejectedRecordsException`
//! carries per-record indices that retry alone, while throttling
//! faults (`ThrottlingException`, HTTP 429/5xx, timeouts) retry the
//! whole batch. Validation faults are terminal dispatch failures.

use async_trait::async_trait;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::{
    now_millis, render_template, BackoffState, BatchQueue, ConnectorError, Result, Sink,
};

pub const TIMESTREAM_TARGET: &str = "Timestream_20181101.WriteRecords";
pub const TIMESTREAM_CONTENT_TYPE: &str = "application/x-amz-json-1.0";

/// Timestream timestamp resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TimestreamTimeUnit {
    #[default]
    Milliseconds,
    Microseconds,
    Nanoseconds,
}

impl TimestreamTimeUnit {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Milliseconds => "MILLISECONDS",
            Self::Microseconds => "MICROSECONDS",
            Self::Nanoseconds => "NANOSECONDS",
        }
    }

    /// Render event millis in this unit.
    pub fn render(self, millis: i64) -> String {
        let millis = millis.max(0) as u64;
        match self {
            Self::Milliseconds => millis.to_string(),
            Self::Microseconds => millis.saturating_mul(1_000).to_string(),
            Self::Nanoseconds => millis.saturating_mul(1_000_000).to_string(),
        }
    }
}

fn default_batch_size() -> Option<usize> {
    Some(100)
}

fn default_batch_bytes() -> Option<usize> {
    Some(1_048_576)
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
    Some(2_500)
}

/// Allowed multi-measure attribute types.
const ALLOWED_MEASURE_TYPES: &[&str] = &["DOUBLE", "BIGINT", "BOOLEAN", "VARCHAR", "TIMESTAMP"];

/// Timestream sink configuration. All depths are optional (`None` =
/// unbounded) with zero clamped ceilings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimestreamSinkConfig {
    /// Timestream database name.
    pub database_name: String,
    /// Timestream table name.
    pub table_name: String,
    /// AWS region, e.g. `us-east-1`.
    pub region: String,
    /// Custom ingest endpoint; defaults to
    /// `https://ingest.timestream.{region}.amazonaws.com`.
    #[serde(default)]
    pub endpoint: Option<String>,
    pub access_key_id: String,
    pub secret_access_key: String,
    /// STS session token for temporary credentials.
    #[serde(default)]
    pub session_token: Option<String>,
    /// Dimension templates (`${client_id}`, `${topic}`, ...).
    #[serde(default)]
    pub dimensions: HashMap<String, String>,
    /// Timestamp resolution (default milliseconds).
    #[serde(default)]
    pub time_unit: TimestreamTimeUnit,
    /// Measure name template (default `${topic}`).
    #[serde(default)]
    pub measure_name_template: Option<String>,
    /// Payload field → measure type (`DOUBLE`, `BIGINT`, `BOOLEAN`,
    /// `VARCHAR`, `TIMESTAMP`).
    #[serde(default)]
    pub multi_measure_mappings: HashMap<String, String>,
    /// Records per `WriteRecords` call (default 100, API cap).
    #[serde(default = "default_batch_size")]
    pub batch_size: Option<usize>,
    /// Batch byte limit (default 1 MiB).
    #[serde(default = "default_batch_bytes")]
    pub batch_bytes: Option<usize>,
    /// Linger flush window in ms (default 20).
    #[serde(default = "default_linger_ms")]
    pub linger_ms: Option<u64>,
    /// Retries on throttles/partials (default 4, `None` unbounded).
    #[serde(default = "default_max_retries")]
    pub max_retries: Option<usize>,
    /// First retry delay in ms (default 100).
    #[serde(default = "default_initial_backoff_ms")]
    pub initial_backoff_ms: Option<u64>,
    /// Retry delay ceiling in ms (default 2500).
    #[serde(default = "default_max_backoff_ms")]
    pub max_backoff_ms: Option<u64>,
}

impl TimestreamSinkConfig {
    pub fn validate(&self) -> Result<()> {
        if self.database_name.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "timestream database_name must not be empty".to_string(),
            ));
        }
        if self.table_name.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "timestream table_name must not be empty".to_string(),
            ));
        }
        if self.region.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "timestream region must not be empty".to_string(),
            ));
        }
        if let Some(endpoint) = &self.endpoint {
            if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
                return Err(ConnectorError::Dispatch(format!(
                    "timestream endpoint must be http(s): {endpoint:?}"
                )));
            }
        }
        if self.access_key_id.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "timestream access_key_id must not be empty".to_string(),
            ));
        }
        if self.secret_access_key.is_empty() {
            return Err(ConnectorError::Dispatch(
                "timestream secret_access_key must not be empty".to_string(),
            ));
        }
        for (name, template) in &self.dimensions {
            if name.trim().is_empty() {
                return Err(ConnectorError::Dispatch(
                    "timestream dimension names must not be empty".to_string(),
                ));
            }
            self.event_vars("dummy", b"{}", QoS::AtMostOnce, 0, template)?;
        }
        if let Some(template) = &self.measure_name_template {
            self.event_vars("dummy", b"{}", QoS::AtMostOnce, 0, template)?;
        }
        for (field, measure_type) in &self.multi_measure_mappings {
            if field.trim().is_empty() {
                return Err(ConnectorError::Dispatch(
                    "timestream measure fields must not be empty".to_string(),
                ));
            }
            if !ALLOWED_MEASURE_TYPES.contains(&measure_type.as_str()) {
                return Err(ConnectorError::Dispatch(format!(
                    "timestream measure type must be one of {ALLOWED_MEASURE_TYPES:?}: {measure_type:?}"
                )));
            }
        }
        if self.batch_size == Some(0) {
            return Err(ConnectorError::Dispatch(
                "timestream batch_size must be >= 1".to_string(),
            ));
        }
        if self.batch_bytes == Some(0) {
            return Err(ConnectorError::Dispatch(
                "timestream batch_bytes must be >= 1".to_string(),
            ));
        }
        Ok(())
    }

    pub fn endpoint_url(&self) -> String {
        match &self.endpoint {
            Some(endpoint) => endpoint.trim_end_matches('/').to_string(),
            None => format!("https://ingest.timestream.{}.amazonaws.com", self.region),
        }
    }

    pub fn effective_batch_size(&self) -> usize {
        self.batch_size.unwrap_or(usize::MAX).max(1)
    }

    pub fn effective_batch_bytes(&self) -> usize {
        self.batch_bytes.unwrap_or(usize::MAX).max(1)
    }

    pub fn effective_linger(&self) -> Duration {
        self.linger_ms.map(Duration::from_millis).unwrap_or(Duration::MAX)
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
        let doc: serde_json::Value = serde_json::from_slice(payload).unwrap_or_default();
        let mut rest = template;
        while let Some(start) = rest.find("${payload.") {
            let after = &rest[start + "${payload.".len()..];
            if let Some(close) = after.find('}') {
                let name = &after[..close];
                let value = match doc.get(name) {
                    Some(serde_json::Value::String(text)) => text.clone(),
                    Some(scalar) if scalar.is_number() || scalar.is_boolean() => {
                        scalar.to_string()
                    }
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
}

// ---------------------------------------------------------------------------
// Wire framing: WriteRecords JSON + SigV4.
// ---------------------------------------------------------------------------

/// One multi-measure record on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimestreamRecord {
    pub dimensions: Vec<(String, String)>,
    pub measure_name: String,
    pub measures: Vec<(String, String, String)>,
    pub time: String,
    pub time_unit: TimestreamTimeUnit,
}

/// One `WriteRecords` call.
#[derive(Debug, Clone)]
pub struct TimestreamWriteRequest {
    pub database: String,
    pub table: String,
    pub records: Vec<TimestreamRecord>,
}

/// Parsed `WriteRecords` outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimestreamWriteResponse {
    /// Total records the services reports ingested.
    pub ingested: u64,
    /// Indices rejected with per-record reasons.
    pub rejected: Vec<(usize, String)>,
}

/// Render the `WriteRecords` JSON body (dimensions sorted by name).
pub fn render_write_records_body(
    database: &str,
    table: &str,
    records: &[TimestreamRecord],
) -> Vec<u8> {
    let mut body = String::from("{\"DatabaseName\":");
    body.push_str(&serde_json::to_string(database).unwrap_or_default());
    body.push_str(",\"TableName\":");
    body.push_str(&serde_json::to_string(table).unwrap_or_default());
    body.push_str(",\"Records\":[");
    for (index, record) in records.iter().enumerate() {
        if index > 0 {
            body.push(',');
        }
        let mut dimensions = record.dimensions.clone();
        dimensions.sort_by(|a, b| a.0.cmp(&b.0));
        body.push_str("{\"Dimensions\":[");
        for (dim_index, (name, value)) in dimensions.iter().enumerate() {
            if dim_index > 0 {
                body.push(',');
            }
            body.push_str("{\"Name\":");
            body.push_str(&serde_json::to_string(name).unwrap_or_default());
            body.push_str(",\"Value\":");
            body.push_str(&serde_json::to_string(value).unwrap_or_default());
            body.push('}');
        }
        body.push_str("],\"MeasureName\":");
        body.push_str(&serde_json::to_string(&record.measure_name).unwrap_or_default());
        body.push_str(",\"MeasureValueType\":\"MULTI\",\"MeasureValues\":[");
        for (measure_index, (name, value, measure_type)) in record.measures.iter().enumerate() {
            if measure_index > 0 {
                body.push(',');
            }
            body.push_str("{\"Name\":");
            body.push_str(&serde_json::to_string(name).unwrap_or_default());
            body.push_str(",\"Value\":");
            body.push_str(&serde_json::to_string(value).unwrap_or_default());
            body.push_str(",\"Type\":");
            body.push_str(&serde_json::to_string(measure_type).unwrap_or_default());
            body.push('}');
        }
        body.push_str("],\"Time\":");
        body.push_str(&serde_json::to_string(&record.time).unwrap_or_default());
        body.push_str(",\"TimeUnit\":");
        body.push_str(&serde_json::to_string(record.time_unit.as_str()).unwrap_or_default());
        body.push('}');
    }
    body.push_str("]}");
    body.into_bytes()
}

/// Outcome of one classified `WriteRecords` call: ingested count
/// or rejected (index, reason) pairs for selective requeue.
pub type TimestreamOutcome = std::result::Result<u64, Vec<(usize, String)>>;

/// Classify a `WriteRecords` HTTP outcome: `Ok(ingested)` on clean
/// 2xx, `Rejected` indices on `RejectedRecordsException`, throttles
/// as retryable connections, everything else terminal.
pub fn classify_write_response(status: u16, body: &[u8]) -> Result<TimestreamOutcome> {
    if status == 429 || (500..=504).contains(&status) {
        return Err(ConnectorError::Connection(format!(
            "timestream throttled with {status}"
        )));
    }
    let doc: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
    let fault = doc
        .get("__type")
        .or_else(|| doc.get("code"))
        .or_else(|| doc.get("Code"))
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let short_fault = fault.rsplit(['#', ':']).next().unwrap_or_default();
    match short_fault {
        "ThrottlingException" | "Throttling" | "TooManyRequestsException"
        | "InternalServerError" | "InternalFailure" => Err(ConnectorError::Connection(format!(
            "timestream throttled with {fault}"
        ))),
        "RejectedRecordsException" => {
            let mut rejected = Vec::new();
            if let Some(records) = doc.get("RejectedRecords").and_then(|v| v.as_array()) {
                for record in records {
                    let index = record
                        .get("RecordIndex")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(usize::MAX as u64) as usize;
                    let reason = record
                        .get("Reason")
                        .and_then(|v| v.as_str())
                        .unwrap_or("rejected")
                        .to_string();
                    rejected.push((index, reason));
                }
            }
            Ok(Err(rejected))
        }
        _ if (200..=299).contains(&status) => {
            let ingested = doc
                .get("RecordsIngested")
                .and_then(|v| v.get("Total"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            Ok(Ok(ingested))
        }
        _ => Err(ConnectorError::Dispatch(format!(
            "timestream write failed with {status}: {fault}"
        ))),
    }
}

/// Sign a `WriteRecords` POST with SigV4 (service `timestream`),
/// returning the `Authorization` value plus the `x-amz-date` stamp.
pub fn sign_write_records(
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
        ("content-type".to_string(), "application/x-amz-json-1.0".to_string()),
        ("host".to_string(), host.to_string()),
        ("x-amz-date".to_string(), date.clone()),
        (
            "x-amz-target".to_string(),
            "Timestream_20181101.WriteRecords".to_string(),
        ),
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
        service: "timestream",
        millis,
    });
    (auth, date)
}

// ---------------------------------------------------------------------------
// Transport.
// ---------------------------------------------------------------------------

/// Scripted per-call outcome for the mock transport.
#[derive(Debug, Clone)]
pub enum MockTimestreamOutcome {
    /// Clean ingest of every record.
    Accepted,
    /// Partial rejection: indices + reasons, retried selectively.
    Rejected(Vec<(usize, String)>),
    /// Whole-batch throttle (retries everything).
    Throttled,
    /// Terminal dispatch failure.
    Terminal(String),
}

#[async_trait]
pub trait TimestreamTransport: Send + Sync {
    async fn write_records(
        &self,
        req: &TimestreamWriteRequest,
    ) -> Result<TimestreamWriteResponse>;
}

/// In-memory transport with scripted outcomes (tests, dry runs).
#[derive(Debug, Default)]
pub struct MockTimestreamTransport {
    scripted: parking_lot::Mutex<std::collections::VecDeque<MockTimestreamOutcome>>,
    captured: parking_lot::Mutex<Vec<TimestreamWriteRequest>>,
    calls: AtomicU64,
}

impl MockTimestreamTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue outcomes consumed in order (default: all accepted).
    pub fn script_outcomes(&self, outcomes: Vec<MockTimestreamOutcome>) {
        *self.scripted.lock() = outcomes.into_iter().collect();
    }

    pub fn captured(&self) -> Vec<TimestreamWriteRequest> {
        self.captured.lock().clone()
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl TimestreamTransport for MockTimestreamTransport {
    async fn write_records(
        &self,
        req: &TimestreamWriteRequest,
    ) -> Result<TimestreamWriteResponse> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.captured.lock().push(TimestreamWriteRequest {
            database: req.database.clone(),
            table: req.table.clone(),
            records: req.records.clone(),
        });
        match self.scripted.lock().pop_front() {
            None | Some(MockTimestreamOutcome::Accepted) => Ok(TimestreamWriteResponse {
                ingested: req.records.len() as u64,
                rejected: Vec::new(),
            }),
            Some(MockTimestreamOutcome::Rejected(rejected)) => Ok(TimestreamWriteResponse {
                ingested: req.records.len().saturating_sub(rejected.len()) as u64,
                rejected,
            }),
            Some(MockTimestreamOutcome::Throttled) => Err(ConnectorError::Connection(
                "mock timestream throttled".to_string(),
            )),
            Some(MockTimestreamOutcome::Terminal(message)) => {
                Err(ConnectorError::Dispatch(message))
            }
        }
    }
}

/// Production transport: signed `POST {endpoint}/` with the JSON body.
pub struct HttpTimestreamTransport {
    endpoint: String,
    host: String,
    region: String,
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
    client: reqwest::Client,
}

impl HttpTimestreamTransport {
    pub fn new(config: &TimestreamSinkConfig, client: reqwest::Client) -> Result<Self> {
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
impl TimestreamTransport for HttpTimestreamTransport {
    async fn write_records(
        &self,
        req: &TimestreamWriteRequest,
    ) -> Result<TimestreamWriteResponse> {
        let body = render_write_records_body(&req.database, &req.table, &req.records);
        let millis = now_millis();
        let (auth, date) = sign_write_records(
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
            .header(reqwest::header::CONTENT_TYPE, TIMESTREAM_CONTENT_TYPE)
            .header("X-Amz-Target", TIMESTREAM_TARGET)
            .header("X-Amz-Date", date)
            .header(reqwest::header::AUTHORIZATION, auth)
            .body(body);
        if let Some(token) = &self.session_token {
            request = request.header("X-Amz-Security-Token", token.as_str());
        }
        let response = request
            .send()
            .await
            .map_err(|e| ConnectorError::Connection(format!("timestream write failed: {e}")))?;
        let status = response.status().as_u16();
        let bytes = response
            .bytes()
            .await
            .map_err(|e| ConnectorError::Connection(format!("timestream read failed: {e}")))?;
        match classify_write_response(status, &bytes)? {
            Ok(ingested) => Ok(TimestreamWriteResponse {
                ingested,
                rejected: Vec::new(),
            }),
            Err(rejected) => {
                let failed: Vec<usize> = rejected.iter().map(|(index, _)| *index).collect();
                Err(ConnectorError::Connection(format!(
                    "timestream rejected records {failed:?}"
                )))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Sink.
// ---------------------------------------------------------------------------

/// One buffered event with render timestamp.
#[derive(Debug, Clone)]
struct TimestreamRow {
    topic: String,
    payload: Vec<u8>,
    qos: u8,
    millis: i64,
}

struct TimestreamBuffer {
    queue: BatchQueue<TimestreamRow>,
    bytes: usize,
}

/// Timestream sink: buffers events, writes multi-measure batches with
/// selective rejected-record requeue.
pub struct TimestreamSink {
    config: TimestreamSinkConfig,
    transport: Arc<dyn TimestreamTransport>,
    buffer: parking_lot::Mutex<TimestreamBuffer>,
    backoff: parking_lot::Mutex<BackoffState>,
    sent_batches: AtomicU64,
    sent_records: AtomicU64,
}

impl TimestreamSink {
    pub fn new(
        config: TimestreamSinkConfig,
        transport: Arc<dyn TimestreamTransport>,
    ) -> Result<Self> {
        config.validate()?;
        let linger = config.effective_linger();
        Ok(Self {
            buffer: parking_lot::Mutex::new(TimestreamBuffer {
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

    pub fn config(&self) -> &TimestreamSinkConfig {
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
        let max = self.config.max_backoff_ms.unwrap_or(2_500).max(1);
        let grown = initial
            .saturating_mul(2u64.saturating_pow(attempt.min(10) as u32))
            .min(max);
        let jitter = (now_millis().max(0) as u64) % (grown / 2 + 1);
        Duration::from_millis(grown.saturating_add(jitter).min(max.saturating_mul(2)))
    }

    /// Build one record: sorted dimensions, measure name, typed
    /// measures (missing fields skipped; empty measure sets fail).
    fn build_record(&self, row: &TimestreamRow) -> Result<TimestreamRecord> {
        let doc: serde_json::Value = serde_json::from_slice(&row.payload).unwrap_or_default();
        let mut dimensions: Vec<(String, String)> = Vec::new();
        for (name, template) in &self.config.dimensions {
            dimensions.push((
                name.clone(),
                self.config.event_vars(&row.topic, &row.payload, qos_from(row.qos), row.millis, template)?,
            ));
        }
        dimensions.push(("topic".to_string(), row.topic.clone()));
        let measure_name = match &self.config.measure_name_template {
            Some(template) => self.config.event_vars(
                &row.topic,
                &row.payload,
                qos_from(row.qos),
                row.millis,
                template,
            )?,
            None => "metrics".to_string(),
        };
        let mut measure_names: Vec<&String> =
            self.config.multi_measure_mappings.keys().collect();
        measure_names.sort();
        let mut measures = Vec::new();
        for field in measure_names {
            let measure_type = &self.config.multi_measure_mappings[field];
            if let Some(value) = doc.get(field) {
                measures.push((
                    field.clone(),
                    json_scalar_text(value, measure_type)?,
                    measure_type.clone(),
                ));
            }
        }
        if measures.is_empty() {
            return Err(ConnectorError::Dispatch(
                "timestream record has no measures".to_string(),
            ));
        }
        Ok(TimestreamRecord {
            dimensions,
            measure_name,
            measures,
            time: self.config.time_unit.render(row.millis),
            time_unit: self.config.time_unit,
        })
    }

    /// Flush buffered rows (no-op when empty). Rejected records
    /// requeue selectively; throttles retry everything; terminal
    /// outcomes restore the pending set and propagate.
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
        let mut pending: Vec<TimestreamRow> = rows;
        let total = pending.len() as u64;
        let max_retries = self.config.max_retries.unwrap_or(usize::MAX);
        let mut attempt = 0usize;
        loop {
            // Records rebuild per attempt (cheap); a build failure
            // restores the whole batch instead of dropping it.
            let mut records = Vec::with_capacity(pending.len());
            for row in &pending {
                match self.build_record(row) {
                    Ok(record) => records.push(record),
                    Err(e) => {
                        return self.restore_err(pending, oldest, taken_bytes, e);
                    }
                }
            }
            let request = TimestreamWriteRequest {
                database: self.config.database_name.clone(),
                table: self.config.table_name.clone(),
                records,
            };
            match self.transport.write_records(&request).await {
                Ok(response) if response.rejected.is_empty() => {
                    self.backoff.lock().success();
                    self.sent_batches.fetch_add(1, Ordering::Relaxed);
                    self.sent_records.fetch_add(total, Ordering::Relaxed);
                    return Ok(());
                }
                Ok(response) => {
                    if attempt >= max_retries {
                        return self.restore_err(
                            pending,
                            oldest,
                            taken_bytes,
                            ConnectorError::Connection(format!(
                                "timestream {} rejections after {attempt} retries",
                                response.rejected.len()
                            )),
                        );
                    }
                    attempt += 1;
                    tokio::time::sleep(self.backoff_delay(attempt)).await;
                    let rejected: Vec<usize> =
                        response.rejected.iter().map(|(index, _)| *index).collect();
                    pending = rejected
                        .into_iter()
                        .filter_map(|index| pending.get(index).cloned())
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
        rows: Vec<TimestreamRow>,
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
                "timestream row requires a non-empty topic".to_string(),
            ));
        }
        let row = TimestreamRow {
            topic: topic.as_str().to_string(),
            payload: payload.to_vec(),
            qos: u8::from(qos),
            millis: now_millis(),
        };
        let added = row.payload.len() + 128;
        let mut buffer = self.buffer.lock();
        let full = buffer.queue.push(row);
        buffer.bytes = buffer.bytes.saturating_add(added);
        Ok(full || buffer.bytes >= self.config.effective_batch_bytes())
    }
}

/// Render one JSON scalar in the declared measure type.
fn json_scalar_text(value: &serde_json::Value, measure_type: &str) -> Result<String> {
    match (value, measure_type) {
        (serde_json::Value::Number(n), "DOUBLE") => n
            .as_f64()
            .map(|v| v.to_string())
            .ok_or_else(|| ConnectorError::Dispatch("timestream DOUBLE needs a number".to_string())),
        (serde_json::Value::Number(n), "BIGINT") => n
            .as_i64()
            .map(|v| v.to_string())
            .ok_or_else(|| ConnectorError::Dispatch("timestream BIGINT needs an integer".to_string())),
        (serde_json::Value::Bool(v), "BOOLEAN") => Ok(v.to_string()),
        (serde_json::Value::String(v), "VARCHAR") => Ok(v.clone()),
        (serde_json::Value::Number(n), "VARCHAR") => Ok(n.to_string()),
        (serde_json::Value::Bool(v), "VARCHAR") => Ok(v.to_string()),
        (serde_json::Value::Number(n), "TIMESTAMP") => n
            .as_i64()
            .map(|v| v.to_string())
            .ok_or_else(|| {
                ConnectorError::Dispatch("timestream TIMESTAMP needs epoch millis".to_string())
            }),
        (serde_json::Value::String(v), "TIMESTAMP") => Ok(v.clone()),
        _ => Err(ConnectorError::Dispatch(format!(
            "timestream value {value} does not fit {measure_type}"
        ))),
    }
}

fn qos_from(value: u8) -> QoS {
    QoS::try_from(value).unwrap_or(QoS::AtMostOnce)
}

#[async_trait]
impl Sink for TimestreamSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        if self.buffer_row(topic, payload, qos)? {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "timestream"
    }
}

/// Management connector handle pairing an id with a Timestream sink.
pub struct TimestreamConnector {
    id: String,
    sink: Arc<TimestreamSink>,
}

impl TimestreamConnector {
    pub fn new(id: impl Into<String>, sink: Arc<TimestreamSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }
}

impl super::Connector for TimestreamConnector {
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

    fn test_config() -> TimestreamSinkConfig {
        TimestreamSinkConfig {
            database_name: "iot_database".to_string(),
            table_name: "telemetry".to_string(),
            region: "us-east-1".to_string(),
            endpoint: None,
            access_key_id: "AKIDEXAMPLE".to_string(),
            secret_access_key: "secret".to_string(),
            session_token: None,
            dimensions: HashMap::from([
                ("device_id".to_string(), "${client_id}".to_string()),
                ("region".to_string(), "${payload.region}".to_string()),
            ]),
            time_unit: TimestreamTimeUnit::Milliseconds,
            measure_name_template: Some("sensor_metrics".to_string()),
            multi_measure_mappings: HashMap::from([
                ("temperature".to_string(), "DOUBLE".to_string()),
                ("status".to_string(), "VARCHAR".to_string()),
            ]),
            batch_size: Some(100),
            batch_bytes: Some(1_048_576),
            linger_ms: Some(20),
            max_retries: Some(4),
            initial_backoff_ms: Some(100),
            max_backoff_ms: Some(2_500),
        }
    }

    fn test_sink(
        config: TimestreamSinkConfig,
    ) -> (Arc<TimestreamSink>, Arc<MockTimestreamTransport>) {
        let transport = Arc::new(MockTimestreamTransport::new());
        let sink = Arc::new(TimestreamSink::new(config, transport.clone()).unwrap());
        (sink, transport)
    }

    #[test]
    fn test_config_validation() {
        let mut config = test_config();
        assert!(config.validate().is_ok());
        assert_eq!(
            config.endpoint_url(),
            "https://ingest.timestream.us-east-1.amazonaws.com"
        );

        config.database_name.clear();
        assert!(config.validate().is_err());
        config.database_name = "iot_database".to_string();

        config.region.clear();
        assert!(config.validate().is_err());
        config.region = "us-east-1".to_string();

        config.dimensions.insert(String::new(), "x".to_string());
        assert!(config.validate().is_err());
        config.dimensions.remove("");

        config.dimensions.insert("bad".to_string(), "${nope}".to_string());
        assert!(config.validate().is_err());
        config.dimensions.remove("bad");

        config.multi_measure_mappings.insert("x".to_string(), "FLOAT".to_string());
        assert!(config.validate().is_err());
        config.multi_measure_mappings.remove("x");

        config.batch_size = Some(0);
        assert!(config.validate().is_err());
        // Unbounded + huge depths accepted: zero clamped ceilings.
        config.batch_size = None;
        config.batch_bytes = Some(10_000_000);
        config.max_retries = None;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_time_unit_rendering() {
        assert_eq!(TimestreamTimeUnit::Milliseconds.render(1_789_211_889_123), "1789211889123");
        assert_eq!(
            TimestreamTimeUnit::Microseconds.render(1_789_211_889_123),
            "1789211889123000"
        );
        assert_eq!(
            TimestreamTimeUnit::Nanoseconds.render(1_789_211_889_123),
            "1789211889123000000"
        );
        assert_eq!(TimestreamTimeUnit::Milliseconds.as_str(), "MILLISECONDS");
    }

    #[test]
    fn test_request_framing() {
        let record = TimestreamRecord {
            dimensions: vec![
                ("topic".to_string(), "factory/line1/temp".to_string()),
                ("device_id".to_string(), "sensor-1".to_string()),
            ],
            measure_name: "sensor_metrics".to_string(),
            measures: vec![("temperature".to_string(), "24.5".to_string(), "DOUBLE".to_string())],
            time: "1726160000000".to_string(),
            time_unit: TimestreamTimeUnit::Milliseconds,
        };
        let body = render_write_records_body("iot_database", "telemetry", &[record]);
        // Dimensions sort by name for deterministic signatures.
        assert_eq!(
            String::from_utf8(body).unwrap(),
            r#"{"DatabaseName":"iot_database","TableName":"telemetry","Records":[{"Dimensions":[{"Name":"device_id","Value":"sensor-1"},{"Name":"topic","Value":"factory/line1/temp"}],"MeasureName":"sensor_metrics","MeasureValueType":"MULTI","MeasureValues":[{"Name":"temperature","Value":"24.5","Type":"DOUBLE"}],"Time":"1726160000000","TimeUnit":"MILLISECONDS"}]}"#
        );

        // Classifier: clean 2xx, rejections, throttles, terminals.
        assert_eq!(
            classify_write_response(200, br#"{"RecordsIngested":{"Total":2}}"#).unwrap(),
            Ok(2)
        );
        assert_eq!(
            classify_write_response(
                400,
                br#"{"__type":"com.amazonaws.timestream#RejectedRecordsException","RejectedRecords":[{"RecordIndex":1,"Reason":"bad time"}]}"#
            )
            .unwrap(),
            Err(vec![(1, "bad time".to_string())])
        );
        assert!(classify_write_response(
            400,
            br#"{"__type":"com.amazonaws.timestream#ThrottlingException"}"#
        )
        .is_err());
        assert!(matches!(
            classify_write_response(400, br#"{"__type":"com.amazonaws.timestream#ValidationException"}"#),
            Err(ConnectorError::Dispatch(_))
        ));
    }

    #[test]
    fn test_sigv4_known_answer() {
        // Independent Python (hmac/hashlib) vector.
        let body = br#"{"DatabaseName":"iot_database","TableName":"telemetry","Records":[{"Dimensions":[{"Name":"device_id","Value":"sensor-1"}],"MeasureName":"sensor_metrics","MeasureValueType":"MULTI","MeasureValues":[{"Name":"temperature","Value":"24.5","Type":"DOUBLE"}],"Time":"1726160000000","TimeUnit":"MILLISECONDS"}]}"#;
        let (auth, date) = sign_write_records(
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            None,
            "us-east-1",
            "ingest.timestream.us-east-1.amazonaws.com",
            body,
            1_789_211_889_000,
        );
        assert_eq!(date, "20260912T111809Z");
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260912/us-east-1/timestream/aws4_request, \
             SignedHeaders=content-type;host;x-amz-date;x-amz-target, \
             Signature=4f13e0d65dc9cd20b0017daffc00882360824cbac5948ce688c7d7ca1f5a1826"
        );
    }

    #[test]
    fn test_dimension_templates_render_per_event() {
        let (sink, _) = test_sink(test_config());
        let row = TimestreamRow {
            topic: "sensors/kitchen".to_string(),
            payload: br#"{"client_id":"d7","region":"eu","temperature":22.5}"#.to_vec(),
            qos: 1,
            millis: 1_789_211_889_123,
        };
        let record = sink.build_record(&row).unwrap();
        let mut dimensions = record.dimensions.clone();
        dimensions.sort();
        assert_eq!(
            dimensions,
            vec![
                ("device_id".to_string(), "d7".to_string()),
                ("region".to_string(), "eu".to_string()),
                ("topic".to_string(), "sensors/kitchen".to_string()),
            ]
        );
    }

    #[test]
    fn test_default_measure_name_is_metrics() {
        let mut config = test_config();
        config.measure_name_template = None;
        config.multi_measure_mappings = HashMap::from([("v".to_string(), "DOUBLE".to_string())]);
        let (sink, _) = test_sink(config);
        let row = TimestreamRow {
            topic: "sensors/t".to_string(),
            payload: br#"{"v":1.5}"#.to_vec(),
            qos: 0,
            millis: 1_000,
        };
        assert_eq!(sink.build_record(&row).unwrap().measure_name, "metrics");
    }

    #[tokio::test]
    async fn test_partial_rejection_requeues_selectively() {
        let mut config = test_config();
        config.batch_size = Some(10);
        config.initial_backoff_ms = Some(1);
        config.max_backoff_ms = Some(2);
        let (sink, transport) = test_sink(config);
        // First pass rejects record 1; the retry carries only it.
        transport.script_outcomes(vec![
            MockTimestreamOutcome::Rejected(vec![(1, "bad time".to_string())]),
            MockTimestreamOutcome::Accepted,
        ]);

        let topic = Topic::new("t").unwrap();
        for temp in [20.5, 21.5] {
            sink.send(&topic, &Bytes::from(format!("{{\"temperature\":{temp}}}")), QoS::AtMostOnce)
                .await
                .unwrap();
        }
        sink.flush().await.unwrap();

        assert_eq!(transport.calls(), 2);
        let captured = transport.captured();
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[0].records.len(), 2);
        assert_eq!(captured[0].database, "iot_database");
        // Retry carries only the rejected record (temp 21.5).
        assert_eq!(captured[1].records.len(), 1);
        assert_eq!(captured[1].records[0].measures[0].1, "21.5");
        assert_eq!(sink.sent_records(), 2);
        assert_eq!(sink.buffered_rows(), 0);
    }

    #[tokio::test]
    async fn test_throttle_retry_and_exhaustion() {
        // Throttle then success.
        let mut config = test_config();
        config.batch_size = Some(10);
        config.initial_backoff_ms = Some(1);
        config.max_backoff_ms = Some(2);
        let (sink, transport) = test_sink(config);
        transport.script_outcomes(vec![
            MockTimestreamOutcome::Throttled,
            MockTimestreamOutcome::Accepted,
        ]);
        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from("{\"temperature\":1.0}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        sink.flush().await.unwrap();
        assert_eq!(transport.calls(), 2);
        assert_eq!(sink.sent_records(), 1);

        // Exhaustion restores everything and fails fast after.
        let mut config = test_config();
        config.batch_size = Some(10);
        config.max_retries = Some(0);
        let (sink, transport) = test_sink(config);
        transport.script_outcomes(vec![MockTimestreamOutcome::Throttled]);
        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from("{\"temperature\":1.0}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        let err = sink.flush().await.expect_err("throttle must exhaust");
        assert!(matches!(err, ConnectorError::Connection(_)));
        assert_eq!(transport.calls(), 1);
        assert_eq!(sink.buffered_rows(), 1);
        assert!(sink.flush().await.is_err());
        assert_eq!(transport.calls(), 1);
    }

    #[tokio::test]
    async fn test_empty_measures_rejected_at_buffer() {
        // Payload without mapped fields: the record would carry no
        // measures, so buffering still succeeds but flush fails loudly.
        let (sink, _) = test_sink(test_config());
        sink.send(&Topic::new("t").unwrap(), &Bytes::from("{}"), QoS::AtMostOnce)
            .await
            .unwrap();
        let err = sink.flush().await.expect_err("empty measures must fail");
        assert!(matches!(err, ConnectorError::Dispatch(_)));
    }
}
