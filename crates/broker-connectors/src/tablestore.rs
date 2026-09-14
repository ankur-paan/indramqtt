//! Alibaba Cloud Tablestore (OTS) wide-column sink (INDRA-190).
//!
//! Buffers MQTT events and writes them with `POST /api/BatchWriteRow`
//! as `RowChange` put-rows: primary-key columns plus attribute columns
//! with millisecond timestamps. Field sources (`${client_id}`,
//! `${topic}`, `${timestamp}`, `${payload.<dotted>}`) coerce into the
//! declared OTS types (String, Integer, Double, Boolean, Binary).
//!
//! Authentication is the clean-room OTS HTTP signature below
//! (HMAC-SHA1 over the canonicalized `x-ots-*` headers plus the body
//! Content-MD5). Partial failures isolate per row: only entries whose
//! `is_ok` is false (e.g. `OTSRowOperationFailed`, `OTSTimeout`)
//! requeue; the rest commit. Batching, restore-on-failure and backoff
//! reuse the shared [`super::BatchQueue`] / [`super::BackoffState`]
//! helpers.

use async_trait::async_trait;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::{hmac_sha1, now_millis, BackoffState, BatchQueue, ConnectorError, Result, Sink};

/// OTS API version pinned on every request.
pub const OTS_API_VERSION: &str = "2015-12-31";

/// BatchWriteRow request path.
pub const BATCH_WRITE_ROW_PATH: &str = "/api/BatchWriteRow";

/// Primary-key column type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PrimaryKeyType {
    String,
    Integer,
    Binary,
}

/// Attribute column type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttributeColumnType {
    String,
    Integer,
    Double,
    Boolean,
    Binary,
}

/// One primary-key column mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrimaryKeyMapping {
    /// Column name.
    pub name: String,
    /// Field source (`${client_id}`, `${topic}`, `${payload.a.b}`).
    pub source: String,
    /// OTS primary-key type.
    pub data_type: PrimaryKeyType,
}

/// One attribute column mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttributeColumnMapping {
    /// Column name.
    pub name: String,
    /// Field source (`${payload.temperature}`, ...).
    pub source: String,
    /// OTS attribute type.
    pub data_type: AttributeColumnType,
}

fn default_batch_size() -> Option<usize> {
    Some(200)
}

/// Tablestore sink configuration. Every depth is user-configurable
/// with no clamped ceiling (`None` = unbounded).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TablestoreSinkConfig {
    /// OTS instance endpoint, e.g.
    /// `https://myinstance.cn-hangzhou.ots.aliyuncs.com`.
    pub endpoint: String,
    /// Tablestore instance identifier.
    pub instance_name: String,
    /// Target wide-column table name.
    pub table_name: String,
    /// Alibaba Cloud Access Key ID.
    pub access_key_id: String,
    /// Alibaba Cloud Access Key Secret.
    pub access_key_secret: String,
    /// Primary-key column mappings (non-empty).
    pub primary_keys: Vec<PrimaryKeyMapping>,
    /// Attribute column mappings.
    #[serde(default)]
    pub attribute_columns: Vec<AttributeColumnMapping>,
    /// Flush trigger row count (default 200 = OTS BatchWriteRow limit).
    #[serde(default = "default_batch_size")]
    pub batch_size: Option<usize>,
    /// Buffer capacity (`None` = unbounded).
    #[serde(default)]
    pub buffer_capacity: Option<usize>,
    /// Linger flush window in ms (default 100).
    #[serde(default = "default_linger_ms")]
    pub linger_ms: Option<u64>,
    /// Request timeout in ms (default 5000).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

fn default_linger_ms() -> Option<u64> {
    Some(100)
}

impl TablestoreSinkConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.unwrap_or(5000).max(1))
    }

    pub fn validate(&self) -> Result<()> {
        if !self.endpoint.starts_with("http://") && !self.endpoint.starts_with("https://") {
            return Err(ConnectorError::Dispatch(format!(
                "tablestore endpoint must be http(s): {:?}",
                self.endpoint
            )));
        }
        if self.instance_name.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "tablestore instance_name must not be empty".to_string(),
            ));
        }
        if self.table_name.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "tablestore table_name must not be empty".to_string(),
            ));
        }
        if self.access_key_id.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "tablestore access_key_id must not be empty".to_string(),
            ));
        }
        if self.access_key_secret.is_empty() {
            return Err(ConnectorError::Dispatch(
                "tablestore access_key_secret must not be empty".to_string(),
            ));
        }
        if self.primary_keys.is_empty() {
            return Err(ConnectorError::Dispatch(
                "tablestore primary_keys must not be empty".to_string(),
            ));
        }
        for pk in &self.primary_keys {
            validate_mapping(&pk.name, &pk.source, "primary_keys")?;
        }
        for attr in &self.attribute_columns {
            validate_mapping(&attr.name, &attr.source, "attribute_columns")?;
        }
        if self.batch_size == Some(0) {
            return Err(ConnectorError::Dispatch(
                "tablestore batch_size must be >= 1".to_string(),
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

    pub(crate) fn linger(&self) -> Duration {
        Duration::from_millis(self.linger_ms.unwrap_or(100).max(1))
    }
}

fn validate_mapping(name: &str, source: &str, what: &str) -> Result<()> {
    if name.trim().is_empty() {
        return Err(ConnectorError::Dispatch(format!(
            "tablestore {what} name must not be empty"
        )));
    }
    parse_source(source)
        .map(|_| ())
        .map_err(|e| ConnectorError::Dispatch(format!("tablestore {what} {name:?}: {e}")))
}

// ---------------------------------------------------------------------------
// Field sources + type coercion.
// ---------------------------------------------------------------------------

/// Parsed `${...}` field source.
#[derive(Debug, Clone, PartialEq, Eq)]
enum FieldSource {
    ClientId,
    Topic,
    Timestamp,
    Payload(Vec<String>),
}

/// Parse a mapping source: `${client_id}`, `${topic}`,
/// `${timestamp}`, or `${payload.<dotted.path>}`. Anything else is a
/// dispatch error so typos fail loudly at buffer time.
fn parse_source(source: &str) -> std::result::Result<FieldSource, String> {
    let inner = source
        .strip_prefix("${")
        .and_then(|s| s.strip_suffix('}'))
        .ok_or_else(|| format!("source must be a ${{...}} reference: {source:?}"))?;
    if inner.is_empty() {
        return Err(format!("empty source reference: {source:?}"));
    }
    match inner {
        "client_id" => Ok(FieldSource::ClientId),
        "topic" => Ok(FieldSource::Topic),
        "timestamp" => Ok(FieldSource::Timestamp),
        _ => match inner.strip_prefix("payload.") {
            Some(path) if !path.is_empty() => Ok(FieldSource::Payload(
                path.split('.').map(str::to_string).collect(),
            )),
            _ => Err(format!("unknown source reference: {source:?}")),
        },
    }
}

/// Extract `client_id` from a JSON payload object (empty when absent,
/// mirroring the SQL projection convention).
fn payload_client_id(payload: &serde_json::Value) -> String {
    payload
        .get("client_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string()
}

/// Resolve a parsed source against the event.
fn resolve_source(
    source: &FieldSource,
    topic: &str,
    payload: &serde_json::Value,
    millis: i64,
) -> serde_json::Value {
    match source {
        FieldSource::ClientId => serde_json::Value::String(payload_client_id(payload)),
        FieldSource::Topic => serde_json::Value::String(topic.to_string()),
        FieldSource::Timestamp => serde_json::Value::Number(millis.into()),
        FieldSource::Payload(path) => {
            let mut current = payload;
            for segment in path {
                match current.get(segment) {
                    Some(next) => current = next,
                    None => return serde_json::Value::Null,
                }
            }
            current.clone()
        }
    }
}

/// Coerced OTS column value.
#[derive(Debug, Clone, PartialEq)]
pub enum OtsValue {
    String(String),
    Integer(i64),
    Double(f64),
    Boolean(bool),
    Binary(Vec<u8>),
}

impl OtsValue {
    /// OTS type tag used in the wire encoding.
    pub fn type_tag(&self) -> &'static str {
        match self {
            OtsValue::String(_) => "string",
            OtsValue::Integer(_) => "integer",
            OtsValue::Double(_) => "double",
            OtsValue::Boolean(_) => "boolean",
            OtsValue::Binary(_) => "binary",
        }
    }

    /// JSON-safe rendering (binary rides base64).
    pub fn wire_value(&self) -> serde_json::Value {
        match self {
            OtsValue::String(s) => serde_json::Value::String(s.clone()),
            OtsValue::Integer(i) => serde_json::json!(*i),
            OtsValue::Double(f) => serde_json::json!(*f),
            OtsValue::Boolean(b) => serde_json::Value::Bool(*b),
            OtsValue::Binary(bytes) => {
                use base64::Engine;
                serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(bytes))
            }
        }
    }
}

fn coerce_pk(value: &serde_json::Value, data_type: PrimaryKeyType, name: &str) -> Result<OtsValue> {
    match data_type {
        PrimaryKeyType::String => value
            .as_str()
            .map(|s| OtsValue::String(s.to_string()))
            .ok_or_else(|| {
                ConnectorError::Dispatch(format!(
                    "tablestore primary key {name:?} needs a JSON string"
                ))
            }),
        PrimaryKeyType::Integer => as_integer(value).map(OtsValue::Integer).ok_or_else(|| {
            ConnectorError::Dispatch(format!(
                "tablestore primary key {name:?} needs a JSON integer"
            ))
        }),
        PrimaryKeyType::Binary => value
            .as_str()
            .map(decode_binary)
            .transpose()?
            .ok_or_else(|| {
                ConnectorError::Dispatch(format!(
                    "tablestore primary key {name:?} needs a base64 JSON string"
                ))
            })
            .map(OtsValue::Binary),
    }
}

fn coerce_attr(
    value: &serde_json::Value,
    data_type: AttributeColumnType,
    name: &str,
) -> Result<OtsValue> {
    match data_type {
        AttributeColumnType::String => value
            .as_str()
            .map(|s| OtsValue::String(s.to_string()))
            .ok_or_else(|| {
                ConnectorError::Dispatch(format!(
                    "tablestore attribute {name:?} needs a JSON string"
                ))
            }),
        AttributeColumnType::Integer => as_integer(value).map(OtsValue::Integer).ok_or_else(|| {
            ConnectorError::Dispatch(format!(
                "tablestore attribute {name:?} needs a JSON integer"
            ))
        }),
        AttributeColumnType::Double => value.as_f64().map(OtsValue::Double).ok_or_else(|| {
            ConnectorError::Dispatch(format!("tablestore attribute {name:?} needs a JSON number"))
        }),
        AttributeColumnType::Boolean => value.as_bool().map(OtsValue::Boolean).ok_or_else(|| {
            ConnectorError::Dispatch(format!(
                "tablestore attribute {name:?} needs a JSON boolean"
            ))
        }),
        AttributeColumnType::Binary => value
            .as_str()
            .map(decode_binary)
            .transpose()?
            .ok_or_else(|| {
                ConnectorError::Dispatch(format!(
                    "tablestore attribute {name:?} needs a base64 JSON string"
                ))
            })
            .map(OtsValue::Binary),
    }
}

/// Integers accept whole-valued floats (1.0 -> 1); anything else fails.
fn as_integer(value: &serde_json::Value) -> Option<i64> {
    match value {
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Some(i)
            } else if let Some(f) = n.as_f64() {
                if f.fract() == 0.0 && f >= i64::MIN as f64 && f <= i64::MAX as f64 {
                    Some(f as i64)
                } else {
                    None
                }
            } else {
                None
            }
        }
        _ => None,
    }
}

fn decode_binary(text: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(|e| ConnectorError::Dispatch(format!("tablestore binary is not base64: {e}")))
}

// ---------------------------------------------------------------------------
// OTS HTTP signature (clean-room HMAC-SHA1).
// ---------------------------------------------------------------------------

/// Base64(MD5(body)) for `x-ots-contentmd5`.
pub fn content_md5_b64(body: &[u8]) -> String {
    use base64::Engine;
    use md5::Digest;
    let mut digest = md5::Md5::new();
    digest.update(body);
    base64::engine::general_purpose::STANDARD.encode(digest.finalize())
}

/// Build the OTS `StringToSign` for `POST /api/BatchWriteRow`.
///
/// ```text
/// /api/BatchWriteRow\nPOST\n{content_md5}\n
/// x-ots-apiversion:2015-12-31\nx-ots-date:{date}\n
/// x-ots-instancename:{instance}\n
/// ```
pub fn string_to_sign(content_md5: &str, date: &str, instance: &str) -> String {
    format!(
        "{BATCH_WRITE_ROW_PATH}\nPOST\n{content_md5}\n\
         x-ots-apiversion:{OTS_API_VERSION}\n\
         x-ots-date:{date}\n\
         x-ots-instancename:{instance}\n"
    )
}

/// `Authorization: OTS {access_key_id}:{Base64(HMAC_SHA1(secret, sts))}`.
pub fn ots_authorization(
    access_key_id: &str,
    access_key_secret: &str,
    string_to_sign: &str,
) -> String {
    use base64::Engine;
    let signature = base64::engine::general_purpose::STANDARD.encode(hmac_sha1(
        access_key_secret.as_bytes(),
        string_to_sign.as_bytes(),
    ));
    format!("OTS {access_key_id}:{signature}")
}

// ---------------------------------------------------------------------------
// BatchWriteRow body + response.
// ---------------------------------------------------------------------------

/// One resolved put-row: coerced primary keys + attributes.
#[derive(Debug, Clone)]
pub struct OtsRow {
    pub primary_keys: Vec<(String, OtsValue)>,
    pub attributes: Vec<(String, OtsValue)>,
    pub timestamp_ms: i64,
}

/// Render the BatchWriteRow JSON body for `table` + `rows`.
pub fn render_batch_body(table: &str, rows: &[OtsRow]) -> Vec<u8> {
    let encoded: Vec<serde_json::Value> = rows
        .iter()
        .map(|row| {
            serde_json::json!({
                "operation": "put",
                "primary_keys": row.primary_keys.iter().map(|(name, value)| {
                    serde_json::json!({
                        "name": name,
                        "type": value.type_tag(),
                        "value": value.wire_value(),
                    })
                }).collect::<Vec<_>>(),
                "attributes": row.attributes.iter().map(|(name, value)| {
                    serde_json::json!({
                        "name": name,
                        "type": value.type_tag(),
                        "value": value.wire_value(),
                        "timestamp_ms": row.timestamp_ms,
                    })
                }).collect::<Vec<_>>(),
            })
        })
        .collect();
    serde_json::json!({ "tables": [{ "table_name": table, "rows": encoded }] })
        .to_string()
        .into_bytes()
}

/// Per-row failure extracted from a BatchWriteRow response body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtsRowFailure {
    pub index: usize,
    pub error_code: String,
}

/// Parse `{"tables":[{"rows":[{"is_ok":bool,"error_code":...}]}]}`,
/// returning the indices of failed rows. Malformed bodies are a
/// dispatch error (never silently committed).
pub fn failed_positions(body: &[u8], row_count: usize) -> Result<Vec<OtsRowFailure>> {
    let parsed: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| ConnectorError::Dispatch(format!("tablestore response is not JSON: {e}")))?;
    let rows = parsed
        .get("tables")
        .and_then(|t| t.as_array())
        .and_then(|t| t.first())
        .and_then(|t| t.get("rows"))
        .and_then(|r| r.as_array())
        .ok_or_else(|| {
            ConnectorError::Dispatch("tablestore response misses tables[0].rows".to_string())
        })?;
    if rows.len() != row_count {
        return Err(ConnectorError::Dispatch(format!(
            "tablestore response has {} rows for {row_count} sent",
            rows.len()
        )));
    }
    let mut failed = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        let ok = row.get("is_ok").and_then(|v| v.as_bool()).unwrap_or(false);
        if !ok {
            let error_code = row
                .get("error_code")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown")
                .to_string();
            failed.push(OtsRowFailure { index, error_code });
        }
    }
    Ok(failed)
}

/// OTS error-code classification: parameter/auth failures are
/// terminal; throttles and server-busy are retryable with backoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtsOutcome {
    Success,
    Retryable,
    Terminal,
}

pub fn classify_error_code(code: &str) -> OtsOutcome {
    match code {
        "OTSParameterInvalid" | "OTSAuthFailed" | "OTSObjectNotExist" | "OTSConditionCheckFail" => {
            OtsOutcome::Terminal
        }
        "OTSTooFrequent" | "OTSServerBusy" | "OTSTimeout" | "OTSRowOperationFailed" => {
            OtsOutcome::Retryable
        }
        _ => OtsOutcome::Retryable,
    }
}

pub fn classify_http_status(status: u16) -> OtsOutcome {
    match status {
        200..=299 => OtsOutcome::Success,
        429 => OtsOutcome::Retryable,
        400..=499 => OtsOutcome::Terminal,
        _ => OtsOutcome::Retryable,
    }
}

// ---------------------------------------------------------------------------
// Transport.
// ---------------------------------------------------------------------------

/// Scripted outcome for the mock transport.
#[derive(Debug, Clone)]
pub enum MockTablestoreOutcome {
    Accepted,
    /// Rows failing transiently (requeued selectively).
    PartialFailed(Vec<usize>),
    /// Whole-batch throttle (retries everything).
    Throttled,
    /// Terminal dispatch failure.
    Terminal(String),
    /// Transport failure (retries in-loop).
    ConnectionError(String),
}

#[async_trait]
pub trait TablestoreTransport: Send + Sync {
    /// Write one batch; returns the positions of failed rows.
    async fn batch_write(
        &self,
        table: &str,
        rows: Vec<OtsRow>,
        auth: &TablestoreAuth,
    ) -> Result<Vec<usize>>;
}

/// Request auth material: proof the signer ran.
#[derive(Debug, Clone)]
pub struct TablestoreAuth {
    pub date: String,
    pub content_md5: String,
    pub authorization: String,
}

/// In-memory transport with scripted outcomes (tests, dry runs).
#[derive(Debug, Default)]
pub struct MockTablestoreTransport {
    scripted: parking_lot::Mutex<std::collections::VecDeque<MockTablestoreOutcome>>,
    captured: parking_lot::Mutex<Vec<Vec<OtsRow>>>,
    pub last_auth: parking_lot::Mutex<Option<TablestoreAuth>>,
    calls: AtomicU64,
}

impl MockTablestoreTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_outcome(&self, outcome: MockTablestoreOutcome) {
        self.scripted.lock().push_back(outcome);
    }

    pub fn captured(&self) -> Vec<Vec<OtsRow>> {
        self.captured.lock().clone()
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl TablestoreTransport for MockTablestoreTransport {
    async fn batch_write(
        &self,
        _table: &str,
        rows: Vec<OtsRow>,
        auth: &TablestoreAuth,
    ) -> Result<Vec<usize>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.last_auth.lock() = Some(auth.clone());
        self.captured.lock().push(rows);
        match self.scripted.lock().pop_front() {
            None | Some(MockTablestoreOutcome::Accepted) => Ok(Vec::new()),
            Some(MockTablestoreOutcome::PartialFailed(failed)) => Ok(failed),
            Some(MockTablestoreOutcome::Throttled) => Err(ConnectorError::Connection(
                "mock tablestore throttled".to_string(),
            )),
            Some(MockTablestoreOutcome::Terminal(message)) => {
                Err(ConnectorError::Dispatch(message))
            }
            Some(MockTablestoreOutcome::ConnectionError(message)) => {
                Err(ConnectorError::Connection(message))
            }
        }
    }
}

/// HTTP transport: `POST {endpoint}/api/BatchWriteRow` with the OTS
/// date/version/instance/md5 headers plus the signature. Failed row
/// positions come from the response body; whole-call failures map by
/// error code (terminal) or status (retryable/terminal).
pub struct HttpTablestoreTransport {
    config: TablestoreSinkConfig,
    client: reqwest::Client,
}

impl HttpTablestoreTransport {
    pub fn new(config: &TablestoreSinkConfig, client: reqwest::Client) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config: config.clone(),
            client,
        })
    }
}

#[async_trait]
impl TablestoreTransport for HttpTablestoreTransport {
    async fn batch_write(
        &self,
        table: &str,
        rows: Vec<OtsRow>,
        _auth: &TablestoreAuth,
    ) -> Result<Vec<usize>> {
        // The signer runs per attempt inside the transport so replays
        // never reuse a stale `x-ots-date` header.
        let body = render_batch_body(table, &rows);
        let date = super::oci_streaming::rfc1123_date(now_millis());
        let content_md5 = content_md5_b64(&body);
        let authorization = ots_authorization(
            &self.config.access_key_id,
            &self.config.access_key_secret,
            &string_to_sign(&content_md5, &date, &self.config.instance_name),
        );
        let url = format!(
            "{}{BATCH_WRITE_ROW_PATH}",
            self.config.endpoint.trim_end_matches('/')
        );
        let response = self
            .client
            .post(&url)
            .header("x-ots-date", &date)
            .header("x-ots-apiversion", OTS_API_VERSION)
            .header("x-ots-instancename", &self.config.instance_name)
            .header("x-ots-contentmd5", &content_md5)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::AUTHORIZATION, authorization)
            .body(body)
            .send()
            .await
            .map_err(|e| ConnectorError::Connection(format!("tablestore write failed: {e}")))?;
        let status = response.status().as_u16();
        let bytes = response
            .bytes()
            .await
            .map_err(|e| ConnectorError::Connection(format!("tablestore read failed: {e}")))?;
        match classify_http_status(status) {
            OtsOutcome::Success => {}
            OtsOutcome::Retryable => {
                return Err(ConnectorError::Connection(format!(
                    "tablestore {table} answered {status}"
                )))
            }
            OtsOutcome::Terminal => {
                return Err(ConnectorError::Dispatch(format!(
                    "tablestore {table} answered {status}"
                )))
            }
        }
        let failures = failed_positions(&bytes, rows.len())?;
        if failures.is_empty() {
            return Ok(Vec::new());
        }
        // Terminal row errors fail the batch loudly; retryable row
        // errors requeue selectively.
        let mut retryable = Vec::new();
        for failure in &failures {
            match classify_error_code(&failure.error_code) {
                OtsOutcome::Terminal => {
                    return Err(ConnectorError::Dispatch(format!(
                        "tablestore row {} failed terminally: {}",
                        failure.index, failure.error_code
                    )))
                }
                _ => retryable.push(failure.index),
            }
        }
        Ok(retryable)
    }
}

// ---------------------------------------------------------------------------
// Sink.
// ---------------------------------------------------------------------------

/// One buffered event: raw topic + parsed JSON payload.
#[derive(Debug, Clone)]
struct TablestoreRow {
    topic: String,
    payload: serde_json::Value,
}

/// Tablestore sink: buffers events, writes typed batches with
/// selective failed-row requeue.
pub struct TablestoreSink {
    config: TablestoreSinkConfig,
    transport: Arc<dyn TablestoreTransport>,
    buffer: parking_lot::Mutex<BatchQueue<TablestoreRow>>,
    backoff: parking_lot::Mutex<BackoffState>,
    sent_batches: AtomicU64,
    sent_records: AtomicU64,
}

impl TablestoreSink {
    pub fn new(
        config: TablestoreSinkConfig,
        transport: Arc<dyn TablestoreTransport>,
    ) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            buffer: parking_lot::Mutex::new(BatchQueue::new(
                config.effective_batch_size(),
                config.linger(),
            )),
            config,
            transport,
            backoff: parking_lot::Mutex::new(BackoffState::default()),
            sent_batches: AtomicU64::new(0),
            sent_records: AtomicU64::new(0),
        })
    }

    pub fn config(&self) -> &TablestoreSinkConfig {
        &self.config
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

    /// Resolve one buffered event into a typed put-row.
    fn resolve_row(&self, event: &TablestoreRow, millis: i64) -> Result<OtsRow> {
        let mut primary_keys = Vec::with_capacity(self.config.primary_keys.len());
        for mapping in &self.config.primary_keys {
            let source = parse_source(&mapping.source).map_err(ConnectorError::Dispatch)?;
            let value = resolve_source(&source, &event.topic, &event.payload, millis);
            primary_keys.push((
                mapping.name.clone(),
                coerce_pk(&value, mapping.data_type, &mapping.name)?,
            ));
        }
        let mut attributes = Vec::with_capacity(self.config.attribute_columns.len());
        for mapping in &self.config.attribute_columns {
            let source = parse_source(&mapping.source).map_err(ConnectorError::Dispatch)?;
            let value = resolve_source(&source, &event.topic, &event.payload, millis);
            attributes.push((
                mapping.name.clone(),
                coerce_attr(&value, mapping.data_type, &mapping.name)?,
            ));
        }
        Ok(OtsRow {
            primary_keys,
            attributes,
            timestamp_ms: millis,
        })
    }

    /// Flush buffered events (no-op when empty). Failed rows requeue
    /// selectively; throttles retry everything; terminal outcomes
    /// restore the pending set and propagate.
    pub async fn flush(&self) -> Result<()> {
        self.backoff.lock().check()?;
        let (events, oldest) = {
            let mut buffer = self.buffer.lock();
            buffer.take_batch()
        };
        if events.is_empty() {
            return Ok(());
        }
        let millis = now_millis();
        let mut pending: Vec<(TablestoreRow, OtsRow)> = Vec::with_capacity(events.len());
        for event in &events {
            pending.push((event.clone(), self.resolve_row(event, millis)?));
        }
        let total = pending.len() as u64;
        let auth = TablestoreAuth {
            date: super::oci_streaming::rfc1123_date(millis),
            content_md5: String::new(),
            authorization: String::new(),
        };
        loop {
            let rows: Vec<OtsRow> = pending.iter().map(|(_, row)| row.clone()).collect();
            match self
                .transport
                .batch_write(&self.config.table_name, rows, &auth)
                .await
            {
                Ok(failed) if failed.is_empty() => {
                    self.backoff.lock().success();
                    self.sent_batches.fetch_add(1, Ordering::Relaxed);
                    self.sent_records.fetch_add(total, Ordering::Relaxed);
                    return Ok(());
                }
                Ok(failed) => {
                    // Selective requeue: keep only failed positions.
                    let mut next = Vec::with_capacity(failed.len());
                    for index in failed {
                        if let Some(entry) = pending.get(index).cloned() {
                            next.push(entry);
                        }
                    }
                    pending = next;
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(ConnectorError::Connection(message)) => {
                    let mut buffer = self.buffer.lock();
                    buffer.restore(
                        pending.into_iter().map(|(event, _)| event).collect(),
                        oldest,
                    );
                    self.backoff.lock().failure();
                    return Err(ConnectorError::Connection(message));
                }
                Err(e) => {
                    let mut buffer = self.buffer.lock();
                    buffer.restore(
                        pending.into_iter().map(|(event, _)| event).collect(),
                        oldest,
                    );
                    self.backoff.lock().failure();
                    return Err(e);
                }
            }
        }
    }

    /// Validate + buffer one event. Returns true when the batch is
    /// full or stale (caller flushes).
    fn buffer_row(&self, topic: &Topic, payload: &Bytes, _qos: QoS) -> Result<bool> {
        if topic.as_str().is_empty() {
            return Err(ConnectorError::Dispatch(
                "tablestore row requires a non-empty topic".to_string(),
            ));
        }
        if self.buffer.lock().len() >= self.config.effective_buffer() {
            return Err(ConnectorError::Connection(
                "tablestore buffer limit reached".to_string(),
            ));
        }
        let text = std::str::from_utf8(payload).map_err(|_| {
            ConnectorError::Dispatch("tablestore payload must be UTF-8".to_string())
        })?;
        let parsed: serde_json::Value = serde_json::from_str(text)
            .map_err(|_| ConnectorError::Dispatch("tablestore payload must be JSON".to_string()))?;
        let mut buffer = self.buffer.lock();
        Ok(buffer.push(TablestoreRow {
            topic: topic.as_str().to_string(),
            payload: parsed,
        }))
    }
}

#[async_trait]
impl Sink for TablestoreSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        if self.buffer_row(topic, payload, qos)? {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "tablestore"
    }
}

/// Management connector handle pairing an id with a Tablestore sink.
pub struct TablestoreConnector {
    id: String,
    sink: Arc<TablestoreSink>,
}

impl TablestoreConnector {
    pub fn new(id: impl Into<String>, sink: Arc<TablestoreSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }
}

impl super::Connector for TablestoreConnector {
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

    fn test_config() -> TablestoreSinkConfig {
        TablestoreSinkConfig {
            endpoint: "https://test-instance.cn-hangzhou.ots.aliyuncs.com".to_string(),
            instance_name: "test-instance".to_string(),
            table_name: "telemetry".to_string(),
            access_key_id: "test-key-id".to_string(),
            access_key_secret: "ots-secret-key".to_string(),
            primary_keys: vec![
                PrimaryKeyMapping {
                    name: "device_id".to_string(),
                    source: "${client_id}".to_string(),
                    data_type: PrimaryKeyType::String,
                },
                PrimaryKeyMapping {
                    name: "ts".to_string(),
                    source: "${timestamp}".to_string(),
                    data_type: PrimaryKeyType::Integer,
                },
            ],
            attribute_columns: vec![
                AttributeColumnMapping {
                    name: "temperature".to_string(),
                    source: "${payload.temperature}".to_string(),
                    data_type: AttributeColumnType::Double,
                },
                AttributeColumnMapping {
                    name: "online".to_string(),
                    source: "${payload.online}".to_string(),
                    data_type: AttributeColumnType::Boolean,
                },
            ],
            batch_size: Some(200),
            buffer_capacity: None,
            linger_ms: Some(100),
        }
    }

    #[test]
    fn test_config_validation() {
        let mut config = test_config();
        assert!(config.validate().is_ok());

        config.endpoint = "test-instance.cn-hangzhou.ots.aliyuncs.com".to_string();
        assert!(config.validate().is_err());
        config.endpoint = test_config().endpoint;

        config.primary_keys.clear();
        assert!(config.validate().is_err());
        config.primary_keys = test_config().primary_keys;

        config.primary_keys[0].source = "${bogus}".to_string();
        assert!(config.validate().is_err());
        config.primary_keys[0].source = "bare-literal".to_string();
        assert!(config.validate().is_err());
        config.primary_keys = test_config().primary_keys;

        config.attribute_columns[0].name = String::new();
        assert!(config.validate().is_err());
        config.attribute_columns = test_config().attribute_columns;

        config.batch_size = Some(0);
        assert!(config.validate().is_err());
        config.batch_size = Some(10_000_000);

        // Zero clamped ceilings: huge depths are accepted.
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_string_to_sign_builder() {
        let sts = string_to_sign(
            "TQ2eDTYmow8FFE+K3ZTCaQ==",
            "Sat, 12 Sep 2026 11:18:09 GMT",
            "test-instance",
        );
        assert_eq!(
            sts,
            "/api/BatchWriteRow\nPOST\nTQ2eDTYmow8FFE+K3ZTCaQ==\n\
             x-ots-apiversion:2015-12-31\n\
             x-ots-date:Sat, 12 Sep 2026 11:18:09 GMT\n\
             x-ots-instancename:test-instance\n"
        );
    }

    #[test]
    fn test_signature_and_md5_known_answers() {
        // Independent Python (hashlib/hmac/base64) vectors: body
        // b'{"tables":[{"table_name":"telemetry","rows":[]}]}'.
        let body = br#"{"tables":[{"table_name":"telemetry","rows":[]}]}"#;
        assert_eq!(content_md5_b64(body), "TQ2eDTYmow8FFE+K3ZTCaQ==");
        let auth = ots_authorization(
            "test-key-id",
            "ots-secret-key",
            &string_to_sign(
                "TQ2eDTYmow8FFE+K3ZTCaQ==",
                "Sat, 12 Sep 2026 11:18:09 GMT",
                "test-instance",
            ),
        );
        assert_eq!(auth, "OTS test-key-id:mYwrpL5qsREFQmkJKGtEGZaa3DE=");
    }

    #[test]
    fn test_source_parsing_and_coercion() {
        assert_eq!(parse_source("${client_id}").unwrap(), FieldSource::ClientId);
        assert_eq!(parse_source("${topic}").unwrap(), FieldSource::Topic);
        assert_eq!(
            parse_source("${timestamp}").unwrap(),
            FieldSource::Timestamp
        );
        assert_eq!(
            parse_source("${payload.a.b}").unwrap(),
            FieldSource::Payload(vec!["a".to_string(), "b".to_string()])
        );
        assert!(parse_source("client_id").is_err());
        assert!(parse_source("${bogus}").is_err());
        assert!(parse_source("${}").is_err());
        assert!(parse_source("${payload.}").is_err());

        // Integer coercion accepts whole floats, rejects fractions.
        assert_eq!(as_integer(&serde_json::json!(7)), Some(7));
        assert_eq!(as_integer(&serde_json::json!(7.0)), Some(7));
        assert_eq!(as_integer(&serde_json::json!(7.5)), None);
        assert_eq!(as_integer(&serde_json::json!("7")), None);

        // Binary is strict base64.
        assert_eq!(decode_binary("aGk=").unwrap(), b"hi");
        assert!(decode_binary("***").is_err());

        // Full mapping coercion errors name the column.
        assert!(coerce_pk(&serde_json::json!(1), PrimaryKeyType::String, "k").is_err());
        assert_eq!(
            coerce_attr(&serde_json::json!(1), AttributeColumnType::Double, "t").unwrap(),
            OtsValue::Double(1.0)
        );
        assert!(coerce_attr(&serde_json::json!("x"), AttributeColumnType::Boolean, "b").is_err());
    }

    #[test]
    fn test_batch_body_encoding() {
        let rows = vec![OtsRow {
            primary_keys: vec![
                (
                    "device_id".to_string(),
                    OtsValue::String("sensor-42".to_string()),
                ),
                ("ts".to_string(), OtsValue::Integer(1_789_211_889_123)),
            ],
            attributes: vec![
                ("temperature".to_string(), OtsValue::Double(22.5)),
                ("online".to_string(), OtsValue::Boolean(true)),
                ("raw".to_string(), OtsValue::Binary(vec![0xDE, 0xAD])),
            ],
            timestamp_ms: 1_789_211_889_123,
        }];
        let body = render_batch_body("telemetry", &rows);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let tables = parsed["tables"].as_array().unwrap();
        assert_eq!(tables[0]["table_name"], "telemetry");
        let encoded = &tables[0]["rows"][0];
        assert_eq!(encoded["operation"], "put");
        assert_eq!(encoded["primary_keys"][0]["value"], "sensor-42");
        assert_eq!(encoded["primary_keys"][1]["type"], "integer");
        assert_eq!(
            encoded["attributes"][0]["timestamp_ms"],
            serde_json::json!(1_789_211_889_123i64)
        );
        assert_eq!(encoded["attributes"][2]["type"], "binary");
        assert_eq!(encoded["attributes"][2]["value"], "3q0=");
    }

    #[test]
    fn test_failed_positions_and_classification() {
        let ok = br#"{"tables":[{"rows":[{"is_ok":true},{"is_ok":true}]}]}"#;
        assert!(failed_positions(ok, 2).unwrap().is_empty());
        let partial = br#"{"tables":[{"rows":[{"is_ok":true},{"is_ok":false,"error_code":"OTSRowOperationFailed"},{"is_ok":false,"error_code":"OTSTimeout"}]}]}"#;
        assert_eq!(
            failed_positions(partial, 3).unwrap(),
            vec![
                OtsRowFailure {
                    index: 1,
                    error_code: "OTSRowOperationFailed".to_string()
                },
                OtsRowFailure {
                    index: 2,
                    error_code: "OTSTimeout".to_string()
                },
            ]
        );
        assert!(failed_positions(ok, 3).is_err(), "count mismatch must fail");
        assert!(failed_positions(b"nope", 1).is_err());

        assert_eq!(
            classify_error_code("OTSParameterInvalid"),
            OtsOutcome::Terminal
        );
        assert_eq!(classify_error_code("OTSAuthFailed"), OtsOutcome::Terminal);
        assert_eq!(classify_error_code("OTSTooFrequent"), OtsOutcome::Retryable);
        assert_eq!(classify_error_code("OTSServerBusy"), OtsOutcome::Retryable);
        assert_eq!(classify_error_code("OTSTimeout"), OtsOutcome::Retryable);
        assert_eq!(
            classify_error_code("OTSRowOperationFailed"),
            OtsOutcome::Retryable
        );
        assert_eq!(classify_http_status(200), OtsOutcome::Success);
        assert_eq!(classify_http_status(400), OtsOutcome::Terminal);
        assert_eq!(classify_http_status(403), OtsOutcome::Terminal);
        assert_eq!(classify_http_status(429), OtsOutcome::Retryable);
        assert_eq!(classify_http_status(500), OtsOutcome::Retryable);
    }

    #[tokio::test]
    async fn test_selective_requeue_flow() {
        let transport = Arc::new(MockTablestoreTransport::new());
        transport.push_outcome(MockTablestoreOutcome::PartialFailed(vec![1]));
        let mut config = test_config();
        config.batch_size = Some(10);
        let sink = TablestoreSink::new(config, transport.clone()).unwrap();

        let topic = Topic::new("sensors/kitchen").unwrap();
        for i in 0..3 {
            let payload = Bytes::from(format!(
                r#"{{"client_id":"d{i}","temperature":{},"online":true}}"#,
                20.0 + i as f64
            ));
            sink.send(&topic, &payload, QoS::AtMostOnce).await.unwrap();
        }
        sink.flush().await.unwrap();
        // First call wrote 3 rows, second call retried only row 1.
        let captured = transport.captured();
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[0].len(), 3);
        assert_eq!(captured[1].len(), 1);
        assert_eq!(
            captured[1][0].primary_keys[0].1,
            OtsValue::String("d1".to_string())
        );
        assert_eq!(sink.sent_batches(), 1);
        assert_eq!(sink.sent_records(), 3);
        // The mock records calls (per-attempt signing lives in the
        // HTTP transport and is covered by the loopback test).
        assert_eq!(transport.calls(), 2);

        // Throttle restores the whole batch and backs off.
        transport.push_outcome(MockTablestoreOutcome::Throttled);
        sink.send(
            &topic,
            &Bytes::from(r#"{"client_id":"dx","temperature":21.0,"online":false}"#),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        let err = sink.flush().await.expect_err("throttle must fail");
        assert!(matches!(err, ConnectorError::Connection(_)));
        assert_eq!(sink.buffered_rows(), 1);
    }

    #[tokio::test]
    async fn test_loopback_headers_and_body() {
        use axum::{extract::State, http::StatusCode, routing::post, Router};

        #[derive(Debug, Default)]
        struct Captured {
            inner: parking_lot::Mutex<Vec<CapturedCall>>,
        }
        #[derive(Debug)]
        struct CapturedCall {
            path: String,
            date: Option<String>,
            version: Option<String>,
            instance: Option<String>,
            md5: Option<String>,
            auth: Option<String>,
            body: Vec<u8>,
        }

        async fn handler(
            headers: axum::http::HeaderMap,
            uri: axum::http::Uri,
            State(state): State<Arc<Captured>>,
            body: Bytes,
        ) -> (StatusCode, String) {
            let get = |name: &str| {
                headers
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string)
            };
            state.inner.lock().push(CapturedCall {
                path: uri.path().to_string(),
                date: get("x-ots-date"),
                version: get("x-ots-apiversion"),
                instance: get("x-ots-instancename"),
                md5: get("x-ots-contentmd5"),
                auth: get("authorization"),
                body: body.to_vec(),
            });
            (
                StatusCode::OK,
                r#"{"tables":[{"rows":[{"is_ok":true}]}]}"#.to_string(),
            )
        }
        let captured = Arc::new(Captured::default());
        let app = Router::new().route(
            "/api/BatchWriteRow",
            post({
                let captured = captured.clone();
                move |headers: axum::http::HeaderMap, uri: axum::http::Uri, body: Bytes| {
                    let captured = captured.clone();
                    async move { handler(headers, uri, State(captured), body).await }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        let mut config = test_config();
        config.endpoint = format!("http://127.0.0.1:{port}");
        config.batch_size = Some(1);
        let transport =
            Arc::new(HttpTablestoreTransport::new(&config, reqwest::Client::new()).unwrap());
        let sink = TablestoreSink::new(config, transport).unwrap();
        sink.send(
            &Topic::new("sensors/t1").unwrap(),
            &Bytes::from(r#"{"client_id":"sensor-42","temperature":22.5,"online":false}"#),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        assert_eq!(sink.sent_batches(), 1);

        let calls = captured.inner.lock();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].path, "/api/BatchWriteRow");
        assert_eq!(calls[0].version.as_deref(), Some("2015-12-31"));
        assert_eq!(calls[0].instance.as_deref(), Some("test-instance"));
        assert!(calls[0].date.as_deref().unwrap().ends_with("GMT"));
        assert!(calls[0]
            .auth
            .as_deref()
            .unwrap()
            .starts_with("OTS test-key-id:"));
        // Content-MD5 matches the received body.
        assert_eq!(
            calls[0].md5.as_deref(),
            Some(content_md5_b64(&calls[0].body).as_str())
        );
        let parsed: serde_json::Value = serde_json::from_slice(&calls[0].body).unwrap();
        let rows = parsed["tables"][0]["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["primary_keys"][0]["value"], "sensor-42");
        assert_eq!(rows[0]["attributes"][0]["value"], 22.5);
        server.abort();
    }
}
