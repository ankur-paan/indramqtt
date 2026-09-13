//! Apache Doris stream load sink (INDRA-185).
//!
//! Buffers MQTT events as JSON documents (or CSV rows) and ingests
//! them with the 2-phase HTTP Stream Load protocol (`PUT
//! http://{fe}:{port}/api/{db}/{table}/_stream_load`): unique label
//! per flush, `Expect: 100-continue`, and a `Status` envelope in the
//! reply. `Success` completes; `Publish Timeout` / `Label Already
//! Exists` retry (fresh label per attempt); other statuses are
//! terminal. HTTP 307 redirects to BE nodes are followed with headers
//! preserved (same-origin; cross-origin auth limits documented).

use async_trait::async_trait;
use base64::Engine;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::{now_millis, render_template, BackoffState, BatchQueue, ConnectorError, Result, Sink};

/// Doris authentication (HTTP Basic).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DorisAuth {
    pub username: String,
    pub password: String,
}

impl DorisAuth {
    pub fn header_value(&self) -> Result<String> {
        if self.username.is_empty() {
            return Err(ConnectorError::Dispatch(
                "doris username must not be empty".to_string(),
            ));
        }
        let credentials = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", self.username, self.password));
        Ok(format!("Basic {credentials}"))
    }
}

/// Stream load body format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DorisFormat {
    /// JSON array with `strip_outer_array: true`.
    #[default]
    Json,
    /// One CSV row per record.
    Csv,
}

fn default_http_port() -> u16 {
    8030
}

fn default_batch_size() -> Option<usize> {
    Some(1_000)
}

fn default_batch_bytes() -> Option<usize> {
    Some(4_194_304)
}

fn default_linger_ms() -> Option<u64> {
    Some(10)
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

fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Doris sink configuration. All depths are optional (`None` =
/// unbounded) with zero clamped ceilings. (`Eq` is skipped: ratios
/// are floating point.)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DorisSinkConfig {
    /// Frontend host or load balancer address.
    pub fe_host: String,
    /// FE HTTP port (default 8030).
    #[serde(default = "default_http_port")]
    pub http_port: u16,
    /// Target database name.
    pub database: String,
    /// Table template (`${topic}`, `${client_id}`, ...).
    pub table_template: String,
    pub auth: DorisAuth,
    /// Body format (default JSON array).
    #[serde(default)]
    pub format: DorisFormat,
    /// Custom `jsonpaths` header value.
    #[serde(default)]
    pub jsonpaths: Option<String>,
    /// `strip_outer_array` header (default true for array batches).
    #[serde(default = "default_true")]
    pub strip_outer_array: bool,
    /// `max_filter_ratio` header (default 0.0 strict).
    #[serde(default)]
    pub max_filter_ratio: Option<f64>,
    /// Records per load (default 1000).
    #[serde(default = "default_batch_size")]
    pub batch_size: Option<usize>,
    /// Batch byte limit (default 4 MiB).
    #[serde(default = "default_batch_bytes")]
    pub batch_bytes: Option<usize>,
    /// Linger flush window in ms (default 10).
    #[serde(default = "default_linger_ms")]
    pub linger_ms: Option<u64>,
    /// Retries on timeouts/label conflicts (default 4, `None`
    /// unbounded, 0 none).
    #[serde(default = "default_max_retries")]
    pub max_retries: Option<usize>,
    /// First retry delay in ms (default 100).
    #[serde(default = "default_initial_backoff_ms")]
    pub initial_backoff_ms: Option<u64>,
    /// Retry delay ceiling in ms (default 2000).
    #[serde(default = "default_max_backoff_ms")]
    pub max_backoff_ms: Option<u64>,
}

fn default_true() -> bool {
    true
}

impl DorisSinkConfig {
    pub fn validate(&self) -> Result<()> {
        if self.fe_host.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "doris fe_host must not be empty".to_string(),
            ));
        }
        if self.http_port == 0 {
            return Err(ConnectorError::Dispatch(
                "doris http_port must be 1..=65535".to_string(),
            ));
        }
        if !is_identifier(&self.database) {
            return Err(ConnectorError::Dispatch(format!(
                "doris database must match [A-Za-z0-9_]+: {:?}",
                self.database
            )));
        }
        if self.table_template.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "doris table_template must not be empty".to_string(),
            ));
        }
        self.resolve_table("dummy/topic", b"{}", QoS::AtMostOnce, 0)?;
        self.auth.header_value().map(|_| ())?;
        if let Some(ratio) = self.max_filter_ratio {
            if !(0.0..=1.0).contains(&ratio) {
                return Err(ConnectorError::Dispatch(format!(
                    "doris max_filter_ratio must be 0.0..=1.0: {ratio}"
                )));
            }
        }
        if self.batch_size == Some(0) {
            return Err(ConnectorError::Dispatch(
                "doris batch_size must be >= 1".to_string(),
            ));
        }
        if self.batch_bytes == Some(0) {
            return Err(ConnectorError::Dispatch(
                "doris batch_bytes must be >= 1".to_string(),
            ));
        }
        Ok(())
    }

    /// `PUT http://{fe}:{port}/api/{db}/{table}/_stream_load`.
    pub fn load_url(&self, table: &str) -> String {
        format!(
            "http://{}:{}/api/{}/{}/_stream_load",
            self.fe_host, self.http_port, self.database, table
        )
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

    /// Resolve + validate the table for one event.
    pub fn resolve_table(
        &self,
        topic: &str,
        payload: &[u8],
        qos: QoS,
        millis: i64,
    ) -> Result<String> {
        let vars = Self::template_vars(topic, payload, qos, millis);
        let borrowed: Vec<(&str, String)> =
            vars.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
        let table = render_template(&self.table_template, &borrowed)?;
        if !is_identifier(&table) {
            return Err(ConnectorError::Dispatch(format!(
                "doris table must match [A-Za-z0-9_]+: {table:?}"
            )));
        }
        Ok(table)
    }
}

// ---------------------------------------------------------------------------
// Wire framing.
// ---------------------------------------------------------------------------

/// Stream load request headers (besides auth + content type).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DorisHeaders {
    pub format: String,
    pub strip_outer_array: bool,
    pub label: String,
    pub jsonpaths: Option<String>,
    pub max_filter_ratio: Option<String>,
}

/// Parsed Stream Load reply envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DorisLoadResult {
    pub status: String,
    pub rows_loaded: u64,
}

/// Parse the `{"Status": ..., ...}` reply envelope.
pub fn parse_load_result(body: &[u8]) -> Result<DorisLoadResult> {
    let doc: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| ConnectorError::Connection(format!("doris bad reply JSON: {e}")))?;
    let status = doc
        .get("Status")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ConnectorError::Connection("doris reply lacks Status".to_string()))?
        .to_string();
    let rows_loaded = doc
        .get("NumberLoadedRows")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    Ok(DorisLoadResult {
        status,
        rows_loaded,
    })
}

/// Classify a load status: success, retryable (timeouts, label
/// conflicts) or terminal.
pub fn classify_status(status: &str) -> Result<()> {
    match status {
        "Success" => Ok(()),
        "Publish Timeout" | "Label Already Exists" => Err(ConnectorError::Connection(format!(
            "doris transient status: {status}"
        ))),
        other => Err(ConnectorError::Dispatch(format!(
            "doris terminal status: {other}"
        ))),
    }
}

/// Render the request body: JSON array or CSV lines.
pub fn render_body(format: DorisFormat, records: &[serde_json::Value]) -> Vec<u8> {
    match format {
        DorisFormat::Json => {
            let mut body = String::from("[");
            for (index, record) in records.iter().enumerate() {
                if index > 0 {
                    body.push(',');
                }
                body.push_str(&record.to_string());
            }
            body.push(']');
            body.into_bytes()
        }
        DorisFormat::Csv => {
            let mut body = Vec::new();
            for record in records {
                body.extend_from_slice(csv_row(record).as_bytes());
                body.push(b'\n');
            }
            body
        }
    }
}

/// One CSV row: timestamp, topic, qos, payload. Fields quote only
/// when they contain `,`, `"` or newlines (RFC 4180 minimal quoting).
fn csv_row(record: &serde_json::Value) -> String {
    let field = |value: &serde_json::Value| match value {
        serde_json::Value::String(text) => text.clone(),
        other => other.to_string(),
    };
    let cells = [
        field(record.get("timestamp").unwrap_or(&serde_json::Value::Null)),
        field(record.get("topic").unwrap_or(&serde_json::Value::Null)),
        field(record.get("qos").unwrap_or(&serde_json::Value::Null)),
        field(record.get("payload").unwrap_or(&serde_json::Value::Null)),
    ];
    cells
        .iter()
        .map(|cell| {
            if cell.contains([',', '"', '\n']) {
                format!("\"{}\"", cell.replace('"', "\"\""))
            } else {
                cell.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

// ---------------------------------------------------------------------------
// Transport.
// ---------------------------------------------------------------------------

/// Scripted outcome for the mock transport.
#[derive(Debug, Clone)]
pub enum MockDorisOutcome {
    Success {
        rows: u64,
    },
    /// Reply envelope status (transient statuses retry).
    Status(String),
    /// HTTP failure (429/503 retry the batch).
    HttpStatus(u16),
    /// Transport failure (retries in-loop).
    ConnectionError(String),
}

/// One captured stream load call.
#[derive(Debug, Clone)]
pub struct CapturedDorisLoad {
    pub db: String,
    pub table: String,
    pub body: Vec<u8>,
    pub headers: DorisHeaders,
    pub auth: String,
}

#[async_trait]
pub trait DorisTransport: Send + Sync {
    async fn stream_load(
        &self,
        db: &str,
        table: &str,
        data: &[u8],
        headers: &DorisHeaders,
        auth: &DorisAuth,
    ) -> Result<DorisLoadResult>;
}

/// In-memory transport with scripted outcomes (tests, dry runs).
#[derive(Debug, Default)]
pub struct MockDorisTransport {
    scripted: parking_lot::Mutex<std::collections::VecDeque<MockDorisOutcome>>,
    captured: parking_lot::Mutex<Vec<CapturedDorisLoad>>,
    calls: AtomicU64,
}

impl MockDorisTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue outcomes consumed in order (default: success).
    pub fn script_outcomes(&self, outcomes: Vec<MockDorisOutcome>) {
        *self.scripted.lock() = outcomes.into_iter().collect();
    }

    pub fn captured(&self) -> Vec<CapturedDorisLoad> {
        self.captured.lock().clone()
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl DorisTransport for MockDorisTransport {
    async fn stream_load(
        &self,
        db: &str,
        table: &str,
        data: &[u8],
        headers: &DorisHeaders,
        auth: &DorisAuth,
    ) -> Result<DorisLoadResult> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.captured.lock().push(CapturedDorisLoad {
            db: db.to_string(),
            table: table.to_string(),
            body: data.to_vec(),
            headers: headers.clone(),
            auth: auth.header_value().unwrap_or_default(),
        });
        match self.scripted.lock().pop_front() {
            None | Some(MockDorisOutcome::Success { .. }) => Ok(DorisLoadResult {
                status: "Success".to_string(),
                rows_loaded: 0,
            }),
            Some(MockDorisOutcome::Status(status)) => {
                classify_status(&status).map(|_| DorisLoadResult {
                    status,
                    rows_loaded: 0,
                })
            }
            Some(MockDorisOutcome::HttpStatus(status)) => Err(match status {
                429 | 503 => {
                    ConnectorError::Connection(format!("mock doris throttled with {status}"))
                }
                _ => ConnectorError::Dispatch(format!("mock doris failed with {status}")),
            }),
            Some(MockDorisOutcome::ConnectionError(message)) => {
                Err(ConnectorError::Connection(message))
            }
        }
    }
}

/// Production transport: `PUT {base}/api/{db}/{table}/_stream_load`
/// with Stream Load headers. reqwest follows 307 redirects to BE
/// nodes automatically (same origin keeps every header; cross-origin
/// drops `Authorization`, which the retry loop then surfaces loudly).
pub struct HttpDorisTransport {
    base: String,
    client: reqwest::Client,
}

impl HttpDorisTransport {
    pub fn new(config: &DorisSinkConfig, client: reqwest::Client) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            base: format!("http://{}:{}", config.fe_host, config.http_port),
            client,
        })
    }
}

#[async_trait]
impl DorisTransport for HttpDorisTransport {
    async fn stream_load(
        &self,
        db: &str,
        table: &str,
        data: &[u8],
        headers: &DorisHeaders,
        auth: &DorisAuth,
    ) -> Result<DorisLoadResult> {
        let url = format!("{}/api/{}/{}/_stream_load", self.base, db, table);
        let mut request = self
            .client
            .put(&url)
            .header(reqwest::header::AUTHORIZATION, auth.header_value()?)
            .header("format", headers.format.as_str())
            .header(
                "strip_outer_array",
                if headers.strip_outer_array {
                    "true"
                } else {
                    "false"
                },
            )
            .header("label", headers.label.as_str())
            .header("Expect", "100-continue")
            .body(data.to_vec());
        if let Some(jsonpaths) = &headers.jsonpaths {
            request = request.header("jsonpaths", jsonpaths.as_str());
        }
        if let Some(ratio) = &headers.max_filter_ratio {
            request = request.header("max_filter_ratio", ratio.as_str());
        }
        let response = request
            .send()
            .await
            .map_err(|e| ConnectorError::Connection(format!("doris load failed: {e}")))?;
        let status = response.status().as_u16();
        if status == 429 || status == 503 {
            return Err(ConnectorError::Connection(format!(
                "doris throttled with {status}"
            )));
        }
        if !(200..=299).contains(&status) {
            return Err(ConnectorError::Dispatch(format!(
                "doris load failed with {status}"
            )));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|e| ConnectorError::Connection(format!("doris read failed: {e}")))?;
        let result = parse_load_result(&bytes)?;
        classify_status(&result.status).map(|_| result)
    }
}

// ---------------------------------------------------------------------------
// Sink.
// ---------------------------------------------------------------------------

/// One buffered record: JSON document + resolved table.
#[derive(Debug, Clone)]
struct DorisRow {
    document: serde_json::Value,
    table: String,
}

struct DorisBuffer {
    queue: BatchQueue<DorisRow>,
    bytes: usize,
}

/// Doris sink: buffers records, stream-loads batches per table.
pub struct DorisSink {
    config: DorisSinkConfig,
    transport: Arc<dyn DorisTransport>,
    buffer: parking_lot::Mutex<DorisBuffer>,
    backoff: parking_lot::Mutex<BackoffState>,
    label_seq: AtomicU64,
    sent_batches: AtomicU64,
    sent_records: AtomicU64,
}

impl DorisSink {
    pub fn new(config: DorisSinkConfig, transport: Arc<dyn DorisTransport>) -> Result<Self> {
        config.validate()?;
        let linger = config.effective_linger();
        Ok(Self {
            buffer: parking_lot::Mutex::new(DorisBuffer {
                queue: BatchQueue::new(config.effective_batch_size(), linger),
                bytes: 0,
            }),
            config,
            transport,
            backoff: parking_lot::Mutex::new(BackoffState::default()),
            label_seq: AtomicU64::new(0),
            sent_batches: AtomicU64::new(0),
            sent_records: AtomicU64::new(0),
        })
    }

    pub fn config(&self) -> &DorisSinkConfig {
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

    /// Build one record document: payload merged with topic/qos/timestamp.
    fn build_record(
        &self,
        topic: &Topic,
        payload: &Bytes,
        qos: QoS,
        millis: i64,
    ) -> Result<serde_json::Value> {
        let text = std::str::from_utf8(payload)
            .map_err(|_| ConnectorError::Dispatch("doris payload must be UTF-8".to_string()))?;
        let value: serde_json::Value = serde_json::from_str(text)
            .map_err(|_| ConnectorError::Dispatch("doris payload must be JSON".to_string()))?;
        let mut document = match value {
            serde_json::Value::Object(map) => serde_json::Value::Object(map),
            other => serde_json::json!({"value": other}),
        };
        if let serde_json::Value::Object(map) = &mut document {
            map.insert("topic".to_string(), serde_json::json!(topic.as_str()));
            map.insert("qos".to_string(), serde_json::json!(u8::from(qos)));
            map.insert("timestamp".to_string(), serde_json::json!(millis));
        }
        Ok(document)
    }

    /// Fresh label per attempt: `indra-{millis}-{seq}`.
    fn fresh_label(&self) -> String {
        let seq = self.label_seq.fetch_add(1, Ordering::SeqCst);
        format!("indra-{}-{seq}", now_millis().max(0))
    }

    /// Flush buffered rows grouped by table (no-op when empty).
    /// Transient statuses retry with fresh labels; terminal failures
    /// and exhaustion restore the buffer, engage backoff, propagate.
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
        // Group by table; each group is one stream load.
        let mut groups: Vec<(String, Vec<serde_json::Value>)> = Vec::new();
        for row in &rows {
            match groups.iter_mut().find(|(table, _)| table == &row.table) {
                Some((_, documents)) => documents.push(row.document.clone()),
                None => groups.push((row.table.clone(), vec![row.document.clone()])),
            }
        }
        let record_count = rows.len() as u64;
        let max_retries = self.config.max_retries.unwrap_or(usize::MAX);
        let mut attempt = 0usize;
        loop {
            let headers = DorisHeaders {
                format: match self.config.format {
                    DorisFormat::Json => "json".to_string(),
                    DorisFormat::Csv => "csv".to_string(),
                },
                strip_outer_array: self.config.strip_outer_array,
                // Fresh label per attempt: conflicts never recycle one.
                label: self.fresh_label(),
                jsonpaths: self.config.jsonpaths.clone(),
                max_filter_ratio: self.config.max_filter_ratio.map(|ratio| ratio.to_string()),
            };
            let mut outcome: Result<()> = Ok(());
            for (table, documents) in &groups {
                let body = render_body(self.config.format, documents);
                if let Err(e) = self
                    .transport
                    .stream_load(
                        &self.config.database,
                        table,
                        &body,
                        &headers,
                        &self.config.auth,
                    )
                    .await
                {
                    outcome = Err(e);
                    break;
                }
            }
            match outcome {
                Ok(_) => {
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
        rows: Vec<DorisRow>,
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
                "doris row requires a non-empty topic".to_string(),
            ));
        }
        let millis = now_millis();
        // Table must resolve at buffer time: bad templates fail loudly
        // instead of poisoning the batch at flush.
        let table = self
            .config
            .resolve_table(topic.as_str(), payload, qos, millis)?;
        let document = self.build_record(topic, payload, qos, millis)?;
        let bytes = document.to_string().len();
        let mut buffer = self.buffer.lock();
        let full = buffer.queue.push(DorisRow { document, table });
        buffer.bytes = buffer.bytes.saturating_add(bytes);
        Ok(full || buffer.bytes >= self.config.effective_batch_bytes())
    }
}

#[async_trait]
impl Sink for DorisSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        if self.buffer_row(topic, payload, qos)? {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "doris"
    }
}

/// Management connector handle pairing an id with a Doris sink.
pub struct DorisConnector {
    id: String,
    sink: Arc<DorisSink>,
}

impl DorisConnector {
    pub fn new(id: impl Into<String>, sink: Arc<DorisSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }
}

impl super::Connector for DorisConnector {
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

    fn test_config() -> DorisSinkConfig {
        DorisSinkConfig {
            fe_host: "127.0.0.1".to_string(),
            http_port: 8030,
            database: "telemetry".to_string(),
            table_template: "events".to_string(),
            auth: DorisAuth {
                username: "root".to_string(),
                password: String::new(),
            },
            format: DorisFormat::Json,
            jsonpaths: None,
            strip_outer_array: true,
            max_filter_ratio: Some(0.0),
            batch_size: Some(1_000),
            batch_bytes: Some(4_194_304),
            linger_ms: Some(10),
            max_retries: Some(4),
            initial_backoff_ms: Some(100),
            max_backoff_ms: Some(2_000),
        }
    }

    fn test_sink(config: DorisSinkConfig) -> (Arc<DorisSink>, Arc<MockDorisTransport>) {
        let transport = Arc::new(MockDorisTransport::new());
        let sink = Arc::new(DorisSink::new(config, transport.clone()).unwrap());
        (sink, transport)
    }

    #[test]
    fn test_config_validation() {
        let mut config = test_config();
        assert!(config.validate().is_ok());
        assert_eq!(
            config.load_url("events"),
            "http://127.0.0.1:8030/api/telemetry/events/_stream_load"
        );

        config.fe_host.clear();
        assert!(config.validate().is_err());
        config.fe_host = "127.0.0.1".to_string();

        config.http_port = 0;
        assert!(config.validate().is_err());
        config.http_port = 8030;

        config.database = "has space".to_string();
        assert!(config.validate().is_err());
        config.database = "telemetry".to_string();

        config.table_template = "a/b".to_string();
        assert!(config.validate().is_err());
        config.table_template = "events".to_string();

        config.auth.username.clear();
        assert!(config.validate().is_err());
        config.auth.username = "root".to_string();

        config.max_filter_ratio = Some(1.5);
        assert!(config.validate().is_err());
        config.max_filter_ratio = Some(0.0);

        config.batch_size = Some(0);
        assert!(config.validate().is_err());
        // Unbounded + huge depths accepted: zero clamped ceilings.
        config.batch_size = None;
        config.batch_bytes = Some(10_000_000);
        config.max_retries = None;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_auth_and_body_framing() {
        assert_eq!(
            DorisAuth {
                username: "root".to_string(),
                password: "secret".to_string()
            }
            .header_value()
            .unwrap(),
            "Basic cm9vdDpzZWNyZXQ="
        );
        // JSON array framing with strip_outer_array semantics.
        let body = render_body(
            DorisFormat::Json,
            &[serde_json::json!({"a": 1}), serde_json::json!({"b": 2})],
        );
        assert_eq!(String::from_utf8(body).unwrap(), "[{\"a\":1},{\"b\":2}]");
        // CSV rows quote + escape only when needed.
        let body = render_body(
            DorisFormat::Csv,
            &[serde_json::json!({"timestamp": 7, "topic": "t", "qos": 0, "payload": "say \"hi\""})],
        );
        assert_eq!(
            String::from_utf8(body).unwrap(),
            "7,t,0,\"say \"\"hi\"\"\"\n"
        );
    }

    #[test]
    fn test_status_classification_and_parsing() {
        assert_eq!(
            parse_load_result(br#"{"Status":"Success","NumberLoadedRows":2}"#).unwrap(),
            DorisLoadResult {
                status: "Success".to_string(),
                rows_loaded: 2
            }
        );
        assert!(classify_status("Success").is_ok());
        assert!(matches!(
            classify_status("Publish Timeout"),
            Err(ConnectorError::Connection(_))
        ));
        assert!(matches!(
            classify_status("Label Already Exists"),
            Err(ConnectorError::Connection(_))
        ));
        assert!(matches!(
            classify_status("Failed"),
            Err(ConnectorError::Dispatch(_))
        ));
        assert!(parse_load_result(b"nope").is_err());
        assert!(parse_load_result(br#"{}"#).is_err());
    }

    #[tokio::test]
    async fn test_csv_format_end_to_end() {
        let mut config = test_config();
        config.format = DorisFormat::Csv;
        config.batch_size = Some(10);
        let (sink, transport) = test_sink(config);
        sink.send(
            &Topic::new("sensors/t1").unwrap(),
            &Bytes::from_static(br#"{"v":1}"#),
            QoS::AtLeastOnce,
        )
        .await
        .unwrap();
        sink.flush().await.unwrap();
        let captured = transport.captured();
        assert_eq!(captured[0].headers.format, "csv");
        let body = String::from_utf8(captured[0].body.clone()).unwrap();
        // timestamp,topic,qos,payload column order.
        assert!(body.contains(",sensors/t1,1,"));
        assert!(body.ends_with('\n'));
    }

    #[tokio::test]
    async fn test_stream_load_headers_and_labels() {
        let (sink, transport) = test_sink(test_config());
        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from("{\"v\":1}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from("{\"v\":2}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        sink.flush().await.unwrap();

        let captured = transport.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].db, "telemetry");
        assert_eq!(captured[0].table, "events");
        assert_eq!(captured[0].auth, "Basic cm9vdDo=");
        assert_eq!(captured[0].headers.format, "json");
        assert!(captured[0].headers.strip_outer_array);
        assert!(captured[0].headers.label.starts_with("indra-"));
        // Body is one JSON array with both records.
        let body: serde_json::Value = serde_json::from_slice(&captured[0].body).unwrap();
        assert_eq!(body.as_array().expect("array").len(), 2);
        assert_eq!(sink.sent_records(), 2);
    }

    #[tokio::test]
    async fn test_label_conflict_retries_with_fresh_label() {
        let mut config = test_config();
        config.batch_size = Some(10);
        config.initial_backoff_ms = Some(1);
        config.max_backoff_ms = Some(2);
        let (sink, transport) = test_sink(config);
        transport.script_outcomes(vec![
            MockDorisOutcome::Status("Label Already Exists".to_string()),
            MockDorisOutcome::Success { rows: 1 },
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
        // Fresh label per attempt: no two calls share one.
        assert_ne!(
            transport.captured()[0].headers.label,
            transport.captured()[1].headers.label
        );
        assert_eq!(sink.sent_records(), 1);
        assert_eq!(sink.buffered_rows(), 0);
    }

    #[tokio::test]
    async fn test_terminal_status_aborts() {
        let mut config = test_config();
        config.batch_size = Some(10);
        config.max_retries = Some(5);
        let (sink, transport) = test_sink(config);
        transport.script_outcomes(vec![MockDorisOutcome::Status("Failed".to_string())]);

        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from("{}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        let err = sink.flush().await.expect_err("Failed must abort");
        assert!(matches!(err, ConnectorError::Dispatch(_)));
        assert_eq!(transport.calls(), 1);
        assert_eq!(sink.buffered_rows(), 1);
    }

    #[tokio::test]
    async fn test_307_redirect_loopback() {
        use axum::{http::StatusCode, routing::put, Router};

        async fn be_route(headers: axum::http::HeaderMap, body: String) -> (StatusCode, String) {
            assert_eq!(
                headers.get("authorization").and_then(|v| v.to_str().ok()),
                Some("Basic cm9vdDo=")
            );
            assert!(headers.get("label").and_then(|v| v.to_str().ok()).is_some());
            assert!(body.starts_with('['));
            (
                StatusCode::OK,
                "{\"Status\":\"Success\",\"NumberLoadedRows\":1}".to_string(),
            )
        }
        let app = Router::new()
            .route(
                "/api/telemetry/events/_stream_load",
                put(|| async {
                    (
                        StatusCode::TEMPORARY_REDIRECT,
                        [("location", "/api/telemetry/events/_be_load")],
                        String::new(),
                    )
                }),
            )
            .route("/api/telemetry/events/_be_load", put(be_route));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        let mut config = test_config();
        config.fe_host = "127.0.0.1".to_string();
        config.http_port = port;
        let transport = Arc::new(HttpDorisTransport::new(&config, reqwest::Client::new()).unwrap());
        let result = transport
            .stream_load(
                "telemetry",
                "events",
                b"[{\"v\":1}]",
                &DorisHeaders {
                    format: "json".to_string(),
                    strip_outer_array: true,
                    label: "indra-test-1".to_string(),
                    jsonpaths: None,
                    max_filter_ratio: Some("0".to_string()),
                },
                &config.auth,
            )
            .await
            .expect("redirect flow succeeds");
        assert_eq!(result.status, "Success");
        assert_eq!(result.rows_loaded, 1);
    }
}
