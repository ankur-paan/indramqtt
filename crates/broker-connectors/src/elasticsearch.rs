//! Elasticsearch / OpenSearch bulk sink (INDRA-184).
//!
//! Buffers MQTT events and flushes full or stale batches with one
//! `POST /_bulk` carrying newline-delimited action/source pairs:
//! `{"index":{"_index":"<index>","_id":"<id>"}}` + the document.
//! Index names resolve `${YYYY}`/`${MM}`/`${DD}`/`${topic}` at flush
//! time (`iot-telemetry-${YYYY.MM.dd}` works: each variable
//! substitutes independently). Document ids come from an optional
//! template (`${timestamp}`, `${seq}`, `${topic}`, date variables, or
//! `${field:<name>}` JSON extraction with `${client_id}` /
//! `${device_id}` aliases); without a template the id is omitted and
//! Elasticsearch auto-generates one.
//!
//! HTTP 429/503 responses retry in place with exponential backoff
//! (preserving the in-flight rows); other failures restore the buffer,
//! engage backoff, and propagate the error.

use async_trait::async_trait;
use base64::Engine;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::{
    now_millis, render_template, rfc3339_millis, ymd_from_millis, BackoffState, BatchQueue,
    ConnectorError, Result, Sink,
};

/// Elasticsearch authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase", tag = "type")]
pub enum ElasticsearchAuth {
    /// No `Authorization` header.
    #[default]
    None,
    /// `Authorization: Basic base64(username:password)`.
    Basic { username: String, password: String },
    /// `Authorization: ApiKey <key>` (caller supplies the encoded key).
    ApiKey { key: String },
}
impl ElasticsearchAuth {
    /// Render the `Authorization` header value, if any.
    pub fn header_value(&self) -> Result<Option<String>> {
        match self {
            Self::None => Ok(None),
            Self::Basic { username, password } => {
                if username.is_empty() {
                    return Err(ConnectorError::Dispatch(
                        "elasticsearch basic auth needs a username".to_string(),
                    ));
                }
                let credentials = base64::engine::general_purpose::STANDARD
                    .encode(format!("{username}:{password}"));
                Ok(Some(format!("Basic {credentials}")))
            }
            Self::ApiKey { key } => {
                if key.trim().is_empty() {
                    return Err(ConnectorError::Dispatch(
                        "elasticsearch api key must not be empty".to_string(),
                    ));
                }
                Ok(Some(format!("ApiKey {key}")))
            }
        }
    }
}

fn default_batch_size() -> usize {
    500
}

fn default_batch_timeout_ms() -> u64 {
    100
}

fn default_max_retries() -> usize {
    5
}

/// Elasticsearch sink configuration. Every depth is user-configurable
/// with no clamped ceiling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElasticsearchSinkConfig {
    /// Base endpoint, e.g. `http://127.0.0.1:9200`.
    pub endpoint: String,
    /// Index template, e.g. `iot-telemetry-${YYYY.MM.dd}` or `device-logs`.
    pub index_template: String,
    /// Optional document id template; omitted ids auto-generate.
    #[serde(default)]
    pub doc_id_template: Option<String>,
    /// Authentication (default none).
    #[serde(default)]
    pub auth: ElasticsearchAuth,
    /// Bulk action buffer size (default 500).
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    /// Linger flush window (default 100 ms).
    #[serde(default = "default_batch_timeout_ms")]
    pub batch_timeout_ms: u64,
    /// In-place retries on 429/503 before restoring (default 5).
    #[serde(default = "default_max_retries")]
    pub max_retries: usize,
    /// Network request timeout in ms (default 5000).
    #[serde(default)]
    pub request_timeout_ms: Option<u64>,
}

impl ElasticsearchSinkConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.request_timeout_ms.unwrap_or(5000).max(1))
    }

    pub fn validate(&self) -> Result<()> {
        if !self.endpoint.starts_with("http://") && !self.endpoint.starts_with("https://") {
            return Err(ConnectorError::Dispatch(format!(
                "elasticsearch endpoint must be http(s): {:?}",
                self.endpoint
            )));
        }
        if self.index_template.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "elasticsearch index_template must not be empty".to_string(),
            ));
        }
        // Strict template checks with dummy values.
        self.resolve_index("dummy", 0)?;
        if let Some(template) = &self.doc_id_template {
            self.resolve_doc_id(template, "dummy", b"{}", 0)?;
        }
        self.auth.header_value().map(|_| ())?;
        if self.batch_size == 0 {
            return Err(ConnectorError::Dispatch(
                "elasticsearch batch_size must be >= 1".to_string(),
            ));
        }
        Ok(())
    }

    /// Render + sanitize the index name for one flush. Elasticsearch
    /// indices must be lowercase without `\/*?"<>| ,#:` — anything
    /// illegal becomes `-`. Date parts are separate variables, so both
    /// `logs-${YYYY}.${MM}.${DD}` and the `logs-${YYYY.MM.dd}`
    /// shorthand resolve (likewise `-` and `/` separators).
    pub fn resolve_index(&self, topic: &str, millis: i64) -> Result<String> {
        let (year, month, day) = ymd_from_millis(millis);
        let vars = [
            ("topic", topic.to_string()),
            ("YYYY", format!("{year:04}")),
            ("MM", format!("{month:02}")),
            ("DD", format!("{day:02}")),
        ];
        let expanded = expand_date_shorthands(&self.index_template);
        let raw = render_template(&expanded, &vars)?;
        let sanitized: String = raw
            .chars()
            .map(|c| {
                if c.is_ascii_lowercase()
                    || c.is_ascii_digit()
                    || matches!(c, '-' | '_' | '+' | '.')
                {
                    c
                } else if c.is_ascii_uppercase() {
                    c.to_ascii_lowercase()
                } else {
                    '-'
                }
            })
            .collect();
        if sanitized.is_empty() || sanitized.starts_with(['-', '_', '+', '.']) {
            return Err(ConnectorError::Dispatch(format!(
                "elasticsearch index_template resolved to an invalid index: {sanitized:?}"
            )));
        }
        Ok(sanitized)
    }

    /// Render one document id. Supported variables: `${timestamp}`
    /// (millis), `${seq}`, `${topic}`, `${YYYY}`/`${MM}`/`${DD}`, and
    /// `${field:<name>}` JSON extraction (`${client_id}` and
    /// `${device_id}` alias their payload fields).
    pub fn resolve_doc_id(
        &self,
        template: &str,
        topic: &str,
        payload: &[u8],
        seq: u64,
    ) -> Result<String> {
        let millis = now_millis();
        let (year, month, day) = ymd_from_millis(millis);
        let doc: serde_json::Value = serde_json::from_slice(payload).unwrap_or_default();
        let field = |name: &str| match doc.get(name) {
            Some(serde_json::Value::String(text)) => text.clone(),
            Some(scalar) if scalar.is_number() || scalar.is_boolean() => scalar.to_string(),
            _ => String::new(),
        };
        // Collect `${field:x}` / alias values by scanning the template.
        let mut extra: Vec<(String, String)> = Vec::new();
        let mut rest = template;
        while let Some(start) = rest.find("${field:") {
            let after = &rest[start + "${field:".len()..];
            if let Some(close) = after.find('}') {
                let name = &after[..close];
                extra.push((format!("field:{name}"), field(name)));
                rest = &after[close + 1..];
            } else {
                break;
            }
        }
        if template.contains("${client_id}") {
            extra.push(("client_id".to_string(), field("client_id")));
        }
        if template.contains("${device_id}") {
            extra.push(("device_id".to_string(), field("device_id")));
        }
        let mut vars = vec![
            ("timestamp", millis.to_string()),
            ("seq", seq.to_string()),
            ("topic", topic.to_string()),
            ("YYYY", format!("{year:04}")),
            ("MM", format!("{month:02}")),
            ("DD", format!("{day:02}")),
        ];
        for (key, value) in &extra {
            vars.push((key.as_str(), value.clone()));
        }
        let borrowed: Vec<(&str, String)> = vars.iter().map(|(k, v)| (*k, v.clone())).collect();
        let id = render_template(template, &borrowed)?;
        if id.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "elasticsearch doc_id_template resolved to an empty id".to_string(),
            ));
        }
        Ok(id)
    }
}

/// Expand `${YYYY.MM.dd}`-style date shorthands (`.`, `-`, `/`
/// separators) into individual `${YYYY}`/`${MM}`/`${DD}` variables so
/// the strict renderer accepts common datemath shapes.
fn expand_date_shorthands(template: &str) -> String {
    template
        .replace("${YYYY.MM.dd}", "${YYYY}.${MM}.${DD}")
        .replace("${YYYY-MM-dd}", "${YYYY}-${MM}-${DD}")
        .replace("${YYYY/MM/dd}", "${YYYY}/${MM}/${DD}")
}

/// One buffered event plus its flush sequence number.
#[derive(Debug, Clone)]
struct EsRow {
    topic: String,
    payload: Vec<u8>,
    qos: u8,
    seq: u64,
}

/// Bulk outcome from the transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BulkOutcome {
    /// 2xx: rows reached Elasticsearch; the body carries the `_bulk`
    /// response so per-item failures can be counted. Empty bodies are
    /// treated as full success (legacy scripted transports).
    Indexed { body: Vec<u8> },
    /// 2xx status, but the response body could not be read, so the
    /// batch cannot be verified. The batch reached Elasticsearch, so
    /// the caller must not restore or retry it.
    IndexedUnverified(String),
    /// 429/503: retry in place with backoff, rows preserved.
    Retryable(u16),
    /// Any other non-2xx: dispatch failure, no retry.
    Failed(u16),
}

#[async_trait]
pub trait ElasticsearchTransport: Send + Sync {
    async fn bulk_post(&self, body: Vec<u8>, auth: Option<String>) -> Result<BulkOutcome>;
}

/// One captured `_bulk` request.
#[derive(Debug, Clone)]
pub struct CapturedBulk {
    pub body: Vec<u8>,
    pub auth: Option<String>,
}

/// In-memory transport with a scripted response queue (tests, dry runs).
/// Each `bulk_post` consumes the next scripted response (default 200 with
/// an empty body); every request is captured regardless of outcome.
#[derive(Debug)]
pub struct MockElasticsearchTransport {
    scripted: parking_lot::Mutex<std::collections::VecDeque<MockScripted>>,
    captured: parking_lot::Mutex<Vec<CapturedBulk>>,
    calls: AtomicU64,
}

#[derive(Debug, Clone)]
enum MockScripted {
    Response(u16, Vec<u8>),
    Unverified(String),
}

impl Default for MockElasticsearchTransport {
    fn default() -> Self {
        Self {
            scripted: parking_lot::Mutex::new(std::collections::VecDeque::new()),
            captured: parking_lot::Mutex::new(Vec::new()),
            calls: AtomicU64::new(0),
        }
    }
}

impl MockElasticsearchTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue response statuses consumed in order (e.g. `[429, 200]`).
    /// Scripted statuses carry an empty `_bulk` body, which counts as
    /// full success on 2xx.
    pub fn script_statuses(&self, statuses: Vec<u16>) {
        self.scripted.lock().extend(
            statuses
                .into_iter()
                .map(|status| MockScripted::Response(status, Vec::new())),
        );
    }

    /// Queue full `(status, body)` responses consumed in order. Use this
    /// to script `_bulk` response bodies with per-item results.
    pub fn script_responses(&self, responses: Vec<(u16, Vec<u8>)>) {
        self.scripted.lock().extend(
            responses
                .into_iter()
                .map(|(status, body)| MockScripted::Response(status, body)),
        );
    }

    /// Queue a 2xx response whose body could not be read (e.g. a
    /// truncated stream). The next `bulk_post` reports it as
    /// [`BulkOutcome::IndexedUnverified`].
    pub fn script_unverified(&self, reason: impl Into<String>) {
        self.scripted
            .lock()
            .push_back(MockScripted::Unverified(reason.into()));
    }

    pub fn captured(&self) -> Vec<CapturedBulk> {
        self.captured.lock().clone()
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ElasticsearchTransport for MockElasticsearchTransport {
    async fn bulk_post(&self, body: Vec<u8>, auth: Option<String>) -> Result<BulkOutcome> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.captured.lock().push(CapturedBulk { body, auth });
        let next = self
            .scripted
            .lock()
            .pop_front()
            .unwrap_or(MockScripted::Response(200, Vec::new()));
        Ok(match next {
            MockScripted::Unverified(reason) => BulkOutcome::IndexedUnverified(reason),
            MockScripted::Response(status, response_body) => match status {
                200..=299 => BulkOutcome::Indexed {
                    body: response_body,
                },
                429 | 503 => BulkOutcome::Retryable(status),
                other => BulkOutcome::Failed(other),
            },
        })
    }
}

/// HTTP transport: `POST {endpoint}/_bulk` as `application/x-ndjson`.
/// Transport errors are connection failures; status mapping follows
/// [`BulkOutcome`] (429/503 retryable, other non-2xx fatal).
pub struct HttpElasticsearchTransport {
    url: String,
    client: reqwest::Client,
}

impl HttpElasticsearchTransport {
    pub fn new(config: &ElasticsearchSinkConfig, client: reqwest::Client) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            url: format!("{}/_bulk", config.endpoint.trim_end_matches('/')),
            client,
        })
    }
}

#[async_trait]
impl ElasticsearchTransport for HttpElasticsearchTransport {
    async fn bulk_post(&self, body: Vec<u8>, auth: Option<String>) -> Result<BulkOutcome> {
        let mut request = self
            .client
            .post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, "application/x-ndjson")
            .body(body);
        if let Some(auth) = auth {
            request = request.header(reqwest::header::AUTHORIZATION, auth);
        }
        let response = request
            .send()
            .await
            .map_err(|e| ConnectorError::Connection(format!("elasticsearch bulk failed: {e}")))?;
        let status = response.status().as_u16();
        Ok(match status {
            200..=299 => match response.bytes().await {
                Ok(body) => BulkOutcome::Indexed {
                    body: body.to_vec(),
                },
                Err(e) => BulkOutcome::IndexedUnverified(e.to_string()),
            },
            429 | 503 => BulkOutcome::Retryable(status),
            _ => BulkOutcome::Failed(status),
        })
    }
}

// ---------------------------------------------------------------------------
// Sink.
// ---------------------------------------------------------------------------

/// Elasticsearch sink: buffers events, POSTs `_bulk` batches.
pub struct ElasticsearchSink {
    config: ElasticsearchSinkConfig,
    transport: Arc<dyn ElasticsearchTransport>,
    buffer: parking_lot::Mutex<BatchQueue<EsRow>>,
    backoff: parking_lot::Mutex<BackoffState>,
    seq: AtomicU64,
    sent_batches: AtomicU64,
    sent_records: AtomicU64,
    inserted_docs: AtomicU64,
    rejected_docs: AtomicU64,
}

impl ElasticsearchSink {
    pub fn new(
        config: ElasticsearchSinkConfig,
        transport: Arc<dyn ElasticsearchTransport>,
    ) -> Result<Self> {
        config.validate()?;
        let linger = Duration::from_millis(config.batch_timeout_ms);
        Ok(Self {
            buffer: parking_lot::Mutex::new(BatchQueue::new(config.batch_size, linger)),
            config,
            transport,
            backoff: parking_lot::Mutex::new(BackoffState::default()),
            seq: AtomicU64::new(0),
            sent_batches: AtomicU64::new(0),
            sent_records: AtomicU64::new(0),
            inserted_docs: AtomicU64::new(0),
            rejected_docs: AtomicU64::new(0),
        })
    }

    pub fn config(&self) -> &ElasticsearchSinkConfig {
        &self.config
    }

    pub fn sent_batches(&self) -> u64 {
        self.sent_batches.load(Ordering::Relaxed)
    }

    pub fn sent_records(&self) -> u64 {
        self.sent_records.load(Ordering::Relaxed)
    }

    /// Documents the `_bulk` response acknowledged as indexed.
    pub fn inserted_docs(&self) -> u64 {
        self.inserted_docs.load(Ordering::Relaxed)
    }

    /// Documents the `_bulk` response reported as failed per item.
    pub fn rejected_docs(&self) -> u64 {
        self.rejected_docs.load(Ordering::Relaxed)
    }

    pub fn buffered_rows(&self) -> usize {
        self.buffer.lock().len()
    }

    /// Render one `_bulk` body for already-taken rows.
    fn render_bulk(&self, rows: &[EsRow], index: &str) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        for row in rows {
            let action = match &self.config.doc_id_template {
                Some(template) => {
                    let id =
                        self.config
                            .resolve_doc_id(template, &row.topic, &row.payload, row.seq)?;
                    serde_json::json!({"index": {"_index": index, "_id": id}})
                }
                None => serde_json::json!({"index": {"_index": index}}),
            };
            body.extend_from_slice(
                serde_json::to_vec(&action)
                    .map_err(|e| {
                        ConnectorError::Dispatch(format!("elasticsearch action encode failed: {e}"))
                    })?
                    .as_slice(),
            );
            body.push(b'\n');
            let payload: serde_json::Value =
                serde_json::from_slice(&row.payload).unwrap_or_else(|_| {
                    serde_json::Value::String(String::from_utf8_lossy(&row.payload).into_owned())
                });
            let doc = serde_json::json!({
                "topic": row.topic,
                "qos": row.qos,
                "payload": payload,
                "timestamp": rfc3339_millis(now_millis()),
            });
            body.extend_from_slice(
                serde_json::to_vec(&doc)
                    .map_err(|e| {
                        ConnectorError::Dispatch(format!("elasticsearch doc encode failed: {e}"))
                    })?
                    .as_slice(),
            );
            body.push(b'\n');
        }
        Ok(body)
    }
}

/// Truncate an error reason to about 200 characters for logs.
fn truncate_reason(reason: &str) -> String {
    const LIMIT: usize = 200;
    if reason.chars().count() <= LIMIT {
        reason.to_string()
    } else {
        let truncated: String = reason.chars().take(LIMIT).collect();
        format!("{truncated}...")
    }
}

/// Inspect one `_bulk` item result object (the value behind `index` /
/// `create` / `update` / `delete`). Returns `(status, error_type,
/// reason)` when the item failed (status >= 300 or an `error` field
/// is present).
fn bulk_item_failure(result: &serde_json::Value) -> Option<(Option<u64>, String, String)> {
    let failed_status = result
        .get("status")
        .and_then(serde_json::Value::as_u64)
        .is_some_and(|status| status >= 300);
    let error = result.get("error");
    if !failed_status && error.is_none() {
        return None;
    }
    let status = result.get("status").and_then(serde_json::Value::as_u64);
    let (error_type, reason) = match error {
        Some(serde_json::Value::Object(map)) => {
            let error_type = map
                .get("type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            let reason = map
                .get("reason")
                .and_then(serde_json::Value::as_str)
                .map_or_else(
                    || {
                        result
                            .get("error")
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "unknown bulk item error".to_string())
                    },
                    std::string::ToString::to_string,
                );
            (error_type, reason)
        }
        Some(serde_json::Value::String(reason)) => ("unknown".to_string(), reason.clone()),
        Some(other) => ("unknown".to_string(), other.to_string()),
        None => (
            "unknown".to_string(),
            "bulk item status indicates failure".to_string(),
        ),
    };
    Some((status, error_type, reason))
}

/// Count per-item `_bulk` failures. Returns `(inserted, rejected)`.
/// Logs each failed item at `warn` with its batch position, status,
/// error type and (truncated) reason; document bodies are never logged.
fn count_bulk_item_outcome(items: &[serde_json::Value]) -> (u64, u64) {
    let mut inserted = 0u64;
    let mut rejected = 0u64;
    for (position, item) in items.iter().enumerate() {
        let result = item.as_object().and_then(|map| map.values().next());
        match result.and_then(bulk_item_failure) {
            Some((status, error_type, reason)) => {
                rejected += 1;
                tracing::warn!(
                    position,
                    ?status,
                    error_type = error_type.as_str(),
                    reason = truncate_reason(&reason).as_str(),
                    "elasticsearch bulk item failed"
                );
            }
            None => {
                inserted += 1;
            }
        }
    }
    (inserted, rejected)
}

impl ElasticsearchSink {
    /// Account for a 2xx `_bulk` response body. Empty bodies count the
    /// whole batch as inserted (legacy scripted transports); otherwise
    /// the body must be valid JSON with an `items` array whenever it
    /// reports `"errors": true`.
    fn account_bulk_body(&self, response_body: &[u8], record_count: u64) -> Result<()> {
        if response_body.iter().all(u8::is_ascii_whitespace) {
            self.inserted_docs
                .fetch_add(record_count, Ordering::Relaxed);
            return Ok(());
        }
        let parsed: serde_json::Value = serde_json::from_slice(response_body).map_err(|e| {
            ConnectorError::Dispatch(format!(
                "elasticsearch bulk response was not valid JSON: {e}"
            ))
        })?;
        let errors = parsed
            .get("errors")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let items = parsed.get("items").and_then(serde_json::Value::as_array);
        match (errors, items) {
            (true, None) => Err(ConnectorError::Dispatch(
                "elasticsearch bulk response reported errors but contained no `items` array"
                    .to_string(),
            )),
            (false, None) => {
                self.inserted_docs
                    .fetch_add(record_count, Ordering::Relaxed);
                Ok(())
            }
            (_, Some(items)) => {
                let (inserted, rejected) = count_bulk_item_outcome(items);
                self.inserted_docs.fetch_add(inserted, Ordering::Relaxed);
                self.rejected_docs.fetch_add(rejected, Ordering::Relaxed);
                if items.len() as u64 != record_count {
                    tracing::warn!(
                        items = items.len(),
                        documents = record_count,
                        inserted,
                        rejected,
                        "elasticsearch bulk response item count mismatch"
                    );
                    return Err(ConnectorError::Dispatch(format!(
                        "elasticsearch bulk response has {} items for {} documents",
                        items.len(),
                        record_count
                    )));
                }
                if rejected > 0 {
                    let total = items.len() as u64;
                    return Err(ConnectorError::Dispatch(format!(
                        "elasticsearch bulk partially failed: {rejected} of {total} documents rejected"
                    )));
                }
                Ok(())
            }
        }
    }

    /// Flush buffered rows as one `_bulk` (no-op when empty). While
    /// backing off, fails fast without touching the transport. 429/503
    /// retries in place up to `max_retries` with exponential backoff
    /// (2s, 4s, ... capped by [`BackoffState`]); terminal failures
    /// restore the buffer, engage backoff, and propagate.
    ///
    /// 2xx responses are additionally inspected per item: documents
    /// Elasticsearch rejected inside an otherwise successful `_bulk`
    /// are counted via [`Self::rejected_docs`] and reported as a
    /// [`ConnectorError::Dispatch`] without restoring the buffer (the
    /// successful documents are already stored).
    pub async fn flush(&self) -> Result<()> {
        self.backoff.lock().check()?;
        let (rows, oldest) = self.buffer.lock().take_batch();
        if rows.is_empty() {
            return Ok(());
        }
        let index = self.config.resolve_index(&rows[0].topic, now_millis())?;
        let body = self.render_bulk(&rows, &index)?;
        let auth = self.config.auth.header_value()?;
        let record_count = rows.len() as u64;
        let mut attempt = 0usize;
        loop {
            match self.transport.bulk_post(body.clone(), auth.clone()).await {
                Ok(BulkOutcome::Indexed {
                    body: response_body,
                }) => {
                    match self.account_bulk_body(&response_body, record_count) {
                        Ok(()) => {
                            self.backoff.lock().success();
                            self.sent_batches.fetch_add(1, Ordering::Relaxed);
                            self.sent_records.fetch_add(record_count, Ordering::Relaxed);
                            return Ok(());
                        }
                        Err(e) => {
                            // The HTTP batch landed: successes are stored,
                            // so never restore or retry; just report.
                            self.backoff.lock().success();
                            return Err(e);
                        }
                    }
                }
                Ok(BulkOutcome::IndexedUnverified(reason)) => {
                    // The batch reached Elasticsearch (2xx) but the body
                    // could not be read, so nothing is verified: never
                    // restore or retry, and count nothing as inserted.
                    self.backoff.lock().success();
                    tracing::warn!(
                        reason = truncate_reason(&reason).as_str(),
                        "elasticsearch bulk response body could not be read"
                    );
                    return Err(ConnectorError::Dispatch(format!(
                        "elasticsearch bulk response body could not be read: {reason}"
                    )));
                }
                Ok(BulkOutcome::Retryable(status)) if attempt < self.config.max_retries => {
                    attempt += 1;
                    self.backoff.lock().failure();
                    // Sleep the backoff window inline: rows stay in hand.
                    let wait =
                        Duration::from_secs(2u64.saturating_pow(attempt.min(5) as u32).min(30));
                    tokio::time::sleep(wait).await;
                    tracing::warn!(
                        status,
                        attempt,
                        "elasticsearch bulk backpressure; retrying in place"
                    );
                }
                Ok(BulkOutcome::Retryable(status)) => {
                    self.buffer.lock().restore(rows, oldest);
                    self.backoff.lock().failure();
                    return Err(ConnectorError::Connection(format!(
                        "elasticsearch bulk backpressure ({status}) after {attempt} retries"
                    )));
                }
                Ok(BulkOutcome::Failed(status)) => {
                    self.buffer.lock().restore(rows, oldest);
                    self.backoff.lock().failure();
                    return Err(ConnectorError::Dispatch(format!(
                        "elasticsearch bulk failed with {status}"
                    )));
                }
                Err(e) => {
                    self.buffer.lock().restore(rows, oldest);
                    self.backoff.lock().failure();
                    return Err(e);
                }
            }
        }
    }

    /// Validate + buffer one event. Returns true when the batch is
    /// full or stale (caller flushes).
    fn buffer_row(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<bool> {
        if topic.as_str().is_empty() {
            return Err(ConnectorError::Dispatch(
                "elasticsearch row requires a non-empty topic".to_string(),
            ));
        }
        std::str::from_utf8(payload).map_err(|_| {
            ConnectorError::Dispatch("elasticsearch payload must be UTF-8".to_string())
        })?;
        Ok(self.buffer.lock().push(EsRow {
            topic: topic.as_str().to_string(),
            payload: payload.to_vec(),
            qos: u8::from(qos),
            seq: self.seq.fetch_add(1, Ordering::SeqCst),
        }))
    }
}

#[async_trait]
impl Sink for ElasticsearchSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        if self.buffer_row(topic, payload, qos)? {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "elasticsearch"
    }
}

/// Management connector handle pairing an id with an Elasticsearch sink.
pub struct ElasticsearchConnector {
    id: String,
    sink: Arc<ElasticsearchSink>,
}

impl ElasticsearchConnector {
    pub fn new(id: impl Into<String>, sink: Arc<ElasticsearchSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }
}

impl super::Connector for ElasticsearchConnector {
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

    fn test_config() -> ElasticsearchSinkConfig {
        ElasticsearchSinkConfig {
            endpoint: "http://127.0.0.1:9200".to_string(),
            index_template: "iot-telemetry-${YYYY.MM.dd}".to_string(),
            doc_id_template: None,
            auth: ElasticsearchAuth::None,
            batch_size: 500,
            batch_timeout_ms: 100,
            max_retries: 5,
            request_timeout_ms: None,
        }
    }

    fn test_sink(
        config: ElasticsearchSinkConfig,
    ) -> (Arc<ElasticsearchSink>, Arc<MockElasticsearchTransport>) {
        let transport = Arc::new(MockElasticsearchTransport::new());
        let sink = Arc::new(ElasticsearchSink::new(config, transport.clone()).unwrap());
        (sink, transport)
    }

    #[test]
    fn test_config_validation() {
        let mut config = test_config();
        assert!(config.validate().is_ok());
        // 2026-09-12T11:18:09.123Z.
        assert_eq!(
            config
                .resolve_index("sensors/t1", 1_789_211_889_123)
                .unwrap(),
            "iot-telemetry-2026.09.12"
        );

        config.endpoint = "127.0.0.1:9200".to_string();
        assert!(config.validate().is_err());
        config.endpoint = "http://127.0.0.1:9200".to_string();

        config.index_template = "UPPER/${YYYY}".to_string();
        assert!(config.validate().is_ok());
        // Uppercase folds down; `/` is illegal in indices and becomes `-`.
        assert_eq!(config.resolve_index("t", 0).unwrap(), "upper-1970");

        config.index_template = "-leading".to_string();
        assert!(config.validate().is_err());
        config.index_template = test_config().index_template;

        config.doc_id_template = Some("${unclosed".to_string());
        assert!(config.validate().is_err());
        config.doc_id_template = Some("${client_id}_${timestamp}".to_string());
        assert!(config.validate().is_ok());

        config.auth = ElasticsearchAuth::Basic {
            username: String::new(),
            password: "p".to_string(),
        };
        assert!(config.validate().is_err());
        config.auth = ElasticsearchAuth::ApiKey {
            key: "  ".to_string(),
        };
        assert!(config.validate().is_err());
        config.auth = ElasticsearchAuth::None;

        config.batch_size = 0;
        assert!(config.validate().is_err());
        // Zero clamped ceilings: huge depths are accepted.
        config.batch_size = 10_000_000;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_auth_headers() {
        assert_eq!(ElasticsearchAuth::None.header_value().unwrap(), None);
        assert_eq!(
            ElasticsearchAuth::Basic {
                username: "elastic".to_string(),
                password: "changeme".to_string(),
            }
            .header_value()
            .unwrap(),
            Some("Basic ZWxhc3RpYzpjaGFuZ2VtZQ==".to_string())
        );
        assert_eq!(
            ElasticsearchAuth::ApiKey {
                key: "abc123".to_string()
            }
            .header_value()
            .unwrap(),
            Some("ApiKey abc123".to_string())
        );
    }

    #[test]
    fn test_doc_id_templates() {
        let config = test_config();
        let payload = br#"{"client_id":"d7","n":3}"#;
        let id = config
            .resolve_doc_id("${client_id}_${timestamp}", "t", payload, 9)
            .unwrap();
        assert!(id.starts_with("d7_"));
        assert_ne!(id, "d7_");
        let id = config
            .resolve_doc_id("${field:n}-${seq}", "t", payload, 9)
            .unwrap();
        assert_eq!(id, "3-9");
        let id = config
            .resolve_doc_id("auto-${seq}", "t", b"not json", 4)
            .unwrap();
        assert_eq!(id, "auto-4");
    }

    #[tokio::test]
    async fn test_bulk_framing() {
        let mut config = test_config();
        config.batch_size = 2;
        config.doc_id_template = Some("evt-${seq}".to_string());
        let (sink, transport) = test_sink(config);

        sink.send(
            &Topic::new("logs/a").unwrap(),
            &Bytes::from(r#"{"m":"x"}"#),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        sink.send(
            &Topic::new("logs/b").unwrap(),
            &Bytes::from("plain"),
            QoS::AtLeastOnce,
        )
        .await
        .unwrap();
        assert_eq!(sink.sent_batches(), 1);

        let captured = transport.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].auth, None);
        let body = String::from_utf8(captured[0].body.clone()).unwrap();
        assert!(body.ends_with('\n'));
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 4);
        let action: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(action["index"]["_id"], "evt-0");
        assert!(action["index"]["_index"]
            .as_str()
            .unwrap()
            .starts_with("iot-telemetry-"));
        let doc: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(doc["topic"], "logs/a");
        assert_eq!(doc["payload"], serde_json::json!({"m": "x"}));
        // Non-JSON payloads ride as strings.
        let doc: serde_json::Value = serde_json::from_str(lines[3]).unwrap();
        assert_eq!(doc["payload"], "plain");
    }

    #[tokio::test]
    async fn test_retry_on_429_then_success() {
        let mut config = test_config();
        config.batch_size = 10;
        config.max_retries = 5;
        // A single scripted 429 exercises the 2s in-place retry sleep.
        let (sink, transport) = test_sink(config);
        transport.script_statuses(vec![429, 200]);

        let topic = Topic::new("t").unwrap();
        sink.send(&topic, &Bytes::from("{}"), QoS::AtMostOnce)
            .await
            .unwrap();
        let started = std::time::Instant::now();
        sink.flush().await.unwrap();
        assert!(started.elapsed() >= Duration::from_secs(2));
        assert_eq!(transport.calls(), 2);
        assert_eq!(sink.sent_batches(), 1);
        assert_eq!(sink.buffered_rows(), 0);
    }

    #[tokio::test]
    async fn test_retry_exhaustion_restores_buffer() {
        let mut config = test_config();
        config.batch_size = 10;
        config.max_retries = 0;
        let (sink, transport) = test_sink(config);
        transport.script_statuses(vec![503]);

        let topic = Topic::new("t").unwrap();
        sink.send(&topic, &Bytes::from("{}"), QoS::AtMostOnce)
            .await
            .unwrap();
        let err = sink.flush().await.expect_err("503 must fail");
        assert!(matches!(err, ConnectorError::Connection(_)));
        assert_eq!(sink.buffered_rows(), 1);
        assert_eq!(transport.calls(), 1);
        // Backoff engaged: immediate retry fails fast, no new call.
        assert!(sink.flush().await.is_err());
        assert_eq!(transport.calls(), 1);
    }

    #[tokio::test]
    async fn test_fatal_status_restores_buffer() {
        let mut config = test_config();
        config.batch_size = 10;
        let (sink, transport) = test_sink(config);
        transport.script_statuses(vec![400]);

        let topic = Topic::new("t").unwrap();
        sink.send(&topic, &Bytes::from("{}"), QoS::AtMostOnce)
            .await
            .unwrap();
        let err = sink.flush().await.expect_err("400 must fail");
        assert!(matches!(err, ConnectorError::Dispatch(_)));
        assert_eq!(sink.buffered_rows(), 1);
    }

    #[tokio::test]
    async fn test_bulk_all_items_succeed_counts_inserted() {
        let mut config = test_config();
        config.batch_size = 10;
        let (sink, transport) = test_sink(config);
        let response = serde_json::json!({
            "took": 5,
            "errors": false,
            "items": [
                {"index": {"_index": "iot", "status": 201}},
                {"index": {"_index": "iot", "status": 201}},
                {"index": {"_index": "iot", "status": 201}}
            ]
        });
        transport.script_responses(vec![(200, serde_json::to_vec(&response).unwrap())]);

        let topic = Topic::new("sensors/a").unwrap();
        for _ in 0..3 {
            sink.send(&topic, &Bytes::from(r#"{"v":1}"#), QoS::AtMostOnce)
                .await
                .unwrap();
        }
        sink.flush().await.unwrap();
        assert_eq!(sink.inserted_docs(), 3);
        assert_eq!(sink.rejected_docs(), 0);
        assert_eq!(sink.buffered_rows(), 0);
    }

    #[tokio::test]
    async fn test_bulk_partial_item_failures_are_counted_and_reported() {
        let mut config = test_config();
        config.batch_size = 10;
        let (sink, transport) = test_sink(config);
        let response = serde_json::json!({
            "took": 5,
            "errors": true,
            "items": [
                {"index": {"_index": "iot", "status": 201}},
                {"index": {
                    "_index": "iot",
                    "status": 400,
                    "error": {
                        "type": "mapper_parsing_exception",
                        "reason": "failed to parse field [v]"
                    }
                }},
                {"index": {"_index": "iot", "status": 201}}
            ]
        });
        transport.script_responses(vec![(200, serde_json::to_vec(&response).unwrap())]);

        let topic = Topic::new("sensors/a").unwrap();
        for _ in 0..3 {
            sink.send(&topic, &Bytes::from(r#"{"v":1}"#), QoS::AtMostOnce)
                .await
                .unwrap();
        }
        let err = sink.flush().await.expect_err("partial failure must err");
        match &err {
            ConnectorError::Dispatch(message) => assert!(
                message.contains("1 of 3"),
                "dispatch must state 1 of 3, got: {message}"
            ),
            other => panic!("expected Dispatch, got: {other:?}"),
        }
        assert_eq!(sink.inserted_docs(), 2);
        assert_eq!(sink.rejected_docs(), 1);
        // Successful documents are already stored: nothing is restored.
        assert_eq!(sink.buffered_rows(), 0);
    }

    #[tokio::test]
    async fn test_bulk_malformed_error_body_is_a_clear_error() {
        let mut config = test_config();
        config.batch_size = 10;
        let (sink, transport) = test_sink(config);
        transport.script_responses(vec![(200, br#"{"took":5,"errors":true}"#.to_vec())]);

        let topic = Topic::new("sensors/a").unwrap();
        sink.send(&topic, &Bytes::from(r#"{"v":1}"#), QoS::AtMostOnce)
            .await
            .unwrap();
        let err = sink.flush().await.expect_err("malformed body must err");
        assert!(
            matches!(err, ConnectorError::Dispatch(_)),
            "expected Dispatch, got: {err:?}"
        );
        assert_eq!(sink.buffered_rows(), 0);
    }

    #[tokio::test]
    async fn test_bulk_unreadable_body_is_not_counted_as_success() {
        let mut config = test_config();
        config.batch_size = 10;
        let (sink, transport) = test_sink(config);
        transport.script_unverified("connection reset");

        let topic = Topic::new("sensors/a").unwrap();
        sink.send(&topic, &Bytes::from(r#"{"v":1}"#), QoS::AtMostOnce)
            .await
            .unwrap();
        let err = sink.flush().await.expect_err("unreadable body must err");
        match &err {
            ConnectorError::Dispatch(message) => assert!(
                message.contains("elasticsearch bulk response body could not be read")
                    && message.contains("connection reset"),
                "dispatch must report unreadable body, got: {message}"
            ),
            other => panic!("expected Dispatch, got: {other:?}"),
        }
        assert_eq!(sink.inserted_docs(), 0);
        assert_eq!(sink.rejected_docs(), 0);
        assert_eq!(sink.buffered_rows(), 0);
    }

    #[tokio::test]
    async fn test_bulk_item_count_mismatch_is_reported() {
        let mut config = test_config();
        config.batch_size = 10;
        let (sink, transport) = test_sink(config);
        let response = serde_json::json!({
            "took": 5,
            "errors": false,
            "items": [
                {"index": {"_index": "iot", "status": 201}},
                {"index": {"_index": "iot", "status": 201}}
            ]
        });
        transport.script_responses(vec![(200, serde_json::to_vec(&response).unwrap())]);

        let topic = Topic::new("sensors/a").unwrap();
        for _ in 0..3 {
            sink.send(&topic, &Bytes::from(r#"{"v":1}"#), QoS::AtMostOnce)
                .await
                .unwrap();
        }
        let err = sink.flush().await.expect_err("item mismatch must err");
        match &err {
            ConnectorError::Dispatch(message) => assert!(
                message.contains("has 2 items for 3 documents"),
                "dispatch must state 2 items for 3 documents, got: {message}"
            ),
            other => panic!("expected Dispatch, got: {other:?}"),
        }
        assert_eq!(sink.inserted_docs(), 2);
        assert_eq!(sink.rejected_docs(), 0);
        assert_eq!(sink.buffered_rows(), 0);
    }
}
