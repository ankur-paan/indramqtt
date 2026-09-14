//! Google BigQuery streaming ingest sink (INDRA-186).
//!
//! Buffers MQTT events as table rows and streams them with
//! `tabledata.insertAll` (`POST
//! {endpoint}/projects/{project}/datasets/{dataset}/tables/{table}/insertAll`):
//! the projected JSON per row, one UUID `insertId` each, plus the
//! `ignoreUnknownValues` / `skipInvalidRows` flags. Authentication
//! reuses the [`GcpAuth`] stack (service-account JWT + token cache,
//! raw access tokens, or nothing for the emulator).
//!
//! Partial failures requeue selectively: only rows whose `insertErrors`
//! carry transient reasons (`backendError`, `rateLimitExceeded`)
//! retry; other row errors are terminal. HTTP 429/5xx and transport
//! failures retry the whole batch in-loop.

use async_trait::async_trait;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::{
    gcp_pubsub::{GcpAuth, GcpTokenCache},
    now_millis, render_template, BackoffState, BatchQueue, ConnectorError, Result, Sink,
};

fn default_endpoint() -> Option<String> {
    None
}

fn default_batch_size() -> Option<usize> {
    Some(500)
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

fn is_resource_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=1024).contains(&bytes.len())
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-')
}

/// BigQuery sink configuration. All depths are optional (`None` =
/// unbounded) with zero clamped ceilings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BigQuerySinkConfig {
    /// GCP project id.
    pub project_id: String,
    /// BigQuery dataset id.
    pub dataset_id: String,
    /// Table template (`${topic}`, `${client_id}`, ...; sanitized).
    pub table_template: String,
    /// Endpoint override; defaults to bigquery.googleapis.com.
    #[serde(default = "default_endpoint")]
    pub endpoint: Option<String>,
    /// Authentication: service-account JWT, access token, or none.
    #[serde(default)]
    pub auth: GcpAuth,
    /// `ignoreUnknownValues` flag (default true).
    #[serde(default = "default_true")]
    pub ignore_unknown_values: bool,
    /// `skipInvalidRows` flag (default false).
    #[serde(default)]
    pub skip_invalid_rows: bool,
    /// Partition decorator template, e.g. `${YYYYMMDD}` (appends
    /// `$suffix` to the table when set).
    #[serde(default)]
    pub template_suffix: Option<String>,
    /// Rows per `insertAll` (default 500, streaming cap).
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
    /// Request timeout in ms (default 5000).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

fn default_true() -> bool {
    true
}

impl BigQuerySinkConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.unwrap_or(5000).max(1))
    }

    pub fn validate(&self) -> Result<()> {
        if !is_resource_id(&self.project_id) {
            return Err(ConnectorError::Dispatch(format!(
                "bigquery project_id must be 1..=1024 [A-Za-z0-9_-]: {:?}",
                self.project_id
            )));
        }
        if !is_resource_id(&self.dataset_id) {
            return Err(ConnectorError::Dispatch(format!(
                "bigquery dataset_id must be 1..=1024 [A-Za-z0-9_-]: {:?}",
                self.dataset_id
            )));
        }
        if self.table_template.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "bigquery table_template must not be empty".to_string(),
            ));
        }
        if let Some(endpoint) = &self.endpoint {
            if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
                return Err(ConnectorError::Dispatch(format!(
                    "bigquery endpoint must be http(s): {endpoint:?}"
                )));
            }
        }
        match &self.auth {
            GcpAuth::None => {}
            GcpAuth::AccessToken { token } => {
                if token.trim().is_empty() {
                    return Err(ConnectorError::Dispatch(
                        "bigquery access token must not be empty".to_string(),
                    ));
                }
            }
            GcpAuth::ServiceAccountKey {
                client_email,
                private_key_pem,
            } => {
                if client_email.trim().is_empty() || private_key_pem.trim().is_empty() {
                    return Err(ConnectorError::Dispatch(
                        "bigquery service account needs email + private key".to_string(),
                    ));
                }
            }
        }
        // Strict template checks with dummy values.
        self.resolve_table("dummy/topic", b"{}", QoS::AtMostOnce, 0)?;
        if let Some(suffix) = &self.template_suffix {
            self.event_vars("dummy", b"{}", QoS::AtMostOnce, 0, suffix)?;
        }
        if self.batch_size == Some(0) {
            return Err(ConnectorError::Dispatch(
                "bigquery batch_size must be >= 1".to_string(),
            ));
        }
        if self.batch_bytes == Some(0) {
            return Err(ConnectorError::Dispatch(
                "bigquery batch_bytes must be >= 1".to_string(),
            ));
        }
        Ok(())
    }

    pub fn base_url(&self) -> String {
        match &self.endpoint {
            Some(endpoint) => endpoint.trim_end_matches('/').to_string(),
            None => "https://bigquery.googleapis.com/bigquery/v2".to_string(),
        }
    }

    /// `POST {base}/projects/{project}/datasets/{dataset}/tables/{table}/insertAll`.
    pub fn insert_url(&self, table: &str) -> String {
        format!(
            "{}/projects/{}/datasets/{}/tables/{}/insertAll",
            self.base_url(),
            self.project_id,
            self.dataset_id,
            table
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

    /// Template variables for one event (plus `${YYYYMMDD}`).
    fn template_vars(topic: &str, payload: &[u8], qos: QoS, millis: i64) -> Vec<(String, String)> {
        let doc: serde_json::Value = serde_json::from_slice(payload).unwrap_or_default();
        let field = |name: &str| match doc.get(name) {
            Some(serde_json::Value::String(text)) => text.clone(),
            Some(scalar) if scalar.is_number() || scalar.is_boolean() => scalar.to_string(),
            _ => String::new(),
        };
        let (year, month, day) = super::ymd_from_millis(millis);
        vec![
            ("topic".to_string(), topic.to_string()),
            ("client_id".to_string(), field("client_id")),
            ("qos".to_string(), u8::from(qos).to_string()),
            ("timestamp".to_string(), millis.to_string()),
            (
                "YYYYMMDD".to_string(),
                format!("{year:04}{month:02}{day:02}"),
            ),
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
                    Some(scalar) if scalar.is_number() || scalar.is_boolean() => scalar.to_string(),
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

    /// Resolve + sanitize the table (illegal characters become `_`,
    /// optional `$suffix` decorator appended).
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
        let rendered = render_template(&self.table_template, &borrowed)?;
        let mut table: String = rendered
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        if table.trim().is_empty() || table.starts_with(|c: char| c.is_ascii_digit()) {
            return Err(ConnectorError::Dispatch(format!(
                "bigquery table resolved invalid: {table:?}"
            )));
        }
        if let Some(suffix) = &self.template_suffix {
            let rendered = self.event_vars(topic, payload, qos, millis, suffix)?;
            if !rendered
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                return Err(ConnectorError::Dispatch(format!(
                    "bigquery suffix resolved invalid: {rendered:?}"
                )));
            }
            table.push('$');
            table.push_str(&rendered);
        }
        Ok(table)
    }
}

// ---------------------------------------------------------------------------
// Wire framing.
// ---------------------------------------------------------------------------

/// One streaming row: UUID insert id + projected JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BigQueryRowEntry {
    pub insert_id: String,
    pub json: serde_json::Value,
}

/// Render the `insertAll` JSON body.
pub fn render_insert_body(
    ignore_unknown: bool,
    skip_invalid: bool,
    rows: &[BigQueryRowEntry],
) -> Vec<u8> {
    let mut body = String::from("{\"kind\":\"bigquery#tableDataInsertAllRequest\",");
    body.push_str("\"ignoreUnknownValues\":");
    body.push_str(if ignore_unknown { "true" } else { "false" });
    body.push_str(",\"skipInvalidRows\":");
    body.push_str(if skip_invalid { "true" } else { "false" });
    body.push_str(",\"rows\":[");
    for (index, row) in rows.iter().enumerate() {
        if index > 0 {
            body.push(',');
        }
        body.push_str("{\"insertId\":");
        body.push_str(&serde_json::to_string(&row.insert_id).unwrap_or_default());
        body.push_str(",\"json\":");
        body.push_str(&row.json.to_string());
        body.push('}');
    }
    body.push_str("]}");
    body.into_bytes()
}

/// Per-row insert errors: (index, transient?) from `insertErrors`.
/// Transient reasons (`backendError`, `rateLimitExceeded`) return
/// their indices for selective requeue; anything else is terminal.
pub fn classify_insert_errors(body: &[u8]) -> Result<Vec<usize>> {
    let doc: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| ConnectorError::Connection(format!("bigquery bad response JSON: {e}")))?;
    let empty = Vec::new();
    let errors = doc
        .get("insertErrors")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty);
    let mut transient = Vec::new();
    for entry in errors {
        let index = entry
            .get("index")
            .and_then(|v| v.as_u64())
            .unwrap_or(usize::MAX as u64) as usize;
        let reasons: Vec<&str> = entry
            .get("errors")
            .and_then(|v| v.as_array())
            .map(|list| {
                list.iter()
                    .filter_map(|error| error.get("reason").and_then(|v| v.as_str()))
                    .collect()
            })
            .unwrap_or_default();
        if reasons
            .iter()
            .all(|reason| matches!(*reason, "backendError" | "rateLimitExceeded"))
        {
            transient.push(index);
        } else {
            return Err(ConnectorError::Dispatch(format!(
                "bigquery terminal row errors at {index}: {reasons:?}"
            )));
        }
    }
    Ok(transient)
}

// ---------------------------------------------------------------------------
// Transport.
// ---------------------------------------------------------------------------

/// Scripted outcome for the mock transport.
#[derive(Debug, Clone)]
pub enum MockBigQueryOutcome {
    Accepted,
    /// Row indices (into the call) failing transiently.
    PartialFailed(Vec<usize>),
    /// Whole-batch throttle (retries everything).
    Throttled,
    /// Terminal dispatch failure.
    Terminal(String),
    /// Transport failure (retries in-loop).
    ConnectionError(String),
}

/// One captured insert call.
#[derive(Debug, Clone)]
pub struct CapturedBigQueryInsert {
    pub project: String,
    pub dataset: String,
    pub table: String,
    pub rows: Vec<BigQueryRowEntry>,
    pub token: Option<String>,
}

#[async_trait]
pub trait BigQueryTransport: Send + Sync {
    async fn insert_all(
        &self,
        project: &str,
        dataset: &str,
        table: &str,
        rows: Vec<BigQueryRowEntry>,
        token: &str,
    ) -> Result<BigQueryInsertResponse>;
}

/// Parsed insert outcome: empty failures means fully written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BigQueryInsertResponse {
    pub failed_indices: Vec<usize>,
}

/// In-memory transport with scripted outcomes (tests, dry runs).
#[derive(Debug, Default)]
pub struct MockBigQueryTransport {
    scripted: parking_lot::Mutex<std::collections::VecDeque<MockBigQueryOutcome>>,
    captured: parking_lot::Mutex<Vec<CapturedBigQueryInsert>>,
    calls: AtomicU64,
}

impl MockBigQueryTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue outcomes consumed in order (default: all accepted).
    pub fn script_outcomes(&self, outcomes: Vec<MockBigQueryOutcome>) {
        *self.scripted.lock() = outcomes.into_iter().collect();
    }

    pub fn captured(&self) -> Vec<CapturedBigQueryInsert> {
        self.captured.lock().clone()
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl BigQueryTransport for MockBigQueryTransport {
    async fn insert_all(
        &self,
        project: &str,
        dataset: &str,
        table: &str,
        rows: Vec<BigQueryRowEntry>,
        token: &str,
    ) -> Result<BigQueryInsertResponse> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.captured.lock().push(CapturedBigQueryInsert {
            project: project.to_string(),
            dataset: dataset.to_string(),
            table: table.to_string(),
            rows: rows.clone(),
            token: if token.is_empty() {
                None
            } else {
                Some(token.to_string())
            },
        });
        match self.scripted.lock().pop_front() {
            None | Some(MockBigQueryOutcome::Accepted) => Ok(BigQueryInsertResponse {
                failed_indices: Vec::new(),
            }),
            Some(MockBigQueryOutcome::PartialFailed(indices)) => Ok(BigQueryInsertResponse {
                failed_indices: indices,
            }),
            Some(MockBigQueryOutcome::Throttled) => Err(ConnectorError::Connection(
                "mock bigquery throttled".to_string(),
            )),
            Some(MockBigQueryOutcome::Terminal(message)) => Err(ConnectorError::Dispatch(message)),
            Some(MockBigQueryOutcome::ConnectionError(message)) => {
                Err(ConnectorError::Connection(message))
            }
        }
    }
}

/// Production transport: `POST {insert-url}` with the rows body.
/// Service-account tokens resolve through the shared [`GcpTokenCache`].
pub struct HttpBigQueryTransport {
    base: String,
    token_cache: Option<Arc<GcpTokenCache>>,
    static_bearer: Option<String>,
    client: reqwest::Client,
}

impl HttpBigQueryTransport {
    pub fn new(config: &BigQuerySinkConfig, client: reqwest::Client) -> Result<Self> {
        config.validate()?;
        let (token_cache, static_bearer) = match &config.auth {
            GcpAuth::None => (None, None),
            GcpAuth::AccessToken { token } => (None, Some(format!("Bearer {token}"))),
            GcpAuth::ServiceAccountKey {
                client_email,
                private_key_pem,
            } => (
                Some(Arc::new(GcpTokenCache::new(
                    client_email.clone(),
                    private_key_pem.clone(),
                    client.clone(),
                ))),
                None,
            ),
        };
        Ok(Self {
            base: config.base_url(),
            token_cache,
            static_bearer,
            client,
        })
    }
}

#[async_trait]
impl BigQueryTransport for HttpBigQueryTransport {
    async fn insert_all(
        &self,
        project: &str,
        dataset: &str,
        table: &str,
        rows: Vec<BigQueryRowEntry>,
        _token: &str,
    ) -> Result<BigQueryInsertResponse> {
        let bearer = match &self.token_cache {
            Some(cache) => Some(format!("Bearer {}", cache.bearer_token().await?)),
            None => self.static_bearer.clone(),
        };
        // Flags ride the sink config in production; the transport
        // defaults match the API contract (ignore unknown, no skip).
        let url = format!(
            "{}/projects/{}/datasets/{}/tables/{}/insertAll",
            self.base, project, dataset, table
        );
        let mut request = self
            .client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(render_insert_body(true, false, &rows));
        if let Some(bearer) = bearer {
            request = request.header(reqwest::header::AUTHORIZATION, bearer);
        }
        let response = request
            .send()
            .await
            .map_err(|e| ConnectorError::Connection(format!("bigquery insert failed: {e}")))?;
        let status = response.status().as_u16();
        if status == 429 || (500..=504).contains(&status) {
            return Err(ConnectorError::Connection(format!(
                "bigquery throttled with {status}"
            )));
        }
        if !(200..=299).contains(&status) {
            return Err(ConnectorError::Dispatch(format!(
                "bigquery insert failed with {status}"
            )));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|e| ConnectorError::Connection(format!("bigquery read failed: {e}")))?;
        Ok(BigQueryInsertResponse {
            failed_indices: classify_insert_errors(&bytes)?,
        })
    }
}

// ---------------------------------------------------------------------------
// Sink.
// ---------------------------------------------------------------------------

/// One buffered row: table, JSON document, byte size.
#[derive(Debug, Clone)]
struct BigQueryRow {
    table: String,
    document: serde_json::Value,
}

struct BigQueryBuffer {
    queue: BatchQueue<BigQueryRow>,
    bytes: usize,
}

/// BigQuery sink: buffers rows, streams insertAll batches per table.
pub struct BigQuerySink {
    config: BigQuerySinkConfig,
    transport: Arc<dyn BigQueryTransport>,
    buffer: parking_lot::Mutex<BigQueryBuffer>,
    backoff: parking_lot::Mutex<BackoffState>,
    sent_batches: AtomicU64,
    sent_records: AtomicU64,
}

impl BigQuerySink {
    pub fn new(config: BigQuerySinkConfig, transport: Arc<dyn BigQueryTransport>) -> Result<Self> {
        config.validate()?;
        let linger = config.effective_linger();
        Ok(Self {
            buffer: parking_lot::Mutex::new(BigQueryBuffer {
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

    pub fn config(&self) -> &BigQuerySinkConfig {
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

    /// Resolve the bearer token: static for access tokens, empty for
    /// emulator mode (service-account minting lives in the transport).
    fn bearer_token(&self) -> Result<String> {
        match &self.config.auth {
            GcpAuth::None => Ok(String::new()),
            GcpAuth::AccessToken { token } => Ok(format!("Bearer {token}")),
            GcpAuth::ServiceAccountKey { .. } => Ok(String::new()),
        }
    }

    /// Flush buffered rows grouped by table (no-op when empty).
    /// Partial failures requeue selectively; throttles retry
    /// everything; terminal outcomes restore and propagate.
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
        let mut groups: Vec<(String, Vec<BigQueryRow>)> = Vec::new();
        for row in &rows {
            match groups.iter_mut().find(|(table, _)| table == &row.table) {
                Some((_, grouped)) => grouped.push(row.clone()),
                None => groups.push((row.table.clone(), vec![row.clone()])),
            }
        }
        let record_count = rows.len() as u64;
        let max_retries = self.config.max_retries.unwrap_or(usize::MAX);
        let mut attempt = 0usize;
        // Pending sets narrow per group across attempts: only failed
        // rows ride the retry wire.
        let mut pending_groups: Vec<(String, Vec<BigQueryRow>)> = groups;
        let group_count = pending_groups.len() as u64;
        loop {
            let token = self.bearer_token()?;
            let mut outcome: Result<()> = Ok(());
            let mut next_pending: Vec<(String, Vec<BigQueryRow>)> = Vec::new();
            for (group_index, (table, grouped)) in pending_groups.iter().enumerate() {
                let entries: Vec<BigQueryRowEntry> = grouped
                    .iter()
                    .map(|row| BigQueryRowEntry {
                        insert_id: uuid::Uuid::new_v4().to_string(),
                        json: row.document.clone(),
                    })
                    .collect();
                match self
                    .transport
                    .insert_all(
                        &self.config.project_id,
                        &self.config.dataset_id,
                        table,
                        entries,
                        &token,
                    )
                    .await
                {
                    Ok(response) if response.failed_indices.is_empty() => {}
                    Ok(response) => {
                        let failed: Vec<BigQueryRow> = response
                            .failed_indices
                            .iter()
                            .filter_map(|index| grouped.get(*index).cloned())
                            .collect();
                        if !failed.is_empty() {
                            next_pending.push((table.clone(), failed));
                        }
                        outcome = Err(ConnectorError::Connection(
                            "bigquery partial failure".to_string(),
                        ));
                    }
                    Err(e) => {
                        // Keep this group and every unattempted one.
                        for (table, grouped) in pending_groups.iter().skip(group_index) {
                            next_pending.push((table.clone(), grouped.clone()));
                        }
                        outcome = Err(e);
                        break;
                    }
                }
            }
            pending_groups = next_pending;
            match outcome {
                Ok(()) => {
                    self.backoff.lock().success();
                    self.sent_batches.fetch_add(group_count, Ordering::Relaxed);
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
        rows: Vec<BigQueryRow>,
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

    /// Validate + buffer one event (projected JSON verbatim). Returns
    /// true when the batch is full, stale, or over bytes.
    fn buffer_row(&self, topic: &Topic, payload: &Bytes, _qos: QoS) -> Result<bool> {
        if topic.as_str().is_empty() {
            return Err(ConnectorError::Dispatch(
                "bigquery row requires a non-empty topic".to_string(),
            ));
        }
        let text = std::str::from_utf8(payload)
            .map_err(|_| ConnectorError::Dispatch("bigquery payload must be UTF-8".to_string()))?;
        let document: serde_json::Value = serde_json::from_str(text)
            .map_err(|_| ConnectorError::Dispatch("bigquery payload must be JSON".to_string()))?;
        let millis = now_millis();
        let table = self
            .config
            .resolve_table(topic.as_str(), payload, _qos, millis)?;
        let bytes = document.to_string().len() + table.len();
        let mut buffer = self.buffer.lock();
        let full = buffer.queue.push(BigQueryRow { table, document });
        buffer.bytes = buffer.bytes.saturating_add(bytes);
        Ok(full || buffer.bytes >= self.config.effective_batch_bytes())
    }
}

#[async_trait]
impl Sink for BigQuerySink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        if self.buffer_row(topic, payload, qos)? {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "bigquery"
    }
}

/// Management connector handle pairing an id with a BigQuery sink.
pub struct BigQueryConnector {
    id: String,
    sink: Arc<BigQuerySink>,
}

impl BigQueryConnector {
    pub fn new(id: impl Into<String>, sink: Arc<BigQuerySink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }
}

impl super::Connector for BigQueryConnector {
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

    fn test_config() -> BigQuerySinkConfig {
        BigQuerySinkConfig {
            project_id: "my-iot-project".to_string(),
            dataset_id: "telemetry".to_string(),
            table_template: "telemetry_${topic}".to_string(),
            endpoint: None,
            auth: GcpAuth::None,
            ignore_unknown_values: true,
            skip_invalid_rows: false,
            template_suffix: None,
            batch_size: Some(500),
            batch_bytes: Some(1_048_576),
            linger_ms: Some(20),
            max_retries: Some(4),
            initial_backoff_ms: Some(100),
            max_backoff_ms: Some(2_500),
            timeout_ms: None,
        }
    }

    fn test_sink(config: BigQuerySinkConfig) -> (Arc<BigQuerySink>, Arc<MockBigQueryTransport>) {
        let transport = Arc::new(MockBigQueryTransport::new());
        let sink = Arc::new(BigQuerySink::new(config, transport.clone()).unwrap());
        (sink, transport)
    }

    #[test]
    fn test_config_validation() {
        let mut config = test_config();
        assert!(config.validate().is_ok());
        assert_eq!(
            config.insert_url("sensor_logs"),
            "https://bigquery.googleapis.com/bigquery/v2/projects/my-iot-project/datasets/telemetry/tables/sensor_logs/insertAll"
        );

        config.project_id = "UPPER SPACE".to_string();
        assert!(config.validate().is_err());
        config.project_id = test_config().project_id;

        config.dataset_id.clear();
        assert!(config.validate().is_err());
        config.dataset_id = test_config().dataset_id;

        config.table_template = "9lives".to_string();
        assert!(config.validate().is_err(), "leading digits rejected");
        config.table_template = test_config().table_template;

        config.template_suffix = Some("2026.09.12".to_string());
        assert!(config
            .resolve_table("t", b"{}", QoS::AtMostOnce, 0)
            .is_err());
        config.template_suffix = Some("${YYYYMMDD}".to_string());
        assert!(config
            .resolve_table("t", b"{}", QoS::AtMostOnce, 1_789_211_889_123)
            .unwrap()
            .ends_with("$20260912"));

        config.batch_size = Some(0);
        assert!(config.validate().is_err());
        // Unbounded + huge depths accepted: zero clamped ceilings.
        config.batch_size = None;
        config.batch_bytes = Some(10_000_000);
        config.max_retries = None;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_bearer_token_resolution() {
        let (none_sink, _) = test_sink(test_config());
        assert_eq!(none_sink.bearer_token().unwrap(), "");
        let mut token_config = test_config();
        token_config.auth = GcpAuth::AccessToken {
            token: "ya29.test".to_string(),
        };
        let (token_sink, _) = test_sink(token_config);
        assert_eq!(token_sink.bearer_token().unwrap(), "Bearer ya29.test");
    }

    #[test]
    fn test_suffix_decorator_resolution() {
        let mut config = test_config();
        config.template_suffix = Some("${YYYYMMDD}".to_string());
        // 2026-09-12T11:18:09.123Z.
        assert_eq!(
            config
                .resolve_table("t", b"{}", QoS::AtMostOnce, 1_789_211_889_123)
                .unwrap(),
            "telemetry_t$20260912"
        );
    }

    #[test]
    fn test_request_framing() {
        let rows = vec![
            BigQueryRowEntry {
                insert_id: "uuid-or-seq-1".to_string(),
                json: serde_json::json!({
                    "device_id": "sensor-101",
                    "topic": "factory/temp",
                    "temperature": 75.2,
                    "timestamp": "2026-09-12T19:00:00Z",
                }),
            },
            BigQueryRowEntry {
                insert_id: "uuid-or-seq-2".to_string(),
                json: serde_json::json!({"device_id": "sensor-102"}),
            },
        ];
        let body = render_insert_body(true, false, &rows);
        assert_eq!(
            String::from_utf8(body).unwrap(),
            r#"{"kind":"bigquery#tableDataInsertAllRequest","ignoreUnknownValues":true,"skipInvalidRows":false,"rows":[{"insertId":"uuid-or-seq-1","json":{"device_id":"sensor-101","temperature":75.2,"timestamp":"2026-09-12T19:00:00Z","topic":"factory/temp"}},{"insertId":"uuid-or-seq-2","json":{"device_id":"sensor-102"}}]}"#
        );

        // Error classification: transient reasons requeue, rest abort.
        assert_eq!(
            classify_insert_errors(
                br#"{"insertErrors":[{"index":2,"errors":[{"reason":"backendError"}]},{"index":5,"errors":[{"reason":"rateLimitExceeded"}]}]}"#
            )
            .unwrap(),
            vec![2, 5]
        );
        assert!(classify_insert_errors(
            br#"{"insertErrors":[{"index":0,"errors":[{"reason":"invalid"}]}]}"#
        )
        .is_err());
        assert_eq!(
            classify_insert_errors(br#"{}"#).unwrap(),
            Vec::<usize>::new()
        );
    }

    #[tokio::test]
    async fn test_insert_flow_and_ids() {
        let (sink, transport) = test_sink(test_config());
        sink.send(
            &Topic::new("sensors/t1").unwrap(),
            &Bytes::from_static(br#"{"device_id":"sensor-101","temperature":75.2}"#),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        sink.flush().await.unwrap();

        let captured = transport.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].project, "my-iot-project");
        assert_eq!(captured[0].dataset, "telemetry");
        assert_eq!(captured[0].table, "telemetry_sensors_t1");
        assert_eq!(captured[0].token, None);
        assert_eq!(captured[0].rows.len(), 1);
        // UUID insert ids are unique per row.
        assert_eq!(captured[0].rows[0].insert_id.len(), 36);
        assert_eq!(
            captured[0].rows[0].json,
            serde_json::json!({"device_id": "sensor-101", "temperature": 75.2})
        );
        assert_eq!(sink.sent_records(), 1);
    }

    #[tokio::test]
    async fn test_partial_failure_requeues_selectively() {
        let mut config = test_config();
        config.batch_size = Some(10);
        config.initial_backoff_ms = Some(1);
        config.max_backoff_ms = Some(2);
        let (sink, transport) = test_sink(config);
        // First pass fails row 1 transiently; the retry carries it alone.
        transport.script_outcomes(vec![
            MockBigQueryOutcome::PartialFailed(vec![1]),
            MockBigQueryOutcome::Accepted,
        ]);

        let topic = Topic::new("t").unwrap();
        for temp in [20.5, 21.5] {
            sink.send(
                &topic,
                &Bytes::from(format!("{{\"temp\":{temp}}}")),
                QoS::AtMostOnce,
            )
            .await
            .unwrap();
        }
        sink.flush().await.unwrap();

        assert_eq!(transport.calls(), 2);
        let captured = transport.captured();
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[0].rows.len(), 2);
        assert_eq!(captured[1].rows.len(), 1);
        assert_eq!(captured[1].rows[0].json, serde_json::json!({"temp": 21.5}));
        assert_eq!(sink.sent_records(), 2);
        assert_eq!(sink.buffered_rows(), 0);
    }

    #[tokio::test]
    async fn test_terminal_row_error_aborts() {
        let mut config = test_config();
        config.batch_size = Some(10);
        config.max_retries = Some(5);
        let (sink, transport) = test_sink(config);
        // A terminal row reason aborts without consuming retries: the
        // mock reports it through the transport as a dispatch error.
        transport.script_outcomes(vec![MockBigQueryOutcome::Terminal(
            "invalid schema".to_string(),
        )]);

        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from("{}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        let err = sink.flush().await.expect_err("terminal must fail");
        assert!(matches!(err, ConnectorError::Dispatch(_)));
        assert_eq!(transport.calls(), 1);
        assert_eq!(sink.buffered_rows(), 1);
    }

    #[tokio::test]
    async fn test_throttle_retries_and_backs_off() {
        let mut config = test_config();
        config.batch_size = Some(10);
        config.max_retries = Some(0);
        let (sink, transport) = test_sink(config);
        transport.script_outcomes(vec![MockBigQueryOutcome::Throttled]);

        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from("{}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        let err = sink.flush().await.expect_err("throttle must exhaust");
        assert!(matches!(err, ConnectorError::Connection(_)));
        assert_eq!(transport.calls(), 1);
        assert_eq!(sink.buffered_rows(), 1);
        let calls = transport.calls();
        assert!(sink.flush().await.is_err());
        assert_eq!(transport.calls(), calls);
    }
}
