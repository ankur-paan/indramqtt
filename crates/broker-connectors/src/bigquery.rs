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
//! The write path runs on the maintained `gcp-bigquery-client` driver
//! ([`SdkBigQueryTransport`] below): `TableDataInsertAllRequest` framing
//! plus `tabledata().insertAll` over OAuth2 Bearer. The legacy
//! hand-written [`HttpBigQueryTransport`] is retained for endpoint
//! overrides and offline unit tests only; production wiring uses the
//! driver transport.
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

// Default batching/ retry numbers and where they come from:
// - 500 rows per `insertAll`: the BigQuery legacy streaming `insertAll`
//   REST contract caps a request at 10_000 rows / 10 MiB; 500 keeps a
//   batch well under both while bounding per-flush memory, and matches the
//   sibling warehouse sinks in this crate.
// - 1_048_576 bytes (1 MiB): bounds the in-memory batch below the 10 MiB
//   service cap so a flush never builds a rejected request.
// - 20 ms linger: bounds added publish latency while still coalescing a
//   burst of rule outputs into one request.
// - 4 retries, 100 ms initial backoff, 2_500 ms ceiling: standard
//   truncated-exponential budget for transient `backendError` /
//   `rateLimitExceeded` / 429 / 5xx; the ceiling keeps the worst-case
//   stall near 100+200+400+800 ms plus jitter.
// - 5_000 ms request timeout: bounds one `insertAll` round trip so a slow
//   server surfaces as a retryable connection error instead of stalling
//   the rule path.
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
    /// Rows per `insertAll` (default 500: BigQuery `insertAll` streaming
    /// cap headroom, see `default_batch_size`).
    #[serde(default = "default_batch_size")]
    pub batch_size: Option<usize>,
    /// Batch byte limit (default 1 MiB: bounds memory below the service cap).
    #[serde(default = "default_batch_bytes")]
    pub batch_bytes: Option<usize>,
    /// Linger flush window in ms (default 20: bounds added latency).
    #[serde(default = "default_linger_ms")]
    pub linger_ms: Option<u64>,
    /// Retries on throttles/partials (default 4, `None` unbounded).
    #[serde(default = "default_max_retries")]
    pub max_retries: Option<usize>,
    /// First retry delay in ms (default 100: backoff floor).
    #[serde(default = "default_initial_backoff_ms")]
    pub initial_backoff_ms: Option<u64>,
    /// Retry delay ceiling in ms (default 2500: bounds worst-case stall).
    #[serde(default = "default_max_backoff_ms")]
    pub max_backoff_ms: Option<u64>,
    /// Request timeout in ms (default 5000: bounds one round trip).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

fn default_true() -> bool {
    true
}

impl BigQuerySinkConfig {
    /// 5_000 ms default: bounds one `insertAll` round trip (see
    /// `default_batch_size` note); `.max(1)` keeps a zero config from
    /// becoming a zero timeout.
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

/// Render a JSON value with object keys in sorted order, so the exact
/// wire assertion holds regardless of Cargo feature unification
/// (`serde_json/preserve_order` switches objects from sorted `BTreeMap`
/// to insertion-order `IndexMap`).
fn sorted_json(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let sorted: std::collections::BTreeMap<&str, serde_json::Value> = map
                .iter()
                .map(|(key, val)| (key.as_str(), sorted_json(val)))
                .collect();
            let mut ordered = serde_json::Map::with_capacity(sorted.len());
            for (key, val) in sorted {
                ordered.insert(key.to_string(), val);
            }
            serde_json::Value::Object(ordered)
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(sorted_json).collect())
        }
        _ => value.clone(),
    }
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
        body.push_str(&sorted_json(&row.json).to_string());
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
/// The loopback fake tests below drive this path end to end.
/// Flag defaults mirror the `insertAll` REST contract (`ignoreUnknownValues`
/// defaults true, `skipInvalidRows` defaults false) and are read from
/// [`BigQuerySinkConfig`] so management configuration drives the wire.
pub struct HttpBigQueryTransport {
    base: String,
    token_cache: Option<Arc<GcpTokenCache>>,
    static_bearer: Option<String>,
    client: reqwest::Client,
    timeout: Duration,
    ignore_unknown_values: bool,
    skip_invalid_rows: bool,
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
            timeout: config.timeout(),
            ignore_unknown_values: config.ignore_unknown_values,
            skip_invalid_rows: config.skip_invalid_rows,
        })
    }

    /// Test hook proving `new` stores the configured base URL; the
    /// production path uses `self.base` in `insert_all` above.
    #[cfg(test)]
    fn base(&self) -> &str {
        &self.base
    }

    /// Flags under test: proves the sink config (not a hardcoded constant)
    /// drives the `insertAll` body.
    #[cfg(test)]
    fn flags(&self) -> (bool, bool) {
        (self.ignore_unknown_values, self.skip_invalid_rows)
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
        // reads them from `BigQuerySinkConfig` (wired in `new` above) so a
        // management change reaches the wire without code edits.
        let url = format!(
            "{}/projects/{}/datasets/{}/tables/{}/insertAll",
            self.base, project, dataset, table
        );
        let mut request = self
            .client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .timeout(self.timeout)
            .body(render_insert_body(
                self.ignore_unknown_values,
                self.skip_invalid_rows,
                &rows,
            ));
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
// Maintained-driver transport (`gcp-bigquery-client`).
// ---------------------------------------------------------------------------

/// Build a driver `TableDataInsertAllRequest` from buffered rows.
pub fn driver_insert_request(
    ignore_unknown: bool,
    skip_invalid: bool,
    rows: &[BigQueryRowEntry],
) -> Result<gcp_bigquery_client::model::table_data_insert_all_request::TableDataInsertAllRequest> {
    let mut request =
        gcp_bigquery_client::model::table_data_insert_all_request::TableDataInsertAllRequest::new();
    if ignore_unknown {
        request.ignore_unknown_values();
    }
    if skip_invalid {
        request.skip_invalid_rows();
    }
    for row in rows {
        request
            .add_row(Some(row.insert_id.clone()), row.json.clone())
            .map_err(|e| ConnectorError::Dispatch(format!("bigquery driver row rejected: {e}")))?;
    }
    Ok(request)
}

/// Classify a driver `TableDataInsertAllResponse`: transient row reasons
/// (`backendError`, `rateLimitExceeded`) return their indices for
/// selective requeue; anything else is terminal.
pub fn classify_driver_response(
    response: &gcp_bigquery_client::model::table_data_insert_all_response::TableDataInsertAllResponse,
) -> Result<Vec<usize>> {
    let mut transient = Vec::new();
    let empty = Vec::new();
    let errors = response.insert_errors.as_ref().unwrap_or(&empty);
    for entry in errors {
        // A missing index cannot be mapped back to a buffered row. Use
        // `usize::MAX` (same sentinel as `classify_insert_errors`) so the
        // sink's `grouped.get(index)` drops it instead of requeueing the
        // wrong row; the batch still reports a partial failure.
        let index = entry.index.map(|v| v as usize).unwrap_or(usize::MAX);
        let reasons: Vec<&str> = entry
            .errors
            .as_ref()
            .map(|list| {
                list.iter()
                    .filter_map(|error| error.reason.as_deref())
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

/// Map a driver `BQError` onto dispatch vs connection failures.
/// HTTP 429 / 5xx and transport/auth outages retry; everything else is
/// terminal. Config and programming errors (bad service-account key,
/// bad column access, serialization, missing data) are terminal because
/// retrying cannot fix them.
fn map_bq_error(error: gcp_bigquery_client::error::BQError) -> ConnectorError {
    use gcp_bigquery_client::error::BQError as BQ;
    match &error {
        BQ::ResponseError { error } => {
            let code = error.error.code;
            if code == 429 || (500..=504).contains(&code) {
                ConnectorError::Connection(format!(
                    "bigquery driver throttled with {code}: {error:?}"
                ))
            } else {
                ConnectorError::Dispatch(format!("bigquery driver rejected with {code}: {error:?}"))
            }
        }
        BQ::RequestError(_)
        | BQ::NoToken
        | BQ::AuthError(_)
        | BQ::YupAuthError(_)
        | BQ::TonicTransportError(_)
        | BQ::TonicStatusError(_)
        | BQ::ConnectionPoolError(_)
        | BQ::SemaphorePermitError(_)
        | BQ::TokioTaskError(_) => {
            ConnectorError::Connection(format!("bigquery driver transport failed: {error}"))
        }
        BQ::InvalidServiceAccountKey(_)
        | BQ::InvalidServiceAccountAuthenticator(_)
        | BQ::InvalidInstalledFlowAuthenticator(_)
        | BQ::InvalidApplicationDefaultCredentialsAuthenticator(_)
        | BQ::InvalidAuthorizedUserAuthenticator(_)
        | BQ::NoDataAvailable
        | BQ::InvalidColumnIndex { .. }
        | BQ::InvalidColumnName { .. }
        | BQ::InvalidColumnType { .. }
        | BQ::SerializationError(_)
        | BQ::TonicInvalidMetadataValueError(_) => {
            ConnectorError::Dispatch(format!("bigquery driver failed: {error}"))
        }
    }
}

/// Static-token authenticator for the driver (raw access tokens and
/// emulator mode). The driver requires an `Authenticator` impl; for a
/// pre-minted token or the emulator there is no refresh to perform, so
/// `access_token` returns the configured token verbatim.
#[derive(Debug, Clone)]
struct StaticTokenAuthenticator {
    token: String,
}

#[async_trait]
impl gcp_bigquery_client::auth::Authenticator for StaticTokenAuthenticator {
    async fn access_token(
        &self,
    ) -> std::result::Result<String, gcp_bigquery_client::error::BQError> {
        Ok(self.token.clone())
    }
}

/// Production transport on the maintained `gcp-bigquery-client` driver:
/// `tabledata().insertAll` with OAuth2 Bearer. Service-account keys map
/// onto `yup-oauth2` service-account flow; raw tokens and `None` map onto
/// a static authenticator (empty for the emulator). An endpoint override
/// rewrites the v2 base URL for loopback fakes.
pub struct SdkBigQueryTransport {
    auth: GcpAuth,
    endpoint: Option<String>,
    ignore_unknown_values: bool,
    skip_invalid_rows: bool,
    client: reqwest::Client,
    timeout: Duration,
    driver: tokio::sync::OnceCell<gcp_bigquery_client::Client>,
}

impl SdkBigQueryTransport {
    pub fn new(config: &BigQuerySinkConfig, client: reqwest::Client) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            auth: config.auth.clone(),
            endpoint: config.endpoint.clone(),
            ignore_unknown_values: config.ignore_unknown_values,
            skip_invalid_rows: config.skip_invalid_rows,
            client,
            timeout: config.timeout(),
            driver: tokio::sync::OnceCell::new(),
        })
    }

    /// Test hook proving `new` stores the configured timeout; the
    /// production path applies `self.timeout` to the driver call in
    /// `insert_all` above.
    #[cfg(test)]
    fn timeout(&self) -> Duration {
        self.timeout
    }

    async fn driver_client(&self) -> Result<gcp_bigquery_client::Client> {
        let auth = self.auth.clone();
        let endpoint = self.endpoint.clone();
        let client = self.client.clone();
        self.driver
            .get_or_try_init(|| async move {
                let mut builder = gcp_bigquery_client::client_builder::ClientBuilder::new();
                if let Some(endpoint) = endpoint {
                    let base = endpoint.trim_end_matches('/').to_string();
                    builder.with_v2_base_url(format!("{base}/bigquery/v2"));
                }
                builder.with_client(client);
                match auth {
                    GcpAuth::None => {
                        let auth: std::sync::Arc<dyn gcp_bigquery_client::auth::Authenticator> =
                            std::sync::Arc::new(StaticTokenAuthenticator {
                                token: String::new(),
                            });
                        builder
                            .build_from_authenticator(auth)
                            .await
                            .map_err(map_bq_error)
                    }
                    GcpAuth::AccessToken { token } => {
                        let auth: std::sync::Arc<dyn gcp_bigquery_client::auth::Authenticator> =
                            std::sync::Arc::new(StaticTokenAuthenticator { token });
                        builder
                            .build_from_authenticator(auth)
                            .await
                            .map_err(map_bq_error)
                    }
                    GcpAuth::ServiceAccountKey {
                        client_email,
                        private_key_pem,
                    } => {
                        let key = gcp_bigquery_client::yup_oauth2::ServiceAccountKey {
                            key_type: Some("service_account".to_string()),
                            project_id: None,
                            private_key_id: None,
                            private_key: private_key_pem,
                            client_email,
                            client_id: None,
                            auth_uri: None,
                            token_uri: "https://oauth2.googleapis.com/token".to_string(),
                            auth_provider_x509_cert_url: None,
                            client_x509_cert_url: None,
                        };
                        builder
                            .build_from_service_account_key(key, false)
                            .await
                            .map_err(map_bq_error)
                    }
                }
            })
            .await
            .cloned()
            .map_err(|e: ConnectorError| e)
    }
}

#[async_trait]
impl BigQueryTransport for SdkBigQueryTransport {
    async fn insert_all(
        &self,
        project: &str,
        dataset: &str,
        table: &str,
        rows: Vec<BigQueryRowEntry>,
        _token: &str,
    ) -> Result<BigQueryInsertResponse> {
        let driver = self.driver_client().await?;
        let request =
            driver_insert_request(self.ignore_unknown_values, self.skip_invalid_rows, &rows)?;
        let timeout = self.timeout;
        let response = tokio::time::timeout(
            timeout,
            driver
                .tabledata()
                .insert_all(project, dataset, table, request),
        )
        .await
        .map_err(|_| {
            ConnectorError::Connection(format!(
                "bigquery driver timed out after {}ms",
                timeout.as_millis()
            ))
        })?
        .map_err(map_bq_error)?;
        Ok(BigQueryInsertResponse {
            failed_indices: classify_driver_response(&response)?,
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
            config.base_url(),
            "https://bigquery.googleapis.com/bigquery/v2"
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
                // Keys in sorted order so the exact wire assertion below
                // holds with and without `serde_json/preserve_order`.
                json: serde_json::json!({
                    "device_id": "sensor-101",
                    "temperature": 75.2,
                    "timestamp": "2026-09-12T19:00:00Z",
                    "topic": "factory/temp",
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

    #[derive(Default)]
    struct FakeBigQuery {
        bodies: parking_lot::Mutex<Vec<serde_json::Value>>,
        paths: parking_lot::Mutex<Vec<String>>,
        script: parking_lot::Mutex<std::collections::VecDeque<(u16, serde_json::Value)>>,
        delay_ms: parking_lot::Mutex<u64>,
    }

    impl FakeBigQuery {
        fn with_script(responses: Vec<(u16, serde_json::Value)>) -> Self {
            Self {
                script: parking_lot::Mutex::new(responses.into_iter().collect()),
                ..Self::default()
            }
        }

        fn captured_bodies(&self) -> Vec<serde_json::Value> {
            self.bodies.lock().clone()
        }

        fn captured_paths(&self) -> Vec<String> {
            self.paths.lock().clone()
        }

        fn call_count(&self) -> usize {
            self.bodies.lock().len()
        }
    }

    async fn serve_fake_bigquery(fake: Arc<FakeBigQuery>) -> String {
        use axum::{extract::State, http::StatusCode, routing::post, Router};
        async fn handler(
            State(fake): State<Arc<FakeBigQuery>>,
            uri: axum::http::Uri,
            body: String,
        ) -> (StatusCode, String) {
            let delay = *fake.delay_ms.lock();
            if delay > 0 {
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
            fake.paths.lock().push(uri.path().to_string());
            let parsed: serde_json::Value =
                serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
            fake.bodies.lock().push(parsed);
            let next = fake.script.lock().pop_front();
            match next {
                Some((status, value)) => (
                    StatusCode::from_u16(status).unwrap_or(StatusCode::OK),
                    value.to_string(),
                ),
                None => (StatusCode::OK, "{}".to_string()),
            }
        }
        let app = Router::new()
            .route("/*rest", post(handler))
            .with_state(fake);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake bigquery");
        let port = listener.local_addr().expect("fake addr").port();
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve fake");
        });
        format!("http://127.0.0.1:{port}")
    }

    fn sdk_config_with_endpoint(endpoint: &str) -> BigQuerySinkConfig {
        let mut config = test_config();
        config.endpoint = Some(endpoint.to_string());
        config
    }

    #[test]
    fn test_driver_request_framing() {
        let rows = vec![
            BigQueryRowEntry {
                insert_id: "11111111-1111-1111-1111-111111111111".to_string(),
                json: serde_json::json!({"device_id": "sensor-101", "temp": 75.2}),
            },
            BigQueryRowEntry {
                insert_id: "22222222-2222-2222-2222-222222222222".to_string(),
                json: serde_json::json!({"device_id": "sensor-102"}),
            },
        ];
        let request = driver_insert_request(true, false, &rows).expect("driver request builds");
        let body = serde_json::to_value(&request).expect("driver request serializes");
        assert_eq!(body["ignoreUnknownValues"], serde_json::json!(true));
        assert_eq!(body["skipInvalidRows"], serde_json::json!(false));
        assert_eq!(body["rows"].as_array().expect("rows").len(), 2);
        assert_eq!(
            body["rows"][0]["insertId"],
            serde_json::json!("11111111-1111-1111-1111-111111111111")
        );
        assert_eq!(
            body["rows"][0]["json"]["device_id"],
            serde_json::json!("sensor-101")
        );

        let flipped = driver_insert_request(false, true, &rows).expect("flags flip");
        let flipped_body = serde_json::to_value(&flipped).expect("serializes");
        assert_eq!(
            flipped_body["ignoreUnknownValues"],
            serde_json::json!(false)
        );
        assert_eq!(flipped_body["skipInvalidRows"], serde_json::json!(true));
    }

    #[tokio::test]
    async fn test_driver_request_framing_reaches_fake() {
        let fake = Arc::new(FakeBigQuery::default());
        let endpoint = serve_fake_bigquery(fake.clone()).await;
        let config = sdk_config_with_endpoint(&endpoint);
        let transport =
            SdkBigQueryTransport::new(&config, reqwest::Client::new()).expect("sdk transport");
        let rows = vec![
            BigQueryRowEntry {
                insert_id: "11111111-1111-1111-1111-111111111111".to_string(),
                json: serde_json::json!({"device_id": "sensor-101", "temp": 75.2}),
            },
            BigQueryRowEntry {
                insert_id: "22222222-2222-2222-2222-222222222222".to_string(),
                json: serde_json::json!({"device_id": "sensor-102"}),
            },
        ];
        let response = transport
            .insert_all("my-iot-project", "telemetry", "telemetry_t", rows, "")
            .await
            .expect("fake insert");
        assert!(response.failed_indices.is_empty());
        assert_eq!(fake.call_count(), 1);
        let captured = fake.captured_bodies();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0]["ignoreUnknownValues"], serde_json::json!(true));
        assert_eq!(captured[0]["skipInvalidRows"], serde_json::json!(false));
        assert_eq!(captured[0]["rows"].as_array().expect("rows").len(), 2);
        assert_eq!(
            captured[0]["rows"][0]["insertId"],
            serde_json::json!("11111111-1111-1111-1111-111111111111")
        );
        assert_eq!(
            captured[0]["rows"][0]["json"]["device_id"],
            serde_json::json!("sensor-101")
        );
        let path = fake.captured_paths().pop().expect("path");
        assert!(
            path.ends_with(
                "/projects/my-iot-project/datasets/telemetry/tables/telemetry_t/insertAll"
            ),
            "unexpected path {path}"
        );
    }

    #[test]
    fn test_driver_response_classification() {
        use gcp_bigquery_client::model::table_data_insert_all_response::TableDataInsertAllResponse;
        let transient: TableDataInsertAllResponse = serde_json::from_value(serde_json::json!({
            "insertErrors": [
                {"index": 2, "errors": [{"reason": "backendError"}]},
                {"index": 5, "errors": [{"reason": "rateLimitExceeded"}]},
            ]
        }))
        .expect("transient parses");
        assert_eq!(classify_driver_response(&transient).unwrap(), vec![2, 5]);

        let terminal: TableDataInsertAllResponse = serde_json::from_value(serde_json::json!({
            "insertErrors": [{"index": 0, "errors": [{"reason": "invalid"}]}]
        }))
        .expect("terminal parses");
        assert!(classify_driver_response(&terminal).is_err());

        let empty: TableDataInsertAllResponse =
            serde_json::from_value(serde_json::json!({})).expect("empty parses");
        assert_eq!(
            classify_driver_response(&empty).unwrap(),
            Vec::<usize>::new()
        );
    }

    #[tokio::test]
    async fn test_driver_response_classification_reaches_fake() {
        // Transient row errors surface as retryable indices through the
        // driver transport, not just the pure classifier.
        let fake = Arc::new(FakeBigQuery::with_script(vec![(
            200,
            serde_json::json!({
                "insertErrors": [
                    {"index": 1, "errors": [{"reason": "backendError"}]},
                ]
            }),
        )]));
        let endpoint = serve_fake_bigquery(fake.clone()).await;
        let config = sdk_config_with_endpoint(&endpoint);
        let transport =
            SdkBigQueryTransport::new(&config, reqwest::Client::new()).expect("sdk transport");
        let rows = vec![
            BigQueryRowEntry {
                insert_id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".to_string(),
                json: serde_json::json!({"temp": 20.5}),
            },
            BigQueryRowEntry {
                insert_id: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb".to_string(),
                json: serde_json::json!({"temp": 21.5}),
            },
        ];
        let response = transport
            .insert_all("my-iot-project", "telemetry", "t", rows, "")
            .await
            .expect("partial maps to indices");
        assert_eq!(response.failed_indices, vec![1]);

        // Terminal row reasons surface as dispatch errors through the
        // same path.
        let terminal_fake = Arc::new(FakeBigQuery::with_script(vec![(
            200,
            serde_json::json!({
                "insertErrors": [{"index": 0, "errors": [{"reason": "invalid"}]}]
            }),
        )]));
        let terminal_endpoint = serve_fake_bigquery(terminal_fake).await;
        let terminal_config = sdk_config_with_endpoint(&terminal_endpoint);
        let terminal_transport =
            SdkBigQueryTransport::new(&terminal_config, reqwest::Client::new())
                .expect("sdk transport");
        let terminal_rows = vec![BigQueryRowEntry {
            insert_id: "cccccccc-cccc-cccc-cccc-cccccccccccc".to_string(),
            json: serde_json::json!({"temp": 22.5}),
        }];
        let err = terminal_transport
            .insert_all("my-iot-project", "telemetry", "t", terminal_rows, "")
            .await
            .expect_err("terminal must fail");
        assert!(matches!(err, ConnectorError::Dispatch(_)));
    }

    #[tokio::test]
    async fn test_sdk_transport_builds_offline() {
        let config = test_config();
        let transport =
            SdkBigQueryTransport::new(&config, reqwest::Client::new()).expect("sdk builds");
        assert_eq!(transport.timeout(), config.timeout());

        let mut bad = test_config();
        bad.project_id = "UPPER SPACE".to_string();
        assert!(SdkBigQueryTransport::new(&bad, reqwest::Client::new()).is_err());

        // The driver initializes without a real server: an endpoint
        // override plus static auth builds a client and performs a
        // round trip against the loopback fake.
        let fake = Arc::new(FakeBigQuery::default());
        let endpoint = serve_fake_bigquery(fake.clone()).await;
        let fake_config = sdk_config_with_endpoint(&endpoint);
        let fake_transport = SdkBigQueryTransport::new(&fake_config, reqwest::Client::new())
            .expect("fake transport builds");
        let client = fake_transport
            .driver_client()
            .await
            .expect("driver initializes offline");
        let _ = client.tabledata();
        assert_eq!(fake_transport.timeout(), fake_config.timeout());
    }

    #[tokio::test]
    async fn test_sdk_sink_flush_against_fake() {
        // Offline qualification mirror: 1000 rule-shaped rows through
        // `BigQuerySink` on `SdkBigQueryTransport`, row count asserted
        // on the fake plus selective requeue of only failed rows.
        let fake = Arc::new(FakeBigQuery::default());
        let endpoint = serve_fake_bigquery(fake.clone()).await;
        let mut config = sdk_config_with_endpoint(&endpoint);
        config.batch_size = Some(100);
        config.batch_bytes = Some(1_048_576);
        config.linger_ms = Some(20);
        config.max_retries = Some(4);
        config.initial_backoff_ms = Some(1);
        config.max_backoff_ms = Some(2);
        config.timeout_ms = Some(15_000);
        assert_eq!(config.timeout(), Duration::from_millis(15_000));
        let transport = Arc::new(
            SdkBigQueryTransport::new(&config, reqwest::Client::new()).expect("sink transport"),
        );
        let sink = BigQuerySink::new(config, transport).expect("sink");
        assert_eq!(sink.kind(), "bigquery");
        let topic = Topic::new("sensors/qual").expect("topic");
        for seq in 0..1000 {
            let payload = Bytes::from(format!(
                r#"{{"device_id":"dev-{seq:04}","temp":{temp},"seq":{seq}}}"#,
                temp = 20.0 + f64::from(seq) * 0.01
            ));
            sink.send(&topic, &payload, QoS::AtLeastOnce)
                .await
                .expect("send");
        }
        sink.flush().await.expect("flush");
        assert_eq!(sink.sent_records(), 1000);
        let total: usize = fake
            .captured_bodies()
            .iter()
            .map(|body| body["rows"].as_array().map_or(0, |rows| rows.len()))
            .sum();
        assert_eq!(total, 1000);
        let bodies = fake.captured_bodies();
        let first = bodies.first().expect("first batch");
        assert_eq!(
            first["rows"][0]["json"]["device_id"]
                .as_str()
                .expect("device"),
            "dev-0000"
        );

        // Partial-failure retry requeues only failed rows through the
        // same sink path.
        let partial_fake = Arc::new(FakeBigQuery::with_script(vec![
            (
                200,
                serde_json::json!({
                    "insertErrors": [{"index": 1, "errors": [{"reason": "rateLimitExceeded"}]}]
                }),
            ),
            (200, serde_json::json!({})),
        ]));
        let partial_endpoint = serve_fake_bigquery(partial_fake.clone()).await;
        let mut partial_config = sdk_config_with_endpoint(&partial_endpoint);
        partial_config.batch_size = Some(10);
        partial_config.initial_backoff_ms = Some(1);
        partial_config.max_backoff_ms = Some(2);
        let partial_transport = Arc::new(
            SdkBigQueryTransport::new(&partial_config, reqwest::Client::new())
                .expect("partial transport"),
        );
        let partial_sink = BigQuerySink::new(partial_config, partial_transport).expect("sink");
        let retry_topic = Topic::new("t").expect("topic");
        for temp in [20.5, 21.5] {
            partial_sink
                .send(
                    &retry_topic,
                    &Bytes::from(format!("{{\"temp\":{temp}}}")),
                    QoS::AtMostOnce,
                )
                .await
                .expect("send");
        }
        partial_sink.flush().await.expect("retry flush");
        assert_eq!(partial_fake.call_count(), 2);
        let retry_bodies = partial_fake.captured_bodies();
        let second = retry_bodies.get(1).expect("retry body");
        assert_eq!(second["rows"].as_array().expect("rows").len(), 1);
        assert_eq!(second["rows"][0]["json"]["temp"], serde_json::json!(21.5));
    }

    #[tokio::test]
    async fn test_sdk_throttle_and_timeout_wire_config() {
        // HTTP 429 from the fake maps to a retryable connection error.
        let throttle_fake = Arc::new(FakeBigQuery::with_script(vec![(
            429,
            serde_json::json!({
                "error": {
                    "code": 429,
                    "message": "throttled",
                    "errors": [],
                    "status": "RESOURCE_EXHAUSTED"
                }
            }),
        )]));
        let throttle_endpoint = serve_fake_bigquery(throttle_fake).await;
        let throttle_config = sdk_config_with_endpoint(&throttle_endpoint);
        let throttle_transport =
            SdkBigQueryTransport::new(&throttle_config, reqwest::Client::new()).expect("transport");
        let err = throttle_transport
            .insert_all(
                "my-iot-project",
                "telemetry",
                "t",
                vec![BigQueryRowEntry {
                    insert_id: "dddddddd-dddd-dddd-dddd-dddddddddddd".to_string(),
                    json: serde_json::json!({"temp": 1.0}),
                }],
                "",
            )
            .await
            .expect_err("429 must retry");
        assert!(matches!(err, ConnectorError::Connection(_)));

        // A slow fake plus a short `timeout_ms` surfaces as a timeout
        // connection error, proving `timeout()` is read.
        let slow_fake = Arc::new(FakeBigQuery::default());
        *slow_fake.delay_ms.lock() = 500;
        let slow_endpoint = serve_fake_bigquery(slow_fake).await;
        let mut slow_config = sdk_config_with_endpoint(&slow_endpoint);
        slow_config.timeout_ms = Some(50);
        assert_eq!(slow_config.timeout(), Duration::from_millis(50));
        let slow_transport =
            SdkBigQueryTransport::new(&slow_config, reqwest::Client::new()).expect("transport");
        assert_eq!(slow_transport.timeout(), Duration::from_millis(50));
        let slow_err = slow_transport
            .insert_all(
                "my-iot-project",
                "telemetry",
                "t",
                vec![BigQueryRowEntry {
                    insert_id: "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee".to_string(),
                    json: serde_json::json!({"temp": 2.0}),
                }],
                "",
            )
            .await
            .expect_err("slow fake must time out");
        assert!(matches!(slow_err, ConnectorError::Connection(_)));
    }

    #[tokio::test]
    async fn test_http_transport_insert_all_against_fake() {
        // The retained hand-written transport stays wired: it posts the
        // legacy body to `{base}/projects/.../insertAll` with the
        // configured timeout and the sink-config flags (no hardcoded
        // `ignoreUnknownValues` / `skipInvalidRows`).
        use axum::{extract::State, http::StatusCode, routing::post, Router};
        #[derive(Default)]
        struct CapturedHttp {
            path: parking_lot::Mutex<String>,
            body: parking_lot::Mutex<String>,
        }
        async fn handler(
            State(captured): State<Arc<CapturedHttp>>,
            uri: axum::http::Uri,
            body: String,
        ) -> (StatusCode, String) {
            *captured.path.lock() = uri.path().to_string();
            *captured.body.lock() = body;
            (StatusCode::OK, "{}".to_string())
        }
        let captured = Arc::new(CapturedHttp::default());
        let app = Router::new()
            .route("/*rest", post(handler))
            .with_state(captured.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        let mut config = test_config();
        config.endpoint = Some(format!("http://127.0.0.1:{port}"));
        config.timeout_ms = Some(5_000);
        let transport =
            HttpBigQueryTransport::new(&config, reqwest::Client::new()).expect("http transport");
        assert_eq!(transport.base(), config.base_url());
        let rows = vec![BigQueryRowEntry {
            insert_id: "ffffffff-ffff-ffff-ffff-ffffffffffff".to_string(),
            json: serde_json::json!({"device_id": "sensor-101"}),
        }];
        let response = transport
            .insert_all("my-iot-project", "telemetry", "sensor_logs", rows, "")
            .await
            .expect("http fake insert");
        assert!(response.failed_indices.is_empty());
        assert!(
            captured.path.lock().ends_with(
                "/projects/my-iot-project/datasets/telemetry/tables/sensor_logs/insertAll"
            ),
            "unexpected {}",
            captured.path.lock()
        );
        assert!(captured.body.lock().contains("sensor-101"));
        assert_eq!(transport.flags(), (true, false));
        assert!(captured
            .body
            .lock()
            .contains("\"ignoreUnknownValues\":true"));
        assert!(captured.body.lock().contains("\"skipInvalidRows\":false"));

        // Flipped flags also reach the wire (proves no hardcoded constants).
        let mut flipped_config = test_config();
        flipped_config.endpoint = Some(config.endpoint.clone().expect("endpoint"));
        flipped_config.ignore_unknown_values = false;
        flipped_config.skip_invalid_rows = true;
        let flipped =
            HttpBigQueryTransport::new(&flipped_config, reqwest::Client::new()).expect("flipped");
        assert_eq!(flipped.flags(), (false, true));
        let flipped_rows = vec![BigQueryRowEntry {
            insert_id: "00000000-0000-0000-0000-000000000000".to_string(),
            json: serde_json::json!({"device_id": "sensor-102"}),
        }];
        flipped
            .insert_all(
                "my-iot-project",
                "telemetry",
                "sensor_logs",
                flipped_rows,
                "",
            )
            .await
            .expect("flipped fake insert");
        assert!(captured
            .body
            .lock()
            .contains("\"ignoreUnknownValues\":false"));
        assert!(captured.body.lock().contains("\"skipInvalidRows\":true"));
    }

    fn qual_env(name: &str) -> Option<String> {
        std::env::var(name).ok().filter(|v| !v.trim().is_empty())
    }

    /// Qualification against a real BigQuery server via the maintained
    /// `gcp-bigquery-client` driver.
    ///
    /// Run with e.g.:
    /// `BIGQUERY_PROJECT=my-project BIGQUERY_DATASET=qual_b306
    ///  BIGQUERY_TABLE=qual_rows
    ///  GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa.json \
    ///  cargo test -p broker-connectors --lib bigquery::tests::test_qualify_driver_write_path -- --ignored --nocapture`
    ///
    /// Creates the dataset/table, streams 1000 rows through [`BigQuerySink`]
    /// on [`SdkBigQueryTransport`] (rule-shaped JSON), asserts row count and
    /// schema through the driver, then proves the mock partial-failure path
    /// requeues only failed rows. Cleans up the table it created and removes
    /// the dataset when it created it.
    #[tokio::test]
    #[ignore = "needs a real BigQuery server (see BIGQUERY_* env)"]
    async fn test_qualify_driver_write_path() {
        let project = qual_env("BIGQUERY_PROJECT").unwrap_or_default();
        if project.is_empty() {
            eprintln!("BIGQUERY_PROJECT is empty; skipping qualification");
            return;
        }
        let dataset_id = qual_env("BIGQUERY_DATASET").unwrap_or_else(|| "bq_qual_b306".to_string());
        let table_id = qual_env("BIGQUERY_TABLE").unwrap_or_else(|| "qual_rows".to_string());
        let sa_key_file = qual_env("GOOGLE_APPLICATION_CREDENTIALS")
            .or_else(|| qual_env("BIGQUERY_SA_KEY_FILE"))
            .unwrap_or_default();
        let endpoint = qual_env("BIGQUERY_ENDPOINT");
        if sa_key_file.is_empty() && endpoint.is_none() {
            eprintln!("no service-account key and no BIGQUERY_ENDPOINT; skipping qualification");
            return;
        }

        let driver_client: gcp_bigquery_client::Client = if sa_key_file.is_empty() {
            let auth: std::sync::Arc<dyn gcp_bigquery_client::auth::Authenticator> =
                std::sync::Arc::new(StaticTokenAuthenticator {
                    token: qual_env("BIGQUERY_TOKEN").unwrap_or_default(),
                });
            let mut builder = gcp_bigquery_client::client_builder::ClientBuilder::new();
            if let Some(endpoint) = endpoint.clone() {
                builder.with_v2_base_url(format!("{}/bigquery/v2", endpoint.trim_end_matches('/')));
            }
            builder
                .build_from_authenticator(auth)
                .await
                .expect("qual driver client")
        } else {
            eprintln!("qual server: sa_key_file set, project={project}");
            gcp_bigquery_client::Client::from_service_account_key_file(&sa_key_file)
                .await
                .expect("qual driver client from key file")
        };
        eprintln!("qual server: project={project} dataset={dataset_id} table={table_id}");

        // Ensure dataset (remember whether we created it for cleanup).
        let mut created_dataset = false;
        if driver_client
            .dataset()
            .get(&project, &dataset_id)
            .await
            .is_err()
        {
            driver_client
                .dataset()
                .create(gcp_bigquery_client::model::dataset::Dataset::new(
                    &project,
                    &dataset_id,
                ))
                .await
                .expect("qual create dataset");
            created_dataset = true;
        }
        driver_client
            .table()
            .delete_if_exists(&project, &dataset_id, &table_id)
            .await;
        let schema = gcp_bigquery_client::model::table_schema::TableSchema::new(vec![
            gcp_bigquery_client::model::table_field_schema::TableFieldSchema::new(
                "device_id",
                gcp_bigquery_client::model::field_type::FieldType::String,
            ),
            gcp_bigquery_client::model::table_field_schema::TableFieldSchema::new(
                "temp",
                gcp_bigquery_client::model::field_type::FieldType::Float,
            ),
            gcp_bigquery_client::model::table_field_schema::TableFieldSchema::new(
                "seq",
                gcp_bigquery_client::model::field_type::FieldType::Integer,
            ),
        ]);
        let table = gcp_bigquery_client::model::table::Table::from_dataset(
            &gcp_bigquery_client::model::dataset::Dataset::new(&project, &dataset_id),
            &table_id,
            schema,
        );
        driver_client
            .table()
            .create(table)
            .await
            .expect("qual create table");

        let config = BigQuerySinkConfig {
            project_id: project.clone(),
            dataset_id: dataset_id.clone(),
            table_template: table_id.clone(),
            endpoint: endpoint.clone(),
            auth: GcpAuth::None,
            ignore_unknown_values: true,
            skip_invalid_rows: false,
            template_suffix: None,
            batch_size: Some(100),
            batch_bytes: Some(1_048_576),
            linger_ms: Some(20),
            max_retries: Some(4),
            initial_backoff_ms: Some(1),
            max_backoff_ms: Some(2),
            timeout_ms: Some(15_000),
        };
        config.validate().expect("qual config validates");
        let transport = Arc::new(
            SdkBigQueryTransport::new(&config, reqwest::Client::new()).expect("qual transport"),
        );
        let sink = BigQuerySink::new(config, transport).expect("qual sink");
        assert_eq!(sink.kind(), "bigquery");
        let topic = Topic::new("sensors/qual").unwrap();
        for seq in 0..1000 {
            let payload = Bytes::from(format!(
                r#"{{"device_id":"dev-{seq:04}","temp":{temp},"seq":{seq}}}"#,
                temp = 20.0 + f64::from(seq) * 0.01
            ));
            sink.send(&topic, &payload, QoS::AtLeastOnce)
                .await
                .expect("qual send");
        }
        sink.flush().await.expect("qual flush");
        assert_eq!(sink.sent_records(), 1000);

        // Row count through the driver (paginated list).
        let mut counted = 0usize;
        let mut page_token: Option<String> = None;
        loop {
            let params = gcp_bigquery_client::tabledata::ListQueryParameters {
                start_index: None,
                max_results: Some(1000),
                page_token: page_token.clone(),
                selected_fields: None,
                format_options: None,
            };
            let page = driver_client
                .tabledata()
                .list(&project, &dataset_id, &table_id, params)
                .await
                .expect("qual list rows");
            counted += page.rows.unwrap_or_default().len();
            let next = page.page_token.unwrap_or_default();
            if next.is_empty() {
                break;
            }
            page_token = Some(next);
        }
        assert_eq!(counted, 1000);

        // Schema through the driver.
        let fetched = driver_client
            .table()
            .get(&project, &dataset_id, &table_id, None)
            .await
            .expect("qual get table");
        let names: Vec<String> = fetched
            .schema
            .fields
            .unwrap_or_default()
            .iter()
            .map(|field| field.name.clone())
            .collect();
        for expected in ["device_id", "temp", "seq"] {
            assert!(
                names.contains(&expected.to_string()),
                "schema has {expected}"
            );
        }

        // Partial-failure retry still requeues only failed rows (mock path).
        let mut mock_config = test_config();
        mock_config.batch_size = Some(10);
        mock_config.initial_backoff_ms = Some(1);
        mock_config.max_backoff_ms = Some(2);
        let (mock_sink, mock_transport) = test_sink(mock_config);
        mock_transport.script_outcomes(vec![
            MockBigQueryOutcome::PartialFailed(vec![1]),
            MockBigQueryOutcome::Accepted,
        ]);
        let mock_topic = Topic::new("t").unwrap();
        for temp in [20.5, 21.5] {
            mock_sink
                .send(
                    &mock_topic,
                    &Bytes::from(format!("{{\"temp\":{temp}}}")),
                    QoS::AtMostOnce,
                )
                .await
                .unwrap();
        }
        mock_sink.flush().await.unwrap();
        assert_eq!(mock_transport.calls(), 2);
        assert_eq!(mock_transport.captured()[1].rows.len(), 1);

        // Cleanup the rows we inserted.
        driver_client
            .table()
            .delete(&project, &dataset_id, &table_id)
            .await
            .expect("qual cleanup table");
        if created_dataset {
            driver_client
                .dataset()
                .delete(&project, &dataset_id, true)
                .await
                .expect("qual cleanup dataset");
        }
    }
}
