//! Databricks lakehouse sink (INDRA-183).
//!
//! Buffers MQTT events as typed statement parameters and executes
//! `INSERT INTO {catalog}.{schema}.{table} (...) VALUES (?, ?, ?)`
//! through the SQL Statements API (`POST
//! https://{host}/api/2.0/sql/statements`) with Bearer auth.
//! Parameters type by JSON shape (`STRING`, `DOUBLE`, `BIGINT`,
//! `BOOLEAN`); non-scalar values ride JSON text as `STRING`.
//!
//! Statement states drive the retry loop: `SUCCEEDED` completes,
//! `PENDING`/`RUNNING` poll `GET .../statements/{id}` to `SUCCEEDED`
//! (bounded; past the bound the batch re-executes at-least-once, like
//! the sibling batch sinks), `FAILED`/`CANCELED`/`CLOSED` are
//! terminal, and 429/503 plus transport failures retry in-loop.
//! Authentication failures (401/403) are terminal: the sink fails
//! closed and never retries with the same Bearer. The Bearer itself
//! is rotatable at runtime (`DatabricksSink::set_token`) so a renewed
//! token takes effect on the next statement without rebuilding.

use async_trait::async_trait;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::{now_millis, render_template, BackoffState, BatchQueue, ConnectorError, Result, Sink};

fn default_catalog() -> String {
    "main".to_string()
}

fn default_schema() -> String {
    "default".to_string()
}

fn default_batch_size() -> Option<usize> {
    Some(200)
}

fn default_batch_bytes() -> Option<usize> {
    Some(2_097_152)
}

fn default_linger_ms() -> Option<u64> {
    Some(10)
}

fn default_max_retries() -> Option<usize> {
    Some(3)
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

/// Databricks sink configuration. All depths are optional (`None` =
/// unbounded) with zero clamped ceilings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabricksSinkConfig {
    /// Workspace host, e.g. `dbc-a1b2c3d4-e5f6.cloud.databricks.com`.
    pub host: String,
    /// Personal Access Token or OAuth Bearer token.
    pub token: String,
    /// Unity Catalog name (default `main`).
    #[serde(default = "default_catalog")]
    pub catalog: String,
    /// Schema name (default `default`).
    #[serde(default = "default_schema")]
    pub schema: String,
    /// Table template (`${topic}`, `${client_id}`, ...).
    pub table_template: String,
    /// SQL warehouse HTTP path (warehouse id = last segment).
    #[serde(default)]
    pub http_path: Option<String>,
    /// Partition template for partitioned tables.
    #[serde(default)]
    pub partition_key_template: Option<String>,
    /// Column → payload-field template (sorted at render).
    #[serde(default)]
    pub column_mappings: HashMap<String, String>,
    /// Records per batch (default 200).
    #[serde(default = "default_batch_size")]
    pub batch_size: Option<usize>,
    /// Batch byte limit (default 2 MiB).
    #[serde(default = "default_batch_bytes")]
    pub batch_bytes: Option<usize>,
    /// Linger flush window in ms (default 10).
    #[serde(default = "default_linger_ms")]
    pub linger_ms: Option<u64>,
    /// Retries on throttles/pending (default 3, `None` unbounded).
    #[serde(default = "default_max_retries")]
    pub max_retries: Option<usize>,
    /// First retry delay in ms (default 100).
    #[serde(default = "default_initial_backoff_ms")]
    pub initial_backoff_ms: Option<u64>,
    /// Retry delay ceiling in ms (default 2000).
    #[serde(default = "default_max_backoff_ms")]
    pub max_backoff_ms: Option<u64>,
    /// Request timeout in ms (default 5000).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

impl DatabricksSinkConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.unwrap_or(5000).max(1))
    }

    pub fn validate(&self) -> Result<()> {
        let bare = self
            .host
            .trim_start_matches("http://")
            .trim_start_matches("https://");
        if bare.trim().is_empty() || bare.contains('/') || bare.contains(' ') {
            return Err(ConnectorError::Dispatch(format!(
                "databricks host must be a bare hostname: {:?}",
                self.host
            )));
        }
        if self.token.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "databricks token must not be empty".to_string(),
            ));
        }
        for (label, value) in [("catalog", &self.catalog), ("schema", &self.schema)] {
            if !is_identifier(value) {
                return Err(ConnectorError::Dispatch(format!(
                    "databricks {label} must match [A-Za-z0-9_]+: {value:?}"
                )));
            }
        }
        if self.table_template.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "databricks table_template must not be empty".to_string(),
            ));
        }
        // Strict template checks with dummy values.
        self.resolve_table("dummy/topic", b"{}", QoS::AtMostOnce, 0)?;
        if let Some(path) = &self.http_path {
            if !path.contains("/warehouses/") {
                return Err(ConnectorError::Dispatch(format!(
                    "databricks http_path must contain /warehouses/: {path:?}"
                )));
            }
            if warehouse_id(path).is_none() {
                return Err(ConnectorError::Dispatch(format!(
                    "databricks http_path has an empty warehouse id: {path:?}"
                )));
            }
        }
        if let Some(template) = &self.partition_key_template {
            self.event_vars("dummy", b"{}", QoS::AtMostOnce, 0, template)?;
        }
        for (column, template) in &self.column_mappings {
            if !is_identifier(column) {
                return Err(ConnectorError::Dispatch(format!(
                    "databricks column must match [A-Za-z0-9_]+: {column:?}"
                )));
            }
            self.event_vars("dummy", b"{}", QoS::AtMostOnce, 0, template)?;
        }
        if self.batch_size == Some(0) {
            return Err(ConnectorError::Dispatch(
                "databricks batch_size must be >= 1".to_string(),
            ));
        }
        if self.batch_bytes == Some(0) {
            return Err(ConnectorError::Dispatch(
                "databricks batch_bytes must be >= 1".to_string(),
            ));
        }
        Ok(())
    }

    /// `POST {scheme}://{host}/api/2.0/sql/statements`.
    pub fn statements_url(&self) -> String {
        if self.host.starts_with("http://") || self.host.starts_with("https://") {
            format!("{}/api/2.0/sql/statements", self.host.trim_end_matches('/'))
        } else {
            format!(
                "https://{}/api/2.0/sql/statements",
                self.host.trim_end_matches('/')
            )
        }
    }

    /// Warehouse id from the HTTP path tail (None when unconfigured).
    pub fn warehouse_id(&self) -> Option<String> {
        self.http_path.as_ref().and_then(|path| warehouse_id(path))
    }

    /// Fully qualified `{catalog}.{schema}.{table}` destination.
    pub fn qualified_table(&self, table: &str) -> String {
        format!("{}.{}.{}", self.catalog, self.schema, table)
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

    /// Resolve + validate the table name.
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
                "databricks table must match [A-Za-z0-9_]+: {table:?}"
            )));
        }
        Ok(table)
    }
}

/// Warehouse id = last `/`-separated segment of the HTTP path.
fn warehouse_id(http_path: &str) -> Option<String> {
    http_path
        .rsplit('/')
        .next()
        .filter(|segment| !segment.is_empty())
        .map(str::to_string)
}

// ---------------------------------------------------------------------------
// Wire framing.
// ---------------------------------------------------------------------------

/// One typed statement parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabricksParam {
    pub name: String,
    pub value: String,
    pub param_type: String,
}

/// Render the SQL statements request body.
pub fn render_statement_body(
    warehouse_id: Option<&str>,
    catalog: &str,
    schema: &str,
    statement: &str,
    params: &[DatabricksParam],
) -> Vec<u8> {
    let mut body = String::from("{");
    if let Some(warehouse) = warehouse_id {
        body.push_str("\"warehouse_id\":");
        body.push_str(&serde_json::to_string(warehouse).unwrap_or_default());
        body.push(',');
    }
    body.push_str("\"catalog\":");
    body.push_str(&serde_json::to_string(catalog).unwrap_or_default());
    body.push_str(",\"schema\":");
    body.push_str(&serde_json::to_string(schema).unwrap_or_default());
    body.push_str(",\"statement\":");
    body.push_str(&serde_json::to_string(statement).unwrap_or_default());
    body.push_str(",\"parameters\":[");
    for (index, param) in params.iter().enumerate() {
        if index > 0 {
            body.push(',');
        }
        body.push_str("{\"name\":");
        body.push_str(&serde_json::to_string(&param.name).unwrap_or_default());
        body.push_str(",\"value\":");
        body.push_str(&serde_json::to_string(&param.value).unwrap_or_default());
        body.push_str(",\"type\":");
        body.push_str(&serde_json::to_string(&param.param_type).unwrap_or_default());
        body.push('}');
    }
    body.push_str("]}");
    body.into_bytes()
}

/// Statement lifecycle states from the API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementState {
    Succeeded,
    Pending,
    Running,
    Failed,
    Canceled,
    Closed,
}

/// Parse the `status.state` of a statement response body.
pub fn parse_statement_state(body: &[u8]) -> Result<StatementState> {
    let doc: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| ConnectorError::Connection(format!("databricks bad response JSON: {e}")))?;
    let state = doc
        .get("status")
        .and_then(|status| status.get("state"))
        .and_then(|state| state.as_str())
        .unwrap_or("");
    match state {
        "SUCCEEDED" => Ok(StatementState::Succeeded),
        "PENDING" => Ok(StatementState::Pending),
        "RUNNING" => Ok(StatementState::Running),
        "FAILED" => Ok(StatementState::Failed),
        "CANCELED" => Ok(StatementState::Canceled),
        "CLOSED" => Ok(StatementState::Closed),
        _ => Err(ConnectorError::Connection(format!(
            "databricks response lacks a state: {}",
            String::from_utf8_lossy(body)
        ))),
    }
}

/// Parse the `statement_id` of a statement response body (`None`
/// for synchronous replies that carry no id; some workspaces omit it
/// on immediate `SUCCEEDED`).
/// TODO(parity): the documented API does not say whether a
/// synchronous reply always carries `statement_id`; absent ids are
/// decided from `status.state` alone.
pub fn parse_statement_id(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()?
        .get("statement_id")
        .and_then(|id| id.as_str())
        .map(str::to_string)
}

/// Parse `(statement_id, state)` of a statement response body.
pub fn parse_statement_response(body: &[u8]) -> Result<(Option<String>, StatementState)> {
    let state = parse_statement_state(body)?;
    Ok((parse_statement_id(body), state))
}

/// Status poll URL for one statement: `{statements-url}/{statement-id}`.
pub fn statement_status_url(statements_url: &str, statement_id: &str) -> String {
    format!("{}/{}", statements_url.trim_end_matches('/'), statement_id)
}

/// Extract `result.data_array` rows (each cell rendered as text) from
/// a `SUCCEEDED` statement response. Used to assert row counts
/// (`SELECT COUNT(*)`) without a second client.
pub fn parse_result_rows(body: &[u8]) -> Result<Vec<Vec<String>>> {
    let doc: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| ConnectorError::Connection(format!("databricks bad response JSON: {e}")))?;
    let mut rows = Vec::new();
    let data = doc
        .get("result")
        .and_then(|result| result.get("data_array"))
        .and_then(|array| array.as_array());
    if let Some(data) = data {
        for row in data {
            let mut cells = Vec::new();
            if let Some(columns) = row.as_array() {
                for cell in columns {
                    cells.push(
                        cell.as_str()
                            .map(str::to_string)
                            .unwrap_or_else(|| cell.to_string()),
                    );
                }
            }
            rows.push(cells);
        }
    }
    Ok(rows)
}

// ---------------------------------------------------------------------------
// Transport.
// ---------------------------------------------------------------------------

/// Scripted outcome for the mock transport.
#[derive(Debug, Clone)]
pub enum MockDatabricksOutcome {
    Succeeded,
    Pending,
    Failed {
        message: String,
    },
    /// Transport failure (retries in-loop).
    ConnectionError(String),
    /// HTTP failure (429/503 retry the batch).
    HttpStatus(u16),
}

/// One captured statement execution.
#[derive(Debug, Clone)]
pub struct CapturedDatabricksStatement {
    pub statement: String,
    pub params: Vec<DatabricksParam>,
    pub token: String,
}

#[async_trait]
pub trait DatabricksTransport: Send + Sync {
    async fn execute_statement(
        &self,
        statement: &str,
        params: Vec<DatabricksParam>,
        token: &str,
    ) -> Result<()>;
}

/// In-memory transport with scripted outcomes (tests, dry runs).
#[derive(Debug, Default)]
pub struct MockDatabricksTransport {
    scripted: parking_lot::Mutex<std::collections::VecDeque<MockDatabricksOutcome>>,
    captured: parking_lot::Mutex<Vec<CapturedDatabricksStatement>>,
    calls: AtomicU64,
}

impl MockDatabricksTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue outcomes consumed in order (default: success).
    pub fn script_outcomes(&self, outcomes: Vec<MockDatabricksOutcome>) {
        *self.scripted.lock() = outcomes.into_iter().collect();
    }

    pub fn captured(&self) -> Vec<CapturedDatabricksStatement> {
        self.captured.lock().clone()
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl DatabricksTransport for MockDatabricksTransport {
    async fn execute_statement(
        &self,
        statement: &str,
        params: Vec<DatabricksParam>,
        token: &str,
    ) -> Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.captured.lock().push(CapturedDatabricksStatement {
            statement: statement.to_string(),
            params,
            token: token.to_string(),
        });
        match self.scripted.lock().pop_front() {
            None | Some(MockDatabricksOutcome::Succeeded) => Ok(()),
            // Queued warehouses re-execute with backoff (at-least-once).
            Some(MockDatabricksOutcome::Pending) => Err(ConnectorError::Connection(
                "mock databricks statement pending".to_string(),
            )),
            Some(MockDatabricksOutcome::Failed { message }) => {
                Err(ConnectorError::Dispatch(message))
            }
            Some(MockDatabricksOutcome::ConnectionError(message)) => {
                Err(ConnectorError::Connection(message))
            }
            Some(MockDatabricksOutcome::HttpStatus(status)) => Err(match status {
                429 | 503 => {
                    ConnectorError::Connection(format!("mock databricks throttled with {status}"))
                }
                _ => ConnectorError::Dispatch(format!("mock databricks failed with {status}")),
            }),
        }
    }
}

/// Polls per statement execution (default 30): 30 x 500 ms is a
/// 15 s upper bound per statement so one slow warehouse cannot stall
/// a flush forever; past the bound the sink retry loop re-executes
/// the statement (at-least-once, like the sibling batch sinks).
const DEFAULT_MAX_POLLS: usize = 30;
/// Delay between status polls (default 500 ms): warehouses start in
/// seconds, so faster polling only burns Statements API quota.
const DEFAULT_POLL_INTERVAL_MS: u64 = 500;

/// Production transport: `POST {statements-url}` with the statement
/// body, then `GET {statements-url}/{statement_id}` polling to
/// `SUCCEEDED`. 429/503 and transport failures surface as retryable
/// connections; 401/403 are terminal (fail closed, never retried with
/// the same Bearer); other non-2xx and failed states are terminal.
pub struct HttpDatabricksTransport {
    url: String,
    catalog: String,
    schema: String,
    warehouse_id: Option<String>,
    client: reqwest::Client,
    timeout: Duration,
    poll_interval: Duration,
    max_polls: usize,
}

impl HttpDatabricksTransport {
    pub fn new(config: &DatabricksSinkConfig, client: reqwest::Client) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            url: config.statements_url(),
            catalog: config.catalog.clone(),
            schema: config.schema.clone(),
            warehouse_id: config.warehouse_id(),
            timeout: config.timeout(),
            poll_interval: Duration::from_millis(DEFAULT_POLL_INTERVAL_MS),
            max_polls: DEFAULT_MAX_POLLS,
            client,
        })
    }

    /// Constructor with explicit polling bounds (qualification and
    /// tests; cold warehouses take minutes, loopback fakes none).
    pub fn with_polling(
        config: &DatabricksSinkConfig,
        client: reqwest::Client,
        poll_interval: Duration,
        max_polls: usize,
    ) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            url: config.statements_url(),
            catalog: config.catalog.clone(),
            schema: config.schema.clone(),
            warehouse_id: config.warehouse_id(),
            timeout: config.timeout(),
            poll_interval,
            max_polls: max_polls.max(1),
            client,
        })
    }

    fn bearer(token: &str) -> String {
        format!("Bearer {token}")
    }

    /// Terminal-vs-retryable mapping for Statements API statuses.
    fn classify_status(status: u16) -> Result<()> {
        if status == 429 || status == 503 {
            return Err(ConnectorError::Connection(format!(
                "databricks throttled with {status}"
            )));
        }
        if status == 401 || status == 403 {
            return Err(ConnectorError::Dispatch(format!(
                "databricks unauthorized with {status}: failing closed, rotate the Bearer"
            )));
        }
        if !(200..=299).contains(&status) {
            return Err(ConnectorError::Dispatch(format!(
                "databricks request failed with {status}"
            )));
        }
        Ok(())
    }

    async fn post_statement(
        &self,
        statement: &str,
        params: &[DatabricksParam],
        token: &str,
    ) -> Result<Vec<u8>> {
        let response = self
            .client
            .post(&self.url)
            .header(reqwest::header::AUTHORIZATION, Self::bearer(token))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .timeout(self.timeout)
            .body(render_statement_body(
                self.warehouse_id.as_deref(),
                &self.catalog,
                &self.schema,
                statement,
                params,
            ))
            .send()
            .await
            .map_err(|e| ConnectorError::Connection(format!("databricks request failed: {e}")))?;
        let status = response.status().as_u16();
        Self::classify_status(status)?;
        response
            .bytes()
            .await
            .map_err(|e| ConnectorError::Connection(format!("databricks read failed: {e}")))
            .map(|bytes| bytes.to_vec())
    }

    async fn get_statement(&self, statement_id: &str, token: &str) -> Result<Vec<u8>> {
        let response = self
            .client
            .get(statement_status_url(&self.url, statement_id))
            .header(reqwest::header::AUTHORIZATION, Self::bearer(token))
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| ConnectorError::Connection(format!("databricks poll failed: {e}")))?;
        let status = response.status().as_u16();
        Self::classify_status(status)?;
        response
            .bytes()
            .await
            .map_err(|e| ConnectorError::Connection(format!("databricks poll read failed: {e}")))
            .map(|bytes| bytes.to_vec())
    }

    /// Poll one statement to a terminal state. `SUCCEEDED` returns the
    /// final response body (carries `result.data_array` for reads);
    /// exhaustion returns a retryable error so the sink re-executes.
    async fn poll_to_terminal(&self, statement_id: &str, token: &str) -> Result<Vec<u8>> {
        for _ in 0..self.max_polls {
            tokio::time::sleep(self.poll_interval).await;
            let body = self.get_statement(statement_id, token).await?;
            let (_, state) = parse_statement_response(&body)?;
            match state {
                StatementState::Succeeded => return Ok(body),
                StatementState::Failed | StatementState::Canceled | StatementState::Closed => {
                    return Err(ConnectorError::Dispatch(
                        "databricks statement failed".to_string(),
                    ));
                }
                StatementState::Pending | StatementState::Running => {}
            }
        }
        Err(ConnectorError::Connection(format!(
            "databricks statement {statement_id} still pending after {} polls",
            self.max_polls
        )))
    }

    /// Execute one statement through POST + polling, returning the
    /// final `data_array` rows (empty for writes).
    pub async fn execute_fetch(
        &self,
        statement: &str,
        params: Vec<DatabricksParam>,
        token: &str,
    ) -> Result<Vec<Vec<String>>> {
        let body = self.post_statement(statement, &params, token).await?;
        let (statement_id, state) = parse_statement_response(&body)?;
        let final_body = match state {
            StatementState::Succeeded => body,
            StatementState::Failed | StatementState::Canceled | StatementState::Closed => {
                return Err(ConnectorError::Dispatch(
                    "databricks statement failed".to_string(),
                ));
            }
            StatementState::Pending | StatementState::Running => match statement_id {
                Some(id) => self.poll_to_terminal(&id, token).await?,
                None => {
                    return Err(ConnectorError::Connection(
                        "databricks statement pending without an id".to_string(),
                    ));
                }
            },
        };
        parse_result_rows(&final_body)
    }
}

#[async_trait]
impl DatabricksTransport for HttpDatabricksTransport {
    async fn execute_statement(
        &self,
        statement: &str,
        params: Vec<DatabricksParam>,
        token: &str,
    ) -> Result<()> {
        self.execute_fetch(statement, params, token)
            .await
            .map(|_| ())
    }
}

// ---------------------------------------------------------------------------
// Sink.
// ---------------------------------------------------------------------------

/// One buffered row: table, columns, typed params.
#[derive(Debug, Clone)]
struct DatabricksRow {
    table: String,
    columns: Vec<String>,
    params: Vec<DatabricksParam>,
}

struct DatabricksBuffer {
    queue: BatchQueue<DatabricksRow>,
    bytes: usize,
}

/// Databricks sink: buffers rows, executes one INSERT per row batch.
pub struct DatabricksSink {
    config: DatabricksSinkConfig,
    transport: Arc<dyn DatabricksTransport>,
    /// Effective Bearer token: the configured value until
    /// [`DatabricksSink::set_token`] rotates it, so a renewed token
    /// takes effect on the next statement without rebuilding the sink.
    /// One lock acquisition per `flush` (batch-level, never per message).
    token: parking_lot::RwLock<String>,
    buffer: parking_lot::Mutex<DatabricksBuffer>,
    backoff: parking_lot::Mutex<BackoffState>,
    sent_batches: AtomicU64,
    sent_records: AtomicU64,
}

impl DatabricksSink {
    pub fn new(
        config: DatabricksSinkConfig,
        transport: Arc<dyn DatabricksTransport>,
    ) -> Result<Self> {
        config.validate()?;
        let linger = config.effective_linger();
        Ok(Self {
            token: parking_lot::RwLock::new(config.token.clone()),
            buffer: parking_lot::Mutex::new(DatabricksBuffer {
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

    pub fn config(&self) -> &DatabricksSinkConfig {
        &self.config
    }

    /// Current Bearer token (the configured value until rotated).
    pub fn current_token(&self) -> String {
        self.token.read().clone()
    }

    /// Rotate the Bearer token; subsequent statements carry it.
    pub fn set_token(&self, token: impl Into<String>) {
        *self.token.write() = token.into();
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

    /// Type one JSON value for statement parameters.
    fn typed_param(name: &str, value: &serde_json::Value) -> DatabricksParam {
        let (param_value, param_type) = match value {
            serde_json::Value::String(text) => (text.clone(), "STRING"),
            serde_json::Value::Number(n) => {
                if n.is_i64() || n.is_u64() {
                    (n.to_string(), "BIGINT")
                } else {
                    (n.to_string(), "DOUBLE")
                }
            }
            serde_json::Value::Bool(v) => (v.to_string(), "BOOLEAN"),
            serde_json::Value::Null => ("NULL".to_string(), "STRING"),
            other => (other.to_string(), "STRING"),
        };
        DatabricksParam {
            name: name.to_string(),
            value: param_value,
            param_type: param_type.to_string(),
        }
    }

    /// Build one row: qualified table, INSERT statement, typed params.
    /// Columns come from mappings (sorted) or the whole document.
    fn build_row(
        &self,
        topic: &Topic,
        payload: &Bytes,
        qos: QoS,
        millis: i64,
    ) -> Result<(DatabricksRow, usize)> {
        let text = std::str::from_utf8(payload).map_err(|_| {
            ConnectorError::Dispatch("databricks payload must be UTF-8".to_string())
        })?;
        let value: serde_json::Value = serde_json::from_str(text)
            .map_err(|_| ConnectorError::Dispatch("databricks payload must be JSON".to_string()))?;
        let table = self
            .config
            .resolve_table(topic.as_str(), payload, qos, millis)?;
        let mut columns: Vec<String> = Vec::new();
        let mut values: Vec<serde_json::Value> = Vec::new();
        if self.config.column_mappings.is_empty() {
            match &value {
                serde_json::Value::Object(map) => {
                    let mut keys: Vec<&String> = map.keys().collect();
                    keys.sort();
                    for key in keys {
                        columns.push(key.clone());
                        values.push(map[key].clone());
                    }
                }
                other => {
                    columns.push("value".to_string());
                    values.push(other.clone());
                }
            }
        } else {
            let mut names: Vec<&String> = self.config.column_mappings.keys().collect();
            names.sort();
            for name in names {
                let template = &self.config.column_mappings[name];
                let rendered =
                    self.config
                        .event_vars(topic.as_str(), payload, qos, millis, template)?;
                let field = serde_json::from_str::<serde_json::Value>(&rendered)
                    .ok()
                    .filter(|v| !v.is_string())
                    .unwrap_or(serde_json::Value::String(rendered));
                columns.push(name.clone());
                values.push(field);
            }
        }
        // Partitioned tables carry the rendered partition value as an
        // explicit `_PARTITION` STRING column (fail loudly when empty).
        if let Some(template) = &self.config.partition_key_template {
            let partition =
                self.config
                    .event_vars(topic.as_str(), payload, qos, millis, template)?;
            if partition.trim().is_empty() {
                return Err(ConnectorError::Dispatch(
                    "databricks partition rendered empty".to_string(),
                ));
            }
            columns.push("_PARTITION".to_string());
            values.push(serde_json::Value::String(partition));
        }
        let placeholders = (1..=columns.len())
            .map(|_| "?".to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let statement = format!(
            "INSERT INTO {} ({}) VALUES ({})",
            self.config.qualified_table(&table),
            columns.join(", "),
            placeholders,
        );
        let mut params = Vec::with_capacity(values.len());
        for (index, field) in values.iter().enumerate() {
            params.push(Self::typed_param(&(index + 1).to_string(), field));
        }
        let bytes: usize = statement.len() + params.iter().map(|p| p.value.len()).sum::<usize>();
        Ok((
            DatabricksRow {
                table,
                columns,
                params,
            },
            bytes,
        ))
    }

    /// Merge one group (same table + columns) into a single
    /// multi-tuple INSERT with sequentially renumbered parameters.
    fn merge_group(
        table: &str,
        columns: &[String],
        rows: &[DatabricksRow],
        config: &DatabricksSinkConfig,
    ) -> (String, Vec<DatabricksParam>) {
        let mut tuples = Vec::with_capacity(rows.len());
        let mut params = Vec::new();
        for row in rows {
            let placeholders = vec!["?"; row.params.len()].join(", ");
            tuples.push(format!("({placeholders})"));
            for param in &row.params {
                params.push(DatabricksParam {
                    name: (params.len() + 1).to_string(),
                    value: param.value.clone(),
                    param_type: param.param_type.clone(),
                });
            }
        }
        let statement = format!(
            "INSERT INTO {} ({}) VALUES {}",
            config.qualified_table(table),
            columns.join(", "),
            tuples.join(", "),
        );
        (statement, params)
    }

    /// Flush buffered rows (no-op when empty): rows sharing a table
    /// and column shape merge into one multi-tuple INSERT per group.
    /// Pending/throttled outcomes retry in place; terminal failures
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
        // Group by (table, columns); each group becomes one statement.
        let mut groups: Vec<(String, Vec<String>, Vec<DatabricksRow>)> = Vec::new();
        for row in &rows {
            match groups
                .iter_mut()
                .find(|(table, columns, _)| table == &row.table && *columns == row.columns)
            {
                Some((_, _, grouped)) => grouped.push(row.clone()),
                None => groups.push((row.table.clone(), row.columns.clone(), vec![row.clone()])),
            }
        }
        let record_count = rows.len() as u64;
        let max_retries = self.config.max_retries.unwrap_or(usize::MAX);
        let token = self.current_token();
        let mut attempt = 0usize;
        loop {
            let mut outcome: Result<()> = Ok(());
            for (table, columns, grouped) in &groups {
                let (statement, params) = Self::merge_group(table, columns, grouped, &self.config);
                if let Err(e) = self
                    .transport
                    .execute_statement(&statement, params, &token)
                    .await
                {
                    outcome = Err(e);
                    break;
                }
            }
            match outcome {
                Ok(()) => {
                    self.backoff.lock().success();
                    self.sent_batches.fetch_add(1, Ordering::Relaxed);
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
        rows: Vec<DatabricksRow>,
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
                "databricks row requires a non-empty topic".to_string(),
            ));
        }
        let millis = now_millis();
        let (row, bytes) = self.build_row(topic, payload, qos, millis)?;
        let mut buffer = self.buffer.lock();
        let full = buffer.queue.push(row);
        buffer.bytes = buffer.bytes.saturating_add(bytes);
        Ok(full || buffer.bytes >= self.config.effective_batch_bytes())
    }
}

#[async_trait]
impl Sink for DatabricksSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        if self.buffer_row(topic, payload, qos)? {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "databricks"
    }
}

/// Management connector handle pairing an id with a Databricks sink.
pub struct DatabricksConnector {
    id: String,
    sink: Arc<DatabricksSink>,
}

impl DatabricksConnector {
    pub fn new(id: impl Into<String>, sink: Arc<DatabricksSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }
}

impl super::Connector for DatabricksConnector {
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
    use axum::{
        extract::{Path, State},
        http::{HeaderMap, StatusCode},
        routing::{get, post},
        Router,
    };
    use std::sync::Mutex as StdMutex;

    fn test_config() -> DatabricksSinkConfig {
        DatabricksSinkConfig {
            host: "dbc-a1b2c3d4-e5f6.cloud.databricks.com".to_string(),
            token: "dapi-test-token".to_string(),
            catalog: "main".to_string(),
            schema: "default".to_string(),
            table_template: "sensor_readings".to_string(),
            http_path: Some("/sql/1.0/warehouses/a1b2c3d4e5f6".to_string()),
            partition_key_template: None,
            column_mappings: HashMap::from([
                ("device_id".to_string(), "${client_id}".to_string()),
                (
                    "temperature".to_string(),
                    "${payload.temperature}".to_string(),
                ),
            ]),
            batch_size: Some(200),
            batch_bytes: Some(2_097_152),
            linger_ms: Some(10),
            max_retries: Some(3),
            initial_backoff_ms: Some(100),
            max_backoff_ms: Some(2_000),
            timeout_ms: None,
        }
    }

    fn test_sink(
        config: DatabricksSinkConfig,
    ) -> (Arc<DatabricksSink>, Arc<MockDatabricksTransport>) {
        let transport = Arc::new(MockDatabricksTransport::new());
        let sink = Arc::new(DatabricksSink::new(config, transport.clone()).unwrap());
        (sink, transport)
    }

    #[test]
    fn test_config_validation() {
        let mut config = test_config();
        assert!(config.validate().is_ok());
        assert_eq!(
            config.statements_url(),
            "https://dbc-a1b2c3d4-e5f6.cloud.databricks.com/api/2.0/sql/statements"
        );
        assert_eq!(config.warehouse_id().as_deref(), Some("a1b2c3d4e5f6"));
        assert_eq!(
            config.qualified_table("sensor_readings"),
            "main.default.sensor_readings"
        );

        config.host = "https://host/path".to_string();
        assert!(config.validate().is_err());
        config.host = test_config().host;

        config.token.clear();
        assert!(config.validate().is_err());
        config.token = test_config().token;

        config.catalog = "has space".to_string();
        assert!(config.validate().is_err());
        config.catalog = "main".to_string();

        config.table_template = "has space".to_string();
        assert!(config.validate().is_err());
        config.table_template = test_config().table_template;

        config.http_path = Some("/sql/1.0/clusters/x".to_string());
        assert!(config.validate().is_err());
        config.http_path = None;
        assert!(config.validate().is_ok());
        assert_eq!(config.warehouse_id(), None);
        config.http_path = test_config().http_path;

        config.batch_size = Some(0);
        assert!(config.validate().is_err());
        // Unbounded + huge depths accepted: zero clamped ceilings.
        config.batch_size = None;
        config.batch_bytes = Some(10_000_000);
        config.max_retries = None;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_statement_rendering_and_typing() {
        let body = render_statement_body(
            Some("a1b2c3d4e5f6"),
            "main",
            "default",
            "INSERT INTO main.default.sensor_readings (device_id, temperature, timestamp) VALUES (?, ?, ?)",
            &[
                DatabricksParam { name: "1".to_string(), value: "dev-42".to_string(), param_type: "STRING".to_string() },
                DatabricksParam { name: "2".to_string(), value: "98.6".to_string(), param_type: "DOUBLE".to_string() },
                DatabricksParam { name: "3".to_string(), value: "1726160000000".to_string(), param_type: "BIGINT".to_string() },
            ],
        );
        assert_eq!(
            String::from_utf8(body).unwrap(),
            r#"{"warehouse_id":"a1b2c3d4e5f6","catalog":"main","schema":"default","statement":"INSERT INTO main.default.sensor_readings (device_id, temperature, timestamp) VALUES (?, ?, ?)","parameters":[{"name":"1","value":"dev-42","type":"STRING"},{"name":"2","value":"98.6","type":"DOUBLE"},{"name":"3","value":"1726160000000","type":"BIGINT"}]}"#
        );

        // Typing follows JSON shape.
        assert_eq!(
            DatabricksSink::typed_param("1", &serde_json::json!("x")).param_type,
            "STRING"
        );
        assert_eq!(
            DatabricksSink::typed_param("1", &serde_json::json!(98.6)).param_type,
            "DOUBLE"
        );
        assert_eq!(
            DatabricksSink::typed_param("1", &serde_json::json!(7)).param_type,
            "BIGINT"
        );
        assert_eq!(
            DatabricksSink::typed_param("1", &serde_json::json!(true)).param_type,
            "BOOLEAN"
        );
        assert_eq!(
            DatabricksSink::typed_param("1", &serde_json::json!({"a": 1})).param_type,
            "STRING"
        );
    }

    #[test]
    fn test_state_parsing() {
        assert_eq!(
            parse_statement_state(br#"{"status":{"state":"SUCCEEDED"}}"#).unwrap(),
            StatementState::Succeeded
        );
        assert_eq!(
            parse_statement_state(br#"{"status":{"state":"PENDING"}}"#).unwrap(),
            StatementState::Pending
        );
        assert_eq!(
            parse_statement_state(br#"{"status":{"state":"RUNNING"}}"#).unwrap(),
            StatementState::Running
        );
        assert_eq!(
            parse_statement_state(br#"{"status":{"state":"FAILED"}}"#).unwrap(),
            StatementState::Failed
        );
        assert!(parse_statement_state(br#"{"status":{}}"#).is_err());
        assert!(parse_statement_state(b"nope").is_err());
    }

    #[tokio::test]
    async fn test_insert_flow_and_bearer() {
        let (sink, transport) = test_sink(test_config());
        sink.send(
            &Topic::new("sensors/t1").unwrap(),
            &Bytes::from_static(br#"{"client_id":"dev-42","temperature":98.6}"#),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        sink.flush().await.unwrap();

        let captured = transport.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(
            captured[0].statement,
            "INSERT INTO main.default.sensor_readings (device_id, temperature) VALUES (?, ?)"
        );
        assert_eq!(
            captured[0].params,
            vec![
                DatabricksParam {
                    name: "1".to_string(),
                    value: "dev-42".to_string(),
                    param_type: "STRING".to_string()
                },
                DatabricksParam {
                    name: "2".to_string(),
                    value: "98.6".to_string(),
                    param_type: "DOUBLE".to_string()
                },
            ]
        );
        assert_eq!(captured[0].token, "dapi-test-token");
        assert_eq!(sink.sent_records(), 1);
    }

    #[tokio::test]
    async fn test_partition_column_appended() {
        let mut config = test_config();
        config.partition_key_template = Some("edge-${client_id}".to_string());
        config.batch_size = Some(10);
        let (sink, transport) = test_sink(config);
        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from_static(br#"{"client_id":"d7"}"#),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        sink.flush().await.unwrap();
        let captured = transport.captured();
        assert!(captured[0].statement.contains("_PARTITION"));
        let last = captured[0].params.last().expect("partition param");
        assert_eq!(
            (
                last.name.as_str(),
                last.value.as_str(),
                last.param_type.as_str()
            ),
            ("3", "edge-d7", "STRING")
        );
    }

    #[tokio::test]
    async fn test_multi_row_merge_single_statement() {
        let mut config = test_config();
        config.batch_size = Some(10);
        let (sink, transport) = test_sink(config);
        let topic = Topic::new("t").unwrap();
        for temp in [20.5, 21.5] {
            sink.send(
                &topic,
                &Bytes::from(format!("{{\"client_id\":\"d\",\"temperature\":{temp}}}")),
                QoS::AtMostOnce,
            )
            .await
            .unwrap();
        }
        sink.flush().await.unwrap();
        // One statement call with two tuples and renumbered params.
        assert_eq!(transport.calls(), 1);
        let captured = transport.captured();
        assert_eq!(
            captured[0].statement,
            "INSERT INTO main.default.sensor_readings (device_id, temperature) VALUES (?, ?), (?, ?)"
        );
        assert_eq!(
            captured[0]
                .params
                .iter()
                .map(|p| p.name.clone())
                .collect::<Vec<_>>(),
            vec!["1", "2", "3", "4"]
        );
        assert_eq!(
            captured[0]
                .params
                .iter()
                .map(|p| p.value.clone())
                .collect::<Vec<_>>(),
            vec!["d", "20.5", "d", "21.5"]
        );
        assert_eq!(sink.sent_records(), 2);
    }

    #[tokio::test]
    async fn test_pending_retries_then_succeeds() {
        let mut config = test_config();
        config.batch_size = Some(10);
        config.initial_backoff_ms = Some(1);
        config.max_backoff_ms = Some(2);
        let (sink, transport) = test_sink(config);
        transport.script_outcomes(vec![
            MockDatabricksOutcome::Pending,
            MockDatabricksOutcome::Succeeded,
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
        assert_eq!(sink.sent_records(), 1);
        assert_eq!(sink.buffered_rows(), 0);
    }

    #[tokio::test]
    async fn test_failed_state_is_terminal() {
        let mut config = test_config();
        config.batch_size = Some(10);
        config.max_retries = Some(5);
        let (sink, transport) = test_sink(config);
        transport.script_outcomes(vec![
            MockDatabricksOutcome::Failed {
                message: "syntax error".to_string(),
            },
            MockDatabricksOutcome::Succeeded,
        ]);

        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from("{}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        let err = sink.flush().await.expect_err("failed must abort");
        assert!(matches!(err, ConnectorError::Dispatch(_)));
        assert_eq!(transport.calls(), 1);
        assert_eq!(sink.buffered_rows(), 1);
    }

    #[test]
    fn test_statement_response_and_result_parsing() {
        let (id, state) = parse_statement_response(
            br#"{"statement_id":"stmt-9","status":{"state":"SUCCEEDED"}}"#,
        )
        .unwrap();
        assert_eq!(id.as_deref(), Some("stmt-9"));
        assert_eq!(state, StatementState::Succeeded);

        // Synchronous replies without an id decide from the state alone.
        let (id, state) = parse_statement_response(br#"{"status":{"state":"PENDING"}}"#).unwrap();
        assert_eq!(id, None);
        assert_eq!(state, StatementState::Pending);

        assert!(parse_statement_response(br#"{"status":{}}"#).is_err());
        assert!(parse_statement_response(b"nope").is_err());

        assert_eq!(
            statement_status_url("https://host/api/2.0/sql/statements", "stmt-9"),
            "https://host/api/2.0/sql/statements/stmt-9"
        );
        assert_eq!(
            statement_status_url("https://host/api/2.0/sql/statements/", "stmt-9"),
            "https://host/api/2.0/sql/statements/stmt-9"
        );

        let rows = parse_result_rows(
            br#"{"status":{"state":"SUCCEEDED"},"result":{"data_array":[[500],["x"]]}}"#,
        )
        .unwrap();
        assert_eq!(rows, vec![vec!["500".to_string()], vec!["x".to_string()]]);
        assert!(parse_result_rows(br#"{"status":{"state":"SUCCEEDED"}}"#)
            .unwrap()
            .is_empty());
    }

    /// Scripted Statements API fake: records Bearers + statements,
    /// answers the first POST with PENDING (forcing GET polls) when
    /// told to, rejects any other Bearer with 401.
    struct FakeStatements {
        good_bearer: String,
        async_first_post: StdMutex<bool>,
        bearers: StdMutex<Vec<String>>,
        statements: StdMutex<Vec<String>>,
        gets: AtomicU64,
    }

    fn bearer_of(headers: &HeaderMap) -> String {
        headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    }

    async fn fake_post(
        State(state): State<Arc<FakeStatements>>,
        headers: HeaderMap,
        body: Bytes,
    ) -> (StatusCode, String) {
        let bearer = bearer_of(&headers);
        state.bearers.lock().unwrap().push(bearer.clone());
        if bearer != state.good_bearer {
            return (
                StatusCode::UNAUTHORIZED,
                r#"{"error_code":"UNAUTHENTICATED","message":"bad token"}"#.to_string(),
            );
        }
        state
            .statements
            .lock()
            .unwrap()
            .push(String::from_utf8_lossy(&body).to_string());
        if *state.async_first_post.lock().unwrap() {
            *state.async_first_post.lock().unwrap() = false;
            (
                StatusCode::OK,
                r#"{"statement_id":"stmt-1","status":{"state":"PENDING"}}"#.to_string(),
            )
        } else {
            (
                StatusCode::OK,
                r#"{"statement_id":"stmt-2","status":{"state":"SUCCEEDED"}}"#.to_string(),
            )
        }
    }

    async fn fake_get(
        State(state): State<Arc<FakeStatements>>,
        Path(id): Path<String>,
        headers: HeaderMap,
    ) -> (StatusCode, String) {
        let bearer = bearer_of(&headers);
        state.bearers.lock().unwrap().push(bearer.clone());
        if bearer != state.good_bearer {
            return (
                StatusCode::UNAUTHORIZED,
                r#"{"error_code":"UNAUTHENTICATED","message":"bad token"}"#.to_string(),
            );
        }
        assert_eq!(id, "stmt-1");
        if state.gets.fetch_add(1, Ordering::SeqCst) == 0 {
            (
                StatusCode::OK,
                r#"{"statement_id":"stmt-1","status":{"state":"RUNNING"}}"#.to_string(),
            )
        } else {
            (
                StatusCode::OK,
                r#"{"statement_id":"stmt-1","status":{"state":"SUCCEEDED"},"result":{"data_array":[]}}"#
                    .to_string(),
            )
        }
    }

    async fn serve_fake(state: Arc<FakeStatements>) -> (String, tokio::task::JoinHandle<()>) {
        let app = Router::new()
            .route("/api/2.0/sql/statements", post(fake_post))
            .route("/api/2.0/sql/statements/:id", get(fake_get))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        (format!("http://127.0.0.1:{port}"), server)
    }

    fn fake_config(host: &str, token: &str) -> DatabricksSinkConfig {
        DatabricksSinkConfig {
            host: host.to_string(),
            token: token.to_string(),
            catalog: "main".to_string(),
            schema: "default".to_string(),
            table_template: "events".to_string(),
            http_path: Some("/sql/1.0/warehouses/abc123".to_string()),
            partition_key_template: None,
            column_mappings: HashMap::new(),
            batch_size: Some(10),
            batch_bytes: Some(2_097_152),
            linger_ms: Some(10),
            max_retries: Some(3),
            initial_backoff_ms: Some(1),
            max_backoff_ms: Some(2),
            timeout_ms: Some(5_000),
        }
    }

    #[tokio::test]
    async fn test_http_polling_reaches_succeeded_through_manager() {
        // Broker path (publish, deliver): ConnectorManager::send ->
        // Sink::send -> flush -> HttpDatabricksTransport POST + GET
        // polls to SUCCEEDED against the loopback Statements API.
        use crate::ConnectorManager;
        let fake = Arc::new(FakeStatements {
            good_bearer: "Bearer tok-1".to_string(),
            async_first_post: StdMutex::new(true),
            bearers: StdMutex::new(Vec::new()),
            statements: StdMutex::new(Vec::new()),
            gets: AtomicU64::new(0),
        });
        let (host, server) = serve_fake(fake.clone()).await;
        let config = fake_config(&host, "tok-1");
        let transport = Arc::new(
            HttpDatabricksTransport::with_polling(
                &config,
                reqwest::Client::new(),
                Duration::from_millis(5),
                10,
            )
            .expect("fake transport"),
        );
        let sink = Arc::new(DatabricksSink::new(config, transport).expect("fake sink"));
        assert_eq!(sink.kind(), "databricks");
        let manager = ConnectorManager::new();
        manager.register("db-poll", sink.clone());
        manager
            .send(
                "db-poll",
                &Topic::new("sensors/q1").unwrap(),
                &Bytes::from_static(br#"{"client_id":"d7","temperature":2.5}"#),
                QoS::AtLeastOnce,
            )
            .await
            .expect("broker send");
        sink.flush().await.expect("polling flush");

        assert_eq!(sink.sent_records(), 1);
        assert_eq!(sink.sent_batches(), 1);
        let statements = fake.statements.lock().unwrap();
        assert_eq!(statements.len(), 1);
        assert!(
            statements[0].contains("INSERT INTO main.default.events"),
            "unexpected statement: {}",
            statements[0]
        );
        assert!(
            fake.gets.load(Ordering::SeqCst) >= 1,
            "PENDING must poll to SUCCEEDED"
        );
        let bearers = fake.bearers.lock().unwrap();
        assert!(!bearers.is_empty());
        assert!(bearers.iter().all(|b| b == "Bearer tok-1"));
        server.abort();
    }

    #[tokio::test]
    async fn test_http_bearer_renewal_and_401_fail_closed() {
        use crate::ConnectorManager;
        let fake = Arc::new(FakeStatements {
            good_bearer: "Bearer tok-2".to_string(),
            async_first_post: StdMutex::new(false),
            bearers: StdMutex::new(Vec::new()),
            statements: StdMutex::new(Vec::new()),
            gets: AtomicU64::new(0),
        });
        let (host, server) = serve_fake(fake.clone()).await;
        let config = fake_config(&host, "tok-1");
        let transport = Arc::new(
            HttpDatabricksTransport::with_polling(
                &config,
                reqwest::Client::new(),
                Duration::from_millis(5),
                10,
            )
            .expect("fake transport"),
        );
        let sink = Arc::new(DatabricksSink::new(config, transport).expect("fake sink"));
        let manager = ConnectorManager::new();
        manager.register("db-renew", sink.clone());
        manager
            .send(
                "db-renew",
                &Topic::new("sensors/q2").unwrap(),
                &Bytes::from_static(br#"{"client_id":"d8"}"#),
                QoS::AtLeastOnce,
            )
            .await
            .expect("broker send");

        // Stale Bearer fails closed and terminal: no retry storm, rows kept.
        let err = sink.flush().await.expect_err("401 must fail");
        assert!(
            matches!(err, ConnectorError::Dispatch(_)),
            "401 must be terminal, got {err:?}"
        );
        assert_eq!(sink.buffered_rows(), 1);
        assert_eq!(sink.sent_records(), 0);

        // Renewed Bearer takes effect without rebuilding the sink.
        // The terminal failure above engaged the 2 s backoff, so wait
        // it out: the renewed flush must exercise the transport, not
        // the backoff gate.
        sink.set_token("tok-2");
        assert_eq!(sink.current_token(), "tok-2");
        tokio::time::sleep(Duration::from_millis(2_500)).await;
        sink.flush().await.expect("renewed flush");
        assert_eq!(sink.sent_records(), 1);
        assert_eq!(sink.buffered_rows(), 0);
        assert_eq!(
            fake.bearers.lock().unwrap().as_slice(),
            &["Bearer tok-1".to_string(), "Bearer tok-2".to_string()]
        );
        server.abort();
    }

    #[tokio::test]
    async fn test_http_unreachable_fails_closed_through_manager() {
        // Unreachable Statements API through the broker path: the
        // production transport must fail closed, never grant access.
        use crate::ConnectorManager;
        let mut config = fake_config("http://127.0.0.1:1", "tok-1");
        config.batch_size = Some(1);
        config.max_retries = Some(0);
        config.timeout_ms = Some(500);
        let transport =
            Arc::new(HttpDatabricksTransport::new(&config, reqwest::Client::new()).expect("sink"));
        let sink = Arc::new(DatabricksSink::new(config, transport).expect("sink"));
        let manager = ConnectorManager::new();
        manager.register("db-dead", sink);
        let err = manager
            .send(
                "db-dead",
                &Topic::new("sensors/q3").unwrap(),
                &Bytes::from_static(br#"{"client_id":"d9"}"#),
                QoS::AtLeastOnce,
            )
            .await
            .expect_err("unreachable must fail");
        assert!(
            matches!(err, ConnectorError::Connection(_)),
            "unreachable must be a connection failure, got {err:?}"
        );
        assert!(
            err.to_string().contains("databricks"),
            "driver error must be observable, got: {err}"
        );
    }

    fn qual_env(name: &str) -> Option<String> {
        std::env::var(name).ok().filter(|v| !v.trim().is_empty())
    }

    /// Qualification against a real workspace via the maintained
    /// `reqwest` Statements API transport.
    ///
    /// Run with e.g.:
    /// `DATABRICKS_HOST=dbc-xxx.cloud.databricks.com DATABRICKS_TOKEN=dapi... \
    ///  DATABRICKS_HTTP_PATH=/sql/1.0/warehouses/abc123 \
    ///  cargo test -p broker-connectors --lib databricks::tests::test_qualify_statements_write_path -- --ignored --nocapture`
    ///
    /// Creates a table, streams 500 inserts through the broker
    /// ([`crate::ConnectorManager`] -> [`DatabricksSink`] on
    /// [`HttpDatabricksTransport`], Bearer auth, `GET` polling to
    /// `SUCCEEDED`), asserts `COUNT(*)` is 500, proves a bad Bearer
    /// fails closed then recovers after [`DatabricksSink::set_token`]
    /// (renewed row lands in the same table), streams one more row
    /// and asserts 502, then drops the table.
    #[tokio::test]
    #[ignore = "needs a real workspace (see DATABRICKS_* env)"]
    async fn test_qualify_statements_write_path() {
        let host = qual_env("DATABRICKS_HOST").unwrap_or_else(|| {
            panic!(
                "DATABRICKS_HOST must point at a real workspace for qualification; \
                 failing closed instead of passing vacuously"
            )
        });
        let token = qual_env("DATABRICKS_TOKEN").unwrap_or_else(|| {
            panic!("DATABRICKS_TOKEN must be set for qualification; failing closed")
        });
        let http_path = qual_env("DATABRICKS_HTTP_PATH")
            .or_else(|| qual_env("DATABRICKS_WAREHOUSE_PATH"))
            .unwrap_or_else(|| {
                panic!(
                    "DATABRICKS_HTTP_PATH must name the warehouse (contains /warehouses/) \
                     for qualification; failing closed"
                )
            });
        let catalog = qual_env("DATABRICKS_CATALOG").unwrap_or_else(|| "main".to_string());
        let schema = qual_env("DATABRICKS_SCHEMA").unwrap_or_else(|| "default".to_string());
        let table =
            qual_env("DATABRICKS_TABLE").unwrap_or_else(|| format!("qual_b312_{}", now_millis()));
        // Cold warehouses take minutes: the per-statement poll bound is
        // wide here (default 120 x 1 s); the loopback default stays 15 s.
        let poll_interval = qual_env("DATABRICKS_POLL_INTERVAL_MS")
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_millis)
            .unwrap_or(Duration::from_secs(1));
        let max_polls = qual_env("DATABRICKS_MAX_POLLS")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(120);

        let config = DatabricksSinkConfig {
            host: host.clone(),
            token: token.clone(),
            catalog: catalog.clone(),
            schema: schema.clone(),
            table_template: table.clone(),
            http_path: Some(http_path.clone()),
            partition_key_template: None,
            column_mappings: HashMap::from([
                ("device_id".to_string(), "${client_id}".to_string()),
                (
                    "temperature".to_string(),
                    "${payload.temperature}".to_string(),
                ),
                ("seq".to_string(), "${payload.seq}".to_string()),
            ]),
            batch_size: Some(50),
            batch_bytes: Some(2_097_152),
            linger_ms: Some(20),
            max_retries: Some(5),
            initial_backoff_ms: Some(200),
            max_backoff_ms: Some(2_000),
            timeout_ms: Some(30_000),
        };
        config.validate().expect("qual config validates");
        let qualified = config.qualified_table(&table);
        let warehouse_id = config.warehouse_id().expect("qual warehouse id");

        // Warehouse identity for the report (best effort; the
        // Statements API itself reports no server version).
        let client = reqwest::Client::new();
        let info_url = format!("https://{host}/api/2.0/sql/warehouses/{warehouse_id}");
        match client
            .get(&info_url)
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
            .timeout(Duration::from_secs(30))
            .send()
            .await
        {
            Ok(response) => match response.bytes().await {
                Ok(body) => {
                    let info: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                    eprintln!(
                        "qual server: warehouse={} name={} state={} size={} table={qualified}",
                        warehouse_id,
                        info.get("name").and_then(|v| v.as_str()).unwrap_or("?"),
                        info.get("state").and_then(|v| v.as_str()).unwrap_or("?"),
                        info.get("cluster_size")
                            .and_then(|v| v.as_str())
                            .unwrap_or("?"),
                    );
                }
                Err(e) => eprintln!("qual warehouse info unreadable (tolerated): {e}"),
            },
            Err(e) => eprintln!("qual warehouse info unreachable (tolerated): {e}"),
        }

        let transport = Arc::new(
            HttpDatabricksTransport::with_polling(
                &config,
                client.clone(),
                poll_interval,
                max_polls,
            )
            .expect("qual transport"),
        );
        transport
            .execute_statement(
                &format!(
                    "CREATE TABLE IF NOT EXISTS {qualified} \
                     (device_id STRING, seq BIGINT, temperature DOUBLE)"
                ),
                Vec::new(),
                &token,
            )
            .await
            .expect("qual create table");

        let sink =
            Arc::new(DatabricksSink::new(config.clone(), transport.clone()).expect("qual sink"));
        assert_eq!(sink.kind(), "databricks");
        // The broker's path: rule actions deliver through the shared
        // connector manager, so the qualification sends through it.
        let manager = Arc::new(crate::ConnectorManager::new());
        manager.register("qual-db", sink.clone());

        let topic = Topic::new("sensors/qual").unwrap();
        for seq in 0..500 {
            let device = format!("qual-{seq:06}");
            // Two decimals always: integer-looking values would type
            // as BIGINT against the DOUBLE column.
            let payload = Bytes::from(format!(
                r#"{{"client_id":"{device}","temperature":{:.2},"seq":{seq}}}"#,
                20.0 + (seq as f64) * 0.01
            ));
            manager
                .send("qual-db", &topic, &payload, QoS::AtLeastOnce)
                .await
                .expect("qual send");
        }
        sink.flush().await.expect("qual flush");
        assert_eq!(sink.sent_records(), 500, "qual row count");
        eprintln!("qual rows sent: records=500 table={qualified}");

        // Row count asserted back from the server, not the counters.
        let rows = transport
            .execute_fetch(
                &format!("SELECT COUNT(*) AS n FROM {qualified}"),
                Vec::new(),
                &token,
            )
            .await
            .expect("qual count");
        assert_eq!(rows, vec![vec!["500".to_string()]], "qual count: {rows:?}");
        eprintln!("qual rows asserted: count=500 table={qualified}");

        // Bearer renewal end to end: a bad Bearer fails closed and
        // terminal (rows kept), the rotated Bearer recovers in place.
        let mut bad_config = config.clone();
        bad_config.token = "dapi-qual-bad".to_string();
        let bad_sink =
            Arc::new(DatabricksSink::new(bad_config, transport.clone()).expect("qual bad sink"));
        bad_sink
            .send(
                &topic,
                &Bytes::from_static(br#"{"client_id":"qual-renew","temperature":1.0,"seq":-1}"#),
                QoS::AtLeastOnce,
            )
            .await
            .expect("qual bad buffer");
        let err = bad_sink.flush().await.expect_err("bad Bearer must fail");
        assert!(
            matches!(err, ConnectorError::Dispatch(_)),
            "bad Bearer must be terminal, got {err:?}"
        );
        assert_eq!(bad_sink.buffered_rows(), 1);
        bad_sink.set_token(token.clone());
        // The terminal failure engaged the 2 s backoff; wait it out so
        // the renewed flush exercises the transport, not the gate.
        tokio::time::sleep(Duration::from_secs(3)).await;
        bad_sink.flush().await.expect("qual renewed flush");
        assert_eq!(bad_sink.sent_records(), 1);
        eprintln!("qual Bearer renewal asserted: 401 terminal then recovered");

        // One more row through the main sink. The renewed row above
        // landed in this same table, so the server count is 502 while
        // the main sink delivered 501 of them.
        sink.set_token(token.clone());
        manager
            .send(
                "qual-db",
                &topic,
                &Bytes::from_static(br#"{"client_id":"qual-000500","temperature":25.0,"seq":500}"#),
                QoS::AtLeastOnce,
            )
            .await
            .expect("qual send 501");
        sink.flush().await.expect("qual flush 501");
        assert_eq!(sink.sent_records(), 501);
        let rows = transport
            .execute_fetch(
                &format!("SELECT COUNT(*) AS n FROM {qualified}"),
                Vec::new(),
                &token,
            )
            .await
            .expect("qual recount");
        assert_eq!(
            rows,
            vec![vec!["502".to_string()]],
            "qual recount: {rows:?}"
        );
        eprintln!("qual rows asserted: count=502 table={qualified}");

        // Cleanup: drop the table created for this run (best effort;
        // a failure is logged, not hidden).
        match transport
            .execute_statement(
                &format!("DROP TABLE IF EXISTS {qualified}"),
                Vec::new(),
                &token,
            )
            .await
        {
            Ok(()) => eprintln!("qual cleanup: dropped table {qualified}"),
            Err(e) => eprintln!("qual cleanup FAILED to drop {qualified} (tolerated): {e}"),
        }
        eprintln!("qual done: rows=502 table={qualified} cleaned table");
    }
}
