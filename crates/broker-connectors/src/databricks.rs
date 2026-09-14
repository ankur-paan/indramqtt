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
//! `PENDING`/`RUNNING` re-execute with backoff (at-least-once, like
//! the sibling batch sinks), `FAILED`/`CANCELED`/`CLOSED` are
//! terminal, and 429/503 plus transport failures retry in-loop.

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
            format!("https://{}/api/2.0/sql/statements", self.host.trim_end_matches('/'))
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

/// Production transport: `POST {statements-url}` with the statement
/// body; PENDING/RUNNING states surface as retryable connections.
pub struct HttpDatabricksTransport {
    url: String,
    catalog: String,
    schema: String,
    warehouse_id: Option<String>,
    client: reqwest::Client,
}

impl HttpDatabricksTransport {
    pub fn new(config: &DatabricksSinkConfig, client: reqwest::Client) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            url: config.statements_url(),
            catalog: config.catalog.clone(),
            schema: config.schema.clone(),
            warehouse_id: config.warehouse_id(),
            client,
        })
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
        let response = self
            .client
            .post(&self.url)
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(render_statement_body(
                self.warehouse_id.as_deref(),
                &self.catalog,
                &self.schema,
                statement,
                &params,
            ))
            .send()
            .await
            .map_err(|e| ConnectorError::Connection(format!("databricks request failed: {e}")))?;
        let status = response.status().as_u16();
        if status == 429 || status == 503 {
            return Err(ConnectorError::Connection(format!(
                "databricks throttled with {status}"
            )));
        }
        if !(200..=299).contains(&status) {
            return Err(ConnectorError::Dispatch(format!(
                "databricks request failed with {status}"
            )));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|e| ConnectorError::Connection(format!("databricks read failed: {e}")))?;
        match parse_statement_state(&bytes)? {
            StatementState::Succeeded => Ok(()),
            StatementState::Pending | StatementState::Running => Err(ConnectorError::Connection(
                "databricks statement pending".to_string(),
            )),
            StatementState::Failed | StatementState::Canceled | StatementState::Closed => Err(
                ConnectorError::Dispatch("databricks statement failed".to_string()),
            ),
        }
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
        let mut attempt = 0usize;
        loop {
            let mut outcome: Result<()> = Ok(());
            for (table, columns, grouped) in &groups {
                let (statement, params) = Self::merge_group(table, columns, grouped, &self.config);
                if let Err(e) = self
                    .transport
                    .execute_statement(&statement, params, &self.config.token)
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
}
