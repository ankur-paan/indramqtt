//! TDengine time-series sink (INDRA-173).
//!
//! Buffers MQTT events as super-table rows and writes them with the
//! REST SQL API (`POST /rest/sql/{database}`): one multi-table
//! `INSERT INTO <sub> USING <stable> TAGS (...) VALUES (...)` statement
//! per flush. Sub-table names, tags and metric values render from
//! strict templates over the event (unknown variables fail loudly);
//! identifiers are validated to `[A-Za-z0-9_]` so no template can
//! inject SQL.
//!
//! A `{"code": 0}` response is success; transport failures and HTTP
//! 429/5xx retry with jittered backoff; other outcomes are terminal
//! dispatch failures (syntax/table mismatches must not loop).

use async_trait::async_trait;
use base64::Engine;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::{now_millis, render_template, BackoffState, BatchQueue, ConnectorError, Result, Sink};

/// TDengine authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", tag = "type")]
pub enum TdengineAuth {
    /// HTTP Basic (`Authorization: Basic base64(user:pass)`).
    Basic { username: String, password: String },
    /// Token (`Authorization: Taosd <token>`).
    Token { token: String },
}

impl Default for TdengineAuth {
    fn default() -> Self {
        Self::Basic {
            username: "root".to_string(),
            password: "taosdata".to_string(),
        }
    }
}

impl TdengineAuth {
    /// The `Authorization` header value.
    pub fn header_value(&self) -> Result<String> {
        match self {
            Self::Basic { username, password } => {
                if username.is_empty() {
                    return Err(ConnectorError::Dispatch(
                        "tdengine basic auth needs a username".to_string(),
                    ));
                }
                let credentials = base64::engine::general_purpose::STANDARD
                    .encode(format!("{username}:{password}"));
                Ok(format!("Basic {credentials}"))
            }
            Self::Token { token } => {
                if token.trim().is_empty() {
                    return Err(ConnectorError::Dispatch(
                        "tdengine token must not be empty".to_string(),
                    ));
                }
                Ok(format!("Taosd {token}"))
            }
        }
    }
}

fn default_batch_size() -> Option<usize> {
    Some(500)
}

fn default_batch_bytes() -> Option<usize> {
    Some(4_194_304)
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
    Some(3_000)
}

fn is_td_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// TDengine sink configuration. All depths are optional (`None` =
/// unbounded) with zero clamped ceilings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TdengineSinkConfig {
    /// REST endpoint, e.g. `http://localhost:6041/rest/sql`.
    pub endpoint: String,
    /// Target database, e.g. `power`.
    pub database: String,
    /// Super-table name, e.g. `meters`.
    pub stable_name: String,
    /// Sub-table template, e.g. `d_${client_id}`.
    pub subtable_template: String,
    /// Authentication (default root/taosdata).
    #[serde(default)]
    pub auth: TdengineAuth,
    /// Tag column → value template (sorted by column at render).
    #[serde(default)]
    pub tags_template: HashMap<String, String>,
    /// Metric column → payload-field template (sorted by column).
    #[serde(default)]
    pub metrics_template: HashMap<String, String>,
    /// Rows per INSERT (default 500).
    #[serde(default = "default_batch_size")]
    pub batch_size: Option<usize>,
    /// Batch byte limit over SQL text (default 4 MiB).
    #[serde(default = "default_batch_bytes")]
    pub batch_bytes: Option<usize>,
    /// Linger flush window in ms (default 20).
    #[serde(default = "default_linger_ms")]
    pub linger_ms: Option<u64>,
    /// Retries on transient failures (default 4, `None` unbounded).
    #[serde(default = "default_max_retries")]
    pub max_retries: Option<usize>,
    /// First retry delay in ms (default 100).
    #[serde(default = "default_initial_backoff_ms")]
    pub initial_backoff_ms: Option<u64>,
    /// Retry delay ceiling in ms (default 3000).
    #[serde(default = "default_max_backoff_ms")]
    pub max_backoff_ms: Option<u64>,
    /// Request / network timeout in ms (default 5000).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

impl TdengineSinkConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.unwrap_or(5000).max(1))
    }

    pub fn validate(&self) -> Result<()> {
        if !self.endpoint.starts_with("http://") && !self.endpoint.starts_with("https://") {
            return Err(ConnectorError::Dispatch(format!(
                "tdengine endpoint must be http(s): {:?}",
                self.endpoint
            )));
        }
        if !is_td_identifier(&self.database) {
            return Err(ConnectorError::Dispatch(format!(
                "tdengine database must match [A-Za-z0-9_]+: {:?}",
                self.database
            )));
        }
        if !is_td_identifier(&self.stable_name) {
            return Err(ConnectorError::Dispatch(format!(
                "tdengine stable_name must match [A-Za-z0-9_]+: {:?}",
                self.stable_name
            )));
        }
        if self.subtable_template.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "tdengine subtable_template must not be empty".to_string(),
            ));
        }
        // Strict template checks with dummy values.
        self.resolve_subtable("dummy", b"{}", QoS::AtMostOnce, 0)?;
        for (column, template) in self
            .tags_template
            .iter()
            .chain(self.metrics_template.iter())
        {
            if !is_td_identifier(column) {
                return Err(ConnectorError::Dispatch(format!(
                    "tdengine column must match [A-Za-z0-9_]+: {column:?}"
                )));
            }
            self.event_vars("dummy", b"{}", QoS::AtMostOnce, 0, template)?;
        }
        self.auth.header_value().map(|_| ())?;
        if self.batch_size == Some(0) {
            return Err(ConnectorError::Dispatch(
                "tdengine batch_size must be >= 1".to_string(),
            ));
        }
        if self.batch_bytes == Some(0) {
            return Err(ConnectorError::Dispatch(
                "tdengine batch_bytes must be >= 1".to_string(),
            ));
        }
        Ok(())
    }

    /// `POST {endpoint}/{database}` (trailing slashes trimmed).
    pub fn insert_url(&self) -> String {
        format!("{}/{}", self.endpoint.trim_end_matches('/'), self.database)
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

    /// Template variables for one event (`${client_id}` from the JSON
    /// field when present, `${payload.<field>}` extraction on top).
    fn event_vars(
        &self,
        topic: &str,
        payload: &[u8],
        qos: QoS,
        millis: i64,
        template: &str,
    ) -> Result<String> {
        let doc: serde_json::Value = serde_json::from_slice(payload).unwrap_or_default();
        let field = |name: &str| {
            let val = doc.get(name)
                .or_else(|| doc.get("payload").and_then(|p| p.get(name)));
            match val {
                Some(serde_json::Value::String(text)) => text.clone(),
                Some(scalar) if scalar.is_number() || scalar.is_boolean() => scalar.to_string(),
                _ => String::new(),
            }
        };
        let client_id_val = doc.get("client_id")
            .or_else(|| doc.get("clientid"))
            .or_else(|| doc.get("device_id"))
            .or_else(|| doc.get("payload").and_then(|p| p.get("client_id").or_else(|| p.get("clientid")).or_else(|| p.get("device_id"))));
        let client_id = match client_id_val {
            Some(serde_json::Value::String(text)) => text.clone(),
            Some(scalar) if scalar.is_number() || scalar.is_boolean() => scalar.to_string(),
            _ => String::new(),
        };
        let mut vars = vec![
            ("topic".to_string(), topic.to_string()),
            ("client_id".to_string(), client_id),
            ("qos".to_string(), u8::from(qos).to_string()),
            ("timestamp".to_string(), millis.to_string()),
        ];
        let mut rest = template;
        while let Some(start) = rest.find("${payload.") {
            let after = &rest[start + "${payload.".len()..];
            if let Some(close) = after.find('}') {
                let name = &after[..close];
                vars.push((format!("payload.{name}"), field(name)));
                rest = &after[close + 1..];
            } else {
                break;
            }
        }
        let borrowed: Vec<(&str, String)> =
            vars.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
        render_template(template, &borrowed)
    }

    /// Resolve + validate the sub-table for one event.
    pub fn resolve_subtable(
        &self,
        topic: &str,
        payload: &[u8],
        qos: QoS,
        millis: i64,
    ) -> Result<String> {
        let vars = Self::base_vars(topic, payload, qos, millis);
        let borrowed: Vec<(&str, String)> =
            vars.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
        let name = render_template(&self.subtable_template, &borrowed)?;
        if !is_td_identifier(&name) {
            return Err(ConnectorError::Dispatch(format!(
                "tdengine sub-table resolved invalid (want [A-Za-z0-9_]+): {name:?}"
            )));
        }
        Ok(name)
    }

    fn base_vars(topic: &str, payload: &[u8], qos: QoS, millis: i64) -> Vec<(String, String)> {
        let doc: serde_json::Value = serde_json::from_slice(payload).unwrap_or_default();
        let client_id_val = doc.get("client_id")
            .or_else(|| doc.get("clientid"))
            .or_else(|| doc.get("device_id"))
            .or_else(|| doc.get("payload").and_then(|p| p.get("client_id").or_else(|| p.get("clientid")).or_else(|| p.get("device_id"))));
        let client_id = match client_id_val {
            Some(serde_json::Value::String(text)) => text.clone(),
            Some(scalar) if scalar.is_number() || scalar.is_boolean() => scalar.to_string(),
            _ => String::new(),
        };
        vec![
            ("topic".to_string(), topic.to_string()),
            ("client_id".to_string(), client_id),
            ("qos".to_string(), u8::from(qos).to_string()),
            ("timestamp".to_string(), millis.to_string()),
        ]
    }
}

/// Render a SQL literal: numbers and booleans ride raw, strings are
/// single-quoted with `''` escaping, null renders NULL.
fn sql_literal(rendered: &str) -> String {
    if rendered == "NULL" {
        return "NULL".to_string();
    }
    if rendered.parse::<f64>().is_ok() && !rendered.trim().is_empty() {
        return rendered.to_string();
    }
    if rendered == "true" || rendered == "false" {
        return rendered.to_uppercase();
    }
    format!("'{}'", rendered.replace('\'', "''"))
}

// ---------------------------------------------------------------------------
// Wire framing.
// ---------------------------------------------------------------------------

/// One super-table row: sub-table, tag literals, metric literals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdengineRow {
    pub subtable: String,
    pub tags: Vec<String>,
    pub metrics: Vec<String>,
    pub timestamp_ms: i64,
}

/// Render one multi-table `INSERT INTO ... USING ...` statement.
/// Tag/metric literals arrive pre-sorted by column for determinism.
pub fn render_insert(stable: &str, rows: &[TdengineRow]) -> String {
    let mut sql = String::from("INSERT INTO ");
    for (index, row) in rows.iter().enumerate() {
        if index > 0 {
            sql.push(' ');
        }
        sql.push_str(&row.subtable);
        sql.push_str(" USING ");
        sql.push_str(stable);
        sql.push_str(" TAGS (");
        sql.push_str(&row.tags.join(", "));
        sql.push_str(") VALUES (");
        sql.push_str(&row.timestamp_ms.to_string());
        for metric in &row.metrics {
            sql.push_str(", ");
            sql.push_str(metric);
        }
        sql.push(')');
    }
    sql.push(';');
    sql
}

/// Parsed `{"code": n, "rows": m}` REST response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TdengineResponse {
    pub code: i64,
    pub rows: u64,
}

pub fn parse_rest_response(body: &[u8]) -> Result<TdengineResponse> {
    let doc: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| ConnectorError::Connection(format!("tdengine bad response JSON: {e}")))?;
    let code = doc
        .get("code")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| ConnectorError::Connection("tdengine response lacks code".to_string()))?;
    let rows = doc.get("rows").and_then(|v| v.as_u64()).unwrap_or(0);
    Ok(TdengineResponse { code, rows })
}

// ---------------------------------------------------------------------------
// Transport.
// ---------------------------------------------------------------------------

/// Scripted outcome for the mock transport.
#[derive(Debug, Clone)]
pub enum MockTdengineOutcome {
    /// `{"code": 0}` with this many affected rows.
    Ok(u64),
    /// Transport failure (retries in-loop).
    ConnectionError(String),
    /// Non-zero TDengine code (terminal, no retry).
    SqlError { code: i64 },
}

/// One captured SQL execution.
#[derive(Debug, Clone)]
pub struct CapturedTdengineSql {
    pub database: String,
    pub sql: String,
    pub auth: String,
}

#[async_trait]
pub trait TdengineTransport: Send + Sync {
    async fn execute_sql(&self, database: &str, sql: &str, auth: &TdengineAuth) -> Result<usize>;
}

/// In-memory transport with scripted outcomes (tests, dry runs).
#[derive(Debug, Default)]
pub struct MockTdengineTransport {
    scripted: parking_lot::Mutex<std::collections::VecDeque<MockTdengineOutcome>>,
    captured: parking_lot::Mutex<Vec<CapturedTdengineSql>>,
    calls: AtomicU64,
}

impl MockTdengineTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue outcomes consumed in order (default: success, 1 row).
    pub fn script_outcomes(&self, outcomes: Vec<MockTdengineOutcome>) {
        *self.scripted.lock() = outcomes.into_iter().collect();
    }

    pub fn captured(&self) -> Vec<CapturedTdengineSql> {
        self.captured.lock().clone()
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl TdengineTransport for MockTdengineTransport {
    async fn execute_sql(&self, database: &str, sql: &str, auth: &TdengineAuth) -> Result<usize> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.captured.lock().push(CapturedTdengineSql {
            database: database.to_string(),
            sql: sql.to_string(),
            auth: auth.header_value().unwrap_or_default(),
        });
        match self.scripted.lock().pop_front() {
            None => Ok(1),
            Some(MockTdengineOutcome::Ok(rows)) => Ok(rows as usize),
            Some(MockTdengineOutcome::ConnectionError(message)) => {
                Err(ConnectorError::Connection(message))
            }
            Some(MockTdengineOutcome::SqlError { code }) => Err(ConnectorError::Dispatch(format!(
                "mock tdengine SQL failed with code {code}"
            ))),
        }
    }
}

/// Production transport: `POST {insert-url}` with the SQL text.
pub struct HttpTdengineTransport {
    url: String,
    client: reqwest::Client,
}

impl HttpTdengineTransport {
    pub fn new(config: &TdengineSinkConfig, client: reqwest::Client) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            url: config.insert_url(),
            client,
        })
    }
}

#[async_trait]
impl TdengineTransport for HttpTdengineTransport {
    async fn execute_sql(&self, _database: &str, sql: &str, auth: &TdengineAuth) -> Result<usize> {
        let response = self
            .client
            .post(&self.url)
            .header(reqwest::header::AUTHORIZATION, auth.header_value()?)
            .body(sql.to_string())
            .send()
            .await
            .map_err(|e| ConnectorError::Connection(format!("tdengine request failed: {e}")))?;
        let status = response.status().as_u16();
        if status == 429 || (500..=504).contains(&status) {
            return Err(ConnectorError::Connection(format!(
                "tdengine throttled with {status}"
            )));
        }
        if !(200..=299).contains(&status) {
            return Err(ConnectorError::Dispatch(format!(
                "tdengine request failed with {status}"
            )));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|e| ConnectorError::Connection(format!("tdengine read failed: {e}")))?;
        let parsed = parse_rest_response(&bytes)?;
        if parsed.code != 0 {
            return Err(ConnectorError::Dispatch(format!(
                "tdengine SQL failed with code {}",
                parsed.code
            )));
        }
        Ok(parsed.rows as usize)
    }
}

// ---------------------------------------------------------------------------
// Sink.
// ---------------------------------------------------------------------------

/// One buffered row.
#[derive(Debug, Clone)]
struct TdRow {
    row: TdengineRow,
}

struct TdBuffer {
    queue: BatchQueue<TdRow>,
    bytes: usize,
}

/// TDengine sink: buffers rows, writes multi-table INSERT batches.
pub struct TdengineSink {
    config: TdengineSinkConfig,
    transport: Arc<dyn TdengineTransport>,
    buffer: parking_lot::Mutex<TdBuffer>,
    backoff: parking_lot::Mutex<BackoffState>,
    sent_batches: AtomicU64,
    sent_records: AtomicU64,
}

impl TdengineSink {
    pub fn new(config: TdengineSinkConfig, transport: Arc<dyn TdengineTransport>) -> Result<Self> {
        config.validate()?;
        let linger = config.effective_linger();
        Ok(Self {
            buffer: parking_lot::Mutex::new(TdBuffer {
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

    pub fn config(&self) -> &TdengineSinkConfig {
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
        let max = self.config.max_backoff_ms.unwrap_or(3_000).max(1);
        let grown = initial
            .saturating_mul(2u64.saturating_pow(attempt.min(10) as u32))
            .min(max);
        let jitter = (now_millis().max(0) as u64) % (grown / 2 + 1);
        Duration::from_millis(grown.saturating_add(jitter).min(max.saturating_mul(2)))
    }

    /// Build one row: sub-table, sorted tag/metric literals, timestamp.
    /// Payloads must be JSON objects (metric columns read fields).
    fn build_row(
        &self,
        topic: &Topic,
        payload: &Bytes,
        qos: QoS,
        millis: i64,
    ) -> Result<(TdengineRow, usize)> {
        let text = std::str::from_utf8(payload)
            .map_err(|_| ConnectorError::Dispatch("tdengine payload must be UTF-8".to_string()))?;
        let value: serde_json::Value = serde_json::from_str(text)
            .map_err(|_| ConnectorError::Dispatch("tdengine payload must be JSON".to_string()))?;
        if !value.is_object() {
            return Err(ConnectorError::Dispatch(
                "tdengine payload must be a JSON object".to_string(),
            ));
        }
        let subtable = self
            .config
            .resolve_subtable(topic.as_str(), payload, qos, millis)?;
        // NOTE: QoS does not shape rows; AtMostOnce renders no variables.
        let mut tags = Vec::new();
        let mut tag_columns: Vec<&String> = self.config.tags_template.keys().collect();
        tag_columns.sort();
        for column in tag_columns {
            let rendered = self.config.event_vars(
                topic.as_str(),
                payload,
                qos,
                millis,
                &self.config.tags_template[column],
            )?;
            tags.push(sql_literal(&rendered));
        }
        let mut metrics = Vec::new();
        let mut metric_columns: Vec<&String> = self.config.metrics_template.keys().collect();
        metric_columns.sort();
        for column in metric_columns {
            let rendered = self.config.event_vars(
                topic.as_str(),
                payload,
                qos,
                millis,
                &self.config.metrics_template[column],
            )?;
            metrics.push(sql_literal(&rendered));
        }
        let bytes = subtable.len() + tags_len(&tags) + tags_len(&metrics) + 32;
        let row = TdengineRow {
            subtable,
            tags,
            metrics,
            timestamp_ms: millis,
        };
        Ok((row, bytes))
    }

    /// Flush buffered rows as one INSERT (no-op when empty).
    /// Transient failures retry in place; terminal failures and
    /// exhaustion restore the buffer, engage backoff, and propagate.
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
        let statements: Vec<TdengineRow> = rows.iter().map(|row| row.row.clone()).collect();
        let sql = render_insert(&self.config.stable_name, &statements);
        let record_count = rows.len() as u64;
        let max_retries = self.config.max_retries.unwrap_or(usize::MAX);
        let mut attempt = 0usize;
        loop {
            match self
                .transport
                .execute_sql(&self.config.database, &sql, &self.config.auth)
                .await
            {
                Ok(_) => {
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
        rows: Vec<TdRow>,
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
    /// (QoS shapes no columns; it travels in `_mqtt`-style tags only
    /// when operators template it in.)
    fn buffer_row(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<bool> {
        if topic.as_str().is_empty() {
            return Err(ConnectorError::Dispatch(
                "tdengine row requires a non-empty topic".to_string(),
            ));
        }
        let millis = now_millis();
        let (row, bytes) = self.build_row(topic, payload, qos, millis)?;
        let mut buffer = self.buffer.lock();
        let full = buffer.queue.push(TdRow { row });
        buffer.bytes = buffer.bytes.saturating_add(bytes);
        Ok(full || buffer.bytes >= self.config.effective_batch_bytes())
    }
}

fn tags_len(tags: &[String]) -> usize {
    tags.iter().map(String::len).sum()
}

#[async_trait]
impl Sink for TdengineSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        if self.buffer_row(topic, payload, qos)? {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "tdengine"
    }
}

/// Management connector handle pairing an id with a TDengine sink.
pub struct TdengineConnector {
    id: String,
    sink: Arc<TdengineSink>,
}

impl TdengineConnector {
    pub fn new(id: impl Into<String>, sink: Arc<TdengineSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }
}

impl super::Connector for TdengineConnector {
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

    fn test_config() -> TdengineSinkConfig {
        TdengineSinkConfig {
            endpoint: "http://127.0.0.1:6041/rest/sql".to_string(),
            database: "power".to_string(),
            stable_name: "meters".to_string(),
            subtable_template: "d_${client_id}".to_string(),
            auth: TdengineAuth::Basic {
                username: "root".to_string(),
                password: "taosdata".to_string(),
            },
            tags_template: HashMap::from([
                ("location".to_string(), "${payload.location}".to_string()),
                ("groupid".to_string(), "${payload.groupid}".to_string()),
            ]),
            metrics_template: HashMap::from([
                ("current".to_string(), "${payload.current}".to_string()),
                ("voltage".to_string(), "${payload.voltage}".to_string()),
            ]),
            batch_size: Some(500),
            batch_bytes: Some(4_194_304),
            linger_ms: Some(20),
            max_retries: Some(4),
            initial_backoff_ms: Some(100),
            max_backoff_ms: Some(3_000),
            timeout_ms: None,
        }
    }

    fn test_sink(config: TdengineSinkConfig) -> (Arc<TdengineSink>, Arc<MockTdengineTransport>) {
        let transport = Arc::new(MockTdengineTransport::new());
        let sink = Arc::new(TdengineSink::new(config, transport.clone()).unwrap());
        (sink, transport)
    }

    #[test]
    fn test_config_validation() {
        let mut config = test_config();
        assert!(config.validate().is_ok());
        assert_eq!(config.insert_url(), "http://127.0.0.1:6041/rest/sql/power");

        config.endpoint = "127.0.0.1:6041".to_string();
        assert!(config.validate().is_err());
        config.endpoint = test_config().endpoint;

        config.database = "has space".to_string();
        assert!(config.validate().is_err());
        config.database = "power".to_string();

        config.stable_name = "meters; DROP TABLE x;".to_string();
        assert!(config.validate().is_err());
        config.stable_name = "meters".to_string();

        config.subtable_template = "d-${topic}".to_string();
        assert!(
            config.validate().is_err(),
            "slash must fail identifier check"
        );
        config.subtable_template = test_config().subtable_template;

        config
            .tags_template
            .insert("bad col".to_string(), "x".to_string());
        assert!(config.validate().is_err());
        config.tags_template.remove("bad col");

        config.auth = TdengineAuth::Token {
            token: "  ".to_string(),
        };
        assert!(config.validate().is_err());
        config.auth = test_config().auth;

        config.batch_size = Some(0);
        assert!(config.validate().is_err());
        // Unbounded + huge depths accepted: zero clamped ceilings.
        config.batch_size = None;
        config.batch_bytes = Some(10_000_000);
        config.max_retries = None;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_auth_headers() {
        assert_eq!(
            TdengineAuth::Basic {
                username: "root".to_string(),
                password: "taosdata".to_string()
            }
            .header_value()
            .unwrap(),
            "Basic cm9vdDp0YW9zZGF0YQ=="
        );
        assert_eq!(
            TdengineAuth::Token {
                token: "abc".to_string()
            }
            .header_value()
            .unwrap(),
            "Taosd abc"
        );
        assert!(TdengineAuth::Basic {
            username: String::new(),
            password: "x".to_string()
        }
        .header_value()
        .is_err());
    }

    #[tokio::test]
    async fn test_insert_rendering() {
        let (sink, transport) = test_sink(test_config());
        sink.send(
            &Topic::new("factory/line1").unwrap(),
            &Bytes::from_static(
                br#"{"client_id":"sensor101","location":"London","groupid":2,"current":10.5,"voltage":220.1}"#,
            ),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        sink.send(
            &Topic::new("factory/line2").unwrap(),
            &Bytes::from_static(
                br#"{"client_id":"sensor102","location":"Leeds","groupid":2,"current":9.5,"voltage":219.9}"#,
            ),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        sink.flush().await.unwrap();

        let captured = transport.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].database, "power");
        assert_eq!(captured[0].auth, "Basic cm9vdDp0YW9zZGF0YQ==");
        // One multi-table statement with sorted tag/metric columns;
        // timestamps normalize away (13-digit, unique in the text).
        let sql = &captured[0].sql;
        let ts0 = captured_timestamp(sql, 0);
        let ts1 = captured_timestamp(sql, 1);
        assert!(ts0 > 1_700_000_000_000 && ts1 > 1_700_000_000_000);
        let normalized = sql
            .replace(&ts0.to_string(), "<TS>")
            .replace(&ts1.to_string(), "<TS>");
        assert_eq!(
            normalized,
            "INSERT INTO d_sensor101 USING meters TAGS (2, 'London') VALUES (<TS>, 10.5, 220.1) \
             d_sensor102 USING meters TAGS (2, 'Leeds') VALUES (<TS>, 9.5, 219.9);"
        );
        assert_eq!(sink.sent_records(), 2);
    }

    fn captured_timestamp(sql: &str, which: usize) -> i64 {
        // Timestamps are the first value in each VALUES (...) group.
        sql.split("VALUES (")
            .skip(1)
            .nth(which)
            .and_then(|group| group.split(',').next())
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or(-1)
    }

    #[test]
    fn test_insert_url_trims_slashes() {
        let mut config = test_config();
        config.endpoint = "http://127.0.0.1:6041/rest/sql/".to_string();
        assert_eq!(config.insert_url(), "http://127.0.0.1:6041/rest/sql/power");
    }

    #[test]
    fn test_subtable_identifier_enforcement() {
        let mut config = test_config();
        config.subtable_template = "d_${topic}".to_string();
        // Slashes and spaces fail the identifier check loudly.
        assert!(config
            .resolve_subtable("a/b", b"{}", QoS::AtMostOnce, 0)
            .is_err());
        assert!(config
            .resolve_subtable("a b", b"{}", QoS::AtMostOnce, 0)
            .is_err());
        // Underscores, digits and dots-free names pass.
        assert_eq!(
            config
                .resolve_subtable("line_1", b"{}", QoS::AtMostOnce, 0)
                .unwrap(),
            "d_line_1"
        );
    }

    #[test]
    fn test_sql_literal_escaping() {
        assert_eq!(sql_literal("10.5"), "10.5");
        assert_eq!(sql_literal("2"), "2");
        assert_eq!(sql_literal("true"), "TRUE");
        assert_eq!(sql_literal("o'clock"), "'o''clock'");
        assert_eq!(sql_literal("NULL"), "NULL");
        let sql = render_insert(
            "meters",
            &[TdengineRow {
                subtable: "d1".to_string(),
                tags: vec!["'a''b'".to_string()],
                metrics: vec!["1".to_string()],
                timestamp_ms: 7,
            }],
        );
        assert_eq!(
            sql,
            "INSERT INTO d1 USING meters TAGS ('a''b') VALUES (7, 1);"
        );
    }

    #[test]
    fn test_response_parsing() {
        assert_eq!(
            parse_rest_response(br#"{"code":0,"rows":2}"#).unwrap(),
            TdengineResponse { code: 0, rows: 2 }
        );
        assert_eq!(
            parse_rest_response(br#"{"code":0}"#).unwrap(),
            TdengineResponse { code: 0, rows: 0 }
        );
        assert_eq!(
            parse_rest_response(br#"{"code":533,"desc":"syntax error"}"#)
                .unwrap()
                .code,
            533
        );
        assert!(parse_rest_response(b"nope").is_err());
        assert!(parse_rest_response(br#"{}"#).is_err());
    }

    #[tokio::test]
    async fn test_transient_retry_then_success() {
        let mut config = test_config();
        config.batch_size = Some(10);
        config.initial_backoff_ms = Some(1);
        config.max_backoff_ms = Some(2);
        let (sink, transport) = test_sink(config);
        transport.script_outcomes(vec![
            MockTdengineOutcome::ConnectionError("pool busy".to_string()),
            MockTdengineOutcome::Ok(2),
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
    async fn test_terminal_error_aborts_without_retry() {
        let mut config = test_config();
        config.batch_size = Some(10);
        config.max_retries = Some(5);
        let (sink, transport) = test_sink(config);
        transport.script_outcomes(vec![
            MockTdengineOutcome::SqlError { code: 533 },
            MockTdengineOutcome::Ok(1),
        ]);

        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from("{}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        let err = sink.flush().await.expect_err("SQL error must fail");
        assert!(matches!(err, ConnectorError::Dispatch(_)));
        assert_eq!(transport.calls(), 1);
        assert_eq!(sink.buffered_rows(), 1);
    }
}
