//! GreptimeDB time-series ingestion sink (INDRA-176).
//!
//! High-performance distributed time-series sink via GreptimeDB HTTP SQL and
//! InfluxDB line-protocol endpoints with precision handling, Basic Auth,
//! and response code validation.

use async_trait::async_trait;
use base64::Engine;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use parking_lot::Mutex;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::{now_millis, BackoffState, BatchQueue, Connector, ConnectorError, Result, Sink};

fn default_greptime_db() -> String {
    "public".to_string()
}

fn default_greptime_format() -> GreptimeFormat {
    GreptimeFormat::SqlInsert
}

fn default_greptime_precision() -> GreptimePrecision {
    GreptimePrecision::Millisecond
}

fn default_batch_size_1000() -> Option<usize> {
    Some(1000)
}

/// Default outer backlog ceiling: 10_000 rows (about ten 1_000-row
/// flushes) so a burst or a stalled server cannot grow the queue
/// without bound while backoff is engaged, while steady throughput
/// still fits in memory (10_000 small JSON-derived rows stay well
/// under tens of MiB). Reason: the connector's send path runs behind
/// the rule engine's bounded queue, so this is a backstop, not new
/// work on the publish path.
fn default_buffer_capacity_10k() -> Option<usize> {
    Some(10_000)
}

/// Ingestion format for GreptimeDB.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GreptimeFormat {
    SqlInsert,
    InfluxLineProtocol,
}

/// Timestamp precision specifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GreptimePrecision {
    Nanosecond,
    Microsecond,
    Millisecond,
    Second,
}

impl GreptimePrecision {
    pub fn as_influx_param(&self) -> &'static str {
        match self {
            Self::Nanosecond => "ns",
            Self::Microsecond => "u",
            Self::Millisecond => "ms",
            Self::Second => "s",
        }
    }

    pub fn scale_timestamp(&self, epoch_millis: i64) -> i64 {
        match self {
            Self::Nanosecond => epoch_millis * 1_000_000,
            Self::Microsecond => epoch_millis * 1_000,
            Self::Millisecond => epoch_millis,
            Self::Second => epoch_millis / 1000,
        }
    }
}

/// Optional Basic Authentication credentials for GreptimeDB.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GreptimeDbAuth {
    pub username: String,
    pub password: String,
}

impl GreptimeDbAuth {
    pub fn auth_header(&self) -> String {
        let creds = format!("{}:{}", self.username, self.password);
        let encoded = base64::engine::general_purpose::STANDARD.encode(creds.as_bytes());
        format!("Basic {encoded}")
    }
}

/// Configuration for GreptimeDB time-series sink.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GreptimeDbConfig {
    /// GreptimeDB HTTP endpoint (e.g. `http://localhost:4000/v1`).
    pub endpoint: String,
    /// Target database (default `public`).
    #[serde(default = "default_greptime_db")]
    pub database: String,
    /// Optional HTTP Basic Auth.
    #[serde(default)]
    pub auth: Option<GreptimeDbAuth>,
    /// Ingestion format (SqlInsert or InfluxLineProtocol).
    #[serde(default = "default_greptime_format")]
    pub format: GreptimeFormat,
    /// Table name template (e.g. `sensor_${topic_segment_1}`).
    pub table_template: String,
    /// Timestamp precision specifier (default Millisecond).
    #[serde(default = "default_greptime_precision")]
    pub timestamp_precision: GreptimePrecision,
    /// Batch flush size (default 1,000 rows: about one SQL multi-row
    /// INSERT or line batch per flush, keeping each HTTP request well
    /// under a MiB while amortising request overhead; `None` maps to
    /// the same finite default, never unlimited).
    #[serde(default = "default_batch_size_1000")]
    pub batch_size: Option<usize>,
    /// In-memory queue backlog ceiling (`None` = default 10_000 rows:
    /// about ten 1_000-row flushes, bounding worst-case backlog memory
    /// while absorbing bursts; an old stored configuration without this
    /// field parses to the same default, so stored configuration keeps
    /// working. When full the sink fails closed with a connection error
    /// instead of growing without bound or shedding rows silently).
    #[serde(default = "default_buffer_capacity_10k")]
    pub buffer_capacity: Option<usize>,
    /// Request / network timeout in ms (default 5000: bounds the tail
    /// of a stalled server so a hung endpoint cannot wedge the flush
    /// behind backoff; 5 s covers a slow insert while still failing
    /// fast enough to retry).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

impl GreptimeDbConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.unwrap_or(5000).max(1))
    }

    /// Outer backlog ceiling (default 10_000 rows: about ten 1_000-row
    /// flushes, bounding worst-case backlog memory while the fail-fast
    /// breaker is engaged and absorbing bursts; `None` means this
    /// finite default, never unlimited).
    pub fn effective_buffer_capacity(&self) -> usize {
        self.buffer_capacity.unwrap_or(10_000).max(1)
    }

    pub fn validate(&self) -> Result<()> {
        if self.endpoint.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "greptimedb endpoint cannot be empty".into(),
            ));
        }
        if self.database.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "greptimedb database cannot be empty".into(),
            ));
        }
        if self.table_template.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "greptimedb table_template cannot be empty".into(),
            ));
        }
        if self.batch_size == Some(0) {
            return Err(ConnectorError::Dispatch(
                "greptimedb batch_size must be >= 1".into(),
            ));
        }
        if self.buffer_capacity == Some(0) {
            return Err(ConnectorError::Dispatch(
                "greptimedb buffer_capacity must be >= 1".into(),
            ));
        }
        Ok(())
    }
}

/// Typed GreptimeDB field value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GreptimeValue {
    Null,
    String(String),
    Number(f64),
    Integer(i64),
    Boolean(bool),
}

/// An individual parsed record for GreptimeDB.
#[derive(Debug, Clone)]
pub struct GreptimeRecord {
    pub table: String,
    pub timestamp: i64,
    pub fields: Vec<(String, GreptimeValue)>,
}

/// Convert JSON value to GreptimeValue.
pub fn json_to_greptime_value(val: &serde_json::Value) -> GreptimeValue {
    match val {
        serde_json::Value::Null => GreptimeValue::Null,
        serde_json::Value::Bool(b) => GreptimeValue::Boolean(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                GreptimeValue::Integer(i)
            } else if let Some(f) = n.as_f64() {
                GreptimeValue::Number(f)
            } else {
                GreptimeValue::String(n.to_string())
            }
        }
        serde_json::Value::String(s) => GreptimeValue::String(s.clone()),
        other => GreptimeValue::String(other.to_string()),
    }
}

/// Resolve table name template from topic segments.
pub fn resolve_table_name(template: &str, topic: &str) -> String {
    let mut resolved = template.to_string();
    let segments: Vec<&str> = topic.split('/').collect();
    for (i, seg) in segments.iter().enumerate() {
        let pat = format!("${{topic_segment_{i}}}");
        resolved = resolved.replace(&pat, seg);
    }
    resolved = resolved.replace("${topic}", topic);
    resolved.replace(|c: char| !c.is_ascii_alphanumeric() && c != '_', "_")
}

/// Escape SQL string literal for GreptimeDB.
pub fn escape_sql_literal(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Format GreptimeValue as SQL literal.
pub fn value_to_sql_literal(val: &GreptimeValue) -> String {
    match val {
        GreptimeValue::Null => "NULL".to_string(),
        GreptimeValue::Boolean(b) => if *b { "true" } else { "false" }.to_string(),
        GreptimeValue::Integer(i) => i.to_string(),
        GreptimeValue::Number(f) => {
            if f.is_nan() || f.is_infinite() {
                "NULL".to_string()
            } else {
                f.to_string()
            }
        }
        GreptimeValue::String(s) => escape_sql_literal(s),
    }
}

/// Quote a SQL identifier (table or column name).
///
/// Names matching `^[a-z_][a-z0-9_]*$` are returned unchanged. Every other
/// name is wrapped in double quotes, with any `"` inside doubled.
pub fn quote_sql_ident(name: &str) -> String {
    if !name.is_empty() {
        let mut bytes = name.bytes();
        let first = bytes.next().unwrap_or(b' ');
        let first_ok = first == b'_' || first.is_ascii_lowercase();
        if first_ok && bytes.all(|b| b == b'_' || b.is_ascii_lowercase() || b.is_ascii_digit()) {
            return name.to_string();
        }
    }
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// Build batch SQL insert statement for a group of records sharing the same table.
pub fn build_greptime_sql_insert(table: &str, records: &[GreptimeRecord]) -> Result<String> {
    if records.is_empty() {
        return Err(ConnectorError::Dispatch(
            "cannot build sql insert for 0 records".into(),
        ));
    }
    if table.is_empty() {
        return Err(ConnectorError::Dispatch(
            "greptimedb table name cannot be empty".into(),
        ));
    }

    let mut cols: Vec<String> = Vec::new();
    for rec in records {
        for (c, _) in &rec.fields {
            // Defensive second line: unreachable from `send()`, which rejects empty names at extract time.
            if c.is_empty() {
                return Err(ConnectorError::Dispatch(
                    "greptimedb column name cannot be empty".into(),
                ));
            }
            if !cols.iter().any(|existing| existing == c) {
                cols.push(c.clone());
            }
        }
    }
    let mut col_list = vec![quote_sql_ident("ts")];
    for col in &cols {
        col_list.push(quote_sql_ident(col));
    }

    let mut row_values = Vec::with_capacity(records.len());
    for rec in records {
        let mut vals = vec![rec.timestamp.to_string()];
        for col in &cols {
            let v = rec
                .fields
                .iter()
                .find(|(k, _)| k == col)
                .map(|(_, val)| value_to_sql_literal(val))
                .unwrap_or_else(|| "NULL".to_string());
            vals.push(v);
        }
        row_values.push(format!("({})", vals.join(", ")));
    }

    Ok(format!(
        "INSERT INTO {} ({}) VALUES {}",
        quote_sql_ident(table),
        col_list.join(", "),
        row_values.join(", ")
    ))
}

/// Escape an InfluxDB line protocol measurement (` ,` and space).
fn escape_influx_measurement(s: &str) -> String {
    s.replace(',', "\\,").replace(' ', "\\ ")
}

/// Escape an InfluxDB line protocol field key (`,`, `=` and space).
fn escape_influx_field_key(s: &str) -> String {
    s.replace(',', "\\,")
        .replace('=', "\\=")
        .replace(' ', "\\ ")
}

/// Escape an InfluxDB line protocol string field value.
fn escape_influx_string_value(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

/// Build Influx line protocol body from records.
pub fn build_influx_line_protocol(records: &[GreptimeRecord]) -> String {
    let mut out = String::new();
    for rec in records {
        out.push_str(&escape_influx_measurement(&rec.table));

        // Fields
        let mut field_strings = Vec::new();
        for (k, v) in &rec.fields {
            let ek = escape_influx_field_key(k);
            match v {
                GreptimeValue::Null => continue,
                GreptimeValue::Boolean(b) => field_strings.push(format!("{ek}={b}")),
                GreptimeValue::Integer(i) => field_strings.push(format!("{ek}={i}i")),
                GreptimeValue::Number(f) => {
                    if !f.is_finite() {
                        continue;
                    }
                    field_strings.push(format!("{ek}={f}"));
                }
                GreptimeValue::String(s) => {
                    field_strings.push(format!("{ek}=\"{}\"", escape_influx_string_value(s)))
                }
            }
        }

        if field_strings.is_empty() {
            field_strings.push("val=0".to_string());
        }

        out.push(' ');
        out.push_str(&field_strings.join(","));
        out.push(' ');
        out.push_str(&rec.timestamp.to_string());
        out.push('\n');
    }
    out
}

/// Extract GreptimeRecord from event payload.
pub fn extract_greptime_record(
    payload: &[u8],
    topic: &str,
    config: &GreptimeDbConfig,
) -> Result<GreptimeRecord> {
    let json_val: serde_json::Value = serde_json::from_slice(payload)
        .map_err(|e| ConnectorError::Dispatch(format!("invalid JSON payload: {e}")))?;

    let table = resolve_table_name(&config.table_template, topic);
    let ts_millis = now_millis();
    let timestamp = config.timestamp_precision.scale_timestamp(ts_millis);

    let mut fields = Vec::new();
    if let serde_json::Value::Object(map) = json_val {
        for (k, v) in map {
            if k == "payload" && v.is_object() {
                if let serde_json::Value::Object(submap) = v {
                    for (sk, sv) in submap {
                        if sk.is_empty() {
                            return Err(ConnectorError::Dispatch(
                                "greptimedb payload has an empty field name".into(),
                            ));
                        }
                        fields.push((sk, json_to_greptime_value(&sv)));
                    }
                }
            } else {
                if k.is_empty() {
                    return Err(ConnectorError::Dispatch(
                        "greptimedb payload has an empty field name".into(),
                    ));
                }
                fields.push((k, json_to_greptime_value(&v)));
            }
        }
    } else {
        fields.push(("val".to_string(), json_to_greptime_value(&json_val)));
    }

    Ok(GreptimeRecord {
        table,
        timestamp,
        fields,
    })
}

/// Transport abstraction for GreptimeDB.
#[async_trait]
pub trait GreptimeDbTransport: Send + Sync {
    async fn post_sql(&self, sql: &str) -> Result<()>;
    async fn post_influx(&self, line_data: &str, precision: &str) -> Result<()>;
}

/// Production HTTP transport for GreptimeDB.
pub struct HttpGreptimeDbTransport {
    client: reqwest::Client,
    sql_url: String,
    influx_url_base: String,
    auth_header: Option<String>,
}

impl HttpGreptimeDbTransport {
    /// Base URL always carrying the `/v1` API prefix. Stored endpoint
    /// values end at the host (`http://host:4000`, as the qualification
    /// environment provides) or already include `/v1`
    /// (`http://host:4000/v1`, as operator configs do); both must hit
    /// the same `/v1/...` routes, so the prefix is added only when
    /// missing.
    pub fn api_base(endpoint: &str) -> String {
        let base = endpoint.trim_end_matches('/');
        if base.ends_with("/v1") {
            base.to_string()
        } else {
            format!("{base}/v1")
        }
    }

    pub fn new(config: &GreptimeDbConfig) -> Self {
        let base = Self::api_base(&config.endpoint);
        let sql_url = format!("{base}/sql?db={}", config.database);
        let influx_url_base = format!("{base}/influxdb/api/v2/write?db={}", config.database);
        let auth_header = config.auth.as_ref().map(|a| a.auth_header());

        Self {
            client: reqwest::Client::builder()
                .timeout(config.timeout())
                .build()
                .unwrap_or_default(),
            sql_url,
            influx_url_base,
            auth_header,
        }
    }
}

#[async_trait]
impl GreptimeDbTransport for HttpGreptimeDbTransport {
    async fn post_sql(&self, sql: &str) -> Result<()> {
        // `form()` percent-encodes the statement (quotes, `&`, `=`,
        // `+` and non-ASCII bytes included); hand-rolled `sql=...`
        // bodies mangled every value containing those bytes.
        let mut req = self.client.post(&self.sql_url).form(&[("sql", sql)]);

        if let Some(ref auth) = self.auth_header {
            req = req.header(AUTHORIZATION, auth);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| ConnectorError::Connection(format!("greptimedb sql error: {e}")))?;

        let status = resp.status();
        let body_text = resp.text().await.unwrap_or_default();

        if status.is_success() {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&body_text) {
                if let Some(code) = val.get("code").and_then(|c| c.as_i64()) {
                    if code != 0 {
                        let err_msg = val
                            .get("error")
                            .and_then(|e| e.as_str())
                            .unwrap_or("unknown error");
                        return Err(ConnectorError::Dispatch(format!(
                            "greptimedb code {code}: {err_msg}"
                        )));
                    }
                }
            }
            Ok(())
        } else if status.as_u16() >= 500 || status.as_u16() == 429 {
            Err(ConnectorError::Connection(format!(
                "greptimedb transient http {status}: {body_text}"
            )))
        } else {
            Err(ConnectorError::Dispatch(format!(
                "greptimedb terminal http {status}: {body_text}"
            )))
        }
    }

    async fn post_influx(&self, line_data: &str, precision: &str) -> Result<()> {
        let url = format!("{}&precision={}", self.influx_url_base, precision);
        let mut req = self
            .client
            .post(&url)
            .header(CONTENT_TYPE, "text/plain")
            .body(line_data.to_string());

        if let Some(ref auth) = self.auth_header {
            req = req.header(AUTHORIZATION, auth);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| ConnectorError::Connection(format!("greptimedb influx error: {e}")))?;

        let status = resp.status();
        let body_text = resp.text().await.unwrap_or_default();

        if status.is_success() {
            Ok(())
        } else if status.as_u16() >= 500 || status.as_u16() == 429 {
            Err(ConnectorError::Connection(format!(
                "greptimedb transient influx http {status}: {body_text}"
            )))
        } else {
            Err(ConnectorError::Dispatch(format!(
                "greptimedb terminal influx http {status}: {body_text}"
            )))
        }
    }
}

/// Mock transport for GreptimeDB verification.
pub struct MockGreptimeDbTransport {
    pub captured_sqls: Mutex<Vec<String>>,
    pub captured_influx: Mutex<Vec<(String, String)>>,
    pub fail_count: Mutex<usize>,
    pub is_terminal: Mutex<bool>,
    pub fail_sql_on_call: Mutex<Option<usize>>,
    pub sql_call_count: Mutex<usize>,
}

impl MockGreptimeDbTransport {
    pub fn new() -> Self {
        Self {
            captured_sqls: Mutex::new(Vec::new()),
            captured_influx: Mutex::new(Vec::new()),
            fail_count: Mutex::new(0),
            is_terminal: Mutex::new(false),
            fail_sql_on_call: Mutex::new(None),
            sql_call_count: Mutex::new(0),
        }
    }

    pub fn with_transient_failures(failures: usize) -> Self {
        Self {
            captured_sqls: Mutex::new(Vec::new()),
            captured_influx: Mutex::new(Vec::new()),
            fail_count: Mutex::new(failures),
            is_terminal: Mutex::new(false),
            fail_sql_on_call: Mutex::new(None),
            sql_call_count: Mutex::new(0),
        }
    }

    pub fn with_terminal_failure() -> Self {
        Self {
            captured_sqls: Mutex::new(Vec::new()),
            captured_influx: Mutex::new(Vec::new()),
            fail_count: Mutex::new(1),
            is_terminal: Mutex::new(true),
            fail_sql_on_call: Mutex::new(None),
            sql_call_count: Mutex::new(0),
        }
    }

    #[cfg(test)]
    pub fn with_fail_sql_on_call(call_no: usize) -> Self {
        Self {
            captured_sqls: Mutex::new(Vec::new()),
            captured_influx: Mutex::new(Vec::new()),
            fail_count: Mutex::new(0),
            is_terminal: Mutex::new(false),
            fail_sql_on_call: Mutex::new(Some(call_no)),
            sql_call_count: Mutex::new(0),
        }
    }
}

impl Default for MockGreptimeDbTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl GreptimeDbTransport for MockGreptimeDbTransport {
    async fn post_sql(&self, sql: &str) -> Result<()> {
        self.captured_sqls.lock().push(sql.to_string());

        let call_no = {
            let mut count = self.sql_call_count.lock();
            *count += 1;
            *count
        };
        if let Some(want) = *self.fail_sql_on_call.lock() {
            if call_no == want {
                return Err(ConnectorError::Connection(
                    "mock greptimedb transient 500 error".into(),
                ));
            }
        }

        let mut fails = self.fail_count.lock();
        if *fails > 0 {
            *fails -= 1;
            if *self.is_terminal.lock() {
                return Err(ConnectorError::Dispatch(
                    "mock greptimedb terminal 400 error".into(),
                ));
            } else {
                return Err(ConnectorError::Connection(
                    "mock greptimedb transient 500 error".into(),
                ));
            }
        }

        Ok(())
    }

    async fn post_influx(&self, line_data: &str, precision: &str) -> Result<()> {
        self.captured_influx
            .lock()
            .push((line_data.to_string(), precision.to_string()));

        let mut fails = self.fail_count.lock();
        if *fails > 0 {
            *fails -= 1;
            if *self.is_terminal.lock() {
                return Err(ConnectorError::Dispatch(
                    "mock greptimedb terminal influx error".into(),
                ));
            } else {
                return Err(ConnectorError::Connection(
                    "mock greptimedb transient influx error".into(),
                ));
            }
        }

        Ok(())
    }
}

/// GreptimeDB time-series ingestion sink.
pub struct GreptimeDbSink {
    config: GreptimeDbConfig,
    transport: Arc<dyn GreptimeDbTransport>,
    queue: Mutex<BatchQueue<GreptimeRecord>>,
    backoff: Mutex<BackoffState>,
    sent: AtomicU64,
}

impl GreptimeDbSink {
    pub fn new(config: GreptimeDbConfig, transport: Arc<dyn GreptimeDbTransport>) -> Result<Self> {
        config.validate()?;
        let batch_size = config.batch_size.unwrap_or(1000).max(1);
        // Linger 50 ms: small batches flush promptly without waiting
        // for a full batch, while steady streams still batch up; 50 ms
        // keeps added latency negligible against the 5 s request
        // timeout.
        Ok(Self {
            config,
            transport,
            queue: Mutex::new(BatchQueue::new(batch_size, Duration::from_millis(50))),
            backoff: Mutex::new(BackoffState::default()),
            sent: AtomicU64::new(0),
        })
    }

    pub fn config(&self) -> &GreptimeDbConfig {
        &self.config
    }

    pub fn sent_count(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }

    pub fn buffered_rows(&self) -> usize {
        self.queue.lock().len()
    }

    pub async fn flush(&self) -> Result<()> {
        self.backoff.lock().check()?;

        let (records, oldest) = {
            let mut q = self.queue.lock();
            if q.is_empty() {
                return Ok(());
            }
            q.take_batch()
        };

        if records.is_empty() {
            return Ok(());
        }

        match self.config.format {
            GreptimeFormat::SqlInsert => {
                let mut tables: Vec<String> = Vec::new();
                let mut groups: Vec<Vec<GreptimeRecord>> = Vec::new();
                let mut index: std::collections::HashMap<String, usize> =
                    std::collections::HashMap::new();
                for rec in records {
                    if let Some(&pos) = index.get(&rec.table) {
                        groups[pos].push(rec);
                    } else {
                        index.insert(rec.table.clone(), groups.len());
                        tables.push(rec.table.clone());
                        groups.push(vec![rec]);
                    }
                }
                for idx in 0..tables.len() {
                    let sql = match build_greptime_sql_insert(&tables[idx], &groups[idx]) {
                        Ok(sql) => sql,
                        Err(e) => {
                            self.backoff.lock().failure();
                            let mut remaining = Vec::new();
                            for g in groups.into_iter().skip(idx) {
                                remaining.extend(g);
                            }
                            self.queue.lock().restore(remaining, oldest);
                            return Err(e);
                        }
                    };
                    match self.transport.post_sql(&sql).await {
                        Ok(_) => {
                            self.sent
                                .fetch_add(groups[idx].len() as u64, Ordering::Relaxed);
                        }
                        Err(e) => {
                            self.backoff.lock().failure();
                            let mut remaining = Vec::new();
                            for g in groups.into_iter().skip(idx) {
                                remaining.extend(g);
                            }
                            self.queue.lock().restore(remaining, oldest);
                            return Err(e);
                        }
                    }
                }
                self.backoff.lock().success();
                Ok(())
            }
            GreptimeFormat::InfluxLineProtocol => {
                let lines = build_influx_line_protocol(&records);
                let prec = self.config.timestamp_precision.as_influx_param();
                match self.transport.post_influx(&lines, prec).await {
                    Ok(_) => {
                        self.backoff.lock().success();
                        self.sent.fetch_add(records.len() as u64, Ordering::Relaxed);
                        Ok(())
                    }
                    Err(e) => {
                        self.backoff.lock().failure();
                        self.queue.lock().restore(records, oldest);
                        Err(e)
                    }
                }
            }
        }
    }
}

#[async_trait]
impl Sink for GreptimeDbSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, _qos: QoS) -> Result<()> {
        let rec = extract_greptime_record(payload, topic.as_str(), &self.config)?;
        let should_flush = {
            let mut q = self.queue.lock();
            // Bounded backlog: past the effective capacity the sink
            // fails closed with a connection error instead of growing
            // without bound; buffered rows are kept, nothing is shed.
            if q.len() >= self.config.effective_buffer_capacity() {
                return Err(ConnectorError::Connection(format!(
                    "greptimedb buffer full ({} rows): failing closed",
                    self.config.effective_buffer_capacity()
                )));
            }
            q.push(rec)
        };

        if should_flush {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "greptimedb"
    }
}

/// Addressable registered connector for GreptimeDB.
pub struct GreptimeDbConnector {
    id: String,
    sink: Arc<GreptimeDbSink>,
}

impl GreptimeDbConnector {
    pub fn new(id: impl Into<String>, sink: Arc<GreptimeDbSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }

    pub fn sink(&self) -> Arc<GreptimeDbSink> {
        self.sink.clone()
    }
}

impl Connector for GreptimeDbConnector {
    fn connector_id(&self) -> &str {
        &self.id
    }

    fn kind(&self) -> &'static str {
        "greptimedb"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_sql_config() -> GreptimeDbConfig {
        GreptimeDbConfig {
            endpoint: "http://localhost:4000/v1".to_string(),
            database: "public".to_string(),
            auth: Some(GreptimeDbAuth {
                username: "greptime_user".to_string(),
                password: "greptime_password".to_string(),
            }),
            format: GreptimeFormat::SqlInsert,
            table_template: "metrics_${topic_segment_1}".to_string(),
            timestamp_precision: GreptimePrecision::Millisecond,
            batch_size: Some(1),
            buffer_capacity: None,
            timeout_ms: None,
        }
    }

    fn sample_influx_config() -> GreptimeDbConfig {
        GreptimeDbConfig {
            endpoint: "http://localhost:4000/v1".to_string(),
            database: "public".to_string(),
            auth: None,
            format: GreptimeFormat::InfluxLineProtocol,
            table_template: "device_telemetry".to_string(),
            timestamp_precision: GreptimePrecision::Nanosecond,
            batch_size: Some(1),
            buffer_capacity: None,
            timeout_ms: None,
        }
    }

    #[test]
    fn test_precision_scaling() {
        let ms = 1_700_000_000_123;
        assert_eq!(GreptimePrecision::Second.scale_timestamp(ms), 1_700_000_000);
        assert_eq!(
            GreptimePrecision::Millisecond.scale_timestamp(ms),
            1_700_000_000_123
        );
        assert_eq!(
            GreptimePrecision::Microsecond.scale_timestamp(ms),
            1_700_000_000_123_000
        );
        assert_eq!(
            GreptimePrecision::Nanosecond.scale_timestamp(ms),
            1_700_000_000_123_000_000
        );
    }

    #[test]
    fn test_table_template_resolution() {
        assert_eq!(
            resolve_table_name("sensor_${topic_segment_1}", "factory/line_1/temp"),
            "sensor_line_1"
        );
        assert_eq!(
            resolve_table_name("dev_${topic}", "sensors/air"),
            "dev_sensors_air"
        );
    }

    #[test]
    fn test_basic_auth_formatting() {
        let auth = GreptimeDbAuth {
            username: "admin".to_string(),
            password: "pass".to_string(),
        };
        assert_eq!(auth.auth_header(), "Basic YWRtaW46cGFzcw==");
    }

    #[test]
    fn test_sql_insert_query_builder() {
        let records = vec![
            GreptimeRecord {
                table: "metrics".to_string(),
                timestamp: 1700000000,
                fields: vec![
                    ("dev_id".to_string(), GreptimeValue::String("dev-1".into())),
                    ("temp".to_string(), GreptimeValue::Number(23.4)),
                ],
            },
            GreptimeRecord {
                table: "metrics".to_string(),
                timestamp: 1700000005,
                fields: vec![
                    ("dev_id".to_string(), GreptimeValue::String("dev-2".into())),
                    ("temp".to_string(), GreptimeValue::Number(25.1)),
                ],
            },
        ];

        let sql = build_greptime_sql_insert("metrics", &records).expect("valid sql");
        assert!(sql.starts_with("INSERT INTO metrics (ts, dev_id, temp) VALUES "));
        assert!(sql.contains("(1700000000, 'dev-1', 23.4)"));
        assert!(sql.contains("(1700000005, 'dev-2', 25.1)"));
    }

    #[test]
    fn test_influx_line_protocol_builder() {
        let records = vec![GreptimeRecord {
            table: "device_telemetry".to_string(),
            timestamp: 1700000000000000000,
            fields: vec![
                ("status".to_string(), GreptimeValue::String("OK".into())),
                ("count".to_string(), GreptimeValue::Integer(10)),
                ("pressure".to_string(), GreptimeValue::Number(101.3)),
            ],
        }];

        let lines = build_influx_line_protocol(&records);
        assert!(lines.starts_with(
            "device_telemetry status=\"OK\",count=10i,pressure=101.3 1700000000000000000\n"
        ));
    }

    #[tokio::test]
    async fn test_greptime_sink_sql_loopback() {
        let cfg = sample_sql_config();
        let transport = Arc::new(MockGreptimeDbTransport::new());
        let sink = GreptimeDbSink::new(cfg, transport.clone()).expect("valid sink");

        let topic = Topic::new("sensors/temp").unwrap();
        let payload = Bytes::from_static(br#"{"sensor_id": "s-1", "val": 42.0}"#);

        sink.send(&topic, &payload, QoS::AtLeastOnce)
            .await
            .expect("send succeeds");

        let sqls = transport.captured_sqls.lock();
        assert_eq!(sqls.len(), 1);
        assert!(sqls[0].starts_with("INSERT INTO metrics_temp "));
        assert_eq!(sink.sent_count(), 1);
    }

    #[tokio::test]
    async fn test_greptime_sink_influx_loopback() {
        let cfg = sample_influx_config();
        let transport = Arc::new(MockGreptimeDbTransport::new());
        let sink = GreptimeDbSink::new(cfg, transport.clone()).expect("valid sink");

        let topic = Topic::new("devices/air").unwrap();
        let payload = Bytes::from_static(br#"{"sensor_id": "a-9", "co2": 412.5}"#);

        sink.send(&topic, &payload, QoS::AtLeastOnce)
            .await
            .expect("send succeeds");

        let items = transport.captured_influx.lock();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].1, "ns");
        assert!(items[0].0.starts_with("device_telemetry "));
        assert_eq!(sink.sent_count(), 1);
    }

    #[tokio::test]
    async fn test_greptime_sink_transient_retry_and_terminal_error() {
        let cfg = sample_sql_config();
        // 1 transient failure then success
        let transport = Arc::new(MockGreptimeDbTransport::with_transient_failures(1));
        let sink = GreptimeDbSink::new(cfg, transport.clone()).expect("valid sink");

        let topic = Topic::new("sensors/temp").unwrap();
        let payload = Bytes::from_static(br#"{"val": 99.0}"#);

        let res = sink.send(&topic, &payload, QoS::AtLeastOnce).await;
        assert!(res.is_err());

        // Reset backoff and retry
        *sink.backoff.lock() = BackoffState::default();
        sink.flush().await.expect("retry flush succeeds");
        assert_eq!(sink.sent_count(), 1);

        // Terminal error check
        let term_transport = Arc::new(MockGreptimeDbTransport::with_terminal_failure());
        let term_sink =
            GreptimeDbSink::new(sample_sql_config(), term_transport).expect("valid sink");
        let term_res = term_sink.send(&topic, &payload, QoS::AtLeastOnce).await;
        assert!(term_res.is_err());
        assert!(matches!(
            term_res.err().unwrap(),
            ConnectorError::Dispatch(_)
        ));
    }

    #[tokio::test]
    async fn test_backoff_keeps_buffered_rows() {
        let mut cfg = sample_sql_config();
        cfg.batch_size = Some(10);
        let transport = Arc::new(MockGreptimeDbTransport::with_transient_failures(1));
        let sink = GreptimeDbSink::new(cfg, transport.clone()).expect("valid sink");

        let topic = Topic::new("sensors/temp").unwrap();
        let payload1 = Bytes::from_static(br#"{"val": 99.0}"#);
        let payload2 = Bytes::from_static(br#"{"val": 100.0}"#);

        sink.send(&topic, &payload1, QoS::AtLeastOnce)
            .await
            .expect("buffer first row");
        assert_eq!(sink.buffered_rows(), 1);

        // First flush fails transiently, restores the batch and enters backoff.
        let first = sink.flush().await;
        assert!(first.is_err());
        assert_eq!(sink.buffered_rows(), 1);

        // Still inside the backoff window: flush must fail without dropping rows.
        sink.send(&topic, &payload2, QoS::AtLeastOnce)
            .await
            .expect("buffer second row");
        let second = sink.flush().await;
        assert!(second.is_err());
        assert_eq!(sink.buffered_rows(), 2);

        // After the backoff resets, one flush delivers both rows exactly once.
        *sink.backoff.lock() = BackoffState::default();
        sink.flush().await.expect("retry flush succeeds");
        assert_eq!(sink.buffered_rows(), 0);
        assert_eq!(sink.sent_count(), 2);
        let sqls = transport.captured_sqls.lock();
        assert_eq!(sqls.len(), 2);
        assert_eq!(sqls[1].matches("), (").count(), 1);
    }

    #[tokio::test]
    async fn test_sql_mixed_tables_one_insert_per_table() {
        let mut cfg = sample_sql_config();
        cfg.batch_size = Some(10);
        cfg.table_template = "metrics_${topic_segment_1}".to_string();
        let transport = Arc::new(MockGreptimeDbTransport::new());
        let sink = GreptimeDbSink::new(cfg, transport.clone()).expect("valid sink");

        let topic_a = Topic::new("plant/a").unwrap();
        let topic_b = Topic::new("plant/b").unwrap();
        sink.send(
            &topic_a,
            &Bytes::from_static(br#"{"v": 1}"#),
            QoS::AtLeastOnce,
        )
        .await
        .expect("buffer a1");
        sink.send(
            &topic_b,
            &Bytes::from_static(br#"{"v": 2}"#),
            QoS::AtLeastOnce,
        )
        .await
        .expect("buffer b");
        sink.send(
            &topic_a,
            &Bytes::from_static(br#"{"v": 3}"#),
            QoS::AtLeastOnce,
        )
        .await
        .expect("buffer a2");
        sink.flush().await.expect("flush succeeds");

        let sqls = transport.captured_sqls.lock();
        assert_eq!(sqls.len(), 2);
        assert!(sqls[0].starts_with("INSERT INTO metrics_a "));
        assert_eq!(sqls[0].matches("), (").count(), 1);
        assert!(sqls[1].starts_with("INSERT INTO metrics_b "));
        assert_eq!(sqls[1].matches("), (").count(), 0);
    }

    #[test]
    fn test_sql_union_of_columns() {
        let records = vec![
            GreptimeRecord {
                table: "t".to_string(),
                timestamp: 1000,
                fields: vec![("a".to_string(), GreptimeValue::Integer(1))],
            },
            GreptimeRecord {
                table: "t".to_string(),
                timestamp: 2000,
                fields: vec![
                    ("a".to_string(), GreptimeValue::Integer(2)),
                    ("b".to_string(), GreptimeValue::Integer(3)),
                ],
            },
        ];
        let sql = build_greptime_sql_insert("t", &records).expect("valid sql");
        assert!(sql.starts_with("INSERT INTO t (ts, a, b) VALUES "));
        assert!(sql.contains("(1000, 1, NULL)"));
        assert!(sql.contains("(2000, 2, 3)"));
    }

    #[tokio::test]
    async fn test_sql_failed_second_table_restores_only_unsent() {
        let mut cfg = sample_sql_config();
        cfg.batch_size = Some(10);
        cfg.table_template = "metrics_${topic_segment_1}".to_string();
        let transport = Arc::new(MockGreptimeDbTransport::with_fail_sql_on_call(2));
        let sink = GreptimeDbSink::new(cfg, transport.clone()).expect("valid sink");

        let topic_a = Topic::new("plant/a").unwrap();
        let topic_b = Topic::new("plant/b").unwrap();
        sink.send(
            &topic_a,
            &Bytes::from_static(br#"{"v": 1}"#),
            QoS::AtLeastOnce,
        )
        .await
        .expect("buffer a");
        sink.send(
            &topic_b,
            &Bytes::from_static(br#"{"v": 2}"#),
            QoS::AtLeastOnce,
        )
        .await
        .expect("buffer b");

        let res = sink.flush().await;
        assert!(res.is_err());
        assert_eq!(sink.sent_count(), 1);
        assert_eq!(sink.buffered_rows(), 1);

        *sink.backoff.lock() = BackoffState::default();
        sink.flush().await.expect("retry succeeds");
        assert_eq!(sink.sent_count(), 2);
        assert_eq!(sink.buffered_rows(), 0);
        let sqls = transport.captured_sqls.lock();
        assert_eq!(sqls.len(), 3);
        assert!(sqls[0].starts_with("INSERT INTO metrics_a "));
        assert!(sqls[1].starts_with("INSERT INTO metrics_b "));
        assert!(sqls[2].starts_with("INSERT INTO metrics_b "));
        assert_eq!(sqls[2].matches("), (").count(), 0);
    }

    #[test]
    fn test_sql_hostile_column_name_is_quoted() {
        let hostile = "a) VALUES (1); DROP TABLE t; --".to_string();
        let records = vec![GreptimeRecord {
            table: "metrics".to_string(),
            timestamp: 1700000000,
            fields: vec![(hostile.clone(), GreptimeValue::Integer(1))],
        }];
        let sql = build_greptime_sql_insert("metrics", &records).expect("valid sql");
        assert!(sql.contains(&format!("\"{hostile}\"")));
        assert_eq!(sql.matches("INSERT INTO").count(), 1);
    }

    #[test]
    fn test_sql_mixed_case_and_quote_identifiers() {
        let records = vec![GreptimeRecord {
            table: "metrics".to_string(),
            timestamp: 1700000000,
            fields: vec![
                ("Temp\"x".to_string(), GreptimeValue::Integer(1)),
                ("temp_c".to_string(), GreptimeValue::Integer(2)),
            ],
        }];
        let sql = build_greptime_sql_insert("metrics", &records).expect("valid sql");
        assert!(sql.contains("\"Temp\"\"x\""));
        assert!(sql.contains("temp_c"));
        assert!(!sql.contains("\"temp_c\""));
    }

    #[test]
    fn test_influx_escaping_keeps_one_line_per_record() {
        let records = vec![GreptimeRecord {
            table: "device_telemetry".to_string(),
            timestamp: 1700000000000000000,
            fields: vec![
                (
                    "my key,x=1".to_string(),
                    GreptimeValue::String("a\"b\\c\nd".to_string()),
                ),
                ("nanf".to_string(), GreptimeValue::Number(f64::NAN)),
            ],
        }];
        let lines = build_influx_line_protocol(&records);
        assert!(lines.ends_with('\n'));
        assert_eq!(lines.matches('\n').count(), 1);
        assert!(!lines[..lines.len() - 1].contains('\n'));
        assert!(lines.contains("my\\ key\\,x\\=1="));
        assert!(lines.contains("a\\\"b\\\\c\\nd"));
        assert!(!lines.contains("nanf"));
    }

    #[test]
    fn test_api_base_normalization() {
        // Stored endpoints end at the host; operator configs already
        // carry `/v1`. Both must hit the same `/v1/...` routes.
        assert_eq!(
            HttpGreptimeDbTransport::api_base("http://127.0.0.1:4000"),
            "http://127.0.0.1:4000/v1"
        );
        assert_eq!(
            HttpGreptimeDbTransport::api_base("http://127.0.0.1:4000/"),
            "http://127.0.0.1:4000/v1"
        );
        assert_eq!(
            HttpGreptimeDbTransport::api_base("http://127.0.0.1:4000/v1"),
            "http://127.0.0.1:4000/v1"
        );
        assert_eq!(
            HttpGreptimeDbTransport::api_base("http://127.0.0.1:4000/v1/"),
            "http://127.0.0.1:4000/v1"
        );
        let cfg = GreptimeDbConfig {
            endpoint: "http://127.0.0.1:4000".to_string(),
            database: "public".to_string(),
            auth: None,
            format: GreptimeFormat::SqlInsert,
            table_template: "t".to_string(),
            timestamp_precision: GreptimePrecision::Millisecond,
            batch_size: Some(1),
            buffer_capacity: None,
            timeout_ms: None,
        };
        let transport = HttpGreptimeDbTransport::new(&cfg);
        assert!(
            transport
                .sql_url
                .starts_with("http://127.0.0.1:4000/v1/sql?db="),
            "sql url must carry /v1: {}",
            transport.sql_url
        );
        assert!(
            transport
                .influx_url_base
                .starts_with("http://127.0.0.1:4000/v1/influxdb/api/v2/write?db="),
            "influx url must carry /v1: {}",
            transport.influx_url_base
        );
    }

    #[test]
    fn test_buffer_capacity_default_and_validation() {
        // A stored configuration without the field parses to the finite
        // default, so old configuration keeps working and the code never
        // chooses unbounded.
        let stored = serde_json::json!({
            "endpoint": "http://127.0.0.1:4000/v1",
            "database": "public",
            "table_template": "t",
        });
        let cfg: GreptimeDbConfig = serde_json::from_value(stored).expect("stored config parses");
        assert_eq!(cfg.buffer_capacity, Some(10_000));
        assert_eq!(cfg.effective_buffer_capacity(), 10_000);
        assert!(cfg.validate().is_ok());

        let mut explicit_none = cfg.clone();
        explicit_none.buffer_capacity = None;
        assert_eq!(explicit_none.effective_buffer_capacity(), 10_000);

        let mut zeroed = cfg.clone();
        zeroed.buffer_capacity = Some(0);
        assert!(zeroed.validate().is_err());
        zeroed.buffer_capacity = Some(10);
        zeroed.batch_size = Some(0);
        assert!(zeroed.validate().is_err());
    }

    #[tokio::test]
    async fn test_send_fails_closed_when_buffer_full() {
        let mut cfg = sample_sql_config();
        cfg.batch_size = Some(10);
        cfg.buffer_capacity = Some(2);
        let transport = Arc::new(MockGreptimeDbTransport::new());
        let sink = GreptimeDbSink::new(cfg, transport.clone()).expect("valid sink");

        let topic = Topic::new("sensors/temp").unwrap();
        sink.send(
            &topic,
            &Bytes::from_static(br#"{"val": 1}"#),
            QoS::AtLeastOnce,
        )
        .await
        .expect("first row fits");
        sink.send(
            &topic,
            &Bytes::from_static(br#"{"val": 2}"#),
            QoS::AtLeastOnce,
        )
        .await
        .expect("second row fits");
        let err = sink
            .send(
                &topic,
                &Bytes::from_static(br#"{"val": 3}"#),
                QoS::AtLeastOnce,
            )
            .await
            .expect_err("full buffer must fail closed");
        assert!(
            matches!(err, ConnectorError::Connection(_)),
            "buffer-full must be a connection error, got {err:?}"
        );
        assert_eq!(sink.buffered_rows(), 2);

        sink.flush().await.expect("flush drains");
        assert_eq!(sink.buffered_rows(), 0);
        assert_eq!(sink.sent_count(), 2);
    }

    /// Decode one `application/x-www-form-urlencoded` body field value:
    /// `+` is a space, `%XX` is the byte. Test-only helper so the
    /// round-trip assertion does not need another dependency.
    fn form_decode_field(body: &str, field: &str) -> Option<String> {
        for pair in body.split('&') {
            let (name, value) = pair.split_once('=')?;
            if name != field {
                continue;
            }
            let mut out = Vec::with_capacity(value.len());
            let mut bytes = value.as_bytes().iter();
            while let Some(&b) = bytes.next() {
                match b {
                    b'+' => out.push(b' '),
                    b'%' => {
                        let hi = bytes.next().copied().unwrap_or(b'0');
                        let lo = bytes.next().copied().unwrap_or(b'0');
                        let hex = |c: u8| match c {
                            b'0'..=b'9' => Some(c - b'0'),
                            b'a'..=b'f' => Some(c - b'a' + 10),
                            b'A'..=b'F' => Some(c - b'A' + 10),
                            _ => None,
                        };
                        out.push((hex(hi)? << 4) | hex(lo)?);
                    }
                    _ => out.push(b),
                }
            }
            return String::from_utf8(out).ok();
        }
        None
    }

    #[tokio::test]
    async fn test_sql_posts_form_encoded_body() {
        use std::sync::Mutex as StdMutex;
        use tokio::net::TcpListener;

        #[derive(Debug, Default)]
        struct Captured {
            path: StdMutex<String>,
            query: StdMutex<String>,
            content_type: StdMutex<String>,
            body: StdMutex<String>,
        }

        let captured = Arc::new(Captured::default());
        let app = {
            let captured = captured.clone();
            axum::Router::new().route(
                "/v1/sql",
                axum::routing::post(
                    move |uri: axum::http::Uri,
                          headers: axum::http::HeaderMap,
                          body: bytes::Bytes| {
                        let captured = captured.clone();
                        async move {
                            *captured.path.lock().unwrap() = uri.path().to_string();
                            *captured.query.lock().unwrap() =
                                uri.query().unwrap_or_default().to_string();
                            *captured.content_type.lock().unwrap() = headers
                                .get("content-type")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or_default()
                                .to_string();
                            // `Bytes` (not `String`): the form content
                            // type is not a text extractor input.
                            *captured.body.lock().unwrap() =
                                String::from_utf8_lossy(&body).into_owned();
                            // Minimal GreptimeDB SQL success envelope.
                            axum::http::StatusCode::OK
                        }
                    },
                ),
            )
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        // Host-only endpoint on purpose: the transport must add `/v1`.
        let mut cfg = sample_sql_config();
        cfg.endpoint = format!("http://127.0.0.1:{port}");
        let transport = HttpGreptimeDbTransport::new(&cfg);
        let sql = "INSERT INTO t (ts, note) VALUES (1700000000, 'O''Brien & \"quoted\" + 100%')";
        transport.post_sql(sql).await.expect("post succeeds");

        assert_eq!(captured.path.lock().unwrap().as_str(), "/v1/sql");
        assert!(
            captured.query.lock().unwrap().contains("db=public"),
            "query must carry db, got {}",
            captured.query.lock().unwrap()
        );
        assert!(
            captured
                .content_type
                .lock()
                .unwrap()
                .contains("application/x-www-form-urlencoded"),
            "content type must be form, got {}",
            captured.content_type.lock().unwrap()
        );
        let decoded =
            form_decode_field(&captured.body.lock().unwrap(), "sql").expect("sql field present");
        assert_eq!(
            decoded, sql,
            "form body must round-trip the statement byte-identical"
        );
        server.abort();
    }

    #[tokio::test]
    async fn test_empty_field_name_rejected_at_send() {
        let mut cfg = sample_sql_config();
        cfg.batch_size = Some(10);
        let transport = Arc::new(MockGreptimeDbTransport::new());
        let sink = GreptimeDbSink::new(cfg, transport.clone()).expect("valid sink");

        let topic = Topic::new("sensors/temp").unwrap();
        let bad = Bytes::from_static(br#"{"": 1}"#);
        let res = sink.send(&topic, &bad, QoS::AtLeastOnce).await;
        assert!(matches!(res, Err(ConnectorError::Dispatch(_))));
        assert_eq!(sink.buffered_rows(), 0);

        let good = Bytes::from_static(br#"{"val": 1}"#);
        sink.send(&topic, &good, QoS::AtLeastOnce)
            .await
            .expect("valid message buffers");
        assert_eq!(sink.buffered_rows(), 1);
        sink.flush().await.expect("flush succeeds");
        assert_eq!(sink.buffered_rows(), 0);
        assert_eq!(sink.sent_count(), 1);
        assert_eq!(transport.captured_sqls.lock().len(), 1);
    }

    fn qual_env(name: &str) -> Option<String> {
        std::env::var(name).ok().filter(|v| !v.trim().is_empty())
    }

    fn qual_now_millis() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis().min(i64::MAX as u128) as i64)
            .unwrap_or(0)
    }

    /// Table names come from the environment, so they must be plain
    /// SQL identifiers before interpolation into DDL.
    fn qual_check_ident(name: &str, value: &str) -> String {
        let ok = !value.is_empty()
            && value
                .bytes()
                .next()
                .is_some_and(|b| b == b'_' || b.is_ascii_lowercase() || b.is_ascii_uppercase())
            && value
                .bytes()
                .all(|b| b == b'_' || b.is_ascii_alphanumeric());
        assert!(ok, "qual {name} must be a plain identifier, got {value:?}");
        value.to_string()
    }

    /// POST one SQL statement to `{base}/sql?db={db}` and return the
    /// raw body. HTTP failures and GreptimeDB `code != 0` envelopes
    /// both fail the test: qualification must fail closed, never pass
    /// on an error the parser did not understand.
    async fn qual_sql(client: &reqwest::Client, sql_url: &str, sql: &str) -> String {
        let resp = client
            .post(sql_url)
            .form(&[("sql", sql)])
            .send()
            .await
            .expect("qual sql send");
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        assert!(
            status.is_success(),
            "qual sql failed: status={status} sql={sql} body={text}"
        );
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&text) {
            if let Some(code) = val.get("code").and_then(|c| c.as_i64()) {
                assert_eq!(code, 0, "qual sql code: sql={sql} body={text}");
            }
        }
        text
    }

    /// Recursively find the first `rows[0][0]` cell and read it as u64
    /// (GreptimeDB `SELECT COUNT(*)` answers
    /// `{"output":[{"records":{"rows":[[2000]]}}]}`).
    fn qual_find_count(value: &serde_json::Value) -> Option<u64> {
        match value {
            serde_json::Value::Object(map) => {
                if let Some(serde_json::Value::Array(rows)) = map.get("rows") {
                    if let Some(serde_json::Value::Array(cells)) = rows.first() {
                        if let Some(cell) = cells.first() {
                            if let Some(n) = cell.as_u64() {
                                return Some(n);
                            }
                            if let Some(n) = cell.as_i64() {
                                return u64::try_from(n).ok();
                            }
                            if let Some(s) = cell.as_str() {
                                return s.trim().parse::<u64>().ok();
                            }
                        }
                    }
                }
                for v in map.values() {
                    if let Some(n) = qual_find_count(v) {
                        return Some(n);
                    }
                }
                None
            }
            serde_json::Value::Array(items) => {
                for v in items {
                    if let Some(n) = qual_find_count(v) {
                        return Some(n);
                    }
                }
                None
            }
            _ => None,
        }
    }

    fn qual_count(body: &str) -> u64 {
        let val: serde_json::Value = serde_json::from_str(body).expect("qual count body parses");
        qual_find_count(&val).expect("qual count has rows[0][0]")
    }

    /// First result row as i64 cells (for `SELECT MIN(ts), MAX(ts)`).
    fn qual_first_row_numbers(body: &str) -> Vec<i64> {
        fn find_rows(value: &serde_json::Value) -> Option<Vec<i64>> {
            match value {
                serde_json::Value::Object(map) => {
                    if let Some(serde_json::Value::Array(rows)) = map.get("rows") {
                        if let Some(serde_json::Value::Array(cells)) = rows.first() {
                            let mut out = Vec::new();
                            for cell in cells {
                                if let Some(n) = cell.as_i64() {
                                    out.push(n);
                                } else if let Some(n) = cell.as_u64() {
                                    out.push(n.min(i64::MAX as u64) as i64);
                                } else if let Some(s) = cell.as_str() {
                                    if let Ok(n) = s.trim().parse::<i64>() {
                                        out.push(n);
                                    }
                                }
                            }
                            return Some(out);
                        }
                    }
                    for v in map.values() {
                        if let Some(row) = find_rows(v) {
                            return Some(row);
                        }
                    }
                    None
                }
                serde_json::Value::Array(items) => {
                    for v in items {
                        if let Some(row) = find_rows(v) {
                            return Some(row);
                        }
                    }
                    None
                }
                _ => None,
            }
        }
        let val: serde_json::Value = serde_json::from_str(body).expect("qual row body parses");
        find_rows(&val).expect("qual row has rows[0]")
    }

    /// Qualification against a real server through the maintained
    /// `reqwest` HTTP write path (SQL form + InfluxDB line protocol).
    ///
    /// Run with e.g.:
    /// `GREPTIMEDB_ENDPOINT=http://127.0.0.1:4000 GREPTIMEDB_DATABASE=public \
    ///  GREPTIMEDB_TABLE=qual_b320 \
    ///  cargo test -p broker-connectors --lib greptimedb::tests::test_qualify_write_path -- --ignored --nocapture --test-threads=1`
    ///
    /// Creates one table per path (the SQL path stores millisecond
    /// `TIMESTAMP`, the line-protocol path stores nanosecond
    /// `TIMESTAMP(9)`), streams 2000 rows through the broker's rule
    /// path ([`crate::ConnectorManager`] -> [`GreptimeDbSink`], 1000
    /// via SQL INSERT at millisecond precision and 1000 via line
    /// protocol at nanosecond precision), asserts the exact query-back
    /// counts (total plus per-path, no tolerance: the protocol permits
    /// duplicates, never loss) and the precision mapping of each path
    /// from the server timestamps, probes Basic auth, then drops both
    /// tables.
    #[tokio::test]
    #[ignore = "needs a real server (see GREPTIMEDB_* env)"]
    async fn test_qualify_write_path() {
        use crate::ConnectorManager;
        let endpoint = qual_env("GREPTIMEDB_ENDPOINT").unwrap_or_else(|| {
            panic!(
                "GREPTIMEDB_ENDPOINT must point at a real server for qualification; failing closed"
            )
        });
        let database = qual_env("GREPTIMEDB_DATABASE").unwrap_or_else(|| {
            panic!("GREPTIMEDB_DATABASE must be set for qualification; failing closed")
        });
        let table = qual_env("GREPTIMEDB_TABLE").unwrap_or_else(|| {
            panic!("GREPTIMEDB_TABLE must be set for qualification; failing closed")
        });
        let table = qual_check_ident("GREPTIMEDB_TABLE", &table);
        let database_ident = qual_check_ident("GREPTIMEDB_DATABASE", &database);
        let base = HttpGreptimeDbTransport::api_base(endpoint.trim_end_matches('/'));
        let sql_url = format!("{base}/sql?db={database}");
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("qual http client");

        // Server identity for the report (best effort; never a constant
        // standing in for a measurement: omit when unreachable).
        match client
            .get(format!("{base}/influxdb/health"))
            .timeout(Duration::from_secs(10))
            .send()
            .await
        {
            Ok(response) => eprintln!(
                "qual server: status={} endpoint={endpoint} database={database} table={table}",
                response.status()
            ),
            Err(e) => eprintln!("qual server: health unreachable (tolerated): {e}"),
        }
        // Best effort only: `SELECT version()` may not exist on every
        // server, so a failure here is logged and tolerated (the CREATE
        // below is the real connectivity proof).
        match client
            .post(&sql_url)
            .form(&[("sql", "SELECT version()")])
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status();
                let text = response.text().await.unwrap_or_default();
                eprintln!(
                    "qual server version probe: status={status} body={}",
                    text.chars().take(200).collect::<String>()
                );
            }
            Err(e) => eprintln!("qual server version probe unreachable (tolerated): {e}"),
        }

        // The SQL path stores `TIMESTAMP` (millisecond) while the
        // InfluxDB line-protocol path always stores `TimestampNanosecond`
        // (server-side, since v0.7): sharing one pre-created table makes
        // the second writer fail with `expect Millisecond, given
        // TIMESTAMP_NANOSECOND`. Each path therefore gets its own table
        // with its native time-index type.
        let line_table = qual_check_ident("GREPTIMEDB_TABLE_LINE", &format!("{table}_line"));
        // Fresh tables for this run (the DROPs are best effort: a missing
        // table on a fresh server must not fail qualification, but the
        // CREATEs below must succeed, proving connectivity).
        for drop_table in [&table, &line_table] {
            match client
                .post(&sql_url)
                .form(&[("sql", format!("DROP TABLE IF EXISTS {drop_table}").as_str())])
                .send()
                .await
            {
                Ok(response) => {
                    let status = response.status();
                    let text = response.text().await.unwrap_or_default();
                    eprintln!(
                        "qual drop: table={drop_table} status={status} body={}",
                        text.chars().take(200).collect::<String>()
                    );
                }
                Err(e) => eprintln!("qual drop unreachable (tolerated): {e}"),
            }
        }
        qual_sql(
            &client,
            &sql_url,
            &format!(
                "CREATE TABLE IF NOT EXISTS {table} \
                 (ts TIMESTAMP TIME INDEX, device STRING, val DOUBLE, seq BIGINT, ingest_path STRING)"
            ),
        )
        .await;
        qual_sql(
            &client,
            &sql_url,
            &format!(
                "CREATE TABLE IF NOT EXISTS {line_table} \
                 (ts TIMESTAMP(9) TIME INDEX, device STRING, val DOUBLE, seq BIGINT, ingest_path STRING)"
            ),
        )
        .await;
        eprintln!(
            "qual tables ensured: database={database_ident} sql_table={table} line_table={line_table}"
        );

        let sql_config = GreptimeDbConfig {
            endpoint: endpoint.clone(),
            database: database.clone(),
            auth: None,
            format: GreptimeFormat::SqlInsert,
            table_template: table.clone(),
            timestamp_precision: GreptimePrecision::Millisecond,
            batch_size: Some(200),
            buffer_capacity: None,
            timeout_ms: Some(30_000),
        };
        let mut line_config = sql_config.clone();
        line_config.format = GreptimeFormat::InfluxLineProtocol;
        line_config.table_template = line_table.clone();
        line_config.timestamp_precision = GreptimePrecision::Nanosecond;
        sql_config.validate().expect("qual sql config validates");
        line_config.validate().expect("qual line config validates");
        assert_eq!(sql_config.effective_buffer_capacity(), 10_000);
        let sql_sink = Arc::new(
            GreptimeDbSink::new(
                sql_config.clone(),
                Arc::new(HttpGreptimeDbTransport::new(&sql_config)),
            )
            .expect("qual sql sink"),
        );
        let line_sink = Arc::new(
            GreptimeDbSink::new(
                line_config.clone(),
                Arc::new(HttpGreptimeDbTransport::new(&line_config)),
            )
            .expect("qual line sink"),
        );
        assert_eq!(sql_sink.kind(), "greptimedb");
        assert_eq!(line_sink.kind(), "greptimedb");
        // Precision parameters each path actually sends.
        assert_eq!(
            sql_config.timestamp_precision.as_influx_param(),
            "ms",
            "sql path precision param"
        );
        assert_eq!(
            line_config.timestamp_precision.as_influx_param(),
            "ns",
            "line path precision param"
        );
        // The broker's path: rule actions deliver through the shared
        // connector manager, so the qualification sends through it.
        let manager = Arc::new(ConnectorManager::new());
        manager.register("qual-greptime-sql", sql_sink.clone());
        manager.register("qual-greptime-line", line_sink.clone());

        // 1000 rows per path (2000 total). One row every ~2 ms so rapid
        // writes never share a millisecond timestamp on the same series:
        // the server's default last-row merge would otherwise collapse
        // same-timestamp rows and the exact count below could not hold.
        // TODO(parity): whether the sink itself should hand out strictly
        // increasing timestamps (as the line-protocol sink does) instead
        // of relying on the wall clock is open.
        const PER_PATH: usize = 1000;
        let topic = Topic::new("qual/b320").unwrap();
        let t0 = qual_now_millis();
        for seq in 0..PER_PATH {
            let payload = Bytes::from(format!(
                r#"{{"device": "dev-sql-{seq:04}", "val": {:.2}, "seq": {seq}, "ingest_path": "sql"}}"#,
                20.0 + seq as f64 * 0.01
            ));
            manager
                .send("qual-greptime-sql", &topic, &payload, QoS::AtLeastOnce)
                .await
                .expect("qual sql send");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        for seq in 0..PER_PATH {
            let payload = Bytes::from(format!(
                r#"{{"device": "dev-line-{seq:04}", "val": {:.2}, "seq": {seq}, "ingest_path": "line"}}"#,
                30.0 + seq as f64 * 0.01
            ));
            manager
                .send("qual-greptime-line", &topic, &payload, QoS::AtLeastOnce)
                .await
                .expect("qual line send");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        sql_sink.flush().await.expect("qual sql flush");
        line_sink.flush().await.expect("qual line flush");
        let t1 = qual_now_millis();
        assert_eq!(sql_sink.buffered_rows(), 0);
        assert_eq!(line_sink.buffered_rows(), 0);
        assert_eq!(sql_sink.sent_count(), PER_PATH as u64);
        assert_eq!(line_sink.sent_count(), PER_PATH as u64);
        eprintln!(
            "qual rows sent: sql={PER_PATH} table={table} line={PER_PATH} table={line_table}"
        );

        // Query-back from the server, not the counters: exact counts, no
        // tolerance (at-least-once permits duplicates, never loss, and
        // the paced timestamps plus per-row devices admit no merges).
        // Each path is counted in its own table with its native
        // timestamp type (SQL: millisecond, line: nanosecond).
        async fn qual_wait_count(
            client: &reqwest::Client,
            sql_url: &str,
            table: &str,
            expect: u64,
        ) -> u64 {
            let mut seen = 0;
            for _ in 0..30 {
                let body = qual_sql(
                    client,
                    sql_url,
                    &format!("SELECT COUNT(*) AS n FROM {table}"),
                )
                .await;
                seen = qual_count(&body);
                if seen == expect {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            seen
        }
        let sql_total = qual_wait_count(&client, &sql_url, &table, PER_PATH as u64).await;
        assert_eq!(sql_total, PER_PATH as u64, "qual sql-path count");
        let line_total = qual_wait_count(&client, &sql_url, &line_table, PER_PATH as u64).await;
        assert_eq!(line_total, PER_PATH as u64, "qual line-path count");
        let total = sql_total + line_total;
        assert_eq!(
            total,
            2 * PER_PATH as u64,
            "qual count: expected {} rows across {table} + {line_table}, got {total}",
            2 * PER_PATH
        );
        eprintln!("qual rows asserted: total={total} sql={PER_PATH} line={PER_PATH}");

        // Precision mapping: the SQL table stores milliseconds inside the
        // write window and the line table stores nanoseconds inside the
        // same window scaled to ns (2 min skew each side for clock
        // drift). A wrong precision on either path lands far outside its
        // window, so the windows prove both mappings end to end; the
        // unit vectors below prove every variant.
        let sql_window = qual_sql(
            &client,
            &sql_url,
            &format!("SELECT MIN(ts) AS mn, MAX(ts) AS mx FROM {table}"),
        )
        .await;
        let sql_ends = qual_first_row_numbers(&sql_window);
        assert_eq!(sql_ends.len(), 2, "qual sql min/max row: {sql_window}");
        for bound in &sql_ends {
            assert!(
                *bound >= t0 - 120_000 && *bound <= t1 + 120_000,
                "qual sql timestamp {bound} outside write window [{t0}, {t1}]"
            );
        }
        assert!(sql_ends[0] <= sql_ends[1], "qual sql min <= max");
        let line_window = qual_sql(
            &client,
            &sql_url,
            &format!("SELECT MIN(ts) AS mn, MAX(ts) AS mx FROM {line_table}"),
        )
        .await;
        let line_ends = qual_first_row_numbers(&line_window);
        assert_eq!(line_ends.len(), 2, "qual line min/max row: {line_window}");
        // SELECT MIN/MAX on a TimestampNanosecond column returns
        // nanoseconds; scale the millisecond write window by 1e6.
        let ns_lo = (t0 - 120_000) * 1_000_000;
        let ns_hi = (t1 + 120_000) * 1_000_000;
        for bound in &line_ends {
            assert!(
                *bound >= ns_lo && *bound <= ns_hi,
                "qual line timestamp {bound} outside ns write window [{ns_lo}, {ns_hi}]"
            );
        }
        assert!(line_ends[0] <= line_ends[1], "qual line min <= max");
        eprintln!(
            "qual precision asserted: sql_min={} sql_max={} window=[{t0}, {t1}] line_min={} line_max={} ns_window=[{ns_lo}, {ns_hi}]",
            sql_ends[0], sql_ends[1], line_ends[0], line_ends[1]
        );
        let probe_ms = 1_700_000_000_123i64;
        assert_eq!(
            GreptimePrecision::Second.scale_timestamp(probe_ms),
            1_700_000_000
        );
        assert_eq!(
            GreptimePrecision::Millisecond.scale_timestamp(probe_ms),
            1_700_000_000_123
        );
        assert_eq!(
            GreptimePrecision::Microsecond.scale_timestamp(probe_ms),
            1_700_000_000_123_000
        );
        assert_eq!(
            GreptimePrecision::Nanosecond.scale_timestamp(probe_ms),
            1_700_000_000_123_000_000
        );
        assert_eq!(GreptimePrecision::Nanosecond.as_influx_param(), "ns");
        assert_eq!(GreptimePrecision::Microsecond.as_influx_param(), "u");
        assert_eq!(GreptimePrecision::Millisecond.as_influx_param(), "ms");
        assert_eq!(GreptimePrecision::Second.as_influx_param(), "s");

        // Basic auth probe after the counts (its row lands in the SQL
        // table, which the cleanup drops). A standalone server without
        // auth enabled answers 200 and the probe is logged as tolerated;
        // a secured server must fail closed as a terminal dispatch error
        // and keep the row.
        // TODO(parity): whether a default server requires Basic auth is
        // open; the fail-closed branch is asserted, the open branch is
        // logged and still exercises the auth-header path shape.
        let mut authed_config = sql_config.clone();
        authed_config.auth = Some(GreptimeDbAuth {
            username: "qual-user".to_string(),
            password: "qual-pass".to_string(),
        });
        let authed_sink = Arc::new(
            GreptimeDbSink::new(
                authed_config.clone(),
                Arc::new(HttpGreptimeDbTransport::new(&authed_config)),
            )
            .expect("qual authed sink"),
        );
        authed_sink
            .send(
                &topic,
                &Bytes::from_static(
                    br#"{"device": "dev-auth-0000", "val": 1.0, "seq": 0, "ingest_path": "authprobe"}"#,
                ),
                QoS::AtLeastOnce,
            )
            .await
            .expect("qual auth buffer");
        match authed_sink.flush().await {
            Ok(()) => {
                eprintln!("qual auth: server answered 200 with Basic credentials (open server, tolerated)")
            }
            Err(e) => {
                assert!(
                    matches!(e, ConnectorError::Dispatch(_)),
                    "bad auth must be terminal, got {e:?}"
                );
                assert_eq!(authed_sink.buffered_rows(), 1);
                eprintln!("qual auth failure asserted: bad Basic auth is a dispatch error");
            }
        }

        // Cleanup: drop both qualification tables (best effort; a failure
        // is logged, not hidden).
        for drop_table in [&table, &line_table] {
            match client
                .post(&sql_url)
                .form(&[("sql", format!("DROP TABLE IF EXISTS {drop_table}").as_str())])
                .send()
                .await
            {
                Ok(response) => {
                    let status = response.status();
                    eprintln!("qual cleanup: dropped table {drop_table} status={status}");
                }
                Err(e) => {
                    eprintln!("qual cleanup FAILED to drop {drop_table} (tolerated): {e}")
                }
            }
        }
        eprintln!(
            "qual done: rows={} tables={table},{line_table} cleaned tables",
            2 * PER_PATH
        );
    }
}
