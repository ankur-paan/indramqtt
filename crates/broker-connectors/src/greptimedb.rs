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
    /// Batch flush size (unbounded scale, default 1,000).
    #[serde(default = "default_batch_size_1000")]
    pub batch_size: Option<usize>,
    /// In-memory queue buffer capacity (`None` = unbounded).
    #[serde(default)]
    pub buffer_capacity: Option<usize>,
    /// Request / network timeout in ms (default 5000).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

impl GreptimeDbConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.unwrap_or(5000).max(1))
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
    pub fn new(config: &GreptimeDbConfig) -> Self {
        let base = config.endpoint.trim_end_matches('/');
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
        let mut req = self
            .client
            .post(&self.sql_url)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(format!("sql={}", urlencoding_like(sql)));

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

fn urlencoding_like(s: &str) -> String {
    s.replace(' ', "+")
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
}
