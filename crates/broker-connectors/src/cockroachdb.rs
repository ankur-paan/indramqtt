//! CockroachDB distributed SQL sink (INDRA-169).
//!
//! Distributed relational SQL sink for CockroachDB using PostgreSQL-compatible
//! parameter binding (`$1`, `$2`, ...), native `UPSERT INTO` syntax with
//! multi-row parameter renumbering, and transaction retry on SQLSTATE `40001`
//! serialization failure.

use async_trait::async_trait;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::{BackoffState, BatchQueue, Connector, ConnectorError, Result, Sink};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn default_batch_size() -> Option<usize> {
    Some(500)
}

fn default_max_retry_attempts() -> usize {
    5
}

/// Configuration for the CockroachDB distributed SQL sink.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CockroachDbConfig {
    /// Connection string (e.g. `postgresql://root@localhost:26257/defaultdb?sslmode=disable`).
    pub connection_string: String,
    /// Target database table name.
    pub table: String,
    /// Vector of primary key columns for conflict resolution / UPSERT.
    #[serde(default)]
    pub upsert_conflict_columns: Vec<String>,
    /// Batch flush size (unbounded scale, default 500).
    #[serde(default = "default_batch_size")]
    pub batch_size: Option<usize>,
    /// Max retry attempts on transaction serialization failure (default 5).
    #[serde(default = "default_max_retry_attempts")]
    pub max_retry_attempts: usize,
    /// In-memory queue buffer capacity (`None` = unbounded).
    #[serde(default)]
    pub buffer_capacity: Option<usize>,
    /// Request / connect timeout in ms (default 5000).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

impl CockroachDbConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.unwrap_or(5000).max(1))
    }

    pub fn validate(&self) -> Result<()> {
        if self.connection_string.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "cockroachdb connection_string cannot be empty".into(),
            ));
        }
        if self.table.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "cockroachdb table cannot be empty".into(),
            ));
        }
        Ok(())
    }
}

/// Typed CockroachDB parameter value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CockroachValue {
    Null,
    String(String),
    Number(f64),
    Integer(i64),
    Boolean(bool),
}

/// Result returned from CockroachDB query execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CockroachQueryResult {
    pub rows_affected: usize,
    pub status: String,
    #[serde(default)]
    pub sqlstate: Option<String>,
    #[serde(default)]
    pub error_message: Option<String>,
}

/// Error classification for CockroachDB SQLSTATEs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CockroachErrorClassification {
    /// Serialization failure / retry transaction (`40001`).
    SerializationFailure,
    /// Connection / network failure (`08006`, `08001`, `57P01`).
    ConnectionFailure,
    /// Terminal error (e.g. `42P01` undefined table, `28P01` invalid password).
    Terminal,
    /// Unknown or generic error.
    Unknown,
}

/// Classify a SQLSTATE code from CockroachDB.
pub fn classify_cockroach_sqlstate(sqlstate_or_msg: &str) -> CockroachErrorClassification {
    let s = sqlstate_or_msg.to_ascii_uppercase();
    if s.contains("40001") || s.contains("SERIALIZATION_FAILURE") || s.contains("RETRY TRANSACTION")
    {
        CockroachErrorClassification::SerializationFailure
    } else if s.contains("08006")
        || s.contains("08001")
        || s.contains("57P01")
        || s.contains("CONNECTION REFUSED")
    {
        CockroachErrorClassification::ConnectionFailure
    } else if s.contains("42P01")
        || s.contains("28P01")
        || s.contains("42703")
        || s.contains("UNDEFINED TABLE")
        || s.contains("PASSWORD AUTHENTICATION FAILED")
    {
        CockroachErrorClassification::Terminal
    } else {
        CockroachErrorClassification::Unknown
    }
}

/// Build a native CockroachDB `UPSERT INTO` query with multi-row parameter renumbering.
pub fn build_native_upsert_query(
    table: &str,
    columns: &[String],
    row_count: usize,
) -> Result<String> {
    if columns.is_empty() {
        return Err(ConnectorError::Dispatch(
            "cannot build upsert query without columns".into(),
        ));
    }
    if row_count == 0 {
        return Err(ConnectorError::Dispatch(
            "cannot build upsert query with 0 rows".into(),
        ));
    }

    let cols_joined = columns.join(", ");
    let mut row_placeholders = Vec::with_capacity(row_count);

    for r in 0..row_count {
        let placeholders: Vec<String> = (0..columns.len())
            .map(|c| format!("${}", r * columns.len() + c + 1))
            .collect();
        row_placeholders.push(format!("({})", placeholders.join(", ")));
    }

    Ok(format!(
        "UPSERT INTO {} ({}) VALUES {}",
        table,
        cols_joined,
        row_placeholders.join(", ")
    ))
}

/// Build an `INSERT INTO ... ON CONFLICT ... DO UPDATE` fallback query.
pub fn build_on_conflict_upsert_query(
    table: &str,
    columns: &[String],
    conflict_keys: &[String],
    row_count: usize,
) -> Result<String> {
    if columns.is_empty() {
        return Err(ConnectorError::Dispatch(
            "cannot build on_conflict query without columns".into(),
        ));
    }
    if conflict_keys.is_empty() {
        return Err(ConnectorError::Dispatch(
            "cannot build on_conflict query without conflict_keys".into(),
        ));
    }
    if row_count == 0 {
        return Err(ConnectorError::Dispatch(
            "cannot build on_conflict query with 0 rows".into(),
        ));
    }

    let cols_joined = columns.join(", ");
    let mut row_placeholders = Vec::with_capacity(row_count);

    for r in 0..row_count {
        let placeholders: Vec<String> = (0..columns.len())
            .map(|c| format!("${}", r * columns.len() + c + 1))
            .collect();
        row_placeholders.push(format!("({})", placeholders.join(", ")));
    }

    let update_sets: Vec<String> = columns
        .iter()
        .filter(|c| !conflict_keys.contains(c))
        .map(|c| format!("{} = EXCLUDED.{}", c, c))
        .collect();

    let on_conflict_clause = if update_sets.is_empty() {
        format!("ON CONFLICT ({}) DO NOTHING", conflict_keys.join(", "))
    } else {
        format!(
            "ON CONFLICT ({}) DO UPDATE SET {}",
            conflict_keys.join(", "),
            update_sets.join(", ")
        )
    };

    Ok(format!(
        "INSERT INTO {} ({}) VALUES {}\n{}",
        table,
        cols_joined,
        row_placeholders.join(", "),
        on_conflict_clause
    ))
}

/// Extracted row for CockroachDB sink ingestion.
#[derive(Debug, Clone)]
pub struct CockroachRow {
    pub topic: String,
    pub columns: Vec<(String, CockroachValue)>,
}

/// Convert JSON value to `CockroachValue`.
pub fn json_to_cockroach_value(val: &serde_json::Value) -> CockroachValue {
    match val {
        serde_json::Value::Null => CockroachValue::Null,
        serde_json::Value::Bool(b) => CockroachValue::Boolean(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                CockroachValue::Integer(i)
            } else if let Some(f) = n.as_f64() {
                CockroachValue::Number(f)
            } else {
                CockroachValue::String(n.to_string())
            }
        }
        serde_json::Value::String(s) => CockroachValue::String(s.clone()),
        other => CockroachValue::String(other.to_string()),
    }
}

/// Extract columns and values from JSON payload for CockroachDB insertion.
pub fn extract_cockroach_row(payload: &[u8], topic: &str) -> Result<CockroachRow> {
    let json_val: serde_json::Value = serde_json::from_slice(payload)
        .map_err(|e| ConnectorError::Dispatch(format!("invalid JSON payload: {e}")))?;

    let mut columns = Vec::new();
    if let serde_json::Value::Object(map) = json_val {
        for (k, v) in map {
            columns.push((k, json_to_cockroach_value(&v)));
        }
    } else {
        columns.push(("payload".to_string(), json_to_cockroach_value(&json_val)));
    }

    Ok(CockroachRow {
        topic: topic.to_string(),
        columns,
    })
}

/// Transport abstraction for executing CockroachDB queries.
#[async_trait]
pub trait CockroachDbTransport: Send + Sync {
    async fn execute(&self, query: &str, params: &[CockroachValue])
        -> Result<CockroachQueryResult>;
}

fn format_cockroach_value(v: &CockroachValue) -> String {
    match v {
        CockroachValue::Null => "NULL".to_string(),
        CockroachValue::Boolean(b) => {
            if *b {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        CockroachValue::Integer(i) => i.to_string(),
        CockroachValue::Number(n) => n.to_string(),
        CockroachValue::String(s) => format!("'{}'", s.replace('\'', "''")),
    }
}

fn parse_cr_conn_str(conn_str: &str) -> (String, u16, String, String) {
    let mut s = conn_str.trim();
    if let Some(rest) = s
        .strip_prefix("postgresql://")
        .or_else(|| s.strip_prefix("postgres://"))
    {
        s = rest;
    }
    if let Some((before_q, _)) = s.split_once('?') {
        s = before_q;
    }
    let (auth, host_part) = if let Some((a, h)) = s.split_once('@') {
        (Some(a), h)
    } else {
        (None, s)
    };
    let user = if let Some(a) = auth {
        if let Some((u, _p)) = a.split_once(':') {
            u.to_string()
        } else {
            a.to_string()
        }
    } else {
        "root".to_string()
    };
    let (host_port, db) = if let Some((hp, d)) = host_part.split_once('/') {
        (hp, d.to_string())
    } else {
        (host_part, "defaultdb".to_string())
    };
    let (host, port) = if let Some((h, p)) = host_port.split_once(':') {
        let parsed_p = p.parse::<u16>().unwrap_or(26257);
        (h.to_string(), parsed_p)
    } else {
        (host_port.to_string(), 26257)
    };
    let host = if host.is_empty() {
        "127.0.0.1".to_string()
    } else {
        host
    };
    let db = if db.is_empty() {
        "defaultdb".to_string()
    } else {
        db
    };
    let user = if user.is_empty() {
        "root".to_string()
    } else {
        user
    };
    (host, port, user, db)
}

async fn read_cr_pg_msg(stream: &mut TcpStream, timeout: Duration) -> Result<(u8, Vec<u8>)> {
    let mut header = [0u8; 5];
    tokio::time::timeout(timeout, stream.read_exact(&mut header))
        .await
        .map_err(|_| ConnectorError::Connection("cockroachdb read timeout".to_string()))?
        .map_err(|e| ConnectorError::Connection(format!("cockroachdb read failed: {e}")))?;
    let tag = header[0];
    let len = i32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if !(4..=16 * 1024 * 1024).contains(&len) {
        return Err(ConnectorError::Connection(format!(
            "cockroachdb bad message length: {len}"
        )));
    }
    let mut body = vec![0u8; len - 4];
    tokio::time::timeout(timeout, stream.read_exact(&mut body))
        .await
        .map_err(|_| ConnectorError::Connection("cockroachdb read timeout".to_string()))?
        .map_err(|e| ConnectorError::Connection(format!("cockroachdb read failed: {e}")))?;
    Ok((tag, body))
}

/// Native TCP transport connecting to CockroachDB.
pub struct TcpCockroachDbTransport {
    connection_string: String,
    timeout: Duration,
}

impl TcpCockroachDbTransport {
    pub fn new(config: &CockroachDbConfig) -> Self {
        Self {
            connection_string: config.connection_string.clone(),
            timeout: config.timeout(),
        }
    }

    pub fn connection_string(&self) -> &str {
        &self.connection_string
    }
}

#[async_trait]
impl CockroachDbTransport for TcpCockroachDbTransport {
    async fn execute(
        &self,
        query: &str,
        params: &[CockroachValue],
    ) -> Result<CockroachQueryResult> {
        let mut full_sql = query.to_string();
        for (idx, p) in params.iter().enumerate() {
            let placeholder = format!("${}", idx + 1);
            full_sql = full_sql.replace(&placeholder, &format_cockroach_value(p));
        }

        let (host, port, user, database) = parse_cr_conn_str(&self.connection_string);
        let addr = format!("{host}:{port}");
        let mut stream = tokio::time::timeout(self.timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| {
                ConnectorError::Connection(format!("cockroachdb connect timeout: {addr}"))
            })?
            .map_err(|e| ConnectorError::Connection(format!("cockroachdb connect failed: {e}")))?;

        // Send StartupMessage
        let mut params_buf = Vec::new();
        params_buf.extend_from_slice(b"user\0");
        params_buf.extend_from_slice(user.as_bytes());
        params_buf.push(0);
        params_buf.extend_from_slice(b"database\0");
        params_buf.extend_from_slice(database.as_bytes());
        params_buf.push(0);
        params_buf.push(0);

        let mut startup_body = Vec::new();
        startup_body.extend_from_slice(&0x0003_0000u32.to_be_bytes());
        startup_body.extend_from_slice(&params_buf);
        let len = (startup_body.len() + 4) as u32;
        let mut startup_msg = Vec::new();
        startup_msg.extend_from_slice(&len.to_be_bytes());
        startup_msg.extend_from_slice(&startup_body);
        stream.write_all(&startup_msg).await.map_err(|e| {
            ConnectorError::Connection(format!("cockroachdb startup write failed: {e}"))
        })?;

        // Drain until 'Z'
        loop {
            let (tag, body) = read_cr_pg_msg(&mut stream, self.timeout).await?;
            if tag == b'Z' {
                break;
            } else if tag == b'E' {
                let msg = String::from_utf8_lossy(&body).into_owned();
                return Err(ConnectorError::Connection(format!(
                    "cockroachdb startup error: {msg}"
                )));
            }
        }

        // Send Simple Query ('Q')
        let sql_bytes = full_sql.as_bytes();
        let q_len = (sql_bytes.len() + 5) as u32;
        let mut q_msg = Vec::with_capacity(q_len as usize + 1);
        q_msg.push(b'Q');
        q_msg.extend_from_slice(&q_len.to_be_bytes());
        q_msg.extend_from_slice(sql_bytes);
        q_msg.push(0);
        stream.write_all(&q_msg).await.map_err(|e| {
            ConnectorError::Connection(format!("cockroachdb query write failed: {e}"))
        })?;

        let mut rows_affected = 1;
        let mut error_msg = None;
        loop {
            let (tag, body) = read_cr_pg_msg(&mut stream, self.timeout).await?;
            if tag == b'C' {
                let s = String::from_utf8_lossy(&body);
                if let Some(cnt_str) = s.split_whitespace().last() {
                    if let Ok(cnt) = cnt_str.trim_matches('\0').parse::<usize>() {
                        rows_affected = cnt;
                    }
                }
            } else if tag == b'E' {
                let s = String::from_utf8_lossy(&body).into_owned();
                error_msg = Some(s);
            } else if tag == b'Z' {
                break;
            }
        }
        if let Some(err) = error_msg {
            return Err(ConnectorError::Dispatch(format!(
                "cockroachdb query failed: {err}"
            )));
        }

        Ok(CockroachQueryResult {
            rows_affected,
            status: "SUCCESS".into(),
            sqlstate: None,
            error_message: None,
        })
    }
}

/// Captured execution for testing.
#[derive(Debug, Clone)]
pub struct CapturedCockroachExecution {
    pub query: String,
    pub params: Vec<CockroachValue>,
}

/// Mock transport with configurable serialization failure counts for testing.
pub struct MockCockroachDbTransport {
    pub executions: Mutex<Vec<CapturedCockroachExecution>>,
    pub fail_count: Mutex<usize>,
    pub sqlstate_outcome: Mutex<Option<String>>,
}

impl MockCockroachDbTransport {
    pub fn new() -> Self {
        Self {
            executions: Mutex::new(Vec::new()),
            fail_count: Mutex::new(0),
            sqlstate_outcome: Mutex::new(None),
        }
    }

    pub fn with_serialization_failures(failures: usize) -> Self {
        Self {
            executions: Mutex::new(Vec::new()),
            fail_count: Mutex::new(failures),
            sqlstate_outcome: Mutex::new(Some("40001".to_string())),
        }
    }

    pub fn with_terminal_error(sqlstate: &str) -> Self {
        Self {
            executions: Mutex::new(Vec::new()),
            fail_count: Mutex::new(1),
            sqlstate_outcome: Mutex::new(Some(sqlstate.to_string())),
        }
    }
}

impl Default for MockCockroachDbTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CockroachDbTransport for MockCockroachDbTransport {
    async fn execute(
        &self,
        query: &str,
        params: &[CockroachValue],
    ) -> Result<CockroachQueryResult> {
        self.executions.lock().push(CapturedCockroachExecution {
            query: query.to_string(),
            params: params.to_vec(),
        });

        let mut fails = self.fail_count.lock();
        if *fails > 0 {
            *fails -= 1;
            let code = self
                .sqlstate_outcome
                .lock()
                .clone()
                .unwrap_or_else(|| "40001".into());
            let class = classify_cockroach_sqlstate(&code);
            match class {
                CockroachErrorClassification::SerializationFailure => {
                    return Err(ConnectorError::Connection(format!(
                        "cockroachdb serialization failure: sqlstate={code}"
                    )));
                }
                CockroachErrorClassification::ConnectionFailure => {
                    return Err(ConnectorError::Connection(format!(
                        "cockroachdb connection failure: sqlstate={code}"
                    )));
                }
                _ => {
                    return Err(ConnectorError::Dispatch(format!(
                        "cockroachdb terminal failure: sqlstate={code}"
                    )));
                }
            }
        }

        Ok(CockroachQueryResult {
            rows_affected: params.len().max(1),
            status: "SUCCESS".into(),
            sqlstate: None,
            error_message: None,
        })
    }
}

/// CockroachDB Distributed SQL Sink.
pub struct CockroachDbSink {
    config: CockroachDbConfig,
    transport: Arc<dyn CockroachDbTransport>,
    queue: Mutex<BatchQueue<CockroachRow>>,
    backoff: Mutex<BackoffState>,
    sent: AtomicU64,
}

impl CockroachDbSink {
    pub fn new(
        config: CockroachDbConfig,
        transport: Arc<dyn CockroachDbTransport>,
    ) -> Result<Self> {
        config.validate()?;
        let batch_size = config.batch_size.unwrap_or(500).max(1);
        Ok(Self {
            config,
            transport,
            queue: Mutex::new(BatchQueue::new(batch_size, Duration::from_millis(50))),
            backoff: Mutex::new(BackoffState::default()),
            sent: AtomicU64::new(0),
        })
    }

    pub fn config(&self) -> &CockroachDbConfig {
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

        let (rows, oldest) = {
            let mut q = self.queue.lock();
            if q.is_empty() {
                return Ok(());
            }
            q.take_batch()
        };

        if rows.is_empty() {
            return Ok(());
        }

        // Aggregate unique columns from first row
        let columns: Vec<String> = rows[0].columns.iter().map(|(c, _)| c.clone()).collect();
        let query = if !self.config.upsert_conflict_columns.is_empty() {
            build_on_conflict_upsert_query(
                &self.config.table,
                &columns,
                &self.config.upsert_conflict_columns,
                rows.len(),
            )?
        } else {
            build_native_upsert_query(&self.config.table, &columns, rows.len())?
        };

        let mut params = Vec::new();
        for row in &rows {
            for (_, val) in &row.columns {
                params.push(val.clone());
            }
        }

        // Retry loop for transaction serialization failure (SQLSTATE 40001)
        let max_attempts = self.config.max_retry_attempts.max(1);
        let mut attempts = 0;
        let mut last_err = None;

        while attempts < max_attempts {
            attempts += 1;
            match self.transport.execute(&query, &params).await {
                Ok(_) => {
                    self.backoff.lock().success();
                    self.sent.fetch_add(rows.len() as u64, Ordering::Relaxed);
                    return Ok(());
                }
                Err(e) => {
                    let err_msg = e.to_string();
                    let classification = classify_cockroach_sqlstate(&err_msg);

                    if classification == CockroachErrorClassification::SerializationFailure {
                        // Retry transaction with brief pause
                        tokio::time::sleep(Duration::from_millis(5 * attempts as u64)).await;
                        last_err = Some(e);
                        continue;
                    } else if classification == CockroachErrorClassification::ConnectionFailure {
                        self.backoff.lock().failure();
                        self.queue.lock().restore(rows, oldest);
                        return Err(e);
                    } else {
                        // Terminal error - do not retry
                        self.backoff.lock().failure();
                        self.queue.lock().restore(rows, oldest);
                        return Err(e);
                    }
                }
            }
        }

        // Exhausted retries
        self.backoff.lock().failure();
        self.queue.lock().restore(rows, oldest);
        Err(last_err.unwrap_or_else(|| {
            ConnectorError::Dispatch("cockroachdb max retry attempts exhausted".into())
        }))
    }
}

#[async_trait]
impl Sink for CockroachDbSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, _qos: QoS) -> Result<()> {
        let row = extract_cockroach_row(payload, topic.as_str())?;
        let should_flush = {
            let mut q = self.queue.lock();
            q.push(row)
        };

        if should_flush {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "cockroachdb"
    }
}

/// Addressable registered connector for CockroachDB.
pub struct CockroachDbConnector {
    id: String,
    sink: Arc<CockroachDbSink>,
}

impl CockroachDbConnector {
    pub fn new(id: impl Into<String>, sink: Arc<CockroachDbSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }

    pub fn sink(&self) -> Arc<CockroachDbSink> {
        self.sink.clone()
    }
}

impl Connector for CockroachDbConnector {
    fn connector_id(&self) -> &str {
        &self.id
    }

    fn kind(&self) -> &'static str {
        "cockroachdb"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> CockroachDbConfig {
        CockroachDbConfig {
            connection_string: "postgresql://root@localhost:26257/defaultdb?sslmode=disable"
                .to_string(),
            table: "telemetry".to_string(),
            upsert_conflict_columns: Vec::new(),
            batch_size: Some(1),
            max_retry_attempts: 3,
            buffer_capacity: None,
            timeout_ms: None,
        }
    }

    #[test]
    fn test_native_upsert_query_builder_single_row() {
        let cols = vec!["device_id".to_string(), "temp".to_string()];
        let q = build_native_upsert_query("telemetry", &cols, 1).expect("valid query");
        assert_eq!(q, "UPSERT INTO telemetry (device_id, temp) VALUES ($1, $2)");
    }

    #[test]
    fn test_native_upsert_query_builder_multi_row() {
        let cols = vec!["device_id".to_string(), "temp".to_string()];
        let q = build_native_upsert_query("telemetry", &cols, 3).expect("valid query");
        assert_eq!(
            q,
            "UPSERT INTO telemetry (device_id, temp) VALUES ($1, $2), ($3, $4), ($5, $6)"
        );
    }

    #[test]
    fn test_on_conflict_query_builder() {
        let cols = vec![
            "device_id".to_string(),
            "temp".to_string(),
            "updated_at".to_string(),
        ];
        let keys = vec!["device_id".to_string()];
        let q = build_on_conflict_upsert_query("telemetry", &cols, &keys, 1).expect("valid query");
        assert!(q.starts_with(
            "INSERT INTO telemetry (device_id, temp, updated_at) VALUES ($1, $2, $3)"
        ));
        assert!(q.contains("ON CONFLICT (device_id) DO UPDATE SET temp = EXCLUDED.temp, updated_at = EXCLUDED.updated_at"));
    }

    #[test]
    fn test_classify_sqlstate() {
        assert_eq!(
            classify_cockroach_sqlstate(
                "40001: restart transaction: TransactionRetryWithProtoRefreshError"
            ),
            CockroachErrorClassification::SerializationFailure
        );
        assert_eq!(
            classify_cockroach_sqlstate("08006: connection failure"),
            CockroachErrorClassification::ConnectionFailure
        );
        assert_eq!(
            classify_cockroach_sqlstate("42P01: relation \"missing\" does not exist"),
            CockroachErrorClassification::Terminal
        );
        assert_eq!(
            classify_cockroach_sqlstate("28P01: password authentication failed"),
            CockroachErrorClassification::Terminal
        );
        assert_eq!(
            classify_cockroach_sqlstate("random string"),
            CockroachErrorClassification::Unknown
        );
    }

    #[test]
    fn test_json_to_cockroach_primitives() {
        assert_eq!(
            json_to_cockroach_value(&serde_json::Value::Null),
            CockroachValue::Null
        );
        assert_eq!(
            json_to_cockroach_value(&serde_json::json!(true)),
            CockroachValue::Boolean(true)
        );
        assert_eq!(
            json_to_cockroach_value(&serde_json::json!(105)),
            CockroachValue::Integer(105)
        );
        assert_eq!(
            json_to_cockroach_value(&serde_json::json!(42.75)),
            CockroachValue::Number(42.75)
        );
        assert_eq!(
            json_to_cockroach_value(&serde_json::json!("edge-node")),
            CockroachValue::String("edge-node".into())
        );
    }

    #[tokio::test]
    async fn test_cockroach_sink_loopback_success() {
        let cfg = sample_config();
        let transport = Arc::new(MockCockroachDbTransport::new());
        let sink = CockroachDbSink::new(cfg, transport.clone()).expect("valid sink");

        let topic = Topic::new("sensors/temp").unwrap();
        let payload = Bytes::from_static(br#"{"device_id": "cr-01", "temp": 77.2}"#);

        sink.send(&topic, &payload, QoS::AtLeastOnce)
            .await
            .expect("send succeeds");

        let execs = transport.executions.lock();
        assert_eq!(execs.len(), 1);
        assert!(execs[0].query.starts_with("UPSERT INTO telemetry"));
        assert_eq!(execs[0].params.len(), 2);
        assert_eq!(sink.sent_count(), 1);
    }

    #[tokio::test]
    async fn test_cockroach_sink_retry_success_after_40001() {
        let cfg = sample_config();
        // 2 failures with 40001, then success on 3rd attempt (max_retry_attempts = 3)
        let transport = Arc::new(MockCockroachDbTransport::with_serialization_failures(2));
        let sink = CockroachDbSink::new(cfg, transport.clone()).expect("valid sink");

        let topic = Topic::new("sensors/temp").unwrap();
        let payload = Bytes::from_static(br#"{"device_id": "cr-02", "temp": 82.0}"#);

        sink.send(&topic, &payload, QoS::AtLeastOnce)
            .await
            .expect("retry loop succeeds");

        let execs = transport.executions.lock();
        assert_eq!(execs.len(), 3); // 2 retries + 1 success
        assert_eq!(sink.sent_count(), 1);
    }

    #[tokio::test]
    async fn test_cockroach_sink_retry_exhaustion_on_persistent_40001() {
        let mut cfg = sample_config();
        cfg.max_retry_attempts = 2;
        // 5 failures, but max_retries = 2 -> will exhaust
        let transport = Arc::new(MockCockroachDbTransport::with_serialization_failures(5));
        let sink = CockroachDbSink::new(cfg, transport.clone()).expect("valid sink");

        let topic = Topic::new("sensors/temp").unwrap();
        let payload = Bytes::from_static(br#"{"device_id": "cr-03", "temp": 88.0}"#);

        let res = sink.send(&topic, &payload, QoS::AtLeastOnce).await;
        assert!(res.is_err());
        let execs = transport.executions.lock();
        assert_eq!(execs.len(), 2); // stopped at max_retries
    }

    #[tokio::test]
    async fn test_cockroach_sink_terminal_error_aborts_immediately() {
        let cfg = sample_config();
        // 42P01: undefined table -> terminal, no retries
        let transport = Arc::new(MockCockroachDbTransport::with_terminal_error("42P01"));
        let sink = CockroachDbSink::new(cfg, transport.clone()).expect("valid sink");

        let topic = Topic::new("sensors/temp").unwrap();
        let payload = Bytes::from_static(br#"{"device_id": "cr-04", "temp": 95.0}"#);

        let res = sink.send(&topic, &payload, QoS::AtLeastOnce).await;
        assert!(res.is_err());
        let execs = transport.executions.lock();
        assert_eq!(execs.len(), 1); // zero retries
    }

    #[tokio::test]
    async fn test_backoff_keeps_buffered_rows() {
        let mut cfg = sample_config();
        cfg.batch_size = Some(10);
        let transport = Arc::new(MockCockroachDbTransport::with_terminal_error(
            "42P01: undefined table",
        ));
        let sink = CockroachDbSink::new(cfg, transport.clone()).expect("valid sink");

        let topic = Topic::new("sensors/temp").unwrap();
        let payload1 = Bytes::from_static(br#"{"device_id": "cr-10", "temp": 70.0}"#);
        let payload2 = Bytes::from_static(br#"{"device_id": "cr-11", "temp": 71.0}"#);

        sink.send(&topic, &payload1, QoS::AtLeastOnce)
            .await
            .expect("buffer first row");
        assert_eq!(sink.buffered_rows(), 1);

        // First flush fails, restores the batch and enters backoff.
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
        let execs = transport.executions.lock();
        assert_eq!(execs.len(), 2);
        assert_eq!(execs[1].params.len(), 4);
    }
}
