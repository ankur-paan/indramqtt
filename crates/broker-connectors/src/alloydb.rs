//! Google AlloyDB accelerated PostgreSQL sink (INDRA-170).
//!
//! Columnar-accelerated PostgreSQL-compatible sink optimized for Google Cloud
//! AlloyDB with Google Cloud IAM OAuth2 token and password authentication,
//! multi-row parameterized batch inserts, and connection failover classification.

use async_trait::async_trait;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::{BackoffState, BatchQueue, Connector, ConnectorError, Result, Sink};

fn default_alloydb_port() -> u16 {
    5432
}

fn default_batch_size_1000() -> Option<usize> {
    Some(1000)
}

/// Column mapping from source payload path to database column.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlloydbColumnMapping {
    /// Field path in source JSON (e.g. `device_id` or `metrics.temperature`).
    pub source_field: String,
    /// Target database column name.
    pub db_column: String,
    /// Optional SQL data type hint (`TEXT`, `NUMERIC`, `TIMESTAMPTZ`, `JSONB`).
    #[serde(default)]
    pub data_type: Option<String>,
}

/// Authentication credentials for AlloyDB.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AlloydbAuth {
    /// Traditional password authentication.
    Password { password: String },
    /// Google Cloud IAM OAuth2 access token passed during password phase.
    IamToken { token: String },
}

/// Configuration for Google Cloud AlloyDB sink.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlloydbConfig {
    /// AlloyDB instance IP or hostname.
    pub host: String,
    /// Port (default 5432).
    #[serde(default = "default_alloydb_port")]
    pub port: u16,
    /// Database name.
    pub database: String,
    /// Database username (e.g. `postgres` or IAM service account email).
    pub username: String,
    /// Authentication credentials (Password or Google Cloud IAM Token).
    pub auth: AlloydbAuth,
    /// Target database table name.
    pub table: String,
    /// Vector of column mappings (source_field -> db_column).
    #[serde(default)]
    pub column_mappings: Vec<AlloydbColumnMapping>,
    /// Batch flush size (unbounded scale, default 1,000).
    #[serde(default = "default_batch_size_1000")]
    pub batch_size: Option<usize>,
    /// In-memory queue buffer capacity (`None` = unbounded).
    #[serde(default)]
    pub buffer_capacity: Option<usize>,
    /// Network connect/query timeout in ms (default 5000).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

impl AlloydbConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.unwrap_or(5000).max(1))
    }

    pub fn validate(&self) -> Result<()> {
        if self.host.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "alloydb host cannot be empty".into(),
            ));
        }
        if self.database.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "alloydb database cannot be empty".into(),
            ));
        }
        if self.username.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "alloydb username cannot be empty".into(),
            ));
        }
        if self.table.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "alloydb table cannot be empty".into(),
            ));
        }
        match &self.auth {
            AlloydbAuth::Password { password } => {
                if password.is_empty() {
                    return Err(ConnectorError::Dispatch(
                        "alloydb password cannot be empty".into(),
                    ));
                }
            }
            AlloydbAuth::IamToken { token } => {
                if token.trim().is_empty() {
                    return Err(ConnectorError::Dispatch(
                        "alloydb iam token cannot be empty".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn credential_secret(&self) -> &str {
        match &self.auth {
            AlloydbAuth::Password { password } => password,
            AlloydbAuth::IamToken { token } => token,
        }
    }
}

/// Typed AlloyDB parameter value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AlloydbValue {
    Null,
    String(String),
    Number(f64),
    Integer(i64),
    Boolean(bool),
}

/// Result returned from AlloyDB query execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlloydbQueryResult {
    pub rows_affected: usize,
    pub status: String,
    #[serde(default)]
    pub sqlstate: Option<String>,
    #[serde(default)]
    pub error_message: Option<String>,
}

/// Error classification for AlloyDB connection and queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlloydbErrorClassification {
    /// Read-pool failover, connection drop, or server restart (`57P01`, `57P03`, `08006`).
    FailoverRetryable,
    /// Terminal error (e.g. `42703` column missing, `42P01` table missing, `28P01` bad creds).
    Terminal,
    /// Unknown or generic error.
    Unknown,
}

/// Classify PostgreSQL error code / SQLSTATE for AlloyDB.
pub fn classify_alloydb_error(err_msg: &str) -> AlloydbErrorClassification {
    let s = err_msg.to_ascii_uppercase();
    if s.contains("57P01")
        || s.contains("57P03")
        || s.contains("08006")
        || s.contains("08001")
        || s.contains("CONNECTION REFUSED")
        || s.contains("READ POOL FAILOVER")
        || s.contains("CANNOT_CONNECT_NOW")
    {
        AlloydbErrorClassification::FailoverRetryable
    } else if s.contains("42703")
        || s.contains("42P01")
        || s.contains("28P01")
        || s.contains("UNDEFINED COLUMN")
        || s.contains("UNDEFINED TABLE")
        || s.contains("PASSWORD AUTHENTICATION FAILED")
    {
        AlloydbErrorClassification::Terminal
    } else {
        AlloydbErrorClassification::Unknown
    }
}

/// Build a multi-row parameterized `INSERT INTO` query.
pub fn build_alloydb_insert_query(
    table: &str,
    columns: &[String],
    row_count: usize,
) -> Result<String> {
    if columns.is_empty() {
        return Err(ConnectorError::Dispatch(
            "cannot build insert query without columns".into(),
        ));
    }
    if row_count == 0 {
        return Err(ConnectorError::Dispatch(
            "cannot build insert query with 0 rows".into(),
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
        "INSERT INTO {} ({}) VALUES {}",
        table,
        cols_joined,
        row_placeholders.join(", ")
    ))
}

/// Extracted row for AlloyDB sink ingestion.
#[derive(Debug, Clone)]
pub struct AlloydbRow {
    pub topic: String,
    pub columns: Vec<(String, AlloydbValue)>,
}

/// Extract value at path (supports simple dots e.g. `metrics.temp`).
pub fn extract_json_path<'a>(
    val: &'a serde_json::Value,
    path: &str,
) -> Option<&'a serde_json::Value> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut curr = val;
    for part in parts {
        match curr {
            serde_json::Value::Object(map) => {
                curr = map.get(part)?;
            }
            _ => return None,
        }
    }
    Some(curr)
}

/// Convert JSON value to `AlloydbValue`.
pub fn json_to_alloydb_value(val: &serde_json::Value) -> AlloydbValue {
    match val {
        serde_json::Value::Null => AlloydbValue::Null,
        serde_json::Value::Bool(b) => AlloydbValue::Boolean(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                AlloydbValue::Integer(i)
            } else if let Some(f) = n.as_f64() {
                AlloydbValue::Number(f)
            } else {
                AlloydbValue::String(n.to_string())
            }
        }
        serde_json::Value::String(s) => AlloydbValue::String(s.clone()),
        other => AlloydbValue::String(other.to_string()),
    }
}

/// Extract columns according to config mappings or top-level keys.
pub fn extract_alloydb_row(
    payload: &[u8],
    topic: &str,
    mappings: &[AlloydbColumnMapping],
) -> Result<AlloydbRow> {
    let json_val: serde_json::Value = serde_json::from_slice(payload)
        .map_err(|e| ConnectorError::Dispatch(format!("invalid JSON payload: {e}")))?;

    let mut columns = Vec::new();

    if !mappings.is_empty() {
        for m in mappings {
            let extracted = extract_json_path(&json_val, &m.source_field)
                .map(json_to_alloydb_value)
                .unwrap_or(AlloydbValue::Null);
            columns.push((m.db_column.clone(), extracted));
        }
    } else if let serde_json::Value::Object(map) = json_val {
        for (k, v) in map {
            columns.push((k, json_to_alloydb_value(&v)));
        }
    } else {
        columns.push(("payload".to_string(), json_to_alloydb_value(&json_val)));
    }

    Ok(AlloydbRow {
        topic: topic.to_string(),
        columns,
    })
}

/// Transport abstraction for executing AlloyDB queries.
#[async_trait]
pub trait AlloydbTransport: Send + Sync {
    async fn execute(&self, query: &str, params: &[AlloydbValue]) -> Result<AlloydbQueryResult>;
}

fn format_alloydb_value(v: &AlloydbValue) -> String {
    match v {
        AlloydbValue::Null => "NULL".to_string(),
        AlloydbValue::Boolean(b) => {
            if *b {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        AlloydbValue::Integer(i) => i.to_string(),
        AlloydbValue::Number(n) => n.to_string(),
        AlloydbValue::String(s) => format!("'{}'", s.replace('\'', "''")),
    }
}

async fn read_alloydb_pg_msg(
    stream: &mut tokio::net::TcpStream,
    timeout: Duration,
) -> Result<(u8, Vec<u8>)> {
    use tokio::io::AsyncReadExt;
    let mut header = [0u8; 5];
    tokio::time::timeout(timeout, stream.read_exact(&mut header))
        .await
        .map_err(|_| ConnectorError::Connection("alloydb read timeout".to_string()))?
        .map_err(|e| ConnectorError::Connection(format!("alloydb read failed: {e}")))?;
    let tag = header[0];
    let len = i32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if !(4..=16 * 1024 * 1024).contains(&len) {
        return Err(ConnectorError::Connection(format!(
            "alloydb bad message length: {len}"
        )));
    }
    let mut body = vec![0u8; len - 4];
    tokio::time::timeout(timeout, stream.read_exact(&mut body))
        .await
        .map_err(|_| ConnectorError::Connection("alloydb read timeout".to_string()))?
        .map_err(|e| ConnectorError::Connection(format!("alloydb read failed: {e}")))?;
    Ok((tag, body))
}

/// Native TCP transport connecting to Google Cloud AlloyDB.
pub struct TcpAlloydbTransport {
    host: String,
    port: u16,
    database: String,
    username: String,
    password: Option<String>,
    timeout: Duration,
}

impl TcpAlloydbTransport {
    pub fn new(config: &AlloydbConfig) -> Self {
        let password = match &config.auth {
            AlloydbAuth::Password { password } => Some(password.clone()),
            AlloydbAuth::IamToken { token } => Some(token.clone()),
        };
        Self {
            host: config.host.clone(),
            port: config.port,
            database: config.database.clone(),
            username: config.username.clone(),
            password,
            timeout: config.timeout(),
        }
    }
}

#[async_trait]
impl AlloydbTransport for TcpAlloydbTransport {
    async fn execute(&self, query: &str, params: &[AlloydbValue]) -> Result<AlloydbQueryResult> {
        use tokio::io::AsyncWriteExt;
        let mut full_sql = query.to_string();
        for (idx, p) in params.iter().enumerate() {
            let placeholder = format!("${}", idx + 1);
            full_sql = full_sql.replace(&placeholder, &format_alloydb_value(p));
        }

        let addr = format!("{}:{}", self.host, self.port);
        let mut stream = tokio::time::timeout(self.timeout, tokio::net::TcpStream::connect(&addr))
            .await
            .map_err(|_| ConnectorError::Connection(format!("alloydb connect timeout: {addr}")))?
            .map_err(|e| ConnectorError::Connection(format!("alloydb connect failed: {e}")))?;

        // Send StartupMessage
        let mut params_buf = Vec::new();
        params_buf.extend_from_slice(b"user\0");
        params_buf.extend_from_slice(self.username.as_bytes());
        params_buf.push(0);
        params_buf.extend_from_slice(b"database\0");
        params_buf.extend_from_slice(self.database.as_bytes());
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
            ConnectorError::Connection(format!("alloydb startup write failed: {e}"))
        })?;

        // Drain until 'Z' (ReadyForQuery)
        loop {
            let (tag, body) = read_alloydb_pg_msg(&mut stream, self.timeout).await?;
            if tag == b'Z' {
                break;
            } else if tag == b'R' {
                let auth_type = if body.len() >= 4 {
                    i32::from_be_bytes([body[0], body[1], body[2], body[3]])
                } else {
                    0
                };
                if auth_type == 3 {
                    // CleartextPassword
                    let pass = self.password.as_deref().unwrap_or("");
                    let p_bytes = pass.as_bytes();
                    let p_len = (p_bytes.len() + 5) as u32;
                    let mut p_msg = Vec::with_capacity(p_len as usize + 1);
                    p_msg.push(b'p');
                    p_msg.extend_from_slice(&p_len.to_be_bytes());
                    p_msg.extend_from_slice(p_bytes);
                    p_msg.push(0);
                    stream.write_all(&p_msg).await.map_err(|e| {
                        ConnectorError::Connection(format!("alloydb password write failed: {e}"))
                    })?;
                }
            } else if tag == b'E' {
                let msg = String::from_utf8_lossy(&body).into_owned();
                return Err(ConnectorError::Connection(format!(
                    "alloydb startup error: {msg}"
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
        stream
            .write_all(&q_msg)
            .await
            .map_err(|e| ConnectorError::Connection(format!("alloydb query write failed: {e}")))?;

        let mut rows_affected = 1;
        let mut error_msg = None;
        loop {
            let (tag, body) = read_alloydb_pg_msg(&mut stream, self.timeout).await?;
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
                "alloydb query error: {err}"
            )));
        }

        Ok(AlloydbQueryResult {
            rows_affected,
            status: "SUCCESS".into(),
            sqlstate: None,
            error_message: None,
        })
    }
}

/// Captured execution for testing.
#[derive(Debug, Clone)]
pub struct CapturedAlloydbExecution {
    pub query: String,
    pub params: Vec<AlloydbValue>,
}

/// Mock transport for unit testing with failover simulation.
pub struct MockAlloydbTransport {
    pub executions: Mutex<Vec<CapturedAlloydbExecution>>,
    pub fail_count: Mutex<usize>,
    pub outcome_code: Mutex<Option<String>>,
}

impl MockAlloydbTransport {
    pub fn new() -> Self {
        Self {
            executions: Mutex::new(Vec::new()),
            fail_count: Mutex::new(0),
            outcome_code: Mutex::new(None),
        }
    }

    pub fn with_failover(failures: usize) -> Self {
        Self {
            executions: Mutex::new(Vec::new()),
            fail_count: Mutex::new(failures),
            outcome_code: Mutex::new(Some("57P01: read pool failover in progress".to_string())),
        }
    }

    pub fn with_terminal_error(sqlstate: &str) -> Self {
        Self {
            executions: Mutex::new(Vec::new()),
            fail_count: Mutex::new(1),
            outcome_code: Mutex::new(Some(sqlstate.to_string())),
        }
    }
}

impl Default for MockAlloydbTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AlloydbTransport for MockAlloydbTransport {
    async fn execute(&self, query: &str, params: &[AlloydbValue]) -> Result<AlloydbQueryResult> {
        self.executions.lock().push(CapturedAlloydbExecution {
            query: query.to_string(),
            params: params.to_vec(),
        });

        let mut fails = self.fail_count.lock();
        if *fails > 0 {
            *fails -= 1;
            let code = self
                .outcome_code
                .lock()
                .clone()
                .unwrap_or_else(|| "57P01".into());
            let class = classify_alloydb_error(&code);
            if class == AlloydbErrorClassification::FailoverRetryable {
                return Err(ConnectorError::Connection(format!(
                    "alloydb transient failover: {code}"
                )));
            } else {
                return Err(ConnectorError::Dispatch(format!(
                    "alloydb terminal error: {code}"
                )));
            }
        }

        Ok(AlloydbQueryResult {
            rows_affected: params.len().max(1),
            status: "SUCCESS".into(),
            sqlstate: None,
            error_message: None,
        })
    }
}

/// Google AlloyDB Accelerated PostgreSQL Sink.
pub struct AlloydbSink {
    config: AlloydbConfig,
    transport: Arc<dyn AlloydbTransport>,
    queue: Mutex<BatchQueue<AlloydbRow>>,
    backoff: Mutex<BackoffState>,
    sent: AtomicU64,
}

impl AlloydbSink {
    pub fn new(config: AlloydbConfig, transport: Arc<dyn AlloydbTransport>) -> Result<Self> {
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

    pub fn config(&self) -> &AlloydbConfig {
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

        let columns: Vec<String> = rows[0].columns.iter().map(|(c, _)| c.clone()).collect();
        let query = build_alloydb_insert_query(&self.config.table, &columns, rows.len())?;

        let mut params = Vec::new();
        for row in &rows {
            for (_, val) in &row.columns {
                params.push(val.clone());
            }
        }

        match self.transport.execute(&query, &params).await {
            Ok(_) => {
                self.backoff.lock().success();
                self.sent.fetch_add(rows.len() as u64, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                self.backoff.lock().failure();
                self.queue.lock().restore(rows, oldest);
                Err(e)
            }
        }
    }
}

#[async_trait]
impl Sink for AlloydbSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, _qos: QoS) -> Result<()> {
        let row = extract_alloydb_row(payload, topic.as_str(), &self.config.column_mappings)?;
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
        "alloydb"
    }
}

/// Addressable registered connector for Google Cloud AlloyDB.
pub struct AlloydbConnector {
    id: String,
    sink: Arc<AlloydbSink>,
}

impl AlloydbConnector {
    pub fn new(id: impl Into<String>, sink: Arc<AlloydbSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }

    pub fn sink(&self) -> Arc<AlloydbSink> {
        self.sink.clone()
    }
}

impl Connector for AlloydbConnector {
    fn connector_id(&self) -> &str {
        &self.id
    }

    fn kind(&self) -> &'static str {
        "alloydb"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_password_config() -> AlloydbConfig {
        AlloydbConfig {
            host: "10.128.0.5".to_string(),
            port: 5432,
            database: "iot_warehouse".to_string(),
            username: "postgres".to_string(),
            auth: AlloydbAuth::Password {
                password: "SecureDbPassword!".to_string(),
            },
            table: "sensor_telemetry".to_string(),
            column_mappings: vec![
                AlloydbColumnMapping {
                    source_field: "device_id".to_string(),
                    db_column: "dev_id".to_string(),
                    data_type: Some("TEXT".to_string()),
                },
                AlloydbColumnMapping {
                    source_field: "metrics.temperature".to_string(),
                    db_column: "temp_celsius".to_string(),
                    data_type: Some("NUMERIC".to_string()),
                },
            ],
            batch_size: Some(1),
            buffer_capacity: None,
            timeout_ms: None,
        }
    }

    fn sample_iam_config() -> AlloydbConfig {
        AlloydbConfig {
            host: "10.128.0.6".to_string(),
            port: 5432,
            database: "telemetry".to_string(),
            username: "service-account@project.iam".to_string(),
            auth: AlloydbAuth::IamToken {
                token: "ya29.c.b0AXv0zT...GcpBearerToken".to_string(),
            },
            table: "events".to_string(),
            column_mappings: Vec::new(),
            batch_size: Some(1),
            buffer_capacity: None,
            timeout_ms: None,
        }
    }

    #[test]
    fn test_config_validation_and_secrets() {
        let pass_cfg = sample_password_config();
        assert!(pass_cfg.validate().is_ok());
        assert_eq!(pass_cfg.credential_secret(), "SecureDbPassword!");

        let iam_cfg = sample_iam_config();
        assert!(iam_cfg.validate().is_ok());
        assert_eq!(
            iam_cfg.credential_secret(),
            "ya29.c.b0AXv0zT...GcpBearerToken"
        );
    }

    #[test]
    fn test_multi_row_insert_query_builder() {
        let cols = vec!["dev_id".to_string(), "temp_celsius".to_string()];
        let q1 = build_alloydb_insert_query("sensor_telemetry", &cols, 1).expect("valid query");
        assert_eq!(
            q1,
            "INSERT INTO sensor_telemetry (dev_id, temp_celsius) VALUES ($1, $2)"
        );

        let q2 = build_alloydb_insert_query("sensor_telemetry", &cols, 2).expect("valid query");
        assert_eq!(
            q2,
            "INSERT INTO sensor_telemetry (dev_id, temp_celsius) VALUES ($1, $2), ($3, $4)"
        );
    }

    #[test]
    fn test_column_mapping_nested_extraction() {
        let payload =
            br#"{"device_id": "d-202", "metrics": {"temperature": 26.8, "humidity": 65}}"#;
        let mappings = vec![
            AlloydbColumnMapping {
                source_field: "device_id".to_string(),
                db_column: "dev_id".to_string(),
                data_type: Some("TEXT".to_string()),
            },
            AlloydbColumnMapping {
                source_field: "metrics.temperature".to_string(),
                db_column: "temp_celsius".to_string(),
                data_type: Some("NUMERIC".to_string()),
            },
        ];

        let row =
            extract_alloydb_row(payload, "sensors/plant1", &mappings).expect("valid extraction");
        assert_eq!(row.columns.len(), 2);
        assert_eq!(row.columns[0].0, "dev_id");
        assert_eq!(row.columns[0].1, AlloydbValue::String("d-202".into()));
        assert_eq!(row.columns[1].0, "temp_celsius");
        assert_eq!(row.columns[1].1, AlloydbValue::Number(26.8));
    }

    #[test]
    fn test_classify_alloydb_errors() {
        assert_eq!(
            classify_alloydb_error("57P01: terminating connection due to read pool failover"),
            AlloydbErrorClassification::FailoverRetryable
        );
        assert_eq!(
            classify_alloydb_error("57P03: the database system is starting up"),
            AlloydbErrorClassification::FailoverRetryable
        );
        assert_eq!(
            classify_alloydb_error("42703: column \"unknown_col\" does not exist"),
            AlloydbErrorClassification::Terminal
        );
        assert_eq!(
            classify_alloydb_error("28P01: password authentication failed for user"),
            AlloydbErrorClassification::Terminal
        );
    }

    #[test]
    fn test_json_to_alloydb_primitives() {
        assert_eq!(
            json_to_alloydb_value(&serde_json::Value::Null),
            AlloydbValue::Null
        );
        assert_eq!(
            json_to_alloydb_value(&serde_json::json!(false)),
            AlloydbValue::Boolean(false)
        );
        assert_eq!(
            json_to_alloydb_value(&serde_json::json!(123456789)),
            AlloydbValue::Integer(123456789)
        );
        assert_eq!(
            json_to_alloydb_value(&serde_json::json!(99.95)),
            AlloydbValue::Number(99.95)
        );
        assert_eq!(
            json_to_alloydb_value(&serde_json::json!("alloy-db")),
            AlloydbValue::String("alloy-db".into())
        );
    }

    #[tokio::test]
    async fn test_alloydb_sink_loopback_success() {
        let cfg = sample_password_config();
        let transport = Arc::new(MockAlloydbTransport::new());
        let sink = AlloydbSink::new(cfg, transport.clone()).expect("valid sink");

        let topic = Topic::new("sensors/temp").unwrap();
        let payload =
            Bytes::from_static(br#"{"device_id": "dev-01", "metrics": {"temperature": 21.5}}"#);

        sink.send(&topic, &payload, QoS::AtLeastOnce)
            .await
            .expect("send succeeds");

        let execs = transport.executions.lock();
        assert_eq!(execs.len(), 1);
        assert!(execs[0]
            .query
            .starts_with("INSERT INTO sensor_telemetry (dev_id, temp_celsius) VALUES ($1, $2)"));
        assert_eq!(execs[0].params.len(), 2);
        assert_eq!(sink.sent_count(), 1);
    }

    #[tokio::test]
    async fn test_alloydb_sink_failover_retry_recovery() {
        let cfg = sample_password_config();
        // 1 transient failover failure, then success
        let transport = Arc::new(MockAlloydbTransport::with_failover(1));
        let sink = AlloydbSink::new(cfg, transport.clone()).expect("valid sink");

        let topic = Topic::new("sensors/temp").unwrap();
        let payload =
            Bytes::from_static(br#"{"device_id": "dev-02", "metrics": {"temperature": 23.0}}"#);

        // First attempt triggers Connection error
        let res = sink.send(&topic, &payload, QoS::AtLeastOnce).await;
        assert!(res.is_err());
        assert!(matches!(res.err().unwrap(), ConnectorError::Connection(_)));

        // Reset backoff and retry flush
        *sink.backoff.lock() = BackoffState::default();
        sink.flush().await.expect("retry flush succeeds");
        assert_eq!(sink.sent_count(), 1);
    }

    #[tokio::test]
    async fn test_alloydb_sink_terminal_error_aborts() {
        let cfg = sample_password_config();
        let transport = Arc::new(MockAlloydbTransport::with_terminal_error(
            "42P01: undefined table",
        ));
        let sink = AlloydbSink::new(cfg, transport.clone()).expect("valid sink");

        let topic = Topic::new("sensors/temp").unwrap();
        let payload =
            Bytes::from_static(br#"{"device_id": "dev-03", "metrics": {"temperature": 25.0}}"#);

        let res = sink.send(&topic, &payload, QoS::AtLeastOnce).await;
        assert!(res.is_err());
        assert!(matches!(res.err().unwrap(), ConnectorError::Dispatch(_)));
    }

    #[tokio::test]
    async fn test_backoff_keeps_buffered_rows() {
        let mut cfg = sample_password_config();
        cfg.batch_size = Some(10);
        let transport = Arc::new(MockAlloydbTransport::with_failover(1));
        let sink = AlloydbSink::new(cfg, transport.clone()).expect("valid sink");

        let topic = Topic::new("sensors/temp").unwrap();
        let payload1 =
            Bytes::from_static(br#"{"device_id": "dev-10", "metrics": {"temperature": 20.0}}"#);
        let payload2 =
            Bytes::from_static(br#"{"device_id": "dev-11", "metrics": {"temperature": 21.0}}"#);

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
        let execs = transport.executions.lock();
        assert_eq!(execs.len(), 2);
        assert_eq!(execs[1].params.len(), 4);
    }
}
