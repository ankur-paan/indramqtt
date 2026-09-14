//! Oracle Database SQL sink (INDRA-166).
//!
//! High-throughput enterprise relational sink for Oracle Database with
//! positional parameter binding (`:1`, `:2`, ...), atomic upserts using
//! `MERGE INTO ... USING DUAL`, and ORA deadlock/transient retry classification.

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

use super::{BackoffState, BatchQueue, Connector, ConnectorError, Result, Sink};

fn default_batch_size() -> Option<usize> {
    Some(500)
}

/// Configuration for the Oracle Database SQL sink.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleSinkConfig {
    /// Oracle REST Data Services (ORDS) endpoint or SQL connection string.
    pub url: String,
    /// Oracle schema name.
    pub schema: String,
    /// Target database table name.
    pub table: String,
    /// Oracle database username.
    pub username: String,
    /// Oracle database password.
    pub password: String,
    /// Optional custom `MERGE INTO` statement override.
    #[serde(default)]
    pub custom_upsert: Option<String>,
    /// Column names serving as primary/match keys.
    #[serde(default)]
    pub key_columns: Vec<String>,
    /// Batch flush size (unbounded scale, default 500).
    #[serde(default = "default_batch_size")]
    pub batch_size: Option<usize>,
    /// In-memory queue buffer capacity (`None` = unbounded).
    #[serde(default)]
    pub buffer_capacity: Option<usize>,
    /// HTTP request / connect timeout in ms (default 5000).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

impl OracleSinkConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.unwrap_or(5000).max(1))
    }

    pub fn validate(&self) -> Result<()> {
        if self.url.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "oracle url cannot be empty".into(),
            ));
        }
        if self.schema.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "oracle schema cannot be empty".into(),
            ));
        }
        if self.table.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "oracle table cannot be empty".into(),
            ));
        }
        if self.username.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "oracle username cannot be empty".into(),
            ));
        }
        if self.custom_upsert.is_none() && self.key_columns.is_empty() {
            return Err(ConnectorError::Dispatch(
                "oracle sink requires key_columns when custom_upsert is not provided".into(),
            ));
        }
        Ok(())
    }

    pub fn basic_auth_header(&self) -> String {
        let creds = format!("{}:{}", self.username, self.password);
        let encoded = base64::engine::general_purpose::STANDARD.encode(creds.as_bytes());
        format!("Basic {encoded}")
    }
}

/// Typed Oracle bind parameter values.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OracleValue {
    Null,
    String(String),
    Number(f64),
    Integer(i64),
    Boolean(bool),
}

impl OracleValue {
    pub fn data_type_hint(&self) -> &'static str {
        match self {
            Self::Null => "VARCHAR2",
            Self::String(_) => "VARCHAR2",
            Self::Number(_) | Self::Integer(_) => "NUMBER",
            Self::Boolean(_) => "NUMBER",
        }
    }
}

/// A positional Oracle bind parameter.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OracleBindParam {
    pub name: String,
    pub value: OracleValue,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_type: Option<String>,
}

/// Result returned from Oracle SQL execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleResponse {
    pub rows_affected: usize,
    pub status: String,
    #[serde(default)]
    pub error_code: Option<String>,
    #[serde(default)]
    pub error_message: Option<String>,
}

/// ORA error classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OraErrorClassification {
    /// Retryable error (e.g. deadlock, EOF, shutdown in progress).
    Retryable,
    /// Terminal error (e.g. missing table, invalid login credentials, syntax error).
    Terminal,
    /// Unknown or generic error.
    Unknown,
}

/// Classify an Oracle error code (e.g. "ORA-00060").
pub fn classify_ora_error(error_code_or_msg: &str) -> OraErrorClassification {
    let text = error_code_or_msg.to_ascii_uppercase();
    if text.contains("ORA-00060")
        || text.contains("ORA-01033")
        || text.contains("ORA-03113")
        || text.contains("ORA-03114")
        || text.contains("ORA-01089")
    {
        OraErrorClassification::Retryable
    } else if text.contains("ORA-00942")
        || text.contains("ORA-01017")
        || text.contains("ORA-00904")
        || text.contains("ORA-00911")
        || text.contains("ORA-00001")
    {
        OraErrorClassification::Terminal
    } else {
        OraErrorClassification::Unknown
    }
}

/// Build an atomic Oracle `MERGE INTO` SQL statement.
pub fn build_merge_sql(
    table: &str,
    key_columns: &[String],
    all_columns: &[String],
) -> Result<String> {
    if key_columns.is_empty() {
        return Err(ConnectorError::Dispatch(
            "cannot build MERGE INTO without key_columns".into(),
        ));
    }
    if all_columns.is_empty() {
        return Err(ConnectorError::Dispatch(
            "cannot build MERGE INTO without all_columns".into(),
        ));
    }

    // USING (SELECT :1 AS c1, :2 AS c2 FROM DUAL) s
    let dual_selects: Vec<String> = all_columns
        .iter()
        .enumerate()
        .map(|(idx, col)| format!(":{} AS {}", idx + 1, col))
        .collect();

    // ON (t.k1 = s.k1 AND t.k2 = s.k2)
    let on_clauses: Vec<String> = key_columns
        .iter()
        .map(|k| format!("t.{} = s.{}", k, k))
        .collect();

    // Non-key columns for UPDATE SET
    let update_sets: Vec<String> = all_columns
        .iter()
        .filter(|c| !key_columns.contains(c))
        .map(|c| format!("t.{} = s.{}", c, c))
        .collect();

    // INSERT (col1, col2) VALUES (s.col1, s.col2)
    let insert_cols: Vec<String> = all_columns.to_vec();
    let insert_vals: Vec<String> = all_columns.iter().map(|c| format!("s.{}", c)).collect();

    let mut sql = format!(
        "MERGE INTO {} t\nUSING (SELECT {} FROM DUAL) s\nON ({})\n",
        table,
        dual_selects.join(", "),
        on_clauses.join(" AND ")
    );

    if !update_sets.is_empty() {
        sql.push_str(&format!(
            "WHEN MATCHED THEN UPDATE SET {}\n",
            update_sets.join(", ")
        ));
    }
    sql.push_str(&format!(
        "WHEN NOT MATCHED THEN INSERT ({}) VALUES ({})",
        insert_cols.join(", "),
        insert_vals.join(", ")
    ));

    Ok(sql)
}

/// Extracted row for Oracle sink ingestion.
#[derive(Debug, Clone)]
pub struct OracleRow {
    pub topic: String,
    pub columns: Vec<(String, OracleValue)>,
}

/// Convert arbitrary JSON value to `OracleValue`.
pub fn json_to_oracle_value(val: &serde_json::Value) -> OracleValue {
    match val {
        serde_json::Value::Null => OracleValue::Null,
        serde_json::Value::Bool(b) => OracleValue::Boolean(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                OracleValue::Integer(i)
            } else if let Some(f) = n.as_f64() {
                OracleValue::Number(f)
            } else {
                OracleValue::String(n.to_string())
            }
        }
        serde_json::Value::String(s) => OracleValue::String(s.clone()),
        other => OracleValue::String(other.to_string()),
    }
}

/// Extract columns and values from JSON payload for Oracle insertion.
pub fn extract_oracle_row(payload: &[u8], topic: &str) -> Result<OracleRow> {
    let json_val: serde_json::Value = serde_json::from_slice(payload)
        .map_err(|e| ConnectorError::Dispatch(format!("invalid JSON payload: {e}")))?;

    let mut columns = Vec::new();
    if let serde_json::Value::Object(map) = json_val {
        for (k, v) in map {
            columns.push((k, json_to_oracle_value(&v)));
        }
    } else {
        columns.push(("payload".to_string(), json_to_oracle_value(&json_val)));
    }

    Ok(OracleRow {
        topic: topic.to_string(),
        columns,
    })
}

/// Transport abstraction for executing Oracle SQL.
#[async_trait]
pub trait OracleTransport: Send + Sync {
    async fn execute(&self, statement: &str, binds: &[OracleBindParam]) -> Result<OracleResponse>;
}

/// Production HTTP transport connecting to Oracle REST Data Services (ORDS).
pub struct HttpOracleTransport {
    client: reqwest::Client,
    url: String,
    auth_header: String,
}

impl HttpOracleTransport {
    pub fn new(config: &OracleSinkConfig) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(config.timeout())
                .build()
                .unwrap_or_default(),
            url: config.url.clone(),
            auth_header: config.basic_auth_header(),
        }
    }
}

#[async_trait]
impl OracleTransport for HttpOracleTransport {
    async fn execute(&self, statement: &str, binds: &[OracleBindParam]) -> Result<OracleResponse> {
        let body = serde_json::json!({
            "statementText": statement,
            "binds": binds
        });

        let resp = self
            .client
            .post(&self.url)
            .header(AUTHORIZATION, &self.auth_header)
            .header(CONTENT_TYPE, "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| ConnectorError::Connection(format!("oracle http request failed: {e}")))?;

        let status = resp.status();
        let body_text = resp
            .text()
            .await
            .unwrap_or_else(|_| "no response body".into());

        if status.is_success() {
            Ok(OracleResponse {
                rows_affected: 1,
                status: "SUCCESS".into(),
                error_code: None,
                error_message: None,
            })
        } else {
            let classification = classify_ora_error(&body_text);
            match classification {
                OraErrorClassification::Retryable => Err(ConnectorError::Connection(format!(
                    "transient oracle error: {body_text}"
                ))),
                _ => Err(ConnectorError::Dispatch(format!(
                    "terminal oracle error: {body_text}"
                ))),
            }
        }
    }
}

/// Captured execution for testing and mock transports.
#[derive(Debug, Clone)]
pub struct CapturedOracleExecution {
    pub statement: String,
    pub binds: Vec<OracleBindParam>,
}

/// Mock transport for unit testing and offline verification.
pub struct MockOracleTransport {
    pub executions: Mutex<Vec<CapturedOracleExecution>>,
    pub fail_count: Mutex<usize>,
    pub outcome_code: Mutex<Option<String>>,
}

impl MockOracleTransport {
    pub fn new() -> Self {
        Self {
            executions: Mutex::new(Vec::new()),
            fail_count: Mutex::new(0),
            outcome_code: Mutex::new(None),
        }
    }

    pub fn with_transient_failures(failures: usize, ora_code: &str) -> Self {
        Self {
            executions: Mutex::new(Vec::new()),
            fail_count: Mutex::new(failures),
            outcome_code: Mutex::new(Some(ora_code.to_string())),
        }
    }
}

impl Default for MockOracleTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl OracleTransport for MockOracleTransport {
    async fn execute(&self, statement: &str, binds: &[OracleBindParam]) -> Result<OracleResponse> {
        self.executions.lock().push(CapturedOracleExecution {
            statement: statement.to_string(),
            binds: binds.to_vec(),
        });

        let mut fails = self.fail_count.lock();
        if *fails > 0 {
            *fails -= 1;
            let code = self
                .outcome_code
                .lock()
                .clone()
                .unwrap_or_else(|| "ORA-00060".into());
            let class = classify_ora_error(&code);
            if class == OraErrorClassification::Retryable {
                return Err(ConnectorError::Connection(format!(
                    "mock transient error: {code}"
                )));
            } else {
                return Err(ConnectorError::Dispatch(format!(
                    "mock terminal error: {code}"
                )));
            }
        }

        Ok(OracleResponse {
            rows_affected: 1,
            status: "SUCCESS".into(),
            error_code: None,
            error_message: None,
        })
    }
}

/// Oracle Database SQL Sink.
pub struct OracleSink {
    config: OracleSinkConfig,
    transport: Arc<dyn OracleTransport>,
    queue: Mutex<BatchQueue<OracleRow>>,
    backoff: Mutex<BackoffState>,
    sent: AtomicU64,
}

impl OracleSink {
    pub fn new(config: OracleSinkConfig, transport: Arc<dyn OracleTransport>) -> Result<Self> {
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

    pub fn config(&self) -> &OracleSinkConfig {
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

        for row in &rows {
            let (statement, binds) = if let Some(ref custom) = self.config.custom_upsert {
                let binds: Vec<OracleBindParam> = row
                    .columns
                    .iter()
                    .enumerate()
                    .map(|(idx, (_, val))| OracleBindParam {
                        name: (idx + 1).to_string(),
                        value: val.clone(),
                        data_type: Some(val.data_type_hint().to_string()),
                    })
                    .collect();
                (custom.clone(), binds)
            } else {
                let all_cols: Vec<String> = row.columns.iter().map(|(c, _)| c.clone()).collect();
                let stmt =
                    build_merge_sql(&self.config.table, &self.config.key_columns, &all_cols)?;
                let binds: Vec<OracleBindParam> = row
                    .columns
                    .iter()
                    .enumerate()
                    .map(|(idx, (_, val))| OracleBindParam {
                        name: (idx + 1).to_string(),
                        value: val.clone(),
                        data_type: Some(val.data_type_hint().to_string()),
                    })
                    .collect();
                (stmt, binds)
            };

            match self.transport.execute(&statement, &binds).await {
                Ok(_) => {
                    self.backoff.lock().success();
                    self.sent.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    self.backoff.lock().failure();
                    self.queue.lock().restore(rows, oldest);
                    return Err(e);
                }
            }
        }

        Ok(())
    }
}

#[async_trait]
impl Sink for OracleSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, _qos: QoS) -> Result<()> {
        let row = extract_oracle_row(payload, topic.as_str())?;
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
        "oracle"
    }
}

/// Addressable registered connector for Oracle Database.
pub struct OracleConnector {
    id: String,
    sink: Arc<OracleSink>,
}

impl OracleConnector {
    pub fn new(id: impl Into<String>, sink: Arc<OracleSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }

    pub fn sink(&self) -> Arc<OracleSink> {
        self.sink.clone()
    }
}

impl Connector for OracleConnector {
    fn connector_id(&self) -> &str {
        &self.id
    }

    fn kind(&self) -> &'static str {
        "oracle"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> OracleSinkConfig {
        OracleSinkConfig {
            url: "https://oracle-host:8080/ords/hr/_/sql".to_string(),
            schema: "HR".to_string(),
            table: "TELEMETRY".to_string(),
            username: "c##appuser".to_string(),
            password: "SecretPassword123!".to_string(),
            custom_upsert: None,
            key_columns: vec!["device_id".to_string()],
            batch_size: Some(1),
            buffer_capacity: None,
            timeout_ms: None,
        }
    }

    #[test]
    fn test_merge_sql_builder() {
        let keys = vec!["device_id".to_string()];
        let cols = vec![
            "device_id".to_string(),
            "temp".to_string(),
            "ts".to_string(),
        ];
        let sql = build_merge_sql("TELEMETRY", &keys, &cols).expect("valid merge sql");
        assert!(sql.starts_with("MERGE INTO TELEMETRY t"));
        assert!(sql.contains("USING (SELECT :1 AS device_id, :2 AS temp, :3 AS ts FROM DUAL) s"));
        assert!(sql.contains("ON (t.device_id = s.device_id)"));
        assert!(sql.contains("WHEN MATCHED THEN UPDATE SET t.temp = s.temp, t.ts = s.ts"));
        assert!(sql.contains(
            "WHEN NOT MATCHED THEN INSERT (device_id, temp, ts) VALUES (s.device_id, s.temp, s.ts)"
        ));
    }

    #[test]
    fn test_custom_upsert_override() {
        let mut cfg = sample_config();
        cfg.custom_upsert = Some("MERGE INTO CUSTOM_TABLE ...".to_string());
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_basic_auth_header() {
        let cfg = sample_config();
        let header = cfg.basic_auth_header();
        assert!(header.starts_with("Basic "));
        let b64 = &header["Basic ".len()..];
        let decoded = String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(b64)
                .expect("valid base64"),
        )
        .expect("utf8 string");
        assert_eq!(decoded, "c##appuser:SecretPassword123!");
    }

    #[test]
    fn test_classify_ora_errors() {
        // Retryable
        assert_eq!(
            classify_ora_error("ORA-00060: deadlock detected"),
            OraErrorClassification::Retryable
        );
        assert_eq!(
            classify_ora_error("ORA-01033: ORACLE initialization in progress"),
            OraErrorClassification::Retryable
        );
        assert_eq!(
            classify_ora_error("ORA-03113: end-of-file on communication channel"),
            OraErrorClassification::Retryable
        );

        // Terminal
        assert_eq!(
            classify_ora_error("ORA-00942: table or view does not exist"),
            OraErrorClassification::Terminal
        );
        assert_eq!(
            classify_ora_error("ORA-01017: invalid username/password"),
            OraErrorClassification::Terminal
        );
        assert_eq!(
            classify_ora_error("ORA-00001: unique constraint violated"),
            OraErrorClassification::Terminal
        );

        // Unknown
        assert_eq!(
            classify_ora_error("Some random error"),
            OraErrorClassification::Unknown
        );
    }

    #[test]
    fn test_json_to_oracle_primitives() {
        let v_null = json_to_oracle_value(&serde_json::Value::Null);
        assert_eq!(v_null, OracleValue::Null);

        let v_int = json_to_oracle_value(&serde_json::json!(42));
        assert_eq!(v_int, OracleValue::Integer(42));
        assert_eq!(v_int.data_type_hint(), "NUMBER");

        let v_float = json_to_oracle_value(&serde_json::json!(23.75));
        assert_eq!(v_float, OracleValue::Number(23.75));

        let v_str = json_to_oracle_value(&serde_json::json!("sensor-alpha"));
        assert_eq!(v_str, OracleValue::String("sensor-alpha".into()));
        assert_eq!(v_str.data_type_hint(), "VARCHAR2");

        let v_bool = json_to_oracle_value(&serde_json::json!(true));
        assert_eq!(v_bool, OracleValue::Boolean(true));
    }

    #[test]
    fn test_row_extraction_nested_or_object() {
        let payload = br#"{"device_id": "d-101", "temp": 72.4, "active": true}"#;
        let row = extract_oracle_row(payload, "factory/sensor1").expect("valid row");
        assert_eq!(row.columns.len(), 3);
        let id_val = row.columns.iter().find(|(k, _)| k == "device_id").unwrap();
        assert_eq!(id_val.1, OracleValue::String("d-101".into()));
    }

    #[tokio::test]
    async fn test_oracle_sink_loopback_success() {
        let cfg = sample_config();
        let transport = Arc::new(MockOracleTransport::new());
        let sink = OracleSink::new(cfg, transport.clone()).expect("valid sink");

        let topic = Topic::new("sensors/temp").unwrap();
        let payload = Bytes::from_static(br#"{"device_id": "dev-01", "temp": 85.5}"#);

        sink.send(&topic, &payload, QoS::AtLeastOnce)
            .await
            .expect("send succeeds");

        let execs = transport.executions.lock();
        assert_eq!(execs.len(), 1);
        assert!(execs[0].statement.contains("MERGE INTO TELEMETRY t"));
        assert_eq!(execs[0].binds.len(), 2);
        assert_eq!(sink.sent_count(), 1);
    }

    #[tokio::test]
    async fn test_oracle_sink_retryable_deadlock_handling() {
        let cfg = sample_config();
        // 1 transient failure (ORA-00060) then success
        let transport = Arc::new(MockOracleTransport::with_transient_failures(1, "ORA-00060"));
        let sink = OracleSink::new(cfg, transport.clone()).expect("valid sink");

        let topic = Topic::new("sensors/temp").unwrap();
        let payload = Bytes::from_static(br#"{"device_id": "dev-02", "temp": 91.0}"#);

        // First attempt fails with Connection error (transient)
        let res = sink.send(&topic, &payload, QoS::AtLeastOnce).await;
        assert!(res.is_err());
        assert!(matches!(res.err().unwrap(), ConnectorError::Connection(_)));

        // Reset backoff to simulate time passage
        *sink.backoff.lock() = BackoffState::default();

        // Flush restores rows and succeeds on next attempt
        sink.flush().await.expect("retry succeeds");
        assert_eq!(sink.sent_count(), 1);
    }

    #[tokio::test]
    async fn test_backoff_keeps_buffered_rows() {
        let mut cfg = sample_config();
        cfg.batch_size = Some(10);
        let transport = Arc::new(MockOracleTransport::with_transient_failures(1, "ORA-00060"));
        let sink = OracleSink::new(cfg, transport.clone()).expect("valid sink");

        let topic = Topic::new("sensors/temp").unwrap();
        let payload1 = Bytes::from_static(br#"{"device_id": "dev-10", "temp": 70.0}"#);
        let payload2 = Bytes::from_static(br#"{"device_id": "dev-11", "temp": 71.0}"#);

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
        assert_eq!(execs.len(), 3);
        assert_eq!(execs[1].binds.len(), 2);
        assert_eq!(execs[2].binds.len(), 2);
    }
}
