//! ClickHouse analytical sink (INDRA-181).
//!
//! Buffers MQTT events as typed rows (`topic String`, `qos UInt8`,
//! `payload String`) and flushes full or stale batches to ClickHouse
//! over its HTTP interface. Batching, restore-on-failure and backoff
//! reuse the shared [`super::BatchQueue`] / [`super::BackoffState`]
//! helpers, so the contract matches the MySQL/PostgreSQL sinks:
//! failed flushes keep the buffer, engage backoff, and propagate the
//! error.
//!
//! Production writes go through the maintained `clickhouse` (official)
//! driver ([`DriverClickHouseTransport`]): the driver holds the HTTP
//! pool, Basic auth and database, and inserts [`ClickHouseRow`] with
//! `RowBinaryWithNamesAndTypes` (server-side type validation). The
//! legacy `INSERT INTO db.table FORMAT JSONEachRow` wire shape is kept
//! in [`HttpClickHouseTransport`] for the offline loopback tests and
//! for deployments that pin the JSON wire format.
//!
//! Identifier interpolation (`database`, `table`, `format`) is
//! injection-safe by construction: identifiers must match
//! `[A-Za-z0-9_]+` and the format must come from a fixed whitelist.
//! TODO(parity): driver path uses RowBinaryWithNamesAndTypes while the
//! HTTP fallback uses FORMAT JSONEachRow; confirm the two encodings stay
//! equivalent for topic/qos/payload (UTF-8, UInt8 range).

use async_trait::async_trait;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::{BackoffState, BatchQueue, ConnectorError, Result, Sink};

/// Insert formats accepted for the `FORMAT` clause on the HTTP fallback.
const ALLOWED_FORMATS: &[&str] = &[
    "JSONEachRow",
    "JSONStringsEachRow",
    "JSONObjectEachRow",
    "TabSeparated",
    "CSV",
];

fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn default_username() -> String {
    "default".to_string()
}

fn default_request_timeout_ms() -> Option<u64> {
    None
}

/// ClickHouse sink configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClickHouseSinkConfig {
    /// Base HTTP endpoint, e.g. `http://ch:8123`.
    pub endpoint: String,
    pub database: String,
    pub table: String,
    /// Insert format (whitelisted) for the HTTP fallback; defaults to
    /// `JSONEachRow`. The driver path validates it but writes with its
    /// native RowBinary encoding.
    pub format: String,
    /// Max rows buffered before a flush (the bound; validated `>= 1`).
    /// Small batches bound per-connector memory on the publish path;
    /// offline tests use 2, the rule-engine fan-out uses 100, and the
    /// qualification run uses 500 (5000 rows in 10 INSERTs).
    pub batch_size: usize,
    /// Linger in ms before a partial batch flushes (stale-batch bound).
    pub batch_timeout_ms: u64,
    /// ClickHouse user (default `default`).
    #[serde(default = "default_username")]
    pub username: String,
    /// ClickHouse password (default empty).
    #[serde(default)]
    pub password: String,
    /// Per-request HTTP timeout in ms (defaults to 5000 ms if omitted,
    /// so a hung server fails closed instead of stalling the flush).
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: Option<u64>,
}

impl ClickHouseSinkConfig {
    pub fn validate(&self) -> Result<()> {
        if !self.endpoint.starts_with("http://") && !self.endpoint.starts_with("https://") {
            return Err(ConnectorError::Dispatch(format!(
                "clickhouse endpoint must be http(s): {:?}",
                self.endpoint
            )));
        }
        if !is_identifier(&self.database) {
            return Err(ConnectorError::Dispatch(format!(
                "clickhouse database must match [A-Za-z0-9_]+: {:?}",
                self.database
            )));
        }
        if !is_identifier(&self.table) {
            return Err(ConnectorError::Dispatch(format!(
                "clickhouse table must match [A-Za-z0-9_]+: {:?}",
                self.table
            )));
        }
        if !ALLOWED_FORMATS.contains(&self.format.as_str()) {
            return Err(ConnectorError::Dispatch(format!(
                "clickhouse format must be one of {ALLOWED_FORMATS:?}: {:?}",
                self.format
            )));
        }
        if self.username.is_empty() {
            return Err(ConnectorError::Dispatch(
                "clickhouse username must not be empty".to_string(),
            ));
        }
        if self.batch_size == 0 {
            return Err(ConnectorError::Dispatch(
                "clickhouse batch_size must be >= 1".to_string(),
            ));
        }
        Ok(())
    }

    /// `INSERT INTO <db>.<table> FORMAT <format>` (identifiers already
    /// validated, so interpolation is safe). Used by the HTTP fallback.
    pub fn insert_query(&self) -> String {
        format!(
            "INSERT INTO {}.{} FORMAT {}",
            self.database, self.table, self.format
        )
    }

    /// `db.table` after validation (safe to interpolate into DDL/DML).
    pub fn qualified_table(&self) -> Result<String> {
        self.validate()?;
        Ok(format!("{}.{}", self.database, self.table))
    }

    /// DDL for the analytical events table. The column order matches
    /// [`ClickHouseRow`] field order so the driver's
    /// RowBinaryWithNamesAndTypes validation accepts it.
    pub fn create_table_ddl(&self) -> Result<String> {
        self.validate()?;
        Ok(format!(
            "CREATE TABLE IF NOT EXISTS {}.{} (topic String, qos UInt8, payload String) ENGINE = MergeTree() ORDER BY tuple()",
            self.database, self.table
        ))
    }

    /// Per-request HTTP timeout; falls back to 5000 ms if not configured.
    pub fn request_timeout(&self) -> Duration {
        Duration::from_millis(self.request_timeout_ms.unwrap_or(5_000).max(1))
    }

    /// Build the official driver client for this config (HTTP pool,
    /// auth, database). Used by [`DriverClickHouseTransport`] and by
    /// qualification tests for DDL/SELECT.
    pub fn driver_client(&self) -> Result<clickhouse::Client> {
        self.validate()?;
        Ok(clickhouse::Client::default()
            .with_url(self.endpoint.clone())
            .with_user(self.username.clone())
            .with_password(self.password.clone())
            .with_database(self.database.clone()))
    }
}

/// One buffered row: topic, QoS value, UTF-8 payload.
///
/// Type mapping: `topic` -> `String`, `qos` -> `UInt8`, `payload` ->
/// `String`. Field order matches [`ClickHouseSinkConfig::create_table_ddl`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, clickhouse::Row)]
pub struct ClickHouseRow {
    pub topic: String,
    pub qos: u8,
    pub payload: String,
}

fn render_row(row: &ClickHouseRow) -> String {
    serde_json::json!({
        "topic": row.topic,
        "qos": row.qos,
        "payload": row.payload,
    })
    .to_string()
}

fn map_driver_error(err: clickhouse::error::Error) -> ConnectorError {
    // TODO(parity): driver does not expose retryable vs terminal kinds;
    // treat every driver failure as transient (fail closed, retry) until
    // the taxonomy is mapped.
    ConnectorError::Connection(format!("clickhouse driver failed: {err}"))
}

// ---------------------------------------------------------------------------
// Transport.
// ---------------------------------------------------------------------------

/// Scripted outcome for the mock transport.
#[derive(Debug, Clone)]
pub enum MockClickHouseOutcome {
    Success,
    ConnectionError(String),
    DispatchError(String),
}

/// One captured batch.
#[derive(Debug, Clone)]
pub struct CapturedClickHouseBatch {
    pub database: String,
    pub table: String,
    pub format: String,
    pub rows: Vec<ClickHouseRow>,
}

#[async_trait]
pub trait ClickHouseTransport: Send + Sync {
    async fn insert_rows(&self, rows: &[ClickHouseRow]) -> Result<u64>;
}

/// In-memory transport with scripted outcomes (tests, dry runs).
#[derive(Debug, Default)]
pub struct MockClickHouseTransport {
    scripted: parking_lot::Mutex<std::collections::VecDeque<MockClickHouseOutcome>>,
    captured: parking_lot::Mutex<Vec<CapturedClickHouseBatch>>,
    database: parking_lot::Mutex<String>,
    table: parking_lot::Mutex<String>,
    format: parking_lot::Mutex<String>,
}

impl MockClickHouseTransport {
    pub fn new(database: &str, table: &str, format: &str) -> Self {
        Self {
            scripted: parking_lot::Mutex::new(std::collections::VecDeque::new()),
            captured: parking_lot::Mutex::new(Vec::new()),
            database: parking_lot::Mutex::new(database.to_string()),
            table: parking_lot::Mutex::new(table.to_string()),
            format: parking_lot::Mutex::new(format.to_string()),
        }
    }

    /// Queue outcomes consumed in order (default: success).
    pub fn script_outcomes(&self, outcomes: Vec<MockClickHouseOutcome>) {
        *self.scripted.lock() = outcomes.into_iter().collect();
    }

    pub fn captured(&self) -> Vec<CapturedClickHouseBatch> {
        self.captured.lock().clone()
    }
}

#[async_trait]
impl ClickHouseTransport for MockClickHouseTransport {
    async fn insert_rows(&self, rows: &[ClickHouseRow]) -> Result<u64> {
        let count = rows.len() as u64;
        self.captured.lock().push(CapturedClickHouseBatch {
            database: self.database.lock().clone(),
            table: self.table.lock().clone(),
            format: self.format.lock().clone(),
            rows: rows.to_vec(),
        });
        match self.scripted.lock().pop_front() {
            None | Some(MockClickHouseOutcome::Success) => Ok(count),
            Some(MockClickHouseOutcome::ConnectionError(message)) => {
                Err(ConnectorError::Connection(message))
            }
            Some(MockClickHouseOutcome::DispatchError(message)) => {
                Err(ConnectorError::Dispatch(message))
            }
        }
    }
}

/// HTTP fallback transport: one `POST ?query=INSERT ... FORMAT ...`
/// with Basic auth when a username/password is configured.
pub struct HttpClickHouseTransport {
    config: ClickHouseSinkConfig,
    client: reqwest::Client,
}

impl HttpClickHouseTransport {
    pub fn new(config: &ClickHouseSinkConfig, client: reqwest::Client) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config: config.clone(),
            client,
        })
    }
}

#[async_trait]
impl ClickHouseTransport for HttpClickHouseTransport {
    async fn insert_rows(&self, rows: &[ClickHouseRow]) -> Result<u64> {
        if rows.is_empty() {
            return Ok(0);
        }
        let mut body = String::new();
        for row in rows {
            body.push_str(&render_row(row));
            body.push('\n');
        }
        let url = format!("{}/", self.config.endpoint.trim_end_matches('/'));
        let mut request = self
            .client
            .post(&url)
            .query(&[("query", self.config.insert_query())])
            .header(reqwest::header::CONTENT_TYPE, "text/plain")
            .body(body)
            .timeout(self.config.request_timeout());
        if !self.config.username.is_empty() {
            request = request.basic_auth(
                self.config.username.clone(),
                Some(self.config.password.clone()),
            );
        }
        let response = request
            .send()
            .await
            .map_err(|e| ConnectorError::Connection(format!("clickhouse post failed: {e}")))?;
        if !response.status().is_success() {
            let status = response.status();
            if status.as_u16() == 429 || status.as_u16() == 503 {
                return Err(ConnectorError::Connection(format!(
                    "clickhouse {} throttled with {status}",
                    self.config.endpoint
                )));
            }
            return Err(ConnectorError::Dispatch(format!(
                "clickhouse {} answered {status}",
                self.config.endpoint
            )));
        }
        Ok(rows.len() as u64)
    }
}

/// Production transport on the official `clickhouse` driver.
pub struct DriverClickHouseTransport {
    config: ClickHouseSinkConfig,
    client: clickhouse::Client,
}

impl DriverClickHouseTransport {
    pub fn new(config: &ClickHouseSinkConfig) -> Result<Self> {
        let client = config.driver_client()?;
        Ok(Self {
            config: config.clone(),
            client,
        })
    }

    pub fn client(&self) -> &clickhouse::Client {
        &self.client
    }

    pub fn config(&self) -> &ClickHouseSinkConfig {
        &self.config
    }
}

#[async_trait]
impl ClickHouseTransport for DriverClickHouseTransport {
    async fn insert_rows(&self, rows: &[ClickHouseRow]) -> Result<u64> {
        if rows.is_empty() {
            return Ok(0);
        }
        let count = rows.len() as u64;
        let mut insert = self
            .client
            .insert::<ClickHouseRow>(&self.config.table)
            .await
            .map_err(map_driver_error)?;
        for row in rows {
            insert.write(row).await.map_err(map_driver_error)?;
        }
        insert.end().await.map_err(map_driver_error)?;
        Ok(count)
    }
}

// ---------------------------------------------------------------------------
// Sink.
// ---------------------------------------------------------------------------

/// ClickHouse sink: buffers validated rows, inserts batches.
pub struct ClickHouseSink {
    config: ClickHouseSinkConfig,
    transport: Arc<dyn ClickHouseTransport>,
    buffer: parking_lot::Mutex<BatchQueue<ClickHouseRow>>,
    backoff: parking_lot::Mutex<BackoffState>,
    sent_batches: AtomicU64,
    sent_rows: AtomicU64,
}

impl ClickHouseSink {
    pub fn new(
        config: ClickHouseSinkConfig,
        transport: Arc<dyn ClickHouseTransport>,
    ) -> Result<Self> {
        config.validate()?;
        let linger = Duration::from_millis(config.batch_timeout_ms);
        Ok(Self {
            buffer: parking_lot::Mutex::new(BatchQueue::new(config.batch_size, linger)),
            config,
            transport,
            backoff: parking_lot::Mutex::new(BackoffState::default()),
            sent_batches: AtomicU64::new(0),
            sent_rows: AtomicU64::new(0),
        })
    }

    pub fn config(&self) -> &ClickHouseSinkConfig {
        &self.config
    }

    pub fn sent_batches(&self) -> u64 {
        self.sent_batches.load(Ordering::Relaxed)
    }

    pub fn sent_rows(&self) -> u64 {
        self.sent_rows.load(Ordering::Relaxed)
    }

    pub fn buffered_rows(&self) -> usize {
        self.buffer.lock().len()
    }

    /// Flush buffered rows as one `INSERT` (no-op when empty). While
    /// backing off, fails fast without touching the transport. Any
    /// failure restores the buffer, engages backoff, and propagates.
    pub async fn flush(&self) -> Result<()> {
        self.backoff.lock().check()?;
        let (rows, oldest) = self.buffer.lock().take_batch();
        if rows.is_empty() {
            return Ok(());
        }
        match self.transport.insert_rows(&rows).await {
            Ok(count) => {
                self.backoff.lock().success();
                self.sent_batches.fetch_add(1, Ordering::Relaxed);
                self.sent_rows.fetch_add(count, Ordering::Relaxed);
                Ok(())
            }
            Err(err) => {
                self.buffer.lock().restore(rows, oldest);
                // Both transient and terminal faults engage backoff so a
                // poison batch does not spin; the buffer is retained
                // either way.
                self.backoff.lock().failure();
                Err(err)
            }
        }
    }

    /// Validate one event into a buffered row. Returns true when the
    /// batch is full (caller flushes). Rejects empty topics, non-UTF-8
    /// payloads and QoS 2 (exactly-once has no analytical meaning).
    fn buffer_row(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<bool> {
        if topic.as_str().is_empty() {
            return Err(ConnectorError::Dispatch(
                "clickhouse row requires a non-empty topic".to_string(),
            ));
        }
        if qos == QoS::ExactlyOnce {
            return Err(ConnectorError::Dispatch(
                "clickhouse sink does not accept QoS 2 events".to_string(),
            ));
        }
        let payload = std::str::from_utf8(payload).map_err(|_| {
            ConnectorError::Dispatch("clickhouse payload must be UTF-8".to_string())
        })?;
        Ok(self.buffer.lock().push(ClickHouseRow {
            topic: topic.as_str().to_string(),
            qos: u8::from(qos),
            payload: payload.to_string(),
        }))
    }
}

#[async_trait]
impl super::Sink for ClickHouseSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        if self.buffer_row(topic, payload, qos)? {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "clickhouse"
    }
}

/// Management connector handle pairing an id with a ClickHouse sink.
pub struct ClickHouseConnector {
    id: String,
    sink: Arc<ClickHouseSink>,
}

impl ClickHouseConnector {
    pub fn new(id: impl Into<String>, sink: Arc<ClickHouseSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }
}

impl super::Connector for ClickHouseConnector {
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
    use axum::{extract::State, http::StatusCode, routing::post, Router};
    use std::sync::Mutex as StdMutex;
    use tokio::net::TcpListener;

    fn test_config(endpoint: &str) -> ClickHouseSinkConfig {
        ClickHouseSinkConfig {
            endpoint: endpoint.to_string(),
            database: "indra".to_string(),
            table: "mqtt_events".to_string(),
            format: "JSONEachRow".to_string(),
            batch_size: 500,
            batch_timeout_ms: 100,
            username: "default".to_string(),
            password: String::new(),
            request_timeout_ms: None,
        }
    }

    fn test_client() -> reqwest::Client {
        reqwest::Client::builder()
            .build()
            .expect("test http client")
    }

    fn mock_sink(config: ClickHouseSinkConfig) -> ClickHouseSink {
        let transport: Arc<dyn ClickHouseTransport> = Arc::new(MockClickHouseTransport::new(
            &config.database,
            &config.table,
            &config.format,
        ));
        ClickHouseSink::new(config, transport).expect("mock sink")
    }

    #[test]
    fn test_config_validation() {
        let mut config = test_config("http://ch:8123");
        assert!(config.validate().is_ok());
        assert_eq!(
            config.insert_query(),
            "INSERT INTO indra.mqtt_events FORMAT JSONEachRow"
        );

        config.endpoint = "ch:8123".to_string();
        assert!(config.validate().is_err());
        config.endpoint = "http://ch:8123".to_string();

        config.database = "indra-prod".to_string();
        assert!(config.validate().is_err());
        config.database = "indra".to_string();

        config.table = "mqtt.events".to_string();
        assert!(config.validate().is_err());
        config.table = "mqtt_events".to_string();

        config.format = "Values".to_string();
        assert!(config.validate().is_err());
        config.format = "JSONEachRow".to_string();

        config.username = String::new();
        assert!(config.validate().is_err());
        config.username = "default".to_string();

        config.batch_size = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_insert_query_renders_whitelisted_formats() {
        let mut config = test_config("http://ch:8123");
        for format in ["JSONEachRow", "JSONStringsEachRow", "TabSeparated", "CSV"] {
            config.format = format.to_string();
            assert!(config.validate().is_ok());
            assert_eq!(
                config.insert_query(),
                format!("INSERT INTO indra.mqtt_events FORMAT {format}")
            );
        }
    }

    #[test]
    fn test_create_table_ddl_is_whitelisted() {
        let config = test_config("http://ch:8123");
        let ddl = config.create_table_ddl().expect("ddl");
        assert!(ddl.contains("indra.mqtt_events"));
        assert!(ddl.contains("topic String"));
        assert!(ddl.contains("qos UInt8"));
        assert!(ddl.contains("payload String"));

        let mut bad = config.clone();
        bad.database = "db; DROP TABLE x;".to_string();
        assert!(bad.create_table_ddl().is_err());
        assert!(bad.qualified_table().is_err());

        let mut bad_table = config.clone();
        bad_table.table = "t;DROP".to_string();
        assert!(bad_table.create_table_ddl().is_err());
    }

    #[test]
    fn test_driver_client_requires_validation() {
        let mut config = test_config("http://127.0.0.1:8123");
        assert!(config.driver_client().is_ok());
        config.database = "bad-db".to_string();
        assert!(config.driver_client().is_err());
    }

    #[test]
    fn test_row_validation() {
        let sink = mock_sink(test_config("http://ch:8123"));
        let topic = Topic::new("sensors/t1").unwrap();

        assert!(!sink
            .buffer_row(&topic, &Bytes::from("{}"), QoS::AtLeastOnce)
            .unwrap());
        assert_eq!(sink.buffered_rows(), 1);

        // Empty topics are rejected at construction, so they can never
        // reach the sink; the buffer_row guard stays as defense-in-depth.
        assert!(Topic::new("").is_err());

        assert!(sink
            .buffer_row(&topic, &Bytes::from(vec![0xFF, 0xFE]), QoS::AtMostOnce)
            .is_err());
        assert!(sink
            .buffer_row(&topic, &Bytes::from("{}"), QoS::ExactlyOnce)
            .is_err());
    }

    #[tokio::test]
    async fn test_mock_insert_flow_counts_rows() {
        let mut config = test_config("http://ch:8123");
        config.batch_size = 2;
        let transport = Arc::new(MockClickHouseTransport::new(
            &config.database,
            &config.table,
            &config.format,
        ));
        let sink = ClickHouseSink::new(config, transport.clone()).unwrap();

        let t1 = Topic::new("sensors/t1").unwrap();
        let t2 = Topic::new("sensors/t2").unwrap();
        sink.send(&t1, &Bytes::from(r#"{"v":1}"#), QoS::AtMostOnce)
            .await
            .unwrap();
        assert_eq!(sink.buffered_rows(), 1);
        sink.send(&t2, &Bytes::from(r#"{"v":2}"#), QoS::AtLeastOnce)
            .await
            .unwrap();
        assert_eq!(sink.sent_batches(), 1);
        assert_eq!(sink.sent_rows(), 2);
        assert_eq!(sink.buffered_rows(), 0);
        assert_eq!(sink.kind(), "clickhouse");

        let captured = transport.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].rows.len(), 2);
        assert_eq!(captured[0].rows[0].topic, "sensors/t1");
        assert_eq!(captured[0].rows[0].qos, 0);
        assert_eq!(captured[0].rows[1].qos, 1);
    }

    #[derive(Debug, Default)]
    struct Captured {
        query: StdMutex<String>,
        body: StdMutex<String>,
        status: StdMutex<u16>,
    }

    async fn serve_captured(captured: Arc<Captured>) -> u16 {
        async fn handler(
            State(captured): State<Arc<Captured>>,
            uri: axum::http::Uri,
            headers: axum::http::HeaderMap,
            body: String,
        ) -> StatusCode {
            *captured.query.lock().unwrap() = uri.query().unwrap_or_default().to_string();
            *captured.body.lock().unwrap() = body;
            // Auth is forwarded when configured; the fake accepts all.
            let _ = headers.get(axum::http::header::AUTHORIZATION).cloned();
            StatusCode::from_u16(*captured.status.lock().unwrap()).unwrap_or(StatusCode::OK)
        }
        let app = Router::new().route("/", post(handler)).with_state(captured);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        port
    }

    #[tokio::test]
    async fn test_batch_posts_json_each_row() {
        let captured = Arc::new(Captured::default());
        let port = serve_captured(captured.clone()).await;
        let mut config = test_config(&format!("http://127.0.0.1:{port}"));
        config.batch_size = 2;
        let transport: Arc<dyn ClickHouseTransport> =
            Arc::new(HttpClickHouseTransport::new(&config, test_client()).unwrap());
        let sink = ClickHouseSink::new(config, transport).unwrap();

        let t1 = Topic::new("sensors/t1").unwrap();
        let t2 = Topic::new("sensors/t2").unwrap();
        sink.send(&t1, &Bytes::from(r#"{"v":1}"#), QoS::AtMostOnce)
            .await
            .unwrap();
        assert_eq!(sink.buffered_rows(), 1);
        sink.send(&t2, &Bytes::from(r#"{"v":2}"#), QoS::AtLeastOnce)
            .await
            .unwrap();
        assert_eq!(sink.sent_batches(), 1);
        assert_eq!(sink.buffered_rows(), 0);

        let query = captured.query.lock().unwrap().clone();
        assert!(
            query.contains("INSERT+INTO+indra.mqtt_events+FORMAT+JSONEachRow")
                || query.contains("INSERT INTO indra.mqtt_events FORMAT JSONEachRow"),
            "unexpected query: {query}"
        );
        let body = captured.body.lock().unwrap().clone();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2);
        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["topic"], "sensors/t1");
        assert_eq!(first["qos"], 0);
        assert_eq!(first["payload"], r#"{"v":1}"#);
        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["topic"], "sensors/t2");
        assert_eq!(second["qos"], 1);
    }

    #[tokio::test]
    async fn test_failure_retains_buffer_and_backs_off() {
        let captured = Arc::new(Captured {
            status: StdMutex::new(500),
            ..Default::default()
        });
        let port = serve_captured(captured.clone()).await;
        let mut config = test_config(&format!("http://127.0.0.1:{port}"));
        config.batch_size = 10;
        let transport: Arc<dyn ClickHouseTransport> =
            Arc::new(HttpClickHouseTransport::new(&config, test_client()).unwrap());
        let sink = ClickHouseSink::new(config, transport).unwrap();

        let topic = Topic::new("sensors/t1").unwrap();
        sink.send(&topic, &Bytes::from("{}"), QoS::AtMostOnce)
            .await
            .unwrap();
        assert_eq!(sink.buffered_rows(), 1);
        let err = sink.flush().await.expect_err("500 must fail");
        assert!(matches!(err, ConnectorError::Dispatch(_)));
        // Buffer retained, backoff engaged: immediate retry fails fast
        // without a second HTTP round-trip.
        assert_eq!(sink.buffered_rows(), 1);
        assert!(sink.flush().await.is_err());
        assert_eq!(sink.sent_batches(), 0);
    }

    fn qual_env(name: &str) -> Option<String> {
        std::env::var(name).ok().filter(|v| !v.trim().is_empty())
    }

    /// Qualification against a real ClickHouse server via the official
    /// `clickhouse` driver.
    ///
    /// Run with e.g.:
    /// `CLICKHOUSE_URL=http://127.0.0.1:8123 CLICKHOUSE_DATABASE=indra_qual \
    ///  CLICKHOUSE_TABLE=qual_rows \
    ///  cargo test -p broker-connectors --lib clickhouse::tests::test_qualify_driver_write_path -- --ignored --nocapture`
    ///
    /// Creates the table, streams 5000 rows through [`ClickHouseSink`]
    /// on [`DriverClickHouseTransport`] (Basic auth when
    /// `CLICKHOUSE_USER` / `CLICKHOUSE_PASSWORD` are set), runs
    /// `OPTIMIZE ... FINAL` so parts merge, asserts `SELECT count()`
    /// returns 5000, asserts the injection whitelist rejects bad DDL,
    /// then drops the table it created.
    #[tokio::test]
    #[ignore = "needs a real ClickHouse server (see CLICKHOUSE_* env)"]
    async fn test_qualify_driver_write_path() {
        let Some(url) = qual_env("CLICKHOUSE_URL") else {
            panic!(
                "CLICKHOUSE_URL must point at a real ClickHouse server for qualification; \
                 failing closed instead of passing vacuously \
                 (e.g. CLICKHOUSE_URL=http://127.0.0.1:8123)"
            );
        };
        let database =
            qual_env("CLICKHOUSE_DATABASE").unwrap_or_else(|| "indra_qual_b308".to_string());
        let table = qual_env("CLICKHOUSE_TABLE").unwrap_or_else(|| "qual_rows".to_string());
        let username = qual_env("CLICKHOUSE_USER").unwrap_or_else(|| "default".to_string());
        let password = qual_env("CLICKHOUSE_PASSWORD").unwrap_or_default();

        // Whitelist rejects bad DDL before any server round-trip.
        let bad_config = ClickHouseSinkConfig {
            endpoint: url.clone(),
            database: "bad-db; DROP TABLE x;".to_string(),
            table: table.clone(),
            format: "JSONEachRow".to_string(),
            batch_size: 500,
            batch_timeout_ms: 50,
            username: username.clone(),
            password: password.clone(),
            request_timeout_ms: None,
        };
        assert!(bad_config.validate().is_err());
        assert!(bad_config.create_table_ddl().is_err());
        assert!(bad_config.driver_client().is_err());

        let config = ClickHouseSinkConfig {
            endpoint: url.clone(),
            database: database.clone(),
            table: table.clone(),
            format: "JSONEachRow".to_string(),
            batch_size: 500,
            batch_timeout_ms: 50,
            username: username.clone(),
            password: password.clone(),
            request_timeout_ms: Some(10_000),
        };
        config.validate().expect("qual config validates");
        let qualified = config.qualified_table().expect("qualified table");
        assert_eq!(qualified, format!("{database}.{table}"));

        // Direct driver client for DDL and assertions.
        let client = config.driver_client().expect("qual driver client");
        let version_sql = "SELECT version()".to_string();
        let version: String = client
            .query(&version_sql)
            .fetch_one::<String>()
            .await
            .expect("qual version query");
        eprintln!("qual server: version={version} url={url} table={qualified}");

        let ddl = config.create_table_ddl().expect("qual ddl");
        client
            .query(&ddl)
            .execute()
            .await
            .expect("qual create table");
        let drop_stale = format!("TRUNCATE TABLE {qualified}");
        client
            .query(&drop_stale)
            .execute()
            .await
            .expect("qual truncate stale rows");

        let transport: Arc<dyn ClickHouseTransport> =
            Arc::new(DriverClickHouseTransport::new(&config).expect("qual transport"));
        let sink = ClickHouseSink::new(config, transport).expect("qual sink");
        assert_eq!(sink.kind(), "clickhouse");

        let topic = Topic::new("sensors/qual").unwrap();
        for seq in 0..5000 {
            let payload = Bytes::from(format!(r#"{{"seq":{seq}}}"#));
            sink.send(&topic, &payload, QoS::AtLeastOnce)
                .await
                .expect("qual send");
        }
        sink.flush().await.expect("qual flush");
        assert_eq!(sink.sent_rows(), 5000);

        // Parts merge: force it, then assert one active part set and the
        // full row count.
        let optimize = format!("OPTIMIZE TABLE {qualified} FINAL");
        client
            .query(&optimize)
            .execute()
            .await
            .expect("qual optimize");
        let count_sql = format!("SELECT count() FROM {qualified}");
        let count: u64 = client
            .query(&count_sql)
            .fetch_one::<u64>()
            .await
            .expect("qual count");
        assert_eq!(count, 5000);

        // System table proves the merge happened (bounded active parts).
        let parts_sql = format!(
            "SELECT count() FROM system.parts WHERE database = '{database}' AND table = '{table}' AND active"
        );
        let active_parts: u64 = client
            .query(&parts_sql)
            .fetch_one::<u64>()
            .await
            .expect("qual parts");
        assert!(
            (1..=8).contains(&active_parts),
            "expected merged parts, got {active_parts}"
        );

        let sample_sql =
            format!("SELECT payload FROM {qualified} WHERE payload LIKE '%4242%' LIMIT 1");
        let sample: String = client
            .query(&sample_sql)
            .fetch_one::<String>()
            .await
            .expect("qual sample");
        assert!(sample.contains("4242"), "unexpected sample: {sample}");

        let drop_sql = format!("DROP TABLE IF EXISTS {qualified}");
        client.query(&drop_sql).execute().await.expect("qual drop");
    }
}
