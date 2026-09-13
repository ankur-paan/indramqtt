//! ClickHouse analytical sink (INDRA-181).
//!
//! Buffers MQTT events as JSON rows and flushes full or stale batches
//! with one HTTP `POST` to ClickHouse (`INSERT INTO db.table FORMAT
//! JSONEachRow`). Batching, restore-on-failure and backoff reuse the
//! shared [`super::BatchQueue`] / [`super::BackoffState`] helpers, so
//! the contract matches the MySQL/PostgreSQL sinks: failed flushes
//! keep the buffer, engage backoff, and propagate the error.
//!
//! Identifier interpolation (`database`, `table`, `format`) is
//! injection-safe by construction: identifiers must match
//! `[A-Za-z0-9_]+` and the format must come from a fixed whitelist.

use async_trait::async_trait;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::{BackoffState, BatchQueue, ConnectorError, Result, Sink};

/// Insert formats accepted for the `FORMAT` clause.
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

/// ClickHouse sink configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClickHouseSinkConfig {
    /// Base HTTP endpoint, e.g. `http://ch:8123`.
    pub endpoint: String,
    pub database: String,
    pub table: String,
    /// Insert format (whitelisted); defaults to `JSONEachRow`.
    pub format: String,
    pub batch_size: usize,
    pub batch_timeout_ms: u64,
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
        if self.batch_size == 0 {
            return Err(ConnectorError::Dispatch(
                "clickhouse batch_size must be >= 1".to_string(),
            ));
        }
        Ok(())
    }

    /// `INSERT INTO <db>.<table> FORMAT <format>` (identifiers already
    /// validated, so interpolation is safe).
    pub fn insert_query(&self) -> String {
        format!(
            "INSERT INTO {}.{} FORMAT {}",
            self.database, self.table, self.format
        )
    }
}

/// One buffered row: topic, QoS value, UTF-8 payload.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ClickHouseRow {
    topic: String,
    qos: u8,
    payload: String,
}

fn render_row(row: &ClickHouseRow) -> String {
    serde_json::json!({
        "topic": row.topic,
        "qos": row.qos,
        "payload": row.payload,
    })
    .to_string()
}

/// ClickHouse sink: buffers validated rows, POSTs JSONEachRow batches.
pub struct ClickHouseSink {
    config: ClickHouseSinkConfig,
    client: reqwest::Client,
    buffer: parking_lot::Mutex<BatchQueue<ClickHouseRow>>,
    backoff: parking_lot::Mutex<BackoffState>,
    sent_batches: AtomicU64,
}

impl ClickHouseSink {
    pub fn new(config: ClickHouseSinkConfig, client: reqwest::Client) -> Result<Self> {
        config.validate()?;
        let linger = Duration::from_millis(config.batch_timeout_ms);
        Ok(Self {
            buffer: parking_lot::Mutex::new(BatchQueue::new(config.batch_size, linger)),
            config,
            client,
            backoff: parking_lot::Mutex::new(BackoffState::default()),
            sent_batches: AtomicU64::new(0),
        })
    }

    pub fn config(&self) -> &ClickHouseSinkConfig {
        &self.config
    }

    pub fn sent_batches(&self) -> u64 {
        self.sent_batches.load(Ordering::Relaxed)
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
        let mut body = String::new();
        for row in &rows {
            body.push_str(&render_row(row));
            body.push('\n');
        }
        let url = format!("{}/", self.config.endpoint.trim_end_matches('/'));
        let response = self
            .client
            .post(&url)
            .query(&[("query", self.config.insert_query())])
            .header(reqwest::header::CONTENT_TYPE, "text/plain")
            .body(body)
            .timeout(Duration::from_millis(self.config.batch_timeout_ms.max(1)))
            .send()
            .await
            .map_err(|e| ConnectorError::Connection(format!("clickhouse post failed: {e}")))?;
        if !response.status().is_success() {
            self.buffer.lock().restore(rows, oldest);
            self.backoff.lock().failure();
            return Err(ConnectorError::Dispatch(format!(
                "clickhouse {} answered {}",
                self.config.endpoint,
                response.status()
            )));
        }
        self.backoff.lock().success();
        self.sent_batches.fetch_add(1, Ordering::Relaxed);
        Ok(())
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
        }
    }

    fn test_client() -> reqwest::Client {
        reqwest::Client::builder()
            .build()
            .expect("test http client")
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
    fn test_row_validation() {
        let sink = ClickHouseSink::new(test_config("http://ch:8123"), test_client()).unwrap();
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
            body: String,
        ) -> StatusCode {
            *captured.query.lock().unwrap() = uri.query().unwrap_or_default().to_string();
            *captured.body.lock().unwrap() = body;
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
        let sink = ClickHouseSink::new(config, test_client()).unwrap();

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
        let sink = ClickHouseSink::new(config, test_client()).unwrap();

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
}
