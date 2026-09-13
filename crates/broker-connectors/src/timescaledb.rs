//! TimescaleDB hypertable sink (INDRA-171).
//!
//! Buffers MQTT events as 4-column rows (`$1` time, `$2` device id,
//! `$3` topic, `$4` metrics JSONB) and flushes full or stale batches
//! through the PostgreSQL extended-query protocol — TimescaleDB is
//! wire-compatible, so the TCP transport reuses [`TcpPgTransport`]
//! and only the shape/validation is hypertable-specific. The template
//! carries UPSERT conflict resolution, e.g.
//! `INSERT INTO sensor_metrics (time, device_id, topic, metrics)
//! VALUES ($1, $2, $3, $4::jsonb) ON CONFLICT (time, device_id)
//! DO UPDATE SET metrics = EXCLUDED.metrics`.
//!
//! Batching, restore-on-failure and backoff reuse the shared
//! [`super::BatchQueue`] / [`super::BackoffState`] helpers.

use async_trait::async_trait;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::{
    now_millis, rfc3339_millis, BackoffState, BatchQueue, ConnectorError, PgBatch, PgTransport,
    Result, Sink, TcpPgTransport,
};

fn default_time_column() -> String {
    "time".to_string()
}

fn default_pool_size() -> usize {
    10
}

fn default_batch_size() -> usize {
    200
}

fn default_batch_timeout_ms() -> u64 {
    50
}

fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// TimescaleDB sink configuration. Every depth is user-configurable
/// with no clamped ceiling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimescaleDbSinkConfig {
    /// PostgreSQL connection URL, e.g.
    /// `postgresql://user:pass@host:5432/timeseries`.
    pub connection_url: String,
    /// Target hypertable, e.g. `sensor_metrics`.
    pub hypertable: String,
    /// Time partition column (default `time`).
    #[serde(default = "default_time_column")]
    pub time_column: String,
    /// Prepared SQL referencing exactly `$1` (time), `$2` (device id),
    /// `$3` (topic) and `$4` (metrics JSONB), with UPSERT resolution.
    pub sql_template: String,
    /// Max connection pool size (default 10).
    #[serde(default = "default_pool_size")]
    pub pool_size: usize,
    /// Batch insert buffer size (default 200).
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    /// Linger flush window (default 50 ms).
    #[serde(default = "default_batch_timeout_ms")]
    pub batch_timeout_ms: u64,
}

impl TimescaleDbSinkConfig {
    pub fn validate(&self) -> Result<()> {
        if !self.connection_url.starts_with("postgresql://")
            && !self.connection_url.starts_with("postgres://")
        {
            return Err(ConnectorError::Dispatch(format!(
                "timescaledb connection_url must be postgresql://: {:?}",
                redact_url(&self.connection_url)
            )));
        }
        if !is_identifier(&self.hypertable) {
            return Err(ConnectorError::Dispatch(format!(
                "timescaledb hypertable must match [A-Za-z0-9_]+: {:?}",
                self.hypertable
            )));
        }
        if !is_identifier(&self.time_column) {
            return Err(ConnectorError::Dispatch(format!(
                "timescaledb time_column must match [A-Za-z0-9_]+: {:?}",
                self.time_column
            )));
        }
        let mut referenced = super::postgres::referenced_params(&self.sql_template)?;
        referenced.sort_unstable();
        referenced.dedup();
        if referenced != vec![1, 2, 3, 4] {
            return Err(ConnectorError::Dispatch(format!(
                "timescaledb sql_template must reference exactly $1 (time), $2 (device_id), \
                 $3 (topic) and $4 (metrics), got {referenced:?}"
            )));
        }
        if self.pool_size == 0 {
            return Err(ConnectorError::Dispatch(
                "timescaledb pool_size must be >= 1".to_string(),
            ));
        }
        if self.batch_size == 0 {
            return Err(ConnectorError::Dispatch(
                "timescaledb batch_size must be >= 1".to_string(),
            ));
        }
        Ok(())
    }
}

/// Redact any password before echoing a URL in errors.
fn redact_url(url: &str) -> String {
    match url.split_once('@') {
        Some((_, rest)) => format!("postgresql://***@{rest}"),
        None => url.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Transport (TimescaleDB speaks the PostgreSQL wire protocol).
// ---------------------------------------------------------------------------

/// One flushed batch: the UPSERT statement plus one 4-column row per
/// event (time, device id, topic, metrics JSONB, all text-encoded).
#[derive(Debug, Clone, Default)]
pub struct TimescaleBatch {
    pub sql: String,
    pub rows: Vec<Vec<Vec<u8>>>,
}

#[async_trait]
pub trait TimescaleDbTransport: Send + Sync {
    async fn execute_batch(&self, batch: &TimescaleBatch) -> Result<()>;
}

/// In-memory transport recording every flushed batch (tests, dry runs).
#[derive(Debug, Default)]
pub struct MockTimescaleTransport {
    batches: parking_lot::Mutex<Vec<TimescaleBatch>>,
    failures_left: parking_lot::Mutex<usize>,
    calls: AtomicU64,
}

impl MockTimescaleTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fail the next `n` executions with a transport error (backoff tests).
    pub fn fail_next(&self, n: usize) {
        *self.failures_left.lock() = n;
    }

    pub fn batches(&self) -> Vec<TimescaleBatch> {
        self.batches.lock().clone()
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl TimescaleDbTransport for MockTimescaleTransport {
    async fn execute_batch(&self, batch: &TimescaleBatch) -> Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut failures = self.failures_left.lock();
        if *failures > 0 {
            *failures -= 1;
            return Err(ConnectorError::Connection(
                "mock timescaledb down".to_string(),
            ));
        }
        self.batches.lock().push(batch.clone());
        Ok(())
    }
}

/// TCP transport delegating batches to the shared PostgreSQL extended
/// protocol driver (same wire format TimescaleDB expects).
pub struct TcpTimescaleTransport {
    inner: TcpPgTransport,
}

impl TcpTimescaleTransport {
    pub fn new(url: &str, pool_size: usize) -> Result<Self> {
        Ok(Self {
            inner: TcpPgTransport::new(url, pool_size)?,
        })
    }
}

#[async_trait]
impl TimescaleDbTransport for TcpTimescaleTransport {
    async fn execute_batch(&self, batch: &TimescaleBatch) -> Result<()> {
        PgTransport::execute_batch(
            &self.inner,
            &PgBatch {
                sql: batch.sql.clone(),
                rows: batch.rows.clone(),
            },
        )
        .await
    }
}

// ---------------------------------------------------------------------------
// Sink.
// ---------------------------------------------------------------------------

/// TimescaleDB sink: buffers 4-column hypertable rows, flushes batches.
pub struct TimescaleDbSink {
    config: TimescaleDbSinkConfig,
    transport: Arc<dyn TimescaleDbTransport>,
    buffer: parking_lot::Mutex<BatchQueue<Vec<Vec<u8>>>>,
    backoff: parking_lot::Mutex<BackoffState>,
    sent_batches: AtomicU64,
}

impl TimescaleDbSink {
    pub fn new(
        config: TimescaleDbSinkConfig,
        transport: Arc<dyn TimescaleDbTransport>,
    ) -> Result<Self> {
        config.validate()?;
        let linger = Duration::from_millis(config.batch_timeout_ms);
        Ok(Self {
            buffer: parking_lot::Mutex::new(BatchQueue::new(config.batch_size, linger)),
            config,
            transport,
            backoff: parking_lot::Mutex::new(BackoffState::default()),
            sent_batches: AtomicU64::new(0),
        })
    }

    pub fn config(&self) -> &TimescaleDbSinkConfig {
        &self.config
    }

    pub fn sent_batches(&self) -> u64 {
        self.sent_batches.load(Ordering::Relaxed)
    }

    pub fn buffered_rows(&self) -> usize {
        self.buffer.lock().len()
    }

    /// Flush buffered rows as one batch (no-op when empty). While
    /// backing off, fails fast without touching the transport. Any
    /// failure restores the buffer, engages backoff, and propagates.
    pub async fn flush(&self) -> Result<()> {
        self.backoff.lock().check()?;
        let (rows, oldest) = self.buffer.lock().take_batch();
        if rows.is_empty() {
            return Ok(());
        }
        let batch = TimescaleBatch {
            sql: self.config.sql_template.clone(),
            rows,
        };
        match self.transport.execute_batch(&batch).await {
            Ok(()) => {
                self.backoff.lock().success();
                self.sent_batches.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                self.buffer.lock().restore(batch.rows, oldest);
                self.backoff.lock().failure();
                Err(e)
            }
        }
    }

    /// Build one 4-column row: RFC 3339 time, device id (JSON
    /// `device_id` field or the topic), topic, metrics JSONB (payload
    /// verbatim when valid JSON, JSON string otherwise). QoS rides
    /// inside the metrics document, not its own column.
    fn buffer_row(&self, topic: &Topic, payload: &Bytes, _qos: QoS) -> Result<bool> {
        if topic.as_str().is_empty() {
            return Err(ConnectorError::Dispatch(
                "timescaledb row requires a non-empty topic".to_string(),
            ));
        }
        let text = std::str::from_utf8(payload).map_err(|_| {
            ConnectorError::Dispatch("timescaledb payload must be UTF-8".to_string())
        })?;
        let value: serde_json::Value = match serde_json::from_str(text) {
            Ok(value) => value,
            Err(_) => serde_json::Value::String(text.to_string()),
        };
        let device_id = match value.get("device_id") {
            Some(serde_json::Value::String(id)) => id.clone().into_bytes(),
            Some(scalar) if scalar.is_number() || scalar.is_boolean() => {
                scalar.to_string().into_bytes()
            }
            _ => topic.as_str().as_bytes().to_vec(),
        };
        let metrics = serde_json::to_vec(&value).map_err(|e| {
            ConnectorError::Dispatch(format!("timescaledb metrics encode failed: {e}"))
        })?;
        Ok(self.buffer.lock().push(vec![
            rfc3339_millis(now_millis()).into_bytes(),
            device_id,
            topic.as_str().as_bytes().to_vec(),
            metrics,
        ]))
    }
}

#[async_trait]
impl Sink for TimescaleDbSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        if self.buffer_row(topic, payload, qos)? {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "timescaledb"
    }
}

/// Management connector handle pairing an id with a TimescaleDB sink.
pub struct TimescaleDbConnector {
    id: String,
    sink: Arc<TimescaleDbSink>,
}

impl TimescaleDbConnector {
    pub fn new(id: impl Into<String>, sink: Arc<TimescaleDbSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }
}

impl super::Connector for TimescaleDbConnector {
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

    fn test_config() -> TimescaleDbSinkConfig {
        TimescaleDbSinkConfig {
            connection_url: "postgresql://user:pass@127.0.0.1:5432/timeseries".to_string(),
            hypertable: "sensor_metrics".to_string(),
            time_column: "time".to_string(),
            sql_template: "INSERT INTO sensor_metrics (time, device_id, topic, metrics) \
                 VALUES ($1, $2, $3, $4::jsonb) \
                 ON CONFLICT (time, device_id) DO UPDATE SET metrics = EXCLUDED.metrics"
                .to_string(),
            pool_size: 10,
            batch_size: 200,
            batch_timeout_ms: 50,
        }
    }

    #[test]
    fn test_config_validation() {
        let mut config = test_config();
        assert!(config.validate().is_ok());

        config.connection_url = "mysql://u:p@h/db".to_string();
        assert!(config.validate().is_err());
        config.connection_url = test_config().connection_url;

        for bad in ["has space", "with;drop", "schema.table", ""] {
            config.hypertable = bad.to_string();
            assert!(config.validate().is_err(), "hypertable {bad:?} must fail");
        }
        config.hypertable = "sensor_metrics".to_string();

        config.time_column = "time; DROP TABLE x;".to_string();
        assert!(config.validate().is_err());
        config.time_column = "time".to_string();

        config.sql_template = "INSERT INTO t VALUES ($1, $2, $3, $5)".to_string();
        assert!(config.validate().is_err());
        config.sql_template = "INSERT INTO t VALUES ($1, $2, $3)".to_string();
        assert!(config.validate().is_err(), "missing $4 must fail");
        config.sql_template = test_config().sql_template;

        config.pool_size = 0;
        assert!(config.validate().is_err());
        config.pool_size = 10;

        config.batch_size = 0;
        assert!(config.validate().is_err());
        // Zero clamped ceilings: huge depths are accepted.
        config.batch_size = 10_000_000;
        assert!(config.validate().is_ok());
    }

    #[tokio::test]
    async fn test_hypertable_parameter_binding() {
        let transport = Arc::new(MockTimescaleTransport::new());
        let mut config = test_config();
        config.batch_size = 10;
        let sink = TimescaleDbSink::new(config.clone(), transport.clone()).unwrap();

        sink.send(
            &Topic::new("sensors/kitchen").unwrap(),
            &Bytes::from(r#"{"device_id":"d7","temp":21.5}"#),
            QoS::AtLeastOnce,
        )
        .await
        .unwrap();
        sink.flush().await.unwrap();

        let batches = transport.batches();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].sql, config.sql_template);
        assert_eq!(batches[0].rows.len(), 1);
        let row = &batches[0].rows[0];
        assert_eq!(row.len(), 4);
        // $1 time is RFC 3339 millis; $2 device id from JSON.
        let time = std::str::from_utf8(&row[0]).unwrap();
        assert_eq!(time.len(), 24);
        assert!(time.ends_with('Z'));
        assert_eq!(row[1], b"d7".to_vec());
        assert_eq!(row[2], b"sensors/kitchen".to_vec());
        let metrics: serde_json::Value = serde_json::from_slice(&row[3]).unwrap();
        assert_eq!(
            metrics,
            serde_json::json!({"device_id": "d7", "temp": 21.5})
        );
    }

    #[tokio::test]
    async fn test_jsonb_handling_and_device_fallback() {
        let transport = Arc::new(MockTimescaleTransport::new());
        let mut config = test_config();
        config.batch_size = 10;
        let sink = TimescaleDbSink::new(config, transport.clone()).unwrap();

        // Non-JSON payload becomes a JSON string; device id falls back
        // to the topic.
        sink.send(
            &Topic::new("sensors/door").unwrap(),
            &Bytes::from("open"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        // Numeric device ids render via their JSON spelling.
        sink.send(
            &Topic::new("sensors/hum").unwrap(),
            &Bytes::from(r#"{"device_id":42}"#),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        sink.flush().await.unwrap();

        let batches = transport.batches();
        assert_eq!(batches[0].rows.len(), 2);
        assert_eq!(batches[0].rows[0][1], b"sensors/door".to_vec());
        let metrics: serde_json::Value = serde_json::from_slice(&batches[0].rows[0][3]).unwrap();
        assert_eq!(metrics, serde_json::Value::String("open".to_string()));
        assert_eq!(batches[0].rows[1][1], b"42".to_vec());
    }

    #[tokio::test]
    async fn test_pipeline_execute_batches() {
        let transport = Arc::new(MockTimescaleTransport::new());
        let mut config = test_config();
        config.batch_size = 2;
        let sink = TimescaleDbSink::new(config, transport.clone()).unwrap();
        let topic = Topic::new("t").unwrap();
        for v in ["1", "2", "3"] {
            sink.send(&topic, &Bytes::from(v), QoS::AtMostOnce)
                .await
                .unwrap();
        }
        // Two rows flushed on count, one still buffered.
        assert_eq!(sink.sent_batches(), 1);
        assert_eq!(sink.buffered_rows(), 1);
        sink.flush().await.unwrap();
        assert_eq!(sink.sent_batches(), 2);
        let batches = transport.batches();
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].rows.len(), 2);
        assert_eq!(batches[1].rows.len(), 1);
    }

    #[tokio::test]
    async fn test_failure_retains_buffer_and_backs_off() {
        let transport = Arc::new(MockTimescaleTransport::new());
        transport.fail_next(100);
        let mut config = test_config();
        config.batch_size = 10;
        let sink = TimescaleDbSink::new(config, transport.clone()).unwrap();
        let topic = Topic::new("t").unwrap();
        sink.send(&topic, &Bytes::from("{}"), QoS::AtMostOnce)
            .await
            .unwrap();
        let err = sink.flush().await.expect_err("mock down must fail");
        assert!(matches!(err, ConnectorError::Connection(_)));
        assert_eq!(sink.buffered_rows(), 1);
        let calls = transport.calls();
        assert!(sink.flush().await.is_err());
        assert_eq!(transport.calls(), calls);
        assert_eq!(sink.sent_batches(), 0);
    }
}
