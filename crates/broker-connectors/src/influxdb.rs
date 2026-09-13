//! InfluxDB time-series sink (INDRA-172).
//!
//! Buffers MQTT events as line-protocol rows and flushes full or stale
//! batches with one HTTP `POST` to `/api/v2/write`. Batching,
//! restore-on-failure and backoff reuse the shared
//! [`super::BatchQueue`] / [`super::BackoffState`] helpers, so the
//! contract matches the other analytical sinks: failed flushes keep
//! the buffer, engage backoff, and propagate the error.
//!
//! Authentication uses `Authorization: Token <token>`. The measurement
//! template supports a literal name or a `{topic}` placeholder (topic
//! with line-protocol escaping applied).

use async_trait::async_trait;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{BackoffState, BatchQueue, ConnectorError, Result, Sink};

/// Write precisions accepted as the `precision` query parameter.
const ALLOWED_PRECISIONS: &[&str] = &["s", "ms", "us", "ns"];

/// InfluxDB sink configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InfluxDbSinkConfig {
    /// Base HTTP endpoint, e.g. `http://influx:8086`.
    pub endpoint: String,
    pub bucket: String,
    pub org: String,
    pub token: String,
    /// Literal measurement name or `{topic}` template.
    pub measurement_template: String,
    /// One of `s`, `ms`, `us`, `ns`; defaults to `ms`.
    pub precision: String,
    pub batch_size: usize,
    pub batch_timeout_ms: u64,
}

impl InfluxDbSinkConfig {
    pub fn validate(&self) -> Result<()> {
        if !self.endpoint.starts_with("http://") && !self.endpoint.starts_with("https://") {
            return Err(ConnectorError::Dispatch(format!(
                "influxdb endpoint must be http(s): {:?}",
                self.endpoint
            )));
        }
        if self.bucket.is_empty() {
            return Err(ConnectorError::Dispatch(
                "influxdb bucket is required".to_string(),
            ));
        }
        if self.org.is_empty() {
            return Err(ConnectorError::Dispatch(
                "influxdb org is required".to_string(),
            ));
        }
        if self.token.is_empty() {
            return Err(ConnectorError::Dispatch(
                "influxdb token is required".to_string(),
            ));
        }
        if self.measurement_template.is_empty() {
            return Err(ConnectorError::Dispatch(
                "influxdb measurement is required".to_string(),
            ));
        }
        if !ALLOWED_PRECISIONS.contains(&self.precision.as_str()) {
            return Err(ConnectorError::Dispatch(format!(
                "influxdb precision must be one of {ALLOWED_PRECISIONS:?}: {:?}",
                self.precision
            )));
        }
        if self.batch_size == 0 {
            return Err(ConnectorError::Dispatch(
                "influxdb batch_size must be >= 1".to_string(),
            ));
        }
        Ok(())
    }

    /// Render the measurement for one topic (`{topic}` substitution).
    pub fn measurement_for(&self, topic: &str) -> String {
        escape_measurement(&self.measurement_template.replace("{topic}", topic))
    }
}

/// Escape commas and spaces in measurement names.
fn escape_measurement(value: &str) -> String {
    value.replace(',', "\\,").replace(' ', "\\ ")
}

/// Escape commas, equal signs and spaces in tag keys/values.
fn escape_tag(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace(',', "\\,")
        .replace('=', "\\=")
        .replace(' ', "\\ ")
}

/// Escape double quotes and backslashes in string field values.
fn escape_field_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn timestamp_for(precision: &str) -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    match precision {
        "s" => now.as_secs() as i64,
        "us" => now.as_micros().min(i64::MAX as u128) as i64,
        "ns" => now.as_nanos().min(i64::MAX as u128) as i64,
        _ => now.as_millis().min(i64::MAX as u128) as i64,
    }
}

/// One buffered row; the timestamp is captured at buffer time.
#[derive(Debug, Clone, PartialEq, Eq)]
struct InfluxRow {
    line: String,
}

fn render_line(config: &InfluxDbSinkConfig, topic: &Topic, payload: &str, qos: QoS) -> String {
    format!(
        "{},topic={} qos={}i,payload=\"{}\" {}",
        config.measurement_for(topic.as_str()),
        escape_tag(topic.as_str()),
        u8::from(qos),
        escape_field_string(payload),
        timestamp_for(&config.precision),
    )
}

/// InfluxDB sink: buffers validated rows, POSTs line-protocol batches.
pub struct InfluxDbSink {
    config: InfluxDbSinkConfig,
    client: reqwest::Client,
    buffer: parking_lot::Mutex<BatchQueue<InfluxRow>>,
    backoff: parking_lot::Mutex<BackoffState>,
    sent_batches: AtomicU64,
}

impl InfluxDbSink {
    pub fn new(config: InfluxDbSinkConfig, client: reqwest::Client) -> Result<Self> {
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

    pub fn config(&self) -> &InfluxDbSinkConfig {
        &self.config
    }

    pub fn sent_batches(&self) -> u64 {
        self.sent_batches.load(Ordering::Relaxed)
    }

    pub fn buffered_rows(&self) -> usize {
        self.buffer.lock().len()
    }

    /// Write URL: `{endpoint}/api/v2/write`.
    pub fn write_url(&self) -> String {
        format!(
            "{}/api/v2/write",
            self.config.endpoint.trim_end_matches('/')
        )
    }

    /// Flush buffered rows as one write (no-op when empty). While
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
            body.push_str(&row.line);
            body.push('\n');
        }
        let response = self
            .client
            .post(self.write_url())
            .query(&[
                ("org", self.config.org.as_str()),
                ("bucket", self.config.bucket.as_str()),
                ("precision", self.config.precision.as_str()),
            ])
            .header("Authorization", format!("Token {}", self.config.token))
            .header(reqwest::header::CONTENT_TYPE, "text/plain")
            .body(body)
            .timeout(Duration::from_millis(self.config.batch_timeout_ms.max(1)))
            .send()
            .await
            .map_err(|e| ConnectorError::Connection(format!("influxdb write failed: {e}")))?;
        if !response.status().is_success() {
            self.buffer.lock().restore(rows, oldest);
            self.backoff.lock().failure();
            return Err(ConnectorError::Dispatch(format!(
                "influxdb {} answered {}",
                self.config.endpoint,
                response.status()
            )));
        }
        self.backoff.lock().success();
        self.sent_batches.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Validate one event into a buffered line. Returns true when the
    /// batch is full (caller flushes). Rejects empty topics and
    /// non-UTF-8 payloads (string field values must be UTF-8).
    fn buffer_row(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<bool> {
        if topic.as_str().is_empty() {
            return Err(ConnectorError::Dispatch(
                "influxdb row requires a non-empty topic".to_string(),
            ));
        }
        let payload = std::str::from_utf8(payload)
            .map_err(|_| ConnectorError::Dispatch("influxdb payload must be UTF-8".to_string()))?;
        Ok(self.buffer.lock().push(InfluxRow {
            line: render_line(&self.config, topic, payload, qos),
        }))
    }
}

#[async_trait]
impl Sink for InfluxDbSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        if self.buffer_row(topic, payload, qos)? {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "influxdb"
    }
}

/// Management connector handle pairing an id with an InfluxDB sink.
pub struct InfluxDbConnector {
    id: String,
    sink: Arc<InfluxDbSink>,
}

impl InfluxDbConnector {
    pub fn new(id: impl Into<String>, sink: Arc<InfluxDbSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }
}

impl super::Connector for InfluxDbConnector {
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
    use axum::{extract::State, http::StatusCode, routing::post, Router};
    use std::sync::Mutex as StdMutex;
    use tokio::net::TcpListener;

    fn test_config(endpoint: &str) -> InfluxDbSinkConfig {
        InfluxDbSinkConfig {
            endpoint: endpoint.to_string(),
            bucket: "mqtt".to_string(),
            org: "indra".to_string(),
            token: "secret".to_string(),
            measurement_template: "mqtt_events".to_string(),
            precision: "ms".to_string(),
            batch_size: 200,
            batch_timeout_ms: 50,
        }
    }

    fn test_client() -> reqwest::Client {
        reqwest::Client::builder()
            .build()
            .expect("test http client")
    }

    #[test]
    fn test_config_validation() {
        let mut config = test_config("http://influx:8086");
        assert!(config.validate().is_ok());
        assert_eq!(config.measurement_for("sensors/t1"), "mqtt_events");

        config.endpoint = "influx:8086".to_string();
        assert!(config.validate().is_err());
        config.endpoint = "http://influx:8086".to_string();

        config.bucket.clear();
        assert!(config.validate().is_err());
        config.bucket = "mqtt".to_string();

        config.org.clear();
        assert!(config.validate().is_err());
        config.org = "indra".to_string();

        config.token.clear();
        assert!(config.validate().is_err());
        config.token = "secret".to_string();

        config.measurement_template.clear();
        assert!(config.validate().is_err());
        config.measurement_template = "mqtt_events".to_string();

        config.precision = "fortnight".to_string();
        assert!(config.validate().is_err());
        config.precision = "ms".to_string();

        config.batch_size = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_measurement_template_and_escaping() {
        let mut config = test_config("http://influx:8086");
        config.measurement_template = "mqtt_{topic}".to_string();
        assert_eq!(config.measurement_for("sensors/t1"), "mqtt_sensors/t1");

        let topic = Topic::new("sensors/t1").unwrap();
        let line = render_line(&config, &topic, "hi", QoS::AtLeastOnce);
        assert!(line.starts_with("mqtt_sensors/t1,topic=sensors/t1 qos=1i,payload=\"hi\" "));

        // Tag escaping: commas, equals and spaces are backslash-escaped.
        let tricky = Topic::new("a,b=c d").unwrap();
        let line = render_line(&config, &tricky, "x", QoS::AtMostOnce);
        assert!(line.contains("topic=a\\,b\\=c\\ d"));

        // Field-string escaping: quotes and backslashes.
        let line = render_line(&config, &topic, "say \"hi\" \\ ok", QoS::AtMostOnce);
        assert!(line.contains("payload=\"say \\\"hi\\\" \\\\ ok\""));
    }

    #[test]
    fn test_precision_controls_timestamp_digits() {
        // (precision, expected digit count in this era).
        for (precision, digits) in [("s", 10), ("ms", 13), ("us", 16), ("ns", 19)] {
            let mut config = test_config("http://influx:8086");
            config.precision = precision.to_string();
            assert!(config.validate().is_ok());
            let line = render_line(
                &config,
                &Topic::new("sensors/t1").unwrap(),
                "{}",
                QoS::AtMostOnce,
            );
            let ts = line.rsplit(' ').next().unwrap_or_default();
            assert_eq!(ts.len(), digits, "precision {precision}: {line}");
            assert!(ts.bytes().all(|b| b.is_ascii_digit()));
        }
    }

    #[test]
    fn test_row_validation() {
        let sink = InfluxDbSink::new(test_config("http://influx:8086"), test_client()).unwrap();
        let topic = Topic::new("sensors/t1").unwrap();

        assert!(!sink
            .buffer_row(&topic, &Bytes::from("{}"), QoS::AtLeastOnce)
            .unwrap());
        assert_eq!(sink.buffered_rows(), 1);

        // Empty topics are rejected at construction; the buffer_row
        // guard stays as defense-in-depth.
        assert!(Topic::new("").is_err());

        assert!(sink
            .buffer_row(&topic, &Bytes::from(vec![0xFF, 0xFE]), QoS::AtMostOnce)
            .is_err());
    }

    #[derive(Debug, Default)]
    struct Captured {
        query: StdMutex<String>,
        auth: StdMutex<String>,
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
            *captured.auth.lock().unwrap() = headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            *captured.body.lock().unwrap() = body;
            StatusCode::from_u16(*captured.status.lock().unwrap()).unwrap_or(StatusCode::NO_CONTENT)
        }
        let app = Router::new()
            .route("/api/v2/write", post(handler))
            .with_state(captured);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        port
    }

    #[tokio::test]
    async fn test_batch_posts_line_protocol() {
        let captured = Arc::new(Captured::default());
        let port = serve_captured(captured.clone()).await;
        let mut config = test_config(&format!("http://127.0.0.1:{port}"));
        config.batch_size = 2;
        let sink = InfluxDbSink::new(config, test_client()).unwrap();

        sink.send(
            &Topic::new("sensors/t1").unwrap(),
            &Bytes::from("on"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        assert_eq!(sink.buffered_rows(), 1);
        sink.send(
            &Topic::new("sensors/t2").unwrap(),
            &Bytes::from("off"),
            QoS::AtLeastOnce,
        )
        .await
        .unwrap();
        assert_eq!(sink.sent_batches(), 1);
        assert_eq!(sink.buffered_rows(), 0);

        let query = captured.query.lock().unwrap().clone();
        assert!(query.contains("org=indra"), "unexpected query: {query}");
        assert!(query.contains("bucket=mqtt"), "unexpected query: {query}");
        assert!(query.contains("precision=ms"), "unexpected query: {query}");
        assert_eq!(captured.auth.lock().unwrap().as_str(), "Token secret");

        let body = captured.body.lock().unwrap().clone();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("mqtt_events,topic=sensors/t1 qos=0i,payload=\"on\" "));
        assert!(lines[1].starts_with("mqtt_events,topic=sensors/t2 qos=1i,payload=\"off\" "));
        // Millisecond timestamps are 13 digits in this era.
        for line in &lines {
            let ts = line.rsplit(' ').next().unwrap_or_default();
            assert_eq!(ts.len(), 13, "expected ms timestamp: {line}");
        }
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
        let sink = InfluxDbSink::new(config, test_client()).unwrap();

        sink.send(
            &Topic::new("sensors/t1").unwrap(),
            &Bytes::from("{}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        assert_eq!(sink.buffered_rows(), 1);
        let err = sink.flush().await.expect_err("500 must fail");
        assert!(matches!(err, ConnectorError::Dispatch(_)));
        assert_eq!(sink.buffered_rows(), 1);
        assert!(sink.flush().await.is_err());
        assert_eq!(sink.sent_batches(), 0);
    }
}
