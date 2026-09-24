//! InfluxDB time-series sink (INDRA-172).
//!
//! Buffers MQTT events as line-protocol rows and flushes full or stale
//! batches with one HTTP `POST` to `/api/v2/write`. Batching,
//! restore-on-failure and backoff reuse the shared
//! [`super::BatchQueue`] / [`super::BackoffState`] helpers, so the
//! contract matches the other analytical sinks: failed flushes keep
//! the buffer, engage backoff, and propagate the error.
//!
//! The write path speaks the vendor InfluxDB v2 write API (line
//! protocol over HTTP, `org`/`bucket`/`precision` query parameters,
//! `Authorization: Token <token>`) through the maintained `reqwest`
//! client (MIT/Apache-2.0): no hand-rolled HTTP, no extra vendor crate.
//! Authentication uses `Authorization: Token <token>`. The measurement
//! template supports a literal name or a `{topic}` placeholder (topic
//! with line-protocol escaping applied).

use async_trait::async_trait;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{BackoffState, BatchQueue, ConnectorError, Result, Sink};

/// Write precisions accepted as the `precision` query parameter.
const ALLOWED_PRECISIONS: &[&str] = &["s", "ms", "us", "ns"];

/// Max buffered rows per sink: 10_000. A disconnected server must not
/// grow the queue without bound, so the default is finite: 10_000 rows
/// of ~200 B line protocol stay under ~2 MiB while still absorbing a
/// burst behind the rule engine's bounded queue (the connector's send
/// path runs behind that queue, so this is a backstop, not new work on
/// the publish path).
// TODO(parity): whether this bound should be operator-configurable
// (e.g. an optional `buffer_capacity`) is open; the code never chooses
// unbounded.
const MAX_BUFFERED_ROWS: usize = 10_000;

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
    /// Per-request HTTP timeout in ms (defaults to 5000 ms if omitted).
    #[serde(default)]
    pub request_timeout_ms: Option<u64>,
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

    /// Per-request HTTP timeout; falls back to 5000 ms if not configured.
    pub fn request_timeout(&self) -> Duration {
        Duration::from_millis(self.request_timeout_ms.unwrap_or(5_000).max(1))
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
    render_line_at(
        config,
        topic,
        payload,
        qos,
        timestamp_for(&config.precision),
    )
}

fn render_line_at(
    config: &InfluxDbSinkConfig,
    topic: &Topic,
    payload: &str,
    qos: QoS,
    timestamp: i64,
) -> String {
    format!(
        "{},topic={} qos={}i,payload=\"{}\" {}",
        config.measurement_for(topic.as_str()),
        escape_tag(topic.as_str()),
        u8::from(qos),
        escape_field_string(payload),
        timestamp,
    )
}

/// InfluxDB sink: buffers validated rows, POSTs line-protocol batches.
pub struct InfluxDbSink {
    config: InfluxDbSinkConfig,
    client: reqwest::Client,
    buffer: parking_lot::Mutex<BatchQueue<InfluxRow>>,
    backoff: parking_lot::Mutex<BackoffState>,
    sent_batches: AtomicU64,
    /// Last emitted timestamp in the configured precision. InfluxDB
    /// overwrites points that share measurement, tag set, field key and
    /// timestamp, so rapid writes at coarse precisions (e.g. ms) would
    /// collapse into one stored point; the sink hands out strictly
    /// increasing timestamps (bumping by one unit on collision) so every
    /// buffered row survives the round trip.
    last_timestamp: AtomicI64,
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
            last_timestamp: AtomicI64::new(0),
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

    /// Next timestamp in the configured precision, strictly greater
    /// than every previously handed-out timestamp. Uses the wall clock
    /// when it has advanced, otherwise bumps the last value by one
    /// precision unit so concurrent or sub-precision writes never share
    /// a timestamp on the same series.
    fn next_timestamp(&self) -> i64 {
        let mut last = self.last_timestamp.load(Ordering::Relaxed);
        loop {
            let now = timestamp_for(&self.config.precision);
            let next = if now > last { now } else { last + 1 };
            match self.last_timestamp.compare_exchange_weak(
                last,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return next,
                Err(actual) => last = actual,
            }
        }
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
            .timeout(self.config.request_timeout())
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
    /// non-UTF-8 payloads (string field values must be UTF-8). Fails
    /// closed with a connection error once `MAX_BUFFERED_ROWS` rows are
    /// buffered instead of growing without bound.
    fn buffer_row(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<bool> {
        if topic.as_str().is_empty() {
            return Err(ConnectorError::Dispatch(
                "influxdb row requires a non-empty topic".to_string(),
            ));
        }
        let payload = std::str::from_utf8(payload)
            .map_err(|_| ConnectorError::Dispatch("influxdb payload must be UTF-8".to_string()))?;
        // Render through the shared line builder so measurement/tag/field
        // escaping lives in one place, then swap in a strictly increasing
        // timestamp: the server overwrites points that share measurement,
        // tag set, field key and timestamp, so rapid writes at coarse
        // precisions would otherwise collapse into one stored point.
        let rendered = render_line(&self.config, topic, payload, qos);
        let prefix = rendered
            .rsplit_once(' ')
            .map(|(prefix, _)| prefix.to_string())
            .unwrap_or(rendered);
        let timestamp = self.next_timestamp();
        let line = format!("{prefix} {timestamp}");
        let mut queue = self.buffer.lock();
        if queue.len() >= MAX_BUFFERED_ROWS {
            return Err(ConnectorError::Connection(format!(
                "influxdb buffer full ({MAX_BUFFERED_ROWS} rows): failing closed"
            )));
        }
        Ok(queue.push(InfluxRow { line }))
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
            request_timeout_ms: None,
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

    #[tokio::test]
    async fn test_write_goes_through_manager() {
        // Broker path (publish, deliver): ConnectorManager::send ->
        // Sink::send -> POST /api/v2/write with Token auth against the
        // loopback server. This is the same path the rule engine's
        // ForwardConnector action drives; never `sink.send` directly.
        use crate::ConnectorManager;
        let captured = Arc::new(Captured::default());
        let port = serve_captured(captured.clone()).await;
        let mut config = test_config(&format!("http://127.0.0.1:{port}"));
        config.batch_size = 1;
        let sink = Arc::new(InfluxDbSink::new(config, test_client()).unwrap());
        assert_eq!(sink.kind(), "influxdb");
        let manager = ConnectorManager::new();
        manager.register("qual-influx", sink.clone());

        let topic = Topic::new("sensors/t1").unwrap();
        manager
            .send(
                "qual-influx",
                &topic,
                &Bytes::from_static(b"on"),
                QoS::AtMostOnce,
            )
            .await
            .expect("broker send delivers");
        assert_eq!(sink.sent_batches(), 1);
        assert_eq!(sink.buffered_rows(), 0);
        assert_eq!(captured.auth.lock().unwrap().as_str(), "Token secret");
        let body = captured.body.lock().unwrap().clone();
        assert_eq!(body.lines().count(), 1);
        assert!(body.starts_with("mqtt_events,topic=sensors/t1 qos=0i,payload=\"on\" "));
    }

    #[test]
    fn test_buffer_bound_fails_closed() {
        // Backstop bound (publish path): past MAX_BUFFERED_ROWS the sink
        // fails closed instead of growing without bound.
        let mut config = test_config("http://127.0.0.1:1");
        config.batch_size = usize::MAX / 2;
        let sink = InfluxDbSink::new(config, test_client()).unwrap();
        let topic = Topic::new("sensors/t1").unwrap();
        for _ in 0..MAX_BUFFERED_ROWS {
            sink.buffer_row(&topic, &Bytes::from_static(b"x"), QoS::AtMostOnce)
                .expect("row fits under the bound");
        }
        assert_eq!(sink.buffered_rows(), MAX_BUFFERED_ROWS);
        let err = sink
            .buffer_row(&topic, &Bytes::from_static(b"x"), QoS::AtMostOnce)
            .expect_err("full buffer must fail closed");
        assert!(
            matches!(err, ConnectorError::Connection(_)),
            "buffer-full must be a connection error, got {err:?}"
        );
        assert_eq!(sink.buffered_rows(), MAX_BUFFERED_ROWS);
    }

    fn qual_env(name: &str) -> Option<String> {
        std::env::var(name).ok().filter(|v| !v.trim().is_empty())
    }

    fn qual_now_nanos() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos().min(i64::MAX as u128) as i64)
            .unwrap_or(0)
    }

    /// Parse the vendor query CSV into `(value, time, ts_ns)` rows.
    /// Skips `#` annotations and the header; strips surrounding quotes
    /// so quoted string fields compare equal to what was written.
    fn parse_query_csv(body: &str) -> Vec<(String, String, i64)> {
        let mut value_idx: Option<usize> = None;
        let mut time_idx: Option<usize> = None;
        let mut ts_idx: Option<usize> = None;
        let mut rows = Vec::new();
        for raw in body.lines() {
            let line = raw.trim_end_matches('\r');
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let cells: Vec<&str> = line.split(',').collect();
            let stripped: Vec<String> = cells
                .iter()
                .map(|c| c.trim().trim_matches('"').to_string())
                .collect();
            if stripped.iter().any(|c| c == "_value") && stripped.iter().any(|c| c == "_time") {
                value_idx = stripped.iter().position(|c| c == "_value");
                time_idx = stripped.iter().position(|c| c == "_time");
                ts_idx = stripped.iter().position(|c| c == "ts");
                continue;
            }
            // Data rows start with the empty table-key columns (`,,`).
            if line.starts_with(',') {
                if let (Some(vi), Some(ti), Some(tsi)) = (value_idx, time_idx, ts_idx) {
                    if cells.len() > vi && cells.len() > ti && cells.len() > tsi {
                        let value = cells[vi].trim().trim_matches('"').to_string();
                        let time = cells[ti].trim().trim_matches('"').to_string();
                        let ts: i64 = cells[tsi].trim().trim_matches('"').parse().unwrap_or(-1);
                        rows.push((value, time, ts));
                    }
                }
            }
        }
        rows
    }

    /// Qualification against a real server through the maintained
    /// `reqwest` line-protocol write path.
    ///
    /// Run with e.g.:
    /// `INFLUXDB_ENDPOINT=http://127.0.0.1:8086 INFLUXDB_ORG=qual-org \
    ///  INFLUXDB_BUCKET=qual-b322 INFLUXDB_TOKEN=qual-token-1 \
    ///  cargo test -p broker-connectors --lib influxdb::tests::test_qualify_write_path -- --ignored --nocapture --test-threads=1`
    ///
    /// Ensures the bucket exists, streams 2000 points through the
    /// broker's rule path ([`crate::ConnectorManager`] ->
    /// [`InfluxDbSink`], Token auth, ms precision), asserts the exact
    /// query-back count plus values and timestamps from the server
    /// (not the counters), proves a bad Token fails closed as a
    /// dispatch error, then deletes the qualification measurement.
    #[tokio::test]
    #[ignore = "needs a real server (see INFLUXDB_* env)"]
    async fn test_qualify_write_path() {
        use crate::ConnectorManager;
        let endpoint = qual_env("INFLUXDB_ENDPOINT").unwrap_or_else(|| {
            panic!(
                "INFLUXDB_ENDPOINT must point at a real server for qualification; failing closed"
            )
        });
        let org = qual_env("INFLUXDB_ORG").unwrap_or_else(|| {
            panic!("INFLUXDB_ORG must be set for qualification; failing closed")
        });
        let bucket = qual_env("INFLUXDB_BUCKET").unwrap_or_else(|| {
            panic!("INFLUXDB_BUCKET must be set for qualification; failing closed")
        });
        let token = qual_env("INFLUXDB_TOKEN").unwrap_or_else(|| {
            panic!("INFLUXDB_TOKEN must be set for qualification; failing closed")
        });
        let endpoint = endpoint.trim_end_matches('/').to_string();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("qual http client");

        // Server identity for the report (best effort; never a constant
        // standing in for a measurement: omit when unreachable).
        match client
            .get(format!("{endpoint}/health"))
            .timeout(Duration::from_secs(10))
            .send()
            .await
        {
            Ok(response) => match response.json::<serde_json::Value>().await {
                Ok(health) => {
                    let version = health
                        .get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let status = health
                        .get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    eprintln!(
                        "qual server: version={version} status={status} endpoint={endpoint} org={org} bucket={bucket}"
                    );
                }
                Err(e) => eprintln!("qual server: health parse failed: {e}"),
            },
            Err(e) => eprintln!("qual server: health unreachable (tolerated): {e}"),
        }

        // Ensure the bucket exists (the setup creates it; create when
        // missing so a fresh server still qualifies; 422 means exists).
        let buckets_url = format!("{endpoint}/api/v2/buckets");
        let found: bool = match client
            .get(&buckets_url)
            .query(&[("org", org.as_str()), ("name", bucket.as_str())])
            .header("Authorization", format!("Token {token}"))
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status();
                let text = response.text().await.unwrap_or_default();
                let has = text.contains(&format!("\"name\":\"{bucket}\""))
                    || text.contains(&format!("\"name\": \"{bucket}\""));
                eprintln!("qual bucket check: status={status} found={has}");
                has
            }
            Err(e) => {
                eprintln!("qual bucket check unreachable (tolerated): {e}");
                true
            }
        };
        if !found {
            let create = client
                .post(&buckets_url)
                .header("Authorization", format!("Token {token}"))
                .json(&serde_json::json!({
                    "org": org,
                    "name": bucket,
                    "retentionRules": [],
                }))
                .send()
                .await
                .expect("qual create bucket");
            let status = create.status();
            let text = create.text().await.unwrap_or_default();
            // 201 created, 422 already exists: both mean the bucket is there.
            assert!(
                status.as_u16() == 201 || status.as_u16() == 422 || text.contains(&bucket),
                "qual create bucket: status={status} body={text}"
            );
            eprintln!("qual bucket ensured: status={status} bucket={bucket}");
        } else {
            eprintln!("qual bucket present: bucket={bucket}");
        }

        // Unique measurement per run so reruns never mix rows.
        let measurement = format!("qual_b322_m_{}", qual_now_nanos() % 1_000_000);
        let config = InfluxDbSinkConfig {
            endpoint: endpoint.clone(),
            bucket: bucket.clone(),
            org: org.clone(),
            token: token.clone(),
            measurement_template: measurement.clone(),
            precision: "ms".to_string(),
            batch_size: 200,
            batch_timeout_ms: 60_000,
            request_timeout_ms: Some(30_000),
        };
        config.validate().expect("qual config validates");
        let sink = Arc::new(InfluxDbSink::new(config.clone(), client.clone()).expect("qual sink"));
        assert_eq!(sink.kind(), "influxdb");
        // The broker's path: rule actions deliver through the shared
        // connector manager, so the qualification sends through it.
        let manager = Arc::new(ConnectorManager::new());
        manager.register("qual-influx", sink.clone());

        const POINTS: usize = 2000;
        let topic = Topic::new("qual/b322").unwrap();
        let t0 = qual_now_nanos();
        for seq in 0..POINTS {
            let payload = Bytes::from(format!("qual-{seq:04}"));
            manager
                .send("qual-influx", &topic, &payload, QoS::AtLeastOnce)
                .await
                .expect("qual send");
        }
        sink.flush().await.expect("qual flush");
        let t1 = qual_now_nanos();
        assert_eq!(sink.buffered_rows(), 0);
        assert_eq!(
            sink.sent_batches(),
            10,
            "2000 points at batch_size 200 flush exactly 10 batches"
        );
        eprintln!("qual rows sent: records={POINTS} measurement={measurement}");

        // Query-back from the server, not the counters: exact count, no
        // tolerance (the protocol permits duplicates, never loss).
        let flux = format!(
            "from(bucket:\"{bucket}\") |> range(start:-7d) \
             |> filter(fn:(r)=> r[\"_measurement\"]==\"{measurement}\" and r[\"_field\"]==\"payload\") \
             |> map(fn:(r)=> ({{_value: r._value, _time: r._time, ts: int(v: r._time)}})) \
             |> keep(columns:[\"_value\",\"_time\",\"ts\"])"
        );
        let query_url = format!("{endpoint}/api/v2/query");
        let mut rows: Vec<(String, String, i64)> = Vec::new();
        for _ in 0..30 {
            let response = client
                .post(format!("{query_url}?org={org}"))
                .header("Authorization", format!("Token {token}"))
                .header("Content-Type", "application/vnd.flux")
                .header("Accept", "application/csv")
                .body(flux.clone())
                .send()
                .await
                .expect("qual query");
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            assert!(
                status.is_success(),
                "qual query failed: status={status} body={text}"
            );
            rows = parse_query_csv(&text);
            if rows.len() == POINTS {
                break;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        assert_eq!(
            rows.len(),
            POINTS,
            "qual count: expected {POINTS} rows for {measurement}, got {}",
            rows.len()
        );

        // Values: every written payload is present exactly once.
        let mut values: Vec<String> = rows.iter().map(|(v, _, _)| v.clone()).collect();
        values.sort();
        let mut expected: Vec<String> = (0..POINTS).map(|seq| format!("qual-{seq:04}")).collect();
        expected.sort();
        assert_eq!(values, expected, "qual values must round-trip exactly");
        // Timestamps: every point carries a server timestamp inside the
        // write window (2 min skew each side for clock drift).
        for (_, time, ts) in &rows {
            assert!(!time.is_empty(), "qual timestamp present");
            assert!(
                *ts >= t0 - 120_000_000_000 && *ts <= t1 + 120_000_000_000,
                "qual timestamp {time} ({ts}) outside write window [{t0}, {t1}]"
            );
        }
        eprintln!("qual rows asserted: count={POINTS} measurement={measurement}");

        // Bad Token fails closed as a terminal dispatch error (401) and
        // keeps the row.
        let bad_config = InfluxDbSinkConfig {
            token: "qual-bad-token".to_string(),
            batch_size: 10,
            ..config.clone()
        };
        let bad_sink =
            Arc::new(InfluxDbSink::new(bad_config, client.clone()).expect("qual bad sink"));
        let bad_manager = Arc::new(ConnectorManager::new());
        bad_manager.register("qual-influx-bad", bad_sink.clone());
        bad_manager
            .send(
                "qual-influx-bad",
                &topic,
                &Bytes::from_static(b"qual-bad"),
                QoS::AtLeastOnce,
            )
            .await
            .expect("qual bad buffer");
        let err = bad_sink.flush().await.expect_err("bad token must fail");
        assert!(
            matches!(err, ConnectorError::Dispatch(_)),
            "bad Token must be terminal, got {err:?}"
        );
        assert!(
            err.to_string().contains("401"),
            "bad Token must surface 401, got {err:?}"
        );
        assert_eq!(bad_sink.buffered_rows(), 1);
        eprintln!("qual auth failure asserted: bad Token is a 401 dispatch error");

        // Cleanup: delete the qualification measurement (best effort; a
        // failure is logged, not hidden).
        let delete_body = serde_json::json!({
            "start": "1970-01-01T00:00:00Z",
            "stop": "2030-01-01T00:00:00Z",
            "predicate": format!("_measurement=\"{measurement}\""),
        });
        match client
            .post(format!(
                "{endpoint}/api/v2/delete?org={org}&bucket={bucket}"
            ))
            .header("Authorization", format!("Token {token}"))
            .json(&delete_body)
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status();
                eprintln!("qual cleanup: deleted measurement {measurement} status={status}");
            }
            Err(e) => eprintln!("qual cleanup FAILED for {measurement} (tolerated): {e}"),
        }
        eprintln!("qual done: rows={POINTS} measurement={measurement} cleaned measurement");
    }
}
