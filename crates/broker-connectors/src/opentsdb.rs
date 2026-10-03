//! OpenTSDB metric ingestion sink (INDRA-175).
//!
//! High-performance time-series metric ingestion sink supporting OpenTSDB HTTP
//! REST (`/api/put?summary`) and Telnet protocols with tag extraction,
//! character sanitization, and gzip compression.

use async_trait::async_trait;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use flate2::write::GzEncoder;
use flate2::Compression;
use parking_lot::Mutex;
use reqwest::header::{CONTENT_ENCODING, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::{now_millis, BackoffState, BatchQueue, Connector, ConnectorError, Result, Sink};

fn default_opentsdb_protocol() -> OpenTsdbProtocol {
    OpenTsdbProtocol::Http
}

fn default_true() -> bool {
    true
}

fn default_opentsdb_compression() -> OpenTsdbCompression {
    OpenTsdbCompression::None
}

fn default_batch_size_1000() -> Option<usize> {
    Some(1000)
}

/// Default outer backlog ceiling: 10_000 rows (about ten 1_000-row
/// flushes) so a burst or a stalled server cannot grow the queue
/// without bound while backoff is engaged, while steady throughput
/// still fits in memory. Reason: the connector's send path runs behind
/// the rule engine's bounded queue, so this is a backstop, not new
/// work on the publish path.
fn default_buffer_capacity_10k() -> Option<usize> {
    Some(10_000)
}

/// OpenTSDB transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OpenTsdbProtocol {
    Http,
    Telnet,
}

/// OpenTSDB payload compression codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OpenTsdbCompression {
    None,
    Gzip,
}

/// Configuration for OpenTSDB metric ingestion sink.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenTsdbConfig {
    /// Endpoint URL (e.g. `http://localhost:4242` or `telnet://localhost:4242`).
    pub endpoint: String,
    /// Protocol mode (Http or Telnet).
    #[serde(default = "default_opentsdb_protocol")]
    pub protocol: OpenTsdbProtocol,
    /// Metric name template (e.g. `telemetry.${topic_segment_1}`).
    pub metric_template: String,
    /// Hash map of tag keys to field templates (e.g. `{"host": "${client_id}", "device": "${payload.device_id}"}`).
    #[serde(default)]
    pub tag_mappings: HashMap<String, String>,
    /// Field source for metric numeric value (e.g. `${payload.temp}` or `value`).
    pub value_field: String,
    /// Request summary metrics `?summary` on HTTP PUT (default true).
    #[serde(default = "default_true")]
    pub summary: bool,
    /// Payload compression codec (None or Gzip).
    #[serde(default = "default_opentsdb_compression")]
    pub compression: OpenTsdbCompression,
    /// Batch flush size (default 1,000 rows: keeps each HTTP or telnet
    /// flush well under a MiB while amortising request overhead; `None`
    /// maps to the same finite default, never unlimited).
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

impl OpenTsdbConfig {
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
                "opentsdb endpoint cannot be empty".into(),
            ));
        }
        if self.metric_template.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "opentsdb metric_template cannot be empty".into(),
            ));
        }
        if self.value_field.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "opentsdb value_field cannot be empty".into(),
            ));
        }
        if self.batch_size == Some(0) {
            return Err(ConnectorError::Dispatch(
                "opentsdb batch_size must be >= 1".into(),
            ));
        }
        if self.buffer_capacity == Some(0) {
            return Err(ConnectorError::Dispatch(
                "opentsdb buffer_capacity must be >= 1".into(),
            ));
        }
        match self.protocol {
            OpenTsdbProtocol::Http => {
                let endpoint = self.endpoint.trim();
                if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
                    return Err(ConnectorError::Dispatch(format!(
                        "opentsdb http endpoint must be http(s): {endpoint:?}"
                    )));
                }
            }
            OpenTsdbProtocol::Telnet => {
                // Fail closed on an unparseable telnet target instead of
                // dialling the wrong host at flush time.
                parse_telnet_addr(&self.endpoint)?;
            }
        }
        Ok(())
    }
}

/// Parse a telnet endpoint into `host:port` for a plain TCP dial.
/// Accepts `telnet://host:port`, `tcp://host:port` or bare
/// `host:port`; a bare host defaults to the vendor telnet port 4242
/// (OpenTSDB telnet listens on 4242 by default). Fails closed with a
/// dispatch error when no host remains.
pub fn parse_telnet_addr(endpoint: &str) -> Result<String> {
    let trimmed = endpoint.trim();
    if trimmed.is_empty() {
        return Err(ConnectorError::Dispatch(
            "opentsdb telnet endpoint cannot be empty".into(),
        ));
    }
    let without_scheme = match trimmed.split_once("://") {
        Some((_, rest)) => rest.trim(),
        None => trimmed,
    };
    let hostport = without_scheme.trim_end_matches('/').trim();
    if hostport.is_empty() {
        return Err(ConnectorError::Dispatch(format!(
            "opentsdb telnet endpoint has no host: {endpoint:?}"
        )));
    }
    if hostport.contains(':') {
        let (host, port) = hostport.rsplit_once(':').unwrap_or((hostport, ""));
        if host.trim().is_empty() || port.trim().is_empty() {
            return Err(ConnectorError::Dispatch(format!(
                "opentsdb telnet endpoint needs host:port: {endpoint:?}"
            )));
        }
        // Validate the port parses; the value itself is passed through
        // to the dial so the failure stays actionable.
        port.trim().parse::<u16>().map_err(|_| {
            ConnectorError::Dispatch(format!(
                "opentsdb telnet endpoint has a bad port: {endpoint:?}"
            ))
        })?;
        Ok(format!("{}:{}", host.trim(), port.trim()))
    } else {
        // Reason: 4242 is the vendor telnet default; a bare host keeps
        // stored configuration working without guessing a new port.
        Ok(format!("{hostport}:4242"))
    }
}

/// Sanitizes an OpenTSDB metric or tag key/value string.
/// OpenTSDB permits: `[a-zA-Z0-9_.-/]`
pub fn sanitize_opentsdb_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-' || c == '/' {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "default".to_string()
    } else {
        out
    }
}

/// An individual OpenTSDB data point.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenTsdbDataPoint {
    pub metric: String,
    pub timestamp: i64,
    pub value: f64,
    pub tags: HashMap<String, String>,
}

/// Summary response returned by OpenTSDB HTTP `/api/put?summary`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenTsdbSummaryResponse {
    pub success: usize,
    pub failed: usize,
    #[serde(default)]
    pub errors: Vec<String>,
}

/// Serialize data points to OpenTSDB Telnet line protocol.
/// Format: `put <metric> <timestamp> <value> <tagk1=tagv1> <tagk2=tagv2>\n`
pub fn serialize_telnet_lines(points: &[OpenTsdbDataPoint]) -> String {
    let mut out = String::new();
    for p in points {
        out.push_str("put ");
        out.push_str(&p.metric);
        out.push(' ');
        out.push_str(&p.timestamp.to_string());
        out.push(' ');
        out.push_str(&p.value.to_string());

        let mut sorted_tags: Vec<(&String, &String)> = p.tags.iter().collect();
        sorted_tags.sort_by(|a, b| a.0.cmp(b.0));

        for (k, v) in sorted_tags {
            out.push(' ');
            out.push_str(k);
            out.push('=');
            out.push_str(v);
        }
        out.push('\n');
    }
    out
}

/// Extract path from JSON (e.g. `${payload.temp}` or `metrics.temp`).
pub fn extract_numeric_value(val: &serde_json::Value, field_expr: &str) -> Option<f64> {
    let clean = field_expr
        .trim_start_matches("${")
        .trim_end_matches('}')
        .trim_start_matches("payload.");

    if clean.is_empty() {
        return val.as_f64();
    }

    let parts: Vec<&str> = clean.split('.').collect();
    let mut curr = val;
    for (i, part) in parts.iter().enumerate() {
        match curr {
            serde_json::Value::Object(map) => {
                if let Some(next) = map.get(*part) {
                    curr = next;
                } else if i == 0 {
                    curr = map.get("payload").and_then(|p| p.get(*part))?;
                } else {
                    return None;
                }
            }
            _ => return None,
        }
    }

    if let Some(f) = curr.as_f64() {
        Some(f)
    } else if let Some(i) = curr.as_i64() {
        Some(i as f64)
    } else if let Some(s) = curr.as_str() {
        s.parse::<f64>().ok()
    } else {
        None
    }
}

/// Extract nested value from JSON object by dot-separated path.
fn extract_json_path<'a>(val: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
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

/// Render template string with `${var}` substitutions, leaving literals intact.
pub fn render_opentsdb_template(template: &str, val: &serde_json::Value, topic: &str) -> String {
    if !template.contains("${") {
        return template.to_string();
    }

    let mut out = String::with_capacity(template.len() + 16);
    let mut chars = template.chars().peekable();
    let segments: Vec<&str> = topic.split('/').collect();

    while let Some(c) = chars.next() {
        if c == '$' && chars.peek() == Some(&'{') {
            chars.next(); // consume '{'
            let mut var = String::new();
            let mut closed = false;
            for vc in chars.by_ref() {
                if vc == '}' {
                    closed = true;
                    break;
                }
                var.push(vc);
            }

            if !closed {
                out.push('$');
                out.push('{');
                out.push_str(&var);
                break;
            }

            if var == "topic" {
                out.push_str(topic);
            } else if var.starts_with("topic_segment_") {
                if let Ok(idx) = var.trim_start_matches("topic_segment_").parse::<usize>() {
                    if idx < segments.len() {
                        out.push_str(segments[idx]);
                    } else {
                        out.push_str("unknown");
                    }
                } else {
                    out.push_str("unknown");
                }
            } else {
                let json_path = var.trim_start_matches("payload.");
                if let Some(v) = extract_json_path(val, json_path)
                    .or_else(|| val.get(&var))
                    .or_else(|| val.get("payload").and_then(|p| p.get(json_path)))
                {
                    match v {
                        serde_json::Value::String(s) => out.push_str(s),
                        serde_json::Value::Number(n) => out.push_str(&n.to_string()),
                        serde_json::Value::Bool(b) => out.push_str(&b.to_string()),
                        other => out.push_str(&other.to_string()),
                    }
                } else {
                    out.push_str("unknown");
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Extract single data point from MQTT event.
pub fn extract_opentsdb_point(
    payload: &[u8],
    topic: &str,
    config: &OpenTsdbConfig,
) -> Result<OpenTsdbDataPoint> {
    let json_val: serde_json::Value = serde_json::from_slice(payload)
        .map_err(|e| ConnectorError::Dispatch(format!("invalid JSON payload: {e}")))?;

    let metric_raw = render_opentsdb_template(&config.metric_template, &json_val, topic);
    let metric = sanitize_opentsdb_string(&metric_raw);

    let value = extract_numeric_value(&json_val, &config.value_field).unwrap_or(0.0);

    let ts_sec = now_millis() / 1000;

    let mut tags = HashMap::new();
    if config.tag_mappings.is_empty() {
        tags.insert("topic".to_string(), sanitize_opentsdb_string(topic));
    } else {
        for (k, v) in &config.tag_mappings {
            let tag_val_raw = render_opentsdb_template(v, &json_val, topic);
            let safe_k = sanitize_opentsdb_string(k);
            let safe_v = sanitize_opentsdb_string(&tag_val_raw);
            tags.insert(safe_k, safe_v);
        }
    }

    Ok(OpenTsdbDataPoint {
        metric,
        timestamp: ts_sec,
        value,
        tags,
    })
}

/// Transport abstraction for OpenTSDB.
#[async_trait]
pub trait OpenTsdbTransport: Send + Sync {
    async fn put_http(
        &self,
        points: &[OpenTsdbDataPoint],
        gzip: bool,
    ) -> Result<OpenTsdbSummaryResponse>;
    async fn put_telnet(&self, telnet_data: &str) -> Result<()>;
}

/// Production HTTP and Telnet transport for OpenTSDB.
///
/// HTTP rides the maintained `reqwest` client (connection pooling,
/// TLS, gzip); telnet rides plain `tokio` TCP (no maintained Rust
/// driver exists for the OpenTSDB telnet `put` line protocol, so the
/// sink owns the few lines of socket code). One TCP connection per
/// flush keeps the code fail-closed without a pool to bound; the
/// connector's send path runs behind the rule engine's bounded queue
/// (see the buffer ceiling on [`OpenTsdbConfig`]), so this is not on
/// the broker's publish path.
// PERF(parity): reuse one pooled telnet connection per sink instead of
// dialling per flush when flush rates grow.
pub struct NetworkOpenTsdbTransport {
    client: reqwest::Client,
    http_url: String,
    telnet_addr: String,
    timeout: Duration,
}

impl NetworkOpenTsdbTransport {
    pub fn new(config: &OpenTsdbConfig) -> Self {
        let base = config.endpoint.trim_end_matches('/');
        let http_url = if config.summary {
            format!("{base}/api/put?summary")
        } else {
            format!("{base}/api/put")
        };
        // The telnet target derives from the same endpoint string so a
        // stored configuration keeps working: `telnet://host:port` or
        // bare `host:port`. An unparseable endpoint fails closed at
        // validate time; here fall back to the raw endpoint so the
        // flush error names the configured value.
        let telnet_addr = parse_telnet_addr(&config.endpoint)
            .unwrap_or_else(|_| config.endpoint.trim().to_string());
        let timeout = config.timeout();
        Self {
            client: reqwest::Client::builder()
                .timeout(timeout)
                .build()
                .unwrap_or_default(),
            http_url,
            telnet_addr,
            timeout,
        }
    }

    /// Telnet target this transport dials (resolved at construction).
    pub fn telnet_addr(&self) -> &str {
        &self.telnet_addr
    }

    /// HTTP `/api/put` URL this transport posts to.
    pub fn http_url(&self) -> &str {
        &self.http_url
    }
}

#[async_trait]
impl OpenTsdbTransport for NetworkOpenTsdbTransport {
    async fn put_http(
        &self,
        points: &[OpenTsdbDataPoint],
        gzip: bool,
    ) -> Result<OpenTsdbSummaryResponse> {
        let json_body = serde_json::to_vec(points)
            .map_err(|e| ConnectorError::Dispatch(format!("failed to serialize points: {e}")))?;

        let mut req = self
            .client
            .post(&self.http_url)
            .header(CONTENT_TYPE, "application/json");

        if gzip {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder
                .write_all(&json_body)
                .map_err(|e| ConnectorError::Dispatch(format!("gzip compression failed: {e}")))?;
            let compressed = encoder
                .finish()
                .map_err(|e| ConnectorError::Dispatch(format!("gzip finish failed: {e}")))?;
            req = req.header(CONTENT_ENCODING, "gzip").body(compressed);
        } else {
            req = req.body(json_body);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| ConnectorError::Connection(format!("opentsdb http error: {e}")))?;

        let status = resp.status();
        let body_text = resp.text().await.unwrap_or_default();

        if status.is_success() {
            if let Ok(summary) = serde_json::from_str::<OpenTsdbSummaryResponse>(&body_text) {
                if summary.failed > 0 {
                    return Err(ConnectorError::Connection(format!(
                        "opentsdb partial failure: {} succeeded, {} failed",
                        summary.success, summary.failed
                    )));
                }
                Ok(summary)
            } else {
                Ok(OpenTsdbSummaryResponse {
                    success: points.len(),
                    failed: 0,
                    errors: Vec::new(),
                })
            }
        } else if status.as_u16() >= 500 || status.as_u16() == 429 {
            Err(ConnectorError::Connection(format!(
                "opentsdb transient http error {status}: {body_text}"
            )))
        } else {
            Err(ConnectorError::Dispatch(format!(
                "opentsdb terminal http error {status}: {body_text}"
            )))
        }
    }

    async fn put_telnet(&self, telnet_data: &str) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        if telnet_data.is_empty() {
            return Ok(());
        }
        let addr = self.telnet_addr.clone();
        let timeout = self.timeout;
        let mut stream = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr))
            .await
            .map_err(|_| {
                ConnectorError::Connection(format!("opentsdb telnet connect timeout: {addr}"))
            })?
            .map_err(|e| {
                ConnectorError::Connection(format!("opentsdb telnet connect failed: {e}"))
            })?;
        tokio::time::timeout(timeout, stream.write_all(telnet_data.as_bytes()))
            .await
            .map_err(|_| {
                ConnectorError::Connection(format!("opentsdb telnet write timeout: {addr}"))
            })?
            .map_err(|e| {
                ConnectorError::Connection(format!("opentsdb telnet write failed: {e}"))
            })?;
        tokio::time::timeout(timeout, stream.flush())
            .await
            .map_err(|_| {
                ConnectorError::Connection(format!("opentsdb telnet flush timeout: {addr}"))
            })?
            .map_err(|e| {
                ConnectorError::Connection(format!("opentsdb telnet flush failed: {e}"))
            })?;
        Ok(())
    }
}

/// Mock transport for unit testing and loopback verification.
pub struct MockOpenTsdbTransport {
    pub captured_points: Mutex<Vec<OpenTsdbDataPoint>>,
    pub captured_telnet: Mutex<Vec<String>>,
    pub fail_count: Mutex<usize>,
    pub is_terminal: Mutex<bool>,
}

impl MockOpenTsdbTransport {
    pub fn new() -> Self {
        Self {
            captured_points: Mutex::new(Vec::new()),
            captured_telnet: Mutex::new(Vec::new()),
            fail_count: Mutex::new(0),
            is_terminal: Mutex::new(false),
        }
    }

    pub fn with_transient_failures(failures: usize) -> Self {
        Self {
            captured_points: Mutex::new(Vec::new()),
            captured_telnet: Mutex::new(Vec::new()),
            fail_count: Mutex::new(failures),
            is_terminal: Mutex::new(false),
        }
    }

    pub fn with_terminal_failure() -> Self {
        Self {
            captured_points: Mutex::new(Vec::new()),
            captured_telnet: Mutex::new(Vec::new()),
            fail_count: Mutex::new(1),
            is_terminal: Mutex::new(true),
        }
    }
}

impl Default for MockOpenTsdbTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl OpenTsdbTransport for MockOpenTsdbTransport {
    async fn put_http(
        &self,
        points: &[OpenTsdbDataPoint],
        _gzip: bool,
    ) -> Result<OpenTsdbSummaryResponse> {
        self.captured_points.lock().extend_from_slice(points);

        let mut fails = self.fail_count.lock();
        if *fails > 0 {
            *fails -= 1;
            if *self.is_terminal.lock() {
                return Err(ConnectorError::Dispatch(
                    "mock opentsdb 400 bad request".into(),
                ));
            } else {
                return Err(ConnectorError::Connection(
                    "mock opentsdb 503 service unavailable".into(),
                ));
            }
        }

        Ok(OpenTsdbSummaryResponse {
            success: points.len(),
            failed: 0,
            errors: Vec::new(),
        })
    }

    async fn put_telnet(&self, telnet_data: &str) -> Result<()> {
        self.captured_telnet.lock().push(telnet_data.to_string());
        Ok(())
    }
}

/// OpenTSDB metric ingestion sink.
pub struct OpenTsdbSink {
    config: OpenTsdbConfig,
    transport: Arc<dyn OpenTsdbTransport>,
    queue: Mutex<BatchQueue<OpenTsdbDataPoint>>,
    backoff: Mutex<BackoffState>,
    sent: AtomicU64,
}

impl OpenTsdbSink {
    pub fn new(config: OpenTsdbConfig, transport: Arc<dyn OpenTsdbTransport>) -> Result<Self> {
        config.validate()?;
        // Reason: ~1 KiB per HTTP/telnet flush amortises request
        // overhead while keeping each flush well under a MiB; `None`
        // maps to the same finite default, never unlimited.
        let batch_size = config.batch_size.unwrap_or(1000).max(1);
        Ok(Self {
            config,
            transport,
            // Reason: 50 ms linger bounds flush latency for sparse
            // series while full batches still flush immediately.
            queue: Mutex::new(BatchQueue::new(batch_size, Duration::from_millis(50))),
            backoff: Mutex::new(BackoffState::default()),
            sent: AtomicU64::new(0),
        })
    }

    pub fn config(&self) -> &OpenTsdbConfig {
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

        let (points, oldest) = {
            let mut q = self.queue.lock();
            if q.is_empty() {
                return Ok(());
            }
            q.take_batch()
        };

        if points.is_empty() {
            return Ok(());
        }

        match self.config.protocol {
            OpenTsdbProtocol::Http => {
                let gzip = self.config.compression == OpenTsdbCompression::Gzip;
                match self.transport.put_http(&points, gzip).await {
                    Ok(summary) => {
                        self.backoff.lock().success();
                        self.sent
                            .fetch_add(summary.success as u64, Ordering::Relaxed);
                        Ok(())
                    }
                    Err(e) => {
                        self.backoff.lock().failure();
                        self.queue.lock().restore(points, oldest);
                        Err(e)
                    }
                }
            }
            OpenTsdbProtocol::Telnet => {
                let telnet_body = serialize_telnet_lines(&points);
                match self.transport.put_telnet(&telnet_body).await {
                    Ok(_) => {
                        self.backoff.lock().success();
                        self.sent.fetch_add(points.len() as u64, Ordering::Relaxed);
                        Ok(())
                    }
                    Err(e) => {
                        self.backoff.lock().failure();
                        self.queue.lock().restore(points, oldest);
                        Err(e)
                    }
                }
            }
        }
    }
}

#[async_trait]
impl Sink for OpenTsdbSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, _qos: QoS) -> Result<()> {
        let point = extract_opentsdb_point(payload, topic.as_str(), &self.config)?;
        let should_flush = {
            let mut q = self.queue.lock();
            // Backstop bound (connector send path runs behind the rule
            // engine's bounded queue): fail closed instead of growing
            // without bound while backoff is engaged.
            if q.len() >= self.config.effective_buffer_capacity() {
                return Err(ConnectorError::Connection(format!(
                    "opentsdb buffer full ({} rows): failing closed",
                    self.config.effective_buffer_capacity()
                )));
            }
            q.push(point)
        };

        if should_flush {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "opentsdb"
    }
}

/// Addressable registered connector for OpenTSDB.
pub struct OpenTsdbConnector {
    id: String,
    sink: Arc<OpenTsdbSink>,
}

impl OpenTsdbConnector {
    pub fn new(id: impl Into<String>, sink: Arc<OpenTsdbSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }

    pub fn sink(&self) -> Arc<OpenTsdbSink> {
        self.sink.clone()
    }
}

impl Connector for OpenTsdbConnector {
    fn connector_id(&self) -> &str {
        &self.id
    }

    fn kind(&self) -> &'static str {
        "opentsdb"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_http_config() -> OpenTsdbConfig {
        let mut tags = HashMap::new();
        tags.insert("host".to_string(), "${payload.host}".to_string());
        tags.insert("sensor".to_string(), "temp".to_string());

        OpenTsdbConfig {
            endpoint: "http://localhost:4242".to_string(),
            protocol: OpenTsdbProtocol::Http,
            metric_template: "factory.telemetry".to_string(),
            tag_mappings: tags,
            value_field: "${payload.temperature}".to_string(),
            summary: true,
            compression: OpenTsdbCompression::None,
            batch_size: Some(1),
            buffer_capacity: None,
            timeout_ms: None,
        }
    }

    fn sample_telnet_config() -> OpenTsdbConfig {
        let mut tags = HashMap::new();
        tags.insert("machine".to_string(), "${payload.device_id}".to_string());

        OpenTsdbConfig {
            endpoint: "telnet://localhost:4242".to_string(),
            protocol: OpenTsdbProtocol::Telnet,
            metric_template: "plant.${topic_segment_1}".to_string(),
            tag_mappings: tags,
            value_field: "temperature".to_string(),
            summary: false,
            compression: OpenTsdbCompression::None,
            batch_size: Some(1),
            buffer_capacity: None,
            timeout_ms: None,
        }
    }

    #[test]
    fn test_tag_and_metric_sanitization() {
        assert_eq!(
            sanitize_opentsdb_string("telemetry@factory#1"),
            "telemetry_factory_1"
        );
        assert_eq!(
            sanitize_opentsdb_string("clean.name-123/sub_tag"),
            "clean.name-123/sub_tag"
        );
        assert_eq!(sanitize_opentsdb_string(""), "default");
    }

    #[test]
    fn test_telnet_serialization_format() {
        let mut tags = HashMap::new();
        tags.insert("host".to_string(), "server01".to_string());
        tags.insert("rack".to_string(), "a_1".to_string());

        let points = vec![OpenTsdbDataPoint {
            metric: "sys.cpu".to_string(),
            timestamp: 1726000000,
            value: 42.5,
            tags,
        }];

        let lines = serialize_telnet_lines(&points);
        assert_eq!(
            lines,
            "put sys.cpu 1726000000 42.5 host=server01 rack=a_1\n"
        );
    }

    #[test]
    fn test_gzip_compression_logic() {
        let points = vec![OpenTsdbDataPoint {
            metric: "test.metric".to_string(),
            timestamp: 1000,
            value: 99.9,
            tags: HashMap::new(),
        }];

        let json_bytes = serde_json::to_vec(&points).unwrap();
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&json_bytes).unwrap();
        let compressed = encoder.finish().unwrap();

        assert!(!compressed.is_empty());
        assert_eq!(compressed[0], 0x1f); // gzip magic 1
        assert_eq!(compressed[1], 0x8b); // gzip magic 2
    }

    #[test]
    fn test_point_extraction_from_event() {
        let cfg = sample_http_config();
        let payload = br#"{"host": "node-42", "temperature": 88.5}"#;
        let pt = extract_opentsdb_point(payload, "sensors/temp", &cfg).expect("valid point");

        assert_eq!(pt.metric, "factory.telemetry");
        assert_eq!(pt.value, 88.5);
        assert_eq!(pt.tags.get("host").unwrap(), "node-42");
        assert_eq!(pt.tags.get("sensor").unwrap(), "temp");
    }

    #[test]
    fn test_summary_response_parsing() {
        let json_str = r#"{"success": 95, "failed": 5, "errors": ["invalid tag"]}"#;
        let summary: OpenTsdbSummaryResponse = serde_json::from_str(json_str).unwrap();
        assert_eq!(summary.success, 95);
        assert_eq!(summary.failed, 5);
        assert_eq!(summary.errors.len(), 1);
    }

    #[tokio::test]
    async fn test_opentsdb_sink_http_loopback() {
        let cfg = sample_http_config();
        let transport = Arc::new(MockOpenTsdbTransport::new());
        let sink = OpenTsdbSink::new(cfg, transport.clone()).expect("valid sink");

        let topic = Topic::new("sensors/temp").unwrap();
        let payload = Bytes::from_static(br#"{"host": "edge-01", "temperature": 75.0}"#);

        sink.send(&topic, &payload, QoS::AtLeastOnce)
            .await
            .expect("send succeeds");

        let pts = transport.captured_points.lock();
        assert_eq!(pts.len(), 1);
        assert_eq!(pts[0].metric, "factory.telemetry");
        assert_eq!(pts[0].value, 75.0);
        assert_eq!(sink.sent_count(), 1);
    }

    #[tokio::test]
    async fn test_opentsdb_sink_telnet_loopback() {
        let cfg = sample_telnet_config();
        let transport = Arc::new(MockOpenTsdbTransport::new());
        let sink = OpenTsdbSink::new(cfg, transport.clone()).expect("valid sink");

        let topic = Topic::new("facility/press_1").unwrap();
        let payload = Bytes::from_static(br#"{"device_id": "press_1", "temperature": 120.4}"#);

        sink.send(&topic, &payload, QoS::AtLeastOnce)
            .await
            .expect("send succeeds");

        let lines = transport.captured_telnet.lock();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].starts_with("put plant.press_1 "));
        assert!(lines[0].contains(" 120.4 machine=press_1\n"));
        assert_eq!(sink.sent_count(), 1);
    }

    #[tokio::test]
    async fn test_opentsdb_sink_transient_retry_and_terminal_abort() {
        let cfg = sample_http_config();
        // 1 transient failure, then retry
        let transport = Arc::new(MockOpenTsdbTransport::with_transient_failures(1));
        let sink = OpenTsdbSink::new(cfg, transport.clone()).expect("valid sink");

        let topic = Topic::new("sensors/temp").unwrap();
        let payload = Bytes::from_static(br#"{"host": "edge-02", "temperature": 80.0}"#);

        let res = sink.send(&topic, &payload, QoS::AtLeastOnce).await;
        assert!(res.is_err());

        // Reset backoff and retry flush
        *sink.backoff.lock() = BackoffState::default();
        sink.flush().await.expect("flush succeeds on retry");
        assert_eq!(sink.sent_count(), 1);

        // Terminal error
        let term_transport = Arc::new(MockOpenTsdbTransport::with_terminal_failure());
        let term_sink =
            OpenTsdbSink::new(sample_http_config(), term_transport).expect("valid sink");
        let term_res = term_sink.send(&topic, &payload, QoS::AtLeastOnce).await;
        assert!(term_res.is_err());
        assert!(matches!(
            term_res.err().unwrap(),
            ConnectorError::Dispatch(_)
        ));
    }

    #[tokio::test]
    async fn test_network_telnet_transport_writes_line_protocol() {
        use tokio::io::{AsyncBufReadExt, BufReader};
        use tokio::net::TcpListener;
        use tokio::sync::mpsc;

        // Loopback TCP server captures exactly what the production
        // telnet path writes: the stub must never return success
        // without touching the socket.
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("loopback addr");
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            let mut reader = BufReader::new(socket);
            let mut line = String::new();
            let mut collected = String::new();
            loop {
                line.clear();
                let n = reader.read_line(&mut line).await.expect("read line");
                if n == 0 {
                    break;
                }
                collected.push_str(&line);
                // One flush writes one line for batch_size 1.
                if collected.ends_with('\n') {
                    break;
                }
            }
            tx.send(collected).expect("capture");
        });

        let mut cfg = sample_telnet_config();
        cfg.endpoint = format!("telnet://{addr}");
        cfg.timeout_ms = Some(5000);
        let transport = NetworkOpenTsdbTransport::new(&cfg);
        assert_eq!(transport.telnet_addr(), &addr.to_string());
        transport
            .put_telnet("put sys.cpu 1726000000 42.5 host=server01\n")
            .await
            .expect("production telnet put writes to the socket");
        let captured = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("capture timeout")
            .expect("captured line");
        assert_eq!(captured, "put sys.cpu 1726000000 42.5 host=server01\n");
        server.abort();

        // An unroutable telnet target fails closed as a connection
        // error (retryable), never as success and never as a stub
        // dispatch error.
        let mut dead_cfg = sample_telnet_config();
        dead_cfg.endpoint = "telnet://127.0.0.1:1".to_string();
        dead_cfg.timeout_ms = Some(500);
        let dead = NetworkOpenTsdbTransport::new(&dead_cfg);
        let err = dead
            .put_telnet("put sys.cpu 1726000000 42.5 host=server01\n")
            .await
            .expect_err("refused telnet port must fail");
        assert!(
            matches!(err, ConnectorError::Connection(_)),
            "telnet dial failure must be a connection error, got {err:?}"
        );
    }

    #[test]
    fn test_parse_telnet_addr_vectors() {
        assert_eq!(
            parse_telnet_addr("telnet://localhost:4242").unwrap(),
            "localhost:4242"
        );
        assert_eq!(
            parse_telnet_addr("127.0.0.1:4242").unwrap(),
            "127.0.0.1:4242"
        );
        assert_eq!(
            parse_telnet_addr("telnet://db.internal").unwrap(),
            "db.internal:4242"
        );
        assert!(parse_telnet_addr("").is_err());
        assert!(parse_telnet_addr("telnet://").is_err());
        assert!(parse_telnet_addr("telnet://host:bad").is_err());
    }

    #[test]
    fn test_buffer_capacity_default_is_finite_and_back_compatible() {
        let mut cfg = sample_http_config();
        // Stored configurations without the field parse to the same
        // finite default so they keep working.
        let json = serde_json::json!({
            "endpoint": "http://localhost:4242",
            "metric_template": "m",
            "value_field": "v",
        });
        let parsed: OpenTsdbConfig = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.buffer_capacity, Some(10_000));
        assert_eq!(parsed.effective_buffer_capacity(), 10_000);
        // Explicit null still maps to the finite default, never
        // unlimited: the code never chooses unbounded.
        cfg.buffer_capacity = None;
        assert_eq!(cfg.effective_buffer_capacity(), 10_000);
        cfg.buffer_capacity = Some(0);
        assert!(cfg.validate().is_err());
        cfg.buffer_capacity = Some(10);
        assert_eq!(cfg.effective_buffer_capacity(), 10);
    }

    #[tokio::test]
    async fn test_buffer_full_fails_closed() {
        let mut cfg = sample_http_config();
        cfg.batch_size = Some(10);
        cfg.buffer_capacity = Some(2);
        let transport = Arc::new(MockOpenTsdbTransport::new());
        let sink = OpenTsdbSink::new(cfg, transport).expect("valid sink");
        let topic = Topic::new("sensors/temp").unwrap();
        for suffix in ["a", "b"] {
            let payload = Bytes::from(format!(
                r#"{{"host": "edge-{suffix}", "temperature": 75.0}}"#
            ));
            sink.send(&topic, &payload, QoS::AtLeastOnce)
                .await
                .expect("row fits under the bound");
        }
        assert_eq!(sink.buffered_rows(), 2);
        let payload = Bytes::from_static(br#"{"host": "edge-c", "temperature": 76.0}"#);
        let err = sink
            .send(&topic, &payload, QoS::AtLeastOnce)
            .await
            .expect_err("full buffer must fail closed");
        assert!(
            matches!(err, ConnectorError::Connection(_)),
            "buffer-full must be a connection error, got {err:?}"
        );
        assert_eq!(sink.buffered_rows(), 2);
    }

    #[tokio::test]
    async fn test_backoff_keeps_buffered_rows() {
        let mut cfg = sample_http_config();
        cfg.batch_size = Some(10);
        let transport = Arc::new(MockOpenTsdbTransport::with_transient_failures(1));
        let sink = OpenTsdbSink::new(cfg, transport.clone()).expect("valid sink");

        let topic = Topic::new("sensors/temp").unwrap();
        let payload1 = Bytes::from_static(br#"{"host": "edge-10", "temperature": 75.0}"#);
        let payload2 = Bytes::from_static(br#"{"host": "edge-11", "temperature": 76.5}"#);

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
        let before = transport.captured_points.lock().len();
        sink.flush().await.expect("retry flush succeeds");
        assert_eq!(sink.buffered_rows(), 0);
        assert_eq!(sink.sent_count(), 2);
        let captured = transport.captured_points.lock();
        assert_eq!(captured.len() - before, 2);
    }

    fn qual_env(name: &str) -> Option<String> {
        std::env::var(name).ok().filter(|v| !v.trim().is_empty())
    }

    fn qual_require(name: &str) -> String {
        qual_env(name).unwrap_or_else(|| {
            panic!(
                "{name} must point at a real server for qualification; failing closed instead of passing vacuously"
            )
        })
    }

    fn qual_now_nanos() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos().min(i64::MAX as u128) as i64)
            .unwrap_or(0)
    }

    /// One exported time series from `/api/v1/export` (JSON line
    /// format): the label set plus its samples.
    struct QualSeries {
        seq: Option<String>,
        values: usize,
        timestamps: Vec<i64>,
    }

    /// Parse `/api/v1/export` JSON lines for one metric. Lines for
    /// other metrics are skipped; malformed lines fail the run (a
    /// tolerance with no protocol reason is a defect).
    fn qual_parse_export(body: &str, metric: &str) -> Vec<QualSeries> {
        let mut out = Vec::new();
        for raw in body.lines() {
            let line = raw.trim();
            if line.is_empty() {
                continue;
            }
            // Prometheus exposition fallback: `metric{seq="s0001"} v ts`.
            if !line.starts_with('{') {
                let head = line.split_whitespace().next().unwrap_or("");
                let name = head.split('{').next().unwrap_or("");
                if name != metric {
                    continue;
                }
                let seq = head
                    .split("seq=\"")
                    .nth(1)
                    .and_then(|rest| rest.split('"').next())
                    .map(str::to_string);
                // Timestamp is the trailing field in ms or s; keep it
                // best effort for the window check below.
                let ts = line
                    .split_whitespace()
                    .nth(2)
                    .and_then(|s| s.parse::<i64>().ok())
                    .map(|v| if v < 10_000_000_000 { v * 1000 } else { v });
                out.push(QualSeries {
                    seq,
                    values: 1,
                    timestamps: ts.into_iter().collect(),
                });
                continue;
            }
            let parsed: serde_json::Value = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("qual export line is not JSON: {e}: {line}"));
            let labels = parsed.get("metric").cloned().unwrap_or_default();
            let name = labels
                .get("__name__")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if name != metric {
                continue;
            }
            let seq = labels
                .get("seq")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let values = parsed
                .get("values")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            let timestamps = parsed
                .get("timestamps")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|v| v.as_i64()).collect::<Vec<i64>>())
                .unwrap_or_default();
            out.push(QualSeries {
                seq,
                values,
                timestamps,
            });
        }
        out
    }

    async fn qual_export_snapshot(
        client: &reqwest::Client,
        query_base: &str,
        metric: &str,
    ) -> Vec<QualSeries> {
        let url = format!("{}/api/v1/export", query_base.trim_end_matches('/'));
        let response = client
            .post(&url)
            .form(&[("match[]", metric), ("start", "-1d")])
            .send()
            .await
            .unwrap_or_else(|e| panic!("qual export request failed: {e:?}"));
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|e| panic!("qual export body failed: {e:?}"));
        if !status.is_success() {
            panic!("qual export status={status} body={body}");
        }
        qual_parse_export(&body, metric)
    }

    /// Qualification against a protocol-compatible server through the
    /// maintained `reqwest` HTTP and `tokio` telnet write paths.
    ///
    /// Run with e.g.:
    /// `OPENTSDB_HTTP_URL=http://127.0.0.1:4243 OPENTSDB_TELNET_ADDR=127.0.0.1:4242 OPENTSDB_QUERY_URL=http://127.0.0.1:8428 \
    ///  cargo test -p broker-connectors --lib opentsdb::tests::test_qualify_write_path -- --ignored --nocapture --test-threads=1`
    ///
    /// Streams 500 points per protocol through the broker's rule path
    /// ([`crate::ConnectorManager`] -> [`OpenTsdbSink`], one sink per
    /// protocol on the production [`NetworkOpenTsdbTransport`]), then
    /// reads them back through `OPENTSDB_QUERY_URL` (`/api/v1/export`)
    /// and asserts exactly 500 points per metric with distinct `seq`
    /// tags and timestamps inside the write window (no tolerance:
    /// at-least-once permits duplicates, never loss, and the per-row
    /// `seq` tags admit no merges). Panics when its environment is
    /// missing (fail closed, never skips).
    #[tokio::test]
    #[ignore = "needs a real server (see OPENTSDB_* env)"]
    async fn test_qualify_write_path() {
        use crate::ConnectorManager;

        const POINTS: usize = 500;

        let http_url = qual_require("OPENTSDB_HTTP_URL");
        let telnet_addr = qual_require("OPENTSDB_TELNET_ADDR");
        let query_base = qual_require("OPENTSDB_QUERY_URL");
        let http_url = http_url.trim_end_matches('/').to_string();
        let query_base = query_base.trim_end_matches('/').to_string();
        let telnet_endpoint = format!("telnet://{}", telnet_addr.trim());

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("qual http client");

        // Server identity for the report (best effort; never a
        // constant standing in for a measurement: omit when
        // unreachable).
        match client
            .get(format!("{query_base}/api/v1/status/buildinfo"))
            .timeout(Duration::from_secs(10))
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status();
                let text = response.text().await.unwrap_or_default();
                eprintln!(
                    "qual server: status={status} query={query_base} http={http_url} telnet={telnet_addr} buildinfo={}",
                    text.chars().take(300).collect::<String>()
                );
            }
            Err(e) => eprintln!("qual server: buildinfo unreachable (tolerated): {e}"),
        }

        // Unique metric names per run so reruns never mix rows.
        // Underscore/digits stay valid after sanitization.
        let suffix = (qual_now_nanos() % 1_000_000).abs();
        let metric_http = format!("qual_b332_http_{suffix:06}");
        let metric_telnet = format!("qual_b332_telnet_{suffix:06}");

        let mut tags = HashMap::new();
        tags.insert("seq".to_string(), "${payload.seq}".to_string());
        let http_config = OpenTsdbConfig {
            endpoint: http_url.clone(),
            protocol: OpenTsdbProtocol::Http,
            metric_template: metric_http.clone(),
            tag_mappings: tags.clone(),
            value_field: "${payload.temperature}".to_string(),
            summary: false,
            compression: OpenTsdbCompression::None,
            batch_size: Some(100),
            buffer_capacity: Some(10_000),
            timeout_ms: Some(30_000),
        };
        let mut telnet_config = http_config.clone();
        telnet_config.endpoint = telnet_endpoint.clone();
        telnet_config.protocol = OpenTsdbProtocol::Telnet;
        telnet_config.metric_template = metric_telnet.clone();
        http_config.validate().expect("qual http config validates");
        telnet_config
            .validate()
            .expect("qual telnet config validates");
        assert_eq!(http_config.effective_buffer_capacity(), 10_000);

        let http_sink = Arc::new(
            OpenTsdbSink::new(
                http_config.clone(),
                Arc::new(NetworkOpenTsdbTransport::new(&http_config)),
            )
            .expect("qual http sink"),
        );
        let telnet_sink = Arc::new(
            OpenTsdbSink::new(
                telnet_config.clone(),
                Arc::new(NetworkOpenTsdbTransport::new(&telnet_config)),
            )
            .expect("qual telnet sink"),
        );
        assert_eq!(http_sink.kind(), "opentsdb");
        assert_eq!(telnet_sink.kind(), "opentsdb");
        // The broker's path: rule actions deliver through the shared
        // connector manager, so the qualification sends through it.
        let manager = Arc::new(ConnectorManager::new());
        manager.register("qual-opentsdb-http", http_sink.clone());
        manager.register("qual-opentsdb-telnet", telnet_sink.clone());

        let topic = Topic::new("qual/b332").unwrap();
        let t0 = now_millis();
        for seq in 0..POINTS {
            let payload = Bytes::from(format!(
                r#"{{"temperature": {:.2}, "seq": "s{:04}"}}"#,
                20.0 + seq as f64 * 0.01,
                seq
            ));
            manager
                .send("qual-opentsdb-http", &topic, &payload, QoS::AtLeastOnce)
                .await
                .unwrap_or_else(|e| panic!("qual http send seq={seq} failed: {e:?}"));
        }
        for seq in 0..POINTS {
            let payload = Bytes::from(format!(
                r#"{{"temperature": {:.2}, "seq": "t{:04}"}}"#,
                30.0 + seq as f64 * 0.01,
                seq
            ));
            manager
                .send("qual-opentsdb-telnet", &topic, &payload, QoS::AtLeastOnce)
                .await
                .unwrap_or_else(|e| panic!("qual telnet send seq={seq} failed: {e:?}"));
        }
        http_sink.flush().await.expect("qual http flush");
        telnet_sink.flush().await.expect("qual telnet flush");
        let t1 = now_millis();
        assert_eq!(http_sink.buffered_rows(), 0);
        assert_eq!(telnet_sink.buffered_rows(), 0);
        assert_eq!(http_sink.sent_count(), POINTS as u64);
        assert_eq!(telnet_sink.sent_count(), POINTS as u64);
        eprintln!(
            "qual rows sent: http={POINTS} metric={metric_http} telnet={POINTS} metric={metric_telnet}"
        );

        // The witness buffers recent writes in memory; force-flush so
        // the export below sees them immediately (best effort).
        match client
            .get(format!("{query_base}/internal/force_flush"))
            .timeout(Duration::from_secs(10))
            .send()
            .await
        {
            Ok(response) => eprintln!("qual force_flush: status={}", response.status()),
            Err(e) => eprintln!("qual force_flush unreachable (tolerated): {e}"),
        }

        // Query-back from the server, not the counters: exact counts,
        // no tolerance (the per-row `seq` tags admit no merges and the
        // protocol permits duplicates, never loss).
        async fn qual_wait_metric(
            client: &reqwest::Client,
            query_base: &str,
            metric: &str,
            expect: usize,
        ) -> Vec<QualSeries> {
            let mut last: Vec<QualSeries> = Vec::new();
            for _ in 0..30 {
                last = qual_export_snapshot(client, query_base, metric).await;
                let total: usize = last.iter().map(|s| s.values).sum();
                if total == expect {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            last
        }

        for (metric, prefix) in [(&metric_http, "s"), (&metric_telnet, "t")] {
            let series = qual_wait_metric(&client, &query_base, metric, POINTS).await;
            let total: usize = series.iter().map(|s| s.values).sum();
            assert_eq!(
                total, POINTS,
                "qual count: expected {POINTS} points for {metric}, got {total}"
            );
            let mut seqs: Vec<String> = series.iter().filter_map(|s| s.seq.clone()).collect();
            seqs.sort();
            seqs.dedup();
            assert_eq!(
                seqs.len(),
                POINTS,
                "qual seq tags: expected {POINTS} distinct series for {metric}, got {}",
                seqs.len()
            );
            for seq in 0..POINTS {
                let key = format!("{prefix}{seq:04}");
                assert!(seqs.contains(&key), "qual missing {key} for {metric}");
            }
            for sample_ts in series.iter().flat_map(|s| s.timestamps.iter()) {
                assert!(
                    *sample_ts >= t0 - 120_000 && *sample_ts <= t1 + 120_000,
                    "qual timestamp {sample_ts} outside write window [{t0}, {t1}] for {metric}"
                );
            }
            eprintln!(
                "qual rows asserted: metric={metric} points={total} series={} window=[{t0},{t1}]",
                seqs.len()
            );
        }

        // Cleanup: delete the qualification series (best effort; the
        // 1 d retention expires them in any case).
        for metric in [&metric_http, &metric_telnet] {
            match client
                .post(format!(
                    "{query_base}/api/v1/admin/tsdb/delete_series?match[]={metric}"
                ))
                .send()
                .await
            {
                Ok(response) => {
                    eprintln!(
                        "qual cleanup: deleted {metric} status={}",
                        response.status()
                    )
                }
                Err(e) => eprintln!("qual cleanup FAILED for {metric} (tolerated): {e}"),
            }
        }
        eprintln!("qual done: http={POINTS} telnet={POINTS} cleaned series");
    }
}
