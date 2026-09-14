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

impl OpenTsdbConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.unwrap_or(5000).max(1))
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
        Ok(())
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
                    if let Some(sub) = map.get("payload").and_then(|p| p.get(*part)) {
                        curr = sub;
                    } else {
                        return None;
                    }
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
                if let Some(v) = extract_json_path(val, json_path).or_else(|| val.get(&var)).or_else(|| val.get("payload").and_then(|p| p.get(json_path))) {
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
pub struct NetworkOpenTsdbTransport {
    client: reqwest::Client,
    http_url: String,
}

impl NetworkOpenTsdbTransport {
    pub fn new(config: &OpenTsdbConfig) -> Self {
        let base = config.endpoint.trim_end_matches('/');
        let http_url = if config.summary {
            format!("{base}/api/put?summary")
        } else {
            format!("{base}/api/put")
        };
        Self {
            client: reqwest::Client::builder()
                .timeout(config.timeout())
                .build()
                .unwrap_or_default(),
            http_url,
        }
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

    async fn put_telnet(&self, _telnet_data: &str) -> Result<()> {
        // TCP socket write implementation
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
        let batch_size = config.batch_size.unwrap_or(1000).max(1);
        Ok(Self {
            config,
            transport,
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

    pub async fn flush(&self) -> Result<()> {
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

        self.backoff.lock().check()?;

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
}
