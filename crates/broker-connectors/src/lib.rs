use async_trait::async_trait;
use bytes::Bytes;
use broker_protocol::{QoS, Topic};
use reqwest::header::{HeaderMap, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;

pub mod kafka;
pub mod rabbitmq;
pub mod postgres;
pub mod redis;
pub mod mysql;
pub mod clickhouse;
pub mod influxdb;
pub mod s3;
pub mod elasticsearch;
pub mod timescaledb;
pub mod http;
pub mod mqtt_bridge;
pub mod disk_log;
pub mod sparkplug_b;

pub use kafka::{KafkaRecord, KafkaSink, KafkaSinkConfig, KafkaTransport, MemoryKafkaTransport, TcpKafkaTransport};
pub use rabbitmq::{AmqpFrame, RabbitMqSink, RabbitMqSinkConfig, RabbitMqTransport, MemoryAmqpTransport, TcpRabbitTransport};
pub use postgres::{MemoryPgTransport, PgBatch, PgTransport, PostgreSqlSink, PostgreSqlSinkConfig, TcpPgTransport};
pub use redis::{MemoryRedisTransport, RedisCommand, RedisCommandKind, RedisReply, RedisSink, RedisSinkConfig, RedisTransport, TcpRedisTransport};
pub use mysql::{MemoryMySqlTransport, MySqlBatch, MySqlSink, MySqlSinkConfig, MySqlTransport, TcpMySqlTransport};
pub use clickhouse::{ClickHouseConnector, ClickHouseSink, ClickHouseSinkConfig};
pub use influxdb::{InfluxDbConnector, InfluxDbSink, InfluxDbSinkConfig};
pub use s3::{HttpS3Transport, MockS3Transport, S3Compression, S3Connector, S3Put, S3Sink, S3SinkConfig, S3Transport, SigV4Request};
pub use elasticsearch::{BulkOutcome, CapturedBulk, ElasticsearchAuth, ElasticsearchConnector, ElasticsearchSink, ElasticsearchSinkConfig, ElasticsearchTransport, HttpElasticsearchTransport, MockElasticsearchTransport};
pub use timescaledb::{MockTimescaleTransport, TcpTimescaleTransport, TimescaleBatch, TimescaleDbConnector, TimescaleDbSink, TimescaleDbSinkConfig, TimescaleDbTransport};
pub use http::{CapturedHttpRequest, HmacAlgorithm, HmacEncoding, HttpAuth, HttpBodyFormat, HttpConnector, HttpHmacSignature, HttpMethod, HttpRequest, HttpResponse, HttpSink, HttpSinkConfig, HttpTransport, MockHttpOutcome, MockHttpTransport, ReqwestHttpTransport};
pub use mqtt_bridge::{BridgeEndpoint, DecodedPublish, MemoryMqttBridgeTransport, MqttBridgeConnector, MqttBridgeProtocol, MqttBridgeSink, MqttBridgeSinkConfig, MqttBridgeTransport, SerializedMqttPacket, TcpMqttBridgeTransport, decode_publish, decode_remaining_length, encode_publish, encode_remaining_length, parse_bridge_address};
pub use disk_log::{BackupInfo, DiskLogCompression, DiskLogConnector, DiskLogFormat, DiskLogSink, DiskLogSinkConfig, DiskLogWriter, DiskSyncMode, FileDiskLogWriter, MemoryDiskLogWriter};
pub use sparkplug_b::{MemorySparkplugTransport, SpbAnomaly, SpbDataType, SpbIngestOutcome, SpbMetric, SpbPayload, SpbValue, SparkplugBConnector, SparkplugBSink, SparkplugFrame, SparkplugMessageType, SparkplugSinkConfig, SparkplugStateMachine, SparkplugTopic, SparkplugTransport, decode_metric, decode_payload, decode_varint, encode_metric, encode_payload, encode_varint, payload_from_json, payload_to_json, tier, SPARKPLUG_TIER};

#[derive(Error, Debug)]
pub enum ConnectorError {
    #[error("Connector dispatch failure: {0}")]
    Dispatch(String),

    #[error("Connector connection error: {0}")]
    Connection(String),

    #[error("Unknown connector: {0}")]
    UnknownConnector(String),
}

pub type Result<T> = std::result::Result<T, ConnectorError>;

/// Unified outbound boundary: every streaming sink implements `Sink`.
#[async_trait]
pub trait Sink: Send + Sync {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()>;
    /// Stable kind name for management display (`webhook`, `console`,
    /// `kafka`, `rabbitmq`, ...).
    fn kind(&self) -> &'static str;
}

/// Unified connector identity: a registered, addressable sink.
pub trait Connector: Send + Sync {
    fn connector_id(&self) -> &str;
    fn kind(&self) -> &'static str;
}

/// Management view of one registered connector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorInfo {
    pub id: String,
    pub kind: String,
}

/// Manager-side handle pairing an id with its sink.
pub struct RegisteredConnector {
    id: String,
    sink: Arc<dyn Sink>,
}

impl RegisteredConnector {
    fn new(id: String, sink: Arc<dyn Sink>) -> Self {
        Self { id, sink }
    }
}

impl Connector for RegisteredConnector {
    fn connector_id(&self) -> &str {
        &self.id
    }

    fn kind(&self) -> &'static str {
        self.sink.kind()
    }
}

/// Default per-request timeout for webhook delivery.
pub const DEFAULT_WEBHOOK_TIMEOUT: Duration = Duration::from_secs(5);

/// HTTP webhook sink: POSTs the raw event payload to a URL.
///
/// The payload bytes travel untouched as the request body (already JSON
/// after SQL projection); topic and QoS ride along as `X-MQTT-Topic` /
/// `X-MQTT-QoS` headers plus any configured custom headers. The shared
/// `reqwest::Client` owns connection pooling. Non-2xx responses are
/// dispatch failures; transport errors are connection failures.
pub struct HttpWebhookSink {
    url: String,
    headers: HeaderMap,
    client: reqwest::Client,
    timeout: Duration,
    sent: AtomicU64,
}

impl HttpWebhookSink {
    pub fn new(url: String, headers: HeaderMap, client: reqwest::Client) -> Self {
        Self {
            url,
            headers,
            client,
            timeout: DEFAULT_WEBHOOK_TIMEOUT,
            sent: AtomicU64::new(0),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn sent_count(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl Sink for HttpWebhookSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        let response = self
            .client
            .post(&self.url)
            .headers(self.headers.clone())
            .header(CONTENT_TYPE, "application/json")
            .header("X-MQTT-Topic", topic.as_str())
            .header("X-MQTT-QoS", u8::from(qos).to_string())
            .body(payload.to_vec())
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| ConnectorError::Connection(e.to_string()))?;

        let status = response.status();
        if !status.is_success() {
            return Err(ConnectorError::Dispatch(format!(
                "webhook {} answered {}",
                self.url, status
            )));
        }
        self.sent.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "webhook"
    }
}

/// Formatted diagnostic sink: traces every event at INFO with a payload
/// preview (full payload when UTF-8 and short). Counts deliveries for
/// tests and health reporting.
pub struct ConsoleLoggerSink {
    name: String,
    max_preview_bytes: usize,
    logged: AtomicU64,
}

impl ConsoleLoggerSink {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            max_preview_bytes: 256,
            logged: AtomicU64::new(0),
        }
    }

    pub fn logged_count(&self) -> u64 {
        self.logged.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl Sink for ConsoleLoggerSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        let preview = match std::str::from_utf8(payload) {
            Ok(text) if text.len() <= self.max_preview_bytes => text.into(),
            Ok(text) => format!("{}…<{} bytes total>", &text[..self.max_preview_bytes], payload.len()),
            Err(_) => format!("<{} non-UTF8 bytes>", payload.len()),
        };
        tracing::info!(
            connector = %self.name,
            topic = %topic,
            qos = u8::from(qos),
            payload = %preview,
            "connector event"
        );
        self.logged.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "console"
    }
}

/// Registry of live outbound connectors by id.
#[derive(Default)]
pub struct ConnectorManager {
    connectors: parking_lot::RwLock<HashMap<String, RegisteredConnector>>,
}

impl ConnectorManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, id: impl Into<String>, sink: Arc<dyn Sink>) {
        let id = id.into();
        self.connectors
            .write()
            .insert(id.clone(), RegisteredConnector::new(id, sink));
    }

    pub fn unregister(&self, id: &str) -> bool {
        self.connectors.write().remove(id).is_some()
    }

    pub fn get(&self, id: &str) -> Option<Arc<dyn Sink>> {
        self.connectors.read().get(id).map(|entry| entry.sink.clone())
    }

    pub fn ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.connectors.read().keys().cloned().collect();
        ids.sort();
        ids
    }

    /// Ordered management view (`id` + `kind`) for the dashboard.
    pub fn infos(&self) -> Vec<ConnectorInfo> {
        let mut infos: Vec<ConnectorInfo> = self
            .connectors
            .read()
            .values()
            .map(|entry| ConnectorInfo {
                id: entry.connector_id().to_string(),
                kind: entry.kind().to_string(),
            })
            .collect();
        infos.sort_by(|a, b| a.id.cmp(&b.id));
        infos
    }

    /// Deliver one event through the named connector.
    pub async fn send(
        &self,
        id: &str,
        topic: &Topic,
        payload: &Bytes,
        qos: QoS,
    ) -> Result<()> {
        match self.get(id) {
            Some(sink) => sink.send(topic, payload, qos).await,
            None => Err(ConnectorError::UnknownConnector(id.to_string())),
        }
    }
}

/// Size- and linger-bounded row buffer shared by batching sinks
/// (Postgres, MySQL, ClickHouse, InfluxDB). Rows accumulate until the
/// batch is full or the oldest row outlives the linger window; failures
/// restore rows in order instead of dropping them.
pub(crate) struct BatchQueue<T> {
    rows: Vec<T>,
    oldest: Option<Instant>,
    max_rows: usize,
    linger: Duration,
}

impl<T> BatchQueue<T> {
    pub(crate) fn new(max_rows: usize, linger: Duration) -> Self {
        Self {
            rows: Vec::new(),
            oldest: None,
            max_rows: max_rows.max(1),
            linger,
        }
    }

    /// Push one row; true means flush now (full or stale).
    pub(crate) fn push(&mut self, row: T) -> bool {
        if self.is_empty() {
            self.oldest = Some(Instant::now());
        }
        self.rows.push(row);
        self.rows.len() >= self.max_rows || self.is_stale()
    }

    pub(crate) fn is_stale(&self) -> bool {
        self.oldest
            .map(|oldest| oldest.elapsed() >= self.linger)
            .unwrap_or(false)
    }

    pub(crate) fn len(&self) -> usize {
        self.rows.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Take all rows, resetting the linger clock. Callers restore via
    /// [`BatchQueue::restore`] when the transport fails.
    pub(crate) fn take_batch(&mut self) -> (Vec<T>, Option<Instant>) {
        let rows = std::mem::take(&mut self.rows);
        let oldest = self.oldest.take();
        (rows, oldest)
    }

    /// Restore a failed batch at the front, preserving order and the
    /// original linger clock.
    pub(crate) fn restore(&mut self, mut rows: Vec<T>, oldest: Option<Instant>) {
        rows.append(&mut self.rows);
        self.rows = rows;
        if self.oldest.is_none() {
            self.oldest = oldest;
        }
    }
}

/// Exponential backoff state (2s, 4s, 8s ... capped at 30s) for failing
/// transports. While backing off, flushes fail fast without touching
/// the transport.
#[derive(Default)]
pub(crate) struct BackoffState {
    consecutive_errors: u32,
    retry_after: Option<Instant>,
}

impl BackoffState {
    pub(crate) fn check(&self) -> Result<()> {
        if let Some(retry_after) = self.retry_after {
            if Instant::now() < retry_after {
                return Err(ConnectorError::Connection(
                    "sink backing off after errors".to_string(),
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn success(&mut self) {
        self.consecutive_errors = 0;
        self.retry_after = None;
    }

    pub(crate) fn failure(&mut self) {
        self.consecutive_errors += 1;
        let secs = 2u64
            .saturating_pow(self.consecutive_errors.min(5))
            .min(30);
        self.retry_after = Some(Instant::now() + Duration::from_secs(secs));
    }
}

/// Strict `${name}` template renderer shared by the object-storage and
/// search sinks (S3 keys, Elasticsearch indices/doc ids). Every
/// `${...}` must close and must name a key present in `vars`; anything
/// else is a dispatch error, so typos fail loudly at buffer time
/// instead of silently producing wrong object names.
pub(crate) fn render_template(template: &str, vars: &[(&str, String)]) -> Result<String> {
    let mut out = String::with_capacity(template.len() + 32);
    let bytes = template.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            let start = i + 2;
            let mut end = start;
            while end < bytes.len() && bytes[end] != b'}' {
                end += 1;
            }
            if end >= bytes.len() {
                return Err(ConnectorError::Dispatch(format!(
                    "unclosed template variable in {template:?}"
                )));
            }
            let name = &template[start..end];
            if name.is_empty() {
                return Err(ConnectorError::Dispatch(format!(
                    "empty template variable in {template:?}"
                )));
            }
            let value = vars
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.clone());
            match value {
                Some(value) => out.push_str(&value),
                None => {
                    return Err(ConnectorError::Dispatch(format!(
                        "unknown template variable {name:?} in {template:?}"
                    )))
                }
            }
            i = end + 1;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    Ok(out)
}

/// Wall-clock milliseconds since the Unix epoch (saturating at zero).
pub(crate) fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}

/// Split Unix millis into civil (year, month, day) via Howard Hinnant's
/// days-from-civil inverse (proleptic Gregorian, UTC). Negative inputs
/// clamp to the epoch so templates never render year 1969 surprises.
pub(crate) fn ymd_from_millis(millis: i64) -> (i32, u32, u32) {
    let days = millis.max(0).div_euclid(86_400_000);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    if m <= 2 {
        y += 1;
    }
    (y as i32, m, d)
}

/// Split Unix millis into (hour, minute, second, milli) UTC time of day.
pub(crate) fn hms_milli_from_millis(millis: i64) -> (u32, u32, u32, u32) {
    let day_millis = millis.max(0).rem_euclid(86_400_000) as u64;
    let secs = day_millis / 1_000;
    (
        (secs / 3_600) as u32,
        ((secs / 60) % 60) as u32,
        (secs % 60) as u32,
        (day_millis % 1_000) as u32,
    )
}

/// RFC 3339 UTC timestamp with millis (`2026-09-12T11:18:09.123Z`).
pub(crate) fn rfc3339_millis(millis: i64) -> String {
    let (y, mo, d) = ymd_from_millis(millis);
    let (h, mi, s, ms) = hms_milli_from_millis(millis);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{ms:03}Z")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{extract::State, http::StatusCode, routing::post, Router};
    use std::sync::Mutex as StdMutex;
    use tokio::net::TcpListener;

    #[derive(Debug, Default)]
    struct RecordingSink {
        events: StdMutex<Vec<(String, Vec<u8>, u8)>>,
    }

    #[async_trait]
    impl Sink for RecordingSink {
        async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
            self.events.lock().unwrap().push((
                topic.as_str().to_string(),
                payload.to_vec(),
                u8::from(qos),
            ));
            Ok(())
        }

        fn kind(&self) -> &'static str {
            "test"
        }
    }

    #[tokio::test]
    async fn test_connector_manager_registry() {
        let manager = ConnectorManager::new();
        assert!(manager.ids().is_empty());
        assert!(manager.get("missing").is_none());

        let sink: Arc<dyn Sink> = Arc::new(RecordingSink::default());
        manager.register("rec", sink);
        assert_eq!(manager.ids(), vec!["rec".to_string()]);

        let topic = Topic::new("a/b").unwrap();
        manager
            .send("rec", &topic, &Bytes::from_static(b"hi"), QoS::AtLeastOnce)
            .await
            .unwrap();
        let err = manager
            .send("missing", &topic, &Bytes::from_static(b"hi"), QoS::AtMostOnce)
            .await
            .expect_err("unknown connector must fail");
        assert!(matches!(err, ConnectorError::UnknownConnector(_)));

        assert!(manager.unregister("rec"));
        assert!(!manager.unregister("rec"));
    }

    #[tokio::test]
    async fn test_console_logger_counts_deliveries() {
        let sink = ConsoleLoggerSink::new("diag");
        let topic = Topic::new("a/b").unwrap();
        sink.send(&topic, &Bytes::from_static(b"hello"), QoS::AtMostOnce)
            .await
            .unwrap();
        sink.send(&topic, &Bytes::from(vec![0xFF, 0xFE]), QoS::AtLeastOnce)
            .await
            .unwrap();
        assert_eq!(sink.logged_count(), 2);
    }

    /// Captured webhook deliveries for the in-process HTTP test.
    #[derive(Debug, Default)]
    struct CapturedPosts {
        bodies: StdMutex<Vec<Vec<u8>>>,
        topics: StdMutex<Vec<String>>,
    }

    async fn capture_handler(
        State(state): State<Arc<CapturedPosts>>,
        headers: axum::http::HeaderMap,
        body: Bytes,
    ) -> StatusCode {
        if let Some(topic) = headers.get("X-MQTT-Topic").and_then(|v| v.to_str().ok()) {
            state.topics.lock().unwrap().push(topic.to_string());
        }
        state.bodies.lock().unwrap().push(body.to_vec());
        StatusCode::OK
    }

    /// In-process HTTP test: an ephemeral Axum server receives exactly
    /// what the webhook sink posts — byte-identical JSON included.
    #[tokio::test]
    async fn test_http_webhook_posts_exact_payload() {
        let captured = Arc::new(CapturedPosts::default());
        let app = Router::new()
            .route("/hook", post(capture_handler))
            .with_state(captured.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("webhook client");
        let mut headers = HeaderMap::new();
        headers.insert("X-Tenant", "acme".parse().unwrap());
        let sink = HttpWebhookSink::new(
            format!("http://127.0.0.1:{port}/hook"),
            headers,
            client,
        );
        assert_eq!(sink.sent_count(), 0);

        let payload = Bytes::from_static(br#"{ "temperature": 85.0 }"#);
        sink.send(&Topic::new("raw/temp").unwrap(), &payload, QoS::AtMostOnce)
            .await
            .expect("webhook delivery");
        assert_eq!(sink.sent_count(), 1);

        assert_eq!(
            captured.bodies.lock().unwrap().as_slice(),
            &[br#"{ "temperature": 85.0 }"#.to_vec()]
        );
        assert_eq!(
            captured.topics.lock().unwrap().as_slice(),
            &["raw/temp".to_string()]
        );
        server.abort();
    }

    #[tokio::test]
    async fn test_http_webhook_reports_http_errors() {
        let app = Router::new().route(
            "/boom",
            post(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "nope") }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        let sink = HttpWebhookSink::new(
            format!("http://127.0.0.1:{port}/boom"),
            HeaderMap::new(),
            reqwest::Client::new(),
        );
        let err = sink
            .send(&Topic::new("a").unwrap(), &Bytes::from_static(b"{}"), QoS::AtMostOnce)
            .await
            .expect_err("5xx must fail");
        assert!(matches!(err, ConnectorError::Dispatch(_)));
        assert_eq!(sink.sent_count(), 0);

        // Unroutable port: connection failure, not dispatch failure.
        let dead = HttpWebhookSink::new(
            "http://127.0.0.1:1/hook".to_string(),
            HeaderMap::new(),
            reqwest::Client::new(),
        )
        .with_timeout(Duration::from_millis(500));
        let err = dead
            .send(&Topic::new("a").unwrap(), &Bytes::from_static(b"{}"), QoS::AtMostOnce)
            .await
            .expect_err("refused port must fail");
        assert!(matches!(err, ConnectorError::Connection(_)));

        server.abort();
    }

    #[test]
    fn test_render_template_strict() {
        let vars = vec![
            ("topic", "sensors/t1".to_string()),
            ("YYYY", "2026".to_string()),
        ];
        assert_eq!(
            render_template("a/${topic}/${YYYY}.ndjson", &vars).unwrap(),
            "a/sensors/t1/2026.ndjson"
        );
        assert_eq!(render_template("plain", &vars).unwrap(), "plain");
        assert!(render_template("a/${nope}", &vars).is_err());
        assert!(render_template("a/${topic", &vars).is_err());
        assert!(render_template("a/${}", &vars).is_err());
        assert!(render_template("price: $5", &vars).is_ok());
    }

    #[test]
    fn test_ymd_and_rfc3339_vectors() {
        assert_eq!(ymd_from_millis(0), (1970, 1, 1));
        // 2024-02-29T00:00:00Z (leap day) and 2026-09-12T11:18:09.123Z.
        assert_eq!(ymd_from_millis(1_709_164_800_000), (2024, 2, 29));
        assert_eq!(ymd_from_millis(1_789_211_889_123), (2026, 9, 12));
        assert_eq!(hms_milli_from_millis(1_789_211_889_123), (11, 18, 9, 123));
        assert_eq!(
            rfc3339_millis(1_789_211_889_123),
            "2026-09-12T11:18:09.123Z"
        );
        assert_eq!(ymd_from_millis(-1), (1970, 1, 1));
    }
}
