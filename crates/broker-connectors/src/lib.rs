use async_trait::async_trait;
use bytes::Bytes;
use broker_protocol::{QoS, Topic};
use reqwest::header::{HeaderMap, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

pub mod kafka;
pub mod rabbitmq;

pub use kafka::{KafkaRecord, KafkaSink, KafkaSinkConfig, KafkaTransport, MemoryKafkaTransport, TcpKafkaTransport};
pub use rabbitmq::{AmqpFrame, RabbitMqSink, RabbitMqSinkConfig, RabbitMqTransport, MemoryAmqpTransport, TcpRabbitTransport};

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
}
