//! Microsoft Azure Event Hubs sink (INDRA-198).
//!
//! Buffers MQTT events and sends them with `POST
//! https://{namespace}.servicebus.windows.net/{hub}/messages` as a
//! JSON batch array. Each item carries the base64 body plus
//! `UserProperties` (templated) and `BrokerProperties` (with the
//! partition key). Authentication uses Shared Access Signatures:
//! `HMAC-SHA256(uri + "\n" + expiry, key)` in URL-encoded base64,
//! where portal-style base64 keys are decoded before signing and raw
//! secrets are used verbatim.
//!
//! HTTP 201 is success; 429/503 throttle with jittered backoff; other
//! non-2xx statuses are terminal dispatch failures.

use async_trait::async_trait;
use base64::Engine;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::{now_millis, render_template, BackoffState, BatchQueue, ConnectorError, Result, Sink};

fn default_token_ttl_secs() -> u64 {
    3_600
}

fn default_batch_size() -> Option<usize> {
    Some(100)
}

fn default_batch_bytes() -> Option<usize> {
    Some(1_048_576)
}

fn default_linger_ms() -> Option<u64> {
    Some(20)
}

fn default_max_retries() -> Option<usize> {
    Some(4)
}

fn default_initial_backoff_ms() -> Option<u64> {
    Some(100)
}

fn default_max_backoff_ms() -> Option<u64> {
    Some(2_500)
}

fn is_namespace(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=63).contains(&bytes.len())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        && bytes[0] != b'-'
        && bytes[bytes.len() - 1] != b'-'
}

fn is_hub_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=256).contains(&bytes.len())
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(*b, b'-' | b'_' | b'.' | b'~'))
}

/// Azure Event Hubs sink configuration. All depths are optional
/// (`None` = unbounded) with zero clamped ceilings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AzureEventHubsSinkConfig {
    /// Service Bus namespace, e.g. `my-eventhub-ns`.
    pub namespace: String,
    /// Event Hub instance, e.g. `telemetry-hub`.
    pub event_hub: String,
    /// Host override; defaults to `{namespace}.servicebus.windows.net`.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// SAS policy rule name, e.g. `SendPolicy`.
    pub shared_access_key_name: String,
    /// SAS secret (portal base64 key or raw string).
    pub shared_access_key: String,
    /// Partition key template (`${client_id}`, `${topic}`, ...).
    #[serde(default)]
    pub partition_key_template: Option<String>,
    /// Custom application properties with template substitution.
    #[serde(default)]
    pub user_properties: HashMap<String, String>,
    /// SAS token lifetime in seconds (default 3600).
    #[serde(default = "default_token_ttl_secs")]
    pub token_ttl_secs: u64,
    /// Events per batch (default 100).
    #[serde(default = "default_batch_size")]
    pub batch_size: Option<usize>,
    /// Batch byte limit (default 1 MiB).
    #[serde(default = "default_batch_bytes")]
    pub batch_bytes: Option<usize>,
    /// Linger flush window in ms (default 20).
    #[serde(default = "default_linger_ms")]
    pub linger_ms: Option<u64>,
    /// Retries on 429/503 (default 4, `None` unbounded, 0 none).
    #[serde(default = "default_max_retries")]
    pub max_retries: Option<usize>,
    /// First retry delay in ms (default 100).
    #[serde(default = "default_initial_backoff_ms")]
    pub initial_backoff_ms: Option<u64>,
    /// Retry delay ceiling in ms (default 2500).
    #[serde(default = "default_max_backoff_ms")]
    pub max_backoff_ms: Option<u64>,
    /// Request timeout in ms (default 5000).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

impl AzureEventHubsSinkConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.unwrap_or(5000).max(1))
    }

    pub fn validate(&self) -> Result<()> {
        if !is_namespace(&self.namespace) {
            return Err(ConnectorError::Dispatch(format!(
                "azure namespace must be 1..=63 [a-z0-9-]: {:?}",
                self.namespace
            )));
        }
        if !is_hub_name(&self.event_hub) {
            return Err(ConnectorError::Dispatch(format!(
                "azure event_hub must be 1..=256 [A-Za-z0-9-_.~]: {:?}",
                self.event_hub
            )));
        }
        if let Some(endpoint) = &self.endpoint {
            if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
                return Err(ConnectorError::Dispatch(format!(
                    "azure endpoint must be http(s): {endpoint:?}"
                )));
            }
        }
        if self.shared_access_key_name.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "azure shared_access_key_name must not be empty".to_string(),
            ));
        }
        if self.shared_access_key.is_empty() {
            return Err(ConnectorError::Dispatch(
                "azure shared_access_key must not be empty".to_string(),
            ));
        }
        if let Some(template) = &self.partition_key_template {
            self.event_vars("dummy", b"{}", QoS::AtMostOnce, 0, template)?;
        }
        for (name, template) in &self.user_properties {
            if name.trim().is_empty() {
                return Err(ConnectorError::Dispatch(
                    "azure user property names must not be empty".to_string(),
                ));
            }
            self.event_vars("dummy", b"{}", QoS::AtMostOnce, 0, template)?;
        }
        if self.batch_size == Some(0) {
            return Err(ConnectorError::Dispatch(
                "azure batch_size must be >= 1".to_string(),
            ));
        }
        if self.batch_bytes == Some(0) {
            return Err(ConnectorError::Dispatch(
                "azure batch_bytes must be >= 1".to_string(),
            ));
        }
        Ok(())
    }

    pub fn host(&self) -> String {
        match &self.endpoint {
            Some(endpoint) => endpoint
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .trim_end_matches('/')
                .to_string(),
            None => format!("{}.servicebus.windows.net", self.namespace),
        }
    }

    /// Resource URI covered by SAS tokens (scheme + host + hub).
    pub fn resource_uri(&self) -> String {
        let scheme = match &self.endpoint {
            Some(e) if e.starts_with("http://") => "http",
            _ => "https",
        };
        format!("{scheme}://{}/{}", self.host(), self.event_hub)
    }

    /// Batch send URL: `{resource_uri}/messages`.
    pub fn send_url(&self) -> String {
        format!("{}/messages", self.resource_uri())
    }

    pub fn effective_batch_size(&self) -> usize {
        self.batch_size.unwrap_or(usize::MAX).max(1)
    }

    pub fn effective_batch_bytes(&self) -> usize {
        self.batch_bytes.unwrap_or(usize::MAX).max(1)
    }

    pub fn effective_linger(&self) -> Duration {
        self.linger_ms
            .map(Duration::from_millis)
            .unwrap_or(Duration::MAX)
    }

    /// Template variables for one event (`${client_id}` from the JSON
    /// field when present, else empty).
    fn template_vars(topic: &str, payload: &[u8], qos: QoS, millis: i64) -> Vec<(String, String)> {
        let doc: serde_json::Value = serde_json::from_slice(payload).unwrap_or_default();
        let client_id = match doc.get("client_id") {
            Some(serde_json::Value::String(text)) => text.clone(),
            _ => String::new(),
        };
        vec![
            ("topic".to_string(), topic.to_string()),
            ("client_id".to_string(), client_id),
            ("qos".to_string(), u8::from(qos).to_string()),
            ("timestamp".to_string(), millis.to_string()),
        ]
    }

    fn event_vars(
        &self,
        topic: &str,
        payload: &[u8],
        qos: QoS,
        millis: i64,
        template: &str,
    ) -> Result<String> {
        let vars = Self::template_vars(topic, payload, qos, millis);
        let borrowed: Vec<(&str, String)> =
            vars.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
        render_template(template, &borrowed)
    }
}

// ---------------------------------------------------------------------------
// SAS token generator.
// ---------------------------------------------------------------------------

/// URL-encode per `encodeURIComponent` (uppercase `%XX`, `/` encoded).
fn url_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Key bytes for HMAC: portal base64 keys decode first, raw secrets
/// pass through verbatim.
fn sas_key_bytes(secret: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(secret.trim())
        .unwrap_or_else(|_| secret.as_bytes().to_vec())
}

/// Build the `Authorization: SharedAccessSignature ...` value for
/// `resource_uri` expiring at `expiry_secs` (Unix seconds).
pub fn sas_token(resource_uri: &str, key_name: &str, secret: &str, expiry_secs: u64) -> String {
    let string_to_sign = format!("{resource_uri}\n{expiry_secs}");
    // HMAC-SHA256 inline (same shape as the shared signer).
    const BLOCK: usize = 64;
    let key = sas_key_bytes(secret);
    let mut key_block = [0u8; BLOCK];
    if key.len() > BLOCK {
        let digest = Sha256::digest(&key);
        key_block[..digest.len()].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(&key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(string_to_sign.as_bytes());
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    let signature = base64::engine::general_purpose::STANDARD.encode(outer.finalize());
    format!(
        "SharedAccessSignature sr={}&sig={}&se={expiry_secs}&skn={key_name}",
        url_encode(resource_uri),
        url_encode(&signature),
    )
}

// ---------------------------------------------------------------------------
// Wire framing.
// ---------------------------------------------------------------------------

/// One event item in the batch array.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AzureEventItem {
    pub body_b64: String,
    pub partition_key: Option<String>,
    pub user_properties: HashMap<String, String>,
}

/// Render the batch JSON array body.
pub fn render_batch_body(events: &[AzureEventItem]) -> Vec<u8> {
    let mut body = String::from("[");
    for (index, event) in events.iter().enumerate() {
        if index > 0 {
            body.push(',');
        }
        body.push_str("{\"Body\":");
        body.push_str(&serde_json::to_string(&event.body_b64).unwrap_or_default());
        body.push_str(",\"UserProperties\":{");
        let mut keys: Vec<&String> = event.user_properties.keys().collect();
        keys.sort();
        for (attr_index, key) in keys.iter().enumerate() {
            if attr_index > 0 {
                body.push(',');
            }
            body.push_str(&serde_json::to_string(key).unwrap_or_default());
            body.push(':');
            body.push_str(&serde_json::to_string(&event.user_properties[*key]).unwrap_or_default());
        }
        body.push_str("},\"BrokerProperties\":{");
        match &event.partition_key {
            Some(key) => {
                body.push_str("\"PartitionKey\":");
                body.push_str(&serde_json::to_string(key).unwrap_or_default());
            }
            None => body.push_str("\"PartitionKey\":null"),
        }
        body.push_str("}}");
    }
    body.push(']');
    body.into_bytes()
}

// ---------------------------------------------------------------------------
// Transport.
// ---------------------------------------------------------------------------

/// One captured batch send.
#[derive(Debug, Clone)]
pub struct CapturedAzureBatch {
    pub hub: String,
    pub events: Vec<AzureEventItem>,
    pub sas_token: String,
}

/// Scripted outcome for the mock transport.
#[derive(Debug, Clone)]
pub enum MockAzureOutcome {
    /// HTTP failure (429/503 retry the batch).
    HttpStatus(u16),
    /// Transport failure (restores immediately, no in-loop retry).
    TransportError(String),
}

#[async_trait]
pub trait AzureEventHubsTransport: Send + Sync {
    async fn send_batch(
        &self,
        hub: &str,
        events: Vec<AzureEventItem>,
        sas_token: &str,
    ) -> Result<()>;
}

/// In-memory transport with scripted outcomes (tests, dry runs).
#[derive(Debug, Default)]
pub struct MockAzureEventHubsTransport {
    scripted: parking_lot::Mutex<std::collections::VecDeque<MockAzureOutcome>>,
    captured: parking_lot::Mutex<Vec<CapturedAzureBatch>>,
    calls: AtomicU64,
}

impl MockAzureEventHubsTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue outcomes consumed in order (default: success).
    pub fn script_outcomes(&self, outcomes: Vec<MockAzureOutcome>) {
        *self.scripted.lock() = outcomes.into_iter().collect();
    }

    pub fn captured(&self) -> Vec<CapturedAzureBatch> {
        self.captured.lock().clone()
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl AzureEventHubsTransport for MockAzureEventHubsTransport {
    async fn send_batch(
        &self,
        hub: &str,
        events: Vec<AzureEventItem>,
        sas_token: &str,
    ) -> Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.captured.lock().push(CapturedAzureBatch {
            hub: hub.to_string(),
            events,
            sas_token: sas_token.to_string(),
        });
        match self.scripted.lock().pop_front() {
            None => Ok(()),
            Some(MockAzureOutcome::HttpStatus(status)) => Err(match status {
                429 | 503 => {
                    ConnectorError::Connection(format!("mock azure throttled with {status}"))
                }
                _ => ConnectorError::Dispatch(format!("mock azure failed with {status}")),
            }),
            Some(MockAzureOutcome::TransportError(message)) => {
                Err(ConnectorError::Connection(message))
            }
        }
    }
}

/// Production transport: signed `POST {send-url}/messages`. The SAS
/// token arrives minted per batch (fresh expiry across backoff
/// retries); the transport only attaches it.
pub struct HttpAzureEventHubsTransport {
    url: String,
    client: reqwest::Client,
}

impl HttpAzureEventHubsTransport {
    pub fn new(config: &AzureEventHubsSinkConfig, client: reqwest::Client) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            url: config.send_url(),
            client,
        })
    }
}

#[async_trait]
impl AzureEventHubsTransport for HttpAzureEventHubsTransport {
    async fn send_batch(
        &self,
        _hub: &str,
        events: Vec<AzureEventItem>,
        sas_token: &str,
    ) -> Result<()> {
        let response = self
            .client
            .post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::AUTHORIZATION, sas_token)
            .body(render_batch_body(&events))
            .send()
            .await
            .map_err(|e| ConnectorError::Connection(format!("azure send failed: {e}")))?;
        let status = response.status().as_u16();
        if status == 201 || (200..=299).contains(&status) {
            return Ok(());
        }
        if status == 429 || status == 503 {
            return Err(ConnectorError::Connection(format!(
                "azure send throttled with {status}"
            )));
        }
        Err(ConnectorError::Dispatch(format!(
            "azure send failed with {status}"
        )))
    }
}

// ---------------------------------------------------------------------------
// Sink.
// ---------------------------------------------------------------------------

/// One buffered event.
#[derive(Debug, Clone)]
struct AzureRow {
    topic: String,
    payload: Vec<u8>,
    qos: u8,
    millis: i64,
}

struct AzureBuffer {
    queue: BatchQueue<AzureRow>,
    bytes: usize,
}

/// Azure Event Hubs sink: buffers events, sends signed batches.
pub struct AzureEventHubsSink {
    config: AzureEventHubsSinkConfig,
    transport: Arc<dyn AzureEventHubsTransport>,
    buffer: parking_lot::Mutex<AzureBuffer>,
    backoff: parking_lot::Mutex<BackoffState>,
    sent_batches: AtomicU64,
    sent_records: AtomicU64,
}

impl AzureEventHubsSink {
    pub fn new(
        config: AzureEventHubsSinkConfig,
        transport: Arc<dyn AzureEventHubsTransport>,
    ) -> Result<Self> {
        config.validate()?;
        let linger = config.effective_linger();
        Ok(Self {
            buffer: parking_lot::Mutex::new(AzureBuffer {
                queue: BatchQueue::new(config.effective_batch_size(), linger),
                bytes: 0,
            }),
            config,
            transport,
            backoff: parking_lot::Mutex::new(BackoffState::default()),
            sent_batches: AtomicU64::new(0),
            sent_records: AtomicU64::new(0),
        })
    }

    pub fn config(&self) -> &AzureEventHubsSinkConfig {
        &self.config
    }

    pub fn sent_batches(&self) -> u64 {
        self.sent_batches.load(Ordering::Relaxed)
    }

    pub fn sent_records(&self) -> u64 {
        self.sent_records.load(Ordering::Relaxed)
    }

    pub fn buffered_rows(&self) -> usize {
        self.buffer.lock().queue.len()
    }

    fn backoff_delay(&self, attempt: usize) -> Duration {
        let initial = self.config.initial_backoff_ms.unwrap_or(100).max(1);
        let max = self.config.max_backoff_ms.unwrap_or(2_500).max(1);
        let grown = initial
            .saturating_mul(2u64.saturating_pow(attempt.min(10) as u32))
            .min(max);
        let jitter = (now_millis().max(0) as u64) % (grown / 2 + 1);
        Duration::from_millis(grown.saturating_add(jitter).min(max.saturating_mul(2)))
    }

    /// Build wire items for rows (partition keys + properties).
    fn events_for(&self, rows: &[AzureRow]) -> Result<Vec<AzureEventItem>> {
        rows.iter()
            .map(|row| {
                let partition_key = match &self.config.partition_key_template {
                    Some(template) => Some(self.config.event_vars(
                        &row.topic,
                        &row.payload,
                        qos_from(row.qos),
                        row.millis,
                        template,
                    )?),
                    None => None,
                };
                let mut user_properties = HashMap::new();
                user_properties.insert("mqtt_topic".to_string(), row.topic.clone());
                user_properties.insert("mqtt_qos".to_string(), row.qos.to_string());
                for (name, template) in &self.config.user_properties {
                    user_properties.insert(
                        name.clone(),
                        self.config.event_vars(
                            &row.topic,
                            &row.payload,
                            qos_from(row.qos),
                            row.millis,
                            template,
                        )?,
                    );
                }
                Ok(AzureEventItem {
                    body_b64: base64::engine::general_purpose::STANDARD.encode(&row.payload),
                    partition_key,
                    user_properties,
                })
            })
            .collect()
    }

    /// Flush buffered rows (no-op when empty). 429/503 retry in place
    /// up to `max_retries`; terminal and transport failures restore
    /// the buffer, engage backoff, and propagate.
    pub async fn flush(&self) -> Result<()> {
        self.backoff.lock().check()?;
        let (rows, oldest, taken_bytes) = {
            let mut buffer = self.buffer.lock();
            let (rows, oldest) = buffer.queue.take_batch();
            let taken = std::mem::replace(&mut buffer.bytes, 0);
            (rows, oldest, taken)
        };
        if rows.is_empty() {
            return Ok(());
        }
        let events = self.events_for(&rows)?;
        let record_count = rows.len() as u64;
        let max_retries = self.config.max_retries.unwrap_or(usize::MAX);
        let mut attempt = 0usize;
        loop {
            // Fresh SAS per attempt: tokens may expire mid-backoff.
            let expiry = (now_millis().max(0) as u64 / 1_000)
                .saturating_add(self.config.token_ttl_secs.max(1));
            let token = sas_token(
                &self.config.resource_uri(),
                &self.config.shared_access_key_name,
                &self.config.shared_access_key,
                expiry,
            );
            match self
                .transport
                .send_batch(&self.config.event_hub, events.clone(), &token)
                .await
            {
                Ok(()) => {
                    self.backoff.lock().success();
                    self.sent_batches.fetch_add(1, Ordering::Relaxed);
                    self.sent_records.fetch_add(record_count, Ordering::Relaxed);
                    return Ok(());
                }
                Err(ConnectorError::Connection(message)) => {
                    if attempt >= max_retries {
                        return self.restore_err(
                            rows,
                            oldest,
                            taken_bytes,
                            ConnectorError::Connection(message),
                        );
                    }
                    attempt += 1;
                    tokio::time::sleep(self.backoff_delay(attempt)).await;
                }
                Err(e) => {
                    return self.restore_err(rows, oldest, taken_bytes, e);
                }
            }
        }
    }

    fn restore_err(
        &self,
        rows: Vec<AzureRow>,
        oldest: Option<std::time::Instant>,
        bytes: usize,
        error: ConnectorError,
    ) -> Result<()> {
        let mut buffer = self.buffer.lock();
        buffer.queue.restore(rows, oldest);
        buffer.bytes = buffer.bytes.saturating_add(bytes);
        self.backoff.lock().failure();
        Err(error)
    }

    /// Validate + buffer one event. Returns true when the batch is
    /// full, stale, or over the byte limit (caller flushes).
    fn buffer_row(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<bool> {
        if topic.as_str().is_empty() {
            return Err(ConnectorError::Dispatch(
                "azure row requires a non-empty topic".to_string(),
            ));
        }
        // Event bodies are binary-safe; UTF-8 is not required.
        let row = AzureRow {
            topic: topic.as_str().to_string(),
            payload: payload.to_vec(),
            qos: u8::from(qos),
            millis: now_millis(),
        };
        let added = row.payload.len() * 4 / 3 + 128;
        let mut buffer = self.buffer.lock();
        let full = buffer.queue.push(row);
        buffer.bytes = buffer.bytes.saturating_add(added);
        Ok(full || buffer.bytes >= self.config.effective_batch_bytes())
    }
}

fn qos_from(value: u8) -> QoS {
    QoS::try_from(value).unwrap_or(QoS::AtMostOnce)
}

#[async_trait]
impl Sink for AzureEventHubsSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        if self.buffer_row(topic, payload, qos)? {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "azure_eventhubs"
    }
}

/// Management connector handle pairing an id with an Event Hubs sink.
pub struct AzureEventHubsConnector {
    id: String,
    sink: Arc<AzureEventHubsSink>,
}

impl AzureEventHubsConnector {
    pub fn new(id: impl Into<String>, sink: Arc<AzureEventHubsSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }
}

impl super::Connector for AzureEventHubsConnector {
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

    fn test_config() -> AzureEventHubsSinkConfig {
        AzureEventHubsSinkConfig {
            namespace: "my-eventhub-ns".to_string(),
            event_hub: "telemetry-hub".to_string(),
            endpoint: None,
            shared_access_key_name: "SendPolicy".to_string(),
            shared_access_key: "dGVzdC1rZXktbWF0ZXJpYWwtMzItYnl0ZXMhIU9L".to_string(),
            partition_key_template: Some("${client_id}".to_string()),
            user_properties: HashMap::from([("source".to_string(), "indramqtt".to_string())]),
            token_ttl_secs: 3_600,
            batch_size: Some(100),
            batch_bytes: Some(1_048_576),
            linger_ms: Some(20),
            max_retries: Some(4),
            initial_backoff_ms: Some(100),
            max_backoff_ms: Some(2_500),
            timeout_ms: None,
        }
    }

    fn test_sink(
        config: AzureEventHubsSinkConfig,
    ) -> (Arc<AzureEventHubsSink>, Arc<MockAzureEventHubsTransport>) {
        let transport = Arc::new(MockAzureEventHubsTransport::new());
        let sink = Arc::new(AzureEventHubsSink::new(config, transport.clone()).unwrap());
        (sink, transport)
    }

    #[test]
    fn test_config_validation() {
        let mut config = test_config();
        assert!(config.validate().is_ok());
        assert_eq!(
            config.resource_uri(),
            "https://my-eventhub-ns.servicebus.windows.net/telemetry-hub"
        );
        assert_eq!(
            config.send_url(),
            "https://my-eventhub-ns.servicebus.windows.net/telemetry-hub/messages"
        );

        config.namespace = "UPPER".to_string();
        assert!(config.validate().is_err());
        config.namespace = "my-eventhub-ns".to_string();

        config.event_hub = "has space".to_string();
        assert!(config.validate().is_err());
        config.event_hub = "telemetry-hub".to_string();

        config.shared_access_key_name.clear();
        assert!(config.validate().is_err());
        config.shared_access_key_name = "SendPolicy".to_string();

        config.partition_key_template = Some("${nope}".to_string());
        assert!(config.validate().is_err());
        config.partition_key_template = None;

        config.batch_size = Some(0);
        assert!(config.validate().is_err());
        // Unbounded + huge depths accepted: zero clamped ceilings.
        config.batch_size = None;
        config.batch_bytes = Some(10_000_000);
        config.max_retries = None;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_sas_known_answer() {
        // Independent Python (hmac/hashlib/base64/urllib) vector.
        assert_eq!(
            sas_token(
                "https://my-eventhub-ns.servicebus.windows.net/telemetry-hub",
                "SendPolicy",
                "dGVzdC1rZXktbWF0ZXJpYWwtMzItYnl0ZXMhIU9L",
                1_789_211_889,
            ),
            "SharedAccessSignature \
             sr=https%3A%2F%2Fmy-eventhub-ns.servicebus.windows.net%2Ftelemetry-hub\
             &sig=S%2B48piTqHO3Zq%2BcSPdVs%2FIQGfL73uf4g6N6VNGZfC6g%3D\
             &se=1789211889&skn=SendPolicy"
        );
        // Raw (non-base64) secrets sign verbatim.
        let token = sas_token("https://ns/hub", "k", "plain-secret-key", 1_789_211_889);
        assert!(token.starts_with("SharedAccessSignature sr=https%3A%2F%2Fns%2Fhub&sig="));
        // The embedded signature decodes to 32 HMAC bytes.
        let sig_enc = token
            .split("&sig=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap();
        let sig_b64 = sig_enc
            .replace("%2B", "+")
            .replace("%2F", "/")
            .replace("%3D", "=");
        let sig = base64::engine::general_purpose::STANDARD
            .decode(&sig_b64)
            .unwrap();
        assert_eq!(sig.len(), 32);
    }

    #[tokio::test]
    async fn test_batch_framing_and_partition_routing() {
        let (sink, transport) = test_sink(test_config());
        sink.send(
            &Topic::new("sensors/t1").unwrap(),
            &Bytes::from_static(br#"{"client_id":"edge-7","v":1}"#),
            QoS::AtLeastOnce,
        )
        .await
        .unwrap();
        sink.flush().await.unwrap();

        let captured = transport.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].hub, "telemetry-hub");
        // SAS token shape on the wire.
        assert!(captured[0]
            .sas_token
            .starts_with("SharedAccessSignature sr="));
        assert!(captured[0].sas_token.contains("&skn=SendPolicy"));
        assert_eq!(captured[0].events.len(), 1);
        let event = &captured[0].events[0];
        assert_eq!(event.partition_key.as_deref(), Some("edge-7"));
        assert_eq!(
            event.user_properties.get("mqtt_topic").map(String::as_str),
            Some("sensors/t1")
        );
        assert_eq!(
            event.user_properties.get("mqtt_qos").map(String::as_str),
            Some("1")
        );
        assert_eq!(
            event.user_properties.get("source").map(String::as_str),
            Some("indramqtt")
        );
        let payload = base64::engine::general_purpose::STANDARD
            .decode(&event.body_b64)
            .unwrap();
        assert_eq!(payload, br#"{"client_id":"edge-7","v":1}"#);

        // Rendered body shape matches the batch contract.
        let body = String::from_utf8(render_batch_body(&captured[0].events)).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(doc[0]["BrokerProperties"]["PartitionKey"], "edge-7");
        assert_eq!(doc[0]["UserProperties"]["mqtt_topic"], "sensors/t1");
    }

    #[tokio::test]
    async fn test_property_templates_and_missing_key() {
        // Templated user properties render per event; a missing
        // partition template means a null BrokerProperties key.
        let mut config = test_config();
        config.partition_key_template = None;
        config.user_properties =
            HashMap::from([("device".to_string(), "${client_id}@${topic}".to_string())]);
        let (sink, transport) = test_sink(config);
        sink.send(
            &Topic::new("sensors/t1").unwrap(),
            &Bytes::from_static(br#"{"client_id":"edge-7"}"#),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        sink.flush().await.unwrap();
        let captured = transport.captured();
        assert_eq!(captured[0].events[0].partition_key, None);
        assert_eq!(
            captured[0].events[0]
                .user_properties
                .get("device")
                .map(String::as_str),
            Some("edge-7@sensors/t1")
        );
        let body = String::from_utf8(render_batch_body(&captured[0].events)).unwrap();
        assert!(body.contains("\"PartitionKey\":null"));
    }

    #[tokio::test]
    async fn test_retry_on_throttle_then_success() {
        let mut config = test_config();
        config.batch_size = Some(10);
        config.initial_backoff_ms = Some(1);
        config.max_backoff_ms = Some(2);
        let (sink, transport) = test_sink(config);
        transport.script_outcomes(vec![
            MockAzureOutcome::HttpStatus(429),
            MockAzureOutcome::HttpStatus(503),
        ]);

        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from("{}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        sink.flush().await.unwrap();
        assert_eq!(transport.calls(), 3);
        assert_eq!(sink.sent_batches(), 1);
        assert_eq!(sink.buffered_rows(), 0);
    }

    #[tokio::test]
    async fn test_terminal_and_transport_failures() {
        // 400: terminal, single attempt, buffer retained.
        let mut config = test_config();
        config.batch_size = Some(10);
        config.max_retries = Some(5);
        let (sink, transport) = test_sink(config);
        transport.script_outcomes(vec![MockAzureOutcome::HttpStatus(400)]);

        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from("{}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        let err = sink.flush().await.expect_err("400 must fail");
        assert!(matches!(err, ConnectorError::Dispatch(_)));
        assert_eq!(transport.calls(), 1);
        assert_eq!(sink.buffered_rows(), 1);

        // Exhaustion (max_retries 0): single attempt, then fail fast.
        let mut config = test_config();
        config.batch_size = Some(10);
        config.max_retries = Some(0);
        let (sink, transport) = test_sink(config);
        transport.script_outcomes(vec![MockAzureOutcome::HttpStatus(503)]);

        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from("{}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        let err = sink
            .flush()
            .await
            .expect_err("503 with no retries must fail");
        assert!(matches!(err, ConnectorError::Connection(_)));
        assert_eq!(transport.calls(), 1);
        assert_eq!(sink.buffered_rows(), 1);
        let calls = transport.calls();
        assert!(sink.flush().await.is_err());
        assert_eq!(transport.calls(), calls);
    }
}
