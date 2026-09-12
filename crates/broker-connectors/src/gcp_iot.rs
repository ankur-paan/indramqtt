//! Google Cloud IoT bridge (INDRA-195).
//!
//! Telemetry bridge for Cloud IoT Device telemetry with RS256 / ES256
//! JWT authentication, the `/devices/{id}/{events,state,config,
//! commands}` topic taxonomy, and proactive token refresh. JWT
//! minting reuses `jsonwebtoken` (shared with the Pub/Sub token
//! cache); ECDSA P-256 signs through the same crate.
//!
//! `UNAUTHENTICATED` forces one token renewal + retry,
//! `RESOURCE_EXHAUSTED` backs off, and `PERMISSION_DENIED` is
//! terminal.

use async_trait::async_trait;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::{
    now_millis, BackoffState, BatchQueue, ConnectorError, Result, Sink,
};

/// JWT signature algorithm for Cloud IoT device credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum GcpIotAlgorithm {
    #[default]
    #[serde(rename = "RS256")]
    Rs256,
    #[serde(rename = "ES256")]
    Es256,
}

impl GcpIotAlgorithm {
    fn jsonwebtoken(self) -> jsonwebtoken::Algorithm {
        match self {
            Self::Rs256 => jsonwebtoken::Algorithm::RS256,
            Self::Es256 => jsonwebtoken::Algorithm::ES256,
        }
    }
}

/// Google Cloud IoT bridge configuration. Buffering is unbounded by
/// default; JWT lifetimes clamp to 24h.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcpIotConfig {
    /// GCP project id.
    pub project_id: String,
    /// Cloud region (`us-central1`, ...).
    pub cloud_region: String,
    /// Device registry id.
    pub registry_id: String,
    /// Device id.
    pub device_id: String,
    /// PKCS#8 private key (RSA or ECDSA P-256).
    pub private_key_pem: String,
    /// Signature algorithm (default RS256).
    #[serde(default)]
    pub algorithm: GcpIotAlgorithm,
    /// JWT validity in seconds (default 3600, max 86400).
    #[serde(default = "default_token_lifetime")]
    pub token_lifetime_secs: u64,
    /// Broker endpoint (default `mqtt.googleapis.com:8883`).
    #[serde(default = "default_endpoint")]
    pub endpoint: String,
    /// Flush trigger row count (default 250).
    #[serde(default = "default_batch_size")]
    pub batch_size: Option<usize>,
    /// Buffer capacity (`None` unbounded).
    #[serde(default)]
    pub buffer_capacity: Option<usize>,
    /// Linger flush window in ms (default 50).
    #[serde(default = "default_linger_ms")]
    pub linger_ms: Option<u64>,
    /// Retries on exhaustion (default 5).
    #[serde(default = "default_max_retries")]
    pub max_retries: Option<usize>,
}

fn default_token_lifetime() -> u64 {
    3_600
}

fn default_endpoint() -> String {
    "mqtt.googleapis.com:8883".to_string()
}

fn default_batch_size() -> Option<usize> {
    Some(250)
}

fn default_linger_ms() -> Option<u64> {
    Some(50)
}

fn default_max_retries() -> Option<usize> {
    Some(5)
}

impl GcpIotConfig {
    pub fn validate(&self) -> Result<()> {
        for (label, value) in [
            ("project_id", &self.project_id),
            ("cloud_region", &self.cloud_region),
            ("registry_id", &self.registry_id),
            ("device_id", &self.device_id),
        ] {
            if value.trim().is_empty() || value.contains(['/', '#', '+']) {
                return Err(ConnectorError::Dispatch(format!(
                    "gcp-iot {label} must be a concrete segment: {value:?}"
                )));
            }
        }
        if self.private_key_pem.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "gcp-iot private_key_pem must not be empty".to_string(),
            ));
        }
        // Key must parse for the selected algorithm now.
        build_jwt(
            &self.private_key_pem,
            self.algorithm,
            &self.project_id,
            1_700_000_000,
            self.token_lifetime_secs,
        )?;
        if self.endpoint.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "gcp-iot endpoint must not be empty".to_string(),
            ));
        }
        if self.batch_size == Some(0) {
            return Err(ConnectorError::Dispatch(
                "gcp-iot batch_size must be >= 1".to_string(),
            ));
        }
        Ok(())
    }

    /// MQTT client id:
    /// `projects/{p}/locations/{r}/registries/{reg}/devices/{d}`.
    pub fn client_id(&self) -> String {
        format!(
            "projects/{}/locations/{}/registries/{}/devices/{}",
            self.project_id, self.cloud_region, self.registry_id, self.device_id
        )
    }

    pub fn effective_batch_size(&self) -> usize {
        self.batch_size.unwrap_or(usize::MAX).max(1)
    }

    pub fn effective_linger(&self) -> Duration {
        self.linger_ms.map(Duration::from_millis).unwrap_or(Duration::MAX)
    }

    pub fn effective_buffer(&self) -> usize {
        self.buffer_capacity.unwrap_or(usize::MAX).max(1)
    }

    pub fn effective_lifetime(&self) -> u64 {
        self.token_lifetime_secs.clamp(60, 86_400)
    }
}

/// JWT claims for Cloud IoT device auth (`aud` = project id).
#[derive(Debug, Serialize, Deserialize)]
struct GcpIotClaims {
    iat: u64,
    exp: u64,
    aud: String,
}

/// Mint an RS256/ES256 JWT for `project_id` (`iat`, `exp = iat +
/// lifetime clamped to 24h`). Pure function: unit-testable.
pub fn build_jwt(
    private_key_pem: &str,
    algorithm: GcpIotAlgorithm,
    project_id: &str,
    now_secs: u64,
    lifetime_secs: u64,
) -> Result<String> {
    if project_id.trim().is_empty() {
        return Err(ConnectorError::Dispatch(
            "gcp-iot project_id must not be empty".to_string(),
        ));
    }
    let lifetime = lifetime_secs.clamp(60, 86_400);
    let claims = GcpIotClaims {
        iat: now_secs,
        exp: now_secs.saturating_add(lifetime),
        aud: project_id.to_string(),
    };
    let key = match algorithm {
        GcpIotAlgorithm::Rs256 => {
            jsonwebtoken::EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
        }
        GcpIotAlgorithm::Es256 => {
            jsonwebtoken::EncodingKey::from_ec_pem(private_key_pem.as_bytes())
        }
    }
    .map_err(|e| ConnectorError::Dispatch(format!("gcp-iot private key rejected: {e}")))?;
    jsonwebtoken::encode(&jsonwebtoken::Header::new(algorithm.jsonwebtoken()), &claims, &key)
        .map_err(|e| ConnectorError::Dispatch(format!("gcp-iot JWT signing failed: {e}")))
}

/// Proactive JWT cache: refreshes 60s before expiry.
pub struct GcpIotTokenCache {
    private_key_pem: String,
    algorithm: GcpIotAlgorithm,
    project_id: String,
    lifetime_secs: u64,
    cached: parking_lot::Mutex<Option<(String, u64)>>,
}

impl GcpIotTokenCache {
    pub fn new(
        private_key_pem: String,
        algorithm: GcpIotAlgorithm,
        project_id: String,
        lifetime_secs: u64,
    ) -> Self {
        Self {
            private_key_pem,
            algorithm,
            project_id,
            lifetime_secs: lifetime_secs.clamp(60, 86_400),
            cached: parking_lot::Mutex::new(None),
        }
    }

    /// Password JWT valid at `now_secs`, renewing inside the skew.
    pub fn token_at(&self, now_secs: u64) -> Result<String> {
        if let Some((token, exp)) = self.cached.lock().clone() {
            if now_secs + 60 < exp {
                return Ok(token);
            }
        }
        let token = build_jwt(
            &self.private_key_pem,
            self.algorithm,
            &self.project_id,
            now_secs,
            self.lifetime_secs,
        )?;
        let exp = now_secs.saturating_add(self.lifetime_secs);
        *self.cached.lock() = Some((token.clone(), exp));
        Ok(token)
    }

    pub fn token_now(&self) -> Result<String> {
        self.token_at(now_millis().max(0) as u64 / 1_000)
    }

    pub fn invalidate(&self) {
        *self.cached.lock() = None;
    }
}

/// Next scheduled refresh in millis for an `exp` (UTC seconds):
/// 60s before expiry, never in the past relative to `now_ms`.
pub fn next_refresh_ms(exp_secs: u64, now_ms: i64) -> i64 {
    let refresh = exp_secs.saturating_mul(1_000).saturating_sub(60_000) as i64;
    refresh.max(now_ms)
}

// ---------------------------------------------------------------------------
// Topic taxonomy.
// ---------------------------------------------------------------------------

/// Telemetry topic: `/devices/{device}/events[/{subfolder}]`.
pub fn telemetry_topic(device_id: &str, subfolder: Option<&str>) -> String {
    match subfolder {
        Some(sub) => format!("/devices/{device_id}/events/{sub}"),
        None => format!("/devices/{device_id}/events"),
    }
}

/// Device state topic: `/devices/{device}/state`.
pub fn state_topic(device_id: &str) -> String {
    format!("/devices/{device_id}/state")
}

/// Parse a telemetry topic into (device, subfolder?).
pub fn parse_telemetry_topic(topic: &str) -> Option<(String, Option<String>)> {
    let rest = topic.strip_prefix("/devices/")?;
    let (device, tail) = rest.split_once("/events")?;
    if device.is_empty() {
        return None;
    }
    match tail {
        "" => Some((device.to_string(), None)),
        _ => tail
            .strip_prefix('/')
            .filter(|sub| !sub.is_empty() && !sub.contains('/'))
            .map(|sub| (device.to_string(), Some(sub.to_string()))),
    }
}

/// Downlink routing: config vs commands topics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DownlinkRoute {
    Config,
    Commands(String),
    Neither,
}

/// Route `/devices/{device}/config` and `/devices/{device}/commands/#`.
pub fn route_downlink(device_id: &str, topic: &str) -> DownlinkRoute {
    if topic == format!("/devices/{device_id}/config") {
        DownlinkRoute::Config
    } else if let Some(rest) = topic.strip_prefix(&format!("/devices/{device_id}/commands/")) {
        if rest.is_empty() {
            DownlinkRoute::Neither
        } else {
            DownlinkRoute::Commands(rest.to_string())
        }
    } else {
        DownlinkRoute::Neither
    }
}

/// Validate a device state snapshot (must be a JSON object).
pub fn validate_state_snapshot(payload: &[u8]) -> Result<serde_json::Value> {
    let value: serde_json::Value = serde_json::from_slice(payload).map_err(|_| {
        ConnectorError::Dispatch("gcp-iot state must be JSON".to_string())
    })?;
    if !value.is_object() {
        return Err(ConnectorError::Dispatch(
            "gcp-iot state must be a JSON object".to_string(),
        ));
    }
    Ok(value)
}

// ---------------------------------------------------------------------------
// Transport + sink (telemetry egress with token renewal).
// ---------------------------------------------------------------------------

/// Scripted outcome for the mock transport.
#[derive(Debug, Clone)]
pub enum MockGcpIotOutcome {
    Ok,
    /// Transport failure (retries in-loop).
    ConnectionError(String),
    /// UNAUTHENTICATED (renews once), RESOURCE_EXHAUSTED (backs
    /// off), PERMISSION_DENIED (terminal).
    GrpcStatus { code: String },
}

/// One captured telemetry publish.
#[derive(Debug, Clone)]
pub struct CapturedGcpIotPublish {
    pub topic: String,
    pub body: Vec<u8>,
    pub password_token: String,
}

#[async_trait]
pub trait GcpIotTransport: Send + Sync {
    async fn publish(&self, topic: &str, body: &[u8], password_token: &str) -> Result<()>;
}

/// In-memory transport with scripted outcomes (tests, dry runs).
#[derive(Debug, Default)]
pub struct MockGcpIotTransport {
    scripted: parking_lot::Mutex<std::collections::VecDeque<MockGcpIotOutcome>>,
    captured: parking_lot::Mutex<Vec<CapturedGcpIotPublish>>,
    calls: AtomicU64,
}

impl MockGcpIotTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue outcomes consumed in order (default: success).
    pub fn script_outcomes(&self, outcomes: Vec<MockGcpIotOutcome>) {
        *self.scripted.lock() = outcomes.into_iter().collect();
    }

    pub fn captured(&self) -> Vec<CapturedGcpIotPublish> {
        self.captured.lock().clone()
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl GcpIotTransport for MockGcpIotTransport {
    async fn publish(&self, topic: &str, body: &[u8], password_token: &str) -> Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.captured.lock().push(CapturedGcpIotPublish {
            topic: topic.to_string(),
            body: body.to_vec(),
            password_token: password_token.to_string(),
        });
        match self.scripted.lock().pop_front() {
            None | Some(MockGcpIotOutcome::Ok) => Ok(()),
            Some(MockGcpIotOutcome::ConnectionError(message)) => {
                Err(ConnectorError::Connection(message))
            }
            Some(MockGcpIotOutcome::GrpcStatus { code }) => Err(match code.as_str() {
                "UNAUTHENTICATED" | "RESOURCE_EXHAUSTED" => {
                    ConnectorError::Connection(format!("mock gcp-iot {code}"))
                }
                _ => ConnectorError::Dispatch(format!("mock gcp-iot {code}")),
            }),
        }
    }
}

/// TCP loopback transport: MQTT PUBLISH framing over a plain socket
/// (TLS terminates in front of it in production).
pub struct TcpGcpIotTransport {
    host: String,
    port: u16,
    stream: tokio::sync::Mutex<Option<tokio::net::TcpStream>>,
}

impl TcpGcpIotTransport {
    pub fn new(endpoint: &str) -> Result<Self> {
        let endpoint = endpoint.trim();
        if endpoint.is_empty() {
            return Err(ConnectorError::Dispatch(
                "gcp-iot endpoint must not be empty".to_string(),
            ));
        }
        let (host, port) = match endpoint.rsplit_once(':') {
            Some((host, port)) if !port.contains('.') => {
                let port: u16 = port.parse().map_err(|_| {
                    ConnectorError::Dispatch(format!("gcp-iot bad port in {endpoint:?}"))
                })?;
                (host, port)
            }
            _ => (endpoint, 8883),
        };
        Ok(Self {
            host: host.to_string(),
            port,
            stream: tokio::sync::Mutex::new(None),
        })
    }
}

#[async_trait]
impl GcpIotTransport for TcpGcpIotTransport {
    async fn publish(&self, topic: &str, body: &[u8], _password_token: &str) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        let bytes = super::mqtt_bridge::encode_publish(topic, 0, false, 0, body, false)?;
        let mut guard = self.stream.lock().await;
        let stream = guard.as_mut().ok_or_else(|| {
            ConnectorError::Connection("gcp-iot not connected".to_string())
        })?;
        stream.write_all(&bytes).await.map_err(|e| {
            ConnectorError::Connection(format!("gcp-iot publish failed: {e}"))
        })?;
        Ok(())
    }
}

impl TcpGcpIotTransport {
    /// Dial the endpoint (idempotent once open).
    pub async fn connect(&self) -> Result<()> {
        if self.stream.lock().await.is_some() {
            return Ok(());
        }
        let addr = format!("{}:{}", self.host, self.port);
        let stream =
            tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(&addr))
                .await
                .map_err(|_| ConnectorError::Connection(format!("gcp-iot connect timeout: {addr}")))?
                .map_err(|e| ConnectorError::Connection(format!("gcp-iot connect failed: {e}")))?;
        *self.stream.lock().await = Some(stream);
        Ok(())
    }
}

/// One buffered telemetry row.
#[derive(Debug, Clone)]
struct GcpIotRow {
    topic: String,
    body: Vec<u8>,
}

/// GCP IoT bridge sink: telemetry egress with token renewal.
pub struct GcpIotSink {
    config: GcpIotConfig,
    transport: Arc<dyn GcpIotTransport>,
    token_cache: Arc<GcpIotTokenCache>,
    buffer: parking_lot::Mutex<BatchQueue<GcpIotRow>>,
    backoff: parking_lot::Mutex<BackoffState>,
    sent_batches: AtomicU64,
    sent_records: AtomicU64,
}

impl GcpIotSink {
    pub fn new(config: GcpIotConfig, transport: Arc<dyn GcpIotTransport>) -> Result<Self> {
        config.validate()?;
        let linger = config.effective_linger();
        let token_cache = Arc::new(GcpIotTokenCache::new(
            config.private_key_pem.clone(),
            config.algorithm,
            config.project_id.clone(),
            config.token_lifetime_secs,
        ));
        Ok(Self {
            buffer: parking_lot::Mutex::new(BatchQueue::new(config.effective_batch_size(), linger)),
            config,
            transport,
            token_cache,
            backoff: parking_lot::Mutex::new(BackoffState::default()),
            sent_batches: AtomicU64::new(0),
            sent_records: AtomicU64::new(0),
        })
    }

    pub fn config(&self) -> &GcpIotConfig {
        &self.config
    }

    pub fn sent_batches(&self) -> u64 {
        self.sent_batches.load(Ordering::Relaxed)
    }

    pub fn sent_records(&self) -> u64 {
        self.sent_records.load(Ordering::Relaxed)
    }

    pub fn buffered_rows(&self) -> usize {
        self.buffer.lock().len()
    }

    fn backoff_delay(&self, attempt: usize) -> Duration {
        let grown = 100u64.saturating_mul(2u64.saturating_pow(attempt.min(10) as u32)).min(2_000);
        let jitter = (now_millis().max(0) as u64) % (grown / 2 + 1);
        Duration::from_millis(grown.saturating_add(jitter).min(4_000))
    }

    /// Flush buffered rows (no-op when empty). UNAUTHENTICATED
    /// renews the token once and retries; exhaustion retries;
    /// terminal failures restore the buffer and propagate.
    pub async fn flush(&self) -> Result<()> {
        self.backoff.lock().check()?;
        let (rows, oldest) = self.buffer.lock().take_batch();
        if rows.is_empty() {
            return Ok(());
        }
        let record_count = rows.len() as u64;
        let max_retries = self.config.max_retries.unwrap_or(usize::MAX);
        let mut attempt = 0usize;
        let mut renewed_once = false;
        loop {
            let token = self.token_cache.token_now()?;
            let mut outcome: Result<()> = Ok(());
            for row in &rows {
                if let Err(e) = self.transport.publish(&row.topic, &row.body, &token).await {
                    outcome = Err(e);
                    break;
                }
            }
            match outcome {
                Ok(()) => {
                    self.backoff.lock().success();
                    self.sent_batches.fetch_add(1, Ordering::Relaxed);
                    self.sent_records.fetch_add(record_count, Ordering::Relaxed);
                    return Ok(());
                }
                Err(ConnectorError::Connection(message))
                    if message.contains("UNAUTHENTICATED") && !renewed_once =>
                {
                    renewed_once = true;
                    self.token_cache.invalidate();
                }
                Err(ConnectorError::Connection(message)) => {
                    if attempt >= max_retries {
                        return self.restore_err(
                            rows,
                            oldest,
                            ConnectorError::Connection(message),
                        );
                    }
                    attempt += 1;
                    tokio::time::sleep(self.backoff_delay(attempt)).await;
                }
                Err(e) => {
                    return self.restore_err(rows, oldest, e);
                }
            }
        }
    }

    fn restore_err(
        &self,
        rows: Vec<GcpIotRow>,
        oldest: Option<std::time::Instant>,
        error: ConnectorError,
    ) -> Result<()> {
        let mut buffer = self.buffer.lock();
        buffer.restore(rows, oldest);
        self.backoff.lock().failure();
        Err(error)
    }

    /// Validate + buffer one telemetry event on the device topic.
    /// Returns true when the batch is full or stale.
    fn buffer_row(&self, topic: &Topic, payload: &Bytes, _qos: QoS) -> Result<bool> {
        if topic.as_str().is_empty() {
            return Err(ConnectorError::Dispatch(
                "gcp-iot row requires a non-empty topic".to_string(),
            ));
        }
        if self.buffer.lock().len() >= self.config.effective_buffer() {
            return Err(ConnectorError::Connection(
                "gcp-iot buffer limit reached".to_string(),
            ));
        }
        validate_state_snapshot(payload)?;
        Ok(self.buffer.lock().push(GcpIotRow {
            topic: telemetry_topic(&self.config.device_id, None),
            body: payload.to_vec(),
        }))
    }
}

#[async_trait]
impl Sink for GcpIotSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        if self.buffer_row(topic, payload, qos)? {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "gcp_iot"
    }
}

/// Management connector handle pairing an id with a GCP IoT sink.
pub struct GcpIotConnector {
    id: String,
    sink: Arc<GcpIotSink>,
}

impl GcpIotConnector {
    pub fn new(id: impl Into<String>, sink: Arc<GcpIotSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }
}

impl super::Connector for GcpIotConnector {
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
    use crate::test_rsa_keys::{PRIVATE_PEM as RSA_PEM, PUBLIC_PEM as RSA_PUB};

    /// Test-only P-256 keypair, PKCS#8 form (openssl-generated, never deployed).
    const EC_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNtx6LMoE4Fs+KdnH\nKNSNbNtkzVHwlVXNYicddZ8NK12hRANCAASiFtHB/nPS7UK0kAIKxnr7AVBb/7MM\ngPYl7vJWoexONyDiBQN0yCt5BM+yDWnzinjmSpKSJPlfTejjsjAJYAFc\n-----END PRIVATE KEY-----\n";
    const EC_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEohbRwf5z0u1CtJACCsZ6+wFQW/+z\nDID2Je7yVqHsTjcg4gUDdMgreQTPsg1p84p45kqSkiT5X03o47IwCWABXA==\n-----END PUBLIC KEY-----\n";

    fn test_config() -> GcpIotConfig {
        GcpIotConfig {
            project_id: "my-iot-project".to_string(),
            cloud_region: "us-central1".to_string(),
            registry_id: "telemetry-registry".to_string(),
            device_id: "edge-7".to_string(),
            private_key_pem: RSA_PEM.to_string(),
            algorithm: GcpIotAlgorithm::Rs256,
            token_lifetime_secs: 3_600,
            endpoint: "mqtt.googleapis.com:8883".to_string(),
            batch_size: Some(250),
            buffer_capacity: None,
            linger_ms: Some(50),
            max_retries: Some(5),
        }
    }

    fn test_sink(config: GcpIotConfig) -> (Arc<GcpIotSink>, Arc<MockGcpIotTransport>) {
        let transport = Arc::new(MockGcpIotTransport::new());
        let sink = Arc::new(GcpIotSink::new(config, transport.clone()).unwrap());
        (sink, transport)
    }

    fn decode_claims(token: &str, public_pem: &str, algorithm: jsonwebtoken::Algorithm) -> serde_json::Value {
        let key = jsonwebtoken::DecodingKey::from_rsa_pem(public_pem.as_bytes())
            .or_else(|_| jsonwebtoken::DecodingKey::from_ec_pem(public_pem.as_bytes()))
            .expect("public key parses");
        let mut validation = jsonwebtoken::Validation::new(algorithm);
        validation.validate_exp = false;
        validation.set_audience(&["my-iot-project"]);
        let data = jsonwebtoken::decode::<serde_json::Value>(token, &key, &validation)
            .expect("verifies");
        data.claims
    }

    #[test]
    fn test_config_validation() {
        let mut config = test_config();
        assert!(config.validate().is_ok());
        assert_eq!(
            config.client_id(),
            "projects/my-iot-project/locations/us-central1/registries/telemetry-registry/devices/edge-7"
        );

        config.device_id = "bad/device".to_string();
        assert!(config.validate().is_err());
        config.device_id = "edge-7".to_string();

        config.private_key_pem = "not-a-key".to_string();
        assert!(config.validate().is_err());
        config.private_key_pem = RSA_PEM.to_string();

        config.batch_size = Some(0);
        assert!(config.validate().is_err());
        // Unbounded depths + clamped lifetime accepted.
        config.batch_size = None;
        config.token_lifetime_secs = 1_000_000;
        assert!(config.validate().is_ok());
        assert_eq!(config.effective_lifetime(), 86_400);
    }

    #[test]
    fn test_rs256_jwt_signs_and_verifies() {
        let now = 1_726_000_000u64;
        let token = build_jwt(RSA_PEM, GcpIotAlgorithm::Rs256, "my-iot-project", now, 3_600).unwrap();
        assert_eq!(token.split('.').count(), 3);
        let claims = decode_claims(&token, RSA_PUB, jsonwebtoken::Algorithm::RS256);
        assert_eq!(claims["aud"], "my-iot-project");
        assert_eq!(claims["iat"], now);
        assert_eq!(claims["exp"], now + 3_600);
        let header = jsonwebtoken::decode_header(&token).unwrap();
        assert_eq!(header.alg, jsonwebtoken::Algorithm::RS256);
    }

    #[test]
    fn test_es256_jwt_signs_and_verifies() {
        let now = 1_726_000_000u64;
        let token = build_jwt(EC_PRIVATE_PEM, GcpIotAlgorithm::Es256, "my-iot-project", now, 3_600).unwrap();
        assert_eq!(token.split('.').count(), 3);
        let claims = decode_claims(&token, EC_PUBLIC_PEM, jsonwebtoken::Algorithm::ES256);
        assert_eq!(claims["aud"], "my-iot-project");
        assert_eq!(claims["exp"], now + 3_600);
        let header = jsonwebtoken::decode_header(&token).unwrap();
        assert_eq!(header.alg, jsonwebtoken::Algorithm::ES256);
        // Wrong-key-type PEMs fail loudly per algorithm.
        assert!(build_jwt(EC_PRIVATE_PEM, GcpIotAlgorithm::Rs256, "p", now, 3_600).is_err());
    }

    #[test]
    fn test_topic_taxonomy() {
        assert_eq!(telemetry_topic("edge-7", None), "/devices/edge-7/events");
        assert_eq!(
            telemetry_topic("edge-7", Some("sensors")),
            "/devices/edge-7/events/sensors"
        );
        assert_eq!(state_topic("edge-7"), "/devices/edge-7/state");
        assert_eq!(
            parse_telemetry_topic("/devices/edge-7/events/sensors"),
            Some(("edge-7".to_string(), Some("sensors".to_string())))
        );
        assert_eq!(
            parse_telemetry_topic("/devices/edge-7/events"),
            Some(("edge-7".to_string(), None))
        );
        assert_eq!(parse_telemetry_topic("/devices//events"), None);
        assert_eq!(parse_telemetry_topic("/devices/edge-7/events/a/b"), None);
        assert_eq!(parse_telemetry_topic("devices/edge-7/events"), None);
    }

    #[test]
    fn test_state_and_downlink_routing() {
        assert!(validate_state_snapshot(br#"{"temp":1}"#).is_ok());
        assert!(validate_state_snapshot(b"[1,2]").is_err());
        assert!(validate_state_snapshot(b"nope").is_err());
        assert_eq!(route_downlink("edge-7", "/devices/edge-7/config"), DownlinkRoute::Config);
        assert_eq!(
            route_downlink("edge-7", "/devices/edge-7/commands/reboot"),
            DownlinkRoute::Commands("reboot".to_string())
        );
        assert_eq!(route_downlink("edge-7", "/devices/edge-7/commands/"), DownlinkRoute::Neither);
        assert_eq!(route_downlink("edge-7", "/devices/other/config"), DownlinkRoute::Neither);
    }

    #[test]
    fn test_refresh_scheduling_math() {
        // 60s skew, never in the past.
        assert_eq!(next_refresh_ms(1_000, 0), 940_000);
        assert_eq!(next_refresh_ms(100, 200_000), 200_000);
        // Cache honors the skew then renews.
        let cache = GcpIotTokenCache::new(RSA_PEM.to_string(), GcpIotAlgorithm::Rs256, "p".to_string(), 3_600);
        let first = cache.token_at(1_000).unwrap();
        assert_eq!(cache.token_at(2_000).unwrap(), first);
        let second = cache.token_at(5_000).unwrap();
        assert_ne!(first, second);
        cache.invalidate();
        assert_ne!(cache.token_at(2_000).unwrap(), second);
    }

    #[tokio::test]
    async fn test_telemetry_egress_and_renewal() {
        let (sink, transport) = test_sink(test_config());
        sink.send(
            &Topic::new("sensors/t1").unwrap(),
            &Bytes::from_static(br#"{"temp":21.5}"#),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        sink.flush().await.unwrap();

        let captured = transport.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].topic, "/devices/edge-7/events");
        assert_eq!(captured[0].body, br#"{"temp":21.5}"#.to_vec());
        assert_eq!(captured[0].password_token.split('.').count(), 3);
        assert_eq!(sink.sent_records(), 1);

        // UNAUTHENTICATED renews the token and retries to success.
        let (sink, transport) = test_sink(test_config());
        transport.script_outcomes(vec![
            MockGcpIotOutcome::GrpcStatus { code: "UNAUTHENTICATED".to_string() },
            MockGcpIotOutcome::Ok,
        ]);
        // Pin the cache so renewal visibly changes the token.
        *sink.token_cache.cached.lock() = Some(("old-token".to_string(), u64::MAX));
        sink.send(&Topic::new("t").unwrap(), &Bytes::from("{}"), QoS::AtMostOnce)
            .await
            .unwrap();
        sink.flush().await.unwrap();
        assert_eq!(transport.calls(), 2);
        assert_eq!(transport.captured()[0].password_token, "old-token");
        assert_ne!(transport.captured()[1].password_token, "old-token");
        assert_eq!(sink.sent_records(), 1);
    }

    #[tokio::test]
    async fn test_exhausted_and_terminal_paths() {
        // RESOURCE_EXHAUSTED backs off; max_retries 0 fails fast.
        let mut config = test_config();
        config.batch_size = Some(10);
        config.max_retries = Some(0);
        let (sink, transport) = test_sink(config);
        transport.script_outcomes(vec![MockGcpIotOutcome::GrpcStatus {
            code: "RESOURCE_EXHAUSTED".to_string(),
        }]);
        sink.send(&Topic::new("t").unwrap(), &Bytes::from("{}"), QoS::AtMostOnce)
            .await
            .unwrap();
        let err = sink.flush().await.expect_err("exhausted must fail");
        assert!(matches!(err, ConnectorError::Connection(_)));
        assert_eq!(transport.calls(), 1);
        assert_eq!(sink.buffered_rows(), 1);

        // PERMISSION_DENIED: terminal, single attempt, retained.
        let (sink, transport) = test_sink(test_config());
        transport.script_outcomes(vec![MockGcpIotOutcome::GrpcStatus {
            code: "PERMISSION_DENIED".to_string(),
        }]);
        sink.send(&Topic::new("t").unwrap(), &Bytes::from("{}"), QoS::AtMostOnce)
            .await
            .unwrap();
        let err = sink.flush().await.expect_err("denied must fail");
        assert!(matches!(err, ConnectorError::Dispatch(_)));
        assert_eq!(transport.calls(), 1);
        assert_eq!(sink.buffered_rows(), 1);
    }

    #[tokio::test]
    async fn test_loopback_telemetry_framing() {
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut head = [0u8; 1];
            stream.read_exact(&mut head).await.expect("head");
            assert_eq!(head[0], 0x30);
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.expect("len");
            let mut rest = vec![0u8; len[0] as usize];
            stream.read_exact(&mut rest).await.expect("body");
            let mut frame = vec![head[0], len[0]];
            frame.extend_from_slice(&rest);
            let decoded = crate::mqtt_bridge::decode_publish(&frame, false).expect("decode");
            assert_eq!(decoded.topic, "/devices/edge-7/events");
            assert_eq!(decoded.qos, 0);
            assert_eq!(decoded.payload, b"{\"temp\":21.5}");
        });

        let transport = Arc::new(TcpGcpIotTransport::new(&format!("127.0.0.1:{port}")).unwrap());
        transport.connect().await.unwrap();
        transport
            .publish("/devices/edge-7/events", b"{\"temp\":21.5}", "jwt-token")
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("server done")
            .expect("server task");
    }
}
