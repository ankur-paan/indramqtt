//! AWS IoT Core bridge (INDRA-193).
//!
//! Bidirectional edge↔cloud bridge: local topics remap to AWS IoT
//! Core topics (with `${client_id}` substitution), telemetry wraps
//! into Device Shadow documents on demand, and SigV4 signs WebSocket
//! URLs (`GET /mqtt`, service `iotdevicegateway`, ALPN `mqtt`) via
//! the shared signer. MQTT travels over TLS with mutual X.509
//! authentication: the client certificate/key come from
//! configuration, the server chain verifies against the configured
//! CA bundle plus the platform roots, and ALPN negotiates `mqtt`
//! where the endpoint requires it.
//!
//! Throttling (429 / `TooManyRequestsException`) and disconnects
//! retry with backoff; authorization rejections (`Unauthorized` /
//! `Forbidden`) are terminal dispatch failures.

use async_trait::async_trait;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

use super::cloud_tls;
use super::{now_millis, render_template, BackoffState, BatchQueue, ConnectorError, Result, Sink};

/// AWS IoT authentication mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", tag = "type")]
pub enum AwsIotAuth {
    /// X.509 mutual TLS (PEM validated, handshake at deploy time).
    Mtls {
        ca_cert_pem: String,
        client_cert_pem: String,
        client_key_pem: String,
    },
    /// SigV4 WebSocket auth on port 443.
    SigV4 {
        access_key_id: String,
        secret_access_key: String,
        session_token: Option<String>,
    },
}

impl Default for AwsIotAuth {
    fn default() -> Self {
        Self::Mtls {
            ca_cert_pem: String::new(),
            client_cert_pem: String::new(),
            client_key_pem: String::new(),
        }
    }
}

impl AwsIotAuth {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Mtls {
                ca_cert_pem,
                client_cert_pem,
                client_key_pem,
            } => {
                for (label, pem, marker) in [
                    ("ca_cert_pem", ca_cert_pem, "BEGIN CERTIFICATE"),
                    ("client_cert_pem", client_cert_pem, "BEGIN CERTIFICATE"),
                    ("client_key_pem", client_key_pem, "BEGIN"),
                ] {
                    if !pem.contains(marker) {
                        return Err(ConnectorError::Dispatch(format!(
                            "aws-iot {label} is not a PEM document"
                        )));
                    }
                }
                Ok(())
            }
            Self::SigV4 {
                access_key_id,
                secret_access_key,
                ..
            } => {
                if access_key_id.trim().is_empty() || secret_access_key.is_empty() {
                    return Err(ConnectorError::Dispatch(
                        "aws-iot SigV4 needs an access key + secret".to_string(),
                    ));
                }
                Ok(())
            }
        }
    }
}

/// Bridge direction for one topic mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum BridgeDirection {
    #[default]
    LocalToRemote,
    RemoteToLocal,
    BiDirectional,
}

impl BridgeDirection {
    pub fn carries_egress(self) -> bool {
        matches!(self, Self::LocalToRemote | Self::BiDirectional)
    }
}

/// One local↔remote topic mapping with `${client_id}` substitution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeTopicMapping {
    pub local_topic: String,
    pub remote_topic: String,
    #[serde(default)]
    pub direction: BridgeDirection,
}

impl BridgeTopicMapping {
    pub fn validate(&self) -> Result<()> {
        if self.local_topic.trim().is_empty() || self.remote_topic.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "aws-iot topic mappings must not be empty".to_string(),
            ));
        }
        // Strict check with a dummy client id.
        self.resolve_remote("dummy-client")?;
        Ok(())
    }

    /// Render the remote topic for one client id.
    pub fn resolve_remote(&self, client_id: &str) -> Result<String> {
        let topic = render_template(&self.remote_topic, &[("client_id", client_id.to_string())])?;
        if topic.trim().is_empty() || topic.contains('+') || topic.contains('#') {
            return Err(ConnectorError::Dispatch(format!(
                "aws-iot remote topic resolved invalid: {topic:?}"
            )));
        }
        Ok(topic)
    }

    /// Render the local pattern for one client id (wildcards allowed:
    /// patterns only, never concrete publishes).
    pub fn resolve_local(&self, client_id: &str) -> Result<String> {
        render_template(&self.local_topic, &[("client_id", client_id.to_string())])
    }
}

/// Device Shadow synchronization: reported-state path template.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowSyncConfig {
    /// Thing name template (`${client_id}` supported).
    pub thing_name_template: String,
}

fn default_batch_size() -> Option<usize> {
    Some(250)
}

fn default_connect_timeout_ms() -> Option<u64> {
    Some(5000)
}

fn default_handshake_timeout_ms() -> Option<u64> {
    Some(5000)
}

fn default_aws_alpn() -> Option<Vec<String>> {
    Some(vec!["mqtt".to_string()])
}

/// AWS IoT bridge configuration. Buffering is unbounded by default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AwsIotConfig {
    /// IoT Core endpoint (`{prefix}-ats.iot.{region}.amazonaws.com`).
    pub endpoint: String,
    /// AWS region.
    pub region: String,
    /// Edge gateway client id.
    pub client_id: String,
    /// Authentication mode.
    #[serde(default)]
    pub auth: AwsIotAuth,
    /// Topic mappings (non-empty).
    pub topic_mappings: Vec<BridgeTopicMapping>,
    /// Optional shadow synchronization.
    #[serde(default)]
    pub shadow_sync: Option<ShadowSyncConfig>,
    /// Flush trigger row count (default 250).
    #[serde(default = "default_batch_size")]
    pub batch_size: Option<usize>,
    /// Buffer capacity (`None` unbounded).
    #[serde(default)]
    pub buffer_capacity: Option<usize>,
    /// Linger flush window in ms (default 50).
    #[serde(default = "default_linger_ms")]
    pub linger_ms: Option<u64>,
    /// Retries on throttles/disconnects (default 5, `None`
    /// unbounded, 0 none).
    #[serde(default = "default_max_retries")]
    pub max_retries: Option<usize>,
    /// Request timeout in ms (default 5000).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// TCP connect timeout in ms (default 5000).
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: Option<u64>,
    /// TLS handshake timeout in ms (default 5000).
    #[serde(default = "default_handshake_timeout_ms")]
    pub handshake_timeout_ms: Option<u64>,
    /// Extra CA bundle PEM for server verification, in addition to
    /// the platform roots and (for mTLS) `auth.ca_cert_pem`.
    #[serde(default)]
    pub ca_bundle_pem: Option<String>,
    /// ALPN protocols offered during the handshake (`Some(["mqtt"])`
    /// by default; `Some([])` disables ALPN).
    #[serde(default = "default_aws_alpn")]
    pub alpn_protocols: Option<Vec<String>>,
}

fn default_max_retries() -> Option<usize> {
    Some(5)
}

fn default_linger_ms() -> Option<u64> {
    Some(50)
}

impl AwsIotConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.unwrap_or(5000).max(1))
    }

    /// TCP connect timeout (default 5000 ms).
    pub fn connect_timeout(&self) -> Duration {
        Duration::from_millis(self.connect_timeout_ms.unwrap_or(5000).max(1))
    }

    /// TLS handshake timeout (default 5000 ms).
    pub fn handshake_timeout(&self) -> Duration {
        Duration::from_millis(self.handshake_timeout_ms.unwrap_or(5000).max(1))
    }

    /// Effective ALPN protocols (`None` means the default `["mqtt"]`).
    pub fn effective_alpn(&self) -> Vec<String> {
        self.alpn_protocols
            .clone()
            .unwrap_or_else(|| vec!["mqtt".to_string()])
    }

    /// Split `endpoint` into host/port (default 8883).
    pub fn host_port(&self) -> Result<(String, u16)> {
        cloud_tls::parse_host_port(&self.endpoint, 8883)
    }

    pub fn validate(&self) -> Result<()> {
        if self.endpoint.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "aws-iot endpoint must not be empty".to_string(),
            ));
        }
        // Endpoint must parse to a concrete host/port now (TLS dials it).
        self.host_port()?;
        if self.region.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "aws-iot region must not be empty".to_string(),
            ));
        }
        if self.client_id.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "aws-iot client_id must not be empty".to_string(),
            ));
        }
        self.auth.validate()?;
        if let Some(bundle) = &self.ca_bundle_pem {
            if !bundle.trim().is_empty() && !bundle.contains("BEGIN CERTIFICATE") {
                return Err(ConnectorError::Dispatch(
                    "aws-iot ca_bundle_pem is not a PEM document".to_string(),
                ));
            }
        }
        if self.topic_mappings.is_empty() {
            return Err(ConnectorError::Dispatch(
                "aws-iot topic_mappings must not be empty".to_string(),
            ));
        }
        for mapping in &self.topic_mappings {
            mapping.validate()?;
        }
        if let Some(shadow) = &self.shadow_sync {
            if shadow.thing_name_template.trim().is_empty() {
                return Err(ConnectorError::Dispatch(
                    "aws-iot thing_name_template must not be empty".to_string(),
                ));
            }
            render_template(
                &shadow.thing_name_template,
                &[("client_id", "dummy".to_string())],
            )?;
        }
        if self.batch_size == Some(0) {
            return Err(ConnectorError::Dispatch(
                "aws-iot batch_size must be >= 1".to_string(),
            ));
        }
        Ok(())
    }

    pub fn effective_batch_size(&self) -> usize {
        self.batch_size.unwrap_or(usize::MAX).max(1)
    }

    pub fn effective_linger(&self) -> Duration {
        self.linger_ms
            .map(Duration::from_millis)
            .unwrap_or(Duration::MAX)
    }

    pub fn effective_buffer(&self) -> usize {
        self.buffer_capacity.unwrap_or(usize::MAX).max(1)
    }
}

// ---------------------------------------------------------------------------
// SigV4 WebSocket URL signer (service iotdevicegateway).
// ---------------------------------------------------------------------------

/// Percent-encode for SigV4 query strings (unreserved marks stay).
fn sigv4_encode(value: &str) -> String {
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

/// Build the `wss://{endpoint}/mqtt?...` URL signed for SigV4 auth.
/// Query parameters sort by name; the payload is unsigned
/// (`UNSIGNED-PAYLOAD`), per AWS IoT WebSocket authentication.
pub fn sign_websocket_url(
    endpoint: &str,
    region: &str,
    access_key_id: &str,
    secret_access_key: &str,
    session_token: Option<&str>,
    millis: i64,
) -> String {
    let date = super::amz_date(millis);
    let short_date = &date[..8];
    let credential = format!("{access_key_id}/{short_date}/{region}/iotdevicegateway/aws4_request");
    let mut params = vec![
        (
            "X-Amz-Algorithm".to_string(),
            "AWS4-HMAC-SHA256".to_string(),
        ),
        ("X-Amz-Credential".to_string(), credential),
        ("X-Amz-Date".to_string(), date.clone()),
        ("X-Amz-Expires".to_string(), "86400".to_string()),
        ("X-Amz-SignedHeaders".to_string(), "host".to_string()),
    ];
    if let Some(token) = session_token {
        params.push(("X-Amz-Security-Token".to_string(), token.to_string()));
    }
    params.sort_by(|a, b| a.0.cmp(&b.0));
    let canonical_qs: Vec<String> = params
        .iter()
        .map(|(key, value)| format!("{}={}", sigv4_encode(key), sigv4_encode(value)))
        .collect();
    let canonical_qs = canonical_qs.join("&");
    let canonical_request =
        format!("GET\n/mqtt\n{canonical_qs}\nhost:{endpoint}\n\nhost\nUNSIGNED-PAYLOAD");
    let scope = format!("{short_date}/{region}/iotdevicegateway/aws4_request");
    let canonical_hash = super::sha256_hex(canonical_request.as_bytes());
    let string_to_sign = format!("AWS4-HMAC-SHA256\n{date}\n{scope}\n{canonical_hash}");
    let mut key = super::hmac_sha256(
        format!("AWS4{secret_access_key}").as_bytes(),
        short_date.as_bytes(),
    );
    for part in [region, "iotdevicegateway", "aws4_request"] {
        key = super::hmac_sha256(&key, part.as_bytes());
    }
    let signature = super::hmac_sha256(&key, string_to_sign.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    format!("wss://{endpoint}/mqtt?{canonical_qs}&X-Amz-Signature={signature}")
}

// ---------------------------------------------------------------------------
// Device Shadow documents.
// ---------------------------------------------------------------------------

/// Build a shadow update document: reported state + client token.
pub fn shadow_update_document(
    reported: &serde_json::Value,
    client_token: &str,
) -> serde_json::Value {
    serde_json::json!({
        "state": { "reported": reported },
        "clientToken": client_token,
    })
}

/// Shadow topic builders for one thing name.
pub struct ShadowTopics;

impl ShadowTopics {
    pub fn update(thing: &str) -> String {
        format!("$aws/things/{thing}/shadow/update")
    }

    pub fn update_accepted(thing: &str) -> String {
        format!("$aws/things/{thing}/shadow/update/accepted")
    }

    pub fn update_rejected(thing: &str) -> String {
        format!("$aws/things/{thing}/shadow/update/rejected")
    }

    pub fn get(thing: &str) -> String {
        format!("$aws/things/{thing}/shadow/get")
    }

    /// Parse a shadow response: `Ok(reported)` for accepted docs,
    /// `Err(message)` for rejected docs (`code` + `message`).
    pub fn parse_response(body: &[u8]) -> Result<serde_json::Value> {
        let doc: serde_json::Value = serde_json::from_slice(body).map_err(|_| {
            ConnectorError::Dispatch("aws-iot shadow response not JSON".to_string())
        })?;
        if let Some(code) = doc.get("code").and_then(|v| v.as_u64()) {
            let message = doc
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("shadow rejected");
            return Err(ConnectorError::Dispatch(format!(
                "aws-iot shadow rejected with {code}: {message}"
            )));
        }
        Ok(doc)
    }
}

// ---------------------------------------------------------------------------
// Transport + sink (egress bridging with backpressure + reconnect).
// ---------------------------------------------------------------------------

/// One bridged egress frame: remote topic + payload + properties.
#[derive(Debug, Clone)]
pub struct AwsIotFrame {
    pub remote_topic: String,
    pub payload: Vec<u8>,
    /// MQTT 5.0 user properties preserved across the bridge.
    pub user_properties: Vec<(String, String)>,
    pub content_type: Option<String>,
    pub correlation_data: Option<Vec<u8>>,
}

#[async_trait]
pub trait AwsIotTransport: Send + Sync {
    async fn connect(&self) -> Result<()>;
    async fn publish(&self, frame: &AwsIotFrame) -> Result<()>;
}

/// Scripted outcome for the mock transport.
#[derive(Debug, Clone)]
pub enum MockAwsIotOutcome {
    Ok,
    /// Transport failure (reconnects + retries in-loop).
    ConnectionError(String),
    /// Throttle (429 / TooManyRequestsException → retry).
    Throttled,
    /// Authorization rejection (terminal, no retry).
    Rejected {
        message: String,
    },
}

/// In-memory transport with scripted outcomes (tests, dry runs).
#[derive(Debug, Default)]
pub struct MockAwsIotTransport {
    scripted: parking_lot::Mutex<std::collections::VecDeque<MockAwsIotOutcome>>,
    captured: parking_lot::Mutex<Vec<AwsIotFrame>>,
    calls: AtomicU64,
    connects: AtomicU64,
}

impl MockAwsIotTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue outcomes consumed in order (default: success).
    pub fn script_outcomes(&self, outcomes: Vec<MockAwsIotOutcome>) {
        *self.scripted.lock() = outcomes.into_iter().collect();
    }

    pub fn captured(&self) -> Vec<AwsIotFrame> {
        self.captured.lock().clone()
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl AwsIotTransport for MockAwsIotTransport {
    async fn connect(&self) -> Result<()> {
        self.connects.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn publish(&self, frame: &AwsIotFrame) -> Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.captured.lock().push(frame.clone());
        match self.scripted.lock().pop_front() {
            None | Some(MockAwsIotOutcome::Ok) => Ok(()),
            Some(MockAwsIotOutcome::ConnectionError(message)) => {
                Err(ConnectorError::Connection(message))
            }
            Some(MockAwsIotOutcome::Throttled) => Err(ConnectorError::Connection(
                "mock aws-iot throttled".to_string(),
            )),
            Some(MockAwsIotOutcome::Rejected { message }) => Err(ConnectorError::Dispatch(message)),
        }
    }
}

/// TLS transport: MQTT over mutual-TLS to AWS IoT Core (port 8883
/// by default). The TCP socket is only ever used as the underlay for
/// the TLS handshake; there is no cleartext MQTT path. SigV4
/// (WebSocket auth on port 443) cannot do MQTT on 8883: construction
/// succeeds so management validation stays offline, but `connect`
/// fails loudly without opening any socket.
pub struct TlsAwsIotTransport {
    host: String,
    port: u16,
    client_id: String,
    tls: Option<Arc<rustls::ClientConfig>>,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    io_timeout: Duration,
    stream: tokio::sync::Mutex<Option<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>>,
}

impl TlsAwsIotTransport {
    pub fn new(config: &AwsIotConfig) -> Result<Self> {
        config.validate()?;
        let (host, port) = config.host_port()?;
        let common = (
            host,
            port,
            config.client_id.clone(),
            config.connect_timeout(),
            config.handshake_timeout(),
            config.timeout(),
        );
        match &config.auth {
            AwsIotAuth::Mtls {
                ca_cert_pem,
                client_cert_pem,
                client_key_pem,
            } => {
                let chain = cloud_tls::certs_from_pem(client_cert_pem).map_err(|e| {
                    ConnectorError::Dispatch(format!("aws-iot client certificate rejected: {e}"))
                })?;
                let key = cloud_tls::private_key_from_pem(client_key_pem).map_err(|e| {
                    ConnectorError::Dispatch(format!("aws-iot client key rejected: {e}"))
                })?;
                let roots =
                    cloud_tls::root_store_with(ca_pem_combine(config, ca_cert_pem).as_deref())?;
                let tls =
                    cloud_tls::client_config(roots, Some((chain, key)), &config.effective_alpn())?;
                Ok(Self {
                    host: common.0,
                    port: common.1,
                    client_id: common.2,
                    tls: Some(tls),
                    connect_timeout: common.3,
                    handshake_timeout: common.4,
                    io_timeout: common.5,
                    stream: tokio::sync::Mutex::new(None),
                })
            }
            AwsIotAuth::SigV4 { .. } => Ok(Self {
                host: common.0,
                port: common.1,
                client_id: common.2,
                tls: None,
                connect_timeout: common.3,
                handshake_timeout: common.4,
                io_timeout: common.5,
                stream: tokio::sync::Mutex::new(None),
            }),
        }
    }

    fn connect_frame(&self) -> Result<Vec<u8>> {
        cloud_tls::encode_mqtt_connect(&self.client_id, true, 60, None, None)
    }
}

fn ca_pem_combine<'a>(config: &'a AwsIotConfig, mtls_ca: &'a str) -> Option<String> {
    let mut combined = String::new();
    if !mtls_ca.trim().is_empty() {
        combined.push_str(mtls_ca);
        if !combined.ends_with('\n') {
            combined.push('\n');
        }
    }
    if let Some(bundle) = &config.ca_bundle_pem {
        if !bundle.trim().is_empty() {
            combined.push_str(bundle);
            if !combined.ends_with('\n') {
                combined.push('\n');
            }
        }
    }
    if combined.trim().is_empty() {
        None
    } else {
        Some(combined)
    }
}

#[async_trait]
impl AwsIotTransport for TlsAwsIotTransport {
    async fn connect(&self) -> Result<()> {
        if self.stream.lock().await.is_some() {
            return Ok(());
        }
        let tls = self.tls.clone().ok_or_else(|| {
            ConnectorError::Dispatch(
                "aws-iot SigV4 is WebSocket auth on port 443; MQTT over TLS needs \
                 mTLS client credentials and has no plain-text fallback"
                    .to_string(),
            )
        })?;
        let mut stream = cloud_tls::tls_dial(
            &self.host,
            self.port,
            tls,
            self.connect_timeout,
            self.handshake_timeout,
            "aws-iot",
        )
        .await?;
        let connect = self.connect_frame()?;
        cloud_tls::mqtt_connect_over_tls(&mut stream, &connect, "aws-iot", self.io_timeout).await?;
        *self.stream.lock().await = Some(stream);
        Ok(())
    }

    async fn publish(&self, frame: &AwsIotFrame) -> Result<()> {
        let bytes = super::mqtt_bridge::encode_publish(
            &frame.remote_topic,
            1,
            false,
            1,
            &frame.payload,
            false,
        )?;
        let mut guard = self.stream.lock().await;
        let stream = guard
            .as_mut()
            .ok_or_else(|| ConnectorError::Connection("aws-iot not connected".to_string()))?;
        tokio::time::timeout(self.io_timeout, stream.write_all(&bytes))
            .await
            .map_err(|_| ConnectorError::Connection("aws-iot publish timeout".to_string()))?
            .map_err(|e| ConnectorError::Connection(format!("aws-iot publish failed: {e}")))?;
        Ok(())
    }
}

/// One buffered row: remote topic + payload + properties.
#[derive(Debug, Clone)]
struct AwsIotRow {
    remote_topic: String,
    payload: Vec<u8>,
    user_properties: Vec<(String, String)>,
}

/// AWS IoT bridge sink: routes egress events through mappings with
/// backpressure and reconnect accounting.
pub struct AwsIotSink {
    config: AwsIotConfig,
    transport: Arc<dyn AwsIotTransport>,
    buffer: parking_lot::Mutex<BatchQueue<AwsIotRow>>,
    backoff: parking_lot::Mutex<BackoffState>,
    sent_batches: AtomicU64,
    sent_records: AtomicU64,
}

impl AwsIotSink {
    pub fn new(config: AwsIotConfig, transport: Arc<dyn AwsIotTransport>) -> Result<Self> {
        config.validate()?;
        let linger = config.effective_linger();
        Ok(Self {
            buffer: parking_lot::Mutex::new(BatchQueue::new(config.effective_batch_size(), linger)),
            config,
            transport,
            backoff: parking_lot::Mutex::new(BackoffState::default()),
            sent_batches: AtomicU64::new(0),
            sent_records: AtomicU64::new(0),
        })
    }

    pub fn config(&self) -> &AwsIotConfig {
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

    /// Flush buffered rows (no-op when empty). Throttles and
    /// disconnects retry in-loop with backoff; rejections and
    /// exhaustion restore the buffer, engage backoff, propagate.
    pub async fn flush(&self) -> Result<()> {
        self.backoff.lock().check()?;
        let (rows, oldest) = self.buffer.lock().take_batch();
        if rows.is_empty() {
            return Ok(());
        }
        let record_count = rows.len() as u64;
        let max_retries = self.config.max_retries.unwrap_or(usize::MAX);
        let mut attempt = 0usize;
        loop {
            let result = async {
                self.transport.connect().await?;
                for row in &rows {
                    self.transport
                        .publish(&AwsIotFrame {
                            remote_topic: row.remote_topic.clone(),
                            payload: row.payload.clone(),
                            user_properties: row.user_properties.clone(),
                            content_type: Some("application/json".to_string()),
                            correlation_data: None,
                        })
                        .await?;
                }
                Ok::<(), ConnectorError>(())
            }
            .await;
            match result {
                Ok(()) => {
                    self.backoff.lock().success();
                    self.sent_batches.fetch_add(1, Ordering::Relaxed);
                    self.sent_records.fetch_add(record_count, Ordering::Relaxed);
                    return Ok(());
                }
                Err(ConnectorError::Connection(message)) => {
                    if attempt >= max_retries {
                        return self.restore_err(rows, oldest, ConnectorError::Connection(message));
                    }
                    attempt += 1;
                    tokio::time::sleep(bridge_backoff(attempt)).await;
                }
                Err(e) => {
                    return self.restore_err(rows, oldest, e);
                }
            }
        }
    }

    fn restore_err(
        &self,
        rows: Vec<AwsIotRow>,
        oldest: Option<std::time::Instant>,
        error: ConnectorError,
    ) -> Result<()> {
        let mut buffer = self.buffer.lock();
        buffer.restore(rows, oldest);
        self.backoff.lock().failure();
        Err(error)
    }

    /// Route one event through the first egress mapping whose local
    /// pattern matches the topic (`+`/`#` wildcards). Unmatched
    /// topics fail loudly (no silent blackhole).
    fn buffer_row(&self, topic: &Topic, payload: &Bytes, _qos: QoS) -> Result<bool> {
        if topic.as_str().is_empty() {
            return Err(ConnectorError::Dispatch(
                "aws-iot row requires a non-empty topic".to_string(),
            ));
        }
        if self.buffer.lock().len() >= self.config.effective_buffer() {
            return Err(ConnectorError::Connection(
                "aws-iot buffer limit reached".to_string(),
            ));
        }
        let mapping = self
            .config
            .topic_mappings
            .iter()
            .find(|mapping| {
                mapping.direction.carries_egress()
                    && topic_matches(&mapping.local_topic, topic.as_str())
            })
            .ok_or_else(|| {
                ConnectorError::Dispatch(format!(
                    "aws-iot no mapping matches topic {:?}",
                    topic.as_str()
                ))
            })?;
        // Local patterns may carry `${client_id}`; resolve with an
        // empty client here (patterns match structurally first).
        let remote_topic = mapping.resolve_remote(&self.config.client_id)?;
        Ok(self.buffer.lock().push(AwsIotRow {
            remote_topic,
            payload: payload.to_vec(),
            user_properties: Vec::new(),
        }))
    }
}

/// Transport-default backoff for bridge retries: 100ms doubling to
/// a 2s ceiling plus wall-clock jitter (no config knobs per the
/// bridge contract; batching depths stay user-configurable).
fn bridge_backoff(attempt: usize) -> Duration {
    let grown = 100u64
        .saturating_mul(2u64.saturating_pow(attempt.min(10) as u32))
        .min(2_000);
    let jitter = (now_millis().max(0) as u64) % (grown / 2 + 1);
    Duration::from_millis(grown.saturating_add(jitter).min(4_000))
}

/// Match a topic against a `+`/`#` pattern.
fn topic_matches(pattern: &str, topic: &str) -> bool {
    let mut filters = pattern.split('/');
    let mut names = topic.split('/');
    loop {
        match (filters.next(), names.next()) {
            (Some("#"), _) => return true,
            (Some("+"), Some(_)) => continue,
            (Some(filter), Some(name)) if filter == name => continue,
            (None, None) => return true,
            _ => return false,
        }
    }
}

#[async_trait]
impl Sink for AwsIotSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        if self.buffer_row(topic, payload, qos)? {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "aws_iot"
    }
}

/// Management connector handle pairing an id with an AWS IoT sink.
pub struct AwsIotConnector {
    id: String,
    sink: Arc<AwsIotSink>,
}

impl AwsIotConnector {
    pub fn new(id: impl Into<String>, sink: Arc<AwsIotSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }
}

impl super::Connector for AwsIotConnector {
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

    fn test_config() -> AwsIotConfig {
        AwsIotConfig {
            endpoint: "abc123-ats.iot.us-east-1.amazonaws.com".to_string(),
            region: "us-east-1".to_string(),
            client_id: "edge-gateway-1".to_string(),
            auth: AwsIotAuth::SigV4 {
                access_key_id: "AKIDEXAMPLE".to_string(),
                secret_access_key: "secret".to_string(),
                session_token: None,
            },
            topic_mappings: vec![BridgeTopicMapping {
                local_topic: "devices/+/telemetry".to_string(),
                remote_topic: "$aws/things/${client_id}/telemetry".to_string(),
                direction: BridgeDirection::LocalToRemote,
            }],
            shadow_sync: Some(ShadowSyncConfig {
                thing_name_template: "${client_id}".to_string(),
            }),
            batch_size: Some(250),
            buffer_capacity: None,
            linger_ms: Some(50),
            max_retries: Some(5),
            timeout_ms: None,
            connect_timeout_ms: None,
            handshake_timeout_ms: None,
            ca_bundle_pem: None,
            alpn_protocols: None,
        }
    }

    fn test_sink(config: AwsIotConfig) -> (Arc<AwsIotSink>, Arc<MockAwsIotTransport>) {
        let transport = Arc::new(MockAwsIotTransport::new());
        let sink = Arc::new(AwsIotSink::new(config, transport.clone()).unwrap());
        (sink, transport)
    }

    #[test]
    fn test_config_validation() {
        let mut config = test_config();
        assert!(config.validate().is_ok());

        config.endpoint.clear();
        assert!(config.validate().is_err());
        config.endpoint = test_config().endpoint;

        config.auth = AwsIotAuth::Mtls {
            ca_cert_pem: "not-a-pem".to_string(),
            client_cert_pem: "x".to_string(),
            client_key_pem: "y".to_string(),
        };
        assert!(config.validate().is_err());
        config.auth = AwsIotAuth::Mtls {
            ca_cert_pem: "-----BEGIN CERTIFICATE-----\nxx\n-----END CERTIFICATE-----".to_string(),
            client_cert_pem: "-----BEGIN CERTIFICATE-----\nxx\n-----END CERTIFICATE-----"
                .to_string(),
            client_key_pem: "-----BEGIN PRIVATE KEY-----\nxx\n-----END PRIVATE KEY-----"
                .to_string(),
        };
        assert!(config.validate().is_ok());
        config.auth = test_config().auth;

        config.topic_mappings.clear();
        assert!(config.validate().is_err());
        config.topic_mappings = test_config().topic_mappings;

        config.batch_size = Some(0);
        assert!(config.validate().is_err());
        // Unbounded depths accepted: zero clamped ceilings.
        config.batch_size = None;
        config.buffer_capacity = Some(10_000_000);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_sigv4_websocket_known_answer() {
        // Independent Python (hmac/hashlib) vector: GET /mqtt at
        // 2026-09-12T11:18:09Z, no session token.
        let url = sign_websocket_url(
            "abc123-ats.iot.us-east-1.amazonaws.com",
            "us-east-1",
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            None,
            1_789_211_889_000,
        );
        assert_eq!(
            url,
            "wss://abc123-ats.iot.us-east-1.amazonaws.com/mqtt\
             ?X-Amz-Algorithm=AWS4-HMAC-SHA256\
             &X-Amz-Credential=AKIDEXAMPLE%2F20260912%2Fus-east-1%2Fiotdevicegateway%2Faws4_request\
             &X-Amz-Date=20260912T111809Z\
             &X-Amz-Expires=86400\
             &X-Amz-SignedHeaders=host\
             &X-Amz-Signature=884c1e3bab089a39b1b5922faf9090785c6e592f9bf8dd79f82a0395ebf26e7e"
        );
        // Session tokens join the signed query.
        let with_token = sign_websocket_url(
            "abc123-ats.iot.us-east-1.amazonaws.com",
            "us-east-1",
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            Some("session-token"),
            1_789_211_889_000,
        );
        assert!(with_token.contains("X-Amz-Security-Token=session-token"));
        assert_ne!(url, with_token);
    }

    #[test]
    fn test_topic_mapping_resolution() {
        let mapping = BridgeTopicMapping {
            local_topic: "devices/+/telemetry".to_string(),
            remote_topic: "$aws/things/${client_id}/telemetry".to_string(),
            direction: BridgeDirection::BiDirectional,
        };
        assert!(mapping.validate().is_ok());
        assert_eq!(
            mapping.resolve_remote("edge-7").unwrap(),
            "$aws/things/edge-7/telemetry"
        );
        assert_eq!(
            mapping.resolve_local("edge-7").unwrap(),
            "devices/+/telemetry"
        );
        assert!(topic_matches(
            "devices/+/telemetry",
            "devices/edge-7/telemetry"
        ));
        assert!(!topic_matches(
            "devices/+/telemetry",
            "devices/edge-7/state"
        ));
        assert!(topic_matches("devices/#", "devices/edge-7/telemetry"));
        assert!(!topic_matches("other/#", "devices/edge-7/telemetry"));

        let bad = BridgeTopicMapping {
            local_topic: "devices/+/telemetry".to_string(),
            remote_topic: "$aws/things/${nope}/telemetry".to_string(),
            direction: BridgeDirection::LocalToRemote,
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn test_shadow_documents() {
        let reported = serde_json::json!({"temperature": 23.4, "status": "active"});
        let doc = shadow_update_document(&reported, "indra-12345");
        assert_eq!(doc["state"]["reported"]["temperature"], 23.4);
        assert_eq!(doc["clientToken"], "indra-12345");

        assert_eq!(
            ShadowTopics::update("thing-1"),
            "$aws/things/thing-1/shadow/update"
        );
        assert_eq!(
            ShadowTopics::update_accepted("thing-1"),
            "$aws/things/thing-1/shadow/update/accepted"
        );
        assert_eq!(
            ShadowTopics::update_rejected("thing-1"),
            "$aws/things/thing-1/shadow/update/rejected"
        );
        assert_eq!(
            ShadowTopics::get("thing-1"),
            "$aws/things/thing-1/shadow/get"
        );

        // Accepted docs pass through; rejected docs fail with code.
        let accepted =
            ShadowTopics::parse_response(br#"{"state":{"reported":{}},"clientToken":"x"}"#)
                .unwrap();
        assert_eq!(accepted["clientToken"], "x");
        let err = ShadowTopics::parse_response(
            br#"{"code":400,"message":"Missing required node: state","clientToken":"x"}"#,
        )
        .expect_err("rejected must fail");
        assert!(matches!(err, ConnectorError::Dispatch(_)));
        assert!(ShadowTopics::parse_response(b"nope").is_err());
    }

    #[tokio::test]
    async fn test_bridge_routing_and_properties() {
        let mut config = test_config();
        config.batch_size = Some(10);
        let (sink, transport) = test_sink(config);
        sink.send(
            &Topic::new("devices/edge-7/telemetry").unwrap(),
            &Bytes::from_static(br#"{"temp":21.5}"#),
            QoS::AtLeastOnce,
        )
        .await
        .unwrap();
        sink.flush().await.unwrap();

        let captured = transport.captured();
        assert_eq!(captured.len(), 1);
        // Remote topic resolves with the gateway client id.
        assert_eq!(
            captured[0].remote_topic,
            "$aws/things/edge-gateway-1/telemetry"
        );
        assert_eq!(captured[0].payload, br#"{"temp":21.5}"#.to_vec());
        assert_eq!(
            captured[0].content_type.as_deref(),
            Some("application/json")
        );
        assert_eq!(sink.sent_records(), 1);

        // Unmatched topics fail loudly (no silent blackhole).
        assert!(sink
            .send(
                &Topic::new("other/thing").unwrap(),
                &Bytes::from("{}"),
                QoS::AtMostOnce
            )
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_throttle_retries_and_rejection_aborts() {
        // Throttle then success (fixed 100ms-class backoff keeps this fast).
        let mut config = test_config();
        config.batch_size = Some(10);
        config.max_retries = Some(3);
        let (sink, transport) = test_sink(config);
        transport.script_outcomes(vec![MockAwsIotOutcome::Throttled, MockAwsIotOutcome::Ok]);
        sink.send(
            &Topic::new("devices/a/telemetry").unwrap(),
            &Bytes::from("{}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        sink.flush().await.unwrap();
        assert_eq!(transport.calls(), 2);
        assert_eq!(sink.sent_records(), 1);
        assert_eq!(sink.buffered_rows(), 0);

        // Authorization rejection: terminal, single attempt, retained.
        let (sink, transport) = test_sink(test_config());
        transport.script_outcomes(vec![MockAwsIotOutcome::Rejected {
            message: "Forbidden: unauthorized".to_string(),
        }]);
        sink.send(
            &Topic::new("devices/a/telemetry").unwrap(),
            &Bytes::from("{}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        let err = sink.flush().await.expect_err("rejection must fail");
        assert!(matches!(err, ConnectorError::Dispatch(_)));
        assert_eq!(transport.calls(), 1);
        assert_eq!(sink.buffered_rows(), 1);
    }

    #[test]
    fn test_no_plain_socket_path() {
        // The module must not contain a cleartext MQTT path: the only
        // TCP dial lives in the shared TLS helper, and SigV4 without
        // mTLS is a dispatch error, never a fallback. The needle is
        // built at runtime so this assertion does not match itself.
        let source = include_str!("aws_iot.rs");
        let needle = ["TcpStream", "connect"].join("::");
        assert!(
            !source.contains(&needle),
            "aws-iot must not open a plain socket"
        );
        let deferred = ["terminates in front", "of it"].join(" ");
        assert!(
            !source.contains(&deferred),
            "aws-iot must not defer TLS to deployment"
        );
    }

    #[tokio::test]
    async fn test_tls_transport_needs_mtls() {
        // SigV4 credentials cannot do MQTT over TLS on 8883: fail
        // loudly at connect time instead of falling back to
        // cleartext. Construction stays offline so management
        // validation never dials.
        let mut config = test_config();
        config.endpoint = "127.0.0.1:8883".to_string();
        let transport = TlsAwsIotTransport::new(&config).unwrap();
        match transport.connect().await {
            Err(ConnectorError::Dispatch(message)) => {
                assert!(message.contains("no plain-text fallback"));
            }
            _ => panic!("SigV4 must not connect over MQTT"),
        }
    }

    #[test]
    fn test_tls_timeouts_and_alpn_defaults() {
        let config = test_config();
        assert_eq!(
            config.connect_timeout(),
            Duration::from_millis(5000),
            "connect default must stay 5000 ms"
        );
        assert_eq!(
            config.handshake_timeout(),
            Duration::from_millis(5000),
            "handshake default must stay 5000 ms"
        );
        assert_eq!(config.effective_alpn(), vec!["mqtt".to_string()]);
        let mut custom = test_config();
        custom.connect_timeout_ms = Some(1500);
        custom.handshake_timeout_ms = Some(2500);
        custom.alpn_protocols = Some(vec![]);
        assert_eq!(custom.connect_timeout(), Duration::from_millis(1500));
        assert_eq!(custom.handshake_timeout(), Duration::from_millis(2500));
        assert!(custom.effective_alpn().is_empty());
    }

    const TEST_CA_PEM: &str = include_str!("../testdata/ca-cert.pem");
    const TEST_SERVER_CERT_PEM: &str = include_str!("../testdata/server-cert.pem");
    const TEST_SERVER_KEY_PEM: &str = include_str!("../testdata/server-key.pem");
    const TEST_CLIENT_CERT_PEM: &str = include_str!("../testdata/client-cert.pem");
    const TEST_CLIENT_KEY_PEM: &str = include_str!("../testdata/client-key.pem");

    fn mtls_test_config(endpoint: &str) -> AwsIotConfig {
        AwsIotConfig {
            endpoint: endpoint.to_string(),
            region: "us-east-1".to_string(),
            client_id: "edge-gateway-1".to_string(),
            auth: AwsIotAuth::Mtls {
                ca_cert_pem: TEST_CA_PEM.to_string(),
                client_cert_pem: TEST_CLIENT_CERT_PEM.to_string(),
                client_key_pem: TEST_CLIENT_KEY_PEM.to_string(),
            },
            topic_mappings: vec![BridgeTopicMapping {
                local_topic: "devices/+/telemetry".to_string(),
                remote_topic: "$aws/things/${client_id}/telemetry".to_string(),
                direction: BridgeDirection::LocalToRemote,
            }],
            shadow_sync: None,
            batch_size: Some(10),
            buffer_capacity: None,
            linger_ms: Some(50),
            max_retries: Some(1),
            timeout_ms: Some(2000),
            connect_timeout_ms: Some(2000),
            handshake_timeout_ms: Some(2000),
            ca_bundle_pem: None,
            alpn_protocols: None,
        }
    }

    #[tokio::test]
    async fn test_tls_handshake_and_publish() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let server_config = crate::cloud_tls::test_certs::server_config(
            TEST_SERVER_CERT_PEM,
            TEST_SERVER_KEY_PEM,
            Some(TEST_CA_PEM),
        )
        .expect("test server config");
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept");
            let mut tls = acceptor.accept(tcp).await.expect("tls accept");
            // Mutual TLS negotiated ALPN `mqtt`.
            let negotiated = tls.get_ref().1.alpn_protocol().map(|v| v.to_vec());
            assert_eq!(negotiated, Some(b"mqtt".to_vec()));
            let (client_id, username, password) = crate::cloud_tls::read_client_connect(&mut tls)
                .await
                .expect("read CONNECT");
            assert_eq!(client_id, "edge-gateway-1");
            assert_eq!(username, None);
            assert_eq!(password, None);
            tls.write_all(&[0x20, 0x02, 0x00, 0x00])
                .await
                .expect("CONNACK");
            // One QoS 1 PUBLISH frame; decode through the shared codec.
            let mut head = [0u8; 1];
            tls.read_exact(&mut head).await.expect("head");
            assert_eq!(head[0], 0x32);
            let mut len_buf = Vec::new();
            loop {
                let mut byte = [0u8; 1];
                tls.read_exact(&mut byte).await.expect("len");
                len_buf.push(byte[0]);
                if byte[0] & 0x80 == 0 {
                    break;
                }
            }
            let (remaining, _) =
                crate::mqtt_bridge::decode_remaining_length(&len_buf).expect("remaining");
            let mut rest = vec![0u8; remaining];
            tls.read_exact(&mut rest).await.expect("body");
            let mut frame = vec![head[0]];
            frame.extend_from_slice(&len_buf);
            frame.extend_from_slice(&rest);
            let decoded = crate::mqtt_bridge::decode_publish(&frame, false).expect("decode");
            assert_eq!(decoded.topic, "$aws/things/edge-gateway-1/telemetry");
            assert_eq!(decoded.packet_id, 1);
            assert_eq!(decoded.payload, b"{\"temp\":21.5}");
        });

        let config = mtls_test_config(&format!("127.0.0.1:{port}"));
        let transport = Arc::new(TlsAwsIotTransport::new(&config).unwrap());
        transport.connect().await.unwrap();
        transport
            .publish(&AwsIotFrame {
                remote_topic: "$aws/things/edge-gateway-1/telemetry".to_string(),
                payload: br#"{"temp":21.5}"#.to_vec(),
                user_properties: Vec::new(),
                content_type: None,
                correlation_data: None,
            })
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .expect("server done")
            .expect("server task");
    }

    #[tokio::test]
    async fn test_plain_listener_cannot_complete_handshake() {
        use tokio::net::TcpListener;

        // A cleartext listener speaks no TLS: the client must fail the
        // handshake instead of leaking MQTT in the clear.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            use tokio::io::AsyncReadExt;
            // Read whatever the client sends, then close without a
            // ServerHello so the handshake cannot complete.
            let mut buf = [0u8; 1024];
            let _ = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf)).await;
        });
        let config = mtls_test_config(&format!("127.0.0.1:{port}"));
        let transport = Arc::new(TlsAwsIotTransport::new(&config).unwrap());
        let err = transport
            .connect()
            .await
            .expect_err("plain listener must fail");
        assert!(matches!(err, ConnectorError::Connection(_)));
        server.abort();
    }
}
