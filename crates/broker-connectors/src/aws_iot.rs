//! AWS IoT Core bridge (INDRA-193).
//!
//! Bidirectional edge↔cloud bridge: local topics remap to AWS IoT
//! Core topics (with `${client_id}` substitution), telemetry wraps
//! into Device Shadow documents on demand, and SigV4 URL signing
//! (`GET /mqtt`, service `iotdevicegateway`) stays as a pure helper
//! for offline validation. MQTT travels over TLS with mutual X.509
//! authentication: the client certificate/key come from
//! configuration, the server chain verifies against the configured
//! CA bundle plus the OS system trust store, and ALPN negotiates `mqtt`
//! where the endpoint requires it.
//!
//! Production traffic runs on the hand-written `TlsAwsIotTransport`
//! below over `tokio-rustls` with `rustls` TLS: mutual TLS on port
//! 8883 with CONNECT, PUBLISH at QoS 0 and 1, PUBACK tracking,
//! keepalive PING and reconnect with backoff. There is no WebSocket
//! transport in this build (no compliant WebSocket client was
//! available without a disallowed licence); SigV4 configurations are
//! rejected at registration. SigV4 URL signatures remain
//! cross-checked against the maintained `aws-sigv4` signing key
//! derivation by unit tests.
//!
//! Throttling (429 / `TooManyRequestsException`) and disconnects
//! retry with backoff; authorization rejections (`Unauthorized` /
//! `Forbidden`) are terminal dispatch failures.

use async_trait::async_trait;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
    /// the OS system trust store and (for mTLS) `auth.ca_cert_pem`.
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
    /// Egress QoS: 0 or 1 only (AWS IoT Core has no QoS 2).
    /// QoS 1 waits for PUBACK; QoS 0 is fire-and-forget.
    pub qos: u8,
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

/// MQTT keepalive for the AWS IoT bridge (seconds). The CONNECT
/// frame advertises this; the transport sends PINGREQ when idle for
/// half of it and expects PINGRESP, so a half-open connection is
/// noticed before the next publish blocks on it.
const AWS_KEEPALIVE_SECS: u16 = 60;

/// TLS transport: MQTT over mutual-TLS to AWS IoT Core (port 8883
/// by default). The TCP socket is only ever used as the underlay for
/// the TLS handshake; there is no cleartext MQTT path. Only mTLS is
/// built in this tree: SigV4 WebSocket auth has no transport and is
/// rejected at construction (registration), never deferred to first
/// publish. Missing client material is likewise refused by `new`,
/// not by `connect` or `publish`.
pub struct TlsAwsIotTransport {
    host: String,
    port: u16,
    client_id: String,
    tls: Arc<rustls::ClientConfig>,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    io_timeout: Duration,
    keepalive: Duration,
    stream: tokio::sync::Mutex<Option<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>>,
    packet_id: AtomicU32,
    last_activity: parking_lot::Mutex<Instant>,
}

impl std::fmt::Debug for TlsAwsIotTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsAwsIotTransport")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("client_id", &self.client_id)
            .field("connect_timeout", &self.connect_timeout)
            .field("handshake_timeout", &self.handshake_timeout)
            .field("io_timeout", &self.io_timeout)
            .field("keepalive", &self.keepalive)
            .field("packet_id", &self.packet_id.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl TlsAwsIotTransport {
    pub fn new(config: &AwsIotConfig) -> Result<Self> {
        config.validate()?;
        let (host, port) = config.host_port()?;
        match &config.auth {
            AwsIotAuth::Mtls {
                ca_cert_pem,
                client_cert_pem,
                client_key_pem,
            } => {
                // Fail fast on bad PEM material so management
                // validation stays offline: a missing certificate or
                // key is a registration error, not a first-publish
                // surprise.
                let chain = cloud_tls::certs_from_pem(client_cert_pem).map_err(|e| {
                    ConnectorError::Dispatch(format!("aws-iot client certificate rejected: {e}"))
                })?;
                let key = cloud_tls::private_key_from_pem(client_key_pem).map_err(|e| {
                    ConnectorError::Dispatch(format!("aws-iot client key rejected: {e}"))
                })?;
                let roots =
                    cloud_tls::root_store_with(ca_pem_combine(config, ca_cert_pem).as_deref())?;
                // Server trust defaults to the OS system store plus the
                // configured bundle (`ca_cert_pem`/`ca_bundle_pem`).
                let tls =
                    cloud_tls::client_config(roots, Some((chain, key)), &config.effective_alpn())?;
                Ok(Self {
                    host,
                    port,
                    client_id: config.client_id.clone(),
                    tls,
                    connect_timeout: config.connect_timeout(),
                    handshake_timeout: config.handshake_timeout(),
                    io_timeout: config.timeout(),
                    keepalive: Duration::from_secs(u64::from(AWS_KEEPALIVE_SECS)),
                    stream: tokio::sync::Mutex::new(None),
                    packet_id: AtomicU32::new(0),
                    last_activity: parking_lot::Mutex::new(Instant::now()),
                })
            }
            AwsIotAuth::SigV4 { .. } => Err(ConnectorError::Dispatch(
                "aws-iot SigV4 WebSocket path is not built in this build; use mTLS client credentials"
                    .to_string(),
            )),
        }
    }

    fn connect_frame(&self) -> Result<Vec<u8>> {
        cloud_tls::encode_mqtt_connect(&self.client_id, true, AWS_KEEPALIVE_SECS, None, None)
    }

    /// Next packet identifier, cycling 1..=65535 and never yielding 0.
    fn next_packet_id(&self) -> u16 {
        (self.packet_id.fetch_add(1, Ordering::SeqCst) % 65_535 + 1) as u16
    }

    pub async fn is_connected(&self) -> bool {
        self.stream.lock().await.is_some()
    }

    /// Drop the TLS stream. The next `connect` dials again (used to
    /// prove reconnect after a rotation or a half-open drop).
    pub async fn disconnect(&self) {
        *self.stream.lock().await = None;
    }

    fn should_ping(&self) -> bool {
        let half = self.keepalive.checked_div(2).unwrap_or(self.keepalive);
        self.last_activity.lock().elapsed() > half
    }

    fn touch(&self) {
        *self.last_activity.lock() = Instant::now();
    }

    async fn ping_stream(
        stream: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
        io_timeout: Duration,
    ) -> Result<()> {
        tokio::time::timeout(io_timeout, stream.write_all(&[0xC0, 0x00]))
            .await
            .map_err(|_| ConnectorError::Connection("aws-iot ping timeout".to_string()))?
            .map_err(|e| ConnectorError::Connection(format!("aws-iot ping failed: {e}")))?;
        let mut resp = [0u8; 2];
        tokio::time::timeout(io_timeout, stream.read_exact(&mut resp))
            .await
            .map_err(|_| ConnectorError::Connection("aws-iot pingresp timeout".to_string()))?
            .map_err(|e| ConnectorError::Connection(format!("aws-iot pingresp failed: {e}")))?;
        if resp != [0xD0, 0x00] {
            return Err(ConnectorError::Connection(
                "aws-iot malformed PINGRESP".to_string(),
            ));
        }
        Ok(())
    }

    async fn write_publish_qos0(
        stream: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
        topic: &str,
        payload: &[u8],
        io_timeout: Duration,
    ) -> Result<()> {
        let bytes = super::mqtt_bridge::encode_publish(topic, 0, false, 0, payload, false)?;
        tokio::time::timeout(io_timeout, stream.write_all(&bytes))
            .await
            .map_err(|_| ConnectorError::Connection("aws-iot publish timeout".to_string()))?
            .map_err(|e| ConnectorError::Connection(format!("aws-iot publish failed: {e}")))?;
        Ok(())
    }

    async fn write_publish_qos1(
        stream: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
        topic: &str,
        payload: &[u8],
        packet_id: u16,
        io_timeout: Duration,
    ) -> Result<()> {
        let bytes = super::mqtt_bridge::encode_publish(topic, 1, false, packet_id, payload, false)?;
        tokio::time::timeout(io_timeout, stream.write_all(&bytes))
            .await
            .map_err(|_| ConnectorError::Connection("aws-iot publish timeout".to_string()))?
            .map_err(|e| ConnectorError::Connection(format!("aws-iot publish failed: {e}")))?;
        let mut ack = [0u8; 4];
        tokio::time::timeout(io_timeout, stream.read_exact(&mut ack))
            .await
            .map_err(|_| ConnectorError::Connection("aws-iot PUBACK timeout".to_string()))?
            .map_err(|e| ConnectorError::Connection(format!("aws-iot PUBACK failed: {e}")))?;
        if ack[0] != 0x40 || ack[1] != 0x02 {
            return Err(ConnectorError::Connection(
                "aws-iot malformed PUBACK".to_string(),
            ));
        }
        let got = u16::from_be_bytes([ack[2], ack[3]]);
        if got != packet_id {
            return Err(ConnectorError::Connection(format!(
                "aws-iot PUBACK id mismatch: got {got}, want {packet_id}"
            )));
        }
        Ok(())
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
        let mut stream = cloud_tls::tls_dial(
            &self.host,
            self.port,
            self.tls.clone(),
            self.connect_timeout,
            self.handshake_timeout,
            "aws-iot",
        )
        .await?;
        let connect = self.connect_frame()?;
        cloud_tls::mqtt_connect_over_tls(&mut stream, &connect, "aws-iot", self.io_timeout).await?;
        *self.stream.lock().await = Some(stream);
        self.touch();
        Ok(())
    }

    async fn publish(&self, frame: &AwsIotFrame) -> Result<()> {
        if frame.qos > 1 {
            return Err(ConnectorError::Dispatch(format!(
                "aws-iot qos {} not supported; use 0 or 1",
                frame.qos
            )));
        }
        // Reconnect is driven by the sink's backoff loop: any
        // `Connection` failure below invalidates the stream so the
        // next `connect` dials again. `Dispatch` failures (bad topic,
        // bad QoS) leave the stream alone.
        let mut guard = self.stream.lock().await;
        if guard.is_none() {
            return Err(ConnectorError::Connection(
                "aws-iot not connected".to_string(),
            ));
        }
        if self.should_ping() {
            let ping_ok = {
                let stream = guard.as_mut().expect("checked above");
                Self::ping_stream(stream, self.io_timeout).await.is_ok()
            };
            if !ping_ok {
                *guard = None;
                return Err(ConnectorError::Connection(
                    "aws-iot keepalive ping failed".to_string(),
                ));
            }
            self.touch();
        }
        if frame.qos == 0 {
            let outcome = {
                let stream = guard.as_mut().expect("checked above");
                Self::write_publish_qos0(
                    stream,
                    &frame.remote_topic,
                    &frame.payload,
                    self.io_timeout,
                )
                .await
            };
            match outcome {
                Ok(()) => {
                    self.touch();
                    Ok(())
                }
                Err(e) => {
                    if matches!(e, ConnectorError::Connection(_)) {
                        *guard = None;
                    }
                    Err(e)
                }
            }
        } else {
            let packet_id = self.next_packet_id();
            let outcome = {
                let stream = guard.as_mut().expect("checked above");
                Self::write_publish_qos1(
                    stream,
                    &frame.remote_topic,
                    &frame.payload,
                    packet_id,
                    self.io_timeout,
                )
                .await
            };
            match outcome {
                Ok(()) => {
                    self.touch();
                    Ok(())
                }
                Err(e) => {
                    // PUBACK timeouts, mismatches and writes are all
                    // `Connection` here, so the stream is no longer
                    // trustworthy for at-least-once; `Dispatch` (bad
                    // topic) leaves it alone.
                    if matches!(e, ConnectorError::Connection(_)) {
                        *guard = None;
                    }
                    Err(e)
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SigV4 signing helpers (manual HMAC chain cross-checked against
// the maintained `aws-sigv4` crate by unit tests).
// ---------------------------------------------------------------------------

/// Derive the SigV4 signing key with the manual HMAC chain (the same
/// chain `sign_websocket_url` uses). Public so qualification tooling
/// and downstream gates can cross-check the maintained `aws-sigv4`
/// derivation below.
pub fn sigv4_signing_key_manual(secret: &str, short_date: &str, region: &str) -> Vec<u8> {
    let mut key = super::hmac_sha256(format!("AWS4{secret}").as_bytes(), short_date.as_bytes());
    for part in [region, "iotdevicegateway", "aws4_request"] {
        key = super::hmac_sha256(&key, part.as_bytes());
    }
    key
}

/// Derive the same signing key through the maintained `aws-sigv4`
/// crate. The two must agree; the unit test below pins that.
pub fn sigv4_signing_key_via_sdk(secret: &str, millis: i64, region: &str) -> Vec<u8> {
    use std::time::{Duration, UNIX_EPOCH};
    let time = UNIX_EPOCH + Duration::from_millis(millis.max(0) as u64);
    aws_sigv4::sign::v4::generate_signing_key(secret, time, region, "iotdevicegateway")
        .as_ref()
        .to_vec()
}

/// Sign `string_to_sign` through the maintained `aws-sigv4` crate.
pub fn sigv4_signature_via_sdk(signing_key: &[u8], string_to_sign: &str) -> String {
    aws_sigv4::sign::v4::calculate_signature(signing_key, string_to_sign.as_bytes())
}

/// One buffered row: remote topic + payload + properties.
#[derive(Debug, Clone)]
struct AwsIotRow {
    remote_topic: String,
    payload: Vec<u8>,
    user_properties: Vec<(String, String)>,
    /// Egress QoS 0 or 1 (ingress ExactlyOnce downgrades to 1: AWS
    /// IoT Core speaks 0/1 only).
    qos: u8,
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
                            qos: row.qos,
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
    fn buffer_row(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<bool> {
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
        // AWS IoT Core speaks QoS 0 and 1 only. Preserve 0/1 from
        // ingress; downgrade ExactlyOnce to AtLeastOnce so QoS 2
        // ingress still delivers instead of failing the bridge.
        // TODO(parity): should QoS 2 ingress be rejected instead of
        // downgraded to QoS 1?
        let qos: u8 = match qos {
            QoS::AtMostOnce => 0,
            QoS::AtLeastOnce | QoS::ExactlyOnce => 1,
        };
        Ok(self.buffer.lock().push(AwsIotRow {
            remote_topic,
            payload: payload.to_vec(),
            user_properties: Vec::new(),
            qos,
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

    #[test]
    fn test_tls_sigv4_rejected_at_registration() {
        // No WebSocket transport exists in this build: SigV4
        // configurations are refused at registration (construction),
        // never deferred to first publish, and never fall back to
        // cleartext. Construction stays offline so management
        // validation never dials.
        let mut config = test_config();
        config.endpoint = "127.0.0.1:8883".to_string();
        match TlsAwsIotTransport::new(&config) {
            Err(ConnectorError::Dispatch(message)) => {
                assert!(
                    message.contains("WebSocket"),
                    "unexpected message: {message}"
                );
            }
            other => panic!("SigV4 must be rejected at registration, got {other:?}"),
        }
    }

    #[test]
    fn test_tls_missing_cert_refused_at_registration() {
        // A missing certificate or key is a registration error, not a
        // first-publish surprise: management validation stays offline
        // and fails fast.
        let mut config = mtls_test_config("127.0.0.1:8883");
        config.auth = AwsIotAuth::Mtls {
            ca_cert_pem: TEST_CA_PEM.to_string(),
            client_cert_pem: String::new(),
            client_key_pem: String::new(),
        };
        assert!(matches!(
            TlsAwsIotTransport::new(&config),
            Err(ConnectorError::Dispatch(_))
        ));
        let mut bad_key = mtls_test_config("127.0.0.1:8883");
        bad_key.auth = AwsIotAuth::Mtls {
            ca_cert_pem: TEST_CA_PEM.to_string(),
            client_cert_pem: TEST_CLIENT_CERT_PEM.to_string(),
            client_key_pem: "not-a-pem".to_string(),
        };
        assert!(matches!(
            TlsAwsIotTransport::new(&bad_key),
            Err(ConnectorError::Dispatch(_))
        ));
        // Valid material builds offline without dialling.
        let ok = mtls_test_config("127.0.0.1:8883");
        assert!(TlsAwsIotTransport::new(&ok).is_ok());
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
    async fn test_tls_handshake_and_publish_qos1_with_puback() {
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
            // PUBACK for the same packet id, through the real codec.
            let ack = [
                0x40,
                0x02,
                (decoded.packet_id >> 8) as u8,
                (decoded.packet_id & 0xFF) as u8,
            ];
            tls.write_all(&ack).await.expect("PUBACK");
        });

        let config = mtls_test_config(&format!("127.0.0.1:{port}"));
        let transport = Arc::new(TlsAwsIotTransport::new(&config).unwrap());
        transport.connect().await.unwrap();
        assert!(transport.is_connected().await);
        transport
            .publish(&AwsIotFrame {
                remote_topic: "$aws/things/edge-gateway-1/telemetry".to_string(),
                payload: br#"{"temp":21.5}"#.to_vec(),
                user_properties: Vec::new(),
                content_type: None,
                correlation_data: None,
                qos: 1,
            })
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .expect("server done")
            .expect("server task");
        transport.disconnect().await;
        assert!(!transport.is_connected().await);
    }

    #[tokio::test]
    async fn test_tls_handshake_and_publish_qos0_no_puback() {
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
            let _ = crate::cloud_tls::read_client_connect(&mut tls)
                .await
                .expect("read CONNECT");
            tls.write_all(&[0x20, 0x02, 0x00, 0x00])
                .await
                .expect("CONNACK");
            // One QoS 0 PUBLISH frame (0x30); no PUBACK follows.
            let mut head = [0u8; 1];
            tls.read_exact(&mut head).await.expect("head");
            assert_eq!(head[0], 0x30);
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
            assert_eq!(decoded.topic, "a/b");
            assert_eq!(decoded.qos, 0);
            assert_eq!(decoded.payload, b"hi");
        });

        let config = mtls_test_config(&format!("127.0.0.1:{port}"));
        let transport = Arc::new(TlsAwsIotTransport::new(&config).unwrap());
        transport.connect().await.unwrap();
        transport
            .publish(&AwsIotFrame {
                remote_topic: "a/b".to_string(),
                payload: b"hi".to_vec(),
                user_properties: Vec::new(),
                content_type: None,
                correlation_data: None,
                qos: 0,
            })
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .expect("server done")
            .expect("server task");
    }

    #[tokio::test]
    async fn test_sink_reconnect_invalidates_on_failure() {
        // Reconnect: a publish without a connection and a dial against
        // a closed port both fail as retryable Connection errors and
        // leave the transport disconnected, so the sink backoff loop
        // dials again instead of reusing a dead stream.
        let mut closed = mtls_test_config("127.0.0.1:1");
        closed.connect_timeout_ms = Some(200);
        closed.handshake_timeout_ms = Some(200);
        closed.timeout_ms = Some(200);
        let tls = Arc::new(TlsAwsIotTransport::new(&closed).unwrap());
        let err = tls
            .publish(&AwsIotFrame {
                remote_topic: "a/b".to_string(),
                payload: b"{}".to_vec(),
                user_properties: Vec::new(),
                content_type: None,
                correlation_data: None,
                qos: 1,
            })
            .await
            .expect_err("not connected must fail");
        assert!(matches!(err, ConnectorError::Connection(_)));
        let err = tls.connect().await.expect_err("closed port must fail");
        assert!(matches!(err, ConnectorError::Connection(_)));
        assert!(!tls.is_connected().await);
    }

    #[tokio::test]
    async fn test_sink_preserves_qos0_qos1_and_downgrades_qos2() {
        // AWS IoT Core speaks QoS 0 and 1 only: ingress AtMostOnce
        // stays 0, AtLeastOnce stays 1, ExactlyOnce downgrades to 1.
        let mut config = test_config();
        config.batch_size = Some(10);
        let (sink, transport) = test_sink(config);
        sink.send(
            &Topic::new("devices/a/telemetry").unwrap(),
            &Bytes::from_static(b"q0"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        sink.send(
            &Topic::new("devices/a/telemetry").unwrap(),
            &Bytes::from_static(b"q1"),
            QoS::AtLeastOnce,
        )
        .await
        .unwrap();
        sink.send(
            &Topic::new("devices/a/telemetry").unwrap(),
            &Bytes::from_static(b"q2"),
            QoS::ExactlyOnce,
        )
        .await
        .unwrap();
        sink.flush().await.unwrap();
        let captured = transport.captured();
        assert_eq!(captured.len(), 3);
        assert_eq!(captured[0].qos, 0);
        assert_eq!(captured[1].qos, 1);
        assert_eq!(captured[2].qos, 1);
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

    #[test]
    fn test_sigv4_sdk_key_matches_manual() {
        // The maintained `aws-sigv4` key derivation must agree with
        // the manual HMAC chain used by `sign_websocket_url`.
        let millis = 1_789_211_889_000;
        let manual = sigv4_signing_key_manual(
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "20260912",
            "us-east-1",
        );
        let via_sdk = sigv4_signing_key_via_sdk(
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            millis,
            "us-east-1",
        );
        assert_eq!(manual, via_sdk);
    }

    #[test]
    fn test_sigv4_sdk_signature_matches_manual() {
        // Same string-to-sign through both paths must give the same
        // hex signature.
        let string_to_sign = "AWS4-HMAC-SHA256\n20260912T111809Z\n20260912/us-east-1/iotdevicegateway/aws4_request\nabc123";
        let manual_key = sigv4_signing_key_manual(
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "20260912",
            "us-east-1",
        );
        let manual_sig = crate::hmac_sha256(&manual_key, string_to_sign.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let sdk_sig = sigv4_signature_via_sdk(&manual_key, string_to_sign);
        assert_eq!(manual_sig, sdk_sig);
        assert_eq!(sdk_sig.len(), 64);
    }

    #[test]
    fn test_mtls_constructs_offline() {
        // mTLS construction validates offline and never dials, so
        // management validation stays offline.
        let mtls = mtls_test_config("127.0.0.1:8883");
        assert!(TlsAwsIotTransport::new(&mtls).is_ok());

        // SigV4 has no transport in this build: rejected at
        // registration, never deferred.
        let sigv4 = test_config();
        assert!(matches!(
            TlsAwsIotTransport::new(&sigv4),
            Err(ConnectorError::Dispatch(_))
        ));
    }

    #[tokio::test]
    async fn test_tls_publish_without_connect_fails() {
        let config = mtls_test_config("127.0.0.1:8883");
        let transport = TlsAwsIotTransport::new(&config).expect("tls transport builds");
        assert!(!transport.is_connected().await);
        let err = transport
            .publish(&AwsIotFrame {
                remote_topic: "indra/qual/telemetry".to_string(),
                payload: b"{}".to_vec(),
                user_properties: Vec::new(),
                content_type: None,
                correlation_data: None,
                qos: 1,
            })
            .await
            .expect_err("publish before connect must fail");
        assert!(matches!(err, ConnectorError::Connection(_)));
        transport.disconnect().await;
    }

    #[test]
    fn test_tls_sink_kind_unchanged() {
        // Stored configuration keeps working: the TLS sink reports the
        // same kind string as before.
        let config = mtls_test_config("127.0.0.1:8883");
        let transport = Arc::new(TlsAwsIotTransport::new(&config).expect("tls builds"));
        let sink = AwsIotSink::new(config, transport).expect("sink builds");
        assert_eq!(sink.kind(), "aws_iot");
    }

    fn qual_env(name: &str) -> Option<String> {
        std::env::var(name).ok().filter(|v| !v.trim().is_empty())
    }

    fn qual_pem(var_pem: &str, var_file: &str) -> Option<String> {
        if let Some(inline) = qual_env(var_pem) {
            return Some(inline.replace("\\n", "\n"));
        }
        if let Some(path) = qual_env(var_file) {
            return std::fs::read_to_string(path).ok();
        }
        None
    }

    /// Qualification against a real AWS IoT Core endpoint (mTLS only).
    ///
    /// Run with e.g.:
    /// `AWS_IOT_ENDPOINT=abc123-ats.iot.us-east-1.amazonaws.com
    ///  AWS_IOT_REGION=us-east-1 AWS_IOT_CLIENT_ID=edge-gateway-qual
    ///  AWS_IOT_CA_FILE=/run/secrets/aws-ca.pem
    ///  AWS_IOT_CLIENT_CERT_FILE=/run/secrets/aws-cert.pem
    ///  AWS_IOT_CLIENT_KEY_FILE=/run/secrets/aws-key.pem
    ///  AWS_IOT_THING=qual-thing-1 \
    ///  cargo test -p broker-connectors --lib aws_iot::tests::test_qualify_tls_write_path -- --ignored --nocapture`
    ///
    /// Registers a thing out of band (console/CLI), attaches a policy
    /// allowing `iot:Connect`/`iot:Publish`/`iot:Subscribe` on the
    /// qual topics below, forwards 500 publishes through
    /// [`AwsIotSink`] on [`TlsAwsIotTransport`], asserts one
    /// shadow update plus 500 telemetry publishes, rotates the
    /// certificate (new transport from `AWS_IOT_CLIENT_CERT_FILE_2` /
    /// `AWS_IOT_CLIENT_KEY_FILE_2` when set, else the same material)
    /// and asserts reconnect plus one further publish. Cleans up by
    /// disconnecting; cloud-side test topics are ephemeral
    /// (`indra/qual/...`) with no retained state.
    #[tokio::test]
    #[ignore = "needs a real AWS IoT Core server (see AWS_IOT_* env)"]
    async fn test_qualify_tls_write_path() {
        let endpoint = qual_env("AWS_IOT_ENDPOINT").unwrap_or_default();
        if endpoint.is_empty() {
            eprintln!("AWS_IOT_ENDPOINT is empty; skipping qualification");
            return;
        }
        let region = qual_env("AWS_IOT_REGION").unwrap_or_else(|| "us-east-1".to_string());
        let client_id =
            qual_env("AWS_IOT_CLIENT_ID").unwrap_or_else(|| "edge-gateway-qual".to_string());
        let thing = qual_env("AWS_IOT_THING").unwrap_or_else(|| client_id.clone());

        let ca_pem = qual_pem("AWS_IOT_CA_PEM", "AWS_IOT_CA_FILE").unwrap_or_default();
        let client_cert = qual_pem("AWS_IOT_CLIENT_CERT_PEM", "AWS_IOT_CLIENT_CERT_FILE");
        let client_key = qual_pem("AWS_IOT_CLIENT_KEY_PEM", "AWS_IOT_CLIENT_KEY_FILE");
        let (Some(cert), Some(key)) = (client_cert, client_key) else {
            eprintln!(
                "no mTLS material; SigV4 WebSocket path is not built; skipping qualification"
            );
            return;
        };
        let auth = AwsIotAuth::Mtls {
            ca_cert_pem: ca_pem.clone(),
            client_cert_pem: cert,
            client_key_pem: key,
        };

        let topic_prefix =
            qual_env("AWS_IOT_TOPIC_PREFIX").unwrap_or_else(|| format!("indra/qual/{client_id}"));
        let config = AwsIotConfig {
            endpoint: endpoint.clone(),
            region: region.clone(),
            client_id: client_id.clone(),
            auth,
            topic_mappings: vec![BridgeTopicMapping {
                local_topic: "devices/+/telemetry".to_string(),
                remote_topic: format!("{topic_prefix}/telemetry"),
                direction: BridgeDirection::LocalToRemote,
            }],
            shadow_sync: Some(ShadowSyncConfig {
                thing_name_template: thing.clone(),
            }),
            batch_size: Some(250),
            buffer_capacity: None,
            linger_ms: Some(50),
            max_retries: Some(5),
            timeout_ms: Some(10_000),
            connect_timeout_ms: Some(10_000),
            handshake_timeout_ms: Some(10_000),
            ca_bundle_pem: if ca_pem.trim().is_empty() {
                None
            } else {
                Some(ca_pem)
            },
            alpn_protocols: None,
        };
        config.validate().expect("qual config validates");
        eprintln!("qual server: endpoint={endpoint} region={region} client_id={client_id}");

        let transport = Arc::new(TlsAwsIotTransport::new(&config).expect("qual transport"));
        transport.connect().await.expect("qual connect");
        assert!(transport.is_connected().await);
        let sink = Arc::new(AwsIotSink::new(config.clone(), transport.clone()).expect("qual sink"));

        // One shadow update first (reported state + client token).
        let shadow_topic = ShadowTopics::update(&thing);
        let reported = serde_json::json!({"qual": 1, "client": client_id});
        let doc = shadow_update_document(&reported, "qual-1");
        let doc_bytes = Bytes::from(serde_json::to_vec(&doc).expect("shadow json"));
        transport
            .publish(&AwsIotFrame {
                remote_topic: shadow_topic,
                payload: doc_bytes.to_vec(),
                user_properties: Vec::new(),
                content_type: Some("application/json".to_string()),
                correlation_data: None,
                qos: 1,
            })
            .await
            .expect("qual shadow publish");

        // 500 telemetry publishes through the rule-shaped sink path.
        let topic = Topic::new("devices/qual-1/telemetry").unwrap();
        for seq in 0..500 {
            let payload = Bytes::from(format!(
                "{{\"seq\":{seq},\"client\":\"{client_id}\",\"temp\":{temp}}}",
                temp = 20.0 + (seq as f64) * 0.01
            ));
            sink.send(&topic, &payload, QoS::AtLeastOnce)
                .await
                .expect("qual send");
        }
        sink.flush().await.expect("qual flush");
        assert_eq!(sink.sent_records(), 500);
        eprintln!("qual rows asserted: shadow=1 telemetry=500");

        // Rotate the certificate and prove reconnect: a fresh
        // transport (rotated files when provided, else the same
        // material) must connect and publish once more.
        transport.disconnect().await;
        assert!(!transport.is_connected().await);
        let rotated_cert = qual_pem("AWS_IOT_CLIENT_CERT_PEM_2", "AWS_IOT_CLIENT_CERT_FILE_2");
        let rotated_key = qual_pem("AWS_IOT_CLIENT_KEY_PEM_2", "AWS_IOT_CLIENT_KEY_FILE_2");
        let rotated_config = match (&config.auth, rotated_cert, rotated_key) {
            (
                AwsIotAuth::Mtls {
                    ca_cert_pem,
                    client_cert_pem,
                    client_key_pem,
                },
                Some(new_cert),
                Some(new_key),
            ) => {
                let _ = (client_cert_pem, client_key_pem);
                AwsIotConfig {
                    auth: AwsIotAuth::Mtls {
                        ca_cert_pem: ca_cert_pem.clone(),
                        client_cert_pem: new_cert,
                        client_key_pem: new_key,
                    },
                    ..config.clone()
                }
            }
            _ => config.clone(),
        };
        let rotated = Arc::new(TlsAwsIotTransport::new(&rotated_config).expect("rotated builds"));
        rotated.connect().await.expect("rotated connect");
        rotated
            .publish(&AwsIotFrame {
                remote_topic: format!("{topic_prefix}/telemetry"),
                payload: b"{\"seq\":501}".to_vec(),
                user_properties: Vec::new(),
                content_type: Some("application/json".to_string()),
                correlation_data: None,
                qos: 1,
            })
            .await
            .expect("rotated publish");
        rotated.disconnect().await;
        transport.disconnect().await;
        eprintln!("qual cleanup: disconnected TLS clients, no retained cloud state");
    }
}
