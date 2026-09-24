//! Cloud IoT device-protocol bridge (INDRA-195).
//!
//! A client for the Cloud IoT MQTT device protocol, which compatible
//! endpoints still speak: MQTT 3.1.1, the device's JWT (RS256 / ES256)
//! as the password, the username ignored, the full device path as the
//! client id, telemetry on `/devices/{id}/events` and state on
//! `/devices/{id}/state`. Google's own Cloud IoT service was retired
//! on 16 August 2023, so there is no Google server to qualify
//! against; qualification runs against a compatible witness endpoint
//! (see the qualification test below). JWT minting reuses
//! `jsonwebtoken` (shared with the Pub/Sub token cache); ECDSA P-256
//! signs through the same crate.
//!
//! Production traffic runs on the hand-written [`TlsGcpIotTransport`]
//! below over `tokio-rustls` with `rustls` TLS: the device JWT rides
//! as the MQTT password (`username = "unused"`), the client id is the
//! full `projects/.../devices/...` resource path, and telemetry
//! publishes at QoS 0. TLS is the default; a `mqtt://` endpoint
//! selects plaintext explicitly (the witness certificate cannot name
//! its address) and logs a warning when it does. There is no
//! `rumqttc` dependency in this build: that crate pins
//! `rustls-webpki 0.102.8` (RUSTSEC-2026-0049) with no patched
//! release, so the sink speaks CONNECT/CONNACK + PUBLISH through the
//! tree's own `mqtt_bridge` codec over the already-pinned `rustls
//! 0.23` stack. The legacy [`TcpGcpIotTransport`] (hand-written
//! PUBLISH framing over a plain socket) is retained for offline unit
//! tests only.
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
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::cloud_tls;
use super::{now_millis, BackoffState, BatchQueue, ConnectorError, Result, Sink};

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

/// Cloud IoT device-protocol bridge configuration. The buffer has a
/// finite default bound (see [`DEFAULT_BUFFER_ROWS`]); JWT lifetimes
/// clamp to 24h.
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
    /// Request timeout in ms (default 5000).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Extra CA bundle PEM for server verification, in addition to
    /// the OS system trust store. Needed for loopback TLS tests and
    /// private-CA endpoints; `None` means system roots only.
    /// Optional so stored configuration keeps parsing.
    #[serde(default)]
    pub ca_bundle_pem: Option<String>,
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

/// Default buffer bound: 10_000 rows. A disconnected bridge must not
/// grow its queue without bound, so the default is finite: 10_000
/// small telemetry rows (a few MB) absorb a minutes-long outage at
/// typical device rates without OOMing the kernel. An operator may
/// still set a larger `buffer_capacity` explicitly.
const DEFAULT_BUFFER_ROWS: usize = 10_000;

impl GcpIotConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.unwrap_or(5000).max(1))
    }

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
        if let Some(bundle) = &self.ca_bundle_pem {
            if !bundle.trim().is_empty() && !bundle.contains("BEGIN CERTIFICATE") {
                return Err(ConnectorError::Dispatch(
                    "gcp-iot ca_bundle_pem is not a PEM document".to_string(),
                ));
            }
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
        self.linger_ms
            .map(Duration::from_millis)
            .unwrap_or(Duration::MAX)
    }

    pub fn effective_buffer(&self) -> usize {
        self.buffer_capacity.unwrap_or(DEFAULT_BUFFER_ROWS).max(1)
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
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(algorithm.jsonwebtoken()),
        &claims,
        &key,
    )
    .map_err(|e| ConnectorError::Dispatch(format!("gcp-iot JWT signing failed: {e}")))
}

/// Proactive JWT cache: refreshes 60s before expiry.
pub struct GcpIotTokenCache {
    private_key_pem: String,
    algorithm: GcpIotAlgorithm,
    project_id: String,
    lifetime_secs: u64,
    cached: parking_lot::Mutex<Option<(String, u64)>>,
    refreshes: AtomicU64,
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
            refreshes: AtomicU64::new(0),
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
        self.refreshes.fetch_add(1, Ordering::SeqCst);
        Ok(token)
    }

    /// JWT mints so far. The qualification test asserts this grows
    /// across token lifetimes, proving renewal actually happened.
    pub fn refreshes(&self) -> u64 {
        self.refreshes.load(Ordering::SeqCst)
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
    let value: serde_json::Value = serde_json::from_slice(payload)
        .map_err(|_| ConnectorError::Dispatch("gcp-iot state must be JSON".to_string()))?;
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
    GrpcStatus {
        code: String,
    },
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
///
/// Retained for offline unit tests only; production wiring uses
/// [`TlsGcpIotTransport`] over `tokio-rustls`.
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
        self.connect().await?;
        use tokio::io::AsyncWriteExt;
        let bytes = super::mqtt_bridge::encode_publish(topic, 0, false, 0, body, false)?;
        let mut guard = self.stream.lock().await;
        let stream = guard
            .as_mut()
            .ok_or_else(|| ConnectorError::Connection("gcp-iot not connected".to_string()))?;
        stream
            .write_all(&bytes)
            .await
            .map_err(|e| ConnectorError::Connection(format!("gcp-iot publish failed: {e}")))?;
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
        let stream = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect(&addr),
        )
        .await
        .map_err(|_| ConnectorError::Connection(format!("gcp-iot connect timeout: {addr}")))?
        .map_err(|e| ConnectorError::Connection(format!("gcp-iot connect failed: {e}")))?;
        *self.stream.lock().await = Some(stream);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// TLS transport (tree codec + tokio-rustls, no rumqttc).
// ---------------------------------------------------------------------------

/// MQTT keepalive advertised in CONNECT (seconds). 60 s follows the
/// device-bridge guidance for telemetry devices: telemetry is QoS 0
/// fire-and-forget, so pings stay rare, while a half-open connection
/// still surfaces as a publish error within a minute and the next
/// publish redials.
const GCP_KEEPALIVE_SECS: u16 = 60;

/// TCP connect budget. 5 s is the vendor SDK default for the device
/// MQTT bridge: an endpoint that cannot accept a socket in 5 s is
/// treated as down and the publish retries with backoff.
const GCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// TLS handshake budget. 5 s matches the same vendor default; a
/// stalled handshake fails closed so a wedged middlebox never holds
/// a publish slot open.
const GCP_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Split the endpoint into `(use_tls, host, port)`. A `mqtt://`
/// prefix selects plaintext explicitly: the qualification witness
/// certificate cannot name its address, so the witness is reached
/// over plain TCP and TLS is proven offline by the loopback TLS
/// test. Anything else (bare `host:port`, `mqtts://`, `ssl://`)
/// defaults to TLS. Plaintext logs a warning at construction; it is
/// never chosen silently.
fn parse_gcp_endpoint(endpoint: &str) -> Result<(bool, String, u16)> {
    let trimmed = endpoint.trim();
    if let Some(rest) = trimmed.strip_prefix("mqtt://") {
        let (host, port) = cloud_tls::parse_host_port(rest, 1883)?;
        tracing::warn!(
            endpoint = %trimmed,
            "gcp-iot plaintext mqtt:// selected; JWT password crosses the network unencrypted"
        );
        Ok((false, host, port))
    } else {
        let rest = trimmed
            .strip_prefix("mqtts://")
            .or_else(|| trimmed.strip_prefix("ssl://"))
            .unwrap_or(trimmed);
        let (host, port) = cloud_tls::parse_host_port(rest, 8883)?;
        Ok((true, host, port))
    }
}

/// One established device session: TLS by default, plaintext only
/// when the endpoint said `mqtt://` explicitly.
enum GcpIotStream {
    Tls(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
    Plain(tokio::net::TcpStream),
}

impl GcpIotStream {
    async fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Tls(stream) => stream.write_all(bytes).await,
            Self::Plain(stream) => stream.write_all(bytes).await,
        }
    }

    async fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        match self {
            Self::Tls(stream) => stream.read_exact(buf).await.map(|_| ()),
            Self::Plain(stream) => stream.read_exact(buf).await.map(|_| ()),
        }
    }
}

/// Write CONNECT and expect a `0x00` CONNACK over a plaintext
/// [`GcpIotStream`] (mirrors [`cloud_tls::mqtt_connect_over_tls`]
/// for the witness path, where there is no TLS session to run it
/// over).
async fn mqtt_connect_over_plain(
    stream: &mut GcpIotStream,
    connect: &[u8],
    context: &str,
    io_timeout: Duration,
) -> Result<()> {
    tokio::time::timeout(io_timeout, stream.write_all(connect))
        .await
        .map_err(|_| ConnectorError::Connection(format!("{context} CONNECT write timeout")))?
        .map_err(|e| ConnectorError::Connection(format!("{context} CONNECT write failed: {e}")))?;
    let mut connack = [0u8; 4];
    tokio::time::timeout(io_timeout, stream.read_exact(&mut connack))
        .await
        .map_err(|_| ConnectorError::Connection(format!("{context} CONNACK read timeout")))?
        .map_err(|e| ConnectorError::Connection(format!("{context} CONNACK read failed: {e}")))?;
    if connack[0] != 0x20 || connack[1] != 0x02 {
        return Err(ConnectorError::Connection(format!(
            "{context} malformed CONNACK"
        )));
    }
    if connack[3] != 0x00 {
        return Err(ConnectorError::Dispatch(format!(
            "{context} connection refused: 0x{:02x}",
            connack[3]
        )));
    }
    Ok(())
}

/// Device-protocol transport: MQTT to the Cloud IoT bridge
/// (TLS to port 8883 by default). The device JWT rides as the MQTT
/// password with username `"unused"`; the client id is the full
/// device resource path. Server trust defaults to the OS system
/// store plus the optional configured CA bundle. A `mqtt://`
/// endpoint selects the plaintext witness path explicitly (with a
/// warning); everything else runs over TLS.
///
/// Bound: at most one session; no background queue.
pub struct TlsGcpIotTransport {
    host: String,
    port: u16,
    use_tls: bool,
    client_id: String,
    tls: Arc<rustls::ClientConfig>,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    io_timeout: Duration,
    stream: tokio::sync::Mutex<Option<GcpIotStream>>,
    password: tokio::sync::Mutex<Option<String>>,
    connects: AtomicU64,
}

impl std::fmt::Debug for TlsGcpIotTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsGcpIotTransport")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("use_tls", &self.use_tls)
            .field("client_id", &self.client_id)
            .field("connect_timeout", &self.connect_timeout)
            .field("handshake_timeout", &self.handshake_timeout)
            .field("io_timeout", &self.io_timeout)
            .field("connects", &self.connects.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl TlsGcpIotTransport {
    pub fn new(config: &GcpIotConfig) -> Result<Self> {
        config.validate()?;
        let (use_tls, host, port) = parse_gcp_endpoint(&config.endpoint)?;
        let roots = cloud_tls::root_store_with(config.ca_bundle_pem.as_deref())?;
        let tls = cloud_tls::client_config(roots, None, &[])?;
        Ok(Self {
            host,
            port,
            use_tls,
            client_id: config.client_id(),
            tls,
            connect_timeout: GCP_CONNECT_TIMEOUT,
            handshake_timeout: GCP_HANDSHAKE_TIMEOUT,
            io_timeout: config.timeout(),
            stream: tokio::sync::Mutex::new(None),
            password: tokio::sync::Mutex::new(None),
            connects: AtomicU64::new(0),
        })
    }

    /// True when the endpoint selected TLS (the default); false only
    /// for an explicit `mqtt://` witness endpoint.
    pub fn uses_tls(&self) -> bool {
        self.use_tls
    }

    pub async fn is_connected(&self) -> bool {
        self.stream.lock().await.is_some()
    }

    /// Successful (re)connects so far (a renewed token redials
    /// instead of reusing a stale session).
    pub fn connects(&self) -> u64 {
        self.connects.load(Ordering::SeqCst)
    }

    /// Drop the TLS session. The next publish dials again (used to
    /// prove reconnect after a token renewal or a half-open drop).
    pub async fn disconnect(&self) {
        *self.stream.lock().await = None;
        *self.password.lock().await = None;
    }

    async fn ensure_connected(&self, password: &str) -> Result<()> {
        if password.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "gcp-iot JWT password missing; anonymous CONNECT refused".to_string(),
            ));
        }
        {
            let stream = self.stream.lock().await;
            let current = self.password.lock().await;
            if stream.is_some() && current.as_deref() == Some(password) {
                return Ok(());
            }
        }
        // Stale session or renewed token: drop before redialling so a
        // half-open socket never serves the next publish.
        *self.stream.lock().await = None;
        *self.password.lock().await = None;
        let connect = cloud_tls::encode_mqtt_connect(
            &self.client_id,
            true,
            GCP_KEEPALIVE_SECS,
            Some("unused"),
            Some(password),
        )?;
        if self.use_tls {
            let mut stream = cloud_tls::tls_dial(
                &self.host,
                self.port,
                self.tls.clone(),
                self.connect_timeout,
                self.handshake_timeout,
                "gcp-iot",
            )
            .await?;
            cloud_tls::mqtt_connect_over_tls(&mut stream, &connect, "gcp-iot", self.io_timeout)
                .await?;
            *self.stream.lock().await = Some(GcpIotStream::Tls(Box::new(stream)));
        } else {
            let addr = format!("{}:{}", self.host, self.port);
            let tcp =
                tokio::time::timeout(self.connect_timeout, tokio::net::TcpStream::connect(&addr))
                    .await
                    .map_err(|_| {
                        ConnectorError::Connection(format!("gcp-iot connect timeout: {addr}"))
                    })?
                    .map_err(|e| {
                        ConnectorError::Connection(format!("gcp-iot connect failed: {e}"))
                    })?;
            tcp.set_nodelay(true).map_err(|e| {
                ConnectorError::Connection(format!("gcp-iot set_nodelay failed: {e}"))
            })?;
            let mut plain = GcpIotStream::Plain(tcp);
            mqtt_connect_over_plain(&mut plain, &connect, "gcp-iot", self.io_timeout).await?;
            *self.stream.lock().await = Some(plain);
        }
        *self.password.lock().await = Some(password.to_string());
        self.connects.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[async_trait]
impl GcpIotTransport for TlsGcpIotTransport {
    async fn publish(&self, topic: &str, body: &[u8], password_token: &str) -> Result<()> {
        if topic.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "gcp-iot topic must not be empty".to_string(),
            ));
        }
        self.ensure_connected(password_token).await?;
        let bytes = super::mqtt_bridge::encode_publish(topic, 0, false, 0, body, false)?;
        let mut guard = self.stream.lock().await;
        let stream = guard
            .as_mut()
            .ok_or_else(|| ConnectorError::Connection("gcp-iot not connected".to_string()))?;
        let outcome = tokio::time::timeout(self.io_timeout, stream.write_all(&bytes))
            .await
            .map_err(|_| ConnectorError::Connection("gcp-iot publish timeout".to_string()))?
            .map_err(|e| ConnectorError::Connection(format!("gcp-iot publish failed: {e}")));
        match outcome {
            Ok(()) => Ok(()),
            Err(e) => {
                // The stream is no longer trustworthy; the next
                // publish redials instead of reusing a dead session.
                *guard = None;
                *self.password.lock().await = None;
                Err(e)
            }
        }
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

    /// Device-JWT mints so far, via the token cache. The
    /// qualification test asserts this grows across token lifetimes,
    /// proving renewal actually happened.
    pub fn token_refreshes(&self) -> u64 {
        self.token_cache.refreshes()
    }

    fn backoff_delay(&self, attempt: usize) -> Duration {
        let grown = 100u64
            .saturating_mul(2u64.saturating_pow(attempt.min(10) as u32))
            .min(2_000);
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
                        return self.restore_err(rows, oldest, ConnectorError::Connection(message));
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
    use crate::test_rsa_keys::{PRIVATE_PEM as RSA_PEM, PUBLIC_PEM as RSA_PUB};
    use crate::Sink;
    use tokio::io::AsyncReadExt;

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
            timeout_ms: None,
            ca_bundle_pem: None,
        }
    }

    fn test_sink(config: GcpIotConfig) -> (Arc<GcpIotSink>, Arc<MockGcpIotTransport>) {
        let transport = Arc::new(MockGcpIotTransport::new());
        let sink = Arc::new(GcpIotSink::new(config, transport.clone()).unwrap());
        (sink, transport)
    }

    fn decode_claims(
        token: &str,
        public_pem: &str,
        algorithm: jsonwebtoken::Algorithm,
    ) -> serde_json::Value {
        let key = jsonwebtoken::DecodingKey::from_rsa_pem(public_pem.as_bytes())
            .or_else(|_| jsonwebtoken::DecodingKey::from_ec_pem(public_pem.as_bytes()))
            .expect("public key parses");
        let mut validation = jsonwebtoken::Validation::new(algorithm);
        validation.validate_exp = false;
        validation.set_audience(&["my-iot-project"]);
        let data =
            jsonwebtoken::decode::<serde_json::Value>(token, &key, &validation).expect("verifies");
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
        let token = build_jwt(
            RSA_PEM,
            GcpIotAlgorithm::Rs256,
            "my-iot-project",
            now,
            3_600,
        )
        .unwrap();
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
        let token = build_jwt(
            EC_PRIVATE_PEM,
            GcpIotAlgorithm::Es256,
            "my-iot-project",
            now,
            3_600,
        )
        .unwrap();
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
        assert_eq!(
            route_downlink("edge-7", "/devices/edge-7/config"),
            DownlinkRoute::Config
        );
        assert_eq!(
            route_downlink("edge-7", "/devices/edge-7/commands/reboot"),
            DownlinkRoute::Commands("reboot".to_string())
        );
        assert_eq!(
            route_downlink("edge-7", "/devices/edge-7/commands/"),
            DownlinkRoute::Neither
        );
        assert_eq!(
            route_downlink("edge-7", "/devices/other/config"),
            DownlinkRoute::Neither
        );
    }

    #[test]
    fn test_refresh_scheduling_math() {
        // 60s skew, never in the past.
        assert_eq!(next_refresh_ms(1_000, 0), 940_000);
        assert_eq!(next_refresh_ms(100, 200_000), 200_000);
        // Cache honors the skew then renews.
        let cache = GcpIotTokenCache::new(
            RSA_PEM.to_string(),
            GcpIotAlgorithm::Rs256,
            "p".to_string(),
            3_600,
        );
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
            MockGcpIotOutcome::GrpcStatus {
                code: "UNAUTHENTICATED".to_string(),
            },
            MockGcpIotOutcome::Ok,
        ]);
        // Pin the cache so renewal visibly changes the token.
        *sink.token_cache.cached.lock() = Some(("old-token".to_string(), u64::MAX));
        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from("{}"),
            QoS::AtMostOnce,
        )
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
        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from("{}"),
            QoS::AtMostOnce,
        )
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
        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from("{}"),
            QoS::AtMostOnce,
        )
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

    #[test]
    fn test_tls_transport_builds_offline() {
        // Production wiring builds offline: management validation must
        // never dial. Construction parses the endpoint, resolves the
        // full device client id and loads the system trust roots.
        let transport = TlsGcpIotTransport::new(&test_config()).expect("builds offline");
        assert_eq!(transport.client_id, test_config().client_id());
        assert_eq!(transport.connects(), 0);

        let mut bad = test_config();
        bad.endpoint = "127.0.0.1:0".to_string();
        // Port 0 fails closed in cloud_tls::parse_host_port (must be
        // 1..=65535), so offline construction rejects it.
        assert!(TlsGcpIotTransport::new(&bad).is_err());
        bad.endpoint.clear();
        assert!(TlsGcpIotTransport::new(&bad).is_err());
        bad = test_config();
        bad.private_key_pem = "not-a-key".to_string();
        assert!(TlsGcpIotTransport::new(&bad).is_err());
        bad = test_config();
        bad.ca_bundle_pem = Some("not-a-pem".to_string());
        assert!(TlsGcpIotTransport::new(&bad).is_err());
    }

    #[tokio::test]
    async fn test_tls_transport_refuses_empty_password_offline() {
        // Fail closed before any dial: an empty JWT never reaches the
        // network as an anonymous CONNECT.
        let transport = TlsGcpIotTransport::new(&test_config()).expect("builds offline");
        let err = transport
            .publish("/devices/edge-7/events", b"{}", "")
            .await
            .expect_err("empty password must fail");
        assert!(matches!(err, ConnectorError::Dispatch(_)));
        assert_eq!(transport.connects(), 0);
        assert!(!transport.is_connected().await);
    }

    const TEST_CA_PEM: &str = include_str!("../testdata/ca-cert.pem");
    const TEST_SERVER_CERT_PEM: &str = include_str!("../testdata/server-cert.pem");
    const TEST_SERVER_KEY_PEM: &str = include_str!("../testdata/server-key.pem");

    /// Test-only device key pair for the JWT-verifying loopback fakes
    /// (committed fixtures; shipped code never loads them).
    const FIXTURE_PRIVATE_PEM: &str =
        include_str!("../tests/fixtures/gcp_iot_device_rs256_private.pem");
    const FIXTURE_PUBLIC_PEM: &str =
        include_str!("../tests/fixtures/gcp_iot_device_rs256_public.pem");

    /// Mint a device JWT from the fixture private key, valid at the
    /// current time.
    fn fixture_token(lifetime_secs: u64) -> String {
        let now_secs = now_millis().max(0) as u64 / 1_000;
        build_jwt(
            FIXTURE_PRIVATE_PEM,
            GcpIotAlgorithm::Rs256,
            "my-iot-project",
            now_secs,
            lifetime_secs,
        )
        .expect("fixture key mints")
    }

    /// Verify a received MQTT password against the fixture public key,
    /// the way the qualification witness verifies device JWTs. A fake
    /// that accepted any placeholder would prove nothing about
    /// authentication.
    fn verify_fixture_token(password: &str) -> serde_json::Value {
        let key = jsonwebtoken::DecodingKey::from_rsa_pem(FIXTURE_PUBLIC_PEM.as_bytes())
            .expect("fixture public key parses");
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_audience(&["my-iot-project"]);
        jsonwebtoken::decode::<serde_json::Value>(password, &key, &validation)
            .expect("loopback fake verifies the device JWT")
            .claims
    }

    fn fixture_test_config(endpoint: &str) -> GcpIotConfig {
        GcpIotConfig {
            private_key_pem: FIXTURE_PRIVATE_PEM.to_string(),
            endpoint: endpoint.to_string(),
            ca_bundle_pem: Some(TEST_CA_PEM.to_string()),
            ..test_config()
        }
    }

    fn tls_test_config(endpoint: &str) -> GcpIotConfig {
        GcpIotConfig {
            endpoint: endpoint.to_string(),
            ca_bundle_pem: Some(TEST_CA_PEM.to_string()),
            ..test_config()
        }
    }

    #[tokio::test]
    async fn test_tls_handshake_connect_and_publish_qos0() {
        use tokio::net::TcpListener;

        let server_config = crate::cloud_tls::test_certs::server_config(
            TEST_SERVER_CERT_PEM,
            TEST_SERVER_KEY_PEM,
            None,
        )
        .expect("test server config");
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let expected_client_id = test_config().client_id();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept");
            let mut tls = acceptor.accept(tcp).await.expect("tls accept");
            let (client_id, username, password) = crate::cloud_tls::read_client_connect(&mut tls)
                .await
                .expect("read CONNECT");
            assert_eq!(client_id, expected_client_id);
            assert_eq!(username.as_deref(), Some("unused"));
            let password = password.expect("JWT password");
            // The fake verifies the JWT against the fixture public
            // key; a placeholder password fails here.
            let claims = verify_fixture_token(&password);
            assert_eq!(claims["aud"], "my-iot-project");
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
            assert_eq!(decoded.topic, "/devices/edge-7/events");
            assert_eq!(decoded.qos, 0);
            assert_eq!(decoded.payload, b"{\"temp\":21.5}");
        });

        let config = fixture_test_config(&format!("127.0.0.1:{port}"));
        let transport = Arc::new(TlsGcpIotTransport::new(&config).unwrap());
        let password = fixture_token(3_600);
        transport.ensure_connected(&password).await.unwrap();
        assert!(transport.is_connected().await);
        assert_eq!(transport.connects(), 1);
        transport
            .publish("/devices/edge-7/events", b"{\"temp\":21.5}", &password)
            .await
            .unwrap();
        // Same password reuses the session; no redial.
        assert_eq!(transport.connects(), 1);
        tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .expect("server done")
            .expect("server task");
        transport.disconnect().await;
        assert!(!transport.is_connected().await);
    }

    #[tokio::test]
    async fn test_tls_token_renewal_reconnects() {
        use tokio::net::TcpListener;

        let server_config = crate::cloud_tls::test_certs::server_config(
            TEST_SERVER_CERT_PEM,
            TEST_SERVER_KEY_PEM,
            None,
        )
        .expect("test server config");
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let seen = Arc::new(parking_lot::Mutex::new(Vec::<String>::new()));
        let seen_server = seen.clone();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (tcp, _) = listener.accept().await.expect("accept");
                let mut tls = acceptor.accept(tcp).await.expect("tls accept");
                let (_, _, password) = crate::cloud_tls::read_client_connect(&mut tls)
                    .await
                    .expect("read CONNECT");
                let password = password.unwrap_or_default();
                // Each session's JWT must verify against the fixture
                // public key; renewed tokens are real JWTs, not
                // placeholders.
                verify_fixture_token(&password);
                seen_server.lock().push(password);
                tls.write_all(&[0x20, 0x02, 0x00, 0x00])
                    .await
                    .expect("CONNACK");
                // One QoS 0 publish per session, then the client goes
                // away (renewal drops the first session).
                let mut head = [0u8; 1];
                if tls.read_exact(&mut head).await.is_err() {
                    break;
                }
                let mut len_buf = Vec::new();
                loop {
                    let mut byte = [0u8; 1];
                    if tls.read_exact(&mut byte).await.is_err() {
                        break;
                    }
                    len_buf.push(byte[0]);
                    if byte[0] & 0x80 == 0 {
                        break;
                    }
                }
                let (remaining, _) =
                    crate::mqtt_bridge::decode_remaining_length(&len_buf).expect("remaining");
                let mut rest = vec![0u8; remaining];
                let _ = tls.read_exact(&mut rest).await;
            }
        });

        let config = fixture_test_config(&format!("127.0.0.1:{port}"));
        let transport = Arc::new(TlsGcpIotTransport::new(&config).unwrap());
        // Two distinct real JWTs (different `iat`), both minted from
        // the fixture key so both verify.
        let now_secs = now_millis().max(0) as u64 / 1_000;
        let token_one = build_jwt(
            FIXTURE_PRIVATE_PEM,
            GcpIotAlgorithm::Rs256,
            "my-iot-project",
            now_secs,
            3_600,
        )
        .expect("token one mints");
        let token_two = build_jwt(
            FIXTURE_PRIVATE_PEM,
            GcpIotAlgorithm::Rs256,
            "my-iot-project",
            now_secs.saturating_add(1_800),
            3_600,
        )
        .expect("token two mints");
        assert_ne!(token_one, token_two);
        transport
            .publish("/devices/edge-7/events", b"{}", &token_one)
            .await
            .unwrap();
        assert_eq!(transport.connects(), 1);
        // A renewed JWT forces a fresh TLS session, never a reuse of
        // the stale one.
        transport
            .publish("/devices/edge-7/events", b"{}", &token_two)
            .await
            .unwrap();
        assert_eq!(transport.connects(), 2);
        tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .expect("server done")
            .expect("server task");
        let seen_tokens = seen.lock().clone();
        assert_eq!(seen_tokens, vec![token_one, token_two]);
        transport.disconnect().await;
    }

    #[tokio::test]
    async fn test_tls_publish_without_connect_fails_closed() {
        // Publish with a valid token but no server behind the port
        // fails as a retryable Connection error and leaves the
        // transport disconnected, so the sink backoff loop redials.
        let mut config = tls_test_config("127.0.0.1:1");
        config.timeout_ms = Some(300);
        let transport = TlsGcpIotTransport::new(&config).expect("builds offline");
        let err = transport
            .publish("/devices/edge-7/events", b"{}", "token")
            .await
            .expect_err("closed port must fail");
        assert!(matches!(err, ConnectorError::Connection(_)));
        assert!(!transport.is_connected().await);
        assert_eq!(transport.connects(), 0);
    }

    #[test]
    fn test_tls_sink_kind_unchanged() {
        // Stored configuration keeps working: the TLS sink reports the
        // same kind string as before.
        let transport = Arc::new(MockGcpIotTransport::new());
        let sink = GcpIotSink::new(test_config(), transport).expect("sink builds");
        assert_eq!(sink.kind(), "gcp_iot");
    }

    fn qual_env(name: &str) -> Option<String> {
        std::env::var(name).ok().filter(|v| !v.trim().is_empty())
    }

    /// Qualification against the pipeline's witness broker (no `rumqttc`).
    ///
    /// The hosted device service this bridge targets is retired, so
    /// there is no vendor server to qualify against. The witness is an
    /// independent MQTT broker, started by the pipeline (see the
    /// QUAL-* lines in the task spec), that verifies each device JWT
    /// against the device's public key and refuses expired, forged and
    /// anonymous connections. "Register device" means the witness is
    /// configured with the device's public key. The witness is reached
    /// over plain TCP (`mqtt://`, the only scheme the sink accepts
    /// without TLS); TLS itself is proven offline by
    /// `test_tls_handshake_connect_and_publish_qos0`.
    ///
    /// Run with e.g.:
    /// `GCP_IOT_MQTT_URL=mqtt://127.0.0.1:1883 \
    ///  GCP_IOT_PRIVATE_KEY_FILE=crates/broker-connectors/tests/fixtures/gcp_iot_device_rs256_private.pem \
    ///  cargo test -p broker-connectors --lib gcp_iot::tests::test_qualify_tls_write_path -- --ignored --nocapture`
    ///
    /// 500 telemetry rows drive through the broker's rule path (a rule
    /// registered with the connector manager, published through it the
    /// way the rule engine's `ForwardConnector` action does; never
    /// `sink.send` directly), paced so the run crosses at least two
    /// token lifetimes. A witness subscriber holding its own valid JWT
    /// must receive exactly 500, and the sink must have refreshed its
    /// token at least twice. No tolerance: the protocol is at-least-once
    /// per row, so every row must arrive.
    #[tokio::test]
    #[ignore = "needs the qualification witness (see GCP_IOT_* env)"]
    async fn test_qualify_tls_write_path() {
        use crate::ConnectorManager;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        fn qual_now_secs() -> u64 {
            now_millis().max(0) as u64 / 1_000
        }

        /// Dial the witness over plain TCP (the witness certificate
        /// cannot name its address, so there is no TLS to it).
        async fn qual_dial(host: &str, port: u16) -> TcpStream {
            let addr = format!("{host}:{port}");
            tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(&addr))
                .await
                .unwrap_or_else(|_| panic!("qual witness dial timeout: {addr}"))
                .unwrap_or_else(|e| panic!("qual witness dial failed: {addr}: {e}"))
        }

        /// Read one CONNACK, returning its return code. A closed
        /// connection (no CONNACK at all) returns `None`: the witness
        /// refused the CONNECT by hanging up.
        async fn qual_connack_rc(stream: &mut TcpStream) -> Option<u8> {
            let mut connack = [0u8; 4];
            match tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut connack))
                .await
            {
                Err(_) => None,
                Ok(Err(_)) => None,
                Ok(Ok(_)) => {
                    assert_eq!(connack[0], 0x20, "witness must answer CONNECT with CONNACK");
                    assert_eq!(connack[1], 0x02, "witness CONNACK must be 4 bytes");
                    Some(connack[3])
                }
            }
        }

        let Some(mqtt_url) = qual_env("GCP_IOT_MQTT_URL") else {
            panic!(
                "GCP_IOT_MQTT_URL must point at the qualification witness for qualification; \
                 failing closed instead of passing vacuously \
                 (e.g. GCP_IOT_MQTT_URL=mqtt://127.0.0.1:1883)"
            )
        };
        assert!(
            mqtt_url.trim().starts_with("mqtt://"),
            "qual witness is reached over plain TCP: GCP_IOT_MQTT_URL must start with mqtt://"
        );
        let private_key_pem = match qual_env("GCP_IOT_PRIVATE_KEY_FILE") {
            Some(path) => std::fs::read_to_string(&path).unwrap_or_else(|_| {
                panic!("GCP_IOT_PRIVATE_KEY_FILE {path:?} must be readable for qualification")
            }),
            None => panic!(
                "GCP_IOT_PRIVATE_KEY_FILE must hold the device private key for qualification; \
                 failing closed"
            ),
        };
        let project = qual_env("GCP_IOT_PROJECT").unwrap_or_else(|| "qual-project".to_string());
        let region = qual_env("GCP_IOT_REGION").unwrap_or_else(|| "us-central1".to_string());
        let registry = qual_env("GCP_IOT_REGISTRY").unwrap_or_else(|| "qual-registry".to_string());
        let device = qual_env("GCP_IOT_DEVICE").unwrap_or_else(|| "qual-device".to_string());
        // MQTT has no version query, so the log records the witness
        // image (from the QUAL-* pipeline setup) instead of a version.
        // That image is all the report may claim about the server. The
        // repository must not name the image, so the default is neutral;
        // the pipeline may export QUAL_WITNESS_IMAGE for the log.
        let witness_image = qual_env("QUAL_WITNESS_IMAGE")
            .unwrap_or_else(|| "witness (see QUAL-IMAGE in the task spec)".to_string());
        // Token lifetime 20 s in the test config (the sink clamps to
        // its 60 s floor, so the run is paced to cross at least two
        // effective lifetimes below).
        let config = GcpIotConfig {
            project_id: project.clone(),
            cloud_region: region.clone(),
            registry_id: registry.clone(),
            device_id: device.clone(),
            private_key_pem: private_key_pem.clone(),
            algorithm: GcpIotAlgorithm::Rs256,
            token_lifetime_secs: 20,
            endpoint: mqtt_url.clone(),
            batch_size: Some(1),
            buffer_capacity: None,
            linger_ms: Some(50),
            max_retries: Some(10),
            timeout_ms: Some(15_000),
            ca_bundle_pem: None,
        };
        config.validate().expect("qual config validates");
        eprintln!("qual server: witness={witness_image} url={mqtt_url} device={device}");

        let transport = Arc::new(TlsGcpIotTransport::new(&config).expect("qual transport"));
        assert!(
            !transport.uses_tls(),
            "qual witness runs over plaintext mqtt://"
        );
        let sink = Arc::new(GcpIotSink::new(config.clone(), transport.clone()).expect("qual sink"));
        // The broker's rule path: the rule engine's `ForwardConnector`
        // action delivers through the shared connector manager, so the
        // qualification registers the rule's connector there and sends
        // through it, never `sink.send` directly.
        let manager = ConnectorManager::new();
        manager.register("qual-gcp-iot", sink.clone());

        let telemetry_topic = format!("/devices/{device}/events");
        let witness_plain = mqtt_url
            .trim()
            .strip_prefix("mqtt://")
            .expect("mqtt:// prefix checked above");
        let (witness_host, witness_port) =
            cloud_tls::parse_host_port(witness_plain, 1883).expect("qual endpoint parses");

        // First, prove the witness really verifies: a JWT signed by a
        // different key must be refused. The key difference is shown
        // deterministically (same inputs, different signatures), then
        // over the wire (refused CONNACK or a hung-up connection).
        let now = qual_now_secs();
        let forged = build_jwt(RSA_PEM, GcpIotAlgorithm::Rs256, &project, now, 60)
            .expect("forged JWT mints");
        let valid_probe = build_jwt(&private_key_pem, GcpIotAlgorithm::Rs256, &project, now, 60)
            .expect("device JWT mints");
        assert_ne!(
            forged, valid_probe,
            "the forged JWT must come from a different key than the device key"
        );
        {
            let mut refused = qual_dial(&witness_host, witness_port).await;
            let forged_connect = cloud_tls::encode_mqtt_connect(
                "qual-gcp-iot-forged",
                true,
                30,
                Some("unused"),
                Some(&forged),
            )
            .expect("forged CONNECT");
            tokio::time::timeout(Duration::from_secs(10), refused.write_all(&forged_connect))
                .await
                .expect("forged CONNECT write")
                .expect("forged CONNECT sent");
            match qual_connack_rc(&mut refused).await {
                None => eprintln!("qual witness refused the forged JWT by hanging up"),
                Some(0x00) => {
                    panic!("qual witness accepted a JWT signed by a different key; it verifies nothing")
                }
                Some(rc) => {
                    eprintln!("qual witness refused the forged JWT with CONNACK 0x{rc:02x}")
                }
            }
        }

        // Witness subscriber with its own valid JWT (long-lived so the
        // witness never expires it mid-run), subscribed to the device
        // telemetry topic. It never connects anonymously. Keepalive is
        // 600 s because the witness only receives: the broker drops an
        // idle client after 1.5x keepalive, and the paced 500-row run
        // lasts ~125 s plus the 120 s drain wait, so 60 s would kick the
        // witness at ~90 s (363 rows) and lose the tail.
        let witness_jwt = build_jwt(
            &private_key_pem,
            GcpIotAlgorithm::Rs256,
            &project,
            qual_now_secs(),
            86_400,
        )
        .expect("witness JWT mints");
        let mut witness_stream = qual_dial(&witness_host, witness_port).await;
        let witness_connect = cloud_tls::encode_mqtt_connect(
            "qual-gcp-iot-witness",
            true,
            600,
            Some("unused"),
            Some(&witness_jwt),
        )
        .expect("qual witness CONNECT");
        tokio::time::timeout(
            Duration::from_secs(10),
            witness_stream.write_all(&witness_connect),
        )
        .await
        .expect("qual witness CONNECT write")
        .expect("qual witness CONNECT sent");
        assert_eq!(
            qual_connack_rc(&mut witness_stream).await,
            Some(0x00),
            "witness must accept the subscriber's valid JWT"
        );
        let subscribe =
            encode_qual_subscribe(1, &[telemetry_topic.as_str()]).expect("qual witness SUBSCRIBE");
        tokio::time::timeout(
            Duration::from_secs(10),
            witness_stream.write_all(&subscribe),
        )
        .await
        .expect("qual subscribe write")
        .expect("qual subscribe sent");
        let mut suback_head = [0u8; 2];
        tokio::time::timeout(
            Duration::from_secs(10),
            witness_stream.read_exact(&mut suback_head),
        )
        .await
        .expect("qual suback read")
        .expect("qual suback bytes");
        assert_eq!(suback_head[0], 0x90, "witness must get SUBACK");
        let mut suback_rest = vec![0u8; suback_head[1] as usize];
        tokio::time::timeout(
            Duration::from_secs(10),
            witness_stream.read_exact(&mut suback_rest),
        )
        .await
        .expect("qual suback body")
        .expect("qual suback rest");
        // Let the SUBACK settle before the first publish so the
        // 500-row count is not short by the subscription race.
        tokio::time::sleep(Duration::from_secs(1)).await;
        let received = Arc::new(AtomicU64::new(0));
        let received_clone = Arc::clone(&received);
        let witness = tokio::spawn(async move {
            let mut stream = witness_stream;
            loop {
                let mut head = [0u8; 1];
                if stream.read_exact(&mut head).await.is_err() {
                    break;
                }
                let packet_type = head[0];
                let mut len_buf = Vec::new();
                let mut ok = true;
                loop {
                    let mut byte = [0u8; 1];
                    if stream.read_exact(&mut byte).await.is_err() {
                        ok = false;
                        break;
                    }
                    len_buf.push(byte[0]);
                    if byte[0] & 0x80 == 0 {
                        break;
                    }
                    if len_buf.len() >= 4 {
                        ok = false;
                        break;
                    }
                }
                if !ok {
                    break;
                }
                let Ok((remaining, _)) = crate::mqtt_bridge::decode_remaining_length(&len_buf)
                else {
                    break;
                };
                let mut rest = vec![0u8; remaining];
                if stream.read_exact(&mut rest).await.is_err() {
                    break;
                }
                if packet_type & 0xF0 == 0x30 {
                    received_clone.fetch_add(1, Ordering::SeqCst);
                }
            }
        });

        // 500 telemetry rows through the broker's rule path, paced at
        // 250 ms so the run lasts ~125 s and crosses at least two
        // effective token lifetimes (the 20 s config clamps to the
        // 60 s floor). Each row flushes immediately (batch of one);
        // the sink mints fresh JWTs and redials as tokens turn over.
        // No tolerance: at-least-once delivery means every row must
        // arrive, exactly once counted here.
        let refreshes_before = sink.token_refreshes();
        for i in 0..500u32 {
            let payload = Bytes::from(format!("{{\"seq\":{i},\"temp\":21.5}}").into_bytes());
            manager
                .send(
                    "qual-gcp-iot",
                    &Topic::new(format!("sensors/{i}")).unwrap(),
                    &payload,
                    QoS::AtMostOnce,
                )
                .await
                .expect("qual send");
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        sink.flush().await.expect("qual flush");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        while received.load(Ordering::SeqCst) < 500 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let got = received.load(Ordering::SeqCst);
        assert_eq!(
            got, 500,
            "witness must receive exactly the 500 telemetry rows"
        );
        assert_eq!(sink.sent_records(), 500);
        let refreshes = sink.token_refreshes();
        assert!(
            refreshes >= refreshes_before + 2,
            "sink must have refreshed its token at least twice across the run \
             (before={refreshes_before} after={refreshes})"
        );
        eprintln!(
            "qual rows asserted: count=500 url={mqtt_url} refreshes={refreshes} reconnects={}",
            transport.connects()
        );

        witness.abort();
        transport.disconnect().await;
        eprintln!("qual cleanup: witness stopped, device session dropped");
    }

    /// Encode one MQTT 3.1.1 SUBSCRIBE frame for `filters` at QoS 0
    /// (qualification witness only).
    fn encode_qual_subscribe(packet_id: u16, filters: &[&str]) -> Result<Vec<u8>> {
        if packet_id == 0 {
            return Err(ConnectorError::Dispatch(
                "gcp-iot subscribe needs a nonzero packet id".to_string(),
            ));
        }
        if filters.is_empty() {
            return Err(ConnectorError::Dispatch(
                "gcp-iot subscribe needs at least one filter".to_string(),
            ));
        }
        let mut body = Vec::new();
        body.extend_from_slice(&packet_id.to_be_bytes());
        for filter in filters {
            if filter.is_empty() || filter.len() > u16::MAX as usize {
                return Err(ConnectorError::Dispatch(
                    "gcp-iot subscribe filter must be 1..=65535 bytes".to_string(),
                ));
            }
            body.extend_from_slice(&(filter.len() as u16).to_be_bytes());
            body.extend_from_slice(filter.as_bytes());
            body.push(0x00);
        }
        let mut frame = vec![0x82];
        crate::mqtt_bridge::encode_remaining_length(body.len(), &mut frame)?;
        frame.extend_from_slice(&body);
        Ok(frame)
    }
}
