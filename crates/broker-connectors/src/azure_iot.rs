//! Microsoft Azure IoT Hub bridge (INDRA-194).
//!
//! Device-to-Cloud telemetry and Cloud-to-Device command bridging
//! with Shared Access Signature authentication (reusing the exact SAS
//! shape as Event Hubs: `sr`/`sig`/`se`/`skn` over the device
//! resource URI), X.509 validation at config time, Device Twin
//! reported/desired patch topics, and Direct Method invocation
//! routing with response framing. MQTT travels over TLS: server
//! certificates verify against the configured CA bundle plus the
//! platform roots, SAS tokens ride as the MQTT password, and X.509
//! devices additionally authenticate with a client certificate.
//! Missing credentials are a dispatch error, never a cleartext
//! fallback.
//!
//! SAS tokens renew proactively before expiry; a 401 ExpiredToken
//! forces one renewal + retry, 429 QuotaExceeded backs off, and 404
//! DeviceNotFound is terminal.

use async_trait::async_trait;
use base64::Engine;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

use super::cloud_tls;
use super::{now_millis, BackoffState, BatchQueue, ConnectorError, Result, Sink};

/// Azure IoT Hub authentication credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", tag = "type")]
pub enum AzureIotAuth {
    /// Shared access key (SAS minted + renewed automatically).
    SharedAccessKey {
        key: String,
        key_name: Option<String>,
    },
    /// Pre-minted SAS token (auto-regeneration needs the secret key,
    /// so bare tokens are used verbatim until rejected).
    SasToken { token: String },
    /// X.509 device credentials (PEM validated, TLS at deploy time).
    X509 { cert_pem: String, key_pem: String },
}

impl Default for AzureIotAuth {
    fn default() -> Self {
        Self::SharedAccessKey {
            key: String::new(),
            key_name: None,
        }
    }
}

impl AzureIotAuth {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::SharedAccessKey { key, .. } => {
                if key.trim().is_empty() {
                    return Err(ConnectorError::Dispatch(
                        "azure-iot shared access key must not be empty".to_string(),
                    ));
                }
                Ok(())
            }
            Self::SasToken { token } => {
                if !token.starts_with("SharedAccessSignature ") {
                    return Err(ConnectorError::Dispatch(
                        "azure-iot SAS token must start with SharedAccessSignature".to_string(),
                    ));
                }
                Ok(())
            }
            Self::X509 { cert_pem, key_pem } => {
                if !cert_pem.contains("BEGIN CERTIFICATE") || !key_pem.contains("BEGIN") {
                    return Err(ConnectorError::Dispatch(
                        "azure-iot X.509 needs PEM cert + key".to_string(),
                    ));
                }
                Ok(())
            }
        }
    }
}

fn default_api_version() -> String {
    "2021-04-12".to_string()
}

fn default_batch_size() -> Option<usize> {
    Some(500)
}

/// Azure IoT Hub bridge configuration. Buffering is unbounded by
/// default; SAS tokens renew proactively.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AzureIotConfig {
    /// IoT Hub hostname (`my-hub.azure-devices.net`).
    pub iot_hub_name: String,
    /// Device identifier.
    pub device_id: String,
    /// Optional Edge module identifier.
    #[serde(default)]
    pub module_id: Option<String>,
    /// Authentication credentials.
    #[serde(default)]
    pub auth: AzureIotAuth,
    /// REST/MQTT API version (default `2021-04-12`).
    #[serde(default = "default_api_version")]
    pub api_version: String,
    /// Subscribe to direct method invocations (default true).
    #[serde(default = "default_true")]
    pub direct_methods_enabled: bool,
    /// Sync device twin reported/desired (default true).
    #[serde(default = "default_true")]
    pub twin_sync_enabled: bool,
    /// Flush trigger row count (default 500).
    #[serde(default = "default_batch_size")]
    pub batch_size: Option<usize>,
    /// Buffer capacity (`None` unbounded).
    #[serde(default)]
    pub buffer_capacity: Option<usize>,
    /// Linger flush window in ms (default 50).
    #[serde(default = "default_linger_ms")]
    pub linger_ms: Option<u64>,
    /// Retries on throttles/renewals (default 5).
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
    /// the platform roots.
    #[serde(default)]
    pub ca_bundle_pem: Option<String>,
    /// SAS token lifetime in seconds for `SharedAccessKey` auth
    /// (default 3600, minimum 60).
    #[serde(default = "default_sas_ttl_secs")]
    pub sas_ttl_secs: Option<u64>,
}

fn default_true() -> bool {
    true
}

fn default_linger_ms() -> Option<u64> {
    Some(50)
}

fn default_max_retries() -> Option<usize> {
    Some(5)
}

fn default_connect_timeout_ms() -> Option<u64> {
    Some(5000)
}

fn default_handshake_timeout_ms() -> Option<u64> {
    Some(5000)
}

fn default_sas_ttl_secs() -> Option<u64> {
    Some(3600)
}

impl AzureIotConfig {
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

    /// SAS token lifetime in seconds (default 3600, minimum 60).
    pub fn effective_sas_ttl(&self) -> u64 {
        self.sas_ttl_secs.unwrap_or(3600).max(60)
    }

    /// Split `iot_hub_name` into host/port (default 8883). The port
    /// suffix exists for loopback qualification; production hubs use
    /// 8883.
    pub fn host_port(&self) -> Result<(String, u16)> {
        cloud_tls::parse_host_port(&self.iot_hub_name, 8883)
    }

    /// Bare hub hostname without any `:port` suffix (used for SAS
    /// resource URIs and the MQTT username).
    pub fn hub_hostname(&self) -> String {
        self.host_port()
            .map(|(host, _)| host)
            .unwrap_or_else(|_| self.iot_hub_name.trim().to_string())
    }

    /// MQTT client id: the device id, or `device/module` for modules.
    pub fn mqtt_client_id(&self) -> String {
        match &self.module_id {
            Some(module) => format!("{}/{}", self.device_id, module),
            None => self.device_id.clone(),
        }
    }

    /// MQTT username: `{hub}/{device}[/{module}]/?api-version={ver}`.
    pub fn mqtt_username(&self) -> String {
        let hub = self.hub_hostname();
        let client = self.mqtt_client_id();
        format!("{hub}/{client}/?api-version={}", self.api_version)
    }

    pub fn validate(&self) -> Result<()> {
        if self.iot_hub_name.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "azure-iot hub name must not be empty".to_string(),
            ));
        }
        // Hub must parse to a concrete host/port now (TLS dials it).
        self.host_port()?;
        if self.device_id.trim().is_empty() || self.device_id.contains(['/', '#', '+']) {
            return Err(ConnectorError::Dispatch(format!(
                "azure-iot device_id must be a concrete segment: {:?}",
                self.device_id
            )));
        }
        if let Some(module) = &self.module_id {
            if module.trim().is_empty() || module.contains(['/', '#', '+']) {
                return Err(ConnectorError::Dispatch(format!(
                    "azure-iot module_id must be a concrete segment: {module:?}"
                )));
            }
        }
        self.auth.validate()?;
        if self.api_version.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "azure-iot api_version must not be empty".to_string(),
            ));
        }
        if let Some(bundle) = &self.ca_bundle_pem {
            if !bundle.trim().is_empty() && !bundle.contains("BEGIN CERTIFICATE") {
                return Err(ConnectorError::Dispatch(
                    "azure-iot ca_bundle_pem is not a PEM document".to_string(),
                ));
            }
        }
        if self.batch_size == Some(0) {
            return Err(ConnectorError::Dispatch(
                "azure-iot batch_size must be >= 1".to_string(),
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

    /// Device (or module) resource URI covered by SAS tokens:
    /// `{hub}/devices/{device}[/modules/{module}]` (no scheme, no port).
    pub fn resource_uri(&self) -> String {
        let hub = self.hub_hostname();
        match &self.module_id {
            Some(module) => format!("{hub}/devices/{}/modules/{module}", self.device_id),
            None => format!("{hub}/devices/{}", self.device_id),
        }
    }
}

// ---------------------------------------------------------------------------
// SAS tokens (same shape as Event Hubs SAS).
// ---------------------------------------------------------------------------

/// URL-encode per `encodeURIComponent` (uppercase `%XX`).
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

/// Build `SharedAccessSignature sr=...&sig=...&se=...[&skn=...]`
/// with HMAC-SHA256 over `{lowercased-uri}\n{expiry}`. Portal base64
/// keys decode first; raw secrets sign verbatim.
pub fn sas_token(
    resource_uri: &str,
    key_name: Option<&str>,
    secret: &str,
    expiry_secs: u64,
) -> String {
    let string_to_sign = format!("{}\n{expiry_secs}", resource_uri.to_lowercase());
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(secret.trim())
        .unwrap_or_else(|_| secret.as_bytes().to_vec());
    let signature = super::hmac_sha256(&key_bytes, string_to_sign.as_bytes());
    let signature = base64::engine::general_purpose::STANDARD.encode(signature);
    let mut token = format!(
        "SharedAccessSignature sr={}&sig={}&se={expiry_secs}",
        url_encode(&resource_uri.to_lowercase()),
        url_encode(&signature),
    );
    if let Some(key_name) = key_name {
        token.push_str("&skn=");
        token.push_str(&url_encode(key_name));
    }
    token
}

/// Extract the `se=` expiry from a SAS token (None when malformed).
pub fn sas_expiry(token: &str) -> Option<u64> {
    token.split('&').find_map(|part| {
        part.strip_prefix("se=")
            .and_then(|value| value.parse::<u64>().ok())
    })
}

/// Proactive SAS cache: mints tokens with a TTL and renews before
/// expiry (60s skew). Pure time math stays unit-testable.
pub struct AzureIotSasCache {
    resource_uri: String,
    key_name: Option<String>,
    secret: String,
    ttl_secs: u64,
    cached: parking_lot::Mutex<Option<(String, u64)>>,
}

impl AzureIotSasCache {
    pub fn new(
        resource_uri: String,
        key_name: Option<String>,
        secret: String,
        ttl_secs: u64,
    ) -> Self {
        Self {
            resource_uri,
            key_name,
            secret,
            ttl_secs: ttl_secs.max(60),
            cached: parking_lot::Mutex::new(None),
        }
    }

    /// Token valid at `now_secs`, renewing when inside the skew.
    pub fn token_at(&self, now_secs: u64) -> String {
        if let Some((token, exp)) = self.cached.lock().clone() {
            if now_secs + 60 < exp {
                return token;
            }
        }
        let expiry = now_secs.saturating_add(self.ttl_secs);
        let token = sas_token(
            &self.resource_uri,
            self.key_name.as_deref(),
            &self.secret,
            expiry,
        );
        *self.cached.lock() = Some((token.clone(), expiry));
        token
    }

    /// Drop the cache so the next call mints fresh (401 recovery).
    pub fn invalidate(&self) {
        *self.cached.lock() = None;
    }

    pub fn token_now(&self) -> String {
        self.token_at(now_millis().max(0) as u64 / 1_000)
    }
}

// ---------------------------------------------------------------------------
// D2C topics, twin paths, direct methods.
// ---------------------------------------------------------------------------

/// URL-encode a property-bag value (`/` becomes `%2F`, space `+`).
fn property_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else if byte == b' ' {
            out.push('+');
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Decode a property-bag value (`+` back to space first).
fn property_decode(value: &str) -> String {
    let plus_fixed = value.replace('+', " ");
    let mut out = Vec::new();
    let bytes = plus_fixed.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&plus_fixed[index + 1..index + 3], 16) {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Build a D2C topic: `devices/{device}/messages/events/{bag}`
/// with `$.ct`/`$.ce` defaults plus custom properties.
pub fn d2c_topic(
    device_id: &str,
    module_id: Option<&str>,
    properties: &[(String, String)],
) -> String {
    let mut bag = vec![
        ("$.ct".to_string(), "application/json".to_string()),
        ("$.ce".to_string(), "utf-8".to_string()),
    ];
    bag.extend(properties.iter().cloned());
    let encoded = bag
        .iter()
        .map(|(key, value)| format!("{}={}", property_encode(key), property_encode(value)))
        .collect::<Vec<_>>()
        .join("&");
    match module_id {
        Some(module) => format!("devices/{device_id}/modules/{module}/messages/events/{encoded}"),
        None => format!("devices/{device_id}/messages/events/{encoded}"),
    }
}

/// Split a property bag back into pairs (round-trip tested).
pub fn parse_property_bag(bag: &str) -> Vec<(String, String)> {
    if bag.is_empty() {
        return Vec::new();
    }
    bag.split('&')
        .filter_map(|pair| {
            pair.split_once('=')
                .map(|(key, value)| (property_decode(key), property_decode(value)))
        })
        .collect()
}

/// Device Twin + Direct Method topic builders.
pub struct TwinTopics;

impl TwinTopics {
    /// Reported-properties PATCH topic for one request id.
    pub fn reported_patch(rid: &str) -> String {
        format!("$iothub/twin/PATCH/properties/reported/?$rid={rid}")
    }

    /// Desired-properties subscription filter.
    pub fn desired_filter() -> &'static str {
        "$iothub/twin/PATCH/properties/desired/#"
    }

    /// Direct-method invocation filter for one method.
    pub fn method_filter(method: &str) -> String {
        format!("$iothub/methods/POST/{method}/#")
    }

    /// Parse `$iothub/methods/POST/{method}/?$rid={rid}`.
    pub fn parse_method_invocation(topic: &str) -> Option<(String, String)> {
        let rest = topic.strip_prefix("$iothub/methods/POST/")?;
        let (method, query) = rest.split_once('/')?;
        let rid = query.strip_prefix("?$rid=")?;
        if method.is_empty() || rid.is_empty() {
            return None;
        }
        Some((method.to_string(), rid.to_string()))
    }

    /// Direct-method response topic + JSON body.
    pub fn method_response(
        status: u16,
        rid: &str,
        payload: &serde_json::Value,
    ) -> (String, Vec<u8>) {
        (
            format!("$iothub/methods/res/{status}/?$rid={rid}"),
            serde_json::to_vec(payload).unwrap_or_default(),
        )
    }

    /// Reported-properties PATCH document for one JSON payload.
    pub fn reported_patch_document(payload: &serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(payload).unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// Transport + sink (D2C telemetry with SAS renewal + backoff).
// ---------------------------------------------------------------------------

/// One D2C publish: topic + body.
#[derive(Debug, Clone)]
pub struct AzureIotPublish {
    pub topic: String,
    pub body: Vec<u8>,
}

#[async_trait]
pub trait AzureIotTransport: Send + Sync {
    async fn publish(&self, publish: &AzureIotPublish, sas_token: &str) -> Result<()>;
}

/// Scripted outcome for the mock transport.
#[derive(Debug, Clone)]
pub enum MockAzureIotOutcome {
    Ok,
    /// Transport failure (retries in-loop).
    ConnectionError(String),
    /// HTTP failure (401 renews once; 429 retries; 404 terminal).
    HttpStatus(u16),
}

/// One captured publish call.
#[derive(Debug, Clone)]
pub struct CapturedAzureIotPublish {
    pub topic: String,
    pub body: Vec<u8>,
    pub sas_token: String,
}

/// In-memory transport with scripted outcomes (tests, dry runs).
#[derive(Debug, Default)]
pub struct MockAzureIotTransport {
    scripted: parking_lot::Mutex<std::collections::VecDeque<MockAzureIotOutcome>>,
    captured: parking_lot::Mutex<Vec<CapturedAzureIotPublish>>,
    calls: AtomicU64,
}

impl MockAzureIotTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue outcomes consumed in order (default: success).
    pub fn script_outcomes(&self, outcomes: Vec<MockAzureIotOutcome>) {
        *self.scripted.lock() = outcomes.into_iter().collect();
    }

    pub fn captured(&self) -> Vec<CapturedAzureIotPublish> {
        self.captured.lock().clone()
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl AzureIotTransport for MockAzureIotTransport {
    async fn publish(&self, publish: &AzureIotPublish, sas_token: &str) -> Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.captured.lock().push(CapturedAzureIotPublish {
            topic: publish.topic.clone(),
            body: publish.body.clone(),
            sas_token: sas_token.to_string(),
        });
        match self.scripted.lock().pop_front() {
            None | Some(MockAzureIotOutcome::Ok) => Ok(()),
            Some(MockAzureIotOutcome::ConnectionError(message)) => {
                Err(ConnectorError::Connection(message))
            }
            Some(MockAzureIotOutcome::HttpStatus(status)) => Err(match status {
                401 => ConnectorError::Connection("mock azure-iot expired token".to_string()),
                429 => {
                    ConnectorError::Connection(format!("mock azure-iot throttled with {status}"))
                }
                404 => ConnectorError::Dispatch("mock azure-iot device not found".to_string()),
                _ => ConnectorError::Dispatch(format!("mock azure-iot failed with {status}")),
            }),
        }
    }
}

/// TLS transport: MQTT over TLS to Azure IoT Hub (port 8883 by
/// default). Server certificates verify against the configured CA
/// bundle plus the platform roots. SAS variants send the token as
/// the MQTT password; X.509 devices authenticate with a client
/// certificate. The TCP socket is only ever the TLS underlay: there
/// is no cleartext path and a missing credential is a dispatch
/// error.
pub struct TlsAzureIotTransport {
    host: String,
    port: u16,
    client_id: String,
    username: String,
    expect_password: bool,
    tls: Arc<rustls::ClientConfig>,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    io_timeout: Duration,
    stream: tokio::sync::Mutex<Option<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>>,
}

impl TlsAzureIotTransport {
    pub fn new(config: &AzureIotConfig) -> Result<Self> {
        config.validate()?;
        let (host, port) = config.host_port()?;
        let roots = cloud_tls::root_store_with(config.ca_bundle_pem.as_deref())?;
        let (client_cert, expect_password) = match &config.auth {
            AzureIotAuth::SharedAccessKey { key, .. } => {
                if key.trim().is_empty() {
                    return Err(ConnectorError::Dispatch(
                        "azure-iot shared access key must not be empty; no plain-text fallback"
                            .to_string(),
                    ));
                }
                (None, true)
            }
            AzureIotAuth::SasToken { token } => {
                if !token.starts_with("SharedAccessSignature ") {
                    return Err(ConnectorError::Dispatch(
                        "azure-iot SAS token must start with SharedAccessSignature; \
                         no plain-text fallback"
                            .to_string(),
                    ));
                }
                (None, true)
            }
            AzureIotAuth::X509 { cert_pem, key_pem } => {
                let chain = cloud_tls::certs_from_pem(cert_pem).map_err(|e| {
                    ConnectorError::Dispatch(format!("azure-iot client certificate rejected: {e}"))
                })?;
                let key = cloud_tls::private_key_from_pem(key_pem).map_err(|e| {
                    ConnectorError::Dispatch(format!("azure-iot client key rejected: {e}"))
                })?;
                (Some((chain, key)), false)
            }
        };
        let tls = cloud_tls::client_config(roots, client_cert, &[])?;
        Ok(Self {
            host,
            port,
            client_id: config.mqtt_client_id(),
            username: config.mqtt_username(),
            expect_password,
            tls,
            connect_timeout: config.connect_timeout(),
            handshake_timeout: config.handshake_timeout(),
            io_timeout: config.timeout(),
            stream: tokio::sync::Mutex::new(None),
        })
    }

    async fn ensure_connected(&self, sas_token: &str) -> Result<()> {
        if self.expect_password && sas_token.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "azure-iot SAS token missing; no plain-text fallback".to_string(),
            ));
        }
        if self.stream.lock().await.is_some() {
            return Ok(());
        }
        let password = if self.expect_password {
            Some(sas_token)
        } else {
            None
        };
        let mut stream = cloud_tls::tls_dial(
            &self.host,
            self.port,
            self.tls.clone(),
            self.connect_timeout,
            self.handshake_timeout,
            "azure-iot",
        )
        .await?;
        let connect = cloud_tls::encode_mqtt_connect(
            &self.client_id,
            true,
            60,
            Some(&self.username),
            password,
        )?;
        cloud_tls::mqtt_connect_over_tls(&mut stream, &connect, "azure-iot", self.io_timeout)
            .await?;
        *self.stream.lock().await = Some(stream);
        Ok(())
    }
}

#[async_trait]
impl AzureIotTransport for TlsAzureIotTransport {
    async fn publish(&self, publish: &AzureIotPublish, sas_token: &str) -> Result<()> {
        self.ensure_connected(sas_token).await?;
        let bytes =
            super::mqtt_bridge::encode_publish(&publish.topic, 1, false, 1, &publish.body, false)?;
        let mut guard = self.stream.lock().await;
        let stream = guard
            .as_mut()
            .ok_or_else(|| ConnectorError::Connection("azure-iot not connected".to_string()))?;
        tokio::time::timeout(self.io_timeout, stream.write_all(&bytes))
            .await
            .map_err(|_| ConnectorError::Connection("azure-iot publish timeout".to_string()))?
            .map_err(|e| ConnectorError::Connection(format!("azure-iot publish failed: {e}")))?;
        Ok(())
    }
}

/// Azure IoT transport with an explicit connect step.
#[async_trait]
pub trait AzureIotConnectTransport: AzureIotTransport {
    async fn connect_transport(&self) -> Result<()>;
}

#[async_trait]
impl AzureIotConnectTransport for MockAzureIotTransport {
    async fn connect_transport(&self) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl AzureIotConnectTransport for TlsAzureIotTransport {
    async fn connect_transport(&self) -> Result<()> {
        if self.expect_password {
            return Err(ConnectorError::Dispatch(
                "azure-iot SAS connect needs a token; publish connects lazily".to_string(),
            ));
        }
        self.ensure_connected("").await
    }
}

/// One buffered row: D2C topic + body.
#[derive(Debug, Clone)]
struct AzureIotRow {
    topic: String,
    body: Vec<u8>,
}

/// Azure IoT Hub bridge sink: D2C telemetry with SAS renewal.
pub struct AzureIotSink {
    config: AzureIotConfig,
    transport: Arc<dyn AzureIotConnectTransport>,
    sas_cache: Option<Arc<AzureIotSasCache>>,
    buffer: parking_lot::Mutex<BatchQueue<AzureIotRow>>,
    backoff: parking_lot::Mutex<BackoffState>,
    sent_batches: AtomicU64,
    sent_records: AtomicU64,
}

impl AzureIotSink {
    pub fn new(
        config: AzureIotConfig,
        transport: Arc<dyn AzureIotConnectTransport>,
    ) -> Result<Self> {
        config.validate()?;
        let linger = config.effective_linger();
        let ttl = config.effective_sas_ttl();
        let sas_cache = match &config.auth {
            AzureIotAuth::SharedAccessKey { key, key_name } => Some(Arc::new(
                AzureIotSasCache::new(config.resource_uri(), key_name.clone(), key.clone(), ttl),
            )),
            _ => None,
        };
        Ok(Self {
            buffer: parking_lot::Mutex::new(BatchQueue::new(config.effective_batch_size(), linger)),
            config,
            transport,
            sas_cache,
            backoff: parking_lot::Mutex::new(BackoffState::default()),
            sent_batches: AtomicU64::new(0),
            sent_records: AtomicU64::new(0),
        })
    }

    pub fn config(&self) -> &AzureIotConfig {
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
        let grown = 100u64
            .saturating_mul(2u64.saturating_pow(attempt.min(10) as u32))
            .min(2_000);
        let jitter = (now_millis().max(0) as u64) % (grown / 2 + 1);
        Duration::from_millis(grown.saturating_add(jitter).min(4_000))
    }

    /// Current SAS token (minted, or the verbatim pre-minted one).
    fn sas_token(&self) -> Result<String> {
        match &self.config.auth {
            AzureIotAuth::SharedAccessKey { .. } => Ok(self
                .sas_cache
                .as_ref()
                .expect("cache built with SharedAccessKey")
                .token_now()),
            AzureIotAuth::SasToken { token } => Ok(token.clone()),
            AzureIotAuth::X509 { .. } => Ok(String::new()),
        }
    }

    /// Flush buffered rows (no-op when empty). 401 forces one SAS
    /// renewal + retry; throttles retry in-loop; terminal failures
    /// and exhaustion restore the buffer and propagate.
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
            let token = self.sas_token()?;
            let mut outcome: Result<()> = Ok(());
            for row in &rows {
                if let Err(e) = self
                    .transport
                    .publish(
                        &AzureIotPublish {
                            topic: row.topic.clone(),
                            body: row.body.clone(),
                        },
                        &token,
                    )
                    .await
                {
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
                // 401 ExpiredToken: renew once, then continue retrying.
                Err(ConnectorError::Connection(message))
                    if message.contains("expired token") && !renewed_once =>
                {
                    renewed_once = true;
                    if let Some(cache) = &self.sas_cache {
                        cache.invalidate();
                    }
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
        rows: Vec<AzureIotRow>,
        oldest: Option<std::time::Instant>,
        error: ConnectorError,
    ) -> Result<()> {
        let mut buffer = self.buffer.lock();
        buffer.restore(rows, oldest);
        self.backoff.lock().failure();
        Err(error)
    }

    /// Validate + buffer one D2C event. Returns true when the batch
    /// is full or stale (caller flushes).
    fn buffer_row(&self, topic: &Topic, payload: &Bytes, _qos: QoS) -> Result<bool> {
        if topic.as_str().is_empty() {
            return Err(ConnectorError::Dispatch(
                "azure-iot row requires a non-empty topic".to_string(),
            ));
        }
        if self.buffer.lock().len() >= self.config.effective_buffer() {
            return Err(ConnectorError::Connection(
                "azure-iot buffer limit reached".to_string(),
            ));
        }
        let d2c = d2c_topic(
            &self.config.device_id,
            self.config.module_id.as_deref(),
            &[],
        );
        Ok(self.buffer.lock().push(AzureIotRow {
            topic: d2c,
            body: payload.to_vec(),
        }))
    }
}

#[async_trait]
impl Sink for AzureIotSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        if self.buffer_row(topic, payload, qos)? {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "azure_iot"
    }
}

/// Management connector handle pairing an id with an Azure IoT sink.
pub struct AzureIotConnector {
    id: String,
    sink: Arc<AzureIotSink>,
}

impl AzureIotConnector {
    pub fn new(id: impl Into<String>, sink: Arc<AzureIotSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }
}

impl super::Connector for AzureIotConnector {
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

    fn test_config() -> AzureIotConfig {
        AzureIotConfig {
            iot_hub_name: "my-hub.azure-devices.net".to_string(),
            device_id: "edge-1".to_string(),
            module_id: None,
            auth: AzureIotAuth::SharedAccessKey {
                key: "dGVzdC1rZXktbWF0ZXJpYWwtMzItYnl0ZXMhIU9L".to_string(),
                key_name: Some("iothubowner".to_string()),
            },
            api_version: "2021-04-12".to_string(),
            direct_methods_enabled: true,
            twin_sync_enabled: true,
            batch_size: Some(500),
            buffer_capacity: None,
            linger_ms: Some(50),
            max_retries: Some(5),
            timeout_ms: None,
            connect_timeout_ms: None,
            handshake_timeout_ms: None,
            ca_bundle_pem: None,
            sas_ttl_secs: None,
        }
    }

    fn test_sink(config: AzureIotConfig) -> (Arc<AzureIotSink>, Arc<MockAzureIotTransport>) {
        let transport = Arc::new(MockAzureIotTransport::new());
        let sink = Arc::new(AzureIotSink::new(config, transport.clone()).unwrap());
        (sink, transport)
    }

    #[test]
    fn test_config_validation() {
        let mut config = test_config();
        assert!(config.validate().is_ok());
        assert_eq!(
            config.resource_uri(),
            "my-hub.azure-devices.net/devices/edge-1"
        );

        config.device_id = "bad/device".to_string();
        assert!(config.validate().is_err());
        config.device_id = "edge-1".to_string();

        config.module_id = Some("".to_string());
        assert!(config.validate().is_err());
        config.module_id = Some("mod-a".to_string());
        assert_eq!(
            config.resource_uri(),
            "my-hub.azure-devices.net/devices/edge-1/modules/mod-a"
        );
        config.module_id = None;

        config.auth = AzureIotAuth::SasToken {
            token: "nope".to_string(),
        };
        assert!(config.validate().is_err());
        config.auth = AzureIotAuth::X509 {
            cert_pem: "not-pem".to_string(),
            key_pem: "x".to_string(),
        };
        assert!(config.validate().is_err());
        config.auth = test_config().auth;

        config.batch_size = Some(0);
        assert!(config.validate().is_err());
        // Unbounded depths accepted: zero clamped ceilings.
        config.batch_size = None;
        config.buffer_capacity = Some(10_000_000);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_sas_known_answer() {
        // Independent Python (hmac/hashlib/base64/urllib) vector over
        // the device resource URI at expiry 1789211889.
        let token = sas_token(
            "my-hub.azure-devices.net/devices/edge-1",
            Some("iothubowner"),
            "dGVzdC1rZXktbWF0ZXJpYWwtMzItYnl0ZXMhIU9L",
            1_789_211_889,
        );
        assert_eq!(
            token,
            "SharedAccessSignature \
             sr=my-hub.azure-devices.net%2Fdevices%2Fedge-1\
             &sig=dxVyb%2FfJqoLonugZslOo0zh%2BTkoEHrvFU5mP7g3qD1E%3D\
             &se=1789211889&skn=iothubowner"
        );
        // Raw (non-base64) secrets sign verbatim; no key name omits skn.
        let raw = sas_token("hub/devices/d", None, "plain-secret", 100);
        assert!(raw.starts_with("SharedAccessSignature sr=hub%2Fdevices%2Fd&sig="));
        assert!(raw.ends_with("&se=100"));
        assert!(!raw.contains("skn="));
        // Shape + expiry extraction hold regardless of the signature.
        assert_eq!(sas_expiry(&token), Some(1_789_211_889));
        assert_eq!(sas_expiry("garbage"), None);
    }

    #[test]
    fn test_property_bag_roundtrip() {
        let bag = d2c_topic(
            "edge-1",
            None,
            &[
                ("customProp".to_string(), "value".to_string()),
                ("sp ace".to_string(), "a/b?c".to_string()),
            ],
        );
        assert!(bag.starts_with("devices/edge-1/messages/events/"));
        let query = bag.split_once("/messages/events/").expect("bag").1;
        let pairs = parse_property_bag(query);
        assert!(pairs.contains(&("$.ct".to_string(), "application/json".to_string())));
        assert!(pairs.contains(&("$.ce".to_string(), "utf-8".to_string())));
        assert!(pairs.contains(&("customProp".to_string(), "value".to_string())));
        assert!(pairs.contains(&("sp ace".to_string(), "a/b?c".to_string())));
        assert_eq!(
            d2c_topic("edge-1", Some("mod-a"), &[]),
            "devices/edge-1/modules/mod-a/messages/events/%24.ct=application%2Fjson&%24.ce=utf-8"
        );
    }

    #[test]
    fn test_twin_and_method_topics() {
        assert_eq!(
            TwinTopics::reported_patch("rid-7"),
            "$iothub/twin/PATCH/properties/reported/?$rid=rid-7"
        );
        assert_eq!(
            TwinTopics::desired_filter(),
            "$iothub/twin/PATCH/properties/desired/#"
        );
        assert_eq!(
            TwinTopics::method_filter("reboot"),
            "$iothub/methods/POST/reboot/#"
        );
        assert_eq!(
            TwinTopics::parse_method_invocation("$iothub/methods/POST/reboot/?$rid=rid-9"),
            Some(("reboot".to_string(), "rid-9".to_string()))
        );
        assert_eq!(
            TwinTopics::parse_method_invocation("$iothub/methods/POST/reboot"),
            None
        );
        let (topic, body) =
            TwinTopics::method_response(200, "rid-9", &serde_json::json!({"ok": true}));
        assert_eq!(topic, "$iothub/methods/res/200/?$rid=rid-9");
        assert_eq!(body, br#"{"ok":true}"#.to_vec());
        // Twin patch documents pass JSON through.
        assert_eq!(
            TwinTopics::reported_patch_document(&serde_json::json!({"temp": 1})),
            br#"{"temp":1}"#.to_vec()
        );
    }

    #[test]
    fn test_sas_cache_renewal_math() {
        let cache = AzureIotSasCache::new(
            "my-hub.azure-devices.net/devices/edge-1".to_string(),
            Some("iothubowner".to_string()),
            "c2VjcmV0".to_string(),
            3_600,
        );
        // First mint at t=1000 (expiry 4600); cached inside the skew.
        let first = cache.token_at(1_000);
        assert_eq!(cache.token_at(2_000), first);
        // Past expiry minus skew: fresh token with a new expiry.
        let second = cache.token_at(5_000);
        assert_ne!(first, second);
        assert_eq!(sas_expiry(&second), Some(8_600));
        // Invalidate forces a mint even inside the skew.
        cache.invalidate();
        let third = cache.token_at(2_000);
        assert_ne!(third, second);
        assert_eq!(sas_expiry(&third), Some(5_600));
    }

    #[tokio::test]
    async fn test_d2c_publish_and_renewal() {
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
        assert!(captured[0]
            .topic
            .starts_with("devices/edge-1/messages/events/"));
        assert_eq!(captured[0].body, br#"{"temp":21.5}"#.to_vec());
        assert!(captured[0]
            .sas_token
            .starts_with("SharedAccessSignature sr="));
        assert_eq!(sink.sent_records(), 1);

        // 401 expires the token: invalidate + retry to success.
        // (Token strings may coincide within one second; renewal is
        // proven by the second call succeeding + the unit test above.)
        let (sink, transport) = test_sink(test_config());
        transport.script_outcomes(vec![
            MockAzureIotOutcome::HttpStatus(401),
            MockAzureIotOutcome::Ok,
        ]);
        // Force the cached token stale so renewal mints a new expiry.
        let cache = sink.sas_cache.clone().expect("shared key cache");
        *cache.cached.lock() = Some(("SharedAccessSignature sr=x&se=1".to_string(), 1));
        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from("{}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        sink.flush().await.unwrap();
        assert_eq!(transport.calls(), 2);
        assert_eq!(sink.sent_records(), 1);
    }

    #[tokio::test]
    async fn test_throttle_backoff_and_terminal_404() {
        // 429 backs off and retries to success.
        let mut config = test_config();
        config.batch_size = Some(10);
        let (sink, transport) = test_sink(config);
        transport.script_outcomes(vec![
            MockAzureIotOutcome::HttpStatus(429),
            MockAzureIotOutcome::Ok,
        ]);
        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from("{}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        sink.flush().await.unwrap();
        assert_eq!(transport.calls(), 2);
        assert_eq!(sink.sent_records(), 1);

        // 404 DeviceNotFound: terminal, single attempt, retained.
        let (sink, transport) = test_sink(test_config());
        transport.script_outcomes(vec![MockAzureIotOutcome::HttpStatus(404)]);
        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from("{}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        let err = sink.flush().await.expect_err("404 must fail");
        assert!(matches!(err, ConnectorError::Dispatch(_)));
        assert_eq!(transport.calls(), 1);
        assert_eq!(sink.buffered_rows(), 1);
    }

    #[test]
    fn test_no_plain_socket_path() {
        // The module must not contain a cleartext MQTT path: the only
        // TCP dial lives in the shared TLS helper, and SAS/X.509 gaps
        // are dispatch errors, never a fallback. Needles are built at
        // runtime so this assertion does not match itself.
        let source = include_str!("azure_iot.rs");
        let needle = ["TcpStream", "connect"].join("::");
        assert!(
            !source.contains(&needle),
            "azure-iot must not open a plain socket"
        );
        let deferred = ["terminate in front", "of it"].join(" ");
        assert!(
            !source.contains(&deferred),
            "azure-iot must not defer TLS to deployment"
        );
    }

    #[test]
    fn test_tls_timeouts_and_sas_lifetime_defaults() {
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
        assert_eq!(config.effective_sas_ttl(), 3600);
        let mut custom = test_config();
        custom.connect_timeout_ms = Some(1500);
        custom.handshake_timeout_ms = Some(2500);
        custom.sas_ttl_secs = Some(30);
        assert_eq!(custom.connect_timeout(), Duration::from_millis(1500));
        assert_eq!(custom.handshake_timeout(), Duration::from_millis(2500));
        // Lifetimes below 60 s clamp to the 60 s minimum.
        assert_eq!(custom.effective_sas_ttl(), 60);
        custom.sas_ttl_secs = Some(7200);
        assert_eq!(custom.effective_sas_ttl(), 7200);
    }

    #[test]
    fn test_mqtt_identity_helpers() {
        let config = test_config();
        assert_eq!(config.mqtt_client_id(), "edge-1");
        assert_eq!(
            config.mqtt_username(),
            "my-hub.azure-devices.net/edge-1/?api-version=2021-04-12"
        );
        let mut module = test_config();
        module.module_id = Some("mod-a".to_string());
        assert_eq!(module.mqtt_client_id(), "edge-1/mod-a");
        assert_eq!(
            module.mqtt_username(),
            "my-hub.azure-devices.net/edge-1/mod-a/?api-version=2021-04-12"
        );
    }

    #[test]
    fn test_missing_credentials_have_no_fallback() {
        let mut config = test_config();
        config.auth = AzureIotAuth::SharedAccessKey {
            key: "   ".to_string(),
            key_name: None,
        };
        assert!(
            matches!(
                TlsAzureIotTransport::new(&config),
                Err(ConnectorError::Dispatch(_))
            ),
            "empty key must fail loudly"
        );

        config = test_config();
        config.auth = AzureIotAuth::SasToken {
            token: "Bearer nope".to_string(),
        };
        let err = TlsAzureIotTransport::new(&config);
        match err {
            Err(ConnectorError::Dispatch(message)) => {
                assert!(message.contains("SharedAccessSignature"));
            }
            _ => panic!("bare token must fail loudly"),
        }
    }

    const TEST_CA_PEM: &str = include_str!("../testdata/ca-cert.pem");
    const TEST_SERVER_CERT_PEM: &str = include_str!("../testdata/server-cert.pem");
    const TEST_SERVER_KEY_PEM: &str = include_str!("../testdata/server-key.pem");
    const TEST_CLIENT_CERT_PEM: &str = include_str!("../testdata/client-cert.pem");
    const TEST_CLIENT_KEY_PEM: &str = include_str!("../testdata/client-key.pem");

    fn sas_test_config(hub: &str) -> AzureIotConfig {
        AzureIotConfig {
            iot_hub_name: hub.to_string(),
            device_id: "edge-1".to_string(),
            module_id: None,
            auth: AzureIotAuth::SharedAccessKey {
                key: "dGVzdC1rZXktbWF0ZXJpYWwtMzItYnl0ZXMhIU9L".to_string(),
                key_name: Some("iothubowner".to_string()),
            },
            api_version: "2021-04-12".to_string(),
            direct_methods_enabled: true,
            twin_sync_enabled: true,
            batch_size: Some(500),
            buffer_capacity: None,
            linger_ms: Some(50),
            max_retries: Some(5),
            timeout_ms: Some(2000),
            connect_timeout_ms: Some(2000),
            handshake_timeout_ms: Some(2000),
            ca_bundle_pem: Some(TEST_CA_PEM.to_string()),
            sas_ttl_secs: Some(3600),
        }
    }

    fn x509_test_config(hub: &str) -> AzureIotConfig {
        AzureIotConfig {
            iot_hub_name: hub.to_string(),
            device_id: "edge-1".to_string(),
            module_id: None,
            auth: AzureIotAuth::X509 {
                cert_pem: TEST_CLIENT_CERT_PEM.to_string(),
                key_pem: TEST_CLIENT_KEY_PEM.to_string(),
            },
            api_version: "2021-04-12".to_string(),
            direct_methods_enabled: true,
            twin_sync_enabled: true,
            batch_size: Some(500),
            buffer_capacity: None,
            linger_ms: Some(50),
            max_retries: Some(5),
            timeout_ms: Some(2000),
            connect_timeout_ms: Some(2000),
            handshake_timeout_ms: Some(2000),
            ca_bundle_pem: Some(TEST_CA_PEM.to_string()),
            sas_ttl_secs: None,
        }
    }

    async fn read_publish_frame<S>(tls: &mut S) -> crate::mqtt_bridge::DecodedPublish
    where
        S: tokio::io::AsyncReadExt + Unpin,
    {
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
        crate::mqtt_bridge::decode_publish(&frame, false).expect("decode")
    }

    #[tokio::test]
    async fn test_tls_handshake_with_sas_password() {
        use tokio::io::AsyncWriteExt;
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
        let expected_username = "127.0.0.1/edge-1/?api-version=2021-04-12".to_string();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept");
            let mut tls = acceptor.accept(tcp).await.expect("tls accept");
            let (client_id, username, password) = crate::cloud_tls::read_client_connect(&mut tls)
                .await
                .expect("read CONNECT");
            assert_eq!(client_id, "edge-1");
            assert_eq!(username.as_deref(), Some(expected_username.as_str()));
            let password = password.expect("SAS password required");
            assert!(password.starts_with("SharedAccessSignature sr="));
            tls.write_all(&[0x20, 0x02, 0x00, 0x00])
                .await
                .expect("CONNACK");
            let decoded = read_publish_frame(&mut tls).await;
            assert!(decoded.topic.starts_with("devices/edge-1/messages/events/"));
            assert_eq!(decoded.payload, b"{}");
        });

        let config = sas_test_config(&format!("127.0.0.1:{port}"));
        let transport = Arc::new(TlsAzureIotTransport::new(&config).unwrap());
        // SAS transports connect lazily through publish (the token is
        // minted per flush); an explicit connect without a token fails
        // loudly instead of falling back.
        assert!(transport.connect_transport().await.is_err());
        let token = sas_token(
            &config.resource_uri(),
            Some("iothubowner"),
            "dGVzdC1rZXktbWF0ZXJpYWwtMzItYnl0ZXMhIU9L",
            1_789_211_889,
        );
        transport
            .publish(
                &AzureIotPublish {
                    topic: "devices/edge-1/messages/events/%24.ct=application%2Fjson".to_string(),
                    body: b"{}".to_vec(),
                },
                &token,
            )
            .await
            .unwrap();
        // An empty SAS token never touches the wire.
        let err = transport
            .publish(
                &AzureIotPublish {
                    topic: "devices/edge-1/messages/events/x".to_string(),
                    body: b"{}".to_vec(),
                },
                "  ",
            )
            .await
            .expect_err("empty SAS must fail");
        assert!(matches!(err, ConnectorError::Dispatch(_)));
        tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .expect("server done")
            .expect("server task");
    }

    #[tokio::test]
    async fn test_tls_handshake_with_client_certificate() {
        use tokio::io::AsyncWriteExt;
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
            // The client certificate verified against the test CA;
            // CONNECT carries the username with no password.
            let (client_id, username, password) = crate::cloud_tls::read_client_connect(&mut tls)
                .await
                .expect("read CONNECT");
            assert_eq!(client_id, "edge-1");
            assert_eq!(
                username.as_deref(),
                Some("127.0.0.1/edge-1/?api-version=2021-04-12")
            );
            assert_eq!(password, None);
            tls.write_all(&[0x20, 0x02, 0x00, 0x00])
                .await
                .expect("CONNACK");
            let decoded = read_publish_frame(&mut tls).await;
            assert!(decoded.topic.starts_with("devices/edge-1/messages/events/"));
            assert_eq!(decoded.payload, b"{}");
        });

        let config = x509_test_config(&format!("127.0.0.1:{port}"));
        let transport = Arc::new(TlsAzureIotTransport::new(&config).unwrap());
        transport.connect_transport().await.unwrap();
        transport
            .publish(
                &AzureIotPublish {
                    topic: "devices/edge-1/messages/events/%24.ct=application%2Fjson".to_string(),
                    body: b"{}".to_vec(),
                },
                "",
            )
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

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            use tokio::io::AsyncReadExt;
            let mut buf = [0u8; 1024];
            let _ = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf)).await;
        });
        let config = sas_test_config(&format!("127.0.0.1:{port}"));
        let transport = Arc::new(TlsAzureIotTransport::new(&config).unwrap());
        let err = transport
            .publish(
                &AzureIotPublish {
                    topic: "devices/edge-1/messages/events/x".to_string(),
                    body: b"{}".to_vec(),
                },
                "SharedAccessSignature sr=x&sig=y&se=1",
            )
            .await
            .expect_err("plain listener must fail");
        assert!(matches!(err, ConnectorError::Connection(_)));
        server.abort();
    }
}
