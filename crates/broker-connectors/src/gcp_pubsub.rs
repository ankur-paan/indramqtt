//! Google Cloud Pub/Sub sink (INDRA-199).
//!
//! Buffers MQTT events and publishes them with `POST
//! /v1/projects/{project}/topics/{topic}:publish`: base64 data,
//! optional per-message ordering keys, and templated attributes
//! (`mqtt_topic` / `mqtt_qos` are always injected). Retries cover HTTP
//! 429 and 500..=504 with jittered backoff; other non-2xx statuses
//! are terminal dispatch failures.
//!
//! Authentication: `None` (emulator), `AccessToken` (raw bearer), or
//! `ServiceAccountKey`, which mints RS256 JWT assertions and exchanges
//! them at the OAuth2 token endpoint with an expiring in-memory cache
//! (fully in-memory testable against a loopback fake endpoint).

use async_trait::async_trait;
use base64::Engine;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::{now_millis, render_template, BackoffState, BatchQueue, ConnectorError, Result, Sink};

pub const GCP_PUBSUB_SCOPE: &str = "https://www.googleapis.com/auth/pubsub";
pub const GCP_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

/// GCP authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase", tag = "type")]
pub enum GcpAuth {
    /// No `Authorization` header (emulator / mock testing).
    #[default]
    None,
    /// Raw OAuth2 access token (`Authorization: Bearer <token>`).
    AccessToken { token: String },
    /// Service-account key: RS256 JWT assertions exchanged for access
    /// tokens (cached to 60s before expiry).
    ServiceAccountKey {
        client_email: String,
        private_key_pem: String,
    },
}

impl GcpAuth {
    /// Static bearer header without network (None for `None` and
    /// `ServiceAccountKey`, whose token needs minting/exchange).
    pub fn static_bearer(&self) -> Result<Option<String>> {
        match self {
            Self::None => Ok(None),
            Self::AccessToken { token } => {
                if token.trim().is_empty() {
                    return Err(ConnectorError::Dispatch(
                        "gcp access token must not be empty".to_string(),
                    ));
                }
                Ok(Some(format!("Bearer {token}")))
            }
            Self::ServiceAccountKey { .. } => Ok(None),
        }
    }
}

/// JWT assertion claims for the OAuth2 JWT-bearer grant.
#[derive(Debug, Serialize, Deserialize)]
struct JwtAssertionClaims {
    iss: String,
    scope: String,
    aud: String,
    exp: u64,
    iat: u64,
}

/// Mint an RS256 JWT assertion for `client_email` valid for one hour
/// from `now_secs`. Pure function: unit-testable without network.
pub fn build_jwt_assertion(
    client_email: &str,
    private_key_pem: &str,
    now_secs: u64,
) -> Result<String> {
    if client_email.trim().is_empty() {
        return Err(ConnectorError::Dispatch(
            "gcp client_email must not be empty".to_string(),
        ));
    }
    let claims = JwtAssertionClaims {
        iss: client_email.to_string(),
        scope: GCP_PUBSUB_SCOPE.to_string(),
        aud: GCP_TOKEN_URL.to_string(),
        exp: now_secs.saturating_add(3_600),
        iat: now_secs,
    };
    let key = jsonwebtoken::EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
        .map_err(|e| ConnectorError::Dispatch(format!("gcp private key rejected: {e}")))?;
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
        &claims,
        &key,
    )
    .map_err(|e| ConnectorError::Dispatch(format!("gcp JWT signing failed: {e}")))
}

/// Expiring OAuth2 access-token cache for service-account keys.
pub struct GcpTokenCache {
    client_email: String,
    private_key_pem: String,
    token_url: String,
    client: reqwest::Client,
    cached: parking_lot::Mutex<Option<(String, u64)>>,
}

impl GcpTokenCache {
    pub fn new(client_email: String, private_key_pem: String, client: reqwest::Client) -> Self {
        Self {
            client_email,
            private_key_pem,
            token_url: GCP_TOKEN_URL.to_string(),
            client,
            cached: parking_lot::Mutex::new(None),
        }
    }

    /// Override the token endpoint (loopback fakes in tests).
    pub fn with_token_url(mut self, url: impl Into<String>) -> Self {
        self.token_url = url.into();
        self
    }

    /// Bearer access token, reusing the cache until 60s before expiry.
    pub async fn bearer_token(&self) -> Result<String> {
        let now = now_millis().max(0) as u64 / 1_000;
        if let Some((token, exp)) = self.cached.lock().clone() {
            if now + 60 < exp {
                return Ok(token);
            }
        }
        let assertion = build_jwt_assertion(&self.client_email, &self.private_key_pem, now)?;
        let response = self
            .client
            .post(&self.token_url)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", assertion.as_str()),
            ])
            .send()
            .await
            .map_err(|e| ConnectorError::Connection(format!("gcp token exchange failed: {e}")))?;
        if !response.status().is_success() {
            return Err(ConnectorError::Dispatch(format!(
                "gcp token exchange answered {}",
                response.status()
            )));
        }
        let doc: serde_json::Value = response.json().await.map_err(|e| {
            ConnectorError::Connection(format!("gcp token response unreadable: {e}"))
        })?;
        let token = doc
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ConnectorError::Connection("gcp token response lacks access_token".to_string())
            })?
            .to_string();
        let expires_in = doc
            .get("expires_in")
            .and_then(|v| v.as_u64())
            .unwrap_or(3_600);
        *self.cached.lock() = Some((token.clone(), now.saturating_add(expires_in)));
        Ok(token)
    }
}

fn default_endpoint() -> Option<String> {
    None
}

fn default_batch_size() -> Option<usize> {
    Some(1_000)
}

fn default_batch_bytes() -> Option<usize> {
    Some(8_388_608)
}

fn default_linger_ms() -> Option<u64> {
    Some(10)
}

fn default_max_retries() -> Option<usize> {
    Some(3)
}

fn default_initial_backoff_ms() -> Option<u64> {
    Some(100)
}

fn default_max_backoff_ms() -> Option<u64> {
    Some(2_000)
}

fn is_resource_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (3..=255).contains(&bytes.len())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

/// GCP Pub/Sub sink configuration. All depths are optional (`None` =
/// unbounded) with zero clamped ceilings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcpPubSubSinkConfig {
    /// GCP project id, e.g. `my-iot-project`.
    pub project_id: String,
    /// Pub/Sub topic id, e.g. `telemetry-events`.
    pub topic_id: String,
    /// Endpoint override (emulator); defaults to pubsub.googleapis.com.
    #[serde(default = "default_endpoint")]
    pub endpoint: Option<String>,
    /// Authentication (default none).
    #[serde(default)]
    pub auth: GcpAuth,
    /// Ordering key template (`${client_id}`, `${topic}`, ...).
    #[serde(default)]
    pub ordering_key_template: Option<String>,
    /// Custom attributes with template substitution.
    #[serde(default)]
    pub attributes: HashMap<String, String>,
    /// Messages per publish call (default 1000).
    #[serde(default = "default_batch_size")]
    pub batch_size: Option<usize>,
    /// Batch byte limit (default 8 MiB).
    #[serde(default = "default_batch_bytes")]
    pub batch_bytes: Option<usize>,
    /// Linger flush window in ms (default 10).
    #[serde(default = "default_linger_ms")]
    pub linger_ms: Option<u64>,
    /// Retries on 429/500..=504 (default 3, `None` unbounded, 0 none).
    #[serde(default = "default_max_retries")]
    pub max_retries: Option<usize>,
    /// First retry delay in ms (default 100).
    #[serde(default = "default_initial_backoff_ms")]
    pub initial_backoff_ms: Option<u64>,
    /// Retry delay ceiling in ms (default 2000).
    #[serde(default = "default_max_backoff_ms")]
    pub max_backoff_ms: Option<u64>,
    /// Request timeout in ms (default 5000).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

impl GcpPubSubSinkConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.unwrap_or(5000).max(1))
    }

    pub fn validate(&self) -> Result<()> {
        if !is_resource_id(&self.project_id) {
            return Err(ConnectorError::Dispatch(format!(
                "gcp project_id must be 3..=255 [a-z0-9-]: {:?}",
                self.project_id
            )));
        }
        if !is_resource_id(&self.topic_id) {
            return Err(ConnectorError::Dispatch(format!(
                "gcp topic_id must be 3..=255 [a-z0-9-]: {:?}",
                self.topic_id
            )));
        }
        if let Some(endpoint) = &self.endpoint {
            if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
                return Err(ConnectorError::Dispatch(format!(
                    "gcp endpoint must be http(s): {endpoint:?}"
                )));
            }
        }
        match &self.auth {
            GcpAuth::None => {}
            GcpAuth::AccessToken { token } => {
                if token.trim().is_empty() {
                    return Err(ConnectorError::Dispatch(
                        "gcp access token must not be empty".to_string(),
                    ));
                }
            }
            GcpAuth::ServiceAccountKey {
                client_email,
                private_key_pem,
            } => {
                if client_email.trim().is_empty() || private_key_pem.trim().is_empty() {
                    return Err(ConnectorError::Dispatch(
                        "gcp service account needs email + private key".to_string(),
                    ));
                }
            }
        }
        if let Some(template) = &self.ordering_key_template {
            self.event_vars("dummy", b"{}", QoS::AtMostOnce, 0, template)?;
        }
        for (name, template) in &self.attributes {
            if name.trim().is_empty() {
                return Err(ConnectorError::Dispatch(
                    "gcp attribute names must not be empty".to_string(),
                ));
            }
            self.event_vars("dummy", b"{}", QoS::AtMostOnce, 0, template)?;
        }
        if self.batch_size == Some(0) {
            return Err(ConnectorError::Dispatch(
                "gcp batch_size must be >= 1".to_string(),
            ));
        }
        if self.batch_bytes == Some(0) {
            return Err(ConnectorError::Dispatch(
                "gcp batch_bytes must be >= 1".to_string(),
            ));
        }
        Ok(())
    }

    pub fn base_url(&self) -> String {
        match &self.endpoint {
            Some(endpoint) => endpoint.trim_end_matches('/').to_string(),
            None => "https://pubsub.googleapis.com".to_string(),
        }
    }

    /// `POST {base}/v1/projects/{project}/topics/{topic}:publish`.
    pub fn publish_url(&self) -> String {
        format!(
            "{}/v1/projects/{}/topics/{}:publish",
            self.base_url(),
            self.project_id,
            self.topic_id
        )
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

    /// Template variables for one event. `${client_id}` resolves from
    /// the JSON `client_id` field when present, else empty.
    fn template_vars(topic: &str, payload: &[u8], qos: QoS, millis: i64) -> Vec<(String, String)> {
        let doc: serde_json::Value = serde_json::from_slice(payload).unwrap_or_default();
        let field = |name: &str| match doc.get(name) {
            Some(serde_json::Value::String(text)) => text.clone(),
            Some(scalar) if scalar.is_number() || scalar.is_boolean() => scalar.to_string(),
            _ => String::new(),
        };
        let vars = vec![
            ("topic".to_string(), topic.to_string()),
            ("client_id".to_string(), field("client_id")),
            ("qos".to_string(), u8::from(qos).to_string()),
            ("timestamp".to_string(), millis.to_string()),
        ];
        vars
    }

    /// Render a template for one event, supporting `${payload.<name>}`
    /// extraction on top of the base variables.
    fn event_vars(
        &self,
        topic: &str,
        payload: &[u8],
        qos: QoS,
        millis: i64,
        template: &str,
    ) -> Result<String> {
        let mut vars = Self::template_vars(topic, payload, qos, millis);
        let doc: serde_json::Value = serde_json::from_slice(payload).unwrap_or_default();
        let mut rest = template;
        while let Some(start) = rest.find("${payload.") {
            let after = &rest[start + "${payload.".len()..];
            if let Some(close) = after.find('}') {
                let name = &after[..close];
                let value = match doc.get(name) {
                    Some(serde_json::Value::String(text)) => text.clone(),
                    Some(scalar) if scalar.is_number() || scalar.is_boolean() => scalar.to_string(),
                    _ => String::new(),
                };
                vars.push((format!("payload.{name}"), value));
                rest = &after[close + 1..];
            } else {
                break;
            }
        }
        let borrowed: Vec<(&str, String)> =
            vars.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
        render_template(template, &borrowed)
    }
}

// ---------------------------------------------------------------------------
// Wire framing.
// ---------------------------------------------------------------------------

/// One Pub/Sub message on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcpPubSubMessage {
    pub data_b64: String,
    pub ordering_key: Option<String>,
    pub attributes: HashMap<String, String>,
}

/// Render the `:publish` JSON body for messages.
pub fn render_publish_body(messages: &[GcpPubSubMessage]) -> Vec<u8> {
    let mut body = String::from("{\"messages\":[");
    for (index, message) in messages.iter().enumerate() {
        if index > 0 {
            body.push(',');
        }
        body.push_str("{\"data\":");
        body.push_str(&serde_json::to_string(&message.data_b64).unwrap_or_default());
        if let Some(key) = &message.ordering_key {
            body.push_str(",\"orderingKey\":");
            body.push_str(&serde_json::to_string(key).unwrap_or_default());
        }
        body.push_str(",\"attributes\":{");
        let mut keys: Vec<&String> = message.attributes.keys().collect();
        keys.sort();
        for (attr_index, key) in keys.iter().enumerate() {
            if attr_index > 0 {
                body.push(',');
            }
            body.push_str(&serde_json::to_string(key).unwrap_or_default());
            body.push(':');
            body.push_str(&serde_json::to_string(&message.attributes[*key]).unwrap_or_default());
        }
        body.push_str("}}");
    }
    body.push_str("]}");
    body.into_bytes()
}

/// Parse a `:publish` response body into message ids.
pub fn parse_publish_response(body: &[u8]) -> Result<Vec<String>> {
    let doc: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| ConnectorError::Connection(format!("gcp bad publish response: {e}")))?;
    doc.get("messageIds")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            ConnectorError::Connection("gcp publish response lacks messageIds".to_string())
        })?
        .iter()
        .map(|id| {
            id.as_str()
                .map(str::to_string)
                .ok_or_else(|| ConnectorError::Connection("gcp messageId not a string".to_string()))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Transport.
// ---------------------------------------------------------------------------

/// Scripted outcome for the mock transport.
#[derive(Debug, Clone)]
pub enum MockGcpOutcome {
    /// 200 with these message ids.
    Ids(Vec<String>),
    /// HTTP failure (429/500..=504 retry the batch).
    HttpStatus(u16),
    /// Transport failure (restores immediately, no in-loop retry).
    TransportError(String),
}

/// One captured publish call.
#[derive(Debug, Clone)]
pub struct CapturedGcpPublish {
    pub project: String,
    pub topic: String,
    pub messages: Vec<GcpPubSubMessage>,
    pub auth: Option<String>,
}

#[async_trait]
pub trait GcpPubSubTransport: Send + Sync {
    async fn publish(
        &self,
        project: &str,
        topic: &str,
        messages: Vec<GcpPubSubMessage>,
        auth: Option<String>,
    ) -> Result<Vec<String>>;
}

/// In-memory transport with scripted outcomes (tests, dry runs).
#[derive(Debug, Default)]
pub struct MockGcpPubSubTransport {
    scripted: parking_lot::Mutex<std::collections::VecDeque<MockGcpOutcome>>,
    captured: parking_lot::Mutex<Vec<CapturedGcpPublish>>,
    calls: AtomicU64,
}

impl MockGcpPubSubTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue outcomes consumed in order (default: synthetic ids).
    pub fn script_outcomes(&self, outcomes: Vec<MockGcpOutcome>) {
        *self.scripted.lock() = outcomes.into_iter().collect();
    }

    pub fn captured(&self) -> Vec<CapturedGcpPublish> {
        self.captured.lock().clone()
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl GcpPubSubTransport for MockGcpPubSubTransport {
    async fn publish(
        &self,
        project: &str,
        topic: &str,
        messages: Vec<GcpPubSubMessage>,
        auth: Option<String>,
    ) -> Result<Vec<String>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let call_index = self.calls.load(Ordering::SeqCst);
        self.captured.lock().push(CapturedGcpPublish {
            project: project.to_string(),
            topic: topic.to_string(),
            messages: messages.clone(),
            auth,
        });
        match self.scripted.lock().pop_front() {
            None => Ok((0..messages.len())
                .map(|index| format!("msg-{call_index}-{index}"))
                .collect()),
            Some(MockGcpOutcome::Ids(ids)) => Ok(ids),
            Some(MockGcpOutcome::HttpStatus(status)) => Err(match status {
                429 | 500..=504 => {
                    ConnectorError::Connection(format!("mock gcp throttled with {status}"))
                }
                _ => ConnectorError::Dispatch(format!("mock gcp failed with {status}")),
            }),
            Some(MockGcpOutcome::TransportError(message)) => {
                Err(ConnectorError::Connection(message))
            }
        }
    }
}

/// Production transport: signed `POST {publish-url}` with JSON.
pub struct HttpGcpPubSubTransport {
    url: String,
    token_cache: Option<Arc<GcpTokenCache>>,
    static_bearer: Option<String>,
    client: reqwest::Client,
}

impl HttpGcpPubSubTransport {
    pub fn new(config: &GcpPubSubSinkConfig, client: reqwest::Client) -> Result<Self> {
        config.validate()?;
        let (token_cache, static_bearer) = match &config.auth {
            GcpAuth::None => (None, None),
            GcpAuth::AccessToken { token } => (None, Some(format!("Bearer {token}"))),
            GcpAuth::ServiceAccountKey {
                client_email,
                private_key_pem,
            } => (
                Some(Arc::new(GcpTokenCache::new(
                    client_email.clone(),
                    private_key_pem.clone(),
                    client.clone(),
                ))),
                None,
            ),
        };
        Ok(Self {
            url: config.publish_url(),
            token_cache,
            static_bearer,
            client,
        })
    }
}

#[async_trait]
impl GcpPubSubTransport for HttpGcpPubSubTransport {
    async fn publish(
        &self,
        _project: &str,
        _topic: &str,
        messages: Vec<GcpPubSubMessage>,
        _auth: Option<String>,
    ) -> Result<Vec<String>> {
        let bearer = match &self.token_cache {
            Some(cache) => Some(format!("Bearer {}", cache.bearer_token().await?)),
            None => self.static_bearer.clone(),
        };
        let mut request = self
            .client
            .post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(render_publish_body(&messages));
        if let Some(bearer) = bearer {
            request = request.header(reqwest::header::AUTHORIZATION, bearer);
        }
        let response = request
            .send()
            .await
            .map_err(|e| ConnectorError::Connection(format!("gcp publish failed: {e}")))?;
        let status = response.status().as_u16();
        if status == 429 || (500..=504).contains(&status) {
            return Err(ConnectorError::Connection(format!(
                "gcp publish throttled with {status}"
            )));
        }
        if !(200..=299).contains(&status) {
            return Err(ConnectorError::Dispatch(format!(
                "gcp publish failed with {status}"
            )));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|e| ConnectorError::Connection(format!("gcp read failed: {e}")))?;
        parse_publish_response(&bytes)
    }
}

// ---------------------------------------------------------------------------
// Sink.
// ---------------------------------------------------------------------------

/// One buffered event.
#[derive(Debug, Clone)]
struct GcpRow {
    topic: String,
    payload: Vec<u8>,
    qos: u8,
    millis: i64,
}

struct GcpBuffer {
    queue: BatchQueue<GcpRow>,
    bytes: usize,
}

/// GCP Pub/Sub sink: buffers events, publishes batches with retry.
pub struct GcpPubSubSink {
    config: GcpPubSubSinkConfig,
    transport: Arc<dyn GcpPubSubTransport>,
    buffer: parking_lot::Mutex<GcpBuffer>,
    backoff: parking_lot::Mutex<BackoffState>,
    sent_batches: AtomicU64,
    sent_records: AtomicU64,
}

impl GcpPubSubSink {
    pub fn new(
        config: GcpPubSubSinkConfig,
        transport: Arc<dyn GcpPubSubTransport>,
    ) -> Result<Self> {
        config.validate()?;
        let linger = config.effective_linger();
        Ok(Self {
            buffer: parking_lot::Mutex::new(GcpBuffer {
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

    pub fn config(&self) -> &GcpPubSubSinkConfig {
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
        let max = self.config.max_backoff_ms.unwrap_or(2_000).max(1);
        let grown = initial
            .saturating_mul(2u64.saturating_pow(attempt.min(10) as u32))
            .min(max);
        let jitter = (now_millis().max(0) as u64) % (grown / 2 + 1);
        Duration::from_millis(grown.saturating_add(jitter).min(max.saturating_mul(2)))
    }

    /// Build wire messages for rows (ordering keys + attributes).
    fn messages_for(&self, rows: &[GcpRow]) -> Result<Vec<GcpPubSubMessage>> {
        rows.iter()
            .map(|row| {
                let ordering_key = match &self.config.ordering_key_template {
                    Some(template) => Some(self.config.event_vars(
                        &row.topic,
                        &row.payload,
                        qos_from(row.qos),
                        row.millis,
                        template,
                    )?),
                    None => None,
                };
                let mut attributes = HashMap::new();
                attributes.insert("mqtt_topic".to_string(), row.topic.clone());
                attributes.insert("mqtt_qos".to_string(), row.qos.to_string());
                for (name, template) in &self.config.attributes {
                    attributes.insert(
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
                Ok(GcpPubSubMessage {
                    data_b64: base64::engine::general_purpose::STANDARD.encode(&row.payload),
                    ordering_key,
                    attributes,
                })
            })
            .collect()
    }

    /// Flush buffered rows (no-op when empty). 429/500..=504 retry in
    /// place up to `max_retries`; terminal and transport failures
    /// restore the buffer, engage backoff, and propagate.
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
        let messages = self.messages_for(&rows)?;
        let auth = self.config.auth.static_bearer()?;
        let record_count = rows.len() as u64;
        let max_retries = self.config.max_retries.unwrap_or(usize::MAX);
        let mut attempt = 0usize;
        loop {
            match self
                .transport
                .publish(
                    &self.config.project_id,
                    &self.config.topic_id,
                    messages.clone(),
                    auth.clone(),
                )
                .await
            {
                Ok(_) => {
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
        rows: Vec<GcpRow>,
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
                "gcp row requires a non-empty topic".to_string(),
            ));
        }
        // Message data is binary-safe; UTF-8 is not required.
        let row = GcpRow {
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
impl Sink for GcpPubSubSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        if self.buffer_row(topic, payload, qos)? {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "gcp_pubsub"
    }
}

/// Management connector handle pairing an id with a Pub/Sub sink.
pub struct GcpPubSubConnector {
    id: String,
    sink: Arc<GcpPubSubSink>,
}

impl GcpPubSubConnector {
    pub fn new(id: impl Into<String>, sink: Arc<GcpPubSubSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }
}

impl super::Connector for GcpPubSubConnector {
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
    use crate::test_rsa_keys::{PRIVATE_PEM as TEST_PRIVATE_PEM, PUBLIC_PEM as TEST_PUBLIC_PEM};
    use crate::Sink;

    fn test_config() -> GcpPubSubSinkConfig {
        GcpPubSubSinkConfig {
            project_id: "my-iot-project".to_string(),
            topic_id: "telemetry-events".to_string(),
            endpoint: None,
            auth: GcpAuth::None,
            ordering_key_template: Some("${client_id}".to_string()),
            attributes: HashMap::from([
                ("source".to_string(), "indramqtt".to_string()),
                ("device".to_string(), "${payload.device_id}".to_string()),
            ]),
            batch_size: Some(1_000),
            batch_bytes: Some(8_388_608),
            linger_ms: Some(10),
            max_retries: Some(3),
            initial_backoff_ms: Some(100),
            max_backoff_ms: Some(2_000),
        }
    }

    fn test_sink(config: GcpPubSubSinkConfig) -> (Arc<GcpPubSubSink>, Arc<MockGcpPubSubTransport>) {
        let transport = Arc::new(MockGcpPubSubTransport::new());
        let sink = Arc::new(GcpPubSubSink::new(config, transport.clone()).unwrap());
        (sink, transport)
    }

    #[test]
    fn test_config_validation() {
        let mut config = test_config();
        assert!(config.validate().is_ok());
        assert_eq!(
            config.publish_url(),
            "https://pubsub.googleapis.com/v1/projects/my-iot-project/topics/telemetry-events:publish"
        );

        config.project_id = "UPPER".to_string();
        assert!(config.validate().is_err());
        config.project_id = "ab".to_string();
        assert!(config.validate().is_err());
        config.project_id = "my-iot-project".to_string();

        config.topic_id = "has/slash".to_string();
        assert!(config.validate().is_err());
        config.topic_id = "telemetry-events".to_string();

        config.endpoint = Some("pubsub:8085".to_string());
        assert!(config.validate().is_err());
        config.endpoint = Some("http://127.0.0.1:8085".to_string());
        assert!(config.validate().is_ok());
        assert!(config
            .publish_url()
            .starts_with("http://127.0.0.1:8085/v1/"));
        config.endpoint = None;

        config.auth = GcpAuth::AccessToken {
            token: "  ".to_string(),
        };
        assert!(config.validate().is_err());
        config.auth = GcpAuth::ServiceAccountKey {
            client_email: "a@b.iam.gserviceaccount.com".to_string(),
            private_key_pem: "pem".to_string(),
        };
        assert!(config.validate().is_ok());
        config.auth = GcpAuth::None;

        config.ordering_key_template = Some("${nope}".to_string());
        assert!(config.validate().is_err());
        config.ordering_key_template = None;

        config.batch_size = Some(0);
        assert!(config.validate().is_err());
        // Unbounded + huge depths accepted: zero clamped ceilings.
        config.batch_size = None;
        config.batch_bytes = Some(10_000_000);
        config.max_retries = None;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_jwt_assertion_signs_and_verifies() {
        let now = now_millis().max(0) as u64 / 1_000;
        let token =
            build_jwt_assertion("bot@example.iam.gserviceaccount.com", TEST_PRIVATE_PEM, now)
                .expect("signs");
        assert_eq!(token.split('.').count(), 3);
        // Independent verification with the public half (jsonwebtoken).
        let key = jsonwebtoken::DecodingKey::from_rsa_pem(TEST_PUBLIC_PEM.as_bytes()).unwrap();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_audience(&[GCP_TOKEN_URL]);
        let data = jsonwebtoken::decode::<JwtAssertionClaims>(&token, &key, &validation)
            .expect("verifies");
        assert_eq!(data.claims.iss, "bot@example.iam.gserviceaccount.com");
        assert_eq!(data.claims.scope, GCP_PUBSUB_SCOPE);
        assert_eq!(data.claims.exp, now + 3_600);
        assert_eq!(data.claims.iat, now);
        // Header pins RS256.
        let header = jsonwebtoken::decode_header(&token).unwrap();
        assert_eq!(header.alg, jsonwebtoken::Algorithm::RS256);

        assert!(build_jwt_assertion("", TEST_PRIVATE_PEM, now).is_err());
        assert!(build_jwt_assertion("a@b", "not-a-key", now).is_err());
    }

    #[tokio::test]
    async fn test_token_cache_caches_and_refreshes() {
        use axum::{http::StatusCode, routing::post, Router};
        use std::sync::atomic::{AtomicU64 as StdAtomicU64, Ordering as StdOrdering};

        let hits = Arc::new(StdAtomicU64::new(0));
        let hits_route = hits.clone();
        let app = Router::new().route(
            "/token",
            post(move || {
                let hits = hits_route.clone();
                async move {
                    hits.fetch_add(1, StdOrdering::SeqCst);
                    (
                        StatusCode::OK,
                        "{\"access_token\":\"tok-1\",\"expires_in\":3600}",
                    )
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        let cache = GcpTokenCache::new(
            "bot@example.iam.gserviceaccount.com".to_string(),
            TEST_PRIVATE_PEM.to_string(),
            reqwest::Client::new(),
        )
        .with_token_url(format!("http://127.0.0.1:{port}/token"));
        assert_eq!(cache.bearer_token().await.unwrap(), "tok-1");
        // Cached: no second HTTP call.
        assert_eq!(cache.bearer_token().await.unwrap(), "tok-1");
        assert_eq!(hits.load(StdOrdering::SeqCst), 1);
        // Expired cache refetches.
        *cache.cached.lock() = Some(("stale".to_string(), 1));
        assert_eq!(cache.bearer_token().await.unwrap(), "tok-1");
        assert_eq!(hits.load(StdOrdering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_publish_framing() {
        let (sink, transport) = test_sink(test_config());
        sink.send(
            &Topic::new("factory/line1/temp").unwrap(),
            &Bytes::from_static(br#"{"client_id":"device-001","device_id":"device-001","v":21.5}"#),
            QoS::AtLeastOnce,
        )
        .await
        .unwrap();
        sink.flush().await.unwrap();

        let captured = transport.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].project, "my-iot-project");
        assert_eq!(captured[0].topic, "telemetry-events");
        assert_eq!(captured[0].auth, None);
        assert_eq!(captured[0].messages.len(), 1);
        let message = &captured[0].messages[0];
        // Base64 decodes back to the exact payload.
        let payload = base64::engine::general_purpose::STANDARD
            .decode(&message.data_b64)
            .unwrap();
        assert_eq!(
            payload,
            br#"{"client_id":"device-001","device_id":"device-001","v":21.5}"#
        );
        assert_eq!(message.ordering_key.as_deref(), Some("device-001"));
        assert_eq!(
            message.attributes.get("mqtt_topic").map(String::as_str),
            Some("factory/line1/temp")
        );
        assert_eq!(
            message.attributes.get("mqtt_qos").map(String::as_str),
            Some("1")
        );
        assert_eq!(
            message.attributes.get("source").map(String::as_str),
            Some("indramqtt")
        );
        assert_eq!(
            message.attributes.get("device").map(String::as_str),
            Some("device-001")
        );
        assert_eq!(sink.sent_records(), 1);

        // Rendered body shape matches the Pub/Sub contract.
        let body = String::from_utf8(render_publish_body(&captured[0].messages)).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(doc["messages"][0]["orderingKey"], "device-001");
        assert_eq!(
            doc["messages"][0]["attributes"]["mqtt_topic"],
            "factory/line1/temp"
        );
    }

    #[tokio::test]
    async fn test_absent_ordering_key_omitted() {
        let mut config = test_config();
        config.ordering_key_template = None;
        let (sink, transport) = test_sink(config);
        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from("{}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        sink.flush().await.unwrap();
        let captured = transport.captured();
        assert_eq!(captured[0].messages[0].ordering_key, None);
        let body = String::from_utf8(render_publish_body(&captured[0].messages)).unwrap();
        assert!(!body.contains("orderingKey"));
    }

    #[tokio::test]
    async fn test_retry_on_429_then_success() {
        let mut config = test_config();
        config.batch_size = Some(10);
        config.initial_backoff_ms = Some(1);
        config.max_backoff_ms = Some(2);
        let (sink, transport) = test_sink(config);
        transport.script_outcomes(vec![
            MockGcpOutcome::HttpStatus(429),
            MockGcpOutcome::Ids(vec!["msg-1".to_string()]),
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
        assert_eq!(sink.sent_batches(), 1);
        assert_eq!(sink.buffered_rows(), 0);
    }

    #[tokio::test]
    async fn test_terminal_and_transport_failures() {
        // 403: terminal, single attempt, buffer retained.
        let mut config = test_config();
        config.batch_size = Some(10);
        config.max_retries = Some(5);
        let (sink, transport) = test_sink(config);
        transport.script_outcomes(vec![
            MockGcpOutcome::HttpStatus(403),
            MockGcpOutcome::Ids(vec!["msg-1".to_string()]),
        ]);
        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from("{}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        let err = sink.flush().await.expect_err("403 must fail");
        assert!(matches!(err, ConnectorError::Dispatch(_)));
        assert_eq!(transport.calls(), 1);
        assert_eq!(sink.buffered_rows(), 1);

        // Transport errors retry in-loop like throttles: exhaust them
        // (default max_retries 3 -> 4 attempts) then restore + back off.
        let (sink, transport) = test_sink(test_config());
        transport.script_outcomes(vec![
            MockGcpOutcome::TransportError("down".to_string()),
            MockGcpOutcome::TransportError("down".to_string()),
            MockGcpOutcome::TransportError("down".to_string()),
            MockGcpOutcome::TransportError("down".to_string()),
        ]);
        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from("{}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        let err = sink.flush().await.expect_err("transport down must fail");
        assert!(matches!(err, ConnectorError::Connection(_)));
        assert_eq!(transport.calls(), 4);
        assert_eq!(sink.buffered_rows(), 1);
        let calls = transport.calls();
        assert!(sink.flush().await.is_err());
        assert_eq!(transport.calls(), calls);
    }

    #[test]
    fn test_response_parsing() {
        assert_eq!(
            parse_publish_response(br#"{"messageIds":["msg-1","msg-2"]}"#).unwrap(),
            vec!["msg-1".to_string(), "msg-2".to_string()]
        );
        assert!(parse_publish_response(br#"{}"#).is_err());
        assert!(parse_publish_response(b"nope").is_err());
    }
}
