//! Industrial-grade HTTP webhook / REST sink (INDRA-192).
//!
//! An enterprise counterpart to the minimal [`super::HttpWebhookSink`]:
//! templated URLs/headers, Basic/Bearer/ApiKey auth, single-event and
//! micro-batch body formats, HMAC request signatures computed over the
//! exact serialized body bytes, and retry with exponential backoff and
//! jitter. Batching, restore-on-failure and fail-fast backoff reuse the
//! shared [`super::BatchQueue`] / [`super::BackoffState`] helpers.
//!
//! Retryable statuses are 429 and 500..=504; 400/401/403/404 fail
//! immediately without retry. Every other non-2xx status is a terminal
//! dispatch failure. All limits are `Option`-typed: `None` means
//! unbounded, with zero clamped ceilings.

use async_trait::async_trait;
use base64::Engine;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::{now_millis, render_template, BackoffState, BatchQueue, ConnectorError, Result, Sink};

/// HTTP method for webhook delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum HttpMethod {
    #[default]
    Post,
    Put,
    Patch,
}

impl HttpMethod {
    /// Uppercase wire name (`POST`, `PUT`, `PATCH`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
        }
    }
}

/// Webhook authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase", tag = "type")]
pub enum HttpAuth {
    /// No `Authorization` header.
    #[default]
    None,
    /// `Authorization: Basic base64(username:password)`.
    Basic { username: String, password: String },
    /// `Authorization: Bearer <token>`.
    Bearer { token: String },
    /// Custom header carrying the raw key.
    ApiKey { header_name: String, key: String },
}

impl HttpAuth {
    /// Extra request headers for this auth scheme (empty for `None`).
    pub fn headers(&self) -> Result<Vec<(String, String)>> {
        match self {
            Self::None => Ok(Vec::new()),
            Self::Basic { username, password } => {
                if username.is_empty() {
                    return Err(ConnectorError::Dispatch(
                        "webhook basic auth needs a username".to_string(),
                    ));
                }
                let credentials = base64::engine::general_purpose::STANDARD
                    .encode(format!("{username}:{password}"));
                Ok(vec![(
                    "Authorization".to_string(),
                    format!("Basic {credentials}"),
                )])
            }
            Self::Bearer { token } => {
                if token.trim().is_empty() {
                    return Err(ConnectorError::Dispatch(
                        "webhook bearer token must not be empty".to_string(),
                    ));
                }
                Ok(vec![(
                    "Authorization".to_string(),
                    format!("Bearer {token}"),
                )])
            }
            Self::ApiKey { header_name, key } => {
                if header_name.trim().is_empty() || key.trim().is_empty() {
                    return Err(ConnectorError::Dispatch(
                        "webhook api key needs a header name and key".to_string(),
                    ));
                }
                Ok(vec![(header_name.clone(), key.clone())])
            }
        }
    }
}

/// Request body encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum HttpBodyFormat {
    /// One request per event carrying the projected JSON verbatim.
    #[default]
    RawJson,
    /// One request per flush carrying `[ {...}, {...} ]`.
    JsonBatchArray,
    /// One request per event, `application/x-www-form-urlencoded`.
    FormUrlEncoded,
}

/// HMAC signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HmacAlgorithm {
    Sha256,
    Sha1,
}

/// Signature output encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HmacEncoding {
    Hex,
    Base64,
}

/// HMAC request signature computed over the exact serialized body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpHmacSignature {
    /// Header key, e.g. `X-Signature-SHA256`.
    pub header_name: String,
    pub algorithm: HmacAlgorithm,
    pub secret: String,
    pub encoding: HmacEncoding,
}

impl HttpHmacSignature {
    pub fn validate(&self) -> Result<()> {
        if self.header_name.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "webhook signature header_name must not be empty".to_string(),
            ));
        }
        if self.secret.is_empty() {
            return Err(ConnectorError::Dispatch(
                "webhook signature secret must not be empty".to_string(),
            ));
        }
        Ok(())
    }

    /// Sign `body` with the configured algorithm + encoding.
    pub fn sign(&self, body: &[u8]) -> String {
        let tag = match self.algorithm {
            HmacAlgorithm::Sha256 => hmac_sha256(self.secret.as_bytes(), body),
            HmacAlgorithm::Sha1 => hmac_sha1(self.secret.as_bytes(), body),
        };
        match self.encoding {
            HmacEncoding::Hex => tag.iter().map(|b| format!("{b:02x}")).collect(),
            HmacEncoding::Base64 => base64::engine::general_purpose::STANDARD.encode(tag),
        }
    }
}

/// HMAC-SHA256 via the sha2 crate (shared shape with the S3 signer).
fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    const BLOCK: usize = 64;
    let mut key_block = [0u8; BLOCK];
    if key.len() > BLOCK {
        let digest = Sha256::digest(key);
        key_block[..digest.len()].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    outer.finalize().to_vec()
}

/// HMAC-SHA1 via the sha1 crate (GitHub-style `X-Hub-Signature-256`
/// uses SHA-256; SHA-1 covers legacy receivers).
fn hmac_sha1(key: &[u8], message: &[u8]) -> Vec<u8> {
    const BLOCK: usize = 64;
    let mut key_block = [0u8; BLOCK];
    if key.len() > BLOCK {
        let mut digest = Sha1::new();
        digest.update(key);
        let sum = digest.finalize();
        key_block[..sum.len()].copy_from_slice(&sum);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }
    let mut inner = Sha1::new();
    inner.update(ipad);
    inner.update(message);
    let inner_digest = inner.finalize();
    let mut outer = Sha1::new();
    outer.update(opad);
    outer.update(inner_digest);
    outer.finalize().to_vec()
}

fn default_batch_size() -> Option<usize> {
    Some(100)
}

fn default_batch_bytes() -> Option<usize> {
    Some(1_048_576)
}

fn default_linger_ms() -> Option<u64> {
    Some(50)
}

fn default_timeout_ms() -> Option<u64> {
    Some(5_000)
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

/// Webhook sink configuration. All limits are optional (`None` =
/// unbounded) with zero clamped ceilings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpSinkConfig {
    /// Target URL with `${topic}`, `${client_id}`, `${qos}` and
    /// `${timestamp}` substitution (http/https only).
    pub url: String,
    /// HTTP method (default POST).
    #[serde(default)]
    pub method: HttpMethod,
    /// Extra headers with the same template substitution.
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Authentication (default none).
    #[serde(default)]
    pub auth: HttpAuth,
    /// Body encoding (default raw JSON per event).
    #[serde(default)]
    pub body_format: HttpBodyFormat,
    /// Optional HMAC signature over the exact body bytes.
    #[serde(default)]
    pub signature: Option<HttpHmacSignature>,
    /// Flush trigger record count (default 100, `None` unbounded).
    #[serde(default = "default_batch_size")]
    pub batch_size: Option<usize>,
    /// Flush trigger byte limit (default 1 MiB, `None` unbounded).
    #[serde(default = "default_batch_bytes")]
    pub batch_bytes: Option<usize>,
    /// Linger flush window in ms (default 50, `None` disables time flush).
    #[serde(default = "default_linger_ms")]
    pub linger_ms: Option<u64>,
    /// Per-request timeout in ms (default 5000).
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: Option<u64>,
    /// Retries on 429/500..=504 (default 3, `None` unbounded, 0 none).
    #[serde(default = "default_max_retries")]
    pub max_retries: Option<usize>,
    /// First retry delay in ms (default 100).
    #[serde(default = "default_initial_backoff_ms")]
    pub initial_backoff_ms: Option<u64>,
    /// Retry delay ceiling in ms (default 2000).
    #[serde(default = "default_max_backoff_ms")]
    pub max_backoff_ms: Option<u64>,
}

impl HttpSinkConfig {
    pub fn validate(&self) -> Result<()> {
        if !self.url.starts_with("http://") && !self.url.starts_with("https://") {
            return Err(ConnectorError::Dispatch(format!(
                "webhook url must be http(s): {:?}",
                self.url
            )));
        }
        // Strict template check with dummy values.
        self.resolve_url("dummy/topic", QoS::AtMostOnce, 0)?;
        for (name, value) in &self.headers {
            if name.trim().is_empty() {
                return Err(ConnectorError::Dispatch(
                    "webhook header names must not be empty".to_string(),
                ));
            }
            self.resolve_text(value, "dummy/topic", QoS::AtMostOnce, 0)?;
        }
        self.auth.headers().map(|_| ())?;
        if let Some(signature) = &self.signature {
            signature.validate()?;
        }
        if self.batch_size == Some(0) {
            return Err(ConnectorError::Dispatch(
                "webhook batch_size must be >= 1".to_string(),
            ));
        }
        if self.batch_bytes == Some(0) {
            return Err(ConnectorError::Dispatch(
                "webhook batch_bytes must be >= 1".to_string(),
            ));
        }
        Ok(())
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

    pub fn effective_timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.unwrap_or(5_000).max(1))
    }

    /// Template variables for one event. `${client_id}` resolves from
    /// the JSON `client_id` field when present, else empty.
    fn event_vars(topic: &str, payload: &[u8], qos: QoS, millis: i64) -> [(String, String); 4] {
        let client_id = serde_json::from_slice::<serde_json::Value>(payload)
            .ok()
            .and_then(|doc| {
                doc.get("client_id")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            })
            .unwrap_or_default();
        [
            ("topic".to_string(), percent_encode_path(topic)),
            ("client_id".to_string(), percent_encode_fragment(&client_id)),
            ("qos".to_string(), u8::from(qos).to_string()),
            ("timestamp".to_string(), millis.to_string()),
        ]
    }

    /// Render the target URL for one event.
    pub fn resolve_url(&self, topic: &str, qos: QoS, millis: i64) -> Result<String> {
        let vars = Self::event_vars(topic, b"", qos, millis);
        let borrowed: Vec<(&str, String)> =
            vars.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
        render_template(&self.url, &borrowed)
    }

    /// Render free text (headers) for one event with the real payload.
    fn resolve_text(&self, template: &str, topic: &str, qos: QoS, millis: i64) -> Result<String> {
        let vars = Self::event_vars(topic, b"", qos, millis);
        let borrowed: Vec<(&str, String)> =
            vars.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
        render_template(template, &borrowed)
    }
}

/// Percent-encode a topic for URL paths: `/` stays structural,
/// everything outside unreserved marks becomes `%XX`.
fn percent_encode_path(value: &str) -> String {
    percent_encode(value, true)
}

/// Percent-encode a fragment (no structural characters kept).
fn percent_encode_fragment(value: &str) -> String {
    percent_encode(value, false)
}

fn percent_encode(value: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else if byte == b'/' && keep_slash {
            out.push('/');
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Percent-encode form fields (`application/x-www-form-urlencoded`):
/// unreserved marks stay, space becomes `+`, the rest is `%XX`.
fn form_encode(value: &str) -> String {
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

// ---------------------------------------------------------------------------
// Transport.
// ---------------------------------------------------------------------------

/// One outbound HTTP request.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Transport-level response (status only; bodies are audit-logged).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
}

#[async_trait]
pub trait HttpTransport: Send + Sync {
    async fn execute(&self, request: &HttpRequest) -> Result<HttpResponse>;
}

/// Scripted mock outcome: a status code or a transport failure.
#[derive(Debug, Clone)]
pub enum MockHttpOutcome {
    Status(u16),
    TransportError(String),
}

/// Captured outbound request for assertions.
#[derive(Debug, Clone)]
pub struct CapturedHttpRequest {
    pub method: HttpMethod,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// In-memory transport with a scripted outcome queue (tests, dry runs).
#[derive(Debug, Default)]
pub struct MockHttpTransport {
    scripted: parking_lot::Mutex<std::collections::VecDeque<MockHttpOutcome>>,
    captured: parking_lot::Mutex<Vec<CapturedHttpRequest>>,
    calls: AtomicU64,
}

impl MockHttpTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue statuses consumed in order (default 200 once exhausted).
    pub fn script_statuses(&self, statuses: Vec<u16>) {
        *self.scripted.lock() = statuses.into_iter().map(MockHttpOutcome::Status).collect();
    }

    /// Queue raw outcomes (statuses and transport errors) in order.
    pub fn script_outcomes(&self, outcomes: Vec<MockHttpOutcome>) {
        *self.scripted.lock() = outcomes.into_iter().collect();
    }

    pub fn captured(&self) -> Vec<CapturedHttpRequest> {
        self.captured.lock().clone()
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl HttpTransport for MockHttpTransport {
    async fn execute(&self, request: &HttpRequest) -> Result<HttpResponse> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.captured.lock().push(CapturedHttpRequest {
            method: request.method,
            url: request.url.clone(),
            headers: request.headers.clone(),
            body: request.body.clone(),
        });
        match self
            .scripted
            .lock()
            .pop_front()
            .unwrap_or(MockHttpOutcome::Status(200))
        {
            MockHttpOutcome::Status(status) => Ok(HttpResponse { status }),
            MockHttpOutcome::TransportError(message) => Err(ConnectorError::Connection(message)),
        }
    }
}

/// Production transport over `reqwest` with a per-request timeout.
pub struct ReqwestHttpTransport {
    client: reqwest::Client,
    timeout: Duration,
}

impl ReqwestHttpTransport {
    pub fn new(config: &HttpSinkConfig, client: reqwest::Client) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            client,
            timeout: config.effective_timeout(),
        })
    }
}

#[async_trait]
impl HttpTransport for ReqwestHttpTransport {
    async fn execute(&self, request: &HttpRequest) -> Result<HttpResponse> {
        let method = match request.method {
            HttpMethod::Post => reqwest::Method::POST,
            HttpMethod::Put => reqwest::Method::PUT,
            HttpMethod::Patch => reqwest::Method::PATCH,
        };
        let mut builder = self
            .client
            .request(method, &request.url)
            .timeout(self.timeout);
        for (name, value) in &request.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        let response = builder
            .body(request.body.clone())
            .send()
            .await
            .map_err(|e| ConnectorError::Connection(format!("webhook request failed: {e}")))?;
        Ok(HttpResponse {
            status: response.status().as_u16(),
        })
    }
}

// ---------------------------------------------------------------------------
// Sink.
// ---------------------------------------------------------------------------

/// One buffered event with its render timestamp.
#[derive(Debug, Clone)]
struct HttpRow {
    topic: String,
    payload: Vec<u8>,
    qos: u8,
    millis: i64,
}

struct HttpBuffer {
    queue: BatchQueue<HttpRow>,
    bytes: usize,
}

/// Enterprise webhook sink: buffers events, delivers per format.
pub struct HttpSink {
    config: HttpSinkConfig,
    transport: Arc<dyn HttpTransport>,
    buffer: parking_lot::Mutex<HttpBuffer>,
    backoff: parking_lot::Mutex<BackoffState>,
    sent_requests: AtomicU64,
    sent_records: AtomicU64,
}

impl HttpSink {
    pub fn new(config: HttpSinkConfig, transport: Arc<dyn HttpTransport>) -> Result<Self> {
        config.validate()?;
        let linger = config.effective_linger();
        Ok(Self {
            buffer: parking_lot::Mutex::new(HttpBuffer {
                queue: BatchQueue::new(config.effective_batch_size(), linger),
                bytes: 0,
            }),
            config,
            transport,
            backoff: parking_lot::Mutex::new(BackoffState::default()),
            sent_requests: AtomicU64::new(0),
            sent_records: AtomicU64::new(0),
        })
    }

    pub fn config(&self) -> &HttpSinkConfig {
        &self.config
    }

    pub fn sent_requests(&self) -> u64 {
        self.sent_requests.load(Ordering::Relaxed)
    }

    pub fn sent_records(&self) -> u64 {
        self.sent_records.load(Ordering::Relaxed)
    }

    pub fn buffered_rows(&self) -> usize {
        self.buffer.lock().queue.len()
    }

    /// Render one event document: projected JSON verbatim, else the
    /// UTF-8 payload as a string (payloads must be UTF-8).
    fn event_document(row: &HttpRow) -> Result<serde_json::Value> {
        let text = std::str::from_utf8(&row.payload)
            .map_err(|_| ConnectorError::Dispatch("webhook payload must be UTF-8".to_string()))?;
        Ok(serde_json::from_str(text)
            .unwrap_or_else(|_| serde_json::Value::String(text.to_string())))
    }

    /// Build the requests for taken rows: one per row for RawJson and
    /// FormUrlEncoded, a single array request for JsonBatchArray.
    fn render_requests(&self, rows: &[HttpRow]) -> Result<Vec<HttpRequest>> {
        match self.config.body_format {
            HttpBodyFormat::JsonBatchArray => {
                let mut documents = Vec::with_capacity(rows.len());
                for row in rows {
                    documents.push(Self::event_document(row)?);
                }
                let body = serde_json::to_vec(&documents).map_err(|e| {
                    ConnectorError::Dispatch(format!("webhook batch encode failed: {e}"))
                })?;
                Ok(vec![self.request_for(
                    rows[0].clone(),
                    body,
                    "application/json",
                )?])
            }
            HttpBodyFormat::RawJson => {
                let mut requests = Vec::with_capacity(rows.len());
                for row in rows {
                    let document = Self::event_document(row)?;
                    let body = serde_json::to_vec(&document).map_err(|e| {
                        ConnectorError::Dispatch(format!("webhook body encode failed: {e}"))
                    })?;
                    requests.push(self.request_for(row.clone(), body, "application/json")?);
                }
                Ok(requests)
            }
            HttpBodyFormat::FormUrlEncoded => {
                let mut requests = Vec::with_capacity(rows.len());
                for row in rows {
                    let document = Self::event_document(row)?;
                    let payload = match &document {
                        serde_json::Value::String(text) => text.clone(),
                        other => other.to_string(),
                    };
                    let body = format!(
                        "topic={}&qos={}&timestamp={}&payload={}",
                        form_encode(&row.topic),
                        row.qos,
                        row.millis,
                        form_encode(&payload),
                    );
                    requests.push(self.request_for(
                        row.clone(),
                        body.into_bytes(),
                        "application/x-www-form-urlencoded",
                    )?);
                }
                Ok(requests)
            }
        }
    }

    /// Assemble one request: method, templated URL/headers, auth,
    /// content type, and the HMAC signature over the exact body.
    fn request_for(
        &self,
        row: HttpRow,
        body: Vec<u8>,
        content_type: &'static str,
    ) -> Result<HttpRequest> {
        let vars =
            HttpSinkConfig::event_vars(&row.topic, &row.payload, qos_from(row.qos), row.millis);
        let borrowed: Vec<(&str, String)> =
            vars.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
        let url = render_template(&self.config.url, &borrowed)?;
        let mut headers = vec![("Content-Type".to_string(), content_type.to_string())];
        for (name, template) in &self.config.headers {
            headers.push((name.clone(), render_template(template, &borrowed)?));
        }
        headers.extend(self.config.auth.headers()?);
        if let Some(signature) = &self.config.signature {
            let tag = signature.sign(&body);
            headers.push((signature.header_name.clone(), tag));
        }
        Ok(HttpRequest {
            method: self.config.method,
            url,
            headers,
            body,
        })
    }

    /// Classify a status: success, retryable (429/500..=504), or
    /// terminal (everything else, including 400/401/403/404).
    fn classify(status: u16) -> Outcome {
        match status {
            200..=299 => Outcome::Success,
            429 | 500..=504 => Outcome::Retryable,
            _ => Outcome::Terminal,
        }
    }

    /// Backoff delay for `attempt` (1-based): exponential from the
    /// initial delay capped at the max, plus sub-millisecond jitter
    /// from the wall clock so fleets do not retry in lockstep.
    fn backoff_delay(&self, attempt: usize) -> Duration {
        let initial = self.config.initial_backoff_ms.unwrap_or(100).max(1);
        let max = self.config.max_backoff_ms.unwrap_or(2_000).max(1);
        let shift = attempt.min(10) as u32;
        let grown = initial.saturating_mul(2u64.saturating_pow(shift)).min(max);
        let jitter = (now_millis().max(0) as u64) % (grown / 2 + 1);
        Duration::from_millis(grown.saturating_add(jitter).min(max.saturating_mul(2)))
    }

    /// Flush buffered rows (no-op when empty). While backing off,
    /// fails fast without touching the transport. Retryable failures
    /// retry in place up to `max_retries` (`None` unbounded, 0 none);
    /// terminal failures and exhaustion restore the buffer, engage
    /// backoff, and propagate.
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
        let record_count = rows.len() as u64;
        let requests = self.render_requests(&rows)?;
        let max_retries = self.config.max_retries.unwrap_or(usize::MAX);
        for request in &requests {
            let mut attempt = 0usize;
            loop {
                match self.transport.execute(request).await {
                    Ok(response) => match Self::classify(response.status) {
                        Outcome::Success => break,
                        Outcome::Terminal => {
                            self.restore(rows, oldest, taken_bytes);
                            self.backoff.lock().failure();
                            return Err(ConnectorError::Dispatch(format!(
                                "webhook {} answered {}",
                                request.url, response.status
                            )));
                        }
                        Outcome::Retryable if attempt >= max_retries => {
                            self.restore(rows, oldest, taken_bytes);
                            self.backoff.lock().failure();
                            return Err(ConnectorError::Connection(format!(
                                "webhook {} backpressure ({}) after {attempt} retries",
                                request.url, response.status
                            )));
                        }
                        Outcome::Retryable => {
                            attempt += 1;
                            tokio::time::sleep(self.backoff_delay(attempt)).await;
                        }
                    },
                    Err(e) => {
                        self.restore(rows, oldest, taken_bytes);
                        self.backoff.lock().failure();
                        return Err(e);
                    }
                }
            }
            self.sent_requests.fetch_add(1, Ordering::Relaxed);
        }
        self.backoff.lock().success();
        self.sent_records.fetch_add(record_count, Ordering::Relaxed);
        Ok(())
    }

    fn restore(&self, rows: Vec<HttpRow>, oldest: Option<std::time::Instant>, bytes: usize) {
        let mut buffer = self.buffer.lock();
        buffer.queue.restore(rows, oldest);
        buffer.bytes = buffer.bytes.saturating_add(bytes);
    }

    /// Validate + buffer one event. Returns true when the batch is
    /// full, stale, or over the byte limit (caller flushes).
    fn buffer_row(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<bool> {
        if topic.as_str().is_empty() {
            return Err(ConnectorError::Dispatch(
                "webhook row requires a non-empty topic".to_string(),
            ));
        }
        std::str::from_utf8(payload)
            .map_err(|_| ConnectorError::Dispatch("webhook payload must be UTF-8".to_string()))?;
        let row = HttpRow {
            topic: topic.as_str().to_string(),
            payload: payload.to_vec(),
            qos: u8::from(qos),
            millis: now_millis(),
        };
        let added = row.payload.len() + row.topic.len() + 16;
        let mut buffer = self.buffer.lock();
        let full = buffer.queue.push(row);
        buffer.bytes = buffer.bytes.saturating_add(added);
        Ok(full || buffer.bytes >= self.config.effective_batch_bytes())
    }
}

fn qos_from(value: u8) -> QoS {
    QoS::try_from(value).unwrap_or(QoS::AtMostOnce)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Success,
    Retryable,
    Terminal,
}

#[async_trait]
impl Sink for HttpSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        if self.buffer_row(topic, payload, qos)? {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "webhook"
    }
}

/// Management connector handle pairing an id with a webhook sink.
pub struct HttpConnector {
    id: String,
    sink: Arc<HttpSink>,
}

impl HttpConnector {
    pub fn new(id: impl Into<String>, sink: Arc<HttpSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }
}

impl super::Connector for HttpConnector {
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

    fn test_config(url: &str) -> HttpSinkConfig {
        HttpSinkConfig {
            url: url.to_string(),
            method: HttpMethod::Post,
            headers: HashMap::new(),
            auth: HttpAuth::None,
            body_format: HttpBodyFormat::RawJson,
            signature: None,
            batch_size: Some(100),
            batch_bytes: Some(1_048_576),
            linger_ms: Some(50),
            timeout_ms: Some(5_000),
            max_retries: Some(3),
            initial_backoff_ms: Some(100),
            max_backoff_ms: Some(2_000),
        }
    }

    fn test_sink(config: HttpSinkConfig) -> (Arc<HttpSink>, Arc<MockHttpTransport>) {
        let transport = Arc::new(MockHttpTransport::new());
        let sink = Arc::new(HttpSink::new(config, transport.clone()).unwrap());
        (sink, transport)
    }

    #[test]
    fn test_config_validation() {
        let mut config = test_config("https://hooks.example.com/ingest/${topic}");
        assert!(config.validate().is_ok());

        config.url = "ftp://hooks.example.com/x".to_string();
        assert!(config.validate().is_err());
        config.url = "https://hooks.example.com/ingest/${topic}".to_string();

        config.url = "https://hooks.example.com/${nope}".to_string();
        assert!(config.validate().is_err());
        config.url = "https://hooks.example.com/ingest".to_string();

        config.headers.insert(String::new(), "v".to_string());
        assert!(config.validate().is_err());
        config.headers.clear();

        config.signature = Some(HttpHmacSignature {
            header_name: "X-Signature-SHA256".to_string(),
            algorithm: HmacAlgorithm::Sha256,
            secret: String::new(),
            encoding: HmacEncoding::Hex,
        });
        assert!(config.validate().is_err());
        config.signature = None;

        config.batch_size = Some(0);
        assert!(config.validate().is_err());
        config.batch_size = None;
        config.batch_bytes = Some(0);
        assert!(config.validate().is_err());
        // Unbounded + huge limits accepted: zero clamped ceilings.
        config.batch_bytes = None;
        config.max_retries = None;
        config.batch_size = Some(10_000_000);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_url_template_substitution() {
        let config = test_config("https://h.example.com/t/${topic}?q=${qos}&ts=${timestamp}");
        let url = config
            .resolve_url("sensors/t1", QoS::AtLeastOnce, 1_789_211_889_123)
            .unwrap();
        assert_eq!(
            url,
            "https://h.example.com/t/sensors/t1?q=1&ts=1789211889123"
        );

        // Spaces and `?` in topics are percent-encoded; `/` stays.
        let url = config.resolve_url("a b?c/d", QoS::AtMostOnce, 0).unwrap();
        assert_eq!(url, "https://h.example.com/t/a%20b%3Fc/d?q=0&ts=0");
    }

    #[test]
    fn test_hmac_known_answers() {
        // RFC 4231 Test Case 1: key = 0x0b * 20, data = "Hi There".
        let key = vec![0x0bu8; 20];
        assert_eq!(
            hmac_sha256(&key, b"Hi There")
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hmac_sha1(&key, b"Hi There")
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );

        // Webhook body vector (independent Python hmac/hashlib).
        let signer = HttpHmacSignature {
            header_name: "X-Signature-SHA256".to_string(),
            algorithm: HmacAlgorithm::Sha256,
            secret: "webhook-secret".to_string(),
            encoding: HmacEncoding::Hex,
        };
        assert_eq!(
            signer.sign(br#"{"topic":"sensors/t1","qos":1}"#),
            "8e48674ceb807931f4d75f8bbf5b1547a3c3b270dc067de449f3b1dbad12de38"
        );
        let b64 = HttpHmacSignature {
            encoding: HmacEncoding::Base64,
            ..signer.clone()
        };
        assert_eq!(
            b64.sign(br#"{"topic":"sensors/t1","qos":1}"#),
            "jkhnTOuAeTH011+Lv1sVR6PDsnDcBn3kSfOx260S3jg="
        );
        let sha1 = HttpHmacSignature {
            algorithm: HmacAlgorithm::Sha1,
            encoding: HmacEncoding::Hex,
            ..signer
        };
        assert_eq!(
            sha1.sign(br#"{"topic":"sensors/t1","qos":1}"#),
            "55ac33d204efaf1baf2eb789cae810d3da1c36f4"
        );
    }

    #[test]
    fn test_auth_headers() {
        assert!(HttpAuth::None.headers().unwrap().is_empty());
        assert_eq!(
            HttpAuth::Basic {
                username: "u".to_string(),
                password: "p".to_string()
            }
            .headers()
            .unwrap(),
            vec![("Authorization".to_string(), "Basic dTpw".to_string())]
        );
        assert_eq!(
            HttpAuth::Bearer {
                token: "tok".to_string()
            }
            .headers()
            .unwrap(),
            vec![("Authorization".to_string(), "Bearer tok".to_string())]
        );
        assert_eq!(
            HttpAuth::ApiKey {
                header_name: "X-Key".to_string(),
                key: "k".to_string()
            }
            .headers()
            .unwrap(),
            vec![("X-Key".to_string(), "k".to_string())]
        );
        assert!(HttpAuth::Bearer {
            token: "  ".to_string()
        }
        .headers()
        .is_err());
    }

    #[tokio::test]
    async fn test_batch_array_wrapping() {
        let mut config = test_config("http://127.0.0.1:1/hook");
        config.body_format = HttpBodyFormat::JsonBatchArray;
        config.batch_size = Some(3);
        config.signature = Some(HttpHmacSignature {
            header_name: "X-Signature-SHA256".to_string(),
            algorithm: HmacAlgorithm::Sha256,
            secret: "s".to_string(),
            encoding: HmacEncoding::Hex,
        });
        let (sink, transport) = test_sink(config);
        let topic = Topic::new("t").unwrap();
        for v in [1, 2, 3] {
            sink.send(
                &topic,
                &Bytes::from(format!("{{\"v\":{v}}}")),
                QoS::AtMostOnce,
            )
            .await
            .unwrap();
        }
        // Third row fills the batch: exactly one array request.
        assert_eq!(sink.sent_requests(), 1);
        assert_eq!(transport.calls(), 1);
        let captured = transport.captured();
        assert_eq!(captured.len(), 1);
        let body: serde_json::Value = serde_json::from_slice(&captured[0].body).unwrap();
        assert_eq!(body, serde_json::json!([{"v": 1}, {"v": 2}, {"v": 3}]));
        // Signature covers the exact array bytes.
        let signed = captured[0]
            .headers
            .iter()
            .find(|(name, _)| name == "X-Signature-SHA256")
            .expect("signature header");
        let expected = HttpHmacSignature {
            header_name: "X-Signature-SHA256".to_string(),
            algorithm: HmacAlgorithm::Sha256,
            secret: "s".to_string(),
            encoding: HmacEncoding::Hex,
        };
        assert_eq!(signed.1, expected.sign(&captured[0].body));
    }

    #[tokio::test]
    async fn test_form_encoding() {
        let mut config = test_config("http://127.0.0.1:1/hook");
        config.body_format = HttpBodyFormat::FormUrlEncoded;
        config.batch_size = Some(1);
        let (sink, transport) = test_sink(config);
        sink.send(
            &Topic::new("sensors/t1").unwrap(),
            &Bytes::from("hello world"),
            QoS::AtLeastOnce,
        )
        .await
        .unwrap();
        let captured = transport.captured();
        assert_eq!(captured.len(), 1);
        let content_type = captured[0]
            .headers
            .iter()
            .find(|(name, _)| name == "Content-Type")
            .expect("content type");
        assert_eq!(content_type.1, "application/x-www-form-urlencoded");
        let body = String::from_utf8(captured[0].body.clone()).unwrap();
        assert!(
            body.starts_with("topic=sensors%2Ft1"),
            "topic encoded: {body}"
        );
        assert!(body.contains("qos=1"), "qos: {body}");
        assert!(body.contains("payload=hello+world"), "payload: {body}");
    }

    #[tokio::test]
    async fn test_retry_on_429_then_success() {
        let mut config = test_config("http://127.0.0.1:1/hook");
        config.batch_size = Some(10);
        config.initial_backoff_ms = Some(1);
        config.max_backoff_ms = Some(2);
        let (sink, transport) = test_sink(config);
        transport.script_statuses(vec![429, 429, 200]);

        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from("{}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        sink.flush().await.unwrap();
        assert_eq!(transport.calls(), 3);
        assert_eq!(sink.sent_requests(), 1);
        assert_eq!(sink.sent_records(), 1);
        assert_eq!(sink.buffered_rows(), 0);
    }

    #[tokio::test]
    async fn test_terminal_status_aborts_without_retry() {
        let mut config = test_config("http://127.0.0.1:1/hook");
        config.batch_size = Some(10);
        config.max_retries = Some(5);
        let (sink, transport) = test_sink(config);
        transport.script_statuses(vec![401, 200]);

        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from("{}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        let err = sink.flush().await.expect_err("401 must fail");
        assert!(matches!(err, ConnectorError::Dispatch(_)));
        // No retry consumed the queued 200; buffer retained for inspection.
        assert_eq!(transport.calls(), 1);
        assert_eq!(sink.buffered_rows(), 1);
    }

    #[tokio::test]
    async fn test_transport_error_retains_and_backs_off() {
        let mut config = test_config("http://127.0.0.1:1/hook");
        config.batch_size = Some(10);
        let (sink, transport) = test_sink(config);
        transport.script_outcomes(vec![MockHttpOutcome::TransportError("down".to_string())]);

        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from("{}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        let bytes_before = sink.buffered_rows();
        let err = sink.flush().await.expect_err("transport down must fail");
        assert!(matches!(err, ConnectorError::Connection(_)));
        assert_eq!(sink.buffered_rows(), bytes_before);
        let calls = transport.calls();
        assert!(sink.flush().await.is_err());
        assert_eq!(transport.calls(), calls);
    }
}
