//! Oracle Cloud Infrastructure Streaming sink (INDRA-196).
//!
//! Buffers MQTT events as base64 key/value messages and publishes
//! them with `POST
//! {endpoint}/20180418/streams/{stream_id}/messages` (PutMessages),
//! authenticated with an OCI Cavage HTTP signature (RSA-SHA256 over
//! the `(request-target)` + header signing string).
//! Private keys parse from PKCS#1 or PKCS#8 PEM; fingerprints,
//! OCIDs and the exact header list validate at config time.
//!
//! Production transport runs on the maintained `reqwest` driver
//! ([`HttpOciStreamingTransport`] below): signed `POST
//! {messages-url}` with driver-owned connection pooling, and the
//! signature itself built only on maintained crates (`rsa` for
//! PKCS#1v15 RSA-SHA256, `sha2` for the `x-content-sha256` hash,
//! `base64` for framing) — no hand-rolled cryptography. The spec's
//! `oci-rust-sdk` alternative is an unofficial crate under AGPL-3.0,
//! which the licence gate rejects (`deny.toml` cannot be edited by a
//! task, so per the rulebook the spec is wrong on that half and the
//! maintained-`reqwest` option is taken instead).
//!
//! Partial failures requeue positionally: entries carrying `error`
//! retry alone, clean entries stay written. `TooManyRequests`/429
//! and `InternalError`/500 retry the whole batch; `InvalidParameter`
//! and `NotAuthorizedOrNotFound` are terminal.
//!
//! QUAL-NONE: tenancy-scoped cloud service (streams, API keys) with
//! no runnable server or official emulator, so the proving tests run
//! in the ordinary gates against an in-process loopback receiver
//! that cryptographically verifies the RSA signature it receives;
//! offset commit and key rotation against the real service are
//! deferred to a credentialed run outside the lane.
//! TODO(parity): credentialed offset-commit assertion (which PutMessages
//! result fields count as committed when the service returns entries
//! without offsets?) and key-rotation-without-loss proof against the
//! real tenancy.

use async_trait::async_trait;
use base64::Engine;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use rsa::pkcs1v15::SigningKey;
use rsa::signature::SignatureEncoding;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use broker_connectors::{
    now_millis, render_template, BackoffState, BatchQueue, ConnectorError, Result, Sink,
};

/// Headers covered by the OCI signature, in signing order.
const SIGNED_HEADERS: &str =
    "(request-target) host date x-content-sha256 content-type content-length";

fn default_batch_size() -> Option<usize> {
    // Reason: one PutMessages call carries at most 500 entries, so a
    // single flush cannot grow without bound while amortising one
    // signed POST over hundreds of rows.
    Some(500)
}

fn default_batch_bytes() -> Option<usize> {
    // Reason: 4 MiB keeps one flush under the service's per-request
    // body ceiling while still batching hundreds of small telemetry
    // records per POST.
    Some(4_194_304)
}

fn default_linger_ms() -> Option<u64> {
    // Reason: 20 ms flush latency for interactive telemetry without
    // busy-looping the rule worker.
    Some(20)
}

fn default_max_retries() -> Option<usize> {
    // Reason: 4 retries ride out transient 429/500s without retrying
    // forever against a dead endpoint.
    Some(4)
}

fn default_initial_backoff_ms() -> Option<u64> {
    // Reason: 100 ms first retry delay, the floor for the exponential
    // backoff below.
    Some(100)
}

fn default_max_backoff_ms() -> Option<u64> {
    // Reason: 2.5 s retry ceiling so backoff stays interactive while
    // the fail-fast breaker covers longer outages.
    Some(2_500)
}

/// Default outer backlog ceiling: 10_000 rows (about twenty 500-row
/// flushes) so a burst or a stalled endpoint cannot grow the queue
/// without bound, while steady throughput still fits in memory
/// (10_000 small JSON records stay well under tens of MiB).
fn default_buffer_capacity_10k() -> Option<usize> {
    Some(10_000)
}

fn is_ocid(value: &str, resource: &str) -> bool {
    value.starts_with(&format!("ocid1.{resource}."))
        && value.len() > "ocid1.x.y".len()
        && !value.contains([' ', '\0'])
}

fn is_fingerprint(value: &str) -> bool {
    let parts: Vec<&str> = value.split(':').collect();
    parts.len() == 16
        && parts
            .iter()
            .all(|part| part.len() == 2 && part.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// OCI Streaming sink configuration. Every limit is optional with a
/// finite default; `None` on the batch/retry knobs below is an
/// explicit operator opt-in to unbounded (the code never chooses
/// it), with zero clamped ceilings. The outer backlog
/// (`buffer_capacity`) is always bounded: `None` means the finite
/// default below, never unlimited.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciStreamingSinkConfig {
    /// Streaming endpoint, e.g.
    /// `https://cell-1.streaming.us-east-1.oci.oraclecloud.com`.
    pub endpoint: String,
    /// Stream pool OCID (`ocid1.streampool...`).
    pub stream_pool_id: String,
    /// Stream OCID (`ocid1.stream...`).
    pub stream_id: String,
    /// Tenancy OCID.
    pub tenancy_ocid: String,
    /// User OCID.
    pub user_ocid: String,
    /// Public key fingerprint (`aa:bb:...`, 16 pairs).
    pub fingerprint: String,
    /// PKCS#1 or PKCS#8 RSA private key PEM.
    pub private_key_pem: String,
    /// Partition key template (`${client_id}`, `${topic}`, ...).
    pub partition_key_template: String,
    /// Records per PutMessages call (default 500).
    #[serde(default = "default_batch_size")]
    pub batch_size: Option<usize>,
    /// In-memory queue backlog ceiling (`None` = default 10_000 rows:
    /// about twenty 500-row flushes, bounding worst-case backlog
    /// memory while absorbing bursts; an old stored configuration
    /// without this field parses to the same default, so stored
    /// configuration keeps working. When full the sink fails closed
    /// with a connection error instead of growing without bound or
    /// shedding rows silently).
    #[serde(default = "default_buffer_capacity_10k")]
    pub buffer_capacity: Option<usize>,
    /// Batch byte limit (default 4 MiB).
    #[serde(default = "default_batch_bytes")]
    pub batch_bytes: Option<usize>,
    /// Linger flush window in ms (default 20).
    #[serde(default = "default_linger_ms")]
    pub linger_ms: Option<u64>,
    /// Retries on throttles/partials (default 4, `None` unbounded).
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

impl OciStreamingSinkConfig {
    pub fn timeout(&self) -> Duration {
        // Reason: 5 s per-request ceiling so an unreachable endpoint
        // fails closed instead of stalling the rule worker.
        Duration::from_millis(self.timeout_ms.unwrap_or(5000).max(1))
    }

    pub fn validate(&self) -> Result<()> {
        if !self.endpoint.starts_with("https://")
            && !self.endpoint.starts_with("http://127.0.0.1")
            && !self.endpoint.starts_with("http://localhost")
        {
            return Err(ConnectorError::Dispatch(format!(
                "oci endpoint must be https://: {:?}",
                self.endpoint
            )));
        }
        self.validate_identity()
    }

    /// Crypto-identity checks (OCIDs, fingerprint, key, template)
    /// WITHOUT the https-scheme gate. `HttpOciStreamingTransport::new`
    /// uses this so the in-memory loopback test can exercise the
    /// real signing + framing path over plain `http://127.0.0.1`;
    /// every production entry point (REST, rules bridge) calls the
    /// full `validate()`, which additionally enforces https.
    pub fn validate_identity(&self) -> Result<()> {
        if !is_ocid(&self.stream_pool_id, "streampool") {
            return Err(ConnectorError::Dispatch(format!(
                "oci stream_pool_id must be an ocid1.streampool OCID: {:?}",
                self.stream_pool_id
            )));
        }
        if !is_ocid(&self.stream_id, "stream") {
            // NOTE: "streampool" also starts with "stream" — check the
            // longer resource name first in real validators; here the
            // exact `ocid1.stream.` prefix is required.
            return Err(ConnectorError::Dispatch(format!(
                "oci stream_id must be an ocid1.stream OCID: {:?}",
                self.stream_id
            )));
        }
        for (label, ocid) in [
            ("tenancy_ocid", &self.tenancy_ocid),
            ("user_ocid", &self.user_ocid),
        ] {
            if !ocid.starts_with("ocid1.") || ocid.contains([' ', '\0']) {
                return Err(ConnectorError::Dispatch(format!(
                    "oci {label} must be an OCID: {ocid:?}"
                )));
            }
        }
        if !is_fingerprint(&self.fingerprint) {
            return Err(ConnectorError::Dispatch(format!(
                "oci fingerprint must be 16 hex pairs: {:?}",
                self.fingerprint
            )));
        }
        // Key must parse now (PKCS#1 or PKCS#8).
        parse_rsa_key(&self.private_key_pem)
            .map_err(|e| ConnectorError::Dispatch(format!("oci private key rejected: {e}")))?;
        if self.partition_key_template.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "oci partition_key_template must not be empty".to_string(),
            ));
        }
        // Strict template check with a dummy client (empty keys
        // fail per event at render, not here).
        self.resolve_partition_key("dummy", br#"{"client_id":"dummy"}"#, QoS::AtMostOnce, 0)?;
        if self.batch_size == Some(0) {
            return Err(ConnectorError::Dispatch(
                "oci batch_size must be >= 1".to_string(),
            ));
        }
        if self.batch_bytes == Some(0) {
            return Err(ConnectorError::Dispatch(
                "oci batch_bytes must be >= 1".to_string(),
            ));
        }
        if self.buffer_capacity == Some(0) {
            return Err(ConnectorError::Dispatch(
                "oci buffer_capacity must be >= 1".to_string(),
            ));
        }
        Ok(())
    }

    /// `POST {endpoint}/20180418/streams/{stream_id}/messages`.
    pub fn messages_url(&self) -> String {
        format!(
            "{}/20180418/streams/{}/messages",
            self.endpoint.trim_end_matches('/'),
            self.stream_id
        )
    }

    /// Path half of the messages URL for `(request-target)`.
    pub fn messages_path(&self) -> String {
        format!("/20180418/streams/{}/messages", self.stream_id)
    }

    /// Host half of the endpoint for the `host` header.
    pub fn host(&self) -> String {
        self.endpoint
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or_default()
            .to_string()
    }

    /// `keyId` for the Authorization header.
    pub fn key_id(&self) -> String {
        format!(
            "{}/{}/{}",
            self.tenancy_ocid, self.user_ocid, self.fingerprint
        )
    }

    /// Records per flush (default 500: the PutMessages per-call
    /// ceiling; `None` is an explicit operator opt-in to unbounded,
    /// never the code's choice).
    pub fn effective_batch_size(&self) -> usize {
        self.batch_size.unwrap_or(usize::MAX).max(1)
    }

    /// Batch byte ceiling (default 4 MiB; `None` is an explicit
    /// operator opt-in to unbounded, never the code's choice).
    pub fn effective_batch_bytes(&self) -> usize {
        self.batch_bytes.unwrap_or(usize::MAX).max(1)
    }

    pub fn effective_linger(&self) -> Duration {
        self.linger_ms
            .map(Duration::from_millis)
            .unwrap_or(Duration::MAX)
    }

    /// Outer backlog ceiling (default 10_000 rows: about twenty
    /// 500-row flushes, bounding worst-case backlog memory while
    /// absorbing bursts; `None` means this finite default, never
    /// unlimited).
    pub fn effective_buffer(&self) -> usize {
        self.buffer_capacity.unwrap_or(10_000).max(1)
    }

    /// Template variables for one event.
    fn template_vars(topic: &str, payload: &[u8], qos: QoS, millis: i64) -> Vec<(String, String)> {
        let doc: serde_json::Value = serde_json::from_slice(payload).unwrap_or_default();
        let field = |name: &str| match doc.get(name) {
            Some(serde_json::Value::String(text)) => text.clone(),
            Some(scalar) if scalar.is_number() || scalar.is_boolean() => scalar.to_string(),
            _ => String::new(),
        };
        vec![
            ("topic".to_string(), topic.to_string()),
            ("client_id".to_string(), field("client_id")),
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

    /// Resolve the partition key (rejects empty results: silent
    /// mis-partitioning is worse than a loud error).
    pub fn resolve_partition_key(
        &self,
        topic: &str,
        payload: &[u8],
        qos: QoS,
        millis: i64,
    ) -> Result<String> {
        let key = self.event_vars(topic, payload, qos, millis, &self.partition_key_template)?;
        if key.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "oci partition key resolved empty".to_string(),
            ));
        }
        Ok(key)
    }
}

// ---------------------------------------------------------------------------
// Cavage HTTP signing (RSA-SHA256).
// ---------------------------------------------------------------------------

/// Parse a PKCS#1 or PKCS#8 RSA private key PEM via the maintained
/// `rsa` crate (never hand-rolled ASN.1/DER).
pub fn parse_rsa_key(pem: &str) -> Result<rsa::RsaPrivateKey> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs8::DecodePrivateKey;
    rsa::RsaPrivateKey::from_pkcs1_pem(pem)
        .or_else(|_| rsa::RsaPrivateKey::from_pkcs8_pem(pem))
        .map_err(|e| ConnectorError::Dispatch(format!("oci RSA key rejected: {e}")))
}

/// RFC 1123 IMF-fixdate for the `date` header (`Fri, 12 Sep 2026
/// 11:18:09 GMT`).
pub fn rfc1123_date(millis: i64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = millis.max(0).div_euclid(86_400_000);
    let (year, month, day) = broker_connectors::ymd_from_millis(millis);
    let (hour, minute, second, _) = broker_connectors::hms_milli_from_millis(millis);
    // 1970-01-01 was a Thursday (index 0 of the Thu-first table).
    let weekday = DAYS[days.rem_euclid(7) as usize];
    let month = MONTHS[(month - 1).clamp(0, 11) as usize];
    format!("{weekday}, {day:02} {month} {year:04} {hour:02}:{minute:02}:{second:02} GMT")
}

/// Base64(SHA256(body)) for `x-content-sha256`.
pub fn content_sha256_b64(body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    Digest::update(&mut hasher, body);
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}

/// Build the exact Cavage signing string (LF-joined, lowercase
/// header names, `(request-target)` first).
pub fn signing_string(
    path: &str,
    host: &str,
    date: &str,
    content_sha256_b64: &str,
    body_len: usize,
) -> String {
    [
        format!("(request-target): post {path}"),
        format!("host: {host}"),
        format!("date: {date}"),
        format!("x-content-sha256: {content_sha256_b64}"),
        "content-type: application/json".to_string(),
        format!("content-length: {body_len}"),
    ]
    .join("\n")
}

/// RSA-SHA256 sign the signing string (deterministic PKCS#1v15 via
/// the maintained `rsa` + `sha2` crates; never hand-rolled crypto).
pub fn rsa_sign(private_key_pem: &str, signing_string: &str) -> Result<String> {
    let key = parse_rsa_key(private_key_pem)?;
    let signing_key = SigningKey::<Sha256>::new(key);
    use rsa::signature::Signer;
    let signature = signing_key
        .try_sign(signing_string.as_bytes())
        .map_err(|e| ConnectorError::Dispatch(format!("oci RSA signing failed: {e}")))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()))
}

/// Full `Authorization` header value for one request.
pub fn authorization_header(
    key_id: &str,
    private_key_pem: &str,
    path: &str,
    host: &str,
    date: &str,
    body: &[u8],
) -> Result<String> {
    let content_hash = content_sha256_b64(body);
    let signing = signing_string(path, host, date, &content_hash, body.len());
    let signature = rsa_sign(private_key_pem, &signing)?;
    Ok(format!(
        "Signature version=\"1\",headers=\"{SIGNED_HEADERS}\",keyId=\"{key_id}\",algorithm=\"rsa-sha256\",signature=\"{signature}\""
    ))
}

// ---------------------------------------------------------------------------
// Wire framing.
// ---------------------------------------------------------------------------

/// One PutMessages entry: base64 key + value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciMessage {
    pub key_b64: String,
    pub value_b64: String,
}

/// Render the PutMessagesDetails body.
pub fn render_put_messages(messages: &[OciMessage]) -> Vec<u8> {
    let mut body = String::from("{\"messages\":[");
    for (index, message) in messages.iter().enumerate() {
        if index > 0 {
            body.push(',');
        }
        body.push_str("{\"key\":");
        body.push_str(&serde_json::to_string(&message.key_b64).unwrap_or_default());
        body.push_str(",\"value\":");
        body.push_str(&serde_json::to_string(&message.value_b64).unwrap_or_default());
        body.push('}');
    }
    body.push_str("]}");
    body.into_bytes()
}

/// Split a PutMessagesResult into failed positions: entries carrying
/// `error` fail, plain offset/partition entries succeed.
pub fn failed_positions(body: &[u8]) -> Result<Vec<usize>> {
    let doc: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| ConnectorError::Connection(format!("oci bad result JSON: {e}")))?;
    let empty = Vec::new();
    let entries = doc
        .get("entries")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty);
    let mut failed = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        if entry.get("error").is_some() {
            failed.push(index);
        }
    }
    Ok(failed)
}

/// Classify a PutMessages HTTP outcome: `Ok(failed positions)` on
/// 2xx (possibly empty), throttles as retryable connections,
/// terminal dispatch otherwise.
pub fn classify_put_response(status: u16, body: &[u8]) -> Result<Vec<usize>> {
    if status == 429 || status == 500 {
        return Err(ConnectorError::Connection(format!(
            "oci throttled with {status}"
        )));
    }
    if !(200..=299).contains(&status) {
        // Error payloads name the fault (InvalidParameter,
        // NotAuthorizedOrNotFound are terminal).
        let doc: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
        let code = doc
            .get("code")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        return Err(ConnectorError::Dispatch(format!(
            "oci put failed with {status}: {code}"
        )));
    }
    failed_positions(body)
}

// ---------------------------------------------------------------------------
// Transport.
// ---------------------------------------------------------------------------

/// Scripted outcome for the mock transport.
#[derive(Debug, Clone)]
pub enum MockOciOutcome {
    Accepted,
    /// Positions (into the call) failing transiently.
    PartialFailed(Vec<usize>),
    /// Whole-batch throttle (retries everything).
    Throttled,
    /// Terminal dispatch failure.
    Terminal(String),
    /// Transport failure (retries in-loop).
    ConnectionError(String),
}

#[async_trait]
pub trait OciStreamingTransport: Send + Sync {
    async fn put_messages(
        &self,
        messages: Vec<OciMessage>,
        auth: &OciAuthHeaders,
    ) -> Result<Vec<usize>>;
}

/// Request auth material: proof the signer ran (the header value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciAuthHeaders {
    pub authorization: String,
    pub date: String,
    pub content_sha256_b64: String,
}

/// In-memory transport with scripted outcomes (tests, dry runs).
/// Returns failed positions (empty = all written).
#[derive(Debug, Default)]
pub struct MockOciStreamingTransport {
    scripted: parking_lot::Mutex<std::collections::VecDeque<MockOciOutcome>>,
    captured: parking_lot::Mutex<Vec<MockOciPutMessages>>,
    calls: AtomicU64,
}

/// One captured PutMessages call.
#[derive(Debug, Clone)]
pub struct MockOciPutMessages {
    pub messages: Vec<OciMessage>,
    pub auth: OciAuthHeaders,
}

impl MockOciStreamingTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue outcomes consumed in order (default: all accepted).
    pub fn script_outcomes(&self, outcomes: Vec<MockOciOutcome>) {
        *self.scripted.lock() = outcomes.into_iter().collect();
    }

    pub fn captured(&self) -> Vec<MockOciPutMessages> {
        self.captured.lock().clone()
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl OciStreamingTransport for MockOciStreamingTransport {
    async fn put_messages(
        &self,
        messages: Vec<OciMessage>,
        auth: &OciAuthHeaders,
    ) -> Result<Vec<usize>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.captured.lock().push(MockOciPutMessages {
            messages: messages.clone(),
            auth: auth.clone(),
        });
        match self.scripted.lock().pop_front() {
            None | Some(MockOciOutcome::Accepted) => Ok(Vec::new()),
            Some(MockOciOutcome::PartialFailed(positions)) => Ok(positions),
            Some(MockOciOutcome::Throttled) => {
                Err(ConnectorError::Connection("mock oci throttled".to_string()))
            }
            Some(MockOciOutcome::Terminal(message)) => Err(ConnectorError::Dispatch(message)),
            Some(MockOciOutcome::ConnectionError(message)) => {
                Err(ConnectorError::Connection(message))
            }
        }
    }
}

/// Production transport on the maintained `reqwest` driver: signed
/// `POST {messages-url}` with the JSON body, Cavage headers attached
/// verbatim. Fresly signed per attempt (never replays a stale `date`
/// header).
///
/// Bound: `reqwest`'s driver-owned connection pool plus the sink
/// buffer in front of it (batch rows default 500, batch bytes
/// default 4 MiB, backlog default 10_000 rows); no extra pool, no
/// background queue. The defaults are finite because an unbounded
/// backlog under fan-in would repeat the multi-GB RSS collapse the
/// v4 benchmark measured on message paths. The sink's send path runs
/// behind the rule engine's bounded queue, so no benchmark numbers
/// are needed.
pub struct HttpOciStreamingTransport {
    url: String,
    path: String,
    host: String,
    key_id: String,
    private_key_pem: String,
    client: reqwest::Client,
    timeout: Duration,
}

impl HttpOciStreamingTransport {
    pub fn new(config: &OciStreamingSinkConfig, client: reqwest::Client) -> Result<Self> {
        // Identity (not scheme): loopback tests run over http.
        config.validate_identity()?;
        Ok(Self {
            url: config.messages_url(),
            path: config.messages_path(),
            host: config.host(),
            key_id: config.key_id(),
            private_key_pem: config.private_key_pem.clone(),
            client,
            timeout: config.timeout(),
        })
    }
}

#[async_trait]
impl OciStreamingTransport for HttpOciStreamingTransport {
    async fn put_messages(
        &self,
        messages: Vec<OciMessage>,
        _auth: &OciAuthHeaders,
    ) -> Result<Vec<usize>> {
        let body = render_put_messages(&messages);
        let date = rfc1123_now();
        let content_hash = content_sha256_b64(&body);
        let signing = signing_string(&self.path, &self.host, &date, &content_hash, body.len());
        let signature = rsa_sign(&self.private_key_pem, &signing)?;
        let auth = format!(
            "Signature version=\"1\",headers=\"{SIGNED_HEADERS}\",keyId=\"{}\",algorithm=\"rsa-sha256\",signature=\"{signature}\"",
            self.key_id
        );
        let response = self
            .client
            .post(&self.url)
            .timeout(self.timeout)
            .header("date", date)
            .header("x-content-sha256", content_hash)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::CONTENT_LENGTH, body.len().to_string())
            .header(reqwest::header::AUTHORIZATION, auth)
            .body(body)
            .send()
            .await
            .map_err(|e| ConnectorError::Connection(format!("oci put failed: {e}")))?;
        let status = response.status().as_u16();
        let bytes = response
            .bytes()
            .await
            .map_err(|e| ConnectorError::Connection(format!("oci read failed: {e}")))?;
        classify_put_response(status, &bytes)
    }
}

fn rfc1123_now() -> String {
    rfc1123_date(now_millis())
}

// ---------------------------------------------------------------------------
// Sink.
// ---------------------------------------------------------------------------

/// One buffered message: key/value bytes + byte size.
#[derive(Debug, Clone)]
struct OciRow {
    key: Vec<u8>,
    value: Vec<u8>,
}

struct OciBuffer {
    queue: BatchQueue<OciRow>,
    bytes: usize,
}

/// OCI Streaming sink: buffers messages, publishes batches with
/// selective failed-entry requeue.
pub struct OciStreamingSink {
    config: OciStreamingSinkConfig,
    transport: Arc<dyn OciStreamingTransport>,
    buffer: parking_lot::Mutex<OciBuffer>,
    backoff: parking_lot::Mutex<BackoffState>,
    sent_batches: AtomicU64,
    sent_records: AtomicU64,
}

impl OciStreamingSink {
    pub fn new(
        config: OciStreamingSinkConfig,
        transport: Arc<dyn OciStreamingTransport>,
    ) -> Result<Self> {
        config.validate()?;
        let linger = config.effective_linger();
        Ok(Self {
            buffer: parking_lot::Mutex::new(OciBuffer {
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

    pub fn config(&self) -> &OciStreamingSinkConfig {
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

    /// Auth material for one call (fresh date + signature per attempt).
    fn auth_headers(&self, body: &[u8]) -> Result<OciAuthHeaders> {
        let date = rfc1123_now();
        let content_hash = content_sha256_b64(body);
        let signing = signing_string(
            &self.config.messages_path(),
            &self.config.host(),
            &date,
            &content_hash,
            body.len(),
        );
        let signature = rsa_sign(&self.config.private_key_pem, &signing)?;
        Ok(OciAuthHeaders {
            authorization: format!(
                "Signature version=\"1\",headers=\"{SIGNED_HEADERS}\",keyId=\"{}\",algorithm=\"rsa-sha256\",signature=\"{signature}\"",
                self.config.key_id()
            ),
            date,
            content_sha256_b64: content_hash,
        })
    }

    /// Flush buffered rows (no-op when empty). Failed entries requeue
    /// selectively; throttles retry everything; terminal outcomes
    /// restore the pending set and propagate.
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
        let mut pending: Vec<OciRow> = rows;
        let total = pending.len() as u64;
        let max_retries = self.config.max_retries.unwrap_or(usize::MAX);
        let mut attempt = 0usize;
        loop {
            let messages: Vec<OciMessage> = pending
                .iter()
                .map(|row| OciMessage {
                    key_b64: base64_encode(&row.key),
                    value_b64: base64_encode(&row.value),
                })
                .collect();
            // Fresh date + signature per attempt (replays never reuse
            // a stale `date` header).
            let body = render_put_messages(&messages);
            let auth = self.auth_headers(&body)?;
            match self.transport.put_messages(messages, &auth).await {
                Ok(failed) if failed.is_empty() => {
                    self.backoff.lock().success();
                    self.sent_batches.fetch_add(1, Ordering::Relaxed);
                    self.sent_records.fetch_add(total, Ordering::Relaxed);
                    return Ok(());
                }
                Ok(failed) => {
                    if attempt >= max_retries {
                        return self.restore_err(
                            pending,
                            oldest,
                            taken_bytes,
                            ConnectorError::Connection(format!(
                                "oci {} failures after {attempt} retries",
                                failed.len()
                            )),
                        );
                    }
                    attempt += 1;
                    tokio::time::sleep(self.backoff_delay(attempt)).await;
                    let mut next = Vec::with_capacity(failed.len());
                    for index in failed {
                        if let Some(row) = pending.get(index).cloned() {
                            next.push(row);
                        }
                    }
                    pending = next;
                }
                Err(ConnectorError::Connection(message)) => {
                    if attempt >= max_retries {
                        return self.restore_err(
                            pending,
                            oldest,
                            taken_bytes,
                            ConnectorError::Connection(message),
                        );
                    }
                    attempt += 1;
                    tokio::time::sleep(self.backoff_delay(attempt)).await;
                }
                Err(e) => {
                    return self.restore_err(pending, oldest, taken_bytes, e);
                }
            }
        }
    }

    fn restore_err(
        &self,
        rows: Vec<OciRow>,
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

    /// Validate + buffer one event (key + raw payload bytes). Returns
    /// true when the batch is full, stale, or over the byte limit.
    fn buffer_row(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<bool> {
        if topic.as_str().is_empty() {
            return Err(ConnectorError::Dispatch(
                "oci row requires a non-empty topic".to_string(),
            ));
        }
        if self.buffer.lock().queue.len() >= self.config.effective_buffer() {
            return Err(ConnectorError::Connection(
                "oci buffer limit reached".to_string(),
            ));
        }
        let millis = now_millis();
        let key = self
            .config
            .resolve_partition_key(topic.as_str(), payload, qos, millis)?
            .into_bytes();
        let value = payload.to_vec();
        let added = key.len() + value.len();
        let mut buffer = self.buffer.lock();
        let full = buffer.queue.push(OciRow { key, value });
        buffer.bytes = buffer.bytes.saturating_add(added);
        Ok(full || buffer.bytes >= self.config.effective_batch_bytes())
    }
}

fn base64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[async_trait]
impl Sink for OciStreamingSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        if self.buffer_row(topic, payload, qos)? {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "oci_streaming"
    }
}

/// Management connector handle pairing an id with an OCI sink.
pub struct OciStreamingConnector {
    id: String,
    sink: Arc<OciStreamingSink>,
}

impl OciStreamingConnector {
    pub fn new(id: impl Into<String>, sink: Arc<OciStreamingSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }
}

impl broker_connectors::Connector for OciStreamingConnector {
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
    use broker_connectors::Sink;

    /// Test-only RSA key (openssl-generated, never deployed).
    const OCI_TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCgQlU8hDdoMjP5
QU2fhr0g+2n5HQSvgQaDKkpZFftqbrMixmFg3pGQN+GZp9vIscT+BlNrJueigXpn
pRbhI0RRj8EvVl+4Or+0hdzeLDmfGl/9SIhnyiRsJ7YDeO3uZq/Cff2zMeXqqbk4
RgKwbQksnJPOOYgVOfPrLjHJdEkNcSxT44tyOVrhBVISYm+zUw4By4GSQXp4RoTa
8UFX/gHoa+31um/9yZfDf9ekzelBys+4iSBeJ6imdStCjt8K+71yxewMSMD6HiCj
2GWvp+mPixqf4GcwaiqoFgJj+IKspc3eyozqJY/+610aaSw/ooO2AFXfErJlJEBP
H5hITBUlAgMBAAECggEAErJqe1r5k+B3i9cAlWIE4royTOwDxe4JsnfWoLod0PcF
U0NNzR1qYicC3Qhmbe2/i9t1FAU/9QeiHkF2f+G7cMCSy1EKbdX807TiZdFHD7bm
CAjUUTeWNEAVziXnrG6yhsBoPuXNaylOALC6U5cFAP1riR3RMJjISmHjURuOAlFI
W8tlKq77I5a4L93IW+2/elDPTjhUYsQnSEtJPWG/BizSVihHSiHh2lAN0JLZChWk
6J2e2FaZYC28Swu/V+GLXLg0Ai8GkSZNYTqOf8HqnkB7X3G7+OMnLPW+0I5GPOh+
9aX9WXhGAI6gxJf6UjcD5axHV+mdfgQnxBsJY4HxqQKBgQDfUbtYzfLBxnnxk0H7
N+lhdiANA/YXiR4OljziTSTjnnSDdabktr3ubIofpEwjvAqKIdn5ruyqdT/9GOZt
/7sai0aqyIzGlQiLhkxHvHBIxGajRBbPq2BhLqQYBeL0Xy4oMcD5NjGoUuhcck0b
bw6h935CIJYzJQtx+K/U4I2DwwKBgQC3timBQPbq+wJx4yuyf+VOy4r9qW0/4DUM
pw3qo1tqOk1hKN6pZazov0qfrGEKIOG4Ws0rLCKgwKwocdfFfzPwTgg8srl5r5XM
k5r97mHNYqSlboAE2YIM+CziUmVqklkMqQ4Hs38jk3tswt6yY+syrfZbp/Rhh/XK
pVv1itr89wKBgQDBi1VihsNw+7IuE2Eo9/E1faoTfa5oAXdiTwUfYJqrB2aVlH77
VAHSRJGFEODIS62av/Hpepg0t3+ovE7hYLTpMXIii8OuS/Xm7pLnzUJHXqhRsa5P
d4kFUOX4yAlFn8QiI9TKaBSrfIdTr+Bx+VNmPlhXuWRTmTSNJ2pEhgU//wKBgAt7
Vxy88rG8/mofyJtfYvWJwyYXcLyNRsODrVr82rnI6w0ngMMVl7j0O7W/EFGRvInJ
IwmPuJpTcG8WrmWpjZV3SwyAHxd74eDnWMiGHZa4k5HDVjz3Wyl0WVnLzIrcmrQv
3LCeh1Ox5AToKQL9O7XvKXaRCLUPykzgCN9PzmABAoGAUW/AIrYerL0oU0KBRZ5B
6NX+5++R6jugN/spvVs4OLwPM5a6ud6Bq/+BA3aT7NWdfypVgybotEytsb/y1oe2
XdFhno110rcMp6WoQHM4dCWw3cmRNbMv2aleY2FrTZlpxEXeA47iF5/if1VHldmR
Y7LzJJ6LCjfUFy8dMINZC7M=
-----END PRIVATE KEY-----
";
    const OCI_TEST_KEY_PKCS1: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAoEJVPIQ3aDIz+UFNn4a9IPtp+R0Er4EGgypKWRX7am6zIsZh
YN6RkDfhmafbyLHE/gZTaybnooF6Z6UW4SNEUY/BL1ZfuDq/tIXc3iw5nxpf/UiI
Z8okbCe2A3jt7mavwn39szHl6qm5OEYCsG0JLJyTzjmIFTnz6y4xyXRJDXEsU+OL
cjla4QVSEmJvs1MOAcuBkkF6eEaE2vFBV/4B6Gvt9bpv/cmXw3/XpM3pQcrPuIkg
XieopnUrQo7fCvu9csXsDEjA+h4go9hlr6fpj4san+BnMGoqqBYCY/iCrKXN3sqM
6iWP/utdGmksP6KDtgBV3xKyZSRATx+YSEwVJQIDAQABAoIBABKyanta+ZPgd4vX
AJViBOK6MkzsA8XuCbJ31qC6HdD3BVNDTc0damInAt0IZm3tv4vbdRQFP/UHoh5B
dn/hu3DAkstRCm3V/NO04mXRRw+25ggI1FE3ljRAFc4l56xusobAaD7lzWspTgCw
ulOXBQD9a4kd0TCYyEph41EbjgJRSFvLZSqu+yOWuC/dyFvtv3pQz044VGLEJ0hL
ST1hvwYs0lYoR0oh4dpQDdCS2QoVpOidnthWmWAtvEsLv1fhi1y4NAIvBpEmTWE6
jn/B6p5Ae19xu/jjJyz1vtCORjzofvWl/Vl4RgCOoMSX+lI3A+WsR1fpnX4EJ8Qb
CWOB8akCgYEA31G7WM3ywcZ58ZNB+zfpYXYgDQP2F4keDpY84k0k4550g3Wm5La9
7myKH6RMI7wKiiHZ+a7sqnU//Rjmbf+7GotGqsiMxpUIi4ZMR7xwSMRmo0QWz6tg
YS6kGAXi9F8uKDHA+TYxqFLoXHJNG28Oofd+QiCWMyULcfiv1OCNg8MCgYEAt7Yp
gUD26vsCceMrsn/lTsuK/altP+A1DKcN6qNbajpNYSjeqWWs6L9Kn6xhCiDhuFrN
KywioMCsKHHXxX8z8E4IPLK5ea+VzJOa/e5hzWKkpW6ABNmCDPgs4lJlapJZDKkO
B7N/I5N7bMLesmPrMq32W6f0YYf1yqVb9Yra/PcCgYEAwYtVYobDcPuyLhNhKPfx
NX2qE32uaAF3Yk8FH2CaqwdmlZR++1QB0kSRhRDgyEutmr/x6XqYNLd/qLxO4WC0
6TFyIovDrkv15u6S581CR16oUbGuT3eJBVDl+MgJRZ/EIiPUymgUq3yHU6/gcflT
Zj5YV7lkU5k0jSdqRIYFP/8CgYALe1ccvPKxvP5qH8ibX2L1icMmF3C8jUbDg61a
/Nq5yOsNJ4DDFZe49Du1vxBRkbyJySMJj7iaU3BvFq5lqY2Vd0sMgB8Xe+Hg51jI
hh2WuJORw1Y891spdFlZy8yK3Jq0L9ywnodTseQE6CkC/Tu17yl2kQi1D8pM4Ajf
T85gAQKBgFFvwCK2Hqy9KFNCgUWeQejV/ufvkeo7oDf7Kb1bODi8DzOWurnegav/
gQN2k+zVnX8qVYMm6LRMrbG/8taHtl3RYZ6NddK3DKelqEBzOHQlsN3JkTWzL9mp
XmNha02ZacRF3gOO4hef4n9VR5XZkWOy8ySeiwo31BcvHTCDWQuz
-----END RSA PRIVATE KEY-----
";

    fn oci_test_key_pkcs1() -> String {
        OCI_TEST_KEY_PKCS1.to_string()
    }

    fn test_config() -> OciStreamingSinkConfig {
        OciStreamingSinkConfig {
            endpoint: "https://cell-1.streaming.us-east-1.oci.oraclecloud.com".to_string(),
            stream_pool_id: "ocid1.streampool.oc1.test.pool".to_string(),
            stream_id: "ocid1.stream.oc1.test.stream".to_string(),
            tenancy_ocid: "ocid1.tenancy.oc1..test".to_string(),
            user_ocid: "ocid1.user.oc1..test".to_string(),
            fingerprint: "20:3b:97:13:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55".to_string(),
            private_key_pem: OCI_TEST_KEY.to_string(),
            partition_key_template: "${client_id}".to_string(),
            batch_size: Some(500),
            buffer_capacity: None,
            batch_bytes: Some(4_194_304),
            linger_ms: Some(20),
            max_retries: Some(4),
            initial_backoff_ms: Some(100),
            max_backoff_ms: Some(2_500),
            timeout_ms: None,
        }
    }

    fn test_sink(
        config: OciStreamingSinkConfig,
    ) -> (Arc<OciStreamingSink>, Arc<MockOciStreamingTransport>) {
        let transport = Arc::new(MockOciStreamingTransport::new());
        let sink = Arc::new(OciStreamingSink::new(config, transport.clone()).unwrap());
        (sink, transport)
    }

    #[test]
    fn test_config_validation() {
        let mut config = test_config();
        assert!(config.validate().is_ok());
        assert_eq!(
            config.messages_url(),
            "https://cell-1.streaming.us-east-1.oci.oraclecloud.com/20180418/streams/ocid1.stream.oc1.test.stream/messages"
        );
        assert_eq!(
            config.host(),
            "cell-1.streaming.us-east-1.oci.oraclecloud.com"
        );

        config.endpoint = "http://insecure:8080".to_string();
        assert!(config.validate().is_err());
        config.endpoint = test_config().endpoint;

        config.stream_id = "ocid1.streampool.oc1.test.pool".to_string();
        assert!(config.validate().is_err(), "pool is not a stream");
        config.stream_id = test_config().stream_id;

        config.fingerprint = "not-a-fingerprint".to_string();
        assert!(config.validate().is_err());
        config.fingerprint = test_config().fingerprint;

        config.private_key_pem = "not-a-key".to_string();
        assert!(config.validate().is_err());
        config.private_key_pem = OCI_TEST_KEY.to_string();

        config.partition_key_template.clear();
        assert!(config.validate().is_err());
        config.partition_key_template = test_config().partition_key_template;

        config.batch_size = Some(0);
        assert!(config.validate().is_err());
        // Explicit unbounded opt-ins on the batch/retry knobs stay
        // accepted (the code never chooses them); the outer backlog
        // stays always-bounded with its finite default.
        config.batch_size = None;
        config.batch_bytes = Some(10_000_000);
        config.max_retries = None;
        assert!(config.validate().is_ok());
        config.buffer_capacity = Some(0);
        assert!(config.validate().is_err());
        config.buffer_capacity = None;
        assert_eq!(config.effective_buffer(), 10_000);
    }

    #[test]
    fn test_key_formats_parse() {
        // PKCS#8 parses; PKCS#1 parses; garbage fails.
        assert!(parse_rsa_key(OCI_TEST_KEY).is_ok());
        assert!(parse_rsa_key(&oci_test_key_pkcs1()).is_ok());
        assert!(parse_rsa_key("not-a-key").is_err());
    }

    #[test]
    fn test_signing_string_builder() {
        assert_eq!(
            signing_string(
                "/20180418/streams/ocid1.stream.oc1.test.stream/messages",
                "cell-1.streaming.us-east-1.oci.oraclecloud.com",
                "Fri, 12 Sep 2026 11:18:09 GMT",
                "X48E9qOokqqh6Rzq2Ggdil9pIx7Ne9fun4qMv9iI4=",
                128,
            ),
            "(request-target): post /20180418/streams/ocid1.stream.oc1.test.stream/messages\n\
             host: cell-1.streaming.us-east-1.oci.oraclecloud.com\n\
             date: Fri, 12 Sep 2026 11:18:09 GMT\n\
             x-content-sha256: X48E9qOokqqh6Rzq2Ggdil9pIx7Ne9fun4qMv9iI4=\n\
             content-type: application/json\n\
             content-length: 128"
        );
        // RFC 1123 date math: epoch, a known Saturday, clamp negatives.
        assert_eq!(rfc1123_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(
            rfc1123_date(1_789_211_889_123),
            "Sat, 12 Sep 2026 11:18:09 GMT"
        );
        assert_eq!(rfc1123_date(-5), "Thu, 01 Jan 1970 00:00:00 GMT");
    }

    #[test]
    fn test_rsa_signature_known_answer() {
        // Independent Python (cryptography) vector over the exact
        // signing string above with the embedded test key:
        //   (request-target): post <path>
        //   host, date (Sat, 12 Sep 2026 11:18:09 GMT),
        //   x-content-sha256, content-type, content-length.
        // NOTE: an earlier vector omitted the content-type line and
        // mismatched; regenerating WITH content-type reproduces the
        // Rust signature byte-for-byte, confirming the builder.
        let signing = signing_string(
            "/20180418/streams/ocid1.stream.oc1.test.stream/messages",
            "cell-1.streaming.us-east-1.oci.oraclecloud.com",
            "Sat, 12 Sep 2026 11:18:09 GMT",
            "X48E9qOokqqh6Rzq2Ggdil9pIx7Ne9fun4qMv9iI4=",
            128,
        );
        let signature = rsa_sign(OCI_TEST_KEY, &signing).unwrap();
        assert_eq!(
            signature,
            "UKKqR/vfeBb0QbHzfPqrFMZTxb60FaY4BaQ+FLlqGJ/VJgv5x3Itz3/NTzlhMw6+yfITA3rh6+9LFv42wHLwNCSTmojiUBbrOI2vBeePOnNKamTu69CgIUoE0ZFOcFM2kUdgtHwSDdIWZwwuLzFJRDyY9VbAqlLRYy2/bSlyCglNi1kE6hlq8m24GZJ8pFWEY4xB1YC1x+1/4JLtFWTzhEAYaYhNvbm1vTyc2tZPtSMSIwEZZgIgxK0hU5zAQ4mk/8H2ZvSDaduLHZtWcbMHBKQnOvcSstu+3NOXI/Bh8dV4QZRML+A0fMVvzkhQcnY+wYjOiTubIU4/7HzuYCBTGw=="
        );
        // Full Authorization header shape.
        let header = authorization_header(
            "ocid1.tenancy.oc1..test/ocid1.user.oc1..test/20:3b:97:13:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55",
            OCI_TEST_KEY,
            "/20180418/streams/ocid1.stream.oc1.test.stream/messages",
            "cell-1.streaming.us-east-1.oci.oraclecloud.com",
            "Fri, 12 Sep 2026 11:18:09 GMT",
            &[0u8; 128],
        )
        .unwrap();
        assert!(header.starts_with("Signature version=\"1\",headers=\"(request-target) host date x-content-sha256 content-type content-length\",keyId=\"ocid1.tenancy.oc1..test/ocid1.user.oc1..test/20:3b:97:13:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55\",algorithm=\"rsa-sha256\",signature=\""));
    }

    #[test]
    fn test_body_and_partial_isolation() {
        // Base64 key/value framing.
        let body = render_put_messages(&[OciMessage {
            key_b64: base64_encode(b"device-1"),
            value_b64: base64_encode(br#"{'temp':24.5}"#),
        }]);
        let doc: serde_json::Value =
            serde_json::from_str(&String::from_utf8(body).unwrap()).unwrap();
        assert_eq!(doc["messages"][0]["key"], "ZGV2aWNlLTE=");
        // Partial entries: error entries fail by position.
        assert_eq!(
            failed_positions(br#"{"failures":1,"entries":[{"offset":100,"partition":"0"},{"error":"TooManyRequests","errorMessage":"slow"}]}"#).unwrap(),
            vec![1]
        );
        assert!(
            failed_positions(br#"{"failures":0,"entries":[{"offset":1,"partition":"0"}]}"#)
                .unwrap()
                .is_empty()
        );
        assert!(failed_positions(b"nope").is_err());
    }

    #[test]
    fn test_status_classification() {
        assert!(
            classify_put_response(200, br#"{"failures":0,"entries":[]}"#)
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            classify_put_response(429, b"{}"),
            Err(ConnectorError::Connection(_))
        ));
        assert!(matches!(
            classify_put_response(500, b"{}"),
            Err(ConnectorError::Connection(_))
        ));
        assert!(matches!(
            classify_put_response(400, br#"{"code":"InvalidParameter"}"#),
            Err(ConnectorError::Dispatch(_))
        ));
        assert!(matches!(
            classify_put_response(404, br#"{"code":"NotAuthorizedOrNotFound"}"#),
            Err(ConnectorError::Dispatch(_))
        ));
    }

    #[tokio::test]
    async fn test_publish_flow_and_requeue() {
        let mut config = test_config();
        config.batch_size = Some(10);
        config.initial_backoff_ms = Some(1);
        config.max_backoff_ms = Some(2);
        let (sink, transport) = test_sink(config);
        // First pass fails position 1; the retry carries it alone.
        transport.script_outcomes(vec![
            MockOciOutcome::PartialFailed(vec![1]),
            MockOciOutcome::Accepted,
        ]);

        let topic = Topic::new("sensors/t1").unwrap();
        for payload in [
            br#"{"client_id":"device-1","v":1}"#.as_slice(),
            br#"{"client_id":"device-1","v":2}"#.as_slice(),
        ] {
            sink.send(&topic, &Bytes::from(payload.to_vec()), QoS::AtMostOnce)
                .await
                .unwrap();
        }
        sink.flush().await.unwrap();

        assert_eq!(transport.calls(), 2);
        let captured = transport.captured();
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[0].messages.len(), 2);
        // Partition keys base64 the client id.
        assert_eq!(captured[0].messages[0].key_b64, "ZGV2aWNlLTE=");
        assert_eq!(captured[1].messages.len(), 1);
        let value = base64::engine::general_purpose::STANDARD
            .decode(&captured[1].messages[0].value_b64)
            .unwrap();
        assert_eq!(value, br#"{"client_id":"device-1","v":2}"#);
        assert_eq!(sink.sent_records(), 2);
        assert_eq!(sink.buffered_rows(), 0);
    }

    /// Cryptographically verify one loopback PUT the way the real
    /// service does: the `keyId` names the test identity, the
    /// `x-content-sha256` header is the exact hash of the body, and
    /// the RSA-SHA256 signature verifies against the public half of
    /// the test key over the reconstructed signing string. A fake
    /// that accepted any signature would prove nothing about
    /// authentication.
    fn verify_loopback_auth(
        path: &str,
        headers: &axum::http::HeaderMap,
        body: &[u8],
        expected_key_id: &str,
    ) -> std::result::Result<(), String> {
        use rsa::pkcs1v15::{Signature, VerifyingKey};
        use rsa::signature::Verifier;
        let header = |name: &str| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string()
        };
        let auth = header("authorization");
        let key_id = auth
            .split("keyId=\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .unwrap_or_default();
        if key_id != expected_key_id {
            return Err(format!("keyId mismatch: {key_id:?}"));
        }
        if !auth.contains("algorithm=\"rsa-sha256\"") {
            return Err("signature algorithm is not rsa-sha256".to_string());
        }
        let signature_b64 = auth
            .split("signature=\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .unwrap_or_default();
        if header("x-content-sha256") != content_sha256_b64(body) {
            return Err("x-content-sha256 is not the body hash".to_string());
        }
        if header("content-type") != "application/json" {
            return Err("content-type is not application/json".to_string());
        }
        if header("content-length") != body.len().to_string() {
            return Err("content-length does not match the body".to_string());
        }
        let signing = signing_string(
            path,
            &header("host"),
            &header("date"),
            &content_sha256_b64(body),
            body.len(),
        );
        let private = parse_rsa_key(OCI_TEST_KEY).map_err(|e| e.to_string())?;
        let verifying = VerifyingKey::<Sha256>::new(rsa::RsaPublicKey::from(&private));
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(signature_b64)
            .map_err(|e| format!("signature is not base64: {e}"))?;
        let signature =
            Signature::try_from(bytes.as_slice()).map_err(|e| format!("bad signature: {e}"))?;
        verifying
            .verify(signing.as_bytes(), &signature)
            .map_err(|e| format!("RSA-SHA256 verification failed: {e}"))
    }

    #[tokio::test]
    async fn test_loopback_signed_put() {
        use axum::{http::StatusCode, routing::post, Router};
        use std::sync::Arc as StdArc;

        struct Loopback {
            key_id: String,
            path: String,
        }
        let state = StdArc::new(Loopback {
            key_id: test_config().key_id(),
            path: test_config().messages_path(),
        });

        async fn handler(
            headers: axum::http::HeaderMap,
            body: bytes::Bytes,
            state: axum::extract::State<StdArc<Loopback>>,
        ) -> (StatusCode, String) {
            verify_loopback_auth(&state.path, &headers, &body, &state.key_id)
                .expect("loopback must verify the RSA signature");
            let parsed: serde_json::Value = serde_json::from_slice(&body).expect("json");
            assert_eq!(parsed["messages"].as_array().expect("array").len(), 1);
            (
                StatusCode::OK,
                "{\"failures\":0,\"entries\":[{\"offset\":1,\"partition\":\"0\"}]}".to_string(),
            )
        }
        let app = Router::new().route(
            "/20180418/streams/ocid1.stream.oc1.test.stream/messages",
            post({
                let state = state.clone();
                move |headers: axum::http::HeaderMap, body: bytes::Bytes| {
                    let state = state.clone();
                    async move { handler(headers, body, axum::extract::State(state)).await }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        let mut config = test_config();
        config.endpoint = format!("http://127.0.0.1:{port}");
        let transport =
            Arc::new(HttpOciStreamingTransport::new(&config, reqwest::Client::new()).unwrap());
        let message = OciMessage {
            key_b64: base64_encode(b"k"),
            value_b64: base64_encode(b"loopback-body"),
        };
        let result = transport
            .put_messages(
                vec![message],
                &OciAuthHeaders {
                    authorization: String::new(),
                    date: String::new(),
                    content_sha256_b64: String::new(),
                },
            )
            .await
            .expect("loopback put succeeds");
        assert!(result.is_empty());
        server.abort();
    }

    /// Manager-level write path over the real `reqwest` driver
    /// ([`HttpOciStreamingTransport`]).
    ///
    /// Serves its own loopback receiver (ephemeral `axum` server that
    /// cryptographically verifies the RSA signature on every PUT),
    /// streams 500 events with rotating partition keys through the
    /// broker's connector manager (`ConnectorManager` ->
    /// `OciStreamingSink`, never `sink.send` directly), asserts exact
    /// per-key counts with no loss, then proves a scripted 429
    /// retries to success. Runs offline: needs only loopback, never
    /// skips.
    ///
    /// QUAL-NONE: tenancy-scoped cloud service with no runnable
    /// server, so there is no `QUAL_RESULT` to produce; offset commit
    /// and key rotation against the real service stay deferred to a
    /// credentialed run (see the module docs).
    #[tokio::test]
    async fn test_oci_loopback_write_path_through_manager() {
        use axum::{http::StatusCode, routing::post, Router};
        use broker_connectors::ConnectorManager;
        use std::sync::{
            atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering},
            Mutex as StdMutex,
        };

        const EVENTS: usize = 500;
        const KEYS: usize = 16;

        #[derive(Debug, Default)]
        struct QualState {
            key_id: String,
            path: String,
            calls: AtomicU64,
            verified: AtomicU64,
            entries: StdMutex<Vec<(String, Vec<u8>)>>,
            fail_first: AtomicBool,
        }

        async fn qual_handler(
            state: axum::extract::State<Arc<QualState>>,
            headers: axum::http::HeaderMap,
            body: bytes::Bytes,
        ) -> (StatusCode, String) {
            state.calls.fetch_add(1, AtomicOrdering::SeqCst);
            verify_loopback_auth(&state.path, &headers, &body, &state.key_id)
                .expect("qual must verify the RSA signature");
            state.verified.fetch_add(1, AtomicOrdering::SeqCst);
            if state.fail_first.swap(false, AtomicOrdering::SeqCst) {
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    "{\"code\":\"TooManyRequests\"}".to_string(),
                );
            }
            let parsed: serde_json::Value =
                serde_json::from_slice(&body).expect("qual body parses");
            let messages = parsed["messages"].as_array().expect("qual array");
            {
                let mut entries = state.entries.lock().unwrap();
                for message in messages {
                    let key = message["key"].as_str().unwrap_or_default().to_string();
                    let value_b64 = message["value"].as_str().unwrap_or_default().to_string();
                    let value = base64::engine::general_purpose::STANDARD
                        .decode(&value_b64)
                        .expect("qual value decodes");
                    entries.push((key, value));
                }
            }
            let entries_json: String = (0..messages.len())
                .map(|index| format!("{{\"offset\":{index},\"partition\":\"0\"}}"))
                .collect::<Vec<_>>()
                .join(",");
            (
                StatusCode::OK,
                format!("{{\"failures\":0,\"entries\":[{entries_json}]}}"),
            )
        }

        let base = test_config();
        let state = Arc::new(QualState {
            key_id: base.key_id(),
            path: base.messages_path(),
            ..QualState::default()
        });
        let app = Router::new().route(
            "/20180418/streams/ocid1.stream.oc1.test.stream/messages",
            post({
                let state = state.clone();
                move |headers: axum::http::HeaderMap, body: bytes::Bytes| async move {
                    qual_handler(axum::extract::State(state), headers, body).await
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("qual bind loopback");
        let port = listener.local_addr().expect("qual addr").port();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("qual serve");
        });

        let mut config = test_config();
        config.endpoint = format!("http://127.0.0.1:{port}");
        config.batch_size = Some(EVENTS);
        config.buffer_capacity = Some(10_000);
        config.initial_backoff_ms = Some(1);
        config.max_backoff_ms = Some(2);
        let transport = Arc::new(
            HttpOciStreamingTransport::new(&config, reqwest::Client::new())
                .expect("qual transport"),
        );
        let sink = Arc::new(OciStreamingSink::new(config, transport).expect("qual sink"));
        assert_eq!(sink.kind(), "oci_streaming");
        let manager = ConnectorManager::new();
        manager.register("qual-oci", sink.clone());

        // 500 events with rotating partition keys (offline analogue
        // of key rotation): every key must arrive exactly, none lost.
        let topic = Topic::new("sensors/qual").unwrap();
        let mut expected: Vec<(String, Vec<u8>)> = Vec::with_capacity(EVENTS);
        for seq in 0..EVENTS {
            let device = format!("dev-{0:02}", seq % KEYS);
            let payload = format!(r#"{{"client_id":"{device}","seq":{seq}}}"#);
            let key_b64 = base64::engine::general_purpose::STANDARD.encode(&device);
            expected.push((key_b64, payload.clone().into_bytes()));
            manager
                .send("qual-oci", &topic, &Bytes::from(payload), QoS::AtLeastOnce)
                .await
                .expect("qual send");
        }
        sink.flush().await.expect("qual flush");
        assert_eq!(sink.sent_records(), EVENTS as u64, "qual row count");
        assert_eq!(sink.buffered_rows(), 0);
        assert_eq!(
            state.verified.load(AtomicOrdering::SeqCst),
            state.calls.load(AtomicOrdering::SeqCst),
            "every PUT must carry a verifiable signature"
        );
        eprintln!(
            "qual rows sent: records={EVENTS} puts={}",
            state.calls.load(AtomicOrdering::SeqCst)
        );

        // Exact per-key counts, no tolerance: at-least-once permits
        // duplicates, never loss, and the loopback server dedups
        // nothing, so every key is present exactly as offered.
        let captured = state.entries.lock().unwrap().clone();
        assert_eq!(captured.len(), EVENTS, "qual captured count");
        let mut per_key = std::collections::HashMap::new();
        for entry in &captured {
            *per_key.entry(entry.0.clone()).or_insert(0usize) += 1;
        }
        assert_eq!(per_key.len(), KEYS, "all rotating keys present");
        for seq in 0..KEYS {
            let key_b64 = base64::engine::general_purpose::STANDARD.encode(format!("dev-{seq:02}"));
            let want = EVENTS / KEYS + usize::from(seq < EVENTS % KEYS);
            assert_eq!(per_key.get(&key_b64), Some(&want), "key {seq:02} count");
        }
        for (index, ((got_key, got_value), (want_key, want_value))) in
            captured.iter().zip(expected.iter()).enumerate()
        {
            assert_eq!(got_key, want_key, "qual key byte mismatch at {index}");
            assert_eq!(got_value, want_value, "qual body byte mismatch at {index}");
        }
        eprintln!("qual rows asserted: count={EVENTS} byte-identical with verified signatures");

        // Scripted 429 retries the whole batch to success.
        let calls_before = state.calls.load(AtomicOrdering::SeqCst);
        let entries_before = state.entries.lock().unwrap().len();
        state.fail_first.store(true, AtomicOrdering::SeqCst);
        manager
            .send(
                "qual-oci",
                &topic,
                &Bytes::from_static(br#"{"client_id":"dev-00","seq":"retry-probe"}"#),
                QoS::AtLeastOnce,
            )
            .await
            .expect("qual retry buffer");
        sink.flush().await.expect("429-then-200 must succeed");
        assert_eq!(
            state.calls.load(AtomicOrdering::SeqCst),
            calls_before + 2,
            "one 429 plus one 200"
        );
        assert_eq!(state.entries.lock().unwrap().len(), entries_before + 1);
        assert_eq!(sink.buffered_rows(), 0);
        eprintln!("qual retry asserted: 429-then-200 delivered once with verified signature");

        // Cleanup: stop the loopback receiver (nothing else to remove;
        // no stream, tenancy, or container was created).
        server.abort();
        eprintln!("qual done: rows={} cleaned loopback receiver", EVENTS + 1);
    }
}
