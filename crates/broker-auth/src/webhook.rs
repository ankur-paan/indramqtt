//! HTTP webhook authentication and authorization (B5-04, T-97).
//!
//! CONNECT authentication and per-publish authorization against a
//! verdict endpoint owned by the operator:
//!
//! - at CONNECT the credentials (username plus the password bytes) are
//!   POSTed as JSON and the endpoint's verdict is honored: `allow: true`
//!   connects, anything else refuses;
//! - on the publish path the publish context (client id plus topic) is
//!   POSTed and the verdict is honored before delivery: `allow: true`
//!   delivers, anything else refuses like an ACL denial.
//!
//! One configured endpoint serves both checks, distinguished by a
//! `kind` field (`"auth"` or `"publish"`), so the operator runs a single
//! verdict service:
//!
//! - auth: `{"kind":"auth","client_id":..,"username":..,"password_b64":..}`
//! - publish: `{"kind":"publish","client_id":..,"topic":..}`
//! - verdict: `{"allow": bool}` with HTTP 200; the `allow` key is
//!   required, so a 200 carrying anything else fails closed.
//!
//! TODO(parity): should authentication and publish authorization use
//! separate endpoint URLs, and should the publish context carry more
//! than client id plus topic (username, QoS, retain, payload)? Neither
//! this rulebook nor the task spec decides the wire shape; the current
//! choice is one endpoint with the minimal context, so enabling the
//! webhook never leaks payload bytes to the verdict service.
//!
//! Resilience, all bounded and all fail-closed (an unreachable, slow or
//! disagreeing endpoint denies access and never grants it, with a clear
//! log line):
//!
//! - a bounded request pool: at most `pool_size` concurrent webhook
//!   requests (semaphore) over a client keeping at most `pool_size`
//!   idle connections per host;
//! - a stated per-request timeout covering connect plus response;
//! - a circuit breaker: `breaker_failure_threshold` consecutive request
//!   failures trip the circuit open; while open every check fails fast
//!   without touching the network; after `breaker_reset_timeout_ms`
//!   one half-open probe is admitted and its outcome closes or re-opens
//!   the circuit;
//! - a bounded verdict cache: at most `cache_max_entries` entries,
//!   each living `cache_ttl_secs` seconds (`0` disables the cache).
//!   Expired entries are evicted lazily on read and swept on insert;
//!   when full after the sweep the oldest-inserted entry is evicted
//!   (one bounded scan of at most `cache_max_entries` keys). Transport
//!   failures are never cached; explicit deny verdicts are cached like
//!   allows, for the same TTL.
//!
//! Publish-path cost: a cache hit is one short mutex lock plus a hash
//! lookup (no I/O, no allocation past the key); a cache miss is one
//! bounded HTTP round-trip behind the semaphore. The breaker check runs
//! before the cache, so an open circuit refuses even cacheable checks.
//!
//! Client: `reqwest` 0.12 (MIT/Apache-2.0), the maintained async HTTP
//! client. No HTTP is hand-rolled. Passwords travel base64-encoded so
//! binary credentials survive JSON exactly.

use crate::{AuthError, Authenticator, Authorizer, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use broker_protocol::{Topic, TopicFilter};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

/// Default bound on concurrent webhook requests (B5-04). Eight permits
/// absorb a CONNECT burst while keeping a slow endpoint from spawning
/// unbounded work; each slot holds at most one small POST of a few
/// hundred bytes. Mirrors the directory pool bound.
pub const WEBHOOK_POOL_SIZE: usize = 8;

/// Default per-request timeout in milliseconds (B5-04). Two seconds
/// bounds the worst case a CONNECT or a publish waits for a verdict
/// while tolerating loopback verdict services under load; the publish
/// path cannot afford the directory's five seconds per packet.
pub const WEBHOOK_REQUEST_TIMEOUT_MS: u64 = 2_000;

/// Default consecutive request failures before the breaker opens
/// (B5-04). Five tolerates one transient (a single dropped connection)
/// while tripping fast under a real outage.
pub const WEBHOOK_BREAKER_THRESHOLD: u32 = 5;

/// Default open-circuit reset timeout in milliseconds (B5-04). Thirty
/// seconds gives a dead endpoint time to recover without hammering it,
/// while a recovered endpoint is re-admitted within half a minute.
pub const WEBHOOK_BREAKER_RESET_MS: u64 = 30_000;

/// Default bound on cached verdicts (B5-04). 1024 entries of under 256
/// bytes each hold the cache under 256 KiB; matches the replay-cache
/// bound so CONNECT-adjacent memory shares one story.
pub const WEBHOOK_CACHE_MAX_ENTRIES: usize = 1024;

/// Default verdict time-to-live in seconds (B5-04). Sixty seconds
/// removes per-packet HTTP cost for steady publishers while capping the
/// stale-verdict window at one minute. `0` disables the cache.
pub const WEBHOOK_CACHE_TTL_SECS: u64 = 60;

fn default_pool_size() -> usize {
    WEBHOOK_POOL_SIZE
}

fn default_request_timeout_ms() -> u64 {
    WEBHOOK_REQUEST_TIMEOUT_MS
}

fn default_breaker_threshold() -> u32 {
    WEBHOOK_BREAKER_THRESHOLD
}

fn default_breaker_reset_ms() -> u64 {
    WEBHOOK_BREAKER_RESET_MS
}

fn default_cache_max_entries() -> usize {
    WEBHOOK_CACHE_MAX_ENTRIES
}

fn default_cache_ttl_secs() -> u64 {
    WEBHOOK_CACHE_TTL_SECS
}

/// HTTP webhook verdict configuration.
///
/// An empty `endpoint_url` disables the mechanism: every check fails
/// closed without opening a socket. `cache_ttl_secs` of `0` disables
/// the verdict cache (every check asks the endpoint, still behind the
/// pool, the timeout and the breaker).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    #[serde(default)]
    pub endpoint_url: String,
    #[serde(default = "default_pool_size")]
    pub pool_size: usize,
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
    #[serde(default = "default_breaker_threshold")]
    pub breaker_failure_threshold: u32,
    #[serde(default = "default_breaker_reset_ms")]
    pub breaker_reset_timeout_ms: u64,
    #[serde(default = "default_cache_max_entries")]
    pub cache_max_entries: usize,
    #[serde(default = "default_cache_ttl_secs")]
    pub cache_ttl_secs: u64,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            endpoint_url: String::new(),
            pool_size: default_pool_size(),
            request_timeout_ms: default_request_timeout_ms(),
            breaker_failure_threshold: default_breaker_threshold(),
            breaker_reset_timeout_ms: default_breaker_reset_ms(),
            cache_max_entries: default_cache_max_entries(),
            cache_ttl_secs: default_cache_ttl_secs(),
        }
    }
}

impl WebhookConfig {
    fn effective_pool_size(&self) -> usize {
        // 1..=32 like the directory pool: at least one request can
        // proceed, never more than a small burst against the endpoint.
        self.pool_size.clamp(1, 32)
    }

    fn effective_request_timeout(&self) -> Duration {
        // 100 ms floors away a zero-timeout typo that would fail every
        // check; 30 s caps the worst case a CONNECT or publish waits.
        Duration::from_millis(self.request_timeout_ms.clamp(100, 30_000))
    }

    fn effective_breaker_threshold(&self) -> u32 {
        // 1..=100: at least one failure trips when asked, never a count
        // so high the breaker is decorative.
        self.breaker_failure_threshold.clamp(1, 100)
    }

    fn effective_breaker_reset_ms(&self) -> u64 {
        // 1 s floors away a hot spin on a dead endpoint; 5 min caps how
        // long a recovered endpoint stays unprobed.
        self.breaker_reset_timeout_ms.clamp(1_000, 300_000)
    }

    fn effective_cache_max(&self) -> usize {
        // 1..=8192: the cache always holds at least one verdict when
        // enabled, never more than a few megabytes of small entries.
        self.cache_max_entries.clamp(1, 8192)
    }

    fn effective_cache_ttl(&self) -> Duration {
        // 1 s floors away sub-second churn; one hour caps the
        // stale-verdict window an operator can configure by accident.
        Duration::from_secs(self.cache_ttl_secs.clamp(1, 3600))
    }

    fn cache_enabled(&self) -> bool {
        self.cache_ttl_secs > 0
    }
}

/// Verdict the endpoint must return (HTTP 200 with this JSON body).
/// `allow` is required: a body without it is a parse error and fails
/// closed rather than guessing.
#[derive(Debug, Deserialize)]
struct VerdictResponse {
    allow: bool,
}

/// One cached verdict plus when the endpoint gave it.
#[derive(Debug, Clone, Copy)]
struct VerdictEntry {
    allow: bool,
    inserted: Instant,
}

/// Breaker positions. `Open` refuses without network I/O; `HalfOpen`
/// admits exactly one probe while the rest refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BreakerKind {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Debug)]
struct BreakerState {
    kind: BreakerKind,
    consecutive_failures: u32,
    opened_at: Option<Instant>,
    probe_in_flight: bool,
}

/// Admission outcome of the breaker gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BreakerDecision {
    /// Proceed (normal closed path).
    Admit,
    /// Proceed as the single half-open probe.
    Probe,
    /// Fail closed fast without touching the network.
    Reject,
}

/// HTTP webhook authenticator and publish authorizer.
///
/// Holds no credential map: every cache miss POSTs to the configured
/// endpoint through `reqwest`. Concurrency is bounded by a semaphore
/// (`pool_size` permits); verdicts are cached bounded with a TTL; the
/// breaker trips open under consecutive request failures. All shared
/// state sits behind short non-async mutexes that are never held across
/// an `.await`.
pub struct WebhookAuth {
    config: WebhookConfig,
    client: reqwest::Client,
    semaphore: Arc<Semaphore>,
    breaker: Mutex<BreakerState>,
    cache: Mutex<HashMap<String, VerdictEntry>>,
}

impl WebhookAuth {
    pub fn new(config: WebhookConfig) -> Self {
        let permits = config.effective_pool_size();
        let timeout = config.effective_request_timeout();
        // Infallible in practice with a clamped timeout and pool bound;
        // a builder failure would mean the HTTP stack itself is broken,
        // which must surface loudly rather than run unverified.
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .pool_max_idle_per_host(permits)
            // Idle-keepalive 90 s: the HTTP client's upstream default, kept
            // so a steady publisher reuses one pooled verdict connection
            // across the 60 s verdict TTL instead of handshaking per TTL
            // window, while idle sockets still close rather than accumulate.
            .pool_idle_timeout(Duration::from_secs(90))
            .build()
            .expect("webhook HTTP client builds with a clamped timeout and pool bound");
        Self {
            config,
            client,
            semaphore: Arc::new(Semaphore::new(permits)),
            breaker: Mutex::new(BreakerState {
                kind: BreakerKind::Closed,
                consecutive_failures: 0,
                opened_at: None,
                probe_in_flight: false,
            }),
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn config(&self) -> &WebhookConfig {
        &self.config
    }

    /// Whether an endpoint is configured. Empty disables the mechanism
    /// (fail closed, no socket opened).
    pub fn is_configured(&self) -> bool {
        !self.config.endpoint_url.is_empty()
    }

    /// Cached verdict count (observed by tests, never on the hot path).
    pub fn cache_len(&self) -> usize {
        self.cache.lock().len()
    }

    /// Whether the breaker is currently open (observed by tests).
    pub fn breaker_is_open(&self) -> bool {
        self.breaker.lock().kind == BreakerKind::Open
    }

    /// Consecutive request failures counted toward the threshold.
    pub fn consecutive_failures(&self) -> u32 {
        self.breaker.lock().consecutive_failures
    }

    fn fail_auth(client_id: &str, reason: &str) -> AuthError {
        AuthError::AuthenticationFailed(format!("{client_id} {reason}"))
    }

    /// Breaker gate: short mutex only, no I/O. An open circuit whose
    /// reset timeout has passed moves to half-open and admits exactly
    /// one probe; every other check while open or probing rejects fast.
    fn breaker_admit(&self) -> BreakerDecision {
        let mut state = self.breaker.lock();
        match state.kind {
            BreakerKind::Closed => BreakerDecision::Admit,
            BreakerKind::Open => {
                let reset = Duration::from_millis(self.config.effective_breaker_reset_ms());
                let elapsed = state.opened_at.map(|at| at.elapsed());
                match elapsed {
                    Some(past) if past >= reset => {
                        state.kind = BreakerKind::HalfOpen;
                        state.probe_in_flight = true;
                        BreakerDecision::Probe
                    }
                    _ => BreakerDecision::Reject,
                }
            }
            BreakerKind::HalfOpen => {
                if state.probe_in_flight {
                    BreakerDecision::Reject
                } else {
                    state.probe_in_flight = true;
                    BreakerDecision::Probe
                }
            }
        }
    }

    /// A successful endpoint round-trip (either verdict) closes the
    /// breaker and clears the failure count.
    fn breaker_success(&self) {
        let mut state = self.breaker.lock();
        state.kind = BreakerKind::Closed;
        state.consecutive_failures = 0;
        state.opened_at = None;
        state.probe_in_flight = false;
    }

    /// A failed endpoint round-trip (transport, timeout, non-2xx or
    /// unreadable body) counts toward the threshold and trips the
    /// circuit open. Explicit deny verdicts never reach here.
    fn breaker_failure(&self) {
        let threshold = self.config.effective_breaker_threshold();
        let mut state = self.breaker.lock();
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        state.probe_in_flight = false;
        if state.kind == BreakerKind::HalfOpen || state.consecutive_failures >= threshold {
            if state.kind != BreakerKind::Open {
                tracing::warn!(
                    failures = state.consecutive_failures,
                    threshold = threshold,
                    "webhook verdict endpoint failing: circuit open, failing closed"
                );
            }
            state.kind = BreakerKind::Open;
            state.opened_at = Some(Instant::now());
        }
    }

    /// Fresh cached verdict, if any. Expired entries are dropped on
    /// read. Short mutex only, no I/O.
    fn cache_lookup(&self, key: &str) -> Option<bool> {
        if !self.config.cache_enabled() {
            return None;
        }
        let ttl = self.config.effective_cache_ttl();
        let mut cache = self.cache.lock();
        match cache.get(key) {
            Some(entry) if entry.inserted.elapsed() <= ttl => Some(entry.allow),
            Some(_) => {
                cache.remove(key);
                None
            }
            None => None,
        }
    }

    /// Store one endpoint verdict. Sweeps expired entries first, then
    /// evicts the oldest-inserted entry when still full (one bounded
    /// scan of at most `cache_max_entries` keys). Short mutex only.
    fn cache_store(&self, key: String, allow: bool) {
        if !self.config.cache_enabled() {
            return;
        }
        let max = self.config.effective_cache_max();
        let ttl = self.config.effective_cache_ttl();
        let now = Instant::now();
        let mut cache = self.cache.lock();
        cache.retain(|_, entry| now.duration_since(entry.inserted) <= ttl);
        if cache.len() >= max && !cache.contains_key(&key) {
            let oldest = cache
                .iter()
                .min_by_key(|(_, entry)| entry.inserted)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                cache.remove(&oldest);
            }
        }
        cache.insert(
            key,
            VerdictEntry {
                allow,
                inserted: now,
            },
        );
    }

    /// Ask the endpoint for one verdict: breaker gate, then cache, then
    /// one bounded HTTP round-trip. `Ok(allow)` carries an explicit
    /// endpoint verdict (cached); `Err(())` is any failure and always
    /// fails closed at the call site.
    async fn verdict(
        &self,
        cache_key: String,
        body: serde_json::Value,
    ) -> std::result::Result<bool, ()> {
        if self.breaker_admit() == BreakerDecision::Reject {
            tracing::warn!("webhook verdict endpoint unavailable: circuit open, failing closed");
            return Err(());
        }
        if let Some(allow) = self.cache_lookup(&cache_key) {
            return Ok(allow);
        }
        let request_timeout = self.config.effective_request_timeout();
        let _permit = match tokio::time::timeout(request_timeout, self.semaphore.acquire()).await {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) => {
                tracing::warn!(
                    "webhook verdict endpoint unavailable: request pool closed, failing closed"
                );
                self.breaker_failure();
                return Err(());
            }
            Err(_) => {
                tracing::warn!(
                    "webhook verdict endpoint unavailable: request pool exhausted, failing closed"
                );
                self.breaker_failure();
                return Err(());
            }
        };
        let response = self
            .client
            .post(self.config.endpoint_url.as_str())
            .json(&body)
            .send()
            .await;
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                tracing::warn!(
                    "webhook verdict endpoint unavailable: request failed ({error}), failing closed"
                );
                self.breaker_failure();
                return Err(());
            }
        };
        if !response.status().is_success() {
            tracing::warn!(
                status = %response.status(),
                "webhook verdict endpoint unavailable: bad status, failing closed"
            );
            self.breaker_failure();
            return Err(());
        }
        match response.json::<VerdictResponse>().await {
            Ok(parsed) => {
                self.breaker_success();
                self.cache_store(cache_key, parsed.allow);
                Ok(parsed.allow)
            }
            Err(error) => {
                tracing::warn!(
                    "webhook verdict endpoint unavailable: unreadable verdict ({error}), failing closed"
                );
                self.breaker_failure();
                Err(())
            }
        }
    }
}

#[async_trait]
impl Authenticator for WebhookAuth {
    async fn authenticate(
        &self,
        client_id: &str,
        username: Option<&str>,
        password: Option<&[u8]>,
    ) -> Result<()> {
        if !self.is_configured() {
            tracing::warn!(
                "webhook authentication unavailable: endpoint_url is not configured, failing closed"
            );
            return Err(Self::fail_auth(
                client_id,
                "presented webhook credentials, but no webhook is configured",
            ));
        }
        let (Some(username), Some(password)) = (username, password) else {
            return Err(Self::fail_auth(
                client_id,
                "presented no webhook credentials",
            ));
        };
        if username.is_empty() {
            return Err(Self::fail_auth(
                client_id,
                "presented no webhook credentials",
            ));
        }
        // The cache key hashes the password (SHA-256 hex) so the secret
        // itself never sits in the map as a plain string.
        let digest = Sha256::digest(password);
        let cache_key = format!(
            "auth\x00{client_id}\x00{username}\x00{}",
            hex_bytes(&digest)
        );
        let body = serde_json::json!({
            "kind": "auth",
            "client_id": client_id,
            "username": username,
            "password_b64": B64.encode(password),
        });
        match self.verdict(cache_key, body).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(Self::fail_auth(client_id, "refused by webhook verdict")),
            Err(()) => Err(Self::fail_auth(
                client_id,
                "presented webhook credentials, but the webhook is unavailable",
            )),
        }
    }
}

#[async_trait]
impl Authorizer for WebhookAuth {
    async fn authorize_publish(&self, client_id: &str, topic: &Topic) -> Result<()> {
        if !self.is_configured() {
            tracing::warn!(
                "webhook authorization unavailable: endpoint_url is not configured, failing closed"
            );
            return Err(AuthError::PublishDenied(format!(
                "{client_id} cannot publish"
            )));
        }
        let cache_key = format!("pub\x00{client_id}\x00{}", topic.as_str());
        let body = serde_json::json!({
            "kind": "publish",
            "client_id": client_id,
            "topic": topic.as_str(),
        });
        match self.verdict(cache_key, body).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(AuthError::PublishDenied(format!(
                "{client_id} cannot publish"
            ))),
            Err(()) => Err(AuthError::PublishDenied(format!(
                "{client_id} cannot publish"
            ))),
        }
    }

    async fn authorize_subscribe(&self, _client_id: &str, _filter: &TopicFilter) -> Result<()> {
        // TODO(parity): should the webhook gate subscriptions too? The
        // task spec covers the publish path only, so subscribes stay
        // with the local ACL; the webhook never widens subscribe rights.
        Ok(())
    }
}

/// Lowercase hex of arbitrary bytes (password-digest form for cache
/// keys; never plaintext, no scheme change).
fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0F) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Test-owned verdict endpoint on loopback. It verifies the
    /// credential it receives: auth requests are allowed only when the
    /// username matches `expected_user` and the base64 password decodes
    /// to `expected_pass`. Publish requests follow the `publish_allow`
    /// flag (flipped mid-test for TTL). `fail` answers 500 to prove the
    /// breaker path. Every request bumps `hits` so tests assert exact
    /// endpoint contact (cache hits must not contact it).
    #[derive(Debug)]
    struct VerdictServer {
        expected_user: String,
        expected_pass: Vec<u8>,
        publish_allow: Mutex<bool>,
        fail: Mutex<bool>,
        hits: AtomicUsize,
    }

    impl VerdictServer {
        fn new(user: &str, pass: &[u8]) -> Self {
            Self {
                expected_user: user.to_string(),
                expected_pass: pass.to_vec(),
                publish_allow: Mutex::new(true),
                fail: Mutex::new(false),
                hits: AtomicUsize::new(0),
            }
        }
    }

    async fn verdict_handler(
        State(server): State<Arc<VerdictServer>>,
        body: axum::body::Bytes,
    ) -> (axum::http::StatusCode, String) {
        server.hits.fetch_add(1, Ordering::Relaxed);
        if *server.fail.lock() {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"error": "fault"}).to_string(),
            );
        }
        let parsed: serde_json::Value =
            serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
        let kind = parsed.get("kind").and_then(|value| value.as_str());
        let allow = match kind {
            Some("auth") => {
                let user_ok = parsed.get("username").and_then(|value| value.as_str())
                    == Some(server.expected_user.as_str());
                let pass_ok = parsed
                    .get("password_b64")
                    .and_then(|value| value.as_str())
                    .and_then(|encoded| B64.decode(encoded).ok())
                    == Some(server.expected_pass.clone());
                user_ok && pass_ok
            }
            Some("publish") => *server.publish_allow.lock(),
            _ => false,
        };
        (
            axum::http::StatusCode::OK,
            serde_json::json!({"allow": allow}).to_string(),
        )
    }

    async fn start_server(server: Arc<VerdictServer>) -> (tokio::task::JoinHandle<()>, String) {
        let app = axum::Router::new()
            .route("/", axum::routing::post(verdict_handler))
            .with_state(server);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let url = format!("http://{}", listener.local_addr().expect("local addr"));
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve verdicts");
        });
        (handle, url)
    }

    fn test_config(url: String) -> WebhookConfig {
        WebhookConfig {
            endpoint_url: url,
            pool_size: 4,
            request_timeout_ms: 2_000,
            breaker_failure_threshold: 5,
            breaker_reset_timeout_ms: 30_000,
            cache_max_entries: 128,
            cache_ttl_secs: 60,
        }
    }

    #[tokio::test]
    async fn webhook_allow_and_deny_verdicts() {
        let server = Arc::new(VerdictServer::new("alice", b"alicepw"));
        let (handle, url) = start_server(server.clone()).await;
        let auth = WebhookAuth::new(test_config(url.clone()));
        assert!(auth.is_configured());
        assert_eq!(auth.config().endpoint_url, url);

        // The endpoint verifies the credential: the right password
        // connects, the wrong one is refused by verdict.
        auth.authenticate("device-1", Some("alice"), Some(b"alicepw"))
            .await
            .expect("matching credential must be allowed");
        assert!(
            auth.authenticate("device-2", Some("alice"), Some(b"wrong"))
                .await
                .is_err(),
            "wrong password must be refused by verdict"
        );
        assert!(
            auth.authenticate("device-3", Some("mallory"), Some(b"alicepw"))
                .await
                .is_err(),
            "unknown user must be refused by verdict"
        );
        assert!(
            auth.authenticate("device-4", None, None).await.is_err(),
            "missing credentials must fail"
        );

        // Publish verdicts follow the flag through the same endpoint.
        let topic = Topic::new("sensors/temp").expect("topic");
        auth.authorize_publish("device-1", &topic)
            .await
            .expect("publish must be allowed while the flag is set");
        *server.publish_allow.lock() = false;
        // A fresh topic misses the cache and re-asks the endpoint.
        let other = Topic::new("sensors/other").expect("topic");
        assert!(
            auth.authorize_publish("device-1", &other).await.is_err(),
            "publish must be refused once the verdict flips"
        );

        handle.abort();
    }

    #[tokio::test]
    async fn webhook_unreachable_fails_closed() {
        // Closed loopback port: connection refused, no server.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("ephemeral port");
        let addr = listener.local_addr().expect("local addr");
        drop(listener);
        let auth = WebhookAuth::new(WebhookConfig {
            endpoint_url: format!("http://{addr}"),
            request_timeout_ms: 1_000,
            ..WebhookConfig::default()
        });
        assert!(
            auth.authenticate("device-1", Some("alice"), Some(b"alicepw"))
                .await
                .is_err(),
            "unreachable webhook must deny CONNECT, never grant it"
        );
        let topic = Topic::new("sensors/temp").expect("topic");
        assert!(
            auth.authorize_publish("device-1", &topic).await.is_err(),
            "unreachable webhook must refuse publishes, never allow them"
        );
    }

    #[tokio::test]
    async fn webhook_empty_endpoint_fails_closed_without_network() {
        let auth = WebhookAuth::new(WebhookConfig::default());
        assert!(!auth.is_configured());
        assert!(
            auth.authenticate("c", Some("alice"), Some(b"pw"))
                .await
                .is_err(),
            "unconfigured webhook must fail closed without a socket"
        );
        let topic = Topic::new("a/b").expect("topic");
        assert!(auth.authorize_publish("c", &topic).await.is_err());
    }

    #[tokio::test]
    async fn webhook_breaker_trips_fast_and_recovers() {
        let server = Arc::new(VerdictServer::new("alice", b"alicepw"));
        let (handle, url) = start_server(server.clone()).await;
        let auth = WebhookAuth::new(WebhookConfig {
            endpoint_url: url,
            pool_size: 4,
            request_timeout_ms: 1_000,
            breaker_failure_threshold: 3,
            breaker_reset_timeout_ms: 1_000,
            cache_max_entries: 128,
            cache_ttl_secs: 0,
        });

        *server.fail.lock() = true;
        // Three consecutive failures trip the breaker (distinct client
        // ids; the cache is disabled so every check asks the endpoint).
        for index in 0..3 {
            let client = format!("flap-{index}");
            assert!(
                auth.authenticate(&client, Some("alice"), Some(b"alicepw"))
                    .await
                    .is_err(),
                "faulting endpoint must fail closed"
            );
        }
        assert!(auth.breaker_is_open(), "breaker must trip open");
        let hits_before = server.hits.load(Ordering::Relaxed);
        assert_eq!(hits_before, 3);
        // While open the verdict fails fast without contacting the
        // endpoint again.
        assert!(
            auth.authenticate("flap-fast", Some("alice"), Some(b"alicepw"))
                .await
                .is_err(),
            "open circuit must fail closed"
        );
        assert_eq!(
            server.hits.load(Ordering::Relaxed),
            hits_before,
            "open circuit must not contact the endpoint"
        );

        // After the reset timeout the half-open probe re-asks: with the
        // fault cleared the endpoint recovers and the breaker closes.
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        *server.fail.lock() = false;
        auth.authenticate("flap-probe", Some("alice"), Some(b"alicepw"))
            .await
            .expect("half-open probe must recover once the endpoint heals");
        assert!(
            !auth.breaker_is_open(),
            "breaker must close after a good probe"
        );
        assert_eq!(auth.consecutive_failures(), 0);

        handle.abort();
    }

    #[tokio::test]
    async fn webhook_cache_ttl_expiry_reasks() {
        let server = Arc::new(VerdictServer::new("alice", b"alicepw"));
        let (handle, url) = start_server(server.clone()).await;
        let auth = WebhookAuth::new(WebhookConfig {
            endpoint_url: url,
            pool_size: 4,
            request_timeout_ms: 2_000,
            breaker_failure_threshold: 5,
            breaker_reset_timeout_ms: 30_000,
            cache_max_entries: 128,
            cache_ttl_secs: 1,
        });

        let topic = Topic::new("sensors/temp").expect("topic");
        auth.authorize_publish("device-1", &topic)
            .await
            .expect("first check asks the endpoint");
        assert_eq!(server.hits.load(Ordering::Relaxed), 1);
        assert_eq!(auth.cache_len(), 1, "endpoint verdict must be cached");
        auth.authorize_publish("device-1", &topic)
            .await
            .expect("cached verdict still allows");
        assert_eq!(
            server.hits.load(Ordering::Relaxed),
            1,
            "cache hit must not contact the endpoint"
        );
        // Flip the verdict: the stale entry still allows until the TTL
        // expires.
        *server.publish_allow.lock() = false;
        auth.authorize_publish("device-1", &topic)
            .await
            .expect("stale cache entry still allows before expiry");
        assert_eq!(server.hits.load(Ordering::Relaxed), 1);
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        assert!(
            auth.authorize_publish("device-1", &topic).await.is_err(),
            "expired cache must re-ask and honor the new deny verdict"
        );
        assert_eq!(
            server.hits.load(Ordering::Relaxed),
            2,
            "TTL expiry must re-ask the endpoint exactly once"
        );

        handle.abort();
    }

    /// B5-04 verdict matrix at the authenticator level (QUAL-NONE: no
    /// vendor webhook-auth server product exists, so the test serves its
    /// own verdict endpoint on loopback with allow, deny, flap and stop
    /// faults plus breaker and TTL assertions, and no container is needed).
    ///
    /// Exercises the same `authenticate`/`authorize_publish` calls the
    /// broker's CONNECT and publish paths make (see `apply_bind` at
    /// `crates/broker-node/src/main.rs:450` and `apply_publish` at
    /// `crates/broker-node/src/main.rs:3021`), asserts exact
    /// endpoint-contact counts by key, and never skips: a missing loopback
    /// bind panics via `expect`, and every fault asserts fail-closed. The
    /// pipeline qualification itself lives in the kernel's broker-path
    /// test `test_qualify_webhook_auth_and_publish_through_broker`, which
    /// drives these same calls via `apply_bind`/`apply_publish`; this
    /// matrix keeps the unit-level verdict coverage alongside it.
    #[tokio::test]
    async fn webhook_auth_and_publish_verdict_matrix() {
        let server = Arc::new(VerdictServer::new("alice", b"alicepw"));
        let (handle, url) = start_server(server.clone()).await;
        let auth = WebhookAuth::new(WebhookConfig {
            endpoint_url: url,
            pool_size: 4,
            request_timeout_ms: 2_000,
            breaker_failure_threshold: 5,
            breaker_reset_timeout_ms: 30_000,
            cache_max_entries: 128,
            cache_ttl_secs: 60,
        });

        // Allow verdict: matching credentials authenticate (exact count 1).
        auth.authenticate("qual-conn-1", Some("alice"), Some(b"alicepw"))
            .await
            .expect("seeded webhook credential must be accepted");
        assert_eq!(
            server.hits.load(Ordering::Relaxed),
            1,
            "allow CONNECT must contact the endpoint exactly once"
        );
        // Deny verdicts: wrong password and unknown user refused, one
        // contact each (exact counts 2 and 3).
        assert!(
            auth.authenticate("qual-conn-2", Some("alice"), Some(b"wrong"))
                .await
                .is_err(),
            "wrong webhook password must be refused"
        );
        assert_eq!(server.hits.load(Ordering::Relaxed), 2);
        assert!(
            auth.authenticate("qual-conn-3", Some("mallory"), Some(b"alicepw"))
                .await
                .is_err(),
            "unknown webhook user must be refused"
        );
        assert_eq!(server.hits.load(Ordering::Relaxed), 3);

        // Publish allow then deny on fresh topics (exact counts 4 and 5).
        let topic = Topic::new("qual/allowed").expect("topic");
        auth.authorize_publish("qual-conn-1", &topic)
            .await
            .expect("allowed webhook topic must be permitted");
        assert_eq!(server.hits.load(Ordering::Relaxed), 4);
        *server.publish_allow.lock() = false;
        let denied = Topic::new("qual/denied").expect("topic");
        assert!(
            auth.authorize_publish("qual-conn-1", &denied)
                .await
                .is_err(),
            "denied webhook topic must be refused exactly once"
        );
        assert_eq!(server.hits.load(Ordering::Relaxed), 5);
        *server.publish_allow.lock() = true;
        handle.abort();

        // Stop fault: a dead endpoint fails closed on both paths, never
        // granting access.
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = closed.local_addr().expect("local addr");
        drop(closed);
        let down = WebhookAuth::new(WebhookConfig {
            endpoint_url: format!("http://{addr}"),
            request_timeout_ms: 1_000,
            ..WebhookConfig::default()
        });
        assert!(
            down.authenticate("qual-down", Some("alice"), Some(b"alicepw"))
                .await
                .is_err(),
            "stopped webhook must deny CONNECT, never grant it"
        );
        assert!(
            down.authorize_publish("qual-down", &topic).await.is_err(),
            "stopped webhook must refuse publishes, never allow them"
        );

        // Flap fault: consecutive failures trip the breaker, the open
        // circuit fails fast without endpoint contact, and the half-open
        // probe recovers once the endpoint heals.
        let flap = Arc::new(VerdictServer::new("alice", b"alicepw"));
        let (flap_handle, flap_url) = start_server(flap.clone()).await;
        let tripping = WebhookAuth::new(WebhookConfig {
            endpoint_url: flap_url,
            pool_size: 4,
            request_timeout_ms: 1_000,
            breaker_failure_threshold: 2,
            breaker_reset_timeout_ms: 1_000,
            cache_max_entries: 128,
            cache_ttl_secs: 0,
        });
        *flap.fail.lock() = true;
        for index in 0..2 {
            let client = format!("qual-flap-{index}");
            assert!(
                tripping
                    .authenticate(&client, Some("alice"), Some(b"alicepw"))
                    .await
                    .is_err(),
                "faulting webhook must fail closed"
            );
        }
        assert!(tripping.breaker_is_open(), "breaker must trip open");
        assert_eq!(flap.hits.load(Ordering::Relaxed), 2);
        assert!(
            tripping
                .authenticate("qual-flap-fast", Some("alice"), Some(b"alicepw"))
                .await
                .is_err(),
            "open circuit must fail closed"
        );
        assert_eq!(
            flap.hits.load(Ordering::Relaxed),
            2,
            "open circuit must not contact the endpoint"
        );
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        *flap.fail.lock() = false;
        tripping
            .authenticate("qual-flap-probe", Some("alice"), Some(b"alicepw"))
            .await
            .expect("half-open probe must recover once the endpoint heals");
        assert!(
            !tripping.breaker_is_open(),
            "breaker must close after a good probe"
        );
        flap_handle.abort();

        // TTL fault: expiry re-asks the endpoint exactly once and honors
        // the new verdict.
        let ttl_server = Arc::new(VerdictServer::new("alice", b"alicepw"));
        let (ttl_handle, ttl_url) = start_server(ttl_server.clone()).await;
        let ttl_auth = WebhookAuth::new(WebhookConfig {
            endpoint_url: ttl_url,
            pool_size: 4,
            request_timeout_ms: 2_000,
            breaker_failure_threshold: 5,
            breaker_reset_timeout_ms: 30_000,
            cache_max_entries: 128,
            cache_ttl_secs: 1,
        });
        let ttl_topic = Topic::new("qual/ttl").expect("topic");
        ttl_auth
            .authorize_publish("qual-ttl", &ttl_topic)
            .await
            .expect("first check asks the endpoint");
        assert_eq!(ttl_server.hits.load(Ordering::Relaxed), 1);
        ttl_auth
            .authorize_publish("qual-ttl", &ttl_topic)
            .await
            .expect("cache hit still allows");
        assert_eq!(
            ttl_server.hits.load(Ordering::Relaxed),
            1,
            "cache hit must not contact the endpoint"
        );
        *ttl_server.publish_allow.lock() = false;
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        assert!(
            ttl_auth
                .authorize_publish("qual-ttl", &ttl_topic)
                .await
                .is_err(),
            "expired cache must re-ask and honor the new deny verdict"
        );
        assert_eq!(
            ttl_server.hits.load(Ordering::Relaxed),
            2,
            "TTL expiry must re-ask the endpoint exactly once"
        );
        ttl_handle.abort();
    }
}
