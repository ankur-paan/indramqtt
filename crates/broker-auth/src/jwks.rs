//! JWT verification against a JWKS endpoint (B5-02, T-95).
//!
//! CONNECT-time authentication for JWT-bearer clients. The broker fetches
//! the JSON Web Key Set document from a configured HTTPS endpoint, selects
//! the verification key by the token's `kid`, and checks the signature,
//! expiry, issuer and audience. Keys rotate without a restart: a background
//! task re-fetches on a stated period, and an unknown `kid` triggers one
//! on-demand refresh (singleflight: one in-flight refresh at a time, so a
//! slow endpoint never stacks refreshes).
//!
//! Fail-closed throughout: an unreachable or invalid endpoint denies
//! CONNECT with a clear log line and never grants it. While the endpoint
//! is unhealthy (the last fetch failed) even cache hits are refused, so
//! stopping the endpoint stops access instead of serving stale trust.
//!
//! Wire crates (all maintained, all permissive licences):
//! - `jsonwebtoken` 11 (MIT): signature verification (`RS256`/`ES256`)
//!   plus `exp`/`iss`/`aud` validation. No JWT parsing is hand-rolled.
//! - `reqwest` 0.12 (MIT/Apache-2.0): HTTPS fetch of the JWKS document
//!   with configured timeouts and an explicit response body cap.
//!
//! Memory bounds (CONNECT only, never on the delivery path):
//! - key cache holds at most `cache_max_keys` entries (default 32, about
//!   2 KiB of JWK JSON each, so about 64 KiB worst case); past the bound
//!   the key set is sorted by `kid` and truncated to the bound, so the
//!   same document always caches the same keys. Entries older than
//!   `cache_ttl_secs` count as a miss and trigger a refresh.
//! - the JWKS response body is capped at `max_document_bytes` (default
//!   64 KiB: 32 keys of about 2 KiB each); larger documents are rejected
//!   before buffering past the cap.
//! - one refresh `Mutex`: concurrent CONNECTs on an unknown `kid` poll
//!   the cache until `refresh_timeout_ms`, never queueing a second fetch.
//! - per-CONNECT allocation is bounded by the inbound password length
//!   (itself bounded by the BrokerLink frame) plus small fixed buffers.

use crate::{AuthError, Authenticator, Result};
use async_trait::async_trait;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Default re-fetch period in seconds: rotation propagates within five
/// minutes while the background fetch stays far off the accept path. Fast
/// rotation is covered by the unknown-`kid` trigger, so the period only
/// needs to bound staleness of TTL-expired entries, not rotation delay.
fn default_refresh_period_secs() -> u64 {
    300
}

/// Default fetch timeout in milliseconds: slow-endpoint tolerant while
/// keeping a stalled accept bounded. Matches the directory 5 s default so
/// every CONNECT-time network call has the same ceiling.
fn default_fetch_timeout_ms() -> u64 {
    5_000
}

/// Default on-demand (unknown-`kid`) refresh timeout in milliseconds:
/// same ceiling as the fetch timeout, covering one fetch plus one cache
/// poll window for a CONNECT that arrived with a fresh key.
fn default_refresh_timeout_ms() -> u64 {
    5_000
}

/// Default key-cache bound: JWKS documents carry a handful of rotation
/// keys; 32 entries of about 2 KiB each cap CONNECT-only key memory near
/// 64 KiB while leaving headroom for large multi-tenant sets.
pub const JWKS_CACHE_MAX_KEYS: usize = 32;

fn default_cache_max_keys() -> usize {
    JWKS_CACHE_MAX_KEYS
}

/// Default cache entry TTL in seconds: equals the refresh period so the
/// background task keeps entries fresh and TTL expiry only fires when the
/// background refresh has failed (fail closed, never silently stale).
fn default_cache_ttl_secs() -> u64 {
    300
}

/// Default cap on the JWKS response body in bytes: 32 keys of about
/// 2 KiB of JWK JSON each. Rejects absurd documents before unbounded
/// buffering on the CONNECT path. Exported so the broker boot path uses
/// the same bound instead of a second hardcoded number.
pub const JWKS_DEFAULT_DOCUMENT_CAP: usize = 64 * 1024;

fn default_max_document_bytes() -> usize {
    JWKS_DEFAULT_DOCUMENT_CAP
}

/// Default clock-skew allowance in seconds for `exp`/`nbf`: tolerates a
/// minute of drift between the issuer and the broker without accepting
/// clearly expired tokens.
fn default_clock_skew_secs() -> u64 {
    60
}

/// Default TLS verification (on). Loopback test endpoints opt out
/// explicitly with `tls_verify = false` plus a clear test-only comment.
fn default_tls_verify() -> bool {
    true
}

/// Upper bound on a single JWK component (`n`, `e`, `x`, `y`) in
/// characters: RSA-4096 `n` is about 730 base64url characters, so 1024
/// admits the largest sane signing key while denying absurd inputs early.
const MAX_JWK_COMPONENT_LEN: usize = 1024;

/// Upper bound on a presented token in bytes: denies absurd passwords
/// before base64 decoding on the CONNECT path.
const MAX_TOKEN_LEN: usize = 16 * 1024;

/// JWKS-backed JWT configuration.
///
/// An empty `jwks_url` disables the mechanism: every attempt fails closed
/// (like an unconfigured directory). `issuer`/`audience` empty skips that
/// claim check (deployments verifying signature plus expiry only); set
/// both in production so a token minted for another service is refused.
/// `ca_cert_path` holds a PEM CA file for private issuers; `tls_verify`
/// stays on everywhere except loopback tests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksConfig {
    #[serde(default)]
    pub jwks_url: String,
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub audience: String,
    #[serde(default = "default_refresh_period_secs")]
    pub refresh_period_secs: u64,
    #[serde(default = "default_fetch_timeout_ms")]
    pub fetch_timeout_ms: u64,
    #[serde(default = "default_refresh_timeout_ms")]
    pub refresh_timeout_ms: u64,
    #[serde(default = "default_cache_max_keys")]
    pub cache_max_keys: usize,
    #[serde(default = "default_cache_ttl_secs")]
    pub cache_ttl_secs: u64,
    #[serde(default = "default_max_document_bytes")]
    pub max_document_bytes: usize,
    #[serde(default = "default_clock_skew_secs")]
    pub clock_skew_secs: u64,
    #[serde(default = "default_tls_verify")]
    pub tls_verify: bool,
    #[serde(default)]
    pub ca_cert_path: Option<String>,
}

impl Default for JwksConfig {
    fn default() -> Self {
        Self {
            jwks_url: String::new(),
            issuer: String::new(),
            audience: String::new(),
            refresh_period_secs: default_refresh_period_secs(),
            fetch_timeout_ms: default_fetch_timeout_ms(),
            refresh_timeout_ms: default_refresh_timeout_ms(),
            cache_max_keys: default_cache_max_keys(),
            cache_ttl_secs: default_cache_ttl_secs(),
            max_document_bytes: default_max_document_bytes(),
            clock_skew_secs: default_clock_skew_secs(),
            tls_verify: default_tls_verify(),
            ca_cert_path: None,
        }
    }
}

impl JwksConfig {
    fn effective_fetch_timeout(&self) -> Duration {
        // Reason: floor 100 ms is the fault-test minimum (a stalled accept must still
        // bound CONNECT); ceiling 60 s matches the directory 5 s default family with
        // headroom, so a misconfigured timeout cannot stall the accept path past a minute.
        Duration::from_millis(self.fetch_timeout_ms.clamp(100, 60_000))
    }

    fn effective_refresh_timeout(&self) -> Duration {
        // Reason: same ceiling as the fetch timeout (one fetch plus one cache poll
        // window); floor 100 ms keeps the singleflight poll (25 ms step) meaningful.
        Duration::from_millis(self.refresh_timeout_ms.clamp(100, 60_000))
    }

    fn effective_period(&self) -> Duration {
        // Reason: floor 1 s lets outage-recovery tests tick fast; ceiling 86_400 s
        // (1 day) bounds staleness so a misconfigured period cannot disable rotation.
        Duration::from_secs(self.refresh_period_secs.clamp(1, 86_400))
    }

    fn effective_cache_max(&self) -> usize {
        // Reason: floor 1 keeps at least the active signing key; ceiling 256 (8x the
        // default 32, about 512 KiB at ~2 KiB/key) caps CONNECT-only key memory.
        self.cache_max_keys.clamp(1, 256)
    }

    fn effective_cache_ttl(&self) -> Duration {
        // Reason: floor 1 s keeps TTL expiry testable; ceiling 86_400 s (1 day)
        // bounds stale trust so a misconfigured TTL cannot pin a rotated-out key.
        Duration::from_secs(self.cache_ttl_secs.clamp(1, 86_400))
    }

    fn effective_document_cap(&self) -> usize {
        // Reason: floor 1024 bytes admits the smallest single-RSA-key document;
        // ceiling 1 MiB (16x the 64 KiB default) rejects absurd bodies before
        // unbounded buffering on the CONNECT path.
        self.max_document_bytes.clamp(1024, 1024 * 1024)
    }

    fn effective_skew(&self) -> u64 {
        // Reason: floor 0 disables leeway explicitly; ceiling 3600 s (1 h) bounds the
        // expiry acceptance window so a misconfigured skew cannot accept long-expired tokens.
        self.clock_skew_secs.clamp(0, 3_600)
    }
}

/// One JWKS document as served (`GET` returns `{"keys": [...]}`).
#[derive(Debug, Deserialize)]
struct JwksDocument {
    #[serde(default)]
    keys: Vec<FetchedJwk>,
}

/// One key entry inside the served document. Unknown fields are ignored
/// so issuer-added metadata can never break the fetch.
#[derive(Debug, Deserialize)]
struct FetchedJwk {
    #[serde(default)]
    kid: String,
    #[serde(default)]
    kty: String,
    #[serde(default)]
    alg: String,
    #[serde(default)]
    n: String,
    #[serde(default)]
    e: String,
    #[serde(default)]
    x: String,
    #[serde(default)]
    y: String,
    #[serde(default)]
    crv: String,
}

/// Cached key material: only the components needed to rebuild a
/// `DecodingKey` for the key's type. Each entry holds a few small strings
/// (about 2 KiB for an RSA-2048 key), bounded in count by
/// `cache_max_keys`.
#[derive(Debug, Clone)]
enum KeyMaterial {
    Rsa { n: String, e: String },
    Ec { x: String, y: String },
}

/// One cached verification key plus the insert time driving TTL expiry.
/// The size bound is enforced by deterministic sorted-by-`kid` truncation
/// on every successful refresh (see `fetch_and_store`), not by
/// oldest-first eviction: a refresh replaces the whole set and re-stamps
/// every surviving entry.
#[derive(Debug, Clone)]
struct CachedKey {
    material: KeyMaterial,
    inserted: Instant,
}

/// A verified token: the claims the broker acts on. The session
/// attribution (username/quota slot) uses the verified `subject` when the
/// token carries one, falling back to the MQTT username (the username
/// string is unverified protocol metadata).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedJwt {
    pub subject: String,
    pub issuer: String,
    pub key_id: String,
    pub expires_at: u64,
}

/// JWKS-backed JWT authenticator, consulted at CONNECT.
///
/// Holds no credential map: every trust decision derives from the live
/// endpoint document. Cloned cheaply (`Arc` inner) across CONNECT tasks.
#[derive(Debug, Clone)]
pub struct JwksAuthenticator {
    inner: Arc<JwksInner>,
}

#[derive(Debug)]
struct JwksInner {
    config: JwksConfig,
    client: Option<reqwest::Client>,
    cache: RwLock<HashMap<String, CachedKey>>,
    /// Singleflight: one in-flight refresh at a time. On-demand callers
    /// use `try_lock` and poll the cache instead of queueing, so a slow
    /// endpoint never stacks fetches no matter how many CONNECTs arrive.
    refresh_lock: tokio::sync::Mutex<()>,
    /// Fail-closed health: set by the last fetch outcome. While false,
    /// even cache hits are refused, so an endpoint outage stops access
    /// instead of serving stale trust. Cleared by the next good fetch.
    healthy: AtomicBool,
    /// Successful fetches (drives rotation tests and observability).
    refresh_count: AtomicU64,
    /// Background task claim: the first spawner wins so boot and tests
    /// can call freely without a task per connection.
    bg_claimed: AtomicBool,
}

impl JwksAuthenticator {
    pub fn new(config: JwksConfig) -> Self {
        let client = build_client(&config);
        Self {
            inner: Arc::new(JwksInner {
                config,
                client,
                cache: RwLock::new(HashMap::new()),
                refresh_lock: tokio::sync::Mutex::new(()),
                healthy: AtomicBool::new(false),
                refresh_count: AtomicU64::new(0),
                bg_claimed: AtomicBool::new(false),
            }),
        }
    }

    pub fn config(&self) -> &JwksConfig {
        &self.inner.config
    }

    /// Whether the mechanism is configured (non-empty URL). The broker
    /// treats a configured endpoint like a configured directory: it
    /// disables the anonymous open mode.
    pub fn is_enabled(&self) -> bool {
        !self.inner.config.jwks_url.trim().is_empty()
    }

    /// Whether the last fetch succeeded. False before the first fetch
    /// and after any failed fetch (fail closed until the next good one).
    pub fn is_healthy(&self) -> bool {
        self.inner.healthy.load(Ordering::Relaxed)
    }

    /// Successful fetches so far (rotation and recovery observability).
    pub fn refresh_count(&self) -> u64 {
        self.inner.refresh_count.load(Ordering::Relaxed)
    }

    /// Cached key count (bounded by `cache_max_keys`).
    pub fn cached_key_count(&self) -> usize {
        self.inner.cache.read().len()
    }

    fn fail(client_id: &str, reason: &str) -> AuthError {
        AuthError::AuthenticationFailed(format!("{client_id} {reason}"))
    }

    /// Whether these password bytes look like a JWT (three base64url
    /// segments). Non-JWT passwords keep the existing credential paths;
    /// only JWT-shaped ones enter JWKS verification.
    pub fn looks_like_jwt(password: &[u8]) -> bool {
        if password.len() > MAX_TOKEN_LEN || password.is_empty() {
            return false;
        }
        let Ok(text) = std::str::from_utf8(password) else {
            return false;
        };
        let mut parts = text.split('.');
        matches!(
            (parts.next(), parts.next(), parts.next(), parts.next()),
            (Some(a), Some(b), Some(c), None)
                if !a.is_empty() && !b.is_empty() && !c.is_empty()
        )
    }

    /// Verify one token: cache hit verifies locally, cache miss triggers
    /// one singleflight refresh and retries once. Any endpoint problem
    /// fails closed with a warn log naming the `kid`, never the token.
    pub async fn verify_token(&self, client_id: &str, token: &str) -> Result<VerifiedJwt> {
        if token.len() > MAX_TOKEN_LEN {
            return Err(Self::fail(
                client_id,
                "presented credentials that cannot be verified",
            ));
        }
        if !self.is_enabled() {
            tracing::warn!("JWKS endpoint unavailable: jwks_url is not configured");
            return Err(Self::fail(
                client_id,
                "presented JWT credentials, but no JWKS endpoint is configured",
            ));
        }
        let header = jsonwebtoken::decode_header(token).map_err(|_| {
            Self::fail(
                client_id,
                "presented JWT credentials that cannot be verified",
            )
        })?;
        let kid = header.kid.clone().unwrap_or_default();
        if kid.is_empty() {
            tracing::warn!("JWT refused: token carries no kid for key selection");
            return Err(Self::fail(
                client_id,
                "presented JWT credentials that cannot be verified",
            ));
        }
        if !matches!(
            header.alg,
            jsonwebtoken::Algorithm::RS256 | jsonwebtoken::Algorithm::ES256
        ) {
            tracing::warn!(kid = %kid, alg = ?header.alg, "JWT refused: unsupported algorithm");
            return Err(Self::fail(
                client_id,
                "presented JWT credentials that cannot be verified",
            ));
        }
        if self.cached(&kid).is_none() {
            self.refresh_for_kid(&kid).await.map_err(|_| {
                Self::fail(
                    client_id,
                    "presented JWT credentials, but the JWKS endpoint is unavailable",
                )
            })?;
        }
        let Some(entry) = self.cached(&kid) else {
            tracing::warn!(kid = %kid, "JWT refused: unknown kid after refresh");
            return Err(Self::fail(
                client_id,
                "presented JWT credentials that cannot be verified",
            ));
        };
        if !self.is_healthy() {
            tracing::warn!(kid = %kid, "JWT refused: JWKS endpoint is unhealthy");
            return Err(Self::fail(
                client_id,
                "presented JWT credentials, but the JWKS endpoint is unavailable",
            ));
        }
        self.verify_with(&entry, &kid, client_id, token, header.alg)
    }

    /// Cache lookup honouring TTL: expired entries read as a miss so the
    /// caller triggers a refresh instead of trusting stale key material.
    fn cached(&self, kid: &str) -> Option<CachedKey> {
        let ttl = self.inner.config.effective_cache_ttl();
        let cache = self.inner.cache.read();
        let entry = cache.get(kid)?;
        if entry.inserted.elapsed() > ttl {
            return None;
        }
        Some(entry.clone())
    }

    /// Ensure `kid` is cached: one fetch at a time (singleflight). The
    /// winner fetches; losers poll the cache until the refresh timeout
    /// instead of queueing a second fetch, then fail closed on expiry.
    async fn refresh_for_kid(&self, kid: &str) -> std::result::Result<(), ()> {
        if let Ok(_guard) = self.inner.refresh_lock.try_lock() {
            let outcome = self.fetch_and_store().await;
            if outcome.is_ok() && self.cached(kid).is_some() {
                return Ok(());
            }
            return outcome;
        }
        let deadline = Instant::now() + self.inner.config.effective_refresh_timeout();
        while Instant::now() < deadline {
            if self.cached(kid).is_some() && self.is_healthy() {
                return Ok(());
            }
            // 25 ms singleflight poll step: 4 wakeups per 100 ms (the
            // minimum `refresh_timeout_ms` clamp), so the worst added
            // wait after the winner's fetch is 25 ms while a slow
            // endpoint never spins the CONNECT task hot.
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        tracing::warn!(kid = %kid, "JWT refused: JWKS refresh already in flight");
        Err(())
    }

    /// Fetch the document and replace the cache. Any failure marks the
    /// endpoint unhealthy and fails closed; success marks it healthy.
    async fn fetch_and_store(&self) -> std::result::Result<(), ()> {
        let Some(client) = self.inner.client.as_ref() else {
            tracing::warn!("JWKS endpoint unavailable: HTTPS client could not be built");
            self.inner.healthy.store(false, Ordering::Relaxed);
            return Err(());
        };
        let url = self.inner.config.jwks_url.clone();
        if !url.starts_with("https://") {
            tracing::warn!(url = %url, "JWKS endpoint unavailable: URL must start with https://");
            self.inner.healthy.store(false, Ordering::Relaxed);
            return Err(());
        }
        let cap = self.inner.config.effective_document_cap();
        let timeout = self.inner.config.effective_fetch_timeout();
        // Every failed refresh marks the key set unhealthy before
        // returning (fail closed): a timeout, a request failure, a body
        // read failure and invalid JWKS JSON all clear health, exactly
        // like a bad status or an oversized document does below.
        let send = tokio::time::timeout(timeout, client.get(&url).send()).await;
        let mut response = match send {
            Err(_) => {
                tracing::warn!(url = %url, "JWKS endpoint unavailable: fetch timed out");
                self.inner.healthy.store(false, Ordering::Relaxed);
                return Err(());
            }
            Ok(Err(e)) => {
                tracing::warn!(url = %url, "JWKS endpoint unavailable: request failed: {e}");
                self.inner.healthy.store(false, Ordering::Relaxed);
                return Err(());
            }
            Ok(Ok(response)) => response,
        };
        if !response.status().is_success() {
            tracing::warn!(url = %url, status = %response.status(), "JWKS endpoint unavailable: bad status");
            self.inner.healthy.store(false, Ordering::Relaxed);
            return Err(());
        }
        let mut body: Vec<u8> = Vec::new();
        loop {
            let chunk = match response.chunk().await {
                Ok(chunk) => chunk,
                Err(e) => {
                    tracing::warn!(url = %url, "JWKS endpoint unavailable: body read failed: {e}");
                    self.inner.healthy.store(false, Ordering::Relaxed);
                    return Err(());
                }
            };
            let Some(chunk) = chunk else {
                break;
            };
            if body.len() + chunk.len() > cap {
                tracing::warn!(url = %url, "JWKS endpoint unavailable: document exceeds byte cap");
                self.inner.healthy.store(false, Ordering::Relaxed);
                return Err(());
            }
            body.extend_from_slice(&chunk);
        }
        let document: JwksDocument = match serde_json::from_slice(&body) {
            Ok(document) => document,
            Err(e) => {
                tracing::warn!(url = %url, "JWKS endpoint unavailable: invalid document: {e}");
                self.inner.healthy.store(false, Ordering::Relaxed);
                return Err(());
            }
        };
        let mut fresh: Vec<(String, CachedKey)> = Vec::new();
        for key in document.keys {
            if let Some((kid, entry)) = accept_key(&key) {
                fresh.push((kid, entry));
            }
        }
        if fresh.is_empty() {
            tracing::warn!(url = %url, "JWKS endpoint unavailable: document holds no usable keys");
            self.inner.healthy.store(false, Ordering::Relaxed);
            return Err(());
        }
        // Deterministic truncation past the bound (sorted by kid), so the
        // same document always caches the same keys.
        fresh.sort_by(|a, b| a.0.cmp(&b.0));
        let max = self.inner.config.effective_cache_max();
        if fresh.len() > max {
            tracing::warn!(
                url = %url,
                kept = max,
                dropped = fresh.len() - max,
                "JWKS document exceeds key cache bound"
            );
            fresh.truncate(max);
        }
        let now = Instant::now();
        let mut cache = self.inner.cache.write();
        cache.clear();
        for (kid, mut entry) in fresh {
            entry.inserted = now;
            cache.insert(kid, entry);
        }
        self.inner.healthy.store(true, Ordering::Relaxed);
        self.inner.refresh_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Verify the signature plus `exp` (always) and `iss`/`aud` (when
    /// configured) against one cached key. Every refusal logs the `kid`
    /// and the reason, never the token.
    fn verify_with(
        &self,
        entry: &CachedKey,
        kid: &str,
        client_id: &str,
        token: &str,
        alg: jsonwebtoken::Algorithm,
    ) -> Result<VerifiedJwt> {
        let key = decoding_key(entry).ok_or_else(|| {
            tracing::warn!(kid = %kid, "JWT refused: key material cannot be used");
            Self::fail(
                client_id,
                "presented JWT credentials that cannot be verified",
            )
        })?;
        let mut validation = jsonwebtoken::Validation::new(alg);
        validation.leeway = self.inner.config.effective_skew();
        // `iss`/`aud` validate only when set (both default to `None`,
        // meaning skip); an empty configured value keeps the skip so
        // signature-plus-expiry deployments keep working.
        if !self.inner.config.issuer.is_empty() {
            validation.iss = Some(HashSet::from([self.inner.config.issuer.clone()]));
        }
        if !self.inner.config.audience.is_empty() {
            validation.aud = Some(HashSet::from([self.inner.config.audience.clone()]));
        }
        let claims =
            jsonwebtoken::decode::<serde_json::Value>(token, &key, &validation).map_err(|e| {
                tracing::warn!(kid = %kid, "JWT refused: verification failed: {e}");
                Self::fail(
                    client_id,
                    "presented JWT credentials that cannot be verified",
                )
            })?;
        let subject = claims
            .claims
            .get("sub")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let issuer = claims
            .claims
            .get("iss")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let expires_at = claims
            .claims
            .get("exp")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        Ok(VerifiedJwt {
            subject,
            issuer,
            key_id: kid.to_string(),
            expires_at,
        })
    }

    /// Start the periodic background refresh (B5-02). The first caller
    /// wins; later callers are no-ops so boot and tests can call freely.
    /// A slow endpoint never stacks: the tick skips when a refresh is
    /// already in flight, and every outcome (healthy/unhealthy) is logged.
    pub fn spawn_background_refresh(self: &Arc<Self>) {
        if self.inner.bg_claimed.swap(true, Ordering::Relaxed) {
            return;
        }
        let owned = Arc::clone(self);
        tokio::spawn(async move {
            let period = owned.inner.config.effective_period();
            loop {
                tokio::time::sleep(period).await;
                // Hold the singleflight guard across the fetch so a
                // background refresh and an on-demand refresh never
                // overlap: the tick skips when a refresh is in flight,
                // and a slow endpoint never stacks fetches.
                let Ok(_guard) = owned.inner.refresh_lock.try_lock() else {
                    continue;
                };
                if owned.fetch_and_store().await.is_err() {
                    tracing::warn!("JWKS background refresh failed: endpoint unhealthy");
                }
            }
        });
    }
}

#[async_trait]
impl Authenticator for JwksAuthenticator {
    async fn authenticate(
        &self,
        client_id: &str,
        _username: Option<&str>,
        password: Option<&[u8]>,
    ) -> Result<()> {
        let Some(password) = password else {
            return Err(Self::fail(client_id, "presented no credentials"));
        };
        if !Self::looks_like_jwt(password) {
            return Err(Self::fail(
                client_id,
                "presented credentials that cannot be verified",
            ));
        };
        let token = std::str::from_utf8(password)
            .map_err(|_| Self::fail(client_id, "presented credentials that cannot be verified"))?;
        self.verify_token(client_id, token).await.map(|_| ())
    }
}

/// Build the HTTPS client once at construction. A bad CA file or TLS
/// setup yields `None` (logged here) so every later attempt fails closed
/// instead of panicking at CONNECT.
fn build_client(config: &JwksConfig) -> Option<reqwest::Client> {
    let mut builder = reqwest::Client::builder().timeout(config.effective_fetch_timeout());
    if !config.tls_verify {
        builder = builder.danger_accept_invalid_certs(true);
    } else if let Some(path) = config.ca_cert_path.as_deref() {
        match std::fs::read(path) {
            Ok(pem) => match reqwest::Certificate::from_pem(&pem) {
                Ok(cert) => {
                    builder = builder.add_root_certificate(cert);
                }
                Err(e) => {
                    tracing::warn!("JWKS endpoint unavailable: cannot parse CA file {path}: {e}");
                    return None;
                }
            },
            Err(e) => {
                tracing::warn!("JWKS endpoint unavailable: cannot read CA file {path}: {e}");
                return None;
            }
        }
    }
    match builder.build() {
        Ok(client) => Some(client),
        Err(e) => {
            tracing::warn!("JWKS endpoint unavailable: cannot build HTTPS client: {e}");
            None
        }
    }
}

/// Accept one served key into the cache: RSA (`n`, `e`) or EC P-256
/// (`x`, `y`, `crv` P-256). Anything else (unknown `kty`, missing `kid`,
/// oversized components, unexpected `alg`) is skipped, never cached, so
/// one bad entry cannot poison verification of the good ones.
/// TODO(parity): ED448/EdDSA and PS256 key types are refused today; add
/// them when an issuer we must accept serves them.
fn accept_key(key: &FetchedJwk) -> Option<(String, CachedKey)> {
    // Reason: 256 bytes admits long URI-style kids (typical kids are <64 chars,
    // e.g. 36-char UUIDs) while bounding the per-CONNECT `kid` clone and map-key
    // comparison on the CONNECT path.
    if key.kid.is_empty() || key.kid.len() > 256 {
        return None;
    }
    for component in [&key.n, &key.e, &key.x, &key.y] {
        if component.len() > MAX_JWK_COMPONENT_LEN {
            return None;
        }
    }
    match key.kty.as_str() {
        "RSA" => {
            if key.n.is_empty() || key.e.is_empty() {
                return None;
            }
            if !key.alg.is_empty() && key.alg != "RS256" {
                return None;
            }
            Some((
                key.kid.clone(),
                CachedKey {
                    material: KeyMaterial::Rsa {
                        n: key.n.clone(),
                        e: key.e.clone(),
                    },
                    inserted: Instant::now(),
                },
            ))
        }
        "EC" => {
            if key.x.is_empty() || key.y.is_empty() {
                return None;
            }
            if !key.crv.is_empty() && key.crv != "P-256" {
                return None;
            }
            if !key.alg.is_empty() && key.alg != "ES256" {
                return None;
            }
            Some((
                key.kid.clone(),
                CachedKey {
                    material: KeyMaterial::Ec {
                        x: key.x.clone(),
                        y: key.y.clone(),
                    },
                    inserted: Instant::now(),
                },
            ))
        }
        _ => None,
    }
}

/// Rebuild a `DecodingKey` from cached components (uses a maintained
/// crate, never hand-rolled crypto).
fn decoding_key(entry: &CachedKey) -> Option<jsonwebtoken::DecodingKey> {
    match &entry.material {
        KeyMaterial::Rsa { n, e } => jsonwebtoken::DecodingKey::from_rsa_components(n, e).ok(),
        KeyMaterial::Ec { x, y } => jsonwebtoken::DecodingKey::from_ec_components(x, y).ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Single-source JWKS fixtures (B5-02): the signing-key minter and the
    // loopback HTTPS server live in `crate::jwks_test_support` (test-only)
    // and are shared with the `broker-node` CONNECT tests via a `#[path]`
    // include of the same file, so there is one copy
    // of the RSA/`CompatRng`/base64/PEM/server logic.
    use crate::jwks_test_support::{TestJwksServer as HttpsJwks, TestSigningKey as SigningKey};
    use std::sync::Arc;

    fn test_config(url: String) -> JwksConfig {
        JwksConfig {
            jwks_url: url,
            issuer: "https://issuer.example".to_string(),
            audience: "indra-mqtt".to_string(),
            refresh_period_secs: 60,
            fetch_timeout_ms: 3_000,
            refresh_timeout_ms: 3_000,
            cache_max_keys: 32,
            cache_ttl_secs: 60,
            max_document_bytes: 64 * 1024,
            clock_skew_secs: 60,
            // Loopback fixture only: production endpoints keep TLS on.
            tls_verify: false,
            ca_cert_path: None,
        }
    }

    #[tokio::test]
    async fn valid_token_verifies_against_live_endpoint() {
        let signing = SigningKey::generate("key-a");
        let server = HttpsJwks::start(vec![signing.jwk_json()]).await;
        let auth = JwksAuthenticator::new(test_config(server.url()));
        let token = signing.mint("https://issuer.example", "indra-mqtt", 3600, false);
        let verified = auth
            .verify_token("device-1", &token)
            .await
            .expect("valid token verifies");
        assert_eq!(verified.key_id, "key-a");
        assert_eq!(verified.subject, "device-1");
        assert!(verified.expires_at > 0);
        assert!(auth.is_healthy());
        assert_eq!(auth.cached_key_count(), 1);
        assert_eq!(auth.refresh_count(), 1);
    }

    #[tokio::test]
    async fn rotated_keys_verify_without_restart_and_unknown_kid_refused() {
        let first = SigningKey::generate("key-a");
        let server = HttpsJwks::start(vec![first.jwk_json()]).await;
        let auth = JwksAuthenticator::new(test_config(server.url()));
        let before = first.mint("https://issuer.example", "indra-mqtt", 3600, false);
        auth.verify_token("device-1", &before)
            .await
            .expect("first key verifies");

        // Rotate the endpoint mid-test: the new kid verifies with no
        // restart (unknown-kid refresh), the old token is refused once
        // its kid leaves the document.
        let second = SigningKey::generate("key-b");
        server.rotate(vec![second.jwk_json()]);
        let after = second.mint("https://issuer.example", "indra-mqtt", 3600, false);
        let verified = auth
            .verify_token("device-1", &after)
            .await
            .expect("rotated key verifies without restart");
        assert_eq!(verified.key_id, "key-b");
        assert!(auth.verify_token("device-1", &before).await.is_err());
        // A token naming a kid the endpoint never served is refused.
        let stranger = SigningKey::generate("key-zzz");
        let unknown = stranger.mint("https://issuer.example", "indra-mqtt", 3600, false);
        assert!(auth.verify_token("device-1", &unknown).await.is_err());
    }

    #[tokio::test]
    async fn expired_wrong_claims_and_bad_signature_refused() {
        let signing = SigningKey::generate("key-a");
        let server = HttpsJwks::start(vec![signing.jwk_json()]).await;
        let auth = JwksAuthenticator::new(test_config(server.url()));
        // Baseline verifies, so refusals below blame the claim, not setup.
        let good = signing.mint("https://issuer.example", "indra-mqtt", 3600, false);
        auth.verify_token("device-1", &good)
            .await
            .expect("baseline verifies");

        // Expired 300 s ago: well past the 60 s clock-skew leeway, so
        // `exp + leeway < now` holds and the token is refused.
        let expired = signing.mint("https://issuer.example", "indra-mqtt", -300, false);
        assert!(auth.verify_token("d", &expired).await.is_err());
        let wrong_aud = signing.mint("https://issuer.example", "other-service", 3600, false);
        assert!(auth.verify_token("d", &wrong_aud).await.is_err());
        let wrong_iss = signing.mint("https://other.example", "indra-mqtt", 3600, false);
        assert!(auth.verify_token("d", &wrong_iss).await.is_err());
        let bad_sig = signing.mint("https://issuer.example", "indra-mqtt", 3600, true);
        assert!(auth.verify_token("d", &bad_sig).await.is_err());
        // Not a JWT at all: refused without touching the endpoint again.
        assert!(auth
            .authenticate("d", Some("u"), Some(b"password"))
            .await
            .is_err());
        assert!(auth.authenticate("d", Some("u"), None).await.is_err());
    }

    #[tokio::test]
    async fn unreachable_endpoint_fails_closed() {
        // Request-failure arm of `fetch_and_store`: nothing listens here
        // (loopback port 1 refuses fast), so the refresh fails closed and
        // marks the key set unhealthy without waiting out a timeout.
        let mut config = test_config("https://127.0.0.1:1/jwks.json".to_string());
        config.fetch_timeout_ms = 1_000;
        config.refresh_timeout_ms = 1_000;
        let auth = JwksAuthenticator::new(config);
        let signing = SigningKey::generate("key-a");
        let token = signing.mint("https://issuer.example", "indra-mqtt", 3600, false);
        assert!(auth.verify_token("device-1", &token).await.is_err());
        assert!(!auth.is_healthy());
        assert_eq!(auth.cached_key_count(), 0);
    }

    /// Build a loopback TLS acceptor from the shared fixture certificate
    /// (same trust as `TestJwksServer`; clients use `tls_verify = false`).
    async fn tls_acceptor_for_fault_tests() -> tokio_rustls::TlsAcceptor {
        use std::sync::Arc;
        let mut cert_reader =
            std::io::BufReader::new(crate::jwks_test_support::TEST_CERT_PEM.as_bytes());
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut cert_reader)
                .expect("fixture cert reads")
                .into_iter()
                .map(rustls::pki_types::CertificateDer::from)
                .collect();
        assert!(!certs.is_empty(), "fixture holds a certificate");
        let mut key_reader =
            std::io::BufReader::new(crate::jwks_test_support::TEST_KEY_PEM.as_bytes());
        let mut private_key = None;
        while let Some(item) = rustls_pemfile::read_one(&mut key_reader).expect("fixture key reads")
        {
            if let rustls_pemfile::Item::PKCS8Key(key) = item {
                private_key = Some(rustls::pki_types::PrivateKeyDer::Pkcs8(key.into()));
                break;
            }
        }
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, private_key.expect("fixture holds a private key"))
            .expect("TLS config builds");
        tokio_rustls::TlsAcceptor::from(Arc::new(config))
    }

    /// Serve exactly one raw HTTPS reply on loopback, then stop: complete
    /// the TLS handshake, read the request, stall past the client's fetch
    /// timeout when asked (writing nothing) or write `reply` verbatim and
    /// close. Fault-injection for the refresh-failure arms without
    /// touching the shared JWKS fixture.
    async fn serve_raw_once(reply: Vec<u8>, stall: Option<Duration>) -> String {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let acceptor = tls_acceptor_for_fault_tests().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback binds");
        let url = format!(
            "https://{}/jwks.json",
            listener.local_addr().expect("addr reads")
        );
        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let Ok(mut tls) = acceptor.accept(stream).await else {
                return;
            };
            let mut buf = vec![0u8; 4096];
            if tls.read(&mut buf).await.is_err() {
                return;
            }
            if let Some(delay) = stall {
                tokio::time::sleep(delay).await;
            } else {
                let _ = tls.write_all(&reply).await;
                let _ = tls.shutdown().await;
            }
        });
        url
    }

    fn fault_config(url: String) -> JwksConfig {
        let mut config = test_config(url);
        // Minimum clamp (100 ms): the fault fires fast while the stall
        // (2 s) stays far past it, so the test proves the timeout arm
        // rather than the server's patience.
        config.fetch_timeout_ms = 100;
        config.refresh_timeout_ms = 100;
        config
    }

    #[tokio::test]
    async fn refresh_fetch_timeout_marks_unhealthy() {
        // Timeout arm: the endpoint accepts and completes TLS but never
        // answers, so the bounded fetch gives up and marks the key set
        // unhealthy instead of returning through `?` with health intact.
        let url = serve_raw_once(Vec::new(), Some(Duration::from_secs(2))).await;
        let auth = JwksAuthenticator::new(fault_config(url));
        let signing = SigningKey::generate("key-a");
        let token = signing.mint("https://issuer.example", "indra-mqtt", 3600, false);
        assert!(auth.verify_token("device-1", &token).await.is_err());
        assert!(!auth.is_healthy());
        assert_eq!(auth.cached_key_count(), 0);
        assert_eq!(auth.refresh_count(), 0);
    }

    #[tokio::test]
    async fn refresh_body_read_failure_marks_unhealthy() {
        // Body-read arm: the endpoint promises 100000 bytes but closes
        // after a fragment, so `chunk()` fails mid-document and the
        // refresh marks the key set unhealthy instead of serving stale
        // trust from the earlier (empty) cache.
        let reply = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 100000\r\nconnection: close\r\n\r\n{\"keys\": [{\"kty\": \"RSA\",".to_vec();
        let url = serve_raw_once(reply, None).await;
        let auth = JwksAuthenticator::new(fault_config(url));
        let signing = SigningKey::generate("key-a");
        let token = signing.mint("https://issuer.example", "indra-mqtt", 3600, false);
        assert!(auth.verify_token("device-1", &token).await.is_err());
        assert!(!auth.is_healthy());
        assert_eq!(auth.cached_key_count(), 0);
        assert_eq!(auth.refresh_count(), 0);
    }

    #[tokio::test]
    async fn refresh_invalid_document_marks_unhealthy() {
        // Invalid-JSON arm: the endpoint answers 200 with a body no JWKS
        // parser accepts, so the refresh marks the key set unhealthy and
        // caches nothing (a later good fetch can still recover).
        let body = "this is not a JSON Web Key Set";
        let reply = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes();
        let url = serve_raw_once(reply, None).await;
        let auth = JwksAuthenticator::new(fault_config(url));
        let signing = SigningKey::generate("key-a");
        let token = signing.mint("https://issuer.example", "indra-mqtt", 3600, false);
        assert!(auth.verify_token("device-1", &token).await.is_err());
        assert!(!auth.is_healthy());
        assert_eq!(auth.cached_key_count(), 0);
        assert_eq!(auth.refresh_count(), 0);
    }

    #[tokio::test]
    async fn outage_denies_cached_tokens_and_recovery_restores() {
        let signing = SigningKey::generate("key-a");
        let server = HttpsJwks::start(vec![signing.jwk_json()]).await;
        let mut config = test_config(server.url());
        config.refresh_period_secs = 1;
        config.fetch_timeout_ms = 1_000;
        config.refresh_timeout_ms = 1_000;
        let auth = Arc::new(JwksAuthenticator::new(config));
        let token = signing.mint("https://issuer.example", "indra-mqtt", 3600, false);
        auth.verify_token("device-1", &token)
            .await
            .expect("baseline verifies");
        auth.spawn_background_refresh();

        // Break the endpoint: the next refresh fails, health drops, and
        // even the cached key is refused (fail closed, never stale trust).
        server.set_failing(true);
        let stranger = SigningKey::generate("key-zzz");
        let unknown = stranger.mint("https://issuer.example", "indra-mqtt", 3600, false);
        assert!(auth.verify_token("device-1", &unknown).await.is_err());
        assert!(!auth.is_healthy());
        assert!(auth.verify_token("device-1", &token).await.is_err());

        // Heal the endpoint: the background tick recovers with no
        // restart and the cached key verifies again.
        server.set_failing(false);
        let mut recovered = false;
        for _ in 0..60 {
            tokio::time::sleep(Duration::from_millis(250)).await;
            if auth.is_healthy() {
                recovered = true;
                break;
            }
        }
        assert!(recovered, "background refresh must recover");
        auth.verify_token("device-1", &token)
            .await
            .expect("healed endpoint verifies");
    }

    #[test]
    fn cache_bound_and_non_jwt_shapes() {
        assert!(JwksAuthenticator::looks_like_jwt(b"a.b.c"));
        assert!(!JwksAuthenticator::looks_like_jwt(b"password"));
        assert!(!JwksAuthenticator::looks_like_jwt(b"a.b"));
        assert!(!JwksAuthenticator::looks_like_jwt(b""));
        assert!(!JwksAuthenticator::looks_like_jwt(b"\xff\xfe.a.b"));
        assert_eq!(JWKS_CACHE_MAX_KEYS, 32);
        // Oversized components never enter the cache.
        let big = FetchedJwk {
            kid: "big".to_string(),
            kty: "RSA".to_string(),
            alg: "RS256".to_string(),
            n: "x".repeat(2048),
            e: "AQAB".to_string(),
            x: String::new(),
            y: String::new(),
            crv: String::new(),
        };
        assert!(accept_key(&big).is_none());
        let unknown_kty = FetchedJwk {
            kid: "k".to_string(),
            kty: "oct".to_string(),
            alg: String::new(),
            n: String::new(),
            e: String::new(),
            x: String::new(),
            y: String::new(),
            crv: String::new(),
        };
        assert!(accept_key(&unknown_kty).is_none());
    }

    // The pipeline BENCH probe for the CONNECT auth-check cost lives in
    // `crates/broker-auth/tests/jwks_connect_bench.rs`: a standalone
    // `#[ignore]` integration test using only base-commit APIs, so the
    // gates can run it on the base commit and on the tree. A probe here
    // could never run at base (this module does not exist there).
}
