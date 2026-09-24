//! Database-backed authentication and authorization (B5-03, T-96).
//!
//! Runtime credential and ACL lookups against PostgreSQL, MySQL, Redis
//! and MongoDB, used at CONNECT (credentials) and on the publish path
//! (ACLs). Each source holds one bounded pool (a semaphore bounding
//! concurrent database operations; connections are short-lived per
//! lookup so no identity leaks between clients), stated connect/read
//! timeouts, and a bounded result cache with a stated TTL.
//!
//! Lookup schema (explicit, documented; the broker never concatenates
//! credentials into queries — every lookup is parameterized):
//!
//! - PostgreSQL / MySQL (tables created by [`PostgresAuth::ensure_schema`]
//!   and [`MysqlAuth::ensure_schema`]):
//!   ```sql
//!   CREATE TABLE mqtt_users(username TEXT PRIMARY KEY, password_hash TEXT NOT NULL);
//!   CREATE TABLE mqtt_acls(username TEXT NOT NULL, topic TEXT NOT NULL,
//!                          action TEXT NOT NULL, allow BOOLEAN NOT NULL);
//!   ```
//!   `password_hash` is lowercase hex SHA-256 of the password (the same
//!   verifier form [`crate::MemoryAuth`] persists). Credential lookup is
//!   `SELECT password_hash FROM mqtt_users WHERE username = $1` (`?` on
//!   MySQL); ACL lookup is
//!   `SELECT topic, action, allow FROM mqtt_acls WHERE username = $1`.
//! - Redis:
//!   - `SET mqtt:user:<username> <hex-sha256>` (STRING): the verifier.
//!   - `HSET mqtt:acls:<username> "<action>|<topic>" "1"` (HASH, `"0"`
//!     denies): the allow-list. `GET` plus `HGETALL` read them; commands
//!     are driver-parameterized (RESP bulk strings, no query language).
//! - MongoDB (collections in the database named by the connection URL):
//!   - `mqtt_users` documents `{username, password_hash}`.
//!   - `mqtt_acls` documents `{username, topic, action, allow}`.
//!     Filters are driver documents (`{username: <value>}`), never strings.
//!
//! ACL semantics: allow-list. A publish (or subscribe) is permitted when
//! at least one row for the user covers the request with `allow = true`;
//! anything else (no rows, only `allow = false` rows, no covering row)
//! is denied.
//! TODO(parity): should database ACLs use first-match-wins ordering like
//! the in-memory rules instead of allow-list? Neither the rulebook nor
//! the task spec decides; the current choice is the conservative one
//! (absent means denied).
//!
//! Every outage fails closed: an unreachable database denies CONNECT and
//! refuses publishes, never grants, with a `tracing::warn!` line.
//!
//! Drivers (all maintained, all permissive licences):
//! - `tokio-postgres` 0.7 (MIT): PostgreSQL wire protocol.
//! - `mysql_async` 0.35 (MIT/Apache-2.0): MySQL wire protocol including
//!   the default server auth plugin.
//! - `redis` 0.27 (MIT, `tokio-comp`): RESP.
//! - `mongodb` 3 (Apache-2.0): OP_MSG plus SCRAM.
//!   No SQL, RESP frame or document is hand-rolled and no password hash is
//!   hand-computed beyond SHA-256 hex (the pre-existing verifier form).

use crate::{AclAction, AuthError, Authenticator, Authorizer, Result};
use async_trait::async_trait;
use broker_protocol::{Topic, TopicFilter};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

/// Default bound on concurrent database operations per source.
fn default_pool_size() -> usize {
    8
}

/// Default connect timeout in milliseconds.
fn default_connect_timeout_ms() -> u64 {
    3_000
}

/// Default per-operation (query/command) timeout in milliseconds.
fn default_read_timeout_ms() -> u64 {
    3_000
}

/// Default bound on cached entries per source and cache kind.
fn default_cache_max_entries() -> usize {
    1_024
}

/// Default cache TTL in seconds.
fn default_cache_ttl_secs() -> u64 {
    60
}

/// Bound on concurrent database operations per source (default 8:
/// enough for CONNECT bursts, small enough to never overwhelm the
/// database; each slot holds at most one short-lived connection of a
/// few KB).
pub const DEFAULT_POOL_SIZE: usize = 8;
/// Connect timeout default in milliseconds (3 s: covers TCP connect
/// plus container-start jitter while failing closed fast enough to not
/// stall accepts).
pub const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 3_000;
/// Per-operation timeout default in milliseconds (3 s: covers one
/// lookup round-trip; slow-database tolerant while keeping CONNECT and
/// the publish path bounded).
pub const DEFAULT_READ_TIMEOUT_MS: u64 = 3_000;
/// Cache size default in entries (1024: each entry holds a username or
/// verdict plus bookkeeping, well under one megabyte total; evicts
/// oldest first).
pub const DEFAULT_CACHE_MAX_ENTRIES: usize = 1_024;
/// Cache TTL default in seconds (60 s: bounds a stale ACL after a
/// change to one minute while absorbing per-packet lookups; the
/// operator lowers it for faster revocation).
pub const DEFAULT_CACHE_TTL_SECS: u64 = 60;
/// Bound on ACL rows consulted per cache-miss lookup (256: bounds
/// per-publish matching work to at most 256 topic-filter matches and
/// memory to a few tens of kilobytes, while covering operational ACL
/// tables; extras are ignored with a warn, never grown unbounded).
pub const MAX_ACL_ROWS: usize = 256;

fn clamp_pool_size(n: usize) -> usize {
    n.clamp(1, 64)
}

fn clamp_timeout_ms(ms: u64) -> Duration {
    Duration::from_millis(ms.clamp(100, 60_000))
}

fn clamp_cache_entries(n: usize) -> usize {
    // Lower bound 1 (not 16) so small operator-configured and test caches
    // honour their bound exactly while staying finite; upper bound 65_536
    // caps memory (each entry is a small key plus verdict, well under a
    // megabyte even at the cap). The default 1_024 is set above.
    n.clamp(1, 65_536)
}

fn clamp_cache_ttl_secs(s: u64) -> Duration {
    Duration::from_secs(s.clamp(1, 3_600))
}

/// Lowercase hex SHA-256 of a password (the verifier form stored in
/// every source; matches the in-memory store's persisted form).
pub fn hash_password_hex(password: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(password);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0F) as usize] as char);
    }
    out
}

/// One ACL row as read from any source.
#[derive(Debug, Clone)]
struct AclRow {
    topic: String,
    action: AclAction,
    allow: bool,
}

fn topic_matches_row(pattern: &str, topic: &Topic) -> bool {
    TopicFilter::new(pattern)
        .map(|filter| filter.matches(topic))
        .unwrap_or(false)
}

fn filter_covered_by_row(pattern: &str, filter: &TopicFilter) -> bool {
    let pattern_levels: Vec<&str> = pattern.split('/').collect();
    let request_levels: Vec<&str> = filter.as_str().split('/').collect();
    let mut pi = 0;
    for &req in request_levels.iter() {
        match pattern_levels.get(pi) {
            Some(&"#") => return true,
            Some(&"+") => {
                pi += 1;
            }
            Some(&pat) if pat == req => {
                pi += 1;
            }
            _ => return false,
        }
    }
    pi == pattern_levels.len() || (pi == pattern_levels.len() - 1 && pattern_levels[pi] == "#")
}

fn publish_allowed(rows: &[AclRow], topic: &Topic) -> bool {
    rows.iter().any(|row| {
        row.allow
            && (row.action == AclAction::Publish || row.action == AclAction::All)
            && topic_matches_row(&row.topic, topic)
    })
}

fn subscribe_allowed(rows: &[AclRow], filter: &TopicFilter) -> bool {
    rows.iter().any(|row| {
        row.allow
            && (row.action == AclAction::Subscribe || row.action == AclAction::All)
            && filter_covered_by_row(&row.topic, filter)
    })
}

fn parse_action(raw: &str) -> Option<AclAction> {
    AclAction::parse(raw)
}

/// Bounded TTL cache with FIFO eviction.
///
/// `max_entries` bounds memory (oldest first past the bound);
/// entries expire lazily on read (TTL expiry at minimum — there is no
/// database change feed, so a changed ACL is visible after the TTL).
/// Expired entries for keys never re-read linger until evicted; the
/// bound still holds because eviction counts them.
#[derive(Debug)]
struct BoundedTtlCache<V: Clone> {
    max_entries: usize,
    ttl: Duration,
    entries: HashMap<String, (V, Instant)>,
    order: VecDeque<String>,
}

impl<V: Clone> BoundedTtlCache<V> {
    fn new(max_entries: usize, ttl: Duration) -> Self {
        Self {
            max_entries: clamp_cache_entries(max_entries),
            ttl,
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn get(&mut self, key: &str) -> Option<V> {
        let (value, at) = self.entries.get(key)?;
        if at.elapsed() >= self.ttl {
            self.entries.remove(key);
            self.order.retain(|k| k != key);
            return None;
        }
        Some(value.clone())
    }

    fn put(&mut self, key: String, value: V) {
        if !self.entries.contains_key(&key) {
            self.order.push_back(key.clone());
        }
        self.entries.insert(key, (value, Instant::now()));
        while self.order.len() > self.max_entries {
            if let Some(old) = self.order.pop_front() {
                self.entries.remove(&old);
            } else {
                break;
            }
        }
    }

    fn remove(&mut self, key: &str) {
        self.entries.remove(key);
        self.order.retain(|k| k != key);
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }

    #[allow(dead_code)]
    fn len(&self) -> usize {
        self.entries.len()
    }

    #[allow(dead_code)]
    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Shared pool/cache/timeout settings applied to each configured
/// database source (one pool per database; each source owns its
/// semaphore and caches).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbSourceSettings {
    #[serde(default = "default_pool_size")]
    pub pool_size: usize,
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_read_timeout_ms")]
    pub read_timeout_ms: u64,
    #[serde(default = "default_cache_max_entries")]
    pub cache_max_entries: usize,
    #[serde(default = "default_cache_ttl_secs")]
    pub cache_ttl_secs: u64,
}

impl Default for DbSourceSettings {
    fn default() -> Self {
        Self {
            pool_size: DEFAULT_POOL_SIZE,
            connect_timeout_ms: DEFAULT_CONNECT_TIMEOUT_MS,
            read_timeout_ms: DEFAULT_READ_TIMEOUT_MS,
            cache_max_entries: DEFAULT_CACHE_MAX_ENTRIES,
            cache_ttl_secs: DEFAULT_CACHE_TTL_SECS,
        }
    }
}

impl DbSourceSettings {
    fn pool_permits(&self) -> usize {
        clamp_pool_size(self.pool_size)
    }

    fn connect_timeout(&self) -> Duration {
        clamp_timeout_ms(self.connect_timeout_ms)
    }

    fn read_timeout(&self) -> Duration {
        clamp_timeout_ms(self.read_timeout_ms)
    }

    fn cache_ttl(&self) -> Duration {
        clamp_cache_ttl_secs(self.cache_ttl_secs)
    }
}

// ---------------------------------------------------------------------------
// PostgreSQL
// ---------------------------------------------------------------------------

/// PostgreSQL credential/ACL source configuration.
///
/// `url` is `postgresql://user:pass@host:port/db`. Empty disables the
/// source (every attempt fails closed without opening a socket).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PostgresAuthConfig {
    #[serde(default)]
    pub url: String,
    #[serde(flatten)]
    pub settings: DbSourceSettings,
}

/// PostgreSQL-backed authenticator and authorizer.
pub struct PostgresAuth {
    config: PostgresAuthConfig,
    semaphore: Arc<Semaphore>,
    auth_cache: Mutex<BoundedTtlCache<String>>,
    acl_cache: Mutex<BoundedTtlCache<bool>>,
}

impl std::fmt::Debug for PostgresAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresAuth")
            .field("configured", &self.is_configured())
            .finish()
    }
}

impl PostgresAuth {
    pub fn new(config: PostgresAuthConfig) -> Self {
        let permits = config.settings.pool_permits();
        let ttl = config.settings.cache_ttl();
        let max = config.settings.cache_max_entries;
        Self {
            config,
            semaphore: Arc::new(Semaphore::new(permits)),
            auth_cache: Mutex::new(BoundedTtlCache::new(max, ttl)),
            acl_cache: Mutex::new(BoundedTtlCache::new(max, ttl)),
        }
    }

    pub fn is_configured(&self) -> bool {
        !self.config.url.trim().is_empty()
    }

    /// Invalidate both caches (credential and ACL verdicts).
    ///
    /// TTL expiry already re-reads the database lazily on the next
    /// lookup; this explicit clear is the operator-driven invalidation
    /// path (for example after rotating credentials or ACLs outside
    /// the broker's own `upsert_user`/`replace_acls` helpers).
    pub fn clear_caches(&self) {
        self.auth_cache.lock().clear();
        self.acl_cache.lock().clear();
    }

    fn fail_closed(client_id: &str) -> AuthError {
        AuthError::AuthenticationFailed(format!(
            "{client_id} presented database credentials, but the database is unavailable"
        ))
    }

    async fn with_permit<T, F, Fut>(&self, client_id: &str, run: F) -> Result<T>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let timeout = self.config.settings.connect_timeout();
        let permit = tokio::time::timeout(timeout, self.semaphore.acquire()).await;
        let _permit = match permit {
            Ok(Ok(guard)) => guard,
            Ok(Err(_)) => {
                tracing::warn!("PostgreSQL pool closed: failing closed for {client_id}");
                return Err(Self::fail_closed(client_id));
            }
            Err(_) => {
                tracing::warn!("PostgreSQL pool exhausted: failing closed for {client_id}");
                return Err(Self::fail_closed(client_id));
            }
        };
        run().await
    }

    async fn connect_client(&self) -> std::result::Result<tokio_postgres::Client, String> {
        let timeout = self.config.settings.connect_timeout();
        let parsed: std::result::Result<(), String> = (|| {
            if self.config.url.trim().is_empty() {
                return Err("no URL configured".to_string());
            }
            if !self.config.url.starts_with("postgresql://")
                && !self.config.url.starts_with("postgres://")
            {
                return Err("URL must start with postgresql://".to_string());
            }
            Ok(())
        })();
        parsed?;
        let connect = tokio::time::timeout(
            timeout,
            tokio_postgres::connect(&self.config.url, tokio_postgres::NoTls),
        )
        .await
        .map_err(|_| "connect timed out".to_string());
        let (client, connection) = connect?.map_err(|e| format!("connect failed: {e}"))?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(client)
    }

    async fn read_password_hash(
        &self,
        username: &str,
    ) -> std::result::Result<Option<String>, String> {
        let client = self.connect_client().await?;
        let read_timeout = self.config.settings.read_timeout();
        // Parameterized: the credential travels out-of-band as $1, never
        // concatenated into the statement.
        let rows = tokio::time::timeout(
            read_timeout,
            client.query(
                "SELECT password_hash FROM mqtt_users WHERE username = $1",
                &[&username],
            ),
        )
        .await
        .map_err(|_| "query timed out".to_string())?
        .map_err(|e| format!("query failed: {e}"))?;
        Ok(rows
            .first()
            .and_then(|row| row.try_get::<_, String>(0).ok()))
    }

    async fn read_acls(&self, username: &str) -> std::result::Result<Vec<AclRow>, String> {
        let client = self.connect_client().await?;
        let read_timeout = self.config.settings.read_timeout();
        // Bounded: SQL LIMIT (a constant, never a credential) caps rows at
        // MAX_ACL_ROWS so a cache-miss publish never grows a Vec unbounded.
        let query = format!(
            "SELECT topic, action, allow FROM mqtt_acls WHERE username = $1 ORDER BY topic LIMIT {}",
            MAX_ACL_ROWS
        );
        let rows = tokio::time::timeout(read_timeout, client.query(query.as_str(), &[&username]))
            .await
            .map_err(|_| "query timed out".to_string())?
            .map_err(|e| format!("query failed: {e}"))?;
        let mut out = Vec::with_capacity(rows.len().min(MAX_ACL_ROWS));
        for row in rows.into_iter().take(MAX_ACL_ROWS) {
            let topic: String = row.try_get(0).map_err(|e| format!("bad row: {e}"))?;
            let action_raw: String = row.try_get(1).map_err(|e| format!("bad row: {e}"))?;
            let allow: bool = row.try_get(2).map_err(|e| format!("bad row: {e}"))?;
            if let Some(action) = parse_action(&action_raw) {
                out.push(AclRow {
                    topic,
                    action,
                    allow,
                });
            }
        }
        Ok(out)
    }

    async fn authenticate_inner(&self, username: &str, password: &[u8]) -> Result<()> {
        if !self.is_configured() {
            tracing::warn!("PostgreSQL unavailable: no URL configured");
            return Err(Self::fail_closed("client"));
        }
        if let Some(cached) = self.auth_cache.lock().get(username) {
            if cached == hash_password_hex(password) {
                return Ok(());
            }
            return Err(Self::fail_closed("client"));
        }
        let stored = self.read_password_hash(username).await.map_err(|detail| {
            tracing::warn!("PostgreSQL unavailable: {detail}");
            Self::fail_closed("client")
        })?;
        let Some(stored) = stored else {
            return Err(Self::fail_closed("client"));
        };
        self.auth_cache
            .lock()
            .put(username.to_string(), stored.clone());
        if stored == hash_password_hex(password) {
            Ok(())
        } else {
            Err(Self::fail_closed("client"))
        }
    }

    async fn authorize_rows(&self, username: &str) -> std::result::Result<Vec<AclRow>, AuthError> {
        self.read_acls(username).await.map_err(|detail| {
            tracing::warn!("PostgreSQL ACL unavailable: {detail}");
            AuthError::PublishDenied("database unavailable".to_string())
        })
    }

    /// Create the lookup tables when missing (qualification seeds
    /// through this; production applies the same DDL offline).
    pub async fn ensure_schema(&self) -> std::result::Result<(), String> {
        let client = self.connect_client().await?;
        let timeout = self.config.settings.read_timeout();
        for ddl in [
            "CREATE TABLE IF NOT EXISTS mqtt_users(username TEXT PRIMARY KEY, password_hash TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS mqtt_acls(username TEXT NOT NULL, topic TEXT NOT NULL, action TEXT NOT NULL, allow BOOLEAN NOT NULL)",
            "CREATE INDEX IF NOT EXISTS idx_mqtt_acls_user ON mqtt_acls(username)",
        ] {
            tokio::time::timeout(timeout, client.execute(ddl, &[]))
                .await
                .map_err(|_| "ddl timed out".to_string())?
                .map_err(|e| format!("ddl failed: {e}"))?;
        }
        Ok(())
    }

    /// Insert or replace a user verifier (parameterized).
    pub async fn upsert_user(
        &self,
        username: &str,
        password: &[u8],
    ) -> std::result::Result<(), String> {
        let client = self.connect_client().await?;
        let timeout = self.config.settings.read_timeout();
        let hash = hash_password_hex(password);
        tokio::time::timeout(
            timeout,
            client.execute(
                "INSERT INTO mqtt_users(username, password_hash) VALUES ($1, $2) ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash",
                &[&username, &hash],
            ),
        )
        .await
        .map_err(|_| "upsert timed out".to_string())?
        .map_err(|e| format!("upsert failed: {e}"))?;
        self.auth_cache.lock().remove(username);
        Ok(())
    }

    /// Replace every ACL row for a user (parameterized; empty allows
    /// nothing afterwards until the TTL lapses — callers re-seed then
    /// wait out the TTL in the TTL test).
    pub async fn replace_acls(
        &self,
        username: &str,
        rows: &[(String, String, bool)],
    ) -> std::result::Result<(), String> {
        let client = self.connect_client().await?;
        let timeout = self.config.settings.read_timeout();
        tokio::time::timeout(
            timeout,
            client.execute("DELETE FROM mqtt_acls WHERE username = $1", &[&username]),
        )
        .await
        .map_err(|_| "delete timed out".to_string())?
        .map_err(|e| format!("delete failed: {e}"))?;
        for (topic, action, allow) in rows {
            tokio::time::timeout(
                timeout,
                client.execute(
                    "INSERT INTO mqtt_acls(username, topic, action, allow) VALUES ($1, $2, $3, $4)",
                    &[&username, &topic, &action, &allow],
                ),
            )
            .await
            .map_err(|_| "insert timed out".to_string())?
            .map_err(|e| format!("insert failed: {e}"))?;
        }
        Ok(())
    }
}

#[async_trait]
impl Authenticator for PostgresAuth {
    async fn authenticate(
        &self,
        client_id: &str,
        username: Option<&str>,
        password: Option<&[u8]>,
    ) -> Result<()> {
        let (Some(username), Some(password)) = (username, password) else {
            return Err(AuthError::AuthenticationFailed(format!(
                "{client_id} presented no database credentials"
            )));
        };
        if username.is_empty() {
            return Err(AuthError::AuthenticationFailed(format!(
                "{client_id} presented no database credentials"
            )));
        }
        self.with_permit(client_id, || self.authenticate_inner(username, password))
            .await
            .map_err(|e| match e {
                AuthError::AuthenticationFailed(msg) => {
                    let suffix = msg
                        .split_once(' ')
                        .map(|(_, rest)| rest)
                        .unwrap_or(msg.as_str());
                    AuthError::AuthenticationFailed(format!("{client_id} {suffix}"))
                }
                other => other,
            })
    }
}

#[async_trait]
impl Authorizer for PostgresAuth {
    // Publish-path cost (same shape in all four sources): cache hit is one
    // short cache lock plus one small key allocation, no I/O; cache miss is
    // one semaphore permit (pool_size bound, default 8, connect timeout) plus
    // one DB round-trip (read timeout) consulting at most MAX_ACL_ROWS rows.
    // No unbounded pool, cache, or queue behind an outage: permits exhaust
    // and fail closed, caches evict oldest-first, reads stop at MAX_ACL_ROWS.
    async fn authorize_publish(&self, client_id: &str, topic: &Topic) -> Result<()> {
        let cache_key = format!("p\x00{client_id}\x00{}", topic.as_str());
        if let Some(allowed) = self.acl_cache.lock().get(&cache_key) {
            return allowed
                .then_some(())
                .ok_or_else(|| AuthError::PublishDenied(format!("{client_id} cannot publish")));
        }
        let outcome: Result<bool> = self
            .with_permit(client_id, || async {
                let rows = self.authorize_rows(client_id).await?;
                Ok(publish_allowed(&rows, topic))
            })
            .await;
        match outcome {
            Ok(allowed) => {
                self.acl_cache.lock().put(cache_key, allowed);
                allowed
                    .then_some(())
                    .ok_or_else(|| AuthError::PublishDenied(format!("{client_id} cannot publish")))
            }
            Err(AuthError::PublishDenied(_)) => {
                tracing::warn!("PostgreSQL publish check failed closed for {client_id}");
                Err(AuthError::PublishDenied(format!(
                    "{client_id} cannot publish"
                )))
            }
            Err(other) => Err(other),
        }
    }

    async fn authorize_subscribe(&self, client_id: &str, filter: &TopicFilter) -> Result<()> {
        let cache_key = format!("s\x00{client_id}\x00{}", filter.as_str());
        if let Some(allowed) = self.acl_cache.lock().get(&cache_key) {
            return allowed.then_some(()).ok_or_else(|| {
                AuthError::SubscribeDenied(format!("{client_id} cannot subscribe"))
            });
        }
        let outcome: Result<bool> = self
            .with_permit(client_id, || async {
                let rows = self.authorize_rows(client_id).await?;
                Ok(subscribe_allowed(&rows, filter))
            })
            .await;
        match outcome {
            Ok(allowed) => {
                self.acl_cache.lock().put(cache_key, allowed);
                allowed.then_some(()).ok_or_else(|| {
                    AuthError::SubscribeDenied(format!("{client_id} cannot subscribe"))
                })
            }
            Err(AuthError::PublishDenied(_)) => {
                tracing::warn!("PostgreSQL subscribe check failed closed for {client_id}");
                Err(AuthError::SubscribeDenied(format!(
                    "{client_id} cannot subscribe"
                )))
            }
            Err(other) => Err(other),
        }
    }
}

// ---------------------------------------------------------------------------
// MySQL
// ---------------------------------------------------------------------------

/// MySQL credential/ACL source configuration (`mysql://user:pass@host:port/db`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MysqlAuthConfig {
    #[serde(default)]
    pub url: String,
    #[serde(flatten)]
    pub settings: DbSourceSettings,
}

/// MySQL-backed authenticator and authorizer (driver: `mysql_async`).
pub struct MysqlAuth {
    config: MysqlAuthConfig,
    semaphore: Arc<Semaphore>,
    auth_cache: Mutex<BoundedTtlCache<String>>,
    acl_cache: Mutex<BoundedTtlCache<bool>>,
}

impl std::fmt::Debug for MysqlAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MysqlAuth")
            .field("configured", &self.is_configured())
            .finish()
    }
}

impl MysqlAuth {
    pub fn new(config: MysqlAuthConfig) -> Self {
        let permits = config.settings.pool_permits();
        let ttl = config.settings.cache_ttl();
        let max = config.settings.cache_max_entries;
        Self {
            config,
            semaphore: Arc::new(Semaphore::new(permits)),
            auth_cache: Mutex::new(BoundedTtlCache::new(max, ttl)),
            acl_cache: Mutex::new(BoundedTtlCache::new(max, ttl)),
        }
    }

    pub fn is_configured(&self) -> bool {
        !self.config.url.trim().is_empty()
    }

    /// Invalidate both caches (credential and ACL verdicts).
    ///
    /// TTL expiry already re-reads the database lazily on the next
    /// lookup; this explicit clear is the operator-driven invalidation
    /// path (for example after rotating credentials or ACLs outside
    /// the broker's own `upsert_user`/`replace_acls` helpers).
    pub fn clear_caches(&self) {
        self.auth_cache.lock().clear();
        self.acl_cache.lock().clear();
    }

    fn fail_closed(client_id: &str) -> AuthError {
        AuthError::AuthenticationFailed(format!(
            "{client_id} presented database credentials, but the database is unavailable"
        ))
    }

    fn pool(&self) -> std::result::Result<mysql_async::Pool, String> {
        if self.config.url.trim().is_empty() {
            return Err("no URL configured".to_string());
        }
        if !self.config.url.starts_with("mysql://") {
            return Err("URL must start with mysql://".to_string());
        }
        mysql_async::Pool::from_url(&self.config.url).map_err(|e| format!("bad URL: {e}"))
    }

    async fn read_password_hash(
        &self,
        username: &str,
    ) -> std::result::Result<Option<String>, String> {
        use mysql_async::prelude::Queryable;
        let pool = self.pool()?;
        let mut conn =
            tokio::time::timeout(self.config.settings.connect_timeout(), pool.get_conn())
                .await
                .map_err(|_| "connect timed out".to_string())?
                .map_err(|e| format!("connect failed: {e}"))?;
        // Parameterized: the credential is bound as `?`, never concatenated.
        let hash: Option<String> = tokio::time::timeout(
            self.config.settings.read_timeout(),
            conn.exec_first(
                "SELECT password_hash FROM mqtt_users WHERE username = ?",
                (username,),
            ),
        )
        .await
        .map_err(|_| "query timed out".to_string())?
        .map_err(|e| format!("query failed: {e}"))?;
        Ok(hash)
    }

    async fn read_acls(&self, username: &str) -> std::result::Result<Vec<AclRow>, String> {
        use mysql_async::prelude::Queryable;
        let pool = self.pool()?;
        let mut conn =
            tokio::time::timeout(self.config.settings.connect_timeout(), pool.get_conn())
                .await
                .map_err(|_| "connect timed out".to_string())?
                .map_err(|e| format!("connect failed: {e}"))?;
        // Bounded: SQL LIMIT (a constant, never a credential) caps rows at
        // MAX_ACL_ROWS so a cache-miss publish never grows a Vec unbounded.
        let query = format!(
            "SELECT topic, action, allow FROM mqtt_acls WHERE username = ? ORDER BY topic LIMIT {}",
            MAX_ACL_ROWS
        );
        let rows: Vec<(String, String, i8)> = tokio::time::timeout(
            self.config.settings.read_timeout(),
            conn.exec(query, (username,)),
        )
        .await
        .map_err(|_| "query timed out".to_string())?
        .map_err(|e| format!("query failed: {e}"))?;
        let mut out = Vec::with_capacity(rows.len().min(MAX_ACL_ROWS));
        for (topic, action_raw, allow) in rows.into_iter().take(MAX_ACL_ROWS) {
            if let Some(action) = parse_action(&action_raw) {
                out.push(AclRow {
                    topic,
                    action,
                    allow: allow != 0,
                });
            }
        }
        Ok(out)
    }

    async fn authenticate_inner(&self, username: &str, password: &[u8]) -> Result<()> {
        if !self.is_configured() {
            tracing::warn!("MySQL unavailable: no URL configured");
            return Err(Self::fail_closed("client"));
        }
        if let Some(cached) = self.auth_cache.lock().get(username) {
            if cached == hash_password_hex(password) {
                return Ok(());
            }
            return Err(Self::fail_closed("client"));
        }
        let stored = self.read_password_hash(username).await.map_err(|detail| {
            tracing::warn!("MySQL unavailable: {detail}");
            Self::fail_closed("client")
        })?;
        let Some(stored) = stored else {
            return Err(Self::fail_closed("client"));
        };
        self.auth_cache
            .lock()
            .put(username.to_string(), stored.clone());
        if stored == hash_password_hex(password) {
            Ok(())
        } else {
            Err(Self::fail_closed("client"))
        }
    }

    /// Create the lookup tables when missing.
    pub async fn ensure_schema(&self) -> std::result::Result<(), String> {
        use mysql_async::prelude::Queryable;
        let pool = self.pool()?;
        let mut conn =
            tokio::time::timeout(self.config.settings.connect_timeout(), pool.get_conn())
                .await
                .map_err(|_| "connect timed out".to_string())?
                .map_err(|e| format!("connect failed: {e}"))?;
        let timeout = self.config.settings.read_timeout();
        for ddl in [
            "CREATE TABLE IF NOT EXISTS mqtt_users(username VARCHAR(255) PRIMARY KEY, password_hash TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS mqtt_acls(username VARCHAR(255) NOT NULL, topic TEXT NOT NULL, action VARCHAR(16) NOT NULL, allow TINYINT NOT NULL, INDEX idx_user (username))",
        ] {
            tokio::time::timeout(timeout, conn.query_drop(ddl))
                .await
                .map_err(|_| "ddl timed out".to_string())?
                .map_err(|e| format!("ddl failed: {e}"))?;
        }
        Ok(())
    }

    /// Insert or replace a user verifier (parameterized).
    pub async fn upsert_user(
        &self,
        username: &str,
        password: &[u8],
    ) -> std::result::Result<(), String> {
        use mysql_async::prelude::Queryable;
        let pool = self.pool()?;
        let mut conn =
            tokio::time::timeout(self.config.settings.connect_timeout(), pool.get_conn())
                .await
                .map_err(|_| "connect timed out".to_string())?
                .map_err(|e| format!("connect failed: {e}"))?;
        let hash = hash_password_hex(password);
        tokio::time::timeout(
            self.config.settings.read_timeout(),
            conn.exec_drop(
                "INSERT INTO mqtt_users(username, password_hash) VALUES (?, ?) ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash)",
                (username, hash.as_str()),
            ),
        )
        .await
        .map_err(|_| "upsert timed out".to_string())?
        .map_err(|e| format!("upsert failed: {e}"))?;
        self.auth_cache.lock().remove(username);
        Ok(())
    }

    /// Replace every ACL row for a user (parameterized).
    pub async fn replace_acls(
        &self,
        username: &str,
        rows: &[(String, String, bool)],
    ) -> std::result::Result<(), String> {
        use mysql_async::prelude::Queryable;
        let pool = self.pool()?;
        let mut conn =
            tokio::time::timeout(self.config.settings.connect_timeout(), pool.get_conn())
                .await
                .map_err(|_| "connect timed out".to_string())?
                .map_err(|e| format!("connect failed: {e}"))?;
        let timeout = self.config.settings.read_timeout();
        tokio::time::timeout(
            timeout,
            conn.exec_drop("DELETE FROM mqtt_acls WHERE username = ?", (username,)),
        )
        .await
        .map_err(|_| "delete timed out".to_string())?
        .map_err(|e| format!("delete failed: {e}"))?;
        for (topic, action, allow) in rows {
            let allow_int: i8 = i8::from(*allow);
            tokio::time::timeout(
                timeout,
                conn.exec_drop(
                    "INSERT INTO mqtt_acls(username, topic, action, allow) VALUES (?, ?, ?, ?)",
                    (username, topic.as_str(), action.as_str(), allow_int),
                ),
            )
            .await
            .map_err(|_| "insert timed out".to_string())?
            .map_err(|e| format!("insert failed: {e}"))?;
        }
        Ok(())
    }
}

#[async_trait]
impl Authenticator for MysqlAuth {
    async fn authenticate(
        &self,
        client_id: &str,
        username: Option<&str>,
        password: Option<&[u8]>,
    ) -> Result<()> {
        let (Some(username), Some(password)) = (username, password) else {
            return Err(AuthError::AuthenticationFailed(format!(
                "{client_id} presented no database credentials"
            )));
        };
        if username.is_empty() {
            return Err(AuthError::AuthenticationFailed(format!(
                "{client_id} presented no database credentials"
            )));
        }
        let timeout = self.config.settings.connect_timeout();
        let permit = tokio::time::timeout(timeout, self.semaphore.acquire()).await;
        let _permit = match permit {
            Ok(Ok(guard)) => guard,
            _ => {
                tracing::warn!("MySQL pool exhausted: failing closed for {client_id}");
                return Err(Self::fail_closed(client_id));
            }
        };
        self.authenticate_inner(username, password)
            .await
            .map_err(|e| match e {
                AuthError::AuthenticationFailed(msg) => {
                    let suffix = msg
                        .split_once(' ')
                        .map(|(_, rest)| rest)
                        .unwrap_or(msg.as_str());
                    AuthError::AuthenticationFailed(format!("{client_id} {suffix}"))
                }
                other => other,
            })
    }
}

#[async_trait]
impl Authorizer for MysqlAuth {
    async fn authorize_publish(&self, client_id: &str, topic: &Topic) -> Result<()> {
        let cache_key = format!("p\x00{client_id}\x00{}", topic.as_str());
        if let Some(allowed) = self.acl_cache.lock().get(&cache_key) {
            return allowed
                .then_some(())
                .ok_or_else(|| AuthError::PublishDenied(format!("{client_id} cannot publish")));
        }
        let timeout = self.config.settings.connect_timeout();
        let permit = tokio::time::timeout(timeout, self.semaphore.acquire()).await;
        let _permit = match permit {
            Ok(Ok(guard)) => guard,
            _ => {
                tracing::warn!("MySQL pool exhausted: failing closed for {client_id}");
                return Err(AuthError::PublishDenied(format!(
                    "{client_id} cannot publish"
                )));
            }
        };
        let rows = self.read_acls(client_id).await.map_err(|detail| {
            tracing::warn!("MySQL ACL unavailable: {detail}");
            AuthError::PublishDenied(format!("{client_id} cannot publish"))
        })?;
        let allowed = publish_allowed(&rows, topic);
        self.acl_cache.lock().put(cache_key, allowed);
        allowed
            .then_some(())
            .ok_or_else(|| AuthError::PublishDenied(format!("{client_id} cannot publish")))
    }

    async fn authorize_subscribe(&self, client_id: &str, filter: &TopicFilter) -> Result<()> {
        let cache_key = format!("s\x00{client_id}\x00{}", filter.as_str());
        if let Some(allowed) = self.acl_cache.lock().get(&cache_key) {
            return allowed.then_some(()).ok_or_else(|| {
                AuthError::SubscribeDenied(format!("{client_id} cannot subscribe"))
            });
        }
        let timeout = self.config.settings.connect_timeout();
        let permit = tokio::time::timeout(timeout, self.semaphore.acquire()).await;
        let _permit = match permit {
            Ok(Ok(guard)) => guard,
            _ => {
                tracing::warn!("MySQL pool exhausted: failing closed for {client_id}");
                return Err(AuthError::SubscribeDenied(format!(
                    "{client_id} cannot subscribe"
                )));
            }
        };
        let rows = self.read_acls(client_id).await.map_err(|detail| {
            tracing::warn!("MySQL ACL unavailable: {detail}");
            AuthError::SubscribeDenied(format!("{client_id} cannot subscribe"))
        })?;
        let allowed = subscribe_allowed(&rows, filter);
        self.acl_cache.lock().put(cache_key, allowed);
        allowed
            .then_some(())
            .ok_or_else(|| AuthError::SubscribeDenied(format!("{client_id} cannot subscribe")))
    }
}

// ---------------------------------------------------------------------------
// Redis
// ---------------------------------------------------------------------------

/// Redis credential/ACL source configuration
/// (`redis://:password@host:port/db`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RedisAuthConfig {
    #[serde(default)]
    pub url: String,
    #[serde(flatten)]
    pub settings: DbSourceSettings,
}

/// Redis-backed authenticator and authorizer (driver: `redis`).
pub struct RedisAuth {
    config: RedisAuthConfig,
    semaphore: Arc<Semaphore>,
    auth_cache: Mutex<BoundedTtlCache<String>>,
    acl_cache: Mutex<BoundedTtlCache<bool>>,
}

impl std::fmt::Debug for RedisAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisAuth")
            .field("configured", &self.is_configured())
            .finish()
    }
}

impl RedisAuth {
    pub fn new(config: RedisAuthConfig) -> Self {
        let permits = config.settings.pool_permits();
        let ttl = config.settings.cache_ttl();
        let max = config.settings.cache_max_entries;
        Self {
            config,
            semaphore: Arc::new(Semaphore::new(permits)),
            auth_cache: Mutex::new(BoundedTtlCache::new(max, ttl)),
            acl_cache: Mutex::new(BoundedTtlCache::new(max, ttl)),
        }
    }

    pub fn is_configured(&self) -> bool {
        !self.config.url.trim().is_empty()
    }

    /// Invalidate both caches (credential and ACL verdicts).
    ///
    /// TTL expiry already re-reads the database lazily on the next
    /// lookup; this explicit clear is the operator-driven invalidation
    /// path (for example after rotating credentials or ACLs outside
    /// the broker's own `upsert_user`/`replace_acls` helpers).
    pub fn clear_caches(&self) {
        self.auth_cache.lock().clear();
        self.acl_cache.lock().clear();
    }

    fn fail_closed(client_id: &str) -> AuthError {
        AuthError::AuthenticationFailed(format!(
            "{client_id} presented database credentials, but the database is unavailable"
        ))
    }

    fn user_key(username: &str) -> String {
        format!("mqtt:user:{username}")
    }

    fn acl_key(username: &str) -> String {
        format!("mqtt:acls:{username}")
    }

    fn acl_field(action: &str, topic: &str) -> String {
        format!("{action}|{topic}")
    }

    async fn connection(&self) -> std::result::Result<redis::aio::MultiplexedConnection, String> {
        if self.config.url.trim().is_empty() {
            return Err("no URL configured".to_string());
        }
        if !self.config.url.starts_with("redis://") {
            return Err("URL must start with redis://".to_string());
        }
        let client =
            redis::Client::open(self.config.url.as_str()).map_err(|e| format!("bad URL: {e}"))?;
        tokio::time::timeout(
            self.config.settings.connect_timeout(),
            client.get_multiplexed_async_connection(),
        )
        .await
        .map_err(|_| "connect timed out".to_string())?
        .map_err(|e| format!("connect failed: {e}"))
    }

    async fn read_password_hash(
        &self,
        username: &str,
    ) -> std::result::Result<Option<String>, String> {
        use redis::AsyncCommands;
        let mut conn = self.connection().await?;
        let key = Self::user_key(username);
        // Binary-safe GET: the username travels as a RESP bulk string,
        // never concatenated into a command line.
        let hash: Option<String> =
            tokio::time::timeout(self.config.settings.read_timeout(), conn.get(key))
                .await
                .map_err(|_| "query timed out".to_string())?
                .map_err(|e| format!("query failed: {e}"))?;
        Ok(hash)
    }

    async fn read_acls(&self, username: &str) -> std::result::Result<Vec<AclRow>, String> {
        use redis::AsyncCommands;
        let mut conn = self.connection().await?;
        let key = Self::acl_key(username);
        let map: HashMap<String, String> =
            tokio::time::timeout(self.config.settings.read_timeout(), conn.hgetall(key))
                .await
                .map_err(|_| "query timed out".to_string())?
                .map_err(|e| format!("query failed: {e}"))?;
        // Bounded: at most MAX_ACL_ROWS rows are consulted so a cache-miss
        // publish never matches unbounded entries; extras are ignored.
        if map.len() > MAX_ACL_ROWS {
            tracing::warn!("Redis ACL set truncated to {MAX_ACL_ROWS} rows");
        }
        let mut out = Vec::with_capacity(map.len().min(MAX_ACL_ROWS));
        for (field, allow_raw) in map {
            if out.len() >= MAX_ACL_ROWS {
                break;
            }
            if let Some((action_raw, topic)) = field.split_once('|') {
                if let Some(action) = parse_action(action_raw) {
                    out.push(AclRow {
                        topic: topic.to_string(),
                        action,
                        allow: allow_raw == "1",
                    });
                }
            }
        }
        out.sort_by(|a, b| a.topic.cmp(&b.topic));
        out.truncate(MAX_ACL_ROWS);
        Ok(out)
    }

    async fn authenticate_inner(&self, username: &str, password: &[u8]) -> Result<()> {
        if !self.is_configured() {
            tracing::warn!("Redis unavailable: no URL configured");
            return Err(Self::fail_closed("client"));
        }
        if let Some(cached) = self.auth_cache.lock().get(username) {
            if cached == hash_password_hex(password) {
                return Ok(());
            }
            return Err(Self::fail_closed("client"));
        }
        let stored = self.read_password_hash(username).await.map_err(|detail| {
            tracing::warn!("Redis unavailable: {detail}");
            Self::fail_closed("client")
        })?;
        let Some(stored) = stored else {
            return Err(Self::fail_closed("client"));
        };
        self.auth_cache
            .lock()
            .put(username.to_string(), stored.clone());
        if stored == hash_password_hex(password) {
            Ok(())
        } else {
            Err(Self::fail_closed("client"))
        }
    }

    /// Seed a user verifier (parameterized SET).
    pub async fn upsert_user(
        &self,
        username: &str,
        password: &[u8],
    ) -> std::result::Result<(), String> {
        use redis::AsyncCommands;
        let mut conn = self.connection().await?;
        let hash = hash_password_hex(password);
        tokio::time::timeout(
            self.config.settings.read_timeout(),
            conn.set::<_, _, ()>(Self::user_key(username), hash),
        )
        .await
        .map_err(|_| "write timed out".to_string())?
        .map_err(|e| format!("write failed: {e}"))?;
        self.auth_cache.lock().remove(username);
        Ok(())
    }

    /// Replace every ACL entry for a user (parameterized DEL plus HSET).
    pub async fn replace_acls(
        &self,
        username: &str,
        rows: &[(String, String, bool)],
    ) -> std::result::Result<(), String> {
        use redis::AsyncCommands;
        let mut conn = self.connection().await?;
        let timeout = self.config.settings.read_timeout();
        tokio::time::timeout(timeout, conn.del::<_, ()>(Self::acl_key(username)))
            .await
            .map_err(|_| "delete timed out".to_string())?
            .map_err(|e| format!("delete failed: {e}"))?;
        for (topic, action, allow) in rows {
            let field = Self::acl_field(action, topic);
            let value = if *allow { "1" } else { "0" };
            tokio::time::timeout(
                timeout,
                conn.hset::<_, _, _, ()>(Self::acl_key(username), field, value),
            )
            .await
            .map_err(|_| "write timed out".to_string())?
            .map_err(|e| format!("write failed: {e}"))?;
        }
        Ok(())
    }

    /// Remove a user and its ACLs (test cleanup).
    pub async fn remove_user(&self, username: &str) -> std::result::Result<(), String> {
        use redis::AsyncCommands;
        let mut conn = self.connection().await?;
        let timeout = self.config.settings.read_timeout();
        tokio::time::timeout(timeout, conn.del::<_, ()>(Self::user_key(username)))
            .await
            .map_err(|_| "delete timed out".to_string())?
            .map_err(|e| format!("delete failed: {e}"))?;
        tokio::time::timeout(timeout, conn.del::<_, ()>(Self::acl_key(username)))
            .await
            .map_err(|_| "delete timed out".to_string())?
            .map_err(|e| format!("delete failed: {e}"))?;
        self.auth_cache.lock().remove(username);
        Ok(())
    }
}

#[async_trait]
impl Authenticator for RedisAuth {
    async fn authenticate(
        &self,
        client_id: &str,
        username: Option<&str>,
        password: Option<&[u8]>,
    ) -> Result<()> {
        let (Some(username), Some(password)) = (username, password) else {
            return Err(AuthError::AuthenticationFailed(format!(
                "{client_id} presented no database credentials"
            )));
        };
        if username.is_empty() {
            return Err(AuthError::AuthenticationFailed(format!(
                "{client_id} presented no database credentials"
            )));
        }
        let timeout = self.config.settings.connect_timeout();
        let permit = tokio::time::timeout(timeout, self.semaphore.acquire()).await;
        let _permit = match permit {
            Ok(Ok(guard)) => guard,
            _ => {
                tracing::warn!("Redis pool exhausted: failing closed for {client_id}");
                return Err(Self::fail_closed(client_id));
            }
        };
        self.authenticate_inner(username, password)
            .await
            .map_err(|e| match e {
                AuthError::AuthenticationFailed(msg) => {
                    let suffix = msg
                        .split_once(' ')
                        .map(|(_, rest)| rest)
                        .unwrap_or(msg.as_str());
                    AuthError::AuthenticationFailed(format!("{client_id} {suffix}"))
                }
                other => other,
            })
    }
}

#[async_trait]
impl Authorizer for RedisAuth {
    async fn authorize_publish(&self, client_id: &str, topic: &Topic) -> Result<()> {
        let cache_key = format!("p\x00{client_id}\x00{}", topic.as_str());
        if let Some(allowed) = self.acl_cache.lock().get(&cache_key) {
            return allowed
                .then_some(())
                .ok_or_else(|| AuthError::PublishDenied(format!("{client_id} cannot publish")));
        }
        let timeout = self.config.settings.connect_timeout();
        let permit = tokio::time::timeout(timeout, self.semaphore.acquire()).await;
        let _permit = match permit {
            Ok(Ok(guard)) => guard,
            _ => {
                tracing::warn!("Redis pool exhausted: failing closed for {client_id}");
                return Err(AuthError::PublishDenied(format!(
                    "{client_id} cannot publish"
                )));
            }
        };
        let rows = self.read_acls(client_id).await.map_err(|detail| {
            tracing::warn!("Redis ACL unavailable: {detail}");
            AuthError::PublishDenied(format!("{client_id} cannot publish"))
        })?;
        let allowed = publish_allowed(&rows, topic);
        self.acl_cache.lock().put(cache_key, allowed);
        allowed
            .then_some(())
            .ok_or_else(|| AuthError::PublishDenied(format!("{client_id} cannot publish")))
    }

    async fn authorize_subscribe(&self, client_id: &str, filter: &TopicFilter) -> Result<()> {
        let cache_key = format!("s\x00{client_id}\x00{}", filter.as_str());
        if let Some(allowed) = self.acl_cache.lock().get(&cache_key) {
            return allowed.then_some(()).ok_or_else(|| {
                AuthError::SubscribeDenied(format!("{client_id} cannot subscribe"))
            });
        }
        let timeout = self.config.settings.connect_timeout();
        let permit = tokio::time::timeout(timeout, self.semaphore.acquire()).await;
        let _permit = match permit {
            Ok(Ok(guard)) => guard,
            _ => {
                tracing::warn!("Redis pool exhausted: failing closed for {client_id}");
                return Err(AuthError::SubscribeDenied(format!(
                    "{client_id} cannot subscribe"
                )));
            }
        };
        let rows = self.read_acls(client_id).await.map_err(|detail| {
            tracing::warn!("Redis ACL unavailable: {detail}");
            AuthError::SubscribeDenied(format!("{client_id} cannot subscribe"))
        })?;
        let allowed = subscribe_allowed(&rows, filter);
        self.acl_cache.lock().put(cache_key, allowed);
        allowed
            .then_some(())
            .ok_or_else(|| AuthError::SubscribeDenied(format!("{client_id} cannot subscribe")))
    }
}

// ---------------------------------------------------------------------------
// MongoDB
// ---------------------------------------------------------------------------

/// MongoDB credential/ACL source configuration
/// (`mongodb://user:pass@host:port/db?authSource=admin`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MongoAuthConfig {
    #[serde(default)]
    pub url: String,
    #[serde(flatten)]
    pub settings: DbSourceSettings,
}

/// MongoDB-backed authenticator and authorizer (driver: `mongodb`).
pub struct MongoAuth {
    config: MongoAuthConfig,
    semaphore: Arc<Semaphore>,
    auth_cache: Mutex<BoundedTtlCache<String>>,
    acl_cache: Mutex<BoundedTtlCache<bool>>,
    client: tokio::sync::OnceCell<mongodb::Client>,
}

impl std::fmt::Debug for MongoAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MongoAuth")
            .field("configured", &self.is_configured())
            .finish()
    }
}

impl MongoAuth {
    pub fn new(config: MongoAuthConfig) -> Self {
        let permits = config.settings.pool_permits();
        let ttl = config.settings.cache_ttl();
        let max = config.settings.cache_max_entries;
        Self {
            config,
            semaphore: Arc::new(Semaphore::new(permits)),
            auth_cache: Mutex::new(BoundedTtlCache::new(max, ttl)),
            acl_cache: Mutex::new(BoundedTtlCache::new(max, ttl)),
            client: tokio::sync::OnceCell::new(),
        }
    }

    pub fn is_configured(&self) -> bool {
        !self.config.url.trim().is_empty()
    }

    /// Invalidate both caches (credential and ACL verdicts).
    ///
    /// TTL expiry already re-reads the database lazily on the next
    /// lookup; this explicit clear is the operator-driven invalidation
    /// path (for example after rotating credentials or ACLs outside
    /// the broker's own `upsert_user`/`replace_acls` helpers).
    pub fn clear_caches(&self) {
        self.auth_cache.lock().clear();
        self.acl_cache.lock().clear();
    }

    fn fail_closed(client_id: &str) -> AuthError {
        AuthError::AuthenticationFailed(format!(
            "{client_id} presented database credentials, but the database is unavailable"
        ))
    }

    /// Database named by the connection URL path (defaults to `qual`
    /// when absent).
    /// TODO(parity): should a URL without a path fail closed instead of
    /// defaulting? The rulebook does not decide; the current choice keeps
    /// the qualification URL working while still failing closed on any
    /// I/O error.
    fn database_name(url: &str) -> String {
        let after_scheme = url.split("://").nth(1).unwrap_or(url);
        let path = after_scheme.split_once('/').map(|(_, p)| p).unwrap_or("");
        let name = path.split('?').next().unwrap_or("").trim();
        if name.is_empty() {
            "qual".to_string()
        } else {
            name.to_string()
        }
    }

    async fn client(&self) -> std::result::Result<mongodb::Client, String> {
        if self.config.url.trim().is_empty() {
            return Err("no URL configured".to_string());
        }
        if !self.config.url.starts_with("mongodb://") {
            return Err("URL must start with mongodb://".to_string());
        }
        match self
            .client
            .get_or_try_init(|| async {
                let mut options = mongodb::options::ClientOptions::parse(&self.config.url)
                    .await
                    .map_err(|e| format!("bad URL: {e}"))?;
                options.max_pool_size = Some(
                    u32::try_from(clamp_pool_size(self.config.settings.pool_size)).unwrap_or(8),
                );
                options.connect_timeout = Some(self.config.settings.connect_timeout());
                options.server_selection_timeout = Some(self.config.settings.connect_timeout());
                mongodb::Client::with_options(options).map_err(|e| format!("client failed: {e}"))
            })
            .await
        {
            Ok(client) => Ok(client.clone()),
            Err(detail) => Err(detail.clone()),
        }
    }

    async fn read_password_hash(
        &self,
        username: &str,
    ) -> std::result::Result<Option<String>, String> {
        let client = self.client().await?;
        let db = client.database(&Self::database_name(&self.config.url));
        let users: mongodb::Collection<mongodb::bson::Document> = db.collection("mqtt_users");
        // Driver filter document: the credential is a BSON value, never
        // concatenated into a query string.
        let filter = mongodb::bson::doc! { "username": username };
        let doc = tokio::time::timeout(self.config.settings.read_timeout(), users.find_one(filter))
            .await
            .map_err(|_| "query timed out".to_string())?
            .map_err(|e| format!("query failed: {e}"))?;
        Ok(doc.and_then(|d| d.get_str("password_hash").ok().map(str::to_string)))
    }

    async fn read_acls(&self, username: &str) -> std::result::Result<Vec<AclRow>, String> {
        use futures::TryStreamExt as _;
        let client = self.client().await?;
        let db = client.database(&Self::database_name(&self.config.url));
        let acls: mongodb::Collection<mongodb::bson::Document> = db.collection("mqtt_acls");
        let filter = mongodb::bson::doc! { "username": username };
        let mut cursor =
            tokio::time::timeout(self.config.settings.read_timeout(), acls.find(filter))
                .await
                .map_err(|_| "query timed out".to_string())?
                .map_err(|e| format!("query failed: {e}"))?;
        // Bounded: the cursor loop stops at MAX_ACL_ROWS so a cache-miss
        // publish never grows a Vec unbounded; extras are ignored.
        let mut out = Vec::new();
        while let Some(doc) =
            tokio::time::timeout(self.config.settings.read_timeout(), cursor.try_next())
                .await
                .map_err(|_| "query timed out".to_string())?
                .map_err(|e| format!("query failed: {e}"))?
        {
            if out.len() >= MAX_ACL_ROWS {
                tracing::warn!("MongoDB ACL set truncated to {MAX_ACL_ROWS} rows");
                break;
            }
            let (Some(topic), Some(action_raw), Some(allow)) = (
                doc.get_str("topic").ok(),
                doc.get_str("action").ok(),
                doc.get_bool("allow").ok(),
            ) else {
                continue;
            };
            if let Some(action) = parse_action(action_raw) {
                out.push(AclRow {
                    topic: topic.to_string(),
                    action,
                    allow,
                });
            }
        }
        out.sort_by(|a, b| a.topic.cmp(&b.topic));
        out.truncate(MAX_ACL_ROWS);
        Ok(out)
    }

    async fn authenticate_inner(&self, username: &str, password: &[u8]) -> Result<()> {
        if !self.is_configured() {
            tracing::warn!("MongoDB unavailable: no URL configured");
            return Err(Self::fail_closed("client"));
        }
        if let Some(cached) = self.auth_cache.lock().get(username) {
            if cached == hash_password_hex(password) {
                return Ok(());
            }
            return Err(Self::fail_closed("client"));
        }
        let stored = self.read_password_hash(username).await.map_err(|detail| {
            tracing::warn!("MongoDB unavailable: {detail}");
            Self::fail_closed("client")
        })?;
        let Some(stored) = stored else {
            return Err(Self::fail_closed("client"));
        };
        self.auth_cache
            .lock()
            .put(username.to_string(), stored.clone());
        if stored == hash_password_hex(password) {
            Ok(())
        } else {
            Err(Self::fail_closed("client"))
        }
    }

    /// Insert or replace a user verifier.
    pub async fn upsert_user(
        &self,
        username: &str,
        password: &[u8],
    ) -> std::result::Result<(), String> {
        let client = self.client().await?;
        let db = client.database(&Self::database_name(&self.config.url));
        let users: mongodb::Collection<mongodb::bson::Document> = db.collection("mqtt_users");
        let hash = hash_password_hex(password);
        let timeout = self.config.settings.read_timeout();
        tokio::time::timeout(
            timeout,
            users
                .update_one(
                    mongodb::bson::doc! { "username": username },
                    mongodb::bson::doc! { "$set": { "username": username, "password_hash": hash } },
                )
                .with_options(
                    mongodb::options::UpdateOptions::builder()
                        .upsert(true)
                        .build(),
                ),
        )
        .await
        .map_err(|_| "upsert timed out".to_string())?
        .map_err(|e| format!("upsert failed: {e}"))?;
        self.auth_cache.lock().remove(username);
        Ok(())
    }

    /// Replace every ACL document for a user.
    pub async fn replace_acls(
        &self,
        username: &str,
        rows: &[(String, String, bool)],
    ) -> std::result::Result<(), String> {
        let client = self.client().await?;
        let db = client.database(&Self::database_name(&self.config.url));
        let acls: mongodb::Collection<mongodb::bson::Document> = db.collection("mqtt_acls");
        let timeout = self.config.settings.read_timeout();
        tokio::time::timeout(
            timeout,
            acls.delete_many(mongodb::bson::doc! { "username": username }),
        )
        .await
        .map_err(|_| "delete timed out".to_string())?
        .map_err(|e| format!("delete failed: {e}"))?;
        for (topic, action, allow) in rows {
            tokio::time::timeout(
                timeout,
                acls.insert_one(
                    mongodb::bson::doc! { "username": username, "topic": topic, "action": action, "allow": *allow },
                ),
            )
            .await
            .map_err(|_| "insert timed out".to_string())?
            .map_err(|e| format!("insert failed: {e}"))?;
        }
        Ok(())
    }
}

#[async_trait]
impl Authenticator for MongoAuth {
    async fn authenticate(
        &self,
        client_id: &str,
        username: Option<&str>,
        password: Option<&[u8]>,
    ) -> Result<()> {
        let (Some(username), Some(password)) = (username, password) else {
            return Err(AuthError::AuthenticationFailed(format!(
                "{client_id} presented no database credentials"
            )));
        };
        if username.is_empty() {
            return Err(AuthError::AuthenticationFailed(format!(
                "{client_id} presented no database credentials"
            )));
        }
        let timeout = self.config.settings.connect_timeout();
        let permit = tokio::time::timeout(timeout, self.semaphore.acquire()).await;
        let _permit = match permit {
            Ok(Ok(guard)) => guard,
            _ => {
                tracing::warn!("MongoDB pool exhausted: failing closed for {client_id}");
                return Err(Self::fail_closed(client_id));
            }
        };
        self.authenticate_inner(username, password)
            .await
            .map_err(|e| match e {
                AuthError::AuthenticationFailed(msg) => {
                    let suffix = msg
                        .split_once(' ')
                        .map(|(_, rest)| rest)
                        .unwrap_or(msg.as_str());
                    AuthError::AuthenticationFailed(format!("{client_id} {suffix}"))
                }
                other => other,
            })
    }
}

#[async_trait]
impl Authorizer for MongoAuth {
    async fn authorize_publish(&self, client_id: &str, topic: &Topic) -> Result<()> {
        let cache_key = format!("p\x00{client_id}\x00{}", topic.as_str());
        if let Some(allowed) = self.acl_cache.lock().get(&cache_key) {
            return allowed
                .then_some(())
                .ok_or_else(|| AuthError::PublishDenied(format!("{client_id} cannot publish")));
        }
        let timeout = self.config.settings.connect_timeout();
        let permit = tokio::time::timeout(timeout, self.semaphore.acquire()).await;
        let _permit = match permit {
            Ok(Ok(guard)) => guard,
            _ => {
                tracing::warn!("MongoDB pool exhausted: failing closed for {client_id}");
                return Err(AuthError::PublishDenied(format!(
                    "{client_id} cannot publish"
                )));
            }
        };
        let rows = self.read_acls(client_id).await.map_err(|detail| {
            tracing::warn!("MongoDB ACL unavailable: {detail}");
            AuthError::PublishDenied(format!("{client_id} cannot publish"))
        })?;
        let allowed = publish_allowed(&rows, topic);
        self.acl_cache.lock().put(cache_key, allowed);
        allowed
            .then_some(())
            .ok_or_else(|| AuthError::PublishDenied(format!("{client_id} cannot publish")))
    }

    async fn authorize_subscribe(&self, client_id: &str, filter: &TopicFilter) -> Result<()> {
        let cache_key = format!("s\x00{client_id}\x00{}", filter.as_str());
        if let Some(allowed) = self.acl_cache.lock().get(&cache_key) {
            return allowed.then_some(()).ok_or_else(|| {
                AuthError::SubscribeDenied(format!("{client_id} cannot subscribe"))
            });
        }
        let timeout = self.config.settings.connect_timeout();
        let permit = tokio::time::timeout(timeout, self.semaphore.acquire()).await;
        let _permit = match permit {
            Ok(Ok(guard)) => guard,
            _ => {
                tracing::warn!("MongoDB pool exhausted: failing closed for {client_id}");
                return Err(AuthError::SubscribeDenied(format!(
                    "{client_id} cannot subscribe"
                )));
            }
        };
        let rows = self.read_acls(client_id).await.map_err(|detail| {
            tracing::warn!("MongoDB ACL unavailable: {detail}");
            AuthError::SubscribeDenied(format!("{client_id} cannot subscribe"))
        })?;
        let allowed = subscribe_allowed(&rows, filter);
        self.acl_cache.lock().put(cache_key, allowed);
        allowed
            .then_some(())
            .ok_or_else(|| AuthError::SubscribeDenied(format!("{client_id} cannot subscribe")))
    }
}

// ---------------------------------------------------------------------------
// Combined set wired into the broker
// ---------------------------------------------------------------------------

/// Configuration for the combined database sources.
///
/// Each non-empty URL enables its source with the shared pool, timeout
/// and cache bounds below (one pool per database). All empty disables
/// database authentication entirely (CONNECT pays one `is_some` branch).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DbAuthSetConfig {
    #[serde(default)]
    pub postgres_url: String,
    #[serde(default)]
    pub mysql_url: String,
    #[serde(default)]
    pub redis_url: String,
    #[serde(default)]
    pub mongodb_url: String,
    #[serde(default = "default_pool_size")]
    pub pool_size: usize,
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_read_timeout_ms")]
    pub read_timeout_ms: u64,
    #[serde(default = "default_cache_max_entries")]
    pub cache_max_entries: usize,
    #[serde(default = "default_cache_ttl_secs")]
    pub cache_ttl_secs: u64,
}

/// The broker's database authentication set: up to four bounded sources.
///
/// CONNECT succeeds when any configured source accepts the credentials;
/// publish/subscribe succeed when any configured source allows them.
/// Anything else — including any outage — fails closed.
/// TODO(parity): should the first configured source holding the user
/// decide instead of any-accept? Neither the rulebook nor the spec
/// decides multi-source precedence; any-accept is the conservative
/// choice that never locks out a user one source knows.
pub struct DbAuthSet {
    postgres: Option<Arc<PostgresAuth>>,
    mysql: Option<Arc<MysqlAuth>>,
    redis: Option<Arc<RedisAuth>>,
    mongo: Option<Arc<MongoAuth>>,
}

impl std::fmt::Debug for DbAuthSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DbAuthSet")
            .field("postgres", &self.postgres.is_some())
            .field("mysql", &self.mysql.is_some())
            .field("redis", &self.redis.is_some())
            .field("mongo", &self.mongo.is_some())
            .finish()
    }
}

impl DbAuthSet {
    pub fn new(config: &DbAuthSetConfig) -> Self {
        let settings = DbSourceSettings {
            pool_size: config.pool_size,
            connect_timeout_ms: config.connect_timeout_ms,
            read_timeout_ms: config.read_timeout_ms,
            cache_max_entries: config.cache_max_entries,
            cache_ttl_secs: config.cache_ttl_secs,
        };
        let postgres = (!config.postgres_url.trim().is_empty()).then(|| {
            Arc::new(PostgresAuth::new(PostgresAuthConfig {
                url: config.postgres_url.clone(),
                settings: settings.clone(),
            }))
        });
        let mysql = (!config.mysql_url.trim().is_empty()).then(|| {
            Arc::new(MysqlAuth::new(MysqlAuthConfig {
                url: config.mysql_url.clone(),
                settings: settings.clone(),
            }))
        });
        let redis = (!config.redis_url.trim().is_empty()).then(|| {
            Arc::new(RedisAuth::new(RedisAuthConfig {
                url: config.redis_url.clone(),
                settings: settings.clone(),
            }))
        });
        let mongo = (!config.mongodb_url.trim().is_empty()).then(|| {
            Arc::new(MongoAuth::new(MongoAuthConfig {
                url: config.mongodb_url.clone(),
                settings: settings.clone(),
            }))
        });
        Self {
            postgres,
            mysql,
            redis,
            mongo,
        }
    }

    /// Whether any database source is configured.
    pub fn is_configured(&self) -> bool {
        self.postgres.is_some()
            || self.mysql.is_some()
            || self.redis.is_some()
            || self.mongo.is_some()
    }

    /// Invalidate every configured source's caches (operator-driven
    /// invalidation alongside lazy TTL expiry).
    pub fn clear_caches(&self) {
        if let Some(pg) = self.postgres.as_ref() {
            pg.clear_caches();
        }
        if let Some(my) = self.mysql.as_ref() {
            my.clear_caches();
        }
        if let Some(rd) = self.redis.as_ref() {
            rd.clear_caches();
        }
        if let Some(mg) = self.mongo.as_ref() {
            mg.clear_caches();
        }
    }

    /// Pool bound shared by every configured source (for the report).
    pub fn pool_size(&self) -> usize {
        clamp_pool_size(
            self.postgres
                .as_ref()
                .map(|s| s.config.settings.pool_size)
                .or_else(|| self.mysql.as_ref().map(|s| s.config.settings.pool_size))
                .or_else(|| self.redis.as_ref().map(|s| s.config.settings.pool_size))
                .or_else(|| self.mongo.as_ref().map(|s| s.config.settings.pool_size))
                .unwrap_or(DEFAULT_POOL_SIZE),
        )
    }
}

#[async_trait]
impl Authenticator for DbAuthSet {
    async fn authenticate(
        &self,
        client_id: &str,
        username: Option<&str>,
        password: Option<&[u8]>,
    ) -> Result<()> {
        let mut attempted = false;
        if let Some(pg) = self.postgres.as_ref() {
            attempted = true;
            if pg.authenticate(client_id, username, password).await.is_ok() {
                return Ok(());
            }
        }
        if let Some(my) = self.mysql.as_ref() {
            attempted = true;
            if my.authenticate(client_id, username, password).await.is_ok() {
                return Ok(());
            }
        }
        if let Some(rd) = self.redis.as_ref() {
            attempted = true;
            if rd.authenticate(client_id, username, password).await.is_ok() {
                return Ok(());
            }
        }
        if let Some(mg) = self.mongo.as_ref() {
            attempted = true;
            if mg.authenticate(client_id, username, password).await.is_ok() {
                return Ok(());
            }
        }
        if attempted {
            tracing::warn!("Database authentication failed closed for {client_id}");
        }
        Err(AuthError::AuthenticationFailed(format!(
            "{client_id} presented database credentials that cannot be verified"
        )))
    }
}

#[async_trait]
impl Authorizer for DbAuthSet {
    async fn authorize_publish(&self, client_id: &str, topic: &Topic) -> Result<()> {
        // Consult each configured source in order (each is itself cached
        // and bounded); the first allow wins, anything else fails closed.
        if let Some(pg) = self.postgres.as_ref() {
            if pg.authorize_publish(client_id, topic).await.is_ok() {
                return Ok(());
            }
        }
        if let Some(my) = self.mysql.as_ref() {
            if my.authorize_publish(client_id, topic).await.is_ok() {
                return Ok(());
            }
        }
        if let Some(rd) = self.redis.as_ref() {
            if rd.authorize_publish(client_id, topic).await.is_ok() {
                return Ok(());
            }
        }
        if let Some(mg) = self.mongo.as_ref() {
            if mg.authorize_publish(client_id, topic).await.is_ok() {
                return Ok(());
            }
        }
        Err(AuthError::PublishDenied(format!(
            "{client_id} cannot publish"
        )))
    }

    async fn authorize_subscribe(&self, client_id: &str, filter: &TopicFilter) -> Result<()> {
        if let Some(pg) = self.postgres.as_ref() {
            if pg.authorize_subscribe(client_id, filter).await.is_ok() {
                return Ok(());
            }
        }
        if let Some(my) = self.mysql.as_ref() {
            if my.authorize_subscribe(client_id, filter).await.is_ok() {
                return Ok(());
            }
        }
        if let Some(rd) = self.redis.as_ref() {
            if rd.authorize_subscribe(client_id, filter).await.is_ok() {
                return Ok(());
            }
        }
        if let Some(mg) = self.mongo.as_ref() {
            if mg.authorize_subscribe(client_id, filter).await.is_ok() {
                return Ok(());
            }
        }
        Err(AuthError::SubscribeDenied(format!(
            "{client_id} cannot subscribe"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn topic(s: &str) -> Topic {
        Topic::new(s).unwrap()
    }

    fn filter(s: &str) -> TopicFilter {
        TopicFilter::new(s).unwrap()
    }

    #[test]
    fn password_hash_is_stable_hex() {
        let a = hash_password_hex(b"qual-pass-1");
        assert_eq!(a.len(), 64);
        assert_eq!(a, hash_password_hex(b"qual-pass-1"));
        assert_ne!(a, hash_password_hex(b"qual-pass-2"));
    }

    #[test]
    fn cache_expires_and_evicts_oldest() {
        let mut cache = BoundedTtlCache::new(2, Duration::from_millis(50));
        cache.put("a".to_string(), 1u32);
        cache.put("b".to_string(), 2u32);
        assert_eq!(cache.get("a"), Some(1));
        cache.put("c".to_string(), 3u32);
        assert_eq!(cache.len(), 2);
        // FIFO: `a` was inserted first, so it evicts past the bound.
        assert_eq!(cache.get("a"), None);
        assert_eq!(cache.get("b"), Some(2));
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(cache.get("b"), None, "TTL expiry must drop the entry");
        assert!(cache.is_empty() || cache.len() <= 2);
    }

    #[tokio::test]
    #[ignore]
    async fn cache_ttl_expiry_re_reads_database() {
        // Against the real PostgreSQL server: seed an allowed ACL, change
        // the ACL, and assert the cached verdict survives until the TTL
        // lapses and the new verdict appears after it.
        let url = require_env("DBAUTH_POSTGRES_URL");
        let auth = PostgresAuth::new(PostgresAuthConfig {
            url,
            settings: DbSourceSettings {
                pool_size: 2,
                connect_timeout_ms: 5_000,
                read_timeout_ms: 5_000,
                cache_max_entries: 16,
                cache_ttl_secs: 1,
            },
        });
        auth.ensure_schema()
            .await
            .unwrap_or_else(|e| panic!("postgres schema failed: {e}"));
        let user = "qual_ttl_user";
        auth.clear_caches();
        auth.upsert_user(user, b"qual-pass-1")
            .await
            .unwrap_or_else(|e| panic!("postgres seed user failed: {e}"));
        auth.replace_acls(
            user,
            &[("qual/allowed".to_string(), "publish".to_string(), true)],
        )
        .await
        .unwrap_or_else(|e| panic!("postgres seed ACL failed: {e}"));
        auth.clear_caches();
        assert!(
            auth.authorize_publish(user, &topic("qual/allowed"))
                .await
                .is_ok(),
            "seeded ACL must permit before the change"
        );
        // Change the ACL to deny-all: replace_acls leaves the verdict cache
        // intact, so only TTL expiry makes the change visible.
        auth.replace_acls(user, &[])
            .await
            .unwrap_or_else(|e| panic!("postgres replace ACL failed: {e}"));
        assert!(
            auth.authorize_publish(user, &topic("qual/allowed"))
                .await
                .is_ok(),
            "cached verdict must survive until the TTL lapses"
        );
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert!(
            auth.authorize_publish(user, &topic("qual/allowed"))
                .await
                .is_err(),
            "TTL expiry must re-read the database and refuse"
        );
    }

    #[test]
    fn acl_allow_list_semantics() {
        let rows = vec![AclRow {
            topic: "qual/allowed".to_string(),
            action: AclAction::Publish,
            allow: true,
        }];
        assert!(publish_allowed(&rows, &topic("qual/allowed")));
        assert!(!publish_allowed(&rows, &topic("qual/denied")));
        assert!(subscribe_allowed(
            &[AclRow {
                topic: "qual/#".to_string(),
                action: AclAction::Subscribe,
                allow: true,
            }],
            &filter("qual/allowed")
        ));
        assert!(!subscribe_allowed(
            &[AclRow {
                topic: "qual/#".to_string(),
                action: AclAction::Publish,
                allow: true,
            }],
            &filter("qual/allowed")
        ));
    }

    #[test]
    fn injection_value_stays_literal() {
        // A filter-injection-shaped username must not match anything: it
        // is always bound as a value, never concatenated.
        let evil = "alice' OR '1'='1";
        assert_ne!(RedisAuth::user_key(evil), RedisAuth::user_key("alice"));
        assert!(RedisAuth::user_key(evil).starts_with("mqtt:user:"));
        assert_eq!(
            MongoAuth::database_name("mongodb://h:27017/qual?authSource=admin"),
            "qual"
        );
    }

    async fn closed_port() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("ephemeral port");
        let addr = listener.local_addr().expect("local addr");
        drop(listener);
        addr.to_string()
    }

    fn short_settings() -> DbSourceSettings {
        DbSourceSettings {
            pool_size: 2,
            connect_timeout_ms: 500,
            read_timeout_ms: 500,
            cache_max_entries: 16,
            cache_ttl_secs: 60,
        }
    }

    #[tokio::test]
    async fn postgres_unreachable_fails_closed() {
        let addr = closed_port().await;
        let auth = PostgresAuth::new(PostgresAuthConfig {
            url: format!("postgresql://qual:qualpass1@{addr}/qual"),
            settings: short_settings(),
        });
        assert!(auth
            .authenticate("c", Some("qualuser"), Some(b"qual-pass-1"))
            .await
            .is_err());
        assert!(auth
            .authorize_publish("qualuser", &topic("qual/allowed"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn mysql_unreachable_fails_closed() {
        let addr = closed_port().await;
        let auth = MysqlAuth::new(MysqlAuthConfig {
            url: format!("mysql://qual:qualpass1@{addr}/qual"),
            settings: short_settings(),
        });
        assert!(auth
            .authenticate("c", Some("qualuser"), Some(b"qual-pass-1"))
            .await
            .is_err());
        assert!(auth
            .authorize_publish("qualuser", &topic("qual/allowed"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn redis_unreachable_fails_closed() {
        let addr = closed_port().await;
        let auth = RedisAuth::new(RedisAuthConfig {
            url: format!("redis://:qualpass1@{addr}/0"),
            settings: short_settings(),
        });
        assert!(auth
            .authenticate("c", Some("qualuser"), Some(b"qual-pass-1"))
            .await
            .is_err());
        assert!(auth
            .authorize_publish("qualuser", &topic("qual/allowed"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn mongodb_unreachable_fails_closed() {
        let addr = closed_port().await;
        let auth = MongoAuth::new(MongoAuthConfig {
            url: format!("mongodb://qual:qualpass1@{addr}/qual?authSource=admin"),
            settings: short_settings(),
        });
        assert!(auth
            .authenticate("c", Some("qualuser"), Some(b"qual-pass-1"))
            .await
            .is_err());
        assert!(auth
            .authorize_publish("qualuser", &topic("qual/allowed"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn db_set_empty_is_not_configured() {
        let set = DbAuthSet::new(&DbAuthSetConfig::default());
        assert!(!set.is_configured());
        assert!(set.authenticate("c", Some("u"), Some(b"p")).await.is_err());
    }

    // ------------------------------------------------------------------
    // Qualification: one ignored test per database. Each seeds its own
    // user and ACL rows through its single-source helper, then asserts
    // through `DbAuthSet` — the exact type the broker consults at CONNECT
    // (`apply_bind` at broker-node main.rs:758,841) and on the publish
    // path (broker-node main.rs:3495): seeded password accepted, wrong
    // password refused, allowed topic permitted, denied topic refused,
    // and outage refused (fails closed). Each panics when its environment
    // is missing — a missing URL never counts as a pass.
    // ------------------------------------------------------------------

    fn qual_settings() -> DbSourceSettings {
        DbSourceSettings {
            pool_size: 4,
            connect_timeout_ms: 5_000,
            read_timeout_ms: 5_000,
            cache_max_entries: 128,
            cache_ttl_secs: 60,
        }
    }

    fn require_env(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| {
            panic!(
                "{name} must be set by the qualification runner (pipeline starts the database); missing environment fails, never skips"
            )
        })
    }

    /// Ask the host to stop the primary (PostgreSQL) server by writing
    /// the fault file, then poll until the broker refuses (fails
    /// closed). Only the primary uses the fault file; every other
    /// database proves fail-closed against a closed port.
    /// Each probe clears both caches first so a cached success cannot
    /// mask the outage, and polls every 100 ms so the brief restart
    /// window the host creates is observed (a 2 s poll misses it).
    /// TODO(parity): the exact fault-file protocol (contents, stop
    /// latency) is host-defined and undocumented in-tree; the current
    /// choice writes `stop postgres` and polls up to two minutes.
    fn qual_set_config(
        postgres_url: String,
        mysql_url: String,
        redis_url: String,
        mongodb_url: String,
    ) -> DbAuthSetConfig {
        let s = qual_settings();
        DbAuthSetConfig {
            postgres_url,
            mysql_url,
            redis_url,
            mongodb_url,
            pool_size: s.pool_size,
            connect_timeout_ms: s.connect_timeout_ms,
            read_timeout_ms: s.read_timeout_ms,
            cache_max_entries: s.cache_max_entries,
            cache_ttl_secs: s.cache_ttl_secs,
        }
    }

    async fn postgres_fault_and_assert_closed(broker: &DbAuthSet, username: &str) {
        let fault_file = std::env::var("QUAL_FAULT_FILE").unwrap_or_else(|_| {
            panic!(
                "QUAL_FAULT_FILE must be set by the qualification runner for the primary-server outage; missing environment fails, never skips"
            )
        });
        std::fs::write(&fault_file, "stop postgres").unwrap_or_else(|e| {
            panic!("cannot write QUAL_FAULT_FILE {fault_file}: {e}");
        });
        let start = Instant::now();
        loop {
            // Bypass the verdict caches: without this, the seeded
            // credential and the allowed-topic verdict hit the cache and
            // report success while the database is stopped.
            broker.clear_caches();
            let auth_failed = broker
                .authenticate("qual-down", Some(username), Some(b"qual-pass-1"))
                .await
                .is_err();
            let pub_failed = broker
                .authorize_publish(username, &topic("qual/allowed"))
                .await
                .is_err();
            if auth_failed && pub_failed {
                break;
            }
            if start.elapsed() > Duration::from_secs(120) {
                panic!("PostgreSQL stop did not fail closed within 120 s");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    #[tokio::test]
    #[ignore]
    async fn test_qualify_postgres_auth_and_acl() {
        let url = require_env("DBAUTH_POSTGRES_URL");
        let seed = PostgresAuth::new(PostgresAuthConfig {
            url: url.clone(),
            settings: qual_settings(),
        });
        seed.ensure_schema()
            .await
            .unwrap_or_else(|e| panic!("postgres schema failed: {e}"));
        let user = "qual_pg_user";
        seed.upsert_user(user, b"qual-pass-1")
            .await
            .unwrap_or_else(|e| panic!("postgres seed user failed: {e}"));
        seed.replace_acls(
            user,
            &[("qual/allowed".to_string(), "publish".to_string(), true)],
        )
        .await
        .unwrap_or_else(|e| panic!("postgres seed ACL failed: {e}"));
        // Assertions go through DbAuthSet, the broker's CONNECT/publish type.
        let broker = DbAuthSet::new(&qual_set_config(
            url,
            String::new(),
            String::new(),
            String::new(),
        ));

        // Through the broker's CONNECT call: seeded password accepted.
        assert!(
            broker
                .authenticate("qual-conn-1", Some(user), Some(b"qual-pass-1"))
                .await
                .is_ok(),
            "seeded postgres password must be accepted"
        );
        // Wrong password refused.
        assert!(
            broker
                .authenticate("qual-conn-2", Some(user), Some(b"wrong"))
                .await
                .is_err(),
            "wrong postgres password must be refused"
        );
        // Unknown user refused.
        assert!(
            broker
                .authenticate("qual-conn-3", Some("no-such"), Some(b"x"))
                .await
                .is_err(),
            "unknown postgres user must be refused"
        );
        // Through the broker's publish call: allowed permitted (exact count 1).
        let mut allowed = 0;
        if broker
            .authorize_publish(user, &topic("qual/allowed"))
            .await
            .is_ok()
        {
            allowed += 1;
        }
        assert_eq!(
            allowed, 1,
            "allowed postgres topic must be permitted exactly once"
        );
        // Denied refused (exact count 1).
        let mut denied = 0;
        if broker
            .authorize_publish(user, &topic("qual/denied"))
            .await
            .is_err()
        {
            denied += 1;
        }
        assert_eq!(
            denied, 1,
            "denied postgres topic must be refused exactly once"
        );

        postgres_fault_and_assert_closed(&broker, user).await;
    }

    #[tokio::test]
    #[ignore]
    async fn test_qualify_mysql_auth_and_acl() {
        let url = require_env("DBAUTH_MYSQL_URL");
        let seed = MysqlAuth::new(MysqlAuthConfig {
            url: url.clone(),
            settings: qual_settings(),
        });
        seed.ensure_schema()
            .await
            .unwrap_or_else(|e| panic!("mysql schema failed: {e}"));
        let user = "qual_my_user";
        seed.upsert_user(user, b"qual-pass-1")
            .await
            .unwrap_or_else(|e| panic!("mysql seed user failed: {e}"));
        seed.replace_acls(
            user,
            &[("qual/allowed".to_string(), "publish".to_string(), true)],
        )
        .await
        .unwrap_or_else(|e| panic!("mysql seed ACL failed: {e}"));
        // Assertions go through DbAuthSet, the broker's CONNECT/publish type.
        let broker = DbAuthSet::new(&qual_set_config(
            String::new(),
            url,
            String::new(),
            String::new(),
        ));

        assert!(
            broker
                .authenticate("qual-conn-1", Some(user), Some(b"qual-pass-1"))
                .await
                .is_ok(),
            "seeded mysql password must be accepted"
        );
        assert!(
            broker
                .authenticate("qual-conn-2", Some(user), Some(b"wrong"))
                .await
                .is_err(),
            "wrong mysql password must be refused"
        );
        assert!(
            broker
                .authenticate("qual-conn-3", Some("no-such"), Some(b"x"))
                .await
                .is_err(),
            "unknown mysql user must be refused"
        );
        let mut allowed = 0;
        if broker
            .authorize_publish(user, &topic("qual/allowed"))
            .await
            .is_ok()
        {
            allowed += 1;
        }
        assert_eq!(
            allowed, 1,
            "allowed mysql topic must be permitted exactly once"
        );
        let mut denied = 0;
        if broker
            .authorize_publish(user, &topic("qual/denied"))
            .await
            .is_err()
        {
            denied += 1;
        }
        assert_eq!(denied, 1, "denied mysql topic must be refused exactly once");

        // Outage fails closed (closed port simulates the stopped server;
        // only the primary stops via the fault file).
        let closed = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("ephemeral port");
            let addr = listener.local_addr().expect("local addr").to_string();
            drop(listener);
            addr
        };
        let s = short_settings();
        let down = DbAuthSet::new(&DbAuthSetConfig {
            postgres_url: String::new(),
            mysql_url: format!("mysql://qual:qualpass1@{closed}/qual"),
            redis_url: String::new(),
            mongodb_url: String::new(),
            pool_size: s.pool_size,
            connect_timeout_ms: s.connect_timeout_ms,
            read_timeout_ms: s.read_timeout_ms,
            cache_max_entries: s.cache_max_entries,
            cache_ttl_secs: s.cache_ttl_secs,
        });
        assert!(
            down.authenticate("qual-down", Some(user), Some(b"qual-pass-1"))
                .await
                .is_err(),
            "stopped mysql must refuse CONNECT"
        );
        assert!(
            down.authorize_publish(user, &topic("qual/allowed"))
                .await
                .is_err(),
            "stopped mysql must refuse publish"
        );
    }

    #[tokio::test]
    #[ignore]
    async fn test_qualify_redis_auth_and_acl() {
        let url = require_env("DBAUTH_REDIS_URL");
        let seed = RedisAuth::new(RedisAuthConfig {
            url: url.clone(),
            settings: qual_settings(),
        });
        let user = "qual_redis_user";
        seed.upsert_user(user, b"qual-pass-1")
            .await
            .unwrap_or_else(|e| panic!("redis seed user failed: {e}"));
        seed.replace_acls(
            user,
            &[("qual/allowed".to_string(), "publish".to_string(), true)],
        )
        .await
        .unwrap_or_else(|e| panic!("redis seed ACL failed: {e}"));
        // Assertions go through DbAuthSet, the broker's CONNECT/publish type.
        let broker = DbAuthSet::new(&qual_set_config(
            String::new(),
            String::new(),
            url,
            String::new(),
        ));

        assert!(
            broker
                .authenticate("qual-conn-1", Some(user), Some(b"qual-pass-1"))
                .await
                .is_ok(),
            "seeded redis password must be accepted"
        );
        assert!(
            broker
                .authenticate("qual-conn-2", Some(user), Some(b"wrong"))
                .await
                .is_err(),
            "wrong redis password must be refused"
        );
        assert!(
            broker
                .authenticate("qual-conn-3", Some("no-such"), Some(b"x"))
                .await
                .is_err(),
            "unknown redis user must be refused"
        );
        let mut allowed = 0;
        if broker
            .authorize_publish(user, &topic("qual/allowed"))
            .await
            .is_ok()
        {
            allowed += 1;
        }
        assert_eq!(
            allowed, 1,
            "allowed redis topic must be permitted exactly once"
        );
        let mut denied = 0;
        if broker
            .authorize_publish(user, &topic("qual/denied"))
            .await
            .is_err()
        {
            denied += 1;
        }
        assert_eq!(denied, 1, "denied redis topic must be refused exactly once");

        let closed = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("ephemeral port");
            let addr = listener.local_addr().expect("local addr").to_string();
            drop(listener);
            addr
        };
        let s = short_settings();
        let down = DbAuthSet::new(&DbAuthSetConfig {
            postgres_url: String::new(),
            mysql_url: String::new(),
            redis_url: format!("redis://:qualpass1@{closed}/0"),
            mongodb_url: String::new(),
            pool_size: s.pool_size,
            connect_timeout_ms: s.connect_timeout_ms,
            read_timeout_ms: s.read_timeout_ms,
            cache_max_entries: s.cache_max_entries,
            cache_ttl_secs: s.cache_ttl_secs,
        });
        assert!(
            down.authenticate("qual-down", Some(user), Some(b"qual-pass-1"))
                .await
                .is_err(),
            "stopped redis must refuse CONNECT"
        );
        assert!(
            down.authorize_publish(user, &topic("qual/allowed"))
                .await
                .is_err(),
            "stopped redis must refuse publish"
        );
        seed.remove_user(user).await.ok();
    }

    #[tokio::test]
    #[ignore]
    async fn test_qualify_mongodb_auth_and_acl() {
        let url = require_env("DBAUTH_MONGODB_URL");
        let seed = MongoAuth::new(MongoAuthConfig {
            url: url.clone(),
            settings: qual_settings(),
        });
        let user = "qual_mongo_user";
        seed.upsert_user(user, b"qual-pass-1")
            .await
            .unwrap_or_else(|e| panic!("mongodb seed user failed: {e}"));
        seed.replace_acls(
            user,
            &[("qual/allowed".to_string(), "publish".to_string(), true)],
        )
        .await
        .unwrap_or_else(|e| panic!("mongodb seed ACL failed: {e}"));
        // Assertions go through DbAuthSet, the broker's CONNECT/publish type.
        let broker = DbAuthSet::new(&qual_set_config(
            String::new(),
            String::new(),
            String::new(),
            url,
        ));

        assert!(
            broker
                .authenticate("qual-conn-1", Some(user), Some(b"qual-pass-1"))
                .await
                .is_ok(),
            "seeded mongodb password must be accepted"
        );
        assert!(
            broker
                .authenticate("qual-conn-2", Some(user), Some(b"wrong"))
                .await
                .is_err(),
            "wrong mongodb password must be refused"
        );
        assert!(
            broker
                .authenticate("qual-conn-3", Some("no-such"), Some(b"x"))
                .await
                .is_err(),
            "unknown mongodb user must be refused"
        );
        let mut allowed = 0;
        if broker
            .authorize_publish(user, &topic("qual/allowed"))
            .await
            .is_ok()
        {
            allowed += 1;
        }
        assert_eq!(
            allowed, 1,
            "allowed mongodb topic must be permitted exactly once"
        );
        let mut denied = 0;
        if broker
            .authorize_publish(user, &topic("qual/denied"))
            .await
            .is_err()
        {
            denied += 1;
        }
        assert_eq!(
            denied, 1,
            "denied mongodb topic must be refused exactly once"
        );

        let closed = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("ephemeral port");
            let addr = listener.local_addr().expect("local addr").to_string();
            drop(listener);
            addr
        };
        let s = short_settings();
        let down = DbAuthSet::new(&DbAuthSetConfig {
            postgres_url: String::new(),
            mysql_url: String::new(),
            redis_url: String::new(),
            mongodb_url: format!("mongodb://qual:qualpass1@{closed}/qual?authSource=admin"),
            pool_size: s.pool_size,
            connect_timeout_ms: s.connect_timeout_ms,
            read_timeout_ms: s.read_timeout_ms,
            cache_max_entries: s.cache_max_entries,
            cache_ttl_secs: s.cache_ttl_secs,
        });
        assert!(
            down.authenticate("qual-down", Some(user), Some(b"qual-pass-1"))
                .await
                .is_err(),
            "stopped mongodb must refuse CONNECT"
        );
        assert!(
            down.authorize_publish(user, &topic("qual/allowed"))
                .await
                .is_err(),
            "stopped mongodb must refuse publish"
        );
    }
}
