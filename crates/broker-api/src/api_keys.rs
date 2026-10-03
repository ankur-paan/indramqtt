//! Operator API-key store: the minimum backing store that lets `indra ctl`
//! authenticate against the management API.
//!
//! The full key lifecycle (list, mint-with-single-secret-return, revoke,
//! scopes, hashing at rest, persistence) belongs to the access wave, not
//! here. This module only holds the set of currently valid opaque key
//! strings so `Authorization: Bearer <api-key>` resolves in
//! [`crate::api_auth::resolve_credentials`]; dashboard tokens keep working
//! exactly as before and Basic API-key credentials still resolve to
//! nothing (fail closed).
//!
//! Store bounds (stated here and enforced below):
//! - at most [`MAX_API_KEYS`] (1024) keys; inserts past the cap are
//!   rejected, never evicted silently. Reason: an operator-managed set is
//!   tiny (a handful of automation keys); 1024 fits every plausible
//!   deployment while keeping the per-request scan constant-time bounded.
//! - the default store is empty: with no keys configured every Bearer
//!   API-key check fails closed and only dashboard tokens authenticate.
//! - per-request work is one short lock plus a scan of at most 1024
//!   constant-time comparisons. Management-plane only: nothing here runs
//!   on the per-message path, so fan-out and fan-in take no new lock and
//!   no new allocation.
//!
//! Key material arrives from the `INDRA_API_KEYS` environment variable
//! (comma-separated, read once per [`ApiKeyStore::from_env`]) or from
//! [`ApiKeyStore::insert`] (tests and future management writes). The
//! plaintext lives in memory exactly like dashboard tokens in
//! [`crate::v5::auth::ApiTokens`]; hashing at rest and persistence arrive
//! with the access wave.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::admin_users::AdminRole;
use crate::v5::auth::TokenInfo;

/// Upper bound on stored operator API keys. Inserts past the cap fail;
/// nothing is evicted to make room.
pub const MAX_API_KEYS: usize = 1024;

/// The minimum length of an operator API key.
///
/// Each key gives administrator access. A key that an attacker can
/// guess gives full control of the broker. A random key of 16
/// characters is too long to guess through the network. The store
/// refuses a shorter key. It does not change the key.
pub const MIN_API_KEY_LEN: usize = 16;

/// Environment variable seeding the store at boot. Comma-separated opaque
/// key strings; blank entries are ignored so a trailing comma is harmless.
pub const API_KEYS_ENV: &str = "INDRA_API_KEYS";

/// Per-request identity lifetime for a resolved API key: one hour from
/// resolution. The key itself does not expire; every request re-resolves,
/// so this only has to outlive the request it authenticates.
/// Reason: matches the dashboard token lifetime the middleware already
/// enforces, so both credential kinds share one freshness expectation.
const API_KEY_IDENTITY_TTL: Duration = Duration::from_secs(60 * 60);

/// Label stamped as the username of an API-key identity. The minimum
/// store keeps opaque keys without names; the access wave replaces this
/// with the per-key name it mints.
// TODO(parity): what identity (username/role/scopes) should an API key
// carry once named keys with scopes exist? Today every key resolves as an
// administrator because the operator CLI needs read plus kick/publish, and
// scoping that down belongs to the access wave.
const API_KEY_USERNAME: &str = "api-key";

/// Bounded set of valid operator API keys (opaque strings).
#[derive(Debug, Default)]
pub struct ApiKeyStore {
    keys: Mutex<HashMap<String, ()>>,
}

impl ApiKeyStore {
    /// Empty store: every API-key check fails closed.
    pub fn new() -> Self {
        Self {
            keys: Mutex::new(HashMap::new()),
        }
    }

    /// Store seeded once from [`API_KEYS_ENV`]. Blank entries are
    /// ignored; past [`MAX_API_KEYS`] entries the remainder is dropped so
    /// boot never fails on an oversized variable (the cap is still
    /// enforced on later inserts).
    pub fn from_env() -> Self {
        let store = Self::new();
        let raw = std::env::var(API_KEYS_ENV).unwrap_or_default();
        let mut too_short = 0usize;
        for key in raw.split(',').map(str::trim).filter(|k| !k.is_empty()) {
            if key.len() < MIN_API_KEY_LEN {
                too_short += 1;
                continue;
            }
            if store.keys.lock().unwrap().len() >= MAX_API_KEYS {
                break;
            }
            store.keys.lock().unwrap().insert(key.to_string(), ());
        }
        if too_short > 0 {
            // The log shows the count only. A key is a credential.
            tracing::warn!(
                ignored = too_short,
                minimum_length = MIN_API_KEY_LEN,
                "ignored operator API keys shorter than the minimum length"
            );
        }
        store
    }

    /// Insert one key. Fails when the store already holds
    /// [`MAX_API_KEYS`] keys. The store also refuses an empty key and a
    /// key that is shorter than [`MIN_API_KEY_LEN`].
    pub fn insert(&self, key: &str) -> Result<(), String> {
        if key.is_empty() {
            return Err("api key must not be empty".to_string());
        }
        if key.len() < MIN_API_KEY_LEN {
            return Err(format!(
                "api key must be at least {MIN_API_KEY_LEN} characters"
            ));
        }
        let mut keys = self.keys.lock().unwrap();
        if keys.len() >= MAX_API_KEYS && !keys.contains_key(key) {
            return Err(format!("api key store is full ({MAX_API_KEYS} keys)"));
        }
        keys.insert(key.to_string(), ());
        Ok(())
    }

    /// Number of stored keys (management introspection only).
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.keys.lock().unwrap().len()
    }

    /// Whether the store holds no keys (management introspection only).
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.keys.lock().unwrap().is_empty()
    }

    /// Resolve one presented Bearer key to an operator identity, or `None`
    /// when the key is unknown. Comparison is constant-time per candidate
    /// so validity cannot be probed byte-by-byte through timing.
    pub fn resolve(&self, presented: &str) -> Option<TokenInfo> {
        if presented.is_empty() {
            return None;
        }
        let keys = self.keys.lock().unwrap();
        let mut matched = false;
        for stored in keys.keys() {
            if secure_eq(stored.as_bytes(), presented.as_bytes()) {
                matched = true;
            }
        }
        if !matched {
            return None;
        }
        Some(TokenInfo {
            username: API_KEY_USERNAME.to_string(),
            role: AdminRole::Administrator,
            expires_at: Instant::now() + API_KEY_IDENTITY_TTL,
            must_change_password: false,
        })
    }
}

/// Constant-time equality for two byte strings: always compares every
/// byte of the longer length, so the duration leaks nothing about where
/// (or whether) the inputs differ.
fn secure_eq(a: &[u8], b: &[u8]) -> bool {
    let len = a.len().max(b.len());
    let mut diff = a.len() ^ b.len();
    for i in 0..len {
        let x = *a.get(i).unwrap_or(&0);
        let y = *b.get(i).unwrap_or(&0);
        diff |= (x ^ y) as usize;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_store_resolves_nothing() {
        let store = ApiKeyStore::new();
        assert!(store.resolve("anything").is_none());
        assert!(store.resolve("").is_none());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn inserted_key_resolves_as_operator_without_password_gate() {
        let store = ApiKeyStore::new();
        store.insert("operator-key-0001").expect("insert");
        let info = store.resolve("operator-key-0001").expect("resolves");
        assert_eq!(info.username, API_KEY_USERNAME);
        assert_eq!(info.role, AdminRole::Administrator);
        assert!(!info.must_change_password);
        assert!(info.expires_at > Instant::now());
        // Wrong keys still fail closed.
        assert!(store.resolve("operator-key-0002").is_none());
        assert!(store.resolve("").is_none());
        assert!(store.resolve("operator-key-000").is_none());
    }

    #[test]
    fn empty_key_is_rejected() {
        let store = ApiKeyStore::new();
        assert!(store.insert("").is_err());
        // The store refuses a key that is one character too short.
        assert!(store.insert(&"k".repeat(MIN_API_KEY_LEN - 1)).is_err());
        assert!(store.insert(&"k".repeat(MIN_API_KEY_LEN)).is_ok());
        assert_eq!(store.len(), 1);
        let store = ApiKeyStore::new();
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn store_is_bounded_and_rejects_past_the_cap() {
        let store = ApiKeyStore::new();
        for i in 0..MAX_API_KEYS {
            store.insert(&format!("operator-key-{i:06}")).expect("insert under cap");
        }
        assert_eq!(store.len(), MAX_API_KEYS);
        assert!(store.insert("operator-key-one-too-many").is_err());
        // Re-inserting an existing key at the cap still succeeds (no growth).
        assert!(store.insert("operator-key-000000").is_ok());
        assert_eq!(store.len(), MAX_API_KEYS);
    }

    #[test]
    fn secure_eq_compares_without_short_circuit() {
        assert!(secure_eq(b"abc", b"abc"));
        assert!(!secure_eq(b"abc", b"abd"));
        assert!(!secure_eq(b"abc", b"ab"));
        assert!(!secure_eq(b"ab", b"abc"));
        assert!(!secure_eq(b"", b"abc"));
        assert!(secure_eq(b"", b""));
    }
}
