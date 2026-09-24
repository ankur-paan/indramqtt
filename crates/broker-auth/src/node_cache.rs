//! Node-level authentication cache behind the management API.
//!
//! Covers the state behind `GET /authentication/node_cache/status` (read)
//! and `POST /authentication/node_cache/reset` (evict). Single-node,
//! management-plane only: entries are recorded on the CONNECT path (one
//! short lock per successful credentialed CONNECT) and read or cleared
//! from the management plane; publish and deliver never touch this store.
//!
//! Store bounds (both stated here and enforced below):
//! - at most [`broker_config::DEFAULT_AUTHN_NODE_CACHE_MAX`] entries
//!   (10 000: the status snapshot clones at most the capped small entries
//!   under one short lock, so the cache must stay small and bounded;
//!   10 000 distinct users cover ordinary nodes with headroom while
//!   keeping per-request clones cheap);
//! - one entry per username (the last successful credentialed CONNECT for
//!   that name), LRU-evicted oldest-first past the cap, so one client
//!   cannot grow the map without limit;
//! - reads clone at most the capped entries once per request under a
//!   short lock; the CONNECT hook takes one short lock per credentialed
//!   success and never the management write path beyond that.
//!
//! Only the built-in database populates this cache in the parity waves;
//! every other backend's decisions are never claimed as cached. Cache
//! contents are memory-only and do not survive a restart; the enabled
//! flag and the cap persist via the config registry
//! ([`broker_config::AuthnNodeCacheConf`]).
// TODO(parity): which status fields plus reset shape does the spec require
// (enabled/size/bounds versus nested metrics, 204 versus 200)? The
// rulebook does not decide the exact shape; the current choice reports
// the honest enabled/size/bounds the broker can supply and omits rate
// counters the broker does not track.

use broker_config::{AuthnNodeCacheConf, ConfigRegistry, DEFAULT_AUTHN_NODE_CACHE_MAX};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

/// Node authentication cache: bounded per-username record of successful
/// credentialed CONNECTs plus the persisted enabled flag and entry cap.
pub struct NodeAuthCache {
    inner: parking_lot::RwLock<CacheInner>,
    enabled: parking_lot::RwLock<bool>,
    max_count: parking_lot::RwLock<usize>,
}

#[derive(Debug, Default)]
struct CacheInner {
    entries: HashMap<String, u64>,
    order: VecDeque<String>,
}

impl NodeAuthCache {
    /// Empty cache with the default config (enabled, 10 000 entries).
    /// Memory-only: mutations are not persisted.
    pub fn new() -> Self {
        Self::from_conf(&AuthnNodeCacheConf::default())
    }

    /// Empty cache seeded from a validated config root. Memory-only.
    pub fn from_conf(conf: &AuthnNodeCacheConf) -> Self {
        Self {
            inner: parking_lot::RwLock::new(CacheInner::default()),
            enabled: parking_lot::RwLock::new(conf.enabled),
            max_count: parking_lot::RwLock::new(
                conf.max_count
                    .clamp(1, broker_config::MAX_AUTHN_NODE_CACHE_MAX),
            ),
        }
    }

    /// Seed the enabled flag and cap from a validated snapshot root.
    /// Memory-only: cached entries are never loaded from disk.
    pub fn from_snapshot(conf: &AuthnNodeCacheConf) -> Self {
        Self::from_conf(conf)
    }

    /// Seed the enabled flag and cap from the registry's current
    /// snapshot. Kernel boot path; cached entries always start empty
    /// (memory-only, never loaded from disk).
    pub fn from_registry(registry: &Arc<ConfigRegistry>) -> Self {
        Self::from_snapshot(&registry.snapshot().authn_node_cache)
    }

    /// Attach the registry snapshot's enabled flag and cap, in place on
    /// the same instance. Cached entries are left alone (they are
    /// memory-only either way).
    pub fn seed_from_registry(&self, registry: &Arc<ConfigRegistry>) {
        let conf = registry.snapshot().authn_node_cache.clone();
        *self.enabled.write() = conf.enabled;
        *self.max_count.write() = conf
            .max_count
            .clamp(1, broker_config::MAX_AUTHN_NODE_CACHE_MAX);
    }

    /// Whether successful CONNECTs are recorded.
    pub fn is_enabled(&self) -> bool {
        *self.enabled.read()
    }

    /// Current entry cap.
    pub fn max_count(&self) -> usize {
        *self.max_count.read()
    }

    /// Number of cached usernames.
    pub fn len(&self) -> usize {
        self.inner.read().entries.len()
    }

    /// Whether the cache holds no entries.
    pub fn is_empty(&self) -> bool {
        self.inner.read().entries.is_empty()
    }

    /// Record one successful credentialed CONNECT for `username`.
    ///
    /// CONNECT-only: one short lock per credentialed success. Anonymous
    /// CONNECTs (no username) are never recorded. When disabled the call
    /// is a no-op. Past the cap the oldest username is evicted first
    /// (LRU by last success), so the map stays bounded. Publish and
    /// deliver never call this.
    pub fn record_success(&self, username: &str) {
        if username.is_empty() || !self.is_enabled() {
            return;
        }
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let cap = self.max_count();
        let mut inner = self.inner.write();
        if inner.entries.contains_key(username) {
            inner.entries.insert(username.to_string(), now_ms);
            if let Some(pos) = inner.order.iter().position(|name| name == username) {
                inner.order.remove(pos);
            }
            inner.order.push_back(username.to_string());
            return;
        }
        while inner.entries.len() >= cap {
            match inner.order.pop_front() {
                Some(oldest) => {
                    inner.entries.remove(&oldest);
                }
                None => break,
            }
        }
        inner.entries.insert(username.to_string(), now_ms);
        inner.order.push_back(username.to_string());
    }

    /// Apply the settings subscriber's node-cache half (enabled flag and
    /// entry cap) in place. Called after every validated settings
    /// replace and once at boot so management writes are visible to the
    /// CONNECT recorder without a restart. Cached entries are left alone
    /// (only the flag and cap move). Management-plane only; the CONNECT
    /// path keeps taking one short lock per success and publish/deliver
    /// never touch this store.
    pub fn apply_settings(&self, enable: bool, max_count: usize) {
        *self.enabled.write() = enable;
        *self.max_count.write() = max_count.clamp(1, broker_config::MAX_AUTHN_NODE_CACHE_MAX);
    }

    /// Evict every cached entry. Evicting an already-empty cache still
    /// succeeds. Management-plane only: one short write lock; the
    /// CONNECT path never blocks on it beyond that lock, and publish
    /// and deliver never touch it.
    pub fn reset(&self) {
        let mut inner = self.inner.write();
        inner.entries.clear();
        inner.order.clear();
    }

    /// Default entry cap stated next to the bound above.
    pub fn default_max() -> usize {
        DEFAULT_AUTHN_NODE_CACHE_MAX
    }
}

impl Default for NodeAuthCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_cache_reports_zero_and_default_cap() {
        let cache = NodeAuthCache::new();
        assert!(cache.is_enabled());
        assert_eq!(cache.max_count(), DEFAULT_AUTHN_NODE_CACHE_MAX);
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn record_and_reset_round_trip() {
        let cache = NodeAuthCache::new();
        cache.record_success("alice");
        cache.record_success("bob");
        assert_eq!(cache.len(), 2);
        cache.reset();
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
        // Resetting an already-empty cache still succeeds.
        cache.reset();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn anonymous_and_empty_names_are_never_recorded() {
        let cache = NodeAuthCache::new();
        cache.record_success("");
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn reauthentication_keeps_one_entry_per_username() {
        let cache = NodeAuthCache::new();
        cache.record_success("alice");
        cache.record_success("alice");
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn entries_evict_oldest_first_past_a_small_cap() {
        let conf = AuthnNodeCacheConf {
            enabled: true,
            max_count: 2,
        };
        let cache = NodeAuthCache::from_conf(&conf);
        cache.record_success("alice");
        cache.record_success("bob");
        cache.record_success("carol");
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn disabled_cache_records_nothing() {
        let conf = AuthnNodeCacheConf {
            enabled: false,
            max_count: DEFAULT_AUTHN_NODE_CACHE_MAX,
        };
        let cache = NodeAuthCache::from_conf(&conf);
        cache.record_success("alice");
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn config_survives_registry_reload_while_entries_do_not() {
        let dir = std::env::temp_dir().join(format!(
            "authn-node-cache-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let registry = Arc::new(ConfigRegistry::load(&dir).expect("fresh data dir loads"));
        let cache = NodeAuthCache::from_registry(&registry);
        cache.record_success("alice");
        assert_eq!(cache.len(), 1);
        // Rebuild from the same data dir (simulating a kernel restart):
        // the enabled flag and cap persist, cached entries do not.
        let reloaded = Arc::new(ConfigRegistry::load(&dir).expect("data dir reloads"));
        let restarted = NodeAuthCache::from_registry(&reloaded);
        assert!(restarted.is_enabled());
        assert_eq!(restarted.max_count(), DEFAULT_AUTHN_NODE_CACHE_MAX);
        assert_eq!(restarted.len(), 0);
        std::fs::remove_dir_all(&dir).ok();
    }
}
