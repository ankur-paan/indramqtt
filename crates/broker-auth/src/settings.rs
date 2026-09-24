//! Global authentication settings behind the management API.
//!
//! Covers the state behind `GET /authentication/settings` (read) and
//! `PUT /authentication/settings` (validated full replace) over the real
//! [`broker_config::AuthnSettingsConf`]. Single-node, management-plane
//! only: handlers clone one small snapshot per request; the CONNECT path
//! loads one lock-free snapshot per connect to observe the
//! backend-failure flag (`crates/broker-node/src/main.rs`, CONNECT
//! handling, and the console CONNECT in `crates/broker-api/src/ws.rs`)
//! and never takes a management lock; publish and deliver never touch
//! this store.
//!
//! Store bounds (both stated here and enforced below):
//! - exactly one small validated struct (flag, cache half, refresh
//!   interval); reads clone it per request and never grow with
//!   connections, sessions or subscriptions;
//! - the node-cache entry cap inside it stays finite
//!   (1..=[`broker_config::MAX_AUTHN_NODE_CACHE_MAX`]); `0` (unlimited)
//!   is rejected instead of growing without limit;
//! - writes go validate-all-before-apply through the config registry
//!   (commit then atomic save); a failed validation or persist applies
//!   nothing new beyond the already-swapped snapshot rule below.
//!
//! Only the built-in database executes in the parity waves; the
//! `ignore_backend_failures` flag is observed on CONNECT but the broker
//! stays fail-closed (an outage denies access and logs) until the checker
//! pins the intended behaviour.
// TODO(parity): which PUT success shape does the spec require (204 versus
// 200)? The rulebook does not decide the exact shape; the current choice
// answers PUT with 204 and reports the honest subset the broker can
// supply, omitting rate counters the broker does not track.

use broker_config::{AuthnSettingsConf, ConfigRegistry};
use std::sync::Arc;

/// Subscriber hook run after a validated settings replace: lets owners
/// propagate the cache half without taking a settings lock on their own
/// path (the node cache applies the enabled flag and cap in place).
pub type SettingsSubscriber = Arc<dyn Fn(&AuthnSettingsConf) + Send + Sync>;

/// Why [`AuthnSettingsStore::replace`] refused an update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingsUpdateError {
    /// The candidate failed validation (message names the field).
    Invalid(String),
    /// The registry commit or atomic save failed after validation.
    Persist(String),
}

/// Global authentication settings: one validated struct with a lock-free
/// read snapshot for the CONNECT path plus registry persistence.
///
/// Management writes validate the candidate before swapping it into view;
/// the CONNECT hook loads the snapshot without taking a write lock and
/// never blocks on a management write beyond one `Arc` swap. Publish and
/// deliver never touch either.
pub struct AuthnSettingsStore {
    current: arc_swap::ArcSwap<AuthnSettingsConf>,
    registry: parking_lot::RwLock<Option<Arc<ConfigRegistry>>>,
    save_lock: parking_lot::Mutex<()>,
    subscriber: parking_lot::RwLock<Option<SettingsSubscriber>>,
}

impl AuthnSettingsStore {
    /// Default settings with no persistence hook.
    pub fn new() -> Self {
        Self {
            current: arc_swap::ArcSwap::from(Arc::new(AuthnSettingsConf::default())),
            registry: parking_lot::RwLock::new(None),
            save_lock: parking_lot::Mutex::new(()),
            subscriber: parking_lot::RwLock::new(None),
        }
    }

    /// Seed from a validated config root. Memory-only.
    pub fn from_conf(conf: &AuthnSettingsConf) -> Self {
        let store = Self::new();
        store.current.store(Arc::new(conf.clone()));
        store
    }

    /// Seed from the registry's current snapshot and persist every later
    /// mutation back through it. Kernel boot path; defaults yield today's
    /// behaviour (fail closed on backend outage, cache enabled).
    pub fn from_registry(registry: &Arc<ConfigRegistry>) -> Self {
        let store = Self::from_conf(&registry.snapshot().authn_settings);
        *store.registry.write() = Some(Arc::clone(registry));
        store
    }

    /// Attach the registry and replace the current contents with its
    /// snapshot, in place on the same instance. Cached decisions are
    /// unaffected (they live in the node cache, not here).
    pub fn seed_from_registry(&self, registry: &Arc<ConfigRegistry>) {
        self.current
            .store(Arc::new(registry.snapshot().authn_settings.clone()));
        *self.registry.write() = Some(Arc::clone(registry));
    }

    /// Install the subscriber callback run after every validated replace
    /// (the node-cache applier). One subscriber only; installing again
    /// replaces the previous one.
    pub fn set_subscriber(&self, hook: SettingsSubscriber) {
        *self.subscriber.write() = Some(hook);
    }

    /// Lock-free snapshot for readers and the CONNECT path: one `Arc`
    /// load, no write lock. Publish and deliver never call this.
    pub fn snapshot(&self) -> Arc<AuthnSettingsConf> {
        self.current.load_full()
    }

    /// Snapshot clone of the current settings.
    pub fn get(&self) -> AuthnSettingsConf {
        (*self.current.load_full()).clone()
    }

    /// Whether a backend outage is ignored (fail-open) or denies access
    /// (fail-closed, the default). Consulted by the broker on CONNECT
    /// only.
    pub fn ignore_backend_failures(&self) -> bool {
        self.current.load().ignore_backend_failures
    }

    /// Replace the stored settings with a full-replacement candidate.
    ///
    /// Validate-all-before-apply: the candidate is validated before it
    /// can become visible, so invalid state is never observable. On
    /// success the snapshot, the persisted registry and the subscriber
    /// all move together; the in-memory swap precedes the atomic save
    /// (mirroring the chain store), so a save failure surfaces as
    /// [`SettingsUpdateError::Persist`] while the validated value stays.
    /// Management-plane only: one short swap per request; the CONNECT
    /// path keeps reading the lock-free snapshot and publish/deliver
    /// never touch this store.
    pub fn replace(
        &self,
        next: AuthnSettingsConf,
    ) -> Result<AuthnSettingsConf, SettingsUpdateError> {
        next.validate()
            .map_err(|e| SettingsUpdateError::Invalid(e.to_string()))?;
        let _guard = self.save_lock.lock();
        self.current.store(Arc::new(next.clone()));
        if let Some(registry) = self.registry.read().clone() {
            registry
                .commit_authn_settings(next.clone())
                .map_err(|e| SettingsUpdateError::Persist(e.to_string()))?;
            registry
                .save()
                .map_err(|e| SettingsUpdateError::Persist(e.to_string()))?;
        }
        if let Some(hook) = self.subscriber.read().clone() {
            hook(&next);
        }
        Ok(next)
    }

    /// Number of bytes in the largest accepted settings document (8 KiB).
    /// Reason: settings ride the per-connect snapshot clone, so one write
    /// cannot balloon memory; larger documents are rejected instead of
    /// growing without limit.
    pub fn max_body_len() -> usize {
        8192
    }
}

impl Default for AuthnSettingsStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_documented_struct() {
        let store = AuthnSettingsStore::new();
        let got = store.get();
        assert!(!got.ignore_backend_failures);
        assert!(got.node_cache.enable);
        assert_eq!(got.node_cache.cache_ttl, "1m");
        assert_eq!(got.node_cache.cleanup_interval, "1m");
        assert_eq!(got.node_cache.stat_update_interval, "5s");
        assert_eq!(
            got.node_cache.max_count,
            broker_config::DEFAULT_AUTHN_NODE_CACHE_MAX
        );
        assert_eq!(got.node_cache.max_memory, "100MB");
        assert_eq!(got.builtin_record_count_refresh_interval, "1h");
        assert!(!store.ignore_backend_failures());
    }

    #[test]
    fn invalid_candidate_is_rejected_without_applying() {
        let store = AuthnSettingsStore::new();
        let before = store.get();
        let mut bad = before.clone();
        bad.node_cache.max_count = 0;
        assert!(matches!(
            store.replace(bad),
            Err(SettingsUpdateError::Invalid(_))
        ));
        assert_eq!(store.get(), before);
        let mut bad_ttl = before.clone();
        bad_ttl.node_cache.cache_ttl = "soon".to_string();
        assert!(matches!(
            store.replace(bad_ttl),
            Err(SettingsUpdateError::Invalid(_))
        ));
        assert_eq!(store.get(), before);
    }

    #[test]
    fn replace_moves_snapshot_and_notifies_subscriber() {
        let store = AuthnSettingsStore::new();
        let seen = Arc::new(parking_lot::Mutex::new(false));
        let seen_clone = Arc::clone(&seen);
        store.set_subscriber(Arc::new(move |next: &AuthnSettingsConf| {
            *seen_clone.lock() = next.ignore_backend_failures;
        }));
        let mut next = store.get();
        next.ignore_backend_failures = true;
        store.replace(next.clone()).expect("valid replace");
        assert_eq!(store.get(), next);
        assert!(*seen.lock());
        assert!(store.ignore_backend_failures());
    }

    #[test]
    fn settings_survive_registry_reload() {
        let dir = std::env::temp_dir().join(format!(
            "authn-settings-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let registry = Arc::new(ConfigRegistry::load(&dir).expect("fresh data dir loads"));
        let store = AuthnSettingsStore::from_registry(&registry);
        let mut next = store.get();
        next.ignore_backend_failures = true;
        next.builtin_record_count_refresh_interval = "30m".to_string();
        store.replace(next.clone()).expect("persist settings");
        assert!(dir.join(broker_config::STATE_FILE_NAME).is_file());
        let reloaded = Arc::new(ConfigRegistry::load(&dir).expect("data dir reloads"));
        let restarted = AuthnSettingsStore::from_registry(&reloaded);
        assert_eq!(restarted.get(), next);
        std::fs::remove_dir_all(&dir).ok();
    }
}
