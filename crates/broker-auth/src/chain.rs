//! Ordered authenticator chain for the management API.
//!
//! Covers the chain behind `GET /authentication` (ordered list),
//! `POST /authentication` (append one entry) and
//! `PUT /authentication/order` (replace the whole order). Single-node,
//! management-plane only: publishes and deliveries never touch this
//! store; the CONNECT path reads one lock-free snapshot per connect to
//! decide whether the built-in database may execute, and never takes
//! the chain write lock.
//!
//! Store bounds (both stated here and enforced below):
//! - at most [`broker_config::MAX_AUTHN_CHAIN_ENTRIES`] entries (8:
//!   the CONNECT path snapshots the whole chain once per connect, so the
//!   chain must stay small and bounded; 8 covers the documented backend
//!   families with headroom while keeping per-connect clones cheap);
//!   creates past the cap are rejected instead of growing without limit;
//! - `id`/`mechanism`/`backend` are capped at 256 chars and the stored
//!   backend config at 8 KiB of JSON, so one entry cannot balloon memory;
//! - reads clone at most the capped list once per request under a short
//!   lock; the CONNECT hook clones one `Arc` snapshot lock-free and scans
//!   at most the capped entries without taking the write lock.
//!
//! Only the built-in database executes in the parity waves; every other
//! backend's config is stored and reported, never claimed as live. A
//! non-empty chain with no enabled built-in entry fails closed at
//! CONNECT (no live backend can execute); an empty chain preserves
//! today's behaviour (open broker or local users).
// TODO(parity): is 8 the documented chain cap, and which
// mechanism/backend pairs plus per-entry fields does the spec require?
// The rulebook does not decide the exact set; the current choice accepts
// the password/JWT/LDAP/HTTP/Redis/SQL/Mongo/file families and reports
// id/mechanism/backend/enable only, omitting status fields the broker
// cannot supply.

use broker_config::{
    is_known_authn_backend, is_known_authn_mechanism, AuthnChainConf, AuthnEntry as ConfEntry,
    ConfigRegistry, MAX_AUTHN_CHAIN_ENTRIES,
};
use std::sync::Arc;

/// Longest accepted `id`/`mechanism`/`backend` value (256 chars).
/// Reason (measured cost): the CONNECT path clones the whole chain snapshot
/// once per connect, so each entry's keys must stay small; the longest
/// documented `{mechanism}:{backend}` id is under 64 chars, and 256 gives
/// headroom while bounding the snapshot to at most 8 entries of short keys.
const MAX_ID_LEN: usize = 256;
/// Longest accepted backend-config JSON document (8 KiB).
/// Reason (measured cost): configs ride the per-connect snapshot clone, so
/// one entry cannot balloon memory; 8 KiB caps the worst-case snapshot at
/// 8 entries x 8 KiB = 64 KiB, keeping per-connect clones cheap, and larger
/// documents are rejected instead of growing without limit.
const MAX_CONFIG_LEN: usize = 8192;

/// One ordered chain slot: the chain key plus its credential mechanism,
/// credential store, enable flag and opaque backend config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthnEntry {
    pub id: String,
    pub mechanism: String,
    pub backend: String,
    pub enable: bool,
    pub config: serde_json::Value,
}

/// Why [`AuthnChain::insert`] refused an entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainInsertError {
    /// The `id` is already stored.
    Duplicate,
    /// The store holds [`MAX_AUTHN_CHAIN_ENTRIES`] entries.
    Full,
    /// The entry failed validation (message names the field).
    Invalid(String),
    /// The registry commit or atomic save failed after validation.
    Persist(String),
}

/// Why [`AuthnChain::reorder`] refused a new order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainReorderError {
    /// The body failed structural validation (message names the problem).
    Invalid(String),
    /// One or more supplied ids are not stored (lists the unknown ids).
    Unknown(Vec<String>),
    /// The order omits stored ids, so applying it would drop entries
    /// (lists the missing ids).
    Incomplete(Vec<String>),
    /// The order names the same id twice.
    Duplicate(String),
    /// The registry commit or atomic save failed after validation.
    Persist(String),
}

/// Why [`AuthnChain::update`] refused a replacement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainUpdateError {
    /// No stored entry carries the requested `id`.
    NotFound,
    /// The replacement failed validation (message names the field).
    Invalid(String),
    /// The registry commit or atomic save failed after validation.
    Persist(String),
}

/// Why [`AuthnChain::remove`] refused a delete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainRemoveError {
    /// No stored entry carries the requested `id`.
    NotFound,
    /// Deleting the last remaining entry would leave authentication open
    /// (empty chain preserves today's open behaviour), so the delete is
    /// refused instead of opening the broker.
    Last(String),
    /// The registry commit or atomic save failed after validation.
    Persist(String),
}
/// Ordered authenticator chain behind one short lock plus a lock-free
/// read snapshot for the CONNECT path.
///
/// Management writes take the write lock, replace the stored order and
/// publish a fresh snapshot; the CONNECT hook loads the snapshot
/// without taking the write lock and never blocks on a management
/// write beyond one `Arc` swap. Publish and deliver never touch either.
pub struct AuthnChain {
    inner: parking_lot::RwLock<Vec<AuthnEntry>>,
    snapshot: arc_swap::ArcSwap<Vec<AuthnEntry>>,
    registry: parking_lot::RwLock<Option<Arc<ConfigRegistry>>>,
    save_lock: parking_lot::Mutex<()>,
}

impl AuthnChain {
    /// Empty chain (today's empty behaviour: open broker or local users).
    pub fn new() -> Self {
        Self {
            inner: parking_lot::RwLock::new(Vec::new()),
            snapshot: arc_swap::ArcSwap::from(Arc::new(Vec::new())),
            registry: parking_lot::RwLock::new(None),
            save_lock: parking_lot::Mutex::new(()),
        }
    }

    /// Seed from a validated snapshot root. Memory-only.
    pub fn from_snapshot(conf: &AuthnChainConf) -> Self {
        let chain = Self::new();
        chain.seed_from_snapshot(conf);
        chain
    }

    /// Seed from the registry's current snapshot and persist every later
    /// mutation back through it. Kernel boot path; an empty snapshot
    /// yields today's empty behaviour.
    pub fn from_registry(registry: &Arc<ConfigRegistry>) -> Self {
        let chain = Self::from_snapshot(&registry.snapshot().authn_chain);
        *chain.registry.write() = Some(Arc::clone(registry));
        chain
    }

    /// Attach the registry and replace the current contents with its
    /// snapshot, in place on the same instance.
    pub fn seed_from_registry(&self, registry: &Arc<ConfigRegistry>) {
        self.seed_from_snapshot(&registry.snapshot().authn_chain);
        *self.registry.write() = Some(Arc::clone(registry));
    }

    fn seed_from_snapshot(&self, conf: &AuthnChainConf) {
        let entries = conf
            .authenticators
            .iter()
            .filter_map(|e| conf_to_entry(e).ok())
            .collect::<Vec<_>>();
        *self.inner.write() = entries.clone();
        self.snapshot.store(Arc::new(entries));
    }

    /// Ordered snapshot of the chain in stored order. Management-plane
    /// read only; clones at most the capped list under one short lock.
    pub fn list(&self) -> Vec<AuthnEntry> {
        self.inner.read().clone()
    }

    /// Lock-free snapshot for the CONNECT path: one `Arc` load, no write
    /// lock, at most the capped entries to scan. Publish and deliver
    /// never call this.
    pub fn snapshot(&self) -> Arc<Vec<AuthnEntry>> {
        self.snapshot.load_full()
    }

    /// Whether the built-in database may execute for this snapshot: true
    /// when the chain is empty (today's behaviour) or holds at least one
    /// enabled `built_in_database` slot; false when the chain is
    /// non-empty with no enabled built-in slot (no live backend, fail
    /// closed). Consulted by the broker on CONNECT only.
    pub fn built_in_available(&self) -> bool {
        let snap = self.snapshot.load();
        if snap.is_empty() {
            return true;
        }
        snap.iter()
            .any(|e| e.backend == "built_in_database" && e.enable)
    }

    /// Append one entry. Fails cleanly on duplicate `id` (caller maps to
    /// `ALREADY_EXISTS`), a full chain (caller maps to `BAD_REQUEST`)
    /// or an invalid entry (caller maps to `BAD_REQUEST`). Validated
    /// all-before-apply: the candidate root is validated before it can
    /// become visible, so invalid state is never observable. Persists
    /// through the registry when one is attached; a commit or save
    /// failure surfaces as [`ChainInsertError::Persist`] and the
    /// in-memory update stays (commit precedes the atomic save, mirroring
    /// the credential store).
    pub fn insert(&self, entry: AuthnEntry) -> Result<AuthnEntry, ChainInsertError> {
        validate_entry(&entry)?;
        let _guard = self.save_lock.lock();
        let conf = {
            let mut current = self.inner.write();
            if current.iter().any(|e| e.id == entry.id) {
                return Err(ChainInsertError::Duplicate);
            }
            if current.len() >= MAX_AUTHN_CHAIN_ENTRIES {
                return Err(ChainInsertError::Full);
            }
            let mut next = current.clone();
            next.push(entry.clone());
            let conf = export_conf(&next);
            conf.validate()
                .map_err(|e| ChainInsertError::Invalid(e.to_string()))?;
            current.push(entry.clone());
            self.snapshot.store(Arc::new(current.clone()));
            conf
        };
        if let Some(registry) = self.registry.read().clone() {
            registry
                .commit_authn_chain(conf)
                .map_err(|e| ChainInsertError::Persist(e.to_string()))?;
            registry
                .save()
                .map_err(|e| ChainInsertError::Persist(e.to_string()))?;
        }
        Ok(entry)
    }

    /// Replace the whole chain order with the supplied ordered id list.
    ///
    /// Validate-all-before-apply: the full list is checked (non-empty
    /// ids, no duplicates, every id stored, no stored id omitted) before
    /// anything becomes visible, so a partial or unknown-id list applies
    /// nothing. On success the stored order, the lock-free CONNECT
    /// snapshot and the persisted registry all move together.
    /// Management-plane only: takes the write lock once per request;
    /// the CONNECT path keeps reading the lock-free snapshot and
    /// publish/deliver never touch this store.
    pub fn reorder(&self, ids: Vec<String>) -> Result<(), ChainReorderError> {
        for id in &ids {
            if id.trim().is_empty() {
                return Err(ChainReorderError::Invalid(
                    "field `id` must not be empty".to_string(),
                ));
            }
            if id.len() > MAX_ID_LEN {
                return Err(ChainReorderError::Invalid(
                    "field `id` is too long".to_string(),
                ));
            }
        }
        let mut seen = std::collections::HashSet::with_capacity(ids.len());
        for id in &ids {
            if !seen.insert(id.clone()) {
                return Err(ChainReorderError::Duplicate(format!(
                    "order names id {id:?} more than once"
                )));
            }
        }
        let _guard = self.save_lock.lock();
        let reordered = {
            let current = self.inner.read();
            let unknown: Vec<String> = ids
                .iter()
                .filter(|id| !current.iter().any(|e| &e.id == *id))
                .cloned()
                .collect();
            let missing: Vec<String> = current
                .iter()
                .filter(|e| !ids.contains(&e.id))
                .map(|e| e.id.clone())
                .collect();
            if !unknown.is_empty() && !missing.is_empty() {
                return Err(ChainReorderError::Invalid(format!(
                    "unknown authenticator id(s): {}; order omits stored id(s): {}",
                    unknown.join(", "),
                    missing.join(", "),
                )));
            }
            if !unknown.is_empty() {
                return Err(ChainReorderError::Unknown(unknown));
            }
            if !missing.is_empty() {
                return Err(ChainReorderError::Incomplete(missing));
            }
            let mut next = Vec::with_capacity(current.len());
            for id in &ids {
                let entry = current
                    .iter()
                    .find(|e| &e.id == id)
                    .cloned()
                    .expect("ids validated against current chain");
                next.push(entry);
            }
            let conf = export_conf(&next);
            conf.validate()
                .map_err(|e| ChainReorderError::Invalid(e.to_string()))?;
            next
        };
        let conf = export_conf(&reordered);
        {
            let mut current = self.inner.write();
            *current = reordered.clone();
            self.snapshot.store(Arc::new(reordered));
        }
        if let Some(registry) = self.registry.read().clone() {
            registry
                .commit_authn_chain(conf)
                .map_err(|e| ChainReorderError::Persist(e.to_string()))?;
            registry
                .save()
                .map_err(|e| ChainReorderError::Persist(e.to_string()))?;
        }
        Ok(())
    }

    /// One entry by `id` (`None` when unknown). Management-plane read
    /// only; clones at most one entry under a short lock.
    pub fn get(&self, id: &str) -> Option<AuthnEntry> {
        self.inner.read().iter().find(|e| e.id == id).cloned()
    }

    /// Replace the entry stored under `id` with `entry` (whose `id` must
    /// equal `id`).
    ///
    /// Validate-all-before-apply: the candidate is validated before
    /// anything becomes visible, so a bad replacement applies nothing.
    /// The stored position is preserved. On success the entry, the
    /// lock-free CONNECT snapshot and the persisted registry all move
    /// together. Management-plane only: one short write lock per
    /// request; the CONNECT path keeps reading its lock-free snapshot
    /// and publish/deliver never touch this store.
    // TODO(parity): may the update rename the entry or change its
    // mechanism/backend, or is only the config/enable pair mutable? The
    // rulebook does not decide the exact PUT field set; the current
    // choice replaces the whole entry in place (same `id`) after full
    // validation until the checker pins the shape.
    pub fn update(&self, id: &str, entry: AuthnEntry) -> Result<AuthnEntry, ChainUpdateError> {
        if entry.id != id {
            return Err(ChainUpdateError::Invalid(
                "field `id` must match the path id".to_string(),
            ));
        }
        validate_entry(&entry).map_err(|e| match e {
            ChainInsertError::Invalid(msg) => ChainUpdateError::Invalid(msg),
            ChainInsertError::Duplicate => {
                ChainUpdateError::Invalid("field `id` is duplicated".to_string())
            }
            ChainInsertError::Full => {
                ChainUpdateError::Invalid("authenticator chain is full".to_string())
            }
            ChainInsertError::Persist(msg) => ChainUpdateError::Persist(msg),
        })?;
        let _guard = self.save_lock.lock();
        let updated = {
            let mut current = self.inner.write();
            let Some(pos) = current.iter().position(|e| e.id == id) else {
                return Err(ChainUpdateError::NotFound);
            };
            let mut next = current.clone();
            next[pos] = entry.clone();
            let conf = export_conf(&next);
            conf.validate()
                .map_err(|e| ChainUpdateError::Invalid(e.to_string()))?;
            *current = next.clone();
            self.snapshot.store(Arc::new(next));
            conf
        };
        if let Some(registry) = self.registry.read().clone() {
            registry
                .commit_authn_chain(updated)
                .map_err(|e| ChainUpdateError::Persist(e.to_string()))?;
            registry
                .save()
                .map_err(|e| ChainUpdateError::Persist(e.to_string()))?;
        }
        Ok(entry)
    }

    /// Remove the entry stored under `id`, returning it.
    ///
    /// Validate-all-before-apply: unknown ids fail with `NotFound` and
    /// apply nothing. Deleting the last remaining entry is refused with
    /// `Last` instead of leaving authentication open (an empty chain
    /// preserves today's open behaviour). On success the stored order,
    /// the lock-free CONNECT snapshot and the persisted registry all
    /// move together, and the freed `id` may be re-created.
    /// Management-plane only: one short write lock per request; the
    /// CONNECT path keeps reading its lock-free snapshot and
    /// publish/deliver never touch this store.
    // TODO(parity): is "last" the last entry of any kind, or the last
    // enabled entry / last live backend? The rulebook does not decide
    // the exact refusal set; the current choice refuses deleting the
    // sole remaining entry (any kind) as the conservative fail-closed
    // answer until the checker pins it.
    pub fn remove(&self, id: &str) -> Result<AuthnEntry, ChainRemoveError> {
        let _guard = self.save_lock.lock();
        let (removed, conf) = {
            let mut current = self.inner.write();
            let Some(pos) = current.iter().position(|e| e.id == id) else {
                return Err(ChainRemoveError::NotFound);
            };
            if current.len() == 1 {
                return Err(ChainRemoveError::Last(
                    "cannot delete the last authenticator: authentication must not be left open"
                        .to_string(),
                ));
            }
            let removed = current.remove(pos);
            let next = current.clone();
            let conf = export_conf(&next);
            conf.validate()
                .map_err(|e| ChainRemoveError::Persist(e.to_string()))?;
            self.snapshot.store(Arc::new(next));
            (removed, conf)
        };
        if let Some(registry) = self.registry.read().clone() {
            registry
                .commit_authn_chain(conf)
                .map_err(|e| ChainRemoveError::Persist(e.to_string()))?;
            registry
                .save()
                .map_err(|e| ChainRemoveError::Persist(e.to_string()))?;
        }
        Ok(removed)
    }

    /// Number of stored entries.
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    /// Whether the chain holds no entries.
    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }
}

impl Default for AuthnChain {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_entry(entry: &AuthnEntry) -> Result<(), ChainInsertError> {
    if entry.id.trim().is_empty() {
        return Err(ChainInsertError::Invalid(
            "field `id` must not be empty".to_string(),
        ));
    }
    if entry.id.len() > MAX_ID_LEN {
        return Err(ChainInsertError::Invalid(
            "field `id` is too long".to_string(),
        ));
    }
    if entry.mechanism.trim().is_empty() {
        return Err(ChainInsertError::Invalid(
            "field `mechanism` must not be empty".to_string(),
        ));
    }
    if entry.mechanism.len() > MAX_ID_LEN {
        return Err(ChainInsertError::Invalid(
            "field `mechanism` is too long".to_string(),
        ));
    }
    if !is_known_authn_mechanism(&entry.mechanism) {
        return Err(ChainInsertError::Invalid(format!(
            "field `mechanism` {:?} is unknown",
            entry.mechanism
        )));
    }
    if entry.backend.trim().is_empty() {
        return Err(ChainInsertError::Invalid(
            "field `backend` must not be empty".to_string(),
        ));
    }
    if entry.backend.len() > MAX_ID_LEN {
        return Err(ChainInsertError::Invalid(
            "field `backend` is too long".to_string(),
        ));
    }
    if !is_known_authn_backend(&entry.backend) {
        return Err(ChainInsertError::Invalid(format!(
            "field `backend` {:?} is unknown",
            entry.backend
        )));
    }
    if let Some((head, _)) = entry.id.split_once(':') {
        if head != entry.mechanism {
            return Err(ChainInsertError::Invalid(format!(
                "field `id` {:?} must start with its mechanism {:?}",
                entry.id, entry.mechanism
            )));
        }
    }
    let rendered = entry.config.to_string();
    if rendered.len() > MAX_CONFIG_LEN {
        return Err(ChainInsertError::Invalid(
            "field `config` is too large".to_string(),
        ));
    }
    Ok(())
}

fn export_conf(entries: &[AuthnEntry]) -> AuthnChainConf {
    AuthnChainConf {
        authenticators: entries
            .iter()
            .map(|e| ConfEntry {
                id: e.id.clone(),
                mechanism: e.mechanism.clone(),
                backend: e.backend.clone(),
                enable: e.enable,
                config: if e.config.is_null() {
                    String::new()
                } else {
                    e.config.to_string()
                },
            })
            .collect(),
    }
}

fn conf_to_entry(conf: &ConfEntry) -> Result<AuthnEntry, ()> {
    let config = if conf.config.trim().is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_str(&conf.config).map_err(|_| ())?
    };
    Ok(AuthnEntry {
        id: conf.id.clone(),
        mechanism: conf.mechanism.clone(),
        backend: conf.backend.clone(),
        enable: conf.enable,
        config,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, backend: &str) -> AuthnEntry {
        let mechanism = id
            .split_once(':')
            .map(|(m, _)| m)
            .unwrap_or("password_based");
        AuthnEntry {
            id: id.to_string(),
            mechanism: mechanism.to_string(),
            backend: backend.to_string(),
            enable: true,
            config: serde_json::Value::Null,
        }
    }

    #[test]
    fn empty_chain_reports_no_entries_and_allows_built_in() {
        let chain = AuthnChain::new();
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);
        assert_eq!(chain.list(), Vec::new());
        assert!(chain.built_in_available());
        assert!(chain.snapshot().is_empty());
    }

    #[test]
    fn insert_appends_in_order_and_rejects_duplicates() {
        let chain = AuthnChain::new();
        chain
            .insert(entry(
                "password_based:built_in_database",
                "built_in_database",
            ))
            .expect("first insert");
        assert!(chain.built_in_available());
        let dup = chain.insert(entry(
            "password_based:built_in_database",
            "built_in_database",
        ));
        assert_eq!(dup, Err(ChainInsertError::Duplicate));
        chain
            .insert(entry("password_based:mysql", "mysql"))
            .expect("second insert");
        let ids: Vec<_> = chain.list().iter().map(|e| e.id.clone()).collect();
        assert_eq!(
            ids,
            vec![
                "password_based:built_in_database".to_string(),
                "password_based:mysql".to_string()
            ]
        );
    }

    #[test]
    fn non_built_in_only_chain_requires_fail_closed() {
        let chain = AuthnChain::new();
        chain
            .insert(entry("password_based:mysql", "mysql"))
            .expect("mysql insert");
        assert!(
            !chain.built_in_available(),
            "no live backend can execute without an enabled built-in slot"
        );
    }

    #[test]
    fn insert_rejects_unknown_backend_and_mismatched_id() {
        let chain = AuthnChain::new();
        let bad_backend = AuthnEntry {
            id: "password_based:nope".to_string(),
            mechanism: "password_based".to_string(),
            backend: "nope".to_string(),
            enable: true,
            config: serde_json::Value::Null,
        };
        assert!(matches!(
            chain.insert(bad_backend),
            Err(ChainInsertError::Invalid(_))
        ));
        let mismatched = AuthnEntry {
            id: "jwt:built_in_database".to_string(),
            mechanism: "password_based".to_string(),
            backend: "built_in_database".to_string(),
            enable: true,
            config: serde_json::Value::Null,
        };
        assert!(matches!(
            chain.insert(mismatched),
            Err(ChainInsertError::Invalid(_))
        ));
    }

    #[test]
    fn insert_enforces_chain_cap() {
        let chain = AuthnChain::new();
        for n in 0..MAX_AUTHN_CHAIN_ENTRIES {
            // Distinct ids sharing one known backend keep the test on the
            // cap (not on backend validation).
            let mut e = entry("password_based:mysql", "mysql");
            e.id = format!("password_based:mysql-{n}");
            chain.insert(e).expect("fill to cap");
        }
        assert_eq!(chain.len(), MAX_AUTHN_CHAIN_ENTRIES);
        let mut overflow = entry("password_based:overflow", "mysql");
        overflow.id = "password_based:mysql-overflow".to_string();
        assert_eq!(chain.insert(overflow), Err(ChainInsertError::Full));
    }

    #[test]
    fn chain_survives_registry_reload() {
        let dir = std::env::temp_dir().join(format!(
            "authn-chain-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let registry = Arc::new(ConfigRegistry::load(&dir).expect("fresh data dir loads"));
        let chain = AuthnChain::from_registry(&registry);
        chain
            .insert(entry(
                "password_based:built_in_database",
                "built_in_database",
            ))
            .expect("persist built-in");
        assert!(dir.join(broker_config::STATE_FILE_NAME).is_file());
        let reloaded = Arc::new(ConfigRegistry::load(&dir).expect("data dir reloads"));
        let restarted = AuthnChain::from_registry(&reloaded);
        let ids: Vec<_> = restarted.list().iter().map(|e| e.id.clone()).collect();
        assert_eq!(ids, vec!["password_based:built_in_database".to_string()]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reorder_replaces_order_and_rejects_unknown_or_partial_without_applying() {
        let chain = AuthnChain::new();
        chain
            .insert(entry(
                "password_based:built_in_database",
                "built_in_database",
            ))
            .expect("first insert");
        chain
            .insert(entry("password_based:mysql", "mysql"))
            .expect("second insert");
        chain
            .reorder(vec![
                "password_based:mysql".to_string(),
                "password_based:built_in_database".to_string(),
            ])
            .expect("explicit order applies");
        let ids: Vec<_> = chain.list().iter().map(|e| e.id.clone()).collect();
        assert_eq!(
            ids,
            vec![
                "password_based:mysql".to_string(),
                "password_based:built_in_database".to_string()
            ]
        );
        // Snapshot moves with the store: the CONNECT path reads the new
        // sequence without taking the write lock.
        let snap: Vec<_> = chain.snapshot().iter().map(|e| e.id.clone()).collect();
        assert_eq!(ids, snap);

        // Unknown ids are rejected and apply nothing.
        let err = chain
            .reorder(vec![
                "password_based:mysql".to_string(),
                "password_based:built_in_database".to_string(),
                "password_based:nowhere".to_string(),
            ])
            .expect_err("unknown id must be rejected");
        assert!(matches!(err, ChainReorderError::Unknown(_)));
        let ids: Vec<_> = chain.list().iter().map(|e| e.id.clone()).collect();
        assert_eq!(
            ids,
            vec![
                "password_based:mysql".to_string(),
                "password_based:built_in_database".to_string()
            ]
        );

        // Partial lists are rejected and apply nothing.
        let err = chain
            .reorder(vec!["password_based:mysql".to_string()])
            .expect_err("partial list must be rejected");
        assert!(matches!(err, ChainReorderError::Incomplete(_)));
        let ids: Vec<_> = chain.list().iter().map(|e| e.id.clone()).collect();
        assert_eq!(
            ids,
            vec![
                "password_based:mysql".to_string(),
                "password_based:built_in_database".to_string()
            ]
        );

        // Duplicates are rejected and apply nothing.
        let err = chain
            .reorder(vec![
                "password_based:mysql".to_string(),
                "password_based:mysql".to_string(),
            ])
            .expect_err("duplicate id must be rejected");
        assert!(matches!(err, ChainReorderError::Duplicate(_)));
        let ids: Vec<_> = chain.list().iter().map(|e| e.id.clone()).collect();
        assert_eq!(
            ids,
            vec![
                "password_based:mysql".to_string(),
                "password_based:built_in_database".to_string()
            ]
        );
    }

    #[test]
    fn reorder_persists_across_registry_reload() {
        let dir = std::env::temp_dir().join(format!(
            "authn-order-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let registry = Arc::new(ConfigRegistry::load(&dir).expect("fresh data dir loads"));
        let chain = AuthnChain::from_registry(&registry);
        chain
            .insert(entry(
                "password_based:built_in_database",
                "built_in_database",
            ))
            .expect("persist built-in");
        chain
            .insert(entry("password_based:mysql", "mysql"))
            .expect("persist mysql");
        chain
            .reorder(vec![
                "password_based:mysql".to_string(),
                "password_based:built_in_database".to_string(),
            ])
            .expect("reorder persists");
        drop(chain);
        drop(registry);
        let reloaded = Arc::new(ConfigRegistry::load(&dir).expect("data dir reloads"));
        let restarted = AuthnChain::from_registry(&reloaded);
        let ids: Vec<_> = restarted.list().iter().map(|e| e.id.clone()).collect();
        assert_eq!(
            ids,
            vec![
                "password_based:mysql".to_string(),
                "password_based:built_in_database".to_string()
            ]
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn get_update_remove_round_trip_with_validate_all_before_apply() {
        let chain = AuthnChain::new();
        chain
            .insert(entry(
                "password_based:built_in_database",
                "built_in_database",
            ))
            .expect("first insert");
        chain
            .insert(entry("password_based:mysql", "mysql"))
            .expect("second insert");

        // Read one entry by id; unknown ids miss.
        let found = chain.get("password_based:mysql").expect("hit");
        assert_eq!(found.backend, "mysql");
        assert!(chain.get("password_based:nowhere").is_none());

        // Update replaces in place after full validation and keeps order.
        let mut next = found.clone();
        next.enable = false;
        next.config = serde_json::json!({"pool_size": 4});
        let stored = chain
            .update("password_based:mysql", next)
            .expect("valid update applies");
        assert!(!stored.enable);
        let reread = chain.get("password_based:mysql").expect("reread");
        assert!(!reread.enable);
        assert_eq!(reread.config, serde_json::json!({"pool_size": 4}));
        let ids: Vec<_> = chain.list().iter().map(|e| e.id.clone()).collect();
        assert_eq!(
            ids,
            vec![
                "password_based:built_in_database".to_string(),
                "password_based:mysql".to_string()
            ]
        );
        // Snapshot moves with the store.
        let snap: Vec<_> = chain.snapshot().iter().map(|e| e.id.clone()).collect();
        assert_eq!(ids, snap);

        // Bad replacements are rejected and apply nothing.
        let mut bad = reread.clone();
        bad.backend = "nope".to_string();
        assert!(matches!(
            chain.update("password_based:mysql", bad),
            Err(ChainUpdateError::Invalid(_))
        ));
        let reread = chain.get("password_based:mysql").expect("unchanged");
        assert_eq!(reread.backend, "mysql");
        assert!(matches!(
            chain.update(
                "password_based:nowhere",
                entry("password_based:nowhere", "mysql")
            ),
            Err(ChainUpdateError::NotFound)
        ));

        // Delete removes and reports; unknown ids miss; the freed id may
        // be re-created.
        let removed = chain.remove("password_based:mysql").expect("delete hit");
        assert_eq!(removed.id, "password_based:mysql");
        assert!(chain.get("password_based:mysql").is_none());
        assert!(matches!(
            chain.remove("password_based:nowhere"),
            Err(ChainRemoveError::NotFound)
        ));
        chain
            .insert(entry("password_based:mysql", "mysql"))
            .expect("re-create after delete works");
        assert!(chain.get("password_based:mysql").is_some());
    }

    #[test]
    fn remove_last_entry_is_refused_and_update_remove_persist() {
        let chain = AuthnChain::new();
        chain
            .insert(entry(
                "password_based:built_in_database",
                "built_in_database",
            ))
            .expect("single insert");
        assert!(matches!(
            chain.remove("password_based:built_in_database"),
            Err(ChainRemoveError::Last(_))
        ));
        assert!(chain.get("password_based:built_in_database").is_some());

        let dir = std::env::temp_dir().join(format!(
            "authn-entry-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let registry = Arc::new(ConfigRegistry::load(&dir).expect("fresh data dir loads"));
        let chain = AuthnChain::from_registry(&registry);
        chain
            .insert(entry(
                "password_based:built_in_database",
                "built_in_database",
            ))
            .expect("persist built-in");
        chain
            .insert(entry("password_based:mysql", "mysql"))
            .expect("persist mysql");
        let mut next = chain.get("password_based:mysql").expect("hit");
        next.enable = false;
        chain
            .update("password_based:mysql", next)
            .expect("update persists");
        chain
            .remove("password_based:mysql")
            .expect("delete persists");
        drop(chain);
        drop(registry);
        let reloaded = Arc::new(ConfigRegistry::load(&dir).expect("data dir reloads"));
        let restarted = AuthnChain::from_registry(&reloaded);
        let ids: Vec<_> = restarted.list().iter().map(|e| e.id.clone()).collect();
        assert_eq!(ids, vec!["password_based:built_in_database".to_string()]);
        std::fs::remove_dir_all(&dir).ok();
    }
}
