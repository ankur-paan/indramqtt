//! Whole-config validation, diffs, version history and effective-value
//! lookup for runtime configuration (M1-05).
//!
//! The registry already validated each root before the swap; this module
//! adds the three behaviours that span roots:
//!
//! * [`validate_whole`] checks a full [`FullSnapshot`] across roots (every
//!   rule `ForwardConnector` action names a connector that exists) and
//!   reports *every* offending setting in one error, so a change set either
//!   applies entirely or not at all and the running snapshot stays
//!   untouched on failure.
//! * [`diff_snapshots`] renders the (setting, old value, new value, layer) rows a
//!   reload shows before applying, and which [`ConfigHistory`] stores per
//!   version.
//! * [`ConfigHistory`] versions every applied change (who, when, what
//!   changed) behind a short lock and restores any version through the same
//!   validate-whole path. Management-plane only; owners on the publish or
//!   deliver path hold read-optimised snapshots, never this lock.
//!
//! Runtime changes persist into the kernel data directory (`state.toml`
//! plus `config-history.json` beside it). Files under the operator config
//! directory (`indra.toml`, `conf.d/`) are never written by the broker.

use std::collections::{HashMap, HashSet};

use crate::layers::Layer;
use crate::schema::BrokerConfig;
use crate::{ConfigError, FullSnapshot};

/// History file beside `state.toml` inside the kernel data directory.
/// Reason: operator files live under the config directory; runtime state
/// (snapshot plus this history) lives under the data directory so a reload
/// can never rewrite an operator file.
pub const HISTORY_FILE_NAME: &str = "config-history.json";

/// Bound on retained config versions.
/// Reason: each version holds a full snapshot; 64 versions bound history
/// memory to 64 snapshots (typically kilobytes) while keeping enough
/// restore points for operators. Older versions drop oldest-first.
pub const MAX_HISTORY_ENTRIES: usize = 64;

/// One changed setting between two snapshots.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConfigDiff {
    /// Dotted setting path (e.g. `rules.rules[rule-1].topic_filter`).
    pub setting: String,
    /// Previous value rendered for display (redacted for secrets).
    pub old_value: String,
    /// New value rendered for display (redacted for secrets).
    pub new_value: String,
    /// Layer that supplied the new value (`runtime` for versioned reloads).
    /// Reason: the spec requires diff rows to show (setting, old, new,
    /// layer); every row here comes from a runtime version.
    #[serde(default = "default_diff_layer")]
    pub layer: String,
}

/// Default layer for diff rows persisted before the layer column existed.
fn default_diff_layer() -> String {
    "runtime".to_string()
}

/// One applied configuration version.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConfigVersion {
    /// Monotonic version id (0 is the boot snapshot).
    pub id: u64,
    /// Unix seconds when the version was recorded.
    pub timestamp_secs: u64,
    /// Who applied the change (API username, `boot`, `restore:N`).
    pub actor: String,
    /// Short human summary of what changed.
    pub summary: String,
    /// Per-setting diff from the previous version.
    pub changes: Vec<ConfigDiff>,
    /// The full snapshot that became visible at this version.
    pub snapshot: FullSnapshot,
}

/// Bounded in-memory version history.
///
/// Oldest-first eviction keeps memory finite; every mutation takes one
/// short lock on the management plane only.
#[derive(Debug, Default)]
pub struct ConfigHistory {
    versions: std::sync::RwLock<Vec<ConfigVersion>>,
    next_id: std::sync::atomic::AtomicU64,
}

impl ConfigHistory {
    /// Empty history; the caller seeds the boot version explicitly.
    #[must_use]
    pub fn new() -> Self {
        Self {
            versions: std::sync::RwLock::new(Vec::new()),
            next_id: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Seed the boot snapshot as version 0 (no-op when history is non-empty,
    /// e.g. after loading the persisted file).
    pub fn seed_boot(&self, snapshot: &FullSnapshot) {
        let mut versions = self.versions.write().expect("history lock");
        if !versions.is_empty() {
            return;
        }
        versions.push(ConfigVersion {
            id: 0,
            timestamp_secs: now_secs(),
            actor: "boot".to_string(),
            summary: "boot snapshot".to_string(),
            changes: Vec::new(),
            snapshot: snapshot.clone(),
        });
        self.next_id.store(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// Record a new version from the diff between `old` and `next`.
    pub fn record(
        &self,
        actor: &str,
        summary: &str,
        old: &FullSnapshot,
        next: &FullSnapshot,
    ) -> u64 {
        let changes = diff_snapshots(old, next);
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut versions = self.versions.write().expect("history lock");
        versions.push(ConfigVersion {
            id,
            timestamp_secs: now_secs(),
            actor: actor.to_string(),
            summary: summary.to_string(),
            changes,
            snapshot: next.clone(),
        });
        while versions.len() > MAX_HISTORY_ENTRIES {
            versions.remove(0);
        }
        id
    }

    /// List versions newest-first (bounded snapshots cloned per call).
    #[must_use]
    pub fn list(&self) -> Vec<ConfigVersion> {
        let versions = self.versions.read().expect("history lock");
        let mut out = versions.clone();
        out.reverse();
        out
    }

    /// Fetch one version by id.
    #[must_use]
    pub fn get(&self, id: u64) -> Option<ConfigVersion> {
        self.versions
            .read()
            .expect("history lock")
            .iter()
            .find(|version| version.id == id)
            .cloned()
    }

    /// Number of retained versions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.versions.read().expect("history lock").len()
    }

    /// True when no version is recorded yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Replace the whole history (load path only).
    pub fn replace(&self, mut versions: Vec<ConfigVersion>) {
        versions.sort_by_key(|version| version.id);
        versions.truncate(MAX_HISTORY_ENTRIES);
        let next = versions.iter().map(|v| v.id + 1).max().unwrap_or(0);
        *self.versions.write().expect("history lock") = versions;
        self.next_id
            .store(next, std::sync::atomic::Ordering::SeqCst);
    }

    /// Reserve the next version id without mutating history.
    #[must_use]
    pub fn next_id(&self) -> u64 {
        self.next_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    /// Commit a pre-built version to history (caller already persisted files).
    pub fn commit_record(&self, version: ConfigVersion) {
        let mut versions = self.versions.write().expect("history lock");
        versions.push(version);
        while versions.len() > MAX_HISTORY_ENTRIES {
            versions.remove(0);
        }
    }

    /// Truncate history to at most `max_len` versions, removing newest first.
    /// Used to roll back history when a reload fails after a version was recorded.
    pub fn truncate_to(&self, max_len: usize) {
        let mut versions = self.versions.write().expect("history lock");
        if versions.len() > max_len {
            versions.truncate(max_len);
        }
    }
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Validate a full snapshot across roots.
///
/// Per-root structural checks run first; then cross-root checks (every rule
/// `ForwardConnector` action names an existing connector id). All failures
/// are collected and reported in one error naming every offending setting,
/// so a change set spanning roots either applies entirely or not at all.
/// TODO(parity): which cross-root references beyond rule->connector should
/// be enforced (ACL usernames, admin names) is undecided; enforcing only
/// rule->connector is the conservative choice (refuse a rule that forwards
/// into nothing) until decided.
pub fn validate_whole(snapshot: &FullSnapshot) -> Result<(), ConfigError> {
    let mut problems: Vec<String> = Vec::new();
    if let Err(err) = snapshot.admin_users.validate() {
        problems.push(err.to_string());
    }
    if let Err(err) = snapshot.mqtt_users.validate() {
        problems.push(err.to_string());
    }
    if let Err(err) = snapshot.rules.validate() {
        problems.push(err.to_string());
    }
    if let Err(err) = snapshot.connectors.validate() {
        problems.push(err.to_string());
    }
    let known: HashSet<&str> = snapshot
        .connectors
        .connectors
        .iter()
        .map(|entry| entry.id.as_str())
        .collect();
    for (index, rule) in snapshot.rules.rules.iter().enumerate() {
        for (action_index, action) in rule.actions.iter().enumerate() {
            if let crate::RuleActionEntry::ForwardConnector { connector_id } = action {
                if !known.contains(connector_id.as_str()) {
                    problems.push(format!(
                        "rules.rules[{index}].actions[{action_index}].connector_id {connector_id:?} names an unknown connector (field `rules.rules[{index}].actions[{action_index}].connector_id`)"
                    ));
                }
            }
        }
    }
    // Secret resolvability (fail closed naming the reference, never the
    // value): an MQTT password held as `file:`/`env:` must resolve at
    // validation time so a missing/unreadable secret rejects the change
    // set instead of applying with a locked account. Reason: the spec
    // requires a missing secret to fail with an error naming the
    // reference; validation is where a change set either applies entirely
    // or not at all.
    for (index, user) in snapshot.mqtt_users.users.iter().enumerate() {
        let trimmed = user.password_hash.trim();
        if crate::secrets::is_secret_ref(trimmed) {
            if let Err(err) = crate::secrets::resolve_secret(trimmed) {
                problems.push(format!(
                    "mqtt_users.users[{index}].password_hash cannot resolve {}: {err} (field `mqtt_users.users[{index}].password_hash`)",
                    crate::secrets::redact_value(trimmed)
                ));
            }
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(ConfigError::Invalid(format!(
            "whole-config validation failed: {}",
            problems.join("; ")
        )))
    }
}

/// Render one diff row, redacting secret references on both sides.
fn row(setting: String, old_value: &str, new_value: &str) -> ConfigDiff {
    ConfigDiff {
        setting,
        old_value: crate::secrets::redact_value(old_value),
        new_value: crate::secrets::redact_value(new_value),
        layer: "runtime".to_string(),
    }
}

/// Redact secret references occurring as string leaves in a JSON value.
fn redact_json_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => {
            if crate::secrets::is_secret_ref(text.trim()) {
                *text = crate::secrets::redact_value(text.trim());
            }
        }
        serde_json::Value::Array(entries) => {
            for entry in entries {
                redact_json_value(entry);
            }
        }
        serde_json::Value::Object(map) => {
            for (_, entry) in map.iter_mut() {
                redact_json_value(entry);
            }
        }
        _ => {}
    }
}

/// Render a connector config string with inner secrets redacted: a bare
/// reference redacts directly; a JSON document redacts its string leaves;
/// anything else passes through unchanged.
fn render_connector_config(config: &str) -> String {
    let trimmed = config.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if crate::secrets::is_secret_ref(trimmed) {
        return crate::secrets::redact_value(trimmed);
    }
    match serde_json::from_str::<serde_json::Value>(config) {
        Ok(mut value) => {
            redact_json_value(&mut value);
            serde_json::to_string(&value).unwrap_or_else(|_| config.to_string())
        }
        Err(_) => config.to_string(),
    }
}

fn render_admin_user(user: &crate::AdminUser) -> String {
    let mut value = serde_json::to_value(user).unwrap_or(serde_json::Value::Null);
    redact_json_value(&mut value);
    serde_json::to_string(&value).unwrap_or_else(|_| {
        format!(
            "role={} description={} must_change_password={} password_hash={}",
            user.role,
            user.description,
            user.must_change_password,
            crate::secrets::redact_value(&user.password_hash)
        )
    })
}

fn render_mqtt_user(user: &crate::MqttUser) -> String {
    let mut value = serde_json::to_value(user).unwrap_or(serde_json::Value::Null);
    redact_json_value(&mut value);
    serde_json::to_string(&value).unwrap_or_else(|_| {
        format!(
            "password_hash={} max_connections={:?} max_publish_rate={:?} max_publish_burst={:?}",
            crate::secrets::redact_value(&user.password_hash),
            user.max_connections,
            user.max_publish_rate,
            user.max_publish_burst
        )
    })
}

fn render_rule(rule: &crate::RuleEntry) -> String {
    let mut value = serde_json::to_value(rule).unwrap_or(serde_json::Value::Null);
    redact_json_value(&mut value);
    serde_json::to_string(&value).unwrap_or_else(|_| {
        format!(
            "filter={} enabled={} sql={:?} actions={:?}",
            rule.topic_filter,
            rule.enabled,
            rule.sql_query,
            serde_json::to_value(&rule.actions).unwrap_or(serde_json::Value::Null)
        )
    })
}

fn render_connector(entry: &crate::ConnectorEntry) -> String {
    format!(
        "type={} enable={} config={}",
        entry.connector_type,
        entry.enable,
        render_connector_config(&entry.config)
    )
}

/// Diff two snapshots into per-setting rows (setting, old, new, layer).
#[must_use]
pub fn diff_snapshots(old: &FullSnapshot, new: &FullSnapshot) -> Vec<ConfigDiff> {
    let mut out = Vec::new();
    // Admin users keyed by username.
    let old_admin: HashMap<&str, &crate::AdminUser> = old
        .admin_users
        .users
        .iter()
        .map(|u| (u.username.as_str(), u))
        .collect();
    let new_admin: HashMap<&str, &crate::AdminUser> = new
        .admin_users
        .users
        .iter()
        .map(|u| (u.username.as_str(), u))
        .collect();
    for username in sorted_keys(&old_admin, &new_admin) {
        match (
            old_admin.get(username.as_str()),
            new_admin.get(username.as_str()),
        ) {
            (Some(a), Some(b)) => {
                if a != b {
                    out.push(row(
                        format!("admin_users.users[{username}]"),
                        &render_admin_user(a),
                        &render_admin_user(b),
                    ));
                }
            }
            (None, Some(_)) => out.push(row(
                format!("admin_users.users[{username}]"),
                "<absent>",
                "<present>",
            )),
            (Some(_), None) => out.push(row(
                format!("admin_users.users[{username}]"),
                "<present>",
                "<absent>",
            )),
            (None, None) => {}
        }
    }
    // MQTT users keyed by username (hashes compared redacted: presence only,
    // never the digest bytes in the diff text).
    let old_mqtt: HashMap<&str, &crate::MqttUser> = old
        .mqtt_users
        .users
        .iter()
        .map(|u| (u.username.as_str(), u))
        .collect();
    let new_mqtt: HashMap<&str, &crate::MqttUser> = new
        .mqtt_users
        .users
        .iter()
        .map(|u| (u.username.as_str(), u))
        .collect();
    for username in sorted_keys(&old_mqtt, &new_mqtt) {
        match (
            old_mqtt.get(username.as_str()),
            new_mqtt.get(username.as_str()),
        ) {
            (Some(a), Some(b)) => {
                if a != b {
                    out.push(row(
                        format!("mqtt_users.users[{username}]"),
                        &render_mqtt_user(a),
                        &render_mqtt_user(b),
                    ));
                }
            }
            (None, Some(_)) => out.push(row(
                format!("mqtt_users.users[{username}]"),
                "<absent>",
                "<present>",
            )),
            (Some(_), None) => out.push(row(
                format!("mqtt_users.users[{username}]"),
                "<present>",
                "<absent>",
            )),
            (None, None) => {}
        }
    }
    if old.mqtt_users.acls != new.mqtt_users.acls {
        let mut old_value =
            serde_json::to_value(&old.mqtt_users.acls).unwrap_or(serde_json::Value::Null);
        redact_json_value(&mut old_value);
        let mut new_value =
            serde_json::to_value(&new.mqtt_users.acls).unwrap_or(serde_json::Value::Null);
        redact_json_value(&mut new_value);
        out.push(row(
            "mqtt_users.acls".to_string(),
            &serde_json::to_string(&old_value)
                .unwrap_or_else(|_| format!("{} entries", old.mqtt_users.acls.len())),
            &serde_json::to_string(&new_value)
                .unwrap_or_else(|_| format!("{} entries", new.mqtt_users.acls.len())),
        ));
    }
    // Rules keyed by id.
    let old_rules: HashMap<&str, &crate::RuleEntry> =
        old.rules.rules.iter().map(|r| (r.id.as_str(), r)).collect();
    let new_rules: HashMap<&str, &crate::RuleEntry> =
        new.rules.rules.iter().map(|r| (r.id.as_str(), r)).collect();
    for id in sorted_keys(&old_rules, &new_rules) {
        match (old_rules.get(id.as_str()), new_rules.get(id.as_str())) {
            (Some(a), Some(b)) => {
                if a != b {
                    out.push(row(
                        format!("rules.rules[{id}]"),
                        &render_rule(a),
                        &render_rule(b),
                    ));
                }
            }
            (None, Some(_)) => out.push(row(format!("rules.rules[{id}]"), "<absent>", "<present>")),
            (Some(_), None) => out.push(row(format!("rules.rules[{id}]"), "<present>", "<absent>")),
            (None, None) => {}
        }
    }
    // Connectors keyed by id (config bodies redacted when they are refs).
    let old_conn: HashMap<&str, &crate::ConnectorEntry> = old
        .connectors
        .connectors
        .iter()
        .map(|c| (c.id.as_str(), c))
        .collect();
    let new_conn: HashMap<&str, &crate::ConnectorEntry> = new
        .connectors
        .connectors
        .iter()
        .map(|c| (c.id.as_str(), c))
        .collect();
    for id in sorted_keys(&old_conn, &new_conn) {
        match (old_conn.get(id.as_str()), new_conn.get(id.as_str())) {
            (Some(a), Some(b)) => {
                if a != b {
                    out.push(row(
                        format!("connectors.connectors[{id}]"),
                        &render_connector(a),
                        &render_connector(b),
                    ));
                }
            }
            (None, Some(_)) => out.push(row(
                format!("connectors.connectors[{id}]"),
                "<absent>",
                "<present>",
            )),
            (Some(_), None) => out.push(row(
                format!("connectors.connectors[{id}]"),
                "<present>",
                "<absent>",
            )),
            (None, None) => {}
        }
    }
    out.sort_by(|a, b| a.setting.cmp(&b.setting));
    out
}

fn sorted_keys<T>(old: &HashMap<&str, T>, new: &HashMap<&str, T>) -> Vec<String> {
    let mut keys: HashSet<String> = HashSet::new();
    for key in old.keys() {
        keys.insert((*key).to_string());
    }
    for key in new.keys() {
        keys.insert((*key).to_string());
    }
    let mut out: Vec<String> = keys.into_iter().collect();
    out.sort();
    out
}

/// Effective scalar value of one schema setting plus its startup layer.
///
/// Values render as TOML (`"host:port"` quoted, numbers bare); unknown
/// paths return `None`. Secret-typed values render redacted: the layer is
/// named exactly, the value never leaks.
#[must_use]
pub fn explain_schema_key(
    config: &BrokerConfig,
    provenance: &HashMap<String, Layer>,
    key: &str,
) -> Option<(String, Layer)> {
    let table = toml::Value::try_from(config).ok()?;
    let value = get_path(table.as_table()?, key)?;
    let layer = provenance.get(key).cloned().unwrap_or(Layer::Defaults);
    Some((render_toml_value_redacted(key, value), layer))
}

fn get_path<'a>(table: &'a toml::Table, path: &str) -> Option<&'a toml::Value> {
    let mut current = table;
    let parts: Vec<&str> = path.split('.').collect();
    for (index, part) in parts.iter().enumerate() {
        if index + 1 == parts.len() {
            return current.get(*part);
        }
        match current.get(*part) {
            Some(toml::Value::Table(nested)) => current = nested,
            _ => return None,
        }
    }
    None
}

/// Render a TOML value, redacting known-secret settings.
fn render_toml_value_redacted(key: &str, value: &toml::Value) -> String {
    if is_secret_setting(key) {
        if let toml::Value::String(raw) = value {
            return crate::secrets::redact_value(raw);
        }
    }
    match value {
        toml::Value::String(s) => format!("{s:?}"),
        other => other.to_string(),
    }
}

/// Settings whose string values are credentials when non-empty.
fn is_secret_setting(key: &str) -> bool {
    matches!(
        key,
        "ldap.bind_password"
            | "licence.license_key"
            | "kerberos.keytab_path"
            | "auth.password_hash"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AdminUser, AdminUsersConf, AuthnChainConf, AuthnNodeCacheConf, AuthnSettingsConf,
        ConnectorEntry, ConnectorsConf, MqttUser, MqttUsersConf,
    };

    fn snapshot_with_forward(valid: bool) -> FullSnapshot {
        FullSnapshot {
            admin_users: AdminUsersConf { users: Vec::new() },
            mqtt_users: MqttUsersConf {
                users: Vec::new(),
                acls: Vec::new(),
            },
            rules: crate::RulesConf {
                rules: vec![crate::RuleEntry {
                    id: "r1".to_string(),
                    name: "r1".to_string(),
                    topic_filter: "a/#".to_string(),
                    sql_query: None,
                    enabled: true,
                    actions: vec![crate::RuleActionEntry::ForwardConnector {
                        connector_id: if valid {
                            "c1".to_string()
                        } else {
                            "missing".to_string()
                        },
                    }],
                }],
            },
            connectors: ConnectorsConf {
                connectors: if valid {
                    vec![ConnectorEntry {
                        id: "c1".to_string(),
                        connector_type: "webhook".to_string(),
                        enable: true,
                        config: String::new(),
                    }]
                } else {
                    Vec::new()
                },
            },
            authn_chain: AuthnChainConf::default(),
            authn_node_cache: AuthnNodeCacheConf::default(),
            authn_settings: AuthnSettingsConf::default(),
        }
    }

    #[test]
    fn whole_validation_accepts_linked_and_names_every_offender() {
        assert!(validate_whole(&snapshot_with_forward(true)).is_ok());
        let mut bad = snapshot_with_forward(false);
        bad.admin_users = AdminUsersConf {
            users: vec![AdminUser {
                username: String::new(),
                password_hash: "h".to_string(),
                role: "viewer".to_string(),
                description: String::new(),
                must_change_password: false,
            }],
        };
        bad.mqtt_users = MqttUsersConf {
            users: vec![MqttUser {
                username: "u".to_string(),
                password_hash: String::new(),
                max_connections: None,
                max_publish_rate: None,
                max_publish_burst: None,
            }],
            acls: Vec::new(),
        };
        let err = validate_whole(&bad).expect_err("must fail");
        let text = err.to_string();
        assert!(
            text.contains("admin_users.users[0].username"),
            "got: {text}"
        );
        assert!(
            text.contains("mqtt_users.users[0].password_hash"),
            "got: {text}"
        );
        assert!(text.contains("connector_id"), "got: {text}");
    }

    #[test]
    fn diff_reports_added_removed_and_changed_rows_sorted() {
        let old = FullSnapshot::default();
        let mut new = FullSnapshot::default();
        new.mqtt_users.users.push(MqttUser {
            username: "sensor".to_string(),
            password_hash: "h".to_string(),
            max_connections: None,
            max_publish_rate: None,
            max_publish_burst: None,
        });
        let diff = diff_snapshots(&old, &new);
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].setting, "mqtt_users.users[sensor]");
        assert_eq!(diff[0].old_value, "<absent>");
    }

    #[test]
    fn history_bounds_and_restores_through_validate_whole() {
        let history = ConfigHistory::new();
        let base = FullSnapshot::default();
        history.seed_boot(&base);
        assert_eq!(history.len(), 1);
        let mut next = base.clone();
        next.mqtt_users.users.push(MqttUser {
            username: "a".to_string(),
            password_hash: "h".to_string(),
            max_connections: None,
            max_publish_rate: None,
            max_publish_burst: None,
        });
        validate_whole(&next).expect("valid");
        let id = history.record("tester", "add user a", &base, &next);
        assert_eq!(id, 1);
        assert_eq!(history.get(1).expect("version").actor, "tester");
        assert!(history.get(999).is_none());
    }
}
