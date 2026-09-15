//! Kernel-owned configuration registry.
//!
//! The registry holds one validated struct per configuration root
//! (admin users, MQTT users/ACLs, rules, connectors) inside a single
//! [`FullSnapshot`]. Readers take lock-free snapshots through
//! `arc_swap::ArcSwap`; writers go through an explicit `commit` that
//! validates the incoming root before it can become visible, so invalid
//! state is never observable. Persistence is a TOML document
//! (`state.toml`) written atomically (write-temp-then-rename with an
//! fsync before the rename).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Name of the persistence file inside the state directory.
pub const STATE_FILE_NAME: &str = "state.toml";

/// Connector types the kernel knows how to instantiate.
///
/// Mirrors the sink kinds registered in `broker-connectors` (`kind()`
/// values plus the `webhook`/`console`/`mqtt_bridge` management aliases).
/// Unknown types are rejected at validation time so a typo can never be
/// persisted.
pub const KNOWN_CONNECTOR_TYPES: &[&str] = &[
    "alloydb",
    "aws_iot",
    "azure_blob",
    "azure_eventhubs",
    "azure_iot",
    "bigquery",
    "cassandra",
    "clickhouse",
    "cockroachdb",
    "confluent",
    "console",
    "couchbase",
    "databricks",
    "datalayers",
    "disk_log",
    "doris",
    "dynamodb",
    "elasticsearch",
    "gcp_iot",
    "gcp_pubsub",
    "greptimedb",
    "http",
    "influxdb",
    "iotdb",
    "kafka",
    "kinesis",
    "mongodb",
    "mqtt",
    "mqtt_bridge",
    "mssql",
    "mysql",
    "oci_streaming",
    "opc_ua",
    "opentsdb",
    "oracle",
    "postgres",
    "pulsar",
    "rabbitmq",
    "redis",
    "redshift",
    "rocketmq",
    "s3",
    "s3_tables",
    "snowflake",
    "sparkplug_b",
    "tablestore",
    "tdengine",
    "test",
    "timescaledb",
    "timestream",
    "webhook",
];

/// Returns true for a connector type the kernel can instantiate.
#[must_use]
pub fn is_known_connector_type(kind: &str) -> bool {
    KNOWN_CONNECTOR_TYPES.contains(&kind)
}

/// Returns true for an ACL action the kernel can evaluate
/// (`publish`, `subscribe` or `all`, case-insensitive).
#[must_use]
pub fn is_known_acl_action(action: &str) -> bool {
    matches!(
        action.to_ascii_lowercase().as_str(),
        "publish" | "subscribe" | "all"
    )
}

/// Errors produced by validation, loading and saving configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// A root failed validation. The message always names the field.
    #[error("{0}")]
    Invalid(String),
    /// The state file could not be read, parsed or validated.
    /// Always names the file and the underlying field/reason.
    #[error("config file {file}: {reason}")]
    Load { file: String, reason: String },
    /// The snapshot could not be serialised or written.
    #[error("config save failed for {file}: {reason}")]
    Save { file: String, reason: String },
}

/// One dashboard/API administrator.
///
/// `password_hash` holds the SCRAM-SHA-256 verifier written by the
/// management API store (never plaintext); the registry treats it as an
/// opaque non-empty string. `role` is `administrator` or `viewer`
/// (missing roles from pre-persistence files load as `viewer`, the least
/// privilege). `must_change_password` forces a password change on next
/// login, matching the in-memory store flag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminUser {
    /// Login name; must be non-empty and unique within the root.
    pub username: String,
    /// Password hash; must be non-empty.
    pub password_hash: String,
    /// Management role (`administrator` or `viewer`).
    #[serde(default = "default_admin_user_role")]
    pub role: String,
    /// Free-form description shown by the user list.
    #[serde(default)]
    pub description: String,
    /// Whether the next login must change the password.
    #[serde(default)]
    pub must_change_password: bool,
}

impl Default for AdminUser {
    fn default() -> Self {
        Self {
            username: String::new(),
            password_hash: String::new(),
            description: String::new(),
            role: default_admin_user_role(),
            must_change_password: false,
        }
    }
}

/// Serde default for a missing admin role: least privilege.
fn default_admin_user_role() -> String {
    "viewer".to_string()
}

/// Root: dashboard/API administrators.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AdminUsersConf {
    #[serde(default)]
    pub users: Vec<AdminUser>,
}

impl AdminUsersConf {
    /// Validates usernames (non-empty, unique), password hashes and roles.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut seen = HashSet::with_capacity(self.users.len());
        for (index, user) in self.users.iter().enumerate() {
            if user.username.trim().is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "admin_users.users[{index}].username must not be empty (field `username`)"
                )));
            }
            if user.password_hash.is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "admin_users.users[{index}].password_hash must not be empty (field `password_hash`)"
                )));
            }
            if user.role != "administrator" && user.role != "viewer" {
                return Err(ConfigError::Invalid(format!(
                    "admin_users.users[{index}].role {:?} is unknown (field `role`)",
                    user.role
                )));
            }
            if !seen.insert(user.username.clone()) {
                return Err(ConfigError::Invalid(format!(
                    "admin_users.users[{index}].username {:?} is duplicated (field `username`)",
                    user.username
                )));
            }
        }
        Ok(())
    }
}

/// One MQTT credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MqttUser {
    /// Client username; must be non-empty and unique within the root.
    pub username: String,
    /// Password hash; must be non-empty.
    pub password_hash: String,
}

/// One ACL entry attached to an MQTT user.
///
/// `username` is the client-id pattern (`*` matches every client),
/// `topic` the MQTT topic filter, `action` one of `publish`,
/// `subscribe` or `all` (case-insensitive), and `allow` selects an
/// allow (`true`) or deny (`false`) entry. The four fields map 1:1 onto
/// `broker_auth::AclRule`, so a snapshot round-trip preserves the exact
/// first-match-wins decision. Entries written before `allow` existed
/// load as `true` (allow), preserving their historical meaning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AclConf {
    /// Username this entry applies to; must name a non-empty user.
    pub username: String,
    /// Topic filter; must be non-empty.
    pub topic: String,
    /// Action (`publish`, `subscribe` or `all`); must be non-empty.
    pub action: String,
    /// Whether the entry allows (`true`) or denies (`false`) access.
    #[serde(default = "default_acl_allow")]
    pub allow: bool,
}

/// Serde default for a missing ACL permission: historical entries only
/// expressed allows, so they keep meaning allow.
fn default_acl_allow() -> bool {
    true
}

/// Root: MQTT users and their ACLs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MqttUsersConf {
    #[serde(default)]
    pub users: Vec<MqttUser>,
    #[serde(default)]
    pub acls: Vec<AclConf>,
}

impl MqttUsersConf {
    /// Validates users (non-empty, unique, password present) and ACLs.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut seen = HashSet::with_capacity(self.users.len());
        for (index, user) in self.users.iter().enumerate() {
            if user.username.trim().is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "mqtt_users.users[{index}].username must not be empty (field `username`)"
                )));
            }
            if user.password_hash.is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "mqtt_users.users[{index}].password_hash must not be empty (field `password_hash`)"
                )));
            }
            if !seen.insert(user.username.clone()) {
                return Err(ConfigError::Invalid(format!(
                    "mqtt_users.users[{index}].username {:?} is duplicated (field `username`)",
                    user.username
                )));
            }
        }
        for (index, acl) in self.acls.iter().enumerate() {
            if acl.username.trim().is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "mqtt_users.acls[{index}].username must not be empty (field `username`)"
                )));
            }
            if acl.topic.trim().is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "mqtt_users.acls[{index}].topic must not be empty (field `topic`)"
                )));
            }
            if acl.action.trim().is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "mqtt_users.acls[{index}].action must not be empty (field `action`)"
                )));
            }
            if !is_known_acl_action(&acl.action) {
                return Err(ConfigError::Invalid(format!(
                    "mqtt_users.acls[{index}].action {:?} is unknown (field `action`)",
                    acl.action
                )));
            }
        }
        Ok(())
    }
}

/// One persisted rule action: the full lossless form of
/// `broker_rules::RuleAction` (every variant field round-trips; no
/// display-string coercion).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum RuleActionEntry {
    /// Republish to `topic` with MQTT wire QoS 0/1/2.
    Republish {
        /// Destination topic; must be non-empty.
        topic: String,
        /// MQTT wire QoS (0, 1 or 2).
        qos: u8,
    },
    /// Emit a structured log line for the matched event.
    Log,
    /// Forward to a registered external connector by id.
    ForwardConnector {
        /// Connector id; must be non-empty.
        connector_id: String,
    },
}

/// Serde default for a missing rule enable flag: historical entries
/// predate the flag and were always enabled.
fn default_rule_enabled() -> bool {
    true
}

/// One routing rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RuleEntry {
    /// Rule id; must be non-empty and unique within the root.
    pub id: String,
    /// Rule name; free-form (pre-persistence files load as empty).
    #[serde(default)]
    pub name: String,
    /// MQTT topic filter; must be non-empty.
    pub topic_filter: String,
    /// Optional streaming-SQL program (`None` = match without SQL).
    /// Pre-persistence files always carry a string, which loads as
    /// `Some`; a present but empty string is rejected at validation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sql_query: Option<String>,
    /// Whether the rule evaluates at ingress.
    #[serde(default = "default_rule_enabled")]
    pub enabled: bool,
    /// Full action list in execution order.
    #[serde(default)]
    pub actions: Vec<RuleActionEntry>,
}

/// Root: routing rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RulesConf {
    #[serde(default)]
    pub rules: Vec<RuleEntry>,
}

impl RulesConf {
    /// Validates rule ids (non-empty, unique), required fields and the
    /// full action list.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut seen = HashSet::with_capacity(self.rules.len());
        for (index, rule) in self.rules.iter().enumerate() {
            if rule.id.trim().is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "rules.rules[{index}].id must not be empty (field `id`)"
                )));
            }
            if rule.topic_filter.trim().is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "rules.rules[{index}].topic_filter must not be empty (field `topic_filter`)"
                )));
            }
            if let Some(sql) = rule.sql_query.as_ref() {
                if sql.trim().is_empty() {
                    return Err(ConfigError::Invalid(format!(
                        "rules.rules[{index}].sql_query must not be empty (field `sql_query`)"
                    )));
                }
            }
            for (action_index, action) in rule.actions.iter().enumerate() {
                match action {
                    RuleActionEntry::Republish { topic, qos } => {
                        if topic.trim().is_empty() {
                            return Err(ConfigError::Invalid(format!(
                                "rules.rules[{index}].actions[{action_index}].topic must not be empty (field `topic`)"
                            )));
                        }
                        if *qos > 2 {
                            return Err(ConfigError::Invalid(format!(
                                "rules.rules[{index}].actions[{action_index}].qos {qos} is out of range (field `qos`)"
                            )));
                        }
                    }
                    RuleActionEntry::Log => {}
                    RuleActionEntry::ForwardConnector { connector_id } => {
                        if connector_id.trim().is_empty() {
                            return Err(ConfigError::Invalid(format!(
                                "rules.rules[{index}].actions[{action_index}].connector_id must not be empty (field `connector_id`)"
                            )));
                        }
                    }
                }
            }
            if !seen.insert(rule.id.clone()) {
                return Err(ConfigError::Invalid(format!(
                    "rules.rules[{index}].id {:?} is duplicated (field `id`)",
                    rule.id
                )));
            }
        }
        Ok(())
    }
}

/// Serde default for a missing connector enable flag: historical
/// entries predate the flag and were always enabled.
fn default_connector_enabled() -> bool {
    true
}

/// One data connector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ConnectorEntry {
    /// Connector id; must be non-empty and unique within the root.
    pub id: String,
    /// Connector type; must name a known connector (field `connector_type`).
    pub connector_type: String,
    /// Whether the connector is enabled (missing entries from
    /// pre-persistence files load as `true`, the historical behaviour).
    #[serde(default = "default_connector_enabled")]
    pub enable: bool,
    /// Opaque connector configuration (URL, table, …); may be empty.
    /// The management API stores the full connector params here as a
    /// JSON document (everything the create call accepts except the
    /// derived `status`/`node_status` display values, which are
    /// recomputed at read time and never persisted).
    #[serde(default)]
    pub config: String,
}

/// Root: data connectors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ConnectorsConf {
    #[serde(default)]
    pub connectors: Vec<ConnectorEntry>,
}

impl ConnectorsConf {
    /// Validates ids (non-empty, unique) and connector types (known).
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut seen = HashSet::with_capacity(self.connectors.len());
        for (index, connector) in self.connectors.iter().enumerate() {
            if connector.id.trim().is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "connectors.connectors[{index}].id must not be empty (field `id`)"
                )));
            }
            if connector.connector_type.trim().is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "connectors.connectors[{index}].connector_type must not be empty (field `connector_type`)"
                )));
            }
            if !is_known_connector_type(&connector.connector_type) {
                return Err(ConfigError::Invalid(format!(
                    "connectors.connectors[{index}].connector_type {:?} is unknown (field `connector_type`)",
                    connector.connector_type
                )));
            }
            if !seen.insert(connector.id.clone()) {
                return Err(ConfigError::Invalid(format!(
                    "connectors.connectors[{index}].id {:?} is duplicated (field `id`)",
                    connector.id
                )));
            }
        }
        Ok(())
    }
}

/// The full validated configuration: all roots in one snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FullSnapshot {
    #[serde(default)]
    pub admin_users: AdminUsersConf,
    #[serde(default)]
    pub mqtt_users: MqttUsersConf,
    #[serde(default)]
    pub rules: RulesConf,
    #[serde(default)]
    pub connectors: ConnectorsConf,
}

impl FullSnapshot {
    /// Validates every root. Empty defaults are valid.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.admin_users.validate()?;
        self.mqtt_users.validate()?;
        self.rules.validate()?;
        self.connectors.validate()?;
        Ok(())
    }
}

/// One validated root ready to be committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigRoot {
    /// Validated admin-users root.
    AdminUsers(AdminUsersConf),
    /// Validated MQTT-users root.
    MqttUsers(MqttUsersConf),
    /// Validated rules root.
    Rules(RulesConf),
    /// Validated connectors root.
    Connectors(ConnectorsConf),
}

static SAVE_TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn state_path(dir: &Path) -> PathBuf {
    dir.join(STATE_FILE_NAME)
}

/// Kernel-owned configuration registry.
///
/// Readers call [`ConfigRegistry::snapshot`], which loads the current
/// [`FullSnapshot`] through `ArcSwap` without taking any lock.
/// Writers call [`ConfigRegistry::commit`] (or one of the per-root
/// helpers), which validates the incoming root before swapping it into
/// view; invalid state can never become visible. [`ConfigRegistry::save`]
/// persists the current snapshot atomically.
#[derive(Debug)]
pub struct ConfigRegistry {
    dir: PathBuf,
    current: ArcSwap<FullSnapshot>,
}

impl ConfigRegistry {
    /// Loads the registry from `<dir>/state.toml`.
    ///
    /// A missing file yields validated defaults (all roots empty). A
    /// corrupt file or a validation failure is an error naming the file
    /// and the field; defaults are never silently substituted.
    pub fn load(dir: &Path) -> Result<Self, ConfigError> {
        let file = state_path(dir);
        let snapshot = if !file.exists() {
            let defaults = FullSnapshot::default();
            defaults.validate().map_err(|err| ConfigError::Load {
                file: file.display().to_string(),
                reason: err.to_string(),
            })?;
            defaults
        } else {
            let text = std::fs::read_to_string(&file).map_err(|err| ConfigError::Load {
                file: file.display().to_string(),
                reason: format!("cannot read file: {err}"),
            })?;
            let parsed: FullSnapshot = toml::from_str(&text).map_err(|err| ConfigError::Load {
                file: file.display().to_string(),
                reason: format!("invalid TOML: {err}"),
            })?;
            parsed.validate().map_err(|err| ConfigError::Load {
                file: file.display().to_string(),
                reason: err.to_string(),
            })?;
            parsed
        };
        Ok(Self {
            dir: dir.to_path_buf(),
            current: ArcSwap::from(Arc::new(snapshot)),
        })
    }

    /// Returns the directory this registry persists into.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Takes a lock-free snapshot of the current configuration.
    #[must_use]
    pub fn snapshot(&self) -> Arc<FullSnapshot> {
        self.current.load_full()
    }

    /// Commits one validated root, swapping it into view atomically.
    ///
    /// The root is validated before the swap; on failure the visible
    /// snapshot is unchanged.
    pub fn commit(&self, root: ConfigRoot) -> Result<(), ConfigError> {
        match root {
            ConfigRoot::AdminUsers(conf) => self.commit_admin_users(conf),
            ConfigRoot::MqttUsers(conf) => self.commit_mqtt_users(conf),
            ConfigRoot::Rules(conf) => self.commit_rules(conf),
            ConfigRoot::Connectors(conf) => self.commit_connectors(conf),
        }
    }

    /// Commits a validated admin-users root.
    pub fn commit_admin_users(&self, conf: AdminUsersConf) -> Result<(), ConfigError> {
        conf.validate()?;
        self.current.rcu(|snapshot| {
            let mut next = (**snapshot).clone();
            next.admin_users = conf.clone();
            next
        });
        Ok(())
    }

    /// Commits a validated MQTT-users root.
    pub fn commit_mqtt_users(&self, conf: MqttUsersConf) -> Result<(), ConfigError> {
        conf.validate()?;
        self.current.rcu(|snapshot| {
            let mut next = (**snapshot).clone();
            next.mqtt_users = conf.clone();
            next
        });
        Ok(())
    }

    /// Commits a validated rules root.
    pub fn commit_rules(&self, conf: RulesConf) -> Result<(), ConfigError> {
        conf.validate()?;
        self.current.rcu(|snapshot| {
            let mut next = (**snapshot).clone();
            next.rules = conf.clone();
            next
        });
        Ok(())
    }

    /// Commits a validated connectors root.
    pub fn commit_connectors(&self, conf: ConnectorsConf) -> Result<(), ConfigError> {
        conf.validate()?;
        self.current.rcu(|snapshot| {
            let mut next = (**snapshot).clone();
            next.connectors = conf.clone();
            next
        });
        Ok(())
    }

    /// Serialises the current snapshot to TOML and writes it atomically.
    ///
    /// The snapshot is written to a unique temp file in the same
    /// directory, fsynced, then renamed over `state.toml`, so readers
    /// never observe a half-written file and no temp file is left behind.
    pub fn save(&self) -> Result<(), ConfigError> {
        let file = state_path(&self.dir);
        let text = toml::to_string(&*self.snapshot()).map_err(|err| ConfigError::Save {
            file: file.display().to_string(),
            reason: format!("cannot serialise snapshot: {err}"),
        })?;
        self.write_atomic(&file, text.as_bytes())
    }

    fn write_atomic(&self, file: &Path, bytes: &[u8]) -> Result<(), ConfigError> {
        let save_error = |reason: String| ConfigError::Save {
            file: file.display().to_string(),
            reason,
        };
        std::fs::create_dir_all(&self.dir)
            .map_err(|err| save_error(format!("cannot create directory: {err}")))?;
        let counter = SAVE_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = self.dir.join(format!(
            ".{STATE_FILE_NAME}.{}.tmp",
            u64::from(std::process::id()) * 1_000_000 + counter
        ));
        let write_result = (|| -> std::io::Result<()> {
            use std::io::Write as _;
            let mut handle = std::fs::File::create(&tmp)?;
            handle.write_all(bytes)?;
            handle.sync_all()?;
            drop(handle);
            std::fs::rename(&tmp, file)?;
            Ok(())
        })();
        if let Err(err) = write_result {
            let _ = std::fs::remove_file(&tmp);
            return Err(save_error(format!("cannot write file: {err}")));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "broker-config-{prefix}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create test dir");
        dir
    }

    fn sample_snapshot() -> FullSnapshot {
        FullSnapshot {
            admin_users: AdminUsersConf {
                users: vec![AdminUser {
                    username: "admin".to_string(),
                    password_hash: "hash-admin".to_string(),
                    role: "administrator".to_string(),
                    description: "Default administrator".to_string(),
                    must_change_password: true,
                }],
            },
            mqtt_users: MqttUsersConf {
                users: vec![MqttUser {
                    username: "sensor".to_string(),
                    password_hash: "hash-sensor".to_string(),
                }],
                acls: vec![AclConf {
                    username: "sensor".to_string(),
                    topic: "sensors/#".to_string(),
                    action: "all".to_string(),
                    allow: true,
                }],
            },
            rules: RulesConf {
                rules: vec![RuleEntry {
                    id: "rule-1".to_string(),
                    name: "rule-1".to_string(),
                    topic_filter: "sensors/#".to_string(),
                    sql_query: Some("SELECT * FROM 'sensors/#'".to_string()),
                    enabled: true,
                    actions: Vec::new(),
                }],
            },
            connectors: ConnectorsConf {
                connectors: vec![ConnectorEntry {
                    id: "mysql-main".to_string(),
                    connector_type: "mysql".to_string(),
                    enable: true,
                    config: "mysql://root:pw@127.0.0.1:3306/db".to_string(),
                }],
            },
        }
    }

    #[test]
    fn admin_validation_rejects_empty_username() {
        let conf = AdminUsersConf {
            users: vec![AdminUser {
                username: String::new(),
                password_hash: "hash".to_string(),
                role: "viewer".to_string(),
                description: String::new(),
                must_change_password: false,
            }],
        };
        let err = conf.validate().expect_err("empty username must fail");
        assert!(
            err.to_string().contains("username"),
            "error must name the field, got: {err}"
        );
    }

    #[test]
    fn rules_validation_rejects_duplicate_id() {
        let rule = RuleEntry {
            id: "rule-1".to_string(),
            name: "rule-1".to_string(),
            topic_filter: "a/#".to_string(),
            sql_query: Some("SELECT * FROM 'a/#'".to_string()),
            enabled: true,
            actions: Vec::new(),
        };
        let conf = RulesConf {
            rules: vec![rule.clone(), rule],
        };
        let err = conf.validate().expect_err("duplicate rule id must fail");
        let text = err.to_string();
        assert!(
            text.contains("id"),
            "error must name the field, got: {text}"
        );
        assert!(
            text.contains("rule-1"),
            "error must name the key, got: {text}"
        );
    }

    #[test]
    fn connectors_validation_rejects_empty_id() {
        let conf = ConnectorsConf {
            connectors: vec![ConnectorEntry {
                id: String::new(),
                connector_type: "mysql".to_string(),
                enable: true,
                config: String::new(),
            }],
        };
        let err = conf.validate().expect_err("empty connector id must fail");
        assert!(
            err.to_string().contains("id"),
            "error must name the field, got: {err}"
        );
    }

    #[test]
    fn connectors_validation_rejects_unknown_type() {
        let conf = ConnectorsConf {
            connectors: vec![ConnectorEntry {
                id: "c1".to_string(),
                connector_type: "not-a-connector".to_string(),
                enable: true,
                config: String::new(),
            }],
        };
        let err = conf.validate().expect_err("unknown type must fail");
        let text = err.to_string();
        assert!(
            text.contains("connector_type"),
            "error must name the field, got: {text}"
        );
        assert!(
            text.contains("not-a-connector"),
            "error must name the value, got: {text}"
        );
    }

    #[test]
    fn round_trip_save_load_preserves_all_roots() {
        let dir = unique_dir("roundtrip");
        let registry = ConfigRegistry::load(&dir).expect("defaults load");
        registry
            .commit(ConfigRoot::AdminUsers(sample_snapshot().admin_users))
            .expect("commit admin");
        registry
            .commit_mqtt_users(sample_snapshot().mqtt_users)
            .expect("commit mqtt");
        registry
            .commit_rules(sample_snapshot().rules)
            .expect("commit rules");
        registry
            .commit_connectors(sample_snapshot().connectors)
            .expect("commit connectors");
        registry.save().expect("save");
        let reloaded = ConfigRegistry::load(&dir).expect("reload");
        assert_eq!(*reloaded.snapshot(), sample_snapshot());
    }

    #[test]
    fn atomic_write_leaves_no_temp_file_behind() {
        let dir = unique_dir("atomic");
        let registry = ConfigRegistry::load(&dir).expect("defaults load");
        registry
            .commit_admin_users(sample_snapshot().admin_users)
            .expect("commit admin");
        registry.save().expect("save");
        assert!(state_path(&dir).exists(), "state.toml must exist");
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .expect("read dir")
            .map(std::io::Result::unwrap)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".tmp") || name.contains(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "no temp file may remain, found: {leftovers:?}"
        );
    }

    #[test]
    fn corrupt_toml_errors_without_booting_defaults() {
        let dir = unique_dir("corrupt");
        std::fs::write(state_path(&dir), "[[[ not valid toml {{{").expect("write corrupt");
        let err = ConfigRegistry::load(&dir).expect_err("corrupt file must fail");
        let text = err.to_string();
        assert!(
            text.contains(STATE_FILE_NAME),
            "error must name the file, got: {text}"
        );
    }

    #[test]
    fn invalid_snapshot_on_disk_errors_naming_the_field() {
        let dir = unique_dir("invalid");
        let mut snapshot = sample_snapshot();
        snapshot.rules.rules[0].id.clear();
        let text = toml::to_string(&snapshot).expect("serialise invalid");
        std::fs::write(state_path(&dir), text).expect("write invalid");
        let err = ConfigRegistry::load(&dir).expect_err("invalid file must fail");
        let message = err.to_string();
        assert!(
            message.contains(STATE_FILE_NAME),
            "error must name the file, got: {message}"
        );
        assert!(
            message.contains("id"),
            "error must name the field, got: {message}"
        );
    }

    #[test]
    fn concurrent_snapshot_readers_never_observe_half_committed_update() {
        let dir = unique_dir("concurrent");
        let registry = Arc::new(ConfigRegistry::load(&dir).expect("defaults load"));
        let before = registry.snapshot();
        assert!(before.rules.rules.is_empty());
        assert!(before.admin_users.users.is_empty());

        let after_admin = AdminUsersConf {
            users: vec![AdminUser {
                username: "admin".to_string(),
                password_hash: "hash".to_string(),
                role: "administrator".to_string(),
                description: String::new(),
                must_change_password: false,
            }],
        };
        let after_rules = RulesConf {
            rules: vec![RuleEntry {
                id: "rule-1".to_string(),
                name: "rule-1".to_string(),
                topic_filter: "sensors/#".to_string(),
                sql_query: Some("SELECT * FROM 'sensors/#'".to_string()),
                enabled: true,
                actions: Vec::new(),
            }],
        };

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let registry = Arc::clone(&registry);
                std::thread::spawn(move || {
                    for _ in 0..500 {
                        let snapshot = registry.snapshot();
                        let admin_count = snapshot.admin_users.users.len();
                        let rule_count = snapshot.rules.rules.len();
                        // The two roots are committed back-to-back; a reader
                        // must see a coherent snapshot where both commits are
                        // individually whole (each root is 0 or 1 entries,
                        // never torn inside one root).
                        assert!(admin_count <= 1, "torn admin root: {admin_count}");
                        assert!(rule_count <= 1, "torn rules root: {rule_count}");
                        if admin_count == 1 {
                            assert_eq!(snapshot.admin_users.users[0].username, "admin");
                        }
                        if rule_count == 1 {
                            assert_eq!(snapshot.rules.rules[0].id, "rule-1");
                        }
                    }
                })
            })
            .collect();
        registry
            .commit_admin_users(after_admin)
            .expect("commit admin");
        registry.commit_rules(after_rules).expect("commit rules");
        for handle in handles {
            handle.join().expect("reader thread");
        }
        let final_snapshot = registry.snapshot();
        assert_eq!(final_snapshot.admin_users.users.len(), 1);
        assert_eq!(final_snapshot.rules.rules.len(), 1);
    }

    #[test]
    fn commit_rejects_invalid_root_without_changing_visible_state() {
        let dir = unique_dir("commit-guard");
        let registry = ConfigRegistry::load(&dir).expect("defaults load");
        let bad = RulesConf {
            rules: vec![RuleEntry {
                id: String::new(),
                name: String::new(),
                topic_filter: "a/#".to_string(),
                sql_query: Some("SELECT 1".to_string()),
                enabled: true,
                actions: Vec::new(),
            }],
        };
        let err = registry
            .commit(ConfigRoot::Rules(bad))
            .expect_err("invalid commit must fail");
        assert!(err.to_string().contains("id"));
        assert!(registry.snapshot().rules.rules.is_empty());
    }

    #[test]
    fn missing_file_boots_validated_defaults() {
        let dir = unique_dir("defaults");
        let registry = ConfigRegistry::load(&dir).expect("missing file loads defaults");
        assert_eq!(*registry.snapshot(), FullSnapshot::default());
    }
}
