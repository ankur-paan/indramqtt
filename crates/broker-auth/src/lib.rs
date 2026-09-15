pub mod kerberos;
pub mod ldap;

pub use kerberos::{KerberosAuthenticator, KerberosConfig, KerberosTicket};
pub use ldap::{LdapAuthenticator, LdapConfig, LdapEntry};

use async_trait::async_trait;
use broker_config::{AclConf, ConfigRegistry, MqttUser, MqttUsersConf};
use broker_protocol::{Topic, TopicFilter};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Authentication failed for client {0}")]
    AuthenticationFailed(String),

    #[error("Permission denied: cannot publish to {0}")]
    PublishDenied(String),

    #[error("Permission denied: cannot subscribe to {0}")]
    SubscribeDenied(String),
}

pub type Result<T> = std::result::Result<T, AuthError>;

#[async_trait]
pub trait Authenticator: Send + Sync {
    async fn authenticate(
        &self,
        client_id: &str,
        username: Option<&str>,
        password: Option<&[u8]>,
    ) -> Result<()>;
}

#[async_trait]
pub trait Authorizer: Send + Sync {
    async fn authorize_publish(&self, client_id: &str, topic: &Topic) -> Result<()>;
    async fn authorize_subscribe(&self, client_id: &str, filter: &TopicFilter) -> Result<()>;
}

#[derive(Default)]
pub struct AllowAllAuth;

#[async_trait]
impl Authenticator for AllowAllAuth {
    async fn authenticate(
        &self,
        _client_id: &str,
        _username: Option<&str>,
        _password: Option<&[u8]>,
    ) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl Authorizer for AllowAllAuth {
    async fn authorize_publish(&self, _client_id: &str, _topic: &Topic) -> Result<()> {
        Ok(())
    }

    async fn authorize_subscribe(&self, _client_id: &str, _filter: &TopicFilter) -> Result<()> {
        Ok(())
    }
}

/// MQTT action gated by an ACL rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AclAction {
    Publish,
    Subscribe,
    All,
}

impl AclAction {
    /// Parse `publish` | `subscribe` | `all` (case-insensitive).
    pub fn parse(action: &str) -> Option<Self> {
        match action.to_ascii_lowercase().as_str() {
            "publish" => Some(AclAction::Publish),
            "subscribe" => Some(AclAction::Subscribe),
            "all" => Some(AclAction::All),
            _ => None,
        }
    }

    fn covers(self, action: AclAction) -> bool {
        self == AclAction::All || self == action
    }
}

/// One ordered ACL entry: first match wins.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclRule {
    pub client_pattern: String,
    pub action: AclAction,
    pub topic_pattern: String,
    pub allow: bool,
}

impl AclRule {
    pub fn new(
        client_pattern: impl Into<String>,
        action: AclAction,
        topic_pattern: impl Into<String>,
        allow: bool,
    ) -> Self {
        Self {
            client_pattern: client_pattern.into(),
            action,
            topic_pattern: topic_pattern.into(),
            allow,
        }
    }

    fn client_matches(&self, client_id: &str) -> bool {
        if self.client_pattern == "*" || self.client_pattern == client_id {
            return true;
        }
        // Otherwise the pattern may use MQTT wildcards over the id.
        if !self.client_pattern.contains(['+', '#']) {
            return false;
        }
        TopicFilter::new(self.client_pattern.as_str())
            .and_then(|filter| Topic::new(client_id).map(|id| (filter, id)))
            .map(|(filter, id)| filter.matches(&id))
            .unwrap_or(false)
    }

    fn topic_matches(&self, topic: &Topic) -> bool {
        TopicFilter::new(self.topic_pattern.as_str())
            .map(|filter| filter.matches(topic))
            .unwrap_or(false)
    }

    /// Whether `filter` (a subscription request) is covered by this rule's
    /// topic pattern: every topic the request could match must also match
    /// the rule pattern. Level-wise: `#` (final) covers anything below,
    /// `+` covers exactly one level, anything else must equal.
    fn filter_covered(&self, filter: &TopicFilter) -> bool {
        let pattern_levels: Vec<&str> = self.topic_pattern.split('/').collect();
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
}

/// In-memory credentials + ACL authorizer.
///
/// Passwords are stored as SHA-256 digests (demo-grade: front with a
/// password-hashing KDF for production). With zero users configured the
/// broker is open; once users exist, unknown names and bad passwords
/// fail. With zero ACL rules everything is allowed; once rules exist the
/// first matching rule decides and anything unmatched is denied.
///
/// When built with [`MemoryAuth::from_registry`] (or seeded in place
/// with [`MemoryAuth::seed_from_registry`]) every user/ACL mutation
/// commits the exported [`MqttUsersConf`] root and atomically saves it,
/// so credentials and ACLs survive kernel restarts. Per-user quotas
/// ([`UserQuotas`]) are deliberately runtime-only and are not persisted:
/// a reload resets every user to unlimited quotas.
#[derive(Debug, Default)]
pub struct MemoryAuth {
    users: RwLock<HashMap<String, UserEntry>>,
    rules: RwLock<Vec<AclRule>>,
    /// Kernel config registry receiving every user/ACL mutation (`None`
    /// in unit tests and standalone state, which stay memory-only).
    registry: RwLock<Option<Arc<ConfigRegistry>>>,
    /// Serialises export-commit-save so concurrent mutations cannot
    /// interleave into a lost update on disk.
    save_lock: parking_lot::Mutex<()>,
}

/// Per-user multi-tenant quotas. Every bound is optional (`None` =
/// unlimited); unset quotas preserve the pre-quota open behavior.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct UserQuotas {
    pub max_connections: Option<u32>,
    pub max_publish_rate: Option<u32>,
    pub max_publish_burst: Option<u32>,
}

#[derive(Debug, Clone)]
struct UserEntry {
    password_hash: [u8; 32],
    quotas: UserQuotas,
}

impl MemoryAuth {
    pub fn new() -> Self {
        Self::default()
    }

    fn digest(password: &[u8]) -> [u8; 32] {
        Sha256::digest(password).into()
    }

    /// Seed from a validated snapshot root. An empty snapshot yields
    /// today's empty behaviour (open broker, everything allowed).
    /// Memory-only: mutations are not persisted.
    pub fn from_snapshot(conf: &MqttUsersConf) -> Self {
        let auth = Self::new();
        auth.seed_from_snapshot(conf);
        auth
    }

    /// Seed from the registry's current snapshot and persist every later
    /// user/ACL mutation back through it. This is the kernel boot path:
    /// an empty snapshot yields today's empty behaviour.
    pub fn from_registry(registry: &Arc<ConfigRegistry>) -> Self {
        let auth = Self::from_snapshot(&registry.snapshot().mqtt_users);
        *auth.registry.write() = Some(Arc::clone(registry));
        auth
    }

    /// Attach the registry and replace the current contents with its
    /// snapshot, in place on the same instance.
    ///
    /// The kernel boot path calls this on the single shared `MemoryAuth`
    /// (serving both the BrokerLink plane and `ApiState.auth`) so no
    /// second copy can diverge. Replacing is idempotent: seeding twice
    /// from the same snapshot yields identical decisions.
    pub fn seed_from_registry(&self, registry: &Arc<ConfigRegistry>) {
        self.seed_from_snapshot(&registry.snapshot().mqtt_users);
        *self.registry.write() = Some(Arc::clone(registry));
    }

    /// Replace users and rules with the snapshot contents. Password
    /// verifiers decode from their stored hex form without re-hashing;
    /// an undecodable verifier locks that account (a sentinel digest no
    /// password can match) instead of silently dropping the user, so the
    /// outage stays visible in `usernames()`. Quotas reset to unlimited.
    fn seed_from_snapshot(&self, conf: &MqttUsersConf) {
        let mut users = HashMap::with_capacity(conf.users.len());
        for entry in &conf.users {
            let password_hash = match decode_verifier(&entry.password_hash) {
                Some(hash) => hash,
                None => LOCKED_VERIFIER,
            };
            users.insert(
                entry.username.clone(),
                UserEntry {
                    password_hash,
                    quotas: UserQuotas::default(),
                },
            );
        }
        // Every entry reaching here through the registry is validated
        // (`MqttUsersConf::validate` rejects unknown actions at commit
        // and load), and `export_conf` only writes canonical spellings,
        // so `parse` succeeds on every round-trip. An unvalidated caller
        // passing an unknown action gets that entry skipped (deny-safe:
        // no rule means denied) rather than widened into `All`.
        let rules = conf
            .acls
            .iter()
            .filter_map(|entry| {
                AclAction::parse(&entry.action).map(|action| {
                    AclRule::new(
                        entry.username.clone(),
                        action,
                        entry.topic.clone(),
                        entry.allow,
                    )
                })
            })
            .collect();
        *self.users.write() = users;
        *self.rules.write() = rules;
    }

    /// Export the current contents as a validated config root: users
    /// sorted by username so the persisted file is deterministic, rules
    /// in evaluation order (first match wins, so order is significant).
    /// Passwords export as lowercase hex of the exact stored SHA-256
    /// digest (never plaintext, no scheme change).
    fn export_conf(&self) -> MqttUsersConf {
        let users = self.users.read();
        let mut entries: Vec<MqttUser> = users
            .iter()
            .map(|(username, entry)| MqttUser {
                username: username.clone(),
                password_hash: encode_verifier(&entry.password_hash),
            })
            .collect();
        entries.sort_by(|a, b| a.username.cmp(&b.username));
        let acls = self
            .rules
            .read()
            .iter()
            .map(|rule| AclConf {
                username: rule.client_pattern.clone(),
                topic: rule.topic_pattern.clone(),
                action: action_to_conf(rule.action).to_string(),
                allow: rule.allow,
            })
            .collect();
        MqttUsersConf {
            users: entries,
            acls,
        }
    }

    /// Commit the exported root and atomically save it. A no-op without
    /// a registry; any commit or save failure surfaces as
    /// [`broker_config::ConfigError`] so callers answer 500 and the loss
    /// is never silent.
    fn persist(&self) -> std::result::Result<(), broker_config::ConfigError> {
        let Some(registry) = self.registry.read().clone() else {
            return Ok(());
        };
        let _guard = self.save_lock.lock();
        let conf = self.export_conf();
        registry.commit_mqtt_users(conf)?;
        registry.save()?;
        Ok(())
    }

    /// Store (or replace) a username with its password digest.
    /// Existing quotas survive a password change. Persists through the
    /// registry when one is attached; a save failure is returned and the
    /// in-memory update stays (commit precedes the atomic save).
    pub fn add_user(
        &self,
        username: impl Into<String>,
        password: &[u8],
    ) -> std::result::Result<(), broker_config::ConfigError> {
        let username = username.into();
        {
            let mut users = self.users.write();
            let quotas = users
                .get(&username)
                .map(|entry| entry.quotas.clone())
                .unwrap_or_default();
            users.insert(
                username,
                UserEntry {
                    password_hash: Self::digest(password),
                    quotas,
                },
            );
        }
        self.persist()
    }

    /// Remove a user (false when unknown; unknown names persist nothing).
    /// Persists through the registry when one is attached.
    pub fn remove_user(
        &self,
        username: &str,
    ) -> std::result::Result<bool, broker_config::ConfigError> {
        let removed = self.users.write().remove(username).is_some();
        if removed {
            self.persist()?;
        }
        Ok(removed)
    }

    pub fn user_count(&self) -> usize {
        self.users.read().len()
    }

    /// Attach quota bounds to an existing user (false when unknown).
    /// Memory-only: quotas are never persisted (see [`MemoryAuth`]).
    pub fn set_quotas(&self, username: &str, quotas: UserQuotas) -> bool {
        match self.users.write().get_mut(username) {
            Some(entry) => {
                entry.quotas = quotas;
                true
            }
            None => false,
        }
    }

    /// Quota bounds for a user (`None` when unknown). Quotas are
    /// runtime-only and are never persisted (see [`MemoryAuth`]).
    pub fn get_quotas(&self, username: &str) -> Option<UserQuotas> {
        self.users
            .read()
            .get(username)
            .map(|entry| entry.quotas.clone())
    }

    /// Sorted usernames (passwords are write-only, never listed).
    pub fn usernames(&self) -> Vec<String> {
        let mut names: Vec<String> = self.users.read().keys().cloned().collect();
        names.sort();
        names
    }

    /// Append an ACL rule (first match wins). Persists through the
    /// registry when one is attached.
    pub fn add_rule(&self, rule: AclRule) -> std::result::Result<(), broker_config::ConfigError> {
        self.rules.write().push(rule);
        self.persist()
    }

    /// Ordered snapshot of the ACL for management display.
    pub fn acl_rules(&self) -> Vec<AclRule> {
        self.rules.read().clone()
    }

    /// Drop every ACL rule. Persists through the registry when one is
    /// attached (a no-op on an already-empty list persists nothing).
    pub fn clear_rules(&self) -> std::result::Result<(), broker_config::ConfigError> {
        if self.rules.read().is_empty() {
            return Ok(());
        }
        self.rules.write().clear();
        self.persist()
    }

    /// Remove the rule at `index` (false when out of bounds; out of
    /// bounds persists nothing). Persists through the registry when one
    /// is attached.
    pub fn remove_rule(
        &self,
        index: usize,
    ) -> std::result::Result<bool, broker_config::ConfigError> {
        let mut rules = self.rules.write();
        if index < rules.len() {
            rules.remove(index);
            drop(rules);
            self.persist()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn check(
        &self,
        client_id: &str,
        action: AclAction,
        matches_rule: impl Fn(&AclRule) -> bool,
    ) -> bool {
        let rules = self.rules.read();
        if rules.is_empty() {
            return true;
        }
        for rule in rules.iter() {
            if rule.client_matches(client_id) && rule.action.covers(action) && matches_rule(rule) {
                return rule.allow;
            }
        }
        false
    }
}

#[async_trait]
impl Authenticator for MemoryAuth {
    async fn authenticate(
        &self,
        client_id: &str,
        username: Option<&str>,
        password: Option<&[u8]>,
    ) -> Result<()> {
        let users = self.users.read();
        if users.is_empty() {
            return Ok(());
        }
        let (username, password) = match (username, password) {
            (Some(username), Some(password)) => (username, password),
            _ => {
                return Err(AuthError::AuthenticationFailed(format!(
                    "{client_id} presented no credentials"
                )))
            }
        };
        match users.get(username) {
            Some(entry) if entry.password_hash == MemoryAuth::digest(password) => Ok(()),
            _ => Err(AuthError::AuthenticationFailed(format!(
                "{client_id} presented bad credentials"
            ))),
        }
    }
}

#[async_trait]
impl Authorizer for MemoryAuth {
    async fn authorize_publish(&self, client_id: &str, topic: &Topic) -> Result<()> {
        let topic = topic.clone();
        if self.check(client_id, AclAction::Publish, |rule| {
            rule.topic_matches(&topic)
        }) {
            Ok(())
        } else {
            Err(AuthError::PublishDenied(format!(
                "{client_id} cannot publish"
            )))
        }
    }

    async fn authorize_subscribe(&self, client_id: &str, filter: &TopicFilter) -> Result<()> {
        let filter = filter.clone();
        if self.check(client_id, AclAction::Subscribe, |rule| {
            rule.filter_covered(&filter)
        }) {
            Ok(())
        } else {
            Err(AuthError::SubscribeDenied(format!(
                "{client_id} cannot subscribe"
            )))
        }
    }
}

/// Sentinel digest for accounts whose stored verifier cannot be decoded
/// (for example a hand-edited `state.toml` bypassing validation). No
/// password hashes to it (SHA-256 preimage), so the account stays locked
/// instead of silently opening or vanishing.
const LOCKED_VERIFIER: [u8; 32] = [0xA5; 32];

/// Lowercase hex of the exact stored SHA-256 digest (the persisted
/// password-verifier form; no plaintext, no scheme change).
fn encode_verifier(hash: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in hash {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0F) as usize] as char);
    }
    out
}

/// Decode the stored hex verifier (`None` when malformed).
fn decode_verifier(raw: &str) -> Option<[u8; 32]> {
    if raw.len() != 64 || !raw.is_ascii() {
        return None;
    }
    let bytes = raw.as_bytes();
    let mut hash = [0u8; 32];
    for (index, slot) in hash.iter_mut().enumerate() {
        let hi = hex_value(bytes[2 * index])?;
        let lo = hex_value(bytes[2 * index + 1])?;
        *slot = (hi << 4) | lo;
    }
    Some(hash)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Canonical config spelling of an [`AclAction`] (matches
/// [`AclAction::parse`]).
fn action_to_conf(action: AclAction) -> &'static str {
    match action {
        AclAction::Publish => "publish",
        AclAction::Subscribe => "subscribe",
        AclAction::All => "all",
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

    #[tokio::test]
    async fn test_authenticate_open_mode_without_users() {
        let auth = MemoryAuth::new();
        // No users configured: everything (even credentialed) passes.
        assert!(auth.authenticate("anon", None, None).await.is_ok());
        assert!(auth
            .authenticate("someone", Some("u"), Some(b"p"))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_authenticate_valid_and_invalid_passwords() {
        let auth = MemoryAuth::new();
        auth.add_user("alice", b"s3cret")
            .expect("memory-only persist cannot fail");
        assert_eq!(auth.user_count(), 1);

        assert!(auth
            .authenticate("device-1", Some("alice"), Some(b"s3cret"))
            .await
            .is_ok());
        assert!(auth
            .authenticate("device-1", Some("alice"), Some(b"wrong"))
            .await
            .is_err());
        assert!(auth
            .authenticate("device-1", Some("mallory"), Some(b"s3cret"))
            .await
            .is_err());
        assert!(auth.authenticate("device-1", None, None).await.is_err());

        assert!(auth
            .remove_user("alice")
            .expect("memory-only persist cannot fail"));
        assert!(!auth
            .remove_user("alice")
            .expect("memory-only persist cannot fail"));
        // Back to open mode once the last user is gone.
        assert!(auth.authenticate("anon", None, None).await.is_ok());
    }

    #[tokio::test]
    async fn test_user_quotas_roundtrip() {
        let auth = MemoryAuth::new();
        assert!(auth.get_quotas("alice").is_none());
        assert!(!auth.set_quotas(
            "alice",
            UserQuotas {
                max_connections: Some(100),
                max_publish_rate: None,
                max_publish_burst: None,
            }
        ));

        auth.add_user("alice", b"s3cret")
            .expect("memory-only persist cannot fail");
        assert_eq!(
            auth.get_quotas("alice"),
            Some(UserQuotas::default()),
            "fresh users start unlimited"
        );
        assert!(auth.set_quotas(
            "alice",
            UserQuotas {
                max_connections: Some(100),
                max_publish_rate: Some(50),
                max_publish_burst: Some(10),
            }
        ));
        assert_eq!(
            auth.get_quotas("alice"),
            Some(UserQuotas {
                max_connections: Some(100),
                max_publish_rate: Some(50),
                max_publish_burst: Some(10),
            })
        );

        // Password rotation preserves quotas.
        auth.add_user("alice", b"n3w")
            .expect("memory-only persist cannot fail");
        assert!(auth
            .authenticate("d", Some("alice"), Some(b"n3w"))
            .await
            .is_ok());
        assert_eq!(
            auth.get_quotas("alice")
                .expect("quotas survive")
                .max_connections,
            Some(100)
        );

        // Removing the user drops quotas with it.
        assert!(auth
            .remove_user("alice")
            .expect("memory-only persist cannot fail"));
        assert!(auth.get_quotas("alice").is_none());
    }

    #[tokio::test]
    async fn test_acl_open_mode_without_rules() {
        let auth = MemoryAuth::new();
        assert!(auth.authorize_publish("any", &topic("a/b")).await.is_ok());
        assert!(auth
            .authorize_subscribe("any", &filter("a/#"))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_acl_allow_and_deny_with_first_match_wins() {
        let auth = MemoryAuth::new();
        auth.add_rule(AclRule::new(
            "sensor-1",
            AclAction::Publish,
            "sensors/#",
            true,
        ))
        .expect("memory-only persist cannot fail");
        auth.add_rule(AclRule::new("sensor-9", AclAction::All, "#", false))
            .expect("memory-only persist cannot fail");
        auth.add_rule(AclRule::new("*", AclAction::Subscribe, "#", true))
            .expect("memory-only persist cannot fail");

        // sensor-1 publishes under sensors/: allowed by rule 1.
        assert!(auth
            .authorize_publish("sensor-1", &topic("sensors/temp"))
            .await
            .is_ok());
        // sensor-1 outside its branch: no rule matches -> denied.
        assert!(auth
            .authorize_publish("sensor-1", &topic("actuators/door"))
            .await
            .is_err());
        // sensor-9 is explicitly denied everything despite rule 3.
        assert!(auth
            .authorize_publish("sensor-9", &topic("sensors/temp"))
            .await
            .is_err());
        assert!(auth
            .authorize_subscribe("sensor-9", &filter("sensors/+"))
            .await
            .is_err());
        // Subscribes for everyone else fall through to the catch-all allow.
        assert!(auth
            .authorize_subscribe("random", &filter("a/b"))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_acl_subscribe_needs_covering_pattern() {
        let auth = MemoryAuth::new();
        auth.add_rule(AclRule::new(
            "*",
            AclAction::Subscribe,
            "sensors/temp",
            true,
        ))
        .expect("memory-only persist cannot fail");

        // Exact grant covers the exact request.
        assert!(auth
            .authorize_subscribe("c", &filter("sensors/temp"))
            .await
            .is_ok());
        // A concrete grant never covers a broader wildcard request.
        assert!(auth
            .authorize_subscribe("c", &filter("sensors/+"))
            .await
            .is_err());
        assert!(auth.authorize_subscribe("c", &filter("#")).await.is_err());
    }

    #[tokio::test]
    async fn test_acl_action_scoping() {
        let auth = MemoryAuth::new();
        auth.add_rule(AclRule::new("pub-only", AclAction::Publish, "#", true))
            .expect("memory-only persist cannot fail");

        assert!(auth
            .authorize_publish("pub-only", &topic("x"))
            .await
            .is_ok());
        // Publish-only grant does not cover subscribes.
        assert!(auth
            .authorize_subscribe("pub-only", &filter("x"))
            .await
            .is_err());
    }
    #[test]
    fn test_acl_action_parse() {
        assert_eq!(AclAction::parse("publish"), Some(AclAction::Publish));
        assert_eq!(AclAction::parse("SUBSCRIBE"), Some(AclAction::Subscribe));
        assert_eq!(AclAction::parse("All"), Some(AclAction::All));
        assert_eq!(AclAction::parse("delete"), None);
    }

    #[tokio::test]
    async fn test_acl_client_mqtt_wildcard_pattern() {
        let auth = MemoryAuth::new();
        // "+" as a full pattern matches any slash-free client id.
        auth.add_rule(AclRule::new("+", AclAction::Publish, "#", true))
            .expect("memory-only persist cannot fail");
        assert!(auth.authorize_publish("edge-1", &topic("a")).await.is_ok());
        // Exact patterns still require equality.
        auth.add_rule(AclRule::new("nope", AclAction::Publish, "#", false))
            .expect("memory-only persist cannot fail");
        assert!(auth.authorize_publish("edge-1", &topic("a")).await.is_ok());
    }

    /// Unique scratch data dir under the OS temp dir (no dev-dependency).
    fn unique_data_dir(prefix: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "broker-auth-{prefix}-{}-{nanos}",
            std::process::id()
        ))
    }

    /// Seed one registry-backed store with users plus representative
    /// allow and deny rules (mirrors the probe matrix below).
    fn seed_restart_fixture(auth: &MemoryAuth) {
        auth.add_user("sensor-1", b"s3cret-1")
            .expect("persist fixture user");
        auth.add_user("sensor-9", b"s3cret-9")
            .expect("persist fixture user");
        for rule in [
            AclRule::new("sensor-1", AclAction::Publish, "sensors/#", true),
            AclRule::new("sensor-9", AclAction::All, "#", false),
            AclRule::new("*", AclAction::Subscribe, "#", true),
        ] {
            auth.add_rule(rule).expect("persist fixture rule");
        }
    }

    /// Probe matrix over (user, action, topic): each entry names the
    /// client, whether it publishes (`true`) or subscribes (`false`),
    /// the topic/filter, and the expected decision.
    fn restart_probes() -> Vec<(&'static str, bool, &'static str, bool)> {
        vec![
            ("sensor-1", true, "sensors/temp", true),
            ("sensor-1", true, "actuators/door", false),
            ("sensor-1", false, "sensors/temp", true),
            ("sensor-9", true, "sensors/temp", false),
            ("sensor-9", false, "sensors/+", false),
            ("random", false, "a/b", true),
            ("random", true, "a/b", false),
        ]
    }

    async fn check_restart_probes(auth: &MemoryAuth) {
        for (client, publish, target, allowed) in restart_probes() {
            let decision = if publish {
                auth.authorize_publish(client, &topic(target)).await.is_ok()
            } else {
                auth.authorize_subscribe(client, &filter(target))
                    .await
                    .is_ok()
            };
            assert_eq!(
                decision, allowed,
                "probe (client={client}, publish={publish}, target={target}) must be {allowed}"
            );
        }
    }

    #[tokio::test]
    async fn mqtt_users_acls_survive_restart() {
        let dir = unique_data_dir("restart");
        let registry =
            Arc::new(broker_config::ConfigRegistry::load(&dir).expect("fresh data dir loads"));
        let auth = MemoryAuth::from_registry(&registry);
        seed_restart_fixture(&auth);
        assert!(dir.join(broker_config::STATE_FILE_NAME).is_file());
        check_restart_probes(&auth).await;

        // Rebuild from the same data dir (simulating a kernel restart).
        let reloaded =
            Arc::new(broker_config::ConfigRegistry::load(&dir).expect("data dir reloads"));
        let restarted = MemoryAuth::from_registry(&reloaded);
        assert_eq!(restarted.usernames(), vec!["sensor-1", "sensor-9"]);
        check_restart_probes(&restarted).await;
        // The reloaded store still authenticates with the same passwords.
        assert!(restarted
            .authenticate("device-1", Some("sensor-1"), Some(b"s3cret-1"))
            .await
            .is_ok());
        assert!(restarted
            .authenticate("device-9", Some("sensor-9"), Some(b"s3cret-9"))
            .await
            .is_ok());
        assert!(restarted
            .authenticate("device-1", Some("sensor-1"), Some(b"wrong"))
            .await
            .is_err());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn mqtt_user_delete_survives_restart() {
        let dir = unique_data_dir("delete");
        let registry =
            Arc::new(broker_config::ConfigRegistry::load(&dir).expect("fresh data dir loads"));
        let auth = MemoryAuth::from_registry(&registry);
        seed_restart_fixture(&auth);
        assert!(auth.remove_user("sensor-1").expect("persist user delete"));

        // Rebuild from the same data dir: the deleted user stays gone.
        let reloaded =
            Arc::new(broker_config::ConfigRegistry::load(&dir).expect("data dir reloads"));
        let restarted = MemoryAuth::from_registry(&reloaded);
        assert_eq!(restarted.usernames(), vec!["sensor-9"]);
        assert!(
            restarted
                .authenticate("device-1", Some("sensor-1"), Some(b"s3cret-1"))
                .await
                .is_err(),
            "deleted user must not authenticate after restart"
        );
        assert!(restarted
            .authenticate("device-9", Some("sensor-9"), Some(b"s3cret-9"))
            .await
            .is_ok());

        std::fs::remove_dir_all(&dir).ok();
    }
}
