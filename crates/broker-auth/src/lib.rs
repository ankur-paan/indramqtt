pub mod kerberos;
pub mod ldap;

pub use kerberos::{KerberosAuthenticator, KerberosConfig, KerberosTicket};
pub use ldap::{LdapAuthenticator, LdapConfig, LdapEntry};

use async_trait::async_trait;
use broker_protocol::{Topic, TopicFilter};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
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
#[derive(Debug, Default)]
pub struct MemoryAuth {
    users: RwLock<HashMap<String, UserEntry>>,
    rules: RwLock<Vec<AclRule>>,
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

    /// Store (or replace) a username with its password digest.
    /// Existing quotas survive a password change.
    pub fn add_user(&self, username: impl Into<String>, password: &[u8]) {
        let username = username.into();
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

    pub fn remove_user(&self, username: &str) -> bool {
        self.users.write().remove(username).is_some()
    }

    pub fn user_count(&self) -> usize {
        self.users.read().len()
    }

    /// Attach quota bounds to an existing user (false when unknown).
    pub fn set_quotas(&self, username: &str, quotas: UserQuotas) -> bool {
        match self.users.write().get_mut(username) {
            Some(entry) => {
                entry.quotas = quotas;
                true
            }
            None => false,
        }
    }

    /// Quota bounds for a user (`None` when unknown).
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

    /// Append an ACL rule (first match wins).
    pub fn add_rule(&self, rule: AclRule) {
        self.rules.write().push(rule);
    }

    /// Ordered snapshot of the ACL for management display.
    pub fn acl_rules(&self) -> Vec<AclRule> {
        self.rules.read().clone()
    }

    pub fn clear_rules(&self) {
        self.rules.write().clear();
    }

    pub fn remove_rule(&self, index: usize) -> bool {
        let mut rules = self.rules.write();
        if index < rules.len() {
            rules.remove(index);
            true
        } else {
            false
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
        auth.add_user("alice", b"s3cret");
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

        assert!(auth.remove_user("alice"));
        assert!(!auth.remove_user("alice"));
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

        auth.add_user("alice", b"s3cret");
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
        auth.add_user("alice", b"n3w");
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
        assert!(auth.remove_user("alice"));
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
        ));
        auth.add_rule(AclRule::new("sensor-9", AclAction::All, "#", false));
        auth.add_rule(AclRule::new("*", AclAction::Subscribe, "#", true));

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
        ));

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
        auth.add_rule(AclRule::new("pub-only", AclAction::Publish, "#", true));

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
        auth.add_rule(AclRule::new("+", AclAction::Publish, "#", true));
        assert!(auth.authorize_publish("edge-1", &topic("a")).await.is_ok());
        // Exact patterns still require equality.
        auth.add_rule(AclRule::new("nope", AclAction::Publish, "#", false));
        assert!(auth.authorize_publish("edge-1", &topic("a")).await.is_ok());
    }
}
