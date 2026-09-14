//! LDAP Active Directory and OpenLDAP Authenticator for IndraMQTT.
//!
//! Provides enterprise LDAP identity integration:
//! - Configurable Server URL, Base DN, Bind DN template, and User Filter
//! - In-memory directory simulation for testing and embedded deployments
//! - Attribute mapping and multi-tenant domain search

use crate::{AuthError, Authenticator, Result};
use async_trait::async_trait;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Configuration for LDAP Authenticator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapConfig {
    pub server_url: String,
    pub base_dn: String,
    pub bind_dn_template: String, // e.g. "uid={username},ou=users,dc=example,dc=com" or "cn={username},dc=ad,dc=corp"
    pub filter_template: String,  // e.g. "(&(objectClass=person)(uid={username}))"
    pub timeout_ms: u64,
}

impl Default for LdapConfig {
    fn default() -> Self {
        Self {
            server_url: "ldap://localhost:389".to_string(),
            base_dn: "dc=example,dc=com".to_string(),
            bind_dn_template: "uid={username},ou=users,dc=example,dc=com".to_string(),
            filter_template: "(&(objectClass=person)(uid={username}))".to_string(),
            timeout_ms: 5000,
        }
    }
}

/// Simulated LDAP Entry stored in local directory
#[derive(Debug, Clone)]
pub struct LdapEntry {
    pub dn: String,
    pub password: Vec<u8>,
    pub attributes: HashMap<String, String>,
}

/// Enterprise LDAP Authenticator
pub struct LdapAuthenticator {
    config: LdapConfig,
    directory: Arc<RwLock<HashMap<String, LdapEntry>>>, // dn -> entry
}

impl LdapAuthenticator {
    pub fn new(config: LdapConfig) -> Self {
        Self {
            config,
            directory: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add an entry to the directory for local validation
    pub fn add_entry(&self, dn: &str, password: &[u8], attributes: HashMap<String, String>) {
        self.directory.write().insert(
            dn.to_ascii_lowercase(),
            LdapEntry {
                dn: dn.to_string(),
                password: password.to_vec(),
                attributes,
            },
        );
    }

    /// Resolve Bind DN for a given username using configured template
    pub fn resolve_bind_dn(&self, username: &str) -> String {
        self.config.bind_dn_template.replace("{username}", username)
    }

    /// Format LDAP search filter for a given username
    pub fn format_filter(&self, username: &str) -> String {
        self.config.filter_template.replace("{username}", username)
    }

    /// Retrieve an entry by DN
    pub fn get_entry(&self, dn: &str) -> Option<LdapEntry> {
        self.directory.read().get(&dn.to_ascii_lowercase()).cloned()
    }
}

#[async_trait]
impl Authenticator for LdapAuthenticator {
    async fn authenticate(
        &self,
        client_id: &str,
        username: Option<&str>,
        password: Option<&[u8]>,
    ) -> Result<()> {
        let username = username.ok_or_else(|| {
            AuthError::AuthenticationFailed(format!("{client_id} presented no LDAP username"))
        })?;

        let password = password.ok_or_else(|| {
            AuthError::AuthenticationFailed(format!("{client_id} presented no LDAP password"))
        })?;

        let bind_dn = self.resolve_bind_dn(username);
        let dir = self.directory.read();

        // Search directory for the resolved DN
        if let Some(entry) = dir.get(&bind_dn.to_ascii_lowercase()) {
            if entry.password.as_slice() == password {
                Ok(())
            } else {
                Err(AuthError::AuthenticationFailed(format!(
                    "LDAP bind failed for {username} (invalid credentials)"
                )))
            }
        } else {
            // Also search by matching attribute 'uid' or 'cn' or 'sAMAccountName' if DN doesn't match directly
            let found = dir.values().find(|e| {
                e.attributes.get("uid").map(|s| s.as_str()) == Some(username)
                    || e.attributes.get("cn").map(|s| s.as_str()) == Some(username)
                    || e.attributes.get("sAMAccountName").map(|s| s.as_str()) == Some(username)
            });

            if let Some(entry) = found {
                if entry.password.as_slice() == password {
                    Ok(())
                } else {
                    Err(AuthError::AuthenticationFailed(format!(
                        "LDAP bind failed for {username} (invalid credentials)"
                    )))
                }
            } else {
                Err(AuthError::AuthenticationFailed(format!(
                    "LDAP user not found: {username} (DN: {bind_dn})"
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ldap_authentication_bind_dn() {
        let config = LdapConfig {
            server_url: "ldap://ad.corp.local:389".to_string(),
            base_dn: "dc=corp,dc=local".to_string(),
            bind_dn_template: "cn={username},ou=Engineers,dc=corp,dc=local".to_string(),
            filter_template: "(&(objectClass=user)(sAMAccountName={username}))".to_string(),
            timeout_ms: 3000,
        };

        let auth = LdapAuthenticator::new(config);

        let mut attrs = HashMap::new();
        attrs.insert("sAMAccountName".to_string(), "john_doe".to_string());
        attrs.insert("mail".to_string(), "john.doe@corp.local".to_string());

        auth.add_entry(
            "cn=john_doe,ou=Engineers,dc=corp,dc=local",
            b"LDAP_Super_Secret_2026!",
            attrs,
        );

        // Success: valid username & password
        assert!(auth
            .authenticate(
                "client-1",
                Some("john_doe"),
                Some(b"LDAP_Super_Secret_2026!")
            )
            .await
            .is_ok());

        // Failure: wrong password
        assert!(auth
            .authenticate("client-1", Some("john_doe"), Some(b"wrong_pass"))
            .await
            .is_err());

        // Failure: non-existent user
        assert!(auth
            .authenticate("client-1", Some("jane_smith"), Some(b"some_pass"))
            .await
            .is_err());
    }
}
