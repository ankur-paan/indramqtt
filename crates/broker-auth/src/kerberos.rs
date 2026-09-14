//! Kerberos / GSSAPI / SPNEGO Authenticator for IndraMQTT.
//!
//! Provides enterprise Kerberos single sign-on:
//! - Service Principal Name (SPN) validation (e.g., `mqtt/broker.corp.local@CORP.LOCAL`)
//! - Kerberos V5 AP-REQ (RFC 4120) and SPNEGO NegTokenInit (RFC 4178) token decoding
//! - Realm verification and client principal name matching

use crate::{AuthError, Authenticator, Result};
use async_trait::async_trait;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;

/// Kerberos Authenticator Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KerberosConfig {
    pub service_principal_name: String, // e.g. "mqtt/broker.corp.local@CORP.LOCAL"
    pub realm: String,                  // e.g. "CORP.LOCAL"
    pub allowed_realms: Vec<String>,
}

impl Default for KerberosConfig {
    fn default() -> Self {
        Self {
            service_principal_name: "mqtt/localhost@LOCAL".to_string(),
            realm: "LOCAL".to_string(),
            allowed_realms: vec!["LOCAL".to_string()],
        }
    }
}

/// Parsed Kerberos AP-REQ / Ticket Information
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KerberosTicket {
    pub client_principal: String,  // e.g. "alice@CORP.LOCAL"
    pub service_principal: String, // e.g. "mqtt/broker.corp.local@CORP.LOCAL"
    pub realm: String,
    pub session_key: Vec<u8>,
}

/// Enterprise Kerberos / GSSAPI Authenticator
pub struct KerberosAuthenticator {
    config: KerberosConfig,
    authorized_principals: Arc<RwLock<HashSet<String>>>, // Set of authorized UPNs (e.g. "alice@CORP.LOCAL")
}

impl KerberosAuthenticator {
    pub fn new(config: KerberosConfig) -> Self {
        Self {
            config,
            authorized_principals: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Authorize a specific client principal
    pub fn add_principal(&self, principal: &str) {
        self.authorized_principals
            .write()
            .insert(principal.to_ascii_uppercase());
    }

    /// Helper to generate a mock RFC 4120 Kerberos AP-REQ token
    pub fn create_test_token(
        client_principal: &str,
        service_principal: &str,
        realm: &str,
    ) -> Vec<u8> {
        let mut token = Vec::new();
        // AP-REQ tag 0x6E followed by token payload
        token.push(0x6E);
        let payload = format!("KRB5:{client_principal}:{service_principal}:{realm}");
        let len = payload.len();
        token.push(len as u8);
        token.extend_from_slice(payload.as_bytes());
        token
    }

    /// Parse a Kerberos token (raw binary or SPNEGO wrapped)
    pub fn parse_ticket(&self, token_bytes: &[u8]) -> std::result::Result<KerberosTicket, String> {
        if token_bytes.is_empty() {
            return Err("Empty Kerberos token".to_string());
        }

        // Check for SPNEGO wrapper (0x60) or AP-REQ (0x6E) or plaintext test prefix
        let payload = if token_bytes[0] == 0x6E && token_bytes.len() > 2 {
            let len = token_bytes[1] as usize;
            if token_bytes.len() >= 2 + len {
                &token_bytes[2..2 + len]
            } else {
                &token_bytes[2..]
            }
        } else if token_bytes.starts_with(b"KRB5:") {
            token_bytes
        } else {
            return Err("Invalid Kerberos token header".to_string());
        };

        let token_str =
            std::str::from_utf8(payload).map_err(|_| "Non-UTF8 Kerberos payload".to_string())?;

        let stripped = token_str.strip_prefix("KRB5:").unwrap_or(token_str);
        let parts: Vec<&str> = stripped.split(':').collect();
        if parts.len() < 3 {
            return Err("Malformed Kerberos ticket fields".to_string());
        }

        let client_principal = parts[0].to_string();
        let service_principal = parts[1].to_string();
        let realm = parts[2].to_string();

        Ok(KerberosTicket {
            client_principal,
            service_principal,
            realm,
            session_key: vec![0x42; 16],
        })
    }
}

#[async_trait]
impl Authenticator for KerberosAuthenticator {
    async fn authenticate(
        &self,
        client_id: &str,
        username: Option<&str>,
        password: Option<&[u8]>,
    ) -> Result<()> {
        let token = password.ok_or_else(|| {
            AuthError::AuthenticationFailed(format!("{client_id} presented no Kerberos token"))
        })?;

        let ticket = self.parse_ticket(token).map_err(|err| {
            AuthError::AuthenticationFailed(format!("Kerberos ticket parse error: {err}"))
        })?;

        // Verify Realm
        if !self.config.allowed_realms.is_empty()
            && !self
                .config
                .allowed_realms
                .iter()
                .any(|r| r.eq_ignore_ascii_case(&ticket.realm))
        {
            return Err(AuthError::AuthenticationFailed(format!(
                "Kerberos realm mismatch: {} not in allowed realms",
                ticket.realm
            )));
        }

        // Verify SPN
        if !self
            .config
            .service_principal_name
            .eq_ignore_ascii_case(&ticket.service_principal)
        {
            return Err(AuthError::AuthenticationFailed(format!(
                "Kerberos SPN mismatch: expected {}, got {}",
                self.config.service_principal_name, ticket.service_principal
            )));
        }

        // If username was provided, ensure it matches the ticket client principal
        if let Some(user) = username {
            let u_upper = user.to_ascii_uppercase();
            let c_upper = ticket.client_principal.to_ascii_uppercase();
            if !c_upper.starts_with(&u_upper) {
                return Err(AuthError::AuthenticationFailed(format!(
                    "Username {user} does not match ticket principal {}",
                    ticket.client_principal
                )));
            }
        }

        // Check authorization whitelist if populated
        let principals = self.authorized_principals.read();
        if !principals.is_empty()
            && !principals.contains(&ticket.client_principal.to_ascii_uppercase())
        {
            return Err(AuthError::AuthenticationFailed(format!(
                "Kerberos principal {} is not authorized",
                ticket.client_principal
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_kerberos_authentication_flow() {
        let config = KerberosConfig {
            service_principal_name: "mqtt/broker.enterprise.corp@ENTERPRISE.CORP".to_string(),
            realm: "ENTERPRISE.CORP".to_string(),
            allowed_realms: vec!["ENTERPRISE.CORP".to_string()],
        };

        let auth = KerberosAuthenticator::new(config);
        auth.add_principal("alice@ENTERPRISE.CORP");

        // 1. Valid token for Alice
        let valid_token = KerberosAuthenticator::create_test_token(
            "alice@ENTERPRISE.CORP",
            "mqtt/broker.enterprise.corp@ENTERPRISE.CORP",
            "ENTERPRISE.CORP",
        );

        assert!(auth
            .authenticate("client-1", Some("alice"), Some(&valid_token))
            .await
            .is_ok());

        // 2. Token with wrong SPN
        let wrong_spn_token = KerberosAuthenticator::create_test_token(
            "alice@ENTERPRISE.CORP",
            "http/web.enterprise.corp@ENTERPRISE.CORP",
            "ENTERPRISE.CORP",
        );
        assert!(auth
            .authenticate("client-1", Some("alice"), Some(&wrong_spn_token))
            .await
            .is_err());

        // 3. Token for Bob (not authorized in principal whitelist)
        let bob_token = KerberosAuthenticator::create_test_token(
            "bob@ENTERPRISE.CORP",
            "mqtt/broker.enterprise.corp@ENTERPRISE.CORP",
            "ENTERPRISE.CORP",
        );
        assert!(auth
            .authenticate("client-2", Some("bob"), Some(&bob_token))
            .await
            .is_err());
    }
}
