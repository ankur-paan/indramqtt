//! Removed Kerberos authenticator (B1-01, T-77).
//!
//! The previous implementation accepted self-described plaintext tokens
//! without contacting a KDC and returned a constant session key, so any
//! client could authenticate as any principal. That implementation has
//! been deleted.
//!
//! This stub keeps the configuration shape so existing configuration
//! files still deserialize, but every authentication attempt fails
//! closed with an explicit "not supported" error. No input
//! authenticates through this path.

use crate::{AuthError, Authenticator, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Retained Kerberos configuration shape for compatibility.
///
/// Deserializing old configuration keeps working; authentication never
/// succeeds. A real implementation needs a KDC, a keytab and real
/// ASN.1 and is out of scope for this change.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KerberosConfig {
    #[serde(default)]
    pub service_principal_name: String,
    #[serde(default)]
    pub realm: String,
    #[serde(default)]
    pub allowed_realms: Vec<String>,
}

/// Stub authenticator that refuses every attempt.
///
/// No ticket is parsed, no session key is issued, and no principal is
/// authorized under any input.
pub struct KerberosAuthenticator {
    _config: KerberosConfig,
}

impl KerberosAuthenticator {
    pub fn new(config: KerberosConfig) -> Self {
        Self { _config: config }
    }
}

#[async_trait]
impl Authenticator for KerberosAuthenticator {
    async fn authenticate(
        &self,
        client_id: &str,
        _username: Option<&str>,
        _password: Option<&[u8]>,
    ) -> Result<()> {
        Err(AuthError::AuthenticationFailed(format!(
            "{client_id} presented a kerberos token, but kerberos authentication is not supported (removed: no KDC verification)"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> KerberosConfig {
        KerberosConfig {
            service_principal_name: "mqtt/broker.enterprise.corp@ENTERPRISE.CORP".to_string(),
            realm: "ENTERPRISE.CORP".to_string(),
            allowed_realms: vec!["ENTERPRISE.CORP".to_string()],
        }
    }

    #[tokio::test]
    async fn legacy_plaintext_token_is_refused() {
        let auth = KerberosAuthenticator::new(config());
        // Old fake shape `KRB5:{client}:{service}:{realm}` that the removed
        // implementation accepted when the fields matched.
        let token = b"KRB5:operator@ENTERPRISE.CORP:mqtt/broker.enterprise.corp@ENTERPRISE.CORP:ENTERPRISE.CORP";
        let err = auth
            .authenticate("workstation-1", Some("operator"), Some(token))
            .await
            .expect_err("legacy plaintext token must be refused");
        assert!(
            matches!(err, AuthError::AuthenticationFailed(_)),
            "must fail closed, got: {err}"
        );
    }

    #[tokio::test]
    async fn legacy_ap_req_tagged_token_is_refused() {
        let auth = KerberosAuthenticator::new(config());
        // Old fake shape: first byte 0x6E (AP-REQ tag), second byte length,
        // then the same plaintext payload.
        let payload = b"KRB5:operator@ENTERPRISE.CORP:mqtt/broker.enterprise.corp@ENTERPRISE.CORP:ENTERPRISE.CORP";
        assert!(
            payload.len() < 256,
            "test payload must fit in one length byte"
        );
        let mut token = Vec::with_capacity(2 + payload.len());
        token.push(0x6E);
        token.push(payload.len() as u8);
        token.extend_from_slice(payload);
        let err = auth
            .authenticate("workstation-1", Some("operator"), Some(&token))
            .await
            .expect_err("legacy 0x6E token must be refused");
        assert!(
            matches!(err, AuthError::AuthenticationFailed(_)),
            "must fail closed, got: {err}"
        );
    }

    #[tokio::test]
    async fn every_input_is_refused() {
        let auth = KerberosAuthenticator::new(KerberosConfig::default());
        assert!(auth.authenticate("c", None, None).await.is_err());
        assert!(auth.authenticate("c", Some("alice"), None).await.is_err());
        assert!(auth
            .authenticate("c", None, Some(b"anything"))
            .await
            .is_err());
        assert!(auth
            .authenticate("c", Some("alice"), Some(b"anything"))
            .await
            .is_err());
    }
}
