//! Real LDAP authentication (B2-01, T-86).
//!
//! Directory-backed authentication used at CONNECT. The flow is the
//! standard service-account pattern:
//!
//! 1. connect to `server_url` (`ldap://` or `ldaps://`)
//! 2. simple bind as the configured service account (`bind_dn`)
//! 3. search under `base_dn` with `user_filter` for the connecting user
//! 4. bind as the found entry DN with the supplied password to verify it
//! 5. check `required_group` against `group_attribute` when configured
//!
//! TLS verification is on by default for `ldaps://`. Private directories
//! supply their CA through `ca_cert_path` (PEM file). Timeouts and the
//! connection bound are configurable so a slow or unreachable directory
//! cannot stall the accept path. Any directory failure fails closed.
//!
//! Client: `ldap3` 0.12 (MIT/Apache-2.0), the maintained pure-Rust async
//! LDAP client. No protocol is hand-rolled and no credential map exists
//! in this crate.

use crate::{AuthError, Authenticator, Result};
use async_trait::async_trait;
use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// Default user search filter (`{username}` is the escaped login name).
fn default_user_filter() -> String {
    "(uid={username})".to_string()
}

/// Default group attribute read from the user entry (`memberOf`).
fn default_group_attribute() -> String {
    "memberOf".to_string()
}

/// Default bound on concurrent directory authentications.
fn default_pool_size() -> usize {
    8
}

/// Default connect timeout in milliseconds.
fn default_connect_timeout_ms() -> u64 {
    5_000
}

/// Default per-operation (bind/search) timeout in milliseconds.
fn default_read_timeout_ms() -> u64 {
    5_000
}

/// Default TLS verification (on).
fn default_tls_verify() -> bool {
    true
}

/// Directory authentication configuration.
///
/// `server_url` is `ldap://host:port` or `ldaps://host:port`. An empty
/// `server_url` disables the mechanism: every attempt fails closed.
/// `user_filter` must contain `{username}`, replaced with the
/// RFC 4515-escaped login name. `required_group` empty disables the group
/// check; otherwise the found entry must list it under `group_attribute`.
///
/// `pool_size` bounds concurrent directory authentications (default 8:
/// enough for CONNECT bursts, small enough to never overwhelm the
/// directory; each slot holds at most one TCP connection of a few KB).
/// `connect_timeout_ms` covers TCP connect plus TLS handshake;
/// `read_timeout_ms` covers each bind/search round-trip (default 5 s
/// each: slow-directory tolerant while keeping the accept path bounded).
///
/// `tls_verify` defaults to true. Private directories set `ca_cert_path`
/// to a PEM file holding their CA certificate, which is added to the
/// system roots for `ldaps://`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapConfig {
    #[serde(default)]
    pub server_url: String,
    #[serde(default)]
    pub base_dn: String,
    #[serde(default)]
    pub bind_dn: String,
    #[serde(default)]
    pub bind_password: String,
    #[serde(default = "default_user_filter")]
    pub user_filter: String,
    #[serde(default = "default_group_attribute")]
    pub group_attribute: String,
    #[serde(default)]
    pub required_group: String,
    #[serde(default = "default_pool_size")]
    pub pool_size: usize,
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_read_timeout_ms")]
    pub read_timeout_ms: u64,
    #[serde(default)]
    pub timeout_ms: u64,
    #[serde(default = "default_tls_verify")]
    pub tls_verify: bool,
    #[serde(default)]
    pub ca_cert_path: Option<String>,
    /// Legacy B1-02 fields, retained so old files still deserialize.
    /// Ignored by the real implementation.
    #[serde(default)]
    pub bind_dn_template: String,
    #[serde(default)]
    pub filter_template: String,
}

impl Default for LdapConfig {
    fn default() -> Self {
        Self {
            server_url: String::new(),
            base_dn: String::new(),
            bind_dn: String::new(),
            bind_password: String::new(),
            user_filter: default_user_filter(),
            group_attribute: default_group_attribute(),
            required_group: String::new(),
            pool_size: default_pool_size(),
            connect_timeout_ms: default_connect_timeout_ms(),
            read_timeout_ms: default_read_timeout_ms(),
            timeout_ms: 0,
            tls_verify: default_tls_verify(),
            ca_cert_path: None,
            bind_dn_template: String::new(),
            filter_template: String::new(),
        }
    }
}

impl LdapConfig {
    fn effective_pool_size(&self) -> usize {
        self.pool_size.clamp(1, 32)
    }

    fn effective_connect_timeout(&self) -> Duration {
        let ms = if self.connect_timeout_ms > 0 {
            self.connect_timeout_ms
        } else if self.timeout_ms > 0 {
            self.timeout_ms
        } else {
            default_connect_timeout_ms()
        };
        Duration::from_millis(ms.clamp(100, 60_000))
    }

    fn effective_read_timeout(&self) -> Duration {
        let ms = if self.read_timeout_ms > 0 {
            self.read_timeout_ms
        } else if self.timeout_ms > 0 {
            self.timeout_ms
        } else {
            default_read_timeout_ms()
        };
        Duration::from_millis(ms.clamp(100, 60_000))
    }
}

/// Escape a login name for embedding in an LDAP search filter (RFC 4515).
pub fn escape_ldap_filter(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '*' => out.push_str("\\2a"),
            '(' => out.push_str("\\28"),
            ')' => out.push_str("\\29"),
            '\\' => out.push_str("\\5c"),
            '\0' => out.push_str("\\00"),
            _ => out.push(ch),
        }
    }
    out
}

/// Real directory authenticator.
///
/// Holds no credential map: every attempt opens a directory connection
/// through `ldap3`. Concurrency is bounded by a semaphore (`pool_size`
/// permits); connections are short-lived per authentication so no bound
/// identity leaks between clients.
#[derive(Debug, Clone)]
pub struct LdapAuthenticator {
    config: LdapConfig,
    semaphore: Arc<Semaphore>,
}

impl LdapAuthenticator {
    pub fn new(config: LdapConfig) -> Self {
        let permits = config.effective_pool_size();
        Self {
            config,
            semaphore: Arc::new(Semaphore::new(permits)),
        }
    }

    pub fn config(&self) -> &LdapConfig {
        &self.config
    }

    fn fail(client_id: &str, reason: &str) -> AuthError {
        AuthError::AuthenticationFailed(format!("{client_id} {reason}"))
    }

    fn build_settings(&self) -> std::result::Result<LdapConnSettings, String> {
        let mut settings =
            LdapConnSettings::new().set_conn_timeout(self.config.effective_connect_timeout());
        let is_ldaps = self.config.server_url.starts_with("ldaps://");
        if is_ldaps {
            if !self.config.tls_verify {
                settings = settings.set_no_tls_verify(true);
            } else if let Some(path) = self.config.ca_cert_path.as_deref() {
                let pem =
                    std::fs::read(path).map_err(|e| format!("cannot read CA file {path}: {e}"))?;
                let cert = native_tls::Certificate::from_pem(&pem)
                    .map_err(|e| format!("cannot parse CA file {path}: {e}"))?;
                let mut builder = native_tls::TlsConnector::builder();
                builder.add_root_certificate(cert);
                let connector = builder
                    .build()
                    .map_err(|e| format!("cannot build TLS connector: {e}"))?;
                settings = settings.set_connector(connector);
            }
        }
        Ok(settings)
    }

    async fn connect(
        &self,
        settings: LdapConnSettings,
    ) -> std::result::Result<ldap3::Ldap, ldap3::LdapError> {
        let (conn, mut ldap) =
            LdapConnAsync::with_settings(settings, &self.config.server_url).await?;
        tokio::spawn(async move {
            let _ = conn.drive().await;
        });
        let _ = &mut ldap;
        Ok(ldap)
    }

    async fn authenticate_inner(&self, username: &str, password: &[u8]) -> Result<()> {
        if self.config.server_url.is_empty() {
            tracing::warn!("LDAP directory unavailable: server_url is not configured");
            return Err(Self::fail(
                "client",
                "presented LDAP credentials, but no directory is configured",
            ));
        }
        if !self.config.server_url.starts_with("ldap://")
            && !self.config.server_url.starts_with("ldaps://")
        {
            tracing::warn!(
                url = %self.config.server_url,
                "LDAP directory unavailable: server_url must start with ldap:// or ldaps://"
            );
            return Err(Self::fail(
                "client",
                "presented LDAP credentials, but the directory URL is invalid",
            ));
        }
        if self.config.base_dn.is_empty()
            || self.config.bind_dn.is_empty()
            || self.config.bind_password.is_empty()
        {
            tracing::warn!("LDAP directory unavailable: base_dn/bind_dn/bind_password incomplete");
            return Err(Self::fail(
                "client",
                "presented LDAP credentials, but the directory is misconfigured",
            ));
        }
        if !self.config.user_filter.contains("{username}") {
            tracing::warn!("LDAP directory unavailable: user_filter lacks {username}");
            return Err(Self::fail(
                "client",
                "presented LDAP credentials, but the directory is misconfigured",
            ));
        }
        let password_str = std::str::from_utf8(password).map_err(|_| {
            tracing::warn!("LDAP authentication failed: password is not UTF-8");
            Self::fail(
                "client",
                "presented LDAP credentials that cannot be verified",
            )
        })?;
        if password_str.is_empty() {
            return Err(Self::fail(
                "client",
                "presented LDAP credentials that cannot be verified",
            ));
        }

        let settings = self.build_settings().map_err(|detail| {
            tracing::warn!("LDAP directory unavailable: {detail}");
            Self::fail(
                "client",
                "presented LDAP credentials, but the directory is unavailable",
            )
        })?;

        let read_timeout = self.config.effective_read_timeout();
        let escaped = escape_ldap_filter(username);
        let filter = self.config.user_filter.replace("{username}", &escaped);

        // Service bind plus user search on one short-lived connection.
        let mut service = self.connect(settings.clone()).await.map_err(|e| {
            tracing::warn!("LDAP directory unavailable: service connect failed: {e}");
            Self::fail(
                "client",
                "presented LDAP credentials, but the directory is unavailable",
            )
        })?;
        let service_bind = service
            .with_timeout(read_timeout)
            .simple_bind(&self.config.bind_dn, &self.config.bind_password)
            .await
            .and_then(|r| r.success());
        if let Err(e) = service_bind {
            let _ = service.unbind().await;
            tracing::warn!("LDAP directory unavailable: service bind failed: {e}");
            return Err(Self::fail(
                "client",
                "presented LDAP credentials, but the directory is unavailable",
            ));
        }

        let group_attr = self.config.group_attribute.clone();
        let search = service
            .with_timeout(read_timeout)
            .search(
                &self.config.base_dn,
                Scope::Subtree,
                &filter,
                vec![group_attr.as_str()],
            )
            .await
            .and_then(|r| r.success());
        let (entries, _res) = match search {
            Ok(result) => result,
            Err(e) => {
                let _ = service.unbind().await;
                tracing::warn!("LDAP directory unavailable: search failed: {e}");
                return Err(Self::fail(
                    "client",
                    "presented LDAP credentials, but the directory is unavailable",
                ));
            }
        };
        if entries.len() != 1 {
            let _ = service.unbind().await;
            return Err(Self::fail(
                "client",
                "presented LDAP credentials that cannot be verified",
            ));
        }
        let Some(raw) = entries.into_iter().next() else {
            let _ = service.unbind().await;
            return Err(Self::fail(
                "client",
                "presented LDAP credentials that cannot be verified",
            ));
        };
        let entry = SearchEntry::construct(raw);
        // SearchEntry::construct panics on malformed BER; the branch above
        // only runs for real directory data. Guard the DN extraction:
        let user_dn = entry.dn.clone();
        if user_dn.is_empty() {
            let _ = service.unbind().await;
            return Err(Self::fail(
                "client",
                "presented LDAP credentials that cannot be verified",
            ));
        }
        let mut member_values: Vec<String> = Vec::new();
        for (name, values) in entry.attrs.iter() {
            if name.eq_ignore_ascii_case(&self.config.group_attribute) {
                member_values.extend(values.iter().cloned());
            }
        }
        let required = self.config.required_group.trim();
        let mut group_ok = required.is_empty()
            || member_values
                .iter()
                .any(|v| v.eq_ignore_ascii_case(required));
        // Fallback for directories without a memberOf overlay: look for a
        // group entry listing this user DN under `member`.
        if !group_ok && !required.is_empty() {
            let escaped_dn = escape_ldap_filter(&user_dn);
            let group_filter = format!("(member={escaped_dn})");
            match service
                .with_timeout(read_timeout)
                .search(
                    &self.config.base_dn,
                    Scope::Subtree,
                    &group_filter,
                    vec!["dn"],
                )
                .await
                .and_then(|r| r.success())
            {
                Ok((group_entries, _)) => {
                    for raw in group_entries {
                        let group = SearchEntry::construct(raw);
                        if group.dn.eq_ignore_ascii_case(required) {
                            group_ok = true;
                            break;
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("LDAP directory unavailable: group search failed: {e}");
                }
            }
        }
        let _ = service.unbind().await;
        if !group_ok {
            return Err(Self::fail(
                "client",
                "presented LDAP credentials without the required directory group",
            ));
        }

        // Verify the password with a fresh bind as the entry DN.
        let mut user_conn = self.connect(settings).await.map_err(|e| {
            tracing::warn!("LDAP directory unavailable: user connect failed: {e}");
            Self::fail(
                "client",
                "presented LDAP credentials, but the directory is unavailable",
            )
        })?;
        let verified = user_conn
            .with_timeout(read_timeout)
            .simple_bind(&user_dn, password_str)
            .await
            .and_then(|r| r.success());
        let _ = user_conn.unbind().await;
        match verified {
            Ok(_) => Ok(()),
            Err(_) => Err(Self::fail(
                "client",
                "presented LDAP credentials that cannot be verified",
            )),
        }
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
        let (Some(username), Some(password)) = (username, password) else {
            return Err(Self::fail(client_id, "presented no LDAP credentials"));
        };
        if username.is_empty() {
            return Err(Self::fail(client_id, "presented no LDAP credentials"));
        }
        let connect_timeout = self.config.effective_connect_timeout();
        let permit = tokio::time::timeout(connect_timeout, self.semaphore.acquire()).await;
        let _permit = match permit {
            Ok(Ok(guard)) => guard,
            Ok(Err(_)) => {
                tracing::warn!("LDAP directory unavailable: connection pool closed");
                return Err(Self::fail(
                    client_id,
                    "presented LDAP credentials, but the directory is unavailable",
                ));
            }
            Err(_) => {
                tracing::warn!(
                    "LDAP directory unavailable: connection pool exhausted, failing closed for {client_id}"
                );
                return Err(Self::fail(
                    client_id,
                    "presented LDAP credentials, but the directory is unavailable",
                ));
            }
        };
        self.authenticate_inner(username, password)
            .await
            .map_err(|e| match e {
                AuthError::AuthenticationFailed(msg) => {
                    // Re-tag with the real client id (inner uses a
                    // placeholder so group/outage paths share one shape).
                    // Preserve the outage wording for log correlation.
                    let suffix = msg.split_once(' ').map(|(_, rest)| rest).unwrap_or(&msg);
                    if msg.contains("unavailable")
                        || msg.contains("misconfigured")
                        || msg.contains("not configured")
                        || msg.contains("invalid")
                    {
                        tracing::warn!(
                            "LDAP authentication failed closed for {client_id}: {suffix}"
                        );
                    }
                    AuthError::AuthenticationFailed(format!("{client_id} {suffix}"))
                }
                other => other,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_escaping_blocks_injection() {
        assert_eq!(escape_ldap_filter("alice"), "alice");
        assert_eq!(escape_ldap_filter("a*b"), "a\\2ab");
        assert_eq!(escape_ldap_filter("a(b)c"), "a\\28b\\29c");
        assert_eq!(escape_ldap_filter("a\\b"), "a\\5cb");
        // A filter-injection attempt stays a literal value.
        assert_eq!(escape_ldap_filter("alice)(uid=*"), "alice\\29\\28uid=\\2a");
    }

    #[test]
    fn defaults_are_documented_values() {
        let config = LdapConfig::default();
        assert_eq!(config.user_filter, "(uid={username})");
        assert_eq!(config.group_attribute, "memberOf");
        assert_eq!(config.pool_size, 8);
        assert_eq!(config.connect_timeout_ms, 5_000);
        assert_eq!(config.read_timeout_ms, 5_000);
        assert!(config.tls_verify);
        assert!(config.ca_cert_path.is_none());
    }

    #[test]
    fn pool_size_is_clamped() {
        let config = LdapConfig {
            pool_size: 0,
            ..LdapConfig::default()
        };
        assert_eq!(config.effective_pool_size(), 1);
        let config = LdapConfig {
            pool_size: 1_000,
            ..LdapConfig::default()
        };
        assert_eq!(config.effective_pool_size(), 32);
    }

    #[test]
    fn legacy_timeout_ms_still_applies() {
        let config = LdapConfig {
            connect_timeout_ms: 0,
            read_timeout_ms: 0,
            timeout_ms: 2_000,
            ..LdapConfig::default()
        };
        assert_eq!(
            config.effective_connect_timeout(),
            Duration::from_millis(2_000)
        );
        assert_eq!(
            config.effective_read_timeout(),
            Duration::from_millis(2_000)
        );
    }

    #[tokio::test]
    async fn empty_config_fails_closed_without_network() {
        let auth = LdapAuthenticator::new(LdapConfig::default());
        assert!(
            auth.authenticate("c", None, None).await.is_err(),
            "missing credentials must fail"
        );
        assert!(
            auth.authenticate("c", Some("alice"), None).await.is_err(),
            "missing password must fail"
        );
        assert!(
            auth.authenticate("c", None, Some(b"pw")).await.is_err(),
            "missing username must fail"
        );
        // Empty server_url fails closed without opening a socket.
        assert!(auth
            .authenticate("c", Some("alice"), Some(b"pw"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn invalid_scheme_fails_closed_without_network() {
        let config = LdapConfig {
            server_url: "http://directory:389".to_string(),
            base_dn: "dc=example,dc=com".to_string(),
            bind_dn: "cn=reader,dc=example,dc=com".to_string(),
            bind_password: "readerpw".to_string(),
            ..LdapConfig::default()
        };
        let auth = LdapAuthenticator::new(config);
        assert!(auth
            .authenticate("c", Some("alice"), Some(b"pw"))
            .await
            .is_err());
    }

    // Integration tests against a real directory server (yamldap, a
    // pure-Rust LDAP server speaking the real wire protocol, not a trait
    // mock). Each test starts its own server on an ephemeral loopback
    // port with a fixed YAML directory.

    #[cfg(test)]
    mod directory {
        use super::super::*;
        use std::io::Write as _;

        const BASE_DN: &str = "dc=example,dc=com";
        const SERVICE_DN: &str = "cn=reader,dc=example,dc=com";
        const SERVICE_PW: &str = "readerpw";
        const REQUIRED_GROUP: &str = "cn=mqtt-users,ou=groups,dc=example,dc=com";

        fn write_directory(path: &std::path::Path) {
            let body = format!(
                r#"directory:
  base_dn: {BASE_DN}
entries:
  - dn: {BASE_DN}
    objectClass: [top, domain]
    dc: example
  - dn: ou=users,{BASE_DN}
    objectClass: [top, organizationalUnit]
    ou: users
  - dn: ou=groups,{BASE_DN}
    objectClass: [top, organizationalUnit]
    ou: groups
  - dn: {SERVICE_DN}
    objectClass: [top, person]
    cn: reader
    sn: reader
    userPassword: {SERVICE_PW}
  - dn: uid=alice,ou=users,{BASE_DN}
    objectClass: [top, person, inetOrgPerson]
    uid: alice
    cn: Alice
    sn: Alice
    userPassword: alicepw
    memberOf: {REQUIRED_GROUP}
  - dn: uid=bob,ou=users,{BASE_DN}
    objectClass: [top, person, inetOrgPerson]
    uid: bob
    cn: Bob
    sn: Bob
    userPassword: bobpw
    memberOf: cn=other-group,ou=groups,{BASE_DN}
  - dn: {REQUIRED_GROUP}
    objectClass: [top, groupOfNames]
    cn: mqtt-users
    member: uid=alice,ou=users,{BASE_DN}
  - dn: cn=other-group,ou=groups,{BASE_DN}
    objectClass: [top, groupOfNames]
    cn: other-group
    member: uid=bob,ou=users,{BASE_DN}
"#
            );
            std::fs::write(path, body).expect("write test directory YAML");
        }

        async fn start_server() -> (yamldap::ServerHandle, String, tempfile::NamedTempFile) {
            let file = tempfile::NamedTempFile::new().expect("temp directory YAML");
            write_directory(file.path());
            // Hold the file open: yamldap reads it at startup.
            let _ = std::io::stderr().flush();
            let config = yamldap::Config::new(file.path())
                .with_bind_address("127.0.0.1:0".parse().expect("loopback"));
            let server = yamldap::Server::new(config)
                .await
                .expect("directory starts");
            let handle = server.start().await.expect("directory listens");
            let url = format!("ldap://{}", handle.local_addr());
            (handle, url, file)
        }

        fn authenticator(url: &str) -> LdapAuthenticator {
            LdapAuthenticator::new(LdapConfig {
                server_url: url.to_string(),
                base_dn: BASE_DN.to_string(),
                bind_dn: SERVICE_DN.to_string(),
                bind_password: SERVICE_PW.to_string(),
                user_filter: "(uid={username})".to_string(),
                group_attribute: "memberOf".to_string(),
                required_group: REQUIRED_GROUP.to_string(),
                pool_size: 4,
                connect_timeout_ms: 3_000,
                read_timeout_ms: 3_000,
                timeout_ms: 0,
                tls_verify: true,
                ca_cert_path: None,
                bind_dn_template: String::new(),
                filter_template: String::new(),
            })
        }

        #[tokio::test]
        async fn valid_bind_succeeds() {
            let (_handle, url, _file) = start_server().await;
            let auth = authenticator(&url);
            auth.authenticate("device-1", Some("alice"), Some(b"alicepw"))
                .await
                .expect("valid directory bind must succeed");
        }

        #[tokio::test]
        async fn wrong_password_fails() {
            let (_handle, url, _file) = start_server().await;
            let auth = authenticator(&url);
            assert!(
                auth.authenticate("device-1", Some("alice"), Some(b"wrong"))
                    .await
                    .is_err(),
                "wrong directory password must fail closed"
            );
        }

        #[tokio::test]
        async fn unknown_user_fails() {
            let (_handle, url, _file) = start_server().await;
            let auth = authenticator(&url);
            assert!(
                auth.authenticate("device-1", Some("mallory"), Some(b"anything"))
                    .await
                    .is_err(),
                "unknown directory user must fail closed"
            );
        }

        #[tokio::test]
        async fn user_in_wrong_group_is_denied() {
            let (_handle, url, _file) = start_server().await;
            let auth = authenticator(&url);
            // Correct password, but memberOf lacks the required group.
            let err = auth
                .authenticate("device-1", Some("bob"), Some(b"bobpw"))
                .await
                .expect_err("wrong-group user must be denied");
            assert!(
                matches!(err, AuthError::AuthenticationFailed(_)),
                "wrong-group denial must fail closed, got: {err}"
            );
        }

        #[tokio::test]
        async fn directory_down_fails_closed() {
            // Closed loopback port: connection refused, no server.
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("ephemeral port");
            let addr = listener.local_addr().expect("local addr");
            drop(listener);
            let auth = LdapAuthenticator::new(LdapConfig {
                server_url: format!("ldap://{addr}"),
                base_dn: BASE_DN.to_string(),
                bind_dn: SERVICE_DN.to_string(),
                bind_password: SERVICE_PW.to_string(),
                user_filter: "(uid={username})".to_string(),
                group_attribute: "memberOf".to_string(),
                required_group: REQUIRED_GROUP.to_string(),
                pool_size: 2,
                connect_timeout_ms: 1_000,
                read_timeout_ms: 1_000,
                timeout_ms: 0,
                tls_verify: true,
                ca_cert_path: None,
                bind_dn_template: String::new(),
                filter_template: String::new(),
            });
            assert!(
                auth.authenticate("device-1", Some("alice"), Some(b"alicepw"))
                    .await
                    .is_err(),
                "unreachable directory must fail closed, never grant access"
            );
        }
    }
}
