//! One typed configuration schema as the source of truth (M1-03).
//!
//! Every startup/file setting has exactly one typed home here: its type,
//! default, valid range and short documentation string live in this module
//! and nowhere else. Runtime validation, the `--help` text in
//! `broker-node`, the user-facing settings reference and the generated
//! JSON Schema are all derived from these definitions.
//!
//! The four registry roots (`admin_users`, `mqtt_users`, `rules`,
//! `connectors` in `super`) are unchanged: they are dynamic state owned by
//! the registry with lock-free snapshots and atomic `state.toml`
//! persistence. This module covers the static startup/file settings that
//! previously lived only as command-line flags or as example-file keys
//! nothing consumed. Wiring each subsystem to read these values happens
//! with its owner; this task only defines, validates and documents them.

pub use crate::ConfigError;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Single-source field catalogue
// ---------------------------------------------------------------------------

/// One row of the schema catalogue: the single place a setting's type,
/// default, valid range and documentation string are stated together.
///
/// The struct definitions below mirror these rows; the `--help` text, the
/// settings reference and the JSON Schema are generated from them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldDoc {
    /// Dotted setting path as it appears in the TOML file.
    pub path: &'static str,
    /// Human-readable type name.
    pub setting_type: &'static str,
    /// Default value as rendered in TOML.
    pub default: &'static str,
    /// Valid range or accepted values.
    pub range: &'static str,
    /// Short documentation string (also used in `--help` output).
    pub doc: &'static str,
}

/// The full catalogue. Each entry's `doc` string is the canonical wording:
/// the `--help` text in `broker-node` repeats it verbatim (checked by the
/// `m1_03_help_contains_schema_docs` test there), and the generated
/// reference and JSON Schema embed it.
#[must_use]
pub fn field_docs() -> Vec<FieldDoc> {
    vec![
            FieldDoc {
                path: "node.id",
                setting_type: "string",
                default: "\"indra-node-1\"",
                range: "1..=64 chars, letters/digits/dots/dashes",
                doc: "Unique identifier for this broker node within the cluster.",
            },
            FieldDoc {
                path: "node.data_dir",
                setting_type: "path string",
                default: "\"./data\"",
                range: "non-empty path",
                doc: "Directory holding kernel persistent state (state.toml). Created on boot when missing.",
            },
            FieldDoc {
                path: "node.brokerlink_bind",
                setting_type: "socket address string",
                default: "\"127.0.0.1:18883\"",
                range: "valid host:port, port 1..=65535",
                doc: "BrokerLink IPC listen address for edge clients (TCP loopback).",
            },
            FieldDoc {
                path: "listeners.tcp.enabled",
                setting_type: "bool",
                default: "true",
                range: "true | false",
                doc: "Whether the plaintext MQTT listener accepts connections.",
            },
            FieldDoc {
                path: "listeners.tcp.bind",
                setting_type: "socket address string",
                default: "\"0.0.0.0:1883\"",
                range: "valid host:port, port 1..=65535",
                doc: "Bind address for the plaintext MQTT listener.",
            },
            FieldDoc {
                path: "listeners.tcp.max_connections",
                setting_type: "u32",
                default: "1000000",
                range: "1..=10000000",
                doc: "Maximum concurrent connections on the plaintext MQTT listener.",
            },
            FieldDoc {
                path: "listeners.tcp.backlog",
                setting_type: "u32",
                default: "1024",
                range: "1..=65536",
                doc: "Listener accept backlog for the plaintext MQTT listener.",
            },
            FieldDoc {
                path: "listeners.tls.enabled",
                setting_type: "bool",
                default: "false",
                range: "true | false",
                doc: "Whether the secure TLS MQTT listener accepts connections.",
            },
            FieldDoc {
                path: "listeners.tls.bind",
                setting_type: "socket address string",
                default: "\"0.0.0.0:8883\"",
                range: "valid host:port, port 1..=65535",
                doc: "Bind address for the secure TLS MQTT listener.",
            },
            FieldDoc {
                path: "listeners.tls.cert_file",
                setting_type: "path string",
                default: "\"\"",
                range: "PEM file path; required when TLS is enabled",
                doc: "Path to the PEM server certificate for the TLS listener.",
            },
            FieldDoc {
                path: "listeners.tls.key_file",
                setting_type: "path string",
                default: "\"\"",
                range: "PEM file path; required when TLS is enabled",
                doc: "Path to the PEM private key for the TLS listener.",
            },
            FieldDoc {
                path: "listeners.ws.enabled",
                setting_type: "bool",
                default: "true",
                range: "true | false",
                doc: "Whether the MQTT-over-WebSocket listener accepts connections.",
            },
            FieldDoc {
                path: "listeners.ws.bind",
                setting_type: "socket address string",
                default: "\"0.0.0.0:8083\"",
                range: "valid host:port, port 1..=65535",
                doc: "Bind address for the MQTT-over-WebSocket listener.",
            },
            FieldDoc {
                path: "listeners.ws.path",
                setting_type: "string",
                default: "\"/ws/mqtt\"",
                range: "must start with '/'",
                doc: "HTTP path serving MQTT-over-WebSocket traffic.",
            },
            FieldDoc {
                path: "listeners.wss.enabled",
                setting_type: "bool",
                default: "false",
                range: "true | false",
                doc: "Whether the secure WebSocket listener accepts connections.",
            },
            FieldDoc {
                path: "listeners.wss.bind",
                setting_type: "socket address string",
                default: "\"0.0.0.0:8084\"",
                range: "valid host:port, port 1..=65535",
                doc: "Bind address for the secure WebSocket listener.",
            },
            FieldDoc {
                path: "listeners.wss.path",
                setting_type: "string",
                default: "\"/ws/mqtt\"",
                range: "must start with '/'",
                doc: "HTTP path serving secure WebSocket traffic.",
            },
            FieldDoc {
                path: "listeners.wss.cert_file",
                setting_type: "path string",
                default: "\"\"",
                range: "PEM file path; required when secure WebSocket is enabled",
                doc: "Path to the PEM server certificate for the secure WebSocket listener.",
            },
            FieldDoc {
                path: "listeners.wss.key_file",
                setting_type: "path string",
                default: "\"\"",
                range: "PEM file path; required when secure WebSocket is enabled",
                doc: "Path to the PEM private key for the secure WebSocket listener.",
            },
            FieldDoc {
                path: "listeners.api.enabled",
                setting_type: "bool",
                default: "true",
                range: "true | false",
                doc: "Whether the management REST API and dashboard serve requests.",
            },
            FieldDoc {
                path: "listeners.api.bind",
                setting_type: "socket address string",
                default: "\"0.0.0.0:18083\"",
                range: "valid host:port, port 1..=65535; empty disables the API",
                doc: "Bind address for the management REST API. Empty disables the API.",
            },
            FieldDoc {
                path: "quotas.default_max_connections",
                setting_type: "u32",
                default: "10000",
                range: "0..=1000000 (0 = unlimited opt-in)",
                doc: "Default max connections per authenticated username (0 = unlimited).",
            },
            FieldDoc {
                path: "quotas.default_max_publish_rate",
                setting_type: "u32",
                default: "50000",
                range: "0..=10000000 msg/s (0 = unlimited opt-in)",
                doc: "Default token-bucket publish rate limit in messages per second (0 = unlimited).",
            },
            FieldDoc {
                path: "quotas.burst_multiplier",
                setting_type: "f64",
                default: "2.0",
                range: "1.0..=10.0",
                doc: "Token bucket burst multiplier (allows bursts up to burst times rate).",
            },
            FieldDoc {
                path: "session.max_session_expiry_secs",
                setting_type: "u64",
                default: "86400",
                range: "0..=2592000 seconds (0 = unlimited opt-in)",
                doc: "Max session expiry interval in seconds.",
            },
            FieldDoc {
                path: "session.max_offline_queue",
                setting_type: "u32",
                default: "50000",
                range: "1..=1000000",
                doc: "Maximum queued offline messages per session.",
            },
            FieldDoc {
                path: "session.max_inflight_messages",
                setting_type: "u32",
                default: "65535",
                range: "1..=65535",
                doc: "Maximum inflight unacknowledged QoS 1 and QoS 2 messages.",
            },
            FieldDoc {
                path: "session.max_qos0_backlog",
                setting_type: "usize",
                default: "1000",
                range: "1..=100000",
                doc: "Per-subscriber QoS 0 egress backlog bound; past it the oldest queued QoS 0 frame drops.",
            },
            FieldDoc {
                path: "session.keep_alive_grace",
                setting_type: "f64",
                default: "1.5",
                range: "1.0..=5.0",
                doc: "Keep-alive grace multiplier before disconnect.",
            },
            FieldDoc {
                path: "logging.level",
                setting_type: "enum string",
                default: "\"info\"",
                range: "trace | debug | info | warn | error",
                doc: "Logging verbosity for the kernel (trace, debug, info, warn, error).",
            },
            FieldDoc {
                path: "rules_engine.window_channel_depth",
                setting_type: "u32",
                default: "65536",
                range: "1..=1000000",
                doc: "Ingress ring buffer channel depth for stateful window worker tasks.",
            },
            FieldDoc {
                path: "rules_engine.backpressure_policy",
                setting_type: "enum string",
                default: "\"DropOldest\"",
                range: "Block | DropNewest | DropOldest | SpillToDisk | RejectPublisher",
                doc: "Default memory backpressure policy when the rule buffer is full.",
            },
            FieldDoc {
                path: "auth.enabled",
                setting_type: "bool",
                default: "true",
                range: "true | false",
                doc: "Whether authentication checks apply to client connects.",
            },
            FieldDoc {
                path: "auth.password_hash",
                setting_type: "enum string",
                default: "\"sha256\"",
                range: "sha256 | bcrypt",
                doc: "Password hashing algorithm for stored credentials.",
            },
            FieldDoc {
                path: "auth.allow_anonymous",
                setting_type: "bool",
                default: "false",
                range: "true | false",
                doc: "Whether anonymous connections are accepted while no users are configured.",
            },
            FieldDoc {
                path: "auth.superusers",
                setting_type: "string list",
                default: "[\"admin\", \"root\"]",
                range: "0..=100 entries",
                doc: "Superuser usernames bypassing ACL rules.",
            },
            FieldDoc {
                path: "cluster.enabled",
                setting_type: "bool",
                default: "false",
                range: "true | false",
                doc: "Whether multi-node distributed clustering is enabled.",
            },
            FieldDoc {
                path: "cluster.bind",
                setting_type: "socket address string",
                default: "\"127.0.0.1:19883\"",
                range: "valid host:port, port 1..=65535",
                doc: "Cluster SWIM UDP bind address for peer discovery and membership.",
            },
            FieldDoc {
                path: "cluster.gossip_bind",
                setting_type: "socket address string",
                default: "\"0.0.0.0:7946\"",
                range: "valid host:port, port 1..=65535",
                doc: "Gossip membership bind address for peer discovery.",
            },
            FieldDoc {
                path: "cluster.quic_bind",
                setting_type: "socket address string",
                default: "\"0.0.0.0:9092\"",
                range: "valid host:port, port 1..=65535",
                doc: "Multiplexed data plane bind address for inter-broker message routing.",
            },
            FieldDoc {
                path: "cluster.seed_nodes",
                setting_type: "string list",
                default: "[]",
                range: "0..=64 entries, each host:port",
                doc: "Seed node addresses to join an existing cluster.",
            },
            FieldDoc {
                path: "licence.license_file",
                setting_type: "path string",
                default: "\"/etc/indramqtt/license.key\"",
                range: "any path; empty means none installed",
                doc: "Path to the enterprise cryptographic license key file.",
            },
            FieldDoc {
                path: "licence.license_key",
                setting_type: "string",
                default: "\"\"",
                range: "any string; empty means use stored token or environment",
                doc: "Enterprise commercial license key for multi-node clustering.",
            },
            FieldDoc {
                path: "licence.trusted_keys_path",
                setting_type: "path string",
                default: "\"\"",
                range: "JSON file or directory; empty trusts nothing",
                doc: "Trusted licence-signing keys: a JSON file or directory of JSON files.",
            },
            FieldDoc {
                path: "licence.request_out",
                setting_type: "path string",
                default: "\"\"",
                range: "any path; empty disables request generation",
                doc: "Write the installation licence request to this path and exit.",
            },
            FieldDoc {
                path: "licence.install_file",
                setting_type: "path string",
                default: "\"\"",
                range: "any path; empty disables licence installation",
                doc: "Install the licence token read from this path and exit.",
            },
            FieldDoc {
                path: "licence.expiry_warn_days",
                setting_type: "u64",
                default: "30",
                range: "0..=365 days",
                doc: "Days before expiry that the approaching-expiry alarm and log warning start.",
            },
            FieldDoc {
                path: "gateway.coap_bind",
                setting_type: "socket address string",
                default: "\"\"",
                range: "empty disables the gateway, else valid host:port",
                doc: "CoAP gateway UDP listen address. Empty disables the gateway.",
            },
            FieldDoc {
                path: "persistence.stream_dir",
                setting_type: "path string",
                default: "\"\"",
                range: "any directory; empty disables journaling",
                doc: "Durable stream journal directory. Empty disables journaling.",
            },
            FieldDoc {
                path: "ldap.server_url",
                setting_type: "string",
                default: "\"\"",
                range: "empty disables LDAP, else ldap:// or ldaps:// URL",
                doc: "Directory server URL for LDAP authentication. Empty disables LDAP.",
            },
            FieldDoc {
                path: "ldap.base_dn",
                setting_type: "string",
                default: "\"\"",
                range: "any DN; required when LDAP is enabled",
                doc: "Base DN under which directory users are searched.",
            },
            FieldDoc {
                path: "ldap.bind_dn",
                setting_type: "string",
                default: "\"\"",
                range: "any DN",
                doc: "Service account DN used for the initial bind plus search.",
            },
            FieldDoc {
                path: "ldap.bind_password",
                setting_type: "string",
                default: "\"\"",
                range: "any string",
                doc: "Service account password for the initial bind.",
            },
            FieldDoc {
                path: "ldap.user_filter",
                setting_type: "string",
                default: "\"(uid={username})\"",
                range: "must contain {username} when LDAP is enabled",
                doc: "User search filter with a {username} placeholder, escaped per RFC 4515.",
            },
            FieldDoc {
                path: "ldap.group_attribute",
                setting_type: "string",
                default: "\"memberOf\"",
                range: "non-empty when LDAP is enabled",
                doc: "User-entry attribute listing directory groups.",
            },
            FieldDoc {
                path: "ldap.required_group",
                setting_type: "string",
                default: "\"\"",
                range: "any DN; empty disables the group check",
                doc: "Required group DN: the entry must list this DN to connect.",
            },
            FieldDoc {
                path: "ldap.ca_cert_path",
                setting_type: "path string",
                default: "\"\"",
                range: "PEM file path; empty uses system roots",
                doc: "Path to a PEM CA certificate for private directories.",
            },
            FieldDoc {
                path: "ldap.pool_size",
                setting_type: "usize",
                default: "8",
                range: "1..=32",
                doc: "Bound on concurrent directory authentications.",
            },
            FieldDoc {
                path: "ldap.connect_timeout_ms",
                setting_type: "u64",
                default: "5000",
                range: "100..=60000 ms",
                doc: "Timeout covering TCP connect plus TLS handshake.",
            },
            FieldDoc {
                path: "ldap.read_timeout_ms",
                setting_type: "u64",
                default: "5000",
                range: "100..=60000 ms",
                doc: "Timeout covering each directory bind/search round-trip.",
            },
            FieldDoc {
                path: "kerberos.keytab_path",
                setting_type: "path string",
                default: "\"\"",
                range: "keytab v2 file; empty disables Kerberos",
                doc: "Keytab file for Kerberos authentication. Empty disables Kerberos.",
            },
            FieldDoc {
                path: "kerberos.service_principal",
                setting_type: "string",
                default: "\"\"",
                range: "required when Kerberos is enabled",
                doc: "Service principal name held in the keytab.",
            },
            FieldDoc {
                path: "kerberos.realm",
                setting_type: "string",
                default: "\"\"",
                range: "any realm; empty disables the realm check",
                doc: "Expected service realm. Empty disables the realm check on the service name.",
            },
            FieldDoc {
                path: "kerberos.allowed_realms",
                setting_type: "string list",
                default: "[]",
                range: "0..=32 entries",
                doc: "Trusted client realms. Empty allows any realm that verifies.",
            },
            FieldDoc {
                path: "kerberos.clock_skew_secs",
                setting_type: "u64",
                default: "300",
                range: "1..=3600 seconds",
                doc: "Clock-skew allowance in seconds for ticket validity and authenticator timestamps.",
            },
            FieldDoc {
                path: "kerberos.role_map",
                setting_type: "string",
                default: "\"\"",
                range: "comma-separated principal=role pairs; empty leaves every principal at user",
                doc: "Comma-separated principal=role mappings for verified client principals.",
            },
            FieldDoc {
                path: "kerberos.replay_max_entries",
                setting_type: "usize",
                default: "1024",
                range: "16..=8192",
                doc: "Replay-cache bound for Kerberos authenticators.",
            },
            FieldDoc { path: "session.max_qos1_inflight", setting_type: "usize", default: "100", range: "1..=100000", doc: "Per-session QoS 1 inflight window bound." },
            FieldDoc { path: "session.max_qos1_spill", setting_type: "usize", default: "1000", range: "1..=100000", doc: "Per-session QoS 1 spill bound past the window." },
            FieldDoc { path: "session.topic_alias_maximum", setting_type: "u16", default: "10", range: "0..=65535", doc: "Inbound topic-alias maximum advertised in CONNACK." },
            FieldDoc { path: "rules_engine.spill_dir", setting_type: "string", default: "\"\"", range: "empty or directory path", doc: "Rule ingress spill directory." },
            FieldDoc { path: "delayed.max_secs", setting_type: "u64", default: "86400", range: "1..=86400", doc: "Upper bound for delayed deferrals in seconds." },
            FieldDoc { path: "observability.monitor_sample_secs", setting_type: "u64", default: "10", range: "0..=3600", doc: "Monitor sampling interval in seconds." },
            FieldDoc { path: "jwks.url", setting_type: "string", default: "\"\"", range: "empty or https URL", doc: "JWKS endpoint URL for JWT authentication." },
            FieldDoc { path: "jwks.issuer", setting_type: "string", default: "\"\"", range: "any string", doc: "Expected JWT issuer." },
            FieldDoc { path: "jwks.audience", setting_type: "string", default: "\"\"", range: "any string", doc: "Expected JWT audience." },
            FieldDoc { path: "dbauth.postgres_url", setting_type: "string", default: "\"\"", range: "empty or URL", doc: "PostgreSQL URL for database authentication." },
            FieldDoc { path: "webhook.url", setting_type: "string", default: "\"\"", range: "empty or URL", doc: "HTTP webhook verdict endpoint." },
        ]
}

/// Look up the canonical documentation string for one setting path.
#[must_use]
pub fn doc_for(path: &str) -> Option<&'static str> {
    field_docs()
        .into_iter()
        .find(|row| row.path == path)
        .map(|row| row.doc)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn invalid(setting: &str, value: &str, why: &str) -> ConfigError {
    ConfigError::Invalid(format!(
        "{setting} {value:?} is invalid: {why} (field `{setting}`)"
    ))
}

/// Validate a `host:port` bind string, naming the setting and value.
fn check_bind(setting: &str, value: &str, allow_empty: bool) -> Result<(), ConfigError> {
    if value.is_empty() {
        if allow_empty {
            return Ok(());
        }
        return Err(invalid(setting, value, "must not be empty"));
    }
    let port_part = value.rsplit(':').next().unwrap_or("");
    let host_part = value.rsplit_once(':').map(|(host, _)| host).unwrap_or("");
    if host_part.is_empty() {
        return Err(invalid(setting, value, "must be host:port"));
    }
    match port_part.parse::<u16>() {
        Ok(port) if port >= 1 => Ok(()),
        _ => Err(invalid(setting, value, "port must be 1..=65535")),
    }
}

fn check_range_u64(setting: &str, value: u64, min: u64, max: u64) -> Result<(), ConfigError> {
    if value < min || value > max {
        return Err(invalid(
            setting,
            &value.to_string(),
            &format!("must be {min}..={max}"),
        ));
    }
    Ok(())
}

fn check_range_usize(
    setting: &str,
    value: usize,
    min: usize,
    max: usize,
) -> Result<(), ConfigError> {
    if value < min || value > max {
        return Err(invalid(
            setting,
            &value.to_string(),
            &format!("must be {min}..={max}"),
        ));
    }
    Ok(())
}

/// Expected TOML kind for one scalar setting, derived from its schema type.
fn expected_kind(setting_type: &str) -> &'static str {
    match setting_type {
        "bool" => "boolean",
        "u16" | "u32" | "u64" | "usize" => "integer",
        "f64" => "float",
        "string list" => "string list",
        _ => "string",
    }
}

/// Candidate TOML keys for one path segment (accepts the pre-rename alias
/// where one exists, so old files fail on values, never on key names).
fn key_candidates(segment: &str) -> Vec<&str> {
    match segment {
        "rules_engine" => vec!["rules_engine", "rules"],
        "ws" => vec!["ws", "websocket"],
        _ => vec![segment],
    }
}

/// Pre-deserialisation type check: every catalogued scalar present in the
/// document must hold the TOML type its schema type implies. A wrong-typed
/// value is a startup error naming the setting and the offending value,
/// independent of the underlying parser's error wording.
fn check_toml_types(table: &toml::Table) -> Result<(), ConfigError> {
    for row in field_docs() {
        let kind = expected_kind(row.setting_type);
        let parts: Vec<&str> = row.path.split('.').collect();
        let (key, tables) = match parts.as_slice() {
            [section, key] => (*key, vec![*section]),
            [section, listener, key] => (*key, vec![*section, *listener]),
            _ => continue,
        };
        let mut current = table;
        let mut resolved = true;
        for segment in tables {
            let mut next: Option<&toml::Table> = None;
            for candidate in key_candidates(segment) {
                if let Some(toml::Value::Table(nested)) = current.get(candidate) {
                    next = Some(nested);
                    break;
                }
            }
            match next {
                Some(nested) => current = nested,
                None => {
                    resolved = false;
                    break;
                }
            }
        }
        if !resolved {
            continue;
        }
        let Some(value) = current.get(key) else {
            continue;
        };
        let ok = match kind {
            "boolean" => value.is_bool(),
            "integer" => matches!(value, toml::Value::Integer(_)),
            "float" => matches!(value, toml::Value::Float(_) | toml::Value::Integer(_)),
            "string list" => matches!(value, toml::Value::Array(_)),
            _ => matches!(value, toml::Value::String(_)),
        };
        if !ok {
            return Err(invalid(
                row.path,
                &value.to_string(),
                &format!("must be {}", row.setting_type),
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Section structs
// ---------------------------------------------------------------------------

/// Node identity and kernel paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeConf {
    /// Unique identifier for this broker node within the cluster.
    #[serde(default = "default_node_id")]
    pub id: String,
    /// Directory holding kernel persistent state (state.toml). Created on boot when missing.
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
    /// BrokerLink IPC listen address for edge clients (TCP loopback).
    #[serde(default = "default_brokerlink_bind")]
    pub brokerlink_bind: String,
}

// Reason: stable default identity used by single-node deployments and tests.
fn default_node_id() -> String {
    "indra-node-1".to_string()
}
// Reason: relative directory keeps developer and test boots self-contained;
// production overrides with an absolute path.
fn default_data_dir() -> String {
    "./data".to_string()
}
// Reason: loopback IPC port keeps edge-to-kernel traffic off the network.
fn default_brokerlink_bind() -> String {
    "127.0.0.1:18883".to_string()
}

impl Default for NodeConf {
    fn default() -> Self {
        Self {
            id: default_node_id(),
            data_dir: default_data_dir(),
            brokerlink_bind: default_brokerlink_bind(),
        }
    }
}

impl NodeConf {
    /// Validates node identity and paths.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.id.trim().is_empty() || self.id.len() > 64 {
            return Err(invalid("node.id", &self.id, "must be 1..=64 characters"));
        }
        if !self
            .id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        {
            return Err(invalid(
                "node.id",
                &self.id,
                "may only use letters, digits, dots, dashes and underscores",
            ));
        }
        if self.data_dir.trim().is_empty() {
            return Err(invalid(
                "node.data_dir",
                &self.data_dir,
                "must not be empty",
            ));
        }
        check_bind("node.brokerlink_bind", &self.brokerlink_bind, false)?;
        Ok(())
    }
}

/// Plaintext MQTT listener.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpListenerConf {
    /// Whether the plaintext MQTT listener accepts connections.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Bind address for the plaintext MQTT listener.
    #[serde(default = "default_tcp_bind")]
    pub bind: String,
    /// Maximum concurrent connections on the plaintext MQTT listener.
    #[serde(default = "default_tcp_max_connections")]
    pub max_connections: u32,
    /// Listener accept backlog for the plaintext MQTT listener.
    #[serde(default = "default_tcp_backlog")]
    pub backlog: u32,
}

fn default_true() -> bool {
    true
}
fn default_false() -> bool {
    false
}
// Reason: the standard plaintext MQTT port every client expects.
fn default_tcp_bind() -> String {
    "0.0.0.0:1883".to_string()
}
// Reason: one million concurrent plaintext connections fits a large
// single-node deployment without pre-allocating per-connection memory.
fn default_tcp_max_connections() -> u32 {
    1_000_000
}
// Reason: 1024 pending accepts absorbs connection bursts without
// growing an unbounded accept queue.
fn default_tcp_backlog() -> u32 {
    1024
}

impl Default for TcpListenerConf {
    fn default() -> Self {
        Self {
            enabled: true,
            bind: default_tcp_bind(),
            max_connections: default_tcp_max_connections(),
            backlog: default_tcp_backlog(),
        }
    }
}

impl TcpListenerConf {
    /// Validates the plaintext listener.
    pub fn validate(&self) -> Result<(), ConfigError> {
        check_bind("listeners.tcp.bind", &self.bind, false)?;
        check_range_u64(
            "listeners.tcp.max_connections",
            u64::from(self.max_connections),
            1,
            10_000_000,
        )?;
        check_range_u64("listeners.tcp.backlog", u64::from(self.backlog), 1, 65_536)?;
        Ok(())
    }
}

/// Secure TLS MQTT listener.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsListenerConf {
    /// Whether the secure TLS MQTT listener accepts connections.
    #[serde(default = "default_false")]
    pub enabled: bool,
    /// Bind address for the secure TLS MQTT listener.
    #[serde(default = "default_tls_bind")]
    pub bind: String,
    /// Path to the PEM server certificate for the TLS listener.
    #[serde(default)]
    pub cert_file: String,
    /// Path to the PEM private key for the TLS listener.
    #[serde(default)]
    pub key_file: String,
}

// Reason: the standard secure MQTT port.
fn default_tls_bind() -> String {
    "0.0.0.0:8883".to_string()
}

impl Default for TlsListenerConf {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: default_tls_bind(),
            cert_file: String::new(),
            key_file: String::new(),
        }
    }
}

impl TlsListenerConf {
    /// Validates the TLS listener.
    pub fn validate(&self) -> Result<(), ConfigError> {
        check_bind("listeners.tls.bind", &self.bind, false)?;
        if self.enabled {
            if self.cert_file.trim().is_empty() {
                return Err(invalid(
                    "listeners.tls.cert_file",
                    &self.cert_file,
                    "is required when TLS is enabled",
                ));
            }
            if self.key_file.trim().is_empty() {
                return Err(invalid(
                    "listeners.tls.key_file",
                    &self.key_file,
                    "is required when TLS is enabled",
                ));
            }
        }
        Ok(())
    }
}

/// MQTT-over-WebSocket listener.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsListenerConf {
    /// Whether the MQTT-over-WebSocket listener accepts connections.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Bind address for the MQTT-over-WebSocket listener.
    #[serde(default = "default_ws_bind")]
    pub bind: String,
    /// HTTP path serving MQTT-over-WebSocket traffic.
    #[serde(default = "default_ws_path")]
    pub path: String,
}

// Reason: keeps the dashboard test console reachable without extra setup.
fn default_ws_bind() -> String {
    "0.0.0.0:8083".to_string()
}
// Reason: single well-known path avoids per-deployment path negotiation.
fn default_ws_path() -> String {
    "/ws/mqtt".to_string()
}

impl Default for WsListenerConf {
    fn default() -> Self {
        Self {
            enabled: true,
            bind: default_ws_bind(),
            path: default_ws_path(),
        }
    }
}

impl WsListenerConf {
    /// Validates the WebSocket listener.
    pub fn validate(&self) -> Result<(), ConfigError> {
        check_bind("listeners.ws.bind", &self.bind, false)?;
        if !self.path.starts_with('/') {
            return Err(invalid(
                "listeners.ws.path",
                &self.path,
                "must start with '/'",
            ));
        }
        Ok(())
    }
}

/// Secure WebSocket listener.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WssListenerConf {
    /// Whether the secure WebSocket listener accepts connections.
    #[serde(default = "default_false")]
    pub enabled: bool,
    /// Bind address for the secure WebSocket listener.
    #[serde(default = "default_wss_bind")]
    pub bind: String,
    /// HTTP path serving secure WebSocket traffic.
    #[serde(default = "default_ws_path")]
    pub path: String,
    /// Path to the PEM server certificate for the secure WebSocket listener.
    #[serde(default)]
    pub cert_file: String,
    /// Path to the PEM private key for the secure WebSocket listener.
    #[serde(default)]
    pub key_file: String,
}

// Reason: TODO(parity): no canonical secure-WebSocket port is decided yet;
// 8084 is the conservative next-port choice and stays disabled by default.
fn default_wss_bind() -> String {
    "0.0.0.0:8084".to_string()
}

impl Default for WssListenerConf {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: default_wss_bind(),
            path: default_ws_path(),
            cert_file: String::new(),
            key_file: String::new(),
        }
    }
}

impl WssListenerConf {
    /// Validates the secure WebSocket listener.
    pub fn validate(&self) -> Result<(), ConfigError> {
        check_bind("listeners.wss.bind", &self.bind, false)?;
        if !self.path.starts_with('/') {
            return Err(invalid(
                "listeners.wss.path",
                &self.path,
                "must start with '/'",
            ));
        }
        if self.enabled {
            if self.cert_file.trim().is_empty() {
                return Err(invalid(
                    "listeners.wss.cert_file",
                    &self.cert_file,
                    "is required when secure WebSocket is enabled",
                ));
            }
            if self.key_file.trim().is_empty() {
                return Err(invalid(
                    "listeners.wss.key_file",
                    &self.key_file,
                    "is required when secure WebSocket is enabled",
                ));
            }
        }
        Ok(())
    }
}

/// Management REST API listener.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiListenerConf {
    /// Whether the management REST API and dashboard serve requests.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Bind address for the management REST API. Empty disables the API.
    #[serde(default = "default_api_bind")]
    pub bind: String,
}

// Reason: loopback-by-default in code would break the shipped template, so
// the template binds all interfaces while tests pass an explicit loopback
// or empty value to disable the API.
fn default_api_bind() -> String {
    "0.0.0.0:18083".to_string()
}

impl Default for ApiListenerConf {
    fn default() -> Self {
        Self {
            enabled: true,
            bind: default_api_bind(),
        }
    }
}

impl ApiListenerConf {
    /// Validates the API listener.
    pub fn validate(&self) -> Result<(), ConfigError> {
        check_bind("listeners.api.bind", &self.bind, true)?;
        Ok(())
    }
}

/// All network listeners.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ListenersConf {
    /// Plaintext MQTT listener.
    #[serde(default)]
    pub tcp: TcpListenerConf,
    /// Secure TLS MQTT listener.
    #[serde(default)]
    pub tls: TlsListenerConf,
    /// MQTT-over-WebSocket listener (`websocket` accepted as an alias for
    /// files written before the rename).
    #[serde(default, alias = "websocket")]
    pub ws: WsListenerConf,
    /// Secure WebSocket listener.
    #[serde(default)]
    pub wss: WssListenerConf,
    /// Management REST API listener.
    #[serde(default)]
    pub api: ApiListenerConf,
}

impl ListenersConf {
    /// Validates every listener.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.tcp.validate()?;
        self.tls.validate()?;
        self.ws.validate()?;
        self.wss.validate()?;
        self.api.validate()?;
        Ok(())
    }
}

/// Multi-tenant quotas and rate limiting.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuotasConf {
    /// Default max connections per authenticated username (0 = unlimited).
    #[serde(default = "default_quota_max_connections")]
    pub default_max_connections: u32,
    /// Default token-bucket publish rate limit in messages per second (0 = unlimited).
    #[serde(default = "default_quota_max_publish_rate")]
    pub default_max_publish_rate: u32,
    /// Token bucket burst multiplier (allows bursts up to burst times rate).
    #[serde(default = "default_burst_multiplier")]
    pub burst_multiplier: f64,
}

// Reason: 10k connections per user fits a large tenant without letting one
// username exhaust the listener bound; 0 stays an explicit unlimited opt-in.
fn default_quota_max_connections() -> u32 {
    10_000
}
// Reason: 50k msg/s per user matches a busy telemetry tenant while keeping
// the token bucket bounded; 0 stays an explicit unlimited opt-in.
fn default_quota_max_publish_rate() -> u32 {
    50_000
}
// Reason: twice the rate absorbs a one-second burst without sizing buckets
// for sustained overload.
fn default_burst_multiplier() -> f64 {
    2.0
}

impl Default for QuotasConf {
    fn default() -> Self {
        Self {
            default_max_connections: default_quota_max_connections(),
            default_max_publish_rate: default_quota_max_publish_rate(),
            burst_multiplier: default_burst_multiplier(),
        }
    }
}

impl QuotasConf {
    /// Validates quota bounds.
    pub fn validate(&self) -> Result<(), ConfigError> {
        check_range_u64(
            "quotas.default_max_connections",
            u64::from(self.default_max_connections),
            0,
            1_000_000,
        )?;
        check_range_u64(
            "quotas.default_max_publish_rate",
            u64::from(self.default_max_publish_rate),
            0,
            10_000_000,
        )?;
        if !(1.0..=10.0).contains(&self.burst_multiplier) {
            return Err(invalid(
                "quotas.burst_multiplier",
                &self.burst_multiplier.to_string(),
                "must be 1.0..=10.0",
            ));
        }
        Ok(())
    }
}

/// Session and protocol invariants.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionConf {
    /// Max session expiry interval in seconds.
    #[serde(default = "default_session_expiry_secs")]
    pub max_session_expiry_secs: u64,
    /// Maximum queued offline messages per session.
    #[serde(default = "default_offline_queue")]
    pub max_offline_queue: u32,
    /// Maximum inflight unacknowledged QoS 1 and QoS 2 messages.
    #[serde(default = "default_inflight_messages")]
    pub max_inflight_messages: u32,
    /// Per-subscriber QoS 0 egress backlog bound; past it the oldest queued QoS 0 frame drops.
    #[serde(default = "default_qos0_backlog")]
    pub max_qos0_backlog: usize,
    /// Per-session QoS 1 inflight window bound. Each live session tracks at most this many
    /// unacknowledged QoS 1 downlinks in the fast in-memory window; past it overflow spills.
    /// Default 100 caps per-session live unacked state near 100 small frames.
    #[serde(default = "default_qos1_inflight_window")]
    pub max_qos1_inflight: usize,
    /// Per-session QoS 1 spill bound past the window. Default 1000 (10x the window).
    #[serde(default = "default_qos1_spill")]
    pub max_qos1_spill: usize,
    /// Inbound topic-alias maximum advertised in CONNACK. Default 10; 0 disables inbound aliases.
    #[serde(default = "default_topic_alias_maximum")]
    pub topic_alias_maximum: u16,
    /// Keep-alive grace multiplier before disconnect.
    #[serde(default = "default_keep_alive_grace")]
    pub keep_alive_grace: f64,
}

// Reason: 100 caps per-session live unacked state near 100 small frames
// while absorbing a short ack stall without spilling.
fn default_qos1_inflight_window() -> usize {
    100
}

// Reason: 10x the window absorbs roughly a 1 s burst at 1k msg/s from a
// stalled acknowledger while keeping per-session tracked memory bounded
// near 1,100 messages total.
fn default_qos1_spill() -> usize {
    1000
}

// Reason: 10 covers typical small-device alias use while capping
// per-connection alias memory near 10 topic strings; 0 disables inbound
// aliases.
fn default_topic_alias_maximum() -> u16 {
    10
}

// Reason: one day covers durable sessions without pinning state forever;
// 0 stays an explicit unlimited opt-in.
fn default_session_expiry_secs() -> u64 {
    86_400
}
// Reason: 50k queued messages bounds a detached durable session near a few
// tens of MB for small frames instead of growing without limit.
fn default_offline_queue() -> u32 {
    50_000
}
// Reason: the MQTT packet-id space caps inflight QoS 1/2 at 65535.
fn default_inflight_messages() -> u32 {
    65_535
}
// Reason: 1000 small frames absorb about a one-second burst at 1k msg/s
// while capping per-subscriber QoS 0 memory; matches the delivery-table
// default so schema and boot agree.
fn default_qos0_backlog() -> usize {
    1_000
}
// Reason: half a keep-alive interval of grace tolerates one missed ping
// without keeping dead connections for multiples.
fn default_keep_alive_grace() -> f64 {
    1.5
}

impl Default for SessionConf {
    fn default() -> Self {
        Self {
            max_session_expiry_secs: default_session_expiry_secs(),
            max_offline_queue: default_offline_queue(),
            max_inflight_messages: default_inflight_messages(),
            max_qos0_backlog: default_qos0_backlog(),
            max_qos1_inflight: default_qos1_inflight_window(),
            max_qos1_spill: default_qos1_spill(),
            topic_alias_maximum: default_topic_alias_maximum(),
            keep_alive_grace: default_keep_alive_grace(),
        }
    }
}

impl SessionConf {
    /// Validates session bounds.
    pub fn validate(&self) -> Result<(), ConfigError> {
        check_range_u64(
            "session.max_session_expiry_secs",
            self.max_session_expiry_secs,
            0,
            2_592_000,
        )?;
        check_range_u64(
            "session.max_offline_queue",
            u64::from(self.max_offline_queue),
            1,
            1_000_000,
        )?;
        check_range_u64(
            "session.max_inflight_messages",
            u64::from(self.max_inflight_messages),
            1,
            65_535,
        )?;
        check_range_usize(
            "session.max_qos0_backlog",
            self.max_qos0_backlog,
            1,
            100_000,
        )?;
        check_range_usize(
            "session.max_qos1_inflight",
            self.max_qos1_inflight,
            1,
            100_000,
        )?;
        check_range_usize("session.max_qos1_spill", self.max_qos1_spill, 1, 100_000)?;
        check_range_u64(
            "session.topic_alias_maximum",
            u64::from(self.topic_alias_maximum),
            0,
            65_535,
        )?;
        if !(1.0..=5.0).contains(&self.keep_alive_grace) {
            return Err(invalid(
                "session.keep_alive_grace",
                &self.keep_alive_grace.to_string(),
                "must be 1.0..=5.0",
            ));
        }
        Ok(())
    }
}

/// Kernel logging.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoggingConf {
    /// Logging verbosity for the kernel (trace, debug, info, warn, error).
    #[serde(default = "default_log_level")]
    pub level: String,
}

// Reason: info keeps production logs readable; debug/trace are opt-in.
fn default_log_level() -> String {
    "info".to_string()
}

/// Logging levels the schema accepts.
pub const KNOWN_LOG_LEVELS: &[&str] = &["trace", "debug", "info", "warn", "error"];

impl Default for LoggingConf {
    fn default() -> Self {
        Self {
            level: default_log_level(),
        }
    }
}

impl LoggingConf {
    /// Validates the logging level enum.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !KNOWN_LOG_LEVELS.contains(&self.level.as_str()) {
            return Err(invalid(
                "logging.level",
                &self.level,
                "must be one of trace, debug, info, warn, error",
            ));
        }
        Ok(())
    }
}

/// Embedded stream-processing (rule engine) tuning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RulesEngineConf {
    /// Ingress ring buffer channel depth for stateful window worker tasks.
    #[serde(default = "default_window_channel_depth")]
    pub window_channel_depth: u32,
    /// Default memory backpressure policy when the rule buffer is full.
    #[serde(default = "default_backpressure_policy")]
    pub backpressure_policy: String,
    /// Rule ingress spill directory. Empty keeps memory-only DropOldest; set to a directory
    /// to build the rule engine with SpillToDisk backpressure (1 MiB segments, 64 MiB total).
    #[serde(default = "default_rule_spill_dir")]
    pub spill_dir: String,
}

fn default_rule_spill_dir() -> String {
    String::new()
}

// Reason: 64k events absorb windowed bursts without pre-allocating a large
// ring per rule.
fn default_window_channel_depth() -> u32 {
    65_536
}
// Reason: shedding the oldest event keeps a stateful window live under
// overload instead of stalling ingress.
fn default_backpressure_policy() -> String {
    "DropOldest".to_string()
}

/// Backpressure policies the schema accepts.
pub const KNOWN_BACKPRESSURE_POLICIES: &[&str] = &[
    "Block",
    "DropNewest",
    "DropOldest",
    "SpillToDisk",
    "RejectPublisher",
];

impl Default for RulesEngineConf {
    fn default() -> Self {
        Self {
            window_channel_depth: default_window_channel_depth(),
            backpressure_policy: default_backpressure_policy(),
            spill_dir: default_rule_spill_dir(),
        }
    }
}

impl RulesEngineConf {
    /// Validates rule-engine tuning.
    pub fn validate(&self) -> Result<(), ConfigError> {
        check_range_u64(
            "rules_engine.window_channel_depth",
            u64::from(self.window_channel_depth),
            1,
            1_000_000,
        )?;
        if !KNOWN_BACKPRESSURE_POLICIES.contains(&self.backpressure_policy.as_str()) {
            return Err(invalid(
                "rules_engine.backpressure_policy",
                &self.backpressure_policy,
                "must be one of Block, DropNewest, DropOldest, SpillToDisk, RejectPublisher",
            ));
        }
        Ok(())
    }
}

/// Authentication and authorisation policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthPolicyConf {
    /// Whether authentication checks apply to client connects.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Password hashing algorithm for stored credentials.
    #[serde(default = "default_password_hash")]
    pub password_hash: String,
    /// Whether anonymous connections are accepted while no users are configured.
    #[serde(default = "default_false")]
    pub allow_anonymous: bool,
    /// Superuser usernames bypassing ACL rules.
    #[serde(default = "default_superusers")]
    pub superusers: Vec<String>,
}

// Reason: SHA-256 is the portable default; bcrypt is the opt-in upgrade.
// TODO(parity): whether additional algorithms should be accepted is undecided.
fn default_password_hash() -> String {
    "sha256".to_string()
}
// Reason: fail closed by default; the operator opts into anonymous access
// explicitly. The shipped template sets this to true as its own opt-in.
fn default_superusers() -> Vec<String> {
    vec!["admin".to_string(), "root".to_string()]
}

/// Password-hash algorithms the schema accepts.
pub const KNOWN_PASSWORD_HASHES: &[&str] = &["sha256", "bcrypt"];

impl Default for AuthPolicyConf {
    fn default() -> Self {
        Self {
            enabled: true,
            password_hash: default_password_hash(),
            allow_anonymous: false,
            superusers: default_superusers(),
        }
    }
}

impl AuthPolicyConf {
    /// Validates auth policy.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !KNOWN_PASSWORD_HASHES.contains(&self.password_hash.as_str()) {
            return Err(invalid(
                "auth.password_hash",
                &self.password_hash,
                "must be one of sha256, bcrypt",
            ));
        }
        if self.superusers.len() > 100 {
            return Err(invalid(
                "auth.superusers",
                &format!("{} entries", self.superusers.len()),
                "must hold at most 100 entries",
            ));
        }
        for name in &self.superusers {
            if name.trim().is_empty() {
                return Err(invalid(
                    "auth.superusers",
                    name,
                    "entries must not be empty",
                ));
            }
        }
        Ok(())
    }
}

/// Multi-tenant assignment rules (MT-01).
///
/// Rules are rendered top-to-bottom at connect time; the first rule
/// whose `attribute` is `"tenant"` and whose expression renders a valid
/// non-empty id assigns that tenant. An empty registry (the default)
/// places every client in the default tenant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TenantsConf {
    /// Tenant assignment rules.
    #[serde(default)]
    pub rules: Vec<TenantRuleConf>,
}

/// One tenant assignment rule row in the configuration file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantRuleConf {
    /// Listener scope (`""` or `"*"` = all listeners).
    #[serde(default)]
    pub listener: String,
    /// Client attribute name (`"tenant"` drives assignment).
    #[serde(default = "default_tenant_attribute")]
    pub attribute: String,
    /// Expression template over the connect context.
    pub expression: String,
}

fn default_tenant_attribute() -> String {
    "tenant".to_string()
}

impl Default for TenantRuleConf {
    fn default() -> Self {
        Self {
            listener: String::new(),
            attribute: default_tenant_attribute(),
            expression: String::new(),
        }
    }
}

impl TenantsConf {
    /// Validates tenant rule bounds.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.rules.len() > broker_session::tenant::MAX_TENANT_RULES {
            return Err(ConfigError::Invalid(format!(
                "field `tenants.rules` holds {} entries, at most {} (code EXCEED_LIMIT)",
                self.rules.len(),
                broker_session::tenant::MAX_TENANT_RULES,
            )));
        }
        for (index, rule) in self.rules.iter().enumerate() {
            if rule.listener.len() > broker_session::tenant::MAX_TENANT_LISTENER_LEN {
                return Err(ConfigError::Invalid(format!(
                    "tenants.rules[{index}].listener must not exceed {} chars",
                    broker_session::tenant::MAX_TENANT_LISTENER_LEN,
                )));
            }
            if rule.attribute.is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "tenants.rules[{index}].attribute must not be empty"
                )));
            }
            if rule.attribute.len() > broker_session::tenant::MAX_TENANT_ATTRIBUTE_LEN {
                return Err(ConfigError::Invalid(format!(
                    "tenants.rules[{index}].attribute must not exceed {} chars",
                    broker_session::tenant::MAX_TENANT_ATTRIBUTE_LEN,
                )));
            }
            if rule.expression.len() > broker_session::tenant::MAX_TENANT_EXPRESSION_LEN {
                return Err(ConfigError::Invalid(format!(
                    "tenants.rules[{index}].expression must not exceed {} chars",
                    broker_session::tenant::MAX_TENANT_EXPRESSION_LEN,
                )));
            }
        }
        Ok(())
    }
}

/// Distributed clustering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterConf {
    /// Whether multi-node distributed clustering is enabled.
    #[serde(default = "default_false")]
    pub enabled: bool,
    /// Cluster SWIM UDP bind address for peer discovery and membership.
    #[serde(default = "default_cluster_bind")]
    pub bind: String,
    /// Gossip membership bind address for peer discovery.
    #[serde(default = "default_gossip_bind")]
    pub gossip_bind: String,
    /// Multiplexed data plane bind address for inter-broker message routing.
    #[serde(default = "default_quic_bind")]
    pub quic_bind: String,
    /// Seed node addresses to join an existing cluster.
    #[serde(default)]
    pub seed_nodes: Vec<String>,
}

// Reason: loopback with a dedicated SWIM port keeps single-node test clusters
// off client ports while matching the `--cluster-bind` flag default.
fn default_cluster_bind() -> String {
    "127.0.0.1:19883".to_string()
}
// Reason: the conventional gossip port keeps peer discovery off client ports.
fn default_gossip_bind() -> String {
    "0.0.0.0:7946".to_string()
}
// Reason: separates the inter-broker data plane from client listeners.
fn default_quic_bind() -> String {
    "0.0.0.0:9092".to_string()
}

impl Default for ClusterConf {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: default_cluster_bind(),
            gossip_bind: default_gossip_bind(),
            quic_bind: default_quic_bind(),
            seed_nodes: Vec::new(),
        }
    }
}

impl ClusterConf {
    /// Validates cluster addresses.
    pub fn validate(&self) -> Result<(), ConfigError> {
        check_bind("cluster.bind", &self.bind, false)?;
        check_bind("cluster.gossip_bind", &self.gossip_bind, false)?;
        check_bind("cluster.quic_bind", &self.quic_bind, false)?;
        if self.seed_nodes.len() > 64 {
            return Err(invalid(
                "cluster.seed_nodes",
                &format!("{} entries", self.seed_nodes.len()),
                "must hold at most 64 entries",
            ));
        }
        for seed in &self.seed_nodes {
            // TODO(parity): the canonical seed address form (host:port vs
            // URL) is undecided; host:port is accepted conservatively.
            check_bind("cluster.seed_nodes", seed, false)?;
        }
        Ok(())
    }
}

/// Commercial licence handling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenceConf {
    /// Path to the enterprise cryptographic license key file.
    #[serde(default = "default_license_file")]
    pub license_file: String,
    /// Enterprise commercial license key for multi-node clustering.
    #[serde(default)]
    pub license_key: String,
    /// Trusted licence-signing keys: a JSON file or directory of JSON files.
    #[serde(default)]
    pub trusted_keys_path: String,
    /// Write the installation licence request to this path and exit.
    #[serde(default)]
    pub request_out: String,
    /// Install the licence token read from this path and exit.
    #[serde(default)]
    pub install_file: String,
    /// Days before expiry that the approaching-expiry alarm and log warning start.
    #[serde(default = "default_expiry_warn_days")]
    pub expiry_warn_days: u64,
}

// Reason: single well-known path for operator tooling; empty means none.
fn default_license_file() -> String {
    "/etc/indramqtt/license.key".to_string()
}
// Reason: 30 days gives operators time to renew before grace runs out.
fn default_expiry_warn_days() -> u64 {
    30
}

impl Default for LicenceConf {
    fn default() -> Self {
        Self {
            license_file: default_license_file(),
            license_key: String::new(),
            trusted_keys_path: String::new(),
            request_out: String::new(),
            install_file: String::new(),
            expiry_warn_days: default_expiry_warn_days(),
        }
    }
}

impl LicenceConf {
    /// Validates licence settings.
    pub fn validate(&self) -> Result<(), ConfigError> {
        check_range_u64("licence.expiry_warn_days", self.expiry_warn_days, 0, 365)?;
        Ok(())
    }
}

/// Protocol gateway settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct GatewayConf {
    /// CoAP gateway UDP listen address. Empty disables the gateway.
    #[serde(default)]
    pub coap_bind: String,
}

impl GatewayConf {
    /// Validates gateway settings.
    pub fn validate(&self) -> Result<(), ConfigError> {
        check_bind("gateway.coap_bind", &self.coap_bind, true)?;
        Ok(())
    }
}

/// Durable persistence settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PersistenceConf {
    /// Durable stream journal directory. Empty disables journaling.
    #[serde(default)]
    pub stream_dir: String,
}

impl PersistenceConf {
    /// Validates persistence settings (any path; empty disables).
    pub fn validate(&self) -> Result<(), ConfigError> {
        Ok(())
    }
}

/// LDAP directory authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LdapConf {
    /// Directory server URL for LDAP authentication. Empty disables LDAP.
    #[serde(default)]
    pub server_url: String,
    /// Base DN under which directory users are searched.
    #[serde(default)]
    pub base_dn: String,
    /// Service account DN used for the initial bind plus search.
    #[serde(default)]
    pub bind_dn: String,
    /// Service account password for the initial bind.
    #[serde(default)]
    pub bind_password: String,
    /// User search filter with a {username} placeholder, escaped per RFC 4515.
    #[serde(default = "default_ldap_user_filter")]
    pub user_filter: String,
    /// User-entry attribute listing directory groups.
    #[serde(default = "default_ldap_group_attribute")]
    pub group_attribute: String,
    /// Required group DN: the entry must list this DN to connect.
    #[serde(default)]
    pub required_group: String,
    /// Path to a PEM CA certificate for private directories.
    #[serde(default)]
    pub ca_cert_path: String,
    /// Bound on concurrent directory authentications.
    #[serde(default = "default_ldap_pool_size")]
    pub pool_size: usize,
    /// Timeout covering TCP connect plus TLS handshake.
    #[serde(default = "default_ldap_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    /// Timeout covering each directory bind/search round-trip.
    #[serde(default = "default_ldap_read_timeout_ms")]
    pub read_timeout_ms: u64,
}

// Reason: matches the directory default the kernel authenticator uses.
fn default_ldap_user_filter() -> String {
    "(uid={username})".to_string()
}
// Reason: the standard directory attribute for group membership.
fn default_ldap_group_attribute() -> String {
    "memberOf".to_string()
}
// Reason: 8 concurrent directory binds absorb CONNECT bursts without
// overwhelming the directory.
fn default_ldap_pool_size() -> usize {
    8
}
// Reason: 5 s tolerates a slow directory while keeping the accept path bounded.
fn default_ldap_connect_timeout_ms() -> u64 {
    5_000
}
// Reason: 5 s per bind/search round-trip matches the connect timeout.
fn default_ldap_read_timeout_ms() -> u64 {
    5_000
}

impl Default for LdapConf {
    fn default() -> Self {
        Self {
            server_url: String::new(),
            base_dn: String::new(),
            bind_dn: String::new(),
            bind_password: String::new(),
            user_filter: default_ldap_user_filter(),
            group_attribute: default_ldap_group_attribute(),
            required_group: String::new(),
            ca_cert_path: String::new(),
            pool_size: default_ldap_pool_size(),
            connect_timeout_ms: default_ldap_connect_timeout_ms(),
            read_timeout_ms: default_ldap_read_timeout_ms(),
        }
    }
}

impl LdapConf {
    /// Whether directory authentication is configured.
    #[must_use]
    pub fn enabled(&self) -> bool {
        !self.server_url.trim().is_empty()
    }

    /// Validates LDAP settings. Fail closed: a half-configured directory
    /// is a startup error, never a silent fallback.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.enabled() {
            check_range_usize("ldap.pool_size", self.pool_size, 1, 32)?;
            check_range_u64(
                "ldap.connect_timeout_ms",
                self.connect_timeout_ms,
                100,
                60_000,
            )?;
            check_range_u64("ldap.read_timeout_ms", self.read_timeout_ms, 100, 60_000)?;
            return Ok(());
        }
        if !(self.server_url.starts_with("ldap://") || self.server_url.starts_with("ldaps://")) {
            return Err(invalid(
                "ldap.server_url",
                &self.server_url,
                "must start with ldap:// or ldaps://",
            ));
        }
        if self.base_dn.trim().is_empty() {
            return Err(invalid(
                "ldap.base_dn",
                &self.base_dn,
                "is required when LDAP is enabled",
            ));
        }
        if !self.user_filter.contains("{username}") {
            return Err(invalid(
                "ldap.user_filter",
                &self.user_filter,
                "must contain {username}",
            ));
        }
        if self.group_attribute.trim().is_empty() {
            return Err(invalid(
                "ldap.group_attribute",
                &self.group_attribute,
                "must not be empty when LDAP is enabled",
            ));
        }
        check_range_usize("ldap.pool_size", self.pool_size, 1, 32)?;
        check_range_u64(
            "ldap.connect_timeout_ms",
            self.connect_timeout_ms,
            100,
            60_000,
        )?;
        check_range_u64("ldap.read_timeout_ms", self.read_timeout_ms, 100, 60_000)?;
        Ok(())
    }
}

/// Kerberos authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KerberosConf {
    /// Keytab file for Kerberos authentication. Empty disables Kerberos.
    #[serde(default)]
    pub keytab_path: String,
    /// Service principal name held in the keytab.
    #[serde(default)]
    pub service_principal: String,
    /// Expected service realm. Empty disables the realm check on the service name.
    #[serde(default)]
    pub realm: String,
    /// Trusted client realms. Empty allows any realm that verifies.
    #[serde(default)]
    pub allowed_realms: Vec<String>,
    /// Clock-skew allowance in seconds for ticket validity and authenticator timestamps.
    #[serde(default = "default_kerberos_clock_skew_secs")]
    pub clock_skew_secs: u64,
    /// Comma-separated principal=role mappings for verified client principals.
    #[serde(default)]
    pub role_map: String,
    /// Replay-cache bound for Kerberos authenticators.
    #[serde(default = "default_kerberos_replay_max")]
    pub replay_max_entries: usize,
}

// Reason: 5 minutes matches the conventional ticket-skew allowance.
fn default_kerberos_clock_skew_secs() -> u64 {
    300
}
// Reason: 1024 entries bounds CONNECT-only memory under 128 KiB (each
// entry is under 128 bytes).
fn default_kerberos_replay_max() -> usize {
    1_024
}

impl Default for KerberosConf {
    fn default() -> Self {
        Self {
            keytab_path: String::new(),
            service_principal: String::new(),
            realm: String::new(),
            allowed_realms: Vec::new(),
            clock_skew_secs: default_kerberos_clock_skew_secs(),
            role_map: String::new(),
            replay_max_entries: default_kerberos_replay_max(),
        }
    }
}

impl KerberosConf {
    /// Whether Kerberos authentication is configured.
    #[must_use]
    pub fn enabled(&self) -> bool {
        !self.keytab_path.trim().is_empty()
    }

    /// Validates Kerberos settings. Fail closed: a keytab without a
    /// service principal is a startup error, never a silent bypass.
    pub fn validate(&self) -> Result<(), ConfigError> {
        check_range_u64("kerberos.clock_skew_secs", self.clock_skew_secs, 1, 3_600)?;
        check_range_usize(
            "kerberos.replay_max_entries",
            self.replay_max_entries,
            16,
            8_192,
        )?;
        if self.allowed_realms.len() > 32 {
            return Err(invalid(
                "kerberos.allowed_realms",
                &format!("{} entries", self.allowed_realms.len()),
                "must hold at most 32 entries",
            ));
        }
        if self.enabled() && self.service_principal.trim().is_empty() {
            return Err(invalid(
                "kerberos.service_principal",
                &self.service_principal,
                "is required when a keytab is configured",
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Top-level file configuration
// ---------------------------------------------------------------------------

/// The full static file configuration: every startup/file setting in one
/// validated document.
///
/// TOML layout mirrors the shipped template: `[node]`, `[listeners.*]`,
/// `[quotas]`, `[session]`, `[logging]`, `[rules_engine]` (with `[rules]`
/// accepted as an alias for files written before the rename),
/// `[auth]`, `[cluster]`, `[licence]`, `[gateway]`, `[persistence]`,
/// `[ldap]` and `[kerberos]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct BrokerConfig {
    /// Node identity and kernel paths.
    #[serde(default)]
    pub node: NodeConf,
    /// Network listeners.
    #[serde(default)]
    pub listeners: ListenersConf,
    /// Quotas and rate limiting.
    #[serde(default)]
    pub quotas: QuotasConf,
    /// Session and protocol invariants.
    #[serde(default)]
    pub session: SessionConf,
    /// Kernel logging.
    #[serde(default)]
    pub logging: LoggingConf,
    /// Rule-engine tuning.
    #[serde(default, alias = "rules")]
    pub rules_engine: RulesEngineConf,
    /// Auth policy.
    #[serde(default)]
    pub auth: AuthPolicyConf,
    /// Tenant assignment rules.
    #[serde(default)]
    pub tenants: TenantsConf,
    /// Clustering.
    #[serde(default)]
    pub cluster: ClusterConf,
    /// Licence handling.
    #[serde(default)]
    pub licence: LicenceConf,
    /// Protocol gateways.
    #[serde(default)]
    pub gateway: GatewayConf,
    /// Durable persistence.
    #[serde(default)]
    pub persistence: PersistenceConf,
    /// LDAP directory authentication.
    #[serde(default)]
    pub ldap: LdapConf,
    /// Kerberos authentication.
    #[serde(default)]
    pub kerberos: KerberosConf,
    /// Delayed-publish scheduler bounds.
    #[serde(default)]
    pub delayed: DelayedConf,
    /// JWT verification against JWKS.
    #[serde(default)]
    pub jwks: JwksConf,
    /// Database-backed authentication.
    #[serde(default)]
    pub dbauth: DbAuthConf,
    /// HTTP webhook verdict service.
    #[serde(default)]
    pub webhook: WebhookConf,
    /// Observability sampling.
    #[serde(default)]
    pub observability: ObservabilityConf,
}

/// Delayed-publish scheduler bounds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DelayedConf {
    /// Upper bound for delayed deferrals in seconds. Default one day (86400).
    #[serde(default = "default_delayed_max_secs")]
    pub max_secs: u64,
}

// Reason: one day covers device schedules without pinning a wheel slot and
// a file row indefinitely; matches the per-message sleep ceiling it replaced.
fn default_delayed_max_secs() -> u64 {
    86400
}

impl Default for DelayedConf {
    fn default() -> Self {
        Self {
            max_secs: default_delayed_max_secs(),
        }
    }
}

impl DelayedConf {
    /// Validates the delayed scheduler bound.
    pub fn validate(&self) -> Result<(), ConfigError> {
        check_range_u64("delayed.max_secs", self.max_secs, 1, 86_400)?;
        Ok(())
    }
}

/// JWT verification against JWKS.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JwksConf {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub audience: String,
    #[serde(default = "default_jwks_refresh_period")]
    pub refresh_period_secs: u64,
    #[serde(default = "default_jwks_fetch_timeout")]
    pub fetch_timeout_ms: u64,
    #[serde(default = "default_jwks_refresh_timeout")]
    pub refresh_timeout_ms: u64,
    #[serde(default = "default_jwks_cache_max")]
    pub cache_max_keys: usize,
    #[serde(default = "default_jwks_cache_ttl")]
    pub cache_ttl_secs: u64,
    #[serde(default = "default_jwks_clock_skew")]
    pub clock_skew_secs: u64,
    #[serde(default)]
    pub ca_cert: String,
}

// Reason: five minutes bounds key staleness while the unknown-kid trigger
// covers fast rotation.
fn default_jwks_refresh_period() -> u64 {
    300
}
// Reason: 5 s tolerates a slow endpoint while keeping a stalled accept bounded.
fn default_jwks_fetch_timeout() -> u64 {
    5000
}
// Reason: 5 s covers one fetch plus the singleflight cache-poll window.
fn default_jwks_refresh_timeout() -> u64 {
    5000
}
// Reason: JWKS documents carry a handful of rotation keys, so 32 entries of
// about 2 KiB cap CONNECT-only key memory near 64 KiB.
fn default_jwks_cache_max() -> usize {
    32
}
// Reason: equals the refresh period so the background task keeps entries fresh.
fn default_jwks_cache_ttl() -> u64 {
    300
}
// Reason: a minute of issuer/broker drift tolerance without accepting clearly
// expired tokens.
fn default_jwks_clock_skew() -> u64 {
    60
}

impl Default for JwksConf {
    fn default() -> Self {
        Self {
            url: String::new(),
            issuer: String::new(),
            audience: String::new(),
            refresh_period_secs: default_jwks_refresh_period(),
            fetch_timeout_ms: default_jwks_fetch_timeout(),
            refresh_timeout_ms: default_jwks_refresh_timeout(),
            cache_max_keys: default_jwks_cache_max(),
            cache_ttl_secs: default_jwks_cache_ttl(),
            clock_skew_secs: default_jwks_clock_skew(),
            ca_cert: String::new(),
        }
    }
}

impl JwksConf {
    /// Whether JWT authentication is configured.
    #[must_use]
    pub fn enabled(&self) -> bool {
        !self.url.trim().is_empty()
    }

    /// Validates JWKS settings. Fail closed: a non-https endpoint is a
    /// startup error, never a silent bypass.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.enabled() && !self.url.starts_with("https://") {
            return Err(invalid("jwks.url", &self.url, "must start with https://"));
        }
        check_range_u64(
            "jwks.refresh_period_secs",
            self.refresh_period_secs,
            1,
            86_400,
        )?;
        check_range_u64("jwks.fetch_timeout_ms", self.fetch_timeout_ms, 100, 60_000)?;
        check_range_u64(
            "jwks.refresh_timeout_ms",
            self.refresh_timeout_ms,
            100,
            60_000,
        )?;
        check_range_usize("jwks.cache_max_keys", self.cache_max_keys, 1, 256)?;
        check_range_u64("jwks.cache_ttl_secs", self.cache_ttl_secs, 1, 86_400)?;
        check_range_u64("jwks.clock_skew_secs", self.clock_skew_secs, 0, 3_600)?;
        Ok(())
    }
}

/// Database-backed authentication.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DbAuthConf {
    #[serde(default)]
    pub postgres_url: String,
    #[serde(default)]
    pub mysql_url: String,
    #[serde(default)]
    pub redis_url: String,
    #[serde(default)]
    pub mongodb_url: String,
    #[serde(default = "default_dbauth_pool")]
    pub pool_size: usize,
    #[serde(default = "default_dbauth_connect_timeout")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_dbauth_read_timeout")]
    pub read_timeout_ms: u64,
    #[serde(default = "default_dbauth_cache_size")]
    pub cache_size: usize,
    #[serde(default = "default_dbauth_cache_ttl")]
    pub cache_ttl_secs: u64,
}

fn default_dbauth_pool() -> usize {
    8
}
// Reason: 3 s covers TCP connect plus container-start jitter while failing
// closed fast enough to not stall accepts.
fn default_dbauth_connect_timeout() -> u64 {
    3000
}
// Reason: 3 s covers one lookup round-trip.
fn default_dbauth_read_timeout() -> u64 {
    3000
}
// Reason: 1024 verdicts per source and kind stay under one megabyte total.
fn default_dbauth_cache_size() -> usize {
    1024
}
// Reason: one minute bounds a stale ACL after a change.
fn default_dbauth_cache_ttl() -> u64 {
    60
}

impl Default for DbAuthConf {
    fn default() -> Self {
        Self {
            postgres_url: String::new(),
            mysql_url: String::new(),
            redis_url: String::new(),
            mongodb_url: String::new(),
            pool_size: default_dbauth_pool(),
            connect_timeout_ms: default_dbauth_connect_timeout(),
            read_timeout_ms: default_dbauth_read_timeout(),
            cache_size: default_dbauth_cache_size(),
            cache_ttl_secs: default_dbauth_cache_ttl(),
        }
    }
}

impl DbAuthConf {
    /// Validates database authentication settings.
    pub fn validate(&self) -> Result<(), ConfigError> {
        check_range_usize("dbauth.pool_size", self.pool_size, 1, 32)?;
        check_range_u64(
            "dbauth.connect_timeout_ms",
            self.connect_timeout_ms,
            100,
            60_000,
        )?;
        check_range_u64("dbauth.read_timeout_ms", self.read_timeout_ms, 100, 60_000)?;
        check_range_usize("dbauth.cache_size", self.cache_size, 0, 100_000)?;
        check_range_u64("dbauth.cache_ttl_secs", self.cache_ttl_secs, 0, 3_600)?;
        Ok(())
    }
}

/// HTTP webhook verdict service.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WebhookConf {
    #[serde(default)]
    pub url: String,
    #[serde(default = "default_webhook_pool")]
    pub pool_size: usize,
    #[serde(default = "default_webhook_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "default_webhook_threshold")]
    pub breaker_threshold: u32,
    #[serde(default = "default_webhook_reset")]
    pub breaker_reset_ms: u64,
    #[serde(default = "default_webhook_cache_size")]
    pub cache_size: usize,
    #[serde(default = "default_webhook_cache_ttl")]
    pub cache_ttl_secs: u64,
}

fn default_webhook_pool() -> usize {
    8
}
// Reason: 2 s bounds the worst case a CONNECT or publish waits while
// tolerating a loaded loopback verdict service.
fn default_webhook_timeout() -> u64 {
    2000
}
// Reason: 5 tolerates one transient while tripping fast under a real outage.
fn default_webhook_threshold() -> u32 {
    5
}
// Reason: 30 s gives a dead endpoint time to recover without hammering it.
fn default_webhook_reset() -> u64 {
    30000
}
// Reason: 1024 small entries hold under 256 KiB.
fn default_webhook_cache_size() -> usize {
    1024
}
// Reason: one minute removes per-packet HTTP cost for steady publishers
// while capping the stale-verdict window.
fn default_webhook_cache_ttl() -> u64 {
    60
}

impl Default for WebhookConf {
    fn default() -> Self {
        Self {
            url: String::new(),
            pool_size: default_webhook_pool(),
            timeout_ms: default_webhook_timeout(),
            breaker_threshold: default_webhook_threshold(),
            breaker_reset_ms: default_webhook_reset(),
            cache_size: default_webhook_cache_size(),
            cache_ttl_secs: default_webhook_cache_ttl(),
        }
    }
}

impl WebhookConf {
    /// Validates webhook settings.
    pub fn validate(&self) -> Result<(), ConfigError> {
        check_range_usize("webhook.pool_size", self.pool_size, 1, 32)?;
        check_range_u64("webhook.timeout_ms", self.timeout_ms, 100, 60_000)?;
        check_range_u64(
            "webhook.breaker_threshold",
            u64::from(self.breaker_threshold),
            1,
            100,
        )?;
        check_range_u64(
            "webhook.breaker_reset_ms",
            self.breaker_reset_ms,
            1_000,
            600_000,
        )?;
        check_range_usize("webhook.cache_size", self.cache_size, 0, 100_000)?;
        check_range_u64("webhook.cache_ttl_secs", self.cache_ttl_secs, 0, 3_600)?;
        Ok(())
    }
}

/// Observability sampling.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservabilityConf {
    #[serde(default = "default_monitor_sample")]
    pub monitor_sample_secs: u64,
}

fn default_monitor_sample() -> u64 {
    10
}

impl Default for ObservabilityConf {
    fn default() -> Self {
        Self {
            monitor_sample_secs: default_monitor_sample(),
        }
    }
}

impl BrokerConfig {
    /// Validates every section. Empty defaults are valid.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.node.validate()?;
        self.listeners.validate()?;
        self.quotas.validate()?;
        self.session.validate()?;
        self.logging.validate()?;
        self.rules_engine.validate()?;
        self.auth.validate()?;
        self.tenants.validate()?;
        self.cluster.validate()?;
        self.licence.validate()?;
        self.gateway.validate()?;
        self.persistence.validate()?;
        self.ldap.validate()?;
        self.kerberos.validate()?;
        self.delayed.validate()?;
        self.jwks.validate()?;
        self.dbauth.validate()?;
        self.webhook.validate()?;
        Ok(())
    }

    /// Parses a TOML document and validates it. Wrong types fail here with
    /// the setting path; out-of-range values fail in [`validate`](Self::validate).
    pub fn parse_toml(text: &str) -> Result<Self, ConfigError> {
        let table: toml::Table = toml::from_str(text)
            .map_err(|err| ConfigError::Invalid(format!("config value is invalid: {err}")))?;
        check_toml_types(&table)?;
        let parsed: Self = toml::Value::Table(table)
            .try_into()
            .map_err(|err| ConfigError::Invalid(format!("config value is invalid: {err}")))?;
        parsed.validate()?;
        Ok(parsed)
    }

    /// Serialises this configuration to TOML.
    pub fn to_toml(&self) -> Result<String, ConfigError> {
        toml::to_string(self)
            .map_err(|err| ConfigError::Invalid(format!("config serialisation failed: {err}")))
    }
}

// ---------------------------------------------------------------------------
// Derived artefacts: JSON Schema and settings reference
// ---------------------------------------------------------------------------

/// Builds the generated JSON Schema (draft 2020-12) for [`BrokerConfig`].
///
/// The schema is data, not hand-written documentation: every property's
/// type, default, valid range and description comes from the section
/// structs above, so the checked-in `schemas/config-schema.json` file can
/// never drift from the code that validates at startup.
#[must_use]
pub fn json_schema() -> serde_json::Value {
    use serde_json::json;
    let mut properties = serde_json::Map::new();
    for (section, fields) in schema_sections() {
        let mut section_props = serde_json::Map::new();
        for field in fields {
            if let Some((group, leaf)) = field.name.split_once('.') {
                // Dotted listener names (e.g. `tcp.bind`) serialise as nested
                // objects (`listeners.tcp.bind`), never as flat `tcp.bind`
                // keys, so the schema nests them to match `BrokerConfig`.
                let group_value = section_props.entry(group.to_string()).or_insert_with(|| {
                    json!({
                        "type": "object",
                        "properties": {},
                    })
                });
                if let Some(group_obj) = group_value.as_object_mut() {
                    if let Some(props) = group_obj.get_mut("properties") {
                        if let Some(props_map) = props.as_object_mut() {
                            props_map.insert(leaf.to_string(), field.json());
                        }
                    }
                }
            } else {
                section_props.insert(field.name.to_string(), field.json());
            }
        }
        properties.insert(
            section.to_string(),
            json!({
                "type": "object",
                "properties": section_props,
            }),
        );
    }
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://indramqtt.com/schemas/config-schema.json",
        "title": "IndraMQTT broker configuration",
        "description": "Typed schema for the IndraMQTT broker file configuration. Generated from the single source of truth in broker-config; do not edit by hand.",
        "type": "object",
        "properties": properties,
    })
}

struct SchemaField {
    name: &'static str,
    field_type: &'static str,
    default: serde_json::Value,
    description: &'static str,
    extra: serde_json::Value,
}

impl SchemaField {
    fn json(&self) -> serde_json::Value {
        let mut obj = serde_json::Map::new();
        obj.insert(
            "type".to_string(),
            serde_json::Value::String(self.field_type.to_string()),
        );
        obj.insert("default".to_string(), self.default.clone());
        obj.insert(
            "description".to_string(),
            serde_json::Value::String(self.description.to_string()),
        );
        if let serde_json::Value::Object(extra) = &self.extra {
            for (key, value) in extra {
                obj.insert(key.clone(), value.clone());
            }
        }
        serde_json::Value::Object(obj)
    }
}

fn str_field(name: &'static str, default: &str, doc: &'static str) -> SchemaField {
    SchemaField {
        name,
        field_type: "string",
        default: serde_json::Value::String(default.to_string()),
        description: doc,
        extra: serde_json::Value::Object(serde_json::Map::new()),
    }
}

fn bool_field(name: &'static str, default: bool, doc: &'static str) -> SchemaField {
    SchemaField {
        name,
        field_type: "boolean",
        default: serde_json::Value::Bool(default),
        description: doc,
        extra: serde_json::Value::Object(serde_json::Map::new()),
    }
}

fn int_field(
    name: &'static str,
    default: u64,
    min: u64,
    max: u64,
    doc: &'static str,
) -> SchemaField {
    SchemaField {
        name,
        field_type: "integer",
        default: serde_json::Value::Number(serde_json::Number::from(default)),
        description: doc,
        extra: serde_json::json!({"minimum": min, "maximum": max}),
    }
}

fn num_field(
    name: &'static str,
    default: f64,
    min: f64,
    max: f64,
    doc: &'static str,
) -> SchemaField {
    SchemaField {
        name,
        field_type: "number",
        default: serde_json::Number::from_f64(default)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        description: doc,
        extra: serde_json::json!({"minimum": min, "maximum": max}),
    }
}

fn enum_field(
    name: &'static str,
    default: &str,
    options: &[&str],
    doc: &'static str,
) -> SchemaField {
    SchemaField {
        name,
        field_type: "string",
        default: serde_json::Value::String(default.to_string()),
        description: doc,
        extra: serde_json::json!({"enum": options}),
    }
}

fn list_field(name: &'static str, doc: &'static str) -> SchemaField {
    SchemaField {
        name,
        field_type: "array",
        default: serde_json::Value::Array(Vec::new()),
        description: doc,
        extra: serde_json::json!({"items": {"type": "string"}}),
    }
}

fn superusers_field() -> SchemaField {
    SchemaField {
        name: "superusers",
        field_type: "array",
        default: serde_json::json!(["admin", "root"]),
        description: "Superuser usernames bypassing ACL rules.",
        extra: serde_json::json!({"items": {"type": "string"}}),
    }
}

/// Section names with their fields, used by both derived artefacts so the
/// JSON Schema and the reference table can never disagree on coverage.
fn schema_sections() -> Vec<(&'static str, Vec<SchemaField>)> {
    vec![
        (
            "node",
            vec![
                str_field(
                    "id",
                    "indra-node-1",
                    "Unique identifier for this broker node within the cluster.",
                ),
                str_field(
                    "data_dir",
                    "./data",
                    "Directory holding kernel persistent state (state.toml). Created on boot when missing.",
                ),
                str_field(
                    "brokerlink_bind",
                    "127.0.0.1:18883",
                    "BrokerLink IPC listen address for edge clients (TCP loopback).",
                ),
            ],
        ),
        (
            "listeners",
            vec![
                bool_field(
                    "tcp.enabled",
                    true,
                    "Whether the plaintext MQTT listener accepts connections.",
                ),
                str_field(
                    "tcp.bind",
                    "0.0.0.0:1883",
                    "Bind address for the plaintext MQTT listener.",
                ),
                int_field(
                    "tcp.max_connections",
                    1_000_000,
                    1,
                    10_000_000,
                    "Maximum concurrent connections on the plaintext MQTT listener.",
                ),
                int_field(
                    "tcp.backlog",
                    1024,
                    1,
                    65_536,
                    "Listener accept backlog for the plaintext MQTT listener.",
                ),
                bool_field(
                    "tls.enabled",
                    false,
                    "Whether the secure TLS MQTT listener accepts connections.",
                ),
                str_field(
                    "tls.bind",
                    "0.0.0.0:8883",
                    "Bind address for the secure TLS MQTT listener.",
                ),
                str_field(
                    "tls.cert_file",
                    "",
                    "Path to the PEM server certificate for the TLS listener.",
                ),
                str_field(
                    "tls.key_file",
                    "",
                    "Path to the PEM private key for the TLS listener.",
                ),
                bool_field(
                    "ws.enabled",
                    true,
                    "Whether the MQTT-over-WebSocket listener accepts connections.",
                ),
                str_field(
                    "ws.bind",
                    "0.0.0.0:8083",
                    "Bind address for the MQTT-over-WebSocket listener.",
                ),
                str_field(
                    "ws.path",
                    "/ws/mqtt",
                    "HTTP path serving MQTT-over-WebSocket traffic.",
                ),
                bool_field(
                    "wss.enabled",
                    false,
                    "Whether the secure WebSocket listener accepts connections.",
                ),
                str_field(
                    "wss.bind",
                    "0.0.0.0:8084",
                    "Bind address for the secure WebSocket listener.",
                ),
                str_field(
                    "wss.path",
                    "/ws/mqtt",
                    "HTTP path serving secure WebSocket traffic.",
                ),
                str_field(
                    "wss.cert_file",
                    "",
                    "Path to the PEM server certificate for the secure WebSocket listener.",
                ),
                str_field(
                    "wss.key_file",
                    "",
                    "Path to the PEM private key for the secure WebSocket listener.",
                ),
                bool_field(
                    "api.enabled",
                    true,
                    "Whether the management REST API and dashboard serve requests.",
                ),
                str_field(
                    "api.bind",
                    "0.0.0.0:18083",
                    "Bind address for the management REST API. Empty disables the API.",
                ),
            ],
        ),
        (
            "quotas",
            vec![
                int_field(
                    "default_max_connections",
                    10_000,
                    0,
                    1_000_000,
                    "Default max connections per authenticated username (0 = unlimited).",
                ),
                int_field(
                    "default_max_publish_rate",
                    50_000,
                    0,
                    10_000_000,
                    "Default token-bucket publish rate limit in messages per second (0 = unlimited).",
                ),
                num_field(
                    "burst_multiplier",
                    2.0,
                    1.0,
                    10.0,
                    "Token bucket burst multiplier (allows bursts up to burst times rate).",
                ),
            ],
        ),
        (
            "session",
            vec![
                int_field(
                    "max_session_expiry_secs",
                    86_400,
                    0,
                    2_592_000,
                    "Max session expiry interval in seconds.",
                ),
                int_field(
                    "max_offline_queue",
                    50_000,
                    1,
                    1_000_000,
                    "Maximum queued offline messages per session.",
                ),
                int_field(
                    "max_inflight_messages",
                    65_535,
                    1,
                    65_535,
                    "Maximum inflight unacknowledged QoS 1 and QoS 2 messages.",
                ),
                int_field(
                    "max_qos0_backlog",
                    1_000,
                    1,
                    100_000,
                    "Per-subscriber QoS 0 egress backlog bound; past it the oldest queued QoS 0 frame drops.",
                ),
                int_field(
                    "max_qos1_inflight",
                    100,
                    1,
                    100_000,
                    "Per-session QoS 1 inflight window bound.",
                ),
                int_field(
                    "max_qos1_spill",
                    1_000,
                    1,
                    100_000,
                    "Per-session QoS 1 spill bound past the window.",
                ),
                int_field(
                    "topic_alias_maximum",
                    10,
                    0,
                    65_535,
                    "Inbound topic-alias maximum advertised in CONNACK.",
                ),
                num_field(
                    "keep_alive_grace",
                    1.5,
                    1.0,
                    5.0,
                    "Keep-alive grace multiplier before disconnect.",
                ),
            ],
        ),
        (
            "logging",
            vec![enum_field(
                "level",
                "info",
                KNOWN_LOG_LEVELS,
                "Logging verbosity for the kernel (trace, debug, info, warn, error).",
            )],
        ),
        (
            "rules_engine",
            vec![
                int_field(
                    "window_channel_depth",
                    65_536,
                    1,
                    1_000_000,
                    "Ingress ring buffer channel depth for stateful window worker tasks.",
                ),
                enum_field(
                    "backpressure_policy",
                    "DropOldest",
                    KNOWN_BACKPRESSURE_POLICIES,
                    "Default memory backpressure policy when the rule buffer is full.",
                ),
                str_field(
                    "spill_dir",
                    "",
                    "Rule ingress spill directory. Empty keeps memory-only DropOldest; set to a directory to build the rule engine with SpillToDisk backpressure (1 MiB segments, 64 MiB total).",
                ),
            ],
        ),
        (
            "auth",
            vec![
                bool_field(
                    "enabled",
                    true,
                    "Whether authentication checks apply to client connects.",
                ),
                enum_field(
                    "password_hash",
                    "sha256",
                    KNOWN_PASSWORD_HASHES,
                    "Password hashing algorithm for stored credentials.",
                ),
                bool_field(
                    "allow_anonymous",
                    false,
                    "Whether anonymous connections are accepted while no users are configured.",
                ),
                superusers_field(),
            ],
        ),
        (
            "cluster",
            vec![
                bool_field(
                    "enabled",
                    false,
                    "Whether multi-node distributed clustering is enabled.",
                ),
                str_field(
                    "bind",
                    "127.0.0.1:19883",
                    "Cluster SWIM UDP bind address for peer discovery and membership.",
                ),
                str_field(
                    "gossip_bind",
                    "0.0.0.0:7946",
                    "Gossip membership bind address for peer discovery.",
                ),
                str_field(
                    "quic_bind",
                    "0.0.0.0:9092",
                    "Multiplexed data plane bind address for inter-broker message routing.",
                ),
                list_field(
                    "seed_nodes",
                    "Seed node addresses to join an existing cluster.",
                ),
            ],
        ),
        (
            "licence",
            vec![
                str_field(
                    "license_file",
                    "/etc/indramqtt/license.key",
                    "Path to the enterprise cryptographic license key file.",
                ),
                str_field(
                    "license_key",
                    "",
                    "Enterprise commercial license key for multi-node clustering.",
                ),
                str_field(
                    "trusted_keys_path",
                    "",
                    "Trusted licence-signing keys: a JSON file or directory of JSON files.",
                ),
                str_field(
                    "request_out",
                    "",
                    "Write the installation licence request to this path and exit.",
                ),
                str_field(
                    "install_file",
                    "",
                    "Install the licence token read from this path and exit.",
                ),
                int_field(
                    "expiry_warn_days",
                    30,
                    0,
                    365,
                    "Days before expiry that the approaching-expiry alarm and log warning start.",
                ),
            ],
        ),
        (
            "gateway",
            vec![str_field(
                "coap_bind",
                "",
                "CoAP gateway UDP listen address. Empty disables the gateway.",
            )],
        ),
        (
            "persistence",
            vec![str_field(
                "stream_dir",
                "",
                "Durable stream journal directory. Empty disables journaling.",
            )],
        ),
        (
            "ldap",
            vec![
                str_field(
                    "server_url",
                    "",
                    "Directory server URL for LDAP authentication. Empty disables LDAP.",
                ),
                str_field(
                    "base_dn",
                    "",
                    "Base DN under which directory users are searched.",
                ),
                str_field(
                    "bind_dn",
                    "",
                    "Service account DN used for the initial bind plus search.",
                ),
                str_field(
                    "bind_password",
                    "",
                    "Service account password for the initial bind.",
                ),
                str_field(
                    "user_filter",
                    "(uid={username})",
                    "User search filter with a {username} placeholder, escaped per RFC 4515.",
                ),
                str_field(
                    "group_attribute",
                    "memberOf",
                    "User-entry attribute listing directory groups.",
                ),
                str_field(
                    "required_group",
                    "",
                    "Required group DN: the entry must list this DN to connect.",
                ),
                str_field(
                    "ca_cert_path",
                    "",
                    "Path to a PEM CA certificate for private directories.",
                ),
                int_field(
                    "pool_size",
                    8,
                    1,
                    32,
                    "Bound on concurrent directory authentications.",
                ),
                int_field(
                    "connect_timeout_ms",
                    5_000,
                    100,
                    60_000,
                    "Timeout covering TCP connect plus TLS handshake.",
                ),
                int_field(
                    "read_timeout_ms",
                    5_000,
                    100,
                    60_000,
                    "Timeout covering each directory bind/search round-trip.",
                ),
            ],
        ),
        (
            "kerberos",
            vec![
                str_field(
                    "keytab_path",
                    "",
                    "Keytab file for Kerberos authentication. Empty disables Kerberos.",
                ),
                str_field(
                    "service_principal",
                    "",
                    "Service principal name held in the keytab.",
                ),
                str_field(
                    "realm",
                    "",
                    "Expected service realm. Empty disables the realm check on the service name.",
                ),
                list_field(
                    "allowed_realms",
                    "Trusted client realms. Empty allows any realm that verifies.",
                ),
                int_field(
                    "clock_skew_secs",
                    300,
                    1,
                    3_600,
                    "Clock-skew allowance in seconds for ticket validity and authenticator timestamps.",
                ),
                str_field(
                    "role_map",
                    "",
                    "Comma-separated principal=role mappings for verified client principals.",
                ),
                int_field(
                    "replay_max_entries",
                    1_024,
                    16,
                    8_192,
                    "Replay-cache bound for Kerberos authenticators.",
                ),
            ],
        ),
        (
            "delayed",
            vec![int_field(
                "max_secs",
                86_400,
                1,
                86_400,
                "Upper bound for delayed deferrals in seconds.",
            )],
        ),
        (
            "observability",
            vec![int_field(
                "monitor_sample_secs",
                10,
                0,
                3_600,
                "Monitor sampling interval in seconds.",
            )],
        ),
        (
            "jwks",
            vec![
                str_field(
                    "url",
                    "",
                    "JWKS endpoint URL for JWT authentication.",
                ),
                str_field(
                    "issuer",
                    "",
                    "Expected JWT issuer.",
                ),
                str_field(
                    "audience",
                    "",
                    "Expected JWT audience.",
                ),
            ],
        ),
        (
            "dbauth",
            vec![str_field(
                "postgres_url",
                "",
                "PostgreSQL URL for database authentication.",
            )],
        ),
        (
            "webhook",
            vec![str_field(
                "url",
                "",
                "HTTP webhook verdict endpoint.",
            )],
        ),
    ]
}

/// Renders the user-facing settings reference as Markdown.
///
/// Generated from the same section table as [`json_schema`], so the two
/// artefacts always agree on coverage. Regenerate with
/// `bash tools/gen_config_schema.sh`.
#[must_use]
pub fn settings_reference_markdown() -> String {
    let mut out = String::new();
    out.push_str("# IndraMQTT settings reference\n\n");
    out.push_str(
        "<!-- GENERATED by `bash tools/gen_config_schema.sh`. Do not edit by hand. -->\n\n",
    );
    out.push_str(
        "Every setting has exactly one typed home in the configuration schema. \
         Wrong types and out-of-range values are startup errors naming the setting.\n\n",
    );
    for (section, fields) in schema_sections() {
        out.push_str(&format!("## {section}\n\n"));
        out.push_str("| Setting | Type | Default | Range | Description |\n");
        out.push_str("|---|---|---|---|---|\n");
        for field in &fields {
            let default = match &field.default {
                serde_json::Value::String(text) => text.clone(),
                other => other.to_string(),
            }
            .replace('|', "\\|");
            let extra = match &field.extra {
                serde_json::Value::Object(map) => {
                    if let Some(values) = map.get("enum") {
                        format!("{values}")
                    } else {
                        let min = map.get("minimum").map(ToString::to_string);
                        let max = map.get("maximum").map(ToString::to_string);
                        match (min, max) {
                            (Some(min), Some(max)) => format!("{min}..={max}"),
                            _ => String::new(),
                        }
                    }
                }
                _ => String::new(),
            };
            let range = if extra.is_empty() {
                field.field_type.to_string()
            } else {
                extra
            };
            out.push_str(&format!(
                "| `{section}.{}` | {} | `{}` | {} | {} |\n",
                field.name, field.field_type, default, range, field.description
            ));
        }
        out.push('\n');
    }
    out
}

/// Checks a JSON sample document against the generated schema's core
/// constraints without any extra dependency.
///
/// Verifies sections exist with the right JSON types, enum fields hold
/// known values, and numeric fields sit inside their ranges. Returns the
/// first violation as a string naming the setting.
pub fn validate_json_sample(sample: &serde_json::Value) -> Result<(), String> {
    let get = |section: &str, field: &str| -> Result<&serde_json::Value, String> {
        let mut current = sample
            .get(section)
            .ok_or_else(|| format!("{section}.{field} is missing"))?;
        for part in field.split('.') {
            current = current
                .get(part)
                .ok_or_else(|| format!("{section}.{field} is missing"))?;
        }
        Ok(current)
    };
    let check_enum = |section: &str, field: &str, known: &[&str]| {
        let value = get(section, field)?;
        let text = value
            .as_str()
            .ok_or_else(|| format!("{section}.{field} must be a string"))?;
        if !known.contains(&text) {
            return Err(format!("{section}.{field} {text:?} is invalid"));
        }
        Ok(())
    };
    let check_bind_field = |section: &str, field: &str, allow_empty: bool| {
        let value = get(section, field)?;
        let text = value
            .as_str()
            .ok_or_else(|| format!("{section}.{field} must be a string"))?;
        if text.is_empty() {
            if allow_empty {
                return Ok(());
            }
            return Err(format!("{section}.{field} must not be empty"));
        }
        check_bind(&format!("{section}.{field}"), text, allow_empty)
            .map_err(|err| err.to_string())?;
        Ok(())
    };
    check_bind_field("node", "brokerlink_bind", false)?;
    check_bind_field("listeners", "tcp.bind", false)?;
    check_enum("logging", "level", KNOWN_LOG_LEVELS)?;
    check_enum(
        "rules_engine",
        "backpressure_policy",
        KNOWN_BACKPRESSURE_POLICIES,
    )?;
    check_enum("auth", "password_hash", KNOWN_PASSWORD_HASHES)?;
    let depth = get("rules_engine", "window_channel_depth")?
        .as_u64()
        .ok_or_else(|| "rules_engine.window_channel_depth must be an integer".to_string())?;
    if !(1..=1_000_000).contains(&depth) {
        return Err("rules_engine.window_channel_depth out of range".to_string());
    }
    let backlog = get("session", "max_qos0_backlog")?
        .as_u64()
        .ok_or_else(|| "session.max_qos0_backlog must be an integer".to_string())?;
    if !(1..=100_000).contains(&backlog) {
        return Err("session.max_qos0_backlog out of range".to_string());
    }
    Ok(())
}

/// Validates a JSON sample document against the generated JSON Schema
/// itself (draft 2020-12 subset used by [`json_schema`]).
///
/// Walks `schema["properties"]` recursively so nested listener objects
/// (`listeners.tcp.bind`, `listeners.api.bind`, ...) are checked where
/// they serialise, not as flat `tcp.bind` keys. Type, `enum`, `minimum`
/// and `maximum` constraints come from the schema document, so the sample
/// cannot pass unless the generated artefact describes it.
pub fn validate_json_against_schema(
    sample: &serde_json::Value,
    schema: &serde_json::Value,
) -> Result<(), String> {
    fn check_value(
        path: &str,
        value: &serde_json::Value,
        node: &serde_json::Value,
    ) -> Result<(), String> {
        if let Some(expected) = node.get("type").and_then(|v| v.as_str()) {
            let ok = match expected {
                "object" => value.is_object(),
                "array" => value.is_array(),
                "string" => value.is_string(),
                "boolean" => value.is_boolean(),
                "integer" => value.as_u64().is_some() || value.as_i64().is_some(),
                "number" => value.is_number(),
                _ => true,
            };
            if !ok {
                return Err(format!("{path} must be {expected}"));
            }
        }
        if let Some(options) = node.get("enum") {
            if let Some(list) = options.as_array() {
                if !list.contains(value) {
                    return Err(format!("{path} {value} is invalid"));
                }
            }
        }
        if let (Some(min), Some(value_num)) =
            (node.get("minimum").and_then(|v| v.as_f64()), value.as_f64())
        {
            if value_num < min {
                return Err(format!("{path} out of range"));
            }
        }
        if let (Some(max), Some(value_num)) =
            (node.get("maximum").and_then(|v| v.as_f64()), value.as_f64())
        {
            if value_num > max {
                return Err(format!("{path} out of range"));
            }
        }
        if let Some(props) = node.get("properties").and_then(|v| v.as_object()) {
            let obj = value
                .as_object()
                .ok_or_else(|| format!("{path} must be an object"))?;
            for (name, sub_schema) in props {
                let child_path = if path.is_empty() {
                    name.clone()
                } else {
                    format!("{path}.{name}")
                };
                if let Some(child) = obj.get(name) {
                    check_value(&child_path, child, sub_schema)?;
                }
            }
        }
        if let Some(items) = node.get("items") {
            if let Some(list) = value.as_array() {
                for entry in list {
                    check_value(path, entry, items)?;
                }
            }
        }
        Ok(())
    }

    check_value("", sample, schema)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_defaults_validate_clean() {
        BrokerConfig::default()
            .validate()
            .expect("schema defaults must validate");
    }

    #[test]
    fn schema_rejects_bad_port_naming_the_setting() {
        let mut config = BrokerConfig::default();
        config.listeners.tcp.bind = "0.0.0.0:notaport".to_string();
        let err = config.validate().expect_err("non-numeric port must fail");
        let text = err.to_string();
        assert!(
            text.contains("listeners.tcp.bind"),
            "error must name the setting, got: {text}"
        );
        assert!(
            text.contains("notaport"),
            "error must name the offending value, got: {text}"
        );
    }

    #[test]
    fn schema_rejects_bad_size_bound_naming_the_setting() {
        let mut config = BrokerConfig::default();
        config.session.max_qos0_backlog = 0;
        let err = config.validate().expect_err("zero backlog must fail");
        let text = err.to_string();
        assert!(
            text.contains("session.max_qos0_backlog"),
            "error must name the setting, got: {text}"
        );
        assert!(
            text.contains('0'),
            "error must name the offending value, got: {text}"
        );
    }

    #[test]
    fn schema_rejects_bad_enum_naming_the_setting() {
        let mut config = BrokerConfig::default();
        config.logging.level = "verbose".to_string();
        let err = config.validate().expect_err("unknown level must fail");
        let text = err.to_string();
        assert!(
            text.contains("logging.level"),
            "error must name the setting, got: {text}"
        );
        assert!(
            text.contains("verbose"),
            "error must name the offending value, got: {text}"
        );
    }

    #[test]
    fn schema_rejects_wrong_toml_types_naming_the_setting() {
        // A port given as a boolean, a size bound as a string and an enum
        // as a number must all fail with the setting named.
        for (document, setting) in [
            ("[listeners.tcp]\nbind = true\n", "listeners.tcp.bind"),
            (
                "[session]\nmax_qos0_backlog = \"lots\"\n",
                "session.max_qos0_backlog",
            ),
            ("[logging]\nlevel = 42\n", "logging.level"),
        ] {
            let err = BrokerConfig::parse_toml(document).expect_err("wrong-typed value must fail");
            let text = err.to_string();
            assert!(
                text.contains(setting) || text.contains(setting.replace('.', " ").as_str()),
                "error must name {setting}, got: {text}"
            );
        }
    }

    #[test]
    fn schema_rejects_bad_backpressure_policy() {
        let mut config = BrokerConfig::default();
        config.rules_engine.backpressure_policy = "Eventually".to_string();
        let err = config.validate().expect_err("unknown policy must fail");
        assert!(err.to_string().contains("rules_engine.backpressure_policy"));
    }

    #[test]
    fn generated_json_schema_parses_and_validates_sample() {
        let schema = json_schema();
        let text = serde_json::to_string_pretty(&schema).expect("schema serialises");
        let parsed: serde_json::Value = serde_json::from_str(&text).expect("schema parses");
        assert_eq!(parsed.get("type").and_then(|v| v.as_str()), Some("object"));
        assert!(parsed.get("properties").is_some());
        // The generated artefact must nest listeners the way `BrokerConfig`
        // serialises: `listeners.tcp.bind`, never a flat `tcp.bind` key.
        let listeners = parsed
            .get("properties")
            .and_then(|v| v.get("listeners"))
            .expect("schema has listeners section");
        let tcp = listeners
            .get("properties")
            .and_then(|v| v.get("tcp"))
            .expect("listeners schema nests tcp");
        assert!(tcp.get("properties").and_then(|v| v.get("bind")).is_some());
        assert!(listeners
            .get("properties")
            .and_then(|v| v.get("tcp.bind"))
            .is_none());

        let sample = serde_json::to_value(BrokerConfig::default()).expect("sample serialises");
        validate_json_sample(&sample).expect("default sample validates");
        validate_json_against_schema(&sample, &parsed)
            .expect("default sample validates against the generated schema");

        let mut bad = sample.clone();
        bad["logging"]["level"] = serde_json::Value::String("verbose".to_string());
        assert!(
            validate_json_sample(&bad).is_err(),
            "bad enum sample must fail"
        );
        assert!(
            validate_json_against_schema(&bad, &parsed).is_err(),
            "bad enum sample must fail schema validation"
        );
    }

    #[test]
    fn settings_reference_covers_every_catalogued_setting() {
        let reference = settings_reference_markdown();
        for row in field_docs() {
            assert!(
                reference.contains(row.path),
                "reference must document {}",
                row.path
            );
            assert!(
                reference.contains(row.doc),
                "reference must carry the doc string for {}",
                row.path
            );
        }
    }

    #[test]
    fn schema_qos0_backlog_default_is_bounded() {
        // The schema's QoS 0 backlog default bounds per-subscriber egress
        // memory: it must stay finite and agree with the delivery table.
        // Through-the-broker delivery with this bound is proved in
        // `broker-node::m1_03_schema_defaults_drive_broker_publish_deliver`
        // (connect, subscribe, publish, deliver through the kernel route
        // path), not from this crate which owns only the schema.
        let config = BrokerConfig::default();
        config.validate().expect("defaults validate");
        assert_eq!(config.session.max_qos0_backlog, 1_000);
        let toml_text = config.to_toml().expect("defaults serialise");
        let reparsed = BrokerConfig::parse_toml(&toml_text).expect("defaults round-trip");
        assert_eq!(reparsed.session.max_qos0_backlog, 1_000);
    }
}
