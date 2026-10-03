//! Layered configuration: files, environment and flags over schema defaults.
//!
//! # Precedence (canonical statement)
//!
//! The effective configuration resolves in this order, each layer winning
//! over the ones before it:
//!
//! ```text
//! built-in schema defaults, then `indra.toml`, then `conf.d/*.toml` in
//! file-name order, then `INDRA_*` environment variables, then
//! command-line flags, then runtime changes made through the API or CLI.
//! ```
//!
//! The same sentence appears verbatim in `docs/configuration.md` (checked
//! by `docs_state_the_documented_precedence` below) and in the M1-04 task
//! report. Command-line flags sit above the environment: an explicitly
//! passed flag always wins over files and the environment, so an operator
//! can override anything at startup without editing files.
//! TODO(parity): the spec lists flags as "one more layer" without fixing
//! their position relative to the environment; flags-above-environment is
//! the conservative choice (explicit operator intent wins) until decided.
//!
//! Runtime changes (M1-05) version whole registry snapshots in
//! `super::runtime` and persist beside `state.toml`; this module resolves
//! the startup layers only and names the `Runtime` layer marker `explain`
//! reports for registry keys. Files under the config directory are never
//! rewritten by the broker.
//!
//! # Files
//!
//! `<config-dir>/indra.toml` is the operator's main file and
//! `<config-dir>/conf.d/*.toml` are drop-in fragments applied in
//! file-name (byte) order, so `20-local.toml` wins over `10-base.toml`.
//! Only `*.toml` entries are read; anything else in `conf.d` is ignored so
//! a stray editor backup can never fail a boot. A missing config directory
//! or a missing `indra.toml` starts on defaults. An unreadable file, a
//! TOML syntax error, an unknown setting, a wrong-typed value or a
//! validation failure refuses startup with an error naming the file and
//! the setting.
//!
//! The config directory itself is bootstrap: it comes from `--config-dir`
//! (default `/etc/indramqtt`, the production mount point; a missing
//! directory starts on defaults so developer boots are unaffected) and has
//! no schema home, because the schema is what the directory locates.
//! TODO(parity): the spec names the file (`indra.toml`) but not the
//! directory or its default; `/etc/indramqtt` is the conservative choice
//! until the packagers (M1-08/M1-09) decide otherwise.
//!
//! # Environment
//!
//! `INDRA_` plus the setting path with `__` between levels, lowercased:
//! `INDRA_LISTENERS__TCP__BIND` sets `listeners.tcp.bind`,
//! `INDRA_SESSION__MAX_QOS0_BACKLOG` sets `session.max_qos0_backlog`.
//! Values are typed by the schema: booleans take `true`/`false`
//! (case-insensitive), integers and floats parse as numbers, everything
//! else is a string, and string lists split on commas
//! (`INDRA_CLUSTER__SEED_NODES="host1:1883,host2:1883"`).
//! TODO(parity): the comma separator for list-valued variables is
//! undecided; comma is the conservative readable choice until decided.
//! A wrong-typed value is a startup error naming the variable. An unknown
//! `INDRA_*` variable is a startup error (fail closed: a typo must never
//! boot a broker the operator did not ask for).
//! TODO(parity): whether unknown `INDRA_*` variables should be ignored
//! instead of refused is undecided; refusing is the conservative choice.
//!
//! Two pre-layer names used by the shipped container files keep working as
//! aliases into their schema homes: `INDRA_LICENSE_KEY` sets
//! `licence.license_key` and `INDRA_API_BIND` sets `listeners.api.bind`.
//! The canonical `INDRA_LICENCE__LICENSE_KEY` / `INDRA_LISTENERS__API__BIND`
//! forms win when both are set.
//!
//! # Flags
//!
//! Every long flag in `broker-node` maps into exactly one schema home (see
//! `CliOverrides`); a flag that is not passed leaves its setting to the
//! lower layers. `--config-dir` is the only bootstrap flag with no schema
//! home. `--allow-anonymous` only spells `true` (matching its historical
//! form), so an explicit `false` from a file or the environment stands
//! when the flag is absent.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::schema::BrokerConfig;
use crate::{schema, ConfigError};

/// Name of the operator's main configuration file inside the config dir.
pub const CONFIG_FILE_NAME: &str = "indra.toml";

/// Name of the drop-in fragment directory inside the config dir.
pub const CONFIG_FRAGMENTS_DIR: &str = "conf.d";

/// Prefix for environment-variable overrides.
pub const ENV_PREFIX: &str = "INDRA_";

/// Default config directory (bootstrap: `--config-dir` overrides it).
///
/// Reason: the production layout mounts operator config at
/// `/etc/indramqtt`; a missing directory starts on defaults so developer
/// and test boots that never create it are unaffected.
pub const DEFAULT_CONFIG_DIR: &str = "/etc/indramqtt";

/// The documented precedence order, stated verbatim here, in
/// `docs/configuration.md` and in the task report.
#[must_use]
pub fn precedence_statement() -> &'static str {
    "built-in schema defaults, then `indra.toml`, then `conf.d/*.toml` in file-name order, then `INDRA_*` environment variables, then command-line flags, then runtime changes made through the API or CLI."
}

/// One startup layer that supplied a setting, for M1-05 `explain` support.
///
/// `Defaults` is the fallback and is never stored: [`LayeredConfig`]
/// answers it for any setting no layer set. `Runtime` names the config
/// version (M1-05 history id) whose applied change last set the setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Layer {
    /// The schema's built-in default (nothing set it).
    Defaults,
    /// The main `<config-dir>/indra.toml` file.
    MainFile(PathBuf),
    /// One `<config-dir>/conf.d/*.toml` fragment, by path.
    Fragment(PathBuf),
    /// One environment variable, by name.
    Env(String),
    /// One command-line flag, by spelling (e.g. `--node-id`).
    Flag(String),
    /// A runtime change applied through the management API, by version id.
    Runtime(u64),
}

impl Layer {
    /// Human-readable source used in error messages and `explain` output.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Defaults => "built-in defaults".to_string(),
            Self::MainFile(path) | Self::Fragment(path) => path.display().to_string(),
            Self::Env(var) => format!("environment variable {var}"),
            Self::Flag(flag) => format!("command-line flag {flag}"),
            Self::Runtime(id) => format!("runtime version {id}"),
        }
    }
}

/// Expected TOML kind of one catalogued setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValueKind {
    Bool,
    Integer,
    Float,
    Str,
    StringList,
}

impl ValueKind {
    fn from_setting_type(setting_type: &str) -> Self {
        match setting_type {
            "bool" => Self::Bool,
            "u16" | "u32" | "u64" | "usize" => Self::Integer,
            "f64" => Self::Float,
            "string list" => Self::StringList,
            _ => Self::Str,
        }
    }

    fn noun(self) -> &'static str {
        match self {
            Self::Bool => "boolean",
            Self::Integer => "integer",
            Self::Float => "float",
            Self::Str => "string",
            Self::StringList => "string list",
        }
    }
}

/// Canonical dotted path (`listeners.tcp.bind`) to its expected kind.
fn catalogue_kinds() -> HashMap<&'static str, ValueKind> {
    schema::field_docs()
        .into_iter()
        .map(|row| (row.path, ValueKind::from_setting_type(row.setting_type)))
        .collect()
}

/// Every table prefix implied by the catalogue (`listeners`,
/// `listeners.tcp`, ...), plus the pre-rename aliases the schema accepts
/// (`rules` for `rules_engine`, `listeners.websocket` for `listeners.ws`).
fn known_prefixes() -> HashSet<String> {
    let mut prefixes = HashSet::new();
    for row in schema::field_docs() {
        let parts: Vec<&str> = row.path.split('.').collect();
        for len in 1..parts.len() {
            prefixes.insert(parts[..len].join("."));
        }
    }
    prefixes.insert("rules".to_string());
    prefixes.insert("listeners.websocket".to_string());
    prefixes.insert("tenants".to_string());
    prefixes
}

/// Rewrite pre-rename alias segments to their canonical homes so old files
/// fail on values, never on key names.
fn canonical_segments(segments: &[String]) -> Vec<String> {
    let mut out: Vec<String> = segments.to_vec();
    if out.first().is_some_and(|first| first == "rules") {
        out[0] = "rules_engine".to_string();
    }
    if out.len() >= 2 && out[0] == "listeners" && out[1] == "websocket" {
        out[1] = "ws".to_string();
    }
    out
}

/// Every command-line flag that feeds the schema, as parsed options.
///
/// A flag that is not passed is `None` and leaves its setting to the lower
/// layers. Each field documents its schema home. `--config-dir` is
/// intentionally absent: it locates the files, so it cannot come from them.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CliOverrides {
    /// `--node-id` -> `node.id`.
    pub node_id: Option<String>,
    /// `--data-dir` -> `node.data_dir`.
    pub data_dir: Option<String>,
    /// `--brokerlink-bind` -> `node.brokerlink_bind`.
    pub brokerlink_bind: Option<String>,
    /// `--bind` -> `listeners.tcp.bind`.
    pub bind: Option<String>,
    /// `--api-bind` -> `listeners.api.bind`.
    pub api_bind: Option<String>,
    /// `--allow-anonymous` -> `auth.allow_anonymous` (only spells `true`).
    pub allow_anonymous: bool,
    /// `--qos0-backlog` -> `session.max_qos0_backlog`.
    pub qos0_backlog: Option<usize>,
    /// `--license-key` -> `licence.license_key`.
    pub license_key: Option<String>,
    /// `--license-keys` -> `licence.trusted_keys_path`.
    pub license_keys: Option<String>,
    /// `--licence-request-out` -> `licence.request_out`.
    pub licence_request_out: Option<String>,
    /// `--licence-install-file` -> `licence.install_file`.
    pub licence_install_file: Option<String>,
    /// `--licence-expiry-warn-days` -> `licence.expiry_warn_days`.
    pub licence_expiry_warn_days: Option<u64>,
    /// `--cluster-seeds` (comma-separated) -> `cluster.seed_nodes`.
    pub cluster_seeds: Option<String>,
    /// `--cluster-bind` -> `cluster.bind`.
    pub cluster_bind: Option<String>,
    /// `--coap-bind` -> `gateway.coap_bind`.
    pub coap_bind: Option<String>,
    /// `--stream-dir` -> `persistence.stream_dir`.
    pub stream_dir: Option<String>,
    /// `--ldap-url` -> `ldap.server_url`.
    pub ldap_url: Option<String>,
    /// `--ldap-base-dn` -> `ldap.base_dn`.
    pub ldap_base_dn: Option<String>,
    /// `--ldap-bind-dn` -> `ldap.bind_dn`.
    pub ldap_bind_dn: Option<String>,
    /// `--ldap-bind-password` -> `ldap.bind_password`.
    pub ldap_bind_password: Option<String>,
    /// `--ldap-user-filter` -> `ldap.user_filter`.
    pub ldap_user_filter: Option<String>,
    /// `--ldap-group-attribute` -> `ldap.group_attribute`.
    pub ldap_group_attribute: Option<String>,
    /// `--ldap-required-group` -> `ldap.required_group`.
    pub ldap_required_group: Option<String>,
    /// `--ldap-ca-cert` -> `ldap.ca_cert_path`.
    pub ldap_ca_cert: Option<String>,
    /// `--kerberos-keytab` -> `kerberos.keytab_path`.
    pub kerberos_keytab: Option<String>,
    /// `--kerberos-service-principal` -> `kerberos.service_principal`.
    pub kerberos_service_principal: Option<String>,
    /// `--kerberos-realm` -> `kerberos.realm`.
    pub kerberos_realm: Option<String>,
    /// `--kerberos-allowed-realms` (comma-separated) -> `kerberos.allowed_realms`.
    pub kerberos_allowed_realms: Option<String>,
    /// `--kerberos-clock-skew-secs` -> `kerberos.clock_skew_secs`.
    pub kerberos_clock_skew_secs: Option<u64>,
    /// `--kerberos-role-map` -> `kerberos.role_map`.
    pub kerberos_role_map: Option<String>,
    /// `--kerberos-replay-max` -> `kerberos.replay_max_entries`.
    pub kerberos_replay_max: Option<usize>,
    /// `--qos1-inflight-window` -> `session.max_qos1_inflight`.
    pub qos1_inflight_window: Option<usize>,
    /// `--qos1-spill` -> `session.max_qos1_spill`.
    pub qos1_spill: Option<usize>,
    /// `--rule-spill-dir` -> `rules_engine.spill_dir`.
    pub rule_spill_dir: Option<String>,
    /// `--jws` etc -> `jwks.*`.
    pub jwks_url: Option<String>,
    pub jwks_issuer: Option<String>,
    pub jwks_audience: Option<String>,
    pub jwks_refresh_period_secs: Option<u64>,
    pub jwks_fetch_timeout_ms: Option<u64>,
    pub jwks_refresh_timeout_ms: Option<u64>,
    pub jwks_cache_max_keys: Option<usize>,
    pub jwks_cache_ttl_secs: Option<u64>,
    pub jwks_clock_skew_secs: Option<u64>,
    pub jwks_ca_cert: Option<String>,
    pub dbauth_postgres_url: Option<String>,
    pub dbauth_mysql_url: Option<String>,
    pub dbauth_redis_url: Option<String>,
    pub dbauth_mongodb_url: Option<String>,
    pub dbauth_pool_size: Option<usize>,
    pub dbauth_connect_timeout_ms: Option<u64>,
    pub dbauth_read_timeout_ms: Option<u64>,
    pub dbauth_cache_size: Option<usize>,
    pub dbauth_cache_ttl_secs: Option<u64>,
    pub webhook_url: Option<String>,
    pub webhook_pool_size: Option<usize>,
    pub webhook_timeout_ms: Option<u64>,
    pub webhook_breaker_threshold: Option<u32>,
    pub webhook_breaker_reset_ms: Option<u64>,
    pub webhook_cache_size: Option<usize>,
    pub webhook_cache_ttl_secs: Option<u64>,
    pub delayed_max_secs: Option<u64>,
    pub topic_alias_maximum: Option<u16>,
    pub monitor_sample_secs: Option<u64>,
}

impl CliOverrides {
    /// Merge every explicitly passed flag into `table`, recording one
    /// provenance entry per dotted setting path.
    fn apply_to(&self, table: &mut toml::Table, provenance: &mut HashMap<String, Layer>) {
        set_str_path(table, provenance, "node.id", "--node-id", &self.node_id);
        set_str_path(
            table,
            provenance,
            "node.data_dir",
            "--data-dir",
            &self.data_dir,
        );
        set_str_path(
            table,
            provenance,
            "node.brokerlink_bind",
            "--brokerlink-bind",
            &self.brokerlink_bind,
        );
        set_str_path(
            table,
            provenance,
            "listeners.tcp.bind",
            "--bind",
            &self.bind,
        );
        set_str_path(
            table,
            provenance,
            "listeners.api.bind",
            "--api-bind",
            &self.api_bind,
        );
        if self.allow_anonymous {
            insert_path(
                table,
                provenance,
                "auth.allow_anonymous",
                toml::Value::Boolean(true),
                "--allow-anonymous",
            );
        }
        if let Some(value) = self.qos0_backlog {
            insert_path(
                table,
                provenance,
                "session.max_qos0_backlog",
                toml::Value::Integer(value as i64),
                "--qos0-backlog",
            );
        }
        set_str_path(
            table,
            provenance,
            "licence.license_key",
            "--license-key",
            &self.license_key,
        );
        set_str_path(
            table,
            provenance,
            "licence.trusted_keys_path",
            "--license-keys",
            &self.license_keys,
        );
        set_str_path(
            table,
            provenance,
            "licence.request_out",
            "--licence-request-out",
            &self.licence_request_out,
        );
        set_str_path(
            table,
            provenance,
            "licence.install_file",
            "--licence-install-file",
            &self.licence_install_file,
        );
        if let Some(value) = self.licence_expiry_warn_days {
            insert_path(
                table,
                provenance,
                "licence.expiry_warn_days",
                toml::Value::Integer(value as i64),
                "--licence-expiry-warn-days",
            );
        }
        if let Some(raw) = &self.cluster_seeds {
            insert_path(
                table,
                provenance,
                "cluster.seed_nodes",
                toml::Value::Array(split_list(raw)),
                "--cluster-seeds",
            );
        }
        set_str_path(
            table,
            provenance,
            "cluster.bind",
            "--cluster-bind",
            &self.cluster_bind,
        );
        set_str_path(
            table,
            provenance,
            "gateway.coap_bind",
            "--coap-bind",
            &self.coap_bind,
        );
        set_str_path(
            table,
            provenance,
            "persistence.stream_dir",
            "--stream-dir",
            &self.stream_dir,
        );
        set_str_path(
            table,
            provenance,
            "ldap.server_url",
            "--ldap-url",
            &self.ldap_url,
        );
        set_str_path(
            table,
            provenance,
            "ldap.base_dn",
            "--ldap-base-dn",
            &self.ldap_base_dn,
        );
        set_str_path(
            table,
            provenance,
            "ldap.bind_dn",
            "--ldap-bind-dn",
            &self.ldap_bind_dn,
        );
        set_str_path(
            table,
            provenance,
            "ldap.bind_password",
            "--ldap-bind-password",
            &self.ldap_bind_password,
        );
        set_str_path(
            table,
            provenance,
            "ldap.user_filter",
            "--ldap-user-filter",
            &self.ldap_user_filter,
        );
        set_str_path(
            table,
            provenance,
            "ldap.group_attribute",
            "--ldap-group-attribute",
            &self.ldap_group_attribute,
        );
        set_str_path(
            table,
            provenance,
            "ldap.required_group",
            "--ldap-required-group",
            &self.ldap_required_group,
        );
        set_str_path(
            table,
            provenance,
            "ldap.ca_cert_path",
            "--ldap-ca-cert",
            &self.ldap_ca_cert,
        );
        set_str_path(
            table,
            provenance,
            "kerberos.keytab_path",
            "--kerberos-keytab",
            &self.kerberos_keytab,
        );
        set_str_path(
            table,
            provenance,
            "kerberos.service_principal",
            "--kerberos-service-principal",
            &self.kerberos_service_principal,
        );
        set_str_path(
            table,
            provenance,
            "kerberos.realm",
            "--kerberos-realm",
            &self.kerberos_realm,
        );
        if let Some(raw) = &self.kerberos_allowed_realms {
            insert_path(
                table,
                provenance,
                "kerberos.allowed_realms",
                toml::Value::Array(split_list(raw)),
                "--kerberos-allowed-realms",
            );
        }
        if let Some(value) = self.kerberos_clock_skew_secs {
            insert_path(
                table,
                provenance,
                "kerberos.clock_skew_secs",
                toml::Value::Integer(value as i64),
                "--kerberos-clock-skew-secs",
            );
        }
        set_str_path(
            table,
            provenance,
            "kerberos.role_map",
            "--kerberos-role-map",
            &self.kerberos_role_map,
        );
        if let Some(value) = self.kerberos_replay_max {
            insert_path(
                table,
                provenance,
                "kerberos.replay_max_entries",
                toml::Value::Integer(value as i64),
                "--kerberos-replay-max",
            );
        }
        if let Some(value) = self.qos1_inflight_window {
            insert_path(
                table,
                provenance,
                "session.max_qos1_inflight",
                toml::Value::Integer(value as i64),
                "--qos1-inflight-window",
            );
        }
        if let Some(value) = self.qos1_spill {
            insert_path(
                table,
                provenance,
                "session.max_qos1_spill",
                toml::Value::Integer(value as i64),
                "--qos1-spill",
            );
        }
        if let Some(ref value) = self.rule_spill_dir {
            insert_path(
                table,
                provenance,
                "rules_engine.spill_dir",
                toml::Value::String(value.clone()),
                "--rule-spill-dir",
            );
        }
        if let Some(ref value) = self.jwks_url {
            insert_path(
                table,
                provenance,
                "jwks.url",
                toml::Value::String(value.clone()),
                "--jwks-url",
            );
        }
        if let Some(ref value) = self.jwks_issuer {
            insert_path(
                table,
                provenance,
                "jwks.issuer",
                toml::Value::String(value.clone()),
                "--jwks-issuer",
            );
        }
        if let Some(ref value) = self.jwks_audience {
            insert_path(
                table,
                provenance,
                "jwks.audience",
                toml::Value::String(value.clone()),
                "--jwks-audience",
            );
        }
        if let Some(value) = self.jwks_refresh_period_secs {
            insert_path(
                table,
                provenance,
                "jwks.refresh_period_secs",
                toml::Value::Integer(value as i64),
                "--jwks-refresh-period-secs",
            );
        }
        if let Some(value) = self.jwks_fetch_timeout_ms {
            insert_path(
                table,
                provenance,
                "jwks.fetch_timeout_ms",
                toml::Value::Integer(value as i64),
                "--jwks-fetch-timeout-ms",
            );
        }
        if let Some(value) = self.jwks_refresh_timeout_ms {
            insert_path(
                table,
                provenance,
                "jwks.refresh_timeout_ms",
                toml::Value::Integer(value as i64),
                "--jwks-refresh-timeout-ms",
            );
        }
        if let Some(value) = self.jwks_cache_max_keys {
            insert_path(
                table,
                provenance,
                "jwks.cache_max_keys",
                toml::Value::Integer(value as i64),
                "--jwks-cache-max-keys",
            );
        }
        if let Some(value) = self.jwks_cache_ttl_secs {
            insert_path(
                table,
                provenance,
                "jwks.cache_ttl_secs",
                toml::Value::Integer(value as i64),
                "--jwks-cache-ttl-secs",
            );
        }
        if let Some(value) = self.jwks_clock_skew_secs {
            insert_path(
                table,
                provenance,
                "jwks.clock_skew_secs",
                toml::Value::Integer(value as i64),
                "--jwks-clock-skew-secs",
            );
        }
        if let Some(ref value) = self.jwks_ca_cert {
            insert_path(
                table,
                provenance,
                "jwks.ca_cert",
                toml::Value::String(value.clone()),
                "--jwks-ca-cert",
            );
        }
        if let Some(ref value) = self.dbauth_postgres_url {
            insert_path(
                table,
                provenance,
                "dbauth.postgres_url",
                toml::Value::String(value.clone()),
                "--dbauth-postgres-url",
            );
        }
        if let Some(ref value) = self.dbauth_mysql_url {
            insert_path(
                table,
                provenance,
                "dbauth.mysql_url",
                toml::Value::String(value.clone()),
                "--dbauth-mysql-url",
            );
        }
        if let Some(ref value) = self.dbauth_redis_url {
            insert_path(
                table,
                provenance,
                "dbauth.redis_url",
                toml::Value::String(value.clone()),
                "--dbauth-redis-url",
            );
        }
        if let Some(ref value) = self.dbauth_mongodb_url {
            insert_path(
                table,
                provenance,
                "dbauth.mongodb_url",
                toml::Value::String(value.clone()),
                "--dbauth-mongodb-url",
            );
        }
        if let Some(value) = self.dbauth_pool_size {
            insert_path(
                table,
                provenance,
                "dbauth.pool_size",
                toml::Value::Integer(value as i64),
                "--dbauth-pool-size",
            );
        }
        if let Some(value) = self.dbauth_connect_timeout_ms {
            insert_path(
                table,
                provenance,
                "dbauth.connect_timeout_ms",
                toml::Value::Integer(value as i64),
                "--dbauth-connect-timeout-ms",
            );
        }
        if let Some(value) = self.dbauth_read_timeout_ms {
            insert_path(
                table,
                provenance,
                "dbauth.read_timeout_ms",
                toml::Value::Integer(value as i64),
                "--dbauth-read-timeout-ms",
            );
        }
        if let Some(value) = self.dbauth_cache_size {
            insert_path(
                table,
                provenance,
                "dbauth.cache_size",
                toml::Value::Integer(value as i64),
                "--dbauth-cache-size",
            );
        }
        if let Some(value) = self.dbauth_cache_ttl_secs {
            insert_path(
                table,
                provenance,
                "dbauth.cache_ttl_secs",
                toml::Value::Integer(value as i64),
                "--dbauth-cache-ttl-secs",
            );
        }
        if let Some(ref value) = self.webhook_url {
            insert_path(
                table,
                provenance,
                "webhook.url",
                toml::Value::String(value.clone()),
                "--webhook-url",
            );
        }
        if let Some(value) = self.webhook_pool_size {
            insert_path(
                table,
                provenance,
                "webhook.pool_size",
                toml::Value::Integer(value as i64),
                "--webhook-pool-size",
            );
        }
        if let Some(value) = self.webhook_timeout_ms {
            insert_path(
                table,
                provenance,
                "webhook.timeout_ms",
                toml::Value::Integer(value as i64),
                "--webhook-timeout-ms",
            );
        }
        if let Some(value) = self.webhook_breaker_threshold {
            insert_path(
                table,
                provenance,
                "webhook.breaker_threshold",
                toml::Value::Integer(value as i64),
                "--webhook-breaker-threshold",
            );
        }
        if let Some(value) = self.webhook_breaker_reset_ms {
            insert_path(
                table,
                provenance,
                "webhook.breaker_reset_ms",
                toml::Value::Integer(value as i64),
                "--webhook-breaker-reset-ms",
            );
        }
        if let Some(value) = self.webhook_cache_size {
            insert_path(
                table,
                provenance,
                "webhook.cache_size",
                toml::Value::Integer(value as i64),
                "--webhook-cache-size",
            );
        }
        if let Some(value) = self.webhook_cache_ttl_secs {
            insert_path(
                table,
                provenance,
                "webhook.cache_ttl_secs",
                toml::Value::Integer(value as i64),
                "--webhook-cache-ttl-secs",
            );
        }
        if let Some(value) = self.delayed_max_secs {
            insert_path(
                table,
                provenance,
                "delayed.max_secs",
                toml::Value::Integer(value as i64),
                "--delayed-max-secs",
            );
        }
        if let Some(value) = self.topic_alias_maximum {
            insert_path(
                table,
                provenance,
                "session.topic_alias_maximum",
                toml::Value::Integer(value as i64),
                "--topic-alias-maximum",
            );
        }
        if let Some(value) = self.monitor_sample_secs {
            insert_path(
                table,
                provenance,
                "observability.monitor_sample_secs",
                toml::Value::Integer(value as i64),
                "--monitor-sample-secs",
            );
        }
    }
}

/// Split a comma-separated flag or environment list value, trimming entries
/// and dropping empties so `"a:1, b:2"` and `"a:1,,b:2"` agree.
fn split_list(raw: &str) -> Vec<toml::Value> {
    raw.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| toml::Value::String(entry.to_string()))
        .collect()
}

/// Insert one optional string flag value plus its flag provenance entry.
fn set_str_path(
    table: &mut toml::Table,
    provenance: &mut HashMap<String, Layer>,
    path: &str,
    flag: &str,
    value: &Option<String>,
) {
    if let Some(text) = value {
        insert_path(
            table,
            provenance,
            path,
            toml::Value::String(text.clone()),
            flag,
        );
    }
}

/// Insert one canonical dotted-path value plus its flag provenance entry.
fn insert_path(
    table: &mut toml::Table,
    provenance: &mut HashMap<String, Layer>,
    path: &str,
    value: toml::Value,
    flag: &str,
) {
    set_path(table, path, value);
    provenance.insert(path.to_string(), Layer::Flag(flag.to_string()));
}

/// The resolved startup configuration plus the winning layer per setting.
///
/// Settings no layer set resolve to schema defaults and report
/// [`Layer::Defaults`]; every other setting names the exact file, variable
/// or flag that set it, which is what M1-05 `explain` will print.
#[derive(Debug, Clone)]
pub struct LayeredConfig {
    config: BrokerConfig,
    provenance: HashMap<String, Layer>,
}

impl LayeredConfig {
    /// The effective configuration after all startup layers.
    #[must_use]
    pub fn config(&self) -> &BrokerConfig {
        &self.config
    }

    /// Winning layer per canonical dotted setting path.
    #[must_use]
    pub fn provenance(&self) -> &HashMap<String, Layer> {
        &self.provenance
    }

    /// Which layer set one canonical dotted setting path
    /// (e.g. `listeners.tcp.bind`), or [`Layer::Defaults`].
    #[must_use]
    pub fn layer_of(&self, dotted_path: &str) -> Layer {
        self.provenance
            .get(dotted_path)
            .cloned()
            .unwrap_or(Layer::Defaults)
    }
}

fn load_error(file: impl Into<String>, reason: impl Into<String>) -> ConfigError {
    ConfigError::Load {
        file: file.into(),
        reason: reason.into(),
    }
}

/// Resolve the startup configuration from the real process environment.
///
/// `config_dir` holds `indra.toml` plus `conf.d/*.toml`; a missing
/// directory or missing files start on defaults. Files that exist but
/// cannot be read, parsed or validated refuse startup naming the file and
/// the setting, as do wrong-typed `INDRA_*` variables (naming the
/// variable) and unknown `INDRA_*` variables.
pub fn load_layered(config_dir: &Path, cli: &CliOverrides) -> Result<LayeredConfig, ConfigError> {
    let env: Vec<(String, String)> = std::env::vars()
        .filter(|(name, _)| name.starts_with(ENV_PREFIX) && !is_credential_env(name))
        .collect();
    load_layered_from(config_dir, &env, cli)
}

/// The `INDRA_*` variables that contain credentials.
///
/// These variables are not settings and have no schema home. `explain`
/// and the configuration exports must not show a key. Thus the settings
/// layer ignores these variables and does not refuse the startup.
///
/// - `INDRA_API_KEYS` gives the operator API keys to the broker.
/// - `INDRA_API_KEY` is the key that `indra ctl` sends. An operator can
///   export it in the shell that starts the broker.
pub const CREDENTIAL_ENV_VARS: &[&str] = &["INDRA_API_KEYS", "INDRA_API_KEY"];

fn is_credential_env(name: &str) -> bool {
    CREDENTIAL_ENV_VARS.contains(&name)
}

/// Resolve the startup configuration from an explicit environment list.
///
/// Test and tool entry point sharing the production merge, typing and
/// validation: `env` holds `(NAME, value)` pairs as `std::env::vars` would.
pub fn load_layered_with_env(
    config_dir: &Path,
    env: &[(String, String)],
    cli: &CliOverrides,
) -> Result<LayeredConfig, ConfigError> {
    load_layered_from(config_dir, env, cli)
}

/// Shared core behind [`load_layered`]: the same file reads, merges,
/// typing and validation run whether the environment comes from the real
/// process or a caller-supplied list.
fn load_layered_from(
    config_dir: &Path,
    env: &[(String, String)],
    cli: &CliOverrides,
) -> Result<LayeredConfig, ConfigError> {
    let kinds = catalogue_kinds();
    let prefixes = known_prefixes();
    let mut merged = toml::Table::new();
    let mut provenance: HashMap<String, Layer> = HashMap::new();

    // Layer 2: the main file. Missing starts on defaults; anything present
    // but unreadable, unparsable or invalid refuses startup.
    let main_file = config_dir.join(CONFIG_FILE_NAME);
    if main_file.exists() {
        let layer = Layer::MainFile(main_file.clone());
        merge_file(
            &main_file,
            &layer,
            &kinds,
            &prefixes,
            &mut merged,
            &mut provenance,
        )?;
    }

    // Layer 3: fragments in file-name order. A missing directory is fine;
    // a path that is not a directory, or an unreadable/invalid fragment,
    // refuses startup.
    let fragments_dir = config_dir.join(CONFIG_FRAGMENTS_DIR);
    if fragments_dir.exists() {
        if !fragments_dir.is_dir() {
            return Err(load_error(
                fragments_dir.display().to_string(),
                format!("`{CONFIG_FRAGMENTS_DIR}` must be a directory"),
            ));
        }
        let entries = std::fs::read_dir(&fragments_dir).map_err(|err| {
            load_error(
                fragments_dir.display().to_string(),
                format!("cannot list directory: {err}"),
            )
        })?;
        let mut fragments: Vec<PathBuf> = Vec::new();
        for entry in entries {
            let path = entry
                .map_err(|err| {
                    load_error(
                        fragments_dir.display().to_string(),
                        format!("cannot read directory entry: {err}"),
                    )
                })?
                .path();
            if path.extension().is_some_and(|ext| ext == "toml") {
                fragments.push(path);
            }
        }
        fragments.sort();
        for path in fragments {
            let layer = Layer::Fragment(path.clone());
            merge_file(
                &path,
                &layer,
                &kinds,
                &prefixes,
                &mut merged,
                &mut provenance,
            )?;
        }
    }

    // Layer 4: the environment. Legacy single-underscore aliases apply
    // first so the canonical double-underscore forms win when both are set.
    let mut canonical: Vec<&(String, String)> = Vec::new();
    for pair in env {
        if let Some(path) = legacy_env_path(&pair.0) {
            let layer = Layer::Env(pair.0.clone());
            merge_env_value(
                path.as_str(),
                &pair.1,
                &layer,
                &kinds,
                &mut merged,
                &mut provenance,
            )?;
        } else {
            canonical.push(pair);
        }
    }
    for (var, raw) in canonical {
        let path = env_path(var)?;
        let layer = Layer::Env(var.clone());
        merge_env_value(&path, raw, &layer, &kinds, &mut merged, &mut provenance)?;
    }

    // Layer 5: explicitly passed command-line flags.
    let mut flag_table = toml::Table::new();
    let mut flag_provenance: HashMap<String, Layer> = HashMap::new();
    cli.apply_to(&mut flag_table, &mut flag_provenance);
    merge_layer(&mut merged, &mut provenance, &flag_table, &flag_provenance);

    let parsed: BrokerConfig = toml::Value::Table(merged).try_into().map_err(|err| {
        attribute(
            ConfigError::Invalid(format!("config value is invalid: {err}")),
            &provenance,
        )
    })?;
    parsed
        .validate()
        .map_err(|err| attribute(err, &provenance))?;
    Ok(LayeredConfig {
        config: parsed,
        provenance,
    })
}

/// Read, parse, per-file check and merge one config file.
fn merge_file(
    path: &Path,
    layer: &Layer,
    kinds: &HashMap<&'static str, ValueKind>,
    prefixes: &HashSet<String>,
    merged: &mut toml::Table,
    provenance: &mut HashMap<String, Layer>,
) -> Result<(), ConfigError> {
    let file = path.display().to_string();
    let text = std::fs::read_to_string(path)
        .map_err(|err| load_error(file.clone(), format!("cannot read file: {err}")))?;
    let table: toml::Table = toml::from_str(&text)
        .map_err(|err| load_error(file.clone(), format!("invalid TOML: {err}")))?;
    check_table(&table, &file, kinds, prefixes, Vec::new())?;
    let mut layer_provenance: HashMap<String, Layer> = HashMap::new();
    merge_table(merged, &table, layer, &mut layer_provenance, Vec::new());
    provenance.extend(layer_provenance);
    Ok(())
}

/// Merge one overlay table over the base, recording provenance per leaf.
fn merge_table(
    base: &mut toml::Table,
    overlay: &toml::Table,
    layer: &Layer,
    provenance: &mut HashMap<String, Layer>,
    prefix: Vec<String>,
) {
    for (key, value) in overlay {
        let mut full = prefix.clone();
        full.push(key.clone());
        let full = canonical_segments(&full);
        match value {
            toml::Value::Table(nested) => {
                let entry = base
                    .entry(canonical_key(key))
                    .or_insert_with(|| toml::Value::Table(toml::Table::new()));
                if let toml::Value::Table(base_nested) = entry {
                    merge_table(base_nested, nested, layer, provenance, full);
                }
            }
            leaf => {
                base.insert(canonical_key(key), leaf.clone());
                provenance.insert(full.join("."), layer.clone());
            }
        }
    }
}

/// Merge a pre-built overlay (flags) whose provenance is already per path.
fn merge_layer(
    base: &mut toml::Table,
    provenance: &mut HashMap<String, Layer>,
    overlay: &toml::Table,
    overlay_provenance: &HashMap<String, Layer>,
) {
    for (path, layer) in overlay_provenance {
        if let Some(value) = get_path(overlay, path) {
            set_path(base, path, value.clone());
            provenance.insert(path.clone(), layer.clone());
        }
    }
}

fn canonical_key(key: &str) -> String {
    match key {
        "rules" => "rules_engine".to_string(),
        "websocket" => "ws".to_string(),
        other => other.to_string(),
    }
}

/// Check one file's table: every leaf must name a known setting and hold
/// the TOML type its schema type implies. Errors name the file, the
/// setting and the offending value.
fn check_table(
    table: &toml::Table,
    file: &str,
    kinds: &HashMap<&'static str, ValueKind>,
    prefixes: &HashSet<String>,
    prefix: Vec<String>,
) -> Result<(), ConfigError> {
    for (key, value) in table {
        let mut full = prefix.clone();
        full.push(key.clone());
        let full = canonical_segments(&full);
        let dotted = full.join(".");
        match value {
            toml::Value::Table(nested) => {
                if !prefixes.contains(&dotted) {
                    return Err(load_error(
                        file,
                        format!("unknown setting `{dotted}` (field `{dotted}`)"),
                    ));
                }
                check_table(nested, file, kinds, prefixes, full)?;
            }
            toml::Value::Array(_) if dotted.starts_with("tenants") => {
                // Array-of-tables (e.g. `[[tenants.rules]]`) is validated by
                // `BrokerConfig::validate`, not the layer kind checker.
            }
            leaf => {
                let Some(kind) = kinds.get(dotted.as_str()) else {
                    return Err(load_error(
                        file,
                        format!("unknown setting `{dotted}` (field `{dotted}`)"),
                    ));
                };
                if !leaf_matches(leaf, *kind) {
                    return Err(load_error(
                        file,
                        format!(
                            "`{dotted}` value {leaf} is invalid: must be {} (field `{dotted}`)",
                            kind.noun()
                        ),
                    ));
                }
                if kind == &ValueKind::StringList && !array_of_strings(leaf) {
                    return Err(load_error(
                        file,
                        format!(
                            "`{dotted}` value {leaf} is invalid: must be a string list (field `{dotted}`)"
                        ),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn leaf_matches(leaf: &toml::Value, kind: ValueKind) -> bool {
    match kind {
        ValueKind::Bool => leaf.is_bool(),
        ValueKind::Integer => matches!(leaf, toml::Value::Integer(_)),
        ValueKind::Float => matches!(leaf, toml::Value::Float(_) | toml::Value::Integer(_)),
        ValueKind::Str => matches!(leaf, toml::Value::String(_)),
        ValueKind::StringList => matches!(leaf, toml::Value::Array(_)),
    }
}

fn array_of_strings(leaf: &toml::Value) -> bool {
    match leaf {
        toml::Value::Array(entries) => entries.iter().all(|entry| entry.is_str()),
        _ => false,
    }
}

/// Map one `INDRA_` variable name to its canonical dotted setting path.
///
/// Unknown variables are a startup error naming the variable (fail closed).
fn env_path(var: &str) -> Result<String, ConfigError> {
    let rest = var.strip_prefix(ENV_PREFIX).unwrap_or(var);
    let segments: Vec<String> = rest.split("__").map(|part| part.to_lowercase()).collect();
    if segments.iter().any(|part| part.is_empty()) {
        return Err(load_error(
            format!("environment variable {var}"),
            format!("`{var}` is invalid: empty path segment (field `{var}`)"),
        ));
    }
    let canonical = canonical_segments(&segments).join(".");
    if catalogue_kinds().contains_key(canonical.as_str()) {
        return Ok(canonical);
    }
    Err(load_error(
        format!("environment variable {var}"),
        format!("`{var}` is invalid: unknown setting `{canonical}` (field `{var}`)"),
    ))
}

/// Pre-layer single-underscore names kept working as aliases into schema homes.
fn legacy_env_path(var: &str) -> Option<String> {
    match var {
        "INDRA_LICENSE_KEY" => Some("licence.license_key".to_string()),
        "INDRA_API_BIND" => Some("listeners.api.bind".to_string()),
        _ => None,
    }
}

/// Convert one environment value to its schema-typed TOML value.
///
/// Wrong types are startup errors naming the variable, independent of the
/// underlying parser's wording.
fn env_toml_value(
    path: &str,
    var: &str,
    raw: &str,
    kinds: &HashMap<&'static str, ValueKind>,
) -> Result<toml::Value, ConfigError> {
    let invalid = |why: &str| {
        load_error(
            format!("environment variable {var}"),
            format!("`{var}` value {raw:?} is invalid for `{path}`: {why} (field `{var}`)"),
        )
    };
    let kind = kinds.get(path).copied().unwrap_or(ValueKind::Str);
    match kind {
        ValueKind::Bool => match raw.trim().to_ascii_lowercase().as_str() {
            "true" => Ok(toml::Value::Boolean(true)),
            "false" => Ok(toml::Value::Boolean(false)),
            _ => Err(invalid("must be true or false")),
        },
        ValueKind::Integer => raw
            .trim()
            .parse::<i64>()
            .map(toml::Value::Integer)
            .map_err(|_| invalid("must be an integer")),
        ValueKind::Float => raw
            .trim()
            .parse::<f64>()
            .map(toml::Value::Float)
            .map_err(|_| invalid("must be a number")),
        ValueKind::Str => Ok(toml::Value::String(raw.to_string())),
        ValueKind::StringList => Ok(toml::Value::Array(split_list(raw))),
    }
}

/// Merge one environment variable into the working table.
fn merge_env_value(
    path: &str,
    raw: &str,
    layer: &Layer,
    kinds: &HashMap<&'static str, ValueKind>,
    merged: &mut toml::Table,
    provenance: &mut HashMap<String, Layer>,
) -> Result<(), ConfigError> {
    let var = match layer {
        Layer::Env(var) => var.clone(),
        _ => layer.describe(),
    };
    let value = env_toml_value(path, &var, raw, kinds)?;
    set_path(merged, path, value);
    provenance.insert(path.to_string(), layer.clone());
    Ok(())
}

/// Read one canonical dotted path out of a nested table.
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

/// Write one canonical dotted path into a nested table, creating parents.
fn set_path(table: &mut toml::Table, path: &str, value: toml::Value) {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = table;
    for (index, part) in parts.iter().enumerate() {
        if index + 1 == parts.len() {
            current.insert((*part).to_string(), value.clone());
            return;
        }
        current = current
            .entry((*part).to_string())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
            .expect("path parents are always tables");
    }
}

/// Attribute a merged-document validation failure to the layer that set
/// the offending setting, so the error names the file, variable or flag
/// as well as the setting.
fn attribute(err: ConfigError, provenance: &HashMap<String, Layer>) -> ConfigError {
    let ConfigError::Invalid(message) = &err else {
        return err;
    };
    let Some(field) = field_in_message(message) else {
        return err;
    };
    match provenance.get(&field) {
        Some(layer) => load_error(layer.describe(), message.clone()),
        None => err,
    }
}

/// Extract the `` (field `x`) `` marker the schema validators always emit.
fn field_in_message(message: &str) -> Option<String> {
    let marker = "(field `";
    let start = message.find(marker)? + marker.len();
    let rest = &message[start..];
    let end = rest.find('`')?;
    Some(rest[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Serialises every test that touches the real process environment:
    /// the loader reads `std::env`, so concurrent mutation would leak
    /// across tests in this binary.
    static ENV_SERIAL: Mutex<()> = Mutex::new(());

    /// Restores every touched variable on drop so no test leaks into the next.
    struct EnvGuard {
        saved: Vec<(String, Option<String>)>,
    }

    impl EnvGuard {
        fn set(pairs: &[(&str, &str)]) -> Self {
            let mut saved = Vec::new();
            for (key, value) in pairs {
                saved.push((key.to_string(), std::env::var(key).ok()));
                std::env::set_var(key, value);
            }
            Self { saved }
        }

        fn clear(names: &[&str]) -> Self {
            let mut saved = Vec::new();
            for key in names {
                saved.push((key.to_string(), std::env::var(key).ok()));
                std::env::remove_var(key);
            }
            Self { saved }
        }

        /// Remove every `INDRA_*` variable in the ambient environment so a
        /// defaults assertion cannot observe the host's own variables.
        fn clear_all_indra() -> Self {
            let names: Vec<String> = std::env::vars()
                .map(|(key, _)| key)
                .filter(|key| key.starts_with(ENV_PREFIX))
                .collect();
            let mut saved = Vec::new();
            for key in names {
                saved.push((key.clone(), std::env::var(&key).ok()));
                std::env::remove_var(&key);
            }
            Self { saved }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, previous) in self.saved.drain(..) {
                match previous {
                    Some(value) => std::env::set_var(&key, value),
                    None => std::env::remove_var(&key),
                }
            }
        }
    }

    fn unique_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "broker-layers-{prefix}-{}-{nanos}",
            std::process::id()
        ))
    }

    fn write(dir: &Path, name: &str, text: &str) -> PathBuf {
        std::fs::create_dir_all(dir).expect("create config dir");
        let path = dir.join(name);
        std::fs::write(&path, text).expect("write config file");
        path
    }

    fn scrub(dir: &Path) {
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn missing_config_dir_starts_on_defaults() {
        let _serial = ENV_SERIAL.lock().expect("env serial");
        let dir = unique_dir("missing");
        let _guard = EnvGuard::clear_all_indra();
        let resolved =
            load_layered(&dir, &CliOverrides::default()).expect("missing dir starts on defaults");
        assert_eq!(*resolved.config(), BrokerConfig::default());
        assert_eq!(resolved.layer_of("node.id"), Layer::Defaults);
        assert!(!dir.exists(), "the loader must not create the config dir");
    }

    #[test]
    fn corrupt_indra_toml_names_the_file_and_refuses_startup() {
        let _serial = ENV_SERIAL.lock().expect("env serial");
        let dir = unique_dir("corrupt");
        let path = write(&dir, "indra.toml", "[[[ not valid toml {{{");
        let err = load_layered(&dir, &CliOverrides::default()).expect_err("corrupt file must fail");
        let text = err.to_string();
        assert!(
            text.contains(&path.display().to_string()),
            "error must name the file, got: {text}"
        );
        assert!(
            text.contains("indra.toml"),
            "error must name the file, got: {text}"
        );
        scrub(&dir);
    }

    #[test]
    fn invalid_value_names_the_file_and_the_setting() {
        let _serial = ENV_SERIAL.lock().expect("env serial");
        let dir = unique_dir("invalid");
        let path = write(
            &dir,
            "indra.toml",
            "[listeners.tcp]\nbind = \"0.0.0.0:notaport\"\n",
        );
        let err = load_layered(&dir, &CliOverrides::default()).expect_err("bad port must fail");
        let text = err.to_string();
        assert!(
            text.contains(&path.display().to_string()),
            "error must name the file, got: {text}"
        );
        assert!(
            text.contains("listeners.tcp.bind"),
            "error must name the setting, got: {text}"
        );
        scrub(&dir);
    }

    #[test]
    fn unknown_setting_in_file_refuses_startup() {
        let _serial = ENV_SERIAL.lock().expect("env serial");
        let dir = unique_dir("unknown");
        let path = write(&dir, "indra.toml", "[node]\nidak = \"typo\"\n");
        let err = load_layered(&dir, &CliOverrides::default()).expect_err("unknown key must fail");
        let text = err.to_string();
        assert!(
            text.contains(&path.display().to_string()),
            "error must name the file, got: {text}"
        );
        assert!(
            text.contains("node.idak"),
            "error must name the setting, got: {text}"
        );
        scrub(&dir);
    }

    #[test]
    fn wrong_typed_value_in_file_names_the_setting() {
        let _serial = ENV_SERIAL.lock().expect("env serial");
        let dir = unique_dir("wrongtype");
        write(&dir, "indra.toml", "[listeners.tcp]\nbind = true\n");
        let err = load_layered(&dir, &CliOverrides::default()).expect_err("wrong type must fail");
        let text = err.to_string();
        assert!(
            text.contains("listeners.tcp.bind"),
            "error must name the setting, got: {text}"
        );
        assert!(
            text.contains("indra.toml"),
            "error must name the file, got: {text}"
        );
        scrub(&dir);
    }

    #[test]
    fn every_layer_sets_the_winner_in_documented_order() {
        let _serial = ENV_SERIAL.lock().expect("env serial");
        let dir = unique_dir("layers");
        write(&dir, "indra.toml", "[node]\nid = \"file-node\"\n");
        let fragments = dir.join("conf.d");
        write(&fragments, "10-base.toml", "[node]\nid = \"frag-a\"\n");
        write(&fragments, "20-local.toml", "[node]\nid = \"frag-b\"\n");
        let _env = EnvGuard::set(&[("INDRA_NODE__ID", "env-node")]);
        let cli = CliOverrides {
            node_id: Some("flag-node".to_string()),
            ..Default::default()
        };

        // All layers set: the flag wins, and provenance says so.
        let resolved = load_layered(&dir, &cli).expect("layered load");
        assert_eq!(resolved.config().node.id, "flag-node");
        assert_eq!(
            resolved.layer_of("node.id"),
            Layer::Flag("--node-id".to_string())
        );

        // Drop the flag: the environment wins.
        let resolved = load_layered(&dir, &CliOverrides::default()).expect("layered load");
        assert_eq!(resolved.config().node.id, "env-node");
        assert_eq!(
            resolved.layer_of("node.id"),
            Layer::Env("INDRA_NODE__ID".to_string())
        );
        drop(_env);

        // Drop the environment: the later conf.d fragment wins.
        let _cleared = EnvGuard::clear(&["INDRA_NODE__ID"]);
        let resolved = load_layered(&dir, &CliOverrides::default()).expect("layered load");
        assert_eq!(resolved.config().node.id, "frag-b");
        assert!(
            matches!(resolved.layer_of("node.id"), Layer::Fragment(_)),
            "provenance must name the fragment, got {:?}",
            resolved.layer_of("node.id")
        );

        // Drop the winning fragment: the earlier fragment wins.
        std::fs::remove_file(fragments.join("20-local.toml")).expect("remove fragment");
        let resolved = load_layered(&dir, &CliOverrides::default()).expect("layered load");
        assert_eq!(resolved.config().node.id, "frag-a");

        // Drop conf.d entirely: the main file wins.
        std::fs::remove_dir_all(&fragments).expect("remove conf.d");
        let resolved = load_layered(&dir, &CliOverrides::default()).expect("layered load");
        assert_eq!(resolved.config().node.id, "file-node");
        assert!(
            matches!(resolved.layer_of("node.id"), Layer::MainFile(_)),
            "provenance must name the main file, got {:?}",
            resolved.layer_of("node.id")
        );

        // Drop the main file: the schema default wins.
        std::fs::remove_file(dir.join("indra.toml")).expect("remove main file");
        let resolved = load_layered(&dir, &CliOverrides::default()).expect("layered load");
        assert_eq!(resolved.config().node.id, "indra-node-1");
        assert_eq!(resolved.layer_of("node.id"), Layer::Defaults);
        scrub(&dir);
    }

    #[test]
    fn confd_name_order_later_name_wins() {
        let _serial = ENV_SERIAL.lock().expect("env serial");
        let _ambient = EnvGuard::clear_all_indra();
        let dir = unique_dir("nameorder");
        let fragments = dir.join("conf.d");
        write(
            &fragments,
            "b-second.toml",
            "[logging]\nlevel = \"debug\"\n",
        );
        write(&fragments, "a-first.toml", "[logging]\nlevel = \"warn\"\n");
        let resolved = load_layered(&dir, &CliOverrides::default()).expect("layered load");
        assert_eq!(resolved.config().logging.level, "debug");
        scrub(&dir);
    }

    #[test]
    fn wrong_typed_env_value_is_a_startup_error_naming_the_variable() {
        let _serial = ENV_SERIAL.lock().expect("env serial");
        let dir = unique_dir("badenv");
        std::fs::create_dir_all(&dir).expect("create config dir");
        let _env = EnvGuard::set(&[("INDRA_SESSION__MAX_QOS0_BACKLOG", "lots")]);
        let err =
            load_layered(&dir, &CliOverrides::default()).expect_err("wrong-typed env must fail");
        let text = err.to_string();
        assert!(
            text.contains("INDRA_SESSION__MAX_QOS0_BACKLOG"),
            "error must name the variable, got: {text}"
        );
        scrub(&dir);
    }

    #[test]
    fn out_of_range_env_value_names_the_variable() {
        let _serial = ENV_SERIAL.lock().expect("env serial");
        let dir = unique_dir("rangeenv");
        std::fs::create_dir_all(&dir).expect("create config dir");
        // Schema range is 1..=100000; 0 must fail and blame the variable.
        let _env = EnvGuard::set(&[("INDRA_SESSION__MAX_QOS0_BACKLOG", "0")]);
        let err =
            load_layered(&dir, &CliOverrides::default()).expect_err("out-of-range env must fail");
        let text = err.to_string();
        assert!(
            text.contains("INDRA_SESSION__MAX_QOS0_BACKLOG"),
            "error must name the variable, got: {text}"
        );
        assert!(
            text.contains("session.max_qos0_backlog"),
            "error must name the setting, got: {text}"
        );
        scrub(&dir);
    }

    #[test]
    fn unknown_env_variable_refuses_startup() {
        let _serial = ENV_SERIAL.lock().expect("env serial");
        let dir = unique_dir("unknownenv");
        std::fs::create_dir_all(&dir).expect("create config dir");
        let _env = EnvGuard::set(&[("INDRA_NOPE__NOT_A_SETTING", "1")]);
        let err = load_layered(&dir, &CliOverrides::default()).expect_err("unknown env must fail");
        assert!(
            err.to_string().contains("INDRA_NOPE__NOT_A_SETTING"),
            "error must name the variable, got: {err}"
        );
        scrub(&dir);
    }

    /// Each flag has a schema home. The file and the environment must
    /// accept that home too. If the catalogue does not contain the home,
    /// an operator can set the value with the flag only.
    #[test]
    fn every_flag_home_is_a_catalogued_setting() {
        let cli = CliOverrides {
            node_id: Some("n".into()),
            data_dir: Some("d".into()),
            brokerlink_bind: Some("127.0.0.1:1".into()),
            bind: Some("127.0.0.1:1".into()),
            api_bind: Some("127.0.0.1:1".into()),
            allow_anonymous: true,
            qos0_backlog: Some(1),
            license_key: Some("k".into()),
            license_keys: Some("p".into()),
            licence_request_out: Some("p".into()),
            licence_install_file: Some("p".into()),
            licence_expiry_warn_days: Some(1),
            cluster_seeds: Some("a:1".into()),
            cluster_bind: Some("127.0.0.1:1".into()),
            coap_bind: Some("127.0.0.1:1".into()),
            stream_dir: Some("d".into()),
            ldap_url: Some("u".into()),
            ldap_base_dn: Some("b".into()),
            ldap_bind_dn: Some("b".into()),
            ldap_bind_password: Some("p".into()),
            ldap_user_filter: Some("f".into()),
            ldap_group_attribute: Some("g".into()),
            ldap_required_group: Some("g".into()),
            ldap_ca_cert: Some("c".into()),
            kerberos_keytab: Some("k".into()),
            kerberos_service_principal: Some("p".into()),
            kerberos_realm: Some("r".into()),
            kerberos_allowed_realms: Some("r".into()),
            kerberos_clock_skew_secs: Some(1),
            kerberos_role_map: Some("m".into()),
            kerberos_replay_max: Some(16),
            qos1_inflight_window: Some(1),
            qos1_spill: Some(1),
            rule_spill_dir: Some("d".into()),
            jwks_url: Some("https://x".into()),
            jwks_issuer: Some("i".into()),
            jwks_audience: Some("a".into()),
            jwks_refresh_period_secs: Some(1),
            jwks_fetch_timeout_ms: Some(100),
            jwks_refresh_timeout_ms: Some(100),
            jwks_cache_max_keys: Some(1),
            jwks_cache_ttl_secs: Some(1),
            jwks_clock_skew_secs: Some(1),
            jwks_ca_cert: Some("c".into()),
            dbauth_postgres_url: Some("u".into()),
            dbauth_mysql_url: Some("u".into()),
            dbauth_redis_url: Some("u".into()),
            dbauth_mongodb_url: Some("u".into()),
            dbauth_pool_size: Some(1),
            dbauth_connect_timeout_ms: Some(100),
            dbauth_read_timeout_ms: Some(100),
            dbauth_cache_size: Some(1),
            dbauth_cache_ttl_secs: Some(1),
            webhook_url: Some("u".into()),
            webhook_pool_size: Some(1),
            webhook_timeout_ms: Some(100),
            webhook_breaker_threshold: Some(1),
            webhook_breaker_reset_ms: Some(1000),
            webhook_cache_size: Some(1),
            webhook_cache_ttl_secs: Some(1),
            delayed_max_secs: Some(1),
            topic_alias_maximum: Some(1),
            monitor_sample_secs: Some(1),
        };
        let mut table = toml::Table::new();
        let mut provenance: HashMap<String, Layer> = HashMap::new();
        cli.apply_to(&mut table, &mut provenance);
        let catalogue = catalogue_kinds();
        let mut missing: Vec<&String> = provenance
            .keys()
            .filter(|path| !catalogue.contains_key(path.as_str()))
            .collect();
        missing.sort();
        assert!(
            missing.is_empty(),
            "these flag homes cannot be set from indra.toml or INDRA_* variables: {missing:?}"
        );
        // The struct literal above has no `..Default::default()`. A new
        // flag field does not compile until this test contains it.
        assert!(provenance.len() >= 60, "got {} homes", provenance.len());
    }

    #[test]
    fn credential_env_variables_do_not_refuse_startup() {
        let _serial = ENV_SERIAL.lock().expect("env serial");
        let dir = unique_dir("credenv");
        std::fs::create_dir_all(&dir).expect("create config dir");
        let _env = EnvGuard::set(&[
            ("INDRA_API_KEYS", "key-one,key-two"),
            ("INDRA_API_KEY", "key-one"),
        ]);
        let layered = load_layered(&dir, &CliOverrides::default())
            .expect("credential variables are not settings");
        // A key is not a setting. No provenance entry refers to a key.
        assert!(layered
            .provenance()
            .values()
            .all(|layer| !format!("{layer:?}").contains("INDRA_API_KEY")));
        scrub(&dir);
    }

    #[test]
    fn legacy_env_aliases_feed_their_schema_homes() {
        let _serial = ENV_SERIAL.lock().expect("env serial");
        let dir = unique_dir("alias");
        std::fs::create_dir_all(&dir).expect("create config dir");
        let _env = EnvGuard::set(&[
            ("INDRA_LICENSE_KEY", "alias-key"),
            ("INDRA_API_BIND", "127.0.0.1:19083"),
        ]);
        let resolved = load_layered(&dir, &CliOverrides::default()).expect("aliases load");
        assert_eq!(resolved.config().licence.license_key, "alias-key");
        assert_eq!(resolved.config().listeners.api.bind, "127.0.0.1:19083");

        // The canonical double-underscore forms win over the aliases.
        let _env2 = EnvGuard::set(&[
            ("INDRA_LICENCE__LICENSE_KEY", "canonical-key"),
            ("INDRA_LISTENERS__API__BIND", "127.0.0.1:19084"),
        ]);
        let resolved = load_layered(&dir, &CliOverrides::default()).expect("aliases load");
        assert_eq!(resolved.config().licence.license_key, "canonical-key");
        assert_eq!(resolved.config().listeners.api.bind, "127.0.0.1:19084");
        scrub(&dir);
    }

    #[test]
    fn env_parses_bools_integers_floats_and_lists() {
        let _serial = ENV_SERIAL.lock().expect("env serial");
        let dir = unique_dir("envtypes");
        std::fs::create_dir_all(&dir).expect("create config dir");
        let _env = EnvGuard::set(&[
            ("INDRA_AUTH__ALLOW_ANONYMOUS", "true"),
            ("INDRA_SESSION__MAX_QOS0_BACKLOG", "7"),
            ("INDRA_QUOTAS__BURST_MULTIPLIER", "3.5"),
            ("INDRA_CLUSTER__SEED_NODES", "host1:19883, host2:19883"),
        ]);
        let resolved = load_layered(&dir, &CliOverrides::default()).expect("typed env loads");
        assert!(resolved.config().auth.allow_anonymous);
        assert_eq!(resolved.config().session.max_qos0_backlog, 7);
        assert_eq!(resolved.config().quotas.burst_multiplier, 3.5);
        assert_eq!(
            resolved.config().cluster.seed_nodes,
            vec!["host1:19883".to_string(), "host2:19883".to_string()]
        );
        scrub(&dir);
    }

    #[test]
    fn pre_rename_section_aliases_still_load() {
        let _serial = ENV_SERIAL.lock().expect("env serial");
        let _ambient = EnvGuard::clear_all_indra();
        let dir = unique_dir("aliases");
        write(
            &dir,
            "indra.toml",
            "[rules]\nwindow_channel_depth = 128\n[listeners.websocket]\nbind = \"127.0.0.1:18083\"\n",
        );
        let resolved = load_layered(&dir, &CliOverrides::default()).expect("aliases load");
        assert_eq!(resolved.config().rules_engine.window_channel_depth, 128);
        assert_eq!(resolved.config().listeners.ws.bind, "127.0.0.1:18083");
        scrub(&dir);
    }

    #[test]
    fn docs_state_the_documented_precedence() {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let docs = manifest
            .join("..")
            .join("..")
            .join("docs")
            .join("configuration.md");
        let text = std::fs::read_to_string(&docs)
            .unwrap_or_else(|_| panic!("docs/configuration.md must exist at {}", docs.display()));
        assert!(
            text.contains(precedence_statement()),
            "user docs must state the precedence verbatim"
        );
    }
}
