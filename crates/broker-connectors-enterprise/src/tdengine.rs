//! TDengine time-series sink (INDRA-173).
//!
//! Buffers MQTT events as super-table rows and writes them with
//! `INSERT INTO <sub> USING <stable> TAGS (...) VALUES (...)`
//! statements (one multi-table statement per flush). Sub-table names,
//! tags and metric values render from strict templates over the event
//! (unknown variables fail loudly); identifiers are validated to
//! `[A-Za-z0-9_]` so no template can inject SQL.
//!
//! Two transports speak the same `INSERT INTO ... USING ... TAGS ...`
//! SQL text over the REST SQL API. [`DriverTdengineTransport`] is the
//! production path for Basic + plaintext endpoints on the maintained
//! `reqwest` driver (`POST /rest/sql/{database}`, Basic auth, driver
//! owned connection setup). [`HttpTdengineTransport`] speaks the same
//! REST SQL API and stays for token auth and TLS endpoints plus
//! offline unit tests (see [`TdengineSinkConfig::use_driver`] for the
//! split). The spec named the official `taos` client, but every `taos`
//! 0.12 line pulls denied `ring` 0.16.20 and `parse_duration` 2.1.1,
//! so the spec cannot pass the licence gate and the driver stays on
//! `reqwest`.
//!
//! Transport failures and throttles retry with jittered backoff; other
//! outcomes are terminal dispatch failures (syntax/table mismatches and
//! auth failures must not loop).

use async_trait::async_trait;
use base64::Engine;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use broker_connectors::{
    now_millis, render_template, BackoffState, BatchQueue, ConnectorError, Result, Sink,
};

/// TDengine authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", tag = "type")]
pub enum TdengineAuth {
    /// HTTP Basic (`Authorization: Basic base64(user:pass)`).
    Basic { username: String, password: String },
    /// Token (`Authorization: Taosd <token>`).
    Token { token: String },
}

impl Default for TdengineAuth {
    fn default() -> Self {
        Self::Basic {
            username: "root".to_string(),
            password: "taosdata".to_string(),
        }
    }
}

impl TdengineAuth {
    /// The `Authorization` header value.
    pub fn header_value(&self) -> Result<String> {
        match self {
            Self::Basic { username, password } => {
                if username.is_empty() {
                    return Err(ConnectorError::Dispatch(
                        "tdengine basic auth needs a username".to_string(),
                    ));
                }
                let credentials = base64::engine::general_purpose::STANDARD
                    .encode(format!("{username}:{password}"));
                Ok(format!("Basic {credentials}"))
            }
            Self::Token { token } => {
                if token.trim().is_empty() {
                    return Err(ConnectorError::Dispatch(
                        "tdengine token must not be empty".to_string(),
                    ));
                }
                Ok(format!("Taosd {token}"))
            }
        }
    }
}

fn default_batch_size() -> Option<usize> {
    // Reason: 500 rows keep one multi-table INSERT a single small HTTP
    // / WebSocket request (typical rows are tens of bytes) while
    // amortising per-request overhead across the batch.
    Some(500)
}

fn default_batch_bytes() -> Option<usize> {
    // Reason: 4 MiB caps one INSERT statement far below any server
    // request-size surprise while still fitting hundreds of telemetry
    // rows per flush.
    Some(4_194_304)
}

fn default_linger_ms() -> Option<u64> {
    // Reason: 20 ms lets a batch fill under burst while keeping
    // interactive flush latency far below one MQTT keep-alive tick.
    Some(20)
}

/// Default outer backlog ceiling: 10_000 rows (about twenty 500-row
/// flushes) so a burst or a stalled server cannot grow the queue
/// without bound while backoff is engaged, while steady throughput
/// still fits in memory (10_000 small template-rendered rows stay well
/// under tens of MiB). Reason: the connector's send path runs behind
/// the rule engine's bounded queue, so this is a backstop, not new
/// work on the publish path.
fn default_buffer_capacity_10k() -> Option<usize> {
    Some(10_000)
}

fn default_max_retries() -> Option<usize> {
    // Reason: 4 retries ride out transient throttle bursts without
    // retrying forever against a persistently failing batch.
    Some(4)
}

fn default_initial_backoff_ms() -> Option<u64> {
    // Reason: 100 ms first delay is longer than a single scheduler
    // quantum so a hot server gets breathing room.
    Some(100)
}

fn default_max_backoff_ms() -> Option<u64> {
    // Reason: 3 s ceiling keeps the retry loop interactive while the
    // fail-fast breaker covers longer outages.
    Some(3_000)
}

fn is_td_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// TDengine sink configuration. Batch depths are optional: `None` on
/// the batch knobs below is an explicit operator opt-in to unbounded
/// (the code never chooses it), with zero clamped ceilings. The outer
/// backlog (`buffer_capacity`) is always bounded: `None` means the
/// finite default below, never unlimited.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TdengineSinkConfig {
    /// REST endpoint, e.g. `http://localhost:6041/rest/sql`. The driver
    /// transport posts to `{scheme://host:port}/rest/sql/{database}`
    /// derived from the same value, so a bare adapter endpoint
    /// (`http://host:6041`) and a full REST endpoint land on one URL.
    pub endpoint: String,
    /// Target database, e.g. `power`.
    pub database: String,
    /// Super-table name, e.g. `meters`.
    pub stable_name: String,
    /// Sub-table template, e.g. `d_${client_id}`.
    pub subtable_template: String,
    /// Authentication (default root/taosdata).
    #[serde(default)]
    pub auth: TdengineAuth,
    /// Tag column → value template (sorted by column at render).
    #[serde(default)]
    pub tags_template: HashMap<String, String>,
    /// Metric column → payload-field template (sorted by column).
    #[serde(default)]
    pub metrics_template: HashMap<String, String>,
    /// Rows per INSERT (default 500: one multi-table statement stays a
    /// single small request; `None` is an explicit operator opt-in to
    /// unbounded, never the code's choice).
    #[serde(default = "default_batch_size")]
    pub batch_size: Option<usize>,
    /// Batch byte limit over SQL text (default 4 MiB: caps one INSERT
    /// far below any server request-size surprise; `None` is an
    /// explicit operator opt-in to unbounded, never the code's choice).
    #[serde(default = "default_batch_bytes")]
    pub batch_bytes: Option<usize>,
    /// Linger flush window in ms (default 20: fills a batch under burst
    /// while keeping interactive flush latency far below one MQTT
    /// keep-alive tick).
    #[serde(default = "default_linger_ms")]
    pub linger_ms: Option<u64>,
    /// In-memory row backlog ceiling (`None` = default 10_000 rows:
    /// about twenty 500-row flushes, bounding worst-case backlog memory
    /// while absorbing bursts; an old stored configuration without this
    /// field parses to the same default, so stored configuration keeps
    /// working. When full the sink fails closed with a connection error
    /// instead of growing without bound or shedding rows silently).
    #[serde(default = "default_buffer_capacity_10k")]
    pub buffer_capacity: Option<usize>,
    /// Retries on transient failures (default 4: rides out throttle
    /// bursts without retrying forever; `None` is an explicit operator
    /// opt-in to unbounded, never the code's choice).
    #[serde(default = "default_max_retries")]
    pub max_retries: Option<usize>,
    /// First retry delay in ms (default 100).
    #[serde(default = "default_initial_backoff_ms")]
    pub initial_backoff_ms: Option<u64>,
    /// Retry delay ceiling in ms (default 3000).
    #[serde(default = "default_max_backoff_ms")]
    pub max_backoff_ms: Option<u64>,
    /// Request / network timeout in ms (default 5000).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

impl TdengineSinkConfig {
    pub fn timeout(&self) -> Duration {
        // Reason: 5 s per-request ceiling so an unreachable server fails
        // closed instead of stalling the rule worker.
        Duration::from_millis(self.timeout_ms.unwrap_or(5000).max(1))
    }

    /// Whether this configuration rides the maintained driver transport.
    /// The driver posts REST SQL on the maintained `reqwest` client
    /// with Basic credentials over plaintext; token auth and TLS
    /// endpoints stay on the REST transport so stored configuration
    /// keeps working. Both transports speak the same `INSERT INTO ...
    /// USING ... TAGS` text; this predicate is the documented split.
    pub fn use_driver(&self) -> bool {
        matches!(self.auth, TdengineAuth::Basic { .. }) && self.endpoint.starts_with("http://")
    }

    pub fn validate(&self) -> Result<()> {
        if !self.endpoint.starts_with("http://") && !self.endpoint.starts_with("https://") {
            return Err(ConnectorError::Dispatch(format!(
                "tdengine endpoint must be http(s): {:?}",
                self.endpoint
            )));
        }
        if !is_td_identifier(&self.database) {
            return Err(ConnectorError::Dispatch(format!(
                "tdengine database must match [A-Za-z0-9_]+: {:?}",
                self.database
            )));
        }
        if !is_td_identifier(&self.stable_name) {
            return Err(ConnectorError::Dispatch(format!(
                "tdengine stable_name must match [A-Za-z0-9_]+: {:?}",
                self.stable_name
            )));
        }
        if self.subtable_template.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "tdengine subtable_template must not be empty".to_string(),
            ));
        }
        // Strict template checks with dummy values.
        self.resolve_subtable("dummy", b"{}", QoS::AtMostOnce, 0)?;
        for (column, template) in self
            .tags_template
            .iter()
            .chain(self.metrics_template.iter())
        {
            if !is_td_identifier(column) {
                return Err(ConnectorError::Dispatch(format!(
                    "tdengine column must match [A-Za-z0-9_]+: {column:?}"
                )));
            }
            self.event_vars("dummy", b"{}", QoS::AtMostOnce, 0, template)?;
        }
        self.auth.header_value().map(|_| ())?;
        if self.batch_size == Some(0) {
            return Err(ConnectorError::Dispatch(
                "tdengine batch_size must be >= 1".to_string(),
            ));
        }
        if self.batch_bytes == Some(0) {
            return Err(ConnectorError::Dispatch(
                "tdengine batch_bytes must be >= 1".to_string(),
            ));
        }
        if self.buffer_capacity == Some(0) {
            return Err(ConnectorError::Dispatch(
                "tdengine buffer_capacity must be >= 1".to_string(),
            ));
        }
        Ok(())
    }

    /// `POST {endpoint}/{database}` (trailing slashes trimmed).
    pub fn insert_url(&self) -> String {
        format!("{}/{}", self.endpoint.trim_end_matches('/'), self.database)
    }

    pub fn effective_batch_size(&self) -> usize {
        // `None` is an explicit operator opt-in to unbounded, never the
        // code's choice; the outer `buffer_capacity` below still bounds
        // worst-case memory.
        self.batch_size.unwrap_or(usize::MAX).max(1)
    }

    pub fn effective_batch_bytes(&self) -> usize {
        // Same opt-in contract as `effective_batch_size`.
        self.batch_bytes.unwrap_or(usize::MAX).max(1)
    }

    /// Outer backlog ceiling (default 10_000 rows: about twenty 500-row
    /// flushes, bounding worst-case backlog memory while absorbing
    /// bursts; `None` means this finite default, never unlimited).
    pub fn effective_buffer_capacity(&self) -> usize {
        self.buffer_capacity.unwrap_or(10_000).max(1)
    }

    pub fn effective_linger(&self) -> Duration {
        self.linger_ms
            .map(Duration::from_millis)
            .unwrap_or(Duration::MAX)
    }

    /// Template variables for one event (`${client_id}` from the JSON
    /// field when present, `${payload.<field>}` extraction on top).
    fn event_vars(
        &self,
        topic: &str,
        payload: &[u8],
        qos: QoS,
        millis: i64,
        template: &str,
    ) -> Result<String> {
        let doc: serde_json::Value = serde_json::from_slice(payload).unwrap_or_default();
        let field = |name: &str| {
            let val = doc
                .get(name)
                .or_else(|| doc.get("payload").and_then(|p| p.get(name)));
            match val {
                Some(serde_json::Value::String(text)) => text.clone(),
                Some(scalar) if scalar.is_number() || scalar.is_boolean() => scalar.to_string(),
                _ => String::new(),
            }
        };
        let client_id_val = doc
            .get("client_id")
            .or_else(|| doc.get("clientid"))
            .or_else(|| doc.get("device_id"))
            .or_else(|| {
                doc.get("payload").and_then(|p| {
                    p.get("client_id")
                        .or_else(|| p.get("clientid"))
                        .or_else(|| p.get("device_id"))
                })
            });
        let client_id = match client_id_val {
            Some(serde_json::Value::String(text)) => text.clone(),
            Some(scalar) if scalar.is_number() || scalar.is_boolean() => scalar.to_string(),
            _ => String::new(),
        };
        let mut vars = vec![
            ("topic".to_string(), topic.to_string()),
            ("client_id".to_string(), client_id),
            ("qos".to_string(), u8::from(qos).to_string()),
            ("timestamp".to_string(), millis.to_string()),
        ];
        let mut rest = template;
        while let Some(start) = rest.find("${payload.") {
            let after = &rest[start + "${payload.".len()..];
            if let Some(close) = after.find('}') {
                let name = &after[..close];
                vars.push((format!("payload.{name}"), field(name)));
                rest = &after[close + 1..];
            } else {
                break;
            }
        }
        let borrowed: Vec<(&str, String)> =
            vars.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
        render_template(template, &borrowed)
    }

    /// Resolve + validate the sub-table for one event.
    pub fn resolve_subtable(
        &self,
        topic: &str,
        payload: &[u8],
        qos: QoS,
        millis: i64,
    ) -> Result<String> {
        let vars = Self::base_vars(topic, payload, qos, millis);
        let borrowed: Vec<(&str, String)> =
            vars.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
        let name = render_template(&self.subtable_template, &borrowed)?;
        if !is_td_identifier(&name) {
            return Err(ConnectorError::Dispatch(format!(
                "tdengine sub-table resolved invalid (want [A-Za-z0-9_]+): {name:?}"
            )));
        }
        Ok(name)
    }

    fn base_vars(topic: &str, payload: &[u8], qos: QoS, millis: i64) -> Vec<(String, String)> {
        let doc: serde_json::Value = serde_json::from_slice(payload).unwrap_or_default();
        let client_id_val = doc
            .get("client_id")
            .or_else(|| doc.get("clientid"))
            .or_else(|| doc.get("device_id"))
            .or_else(|| {
                doc.get("payload").and_then(|p| {
                    p.get("client_id")
                        .or_else(|| p.get("clientid"))
                        .or_else(|| p.get("device_id"))
                })
            });
        let client_id = match client_id_val {
            Some(serde_json::Value::String(text)) => text.clone(),
            Some(scalar) if scalar.is_number() || scalar.is_boolean() => scalar.to_string(),
            _ => String::new(),
        };
        vec![
            ("topic".to_string(), topic.to_string()),
            ("client_id".to_string(), client_id),
            ("qos".to_string(), u8::from(qos).to_string()),
            ("timestamp".to_string(), millis.to_string()),
        ]
    }
}

/// Render a SQL literal: numbers and booleans ride raw, strings are
/// single-quoted with `''` escaping, null renders NULL.
fn sql_literal(rendered: &str) -> String {
    if rendered == "NULL" {
        return "NULL".to_string();
    }
    if rendered.parse::<f64>().is_ok() && !rendered.trim().is_empty() {
        return rendered.to_string();
    }
    if rendered == "true" || rendered == "false" {
        return rendered.to_uppercase();
    }
    format!("'{}'", rendered.replace('\'', "''"))
}

// ---------------------------------------------------------------------------
// Wire framing.
// ---------------------------------------------------------------------------

/// One super-table row: sub-table, tag literals, metric literals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdengineRow {
    pub subtable: String,
    pub tags: Vec<String>,
    pub metrics: Vec<String>,
    pub timestamp_ms: i64,
}

/// Render one multi-table `INSERT INTO ... USING ...` statement.
/// Tag/metric literals arrive pre-sorted by column for determinism.
pub fn render_insert(stable: &str, rows: &[TdengineRow]) -> String {
    let mut sql = String::from("INSERT INTO ");
    for (index, row) in rows.iter().enumerate() {
        if index > 0 {
            sql.push(' ');
        }
        sql.push_str(&row.subtable);
        sql.push_str(" USING ");
        sql.push_str(stable);
        sql.push_str(" TAGS (");
        sql.push_str(&row.tags.join(", "));
        sql.push_str(") VALUES (");
        sql.push_str(&row.timestamp_ms.to_string());
        for metric in &row.metrics {
            sql.push_str(", ");
            sql.push_str(metric);
        }
        sql.push(')');
    }
    sql.push(';');
    sql
}

/// Parsed `{"code": n, "rows": m}` REST response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TdengineResponse {
    pub code: i64,
    pub rows: u64,
}

pub fn parse_rest_response(body: &[u8]) -> Result<TdengineResponse> {
    let doc: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| ConnectorError::Connection(format!("tdengine bad response JSON: {e}")))?;
    let code = doc
        .get("code")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| ConnectorError::Connection("tdengine response lacks code".to_string()))?;
    let rows = doc.get("rows").and_then(|v| v.as_u64()).unwrap_or(0);
    Ok(TdengineResponse { code, rows })
}

// ---------------------------------------------------------------------------
// Transport.
// ---------------------------------------------------------------------------

/// Scripted outcome for the mock transport.
#[derive(Debug, Clone)]
pub enum MockTdengineOutcome {
    /// `{"code": 0}` with this many affected rows.
    Ok(u64),
    /// Transport failure (retries in-loop).
    ConnectionError(String),
    /// Non-zero TDengine code (terminal, no retry).
    SqlError { code: i64 },
}

/// One captured SQL execution.
#[derive(Debug, Clone)]
pub struct CapturedTdengineSql {
    pub database: String,
    pub sql: String,
    pub auth: String,
}

#[async_trait]
pub trait TdengineTransport: Send + Sync {
    async fn execute_sql(&self, database: &str, sql: &str, auth: &TdengineAuth) -> Result<usize>;
}

/// In-memory transport with scripted outcomes (tests, dry runs).
#[derive(Debug, Default)]
pub struct MockTdengineTransport {
    scripted: parking_lot::Mutex<std::collections::VecDeque<MockTdengineOutcome>>,
    captured: parking_lot::Mutex<Vec<CapturedTdengineSql>>,
    calls: AtomicU64,
}

impl MockTdengineTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue outcomes consumed in order (default: success, 1 row).
    pub fn script_outcomes(&self, outcomes: Vec<MockTdengineOutcome>) {
        *self.scripted.lock() = outcomes.into_iter().collect();
    }

    pub fn captured(&self) -> Vec<CapturedTdengineSql> {
        self.captured.lock().clone()
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl TdengineTransport for MockTdengineTransport {
    async fn execute_sql(&self, database: &str, sql: &str, auth: &TdengineAuth) -> Result<usize> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.captured.lock().push(CapturedTdengineSql {
            database: database.to_string(),
            sql: sql.to_string(),
            auth: auth.header_value().unwrap_or_default(),
        });
        match self.scripted.lock().pop_front() {
            None => Ok(1),
            Some(MockTdengineOutcome::Ok(rows)) => Ok(rows as usize),
            Some(MockTdengineOutcome::ConnectionError(message)) => {
                Err(ConnectorError::Connection(message))
            }
            Some(MockTdengineOutcome::SqlError { code }) => Err(ConnectorError::Dispatch(format!(
                "mock tdengine SQL failed with code {code}"
            ))),
        }
    }
}

/// Production transport: `POST {insert-url}` with the SQL text.
pub struct HttpTdengineTransport {
    url: String,
    client: reqwest::Client,
}

impl HttpTdengineTransport {
    pub fn new(config: &TdengineSinkConfig, client: reqwest::Client) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            url: config.insert_url(),
            client,
        })
    }
}

#[async_trait]
impl TdengineTransport for HttpTdengineTransport {
    async fn execute_sql(&self, _database: &str, sql: &str, auth: &TdengineAuth) -> Result<usize> {
        let response = self
            .client
            .post(&self.url)
            .header(reqwest::header::AUTHORIZATION, auth.header_value()?)
            .body(sql.to_string())
            .send()
            .await
            .map_err(|e| ConnectorError::Connection(format!("tdengine request failed: {e}")))?;
        let status = response.status().as_u16();
        if status == 429 || (500..=504).contains(&status) {
            return Err(ConnectorError::Connection(format!(
                "tdengine throttled with {status}"
            )));
        }
        if !(200..=299).contains(&status) {
            return Err(ConnectorError::Dispatch(format!(
                "tdengine request failed with {status}"
            )));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|e| ConnectorError::Connection(format!("tdengine read failed: {e}")))?;
        let parsed = parse_rest_response(&bytes)?;
        if parsed.code != 0 {
            return Err(ConnectorError::Dispatch(format!(
                "tdengine SQL failed with code {}",
                parsed.code
            )));
        }
        Ok(parsed.rows as usize)
    }
}

// ---------------------------------------------------------------------------
// Driver transport (production path for Basic + plaintext endpoints).
// ---------------------------------------------------------------------------

/// Split a validated `http(s)://host[:port][/...]` endpoint into
/// `(tls, host, port)`. The port defaults to 6041: the adapter port
/// serving the REST SQL interface.
fn split_driver_endpoint(endpoint: &str) -> Result<(bool, String, u16)> {
    let (tls, rest) = if let Some(rest) = endpoint.strip_prefix("http://") {
        (false, rest)
    } else if let Some(rest) = endpoint.strip_prefix("https://") {
        (true, rest)
    } else {
        return Err(ConnectorError::Dispatch(format!(
            "tdengine endpoint must be http(s): {endpoint:?}"
        )));
    };
    let host_port = rest.split('/').next().unwrap_or("");
    if host_port.is_empty() || host_port.contains('@') {
        return Err(ConnectorError::Dispatch(format!(
            "tdengine endpoint has no host: {endpoint:?}"
        )));
    }
    let (host, port) = match host_port.rsplit_once(':') {
        Some((host, port_text)) => {
            if host.is_empty() {
                return Err(ConnectorError::Dispatch(format!(
                    "tdengine endpoint has no host: {endpoint:?}"
                )));
            }
            let port: u16 = port_text.parse().map_err(|_| {
                ConnectorError::Dispatch(format!("tdengine endpoint has a bad port: {endpoint:?}"))
            })?;
            (host.to_string(), port)
        }
        // Reason: 6041 is the adapter port serving the REST SQL
        // interface, so a bare host means the default adapter.
        None => (host_port.to_string(), 6041),
    };
    Ok((tls, host, port))
}

/// Build the REST SQL URL for this configuration:
/// `{base}/rest/sql` without a database (for `CREATE DATABASE` and other
/// admin statements that must run before the database exists), or
/// `{base}/rest/sql/{database}` with one. `{base}` is the
/// `scheme://host:port` from [`split_driver_endpoint`], so both a bare
/// adapter endpoint (`http://host:6041`, as the qualification env
/// provides) and a full REST endpoint (`http://host:6041/rest/sql`, as
/// stored configuration carries) land on the same URL.
fn rest_url_for(endpoint: &str, database_override: Option<&str>) -> Result<String> {
    let (tls, host, port) = split_driver_endpoint(endpoint)?;
    let scheme = if tls { "https" } else { "http" };
    // Reason: 6041 is the adapter port (REST SQL lives under it), so the
    // base is always explicit here rather than inherited from the config
    // string's path.
    let base = format!("{scheme}://{host}:{port}");
    match database_override {
        Some(database) => {
            if !is_td_identifier(database) {
                return Err(ConnectorError::Dispatch(format!(
                    "tdengine database must match [A-Za-z0-9_]+: {database:?}"
                )));
            }
            Ok(format!("{base}/rest/sql/{database}"))
        }
        None => Ok(format!("{base}/rest/sql")),
    }
}

/// Classify a driver error string. Timeouts, refused connections and
/// throttled servers retry as connection failures; authentication and
/// syntax failures are terminal dispatch errors (a wrong password or a
/// bad statement must fail closed, never loop). Anything unrecognised
/// fails closed as terminal too: an unknown error must not spin the
/// retry loop.
fn map_driver_error(context: &str, message: &str) -> ConnectorError {
    let folded = message.to_lowercase();
    if folded.contains("timed out")
        || folded.contains("timeout")
        || folded.contains("connection refused")
        || folded.contains("connection reset")
        || folded.contains("network")
        || folded.contains("temporar")
        || folded.contains("throttl")
        || folded.contains("busy")
        || folded.contains("429")
        || folded.contains("503")
        || folded.contains("500")
    {
        return ConnectorError::Connection(format!("tdengine driver {context}: {message}"));
    }
    if folded.contains("auth")
        || folded.contains("unauthor")
        || folded.contains("login")
        || folded.contains("password")
        || folded.contains("denied")
        || folded.contains("401")
        || folded.contains("403")
    {
        return ConnectorError::Dispatch(format!("tdengine driver auth {context}: {message}"));
    }
    ConnectorError::Dispatch(format!("tdengine driver {context}: {message}"))
}

/// Decode a TDengine REST SQL `SELECT` body into rows of `T`.
/// `column_meta` names the columns, `data` carries the rows
/// positionally; zipping them into objects lets `T`'s named fields (the
/// statement's column aliases) deserialise.
fn decode_rest_rows<T>(doc: &serde_json::Value) -> Result<Vec<T>>
where
    T: serde::de::DeserializeOwned,
{
    let empty = Vec::new();
    let metas = doc
        .get("column_meta")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty);
    let names: Vec<String> = metas
        .iter()
        .filter_map(|col| {
            col.as_array()
                .and_then(|parts| parts.first())
                .and_then(|name| name.as_str())
                .map(str::to_string)
        })
        .collect();
    let data = doc
        .get("data")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut rows = Vec::with_capacity(data.len());
    for values in data {
        let cells = values.as_array().cloned().unwrap_or_default();
        let mut map = serde_json::Map::with_capacity(names.len());
        for (index, name) in names.iter().enumerate() {
            let cell = cells.get(index).cloned().unwrap_or(serde_json::Value::Null);
            map.insert(name.clone(), cell);
        }
        let row: T = serde_json::from_value(serde_json::Value::Object(map))
            .map_err(|e| map_driver_error("query", &format!("decode row: {e}")))?;
        rows.push(row);
    }
    Ok(rows)
}
/// Production transport on the maintained `reqwest` REST SQL driver.
///
/// Holds the validated config and posts the same `INSERT INTO ...
/// USING ... TAGS ...` text the REST path sends, to
/// `{base}/rest/sql/{database}` with Basic auth. `new` is sync (so
/// management wiring stays sync like the other driver transports);
/// the client owns its connection pool.
/// PERF(parity): a pooled client already serves all flushes; no extra
/// setup runs per call.
pub struct DriverTdengineTransport {
    config: TdengineSinkConfig,
    client: reqwest::Client,
}

impl DriverTdengineTransport {
    pub fn new(config: &TdengineSinkConfig) -> Result<Self> {
        config.validate()?;
        // The driver path posts REST SQL with Basic credentials over
        // plaintext. Token auth and TLS endpoints stay on the REST
        // transport (see `TdengineSinkConfig::use_driver`): rejecting
        // them here fails closed instead of silently sending with the
        // wrong credential.
        if !config.use_driver() {
            return Err(ConnectorError::Dispatch(
                "tdengine driver needs Basic auth with a plaintext http endpoint; \
                 token auth and https endpoints stay on the REST transport"
                    .to_string(),
            ));
        }
        // Fail closed at construction when the URL itself cannot build
        // (bad host, bad database), with no I/O.
        let _ = rest_url_for(&config.endpoint, Some(config.database.as_str()))?;
        let _ = rest_url_for(&config.endpoint, None)?;
        let client = reqwest::Client::builder()
            .timeout(config.timeout())
            .build()
            .map_err(|e| {
                ConnectorError::Connection(format!("tdengine driver client failed: {e}"))
            })?;
        Ok(Self {
            config: config.clone(),
            client,
        })
    }

    async fn run_exec(&self, database: Option<&str>, sql: &str) -> Result<usize> {
        let url = rest_url_for(&self.config.endpoint, database)?;
        let auth = self.config.auth.header_value()?;
        let response = self
            .client
            .post(&url)
            .header(reqwest::header::AUTHORIZATION, auth)
            .body(sql.to_string())
            .send()
            .await
            .map_err(|e| map_driver_error("exec", &e.to_string()))?;
        let status = response.status().as_u16();
        if status == 429 || (500..=504).contains(&status) {
            return Err(ConnectorError::Connection(format!(
                "tdengine driver exec throttled with {status}"
            )));
        }
        if status == 401 || status == 403 {
            return Err(ConnectorError::Dispatch(format!(
                "tdengine driver auth exec failed with {status}"
            )));
        }
        if !(200..=299).contains(&status) {
            return Err(map_driver_error(
                "exec",
                &format!("request failed with {status}"),
            ));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|e| map_driver_error("exec", &e.to_string()))?;
        let doc: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
            ConnectorError::Connection(format!("tdengine driver bad response JSON: {e}"))
        })?;
        let code = doc.get("code").and_then(|v| v.as_i64()).ok_or_else(|| {
            ConnectorError::Connection("tdengine driver response lacks code".to_string())
        })?;
        if code != 0 {
            let desc = doc.get("desc").and_then(|v| v.as_str()).unwrap_or("");
            return Err(map_driver_error(
                "exec",
                &format!("SQL failed with code {code} {desc}"),
            ));
        }
        let rows = doc.get("rows").and_then(|v| v.as_u64()).unwrap_or(0);
        Ok(rows as usize)
    }

    async fn run_query<T>(&self, database: Option<&str>, sql: &str) -> Result<Vec<T>>
    where
        T: serde::de::DeserializeOwned,
    {
        let url = rest_url_for(&self.config.endpoint, database)?;
        let auth = self.config.auth.header_value()?;
        let response = self
            .client
            .post(&url)
            .header(reqwest::header::AUTHORIZATION, auth)
            .body(sql.to_string())
            .send()
            .await
            .map_err(|e| map_driver_error("query", &e.to_string()))?;
        let status = response.status().as_u16();
        if status == 429 || (500..=504).contains(&status) {
            return Err(ConnectorError::Connection(format!(
                "tdengine driver query throttled with {status}"
            )));
        }
        if status == 401 || status == 403 {
            return Err(ConnectorError::Dispatch(format!(
                "tdengine driver auth query failed with {status}"
            )));
        }
        if !(200..=299).contains(&status) {
            return Err(map_driver_error(
                "query",
                &format!("request failed with {status}"),
            ));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|e| map_driver_error("query", &e.to_string()))?;
        let doc: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
            ConnectorError::Connection(format!("tdengine driver bad response JSON: {e}"))
        })?;
        let code = doc.get("code").and_then(|v| v.as_i64()).ok_or_else(|| {
            ConnectorError::Connection("tdengine driver response lacks code".to_string())
        })?;
        if code != 0 {
            let desc = doc.get("desc").and_then(|v| v.as_str()).unwrap_or("");
            return Err(map_driver_error(
                "query",
                &format!("SQL failed with code {code} {desc}"),
            ));
        }
        decode_rest_rows(&doc)
    }

    /// Execute one admin statement without a database context
    /// (`CREATE DATABASE`, `CREATE STABLE`, `DROP ...`): the target
    /// database may not exist yet, so the URL carries none and the
    /// statement names it explicitly.
    pub async fn exec_admin(&self, sql: &str) -> Result<usize> {
        self.run_exec(None, sql).await
    }

    /// Query through the driver, deserialising each row into `T`
    /// (named fields match the statement's column aliases).
    /// `database` selects the REST URL database; `None` queries without one.
    pub async fn query_rows<T>(&self, database: Option<&str>, sql: &str) -> Result<Vec<T>>
    where
        T: serde::de::DeserializeOwned,
    {
        self.run_query(database, sql).await
    }
}

#[async_trait]
impl TdengineTransport for DriverTdengineTransport {
    async fn execute_sql(&self, database: &str, sql: &str, auth: &TdengineAuth) -> Result<usize> {
        // The sink passes its own auth back in; a caller swapping the
        // credential mid-stream must fail closed, never execute with a
        // different identity than the transport was built for.
        if auth != &self.config.auth {
            return Err(ConnectorError::Dispatch(
                "tdengine driver auth mismatch: failing closed".to_string(),
            ));
        }
        self.run_exec(Some(database), sql).await
    }
}

// ---------------------------------------------------------------------------
// Sink.
// ---------------------------------------------------------------------------

/// One buffered row.
#[derive(Debug, Clone)]
struct TdRow {
    row: TdengineRow,
}

struct TdBuffer {
    queue: BatchQueue<TdRow>,
    bytes: usize,
}

/// TDengine sink: buffers rows, writes multi-table INSERT batches.
pub struct TdengineSink {
    config: TdengineSinkConfig,
    transport: Arc<dyn TdengineTransport>,
    buffer: parking_lot::Mutex<TdBuffer>,
    backoff: parking_lot::Mutex<BackoffState>,
    sent_batches: AtomicU64,
    sent_records: AtomicU64,
}

impl TdengineSink {
    pub fn new(config: TdengineSinkConfig, transport: Arc<dyn TdengineTransport>) -> Result<Self> {
        config.validate()?;
        let linger = config.effective_linger();
        Ok(Self {
            buffer: parking_lot::Mutex::new(TdBuffer {
                queue: BatchQueue::new(config.effective_batch_size(), linger),
                bytes: 0,
            }),
            config,
            transport,
            backoff: parking_lot::Mutex::new(BackoffState::default()),
            sent_batches: AtomicU64::new(0),
            sent_records: AtomicU64::new(0),
        })
    }

    pub fn config(&self) -> &TdengineSinkConfig {
        &self.config
    }

    pub fn sent_batches(&self) -> u64 {
        self.sent_batches.load(Ordering::Relaxed)
    }

    pub fn sent_records(&self) -> u64 {
        self.sent_records.load(Ordering::Relaxed)
    }

    pub fn buffered_rows(&self) -> usize {
        self.buffer.lock().queue.len()
    }

    fn backoff_delay(&self, attempt: usize) -> Duration {
        let initial = self.config.initial_backoff_ms.unwrap_or(100).max(1);
        let max = self.config.max_backoff_ms.unwrap_or(3_000).max(1);
        let grown = initial
            .saturating_mul(2u64.saturating_pow(attempt.min(10) as u32))
            .min(max);
        let jitter = (now_millis().max(0) as u64) % (grown / 2 + 1);
        Duration::from_millis(grown.saturating_add(jitter).min(max.saturating_mul(2)))
    }

    /// Build one row: sub-table, sorted tag/metric literals, timestamp.
    /// Payloads must be JSON objects (metric columns read fields).
    fn build_row(
        &self,
        topic: &Topic,
        payload: &Bytes,
        qos: QoS,
        millis: i64,
    ) -> Result<(TdengineRow, usize)> {
        let text = std::str::from_utf8(payload)
            .map_err(|_| ConnectorError::Dispatch("tdengine payload must be UTF-8".to_string()))?;
        let value: serde_json::Value = serde_json::from_str(text)
            .map_err(|_| ConnectorError::Dispatch("tdengine payload must be JSON".to_string()))?;
        if !value.is_object() {
            return Err(ConnectorError::Dispatch(
                "tdengine payload must be a JSON object".to_string(),
            ));
        }
        let subtable = self
            .config
            .resolve_subtable(topic.as_str(), payload, qos, millis)?;
        // NOTE: QoS does not shape rows; AtMostOnce renders no variables.
        let mut tags = Vec::new();
        let mut tag_columns: Vec<&String> = self.config.tags_template.keys().collect();
        tag_columns.sort();
        for column in tag_columns {
            let rendered = self.config.event_vars(
                topic.as_str(),
                payload,
                qos,
                millis,
                &self.config.tags_template[column],
            )?;
            tags.push(sql_literal(&rendered));
        }
        let mut metrics = Vec::new();
        let mut metric_columns: Vec<&String> = self.config.metrics_template.keys().collect();
        metric_columns.sort();
        for column in metric_columns {
            let rendered = self.config.event_vars(
                topic.as_str(),
                payload,
                qos,
                millis,
                &self.config.metrics_template[column],
            )?;
            metrics.push(sql_literal(&rendered));
        }
        let bytes = subtable.len() + tags_len(&tags) + tags_len(&metrics) + 32;
        let row = TdengineRow {
            subtable,
            tags,
            metrics,
            timestamp_ms: millis,
        };
        Ok((row, bytes))
    }

    /// Flush buffered rows as one INSERT (no-op when empty).
    /// Transient failures retry in place; terminal failures and
    /// exhaustion restore the buffer, engage backoff, and propagate.
    pub async fn flush(&self) -> Result<()> {
        self.backoff.lock().check()?;
        let (rows, oldest, taken_bytes) = {
            let mut buffer = self.buffer.lock();
            let (rows, oldest) = buffer.queue.take_batch();
            let taken = std::mem::replace(&mut buffer.bytes, 0);
            (rows, oldest, taken)
        };
        if rows.is_empty() {
            return Ok(());
        }
        let statements: Vec<TdengineRow> = rows.iter().map(|row| row.row.clone()).collect();
        let sql = render_insert(&self.config.stable_name, &statements);
        let record_count = rows.len() as u64;
        let max_retries = self.config.max_retries.unwrap_or(usize::MAX);
        let mut attempt = 0usize;
        loop {
            match self
                .transport
                .execute_sql(&self.config.database, &sql, &self.config.auth)
                .await
            {
                Ok(_) => {
                    self.backoff.lock().success();
                    self.sent_batches.fetch_add(1, Ordering::Relaxed);
                    self.sent_records.fetch_add(record_count, Ordering::Relaxed);
                    return Ok(());
                }
                Err(ConnectorError::Connection(message)) => {
                    if attempt >= max_retries {
                        return self.restore_err(
                            rows,
                            oldest,
                            taken_bytes,
                            ConnectorError::Connection(message),
                        );
                    }
                    attempt += 1;
                    tokio::time::sleep(self.backoff_delay(attempt)).await;
                }
                Err(e) => {
                    return self.restore_err(rows, oldest, taken_bytes, e);
                }
            }
        }
    }

    fn restore_err(
        &self,
        rows: Vec<TdRow>,
        oldest: Option<std::time::Instant>,
        bytes: usize,
        error: ConnectorError,
    ) -> Result<()> {
        let mut buffer = self.buffer.lock();
        buffer.queue.restore(rows, oldest);
        buffer.bytes = buffer.bytes.saturating_add(bytes);
        self.backoff.lock().failure();
        Err(error)
    }

    /// Validate + buffer one event. Returns true when the batch is
    /// full, stale, or over the byte limit (caller flushes).
    /// (QoS shapes no columns; it travels in `_mqtt`-style tags only
    /// when operators template it in.)
    fn buffer_row(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<bool> {
        if topic.as_str().is_empty() {
            return Err(ConnectorError::Dispatch(
                "tdengine row requires a non-empty topic".to_string(),
            ));
        }
        let millis = now_millis();
        let (row, bytes) = self.build_row(topic, payload, qos, millis)?;
        let mut buffer = self.buffer.lock();
        // Bounded backlog: past the effective capacity the sink fails
        // closed with a connection error instead of growing without
        // bound; buffered rows are kept, nothing is shed.
        if buffer.queue.len() >= self.config.effective_buffer_capacity() {
            return Err(ConnectorError::Connection(format!(
                "tdengine buffer full ({} rows): failing closed",
                self.config.effective_buffer_capacity()
            )));
        }
        let full = buffer.queue.push(TdRow { row });
        buffer.bytes = buffer.bytes.saturating_add(bytes);
        Ok(full || buffer.bytes >= self.config.effective_batch_bytes())
    }
}

fn tags_len(tags: &[String]) -> usize {
    tags.iter().map(String::len).sum()
}

#[async_trait]
impl Sink for TdengineSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        if self.buffer_row(topic, payload, qos)? {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "tdengine"
    }
}

/// Management connector handle pairing an id with a TDengine sink.
pub struct TdengineConnector {
    id: String,
    sink: Arc<TdengineSink>,
}

impl TdengineConnector {
    pub fn new(id: impl Into<String>, sink: Arc<TdengineSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }
}

impl broker_connectors::Connector for TdengineConnector {
    fn connector_id(&self) -> &str {
        &self.id
    }

    fn kind(&self) -> &'static str {
        self.sink.kind()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use broker_connectors::Sink;

    fn test_config() -> TdengineSinkConfig {
        TdengineSinkConfig {
            endpoint: "http://127.0.0.1:6041/rest/sql".to_string(),
            database: "power".to_string(),
            stable_name: "meters".to_string(),
            subtable_template: "d_${client_id}".to_string(),
            auth: TdengineAuth::Basic {
                username: "root".to_string(),
                password: "taosdata".to_string(),
            },
            tags_template: HashMap::from([
                ("location".to_string(), "${payload.location}".to_string()),
                ("groupid".to_string(), "${payload.groupid}".to_string()),
            ]),
            metrics_template: HashMap::from([
                ("current".to_string(), "${payload.current}".to_string()),
                ("voltage".to_string(), "${payload.voltage}".to_string()),
            ]),
            batch_size: Some(500),
            batch_bytes: Some(4_194_304),
            linger_ms: Some(20),
            buffer_capacity: None,
            max_retries: Some(4),
            initial_backoff_ms: Some(100),
            max_backoff_ms: Some(3_000),
            timeout_ms: None,
        }
    }

    fn test_sink(config: TdengineSinkConfig) -> (Arc<TdengineSink>, Arc<MockTdengineTransport>) {
        let transport = Arc::new(MockTdengineTransport::new());
        let sink = Arc::new(TdengineSink::new(config, transport.clone()).unwrap());
        (sink, transport)
    }

    #[test]
    fn test_config_validation() {
        let mut config = test_config();
        assert!(config.validate().is_ok());
        assert_eq!(config.insert_url(), "http://127.0.0.1:6041/rest/sql/power");

        config.endpoint = "127.0.0.1:6041".to_string();
        assert!(config.validate().is_err());
        config.endpoint = test_config().endpoint;

        config.database = "has space".to_string();
        assert!(config.validate().is_err());
        config.database = "power".to_string();

        config.stable_name = "meters; DROP TABLE x;".to_string();
        assert!(config.validate().is_err());
        config.stable_name = "meters".to_string();

        config.subtable_template = "d-${topic}".to_string();
        assert!(
            config.validate().is_err(),
            "slash must fail identifier check"
        );
        config.subtable_template = test_config().subtable_template;

        config
            .tags_template
            .insert("bad col".to_string(), "x".to_string());
        assert!(config.validate().is_err());
        config.tags_template.remove("bad col");

        config.auth = TdengineAuth::Token {
            token: "  ".to_string(),
        };
        assert!(config.validate().is_err());
        config.auth = test_config().auth;

        config.batch_size = Some(0);
        assert!(config.validate().is_err());
        // Explicit unbounded opt-in on the batch knobs stays accepted
        // (the code never chooses it); the outer backlog stays
        // always-bounded with its finite default.
        config.batch_size = None;
        config.batch_bytes = Some(10_000_000);
        config.max_retries = None;
        assert!(config.validate().is_ok());
        config.buffer_capacity = Some(0);
        assert!(config.validate().is_err());
        config.buffer_capacity = None;
        assert_eq!(config.effective_buffer_capacity(), 10_000);
    }

    #[test]
    fn test_buffer_capacity_default_and_use_driver() {
        // A stored configuration without the field parses to the finite
        // default, so old configuration keeps working and the code never
        // chooses unbounded.
        let stored = serde_json::json!({
            "endpoint": "http://127.0.0.1:6041/rest/sql",
            "database": "power",
            "stable_name": "meters",
            "subtable_template": "d_${client_id}",
        });
        let cfg: TdengineSinkConfig = serde_json::from_value(stored).expect("stored config parses");
        assert_eq!(cfg.buffer_capacity, Some(10_000));
        assert_eq!(cfg.effective_buffer_capacity(), 10_000);
        assert!(cfg.validate().is_ok());
        // Basic + plaintext rides the driver; token auth and TLS stay
        // on REST so stored configuration keeps working.
        assert!(cfg.use_driver());
        let mut token = cfg.clone();
        token.auth = TdengineAuth::Token {
            token: "abc".to_string(),
        };
        assert!(!token.use_driver());
        let mut tls = cfg.clone();
        tls.endpoint = "https://127.0.0.1:6041/rest/sql".to_string();
        assert!(!tls.use_driver());
    }

    #[test]
    fn test_driver_rest_url_shapes() {
        // A full REST endpoint and a bare adapter host land on the same
        // URL; trailing slashes and extra path segments never leak in.
        assert_eq!(
            rest_url_for("http://127.0.0.1:6041/rest/sql", Some("power")).unwrap(),
            "http://127.0.0.1:6041/rest/sql/power"
        );
        assert_eq!(
            rest_url_for("http://127.0.0.1:6041", Some("power")).unwrap(),
            "http://127.0.0.1:6041/rest/sql/power"
        );
        assert_eq!(
            rest_url_for("http://dbhost/rest/sql/", Some("power")).unwrap(),
            "http://dbhost:6041/rest/sql/power"
        );
        // Admin statements run without a database context.
        assert_eq!(
            rest_url_for("http://127.0.0.1:6041/rest/sql", None).unwrap(),
            "http://127.0.0.1:6041/rest/sql"
        );
        // TLS endpoints select the secure scheme.
        assert_eq!(
            rest_url_for("https://dbhost:16041/x", Some("power")).unwrap(),
            "https://dbhost:16041/rest/sql/power"
        );
        assert!(rest_url_for("127.0.0.1:6041", Some("power")).is_err());
        assert!(rest_url_for("http://127.0.0.1:6041", Some("has space")).is_err());
    }

    #[test]
    fn test_decode_rest_rows_select_shape() {
        // The REST `SELECT` body carries columns in `column_meta` and
        // rows positionally in `data`; decoding zips them by alias.
        #[derive(Debug, PartialEq, serde::Deserialize)]
        struct Row {
            n: i64,
        }
        let doc: serde_json::Value = serde_json::from_str(
            r#"{"code":0,"column_meta":[["n","BIGINT",8]],"data":[[2000]],"rows":1}"#,
        )
        .unwrap();
        let rows: Vec<Row> = decode_rest_rows(&doc).unwrap();
        assert_eq!(rows, vec![Row { n: 2000 }]);
        // A missing `data` array decodes to no rows (never a failure).
        let empty: serde_json::Value = serde_json::from_str(r#"{"code":0}"#).unwrap();
        let rows: Vec<Row> = decode_rest_rows(&empty).unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn test_driver_transport_construction() {
        // Basic + plaintext is the qualified driver path.
        assert!(DriverTdengineTransport::new(&test_config()).is_ok());
        // Token auth and TLS fail closed at construction: they stay on
        // the REST transport instead of sending with a wrong credential.
        let mut token = test_config();
        token.auth = TdengineAuth::Token {
            token: "abc".to_string(),
        };
        assert!(DriverTdengineTransport::new(&token).is_err());
        let mut tls = test_config();
        tls.endpoint = "https://127.0.0.1:6041/rest/sql".to_string();
        assert!(DriverTdengineTransport::new(&tls).is_err());
    }

    #[test]
    fn test_driver_rest_url_builds() {
        // The driver posts REST SQL. A full REST endpoint and a bare
        // adapter host land on the same URL.
        let cfg = test_config();
        assert_eq!(
            rest_url_for(&cfg.endpoint, Some("power")).unwrap(),
            "http://127.0.0.1:6041/rest/sql/power"
        );
        assert_eq!(
            rest_url_for(&cfg.endpoint, None).unwrap(),
            "http://127.0.0.1:6041/rest/sql"
        );
        let bare = "http://127.0.0.1:6041".to_string();
        assert_eq!(
            rest_url_for(&bare, Some("power")).unwrap(),
            "http://127.0.0.1:6041/rest/sql/power"
        );
        // The driver transport builds without I/O here.
        assert!(DriverTdengineTransport::new(&cfg).is_ok());
        assert!(rest_url_for(&cfg.endpoint, Some("has space")).is_err());
    }

    #[test]
    fn test_map_driver_error_classification() {
        // Authentication failures are terminal: a wrong password must
        // fail closed, never spin the retry loop.
        for message in [
            "Authentication failure",
            "unauthorized",
            "login failed",
            "wrong password",
            "access denied",
            "code 0x26000: auth error",
        ] {
            assert!(
                matches!(
                    map_driver_error("exec", message),
                    ConnectorError::Dispatch(_)
                ),
                "auth must be terminal, got {message:?}"
            );
        }
        // Timeouts, refused connections and throttles retry.
        for message in [
            "timed out after 5s",
            "connection refused",
            "network unreachable",
            "server busy",
            "temporarily unavailable",
            "throttled with 503",
        ] {
            assert!(
                matches!(
                    map_driver_error("exec", message),
                    ConnectorError::Connection(_)
                ),
                "transient must retry, got {message:?}"
            );
        }
        // Syntax and everything unknown fail closed as terminal: an
        // unknown error must not spin the retry loop.
        for message in ["syntax error near INTO", "table does not exist", "weird?!"] {
            assert!(
                matches!(
                    map_driver_error("exec", message),
                    ConnectorError::Dispatch(_)
                ),
                "unknown must be terminal, got {message:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_send_fails_closed_when_buffer_full() {
        let mut cfg = test_config();
        cfg.batch_size = Some(10);
        cfg.buffer_capacity = Some(2);
        let (sink, _) = test_sink(cfg);
        let topic = Topic::new("sensors/temp").unwrap();
        sink.send(
            &topic,
            &Bytes::from_static(br#"{"client_id":"s1","current":1.0,"voltage":2.0}"#),
            QoS::AtLeastOnce,
        )
        .await
        .expect("first row fits");
        sink.send(
            &topic,
            &Bytes::from_static(br#"{"client_id":"s2","current":1.0,"voltage":2.0}"#),
            QoS::AtLeastOnce,
        )
        .await
        .expect("second row fits");
        let err = sink
            .send(
                &topic,
                &Bytes::from_static(br#"{"client_id":"s3","current":1.0,"voltage":2.0}"#),
                QoS::AtLeastOnce,
            )
            .await
            .expect_err("full buffer must fail closed");
        assert!(
            matches!(err, ConnectorError::Connection(_)),
            "buffer-full must be a connection error, got {err:?}"
        );
        assert_eq!(sink.buffered_rows(), 2);
    }

    #[test]
    fn test_auth_headers() {
        assert_eq!(
            TdengineAuth::Basic {
                username: "root".to_string(),
                password: "taosdata".to_string()
            }
            .header_value()
            .unwrap(),
            "Basic cm9vdDp0YW9zZGF0YQ=="
        );
        assert_eq!(
            TdengineAuth::Token {
                token: "abc".to_string()
            }
            .header_value()
            .unwrap(),
            "Taosd abc"
        );
        assert!(TdengineAuth::Basic {
            username: String::new(),
            password: "x".to_string()
        }
        .header_value()
        .is_err());
    }

    #[tokio::test]
    async fn test_insert_rendering() {
        let (sink, transport) = test_sink(test_config());
        sink.send(
            &Topic::new("factory/line1").unwrap(),
            &Bytes::from_static(
                br#"{"client_id":"sensor101","location":"London","groupid":2,"current":10.5,"voltage":220.1}"#,
            ),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        sink.send(
            &Topic::new("factory/line2").unwrap(),
            &Bytes::from_static(
                br#"{"client_id":"sensor102","location":"Leeds","groupid":2,"current":9.5,"voltage":219.9}"#,
            ),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        sink.flush().await.unwrap();

        let captured = transport.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].database, "power");
        assert_eq!(captured[0].auth, "Basic cm9vdDp0YW9zZGF0YQ==");
        // One multi-table statement with sorted tag/metric columns;
        // timestamps normalize away (13-digit, unique in the text).
        let sql = &captured[0].sql;
        let ts0 = captured_timestamp(sql, 0);
        let ts1 = captured_timestamp(sql, 1);
        assert!(ts0 > 1_700_000_000_000 && ts1 > 1_700_000_000_000);
        let normalized = sql
            .replace(&ts0.to_string(), "<TS>")
            .replace(&ts1.to_string(), "<TS>");
        assert_eq!(
            normalized,
            "INSERT INTO d_sensor101 USING meters TAGS (2, 'London') VALUES (<TS>, 10.5, 220.1) \
             d_sensor102 USING meters TAGS (2, 'Leeds') VALUES (<TS>, 9.5, 219.9);"
        );
        assert_eq!(sink.sent_records(), 2);
    }

    fn captured_timestamp(sql: &str, which: usize) -> i64 {
        // Timestamps are the first value in each VALUES (...) group.
        sql.split("VALUES (")
            .skip(1)
            .nth(which)
            .and_then(|group| group.split(',').next())
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or(-1)
    }

    #[test]
    fn test_insert_url_trims_slashes() {
        let mut config = test_config();
        config.endpoint = "http://127.0.0.1:6041/rest/sql/".to_string();
        assert_eq!(config.insert_url(), "http://127.0.0.1:6041/rest/sql/power");
    }

    #[test]
    fn test_subtable_identifier_enforcement() {
        let mut config = test_config();
        config.subtable_template = "d_${topic}".to_string();
        // Slashes and spaces fail the identifier check loudly.
        assert!(config
            .resolve_subtable("a/b", b"{}", QoS::AtMostOnce, 0)
            .is_err());
        assert!(config
            .resolve_subtable("a b", b"{}", QoS::AtMostOnce, 0)
            .is_err());
        // Underscores, digits and dots-free names pass.
        assert_eq!(
            config
                .resolve_subtable("line_1", b"{}", QoS::AtMostOnce, 0)
                .unwrap(),
            "d_line_1"
        );
    }

    #[test]
    fn test_sql_literal_escaping() {
        assert_eq!(sql_literal("10.5"), "10.5");
        assert_eq!(sql_literal("2"), "2");
        assert_eq!(sql_literal("true"), "TRUE");
        assert_eq!(sql_literal("o'clock"), "'o''clock'");
        assert_eq!(sql_literal("NULL"), "NULL");
        let sql = render_insert(
            "meters",
            &[TdengineRow {
                subtable: "d1".to_string(),
                tags: vec!["'a''b'".to_string()],
                metrics: vec!["1".to_string()],
                timestamp_ms: 7,
            }],
        );
        assert_eq!(
            sql,
            "INSERT INTO d1 USING meters TAGS ('a''b') VALUES (7, 1);"
        );
    }

    #[test]
    fn test_response_parsing() {
        assert_eq!(
            parse_rest_response(br#"{"code":0,"rows":2}"#).unwrap(),
            TdengineResponse { code: 0, rows: 2 }
        );
        assert_eq!(
            parse_rest_response(br#"{"code":0}"#).unwrap(),
            TdengineResponse { code: 0, rows: 0 }
        );
        assert_eq!(
            parse_rest_response(br#"{"code":533,"desc":"syntax error"}"#)
                .unwrap()
                .code,
            533
        );
        assert!(parse_rest_response(b"nope").is_err());
        assert!(parse_rest_response(br#"{}"#).is_err());
    }

    #[tokio::test]
    async fn test_transient_retry_then_success() {
        let mut config = test_config();
        config.batch_size = Some(10);
        config.initial_backoff_ms = Some(1);
        config.max_backoff_ms = Some(2);
        let (sink, transport) = test_sink(config);
        transport.script_outcomes(vec![
            MockTdengineOutcome::ConnectionError("pool busy".to_string()),
            MockTdengineOutcome::Ok(2),
        ]);

        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from("{}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        sink.flush().await.unwrap();
        assert_eq!(transport.calls(), 2);
        assert_eq!(sink.sent_records(), 1);
        assert_eq!(sink.buffered_rows(), 0);
    }

    #[tokio::test]
    async fn test_terminal_error_aborts_without_retry() {
        let mut config = test_config();
        config.batch_size = Some(10);
        config.max_retries = Some(5);
        let (sink, transport) = test_sink(config);
        transport.script_outcomes(vec![
            MockTdengineOutcome::SqlError { code: 533 },
            MockTdengineOutcome::Ok(1),
        ]);

        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from("{}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        let err = sink.flush().await.expect_err("SQL error must fail");
        assert!(matches!(err, ConnectorError::Dispatch(_)));
        assert_eq!(transport.calls(), 1);
        assert_eq!(sink.buffered_rows(), 1);
    }
}
