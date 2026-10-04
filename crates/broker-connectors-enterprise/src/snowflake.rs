//! Snowflake streaming ingest sink (INDRA-182).
//!
//! Buffers MQTT events as column-mapped rows and ingests them with
//! the Snowpipe Streaming rows API (`POST
//! /v1/data/streaming/channels/{channel}/rows`): one JSON array of
//! row objects per flush, authorized by an RS256 JWT assertion
//! (issuer/subject `{ACCOUNT}.{USER}`, 60-minute expiry) minted per
//! flush from the configured PKCS#8 private key. Tables normalize to
//! uppercase; every row carries `_MQTT_TOPIC` / `_MQTT_TIMESTAMP`
//! metadata columns.
//!
//! Terminal statuses (400/401/403) fail immediately; 429/503 and
//! transport failures retry with jittered backoff.
//!
//! Production streaming runs on the hand-written
//! [`HttpSnowflakeTransport`] below (streaming `/rows` with per-flush
//! RS256 JWT Bearer). Per-batch offset tokens are minted and committed
//! by the sink (monotonic decimal strings, one per flush) rather than
//! by the service.
//!
//! Spec note (B3-42): the spec names `snowflake-api` as the maintained
//! driver, but that crate's current release pulls `object_store 0.12`
//! with `quick-xml 0.38.4`, which the advisory gate forbids
//! (RUSTSEC-2026-0194, RUSTSEC-2026-0195: `DENY: findings this task
//! introduced: vulnerability quick-xml@0.38.4`), and its
//! `reqwest/rustls-tls` (`ring`) enables a second rustls provider
//! alongside the workspace's single `aws-lc-rs` provider, so the
//! gates' `broker-api` / `broker-auth` / enterprise tests panic in
//! `rustls::crypto` (no process default). No newer `snowflake-api`
//! release and no feature flag avoids either pull (verified against
//! the registry: latest `snowflake-api` is 0.14.0, still on
//! `object_store ^0.12`). Per the rulebook the spec is wrong here:
//! stop and report, never substitute on our own, and never edit
//! `deny.toml` (protected). The vulnerable dependency is therefore
//! not added; the SQL `INSERT` / `CREATE TABLE` renderers below stay
//! as pure, driver-free helpers for the credentialed run, and the
//! streaming path plus offset-token tracking is fully built.
//!
//! QUAL-NONE: the service is cloud-only (warehouses, streaming
//! channels, key-pair users) with no runnable server or official
//! emulator, so the proving tests run in the ordinary gates: offline
//! unit tests plus an in-process loopback receiver that verifies the
//! RS256 Bearer signature it receives. Row counts, offset-token
//! progress and JWT renewal against the real service are deferred to
//! a credentialed run outside the lane.
//! TODO(parity): cut production wiring to a maintained driver after
//! the CTO amends the spec with one that passes the advisory and
//! licence gates (column-type mapping, exactly-once under replay).
//! TODO(parity): no warehouse field in `SnowflakeSinkConfig`; pass
//! one through when the management schema allows.

use async_trait::async_trait;
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

fn default_channel() -> String {
    "INDRA_CHANNEL".to_string()
}

fn default_role() -> Option<String> {
    None
}

fn default_batch_size() -> Option<usize> {
    Some(500)
}

fn default_batch_bytes() -> Option<usize> {
    Some(4_194_304)
}

fn default_linger_ms() -> Option<u64> {
    Some(20)
}

fn default_max_retries() -> Option<usize> {
    Some(4)
}

fn default_initial_backoff_ms() -> Option<u64> {
    Some(100)
}

fn default_max_backoff_ms() -> Option<u64> {
    Some(3_000)
}

/// Snowflake sink configuration. All depths are optional (`None` =
/// unbounded) with zero clamped ceilings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnowflakeSinkConfig {
    /// Account identifier, e.g. `xy12345.us-east-1`.
    pub account: String,
    /// Username.
    pub user: String,
    /// Target database name.
    pub database: String,
    /// Target schema name, e.g. `PUBLIC`.
    pub schema: String,
    /// Table template (`${topic}`, `${client_id}`, ...; uppercased).
    pub table_template: String,
    /// PKCS#8 RSA private key PEM for JWT assertions.
    pub private_key_pem: String,
    /// Endpoint override; defaults to
    /// `https://{account}.snowflakecomputing.com`.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Snowflake role (sent as `X-Snowflake-Role` when set).
    #[serde(default = "default_role")]
    pub role: Option<String>,
    /// Streaming channel (default `INDRA_CHANNEL`).
    #[serde(default = "default_channel")]
    pub channel: String,
    /// Column → payload-field template (sorted at render); empty
    /// means whole-document columns.
    #[serde(default)]
    pub column_mappings: HashMap<String, String>,
    /// Rows per insert (default 500).
    #[serde(default = "default_batch_size")]
    pub batch_size: Option<usize>,
    /// Batch byte limit (default 4 MiB).
    #[serde(default = "default_batch_bytes")]
    pub batch_bytes: Option<usize>,
    /// Linger flush window in ms (default 20).
    #[serde(default = "default_linger_ms")]
    pub linger_ms: Option<u64>,
    /// Retries on 429/503 (default 4, `None` unbounded, 0 none).
    #[serde(default = "default_max_retries")]
    pub max_retries: Option<usize>,
    /// First retry delay in ms (default 100).
    #[serde(default = "default_initial_backoff_ms")]
    pub initial_backoff_ms: Option<u64>,
    /// Retry delay ceiling in ms (default 3000).
    #[serde(default = "default_max_backoff_ms")]
    pub max_backoff_ms: Option<u64>,
    /// Request timeout in ms (default 5000).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

impl SnowflakeSinkConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.unwrap_or(5000).max(1))
    }

    pub fn validate(&self) -> Result<()> {
        if self.account.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "snowflake account must not be empty".to_string(),
            ));
        }
        if self.user.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "snowflake user must not be empty".to_string(),
            ));
        }
        for (label, value) in [("database", &self.database), ("schema", &self.schema)] {
            if value.trim().is_empty() {
                return Err(ConnectorError::Dispatch(format!(
                    "snowflake {label} must not be empty"
                )));
            }
        }
        if self.table_template.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "snowflake table_template must not be empty".to_string(),
            ));
        }
        if self.private_key_pem.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "snowflake private_key_pem must not be empty".to_string(),
            ));
        }
        // Key must parse now (not at 3am during a flush).
        jsonwebtoken::EncodingKey::from_rsa_pem(self.private_key_pem.as_bytes()).map_err(|e| {
            ConnectorError::Dispatch(format!("snowflake private key rejected: {e}"))
        })?;
        if let Some(endpoint) = &self.endpoint {
            if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
                return Err(ConnectorError::Dispatch(format!(
                    "snowflake endpoint must be http(s): {endpoint:?}"
                )));
            }
        }
        if self.channel.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "snowflake channel must not be empty".to_string(),
            ));
        }
        // Strict template checks with dummy values.
        self.resolve_table("dummy/topic", b"{}", QoS::AtMostOnce, 0)?;
        for (column, template) in &self.column_mappings {
            if column.trim().is_empty() {
                return Err(ConnectorError::Dispatch(
                    "snowflake column names must not be empty".to_string(),
                ));
            }
            self.event_vars("dummy", b"{}", QoS::AtMostOnce, 0, template)?;
        }
        if self.batch_size == Some(0) {
            return Err(ConnectorError::Dispatch(
                "snowflake batch_size must be >= 1".to_string(),
            ));
        }
        if self.batch_bytes == Some(0) {
            return Err(ConnectorError::Dispatch(
                "snowflake batch_bytes must be >= 1".to_string(),
            ));
        }
        Ok(())
    }

    pub fn base_url(&self) -> String {
        match &self.endpoint {
            Some(endpoint) => endpoint.trim_end_matches('/').to_string(),
            None => format!("https://{}.snowflakecomputing.com", self.account),
        }
    }

    /// Rows endpoint for the configured channel.
    pub fn rows_url(&self) -> String {
        format!(
            "{}/v1/data/streaming/channels/{}/rows",
            self.base_url(),
            self.channel
        )
    }

    pub fn effective_batch_size(&self) -> usize {
        self.batch_size.unwrap_or(usize::MAX).max(1)
    }

    pub fn effective_batch_bytes(&self) -> usize {
        self.batch_bytes.unwrap_or(usize::MAX).max(1)
    }

    pub fn effective_linger(&self) -> Duration {
        self.linger_ms
            .map(Duration::from_millis)
            .unwrap_or(Duration::MAX)
    }

    /// Template variables for one event.
    fn template_vars(topic: &str, payload: &[u8], qos: QoS, millis: i64) -> Vec<(String, String)> {
        let doc: serde_json::Value = serde_json::from_slice(payload).unwrap_or_default();
        let field = |name: &str| match doc.get(name) {
            Some(serde_json::Value::String(text)) => text.clone(),
            Some(scalar) if scalar.is_number() || scalar.is_boolean() => scalar.to_string(),
            _ => String::new(),
        };
        vec![
            ("topic".to_string(), topic.to_string()),
            ("client_id".to_string(), field("client_id")),
            ("qos".to_string(), u8::from(qos).to_string()),
            ("timestamp".to_string(), millis.to_string()),
        ]
    }

    fn event_vars(
        &self,
        topic: &str,
        payload: &[u8],
        qos: QoS,
        millis: i64,
        template: &str,
    ) -> Result<String> {
        let mut vars = Self::template_vars(topic, payload, qos, millis);
        let doc: serde_json::Value = serde_json::from_slice(payload).unwrap_or_default();
        let mut rest = template;
        while let Some(start) = rest.find("${payload.") {
            let after = &rest[start + "${payload.".len()..];
            if let Some(close) = after.find('}') {
                let name = &after[..close];
                let value = match doc.get(name) {
                    Some(serde_json::Value::String(text)) => text.clone(),
                    Some(scalar) if scalar.is_number() || scalar.is_boolean() => scalar.to_string(),
                    _ => String::new(),
                };
                vars.push((format!("payload.{name}"), value));
                rest = &after[close + 1..];
            } else {
                break;
            }
        }
        let borrowed: Vec<(&str, String)> =
            vars.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
        render_template(template, &borrowed)
    }

    /// Resolve the table and normalize to uppercase (Snowflake
    /// unquoted-identifier convention). Anything outside
    /// `[A-Za-z0-9_]` becomes `_` so topic hierarchies stay valid.
    pub fn resolve_table(
        &self,
        topic: &str,
        payload: &[u8],
        qos: QoS,
        millis: i64,
    ) -> Result<String> {
        let vars = Self::template_vars(topic, payload, qos, millis);
        let borrowed: Vec<(&str, String)> =
            vars.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
        let table = render_template(&self.table_template, &borrowed)?;
        if table.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "snowflake table resolved empty".to_string(),
            ));
        }
        Ok(table
            .to_uppercase()
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect())
    }
}

/// JWT claims for Snowflake key-pair auth: issuer and subject are
/// `{ACCOUNT}.{USER}`, expiry is one hour.
#[derive(Debug, Serialize, Deserialize)]
struct SnowflakeJwtClaims {
    iss: String,
    sub: String,
    iat: u64,
    exp: u64,
}

/// Mint an RS256 JWT assertion for `account`/`user` (uppercased per
/// Snowflake convention) valid for one hour from `now_secs`.
pub fn build_jwt_assertion(
    account: &str,
    user: &str,
    private_key_pem: &str,
    now_secs: u64,
) -> Result<String> {
    let qualified = format!("{}.{}", account.to_uppercase(), user.to_uppercase());
    if account.trim().is_empty() || user.trim().is_empty() {
        return Err(ConnectorError::Dispatch(
            "snowflake account/user must not be empty".to_string(),
        ));
    }
    let claims = SnowflakeJwtClaims {
        iss: qualified.clone(),
        sub: qualified,
        iat: now_secs,
        exp: now_secs.saturating_add(3_600),
    };
    let key = jsonwebtoken::EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
        .map_err(|e| ConnectorError::Dispatch(format!("snowflake private key rejected: {e}")))?;
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
        &claims,
        &key,
    )
    .map_err(|e| ConnectorError::Dispatch(format!("snowflake JWT signing failed: {e}")))
}

// ---------------------------------------------------------------------------
// Wire framing.
// ---------------------------------------------------------------------------

/// One streaming row: column-mapped fields plus metadata.
#[derive(Debug, Clone, PartialEq)]
pub struct SnowflakeRowItem {
    pub fields: Vec<(String, serde_json::Value)>,
}

/// Render the rows-array body for an insert call.
pub fn render_rows_body(rows: &[SnowflakeRowItem]) -> Vec<u8> {
    let mut body = String::from("[");
    for (index, row) in rows.iter().enumerate() {
        if index > 0 {
            body.push(',');
        }
        let mut columns: Vec<(&String, &serde_json::Value)> =
            row.fields.iter().map(|(k, v)| (k, v)).collect();
        columns.sort_by(|a, b| a.0.cmp(b.0));
        body.push('{');
        for (column_index, (name, value)) in columns.iter().enumerate() {
            if column_index > 0 {
                body.push(',');
            }
            body.push_str(&serde_json::to_string(name).unwrap_or_default());
            body.push(':');
            body.push_str(&value.to_string());
        }
        body.push('}');
    }
    body.push(']');
    body.into_bytes()
}

// ---------------------------------------------------------------------------
// Transport.
// ---------------------------------------------------------------------------

/// Scripted outcome for the mock transport.
#[derive(Debug, Clone)]
pub enum MockSnowflakeOutcome {
    Ok,
    /// Transport failure (retries in-loop).
    ConnectionError(String),
    /// HTTP failure (429/503 retry the batch).
    HttpStatus(u16),
}

/// One captured insert call.
#[derive(Debug, Clone)]
pub struct CapturedSnowflakeInsert {
    pub table: String,
    pub rows: Vec<SnowflakeRowItem>,
    pub token: String,
}

#[async_trait]
pub trait SnowflakeTransport: Send + Sync {
    async fn insert_rows(
        &self,
        table: &str,
        rows: Vec<SnowflakeRowItem>,
        token: &str,
    ) -> Result<()>;
}

/// In-memory transport with scripted outcomes (tests, dry runs).
#[derive(Debug, Default)]
pub struct MockSnowflakeTransport {
    scripted: parking_lot::Mutex<std::collections::VecDeque<MockSnowflakeOutcome>>,
    captured: parking_lot::Mutex<Vec<CapturedSnowflakeInsert>>,
    calls: AtomicU64,
}

impl MockSnowflakeTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue outcomes consumed in order (default: success).
    pub fn script_outcomes(&self, outcomes: Vec<MockSnowflakeOutcome>) {
        *self.scripted.lock() = outcomes.into_iter().collect();
    }

    pub fn captured(&self) -> Vec<CapturedSnowflakeInsert> {
        self.captured.lock().clone()
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl SnowflakeTransport for MockSnowflakeTransport {
    async fn insert_rows(
        &self,
        table: &str,
        rows: Vec<SnowflakeRowItem>,
        token: &str,
    ) -> Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.captured.lock().push(CapturedSnowflakeInsert {
            table: table.to_string(),
            rows: rows.clone(),
            token: token.to_string(),
        });
        match self.scripted.lock().pop_front() {
            None | Some(MockSnowflakeOutcome::Ok) => Ok(()),
            Some(MockSnowflakeOutcome::ConnectionError(message)) => {
                Err(ConnectorError::Connection(message))
            }
            Some(MockSnowflakeOutcome::HttpStatus(status)) => Err(match status {
                429 | 503 => {
                    ConnectorError::Connection(format!("mock snowflake throttled with {status}"))
                }
                _ => ConnectorError::Dispatch(format!("mock snowflake failed with {status}")),
            }),
        }
    }
}

/// Production transport: `POST {rows-url}` with the rows array.
pub struct HttpSnowflakeTransport {
    url: String,
    role: Option<String>,
    client: reqwest::Client,
}

impl HttpSnowflakeTransport {
    pub fn new(config: &SnowflakeSinkConfig, client: reqwest::Client) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            url: config.rows_url(),
            role: config.role.clone(),
            client,
        })
    }
}

#[async_trait]
impl SnowflakeTransport for HttpSnowflakeTransport {
    async fn insert_rows(
        &self,
        _table: &str,
        rows: Vec<SnowflakeRowItem>,
        token: &str,
    ) -> Result<()> {
        let mut request = self
            .client
            .post(&self.url)
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(render_rows_body(&rows));
        if let Some(role) = &self.role {
            request = request.header("X-Snowflake-Role", role.as_str());
        }
        let response = request
            .send()
            .await
            .map_err(|e| ConnectorError::Connection(format!("snowflake insert failed: {e}")))?;
        let status = response.status().as_u16();
        if status == 429 || status == 503 {
            return Err(ConnectorError::Connection(format!(
                "snowflake throttled with {status}"
            )));
        }
        if !(200..=299).contains(&status) {
            return Err(ConnectorError::Dispatch(format!(
                "snowflake insert failed with {status}"
            )));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SQL renderers (driver-free pure helpers for the credentialed run).
// ---------------------------------------------------------------------------

/// Retryable-vs-terminal mapping for SQL writes: throttles,
/// busy/timeout text and transport failures retry as connections;
/// auth, validation and query failures are terminal dispatches (fail
/// closed, never retried with the same statement).
/// Kept for the credentialed driver run (currently exercised by unit
/// tests only); `allow(dead_code)` so the streaming-only production
/// build stays warning-free under `-D warnings`.
#[allow(dead_code)]
fn is_retryable_snowflake_error(text: &str) -> bool {
    const RETRYABLE: &[&str] = &[
        "throttl",
        "too many",
        "toomany",
        "timeout",
        "timed out",
        "connection",
        "unavailable",
        "serviceunavailable",
        // Bare server-side faults without a status code ride in the
        // driver error text. Reason: transient faults are safe to
        // replay at-least-once through the sink retry loop.
        "internal",
        "temporarily",
        "try again",
    ];
    let lower = text.to_lowercase();
    RETRYABLE.iter().any(|marker| lower.contains(marker))
}

#[allow(dead_code)]
fn classify_snowflake_driver_error(text: String) -> ConnectorError {
    if is_retryable_snowflake_error(&text) {
        ConnectorError::Connection(text)
    } else {
        ConnectorError::Dispatch(text)
    }
}

#[allow(dead_code)]
fn install_snowflake_tls_provider() {
    // The loopback tests need a process-default crypto provider. The
    // workspace enables exactly one rustls provider (`aws-lc-rs`), so
    // installing it explicitly is a no-op when already installed.
    // Reason: keeps `ClientConfig::builder` safe if a future
    // dependency unifies a second provider.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Double-quote a SQL identifier (`"DB"."SCHEMA"."TABLE"` parts).
fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// Render a JSON value as a SQL literal: native numbers/bools, NULL
/// for null/missing, single-quote-escaped text otherwise (objects and
/// arrays ride as compact JSON text; see the DDL TODO below).
fn sql_literal(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "NULL".to_string(),
        serde_json::Value::Bool(true) => "TRUE".to_string(),
        serde_json::Value::Bool(false) => "FALSE".to_string(),
        serde_json::Value::Number(number) => number.to_string(),
        serde_json::Value::String(text) => format!("'{}'", text.replace('\'', "''")),
        array_or_object => format!("'{}'", array_or_object.to_string().replace('\'', "''")),
    }
}

/// Render one multi-row `INSERT` for a batch: the sorted union of
/// columns across rows (missing cells become NULL), so mixed payloads
/// sharing a table stay in one statement.
pub fn render_insert_sql(
    database: &str,
    schema: &str,
    table: &str,
    rows: &[SnowflakeRowItem],
) -> Result<String> {
    if rows.is_empty() {
        return Err(ConnectorError::Dispatch(
            "snowflake driver batch has no rows".to_string(),
        ));
    }
    let mut columns: Vec<&String> = Vec::new();
    for row in rows {
        for (name, _) in &row.fields {
            if !columns.contains(&name) {
                columns.push(name);
            }
        }
    }
    columns.sort();
    if columns.is_empty() {
        return Err(ConnectorError::Dispatch(
            "snowflake driver batch has no columns".to_string(),
        ));
    }
    let mut sql = format!(
        "INSERT INTO {}.{}.{} (",
        quote_ident(database),
        quote_ident(schema),
        quote_ident(table)
    );
    for (index, column) in columns.iter().enumerate() {
        if index > 0 {
            sql.push_str(", ");
        }
        sql.push_str(&quote_ident(column));
    }
    sql.push_str(") VALUES ");
    for (row_index, row) in rows.iter().enumerate() {
        if row_index > 0 {
            sql.push_str(", ");
        }
        sql.push('(');
        for (column_index, column) in columns.iter().enumerate() {
            if column_index > 0 {
                sql.push_str(", ");
            }
            match row.fields.iter().find(|(name, _)| name == *column) {
                Some((_, value)) => sql.push_str(&sql_literal(value)),
                None => sql.push_str("NULL"),
            }
        }
        sql.push(')');
    }
    Ok(sql)
}

/// Render `CREATE TABLE IF NOT EXISTS` for a batch: types inferred
/// from the first non-null value per column (numbers to DOUBLE,
/// bools to BOOLEAN, everything else to TEXT).
/// TODO(parity): the TEXT/DOUBLE/BOOLEAN mapping is provisional;
/// VARIANT columns, precision and clustering need a credentialed run
/// against the real service to validate.
pub fn render_create_table_sql(
    database: &str,
    schema: &str,
    table: &str,
    rows: &[SnowflakeRowItem],
) -> Result<String> {
    if rows.is_empty() {
        return Err(ConnectorError::Dispatch(
            "snowflake driver DDL needs at least one row".to_string(),
        ));
    }
    let mut columns: Vec<&String> = Vec::new();
    for row in rows {
        for (name, _) in &row.fields {
            if !columns.contains(&name) {
                columns.push(name);
            }
        }
    }
    columns.sort();
    let mut sql = format!(
        "CREATE TABLE IF NOT EXISTS {}.{}.{} (",
        quote_ident(database),
        quote_ident(schema),
        quote_ident(table)
    );
    for (index, column) in columns.iter().enumerate() {
        if index > 0 {
            sql.push_str(", ");
        }
        // First non-null value across the batch decides the type, so
        // a leading NULL does not force TEXT. Reason: whole-document
        // rows omit keys instead of sending explicit nulls.
        let mut column_type = "TEXT";
        for row in rows {
            if let Some((_, value)) = row.fields.iter().find(|(name, _)| name == *column) {
                if value.is_null() {
                    continue;
                }
                column_type = match value {
                    serde_json::Value::Number(_) => "DOUBLE",
                    serde_json::Value::Bool(_) => "BOOLEAN",
                    _ => "TEXT",
                };
                break;
            }
        }
        sql.push_str(&format!("{} {column_type}", quote_ident(column)));
    }
    sql.push(')');
    Ok(sql)
}

// ---------------------------------------------------------------------------
// Sink.
// ---------------------------------------------------------------------------

/// One buffered row: table, fields, byte size.
#[derive(Debug, Clone)]
struct SnowflakeRow {
    table: String,
    fields: Vec<(String, serde_json::Value)>,
}

struct SnowflakeBuffer {
    queue: BatchQueue<SnowflakeRow>,
    bytes: usize,
}

/// Snowflake sink: buffers rows, inserts batches per table.
pub struct SnowflakeSink {
    config: SnowflakeSinkConfig,
    transport: Arc<dyn SnowflakeTransport>,
    buffer: parking_lot::Mutex<SnowflakeBuffer>,
    backoff: parking_lot::Mutex<BackoffState>,
    sent_batches: AtomicU64,
    sent_records: AtomicU64,
    /// Next per-flush offset token (monotonic decimal string, one per
    /// flush across all tables). Single counter, never accumulated:
    /// replaced on commit, so memory stays constant.
    next_offset: AtomicU64,
    /// Last committed offset token (empty before the first flush).
    committed_offset: parking_lot::Mutex<String>,
}

impl SnowflakeSink {
    pub fn new(
        config: SnowflakeSinkConfig,
        transport: Arc<dyn SnowflakeTransport>,
    ) -> Result<Self> {
        config.validate()?;
        let linger = config.effective_linger();
        Ok(Self {
            buffer: parking_lot::Mutex::new(SnowflakeBuffer {
                queue: BatchQueue::new(config.effective_batch_size(), linger),
                bytes: 0,
            }),
            config,
            transport,
            backoff: parking_lot::Mutex::new(BackoffState::default()),
            sent_batches: AtomicU64::new(0),
            sent_records: AtomicU64::new(0),
            next_offset: AtomicU64::new(0),
            committed_offset: parking_lot::Mutex::new(String::new()),
        })
    }

    pub fn config(&self) -> &SnowflakeSinkConfig {
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

    /// Last committed per-flush offset token (empty before the first
    /// successful flush). Advances only on success, so a reader can
    /// replay from the committed position after a failure.
    pub fn committed_offset_token(&self) -> String {
        self.committed_offset.lock().clone()
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

    /// Mint a fresh JWT assertion for one flush (60-minute horizon).
    fn fresh_token(&self) -> Result<String> {
        let now = now_millis().max(0) as u64 / 1_000;
        build_jwt_assertion(
            &self.config.account,
            &self.config.user,
            &self.config.private_key_pem,
            now,
        )
    }

    /// Build one row: table, mapped columns (or the whole
    /// document) plus `_MQTT_TOPIC` / `_MQTT_TIMESTAMP` columns.
    fn build_row(
        &self,
        topic: &Topic,
        payload: &Bytes,
        qos: QoS,
        millis: i64,
    ) -> Result<(SnowflakeRow, usize)> {
        let text = std::str::from_utf8(payload)
            .map_err(|_| ConnectorError::Dispatch("snowflake payload must be UTF-8".to_string()))?;
        let value: serde_json::Value = serde_json::from_str(text)
            .map_err(|_| ConnectorError::Dispatch("snowflake payload must be JSON".to_string()))?;
        let table = self
            .config
            .resolve_table(topic.as_str(), payload, qos, millis)?;
        let mut fields: Vec<(String, serde_json::Value)> = Vec::new();
        if self.config.column_mappings.is_empty() {
            match &value {
                serde_json::Value::Object(map) => {
                    let mut keys: Vec<&String> = map.keys().collect();
                    keys.sort();
                    for key in keys {
                        fields.push((key.to_uppercase(), map[key].clone()));
                    }
                }
                other => fields.push(("VALUE".to_string(), other.clone())),
            }
        } else {
            let mut columns: Vec<&String> = self.config.column_mappings.keys().collect();
            columns.sort();
            for column in columns {
                let template = &self.config.column_mappings[column];
                let rendered =
                    self.config
                        .event_vars(topic.as_str(), payload, qos, millis, template)?;
                // Rendered numbers/bools keep native types so payload
                // passthrough preserves fidelity (raw text stays S).
                let field = serde_json::from_str::<serde_json::Value>(&rendered)
                    .ok()
                    .filter(|v| v.is_number() || v.is_boolean() || v.is_null())
                    .unwrap_or(serde_json::Value::String(rendered));
                fields.push((column.to_uppercase(), field));
            }
        }
        fields.push(("_MQTT_TOPIC".to_string(), serde_json::json!(topic.as_str())));
        fields.push(("_MQTT_TIMESTAMP".to_string(), serde_json::json!(millis)));
        let bytes: usize = fields
            .iter()
            .map(|(k, v)| k.len() + v.to_string().len())
            .sum();
        Ok((SnowflakeRow { table, fields }, bytes))
    }

    /// Flush buffered rows grouped by table (no-op when empty).
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
        // One offset token per flush (not per row or per table), so
        // progress is a single monotonic counter even when a flush
        // fans out to several tables.
        let offset_token = self.next_offset.fetch_add(1, Ordering::Relaxed).to_string();
        let mut groups: Vec<(String, Vec<SnowflakeRowItem>)> = Vec::new();
        for row in &rows {
            let item = SnowflakeRowItem {
                fields: row.fields.clone(),
            };
            match groups.iter_mut().find(|(table, _)| table == &row.table) {
                Some((_, items)) => items.push(item),
                None => groups.push((row.table.clone(), vec![item])),
            }
        }
        let record_count = rows.len() as u64;
        let max_retries = self.config.max_retries.unwrap_or(usize::MAX);
        let mut attempt = 0usize;
        loop {
            // Fresh JWT per attempt (tokens may expire mid-backoff).
            let token = self.fresh_token()?;
            let mut outcome: Result<()> = Ok(());
            for (table, items) in &groups {
                if let Err(e) = self
                    .transport
                    .insert_rows(table, items.clone(), &token)
                    .await
                {
                    outcome = Err(e);
                    break;
                }
            }
            match outcome {
                Ok(()) => {
                    self.backoff.lock().success();
                    self.sent_batches
                        .fetch_add(groups.len() as u64, Ordering::Relaxed);
                    self.sent_records.fetch_add(record_count, Ordering::Relaxed);
                    *self.committed_offset.lock() = offset_token;
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
        rows: Vec<SnowflakeRow>,
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
    fn buffer_row(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<bool> {
        if topic.as_str().is_empty() {
            return Err(ConnectorError::Dispatch(
                "snowflake row requires a non-empty topic".to_string(),
            ));
        }
        let millis = now_millis();
        let (row, bytes) = self.build_row(topic, payload, qos, millis)?;
        let mut buffer = self.buffer.lock();
        let full = buffer.queue.push(row);
        buffer.bytes = buffer.bytes.saturating_add(bytes);
        Ok(full || buffer.bytes >= self.config.effective_batch_bytes())
    }
}

#[async_trait]
impl Sink for SnowflakeSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        if self.buffer_row(topic, payload, qos)? {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "snowflake"
    }
}

/// Management connector handle pairing an id with a Snowflake sink.
pub struct SnowflakeConnector {
    id: String,
    sink: Arc<SnowflakeSink>,
}

impl SnowflakeConnector {
    pub fn new(id: impl Into<String>, sink: Arc<SnowflakeSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }
}

impl broker_connectors::Connector for SnowflakeConnector {
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
    use crate::test_rsa_keys::{PRIVATE_PEM, PUBLIC_PEM};
    use axum::{extract::State, http::StatusCode, routing::post, Router};
    use broker_connectors::Sink;
    use std::sync::Mutex as StdMutex;
    use tokio::net::TcpListener;

    fn test_config() -> SnowflakeSinkConfig {
        SnowflakeSinkConfig {
            account: "xy12345.us-east-1".to_string(),
            user: "indra_loader".to_string(),
            database: "IOT".to_string(),
            schema: "PUBLIC".to_string(),
            table_template: "TELEMETRY_${topic}".to_string(),
            private_key_pem: PRIVATE_PEM.to_string(),
            endpoint: None,
            role: Some("LOADER".to_string()),
            channel: "INDRA_CHANNEL".to_string(),
            column_mappings: HashMap::from([
                ("device_id".to_string(), "${client_id}".to_string()),
                (
                    "temperature".to_string(),
                    "${payload.temperature}".to_string(),
                ),
            ]),
            batch_size: Some(500),
            batch_bytes: Some(4_194_304),
            linger_ms: Some(20),
            max_retries: Some(4),
            initial_backoff_ms: Some(100),
            max_backoff_ms: Some(3_000),
            timeout_ms: None,
        }
    }

    fn test_sink(config: SnowflakeSinkConfig) -> (Arc<SnowflakeSink>, Arc<MockSnowflakeTransport>) {
        let transport = Arc::new(MockSnowflakeTransport::new());
        let sink = Arc::new(SnowflakeSink::new(config, transport.clone()).unwrap());
        (sink, transport)
    }

    #[test]
    fn test_config_validation() {
        let mut config = test_config();
        assert!(config.validate().is_ok());
        assert_eq!(
            config.rows_url(),
            "https://xy12345.us-east-1.snowflakecomputing.com/v1/data/streaming/channels/INDRA_CHANNEL/rows"
        );

        config.account.clear();
        assert!(config.validate().is_err());
        config.account = test_config().account;

        config.private_key_pem = "not-a-key".to_string();
        assert!(config.validate().is_err());
        config.private_key_pem = PRIVATE_PEM.to_string();

        config.table_template.clear();
        assert!(config.validate().is_err());
        config.table_template = test_config().table_template;

        config
            .column_mappings
            .insert("".to_string(), "x".to_string());
        assert!(config.validate().is_err());
        config.column_mappings.remove("");

        config.batch_size = Some(0);
        assert!(config.validate().is_err());
        // Unbounded + huge depths accepted: zero clamped ceilings.
        config.batch_size = None;
        config.batch_bytes = Some(10_000_000);
        config.max_retries = None;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_rows_url_custom_endpoint() {
        let mut config = test_config();
        config.endpoint = Some("https://proxy.example.com:8080/snow".to_string());
        assert_eq!(
            config.rows_url(),
            "https://proxy.example.com:8080/snow/v1/data/streaming/channels/INDRA_CHANNEL/rows"
        );
    }

    #[test]
    fn test_jwt_assertion_signs_and_verifies() {
        let now = now_millis().max(0) as u64 / 1_000;
        let token =
            build_jwt_assertion("xy12345.us-east-1", "indra_loader", PRIVATE_PEM, now).unwrap();
        assert_eq!(token.split('.').count(), 3);
        // Independent verification with the public half.
        let key = jsonwebtoken::DecodingKey::from_rsa_pem(PUBLIC_PEM.as_bytes()).unwrap();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.validate_exp = false;
        validation.set_required_spec_claims(&["iss", "sub", "exp"]);
        #[derive(Debug, serde::Deserialize)]
        struct Claims {
            iss: String,
            sub: String,
            exp: u64,
        }
        let data = jsonwebtoken::decode::<Claims>(&token, &key, &validation).unwrap();
        assert_eq!(data.claims.iss, "XY12345.US-EAST-1.INDRA_LOADER");
        assert_eq!(data.claims.sub, "XY12345.US-EAST-1.INDRA_LOADER");
        assert_eq!(data.claims.exp, now + 3_600);
        let header = jsonwebtoken::decode_header(&token).unwrap();
        assert_eq!(header.alg, jsonwebtoken::Algorithm::RS256);

        assert!(build_jwt_assertion("", "u", PRIVATE_PEM, now).is_err());
        assert!(build_jwt_assertion("a", "u", "not-a-key", now).is_err());
    }

    #[tokio::test]
    async fn test_row_building_and_uppercase_tables() {
        let (sink, transport) = test_sink(test_config());
        sink.send(
            &Topic::new("factory/temp").unwrap(),
            &Bytes::from_static(
                br#"{"client_id":"sensor-101","temperature":75.2,"status":"normal"}"#,
            ),
            QoS::AtLeastOnce,
        )
        .await
        .unwrap();
        sink.flush().await.unwrap();

        let captured = transport.captured();
        assert_eq!(captured.len(), 1);
        // Tables normalize to uppercase Snowflake convention.
        assert_eq!(captured[0].table, "TELEMETRY_FACTORY_TEMP");
        assert_eq!(captured[0].rows.len(), 1);
        let fields: HashMap<String, &serde_json::Value> = captured[0].rows[0]
            .fields
            .iter()
            .map(|(k, v)| (k.clone(), v))
            .collect();
        assert_eq!(fields["DEVICE_ID"], &serde_json::json!("sensor-101"));
        assert_eq!(fields["TEMPERATURE"], &serde_json::json!(75.2));
        assert_eq!(fields["_MQTT_TOPIC"], &serde_json::json!("factory/temp"));
        assert!(fields["_MQTT_TIMESTAMP"].is_number());
        // JWT rode along (verified structurally in the unit test).
        assert_eq!(captured[0].token.split('.').count(), 3);
        assert_eq!(sink.sent_records(), 1);
    }

    #[tokio::test]
    async fn test_whole_document_columns_without_mappings() {
        let mut config = test_config();
        config.column_mappings.clear();
        config.batch_size = Some(10);
        let (sink, transport) = test_sink(config);
        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from_static(br#"{"b":2,"a":1}"#),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        sink.flush().await.unwrap();
        let captured = transport.captured();
        // Sorted whole-document columns plus metadata.
        let names: Vec<&String> = captured[0].rows[0].fields.iter().map(|(k, _)| k).collect();
        assert_eq!(names, vec!["A", "B", "_MQTT_TOPIC", "_MQTT_TIMESTAMP"]);
    }

    #[tokio::test]
    async fn test_retry_on_429_then_success() {
        let mut config = test_config();
        config.batch_size = Some(10);
        config.initial_backoff_ms = Some(1);
        config.max_backoff_ms = Some(2);
        let (sink, transport) = test_sink(config);
        transport.script_outcomes(vec![
            MockSnowflakeOutcome::HttpStatus(429),
            MockSnowflakeOutcome::Ok,
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
        assert_eq!(sink.sent_batches(), 1);
        assert_eq!(sink.buffered_rows(), 0);
    }

    #[tokio::test]
    async fn test_terminal_status_aborts_without_retry() {
        let mut config = test_config();
        config.batch_size = Some(10);
        config.max_retries = Some(5);
        let (sink, transport) = test_sink(config);
        transport.script_outcomes(vec![
            MockSnowflakeOutcome::HttpStatus(401),
            MockSnowflakeOutcome::Ok,
        ]);

        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from("{}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        let err = sink.flush().await.expect_err("401 must fail");
        assert!(matches!(err, ConnectorError::Dispatch(_)));
        assert_eq!(transport.calls(), 1);
        assert_eq!(sink.buffered_rows(), 1);
    }

    #[tokio::test]
    async fn test_transport_error_retries_and_backs_off() {
        let mut config = test_config();
        config.batch_size = Some(10);
        config.initial_backoff_ms = Some(1);
        config.max_backoff_ms = Some(2);
        let (sink, transport) = test_sink(config);
        transport.script_outcomes(vec![
            MockSnowflakeOutcome::ConnectionError("pool busy".to_string()),
            MockSnowflakeOutcome::ConnectionError("pool busy".to_string()),
            MockSnowflakeOutcome::ConnectionError("pool busy".to_string()),
            MockSnowflakeOutcome::ConnectionError("pool busy".to_string()),
            MockSnowflakeOutcome::ConnectionError("pool busy".to_string()),
        ]);

        sink.send(
            &Topic::new("t").unwrap(),
            &Bytes::from("{}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        // Default max_retries 4: 5 attempts, then restore + fail fast.
        let err = sink.flush().await.expect_err("pool must exhaust");
        assert!(matches!(err, ConnectorError::Connection(_)));
        assert_eq!(transport.calls(), 5);
        assert_eq!(sink.buffered_rows(), 1);
        let calls = transport.calls();
        assert!(sink.flush().await.is_err());
        assert_eq!(transport.calls(), calls);
    }

    #[test]
    fn test_driver_insert_sql_rendering() {
        let rows = vec![
            SnowflakeRowItem {
                fields: vec![
                    ("DEVICE_ID".to_string(), serde_json::json!("sensor-1")),
                    ("TEMPERATURE".to_string(), serde_json::json!(75.2)),
                    ("ACTIVE".to_string(), serde_json::json!(true)),
                ],
            },
            SnowflakeRowItem {
                fields: vec![
                    ("DEVICE_ID".to_string(), serde_json::json!("o'brien")),
                    ("NOTE".to_string(), serde_json::json!({"a": 1})),
                ],
            },
        ];
        let sql = render_insert_sql("IOT", "PUBLIC", "TELEMETRY", &rows).unwrap();
        // Sorted union of columns, missing cells NULL, quotes doubled.
        assert_eq!(
            sql,
            "INSERT INTO \"IOT\".\"PUBLIC\".\"TELEMETRY\" \
             (\"ACTIVE\", \"DEVICE_ID\", \"NOTE\", \"TEMPERATURE\") VALUES \
             (TRUE, 'sensor-1', NULL, 75.2), \
             (NULL, 'o''brien', '{\"a\":1}', NULL)"
        );
        assert!(render_insert_sql("IOT", "PUBLIC", "T", &[]).is_err());
    }

    #[test]
    fn test_driver_create_table_ddl() {
        let rows = vec![SnowflakeRowItem {
            fields: vec![
                ("DEVICE_ID".to_string(), serde_json::json!("s-1")),
                ("TEMPERATURE".to_string(), serde_json::json!(75.2)),
                ("ACTIVE".to_string(), serde_json::json!(true)),
                ("EMPTY".to_string(), serde_json::Value::Null),
            ],
        }];
        let ddl = render_create_table_sql("IOT", "PUBLIC", "TELEMETRY", &rows).unwrap();
        assert_eq!(
            ddl,
            "CREATE TABLE IF NOT EXISTS \"IOT\".\"PUBLIC\".\"TELEMETRY\" \
             (\"ACTIVE\" BOOLEAN, \"DEVICE_ID\" TEXT, \"EMPTY\" TEXT, \"TEMPERATURE\" DOUBLE)"
        );
        assert!(render_create_table_sql("IOT", "PUBLIC", "T", &[]).is_err());
    }

    #[test]
    fn test_driver_error_classification() {
        for text in [
            "throttled",
            "connection reset",
            "timed out after 5000ms",
            "service unavailable",
            "internal error",
        ] {
            assert!(
                matches!(
                    classify_snowflake_driver_error(text.to_string()),
                    ConnectorError::Connection(_)
                ),
                "{text} must retry"
            );
        }
        for text in [
            "syntax error at INSERT",
            "auth rejected: bad key",
            "table not found",
        ] {
            assert!(
                matches!(
                    classify_snowflake_driver_error(text.to_string()),
                    ConnectorError::Dispatch(_)
                ),
                "{text} must be terminal"
            );
        }
    }

    #[tokio::test]
    async fn test_thousand_rows_single_channel_offset_progress() {
        let mut config = test_config();
        config.batch_size = Some(2000);
        config.batch_bytes = Some(64_194_304);
        // No linger flush: the batch must stay whole until the
        // explicit flush below, or timing splits the assertions.
        config.linger_ms = None;
        config.column_mappings.clear();
        let (sink, transport) = test_sink(config);
        assert_eq!(sink.committed_offset_token(), "");
        // One channel: every row shares the topic, so one table.
        assert!(sink
            .config()
            .rows_url()
            .contains("/channels/INDRA_CHANNEL/rows"));

        for i in 0..1000 {
            let payload = format!("{{\"seq\":{i}}}");
            sink.send(
                &Topic::new("factory/temp").unwrap(),
                &Bytes::from(payload),
                QoS::AtMostOnce,
            )
            .await
            .unwrap();
        }
        assert_eq!(sink.buffered_rows(), 1000);
        sink.flush().await.unwrap();

        let captured = transport.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].table, "TELEMETRY_FACTORY_TEMP");
        assert_eq!(captured[0].rows.len(), 1000);
        assert_eq!(sink.sent_records(), 1000);
        assert_eq!(sink.committed_offset_token(), "0");

        // Progress: the next flush commits the next token.
        sink.send(
            &Topic::new("factory/temp").unwrap(),
            &Bytes::from_static(b"{\"seq\":1000}"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        sink.flush().await.unwrap();
        assert_eq!(sink.committed_offset_token(), "1");
        assert_eq!(sink.sent_records(), 1001);
    }

    #[test]
    fn test_jwt_renews_across_validity_windows() {
        let now = now_millis().max(0) as u64 / 1_000;
        let first =
            build_jwt_assertion("xy12345.us-east-1", "indra_loader", PRIVATE_PEM, now).unwrap();
        let second = build_jwt_assertion(
            "xy12345.us-east-1",
            "indra_loader",
            PRIVATE_PEM,
            now + 3_600,
        )
        .unwrap();
        // A fresh assertion per validity window: different token,
        // expiry advanced by exactly one window.
        assert_ne!(first, second);
        let key = jsonwebtoken::DecodingKey::from_rsa_pem(PUBLIC_PEM.as_bytes()).unwrap();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.validate_exp = false;
        validation.set_required_spec_claims(&["iss", "sub", "exp"]);
        #[derive(Debug, serde::Deserialize)]
        struct ExpOnly {
            exp: u64,
        }
        let first_exp = jsonwebtoken::decode::<ExpOnly>(&first, &key, &validation)
            .unwrap()
            .claims
            .exp;
        let second_exp = jsonwebtoken::decode::<ExpOnly>(&second, &key, &validation)
            .unwrap()
            .claims
            .exp;
        assert_eq!(second_exp - first_exp, 3_600);
    }

    /// Captured streaming POSTs for the in-process loopback test.
    #[derive(Debug, Default)]
    struct CapturedStreamingPosts {
        auth: StdMutex<Vec<String>>,
        roles: StdMutex<Vec<Option<String>>>,
        bodies: StdMutex<Vec<Vec<u8>>>,
    }

    async fn streaming_capture_handler(
        State(state): State<Arc<CapturedStreamingPosts>>,
        headers: axum::http::HeaderMap,
        body: Bytes,
    ) -> StatusCode {
        if let Some(value) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
            state.auth.lock().unwrap().push(value.to_string());
        }
        state.roles.lock().unwrap().push(
            headers
                .get("x-snowflake-role")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string),
        );
        state.bodies.lock().unwrap().push(body.to_vec());
        StatusCode::OK
    }

    /// Loopback streaming proof: an ephemeral receiver gets exactly
    /// what the transport posts, and verifies the RS256 Bearer
    /// signature against the public half (a fake that accepts any
    /// token would prove nothing about authentication).
    #[tokio::test]
    async fn test_streaming_rows_loopback_verifies_bearer() {
        install_snowflake_tls_provider();
        let captured = Arc::new(CapturedStreamingPosts::default());
        let app = Router::new()
            .route(
                "/v1/data/streaming/channels/TESTCHAN/rows",
                post(streaming_capture_handler),
            )
            .with_state(captured.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        let mut config = test_config();
        config.channel = "TESTCHAN".to_string();
        config.endpoint = Some(format!("http://127.0.0.1:{port}"));
        let transport =
            HttpSnowflakeTransport::new(&config, reqwest::Client::new()).expect("transport");
        let token = build_jwt_assertion(
            &config.account,
            &config.user,
            PRIVATE_PEM,
            now_millis().max(0) as u64 / 1_000,
        )
        .unwrap();
        transport
            .insert_rows(
                "TELEMETRY",
                vec![SnowflakeRowItem {
                    fields: vec![("DEVICE_ID".to_string(), serde_json::json!("s-1"))],
                }],
                &token,
            )
            .await
            .expect("insert");

        let auth = captured.auth.lock().unwrap();
        assert_eq!(auth.len(), 1);
        let bearer = auth[0].strip_prefix("Bearer ").expect("bearer scheme");
        assert_eq!(bearer.split('.').count(), 3);
        let key = jsonwebtoken::DecodingKey::from_rsa_pem(PUBLIC_PEM.as_bytes()).unwrap();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.validate_exp = false;
        validation.set_required_spec_claims(&["iss", "sub", "exp"]);
        #[derive(Debug, serde::Deserialize)]
        struct IssSub {
            iss: String,
            sub: String,
        }
        let claims = jsonwebtoken::decode::<IssSub>(bearer, &key, &validation)
            .unwrap()
            .claims;
        assert_eq!(claims.iss, "XY12345.US-EAST-1.INDRA_LOADER");
        assert_eq!(claims.sub, "XY12345.US-EAST-1.INDRA_LOADER");
        assert_eq!(
            captured.roles.lock().unwrap().as_slice(),
            &[Some("LOADER".to_string())]
        );
        let bodies = captured.bodies.lock().unwrap();
        assert_eq!(bodies.len(), 1);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bodies[0]).unwrap(),
            serde_json::json!([{"DEVICE_ID": "s-1"}])
        );
        server.abort();
    }

    /// Broker-path proof: the sink delivers through the rule engine
    /// (publish ingress, rule projection, connector forward), never
    /// through a direct store call.
    #[tokio::test]
    async fn test_snowflake_through_rule_engine() {
        use broker_protocol::TopicFilter;
        use broker_rules::{BackpressurePolicy, RuleEngine};

        struct NullBrokerSink;

        #[async_trait::async_trait]
        impl broker_rules::BrokerSink for NullBrokerSink {
            async fn publish(
                &self,
                _topic: Topic,
                _payload: Bytes,
                _qos: QoS,
                _retain: bool,
            ) -> std::result::Result<(), broker_rules::RuleEngineError> {
                Ok(())
            }
        }

        let engine = RuleEngine::new(65_536, BackpressurePolicy::DropOldest);
        let mut config = test_config();
        config.column_mappings.clear();
        config.batch_size = Some(1);
        let transport = Arc::new(MockSnowflakeTransport::new());
        let sink = Arc::new(SnowflakeSink::new(config, transport.clone()).expect("sink"));
        assert_eq!(sink.kind(), "snowflake");
        engine.connectors().register("snow-rule", sink.clone());
        engine
            .create_rule(
                "snow-rule".to_string(),
                TopicFilter::new("sensors/+").unwrap(),
                Some(
                    r#"SELECT client_id, temp FROM "sensors/+" WHERE temp > 20.0 INTO connector("snow-rule")"#.to_string(),
                ),
                true,
                vec![],
            )
            .expect("rule creates");
        let egress: Arc<dyn broker_rules::BrokerSink> = Arc::new(NullBrokerSink);
        engine
            .dispatch_ingress(
                &Topic::new("sensors/kitchen").unwrap(),
                &Bytes::from_static(br#"{ "client_id": "device-42", "temp": 22.5 }"#),
                QoS::AtMostOnce,
                &egress,
            )
            .await;

        let captured = transport.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].rows.len(), 1);
        let fields: HashMap<String, &serde_json::Value> = captured[0].rows[0]
            .fields
            .iter()
            .map(|(k, v)| (k.clone(), v))
            .collect();
        assert_eq!(fields["CLIENT_ID"], &serde_json::json!("device-42"));
        assert_eq!(fields["TEMP"], &serde_json::json!(22.5));
        assert_eq!(sink.sent_records(), 1);
        assert_eq!(sink.committed_offset_token(), "0");
    }
}
