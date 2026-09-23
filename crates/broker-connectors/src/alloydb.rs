//! Google AlloyDB accelerated PostgreSQL sink (INDRA-170).
//!
//! Columnar-accelerated PostgreSQL-compatible sink optimized for Google Cloud
//! AlloyDB with Google Cloud IAM OAuth2 token and password authentication,
//! multi-row parameterized batch inserts, and connection failover classification.
//!
//! The write path runs on the maintained `tokio-postgres` driver with a
//! `rustls` TLS connector (`tokio-postgres-rustls`, system trust store
//! plus an optional private CA from configuration). IAM
//! database authentication uses a short-lived OAuth2 access token as the
//! PostgreSQL password, refreshed from Application Default Credentials via
//! `google-cloud-auth`. The legacy hand-written `TcpAlloydbTransport` is
//! retained for offline unit tests only; production wiring uses
//! `PgDriverAlloydbTransport` below.

use async_trait::async_trait;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::{BackoffState, BatchQueue, Connector, ConnectorError, Result, Sink};

const PG_MAX_BIND_PARAMS: usize = 65535;

fn rows_per_statement(columns: usize, max_params: usize) -> usize {
    if columns == 0 {
        return 1;
    }
    std::cmp::max(1, max_params / columns)
}

fn default_alloydb_port() -> u16 {
    5432
}

fn default_batch_size_1000() -> Option<usize> {
    Some(1000)
}

/// Column mapping from source payload path to database column.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlloydbColumnMapping {
    /// Field path in source JSON (e.g. `device_id` or `metrics.temperature`).
    pub source_field: String,
    /// Target database column name.
    pub db_column: String,
    /// Optional SQL data type hint (`TEXT`, `NUMERIC`, `TIMESTAMPTZ`, `JSONB`).
    #[serde(default)]
    pub data_type: Option<String>,
}

/// Authentication credentials for AlloyDB.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AlloydbAuth {
    /// Traditional password authentication.
    Password { password: String },
    /// Google Cloud IAM OAuth2 access token passed during password phase.
    IamToken { token: String },
    /// Fetch a short-lived IAM access token from Application Default
    /// Credentials at connect time via `google-cloud-auth` and use it as
    /// the PostgreSQL password (AlloyDB IAM database authentication).
    IamAuto {
        /// Optional OAuth2 scopes. Defaults to the AlloyDB / Cloud SQL
        /// admin scope when empty.
        #[serde(default)]
        scopes: Vec<String>,
    },
}

/// Configuration for Google Cloud AlloyDB sink.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlloydbConfig {
    /// AlloyDB instance IP or hostname.
    pub host: String,
    /// Port (default 5432).
    #[serde(default = "default_alloydb_port")]
    pub port: u16,
    /// Database name.
    pub database: String,
    /// Database username (e.g. `postgres` or IAM service account email).
    pub username: String,
    /// Authentication credentials (Password or Google Cloud IAM Token).
    pub auth: AlloydbAuth,
    /// Target database table name.
    pub table: String,
    /// Vector of column mappings (source_field -> db_column).
    #[serde(default)]
    pub column_mappings: Vec<AlloydbColumnMapping>,
    /// Batch flush size (unbounded scale, default 1,000).
    #[serde(default = "default_batch_size_1000")]
    pub batch_size: Option<usize>,
    /// In-memory queue buffer capacity (`None` = unbounded).
    #[serde(default)]
    pub buffer_capacity: Option<usize>,
    /// Network connect/query timeout in ms (default 5000).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Use TLS via `rustls` (system trust store plus optional private
    /// CA). Defaults to true; set to false only for local
    /// PostgreSQL-compatible test instances without certificates.
    /// AlloyDB itself always requires TLS.
    #[serde(default)]
    pub tls: Option<bool>,
    /// Extra CA bundle PEM for server verification, in addition to the
    /// OS system trust store. Lets an operator trust a private CA
    /// without rebuilding the binary.
    #[serde(default)]
    pub ca_bundle_pem: Option<String>,
    /// Path to a PEM bundle file with the same effect as
    /// `ca_bundle_pem`. When both are set the two bundles combine.
    #[serde(default)]
    pub tls_ca_file: Option<String>,
}

impl AlloydbConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.unwrap_or(5000).max(1))
    }

    pub fn validate(&self) -> Result<()> {
        if self.host.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "alloydb host cannot be empty".into(),
            ));
        }
        if self.database.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "alloydb database cannot be empty".into(),
            ));
        }
        if self.username.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "alloydb username cannot be empty".into(),
            ));
        }
        if self.table.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "alloydb table cannot be empty".into(),
            ));
        }
        match &self.auth {
            AlloydbAuth::Password { password } => {
                if password.is_empty() {
                    return Err(ConnectorError::Dispatch(
                        "alloydb password cannot be empty".into(),
                    ));
                }
            }
            AlloydbAuth::IamToken { token } => {
                if token.trim().is_empty() {
                    return Err(ConnectorError::Dispatch(
                        "alloydb iam token cannot be empty".into(),
                    ));
                }
            }
            AlloydbAuth::IamAuto { .. } => {}
        }
        if let Some(bundle) = &self.ca_bundle_pem {
            if !bundle.trim().is_empty() && !bundle.contains("BEGIN CERTIFICATE") {
                return Err(ConnectorError::Dispatch(
                    "alloydb ca_bundle_pem is not a PEM document".into(),
                ));
            }
        }
        if let Some(path) = &self.tls_ca_file {
            if path.trim().is_empty() {
                return Err(ConnectorError::Dispatch(
                    "alloydb tls_ca_file must not be empty".into(),
                ));
            }
        }
        Ok(())
    }

    /// Whether the driver transport should negotiate TLS.
    pub fn use_tls(&self) -> bool {
        self.tls.unwrap_or(true)
    }

    /// Default OAuth2 scopes for AlloyDB IAM database authentication.
    pub fn iam_scopes(auth: &AlloydbAuth) -> Vec<String> {
        match auth {
            AlloydbAuth::IamAuto { scopes } if !scopes.is_empty() => scopes.clone(),
            _ => vec!["https://www.googleapis.com/auth/cloud-platform".to_string()],
        }
    }

    pub fn credential_secret(&self) -> &str {
        match &self.auth {
            AlloydbAuth::Password { password } => password,
            AlloydbAuth::IamToken { token } => token,
            AlloydbAuth::IamAuto { .. } => "<adc>",
        }
    }

    /// Static password for `Password` / `IamToken` auth. `IamAuto` has no
    /// static secret; use [`resolve_alloydb_password`] at connect time.
    pub fn static_password(&self) -> Option<String> {
        match &self.auth {
            AlloydbAuth::Password { password } => Some(password.clone()),
            AlloydbAuth::IamToken { token } => Some(token.clone()),
            AlloydbAuth::IamAuto { .. } => None,
        }
    }
}

/// Resolve the PostgreSQL password for a connection attempt.
///
/// Static credentials are returned directly. `IamAuto` fetches a
/// short-lived OAuth2 access token from Application Default Credentials
/// via `google-cloud-auth`.
pub async fn resolve_alloydb_password(config: &AlloydbConfig) -> Result<String> {
    match &config.auth {
        AlloydbAuth::Password { password } => Ok(password.clone()),
        AlloydbAuth::IamToken { token } => Ok(token.clone()),
        AlloydbAuth::IamAuto { .. } => {
            let scopes = AlloydbConfig::iam_scopes(&config.auth);
            let credentials =
                google_cloud_auth::credentials::Builder::default().with_scopes(scopes);
            let credentials = credentials.build_access_token_credentials().map_err(|e| {
                ConnectorError::Connection(format!("alloydb IAM ADC build failed: {e}"))
            })?;
            let token = credentials.access_token().await.map_err(|e| {
                ConnectorError::Connection(format!("alloydb IAM token fetch failed: {e}"))
            })?;
            if token.token.trim().is_empty() {
                return Err(ConnectorError::Connection(
                    "alloydb IAM token fetch returned an empty token".into(),
                ));
            }
            Ok(token.token)
        }
    }
}

/// Typed AlloyDB parameter value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AlloydbValue {
    Null,
    String(String),
    Number(f64),
    Integer(i64),
    Boolean(bool),
}

/// Result returned from AlloyDB query execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlloydbQueryResult {
    pub rows_affected: usize,
    pub status: String,
    #[serde(default)]
    pub sqlstate: Option<String>,
    #[serde(default)]
    pub error_message: Option<String>,
}

/// Error classification for AlloyDB connection and queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlloydbErrorClassification {
    /// Read-pool failover, connection drop, or server restart (`57P01`, `57P03`, `08006`).
    FailoverRetryable,
    /// A single row the database refuses (SQLSTATE class `22`/`23`, `42703`, `42804`).
    DataRejected,
    /// Terminal error (e.g. `42P01` table missing, `28P01` bad creds).
    Terminal,
    /// Unknown or generic error.
    Unknown,
}

fn contains_sqlstate_token(haystack_upper: &str, token_upper: &str) -> bool {
    let h = haystack_upper.as_bytes();
    let n = token_upper.as_bytes();
    if n.is_empty() || h.len() < n.len() {
        return false;
    }
    for i in 0..=h.len() - n.len() {
        if &h[i..i + n.len()] == n {
            let before_ok = i == 0 || !h[i - 1].is_ascii_alphanumeric();
            let after_ok = i + n.len() == h.len() || !h[i + n.len()].is_ascii_alphanumeric();
            if before_ok && after_ok {
                return true;
            }
        }
    }
    false
}

fn contains_sqlstate_class(haystack_upper: &str, class_prefix: &str) -> bool {
    let h = haystack_upper.as_bytes();
    let p = class_prefix.as_bytes();
    if h.len() < 5 || p.len() != 2 {
        return false;
    }
    for i in 0..=h.len() - 5 {
        if &h[i..i + 2] == p && h[i..i + 5].iter().all(|b| b.is_ascii_alphanumeric()) {
            let before_ok = i == 0 || !h[i - 1].is_ascii_alphanumeric();
            let after_ok = i + 5 == h.len() || !h[i + 5].is_ascii_alphanumeric();
            if before_ok && after_ok {
                return true;
            }
        }
    }
    false
}

/// Classify PostgreSQL error code / SQLSTATE for AlloyDB.
pub fn classify_alloydb_error(err_msg: &str) -> AlloydbErrorClassification {
    let s = err_msg.to_ascii_uppercase();
    if contains_sqlstate_token(&s, "57P01")
        || contains_sqlstate_token(&s, "57P03")
        || contains_sqlstate_token(&s, "08006")
        || contains_sqlstate_token(&s, "08001")
        || s.contains("CONNECTION REFUSED")
        || s.contains("READ POOL FAILOVER")
        || s.contains("CANNOT_CONNECT_NOW")
    {
        AlloydbErrorClassification::FailoverRetryable
    } else if contains_sqlstate_class(&s, "22")
        || contains_sqlstate_class(&s, "23")
        || contains_sqlstate_token(&s, "42703")
        || contains_sqlstate_token(&s, "42804")
    {
        AlloydbErrorClassification::DataRejected
    } else if contains_sqlstate_token(&s, "42P01")
        || contains_sqlstate_token(&s, "28P01")
        || s.contains("UNDEFINED COLUMN")
        || s.contains("UNDEFINED TABLE")
        || s.contains("PASSWORD AUTHENTICATION FAILED")
    {
        AlloydbErrorClassification::Terminal
    } else {
        AlloydbErrorClassification::Unknown
    }
}

/// Quote a PostgreSQL identifier if needed.
///
/// Names matching `^[a-z_][a-z0-9_]*$` are returned unchanged so existing
/// lower-case schemas behave exactly as today; any other non-empty name is
/// wrapped in double quotes with embedded `"` doubled.
fn quote_pg_ident(name: &str) -> Result<String> {
    if name.is_empty() {
        return Err(ConnectorError::Dispatch(
            "cannot quote empty identifier".into(),
        ));
    }
    let mut bytes = name.bytes();
    let first = bytes.next().expect("non-empty checked above");
    let first_ok = first == b'_' || first.is_ascii_lowercase();
    let rest_ok = bytes.all(|b| b == b'_' || b.is_ascii_lowercase() || b.is_ascii_digit());
    if first_ok && rest_ok {
        return Ok(name.to_string());
    }
    Ok(format!("\"{}\"", name.replace('"', "\"\"")))
}

/// Build a multi-row parameterized `INSERT INTO` query.
pub fn build_alloydb_insert_query(
    table: &str,
    columns: &[String],
    row_count: usize,
) -> Result<String> {
    if columns.is_empty() {
        return Err(ConnectorError::Dispatch(
            "cannot build insert query without columns".into(),
        ));
    }
    if row_count == 0 {
        return Err(ConnectorError::Dispatch(
            "cannot build insert query with 0 rows".into(),
        ));
    }

    let mut quoted = Vec::with_capacity(columns.len());
    for c in columns {
        quoted.push(quote_pg_ident(c)?);
    }
    let cols_joined = quoted.join(", ");
    let mut row_placeholders = Vec::with_capacity(row_count);

    for r in 0..row_count {
        let placeholders: Vec<String> = (0..columns.len())
            .map(|c| format!("${}", r * columns.len() + c + 1))
            .collect();
        row_placeholders.push(format!("({})", placeholders.join(", ")));
    }

    Ok(format!(
        "INSERT INTO {} ({}) VALUES {}",
        table,
        cols_joined,
        row_placeholders.join(", ")
    ))
}

/// Extracted row for AlloyDB sink ingestion.
#[derive(Debug, Clone)]
pub struct AlloydbRow {
    pub topic: String,
    pub columns: Vec<(String, AlloydbValue)>,
}

/// Extract value at path (supports simple dots e.g. `metrics.temp`).
pub fn extract_json_path<'a>(
    val: &'a serde_json::Value,
    path: &str,
) -> Option<&'a serde_json::Value> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut curr = val;
    for part in parts {
        match curr {
            serde_json::Value::Object(map) => {
                curr = map.get(part)?;
            }
            _ => return None,
        }
    }
    Some(curr)
}

/// Convert JSON value to `AlloydbValue`.
pub fn json_to_alloydb_value(val: &serde_json::Value) -> AlloydbValue {
    match val {
        serde_json::Value::Null => AlloydbValue::Null,
        serde_json::Value::Bool(b) => AlloydbValue::Boolean(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                AlloydbValue::Integer(i)
            } else if let Some(f) = n.as_f64() {
                AlloydbValue::Number(f)
            } else {
                AlloydbValue::String(n.to_string())
            }
        }
        serde_json::Value::String(s) => AlloydbValue::String(s.clone()),
        other => AlloydbValue::String(other.to_string()),
    }
}

/// Extract columns according to config mappings or top-level keys.
pub fn extract_alloydb_row(
    payload: &[u8],
    topic: &str,
    mappings: &[AlloydbColumnMapping],
) -> Result<AlloydbRow> {
    let json_val: serde_json::Value = serde_json::from_slice(payload)
        .map_err(|e| ConnectorError::Dispatch(format!("invalid JSON payload: {e}")))?;

    let mut columns = Vec::new();

    if !mappings.is_empty() {
        for m in mappings {
            let extracted = extract_json_path(&json_val, &m.source_field)
                .map(json_to_alloydb_value)
                .unwrap_or(AlloydbValue::Null);
            columns.push((m.db_column.clone(), extracted));
        }
    } else if let serde_json::Value::Object(map) = json_val {
        if map.is_empty() {
            return Err(ConnectorError::Dispatch(
                "alloydb payload object has no keys".into(),
            ));
        }
        for (k, v) in map {
            if k.is_empty() {
                return Err(ConnectorError::Dispatch(
                    "alloydb payload contains an empty column name".into(),
                ));
            }
            columns.push((k, json_to_alloydb_value(&v)));
        }
    } else {
        columns.push(("payload".to_string(), json_to_alloydb_value(&json_val)));
    }

    Ok(AlloydbRow {
        topic: topic.to_string(),
        columns,
    })
}

/// Transport abstraction for executing AlloyDB queries.
#[async_trait]
pub trait AlloydbTransport: Send + Sync {
    async fn execute(&self, query: &str, params: &[AlloydbValue]) -> Result<AlloydbQueryResult>;
}

fn format_alloydb_value(v: &AlloydbValue) -> String {
    match v {
        AlloydbValue::Null => "NULL".to_string(),
        AlloydbValue::Boolean(b) => {
            if *b {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        AlloydbValue::Integer(i) => i.to_string(),
        AlloydbValue::Number(n) => n.to_string(),
        AlloydbValue::String(s) => format!("'{}'", s.replace('\'', "''")),
    }
}

async fn read_alloydb_pg_msg(
    stream: &mut tokio::net::TcpStream,
    timeout: Duration,
) -> Result<(u8, Vec<u8>)> {
    use tokio::io::AsyncReadExt;
    let mut header = [0u8; 5];
    tokio::time::timeout(timeout, stream.read_exact(&mut header))
        .await
        .map_err(|_| ConnectorError::Connection("alloydb read timeout".to_string()))?
        .map_err(|e| ConnectorError::Connection(format!("alloydb read failed: {e}")))?;
    let tag = header[0];
    let len = i32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if !(4..=16 * 1024 * 1024).contains(&len) {
        return Err(ConnectorError::Connection(format!(
            "alloydb bad message length: {len}"
        )));
    }
    let mut body = vec![0u8; len - 4];
    tokio::time::timeout(timeout, stream.read_exact(&mut body))
        .await
        .map_err(|_| ConnectorError::Connection("alloydb read timeout".to_string()))?
        .map_err(|e| ConnectorError::Connection(format!("alloydb read failed: {e}")))?;
    Ok((tag, body))
}

/// Native TCP transport connecting to Google Cloud AlloyDB.
pub struct TcpAlloydbTransport {
    host: String,
    port: u16,
    database: String,
    username: String,
    password: Option<String>,
    timeout: Duration,
}

impl TcpAlloydbTransport {
    pub fn new(config: &AlloydbConfig) -> Self {
        let password = match &config.auth {
            AlloydbAuth::Password { password } => Some(password.clone()),
            AlloydbAuth::IamToken { token } => Some(token.clone()),
            AlloydbAuth::IamAuto { .. } => None,
        };
        Self {
            host: config.host.clone(),
            port: config.port,
            database: config.database.clone(),
            username: config.username.clone(),
            password,
            timeout: config.timeout(),
        }
    }
}

#[async_trait]
impl AlloydbTransport for TcpAlloydbTransport {
    async fn execute(&self, query: &str, params: &[AlloydbValue]) -> Result<AlloydbQueryResult> {
        use tokio::io::AsyncWriteExt;
        let mut full_sql = query.to_string();
        for (idx, p) in params.iter().enumerate() {
            let placeholder = format!("${}", idx + 1);
            full_sql = full_sql.replace(&placeholder, &format_alloydb_value(p));
        }

        let addr = format!("{}:{}", self.host, self.port);
        let mut stream = tokio::time::timeout(self.timeout, tokio::net::TcpStream::connect(&addr))
            .await
            .map_err(|_| ConnectorError::Connection(format!("alloydb connect timeout: {addr}")))?
            .map_err(|e| ConnectorError::Connection(format!("alloydb connect failed: {e}")))?;

        // Send StartupMessage
        let mut params_buf = Vec::new();
        params_buf.extend_from_slice(b"user\0");
        params_buf.extend_from_slice(self.username.as_bytes());
        params_buf.push(0);
        params_buf.extend_from_slice(b"database\0");
        params_buf.extend_from_slice(self.database.as_bytes());
        params_buf.push(0);
        params_buf.push(0);

        let mut startup_body = Vec::new();
        startup_body.extend_from_slice(&0x0003_0000u32.to_be_bytes());
        startup_body.extend_from_slice(&params_buf);
        let len = (startup_body.len() + 4) as u32;
        let mut startup_msg = Vec::new();
        startup_msg.extend_from_slice(&len.to_be_bytes());
        startup_msg.extend_from_slice(&startup_body);
        stream.write_all(&startup_msg).await.map_err(|e| {
            ConnectorError::Connection(format!("alloydb startup write failed: {e}"))
        })?;

        // Drain until 'Z' (ReadyForQuery)
        loop {
            let (tag, body) = read_alloydb_pg_msg(&mut stream, self.timeout).await?;
            if tag == b'Z' {
                break;
            } else if tag == b'R' {
                let auth_type = if body.len() >= 4 {
                    i32::from_be_bytes([body[0], body[1], body[2], body[3]])
                } else {
                    0
                };
                if auth_type == 3 {
                    // CleartextPassword
                    let pass = self.password.as_deref().unwrap_or("");
                    let p_bytes = pass.as_bytes();
                    let p_len = (p_bytes.len() + 5) as u32;
                    let mut p_msg = Vec::with_capacity(p_len as usize + 1);
                    p_msg.push(b'p');
                    p_msg.extend_from_slice(&p_len.to_be_bytes());
                    p_msg.extend_from_slice(p_bytes);
                    p_msg.push(0);
                    stream.write_all(&p_msg).await.map_err(|e| {
                        ConnectorError::Connection(format!("alloydb password write failed: {e}"))
                    })?;
                }
            } else if tag == b'E' {
                let msg = String::from_utf8_lossy(&body).into_owned();
                return Err(ConnectorError::Connection(format!(
                    "alloydb startup error: {msg}"
                )));
            }
        }

        // Send Simple Query ('Q')
        let sql_bytes = full_sql.as_bytes();
        let q_len = (sql_bytes.len() + 5) as u32;
        let mut q_msg = Vec::with_capacity(q_len as usize + 1);
        q_msg.push(b'Q');
        q_msg.extend_from_slice(&q_len.to_be_bytes());
        q_msg.extend_from_slice(sql_bytes);
        q_msg.push(0);
        stream
            .write_all(&q_msg)
            .await
            .map_err(|e| ConnectorError::Connection(format!("alloydb query write failed: {e}")))?;

        let mut rows_affected = 1;
        let mut error_msg = None;
        loop {
            let (tag, body) = read_alloydb_pg_msg(&mut stream, self.timeout).await?;
            if tag == b'C' {
                let s = String::from_utf8_lossy(&body);
                if let Some(cnt_str) = s.split_whitespace().last() {
                    if let Ok(cnt) = cnt_str.trim_matches('\0').parse::<usize>() {
                        rows_affected = cnt;
                    }
                }
            } else if tag == b'E' {
                let s = String::from_utf8_lossy(&body).into_owned();
                error_msg = Some(s);
            } else if tag == b'Z' {
                break;
            }
        }

        if let Some(err) = error_msg {
            return Err(ConnectorError::Dispatch(format!(
                "alloydb query error: {err}"
            )));
        }

        Ok(AlloydbQueryResult {
            rows_affected,
            status: "SUCCESS".into(),
            sqlstate: None,
            error_message: None,
        })
    }
}

/// Build a `tokio-postgres` connection config from an AlloyDB config.
///
/// Password (or IAM token) is supplied separately so `IamAuto` can refresh
/// it per connection attempt without mutating the stored config.
pub fn alloydb_connect_config(config: &AlloydbConfig, password: &str) -> tokio_postgres::Config {
    let mut cfg = tokio_postgres::Config::new();
    cfg.host(&config.host);
    cfg.port(config.port);
    cfg.dbname(&config.database);
    cfg.user(&config.username);
    cfg.password(password);
    cfg.connect_timeout(config.timeout());
    cfg
}

/// Convert an [`AlloydbValue`] into an owned `ToSql` parameter.
///
/// `Null` becomes `None::<String>` so the driver binds SQL NULL; numbers,
/// integers, booleans and strings keep their native PostgreSQL types.
pub fn alloydb_value_to_boxed(
    value: &AlloydbValue,
) -> Box<dyn tokio_postgres::types::ToSql + Sync + Send> {
    match value {
        AlloydbValue::Null => Box::new(None::<String>),
        AlloydbValue::String(s) => Box::new(s.clone()),
        AlloydbValue::Integer(i) => Box::new(*i),
        AlloydbValue::Number(n) => Box::new(*n),
        AlloydbValue::Boolean(b) => Box::new(*b),
    }
}

/// Map a `tokio-postgres` error onto [`ConnectorError`], preserving the
/// SQLSTATE text so [`classify_alloydb_error`] keeps working.
///
/// Failover-retryable conditions (connection loss, `57P01`/`57P03`,
/// `08001`/`08006`) become `Connection` so the sink restores the batch and
/// backs off; everything else becomes `Dispatch` for per-row handling.
pub fn map_driver_error(err: &tokio_postgres::Error) -> ConnectorError {
    let mut detail = err.to_string();
    let mut code_text: Option<String> = None;
    if let Some(db) = err.as_db_error() {
        let code_str = db.code().code().to_string();
        code_text = Some(code_str.clone());
        let message = db.message();
        detail = format!("{code_str}: {message}");
        if let Some(hint) = db.hint() {
            detail.push_str(&format!(" (hint: {hint})"));
        }
    }
    let probe = if let Some(code) = code_text {
        format!("{code} {detail}")
    } else {
        detail.clone()
    };
    match classify_alloydb_error(&probe) {
        AlloydbErrorClassification::FailoverRetryable => {
            ConnectorError::Connection(format!("alloydb driver error: {detail}"))
        }
        _ => ConnectorError::Dispatch(format!("alloydb driver error: {detail}")),
    }
}

fn install_alloydb_tls_provider() {
    // The TLS connector below needs a process-default crypto provider.
    // The workspace enables exactly one rustls provider (`aws-lc-rs` via
    // the default features), so installing it explicitly is a no-op when
    // already installed and keeps the call safe under feature
    // unification.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Extra CA PEMs from configuration: inline `ca_bundle_pem` plus the
/// file at `tls_ca_file` when set. Both combine with the system store;
/// either may be absent.
fn alloydb_extra_ca_pems(config: &AlloydbConfig) -> Result<Vec<String>> {
    let mut pems = Vec::new();
    if let Some(bundle) = &config.ca_bundle_pem {
        if !bundle.trim().is_empty() {
            pems.push(bundle.clone());
        }
    }
    if let Some(path) = &config.tls_ca_file {
        if !path.trim().is_empty() {
            let pem = std::fs::read_to_string(path).map_err(|e| {
                tracing::warn!(error = %e, path = %path, "alloydb CA file unreadable");
                ConnectorError::Connection(format!("alloydb CA file unreadable: {e}"))
            })?;
            if pem.trim().is_empty() {
                return Err(ConnectorError::Dispatch(
                    "alloydb CA file has no PEM sections".into(),
                ));
            }
            pems.push(pem);
        }
    }
    Ok(pems)
}

fn alloydb_certs_from_pem(pem: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut reader)
        .map_err(|e| ConnectorError::Dispatch(format!("alloydb CA bundle read failed: {e}")))?;
    if certs.is_empty() {
        return Err(ConnectorError::Dispatch(
            "alloydb CA bundle has no certificate section".into(),
        ));
    }
    Ok(certs
        .into_iter()
        .map(rustls::pki_types::CertificateDer::from)
        .collect())
}

/// Root store for AlloyDB TLS: the OS system trust store plus the
/// operator-supplied private CA bundle from configuration. Fail closed
/// when nothing trusted anything: no bundled Mozilla fallback, so an
/// unreachable system store denies the connection instead of silently
/// trusting a stale list.
fn alloydb_root_store(config: &AlloydbConfig) -> Result<rustls::RootCertStore> {
    let mut store = rustls::RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        let _ = store.add(cert);
    }
    if !native.errors.is_empty() {
        tracing::warn!(
            errors = native.errors.len(),
            "alloydb system trust store reported load errors"
        );
    }
    for pem in alloydb_extra_ca_pems(config)? {
        for cert in alloydb_certs_from_pem(&pem)? {
            store.add(cert).map_err(|e| {
                ConnectorError::Dispatch(format!("alloydb CA bundle rejected: {e}"))
            })?;
        }
    }
    if store.is_empty() {
        return Err(ConnectorError::Connection(
            "alloydb TLS trust store is empty: system store unreadable and no private CA configured"
                .into(),
        ));
    }
    Ok(store)
}

/// Client TLS config for AlloyDB: system roots plus the configured
/// private CA, with no client authentication.
fn build_alloydb_tls_config(config: &AlloydbConfig) -> Result<rustls::ClientConfig> {
    install_alloydb_tls_provider();
    let roots = alloydb_root_store(config)?;
    Ok(rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

/// TLS connector for the `tokio-postgres` driver built from the system
/// trust store plus the configured private CA.
fn alloydb_tls_connector(
    config: &AlloydbConfig,
) -> Result<tokio_postgres_rustls::MakeRustlsConnect> {
    Ok(tokio_postgres_rustls::MakeRustlsConnect::new(
        build_alloydb_tls_config(config)?,
    ))
}

/// Production transport for Google Cloud AlloyDB.
///
/// Speaks the PostgreSQL-compatible wire protocol (startup,
/// SASL/SCRAM-SHA-256 and cleartext password, extended-query Parse/Bind/
/// Execute) through the maintained `tokio-postgres` driver with a `rustls`
/// TLS connector. IAM database authentication passes the OAuth2 access
/// token as the password; `IamAuto` refreshes it per connection via
/// `google-cloud-auth`.
pub struct PgDriverAlloydbTransport {
    config: AlloydbConfig,
}

impl PgDriverAlloydbTransport {
    pub fn new(config: &AlloydbConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    pub fn config(&self) -> &AlloydbConfig {
        &self.config
    }

    async fn connect_client(&self, password: &str) -> Result<tokio_postgres::Client> {
        let pg_config = alloydb_connect_config(&self.config, password);
        if self.config.use_tls() {
            let tls = alloydb_tls_connector(&self.config)?;
            let connect = pg_config.connect(tls);
            let (client, connection) = tokio::time::timeout(self.config.timeout(), connect)
                .await
                .map_err(|_| ConnectorError::Connection("alloydb connect timeout".to_string()))?
                .map_err(|e| ConnectorError::Connection(format!("alloydb connect failed: {e}")))?;
            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    tracing::warn!(error = %e, "alloydb driver connection closed");
                }
            });
            Ok(client)
        } else {
            let connect = pg_config.connect(tokio_postgres::NoTls);
            let (client, connection) = tokio::time::timeout(self.config.timeout(), connect)
                .await
                .map_err(|_| ConnectorError::Connection("alloydb connect timeout".to_string()))?
                .map_err(|e| ConnectorError::Connection(format!("alloydb connect failed: {e}")))?;
            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    tracing::warn!(error = %e, "alloydb driver connection closed");
                }
            });
            Ok(client)
        }
    }
}

#[async_trait]
impl AlloydbTransport for PgDriverAlloydbTransport {
    async fn execute(&self, query: &str, params: &[AlloydbValue]) -> Result<AlloydbQueryResult> {
        let password = resolve_alloydb_password(&self.config).await?;
        let client = self.connect_client(&password).await?;
        let owned: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> =
            params.iter().map(alloydb_value_to_boxed).collect();
        let refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            owned.iter().map(|b| b.as_ref() as _).collect();
        let rows = tokio::time::timeout(self.config.timeout(), client.execute(query, &refs))
            .await
            .map_err(|_| ConnectorError::Connection("alloydb query timeout".to_string()))?
            .map_err(|e| map_driver_error(&e))?;
        Ok(AlloydbQueryResult {
            rows_affected: rows as usize,
            status: "SUCCESS".into(),
            sqlstate: None,
            error_message: None,
        })
    }
}

/// Captured execution for testing.
#[derive(Debug, Clone)]
pub struct CapturedAlloydbExecution {
    pub query: String,
    pub params: Vec<AlloydbValue>,
}

/// Mock transport for unit testing with failover simulation.
pub struct MockAlloydbTransport {
    pub executions: Mutex<Vec<CapturedAlloydbExecution>>,
    pub fail_count: Mutex<usize>,
    pub outcome_code: Mutex<Option<String>>,
    pub fail_at: Mutex<Option<usize>>,
    pub fail_on_value: Mutex<Option<AlloydbValue>>,
    pub fail_on_message: Mutex<Option<String>>,
}

impl MockAlloydbTransport {
    pub fn new() -> Self {
        Self {
            executions: Mutex::new(Vec::new()),
            fail_count: Mutex::new(0),
            outcome_code: Mutex::new(None),
            fail_at: Mutex::new(None),
            fail_on_value: Mutex::new(None),
            fail_on_message: Mutex::new(None),
        }
    }

    pub fn with_failover(failures: usize) -> Self {
        Self {
            executions: Mutex::new(Vec::new()),
            fail_count: Mutex::new(failures),
            outcome_code: Mutex::new(Some("57P01: read pool failover in progress".to_string())),
            fail_at: Mutex::new(None),
            fail_on_value: Mutex::new(None),
            fail_on_message: Mutex::new(None),
        }
    }

    pub fn with_terminal_error(sqlstate: &str) -> Self {
        Self {
            executions: Mutex::new(Vec::new()),
            fail_count: Mutex::new(1),
            outcome_code: Mutex::new(Some(sqlstate.to_string())),
            fail_at: Mutex::new(None),
            fail_on_value: Mutex::new(None),
            fail_on_message: Mutex::new(None),
        }
    }

    pub fn with_value_failure(value: AlloydbValue, message: &str) -> Self {
        Self {
            executions: Mutex::new(Vec::new()),
            fail_count: Mutex::new(0),
            outcome_code: Mutex::new(None),
            fail_at: Mutex::new(None),
            fail_on_value: Mutex::new(Some(value)),
            fail_on_message: Mutex::new(Some(message.to_string())),
        }
    }
}

impl Default for MockAlloydbTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AlloydbTransport for MockAlloydbTransport {
    async fn execute(&self, query: &str, params: &[AlloydbValue]) -> Result<AlloydbQueryResult> {
        self.executions.lock().push(CapturedAlloydbExecution {
            query: query.to_string(),
            params: params.to_vec(),
        });

        let call_idx = self.executions.lock().len().saturating_sub(1);
        if let Some(fail_idx) = *self.fail_at.lock() {
            if call_idx == fail_idx {
                if let Some(code) = self.outcome_code.lock().clone() {
                    let class = classify_alloydb_error(&code);
                    if class == AlloydbErrorClassification::FailoverRetryable {
                        return Err(ConnectorError::Connection(format!(
                            "alloydb transient failover: {code}"
                        )));
                    }
                    return Err(ConnectorError::Dispatch(format!(
                        "alloydb terminal error: {code}"
                    )));
                }
                return Err(ConnectorError::Connection(format!(
                    "alloydb mock failure at call {call_idx}"
                )));
            }
        }

        let mut fails = self.fail_count.lock();
        if *fails > 0 {
            *fails -= 1;
            let code = self
                .outcome_code
                .lock()
                .clone()
                .unwrap_or_else(|| "57P01".into());
            let class = classify_alloydb_error(&code);
            if class == AlloydbErrorClassification::FailoverRetryable {
                return Err(ConnectorError::Connection(format!(
                    "alloydb transient failover: {code}"
                )));
            } else {
                return Err(ConnectorError::Dispatch(format!(
                    "alloydb terminal error: {code}"
                )));
            }
        }

        if let Some(want) = self.fail_on_value.lock().clone() {
            if params.contains(&want) {
                let code = self
                    .fail_on_message
                    .lock()
                    .clone()
                    .unwrap_or_else(|| "23514: check constraint violated".into());
                let class = classify_alloydb_error(&code);
                if class == AlloydbErrorClassification::FailoverRetryable {
                    return Err(ConnectorError::Connection(format!(
                        "alloydb transient failover: {code}"
                    )));
                } else {
                    return Err(ConnectorError::Dispatch(format!(
                        "alloydb terminal error: {code}"
                    )));
                }
            }
        }

        Ok(AlloydbQueryResult {
            rows_affected: params.len().max(1),
            status: "SUCCESS".into(),
            sqlstate: None,
            error_message: None,
        })
    }
}

/// Google AlloyDB Accelerated PostgreSQL Sink.
pub struct AlloydbSink {
    config: AlloydbConfig,
    transport: Arc<dyn AlloydbTransport>,
    queue: Mutex<BatchQueue<AlloydbRow>>,
    backoff: Mutex<BackoffState>,
    sent: AtomicU64,
    rejected_rows: AtomicU64,
}

impl AlloydbSink {
    pub fn new(config: AlloydbConfig, transport: Arc<dyn AlloydbTransport>) -> Result<Self> {
        config.validate()?;
        let batch_size = config.batch_size.unwrap_or(1000).max(1);
        Ok(Self {
            config,
            transport,
            queue: Mutex::new(BatchQueue::new(batch_size, Duration::from_millis(50))),
            backoff: Mutex::new(BackoffState::default()),
            sent: AtomicU64::new(0),
            rejected_rows: AtomicU64::new(0),
        })
    }

    pub fn config(&self) -> &AlloydbConfig {
        &self.config
    }

    pub fn sent_count(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }

    pub fn rejected_rows(&self) -> u64 {
        self.rejected_rows.load(Ordering::Relaxed)
    }

    pub fn buffered_rows(&self) -> usize {
        self.queue.lock().len()
    }

    pub async fn flush(&self) -> Result<()> {
        self.flush_with_limit(PG_MAX_BIND_PARAMS).await
    }

    async fn flush_with_limit(&self, max_params: usize) -> Result<()> {
        self.backoff.lock().check()?;

        let (rows, oldest) = {
            let mut q = self.queue.lock();
            if q.is_empty() {
                return Ok(());
            }
            q.take_batch()
        };

        if rows.is_empty() {
            return Ok(());
        }

        let mut columns: Vec<String> = Vec::new();
        for row in &rows {
            for (c, _) in &row.columns {
                if !columns.iter().any(|e| e == c) {
                    columns.push(c.clone());
                }
            }
        }
        if columns.len() > max_params {
            tracing::warn!(
                rows = rows.len(),
                columns = columns.len(),
                max_params = max_params,
                "alloydb dropping batch that exceeds bind parameter limit"
            );
            return Err(ConnectorError::Dispatch(
                "alloydb batch exceeds bind parameter limit".into(),
            ));
        }
        let mut rows = rows;
        let per_statement = rows_per_statement(columns.len(), max_params).max(1);
        let total = rows.len();
        let mut idx = 0;
        let mut rejected: u64 = 0;
        let mut first_reject_msg: Option<String> = None;
        while idx < total {
            let end = (idx + per_statement).min(total);
            let chunk_len = end - idx;
            let query = match build_alloydb_insert_query(&self.config.table, &columns, chunk_len) {
                Ok(q) => q,
                Err(e) => {
                    // Query build errors are permanent (payload-derived), so the batch is dropped, not restored.
                    tracing::warn!(error = %e, rows = chunk_len, "alloydb dropping unbuildable batch");
                    return Err(e);
                }
            };

            let mut params = Vec::with_capacity(chunk_len * columns.len());
            for row in &rows[idx..end] {
                for col in &columns {
                    let val = row
                        .columns
                        .iter()
                        .find(|(c, _)| c == col)
                        .map(|(_, v)| v.clone())
                        .unwrap_or(AlloydbValue::Null);
                    params.push(val);
                }
            }

            match self.transport.execute(&query, &params).await {
                Ok(_) => {
                    self.sent.fetch_add(chunk_len as u64, Ordering::Relaxed);
                    idx = end;
                }
                Err(e) => {
                    let msg = e.to_string();
                    if classify_alloydb_error(&msg) != AlloydbErrorClassification::DataRejected {
                        self.backoff.lock().failure();
                        let remaining = rows.split_off(idx);
                        self.queue.lock().restore(remaining, oldest);
                        return Err(e);
                    }
                    if chunk_len == 1 {
                        rejected += 1;
                        self.rejected_rows.fetch_add(1, Ordering::Relaxed);
                        if first_reject_msg.is_none() {
                            first_reject_msg = Some(msg);
                        }
                        idx = end;
                        continue;
                    }
                    let mut row_idx = idx;
                    while row_idx < end {
                        let single_query =
                            match build_alloydb_insert_query(&self.config.table, &columns, 1) {
                                Ok(q) => q,
                                Err(build_err) => {
                                    rejected += 1;
                                    self.rejected_rows.fetch_add(1, Ordering::Relaxed);
                                    if first_reject_msg.is_none() {
                                        first_reject_msg = Some(build_err.to_string());
                                    }
                                    row_idx += 1;
                                    continue;
                                }
                            };
                        let mut single_params = Vec::with_capacity(columns.len());
                        for col in &columns {
                            let val = rows[row_idx]
                                .columns
                                .iter()
                                .find(|(c, _)| c == col)
                                .map(|(_, v)| v.clone())
                                .unwrap_or(AlloydbValue::Null);
                            single_params.push(val);
                        }
                        match self.transport.execute(&single_query, &single_params).await {
                            Ok(_) => {
                                self.sent.fetch_add(1, Ordering::Relaxed);
                                row_idx += 1;
                            }
                            Err(row_err) => {
                                let row_msg = row_err.to_string();
                                if classify_alloydb_error(&row_msg)
                                    == AlloydbErrorClassification::DataRejected
                                {
                                    rejected += 1;
                                    self.rejected_rows.fetch_add(1, Ordering::Relaxed);
                                    if first_reject_msg.is_none() {
                                        first_reject_msg = Some(row_msg);
                                    }
                                    row_idx += 1;
                                } else {
                                    self.backoff.lock().failure();
                                    let remaining = rows.split_off(row_idx);
                                    self.queue.lock().restore(remaining, oldest);
                                    return Err(row_err);
                                }
                            }
                        }
                    }
                    idx = end;
                }
            }
        }
        if rejected > 0 {
            tracing::warn!(
                rejected = rejected,
                error = first_reject_msg.as_deref().unwrap_or("unknown"),
                "alloydb rejected rows the database refused"
            );
        }
        self.backoff.lock().success();
        Ok(())
    }
}

#[async_trait]
impl Sink for AlloydbSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, _qos: QoS) -> Result<()> {
        let row = extract_alloydb_row(payload, topic.as_str(), &self.config.column_mappings)?;
        let should_flush = {
            let mut q = self.queue.lock();
            q.push(row)
        };

        if should_flush {
            // While backing off, keep rows buffered instead of failing the
            // send: an explicit flush reports the backoff without dropping.
            if self.backoff.lock().check().is_err() {
                return Ok(());
            }
            if let Err(e) = self.flush().await {
                if let ConnectorError::Connection(msg) = &e {
                    if msg == "sink backing off after errors" {
                        return Ok(());
                    }
                }
                return Err(e);
            }
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "alloydb"
    }
}

/// Addressable registered connector for Google Cloud AlloyDB.
pub struct AlloydbConnector {
    id: String,
    sink: Arc<AlloydbSink>,
}

impl AlloydbConnector {
    pub fn new(id: impl Into<String>, sink: Arc<AlloydbSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }

    pub fn sink(&self) -> Arc<AlloydbSink> {
        self.sink.clone()
    }
}

impl Connector for AlloydbConnector {
    fn connector_id(&self) -> &str {
        &self.id
    }

    fn kind(&self) -> &'static str {
        "alloydb"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_password_config() -> AlloydbConfig {
        AlloydbConfig {
            host: "10.128.0.5".to_string(),
            port: 5432,
            database: "iot_warehouse".to_string(),
            username: "postgres".to_string(),
            auth: AlloydbAuth::Password {
                password: "SecureDbPassword!".to_string(),
            },
            table: "sensor_telemetry".to_string(),
            column_mappings: vec![
                AlloydbColumnMapping {
                    source_field: "device_id".to_string(),
                    db_column: "dev_id".to_string(),
                    data_type: Some("TEXT".to_string()),
                },
                AlloydbColumnMapping {
                    source_field: "metrics.temperature".to_string(),
                    db_column: "temp_celsius".to_string(),
                    data_type: Some("NUMERIC".to_string()),
                },
            ],
            batch_size: Some(1),
            buffer_capacity: None,
            timeout_ms: None,
            tls: None,
            ca_bundle_pem: None,
            tls_ca_file: None,
        }
    }

    fn sample_iam_config() -> AlloydbConfig {
        AlloydbConfig {
            host: "10.128.0.6".to_string(),
            port: 5432,
            database: "telemetry".to_string(),
            username: "service-account@project.iam".to_string(),
            auth: AlloydbAuth::IamToken {
                token: "ya29.c.b0AXv0zT...GcpBearerToken".to_string(),
            },
            table: "events".to_string(),
            column_mappings: Vec::new(),
            batch_size: Some(1),
            buffer_capacity: None,
            timeout_ms: None,
            tls: None,
            ca_bundle_pem: None,
            tls_ca_file: None,
        }
    }

    #[test]
    fn test_config_validation_and_secrets() {
        let pass_cfg = sample_password_config();
        assert!(pass_cfg.validate().is_ok());
        assert_eq!(pass_cfg.credential_secret(), "SecureDbPassword!");

        let iam_cfg = sample_iam_config();
        assert!(iam_cfg.validate().is_ok());
        assert_eq!(
            iam_cfg.credential_secret(),
            "ya29.c.b0AXv0zT...GcpBearerToken"
        );
    }

    #[test]
    fn test_multi_row_insert_query_builder() {
        let cols = vec!["dev_id".to_string(), "temp_celsius".to_string()];
        let q1 = build_alloydb_insert_query("sensor_telemetry", &cols, 1).expect("valid query");
        assert_eq!(
            q1,
            "INSERT INTO sensor_telemetry (dev_id, temp_celsius) VALUES ($1, $2)"
        );

        let q2 = build_alloydb_insert_query("sensor_telemetry", &cols, 2).expect("valid query");
        assert_eq!(
            q2,
            "INSERT INTO sensor_telemetry (dev_id, temp_celsius) VALUES ($1, $2), ($3, $4)"
        );
    }

    #[test]
    fn test_column_mapping_nested_extraction() {
        let payload =
            br#"{"device_id": "d-202", "metrics": {"temperature": 26.8, "humidity": 65}}"#;
        let mappings = vec![
            AlloydbColumnMapping {
                source_field: "device_id".to_string(),
                db_column: "dev_id".to_string(),
                data_type: Some("TEXT".to_string()),
            },
            AlloydbColumnMapping {
                source_field: "metrics.temperature".to_string(),
                db_column: "temp_celsius".to_string(),
                data_type: Some("NUMERIC".to_string()),
            },
        ];

        let row =
            extract_alloydb_row(payload, "sensors/plant1", &mappings).expect("valid extraction");
        assert_eq!(row.columns.len(), 2);
        assert_eq!(row.columns[0].0, "dev_id");
        assert_eq!(row.columns[0].1, AlloydbValue::String("d-202".into()));
        assert_eq!(row.columns[1].0, "temp_celsius");
        assert_eq!(row.columns[1].1, AlloydbValue::Number(26.8));
    }

    #[test]
    fn test_classify_alloydb_errors() {
        assert_eq!(
            classify_alloydb_error("57P01: terminating connection due to read pool failover"),
            AlloydbErrorClassification::FailoverRetryable
        );
        assert_eq!(
            classify_alloydb_error("57P03: the database system is starting up"),
            AlloydbErrorClassification::FailoverRetryable
        );
        assert_eq!(
            classify_alloydb_error("42703: column \"unknown_col\" does not exist"),
            AlloydbErrorClassification::DataRejected
        );
        assert_eq!(
            classify_alloydb_error("28P01: password authentication failed for user"),
            AlloydbErrorClassification::Terminal
        );
    }

    #[test]
    fn test_json_to_alloydb_primitives() {
        assert_eq!(
            json_to_alloydb_value(&serde_json::Value::Null),
            AlloydbValue::Null
        );
        assert_eq!(
            json_to_alloydb_value(&serde_json::json!(false)),
            AlloydbValue::Boolean(false)
        );
        assert_eq!(
            json_to_alloydb_value(&serde_json::json!(123456789)),
            AlloydbValue::Integer(123456789)
        );
        assert_eq!(
            json_to_alloydb_value(&serde_json::json!(99.95)),
            AlloydbValue::Number(99.95)
        );
        assert_eq!(
            json_to_alloydb_value(&serde_json::json!("alloy-db")),
            AlloydbValue::String("alloy-db".into())
        );
    }

    const TEST_CA_PEM: &str = include_str!("../testdata/ca-cert.pem");
    const TEST_SERVER_CERT_PEM: &str = include_str!("../testdata/server-cert.pem");
    const TEST_SERVER_KEY_PEM: &str = include_str!("../testdata/server-key.pem");

    /// Write `pem` to a unique temp file and return its path. The caller
    /// removes the file when done.
    fn write_temp_ca_file(pem: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "alloydb-test-ca-{}-{}-{}.pem",
            std::process::id(),
            id,
            now_millis_for_test()
        ));
        std::fs::write(&path, pem).expect("write temp CA file");
        path
    }

    fn now_millis_for_test() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }

    fn tls_test_base_config() -> AlloydbConfig {
        AlloydbConfig {
            host: "127.0.0.1".to_string(),
            port: 5432,
            database: "telemetry".to_string(),
            username: "postgres".to_string(),
            auth: AlloydbAuth::Password {
                password: "secret".to_string(),
            },
            table: "readings".to_string(),
            column_mappings: Vec::new(),
            batch_size: Some(1),
            buffer_capacity: None,
            timeout_ms: Some(5000),
            tls: Some(true),
            ca_bundle_pem: None,
            tls_ca_file: None,
        }
    }

    /// Private CA from configuration is trusted: the sink's own TLS
    /// builder (`PgDriverAlloydbTransport::connect_client` path)
    /// completes a handshake with a local endpoint whose certificate is
    /// signed by that CA, then publishes one row through the sink.
    #[tokio::test]
    async fn test_alloydb_tls_trusts_private_ca_from_config_file() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let ca_path = write_temp_ca_file(TEST_CA_PEM);
        let mut config = tls_test_base_config();
        config.tls_ca_file = Some(ca_path.to_string_lossy().to_string());
        config.validate().expect("CA file config validates");

        // Same builder the driver transport uses on every connect.
        let client_config = build_alloydb_tls_config(&config).expect("TLS config with private CA");
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_config));

        let server_config = crate::cloud_tls::test_certs::server_config(
            TEST_SERVER_CERT_PEM,
            TEST_SERVER_KEY_PEM,
            None,
        )
        .expect("test server config");
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept");
            let mut tls = acceptor.accept(tcp).await.expect("tls accept");
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).await.expect("server read");
            assert_eq!(&buf, b"ping");
            tls.write_all(b"pong").await.expect("server write");
        });

        let tcp = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .expect("tcp connect");
        let server_name =
            rustls::pki_types::ServerName::try_from("127.0.0.1".to_string()).expect("server name");
        let mut tls =
            tokio::time::timeout(Duration::from_secs(10), connector.connect(server_name, tcp))
                .await
                .expect("handshake timeout")
                .expect("handshake with private CA succeeds");
        tls.write_all(b"ping").await.expect("client write");
        let mut buf = [0u8; 4];
        tls.read_exact(&mut buf).await.expect("client read");
        assert_eq!(&buf, b"pong");
        tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .expect("server done")
            .expect("server task");

        // The same config also drives a publish through the sink, so the
        // trust path is wired to the broker event, not only to the store.
        let transport = Arc::new(MockAlloydbTransport::new());
        let sink = AlloydbSink::new(config.clone(), transport.clone()).expect("valid sink");
        let topic = Topic::new("sensors/tls-ok").unwrap();
        sink.send(
            &topic,
            &Bytes::from_static(br#"{"device_id":"tls-1"}"#),
            QoS::AtLeastOnce,
        )
        .await
        .expect("sink send with CA config");
        assert_eq!(sink.sent_count(), 1);

        let _ = std::fs::remove_file(&ca_path);
    }

    /// Same endpoint without the private CA is refused: the handshake
    /// fails (or the builder fails closed on an empty store), so a
    /// private endpoint can never be reached on system roots alone.
    #[tokio::test]
    async fn test_alloydb_tls_refuses_private_ca_without_config() {
        let config = tls_test_base_config();
        config.validate().expect("no-CA config validates");

        let server_config = crate::cloud_tls::test_certs::server_config(
            TEST_SERVER_CERT_PEM,
            TEST_SERVER_KEY_PEM,
            None,
        )
        .expect("test server config");
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = tokio::spawn(async move {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            // The client must fail the handshake, so the server side is
            // expected to fail too; ignore either outcome.
            let _ = acceptor.accept(tcp).await;
        });

        match build_alloydb_tls_config(&config) {
            Err(e) => {
                // Fail-closed on an empty store is also a refusal.
                assert!(
                    matches!(e, ConnectorError::Connection(_)),
                    "empty store must fail closed, got {e:?}"
                );
            }
            Ok(client_config) => {
                let connector =
                    tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_config));
                let tcp = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
                    .await
                    .expect("tcp connect");
                let server_name = rustls::pki_types::ServerName::try_from("127.0.0.1".to_string())
                    .expect("server name");
                let res = tokio::time::timeout(
                    Duration::from_secs(10),
                    connector.connect(server_name, tcp),
                )
                .await
                .expect("handshake attempt finishes");
                assert!(res.is_err(), "private CA without config must be refused");
            }
        }
        server.abort();
    }

    #[test]
    fn test_alloydb_ca_config_validation() {
        let mut config = tls_test_base_config();
        config.ca_bundle_pem = Some("not-a-pem".to_string());
        assert!(config.validate().is_err());
        config.ca_bundle_pem = None;
        config.tls_ca_file = Some("   ".to_string());
        assert!(config.validate().is_err());
    }

    #[tokio::test]
    async fn test_alloydb_sink_loopback_success() {
        let cfg = sample_password_config();
        let transport = Arc::new(MockAlloydbTransport::new());
        let sink = AlloydbSink::new(cfg, transport.clone()).expect("valid sink");

        let topic = Topic::new("sensors/temp").unwrap();
        let payload =
            Bytes::from_static(br#"{"device_id": "dev-01", "metrics": {"temperature": 21.5}}"#);

        sink.send(&topic, &payload, QoS::AtLeastOnce)
            .await
            .expect("send succeeds");

        let execs = transport.executions.lock();
        assert_eq!(execs.len(), 1);
        assert!(execs[0]
            .query
            .starts_with("INSERT INTO sensor_telemetry (dev_id, temp_celsius) VALUES ($1, $2)"));
        assert_eq!(execs[0].params.len(), 2);
        assert_eq!(sink.sent_count(), 1);
    }

    #[tokio::test]
    async fn test_alloydb_sink_failover_retry_recovery() {
        let cfg = sample_password_config();
        // 1 transient failover failure, then success
        let transport = Arc::new(MockAlloydbTransport::with_failover(1));
        let sink = AlloydbSink::new(cfg, transport.clone()).expect("valid sink");

        let topic = Topic::new("sensors/temp").unwrap();
        let payload =
            Bytes::from_static(br#"{"device_id": "dev-02", "metrics": {"temperature": 23.0}}"#);

        // First attempt triggers Connection error
        let res = sink.send(&topic, &payload, QoS::AtLeastOnce).await;
        assert!(res.is_err());
        assert!(matches!(res.err().unwrap(), ConnectorError::Connection(_)));

        // Reset backoff and retry flush
        *sink.backoff.lock() = BackoffState::default();
        sink.flush().await.expect("retry flush succeeds");
        assert_eq!(sink.sent_count(), 1);
    }

    #[tokio::test]
    async fn test_alloydb_sink_terminal_error_aborts() {
        let cfg = sample_password_config();
        let transport = Arc::new(MockAlloydbTransport::with_terminal_error(
            "42P01: undefined table",
        ));
        let sink = AlloydbSink::new(cfg, transport.clone()).expect("valid sink");

        let topic = Topic::new("sensors/temp").unwrap();
        let payload =
            Bytes::from_static(br#"{"device_id": "dev-03", "metrics": {"temperature": 25.0}}"#);

        let res = sink.send(&topic, &payload, QoS::AtLeastOnce).await;
        assert!(res.is_err());
        assert!(matches!(res.err().unwrap(), ConnectorError::Dispatch(_)));
    }

    #[tokio::test]
    async fn test_backoff_keeps_buffered_rows() {
        let mut cfg = sample_password_config();
        cfg.batch_size = Some(10);
        let transport = Arc::new(MockAlloydbTransport::with_failover(1));
        let sink = AlloydbSink::new(cfg, transport.clone()).expect("valid sink");

        let topic = Topic::new("sensors/temp").unwrap();
        let payload1 =
            Bytes::from_static(br#"{"device_id": "dev-10", "metrics": {"temperature": 20.0}}"#);
        let payload2 =
            Bytes::from_static(br#"{"device_id": "dev-11", "metrics": {"temperature": 21.0}}"#);

        sink.send(&topic, &payload1, QoS::AtLeastOnce)
            .await
            .expect("buffer first row");
        assert_eq!(sink.buffered_rows(), 1);

        // First flush fails transiently, restores the batch and enters backoff.
        let first = sink.flush().await;
        assert!(first.is_err());
        assert_eq!(sink.buffered_rows(), 1);

        // Still inside the backoff window: flush must fail without dropping rows.
        sink.send(&topic, &payload2, QoS::AtLeastOnce)
            .await
            .expect("buffer second row");
        let second = sink.flush().await;
        assert!(second.is_err());
        assert_eq!(sink.buffered_rows(), 2);

        // After the backoff resets, one flush delivers both rows exactly once.
        *sink.backoff.lock() = BackoffState::default();
        sink.flush().await.expect("retry flush succeeds");
        assert_eq!(sink.buffered_rows(), 0);
        assert_eq!(sink.sent_count(), 2);
        let execs = transport.executions.lock();
        assert_eq!(execs.len(), 2);
        assert_eq!(execs[1].params.len(), 4);
    }

    fn strip_quoted_idents(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut chars = s.chars().peekable();
        let mut in_quotes = false;
        while let Some(c) = chars.next() {
            if in_quotes {
                if c == '"' {
                    if chars.peek() == Some(&'"') {
                        chars.next();
                    } else {
                        in_quotes = false;
                    }
                }
            } else if c == '"' {
                in_quotes = true;
            } else {
                out.push(c);
            }
        }
        out
    }

    #[tokio::test]
    async fn test_mixed_keys_batch_params_aligned() {
        let mut cfg = sample_iam_config();
        cfg.batch_size = Some(10);
        let transport = Arc::new(MockAlloydbTransport::new());
        let sink = AlloydbSink::new(cfg, transport.clone()).expect("valid sink");

        let topic = Topic::new("sensors/mixed").unwrap();
        sink.send(&topic, &Bytes::from_static(br#"{"a":1}"#), QoS::AtLeastOnce)
            .await
            .expect("buffer row 1");
        sink.send(
            &topic,
            &Bytes::from_static(br#"{"b":2,"a":3}"#),
            QoS::AtLeastOnce,
        )
        .await
        .expect("buffer row 2");
        sink.flush().await.expect("flush succeeds");

        let execs = transport.executions.lock();
        assert_eq!(execs.len(), 1);
        assert!(execs[0].query.contains("(a, b)"));
        assert_eq!(
            execs[0].params,
            vec![
                AlloydbValue::Integer(1),
                AlloydbValue::Null,
                AlloydbValue::Integer(3),
                AlloydbValue::Integer(2),
            ]
        );
        assert_eq!(execs[0].query.matches('$').count(), 4);
    }

    #[tokio::test]
    async fn test_hostile_key_is_quoted() {
        let mut cfg = sample_iam_config();
        cfg.batch_size = Some(10);
        let transport = Arc::new(MockAlloydbTransport::new());
        let sink = AlloydbSink::new(cfg, transport.clone()).expect("valid sink");

        let topic = Topic::new("sensors/hostile").unwrap();
        sink.send(
            &topic,
            &Bytes::from_static(br#"{"x) VALUES (1); DROP TABLE t; --": 1}"#),
            QoS::AtLeastOnce,
        )
        .await
        .expect("buffer hostile row");
        sink.flush().await.expect("flush succeeds");

        let execs = transport.executions.lock();
        assert_eq!(execs.len(), 1);
        let hostile = "x) VALUES (1); DROP TABLE t; --";
        let quoted = format!("\"{hostile}\"");
        assert!(execs[0].query.contains(&quoted));
        let stripped = strip_quoted_idents(&execs[0].query);
        assert!(!stripped.contains(hostile));
        assert!(!stripped.contains(';'));
    }

    #[tokio::test]
    async fn test_empty_key_rejected_at_send() {
        let mut cfg = sample_iam_config();
        cfg.batch_size = Some(10);
        let transport = Arc::new(MockAlloydbTransport::new());
        let sink = AlloydbSink::new(cfg, transport.clone()).expect("valid sink");

        let topic = Topic::new("sensors/empty-key").unwrap();
        let res = sink
            .send(&topic, &Bytes::from_static(br#"{"": 1}"#), QoS::AtLeastOnce)
            .await;
        assert!(matches!(res.err().unwrap(), ConnectorError::Dispatch(_)));
        assert_eq!(sink.buffered_rows(), 0);

        sink.send(
            &topic,
            &Bytes::from_static(br#"{"a": 1}"#),
            QoS::AtLeastOnce,
        )
        .await
        .expect("buffer valid row");
        sink.flush().await.expect("flush succeeds");
        assert_eq!(sink.sent_count(), 1);
    }

    #[tokio::test]
    async fn test_empty_object_rejected_at_send() {
        let mut cfg = sample_iam_config();
        cfg.batch_size = Some(10);
        let transport = Arc::new(MockAlloydbTransport::new());
        let sink = AlloydbSink::new(cfg, transport.clone()).expect("valid sink");

        let topic = Topic::new("sensors/empty-obj").unwrap();
        let res = sink
            .send(&topic, &Bytes::from_static(br#"{}"#), QoS::AtLeastOnce)
            .await;
        assert!(matches!(res.err().unwrap(), ConnectorError::Dispatch(_)));
        assert_eq!(sink.buffered_rows(), 0);
    }

    #[test]
    fn test_rows_per_statement() {
        assert_eq!(rows_per_statement(3, 65535), 21845);
        assert_eq!(rows_per_statement(70, 65535), 936);
        assert_eq!(rows_per_statement(70000, 65535), 1);
    }

    #[tokio::test]
    async fn test_flush_splits_into_chunks() {
        let mut cfg = sample_iam_config();
        cfg.batch_size = Some(10);
        let transport = Arc::new(MockAlloydbTransport::new());
        let sink = AlloydbSink::new(cfg, transport.clone()).expect("valid sink");

        let topic = Topic::new("sensors/chunks").unwrap();
        for i in 0..5 {
            let payload = Bytes::from(format!(r#"{{"a":{i},"b":{i}}}"#));
            sink.send(&topic, &payload, QoS::AtLeastOnce)
                .await
                .expect("buffer row");
        }
        sink.flush_with_limit(4).await.expect("flush succeeds");

        let execs = transport.executions.lock();
        assert_eq!(execs.len(), 3);
        assert_eq!(execs[0].params.len(), 4);
        assert_eq!(execs[1].params.len(), 4);
        assert_eq!(execs[2].params.len(), 2);
        assert_eq!(execs[0].query.matches('$').count(), 4);
        assert_eq!(execs[1].query.matches('$').count(), 4);
        assert_eq!(execs[2].query.matches('$').count(), 2);
        assert_eq!(sink.sent_count(), 5);
        assert_eq!(sink.buffered_rows(), 0);
    }

    #[tokio::test]
    async fn test_failed_chunk_restores_only_unsent() {
        let mut cfg = sample_iam_config();
        cfg.batch_size = Some(10);
        let transport = Arc::new(MockAlloydbTransport::new());
        *transport.fail_at.lock() = Some(1);
        let sink = AlloydbSink::new(cfg, transport.clone()).expect("valid sink");

        let topic = Topic::new("sensors/chunks").unwrap();
        for i in 0..5 {
            let payload = Bytes::from(format!(r#"{{"a":{i},"b":{i}}}"#));
            sink.send(&topic, &payload, QoS::AtLeastOnce)
                .await
                .expect("buffer row");
        }
        let res = sink.flush_with_limit(4).await;
        assert!(res.is_err());
        assert_eq!(sink.sent_count(), 2);
        assert_eq!(sink.buffered_rows(), 3);
    }

    #[tokio::test]
    async fn test_bad_row_rejected_rest_sent() {
        let mut cfg = sample_iam_config();
        cfg.batch_size = Some(10);
        let transport = Arc::new(MockAlloydbTransport::with_value_failure(
            AlloydbValue::Integer(13),
            "23514: new row violates check constraint",
        ));
        let sink = AlloydbSink::new(cfg, transport.clone()).expect("valid sink");

        let topic = Topic::new("sensors/bad-row").unwrap();
        for v in [0, 1, 13, 3, 4] {
            let payload = Bytes::from(format!(r#"{{"a":{v},"b":0}}"#));
            sink.send(&topic, &payload, QoS::AtLeastOnce)
                .await
                .expect("buffer row");
        }
        sink.flush().await.expect("flush succeeds with rejection");
        assert_eq!(sink.sent_count(), 4);
        assert_eq!(sink.rejected_rows(), 1);
        assert_eq!(sink.buffered_rows(), 0);
    }

    #[tokio::test]
    async fn test_connection_error_during_row_retry_restores_rest() {
        let mut cfg = sample_iam_config();
        cfg.batch_size = Some(10);
        let transport = Arc::new(MockAlloydbTransport::new());
        *transport.fail_count.lock() = 1;
        *transport.outcome_code.lock() =
            Some("23514: new row violates check constraint".to_string());
        *transport.fail_on_value.lock() = Some(AlloydbValue::Integer(1));
        *transport.fail_on_message.lock() = Some("08006: connection failure".to_string());
        let sink = AlloydbSink::new(cfg, transport.clone()).expect("valid sink");

        let topic = Topic::new("sensors/row-retry").unwrap();
        for i in 0..5 {
            let payload = Bytes::from(format!(r#"{{"a":{i},"b":0}}"#));
            sink.send(&topic, &payload, QoS::AtLeastOnce)
                .await
                .expect("buffer row");
        }
        let res = sink.flush().await;
        assert!(res.is_err());
        assert_eq!(sink.sent_count(), 1);
        assert_eq!(sink.buffered_rows(), 4);
        assert_eq!(sink.rejected_rows(), 0);
    }

    #[test]
    fn test_sqlstate_token_matching() {
        assert_ne!(
            classify_alloydb_error("value 1423514x"),
            AlloydbErrorClassification::DataRejected
        );
        assert_eq!(
            classify_alloydb_error("ERROR: 23514: check"),
            AlloydbErrorClassification::DataRejected
        );
        assert_eq!(
            classify_alloydb_error("42P01"),
            AlloydbErrorClassification::Terminal
        );
    }

    #[test]
    fn test_iam_auto_validates_without_static_secret() {
        let mut cfg = sample_password_config();
        cfg.auth = AlloydbAuth::IamAuto { scopes: vec![] };
        assert!(cfg.validate().is_ok());
        assert_eq!(cfg.credential_secret(), "<adc>");
        assert!(cfg.static_password().is_none());
        assert_eq!(
            AlloydbConfig::iam_scopes(&cfg.auth),
            vec!["https://www.googleapis.com/auth/cloud-platform".to_string()]
        );

        let custom = AlloydbAuth::IamAuto {
            scopes: vec!["https://www.googleapis.com/auth/sqlservice.admin".to_string()],
        };
        assert_eq!(
            AlloydbConfig::iam_scopes(&custom),
            vec!["https://www.googleapis.com/auth/sqlservice.admin".to_string()]
        );
    }

    #[test]
    fn test_tls_defaults_on_and_opts_out() {
        let cfg = sample_password_config();
        assert!(cfg.use_tls());
        let mut plain = sample_iam_config();
        plain.tls = Some(false);
        assert!(!plain.use_tls());
    }

    #[test]
    fn test_connect_config_carries_endpoint() {
        let cfg = sample_password_config();
        let pg = alloydb_connect_config(&cfg, "secret");
        // `tokio-postgres` has no getter for hosts, so assert via debug text
        // plus the typed timeout we set explicitly.
        let dbg = format!("{pg:?}");
        assert!(dbg.contains("10.128.0.5"));
        assert!(dbg.contains("iot_warehouse"));
        assert!(cfg.timeout() == Duration::from_millis(5000));
    }

    #[test]
    fn test_driver_error_text_stays_classifiable() {
        // The driver wrapper prefixes SQLSTATE text; classification must survive it.
        assert_eq!(
            classify_alloydb_error("alloydb driver error: 57P01: terminating connection"),
            AlloydbErrorClassification::FailoverRetryable
        );
        assert_eq!(
            classify_alloydb_error("alloydb driver error: 23514: check violated"),
            AlloydbErrorClassification::DataRejected
        );
    }

    #[tokio::test]
    async fn test_static_password_resolution() {
        let pass = sample_password_config();
        assert_eq!(
            resolve_alloydb_password(&pass).await.expect("password"),
            "SecureDbPassword!"
        );
        let iam = sample_iam_config();
        assert_eq!(
            resolve_alloydb_password(&iam).await.expect("token"),
            "ya29.c.b0AXv0zT...GcpBearerToken"
        );
    }

    /// Qualification against a real PostgreSQL-compatible AlloyDB server.
    ///
    /// Run with e.g.:
    /// `ALLOYDB_HOST=10.128.0.5 ALLOYDB_DATABASE=iot_warehouse
    ///  ALLOYDB_USER=postgres ALLOYDB_PASSWORD=... ALLOYDB_TLS=true \
    ///  cargo test -p broker-connectors --lib alloydb::tests::test_qualify_driver_write_path -- --ignored --nocapture`
    ///
    /// Uses a plain PostgreSQL-compatible instance for the write path
    /// (AlloyDB speaks the same wire protocol). Creates the table, streams
    /// 1000 rows through [`AlloydbSink`] on [`PgDriverAlloydbTransport`],
    /// asserts row count and column types, recreates the sink to simulate a
    /// broker restart, and asserts no duplicates.
    #[tokio::test]
    #[ignore = "needs a real AlloyDB / PostgreSQL-compatible server (see ALLOYDB_* env)"]
    async fn test_qualify_driver_write_path() {
        let host = std::env::var("ALLOYDB_HOST").unwrap_or_else(|_| "127.0.0.1".into());
        let port: u16 = std::env::var("ALLOYDB_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5432);
        let database = std::env::var("ALLOYDB_DATABASE").unwrap_or_else(|_| "postgres".into());
        let username = std::env::var("ALLOYDB_USER").unwrap_or_else(|_| "postgres".into());
        let password = std::env::var("ALLOYDB_PASSWORD").unwrap_or_default();
        if password.is_empty() {
            eprintln!("ALLOYDB_PASSWORD is empty; skipping qualification");
            return;
        }
        let table = std::env::var("ALLOYDB_TABLE").unwrap_or_else(|_| "alloydb_qual_b301".into());
        let use_tls = std::env::var("ALLOYDB_TLS")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let config = AlloydbConfig {
            host: host.clone(),
            port,
            database: database.clone(),
            username: username.clone(),
            auth: AlloydbAuth::Password {
                password: password.clone(),
            },
            table: table.clone(),
            column_mappings: Vec::new(),
            batch_size: Some(100),
            buffer_capacity: None,
            timeout_ms: Some(10_000),
            tls: Some(use_tls),
            ca_bundle_pem: std::env::var("ALLOYDB_CA_PEM").ok(),
            tls_ca_file: std::env::var("ALLOYDB_CA_FILE").ok(),
        };
        config.validate().expect("qual config validates");

        // Direct driver client for DDL and assertions.
        let mut pg = tokio_postgres::Config::new();
        pg.host(&host);
        pg.port(port);
        pg.dbname(&database);
        pg.user(&username);
        pg.password(&password);
        pg.connect_timeout(Duration::from_secs(10));
        let client = if use_tls {
            let tls = alloydb_tls_connector(&config).expect("qual TLS connector");
            let (client, conn) = pg.connect(tls).await.expect("qual connect");
            tokio::spawn(async move {
                let _ = conn.await;
            });
            client
        } else {
            let (client, conn) = pg
                .connect(tokio_postgres::NoTls)
                .await
                .expect("qual connect");
            tokio::spawn(async move {
                let _ = conn.await;
            });
            client
        };
        let server_version: String = client
            .query_one("SELECT version()", &[])
            .await
            .expect("server version")
            .get(0);
        eprintln!("qual server: {server_version}");

        client
            .execute(&format!("DROP TABLE IF EXISTS {table}"), &[])
            .await
            .expect("drop qual table");
        client
            .execute(
                &format!(
                    "CREATE TABLE {table} (device_id TEXT NOT NULL, temp DOUBLE PRECISION NOT NULL, seq BIGINT NOT NULL)"
                ),
                &[],
            )
            .await
            .expect("create qual table");

        let transport = Arc::new(PgDriverAlloydbTransport::new(&config));
        let sink = AlloydbSink::new(config.clone(), transport).expect("qual sink");
        let topic = Topic::new("sensors/qual").unwrap();
        for seq in 0..1000 {
            let payload = Bytes::from(format!(
                r#"{{"device_id":"dev-{seq:04}","temp":{temp},"seq":{seq}}}"#,
                temp = 20.0 + (seq as f64) * 0.01
            ));
            sink.send(&topic, &payload, QoS::AtLeastOnce)
                .await
                .expect("qual send");
        }
        sink.flush().await.expect("qual flush");
        assert_eq!(sink.sent_count(), 1000);

        let count: i64 = client
            .query_one(&format!("SELECT COUNT(*) FROM {table}"), &[])
            .await
            .expect("qual count")
            .get(0);
        assert_eq!(count, 1000);

        let row = client
            .query_one(
                &format!("SELECT device_id, temp, seq FROM {table} WHERE seq = 424"),
                &[],
            )
            .await
            .expect("qual sample");
        let device: String = row.get(0);
        let temp: f64 = row.get(1);
        let seq: i64 = row.get(2);
        assert_eq!(device, "dev-0424");
        assert_eq!(seq, 424);
        assert!((temp - 24.24).abs() < 0.001);

        // Simulate a broker restart: a fresh sink must not duplicate rows.
        drop(sink);
        let transport2 = Arc::new(PgDriverAlloydbTransport::new(&config));
        let sink2 = AlloydbSink::new(config, transport2).expect("qual sink2");
        sink2.flush().await.expect("post-restart flush is a no-op");
        let count2: i64 = client
            .query_one(&format!("SELECT COUNT(*) FROM {table}"), &[])
            .await
            .expect("qual recount")
            .get(0);
        assert_eq!(count2, 1000);

        client
            .execute(&format!("DROP TABLE {table}"), &[])
            .await
            .expect("qual cleanup");
    }
}
