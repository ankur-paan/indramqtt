//! TimescaleDB hypertable sink (INDRA-171).
//!
//! Buffers MQTT events as 4-column rows (`$1` time, `$2` device id,
//! `$3` topic, `$4` metrics JSONB) and flushes full or stale batches
//! through the maintained `tokio-postgres` driver with a `rustls` TLS
//! connector ([`DriverTimescaleDbTransport`]) — TimescaleDB is
//! wire-compatible with PostgreSQL, so values travel bound out-of-band
//! through the driver's extended-protocol path and SQL injection is
//! structurally impossible. The template carries UPSERT conflict
//! resolution, e.g.
//! `INSERT INTO sensor_metrics (time, device_id, topic, metrics)
//! VALUES ($1, $2, $3, $4::jsonb) ON CONFLICT (time, device_id)
//! DO UPDATE SET metrics = EXCLUDED.metrics`.
//!
//! Batching, restore-on-failure and backoff reuse the shared
//! [`super::BatchQueue`] / [`super::BackoffState`] helpers.
//! [`TcpTimescaleTransport`] is the hand-written framing retained for
//! offline unit tests only; production wiring uses the driver transport.

use async_trait::async_trait;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::{
    now_millis, rfc3339_millis, BackoffState, BatchQueue, ConnectorError, PgBatch, PgTransport,
    Result, Sink, TcpPgTransport,
};

fn default_time_column() -> String {
    "time".to_string()
}

fn default_pool_size() -> usize {
    10
}

fn default_batch_size() -> usize {
    200
}

fn default_batch_timeout_ms() -> u64 {
    50
}

fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// TimescaleDB sink configuration. Every depth is user-configurable
/// with no clamped ceiling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimescaleDbSinkConfig {
    /// PostgreSQL connection URL, e.g.
    /// `postgresql://user:pass@host:5432/timeseries`.
    pub connection_url: String,
    /// Target hypertable, e.g. `sensor_metrics`.
    pub hypertable: String,
    /// Time partition column (default `time`).
    #[serde(default = "default_time_column")]
    pub time_column: String,
    /// Prepared SQL referencing exactly `$1` (time), `$2` (device id),
    /// `$3` (topic) and `$4` (metrics JSONB), with UPSERT resolution.
    pub sql_template: String,
    /// Max connection pool size (default 10). The pool holds at most
    /// `pool_size` driver clients plus the sink buffer in front of it;
    /// no background queue. The default is finite because an unbounded
    /// pool under fan-in would repeat the multi-GB RSS collapse the v4
    /// benchmark measured on this path.
    #[serde(default = "default_pool_size")]
    pub pool_size: usize,
    /// Batch insert buffer size (default 200). Bounds buffered rows per
    /// sink so per-sink memory stays finite under slow-server backoff;
    /// 200 rows of 4 small columns keep one flush well under a
    /// millisecond of server time while capping memory per sink.
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    /// Linger flush window (default 50 ms).
    #[serde(default = "default_batch_timeout_ms")]
    pub batch_timeout_ms: u64,
}

impl TimescaleDbSinkConfig {
    pub fn validate(&self) -> Result<()> {
        if !self.connection_url.starts_with("postgresql://")
            && !self.connection_url.starts_with("postgres://")
        {
            return Err(ConnectorError::Dispatch(format!(
                "timescaledb connection_url must be postgresql://: {:?}",
                redact_url(&self.connection_url)
            )));
        }
        if !is_identifier(&self.hypertable) {
            return Err(ConnectorError::Dispatch(format!(
                "timescaledb hypertable must match [A-Za-z0-9_]+: {:?}",
                self.hypertable
            )));
        }
        if !is_identifier(&self.time_column) {
            return Err(ConnectorError::Dispatch(format!(
                "timescaledb time_column must match [A-Za-z0-9_]+: {:?}",
                self.time_column
            )));
        }
        let mut referenced = super::postgres::referenced_params(&self.sql_template)?;
        referenced.sort_unstable();
        referenced.dedup();
        if referenced != vec![1, 2, 3, 4] {
            return Err(ConnectorError::Dispatch(format!(
                "timescaledb sql_template must reference exactly $1 (time), $2 (device_id), \
                 $3 (topic) and $4 (metrics), got {referenced:?}"
            )));
        }
        if self.pool_size == 0 {
            return Err(ConnectorError::Dispatch(
                "timescaledb pool_size must be >= 1".to_string(),
            ));
        }
        if self.batch_size == 0 {
            return Err(ConnectorError::Dispatch(
                "timescaledb batch_size must be >= 1".to_string(),
            ));
        }
        Ok(())
    }
}

/// Redact any password before echoing a URL in errors.
fn redact_url(url: &str) -> String {
    match url.split_once('@') {
        Some((_, rest)) => format!("postgresql://***@{rest}"),
        None => url.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Transport (TimescaleDB speaks the PostgreSQL wire protocol).
// ---------------------------------------------------------------------------

/// One flushed batch: the UPSERT statement plus one 4-column row per
/// event (time, device id, topic, metrics JSONB, all text-encoded).
#[derive(Debug, Clone, Default)]
pub struct TimescaleBatch {
    pub sql: String,
    pub rows: Vec<Vec<Vec<u8>>>,
}

#[async_trait]
pub trait TimescaleDbTransport: Send + Sync {
    async fn execute_batch(&self, batch: &TimescaleBatch) -> Result<()>;
}

/// In-memory transport recording every flushed batch (tests, dry runs).
#[derive(Debug, Default)]
pub struct MockTimescaleTransport {
    batches: parking_lot::Mutex<Vec<TimescaleBatch>>,
    failures_left: parking_lot::Mutex<usize>,
    calls: AtomicU64,
}

impl MockTimescaleTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fail the next `n` executions with a transport error (backoff tests).
    pub fn fail_next(&self, n: usize) {
        *self.failures_left.lock() = n;
    }

    pub fn batches(&self) -> Vec<TimescaleBatch> {
        self.batches.lock().clone()
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl TimescaleDbTransport for MockTimescaleTransport {
    async fn execute_batch(&self, batch: &TimescaleBatch) -> Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut failures = self.failures_left.lock();
        if *failures > 0 {
            *failures -= 1;
            return Err(ConnectorError::Connection(
                "mock timescaledb down".to_string(),
            ));
        }
        self.batches.lock().push(batch.clone());
        Ok(())
    }
}

/// TCP transport delegating batches to the shared PostgreSQL extended
/// protocol driver (same wire format TimescaleDB expects). Retained for
/// offline unit tests only; production wiring uses
/// [`DriverTimescaleDbTransport`] on the maintained `tokio-postgres`
/// driver.
pub struct TcpTimescaleTransport {
    inner: TcpPgTransport,
}

impl TcpTimescaleTransport {
    pub fn new(url: &str, pool_size: usize) -> Result<Self> {
        Ok(Self {
            inner: TcpPgTransport::new(url, pool_size)?,
        })
    }
}

#[async_trait]
impl TimescaleDbTransport for TcpTimescaleTransport {
    async fn execute_batch(&self, batch: &TimescaleBatch) -> Result<()> {
        PgTransport::execute_batch(
            &self.inner,
            &PgBatch {
                sql: batch.sql.clone(),
                rows: batch.rows.clone(),
            },
        )
        .await
    }
}

// ---------------------------------------------------------------------------
// Production transport on the maintained `tokio-postgres` driver.
// ---------------------------------------------------------------------------

/// Checkout timeout for one driver connection: 5 s matches the legacy
/// [`TcpPgTransport`] dial timeout (the protocol requirement is a
/// bounded handshake, not a specific value).
const TS_DRIVER_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Per-batch statement timeout: 10 s matches the legacy `read_msg`
/// timeout on the same path.
const TS_DRIVER_STATEMENT_TIMEOUT: Duration = Duration::from_secs(10);

/// Split `postgresql://[user[:password]@]host[:port][/dbname][?params]`
/// into (host, port, user, password, database, use_tls). Both the
/// `postgresql://` and the `postgres://` spellings are accepted so
/// stored configuration written with either spelling keeps working.
fn parse_ts_driver_endpoint(url: &str) -> Result<(String, u16, String, String, String, bool)> {
    let rest = url
        .strip_prefix("postgresql://")
        .or_else(|| url.strip_prefix("postgres://"))
        .ok_or_else(|| {
            ConnectorError::Dispatch(format!(
                "timescaledb url must start with postgresql://: {:?}",
                redact_url(url)
            ))
        })?;
    let (authority_path, query) = match rest.split_once('?') {
        Some((left, query)) => (left, query),
        None => (rest, ""),
    };
    // Plaintext unless the stored URL explicitly asks for TLS. Stored
    // configuration carries no TLS expectation, so an explicit
    // `sslmode=require` (or `verify-ca` / `verify-full`) opts into
    // `rustls` instead of failing against a TLS-demanding server.
    // TODO(parity): should a missing `sslmode` fail closed to TLS
    // instead of plaintext? Plaintext preserves stored-config
    // compatibility; a server that demands TLS still refuses the
    // handshake, so nothing is silently downgraded.
    let mut use_tls = false;
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key.eq_ignore_ascii_case("sslmode")
            && (value.eq_ignore_ascii_case("require")
                || value.eq_ignore_ascii_case("verify-ca")
                || value.eq_ignore_ascii_case("verify-full"))
        {
            use_tls = true;
        }
    }
    let (authority, dbname) = match authority_path.split_once('/') {
        Some((authority, dbname)) => (authority, dbname),
        None => (authority_path, ""),
    };
    let (credentials, hostport) = match authority.rsplit_once('@') {
        Some((credentials, hostport)) => (credentials, hostport),
        None => ("", authority),
    };
    let (user, password) = match credentials.split_once(':') {
        Some((user, pass)) => (user.to_string(), pass.to_string()),
        None => (credentials.to_string(), String::new()),
    };
    let user = if user.is_empty() {
        "postgres".to_string()
    } else {
        user
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((host, port)) => (
            host.to_string(),
            port.parse::<u16>().map_err(|_| {
                ConnectorError::Dispatch(format!("timescaledb bad port in {:?}", redact_url(url)))
            })?,
        ),
        None => (hostport.to_string(), 5432),
    };
    if host.is_empty() {
        return Err(ConnectorError::Dispatch(format!(
            "timescaledb url needs a host: {:?}",
            redact_url(url)
        )));
    }
    let database = if dbname.is_empty() {
        user.clone()
    } else {
        dbname.to_string()
    };
    Ok((host, port, user, password, database, use_tls))
}

/// Build a `tokio-postgres` connection config from parsed endpoint
/// fields. Field-by-field construction (never the driver's own URL
/// parser) so the default port stays 5432 and `sslmode` handling stays
/// in [`parse_ts_driver_endpoint`].
fn ts_connect_config(
    host: &str,
    port: u16,
    user: &str,
    password: &str,
    database: &str,
) -> tokio_postgres::Config {
    // TODO(parity): the password travels percent-encoded in a URL but
    // is used verbatim here; does any stored configuration rely on
    // encoded characters that must be decoded first?
    let mut cfg = tokio_postgres::Config::new();
    cfg.host(host);
    cfg.port(port);
    cfg.dbname(database);
    cfg.user(user);
    if !password.is_empty() {
        cfg.password(password);
    }
    cfg.connect_timeout(TS_DRIVER_CONNECT_TIMEOUT);
    cfg
}

/// True for SQLSTATEs that mean the session is gone or must retry, not
/// that a row was bad: class `08` (connection exception), `57P01`
/// (admin shutdown) / `57P02` (crash shutdown) / `57P03` (cannot
/// connect now), `40001` (serialization failure) and `40P01`
/// (deadlock). The reason is written here because the sink treats the
/// two classes oppositely: `Connection` restores the batch and backs
/// off, `Dispatch` drops the row and counts it rejected.
fn is_ts_retryable_sqlstate(code: &str) -> bool {
    code.starts_with("08") || matches!(code, "57P01" | "57P02" | "57P03" | "40001" | "40P01")
}

/// Map a `tokio-postgres` error onto [`ConnectorError`], preserving the
/// SQLSTATE text so data rejections (class `22`/`23`, `42703`,
/// `42804`) stay `Dispatch` for the sink's per-row isolation.
fn map_ts_driver_error(err: &tokio_postgres::Error) -> ConnectorError {
    let mut detail = err.to_string();
    let mut code_text: Option<String> = None;
    if let Some(db) = err.as_db_error() {
        let code_str = db.code().code().to_string();
        code_text = Some(code_str.clone());
        let message = db.message();
        detail = format!("{code_str}: {message}");
    }
    if let Some(code) = code_text {
        if is_ts_retryable_sqlstate(&code) {
            return ConnectorError::Connection(format!("timescaledb driver error: {detail}"));
        }
        return ConnectorError::Dispatch(format!("timescaledb driver error: {detail}"));
    }
    ConnectorError::Connection(format!("timescaledb driver error: {detail}"))
}

fn install_ts_tls_provider() {
    // The TLS connector below needs a process-default crypto provider.
    // The workspace enables exactly one rustls provider (`aws-lc-rs` via
    // the default features), so installing it explicitly is a no-op when
    // already installed and keeps the call safe under feature
    // unification.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Root store for driver TLS: the OS system trust store. Fail closed
/// when nothing trusted anything: no bundled fallback, so an
/// unreachable system store denies the connection instead of silently
/// trusting a stale list.
fn ts_root_store() -> Result<rustls::RootCertStore> {
    let mut store = rustls::RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        let _ = store.add(cert);
    }
    if !native.errors.is_empty() {
        tracing::warn!(
            errors = native.errors.len(),
            "timescaledb system trust store reported load errors"
        );
    }
    if store.is_empty() {
        return Err(ConnectorError::Connection(
            "timescaledb TLS trust store is empty: system store unreadable".into(),
        ));
    }
    Ok(store)
}

/// TLS connector for the `tokio-postgres` driver built from the system
/// trust store.
fn ts_tls_connector() -> Result<tokio_postgres_rustls::MakeRustlsConnect> {
    install_ts_tls_provider();
    let roots = ts_root_store()?;
    let tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(tokio_postgres_rustls::MakeRustlsConnect::new(tls))
}

/// Decode one buffered row column as TEXT for the driver. A column that
/// is not valid UTF-8 surfaces SQLSTATE `22021` (character not in
/// repertoire, class `22`) so the row counts rejected instead of being
/// restored forever.
// TODO(parity): binary (non-UTF-8) payloads cannot travel as TEXT
// parameters; is BYTEA binding (with a server-side cast) the correct
// mapping, or must such rows stay rejected as here?
fn ts_text_column(row: &[Vec<u8>], index: usize, name: &str) -> Result<String> {
    let bytes = row.get(index).cloned().unwrap_or_default();
    String::from_utf8(bytes).map_err(|_| {
        ConnectorError::Dispatch(format!(
            "timescaledb driver error: 22021: {name} is not valid UTF-8"
        ))
    })
}

/// Days from the civil date using Howard Hinnant's forward algorithm
/// (proleptic Gregorian, UTC), the inverse of the `ymd_from_millis`
/// split the sink's clock uses to render `$1`.
fn ts_days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = ((m + 9) % 12) as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Parse the sink's `$1` clock text (`YYYY-MM-DDTHH:MM:SS.sssZ`, exactly
/// what the sink's RFC 3339 millis clock renders) back to a `SystemTime` for
/// TIMESTAMPTZ/TIMESTAMP binding. Unparseable input is a `Dispatch`
/// data error (SQLSTATE `22008`, class `22`) so the row counts
/// rejected instead of restoring forever.
fn parse_ts_time(text: &str) -> Result<std::time::SystemTime> {
    let invalid = || {
        ConnectorError::Dispatch(format!(
            "timescaledb driver error: 22008: time is not RFC 3339 millis: {text:?}"
        ))
    };
    let bytes = text.as_bytes();
    if bytes.len() != 24 {
        return Err(invalid());
    }
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'.'
        || bytes[23] != b'Z'
    {
        return Err(invalid());
    }
    let num = |lo: usize, hi: usize| -> Result<i64> {
        // `str::get` (never slicing) so non-ASCII input is a data error,
        // never a panic on a char boundary.
        text.get(lo..hi)
            .and_then(|s| s.parse::<i64>().ok())
            .ok_or_else(invalid)
    };
    let year = num(0, 4)?;
    let month = num(5, 7)?;
    let day = num(8, 10)?;
    let hour = num(11, 13)?;
    let minute = num(14, 16)?;
    let second = num(17, 19)?;
    let milli = num(20, 23)?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
        || milli > 999
    {
        return Err(invalid());
    }
    let days = ts_days_from_civil(year, month as u32, day as u32);
    let millis = days * 86_400_000 + hour * 3_600_000 + minute * 60_000 + second * 1_000 + milli;
    if millis < 0 {
        return Err(invalid());
    }
    Ok(std::time::UNIX_EPOCH + Duration::from_millis(millis as u64))
}

/// `$1` (time) bound parameter. The sink buffers the clock as RFC 3339
/// millis text, but the hypertable's time column is TIMESTAMPTZ, so a
/// plain `String` binding fails client-side (`error serializing
/// parameter 0`, no SQLSTATE, mapped to `Connection`). This wrapper
/// encodes per the server-inferred type: `SystemTime` binary for
/// TIMESTAMPTZ/TIMESTAMP, days-since-2000 for DATE, raw text otherwise.
#[derive(Debug)]
struct TsTimeParam {
    text: String,
    when: std::time::SystemTime,
}

impl tokio_postgres::types::ToSql for TsTimeParam {
    fn to_sql(
        &self,
        ty: &tokio_postgres::types::Type,
        out: &mut bytes::BytesMut,
    ) -> std::result::Result<tokio_postgres::types::IsNull, Box<dyn std::error::Error + Sync + Send>>
    {
        use tokio_postgres::types::{IsNull, Type};
        match *ty {
            Type::TIMESTAMPTZ | Type::TIMESTAMP => {
                <std::time::SystemTime as tokio_postgres::types::ToSql>::to_sql(&self.when, ty, out)
            }
            Type::DATE => {
                let millis = self
                    .when
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as i64)
                    .unwrap_or(0);
                // PostgreSQL DATE binary is days since 2000-01-01;
                // 1970-01-01 to 2000-01-01 is 10957 days (30 years with
                // 7 leap days), so pre-2000 dates stay representable.
                let days = (millis.div_euclid(86_400_000) - 10_957) as i32;
                out.extend_from_slice(&days.to_be_bytes());
                Ok(IsNull::No)
            }
            _ => {
                out.extend_from_slice(self.text.as_bytes());
                Ok(IsNull::No)
            }
        }
    }

    fn accepts(ty: &tokio_postgres::types::Type) -> bool {
        use tokio_postgres::types::Type;
        matches!(
            *ty,
            Type::TIMESTAMPTZ
                | Type::TIMESTAMP
                | Type::DATE
                | Type::VARCHAR
                | Type::TEXT
                | Type::BPCHAR
                | Type::NAME
                | Type::UNKNOWN
        )
    }

    fn to_sql_checked(
        &self,
        ty: &tokio_postgres::types::Type,
        out: &mut bytes::BytesMut,
    ) -> std::result::Result<tokio_postgres::types::IsNull, Box<dyn std::error::Error + Sync + Send>>
    {
        if !<Self as tokio_postgres::types::ToSql>::accepts(ty) {
            return Err(format!("timescaledb time parameter has no binding for {ty}").into());
        }
        <Self as tokio_postgres::types::ToSql>::to_sql(self, ty, out)
    }
}

/// `$4` (metrics) bound parameter: the sink buffers the JSON document
/// bytes, but the server may expect JSON/JSONB (`$4::jsonb`) or text.
/// The driver's `String` binding only accepts TEXT-like server types,
/// so a JSONB target fails client-side before the statement reaches the
/// server. This wrapper accepts both families: JSONB targets get the
/// binary encoding (version byte `1` plus the JSON document), every
/// other target gets the raw text.
#[derive(Debug)]
struct TsMetricsParam(String);

impl tokio_postgres::types::ToSql for TsMetricsParam {
    fn to_sql(
        &self,
        ty: &tokio_postgres::types::Type,
        out: &mut bytes::BytesMut,
    ) -> std::result::Result<tokio_postgres::types::IsNull, Box<dyn std::error::Error + Sync + Send>>
    {
        use tokio_postgres::types::{IsNull, Type};
        match *ty {
            Type::JSONB => {
                out.extend_from_slice(&[1u8]);
                out.extend_from_slice(self.0.as_bytes());
                Ok(IsNull::No)
            }
            _ => {
                out.extend_from_slice(self.0.as_bytes());
                Ok(IsNull::No)
            }
        }
    }

    fn accepts(ty: &tokio_postgres::types::Type) -> bool {
        use tokio_postgres::types::Type;
        matches!(
            *ty,
            Type::JSON
                | Type::JSONB
                | Type::VARCHAR
                | Type::TEXT
                | Type::BPCHAR
                | Type::NAME
                | Type::UNKNOWN
                | Type::BYTEA
        ) || matches!(ty.name(), "citext")
    }

    fn to_sql_checked(
        &self,
        ty: &tokio_postgres::types::Type,
        out: &mut bytes::BytesMut,
    ) -> std::result::Result<tokio_postgres::types::IsNull, Box<dyn std::error::Error + Sync + Send>>
    {
        if !<Self as tokio_postgres::types::ToSql>::accepts(ty) {
            return Err(format!("timescaledb metrics parameter has no binding for {ty}").into());
        }
        <Self as tokio_postgres::types::ToSql>::to_sql(self, ty, out)
    }
}

/// Production TimescaleDB transport on the maintained `tokio-postgres`
/// driver (MIT) with a `rustls` TLS connector (system trust store) when
/// the URL opts in via `sslmode=require`, plaintext otherwise. Startup,
/// MD5 and SCRAM-SHA-256 authentication and the extended query protocol
/// (Parse/Bind/Describe/Execute/Sync) all run inside the driver;
/// parameters travel bound (`$1` time, `$2` device id, `$3` topic,
/// `$4` metrics JSONB), so values stay out-of-band exactly as on the
/// legacy path. The legacy [`TcpTimescaleTransport`] stays for offline
/// unit tests only; production wiring uses this transport.
///
/// Bound: the pool holds at most `pool_size` driver clients plus the
/// sink buffer in front of it; no background queue. `pool_size`
/// carries the configured default 10 (`default_pool_size`): the
/// default is finite because an unbounded pool under fan-in would
/// repeat the multi-GB RSS collapse the v4 benchmark measured on this
/// path.
pub struct DriverTimescaleDbTransport {
    pg_config: tokio_postgres::Config,
    use_tls: bool,
    pool: Vec<tokio::sync::Mutex<Option<tokio_postgres::Client>>>,
    cursor: AtomicU64,
}

impl DriverTimescaleDbTransport {
    pub fn new(url: &str, pool_size: usize) -> Result<Self> {
        if pool_size == 0 {
            return Err(ConnectorError::Dispatch(
                "timescaledb pool_size must be >= 1".to_string(),
            ));
        }
        let (host, port, user, password, database, use_tls) = parse_ts_driver_endpoint(url)?;
        Ok(Self {
            pg_config: ts_connect_config(&host, port, &user, &password, &database),
            use_tls,
            pool: (0..pool_size)
                .map(|_| tokio::sync::Mutex::new(None))
                .collect(),
            cursor: AtomicU64::new(0),
        })
    }

    async fn dial(&self) -> Result<tokio_postgres::Client> {
        if self.use_tls {
            let tls = ts_tls_connector()?;
            let connect = self.pg_config.connect(tls);
            let (client, connection) = tokio::time::timeout(TS_DRIVER_CONNECT_TIMEOUT, connect)
                .await
                .map_err(|_| ConnectorError::Connection("timescaledb connect timeout".to_string()))?
                .map_err(|e| {
                    ConnectorError::Connection(format!("timescaledb connect failed: {e}"))
                })?;
            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    tracing::warn!(error = %e, "timescaledb driver connection closed");
                }
            });
            Ok(client)
        } else {
            let connect = self.pg_config.connect(tokio_postgres::NoTls);
            let (client, connection) = tokio::time::timeout(TS_DRIVER_CONNECT_TIMEOUT, connect)
                .await
                .map_err(|_| ConnectorError::Connection("timescaledb connect timeout".to_string()))?
                .map_err(|e| {
                    ConnectorError::Connection(format!("timescaledb connect failed: {e}"))
                })?;
            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    tracing::warn!(error = %e, "timescaledb driver connection closed");
                }
            });
            Ok(client)
        }
    }

    /// Execute one row's bound parameters through the driver's
    /// extended-protocol path.
    async fn execute_row(
        client: &tokio_postgres::Client,
        sql: &str,
        row: &[Vec<u8>],
    ) -> Result<()> {
        // The sink always buffers exactly four values (time, device id,
        // topic, metrics); the empty default keeps a hand-built batch
        // total instead of panicking.
        let time_text = ts_text_column(row, 0, "time")?;
        let when = parse_ts_time(&time_text)?;
        let time = TsTimeParam {
            text: time_text,
            when,
        };
        let device_id = ts_text_column(row, 1, "device_id")?;
        let topic = ts_text_column(row, 2, "topic")?;
        let metrics = TsMetricsParam(ts_text_column(row, 3, "metrics")?);
        // PERF(parity): one extended-protocol round trip per row; the
        // fast version would pack the batch into a single multi-row
        // VALUES list. Kept per-row so a bad row fails alone and the
        // sink's row-by-row isolation keeps working.
        let refs: &[&(dyn tokio_postgres::types::ToSql + Sync)] =
            &[&time, &device_id, &topic, &metrics];
        tokio::time::timeout(TS_DRIVER_STATEMENT_TIMEOUT, client.execute(sql, refs))
            .await
            .map_err(|_| ConnectorError::Connection("timescaledb query timeout".to_string()))?
            .map(|_| ())
            .map_err(|e| map_ts_driver_error(&e))
    }

    async fn execute_rows(
        client: &tokio_postgres::Client,
        sql: &str,
        rows: &[Vec<Vec<u8>>],
    ) -> Result<()> {
        for row in rows {
            Self::execute_row(client, sql, row).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl TimescaleDbTransport for DriverTimescaleDbTransport {
    async fn execute_batch(&self, batch: &TimescaleBatch) -> Result<()> {
        if batch.rows.is_empty() {
            return Ok(());
        }
        // Round-robin checkout with reconnect-once for I/O failures. A
        // server data error (Dispatch) leaves the connection healthy,
        // so it is kept and nothing is replayed; a connection failure
        // drops the slot and the batch is retried once on a fresh
        // client, which is also what recovers a killed backend.
        let slot = (self.cursor.fetch_add(1, Ordering::SeqCst) as usize) % self.pool.len();
        let mut guard = self.pool[slot].lock().await;
        let mut last_error: Option<ConnectorError> = None;
        for _ in 0..2 {
            if guard.is_none() {
                *guard = Some(self.dial().await?);
            }
            let client = guard.as_ref().expect("connected");
            match Self::execute_rows(client, &batch.sql, &batch.rows).await {
                Ok(()) => return Ok(()),
                Err(ConnectorError::Connection(message)) => {
                    *guard = None;
                    last_error = Some(ConnectorError::Connection(message));
                }
                Err(other) => return Err(other),
            }
        }
        Err(match last_error {
            Some(ConnectorError::Connection(message)) => ConnectorError::Connection(format!(
                "timescaledb batch failed after reconnect: {message}"
            )),
            Some(other) => other,
            None => {
                ConnectorError::Connection("timescaledb batch failed after reconnect".to_string())
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Sink.
// ---------------------------------------------------------------------------

/// TimescaleDB sink: buffers 4-column hypertable rows, flushes batches.
pub struct TimescaleDbSink {
    config: TimescaleDbSinkConfig,
    transport: Arc<dyn TimescaleDbTransport>,
    buffer: parking_lot::Mutex<BatchQueue<Vec<Vec<u8>>>>,
    backoff: parking_lot::Mutex<BackoffState>,
    sent_batches: AtomicU64,
}

impl TimescaleDbSink {
    pub fn new(
        config: TimescaleDbSinkConfig,
        transport: Arc<dyn TimescaleDbTransport>,
    ) -> Result<Self> {
        config.validate()?;
        let linger = Duration::from_millis(config.batch_timeout_ms);
        Ok(Self {
            buffer: parking_lot::Mutex::new(BatchQueue::new(config.batch_size, linger)),
            config,
            transport,
            backoff: parking_lot::Mutex::new(BackoffState::default()),
            sent_batches: AtomicU64::new(0),
        })
    }

    pub fn config(&self) -> &TimescaleDbSinkConfig {
        &self.config
    }

    pub fn sent_batches(&self) -> u64 {
        self.sent_batches.load(Ordering::Relaxed)
    }

    pub fn buffered_rows(&self) -> usize {
        self.buffer.lock().len()
    }

    /// Flush buffered rows as one batch (no-op when empty). While
    /// backing off, fails fast without touching the transport. Any
    /// failure restores the buffer, engages backoff, and propagates.
    pub async fn flush(&self) -> Result<()> {
        self.backoff.lock().check()?;
        let (rows, oldest) = self.buffer.lock().take_batch();
        if rows.is_empty() {
            return Ok(());
        }
        let batch = TimescaleBatch {
            sql: self.config.sql_template.clone(),
            rows,
        };
        match self.transport.execute_batch(&batch).await {
            Ok(()) => {
                self.backoff.lock().success();
                self.sent_batches.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                self.buffer.lock().restore(batch.rows, oldest);
                self.backoff.lock().failure();
                Err(e)
            }
        }
    }

    /// Build one 4-column row: RFC 3339 time, device id (JSON
    /// `device_id` field or the topic), topic, metrics JSONB (payload
    /// verbatim when valid JSON, JSON string otherwise). QoS rides
    /// inside the metrics document, not its own column.
    fn buffer_row(&self, topic: &Topic, payload: &Bytes, _qos: QoS) -> Result<bool> {
        if topic.as_str().is_empty() {
            return Err(ConnectorError::Dispatch(
                "timescaledb row requires a non-empty topic".to_string(),
            ));
        }
        let text = std::str::from_utf8(payload).map_err(|_| {
            ConnectorError::Dispatch("timescaledb payload must be UTF-8".to_string())
        })?;
        let value: serde_json::Value = match serde_json::from_str(text) {
            Ok(value) => value,
            Err(_) => serde_json::Value::String(text.to_string()),
        };
        let device_id = match value.get("device_id") {
            Some(serde_json::Value::String(id)) => id.clone().into_bytes(),
            Some(scalar) if scalar.is_number() || scalar.is_boolean() => {
                scalar.to_string().into_bytes()
            }
            _ => topic.as_str().as_bytes().to_vec(),
        };
        let metrics = serde_json::to_vec(&value).map_err(|e| {
            ConnectorError::Dispatch(format!("timescaledb metrics encode failed: {e}"))
        })?;
        Ok(self.buffer.lock().push(vec![
            rfc3339_millis(now_millis()).into_bytes(),
            device_id,
            topic.as_str().as_bytes().to_vec(),
            metrics,
        ]))
    }
}

#[async_trait]
impl Sink for TimescaleDbSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        if self.buffer_row(topic, payload, qos)? {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "timescaledb"
    }
}

/// Management connector handle pairing an id with a TimescaleDB sink.
pub struct TimescaleDbConnector {
    id: String,
    sink: Arc<TimescaleDbSink>,
}

impl TimescaleDbConnector {
    pub fn new(id: impl Into<String>, sink: Arc<TimescaleDbSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }
}

impl super::Connector for TimescaleDbConnector {
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
    use crate::Sink;

    fn test_config() -> TimescaleDbSinkConfig {
        TimescaleDbSinkConfig {
            connection_url: "postgresql://user:pass@127.0.0.1:5432/timeseries".to_string(),
            hypertable: "sensor_metrics".to_string(),
            time_column: "time".to_string(),
            sql_template: "INSERT INTO sensor_metrics (time, device_id, topic, metrics) \
                 VALUES ($1, $2, $3, $4::jsonb) \
                 ON CONFLICT (time, device_id) DO UPDATE SET metrics = EXCLUDED.metrics"
                .to_string(),
            pool_size: 10,
            batch_size: 200,
            batch_timeout_ms: 50,
        }
    }

    #[test]
    fn test_config_validation() {
        let mut config = test_config();
        assert!(config.validate().is_ok());

        config.connection_url = "mysql://u:p@h/db".to_string();
        assert!(config.validate().is_err());
        config.connection_url = test_config().connection_url;

        for bad in ["has space", "with;drop", "schema.table", ""] {
            config.hypertable = bad.to_string();
            assert!(config.validate().is_err(), "hypertable {bad:?} must fail");
        }
        config.hypertable = "sensor_metrics".to_string();

        config.time_column = "time; DROP TABLE x;".to_string();
        assert!(config.validate().is_err());
        config.time_column = "time".to_string();

        config.sql_template = "INSERT INTO t VALUES ($1, $2, $3, $5)".to_string();
        assert!(config.validate().is_err());
        config.sql_template = "INSERT INTO t VALUES ($1, $2, $3)".to_string();
        assert!(config.validate().is_err(), "missing $4 must fail");
        config.sql_template = test_config().sql_template;

        config.pool_size = 0;
        assert!(config.validate().is_err());
        config.pool_size = 10;

        config.batch_size = 0;
        assert!(config.validate().is_err());
        // Zero clamped ceilings: huge depths are accepted.
        config.batch_size = 10_000_000;
        assert!(config.validate().is_ok());
    }

    #[tokio::test]
    async fn test_hypertable_parameter_binding() {
        let transport = Arc::new(MockTimescaleTransport::new());
        let mut config = test_config();
        config.batch_size = 10;
        let sink = TimescaleDbSink::new(config.clone(), transport.clone()).unwrap();

        sink.send(
            &Topic::new("sensors/kitchen").unwrap(),
            &Bytes::from(r#"{"device_id":"d7","temp":21.5}"#),
            QoS::AtLeastOnce,
        )
        .await
        .unwrap();
        sink.flush().await.unwrap();

        let batches = transport.batches();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].sql, config.sql_template);
        assert_eq!(batches[0].rows.len(), 1);
        let row = &batches[0].rows[0];
        assert_eq!(row.len(), 4);
        // $1 time is RFC 3339 millis; $2 device id from JSON.
        let time = std::str::from_utf8(&row[0]).unwrap();
        assert_eq!(time.len(), 24);
        assert!(time.ends_with('Z'));
        assert_eq!(row[1], b"d7".to_vec());
        assert_eq!(row[2], b"sensors/kitchen".to_vec());
        let metrics: serde_json::Value = serde_json::from_slice(&row[3]).unwrap();
        assert_eq!(
            metrics,
            serde_json::json!({"device_id": "d7", "temp": 21.5})
        );
    }

    #[tokio::test]
    async fn test_jsonb_handling_and_device_fallback() {
        let transport = Arc::new(MockTimescaleTransport::new());
        let mut config = test_config();
        config.batch_size = 10;
        let sink = TimescaleDbSink::new(config, transport.clone()).unwrap();

        // Non-JSON payload becomes a JSON string; device id falls back
        // to the topic.
        sink.send(
            &Topic::new("sensors/door").unwrap(),
            &Bytes::from("open"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        // Numeric device ids render via their JSON spelling.
        sink.send(
            &Topic::new("sensors/hum").unwrap(),
            &Bytes::from(r#"{"device_id":42}"#),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        sink.flush().await.unwrap();

        let batches = transport.batches();
        assert_eq!(batches[0].rows.len(), 2);
        assert_eq!(batches[0].rows[0][1], b"sensors/door".to_vec());
        let metrics: serde_json::Value = serde_json::from_slice(&batches[0].rows[0][3]).unwrap();
        assert_eq!(metrics, serde_json::Value::String("open".to_string()));
        assert_eq!(batches[0].rows[1][1], b"42".to_vec());
    }

    #[tokio::test]
    async fn test_pipeline_execute_batches() {
        let transport = Arc::new(MockTimescaleTransport::new());
        let mut config = test_config();
        config.batch_size = 2;
        let sink = TimescaleDbSink::new(config, transport.clone()).unwrap();
        let topic = Topic::new("t").unwrap();
        for v in ["1", "2", "3"] {
            sink.send(&topic, &Bytes::from(v), QoS::AtMostOnce)
                .await
                .unwrap();
        }
        // Two rows flushed on count, one still buffered.
        assert_eq!(sink.sent_batches(), 1);
        assert_eq!(sink.buffered_rows(), 1);
        sink.flush().await.unwrap();
        assert_eq!(sink.sent_batches(), 2);
        let batches = transport.batches();
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].rows.len(), 2);
        assert_eq!(batches[1].rows.len(), 1);
    }

    #[tokio::test]
    async fn test_failure_retains_buffer_and_backs_off() {
        let transport = Arc::new(MockTimescaleTransport::new());
        transport.fail_next(100);
        let mut config = test_config();
        config.batch_size = 10;
        let sink = TimescaleDbSink::new(config, transport.clone()).unwrap();
        let topic = Topic::new("t").unwrap();
        sink.send(&topic, &Bytes::from("{}"), QoS::AtMostOnce)
            .await
            .unwrap();
        let err = sink.flush().await.expect_err("mock down must fail");
        assert!(matches!(err, ConnectorError::Connection(_)));
        assert_eq!(sink.buffered_rows(), 1);
        let calls = transport.calls();
        assert!(sink.flush().await.is_err());
        assert_eq!(transport.calls(), calls);
        assert_eq!(sink.sent_batches(), 0);
    }

    fn qual_env(name: &str) -> Option<String> {
        std::env::var(name).ok().filter(|v| !v.trim().is_empty())
    }

    fn qual_require(name: &str) -> String {
        qual_env(name).unwrap_or_else(|| {
            panic!(
                "{name} must point at a real TimescaleDB server for qualification; \
                 failing closed instead of passing vacuously"
            )
        })
    }

    fn qual_identifier(name: &str, value: &str) -> String {
        assert!(
            !value.is_empty() && value.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
            "qual {name} must match [A-Za-z0-9_]+, got {value:?} (failing closed)"
        );
        value.to_string()
    }

    /// Direct driver client for DDL and row-count assertions. Panics on
    /// failure: the qualification gate always provides the server, so a
    /// failed connect is a defect, never a skip.
    async fn qual_client(url: &str) -> tokio_postgres::Client {
        let (host, port, user, password, database, use_tls) =
            parse_ts_driver_endpoint(url).expect("qual url parses");
        let cfg = ts_connect_config(&host, port, &user, &password, &database);
        let connect = async {
            if use_tls {
                let tls = ts_tls_connector().expect("qual tls connector");
                let (client, connection) = cfg.connect(tls).await.expect("qual tls connect");
                tokio::spawn(async move {
                    if let Err(e) = connection.await {
                        eprintln!("qual connection closed: {e}");
                    }
                });
                client
            } else {
                let (client, connection) = cfg
                    .connect(tokio_postgres::NoTls)
                    .await
                    .expect("qual connect");
                tokio::spawn(async move {
                    if let Err(e) = connection.await {
                        eprintln!("qual connection closed: {e}");
                    }
                });
                client
            }
        };
        tokio::time::timeout(TS_DRIVER_CONNECT_TIMEOUT, connect)
            .await
            .expect("qual connect timeout")
    }

    /// Qualification against a real TimescaleDB server over the
    /// maintained `tokio-postgres` driver ([`DriverTimescaleDbTransport`]).
    ///
    /// Run with e.g.:
    /// `TIMESCALEDB_HOST=127.0.0.1 TIMESCALEDB_PORT=5432 TIMESCALEDB_DATABASE=qual \
    ///  TIMESCALEDB_USER=qual TIMESCALEDB_PASSWORD=qualpass1 \
    ///  TIMESCALEDB_TABLE=ts_qual_b346 \
    ///  cargo test -p broker-connectors --lib timescaledb::tests::test_qualify_driver_write_path -- --ignored --nocapture --test-threads=1`
    ///
    /// Creates a hypertable (`create_hypertable`, daily chunks), streams
    /// 5000 rows (10 batches of 500, one unique device per row) through
    /// the broker ([`crate::ConnectorManager`] -> [`TimescaleDbSink`] on
    /// [`DriverTimescaleDbTransport`]), asserts `SELECT COUNT(*)` returns
    /// 5000, asserts chunking (`show_chunks`), a time-bucket aggregate
    /// and compression (at least one compressed chunk), kills the pooled
    /// backends and proves the next flush recovers, proves a wrong
    /// password fails closed, then drops the table it created. Panics
    /// when its environment is missing; never skips.
    #[tokio::test]
    #[ignore = "needs a real TimescaleDB server (see TIMESCALEDB_* env)"]
    async fn test_qualify_driver_write_path() {
        use crate::ConnectorManager;

        let host = qual_require("TIMESCALEDB_HOST");
        let port: u16 = qual_require("TIMESCALEDB_PORT")
            .parse()
            .expect("qual TIMESCALEDB_PORT must be a port number");
        let database = qual_identifier("database", &qual_require("TIMESCALEDB_DATABASE"));
        let user = qual_require("TIMESCALEDB_USER");
        let password = qual_require("TIMESCALEDB_PASSWORD");
        let table = qual_identifier("table", &qual_require("TIMESCALEDB_TABLE"));
        const ROWS: i64 = 5000;
        const RECOVERY_ROWS: i64 = 10;

        let url = format!("postgresql://{user}:{password}@{host}:{port}/{database}");

        // Direct driver client for DDL and assertions; connecting at
        // all is the first authentication proof.
        let ddl = qual_client(&url).await;
        let version: String = ddl
            .query_one("SELECT version()", &[])
            .await
            .expect("qual server version")
            .get(0);
        eprintln!("qual server: version={version} host={host}:{port} database={database}");
        assert!(
            version.contains("PostgreSQL"),
            "qualification must run against a PostgreSQL-wire server, got: {version}"
        );
        ddl.batch_execute("CREATE EXTENSION IF NOT EXISTS timescaledb")
            .await
            .expect("qual install timescaledb extension");
        let ext: Option<String> = ddl
            .query_opt(
                "SELECT extversion FROM pg_extension WHERE extname = 'timescaledb'",
                &[],
            )
            .await
            .expect("qual extension lookup")
            .map(|row| row.get(0));
        let ext = ext.expect("qual TimescaleDB extension must be installed");
        eprintln!("qual timescaledb extension version={ext}");

        ddl.batch_execute(format!("DROP TABLE IF EXISTS {table}").as_str())
            .await
            .expect("qual drop stale table");
        ddl.batch_execute(
            format!(
                "CREATE TABLE {table} (\"time\" TIMESTAMPTZ NOT NULL, device_id TEXT NOT NULL, \
                 topic TEXT NOT NULL, metrics JSONB NOT NULL, \
                 PRIMARY KEY (\"time\", device_id))"
            )
            .as_str(),
        )
        .await
        .expect("qual create hypertable base table");
        ddl.batch_execute(
            format!(
                "SELECT create_hypertable('{table}', 'time', \
                 chunk_time_interval => INTERVAL '1 day')"
            )
            .as_str(),
        )
        .await
        .expect("qual create_hypertable");
        let hypertables: i64 = ddl
            .query_one(
                "SELECT COUNT(*) FROM timescaledb_information.hypertables WHERE hypertable_name = $1",
                &[&table],
            )
            .await
            .expect("qual hypertable check")
            .get(0);
        assert_eq!(hypertables, 1, "qual {table} must be a hypertable");
        eprintln!("qual hypertable asserted: table={table}");

        let template = format!(
            "INSERT INTO {table} (\"time\", device_id, topic, metrics) VALUES ($1, $2, $3, $4::jsonb) \
             ON CONFLICT (\"time\", device_id) DO UPDATE SET metrics = EXCLUDED.metrics"
        );
        let transport =
            Arc::new(DriverTimescaleDbTransport::new(&url, 2).expect("qual driver transport"));

        // The broker's path: rule actions deliver through the shared
        // connector manager, so the qualification sends through it and
        // never `sink.send` directly.
        let config = TimescaleDbSinkConfig {
            connection_url: url.clone(),
            hypertable: table.clone(),
            time_column: "time".to_string(),
            sql_template: template.clone(),
            pool_size: 2,
            batch_size: 500,
            batch_timeout_ms: 60_000, // explicit flushes only; keeps staleness out
        };
        let sink = Arc::new(TimescaleDbSink::new(config, transport.clone()).expect("qual sink"));
        assert_eq!(sink.kind(), "timescaledb");
        let manager = ConnectorManager::new();
        manager.register("qual-timescaledb", sink.clone());

        // One unique device per row so the (time, device_id) primary key
        // never collapses two rows: the sink stamps `$1` with millisecond
        // precision and 5000 rapid sends share timestamps.
        let topic = Topic::new("sensors/qual").unwrap();
        for seq in 0..ROWS {
            let payload = Bytes::from(format!(
                r#"{{"device_id":"dev-{seq:05}","seq":{seq},"temp":21.5}}"#
            ));
            manager
                .send("qual-timescaledb", &topic, &payload, QoS::AtLeastOnce)
                .await
                .expect("qual send");
        }
        sink.flush().await.expect("qual flush");
        assert_eq!(sink.sent_batches(), 10, "qual batches");
        eprintln!("qual rows sent: rows={ROWS}");

        // Row count asserted back from the server, not the counters.
        let count_sql = format!("SELECT COUNT(*) FROM {table}");
        let count: i64 = ddl
            .query_one(count_sql.as_str(), &[])
            .await
            .expect("qual count")
            .get(0);
        assert_eq!(count, ROWS, "qual count mismatch");
        eprintln!("qual rows asserted: count={count} table={table}");

        // Chunking: at least one Timescale chunk holds the rows.
        let chunks: i64 = ddl
            .query_one(
                format!("SELECT COUNT(*) FROM show_chunks('{table}')").as_str(),
                &[],
            )
            .await
            .expect("qual chunks")
            .get(0);
        assert!(
            chunks >= 1,
            "qual expected at least one chunk, got {chunks}"
        );
        eprintln!("qual chunking asserted: chunks={chunks}");

        // Time-bucket aggregate over the hypertable covers every row.
        let bucket_row = ddl
            .query_one(
                format!(
                    "SELECT COUNT(*), COUNT(DISTINCT time_bucket('1 day', \"time\")) FROM {table}"
                )
                .as_str(),
                &[],
            )
            .await
            .expect("qual time bucket");
        let bucketed: i64 = bucket_row.get(0);
        let buckets: i64 = bucket_row.get(1);
        assert_eq!(bucketed, ROWS, "qual time-bucket coverage");
        assert!(buckets >= 1, "qual expected at least one day bucket");
        eprintln!("qual time-bucket asserted: rows={bucketed} buckets={buckets}");

        // Compression: enable it, compress every chunk, prove at least
        // one chunk reports compressed.
        ddl.batch_execute(
            format!(
                "ALTER TABLE {table} SET (timescaledb.compress, \
                 timescaledb.compress_segmentby = 'device_id')"
            )
            .as_str(),
        )
        .await
        .expect("qual enable compression");
        ddl.batch_execute(
            format!("SELECT compress_chunk(c) FROM show_chunks('{table}') c").as_str(),
        )
        .await
        .expect("qual compress chunks");
        let compressed: i64 = ddl
            .query_one(
                "SELECT COUNT(*) FROM timescaledb_information.chunks \
                 WHERE hypertable_name = $1 AND is_compressed",
                &[&table],
            )
            .await
            .expect("qual compressed chunks")
            .get(0);
        assert!(
            compressed >= 1,
            "qual expected at least one compressed chunk, got {compressed}"
        );
        eprintln!("qual compression asserted: compressed_chunks={compressed}");

        // Pool recovery: kill every pooled backend (all but this DDL
        // session), then prove the next flush reconnects instead of
        // failing. The sleep lets the SIGTERMs land so the reconnect
        // path is actually exercised.
        let killed: Vec<bool> = ddl
            .query(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
                 WHERE datname = $1 AND pid <> pg_backend_pid()",
                &[&database],
            )
            .await
            .expect("qual kill backends")
            .iter()
            .map(|row| row.get(0))
            .collect();
        let killed_n = killed.into_iter().filter(|granted| *granted).count();
        eprintln!("qual killed {killed_n} backends");
        assert!(killed_n >= 1, "qual expected pooled backends to kill");
        tokio::time::sleep(Duration::from_millis(500)).await;
        for seq in 0..RECOVERY_ROWS {
            let payload = Bytes::from(format!(
                r#"{{"device_id":"dev-recovery-{seq:02}","seq":{seq}}}"#
            ));
            manager
                .send("qual-timescaledb", &topic, &payload, QoS::AtLeastOnce)
                .await
                .expect("qual recovery send");
        }
        sink.flush()
            .await
            .expect("qual pool must recover after backend kill");
        eprintln!("qual recovery asserted: flush after kill succeeded");
        let count: i64 = ddl
            .query_one(count_sql.as_str(), &[])
            .await
            .expect("qual recount")
            .get(0);
        assert_eq!(count, ROWS + RECOVERY_ROWS, "qual count after recovery");

        // Wrong password fails closed: no rows written, connection
        // error, and the count is unchanged.
        let bad_url = format!("postgresql://{user}:wrongpass@{host}:{port}/{database}");
        let bad_transport =
            DriverTimescaleDbTransport::new(&bad_url, 1).expect("qual bad transport");
        let bad_batch = TimescaleBatch {
            sql: template.clone(),
            rows: vec![vec![
                b"2026-05-01T00:00:00.000Z".to_vec(),
                b"dev-bad".to_vec(),
                b"sensors/qual".to_vec(),
                br#"{"seq":0}"#.to_vec(),
            ]],
        };
        let err = bad_transport
            .execute_batch(&bad_batch)
            .await
            .expect_err("qual bad password must fail");
        assert!(
            matches!(err, ConnectorError::Connection(_)),
            "qual bad password must fail closed, got: {err}"
        );
        eprintln!("qual auth asserted: wrong password fails closed");
        let count: i64 = ddl
            .query_one(count_sql.as_str(), &[])
            .await
            .expect("qual final count")
            .get(0);
        assert_eq!(count, ROWS + RECOVERY_ROWS, "qual count unchanged");

        // Cleanup: drop the table created for this run (best effort).
        match ddl
            .batch_execute(format!("DROP TABLE IF EXISTS {table}").as_str())
            .await
        {
            Ok(()) => eprintln!("qual cleanup: dropped table {table}"),
            Err(e) => {
                eprintln!("qual cleanup FAILED to drop {table} (tolerated): {e}");
            }
        }
        eprintln!(
            "qual done: rows={} table={table} cleaned table",
            ROWS + RECOVERY_ROWS
        );
    }
}
