//! MySQL / MariaDB sink over the native client protocol.
//!
//! MQTT events become parameterized rows: `?` markers bind `(topic,
//! QoS, payload)` positionally, so values travel out-of-band and SQL
//! injection is structurally impossible. Execution prepares once per
//! connection and runs one `COM_STMT_EXECUTE` per buffered row,
//! pipelined in a single write. The [`MySqlTransport`] boundary keeps
//! unit tests broker-free ([`MemoryMySqlTransport`]); [`TcpMySqlTransport`]
//! speaks handshake (mysql_native_password), prepare, and execute.

use super::{ConnectorError, Result, Sink};
use async_trait::async_trait;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::Notify;

fn default_pool_size() -> usize {
    10
}

fn default_batch_size() -> usize {
    100
}

fn default_batch_timeout_ms() -> u64 {
    50
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MySqlSinkConfig {
    pub connection_url: String,
    pub sql_template: String,
    #[serde(default = "default_pool_size")]
    pub pool_size: usize,
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    #[serde(default = "default_batch_timeout_ms")]
    pub batch_timeout_ms: u64,
}

impl MySqlSinkConfig {
    pub fn validate(&self) -> Result<()> {
        if self.connection_url.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "mysql connection_url must not be empty".to_string(),
            ));
        }
        if self.sql_template.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "mysql sql_template must not be empty".to_string(),
            ));
        }
        if count_placeholders(&self.sql_template) == 0 {
            return Err(ConnectorError::Dispatch(
                "mysql sql_template needs at least one ? marker".to_string(),
            ));
        }
        if self.pool_size == 0 {
            return Err(ConnectorError::Dispatch(
                "mysql pool_size must be >= 1".to_string(),
            ));
        }
        if self.batch_size == 0 {
            return Err(ConnectorError::Dispatch(
                "mysql batch_size must be >= 1".to_string(),
            ));
        }
        // The sink always binds exactly three values (topic, QoS,
        // payload), so the template must carry exactly three markers.
        if count_placeholders(&self.sql_template) != 3 {
            return Err(ConnectorError::Dispatch(
                "mysql sql_template must carry exactly 3 ? markers (topic, qos, payload)"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

/// Count `?` markers outside strings, quoted identifiers, and comments.
/// The sink always binds exactly three values (topic, QoS, payload), so
/// templates must carry exactly three markers.
pub fn count_placeholders(template: &str) -> usize {
    let chars: Vec<char> = template.chars().collect();
    let n = chars.len();
    let mut count = 0;
    let mut i = 0;
    let mut in_string: Option<char> = None;
    let mut in_line_comment = false;
    let mut in_block_comment = false;
    while i < n {
        let c = chars[i];
        if in_line_comment {
            if c == '\n' {
                in_line_comment = false;
            }
            i += 1;
            continue;
        }
        if in_block_comment {
            if c == '*' && i + 1 < n && chars[i + 1] == '/' {
                in_block_comment = false;
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        if let Some(quote) = in_string {
            if c == quote {
                if (quote == '\'' || quote == '"') && i + 1 < n && chars[i + 1] == quote {
                    i += 2;
                } else {
                    in_string = None;
                    i += 1;
                }
            } else if quote == '`' && c == '\\' {
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        match c {
            '\'' | '"' | '`' => {
                in_string = Some(c);
                i += 1;
            }
            '-' if i + 1 < n && chars[i + 1] == '-' => {
                in_line_comment = true;
                i += 2;
            }
            '#' => {
                in_line_comment = true;
                i += 1;
            }
            '/' if i + 1 < n && chars[i + 1] == '*' => {
                in_block_comment = true;
                i += 2;
            }
            '?' => {
                count += 1;
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }
    count
}

/// One flushed batch: the statement plus one 3-column row per event.
#[derive(Debug, Clone, Default)]
pub struct MySqlBatch {
    pub sql: String,
    pub rows: Vec<Vec<Vec<u8>>>,
}

/// Outcome of one batch execution: `processed` counts the prefix of
/// rows that reached a final state (inserted or rejected — those rows
/// are never sent again), `rejected` carries the batch index and server
/// message of each row the server refused, and `error` reports the
/// connection- or statement-level failure that stopped the batch early,
/// if any.
#[derive(Debug, Default)]
pub struct MySqlBatchOutcome {
    pub processed: usize,
    pub rejected: Vec<(usize, String)>,
    pub error: Option<ConnectorError>,
}

#[async_trait]
pub trait MySqlTransport: Send + Sync {
    async fn execute_batch(&self, batch: &MySqlBatch) -> MySqlBatchOutcome;
}

/// In-memory transport recording every flushed batch (tests, dry runs).
#[derive(Debug, Default)]
pub struct MemoryMySqlTransport {
    batches: parking_lot::Mutex<Vec<MySqlBatch>>,
    failures_left: parking_lot::Mutex<usize>,
    calls: AtomicU64,
}

impl MemoryMySqlTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fail the next `n` executions with a transport error (backoff tests).
    pub fn fail_next(&self, n: usize) {
        *self.failures_left.lock() = n;
    }

    pub fn batches(&self) -> Vec<MySqlBatch> {
        self.batches.lock().clone()
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl MySqlTransport for MemoryMySqlTransport {
    async fn execute_batch(&self, batch: &MySqlBatch) -> MySqlBatchOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut failures = self.failures_left.lock();
        if *failures > 0 {
            *failures -= 1;
            return MySqlBatchOutcome {
                processed: 0,
                rejected: Vec::new(),
                error: Some(ConnectorError::Connection(
                    "mock transport down".to_string(),
                )),
            };
        }
        self.batches.lock().push(batch.clone());
        MySqlBatchOutcome {
            processed: batch.rows.len(),
            rejected: Vec::new(),
            error: None,
        }
    }
}

// ---------------------------------------------------------------------------
// MySQL client protocol (handshake, prepare, execute).
// ---------------------------------------------------------------------------

const CAP_LONG_PASSWORD: u32 = 0x0000_0001;
const CAP_LONG_FLAG: u32 = 0x0000_0004;
const CAP_CONNECT_WITH_DB: u32 = 0x0000_0008;
const CAP_PROTOCOL_41: u32 = 0x0000_0200;
const CAP_SECURE_CONNECTION: u32 = 0x0000_8000;
const CAP_PLUGIN_AUTH: u32 = 0x0008_0000;
const CLIENT_CAPABILITIES: u32 =
    CAP_LONG_PASSWORD | CAP_LONG_FLAG | CAP_PROTOCOL_41 | CAP_SECURE_CONNECTION | CAP_PLUGIN_AUTH;

const MYSQL_NATIVE_PASSWORD: &str = "mysql_native_password";
const MYSQL_TYPE_VAR_STRING: u16 = 0xFD;

#[derive(Debug, Clone)]
struct MySqlEndpoint {
    host: String,
    port: u16,
    user: String,
    password: String,
    database: String,
}

/// Parse `mysql://[user[:password]@]host[:port][/db]`.
fn parse_endpoint(url: &str) -> Result<MySqlEndpoint> {
    let rest = url.strip_prefix("mysql://").ok_or_else(|| {
        ConnectorError::Dispatch(format!("mysql url must start with mysql://: {url:?}"))
    })?;
    let (authority_path, query) = match rest.split_once('?') {
        Some((left, query)) => (left, query),
        None => (rest, ""),
    };
    if !query.is_empty() {
        // Query options are accepted and ignored (documented).
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
        "root".to_string()
    } else {
        user
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((host, port)) => (
            host.to_string(),
            port.parse::<u16>()
                .map_err(|_| ConnectorError::Dispatch(format!("mysql bad port in {url:?}")))?,
        ),
        None => (hostport.to_string(), 3306),
    };
    if host.is_empty() {
        return Err(ConnectorError::Dispatch(format!(
            "mysql url needs a host: {url:?}"
        )));
    }
    Ok(MySqlEndpoint {
        host,
        port,
        user,
        password,
        database: dbname.to_string(),
    })
}

/// Length-encoded integer (client -> server only needs the small forms,
/// but the full range keeps the fake-server parser honest).
fn encode_lenenc(value: u64, out: &mut Vec<u8>) {
    if value < 251 {
        out.push(value as u8);
    } else if value < 65536 {
        out.push(0xFC);
        out.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value < 16_777_216 {
        out.push(0xFD);
        let bytes = (value as u32).to_le_bytes();
        out.extend_from_slice(&bytes[..3]);
    } else {
        out.push(0xFE);
        out.extend_from_slice(&value.to_le_bytes());
    }
}

fn read_cstring(cursor: &mut &[u8]) -> Result<Vec<u8>> {
    match cursor.iter().position(|&b| b == 0) {
        Some(end) => {
            let value = cursor[..end].to_vec();
            *cursor = &cursor[end + 1..];
            Ok(value)
        }
        None => Err(ConnectorError::Connection(
            "unterminated mysql string".to_string(),
        )),
    }
}

/// mysql_native_password token: `SHA1(password) XOR SHA1(salt +
/// SHA1(SHA1(password)))`; empty for empty passwords.
fn native_password_token(password: &[u8], salt: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    let stage1 = {
        let mut hasher = Sha1::new();
        hasher.update(password);
        hasher.finalize().to_vec()
    };
    let mut second = Sha1::new();
    second.update(&stage1);
    let stage2 = second.finalize().to_vec();
    let mut salted = salt.to_vec();
    salted.extend_from_slice(&stage2);
    let mut third = Sha1::new();
    third.update(&salted);
    let stage3 = third.finalize().to_vec();
    stage1
        .iter()
        .zip(stage3.iter())
        .map(|(a, b)| a ^ b)
        .collect()
}

struct MySqlPacket {
    seq: u8,
    body: Vec<u8>,
}

async fn read_packet(stream: &mut TcpStream) -> Result<MySqlPacket> {
    let mut header = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut header))
        .await
        .map_err(|_| ConnectorError::Connection("mysql read timeout".to_string()))?
        .map_err(|e| ConnectorError::Connection(format!("mysql read failed: {e}")))?;
    let len = u32::from_le_bytes([header[0], header[1], header[2], 0]) as usize;
    if len > 16 * 1024 * 1024 {
        return Err(ConnectorError::Connection(format!(
            "mysql packet too large: {len}"
        )));
    }
    let mut body = vec![0u8; len];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut body))
        .await
        .map_err(|_| ConnectorError::Connection("mysql read timeout".to_string()))?
        .map_err(|e| ConnectorError::Connection(format!("mysql read failed: {e}")))?;
    Ok(MySqlPacket {
        seq: header[3],
        body,
    })
}

async fn write_packet(stream: &mut TcpStream, seq: &mut u8, body: &[u8]) -> Result<()> {
    let mut frame = Vec::with_capacity(4 + body.len());
    let len = body.len() as u32;
    frame.push((len & 0xFF) as u8);
    frame.push(((len >> 8) & 0xFF) as u8);
    frame.push(((len >> 16) & 0xFF) as u8);
    frame.push(*seq);
    *seq = seq.wrapping_add(1);
    frame.extend_from_slice(body);
    stream
        .write_all(&frame)
        .await
        .map_err(|e| ConnectorError::Connection(format!("mysql write failed: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| ConnectorError::Connection(format!("mysql flush failed: {e}")))?;
    Ok(())
}

/// Translate an ERR packet body into a message (errno + sqlstate + text).
fn error_text(body: &[u8]) -> String {
    if body.len() < 3 || body[0] != 0xFF {
        return "mysql error (unparseable)".to_string();
    }
    let errno = u16::from_le_bytes([body[1], body[2]]);
    let message = if body.len() > 9 && body[3] == b'#' {
        String::from_utf8_lossy(&body[9..]).to_string()
    } else {
        String::from_utf8_lossy(&body[3..]).to_string()
    };
    format!("mysql errno {errno}: {message}")
}

struct MysqlConn {
    stream: TcpStream,
    prepared_stmt: Option<u32>,
}

async fn handshake(endpoint: &MySqlEndpoint, stream: &mut TcpStream) -> Result<()> {
    // Server greeting.
    let greeting = read_packet(stream).await?;
    if greeting.seq != 0 {
        return Err(ConnectorError::Connection(
            "mysql greeting must use sequence 0".to_string(),
        ));
    }
    // Client packets continue the server's sequence within the handshake.
    let mut seq = greeting.seq.wrapping_add(1);
    if greeting.body.first() == Some(&0xFF) {
        return Err(ConnectorError::Connection(format!(
            "mysql greeting failed: {}",
            error_text(&greeting.body)
        )));
    }
    let mut cursor = greeting.body.as_slice();
    if cursor.first() != Some(&10) {
        return Err(ConnectorError::Connection(
            "unsupported mysql protocol version".to_string(),
        ));
    }
    cursor = &cursor[1..];
    read_cstring(&mut cursor)?; // server version
    if cursor.len() < 4 + 8 + 1 + 2 + 1 + 2 + 2 + 1 + 10 {
        return Err(ConnectorError::Connection(
            "truncated mysql greeting".to_string(),
        ));
    }
    cursor = &cursor[4..]; // connection id
    let seed_part1 = cursor[..8].to_vec();
    cursor = &cursor[8 + 1..]; // seed part 1 + filler
    cursor = &cursor[2 + 1 + 2 + 2 + 1..]; // caps, charset, status, caps, auth len
    cursor = &cursor[10..]; // reserved
                            // Remainder: seed part 2 (NUL-terminated) + plugin name.
    let mut salt = seed_part1;
    let seed_part2 = read_cstring(&mut cursor).unwrap_or_default();
    salt.extend_from_slice(&seed_part2[..seed_part2.len().min(12)]);
    let salt: Vec<u8> = salt.into_iter().take(20).collect();

    // HandshakeResponse41.
    let token = native_password_token(endpoint.password.as_bytes(), &salt[..salt.len().min(20)]);
    let mut body = Vec::new();
    let mut caps = CLIENT_CAPABILITIES;
    if !endpoint.database.is_empty() {
        caps |= CAP_CONNECT_WITH_DB;
    }
    body.extend_from_slice(&caps.to_le_bytes());
    body.extend_from_slice(&0x01000000u32.to_le_bytes()); // max packet 16MB
    body.push(45); // utf8mb4
    body.extend_from_slice(&[0u8; 23]);
    body.extend_from_slice(endpoint.user.as_bytes());
    body.push(0);
    body.push(token.len() as u8);
    body.extend_from_slice(&token);
    if !endpoint.database.is_empty() {
        body.extend_from_slice(endpoint.database.as_bytes());
        body.push(0);
    }
    body.extend_from_slice(MYSQL_NATIVE_PASSWORD.as_bytes());
    body.push(0);
    write_packet(stream, &mut seq, &body).await?;

    // Auth switch / more-data loop, then OK.
    loop {
        let packet = read_packet(stream).await?;
        match packet.body.first() {
            Some(0x00) => break,
            Some(0xFF) => {
                return Err(ConnectorError::Connection(format!(
                    "mysql auth failed: {}",
                    error_text(&packet.body)
                )));
            }
            Some(0xFE) => {
                // AuthSwitchRequest: plugin\0 + seed.
                let mut cursor = &packet.body[1..];
                let name = read_cstring(&mut cursor).unwrap_or_default();
                let name = String::from_utf8_lossy(&name).to_string();
                if name != MYSQL_NATIVE_PASSWORD {
                    return Err(ConnectorError::Connection(format!(
                        "unsupported mysql auth plugin {name:?} (only mysql_native_password)"
                    )));
                }
                // The seed is NUL-terminated on the wire; the scramble
                // uses only the bytes before the terminator.
                let seed = cursor.strip_suffix(&[0]).unwrap_or(cursor);
                let token = native_password_token(endpoint.password.as_bytes(), seed);
                seq = packet.seq.wrapping_add(1);
                write_packet(stream, &mut seq, &token).await?;
            }
            Some(0x01) => {
                return Err(ConnectorError::Connection(
                    "mysql auth requires caching_sha2_password (unsupported)".to_string(),
                ));
            }
            _ => {
                return Err(ConnectorError::Connection(
                    "unexpected mysql handshake packet".to_string(),
                ));
            }
        }
    }
    Ok(())
}

/// TCP transport with a tiny round-robin pool. Connections establish
/// lazily on first use (creation never blocks on external brokers).
pub struct TcpMySqlTransport {
    endpoint: MySqlEndpoint,
    pool: Vec<AsyncMutex<Option<MysqlConn>>>,
    cursor: AtomicU64,
}

impl TcpMySqlTransport {
    pub fn new(url: &str, pool_size: usize) -> Result<Self> {
        if pool_size == 0 {
            return Err(ConnectorError::Dispatch(
                "mysql pool_size must be >= 1".to_string(),
            ));
        }
        Ok(Self {
            endpoint: parse_endpoint(url)?,
            pool: (0..pool_size).map(|_| AsyncMutex::new(None)).collect(),
            cursor: AtomicU64::new(0),
        })
    }

    async fn dial(&self) -> Result<MysqlConn> {
        let addr = format!("{}:{}", self.endpoint.host, self.endpoint.port);
        let mut stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&addr))
            .await
            .map_err(|_| ConnectorError::Connection(format!("mysql connect timeout: {addr}")))?
            .map_err(|e| ConnectorError::Connection(format!("mysql connect failed: {e}")))?;
        handshake(&self.endpoint, &mut stream).await?;
        Ok(MysqlConn {
            stream,
            prepared_stmt: None,
        })
    }
}

/// COM_STMT_PREPARE the template; returns the statement id and the
/// server-reported parameter count.
async fn prepare_statement(conn: &mut MysqlConn, sql: &str) -> Result<(u32, u16)> {
    let mut body = vec![0x16];
    body.extend_from_slice(sql.as_bytes());
    let mut seq = 0u8;
    write_packet(&mut conn.stream, &mut seq, &body).await?;
    let response = read_packet(&mut conn.stream).await?;
    if response.body.first() == Some(&0xFF) {
        return Err(ConnectorError::Dispatch(format!(
            "mysql prepare failed: {}",
            error_text(&response.body)
        )));
    }
    if response.body.first() != Some(&0x00) || response.body.len() < 12 {
        return Err(ConnectorError::Connection(
            "malformed mysql prepare response".to_string(),
        ));
    }
    let stmt_id = u32::from_le_bytes([
        response.body[1],
        response.body[2],
        response.body[3],
        response.body[4],
    ]);
    let columns = u16::from_le_bytes([response.body[5], response.body[6]]);
    let params = u16::from_le_bytes([response.body[7], response.body[8]]);
    // Drain parameter + column definitions (each followed by EOF).
    for _ in 0..(params as usize) {
        let packet = read_packet(&mut conn.stream).await?;
        if packet.body.first() == Some(&0xFF) {
            return Err(ConnectorError::Dispatch(format!(
                "mysql prepare failed: {}",
                error_text(&packet.body)
            )));
        }
    }
    if params > 0 {
        expect_eof(&mut conn.stream).await?;
    }
    for _ in 0..(columns as usize) {
        let packet = read_packet(&mut conn.stream).await?;
        if packet.body.first() == Some(&0xFF) {
            return Err(ConnectorError::Dispatch(format!(
                "mysql prepare failed: {}",
                error_text(&packet.body)
            )));
        }
    }
    if columns > 0 {
        expect_eof(&mut conn.stream).await?;
    }
    Ok((stmt_id, params))
}

async fn expect_eof(stream: &mut TcpStream) -> Result<()> {
    let packet = read_packet(stream).await?;
    if packet.body.first() == Some(&0xFE) && packet.body.len() < 9 {
        return Ok(());
    }
    if packet.body.first() == Some(&0xFF) {
        return Err(ConnectorError::Dispatch(format!(
            "mysql error: {}",
            error_text(&packet.body)
        )));
    }
    Err(ConnectorError::Connection(
        "expected mysql EOF packet".to_string(),
    ))
}

/// COM_STMT_EXECUTE one row: all params sent as VAR_STRING text values.
fn encode_execute(stmt_id: u32, row: &[Vec<u8>]) -> Vec<u8> {
    let mut body = vec![0x17];
    body.extend_from_slice(&stmt_id.to_le_bytes());
    body.push(0); // flags: no cursor
    body.extend_from_slice(&1u32.to_le_bytes()); // iteration count
    let bitmap_len = row.len().div_ceil(8);
    body.extend_from_slice(&vec![0u8; bitmap_len]); // NULL bitmap: none null
    body.push(1); // new-params-bind-flag
    for _ in row {
        body.extend_from_slice(&MYSQL_TYPE_VAR_STRING.to_le_bytes());
    }
    for value in row {
        encode_lenenc(value.len() as u64, &mut body);
        body.extend_from_slice(value);
    }
    body
}

#[async_trait]
impl MySqlTransport for TcpMySqlTransport {
    async fn execute_batch(&self, batch: &MySqlBatch) -> MySqlBatchOutcome {
        let mut outcome = MySqlBatchOutcome::default();
        if batch.rows.is_empty() {
            return outcome;
        }
        let slot = (self.cursor.fetch_add(1, Ordering::SeqCst) as usize) % self.pool.len();
        let mut guard = self.pool[slot].lock().await;
        for attempt in 0..2 {
            if guard.is_none() {
                match self.dial().await {
                    Ok(conn) => *guard = Some(conn),
                    Err(e) => {
                        outcome.error = Some(e);
                        return outcome;
                    }
                }
            }
            let conn = guard.as_mut().expect("connected");
            let part = execute_batch_on_conn(conn, batch, outcome.processed).await;
            outcome.processed += part.processed;
            outcome.rejected.extend(part.rejected);
            let Some(error) = part.error else {
                return outcome;
            };
            if !matches!(error, ConnectorError::Connection(_)) {
                // Statement-level failure (prepare rejected, parameter
                // count mismatch): the connection is still usable, so
                // keep it and do not reconnect — retrying would fail
                // the same way.
                outcome.error = Some(error);
                return outcome;
            }
            tracing::warn!("mysql connection lost during batch (attempt {attempt}): {error}");
            *guard = None;
            if attempt == 1 {
                outcome.error = Some(ConnectorError::Connection(format!(
                    "mysql batch failed after reconnect: {error}"
                )));
                return outcome;
            }
            // Reconnect once and resume from the first row that has not
            // reached a final state; processed rows are never re-sent.
        }
        outcome
    }
}

/// Per-connection outcome: `processed` counts rows executed to a final
/// state on this call, `rejected` lists batch-relative row indices the
/// server refused, and `error` stops the batch when set.
struct ConnExecuteOutcome {
    processed: usize,
    rejected: Vec<(usize, String)>,
    error: Option<ConnectorError>,
}

/// Run the batch's unprocessed rows (the `skip` prefix is already done)
/// on one connection. A row the server rejects with an ERR packet is
/// dropped (logged and counted) and execution continues with the next
/// row on the same connection; only connection- and statement-level
/// failures stop the batch.
async fn execute_batch_on_conn(
    conn: &mut MysqlConn,
    batch: &MySqlBatch,
    skip: usize,
) -> ConnExecuteOutcome {
    let mut outcome = ConnExecuteOutcome {
        processed: 0,
        rejected: Vec::new(),
        error: None,
    };
    let stmt_id = match conn.prepared_stmt {
        Some(id) => id,
        None => {
            let (id, param_count) = match prepare_statement(conn, &batch.sql).await {
                Ok(prepared) => prepared,
                Err(e) => {
                    outcome.error = Some(e);
                    return outcome;
                }
            };
            if param_count as usize != batch.rows.first().map(|row| row.len()).unwrap_or(0) {
                outcome.error = Some(ConnectorError::Dispatch(format!(
                    "mysql prepared param count {param_count} mismatches row width"
                )));
                return outcome;
            }
            conn.prepared_stmt = Some(id);
            id
        }
    };
    for (index, row) in batch.rows.iter().enumerate().skip(skip) {
        let frame = encode_execute(stmt_id, row);
        let mut seq = 0u8;
        if let Err(e) = write_packet(&mut conn.stream, &mut seq, &frame).await {
            outcome.error = Some(e);
            return outcome;
        }
        let response = match read_packet(&mut conn.stream).await {
            Ok(response) => response,
            Err(e) => {
                // The reply is lost, so the row may or may not have been
                // applied server-side: it has not reached a final state
                // and is re-sent after the reconnect. Delivery across a
                // reconnect is therefore at-least-once (a duplicate is
                // possible), never exactly-once.
                outcome.error = Some(e);
                return outcome;
            }
        };
        match response.body.first() {
            Some(0x00) => {
                outcome.processed += 1;
            }
            Some(0xFF) => {
                // Row-level rejection (e.g. a CHECK constraint): log and
                // count the row, then continue with the next row on the
                // same connection.
                let message = error_text(&response.body);
                tracing::warn!("mysql row {index} rejected by server: {message}");
                outcome.rejected.push((index, message));
                outcome.processed += 1;
            }
            _ => {
                outcome.error = Some(ConnectorError::Connection(
                    "unexpected mysql execute response".to_string(),
                ));
                return outcome;
            }
        }
    }
    outcome
}

// ---------------------------------------------------------------------------
// Sink.
// ---------------------------------------------------------------------------

/// MySQL sink: buffers MQTT events as 3-column rows
/// (`?` topic, QoS, payload positional) and flushes full or stale
/// batches through the transport, with the same backoff contract as the
/// PostgreSQL sink. Rows the server rejects are dropped (counted via
/// [`MySqlSink::rejected_rows`]); after a failure only rows that never
/// reached a final state are restored to the buffer, in order.
pub struct MySqlSink {
    core: Arc<MySqlSinkCore>,
}

/// Shared sink state; the linger-flush task holds only a weak reference
/// to it, so dropping the sink stops the task.
struct MySqlSinkCore {
    config: MySqlSinkConfig,
    transport: Arc<dyn MySqlTransport>,
    buffer: parking_lot::Mutex<super::BatchQueue<Vec<Vec<u8>>>>,
    backoff: parking_lot::Mutex<super::BackoffState>,
    sent_batches: AtomicU64,
    inserted_rows: AtomicU64,
    rejected_rows: AtomicU64,
    /// Notifies the linger task that new rows are available.
    linger_notify: Arc<Notify>,
    /// Tracks the last logged error text for rate-limiting.
    last_linger_error: parking_lot::Mutex<Option<String>>,
    /// Tracks when the last linger error was logged.
    last_linger_error_time: parking_lot::Mutex<Option<Instant>>,
}

impl MySqlSinkCore {
    async fn flush(&self) -> Result<()> {
        self.backoff.lock().check()?;
        let (rows, oldest) = self.buffer.lock().take_batch();
        if rows.is_empty() {
            return Ok(());
        }
        let batch = MySqlBatch {
            sql: self.config.sql_template.clone(),
            rows,
        };
        let outcome = self.transport.execute_batch(&batch).await;
        let inserted = outcome.processed.saturating_sub(outcome.rejected.len()) as u64;
        self.inserted_rows.fetch_add(inserted, Ordering::Relaxed);
        self.rejected_rows
            .fetch_add(outcome.rejected.len() as u64, Ordering::Relaxed);
        match outcome.error {
            None => {
                self.backoff.lock().success();
                self.sent_batches.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Some(e) => {
                // Only rows that never reached a final state go back
                // into the buffer, in their original order; inserted or
                // rejected rows are never sent again.
                let remaining: Vec<_> = batch.rows.into_iter().skip(outcome.processed).collect();
                self.buffer.lock().restore(remaining, oldest);
                // Notify the linger task that rows are available again
                self.linger_notify.notify_one();
                self.backoff.lock().failure();
                Err(e)
            }
        }
    }
}

impl MySqlSink {
    pub fn new(config: MySqlSinkConfig, transport: Arc<dyn MySqlTransport>) -> Result<Self> {
        config.validate()?;
        let linger = Duration::from_millis(config.batch_timeout_ms);
        let core = Arc::new(MySqlSinkCore {
            buffer: parking_lot::Mutex::new(super::BatchQueue::new(config.batch_size, linger)),
            config,
            transport,
            backoff: parking_lot::Mutex::new(super::BackoffState::default()),
            sent_batches: AtomicU64::new(0),
            inserted_rows: AtomicU64::new(0),
            rejected_rows: AtomicU64::new(0),
            linger_notify: Arc::new(Notify::new()),
            last_linger_error: parking_lot::Mutex::new(None),
            last_linger_error_time: parking_lot::Mutex::new(None),
        });
        spawn_linger_flush(&core, linger);
        Ok(Self { core })
    }

    pub fn config(&self) -> &MySqlSinkConfig {
        &self.core.config
    }

    pub fn sent_batches(&self) -> u64 {
        self.core.sent_batches.load(Ordering::Relaxed)
    }

    /// Rows the server acknowledged (OK reply to COM_STMT_EXECUTE).
    pub fn inserted_rows(&self) -> u64 {
        self.core.inserted_rows.load(Ordering::Relaxed)
    }

    /// Rows the server rejected (ERR reply) and the sink dropped.
    pub fn rejected_rows(&self) -> u64 {
        self.core.rejected_rows.load(Ordering::Relaxed)
    }

    pub fn buffered_rows(&self) -> usize {
        self.core.buffer.lock().len()
    }

    /// Flush buffered rows as one batch (no-op when empty). While
    /// backing off, fails fast without touching the transport.
    pub async fn flush(&self) -> Result<()> {
        self.core.flush().await
    }

    fn buffer_row(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> bool {
        let was_empty = self.core.buffer.lock().is_empty();
        let should_flush = self.core.buffer.lock().push(vec![
            topic.as_str().as_bytes().to_vec(),
            u8::from(qos).to_string().into_bytes(),
            payload.to_vec(),
        ]);
        if was_empty {
            self.core.linger_notify.notify_one();
        }
        should_flush
    }
}

/// Flush stale rows without waiting for new events: the timer runs only
/// while rows are buffered. It arms when a row lands in an empty buffer
/// or rows are restored after a failure; it ends when the buffer is
/// empty. While backing off, it waits for the backoff window instead of
/// spinning. The task holds only a weak reference to the sink state, so
/// dropping the sink stops it; with no tokio runtime (sink built outside
/// one) no task is spawned and flushing stays event-driven.
fn spawn_linger_flush(core: &Arc<MySqlSinkCore>, linger: Duration) {
    if linger.is_zero() {
        // Zero linger flushes on every push, and a zero period would
        // panic tokio's interval.
        return;
    }
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let weak = Arc::downgrade(core);
    let notify = core.linger_notify.clone();

    handle.spawn(async move {
        const BACKOFF_POLL_INTERVAL: Duration = Duration::from_secs(1);
        const ERROR_LOG_THROTTLE: Duration = Duration::from_secs(30);

        loop {
            // Snapshot buffer/backoff state, then drop the strong
            // reference before any wait so a dropped sink is freed
            // promptly instead of being pinned for up to 60 s.
            let (has_rows, is_stale, in_backoff) = match weak.upgrade() {
                None => break,
                Some(core) => {
                    let (has_rows, is_stale) = {
                        let buffer = core.buffer.lock();
                        (!buffer.is_empty(), buffer.is_stale())
                    };
                    let in_backoff = core.backoff.lock().check().is_err();
                    drop(core);
                    (has_rows, is_stale, in_backoff)
                }
            };

            if !has_rows {
                // Buffer empty: wait for notification of new rows.
                // Use a long periodic sleep to re-check sink existence.
                tokio::select! {
                    _ = notify.notified() => continue,
                    _ = tokio::time::sleep(Duration::from_secs(60)) => continue,
                }
            }

            // Buffer has rows. Check backoff state.
            if in_backoff {
                // In backoff: wait for backoff window or new rows.
                tokio::select! {
                    _ = notify.notified() => continue,
                    _ = tokio::time::sleep(BACKOFF_POLL_INTERVAL) => continue,
                }
            }

            // Not in backoff. If stale, flush immediately; else wait for linger or new rows.
            if !is_stale {
                let timed_out = tokio::select! {
                    _ = notify.notified() => false,
                    _ = tokio::time::sleep(linger) => true,
                };
                if !timed_out {
                    continue;
                }
                // Linger timeout: re-check staleness (a new row may have arrived).
                let is_stale = match weak.upgrade() {
                    None => break,
                    Some(core) => {
                        let stale = core.buffer.lock().is_stale();
                        drop(core);
                        stale
                    }
                };
                if !is_stale {
                    continue;
                }
                // Fall through to flush.
            }

            // Re-upgrade for the flush; holding the strong reference
            // during `flush().await` is fine.
            let Some(core) = weak.upgrade() else {
                break;
            };

            // Flush stale batch.
            let result = core.flush().await;

            // Logging with rate limiting. The backoff fast-fail is not a
            // new failure (its cause was already logged), so it is never
            // logged here.
            match result {
                Ok(()) => {
                    let mut last_error = core.last_linger_error.lock();
                    let mut last_error_time = core.last_linger_error_time.lock();
                    // Successful flush after previous failure: log recovery once.
                    if last_error.is_some() {
                        tracing::info!("mysql linger flush recovered");
                        *last_error = None;
                        *last_error_time = None;
                    }
                }
                Err(e) => {
                    let error_text = e.to_string();
                    if error_text.contains("sink backing off after errors") {
                        continue;
                    }
                    let mut last_error = core.last_linger_error.lock();
                    let mut last_error_time = core.last_linger_error_time.lock();
                    let now = Instant::now();
                    let should_log = last_error
                        .as_ref()
                        .map(|last| last != &error_text)
                        .unwrap_or(true)
                        || last_error_time
                            .map(|t| now.saturating_duration_since(t) > ERROR_LOG_THROTTLE)
                            .unwrap_or(true);

                    if should_log {
                        tracing::warn!("mysql linger flush failed: {error_text}");
                        *last_error = Some(error_text);
                        *last_error_time = Some(now);
                    }
                    // Backoff is already recorded by flush(); the loop will
                    // pick it up on the next iteration and wait.
                }
            }
        }
    });
}

#[async_trait]
impl Sink for MySqlSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> super::Result<()> {
        if self.buffer_row(topic, payload, qos) {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "mysql"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> MySqlSinkConfig {
        MySqlSinkConfig {
            connection_url: "mysql://user:pass@127.0.0.1:3306/db".to_string(),
            sql_template:
                "INSERT INTO sensor_data (topic, qos, payload, recorded_at) VALUES (?, ?, ?, NOW())"
                    .to_string(),
            pool_size: 2,
            batch_size: 100,
            batch_timeout_ms: 50,
        }
    }

    #[test]
    fn test_config_validation() {
        let mut config = test_config();
        assert!(config.validate().is_ok());

        config.connection_url.clear();
        assert!(config.validate().is_err());
        config.connection_url = "mysql://h/db".to_string();

        config.sql_template = "INSERT INTO t VALUES (?, ?)".to_string();
        assert!(config.validate().is_err());

        config.pool_size = 0;
        assert!(config.validate().is_err());
        config.pool_size = 2;

        config.batch_size = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_placeholder_counting() {
        assert_eq!(count_placeholders("VALUES (?, ?, ?)"), 3);
        assert_eq!(count_placeholders("no markers"), 0);
        // Markers inside strings and comments do not count.
        assert_eq!(count_placeholders("VALUES (?) -- what (?)"), 1);
        assert_eq!(count_placeholders("VALUES ('a?b', ?)"), 1);
        assert_eq!(count_placeholders("VALUES (/* ? */ ?)"), 1);
        assert_eq!(count_placeholders("VALUES (`weird?col`, ?)"), 1);
        assert_eq!(count_placeholders("VALUES (# ?)"), 0);
    }

    #[test]
    fn test_endpoint_parsing() {
        let endpoint =
            parse_endpoint("mysql://user:pass@db.internal:3307/telemetry").expect("parses");
        assert_eq!(endpoint.host, "db.internal");
        assert_eq!(endpoint.port, 3307);
        assert_eq!(endpoint.user, "user");
        assert_eq!(endpoint.password, "pass");
        assert_eq!(endpoint.database, "telemetry");

        let endpoint = parse_endpoint("mysql://dbhost").expect("defaults");
        assert_eq!(endpoint.port, 3306);
        assert_eq!(endpoint.user, "root");
        assert_eq!(endpoint.database, "");

        assert!(parse_endpoint("postgres://h/db").is_err());
        assert!(parse_endpoint("mysql://h:notaport/db").is_err());
        assert!(parse_endpoint("mysql:///db").is_err());
    }

    #[test]
    fn test_native_password_token_vectors() {
        // Empty password authenticates with an empty token.
        assert!(native_password_token(b"", b"12345678901234567890").is_empty());
        // Deterministic 20-byte XOR token otherwise.
        let token = native_password_token(b"pass", b"12345678901234567890");
        assert_eq!(token.len(), 20);
        assert_eq!(
            token,
            native_password_token(b"pass", b"12345678901234567890")
        );
        assert_ne!(
            token,
            native_password_token(b"pass", b"AAAAAAAAAAAAAAAAAAAA")
        );
        assert_ne!(
            token,
            native_password_token(b"word", b"12345678901234567890")
        );
    }

    #[test]
    fn test_execute_encoding_shapes() {
        // One row, three params: header + bitmap + types + values.
        let frame = encode_execute(7, &[b"a/b".to_vec(), b"1".to_vec(), b"{}".to_vec()]);
        assert_eq!(frame[0], 0x17);
        assert_eq!(&frame[1..5], &[7, 0, 0, 0]);
        assert_eq!(frame[5], 0); // flags
        assert_eq!(&frame[6..10], &[1, 0, 0, 0]); // iteration count
        assert_eq!(frame[10], 0); // null bitmap (3 params -> 1 byte)
        assert_eq!(frame[11], 1); // new-params-bind
        assert_eq!(&frame[12..18], &[0xFD, 0, 0xFD, 0, 0xFD, 0]); // 3x VAR_STRING
                                                                  // Values are length-prefixed blobs.
        assert!(frame.windows(3).any(|w| w == b"a/b"));
    }

    /// In-process fake MySQL server: greeting with a fixed seed,
    /// mysql_native_password verification, Prepare capturing the SQL,
    /// then per-row Execute capture with independent param decoding.
    #[tokio::test]
    async fn test_tcp_handshake_prepare_and_batch_params() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let captured_sql = Arc::new(parking_lot::Mutex::new(String::new()));
        let captured_rows = Arc::new(parking_lot::Mutex::new(Vec::<Vec<Vec<u8>>>::new()));
        let captured_sql_rx = captured_sql.clone();
        let captured_rows_rx = captured_rows.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            // Greeting: protocol 10, version, conn id, seed part 1.
            let seed_part1 = b"12345678";
            let seed_part2 = b"ABCDEFGHJKLM";
            let mut greeting = vec![10u8];
            greeting.extend_from_slice(b"8.0.36-test\0");
            greeting.extend_from_slice(&42u32.to_le_bytes());
            greeting.extend_from_slice(seed_part1);
            greeting.push(0);
            greeting.extend_from_slice(&0xFFFFu16.to_le_bytes());
            greeting.push(33);
            greeting.extend_from_slice(&0u16.to_be_bytes());
            greeting.extend_from_slice(&0u16.to_be_bytes()); // cap high
            greeting.push(21);
            greeting.extend_from_slice(&[0u8; 10]);
            greeting.extend_from_slice(seed_part2);
            greeting.push(0);
            greeting.extend_from_slice(b"mysql_native_password\0");
            write_server_packet(&mut stream, 0, &greeting).await;
            // Handshake response: verify plugin + native-password digest.
            // (Index 0 is the packet sequence number.)
            let request = read_server_packet(&mut stream).await;
            assert_eq!(
                u32::from_le_bytes([request[1], request[2], request[3], request[4]]) & 0x00080000,
                0x00080000
            );
            let mut cursor = &request[1 + 4 + 4 + 1 + 23..];
            let user = read_cstring(&mut cursor);
            assert_eq!(user, b"u");
            assert_eq!(cursor[0] as usize, 20);
            let presented = &cursor[1..21];
            cursor = &cursor[21..];
            let db = read_cstring(&mut cursor);
            assert_eq!(db, b"db");
            let plugin = read_cstring(&mut cursor);
            assert_eq!(plugin, b"mysql_native_password");
            // Independent digest check: SHA1(pw) XOR SHA1(seed + SHA1(SHA1(pw))).
            let mut seed = seed_part1.to_vec();
            seed.extend_from_slice(&seed_part2[..12.min(seed_part2.len())]);
            let mut h1 = Sha1::new();
            h1.update(b"pwd");
            let stage1 = h1.finalize().to_vec();
            let mut h2 = Sha1::new();
            h2.update(&stage1);
            let stage2 = h2.finalize().to_vec();
            let mut salted = seed.clone();
            salted.extend_from_slice(&stage2);
            let mut h3 = Sha1::new();
            h3.update(&salted);
            let stage3 = h3.finalize().to_vec();
            let expected: Vec<u8> = stage1
                .iter()
                .zip(stage3.iter())
                .map(|(a, b)| a ^ b)
                .collect();
            assert_eq!(
                presented,
                expected.as_slice(),
                "native password must verify"
            );
            write_server_packet(&mut stream, 1, &[0x00, 0, 0, 0, 0, 0, 0]).await;
            // Prepare: capture SQL, report stmt 7 with 3 params, then the
            // parameter definitions plus EOF the client drains.
            let request = read_server_packet(&mut stream).await;
            assert_eq!(request[1], 0x16);
            captured_sql_rx
                .lock()
                .push_str(std::str::from_utf8(&request[2..]).expect("sql"));
            let mut prepare_ok = vec![0x00];
            prepare_ok.extend_from_slice(&7u32.to_le_bytes());
            prepare_ok.extend_from_slice(&0u16.to_le_bytes());
            prepare_ok.extend_from_slice(&3u16.to_le_bytes());
            prepare_ok.extend_from_slice(&0u16.to_le_bytes());
            prepare_ok.extend_from_slice(&[0u8; 3]);
            write_server_packet(&mut stream, 2, &prepare_ok).await;
            for _ in 0..3 {
                // Minimal column definition: empty catalog/schema/table.
                let mut def = vec![0, 0, 0, 0, 0, 0];
                def.extend_from_slice(&33u16.to_le_bytes());
                def.extend_from_slice(&0u32.to_be_bytes());
                def.push(0xFD);
                def.extend_from_slice(&0u16.to_be_bytes());
                def.push(0);
                def.extend_from_slice(&[0, 0]);
                write_server_packet(&mut stream, 2, &def).await;
            }
            write_server_packet(&mut stream, 2, &[0xFE, 0, 0, 0, 0]).await;
            // Execute loop: two rows expected; values are lenenc blobs.
            let mut rows = Vec::new();
            for _ in 0..2 {
                let request = read_server_packet(&mut stream).await;
                assert_eq!(request[1], 0x17);
                let stmt_id = u32::from_le_bytes([request[2], request[3], request[4], request[5]]);
                assert_eq!(stmt_id, 7);
                // flags(1) + iteration(4) + null bitmap(1) + bind flag(1).
                let mut cursor = &request[6 + 1 + 4 + 1 + 1..];
                for _ in 0..3 {
                    assert_eq!(u16::from_le_bytes([cursor[0], cursor[1]]), 0xFD);
                    cursor = &cursor[2..];
                }
                let mut row = Vec::new();
                for _ in 0..3 {
                    let (len, rest) = decode_lenenc(cursor);
                    row.push(rest[..len].to_vec());
                    cursor = &rest[len..];
                }
                rows.push(row);
                write_server_packet(&mut stream, 3, &[0x00, 1, 0, 0, 0, 0, 0]).await;
            }
            captured_rows_rx.lock().extend(rows);
        });

        let transport = TcpMySqlTransport::new(&format!("mysql://u:pwd@127.0.0.1:{port}/db"), 1)
            .expect("valid transport");
        let mut config = test_config();
        config.batch_size = 2;
        let sink = MySqlSink::new(config, Arc::new(transport)).expect("valid sink");
        let topic = Topic::new("sensors/temp").unwrap();
        sink.send(
            &topic,
            &Bytes::from_static(br#"{ "v": 1 }"#),
            QoS::AtLeastOnce,
        )
        .await
        .expect("row one");
        sink.send(
            &topic,
            &Bytes::from_static(br#"{ "v": 2 }"#),
            QoS::AtLeastOnce,
        )
        .await
        .expect("row two triggers flush");
        assert_eq!(sink.sent_batches(), 1);

        let mut done = false;
        for _ in 0..500 {
            if server.is_finished() {
                done = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(done, "fake server never finished");
        server.await.expect("fake server task");
        assert!(captured_sql.lock().contains("INSERT INTO sensor_data"));
        let rows = captured_rows.lock().clone();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0][0], b"sensors/temp");
        assert_eq!(rows[0][1], b"1");
        assert_eq!(rows[0][2], br#"{ "v": 1 }"#);
        assert_eq!(rows[1][2], br#"{ "v": 2 }"#);
    }

    #[tokio::test]
    async fn test_stale_rows_flush_without_new_events() {
        // One buffered row flushes on its own once it outlives the
        // linger window; no further event is needed.
        let transport = Arc::new(MemoryMySqlTransport::new());
        let mut config = test_config();
        config.batch_size = 100;
        config.batch_timeout_ms = 20;
        let sink = MySqlSink::new(config, transport.clone()).expect("valid sink");
        let topic = Topic::new("sensors/temp").unwrap();
        sink.send(
            &topic,
            &Bytes::from_static(br#"{ "v": 1 }"#),
            QoS::AtMostOnce,
        )
        .await
        .expect("row buffers");
        assert_eq!(sink.buffered_rows(), 1);
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert_eq!(sink.sent_batches(), 1);
        assert_eq!(sink.buffered_rows(), 0);
        let batches = transport.batches();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].rows.len(), 1);
    }

    /// Server-rejected rows are dropped, counted, and never replayed:
    /// the batch continues on the same connection and no reconnect
    /// happens.
    #[tokio::test]
    async fn test_rejected_row_is_dropped_without_replaying_batch() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            // Greeting: protocol 10, version, conn id, seed parts.
            let mut greeting = vec![10u8];
            greeting.extend_from_slice(b"8.4.11-test\0");
            greeting.extend_from_slice(&42u32.to_le_bytes());
            greeting.extend_from_slice(b"12345678");
            greeting.push(0);
            greeting.extend_from_slice(&0xFFFFu16.to_le_bytes());
            greeting.push(33);
            greeting.extend_from_slice(&0u16.to_be_bytes());
            greeting.extend_from_slice(&0u16.to_be_bytes()); // cap high
            greeting.push(21);
            greeting.extend_from_slice(&[0u8; 10]);
            greeting.extend_from_slice(b"ABCDEFGHJKLM");
            greeting.push(0);
            greeting.extend_from_slice(b"mysql_native_password\0");
            write_server_packet(&mut stream, 0, &greeting).await;
            let _request = read_server_packet(&mut stream).await; // handshake response
            write_server_packet(&mut stream, 1, &[0x00, 0, 0, 0, 0, 0, 0]).await;
            // Prepare: report stmt 7 with 3 params, then the parameter
            // definitions plus EOF the client drains.
            let request = read_server_packet(&mut stream).await;
            assert_eq!(request[1], 0x16);
            let mut prepare_ok = vec![0x00];
            prepare_ok.extend_from_slice(&7u32.to_le_bytes());
            prepare_ok.extend_from_slice(&0u16.to_le_bytes());
            prepare_ok.extend_from_slice(&3u16.to_le_bytes());
            prepare_ok.extend_from_slice(&0u16.to_le_bytes());
            prepare_ok.extend_from_slice(&[0u8; 3]);
            write_server_packet(&mut stream, 2, &prepare_ok).await;
            for _ in 0..3 {
                // Minimal column definition: empty catalog/schema/table.
                let mut def = vec![0, 0, 0, 0, 0, 0];
                def.extend_from_slice(&33u16.to_le_bytes());
                def.extend_from_slice(&0u32.to_be_bytes());
                def.push(0xFD);
                def.extend_from_slice(&0u16.to_be_bytes());
                def.push(0);
                def.extend_from_slice(&[0, 0]);
                write_server_packet(&mut stream, 2, &def).await;
            }
            write_server_packet(&mut stream, 2, &[0xFE, 0, 0, 0, 0]).await;
            // Three executes: OK, ERR 3819 (CHECK constraint), OK.
            for reply in 0..3 {
                let request = read_server_packet(&mut stream).await;
                assert_eq!(request[1], 0x17);
                let stmt_id = u32::from_le_bytes([request[2], request[3], request[4], request[5]]);
                assert_eq!(stmt_id, 7);
                if reply == 1 {
                    let mut err = vec![0xFF];
                    err.extend_from_slice(&3819u16.to_le_bytes());
                    err.push(b'#');
                    err.extend_from_slice(b"23000");
                    err.extend_from_slice(b"Check constraint 'payload_chk' is violated.");
                    write_server_packet(&mut stream, 3, &err).await;
                } else {
                    write_server_packet(&mut stream, 3, &[0x00, 1, 0, 0, 0, 0, 0]).await;
                }
            }
            // No replay and no reconnect: the connection stays quiet and
            // no second connection arrives.
            let mut header = [0u8; 4];
            let extra =
                tokio::time::timeout(Duration::from_millis(200), stream.read_exact(&mut header))
                    .await;
            assert!(extra.is_err(), "no further packets on the connection");
            let second = tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
            assert!(second.is_err(), "no second connection within 200 ms");
        });

        let transport = TcpMySqlTransport::new(&format!("mysql://u:pwd@127.0.0.1:{port}/db"), 1)
            .expect("valid transport");
        let mut config = test_config();
        config.batch_size = 3;
        config.batch_timeout_ms = 60_000; // keep the linger task out of the way
        let sink = MySqlSink::new(config, Arc::new(transport)).expect("valid sink");
        let topic = Topic::new("sensors/temp").unwrap();
        for i in 0..3 {
            sink.send(
                &topic,
                &Bytes::from(format!("{{ \"v\": {i} }}")),
                QoS::AtLeastOnce,
            )
            .await
            .expect("row accepted");
        }
        assert_eq!(sink.sent_batches(), 1);
        assert_eq!(sink.inserted_rows(), 2);
        assert_eq!(sink.rejected_rows(), 1);
        assert_eq!(sink.buffered_rows(), 0);
        server.await.expect("fake server assertions hold");
    }

    /// Test transport: the first call processes `first_processed` rows
    /// then fails with a connection error; later calls succeed fully.
    struct PartialMySqlTransport {
        first_processed: usize,
        batches: parking_lot::Mutex<Vec<MySqlBatch>>,
    }

    impl PartialMySqlTransport {
        fn new(first_processed: usize) -> Self {
            Self {
                first_processed,
                batches: parking_lot::Mutex::new(Vec::new()),
            }
        }

        fn batches(&self) -> Vec<MySqlBatch> {
            self.batches.lock().clone()
        }
    }

    #[async_trait]
    impl MySqlTransport for PartialMySqlTransport {
        async fn execute_batch(&self, batch: &MySqlBatch) -> MySqlBatchOutcome {
            let first = {
                let mut batches = self.batches.lock();
                let first = batches.is_empty();
                batches.push(batch.clone());
                first
            };
            if first {
                return MySqlBatchOutcome {
                    processed: self.first_processed,
                    rejected: Vec::new(),
                    error: Some(ConnectorError::Connection(
                        "mock partial failure".to_string(),
                    )),
                };
            }
            MySqlBatchOutcome {
                processed: batch.rows.len(),
                rejected: Vec::new(),
                error: None,
            }
        }
    }

    #[tokio::test]
    async fn test_transport_failure_retries_only_unprocessed_rows() {
        let transport = Arc::new(PartialMySqlTransport::new(2));
        let mut config = test_config();
        config.batch_size = 4;
        config.batch_timeout_ms = 60_000; // keep the linger task out of the way
        let sink = MySqlSink::new(config, transport.clone()).expect("valid sink");
        let topic = Topic::new("sensors/temp").unwrap();
        for i in 0..3 {
            sink.send(&topic, &Bytes::from(format!("row-{i}")), QoS::AtLeastOnce)
                .await
                .expect("rows buffer");
        }
        // The fourth row fills the batch; the transport fails after
        // processing two of the four rows.
        let err = sink
            .send(&topic, &Bytes::from_static(b"row-3"), QoS::AtLeastOnce)
            .await
            .expect_err("partial failure surfaces");
        assert!(matches!(err, ConnectorError::Connection(_)));
        assert_eq!(sink.inserted_rows(), 2);
        assert_eq!(sink.buffered_rows(), 2);
        // During backoff, flush fails fast without touching the transport.
        assert!(sink.flush().await.is_err());
        assert_eq!(transport.batches().len(), 1);
        // After the backoff window, the retry carries exactly rows 3 and
        // 4, in order; the first two rows are never re-sent.
        tokio::time::sleep(Duration::from_millis(2_100)).await;
        sink.flush().await.expect("retry succeeds");
        assert_eq!(sink.inserted_rows(), 4);
        assert_eq!(sink.buffered_rows(), 0);
        let batches = transport.batches();
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[1].rows.len(), 2);
        assert_eq!(batches[1].rows[0][2], b"row-2");
        assert_eq!(batches[1].rows[1][2], b"row-3");
    }

    /// MySQL 8.x greets with caching_sha2_password even for a
    /// mysql_native_password account, then sends an AuthSwitchRequest.
    /// The reply must continue the server's sequence and scramble only
    /// the 20 seed bytes before the NUL terminator.
    #[tokio::test]
    async fn test_tcp_handshake_auth_switch_to_native_password() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut greeting = vec![10u8];
            greeting.extend_from_slice(b"8.4.11-test\0");
            greeting.extend_from_slice(&42u32.to_le_bytes());
            greeting.extend_from_slice(b"12345678");
            greeting.push(0);
            greeting.extend_from_slice(&0xFFFFu16.to_le_bytes());
            greeting.push(33);
            greeting.extend_from_slice(&0u16.to_be_bytes());
            greeting.extend_from_slice(&0u16.to_be_bytes()); // cap high
            greeting.push(21);
            greeting.extend_from_slice(&[0u8; 10]);
            greeting.extend_from_slice(b"ABCDEFGHJKLM");
            greeting.push(0);
            greeting.extend_from_slice(b"caching_sha2_password\0");
            write_server_packet(&mut stream, 0, &greeting).await;
            let response = read_server_packet(&mut stream).await;
            assert_eq!(response[0], 1, "handshake response uses sequence 1");
            let switch_seed = b"zyxwvutsrqponmlkjihg";
            let mut switch = vec![0xFE];
            switch.extend_from_slice(b"mysql_native_password\0");
            switch.extend_from_slice(switch_seed);
            switch.push(0);
            write_server_packet(&mut stream, 2, &switch).await;
            let auth = read_server_packet(&mut stream).await;
            assert_eq!(
                auth[0], 3,
                "auth switch reply continues the server sequence"
            );
            assert_eq!(
                &auth[1..],
                native_password_token(b"pwd", switch_seed).as_slice(),
                "scramble uses the seed without its NUL terminator"
            );
            write_server_packet(&mut stream, 4, &[0x00, 0, 0, 0, 0, 0, 0]).await;
        });

        let transport = TcpMySqlTransport::new(&format!("mysql://u:pwd@127.0.0.1:{port}/db"), 1)
            .expect("valid transport");
        transport
            .dial()
            .await
            .expect("auth switch handshake succeeds");
        server.await.expect("fake server assertions hold");
    }

    async fn read_server_packet(stream: &mut TcpStream) -> Vec<u8> {
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await.expect("pkt head");
        let len = u32::from_le_bytes([header[0], header[1], header[2], 0]) as usize;
        let mut body = vec![0u8; 1 + len];
        body[0] = header[3];
        stream.read_exact(&mut body[1..]).await.expect("pkt body");
        body
    }

    async fn write_server_packet(stream: &mut TcpStream, seq: u8, body: &[u8]) {
        let len = body.len() as u32;
        let mut frame = vec![
            (len & 0xFF) as u8,
            ((len >> 8) & 0xFF) as u8,
            ((len >> 16) & 0xFF) as u8,
            seq,
        ];
        frame.extend_from_slice(body);
        stream.write_all(&frame).await.expect("pkt write");
    }

    fn read_cstring(cursor: &mut &[u8]) -> Vec<u8> {
        let end = cursor.iter().position(|&b| b == 0).expect("cstr");
        let value = cursor[..end].to_vec();
        *cursor = &cursor[end + 1..];
        value
    }

    /// Length-encoded integer for the fake server's assertions.
    fn decode_lenenc(cursor: &[u8]) -> (usize, &[u8]) {
        match cursor[0] {
            0xFC => (
                u16::from_le_bytes([cursor[1], cursor[2]]) as usize,
                &cursor[3..],
            ),
            0xFD => (
                u32::from_le_bytes([cursor[1], cursor[2], cursor[3], 0]) as usize,
                &cursor[4..],
            ),
            0xFE => (
                u64::from_le_bytes([
                    cursor[1], cursor[2], cursor[3], cursor[4], cursor[5], cursor[6], cursor[7],
                    cursor[8],
                ]) as usize,
                &cursor[9..],
            ),
            byte => (byte as usize, &cursor[1..]),
        }
    }

    /// A test transport that always fails with the given message.
    struct AlwaysFailTransport {
        message: String,
        calls: AtomicU64,
    }

    impl AlwaysFailTransport {
        fn new(message: String) -> Self {
            Self {
                message,
                calls: AtomicU64::new(0),
            }
        }

        fn calls(&self) -> u64 {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl MySqlTransport for AlwaysFailTransport {
        async fn execute_batch(&self, _batch: &MySqlBatch) -> MySqlBatchOutcome {
            self.calls.fetch_add(1, Ordering::SeqCst);
            MySqlBatchOutcome {
                processed: 0,
                rejected: Vec::new(),
                error: Some(ConnectorError::Connection(self.message.clone())),
            }
        }
    }

    /// A test transport that succeeds on the first call, then fails once,
    /// then succeeds again (for recovery test).
    struct FailOnceTransport {
        fail_on_call: u64,
        calls: AtomicU64,
    }

    impl FailOnceTransport {
        fn new(fail_on_call: u64) -> Self {
            Self {
                fail_on_call,
                calls: AtomicU64::new(0),
            }
        }

        fn calls(&self) -> u64 {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl MySqlTransport for FailOnceTransport {
        async fn execute_batch(&self, batch: &MySqlBatch) -> MySqlBatchOutcome {
            let call_num = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if call_num == self.fail_on_call {
                MySqlBatchOutcome {
                    processed: 0,
                    rejected: Vec::new(),
                    error: Some(ConnectorError::Connection(
                        "mock transient failure".to_string(),
                    )),
                }
            } else {
                MySqlBatchOutcome {
                    processed: batch.rows.len(),
                    rejected: Vec::new(),
                    error: None,
                }
            }
        }
    }

    /// A test transport that records every flushed batch.
    struct RecordingTransport {
        batches: parking_lot::Mutex<Vec<MySqlBatch>>,
    }

    impl RecordingTransport {
        fn new() -> Self {
            Self {
                batches: parking_lot::Mutex::new(Vec::new()),
            }
        }

        fn batches(&self) -> Vec<MySqlBatch> {
            self.batches.lock().clone()
        }

        fn calls(&self) -> u64 {
            self.batches.lock().len() as u64
        }
    }

    #[async_trait]
    impl MySqlTransport for RecordingTransport {
        async fn execute_batch(&self, batch: &MySqlBatch) -> MySqlBatchOutcome {
            self.batches.lock().push(batch.clone());
            MySqlBatchOutcome {
                processed: batch.rows.len(),
                rejected: Vec::new(),
                error: None,
            }
        }
    }

    /// Simple test subscriber that captures log lines.
    struct TestSubscriber {
        logs: parking_lot::Mutex<Vec<String>>,
    }

    impl TestSubscriber {
        fn new() -> Self {
            Self {
                logs: parking_lot::Mutex::new(Vec::new()),
            }
        }

        fn count_contains(&self, needle: &str) -> usize {
            self.logs
                .lock()
                .iter()
                .filter(|l| l.contains(needle))
                .count()
        }
    }

    impl tracing::Subscriber for TestSubscriber {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            let mut message = String::new();
            let mut visitor = TestVisitor(&mut message);
            event.record(&mut visitor);
            let metadata = event.metadata();
            let level = *metadata.level();
            let target = metadata.target();
            let log_line = format!("{} {}: {}", level, target, message);
            self.logs.lock().push(log_line);
        }

        fn enter(&self, _id: &tracing::span::Id) {}

        fn exit(&self, _id: &tracing::span::Id) {}
    }

    struct TestVisitor<'a>(&'a mut String);

    impl tracing::field::Visit for TestVisitor<'_> {
        fn record_debug(&mut self, _field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            // Formatted event messages (e.g. `tracing::warn!("... {x}")`)
            // arrive here as `fmt::Arguments`.
            self.0.push_str(&format!("{value:?}"));
        }

        fn record_str(&mut self, _field: &tracing::field::Field, value: &str) {
            self.0.push_str(value);
        }
    }

    #[tokio::test]
    async fn test_linger_flush_failure_is_logged_once_per_backoff() {
        let subscriber = Arc::new(TestSubscriber::new());
        let _guard = tracing::subscriber::set_default(subscriber.clone());

        let transport = Arc::new(AlwaysFailTransport::new(
            "mock connection error".to_string(),
        ));
        let mut config = test_config();
        config.batch_size = 100;
        config.batch_timeout_ms = 50;
        let sink = MySqlSink::new(config, transport.clone()).expect("valid sink");
        let topic = Topic::new("sensors/temp").unwrap();

        // Send one row (fewer than batch_size, so only linger flushes it)
        sink.send(&topic, &Bytes::from_static(b"row-1"), QoS::AtMostOnce)
            .await
            .expect("row buffers");
        assert_eq!(sink.buffered_rows(), 1);

        // Wait through the first 2s backoff window: the linger task keeps
        // polling during backoff but must not reflood the log.
        tokio::time::sleep(Duration::from_secs(3)).await;

        assert!(
            transport.calls() >= 1,
            "the linger task attempted at least one flush"
        );
        assert_eq!(
            subscriber.count_contains("mysql linger flush failed"),
            1,
            "the failure is logged exactly once, not on every tick"
        );

        // The backoff fast-fail should NOT be logged on every tick
        let backoff_logs = subscriber.count_contains("sink backing off after errors");
        assert_eq!(
            backoff_logs, 0,
            "backoff fast-fail should not be logged by linger task"
        );

        // Clean up
        drop(sink);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_linger_flush_logs_recovery_on_success() {
        let subscriber = Arc::new(TestSubscriber::new());
        let _guard = tracing::subscriber::set_default(subscriber.clone());

        // The first linger flush fails; the retry after the 2s backoff
        // window succeeds.
        let transport = Arc::new(FailOnceTransport::new(1));
        let mut config = test_config();
        config.batch_size = 100;
        config.batch_timeout_ms = 50;
        let sink = MySqlSink::new(config, transport.clone()).expect("valid sink");
        let topic = Topic::new("sensors/temp").unwrap();

        sink.send(&topic, &Bytes::from_static(b"row-1"), QoS::AtMostOnce)
            .await
            .expect("row buffers");

        tokio::time::sleep(Duration::from_secs(3)).await;

        assert_eq!(transport.calls(), 2, "one failed flush plus one retry");
        assert_eq!(sink.buffered_rows(), 0);
        assert_eq!(sink.sent_batches(), 1);
        assert_eq!(
            subscriber.count_contains("mysql linger flush failed"),
            1,
            "the failure is logged once"
        );
        assert_eq!(
            subscriber.count_contains("mysql linger flush recovered"),
            1,
            "recovery is logged once at info"
        );

        drop(sink);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_linger_timer_idle_when_buffer_empty() {
        let transport = Arc::new(RecordingTransport::new());
        let mut config = test_config();
        config.batch_size = 100;
        config.batch_timeout_ms = 50;
        let sink = MySqlSink::new(config, transport.clone()).expect("valid sink");
        let topic = Topic::new("sensors/temp").unwrap();

        // Send one row - it will be flushed by linger timer
        sink.send(&topic, &Bytes::from_static(b"row-1"), QoS::AtMostOnce)
            .await
            .expect("row buffers");
        assert_eq!(sink.buffered_rows(), 1);

        // Wait for linger flush
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Row should be flushed
        assert_eq!(sink.buffered_rows(), 0);
        assert_eq!(sink.sent_batches(), 1);
        assert_eq!(transport.calls(), 1);

        // Now wait longer - the timer should be idle, no more flushes
        let calls_after_idle = transport.calls();
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            transport.calls(),
            calls_after_idle,
            "timer should be idle when buffer empty"
        );

        // Send another row - timer should re-arm and flush
        sink.send(&topic, &Bytes::from_static(b"row-2"), QoS::AtMostOnce)
            .await
            .expect("row buffers");
        assert_eq!(sink.buffered_rows(), 1);

        tokio::time::sleep(Duration::from_millis(200)).await;

        assert_eq!(sink.buffered_rows(), 0);
        assert_eq!(sink.sent_batches(), 2);
        assert_eq!(transport.calls(), 2);

        drop(sink);
    }

    #[tokio::test]
    async fn test_row_arriving_while_timer_stops_is_not_stranded() {
        // Many short send/flush cycles with rows arriving around the
        // linger deadline; every row is eventually flushed.
        let transport = Arc::new(RecordingTransport::new());
        let mut config = test_config();
        config.batch_size = 100;
        config.batch_timeout_ms = 20;
        let sink = MySqlSink::new(config, transport.clone()).expect("valid sink");
        let topic = Topic::new("sensors/temp").unwrap();

        let mut expected_rows = 0;

        for i in 0..50 {
            sink.send(&topic, &Bytes::from(format!("row-{i}")), QoS::AtMostOnce)
                .await
                .expect("send");
            expected_rows += 1;

            // Random small delay around the linger timeout to create races
            if i % 7 == 0 {
                tokio::time::sleep(Duration::from_millis(15)).await; // less than linger
            } else if i % 11 == 0 {
                tokio::time::sleep(Duration::from_millis(25)).await; // more than linger
            }
        }

        // Final wait to ensure all lingering rows flush
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert_eq!(sink.buffered_rows(), 0, "no rows should be stranded");
        assert_eq!(
            sink.sent_batches(),
            transport.calls(),
            "sent_batches should match transport calls"
        );

        // Total rows sent should equal total rows in all batches
        let total_rows: usize = transport.batches().iter().map(|b| b.rows.len()).sum();
        assert_eq!(
            total_rows, expected_rows,
            "all rows should be flushed exactly once"
        );

        drop(sink);
    }

    #[tokio::test]
    async fn test_dropped_sink_stops_linger_task_promptly() {
        // With an empty buffer the linger task waits on a timer or
        // notification; it must not pin the sink core while waiting,
        // so dropping the sink frees the core within 200 ms.
        // The probe clones the inner `linger_notify` Arc: while the
        // core is alive the count is 3 (core + task + probe), and once
        // the core is freed it drops to 2 (task + probe).
        let transport = Arc::new(MemoryMySqlTransport::new());
        let mut config = test_config();
        config.batch_size = 100;
        config.batch_timeout_ms = 50;
        let sink = MySqlSink::new(config, transport).expect("valid sink");
        let probe = sink.core.linger_notify.clone();
        assert_eq!(Arc::strong_count(&probe), 3);
        drop(sink);
        let mut freed = false;
        for _ in 0..20 {
            if Arc::strong_count(&probe) == 2 {
                freed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(freed, "dropped sink core was not freed within 200 ms");
    }
}
