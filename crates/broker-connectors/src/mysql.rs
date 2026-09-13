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
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex as AsyncMutex;

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

#[async_trait]
pub trait MySqlTransport: Send + Sync {
    async fn execute_batch(&self, batch: &MySqlBatch) -> Result<()>;
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
    async fn execute_batch(&self, batch: &MySqlBatch) -> Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut failures = self.failures_left.lock();
        if *failures > 0 {
            *failures -= 1;
            return Err(ConnectorError::Connection(
                "mock transport down".to_string(),
            ));
        }
        self.batches.lock().push(batch.clone());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MySQL client protocol (handshake, prepare, execute).
// ---------------------------------------------------------------------------

const CAP_LONG_PASSWORD: u32 = 0x0000_0001;
const CAP_LONG_FLAG: u32 = 0x0000_0004;
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

fn decode_lenenc(cursor: &mut &[u8]) -> Result<u64> {
    fn underflow() -> ConnectorError {
        ConnectorError::Connection("truncated mysql packet".to_string())
    }
    if cursor.is_empty() {
        return Err(underflow());
    }
    let first = cursor[0];
    *cursor = &cursor[1..];
    match first {
        0xFB => Err(ConnectorError::Connection(
            "unexpected mysql NULL length".to_string(),
        )),
        0xFC => {
            if cursor.len() < 2 {
                return Err(underflow());
            }
            let value = u16::from_le_bytes([cursor[0], cursor[1]]) as u64;
            *cursor = &cursor[2..];
            Ok(value)
        }
        0xFD => {
            if cursor.len() < 3 {
                return Err(underflow());
            }
            let value = u32::from_le_bytes([cursor[0], cursor[1], cursor[2], 0]) as u64;
            *cursor = &cursor[3..];
            Ok(value)
        }
        0xFE => {
            if cursor.len() < 8 {
                return Err(underflow());
            }
            let value = u64::from_le_bytes([
                cursor[0], cursor[1], cursor[2], cursor[3], cursor[4], cursor[5], cursor[6],
                cursor[7],
            ]);
            *cursor = &cursor[8..];
            Ok(value)
        }
        byte => Ok(byte as u64),
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
    seq: u8,
    prepared_stmt: Option<u32>,
}

async fn handshake(endpoint: &MySqlEndpoint, stream: &mut TcpStream, seq: &mut u8) -> Result<()> {
    // Server greeting.
    let greeting = read_packet(stream).await?;
    if greeting.seq != 0 {
        return Err(ConnectorError::Connection(
            "mysql greeting must use sequence 0".to_string(),
        ));
    }
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
    body.extend_from_slice(&CLIENT_CAPABILITIES.to_le_bytes());
    body.extend_from_slice(&0x01000000u32.to_le_bytes()); // max packet 16MB
    body.push(45); // utf8mb4
    body.extend_from_slice(&[0u8; 23]);
    body.extend_from_slice(endpoint.user.as_bytes());
    body.push(0);
    body.push(token.len() as u8);
    body.extend_from_slice(&token);
    if !endpoint.database.is_empty() {
        body.extend_from_slice(endpoint.database.as_bytes());
    }
    body.push(0);
    body.extend_from_slice(MYSQL_NATIVE_PASSWORD.as_bytes());
    body.push(0);
    write_packet(stream, seq, &body).await?;

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
                let seed = cursor.to_vec();
                let token = native_password_token(endpoint.password.as_bytes(), &seed);
                write_packet(stream, seq, &token).await?;
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
        let mut seq = 0u8;
        // Greeting sequence number starts at 0 server-side; our first
        // client packet uses 1.
        seq = seq.wrapping_add(1);
        handshake(&self.endpoint, &mut stream, &mut seq).await?;
        Ok(MysqlConn {
            stream,
            seq,
            prepared_stmt: None,
        })
    }
}

/// COM_STMT_PREPARE the template; returns the statement id and the
/// server-reported parameter count.
async fn prepare_statement(conn: &mut MysqlConn, sql: &str) -> Result<(u32, u16)> {
    let mut body = vec![0x16];
    body.extend_from_slice(sql.as_bytes());
    write_packet(&mut conn.stream, &mut conn.seq, &body).await?;
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
    let _columns = u16::from_le_bytes([response.body[5], response.body[6]]);
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
    async fn execute_batch(&self, batch: &MySqlBatch) -> Result<()> {
        if batch.rows.is_empty() {
            return Ok(());
        }
        let slot = (self.cursor.fetch_add(1, Ordering::SeqCst) as usize) % self.pool.len();
        let mut guard = self.pool[slot].lock().await;
        for _ in 0..2 {
            if guard.is_none() {
                *guard = Some(self.dial().await?);
            }
            let conn = guard.as_mut().expect("connected");
            match execute_batch_on_conn(conn, batch).await {
                Ok(()) => return Ok(()),
                Err(_) => {
                    *guard = None;
                }
            }
        }
        Err(ConnectorError::Connection(
            "mysql batch failed after reconnect".to_string(),
        ))
    }
}

async fn execute_batch_on_conn(conn: &mut MysqlConn, batch: &MySqlBatch) -> Result<()> {
    let stmt_id = match conn.prepared_stmt {
        Some(id) => id,
        None => {
            let (id, param_count) = prepare_statement(conn, &batch.sql).await?;
            if param_count as usize != batch.rows.first().map(|row| row.len()).unwrap_or(0) {
                return Err(ConnectorError::Dispatch(format!(
                    "mysql prepared param count {param_count} mismatches row width"
                )));
            }
            conn.prepared_stmt = Some(id);
            id
        }
    };
    // Pipeline every row's Execute, then drain one OK/ERR per row.
    for row in &batch.rows {
        let frame = encode_execute(stmt_id, row);
        let mut packet = Vec::with_capacity(4 + frame.len());
        let len = frame.len() as u32;
        packet.push((len & 0xFF) as u8);
        packet.push(((len >> 8) & 0xFF) as u8);
        packet.push(((len >> 16) & 0xFF) as u8);
        packet.push(conn.seq);
        conn.seq = conn.seq.wrapping_add(1);
        packet.extend_from_slice(&frame);
        conn.stream
            .write_all(&packet)
            .await
            .map_err(|e| ConnectorError::Connection(format!("mysql write failed: {e}")))?;
    }
    conn.stream
        .flush()
        .await
        .map_err(|e| ConnectorError::Connection(format!("mysql flush failed: {e}")))?;
    for _ in &batch.rows {
        let response = read_packet(&mut conn.stream).await?;
        match response.body.first() {
            Some(0x00) => {
                // OK packet: affected-rows + last-insert-id (lenenc).
                let mut cursor = &response.body[1..];
                decode_lenenc(&mut cursor)?;
                decode_lenenc(&mut cursor)?;
            }
            Some(0xFF) => {
                return Err(ConnectorError::Dispatch(format!(
                    "mysql execute failed: {}",
                    error_text(&response.body)
                )));
            }
            _ => {
                return Err(ConnectorError::Connection(
                    "unexpected mysql execute response".to_string(),
                ));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Sink.
// ---------------------------------------------------------------------------

/// MySQL sink: buffers MQTT events as 3-column rows
/// (`?` topic, QoS, payload positional) and flushes full or stale
/// batches through the transport, with the same backoff-with-restore
/// contract as the PostgreSQL sink.
pub struct MySqlSink {
    config: MySqlSinkConfig,
    transport: Arc<dyn MySqlTransport>,
    buffer: parking_lot::Mutex<super::BatchQueue<Vec<Vec<u8>>>>,
    backoff: parking_lot::Mutex<super::BackoffState>,
    sent_batches: AtomicU64,
}

impl MySqlSink {
    pub fn new(config: MySqlSinkConfig, transport: Arc<dyn MySqlTransport>) -> Result<Self> {
        config.validate()?;
        let linger = Duration::from_millis(config.batch_timeout_ms);
        Ok(Self {
            buffer: parking_lot::Mutex::new(super::BatchQueue::new(config.batch_size, linger)),
            config,
            transport,
            backoff: parking_lot::Mutex::new(super::BackoffState::default()),
            sent_batches: AtomicU64::new(0),
        })
    }

    pub fn config(&self) -> &MySqlSinkConfig {
        &self.config
    }

    pub fn sent_batches(&self) -> u64 {
        self.sent_batches.load(Ordering::Relaxed)
    }

    pub fn buffered_rows(&self) -> usize {
        self.buffer.lock().len()
    }

    /// Flush buffered rows as one batch (no-op when empty). While
    /// backing off, fails fast without touching the transport.
    pub async fn flush(&self) -> Result<()> {
        self.backoff.lock().check()?;
        let (rows, oldest) = self.buffer.lock().take_batch();
        if rows.is_empty() {
            return Ok(());
        }
        let batch = MySqlBatch {
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

    fn buffer_row(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> bool {
        self.buffer.lock().push(vec![
            topic.as_str().as_bytes().to_vec(),
            u8::from(qos).to_string().into_bytes(),
            payload.to_vec(),
        ])
    }
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
    async fn test_stale_batch_flushes_on_linger() {
        // Batch of 100 never fills; the second row arrives after the
        // linger timeout, so the stale batch flushes through the
        // in-memory transport.
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
        .expect("row one buffers");
        assert_eq!(sink.buffered_rows(), 1);
        tokio::time::sleep(Duration::from_millis(60)).await;
        sink.send(
            &topic,
            &Bytes::from_static(br#"{ "v": 2 }"#),
            QoS::AtMostOnce,
        )
        .await
        .expect("stale batch flushes");
        assert_eq!(sink.sent_batches(), 1);
        assert_eq!(sink.buffered_rows(), 0);
        let batches = transport.batches();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].rows.len(), 2);
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
}
