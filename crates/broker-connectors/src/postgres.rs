//! PostgreSQL sink over the native wire protocol.
//!
//! MQTT events become parameterized `INSERT` rows: `$1` is the topic,
//! `$2` the QoS level, `$3` the raw payload (cast server-side, e.g.
//! `$3::jsonb`); any other `$N` marker is rejected so statements can
//! never address unbound parameters. Execution uses the extended query
//! protocol (Parse/Bind/Describe/Execute/Sync pipelined per flush), so
//! values travel out-of-band and SQL injection is structurally
//! impossible. The [`PgTransport`] boundary keeps unit tests
//! broker-free ([`MemoryPgTransport`]); [`TcpPgTransport`] speaks startup,
//! trust/MD5/SCRAM-SHA-256 auth, and batched extended-protocol inserts.

use super::{ConnectorError, Result, Sink};
use async_trait::async_trait;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use md5::Digest as Md5Digest;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex as AsyncMutex;

fn md5_hex(data: &[u8]) -> String {
    format!("{:x}", md5::Md5::digest(data))
}

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
pub struct PostgreSqlSinkConfig {
    pub connection_url: String,
    pub sql_template: String,
    #[serde(default = "default_pool_size")]
    pub pool_size: usize,
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    #[serde(default = "default_batch_timeout_ms")]
    pub batch_timeout_ms: u64,
}

impl PostgreSqlSinkConfig {
    pub fn validate(&self) -> Result<()> {
        if self.connection_url.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "postgres connection_url must not be empty".to_string(),
            ));
        }
        if self.sql_template.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "postgres sql_template must not be empty".to_string(),
            ));
        }
        validate_placeholders(&self.sql_template)?;
        if self.pool_size == 0 {
            return Err(ConnectorError::Dispatch(
                "postgres pool_size must be >= 1".to_string(),
            ));
        }
        if self.batch_size == 0 {
            return Err(ConnectorError::Dispatch(
                "postgres batch_size must be >= 1".to_string(),
            ));
        }
        Ok(())
    }
}

/// Scan a template for `$N` markers outside strings, quoted identifiers,
/// and comments. Only `$1..=$3` exist (`$1` topic, `$2` QoS, `$3`
/// payload); anything else is rejected so unbound parameters can never
/// reach the server.
fn referenced_params(template: &str) -> Result<Vec<u32>> {
    let chars: Vec<char> = template.chars().collect();
    let n = chars.len();
    let mut found = Vec::new();
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
                if quote == '\'' && i + 1 < n && chars[i + 1] == '\'' {
                    i += 2; // escaped quote
                } else {
                    in_string = None;
                    i += 1;
                }
            } else {
                i += 1;
            }
            continue;
        }
        match c {
            '\'' | '"' => {
                in_string = Some(c);
                i += 1;
            }
            '-' if i + 1 < n && chars[i + 1] == '-' => {
                in_line_comment = true;
                i += 2;
            }
            '/' if i + 1 < n && chars[i + 1] == '*' => {
                in_block_comment = true;
                i += 2;
            }
            '$' => {
                let mut j = i + 1;
                while j < n && chars[j].is_ascii_digit() {
                    j += 1;
                }
                if j == i + 1 {
                    i += 1; // lone `$`: not a marker (e.g. dollar quoting edge)
                    continue;
                }
                let number: u32 = chars[i + 1..j].iter().collect::<String>().parse().map_err(
                    |_| ConnectorError::Dispatch("postgres parameter number overflow".to_string()),
                )?;
                found.push(number);
                i = j;
            }
            _ => {
                i += 1;
            }
        }
    }
    Ok(found)
}

fn validate_placeholders(template: &str) -> Result<()> {
    for number in referenced_params(template)? {
        if number == 0 || number > 3 {
            return Err(ConnectorError::Dispatch(format!(
                "postgres only $1 (topic), $2 (qos) and $3 (payload) exist, got ${number}"
            )));
        }
    }
    Ok(())
}

/// One flushed batch: the statement plus one 3-column row per event.
#[derive(Debug, Clone, Default)]
pub struct PgBatch {
    pub sql: String,
    pub rows: Vec<Vec<Vec<u8>>>,
}

#[async_trait]
pub trait PgTransport: Send + Sync {
    async fn execute_batch(&self, batch: &PgBatch) -> Result<()>;
}

/// In-memory transport recording every flushed batch (tests, dry runs).
#[derive(Debug, Default)]
pub struct MemoryPgTransport {
    batches: parking_lot::Mutex<Vec<PgBatch>>,
    failures_left: parking_lot::Mutex<usize>,
    calls: AtomicU64,
}

impl MemoryPgTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fail the next `n` executions with a transport error (backoff tests).
    pub fn fail_next(&self, n: usize) {
        *self.failures_left.lock() = n;
    }

    pub fn batches(&self) -> Vec<PgBatch> {
        self.batches.lock().clone()
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl PgTransport for MemoryPgTransport {
    async fn execute_batch(&self, batch: &PgBatch) -> Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut failures = self.failures_left.lock();
        if *failures > 0 {
            *failures -= 1;
            return Err(ConnectorError::Connection("mock transport down".to_string()));
        }
        self.batches.lock().push(batch.clone());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PostgreSQL wire protocol (startup, auth, extended query).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct PgEndpoint {
    host: String,
    port: u16,
    user: String,
    password: String,
    database: String,
}

/// Parse `postgresql://[user[:password]@]host[:port][/dbname][?params]`.
/// `sslmode=require` is rejected: this transport is cleartext-only by
/// design (terminate TLS upstream instead of silently downgrading).
fn parse_endpoint(url: &str) -> Result<PgEndpoint> {
    let rest = url.strip_prefix("postgresql://").ok_or_else(|| {
        ConnectorError::Dispatch(format!("postgres url must start with postgresql://: {url:?}"))
    })?;
    let (authority_path, query) = match rest.split_once('?') {
        Some((left, query)) => (left, query),
        None => (rest, ""),
    };
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, _) = pair.split_once('=').unwrap_or((pair, ""));
        if key.eq_ignore_ascii_case("sslmode") {
            let value = pair.split_once('=').map(|(_, v)| v).unwrap_or("");
            if value.eq_ignore_ascii_case("require") || value.eq_ignore_ascii_case("verify-full") {
                return Err(ConnectorError::Dispatch(
                    "postgres TLS is not supported by this transport; terminate upstream or use sslmode=disable"
                        .to_string(),
                ));
            }
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
    let user = if user.is_empty() { "postgres".to_string() } else { user };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((host, port)) => (
            host.to_string(),
            port.parse::<u16>().map_err(|_| {
                ConnectorError::Dispatch(format!("postgres bad port in {url:?}"))
            })?,
        ),
        None => (hostport.to_string(), 5432),
    };
    if host.is_empty() {
        return Err(ConnectorError::Dispatch(format!(
            "postgres url needs a host: {url:?}"
        )));
    }
    let database = if dbname.is_empty() { user.clone() } else { dbname.to_string() };
    Ok(PgEndpoint {
        host,
        port,
        user,
        password,
        database,
    })
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut padded = [0u8; BLOCK];
    if key.len() > BLOCK {
        padded[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        padded[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5eu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= padded[i];
        opad[i] ^= padded[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(data);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    outer.finalize().into()
}

fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut block = Vec::with_capacity(salt.len() + 4);
    block.extend_from_slice(salt);
    block.extend_from_slice(&1u32.to_be_bytes());
    let mut u = hmac_sha256(password, &block);
    let mut result = u;
    for _ in 1..iterations {
        u = hmac_sha256(password, &u);
        for (slot, byte) in result.iter_mut().zip(u.iter()) {
            *slot ^= *byte;
        }
    }
    result
}

fn escape_scram_name(name: &str) -> String {
    name.replace('=', "=3D").replace(',', "=2C")
}

static SCRAM_NONCE_COUNTER: AtomicU64 = AtomicU64::new(1);

fn scram_nonce() -> String {
    use base64::Engine;
    let counter = SCRAM_NONCE_COUNTER.fetch_add(1, Ordering::SeqCst);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut raw = counter.to_be_bytes().to_vec();
    raw.extend_from_slice(&now.to_be_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
}

async fn read_msg(stream: &mut TcpStream) -> Result<(u8, Vec<u8>)> {
    let mut header = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut header))
        .await
        .map_err(|_| ConnectorError::Connection("postgres read timeout".to_string()))?
        .map_err(|e| ConnectorError::Connection(format!("postgres read failed: {e}")))?;
    let len = i32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if len < 4 || len > 16 * 1024 * 1024 {
        return Err(ConnectorError::Connection(format!(
            "postgres bad message length: {len}"
        )));
    }
    let mut body = vec![0u8; len - 4];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut body))
        .await
        .map_err(|_| ConnectorError::Connection("postgres read timeout".to_string()))?
        .map_err(|e| ConnectorError::Connection(format!("postgres read failed: {e}")))?;
    Ok((header[0], body))
}

async fn write_msg(stream: &mut TcpStream, tag: u8, body: &[u8]) -> Result<()> {
    let mut frame = Vec::with_capacity(5 + body.len());
    frame.push(tag);
    frame.extend_from_slice(&((body.len() + 4) as i32).to_be_bytes());
    frame.extend_from_slice(body);
    stream
        .write_all(&frame)
        .await
        .map_err(|e| ConnectorError::Connection(format!("postgres write failed: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| ConnectorError::Connection(format!("postgres flush failed: {e}")))?;
    Ok(())
}

/// Extract the human message (`M` field) from an ErrorResponse body.
fn error_message(body: &[u8]) -> String {
    let mut cursor = body;
    while cursor.len() >= 2 {
        let code = cursor[0];
        cursor = &cursor[1..];
        let end = cursor.iter().position(|&b| b == 0).unwrap_or(cursor.len());
        let value = String::from_utf8_lossy(&cursor[..end]).to_string();
        cursor = &cursor[end.min(cursor.len())..];
        if !cursor.is_empty() {
            cursor = &cursor[1..];
        }
        if code == b'M' && !value.is_empty() {
            return value;
        }
    }
    "postgres error (no message field)".to_string()
}

/// Drain server messages until ReadyForQuery, surfacing the first error.
async fn drain_to_ready(stream: &mut TcpStream) -> Result<()> {
    let mut failure: Option<String> = None;
    loop {
        let (tag, body) = read_msg(stream).await?;
        match tag {
            b'Z' => break,
            b'E' if failure.is_none() => {
                failure = Some(error_message(&body));
            }
            _ => {}
        }
    }
    match failure {
        Some(message) => Err(ConnectorError::Dispatch(format!("postgres: {message}"))),
        None => Ok(()),
    }
}

struct PgConn {
    stream: TcpStream,
}

async fn startup_handshake(endpoint: &PgEndpoint, stream: &mut TcpStream) -> Result<()> {
    // SSLRequest first: proceed only on explicit 'N' (cleartext).
    let mut probe = (8i32).to_be_bytes().to_vec();
    probe.extend_from_slice(&80877103i32.to_be_bytes());
    stream
        .write_all(&probe)
        .await
        .map_err(|e| ConnectorError::Connection(format!("postgres write failed: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| ConnectorError::Connection(format!("postgres flush failed: {e}")))?;
    let mut answer = [0u8; 1];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut answer))
        .await
        .map_err(|_| ConnectorError::Connection("postgres SSL probe timeout".to_string()))?
        .map_err(|e| ConnectorError::Connection(format!("postgres read failed: {e}")))?;
    if answer[0] == b'S' {
        return Err(ConnectorError::Connection(
            "postgres server demands TLS; this transport is cleartext-only".to_string(),
        ));
    }

    // StartupMessage: protocol 3.0 + user/database/client_encoding.
    let mut params = Vec::new();
    for (key, value) in [
        ("user", endpoint.user.as_str()),
        ("database", endpoint.database.as_str()),
        ("client_encoding", "UTF8"),
        ("application_name", "indramqtt"),
    ] {
        params.extend_from_slice(key.as_bytes());
        params.push(0);
        params.extend_from_slice(value.as_bytes());
        params.push(0);
    }
    params.push(0);
    let mut startup = (params.len() as i32 + 8).to_be_bytes().to_vec();
    startup.extend_from_slice(&196608i32.to_be_bytes());
    startup.extend_from_slice(&params);
    stream
        .write_all(&startup)
        .await
        .map_err(|e| ConnectorError::Connection(format!("postgres write failed: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| ConnectorError::Connection(format!("postgres flush failed: {e}")))?;

    // Authentication loop.
    loop {
        let (tag, body) = read_msg(stream).await?;
        match tag {
            b'R' => {
                if body.len() < 4 {
                    return Err(ConnectorError::Connection(
                        "truncated auth request".to_string(),
                    ));
                }
                let kind = i32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                match kind {
                    0 => break, // AuthenticationOk
                    5 => {
                        // MD5: md5(md5(password + user) + salt).
                        if body.len() < 8 {
                            return Err(ConnectorError::Connection(
                                "truncated md5 salt".to_string(),
                            ));
                        }
                        let salt = &body[4..8];
                        let mut first = endpoint.password.clone();
                        first.push_str(&endpoint.user);
                        let inner = md5_hex(first.as_bytes());
                        let mut outer = inner;
                        outer.push_str(&hex(salt));
                        let response = format!("md5{}", md5_hex(outer.as_bytes()));
                        let mut msg = response.into_bytes();
                        msg.push(0);
                        write_msg(stream, b'p', &msg).await?;
                    }
                    10 => {
                        // SASL: require SCRAM-SHA-256, then run the exchange.
                        if !body[4..].split(|b| *b == 0).any(|m| m == b"SCRAM-SHA-256") {
                            return Err(ConnectorError::Connection(
                                "postgres offers no SCRAM-SHA-256".to_string(),
                            ));
                        }
                        scram_exchange(&endpoint.user, endpoint.password.as_bytes(), stream).await?;
                    }
                    _ => {
                        return Err(ConnectorError::Connection(format!(
                            "unsupported postgres auth method {kind}"
                        )));
                    }
                }
            }
            b'E' => {
                return Err(ConnectorError::Connection(format!(
                    "postgres startup failed: {}",
                    error_message(&body)
                )));
            }
            _ => {}
        }
    }

    // ParameterStatus / BackendKeyData until ReadyForQuery.
    drain_to_ready(stream).await?;
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

async fn scram_exchange(user: &str, password: &[u8], stream: &mut TcpStream) -> Result<()> {
    use base64::Engine;
    let client_nonce = scram_nonce();
    let client_first_bare = format!("n={},r={}", escape_scram_name(user), client_nonce);

    // SASLInitialResponse: mechanism + initial response.
    let mut initial = b"SCRAM-SHA-256\0".to_vec();
    initial.extend_from_slice(&(client_first_bare.len() as i32).to_be_bytes());
    initial.extend_from_slice(client_first_bare.as_bytes());
    write_msg(stream, b'p', &initial).await?;

    // AuthenticationSASLContinue: server-first-message.
    let (tag, body) = read_msg(stream).await?;
    if tag != b'R' || body.len() < 4 || i32::from_be_bytes([body[0], body[1], body[2], body[3]]) != 11
    {
        return Err(ConnectorError::Connection(
            "expected SASL continue".to_string(),
        ));
    }
    let server_first = std::str::from_utf8(&body[4..])
        .map_err(|_| ConnectorError::Connection("non-utf8 SASL message".to_string()))?;
    let mut combined_nonce = String::new();
    let mut salt_b64 = String::new();
    let mut iterations = 0u32;
    for part in server_first.split(',') {
        let (key, value) = part.split_once('=').ok_or_else(|| {
            ConnectorError::Connection("malformed SASL server-first".to_string())
        })?;
        match key {
            "r" => combined_nonce = value.to_string(),
            "s" => salt_b64 = value.to_string(),
            "i" => {
                iterations = value.parse().map_err(|_| {
                    ConnectorError::Connection("malformed SASL iteration count".to_string())
                })?
            }
            _ => {}
        }
    }
    if !combined_nonce.starts_with(&client_nonce) || salt_b64.is_empty() || iterations == 0 {
        return Err(ConnectorError::Connection(
            "invalid SASL server-first message".to_string(),
        ));
    }
    let salt = base64::engine::general_purpose::STANDARD
        .decode(&salt_b64)
        .map_err(|_| ConnectorError::Connection("bad SASL salt".to_string()))?;

    let salted = pbkdf2_sha256(password, &salt, iterations);
    let client_key = hmac_sha256(&salted, b"Client Key");
    let mut hasher = Sha256::new();
    hasher.update(client_key);
    let stored_key: [u8; 32] = hasher.finalize().into();
    let client_final_without_proof = format!("c=biws,r={combined_nonce}");
    let auth_message = format!("{client_first_bare},{server_first},{client_final_without_proof}");
    let client_signature = hmac_sha256(&stored_key, auth_message.as_bytes());
    let mut proof = client_key;
    for (slot, byte) in proof.iter_mut().zip(client_signature.iter()) {
        *slot ^= *byte;
    }
    let client_final = format!(
        "{client_final_without_proof},p={}",
        base64::engine::general_purpose::STANDARD.encode(proof)
    );
    write_msg(stream, b'p', client_final.as_bytes()).await?;

    // AuthenticationSASLFinal: verify the server signature (no blind trust).
    let (tag, body) = read_msg(stream).await?;
    if tag != b'R' || body.len() < 4 || i32::from_be_bytes([body[0], body[1], body[2], body[3]]) != 12
    {
        return Err(ConnectorError::Connection(
            "expected SASL final".to_string(),
        ));
    }
    let server_final = std::str::from_utf8(&body[4..])
        .map_err(|_| ConnectorError::Connection("non-utf8 SASL final".to_string()))?;
    let server_signature = server_final
        .strip_prefix("v=")
        .ok_or_else(|| ConnectorError::Connection("malformed SASL final".to_string()))?;
    let server_key = hmac_sha256(&salted, b"Server Key");
    let expected = hmac_sha256(&server_key, auth_message.as_bytes());
    let expected_b64 = base64::engine::general_purpose::STANDARD.encode(expected);
    if expected_b64 != server_signature {
        return Err(ConnectorError::Connection(
            "postgres server signature mismatch".to_string(),
        ));
    }
    Ok(())
}

/// TCP transport with a tiny round-robin pool. Connections establish
/// lazily on first use (creation never blocks on external brokers).
pub struct TcpPgTransport {
    endpoint: PgEndpoint,
    pool: Vec<AsyncMutex<Option<PgConn>>>,
    cursor: AtomicU64,
}

impl TcpPgTransport {
    pub fn new(url: &str, pool_size: usize) -> Result<Self> {
        if pool_size == 0 {
            return Err(ConnectorError::Dispatch(
                "postgres pool_size must be >= 1".to_string(),
            ));
        }
        Ok(Self {
            endpoint: parse_endpoint(url)?,
            pool: (0..pool_size).map(|_| AsyncMutex::new(None)).collect(),
            cursor: AtomicU64::new(0),
        })
    }

    async fn dial(&self) -> Result<PgConn> {
        let addr = format!("{}:{}", self.endpoint.host, self.endpoint.port);
        let mut stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&addr))
            .await
            .map_err(|_| {
                ConnectorError::Connection(format!("postgres connect timeout: {addr}"))
            })?
            .map_err(|e| ConnectorError::Connection(format!("postgres connect failed: {e}")))?;
        startup_handshake(&self.endpoint, &mut stream).await?;
        Ok(PgConn { stream })
    }
}

#[async_trait]
impl PgTransport for TcpPgTransport {
    async fn execute_batch(&self, batch: &PgBatch) -> Result<()> {
        if batch.rows.is_empty() {
            return Ok(());
        }
        // Round-robin checkout with reconnect-once: a poisoned slot is
        // dropped and the batch retried on a fresh connection.
        let slot = (self.cursor.fetch_add(1, Ordering::SeqCst) as usize) % self.pool.len();
        let mut guard = self.pool[slot].lock().await;
        for _ in 0..2 {
            if guard.is_none() {
                *guard = Some(self.dial().await?);
            }
            let stream = &mut guard.as_mut().expect("connected").stream;
            match execute_extended(stream, &batch).await {
                Ok(()) => return Ok(()),
                Err(_) => {
                    *guard = None;
                }
            }
        }
        Err(ConnectorError::Connection(
            "postgres batch failed after reconnect".to_string(),
        ))
    }
}

/// Run one batch through the extended protocol, pipelined in a single
/// write: Parse once, then Bind/Describe/Execute per row, then Sync.
/// Values travel as TEXT params; the server casts (e.g. `$3::jsonb`).
fn encode_extended_batch(batch: &PgBatch) -> Vec<u8> {
    fn push_msg(out: &mut Vec<u8>, tag: u8, body: &[u8]) {
        out.push(tag);
        out.extend_from_slice(&((body.len() + 4) as i32).to_be_bytes());
        out.extend_from_slice(body);
    }

    let mut out = Vec::new();
    // Parse: unnamed statement, inferred param types.
    let mut parse = Vec::new();
    parse.push(0);
    parse.extend_from_slice(batch.sql.as_bytes());
    parse.push(0);
    parse.extend_from_slice(&0u16.to_be_bytes());
    push_msg(&mut out, b'P', &parse);

    for (index, row) in batch.rows.iter().enumerate() {
        let portal = format!("indra_{index}");
        // Bind: named portal, unnamed statement, all-TEXT formats.
        let mut bind = Vec::new();
        bind.extend_from_slice(portal.as_bytes());
        bind.push(0);
        bind.push(0);
        bind.extend_from_slice(&(row.len() as u16).to_be_bytes());
        for _ in row {
            bind.extend_from_slice(&0u16.to_be_bytes());
        }
        bind.extend_from_slice(&(row.len() as u16).to_be_bytes());
        for value in row {
            bind.extend_from_slice(&(value.len() as i32).to_be_bytes());
            bind.extend_from_slice(value);
        }
        bind.extend_from_slice(&0u16.to_be_bytes());
        push_msg(&mut out, b'B', &bind);
        // Describe portal (drains parameter/row descriptions).
        let mut describe = vec![b'P'];
        describe.extend_from_slice(portal.as_bytes());
        describe.push(0);
        push_msg(&mut out, b'D', &describe);
        // Execute to completion.
        let mut execute = Vec::new();
        execute.extend_from_slice(portal.as_bytes());
        execute.push(0);
        execute.extend_from_slice(&0i32.to_be_bytes());
        push_msg(&mut out, b'E', &execute);
    }
    push_msg(&mut out, b'S', &[]);
    out
}

async fn execute_extended(stream: &mut TcpStream, batch: &PgBatch) -> Result<()> {
    let bytes = encode_extended_batch(batch);
    stream
        .write_all(&bytes)
        .await
        .map_err(|e| ConnectorError::Connection(format!("postgres write failed: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| ConnectorError::Connection(format!("postgres flush failed: {e}")))?;
    drain_to_ready(stream).await
}

// ---------------------------------------------------------------------------
// Sink.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct RowBuffer {
    rows: Vec<Vec<Vec<u8>>>,
    oldest: Option<Instant>,
}

/// PostgreSQL sink: buffers MQTT events as 3-column rows
/// (`$1` topic, `$2` QoS, `$3` payload) and flushes full or stale
/// batches through the transport. Transport failures back off
/// exponentially (capped) without losing buffered rows.
pub struct PostgreSqlSink {
    config: PostgreSqlSinkConfig,
    transport: Arc<dyn PgTransport>,
    buffer: parking_lot::Mutex<RowBuffer>,
    backoff: parking_lot::Mutex<BackoffState>,
    sent_batches: AtomicU64,
}

#[derive(Default)]
struct BackoffState {
    consecutive_errors: u32,
    retry_after: Option<Instant>,
}

impl PostgreSqlSink {
    pub fn new(config: PostgreSqlSinkConfig, transport: Arc<dyn PgTransport>) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            transport,
            buffer: parking_lot::Mutex::new(RowBuffer::default()),
            backoff: parking_lot::Mutex::new(BackoffState::default()),
            sent_batches: AtomicU64::new(0),
        })
    }

    pub fn config(&self) -> &PostgreSqlSinkConfig {
        &self.config
    }

    pub fn sent_batches(&self) -> u64 {
        self.sent_batches.load(Ordering::Relaxed)
    }

    pub fn buffered_rows(&self) -> usize {
        self.buffer.lock().rows.len()
    }

    /// Flush buffered rows as one batch (no-op when empty). While
    /// backing off, fails fast without touching the transport.
    pub async fn flush(&self) -> Result<()> {
        {
            let backoff = self.backoff.lock();
            if let Some(retry_after) = backoff.retry_after {
                if Instant::now() < retry_after {
                    return Err(ConnectorError::Connection(
                        "postgres sink backing off after errors".to_string(),
                    ));
                }
            }
        }
        let (batch, oldest) = {
            let mut buffer = self.buffer.lock();
            if buffer.rows.is_empty() {
                return Ok(());
            }
            let rows = std::mem::take(&mut buffer.rows);
            let oldest = buffer.oldest.take();
            (
                PgBatch {
                    sql: self.config.sql_template.clone(),
                    rows,
                },
                oldest,
            )
        };
        match self.transport.execute_batch(&batch).await {
            Ok(()) => {
                let mut backoff = self.backoff.lock();
                backoff.consecutive_errors = 0;
                backoff.retry_after = None;
                self.sent_batches.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                // Restore the batch at the front (order preserved) so a
                // failed flush loses nothing.
                let mut buffer = self.buffer.lock();
                let mut restored = batch.rows;
                restored.append(&mut buffer.rows);
                buffer.rows = restored;
                if buffer.oldest.is_none() {
                    buffer.oldest = oldest;
                }
                let mut backoff = self.backoff.lock();
                backoff.consecutive_errors += 1;
                let secs = 2u64.saturating_pow(backoff.consecutive_errors.min(5)).min(30);
                backoff.retry_after = Some(Instant::now() + Duration::from_secs(secs));
                Err(e)
            }
        }
    }

    fn buffer_row(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> bool {
        let mut buffer = self.buffer.lock();
        if buffer.rows.is_empty() {
            buffer.oldest = Some(Instant::now());
        }
        buffer.rows.push(vec![
            topic.as_str().as_bytes().to_vec(),
            u8::from(qos).to_string().into_bytes(),
            payload.to_vec(),
        ]);
        let stale = buffer
            .oldest
            .map(|oldest| oldest.elapsed().as_millis() >= u128::from(self.config.batch_timeout_ms))
            .unwrap_or(false);
        buffer.rows.len() >= self.config.batch_size || stale
    }
}

#[async_trait]
impl Sink for PostgreSqlSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> super::Result<()> {
        if self.buffer_row(topic, payload, qos) {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "postgres"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> PostgreSqlSinkConfig {
        PostgreSqlSinkConfig {
            connection_url: "postgresql://user:pass@127.0.0.1:5432/db".to_string(),
            sql_template: "INSERT INTO sensor_data (topic, qos, payload, recorded_at) VALUES ($1, $2, $3::jsonb, NOW())".to_string(),
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
        config.connection_url = "postgresql://h/db".to_string();

        config.sql_template.clear();
        assert!(config.validate().is_err());

        // Unknown / zero markers rejected (only $1..=$3 exist).
        for bad in [
            "INSERT INTO t VALUES ($1, $2, $4)",
            "INSERT INTO t VALUES ($0)",
            "INSERT INTO t VALUES ($1, $2, $3, $9)",
        ] {
            config.sql_template = bad.to_string();
            assert!(config.validate().is_err(), "must reject {bad:?}");
        }
        // Markers inside strings and comments are not parameters.
        config.sql_template =
            "INSERT INTO t (topic, note) VALUES ($1, 'cost $5 -- $9 /* $7 */')".to_string();
        assert!(config.validate().is_ok());
        config.sql_template =
            "INSERT INTO t (topic) VALUES ($1) -- trailing $8 comment".to_string();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_endpoint_parsing() {
        let endpoint =
            parse_endpoint("postgresql://user:pass@db.internal:5433/telemetry").expect("parses");
        assert_eq!(endpoint.host, "db.internal");
        assert_eq!(endpoint.port, 5433);
        assert_eq!(endpoint.user, "user");
        assert_eq!(endpoint.password, "pass");
        assert_eq!(endpoint.database, "telemetry");

        let endpoint = parse_endpoint("postgresql://dbhost").expect("defaults");
        assert_eq!(endpoint.port, 5432);
        assert_eq!(endpoint.user, "postgres");
        assert_eq!(endpoint.database, "postgres");

        assert!(parse_endpoint("mysql://h/db").is_err());
        assert!(parse_endpoint("postgresql://h/db?sslmode=require").is_err());
        assert!(parse_endpoint("postgresql://h:notaport/db").is_err());
        assert!(parse_endpoint("postgresql://:pass@/db").is_err());
    }

    fn test_sink(config: PostgreSqlSinkConfig) -> (PostgreSqlSink, Arc<MemoryPgTransport>) {
        let transport = Arc::new(MemoryPgTransport::new());
        let sink = PostgreSqlSink::new(config, transport.clone()).expect("valid sink");
        (sink, transport)
    }

    #[tokio::test]
    async fn test_batch_aggregation_and_parameter_binding() {
        let (sink, transport) = test_sink(test_config());
        let topic = Topic::new("sensors/temp").unwrap();

        // Three sends stay buffered (batch_size 100)...
        for _ in 0..3 {
            sink.send(&topic, &Bytes::from_static(br#"{ "v": 1 }"#), QoS::AtLeastOnce)
                .await
                .unwrap();
        }
        assert_eq!(sink.buffered_rows(), 3);
        assert!(transport.batches().is_empty());

        // ...until an explicit flush ships one 3-row batch.
        sink.flush().await.unwrap();
        assert_eq!(sink.buffered_rows(), 0);
        assert_eq!(sink.sent_batches(), 1);
        let batches = transport.batches();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].rows.len(), 3);
        assert!(batches[0].sql.contains("INSERT INTO sensor_data"));
        // $1 topic, $2 qos, $3 payload — no string interpolation.
        assert_eq!(batches[0].rows[0][0], b"sensors/temp");
        assert_eq!(batches[0].rows[0][1], b"1");
        assert_eq!(batches[0].rows[0][2], br#"{ "v": 1 }"#);
        assert!(!batches[0].sql.contains("sensors/temp"), "values stay bound");
    }

    #[tokio::test]
    async fn test_batch_size_triggers_flush() {
        let mut config = test_config();
        config.batch_size = 2;
        let (sink, transport) = test_sink(config);
        let topic = Topic::new("t").unwrap();
        sink.send(&topic, &Bytes::from_static(b"a"), QoS::AtMostOnce)
            .await
            .unwrap();
        assert!(transport.batches().is_empty());
        sink.send(&topic, &Bytes::from_static(b"b"), QoS::AtMostOnce)
            .await
            .unwrap();
        assert_eq!(transport.batches().len(), 1);
        assert_eq!(transport.batches()[0].rows.len(), 2);
    }

    #[tokio::test]
    async fn test_error_backoff_skips_transport() {
        // Batch of one: every send attempts a flush.
        let mut config = test_config();
        config.batch_size = 1;
        let (sink, transport) = test_sink(config);
        let topic = Topic::new("t").unwrap();
        transport.fail_next(10);

        sink.send(&topic, &Bytes::from_static(b"a"), QoS::AtMostOnce)
            .await
            .expect_err("first flush fails");
        assert_eq!(transport.calls(), 1);
        // Still backing off: the transport is not even consulted, and the
        // failed row is restored, not lost.
        sink.send(&topic, &Bytes::from_static(b"b"), QoS::AtMostOnce)
            .await
            .expect_err("backoff fails fast");
        assert_eq!(transport.calls(), 1, "backoff must skip the transport");
        assert_eq!(sink.buffered_rows(), 2);
    }

    // -- Fake PostgreSQL server helpers ----------------------------------

    async fn read_pg_msg(stream: &mut TcpStream) -> (u8, Vec<u8>) {
        let mut header = [0u8; 5];
        stream.read_exact(&mut header).await.expect("pg head");
        let len = i32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
        let mut body = vec![0u8; len - 4];
        stream.read_exact(&mut body).await.expect("pg body");
        (header[0], body)
    }

    async fn write_pg_msg(stream: &mut TcpStream, tag: u8, body: &[u8]) {
        let mut frame = vec![tag];
        frame.extend_from_slice(&((body.len() + 4) as i32).to_be_bytes());
        frame.extend_from_slice(body);
        stream.write_all(&frame).await.expect("pg write");
    }

    fn startup_params(body: &[u8]) -> Vec<(String, String)> {
        // `body` is the parameter block after the protocol version.
        let mut params = Vec::new();
        let mut parts = body.split(|b| *b == 0);
        while let (Some(key), Some(value)) = (parts.next(), parts.next()) {
            if key.is_empty() {
                break;
            }
            params.push((
                String::from_utf8_lossy(key).to_string(),
                String::from_utf8_lossy(value).to_string(),
            ));
        }
        params
    }

    async fn read_startup(stream: &mut TcpStream) -> Vec<(String, String)> {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await.expect("startup len");
        let len = i32::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; len - 4];
        stream.read_exact(&mut body).await.expect("startup body");
        assert_eq!(&body[..4], &196608i32.to_be_bytes(), "protocol 3.0");
        startup_params(&body[4..])
    }

    async fn send_ready(stream: &mut TcpStream) {
        write_pg_msg(stream, b'Z', b"I").await;
    }

    /// In-process fake PostgreSQL: scripted MD5 handshake, then one
    /// extended-protocol batch whose bound parameters are captured.
    #[tokio::test]
    async fn test_tcp_md5_auth_and_batch_params() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let captured = Arc::new(parking_lot::Mutex::new(Vec::<Vec<Vec<u8>>>::new()));
        let captured_rx = captured.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            // SSLRequest -> 'N' (cleartext).
            let mut probe = [0u8; 8];
            stream.read_exact(&mut probe).await.expect("ssl probe");
            assert_eq!(&probe[4..8], &80877103i32.to_be_bytes());
            stream.write_all(b"N").await.expect("ssl deny");
            // Startup params carry user + database.
            let params = read_startup(&mut stream).await;
            assert!(params.contains(&("user".to_string(), "u".to_string())));
            assert!(params.contains(&("database".to_string(), "db".to_string())));
            // MD5 challenge with a fixed salt; verify the client digest.
            let salt = [0x11u8, 0x22, 0x33, 0x44];
            let mut auth = 5i32.to_be_bytes().to_vec();
            auth.extend_from_slice(&salt);
            write_pg_msg(&mut stream, b'R', &auth).await;
            let (tag, body) = read_pg_msg(&mut stream).await;
            assert_eq!(tag, b'p');
            let presented = std::str::from_utf8(&body[..body.len() - 1]).expect("utf8");
            let inner = md5_hex(b"pwdu");
            let expected = format!("md5{}", md5_hex(format!("{inner}{}", hex(&salt)).as_bytes()));
            assert_eq!(presented, expected, "MD5 digest must verify");
            write_pg_msg(&mut stream, b'R', &0i32.to_be_bytes()).await;
            send_ready(&mut stream).await;
            // Extended batch: Parse, then per-row Bind/Describe/Execute.
            let (tag, _) = read_pg_msg(&mut stream).await;
            assert_eq!(tag, b'P');
            let mut rows = Vec::new();
            loop {
                let (tag, body) = read_pg_msg(&mut stream).await;
                match tag {
                    b'B' => {
                        // Bind: portal\0 stmt\0 formats, values, result formats.
                        let mut cursor = &body[..];
                        let skip_cstr = |cursor: &mut &[u8]| {
                            let end = cursor.iter().position(|&b| b == 0).expect("cstr");
                            *cursor = &cursor[end + 1..];
                        };
                        skip_cstr(&mut cursor); // portal
                        skip_cstr(&mut cursor); // statement
                        let formats = u16::from_be_bytes([cursor[0], cursor[1]]) as usize;
                        cursor = &cursor[2 + formats * 2..];
                        let count = u16::from_be_bytes([cursor[0], cursor[1]]) as usize;
                        cursor = &cursor[2..];
                        let mut row = Vec::new();
                        for _ in 0..count {
                            let len = i32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]);
                            cursor = &cursor[4..];
                            row.push(cursor[..len as usize].to_vec());
                            cursor = &cursor[len as usize..];
                        }
                        rows.push(row);
                    }
                    b'D' | b'E' => {}
                    b'S' => break,
                    other => panic!("unexpected tag {other}"),
                }
            }
            captured_rx.lock().extend(rows);
            // CommandComplete per Execute + ReadyForQuery.
            for _ in 0..2 {
                let mut complete = b"INSERT 0 1\0".to_vec();
                let _ = &mut complete;
                write_pg_msg(&mut stream, b'C', b"INSERT 0 1\0").await;
            }
            send_ready(&mut stream).await;
        });

        let transport = TcpPgTransport::new(
            &format!("postgresql://u:pwd@127.0.0.1:{port}/db"),
            1,
        )
        .expect("valid transport");
        let mut config = test_config();
        config.batch_size = 2;
        let sink = PostgreSqlSink::new(
            config,
            Arc::new(transport),
        )
        .expect("valid sink");
        let topic = Topic::new("sensors/temp").unwrap();
        sink.send(&topic, &Bytes::from_static(br#"{ "v": 1 }"#), QoS::AtLeastOnce)
            .await
            .expect("row one");
        sink.send(&topic, &Bytes::from_static(br#"{ "v": 2 }"#), QoS::AtLeastOnce)
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
        assert!(done, "fake broker never finished");
        server.await.expect("fake broker task");
        let rows = captured.lock().clone();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0][0], b"sensors/temp");
        assert_eq!(rows[0][1], b"1");
        assert_eq!(rows[0][2], br#"{ "v": 1 }"#);
        assert_eq!(rows[1][2], br#"{ "v": 2 }"#);
    }

    /// SCRAM-SHA-256 flow with an independently verifying fake server.
    #[tokio::test]
    async fn test_tcp_scram_auth_verifies_proof() {
        use base64::Engine;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut probe = [0u8; 8];
            stream.read_exact(&mut probe).await.expect("ssl probe");
            stream.write_all(b"N").await.expect("ssl deny");
            let _params = read_startup(&mut stream).await;
            // Offer SCRAM-SHA-256 only.
            let mut auth = 10i32.to_be_bytes().to_vec();
            auth.extend_from_slice(b"SCRAM-SHA-256\0\0");
            write_pg_msg(&mut stream, b'R', &auth).await;
            // Read SASLInitialResponse; extract the client nonce.
            let (tag, body) = read_pg_msg(&mut stream).await;
            assert_eq!(tag, b'p');
            let mech_end = body.iter().position(|&b| b == 0).expect("mech");
            assert_eq!(&body[..mech_end], b"SCRAM-SHA-256");
            let rest = &body[mech_end + 1..];
            let initial_len = i32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
            let initial = std::str::from_utf8(&rest[4..4 + initial_len]).expect("utf8");
            assert!(initial.starts_with("n=user,r="));
            let client_nonce = initial["n=user,r=".len()..].to_string();
            // Server-first with a fixed salt + low iteration count.
            let salt = b"testsalt";
            let iterations = 4096u32;
            let server_first = format!(
                "r={client_nonce}SERVER,s={},i={iterations}",
                base64::engine::general_purpose::STANDARD.encode(salt)
            );
            let mut msg = 11i32.to_be_bytes().to_vec();
            msg.extend_from_slice(server_first.as_bytes());
            write_pg_msg(&mut stream, b'R', &msg).await;
            // Client-final: verify the proof independently (server-side
            // derivation from the known password, not the client's math).
            let (tag, body) = read_pg_msg(&mut stream).await;
            assert_eq!(tag, b'p');
            let client_final = std::str::from_utf8(&body).expect("utf8");
            assert!(client_final.starts_with("c=biws,r="));
            let proof_b64 = client_final.rsplit(",p=").next().expect("proof");
            let client_first_bare = format!("n=user,r={client_nonce}");
            let without_proof = &client_final[..client_final.len() - proof_b64.len() - 3];
            let auth_message = format!("{client_first_bare},{server_first},{without_proof}");
            let salted = pbkdf2_sha256(b"pwd", salt, iterations);
            let mut hasher = Sha256::new();
            hasher.update(hmac_sha256(&salted, b"Client Key"));
            let stored: [u8; 32] = hasher.finalize().into();
            // proof XOR signature must recover the client key.
            let presented =
                base64::engine::general_purpose::STANDARD.decode(proof_b64).expect("b64 proof");
            assert_eq!(presented.len(), 32);
            let signature = hmac_sha256(&stored, auth_message.as_bytes());
            let mut derived_key = presented;
            for (slot, byte) in derived_key.iter_mut().zip(signature.iter()) {
                *slot ^= *byte;
            }
            let mut check = Sha256::new();
            check.update(&derived_key);
            let check_stored: [u8; 32] = check.finalize().into();
            assert_eq!(check_stored, stored, "client proof must verify");
            // Server-final with the matching signature.
            let server_key = hmac_sha256(&salted, b"Server Key");
            let server_sig = hmac_sha256(&server_key, auth_message.as_bytes());
            let final_msg = format!(
                "v={}",
                base64::engine::general_purpose::STANDARD.encode(server_sig)
            );
            let mut msg = 12i32.to_be_bytes().to_vec();
            msg.extend_from_slice(final_msg.as_bytes());
            write_pg_msg(&mut stream, b'R', &msg).await;
            // AuthenticationOk precedes ReadyForQuery, as on the wire.
            write_pg_msg(&mut stream, b'R', &0i32.to_be_bytes()).await;
            send_ready(&mut stream).await;
            // Serve one extended-protocol batch: count Executes, then
            // acknowledge each plus ReadyForQuery.
            let mut executes = 0;
            loop {
                let (tag, _) = read_pg_msg(&mut stream).await;
                match tag {
                    b'E' => executes += 1,
                    b'S' => break,
                    _ => {}
                }
            }
            assert_eq!(executes, 1, "one row flushed");
            write_pg_msg(&mut stream, b'C', b"INSERT 0 1\0").await;
            send_ready(&mut stream).await;
        });

        let transport = TcpPgTransport::new(
            &format!("postgresql://user:pwd@127.0.0.1:{port}/db"),
            1,
        )
        .expect("valid transport");
        let sink = PostgreSqlSink::new(test_config(), Arc::new(transport)).expect("valid sink");
        // A single row flush exercises the handshake plus one batch.
        sink.send(&Topic::new("t").unwrap(), &Bytes::from_static(b"{}"), QoS::AtMostOnce)
            .await
            .expect("buffered");
        match sink.flush().await {
            Ok(()) => {}
            Err(e) => panic!("scram flush failed: {e}"),
        }
        assert_eq!(sink.sent_batches(), 1);

        tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .expect("fake broker finishes")
            .expect("fake broker task");
    }
}
