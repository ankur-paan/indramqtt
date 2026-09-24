//! Redis sink speaking native RESP.
//!
//! MQTT events become Redis commands: `SET` (device-state caching, with
//! optional TTL), `HSET` (hash field updates), `PUBLISH` (Pub/Sub
//! bridge), and `XADD` (Streams append with optional `MAXLEN ~` trim).
//! Key/channel/stream/field templates render `${topic}` against the
//! MQTT topic. The [`RedisTransport`] boundary keeps unit tests
//! broker-free ([`MemoryRedisTransport`]); [`TcpRedisTransport`] is the
//! legacy hand-written RESP path (AUTH + SELECT on connect, pipelined
//! execution), retained for offline unit tests only. Production wiring
//! uses [`DriverRedisTransport`] on the maintained `redis` driver
//! (BSD-3-Clause) below.

use super::{ConnectorError, Result, Sink};
use async_trait::async_trait;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex as AsyncMutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "lowercase")]
pub enum RedisCommandKind {
    Set {
        key_template: String,
        #[serde(default)]
        ttl_seconds: Option<u64>,
    },
    HSet {
        key_template: String,
        field_template: String,
    },
    Publish {
        channel_template: String,
    },
    XAdd {
        stream_template: String,
        #[serde(default)]
        maxlen: Option<usize>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisSinkConfig {
    pub endpoint: String,
    #[serde(flatten)]
    pub command: RedisCommandKind,
}

impl RedisSinkConfig {
    pub fn validate(&self) -> Result<()> {
        if self.endpoint.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "redis endpoint must not be empty".to_string(),
            ));
        }
        let template = match &self.command {
            RedisCommandKind::Set { key_template, .. } => key_template,
            RedisCommandKind::HSet { key_template, .. } => key_template,
            RedisCommandKind::Publish { channel_template } => channel_template,
            RedisCommandKind::XAdd {
                stream_template, ..
            } => stream_template,
        };
        if template.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "redis key/channel/stream template must not be empty".to_string(),
            ));
        }
        if let RedisCommandKind::HSet { field_template, .. } = &self.command {
            if field_template.trim().is_empty() {
                return Err(ConnectorError::Dispatch(
                    "redis hset field_template must not be empty".to_string(),
                ));
            }
        }
        Ok(())
    }
}

/// Render `${topic}` placeholders. Anything else passes through
/// literally (keys stay exactly as configured).
pub fn render_template(template: &str, topic: &str) -> String {
    template.replace("${topic}", topic)
}

// ---------------------------------------------------------------------------
// RESP command encoding.
// ---------------------------------------------------------------------------

/// One Redis command, ready to encode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedisCommand {
    pub argv: Vec<Vec<u8>>,
}

impl RedisCommand {
    fn new(name: &'static str) -> Self {
        Self {
            argv: vec![name.as_bytes().to_vec()],
        }
    }

    fn arg(mut self, value: &[u8]) -> Self {
        self.argv.push(value.to_vec());
        self
    }

    /// Encode as a RESP array of bulk strings.
    pub fn encode_resp(&self) -> Vec<u8> {
        let mut out = format!("*{}\r\n", self.argv.len()).into_bytes();
        for arg in &self.argv {
            out.extend_from_slice(format!("${}\r\n", arg.len()).as_bytes());
            out.extend_from_slice(arg);
            out.extend_from_slice(b"\r\n");
        }
        out
    }
}

/// Build the wire command for one MQTT event under `config`.
pub fn build_command(config: &RedisSinkConfig, topic: &Topic, payload: &Bytes) -> RedisCommand {
    match &config.command {
        RedisCommandKind::Set {
            key_template,
            ttl_seconds,
        } => {
            let mut command = RedisCommand::new("SET")
                .arg(render_template(key_template, topic.as_str()).as_bytes())
                .arg(payload);
            if let Some(ttl) = ttl_seconds {
                command = command.arg(b"EX").arg(ttl.to_string().as_bytes());
            }
            command
        }
        RedisCommandKind::HSet {
            key_template,
            field_template,
        } => RedisCommand::new("HSET")
            .arg(render_template(key_template, topic.as_str()).as_bytes())
            .arg(render_template(field_template, topic.as_str()).as_bytes())
            .arg(payload),
        RedisCommandKind::Publish { channel_template } => RedisCommand::new("PUBLISH")
            .arg(render_template(channel_template, topic.as_str()).as_bytes())
            .arg(payload),
        RedisCommandKind::XAdd {
            stream_template,
            maxlen,
        } => {
            let mut command = RedisCommand::new("XADD")
                .arg(render_template(stream_template, topic.as_str()).as_bytes());
            if let Some(maxlen) = maxlen {
                command = command
                    .arg(b"MAXLEN")
                    .arg(b"~")
                    .arg(maxlen.to_string().as_bytes());
            }
            command.arg(b"*").arg(b"payload").arg(payload)
        }
    }
}

/// Minimal RESP reply for status assertions in tests and transports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedisReply {
    Simple(String),
    Error(String),
    Integer(i64),
    Bulk(Option<Vec<u8>>),
}

/// Parse one RESP reply from the front of `buf`, returning the reply
/// plus consumed bytes (`None` when incomplete).
pub fn parse_reply(buf: &[u8]) -> Option<(RedisReply, usize)> {
    let (kind, mut cursor) = buf.split_first()?;
    let line_end = cursor
        .windows(2)
        .position(|w| w == b"\r\n")
        .map(|pos| pos + 2)?;
    let line = &cursor[..line_end - 2];
    cursor = &cursor[line_end..];
    let text = std::str::from_utf8(line).ok()?;
    match kind {
        b'+' => Some((
            RedisReply::Simple(text.to_string()),
            buf.len() - cursor.len(),
        )),
        b'-' => Some((
            RedisReply::Error(text.to_string()),
            buf.len() - cursor.len(),
        )),
        b':' => Some((
            RedisReply::Integer(text.parse().ok()?),
            buf.len() - cursor.len(),
        )),
        b'$' => {
            let len: i64 = text.parse().ok()?;
            if len < 0 {
                return Some((RedisReply::Bulk(None), buf.len() - cursor.len()));
            }
            let len = len as usize;
            if cursor.len() < len + 2 {
                return None;
            }
            let data = cursor[..len].to_vec();
            if &cursor[len..len + 2] != b"\r\n" {
                return None;
            }
            let consumed = buf.len() - (cursor.len() - len - 2);
            Some((RedisReply::Bulk(Some(data)), consumed))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Transports.
// ---------------------------------------------------------------------------

#[async_trait]
pub trait RedisTransport: Send + Sync {
    async fn execute(&self, command: RedisCommand) -> Result<RedisReply>;
    /// Pipelined execution: all commands written back-to-back, replies
    /// read in order. Defaults to sequential execution.
    async fn execute_pipelined(&self, commands: Vec<RedisCommand>) -> Result<Vec<RedisReply>> {
        let mut replies = Vec::with_capacity(commands.len());
        for command in &commands {
            replies.push(self.execute(command.clone()).await?);
        }
        Ok(replies)
    }
}

/// In-memory transport recording every command (tests, dry runs).
#[derive(Debug, Default)]
pub struct MemoryRedisTransport {
    commands: parking_lot::Mutex<Vec<RedisCommand>>,
}

impl MemoryRedisTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn commands(&self) -> Vec<RedisCommand> {
        self.commands.lock().clone()
    }
}

#[async_trait]
impl RedisTransport for MemoryRedisTransport {
    async fn execute(&self, command: RedisCommand) -> Result<RedisReply> {
        self.commands.lock().push(command);
        Ok(RedisReply::Simple("OK".to_string()))
    }
}

#[derive(Debug, Clone)]
struct RedisEndpoint {
    host: String,
    port: u16,
    password: Option<String>,
    database: u8,
}

/// Parse `redis://[:password@]host[:port][/db]`.
fn parse_endpoint(endpoint: &str) -> Result<RedisEndpoint> {
    let rest = endpoint.strip_prefix("redis://").ok_or_else(|| {
        ConnectorError::Dispatch(format!(
            "redis endpoint must start with redis://: {endpoint:?}"
        ))
    })?;
    let (authority, db) = match rest.split_once('/') {
        Some((authority, db)) => (authority, db),
        None => (rest, "0"),
    };
    let database: u8 = if db.is_empty() {
        0
    } else {
        db.parse().map_err(|_| {
            ConnectorError::Dispatch(format!("redis bad database index in {endpoint:?}"))
        })?
    };
    let (credentials, hostport) = match authority.rsplit_once('@') {
        Some((credentials, hostport)) => (credentials, hostport),
        None => ("", authority),
    };
    let password = credentials
        .strip_prefix(':')
        .map(str::to_string)
        .filter(|password| !password.is_empty());
    let (host, port) = match hostport.rsplit_once(':') {
        Some((host, port)) => (
            host.to_string(),
            port.parse::<u16>()
                .map_err(|_| ConnectorError::Dispatch(format!("redis bad port in {endpoint:?}")))?,
        ),
        None => (hostport.to_string(), 6379),
    };
    if host.is_empty() {
        return Err(ConnectorError::Dispatch(format!(
            "redis endpoint needs a host: {endpoint:?}"
        )));
    }
    Ok(RedisEndpoint {
        host,
        port,
        password,
        database,
    })
}

/// TCP transport with AUTH + SELECT on connect and true pipelining.
/// Connects lazily; drops and redials once per failed call.
///
/// Legacy path retained for offline unit tests only (the in-process
/// fake server in `tests` below); production wiring uses
/// [`DriverRedisTransport`] on the maintained driver.
pub struct TcpRedisTransport {
    endpoint: RedisEndpoint,
    conn: AsyncMutex<Option<TcpStream>>,
}

impl TcpRedisTransport {
    pub fn new(endpoint: &str) -> Result<Self> {
        Ok(Self {
            endpoint: parse_endpoint(endpoint)?,
            conn: AsyncMutex::new(None),
        })
    }

    async fn dial(&self) -> Result<TcpStream> {
        let addr = format!("{}:{}", self.endpoint.host, self.endpoint.port);
        let mut stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&addr))
            .await
            .map_err(|_| ConnectorError::Connection(format!("redis connect timeout: {addr}")))?
            .map_err(|e| ConnectorError::Connection(format!("redis connect failed: {e}")))?;
        if let Some(password) = &self.endpoint.password {
            let reply = self
                .roundtrip_raw(
                    &mut stream,
                    &RedisCommand {
                        argv: vec![b"AUTH".to_vec(), password.as_bytes().to_vec()],
                    },
                )
                .await?;
            if reply != RedisReply::Simple("OK".to_string()) {
                return Err(ConnectorError::Connection(format!(
                    "redis AUTH rejected: {reply:?}"
                )));
            }
        }
        if self.endpoint.database != 0 {
            let reply = self
                .roundtrip_raw(
                    &mut stream,
                    &RedisCommand {
                        argv: vec![
                            b"SELECT".to_vec(),
                            self.endpoint.database.to_string().into_bytes(),
                        ],
                    },
                )
                .await?;
            if reply != RedisReply::Simple("OK".to_string()) {
                return Err(ConnectorError::Connection(format!(
                    "redis SELECT rejected: {reply:?}"
                )));
            }
        }
        Ok(stream)
    }

    async fn roundtrip_raw(
        &self,
        stream: &mut TcpStream,
        command: &RedisCommand,
    ) -> Result<RedisReply> {
        stream
            .write_all(&command.encode_resp())
            .await
            .map_err(|e| ConnectorError::Connection(format!("redis write failed: {e}")))?;
        stream
            .flush()
            .await
            .map_err(|e| ConnectorError::Connection(format!("redis flush failed: {e}")))?;
        let mut buf = Vec::new();
        loop {
            if let Some((reply, _)) = parse_reply(&buf) {
                return Ok(reply);
            }
            let mut chunk = [0u8; 4096];
            let read = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut chunk))
                .await
                .map_err(|_| ConnectorError::Connection("redis read timeout".to_string()))?
                .map_err(|e| ConnectorError::Connection(format!("redis read failed: {e}")))?;
            if read == 0 {
                return Err(ConnectorError::Connection(
                    "redis closed the connection".to_string(),
                ));
            }
            buf.extend_from_slice(&chunk[..read]);
            if buf.len() > 4 * 1024 * 1024 {
                return Err(ConnectorError::Connection(
                    "redis reply too large".to_string(),
                ));
            }
        }
    }

    async fn roundtrip_pipelined_raw(
        &self,
        stream: &mut TcpStream,
        commands: &[RedisCommand],
    ) -> Result<Vec<RedisReply>> {
        let mut bytes = Vec::new();
        for command in commands {
            bytes.extend_from_slice(&command.encode_resp());
        }
        stream
            .write_all(&bytes)
            .await
            .map_err(|e| ConnectorError::Connection(format!("redis write failed: {e}")))?;
        stream
            .flush()
            .await
            .map_err(|e| ConnectorError::Connection(format!("redis flush failed: {e}")))?;
        let mut buf = Vec::new();
        let mut replies = Vec::with_capacity(commands.len());
        while replies.len() < commands.len() {
            let mut chunk = [0u8; 4096];
            let read = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut chunk))
                .await
                .map_err(|_| ConnectorError::Connection("redis read timeout".to_string()))?
                .map_err(|e| ConnectorError::Connection(format!("redis read failed: {e}")))?;
            if read == 0 {
                return Err(ConnectorError::Connection(
                    "redis closed the connection".to_string(),
                ));
            }
            buf.extend_from_slice(&chunk[..read]);
            while replies.len() < commands.len() {
                match parse_reply(&buf) {
                    Some((reply, consumed)) => {
                        buf.drain(..consumed);
                        replies.push(reply);
                    }
                    None => break,
                }
            }
            if buf.len() > 4 * 1024 * 1024 {
                return Err(ConnectorError::Connection(
                    "redis reply too large".to_string(),
                ));
            }
        }
        Ok(replies)
    }
}

#[async_trait]
impl RedisTransport for TcpRedisTransport {
    async fn execute(&self, command: RedisCommand) -> Result<RedisReply> {
        for _ in 0..2 {
            let mut guard = self.conn.lock().await;
            if guard.is_none() {
                *guard = Some(self.dial().await?);
            }
            let stream = guard.as_mut().expect("connected");
            match self.roundtrip_raw(stream, &command).await {
                Ok(reply) => {
                    return match reply {
                        RedisReply::Error(message) => Err(ConnectorError::Dispatch(format!(
                            "redis command failed: {message}"
                        ))),
                        ok => Ok(ok),
                    }
                }
                Err(_) => {
                    *guard = None;
                }
            }
        }
        Err(ConnectorError::Connection(
            "redis command failed after reconnect".to_string(),
        ))
    }

    async fn execute_pipelined(&self, commands: Vec<RedisCommand>) -> Result<Vec<RedisReply>> {
        if commands.is_empty() {
            return Ok(Vec::new());
        }
        for _ in 0..2 {
            let mut guard = self.conn.lock().await;
            if guard.is_none() {
                *guard = Some(self.dial().await?);
            }
            let stream = guard.as_mut().expect("connected");
            match self.roundtrip_pipelined_raw(stream, &commands).await {
                Ok(replies) => {
                    for reply in &replies {
                        if let RedisReply::Error(message) = reply {
                            return Err(ConnectorError::Dispatch(format!(
                                "redis pipelined command failed: {message}"
                            )));
                        }
                    }
                    return Ok(replies);
                }
                Err(_) => {
                    *guard = None;
                }
            }
        }
        Err(ConnectorError::Connection(
            "redis pipeline failed after reconnect".to_string(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Production transport on the maintained `redis` driver.
// ---------------------------------------------------------------------------

/// Dial timeout for the driver handshake: 5 s matches the legacy
/// [`TcpRedisTransport`] dial timeout (the protocol requirement is a
/// bounded handshake, not a specific value).
const DRIVER_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Per-command timeout for single and pipelined executions: 10 s
/// matches the legacy `read_packet` timeout on the same path.
const DRIVER_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

/// Build a driver command from one [`RedisCommand`]: the first argv
/// entry is the command name, the rest ride as binary arguments so
/// payloads travel out-of-band exactly as on the legacy path.
fn driver_cmd(command: &RedisCommand) -> Result<redis::Cmd> {
    let name = command
        .argv
        .first()
        .ok_or_else(|| ConnectorError::Dispatch("redis command has no name".to_string()))?;
    let name = String::from_utf8_lossy(name).into_owned();
    let mut cmd = redis::cmd(&name);
    for arg in command.argv.iter().skip(1) {
        cmd.arg(arg.as_slice());
    }
    Ok(cmd)
}

/// Map a driver success value onto the sink's [`RedisReply`] surface:
/// `OK`/status strings stay `Simple`, integers stay `Integer`, bulk
/// strings (including Stream entry ids) stay `Bulk`. Server `-ERR`
/// replies never reach here: the driver surfaces them as
/// `Err(ResponseError)`, mapped to `Dispatch` below.
/// (`redis` 0.25 names them `Status`/`Data`; 1.x renamed them to
/// `SimpleString`/`BulkString` with identical wire meaning.)
fn driver_reply(value: redis::Value) -> Result<RedisReply> {
    match value {
        redis::Value::Okay => Ok(RedisReply::Simple("OK".to_string())),
        redis::Value::Status(text) => Ok(RedisReply::Simple(text)),
        redis::Value::Int(number) => Ok(RedisReply::Integer(number)),
        redis::Value::Data(bytes) => Ok(RedisReply::Bulk(Some(bytes))),
        redis::Value::Nil => Ok(RedisReply::Bulk(None)),
        other => Err(ConnectorError::Dispatch(format!(
            "redis unexpected reply: {other:?}"
        ))),
    }
}

/// Map a driver error: server `-ERR` replies (wrong type, bad
/// syntax, unknown command) are dispatch failures; everything else
/// (refused connection, timeout, AUTH rejection) is a connection
/// failure so callers fail closed and retry after redial.
fn map_driver_error(error: redis::RedisError) -> ConnectorError {
    if error.kind() == redis::ErrorKind::ResponseError {
        ConnectorError::Dispatch(format!("redis command failed: {error}"))
    } else {
        ConnectorError::Connection(format!("redis driver failed: {error}"))
    }
}

/// Production Redis transport on the maintained `redis` driver
/// (BSD-3-Clause): RESP with AUTH/SELECT taken from the endpoint URL
/// (`redis://[:password@]host[:port][/db]`), one shared multiplexed
/// tokio connection created lazily and reused, pipelining via
/// `redis::pipe` (all commands written back-to-back, replies read in
/// order). The legacy [`TcpRedisTransport`] stays for offline unit
/// tests only; production wiring uses this transport.
///
/// Bound: one shared connection and no background queue; each `send`
/// is one round trip (or one pipeline round trip) with bounded
/// timeouts. The sink's send path runs behind the rule engine's
/// bounded queue, so no benchmark numbers are needed.
pub struct DriverRedisTransport {
    client: redis::Client,
    conn: AsyncMutex<Option<redis::aio::MultiplexedConnection>>,
}

impl DriverRedisTransport {
    pub fn new(endpoint: &str) -> Result<Self> {
        // Validate the URL shape now so misconfiguration fails at
        // connector creation, never at first publish.
        parse_endpoint(endpoint)?;
        let client = redis::Client::open(endpoint.to_string())
            .map_err(|e| ConnectorError::Dispatch(format!("redis invalid endpoint: {e}")))?;
        Ok(Self {
            client,
            conn: AsyncMutex::new(None),
        })
    }

    async fn connection(&self) -> Result<redis::aio::MultiplexedConnection> {
        let mut guard = self.conn.lock().await;
        if let Some(conn) = guard.clone() {
            return Ok(conn);
        }
        let conn = tokio::time::timeout(
            DRIVER_CONNECT_TIMEOUT,
            self.client.get_multiplexed_async_connection(),
        )
        .await
        .map_err(|_| ConnectorError::Connection("redis driver connect timeout".to_string()))?
        .map_err(map_driver_error)?;
        *guard = Some(conn.clone());
        Ok(conn)
    }

    async fn execute_once(&self, command: &RedisCommand) -> Result<RedisReply> {
        let mut conn = self.connection().await?;
        let cmd = driver_cmd(command)?;
        let value: redis::Value =
            tokio::time::timeout(DRIVER_COMMAND_TIMEOUT, cmd.query_async(&mut conn))
                .await
                .map_err(|_| {
                    ConnectorError::Connection("redis driver command timeout".to_string())
                })?
                .map_err(map_driver_error)?;
        driver_reply(value)
    }

    async fn execute_pipelined_once(&self, commands: &[RedisCommand]) -> Result<Vec<RedisReply>> {
        let mut conn = self.connection().await?;
        let mut pipe = redis::pipe();
        for command in commands {
            pipe.add_command(driver_cmd(command)?);
        }
        let values: Vec<redis::Value> =
            tokio::time::timeout(DRIVER_COMMAND_TIMEOUT, pipe.query_async(&mut conn))
                .await
                .map_err(|_| {
                    ConnectorError::Connection("redis driver pipeline timeout".to_string())
                })?
                .map_err(map_driver_error)?;
        if values.len() != commands.len() {
            return Err(ConnectorError::Connection(format!(
                "redis pipeline short reply: {} of {}",
                values.len(),
                commands.len()
            )));
        }
        values.into_iter().map(driver_reply).collect()
    }
}

#[async_trait]
impl RedisTransport for DriverRedisTransport {
    async fn execute(&self, command: RedisCommand) -> Result<RedisReply> {
        match self.execute_once(&command).await {
            Ok(reply) => Ok(reply),
            Err(ConnectorError::Connection(_)) => {
                // Drop the poisoned connection and retry once fresh,
                // mirroring the legacy transport's contract.
                *self.conn.lock().await = None;
                self.execute_once(&command).await
            }
            Err(other) => Err(other),
        }
    }

    async fn execute_pipelined(&self, commands: Vec<RedisCommand>) -> Result<Vec<RedisReply>> {
        if commands.is_empty() {
            return Ok(Vec::new());
        }
        match self.execute_pipelined_once(&commands).await {
            Ok(replies) => Ok(replies),
            Err(ConnectorError::Connection(_)) => {
                *self.conn.lock().await = None;
                self.execute_pipelined_once(&commands).await
            }
            Err(other) => Err(other),
        }
    }
}

// ---------------------------------------------------------------------------
// Sink.
// ---------------------------------------------------------------------------

/// Redis sink: renders one command per MQTT event and dispatches it.
pub struct RedisSink {
    config: RedisSinkConfig,
    transport: Arc<dyn RedisTransport>,
    sent: AtomicU64,
}

impl RedisSink {
    pub fn new(config: RedisSinkConfig, transport: Arc<dyn RedisTransport>) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            transport,
            sent: AtomicU64::new(0),
        })
    }

    pub fn config(&self) -> &RedisSinkConfig {
        &self.config
    }

    pub fn sent_count(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl Sink for RedisSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, _qos: QoS) -> super::Result<()> {
        let command = build_command(&self.config, topic, payload);
        self.transport.execute(command).await?;
        self.sent.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "redis"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_config() -> RedisSinkConfig {
        RedisSinkConfig {
            endpoint: "redis://127.0.0.1:6379".to_string(),
            command: RedisCommandKind::Set {
                key_template: "device:${topic}:state".to_string(),
                ttl_seconds: Some(300),
            },
        }
    }

    #[test]
    fn test_config_validation() {
        let mut config = set_config();
        assert!(config.validate().is_ok());

        config.endpoint.clear();
        assert!(config.validate().is_err());
        config.endpoint = "redis://h".to_string();

        config.command = RedisCommandKind::HSet {
            key_template: "".to_string(),
            field_template: "f".to_string(),
        };
        assert!(config.validate().is_err());
        config.command = RedisCommandKind::HSet {
            key_template: "k".to_string(),
            field_template: "".to_string(),
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_endpoint_parsing() {
        let endpoint = parse_endpoint("redis://:s3cret@cache.internal:6380/2").expect("parses");
        assert_eq!(endpoint.host, "cache.internal");
        assert_eq!(endpoint.port, 6380);
        assert_eq!(endpoint.password, Some("s3cret".to_string()));
        assert_eq!(endpoint.database, 2);

        let endpoint = parse_endpoint("redis://127.0.0.1").expect("defaults");
        assert_eq!(endpoint.port, 6379);
        assert_eq!(endpoint.password, None);
        assert_eq!(endpoint.database, 0);

        assert!(parse_endpoint("http://x").is_err());
        assert!(parse_endpoint("redis://:pass@/db").is_err());
        assert!(parse_endpoint("redis://h:notaport").is_err());
        assert!(parse_endpoint("redis://h/notadb").is_err());
    }

    #[test]
    fn test_resp_vectors() {
        // SET with TTL.
        let command = build_command(
            &set_config(),
            &Topic::new("a/b").unwrap(),
            &Bytes::from_static(b"online"),
        );
        assert_eq!(
            command.encode_resp(),
            b"*5\r\n$3\r\nSET\r\n$16\r\ndevice:a/b:state\r\n$6\r\nonline\r\n$2\r\nEX\r\n$3\r\n300\r\n".to_vec()
        );

        // HSET key field value.
        let config = RedisSinkConfig {
            endpoint: "redis://h".to_string(),
            command: RedisCommandKind::HSet {
                key_template: "device".to_string(),
                field_template: "temp:${topic}".to_string(),
            },
        };
        let command = build_command(
            &config,
            &Topic::new("s").unwrap(),
            &Bytes::from_static(b"1"),
        );
        assert_eq!(
            command.encode_resp(),
            b"*4\r\n$4\r\nHSET\r\n$6\r\ndevice\r\n$6\r\ntemp:s\r\n$1\r\n1\r\n".to_vec()
        );

        // PUBLISH channel message.
        let config = RedisSinkConfig {
            endpoint: "redis://h".to_string(),
            command: RedisCommandKind::Publish {
                channel_template: "alerts".to_string(),
            },
        };
        let command = build_command(
            &config,
            &Topic::new("t").unwrap(),
            &Bytes::from_static(b"m"),
        );
        assert_eq!(
            command.encode_resp(),
            b"*3\r\n$7\r\nPUBLISH\r\n$6\r\nalerts\r\n$1\r\nm\r\n".to_vec()
        );

        // XADD with MAXLEN trim + payload field.
        let config = RedisSinkConfig {
            endpoint: "redis://h".to_string(),
            command: RedisCommandKind::XAdd {
                stream_template: "events".to_string(),
                maxlen: Some(1000),
            },
        };
        let command = build_command(
            &config,
            &Topic::new("t").unwrap(),
            &Bytes::from_static(b"v"),
        );
        assert_eq!(
            command.encode_resp(),
            b"*8\r\n$4\r\nXADD\r\n$6\r\nevents\r\n$6\r\nMAXLEN\r\n$1\r\n~\r\n$4\r\n1000\r\n$1\r\n*\r\n$7\r\npayload\r\n$1\r\nv\r\n".to_vec()
        );

        // XADD without trim.
        let config = RedisSinkConfig {
            endpoint: "redis://h".to_string(),
            command: RedisCommandKind::XAdd {
                stream_template: "events".to_string(),
                maxlen: None,
            },
        };
        let command = build_command(
            &config,
            &Topic::new("t").unwrap(),
            &Bytes::from_static(b"v"),
        );
        assert_eq!(
            command.encode_resp(),
            b"*5\r\n$4\r\nXADD\r\n$6\r\nevents\r\n$1\r\n*\r\n$7\r\npayload\r\n$1\r\nv\r\n".to_vec()
        );
    }

    #[test]
    fn test_reply_parsing() {
        assert_eq!(
            parse_reply(b"+OK\r\n"),
            Some((RedisReply::Simple("OK".to_string()), 5))
        );
        assert_eq!(parse_reply(b":42\r\n"), Some((RedisReply::Integer(42), 5)));
        assert_eq!(parse_reply(b"$-1\r\n"), Some((RedisReply::Bulk(None), 5)));
        assert_eq!(
            parse_reply(b"$2\r\nhi\r\n"),
            Some((RedisReply::Bulk(Some(b"hi".to_vec())), 8))
        );
        assert_eq!(parse_reply(b"+OK"), None);
        assert_eq!(parse_reply(b"?x\r\n"), None);
    }

    #[tokio::test]
    async fn test_sink_routes_through_memory_transport() {
        let transport = Arc::new(MemoryRedisTransport::new());
        let sink = RedisSink::new(set_config(), transport.clone()).expect("valid sink");
        sink.send(
            &Topic::new("a/b").unwrap(),
            &Bytes::from_static(b"online"),
            QoS::AtMostOnce,
        )
        .await
        .expect("delivers");
        assert_eq!(sink.sent_count(), 1);

        let commands = transport.commands();
        assert_eq!(commands.len(), 1);
        assert_eq!(
            commands[0].encode_resp(),
            b"*5\r\n$3\r\nSET\r\n$16\r\ndevice:a/b:state\r\n$6\r\nonline\r\n$2\r\nEX\r\n$3\r\n300\r\n".to_vec()
        );
    }

    /// In-process fake Redis: parses RESP arrays minimally, asserts the
    /// command shape, and answers canned replies (AUTH/SELECT +OK).
    #[tokio::test]
    async fn test_tcp_auth_select_and_pipelining() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let seen = Arc::new(parking_lot::Mutex::new(Vec::<Vec<String>>::new()));
        let seen_rx = seen.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buf = Vec::new();
            let mut commands = 0;
            loop {
                let mut chunk = [0u8; 4096];
                let n = stream.read(&mut chunk).await.expect("read");
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                // Drain every complete RESP array in the buffer.
                while let Some(argv) = parse_command(&buf) {
                    let consumed = argv_consumed(&buf);
                    buf.drain(..consumed);
                    commands += 1;
                    let strings: Vec<String> = argv
                        .iter()
                        .map(|arg| String::from_utf8_lossy(arg).to_string())
                        .collect();
                    seen_rx.lock().push(strings.clone());
                    let reply = match strings.first().map(String::as_str) {
                        Some("AUTH") => b"+OK\r\n".to_vec(),
                        Some("SELECT") => b"+OK\r\n".to_vec(),
                        Some("SET") => b"+OK\r\n".to_vec(),
                        Some("PUBLISH") => b":1\r\n".to_vec(),
                        _ => b"-ERR unknown\r\n".to_vec(),
                    };
                    stream.write_all(&reply).await.expect("write");
                    if commands >= 4 {
                        return;
                    }
                }
            }
        });

        // Password + non-zero db exercise AUTH and SELECT on connect.
        let transport = TcpRedisTransport::new(&format!("redis://:pw@127.0.0.1:{port}/3"))
            .expect("valid endpoint");
        // Pipelined SET + PUBLISH: one write, ordered replies.
        let set = build_command(
            &set_config(),
            &Topic::new("a/b").unwrap(),
            &Bytes::from_static(b"online"),
        );
        let publish = build_command(
            &RedisSinkConfig {
                endpoint: format!("redis://127.0.0.1:{port}"),
                command: RedisCommandKind::Publish {
                    channel_template: "alerts".to_string(),
                },
            },
            &Topic::new("t").unwrap(),
            &Bytes::from_static(b"m"),
        );
        let replies = transport
            .execute_pipelined(vec![set, publish])
            .await
            .expect("pipelined");
        assert_eq!(
            replies,
            vec![RedisReply::Simple("OK".to_string()), RedisReply::Integer(1)]
        );

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
        let seen = seen.lock().clone();
        assert_eq!(seen[0][0], "AUTH");
        assert_eq!(seen[1], vec!["SELECT".to_string(), "3".to_string()]);
        assert_eq!(seen[2][0], "SET");
        assert_eq!(seen[3][0], "PUBLISH");
        assert_eq!(seen[3][2], "m");
    }

    /// Minimal RESP-array splitter for the fake server (bulk strings only).
    fn parse_command(buf: &[u8]) -> Option<Vec<Vec<u8>>> {
        if buf.first() != Some(&b'*') {
            return None;
        }
        let header_end = buf.windows(2).position(|w| w == b"\r\n")? + 2;
        let count: usize = std::str::from_utf8(&buf[1..header_end - 2])
            .ok()?
            .parse()
            .ok()?;
        let mut argv = Vec::with_capacity(count);
        let mut cursor = &buf[header_end..];
        for _ in 0..count {
            if cursor.first() != Some(&b'$') {
                return None;
            }
            let end = cursor.windows(2).position(|w| w == b"\r\n")? + 2;
            let len: usize = std::str::from_utf8(&cursor[1..end - 2])
                .ok()?
                .parse()
                .ok()?;
            cursor = &cursor[end..];
            if cursor.len() < len + 2 {
                return None;
            }
            argv.push(cursor[..len].to_vec());
            cursor = &cursor[len + 2..];
        }
        Some(argv)
    }

    fn argv_consumed(buf: &[u8]) -> usize {
        // Re-walk with the same parser to measure the consumed prefix.
        let Some(argv) = parse_command(buf) else {
            return 0;
        };
        let mut size = format!("*{}\r\n", argv.len()).len();
        for arg in &argv {
            size += format!("${}\r\n", arg.len()).len() + arg.len() + 2;
        }
        size
    }

    #[test]
    fn test_driver_transport_rejects_bad_endpoint() {
        assert!(DriverRedisTransport::new("http://x").is_err());
        assert!(DriverRedisTransport::new("").is_err());
        assert!(DriverRedisTransport::new("redis://127.0.0.1:6379").is_ok());
        assert!(DriverRedisTransport::new("redis://:pw@127.0.0.1:6379/0").is_ok());
    }

    #[test]
    fn test_driver_cmd_and_reply_mapping() {
        let command = RedisCommand {
            argv: vec![b"SET".to_vec(), b"k".to_vec(), b"v".to_vec()],
        };
        // The driver command packs the same argv the legacy path encodes.
        let packed = driver_cmd(&command).expect("packs");
        assert_eq!(
            packed.get_packed_command(),
            command.encode_resp(),
            "driver and legacy paths must encode identical RESP"
        );
        assert!(driver_cmd(&RedisCommand { argv: Vec::new() }).is_err());

        assert_eq!(
            driver_reply(redis::Value::Okay).expect("ok"),
            RedisReply::Simple("OK".to_string())
        );
        assert_eq!(
            driver_reply(redis::Value::Status("OK".to_string())).expect("status"),
            RedisReply::Simple("OK".to_string())
        );
        assert_eq!(
            driver_reply(redis::Value::Int(2)).expect("int"),
            RedisReply::Integer(2)
        );
        assert_eq!(
            driver_reply(redis::Value::Data(b"1700000000000-0".to_vec())).expect("bulk"),
            RedisReply::Bulk(Some(b"1700000000000-0".to_vec()))
        );
        assert_eq!(
            driver_reply(redis::Value::Nil).expect("nil"),
            RedisReply::Bulk(None)
        );
        assert!(driver_reply(redis::Value::Bulk(Vec::new())).is_err());
    }

    fn qual_env(name: &str) -> Option<String> {
        std::env::var(name).ok().filter(|v| !v.trim().is_empty())
    }

    fn qual_require(name: &str) -> String {
        qual_env(name).unwrap_or_else(|| {
            panic!(
                "{name} must point at a real Redis server for qualification; \
                 failing closed instead of passing vacuously \
                 (e.g. REDIS_HOST=127.0.0.1)"
            )
        })
    }

    /// Qualification against a real Redis server over the maintained
    /// `redis` driver ([`DriverRedisTransport`]).
    ///
    /// Run with e.g.:
    /// `REDIS_HOST=127.0.0.1 REDIS_PORT=6379 REDIS_PASSWORD=qualpass1 REDIS_DB=0 \
    ///  cargo test -p broker-connectors --lib redis::tests::test_qualify_driver_write_path -- --ignored --nocapture --test-threads=1`
    ///
    /// Streams 2000 HSET fields, 2000 XADD entries and 2000 LPUSH
    /// elements plus 2000 PUBLISH messages through the broker path
    /// ([`crate::ConnectorManager`] -> [`RedisSink`] /
    /// [`DriverRedisTransport`], never `sink.send` directly, except
    /// LPUSH which has no sink command kind and goes through the
    /// transport's write path with the same driver connection), asserts
    /// every payload back from the server (duplicates tolerated, loss
    /// is not), asserts a mixed pipelined batch returns ordered
    /// replies, proves a wrong password fails closed, then deletes the
    /// keys it created. Panics when its environment is missing (fail
    /// closed, never skips).
    #[tokio::test]
    #[ignore = "needs a real Redis server (see REDIS_* env)"]
    async fn test_qualify_driver_write_path() {
        use crate::ConnectorManager;
        use futures::StreamExt as _;
        use std::collections::{HashMap, HashSet};

        const COMMANDS: usize = 2000;

        let host = qual_require("REDIS_HOST");
        let port: u16 = qual_require("REDIS_PORT")
            .parse()
            .expect("qual REDIS_PORT must be a port number");
        let password = qual_require("REDIS_PASSWORD");
        let db: u8 = qual_require("REDIS_DB")
            .parse()
            .expect("qual REDIS_DB must be a database index");
        let endpoint = format!("redis://:{password}@{host}:{port}/{db}");

        let hset_key = "qual_b337:hset";
        let stream_key = "qual_b337:stream";
        let list_key = "qual_b337:list";
        let channel = "qual_b337:events";
        let pipe_key = "qual_b337:pipe";

        // Server version for the report (connectivity is already proved
        // by connecting below; the version string is context). The
        // endpoint line is the measured endpoint, never a substitute
        // version string.
        let client = redis::Client::open(endpoint.as_str())
            .unwrap_or_else(|e| panic!("qual client open failed: {e:?}"));
        let mut admin = tokio::time::timeout(
            Duration::from_secs(30),
            client.get_multiplexed_async_connection(),
        )
        .await
        .expect("qual connect timeout")
        .unwrap_or_else(|e| panic!("qual connect failed: {e:?}"));
        let info: String = redis::cmd("INFO")
            .arg("server")
            .query_async(&mut admin)
            .await
            .unwrap_or_else(|e| panic!("qual INFO failed: {e:?}"));
        let version = info
            .lines()
            .find_map(|line| line.strip_prefix("redis_version:"))
            .unwrap_or("unknown");
        eprintln!("qual server: version={version} host={host}:{port} db={db}");

        // Start clean: remove keys from any previous run (best effort).
        let _: redis::Value = redis::cmd("DEL")
            .arg(hset_key)
            .arg(stream_key)
            .arg(list_key)
            .arg(pipe_key)
            .arg(format!("{pipe_key}:hash"))
            .arg(format!("{pipe_key}:list"))
            .query_async(&mut admin)
            .await
            .unwrap_or_else(|e| panic!("qual DEL failed: {e:?}"));

        // HSET workload through the broker path: one field per sequence.
        let hset_config = RedisSinkConfig {
            endpoint: endpoint.clone(),
            command: RedisCommandKind::HSet {
                key_template: hset_key.to_string(),
                field_template: "${topic}".to_string(),
            },
        };
        hset_config.validate().expect("qual hset config validates");
        let hset_transport =
            Arc::new(DriverRedisTransport::new(&endpoint).expect("qual hset transport"));
        let hset_sink =
            Arc::new(RedisSink::new(hset_config, hset_transport).expect("qual hset sink"));
        assert_eq!(hset_sink.kind(), "redis");
        let manager = ConnectorManager::new();
        manager.register("qual-redis-hset", hset_sink.clone());
        for seq in 0..COMMANDS {
            let topic = Topic::new(format!("qual/{seq:06}"))
                .unwrap_or_else(|e| panic!("qual topic: {e:?}"));
            let payload = Bytes::from(format!("hset-{seq:06}"));
            manager
                .send("qual-redis-hset", &topic, &payload, QoS::AtLeastOnce)
                .await
                .unwrap_or_else(|e| panic!("qual hset send seq={seq} failed: {e:?}"));
        }
        assert_eq!(hset_sink.sent_count(), COMMANDS as u64);
        eprintln!("qual rows sent: hset={COMMANDS} key={hset_key}");

        // XADD workload through the broker path: one entry per sequence.
        let xadd_config = RedisSinkConfig {
            endpoint: endpoint.clone(),
            command: RedisCommandKind::XAdd {
                stream_template: stream_key.to_string(),
                maxlen: None,
            },
        };
        xadd_config.validate().expect("qual xadd config validates");
        let xadd_transport =
            Arc::new(DriverRedisTransport::new(&endpoint).expect("qual xadd transport"));
        let xadd_sink =
            Arc::new(RedisSink::new(xadd_config, xadd_transport).expect("qual xadd sink"));
        manager.register("qual-redis-xadd", xadd_sink.clone());
        for seq in 0..COMMANDS {
            let topic = Topic::new(format!("qual/{seq:06}"))
                .unwrap_or_else(|e| panic!("qual topic: {e:?}"));
            let payload = Bytes::from(format!("xadd-{seq:06}"));
            manager
                .send("qual-redis-xadd", &topic, &payload, QoS::AtLeastOnce)
                .await
                .unwrap_or_else(|e| panic!("qual xadd send seq={seq} failed: {e:?}"));
        }
        assert_eq!(xadd_sink.sent_count(), COMMANDS as u64);
        eprintln!("qual rows sent: xadd={COMMANDS} stream={stream_key}");

        // LPUSH workload through the driver write path: the sink has no
        // LPUSH command kind, so each element travels as a raw LPUSH
        // command over the same driver transport the sink uses.
        let lpush_transport =
            Arc::new(DriverRedisTransport::new(&endpoint).expect("qual lpush transport"));
        for seq in 0..COMMANDS {
            let command = RedisCommand {
                argv: vec![
                    b"LPUSH".to_vec(),
                    list_key.as_bytes().to_vec(),
                    format!("lpush-{seq:06}").into_bytes(),
                ],
            };
            lpush_transport
                .execute(command)
                .await
                .unwrap_or_else(|e| panic!("qual lpush seq={seq} failed: {e:?}"));
        }
        eprintln!("qual rows sent: lpush={COMMANDS} key={list_key}");

        // PUBLISH workload through the broker path with a live
        // subscriber asserting exact delivery (duplicates tolerated,
        // loss is not).
        let mut pubsub = client
            .get_async_pubsub()
            .await
            .unwrap_or_else(|e| panic!("qual pubsub connect failed: {e:?}"));
        pubsub
            .subscribe(channel)
            .await
            .unwrap_or_else(|e| panic!("qual subscribe failed: {e:?}"));
        let mut messages = pubsub.on_message();
        let publish_config = RedisSinkConfig {
            endpoint: endpoint.clone(),
            command: RedisCommandKind::Publish {
                channel_template: channel.to_string(),
            },
        };
        publish_config
            .validate()
            .expect("qual publish config validates");
        let publish_transport =
            Arc::new(DriverRedisTransport::new(&endpoint).expect("qual publish transport"));
        let publish_sink =
            Arc::new(RedisSink::new(publish_config, publish_transport).expect("qual publish sink"));
        manager.register("qual-redis-pub", publish_sink.clone());
        for seq in 0..COMMANDS {
            let topic = Topic::new(format!("qual/{seq:06}"))
                .unwrap_or_else(|e| panic!("qual topic: {e:?}"));
            let payload = Bytes::from(format!("pub-{seq:06}"));
            manager
                .send("qual-redis-pub", &topic, &payload, QoS::AtLeastOnce)
                .await
                .unwrap_or_else(|e| panic!("qual publish send seq={seq} failed: {e:?}"));
        }
        assert_eq!(publish_sink.sent_count(), COMMANDS as u64);
        let mut seen: HashSet<String> = HashSet::new();
        // 120 s receive window for 2000 publishes: generous against
        // the 1800 s gate timeout so a slow server still converges,
        // while a stuck bridge fails instead of hanging the gate.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        while seen.len() < COMMANDS {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                panic!(
                    "qual receive timeout: got {} of {COMMANDS} distinct publishes",
                    seen.len()
                );
            }
            let msg = tokio::time::timeout(remaining, messages.next())
                .await
                .expect("qual recv timeout")
                .unwrap_or_else(|| panic!("qual pubsub stream ended early"));
            let payload: String = msg
                .get_payload()
                .unwrap_or_else(|e| panic!("qual payload decode: {e:?}"));
            seen.insert(payload);
        }
        for seq in 0..COMMANDS {
            let key = format!("pub-{seq:06}");
            assert!(seen.contains(&key), "qual missing publish {key}");
        }
        eprintln!(
            "qual rows asserted: publish distinct={} channel={channel}",
            seen.len()
        );
        drop(messages);
        drop(pubsub);

        // Row counts asserted back from the server, not the counters.
        let hlen: i64 = redis::cmd("HLEN")
            .arg(hset_key)
            .query_async(&mut admin)
            .await
            .unwrap_or_else(|e| panic!("qual HLEN failed: {e:?}"));
        assert_eq!(hlen, COMMANDS as i64, "qual hset count mismatch");
        let all: HashMap<String, String> = redis::cmd("HGETALL")
            .arg(hset_key)
            .query_async(&mut admin)
            .await
            .unwrap_or_else(|e| panic!("qual HGETALL failed: {e:?}"));
        assert_eq!(all.len(), COMMANDS, "qual hset field count");
        for seq in 0..COMMANDS {
            let field = format!("qual/{seq:06}");
            let expected = format!("hset-{seq:06}");
            assert_eq!(
                all.get(&field).map(String::as_str),
                Some(expected.as_str()),
                "qual missing hset field {field}"
            );
        }
        eprintln!("qual rows asserted: hset={hlen} key={hset_key}");

        let xlen: i64 = redis::cmd("XLEN")
            .arg(stream_key)
            .query_async(&mut admin)
            .await
            .unwrap_or_else(|e| panic!("qual XLEN failed: {e:?}"));
        assert_eq!(xlen, COMMANDS as i64, "qual xadd count mismatch");
        eprintln!("qual rows asserted: xadd={xlen} stream={stream_key}");

        let llen: i64 = redis::cmd("LLEN")
            .arg(list_key)
            .query_async(&mut admin)
            .await
            .unwrap_or_else(|e| panic!("qual LLEN failed: {e:?}"));
        assert_eq!(llen, COMMANDS as i64, "qual lpush count mismatch");
        let listed: Vec<String> = redis::cmd("LRANGE")
            .arg(list_key)
            .arg(0)
            .arg(-1)
            .query_async(&mut admin)
            .await
            .unwrap_or_else(|e| panic!("qual LRANGE failed: {e:?}"));
        let listed_set: HashSet<String> = listed.into_iter().collect();
        assert_eq!(listed_set.len(), COMMANDS, "qual lpush element count");
        for seq in 0..COMMANDS {
            let key = format!("lpush-{seq:06}");
            assert!(listed_set.contains(&key), "qual missing lpush {key}");
        }
        eprintln!("qual rows asserted: lpush={llen} key={list_key}");

        // Pipelined replies: one mixed batch across SET, HSET, LPUSH and
        // PUBLISH returns one ordered reply per command.
        let pipe_transport =
            Arc::new(DriverRedisTransport::new(&endpoint).expect("qual pipe transport"));
        let pipe_commands = vec![
            RedisCommand {
                argv: vec![b"SET".to_vec(), pipe_key.as_bytes().to_vec(), b"v".to_vec()],
            },
            RedisCommand {
                argv: vec![
                    b"HSET".to_vec(),
                    format!("{pipe_key}:hash").into_bytes(),
                    b"f".to_vec(),
                    b"v".to_vec(),
                ],
            },
            RedisCommand {
                argv: vec![
                    b"LPUSH".to_vec(),
                    format!("{pipe_key}:list").into_bytes(),
                    b"v".to_vec(),
                ],
            },
            RedisCommand {
                argv: vec![
                    b"PUBLISH".to_vec(),
                    channel.as_bytes().to_vec(),
                    b"pipe-probe".to_vec(),
                ],
            },
        ];
        let replies = pipe_transport
            .execute_pipelined(pipe_commands)
            .await
            .unwrap_or_else(|e| panic!("qual pipeline failed: {e:?}"));
        assert_eq!(replies.len(), 4, "qual pipeline reply count");
        assert_eq!(replies[0], RedisReply::Simple("OK".to_string()));
        assert!(
            matches!(replies[1], RedisReply::Integer(_)),
            "qual HSET pipelined reply must be an integer, got {:?}",
            replies[1]
        );
        assert!(
            matches!(replies[2], RedisReply::Integer(_)),
            "qual LPUSH pipelined reply must be an integer, got {:?}",
            replies[2]
        );
        assert!(
            matches!(replies[3], RedisReply::Integer(_)),
            "qual PUBLISH pipelined reply must be an integer, got {:?}",
            replies[3]
        );
        eprintln!("qual pipeline asserted: replies={replies:?}");

        // AUTH failure surfaces: a wrong password fails closed.
        let bad_endpoint = format!("redis://:wrongpass1@{host}:{port}/{db}");
        let bad_transport =
            DriverRedisTransport::new(&bad_endpoint).expect("qual bad transport builds");
        let bad_command = RedisCommand {
            argv: vec![b"SET".to_vec(), b"qual_b337:bad".to_vec(), b"v".to_vec()],
        };
        let bad_result = bad_transport.execute(bad_command).await;
        let bad_error = bad_result.expect_err("qual wrong password must fail");
        assert!(
            matches!(bad_error, crate::ConnectorError::Connection(_)),
            "qual wrong password must fail closed, got {bad_error:?}"
        );
        eprintln!("qual auth asserted: wrong password fails closed");

        // Counts unchanged after the failed AUTH.
        let hlen_after: i64 = redis::cmd("HLEN")
            .arg(hset_key)
            .query_async(&mut admin)
            .await
            .expect("qual recount");
        assert_eq!(hlen_after, COMMANDS as i64, "qual count unchanged");

        // Cleanup: delete the keys created for this run (best effort).
        let _: redis::Value = redis::cmd("DEL")
            .arg(hset_key)
            .arg(stream_key)
            .arg(list_key)
            .arg(pipe_key)
            .arg(format!("{pipe_key}:hash"))
            .arg(format!("{pipe_key}:list"))
            .query_async(&mut admin)
            .await
            .unwrap_or_else(|e| panic!("qual cleanup DEL failed: {e:?}"));
        eprintln!(
            "qual cleanup: deleted keys {hset_key} {stream_key} {list_key} {pipe_key}(+hash/list)"
        );
        eprintln!("qual done: hset={COMMANDS} xadd={COMMANDS} lpush={COMMANDS} publish={COMMANDS} cleaned keys");
    }
}
