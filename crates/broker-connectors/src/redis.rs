//! Redis sink speaking native RESP.
//!
//! MQTT events become Redis commands: `SET` (device-state caching, with
//! optional TTL), `HSET` (hash field updates), `PUBLISH` (Pub/Sub
//! bridge), and `XADD` (Streams append with optional `MAXLEN ~` trim).
//! Key/channel/stream/field templates render `${topic}` against the
//! MQTT topic. The [`RedisTransport`] boundary keeps unit tests
//! broker-free ([`MemoryRedisTransport`]); [`TcpRedisTransport`] speaks
//! RESP over TCP (AUTH + SELECT on connect, pipelined execution).

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
            RedisCommandKind::XAdd { stream_template, .. } => stream_template,
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
pub fn build_command(
    config: &RedisSinkConfig,
    topic: &Topic,
    payload: &Bytes,
) -> RedisCommand {
    match &config.command {
        RedisCommandKind::Set { key_template, ttl_seconds } => {
            let mut command = RedisCommand::new("SET")
                .arg(render_template(key_template, topic.as_str()).as_bytes())
                .arg(payload);
            if let Some(ttl) = ttl_seconds {
                command = command
                    .arg(b"EX")
                    .arg(ttl.to_string().as_bytes());
            }
            command
        }
        RedisCommandKind::HSet { key_template, field_template } => RedisCommand::new("HSET")
            .arg(render_template(key_template, topic.as_str()).as_bytes())
            .arg(render_template(field_template, topic.as_str()).as_bytes())
            .arg(payload),
        RedisCommandKind::Publish { channel_template } => RedisCommand::new("PUBLISH")
            .arg(render_template(channel_template, topic.as_str()).as_bytes())
            .arg(payload),
        RedisCommandKind::XAdd { stream_template, maxlen } => {
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
        b'+' => Some((RedisReply::Simple(text.to_string()), buf.len() - cursor.len())),
        b'-' => Some((RedisReply::Error(text.to_string()), buf.len() - cursor.len())),
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
        ConnectorError::Dispatch(format!("redis endpoint must start with redis://: {endpoint:?}"))
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
            port.parse::<u16>().map_err(|_| {
                ConnectorError::Dispatch(format!("redis bad port in {endpoint:?}"))
            })?,
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
            .map_err(|_| {
                ConnectorError::Connection(format!("redis connect timeout: {addr}"))
            })?
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
        let command = build_command(&config, &Topic::new("s").unwrap(), &Bytes::from_static(b"1"));
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
        let command = build_command(&config, &Topic::new("t").unwrap(), &Bytes::from_static(b"m"));
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
        let command = build_command(&config, &Topic::new("t").unwrap(), &Bytes::from_static(b"v"));
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
        let command = build_command(&config, &Topic::new("t").unwrap(), &Bytes::from_static(b"v"));
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
        assert_eq!(
            parse_reply(b":42\r\n"),
            Some((RedisReply::Integer(42), 5))
        );
        assert_eq!(
            parse_reply(b"$-1\r\n"),
            Some((RedisReply::Bulk(None), 5))
        );
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
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
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
                loop {
                    let Some(argv) = parse_command(&buf) else {
                        break;
                    };
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
            vec![
                RedisReply::Simple("OK".to_string()),
                RedisReply::Integer(1)
            ]
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
        let count: usize = std::str::from_utf8(&buf[1..header_end - 2]).ok()?.parse().ok()?;
        let mut argv = Vec::with_capacity(count);
        let mut cursor = &buf[header_end..];
        for _ in 0..count {
            if cursor.first() != Some(&b'$') {
                return None;
            }
            let end = cursor.windows(2).position(|w| w == b"\r\n")? + 2;
            let len: usize = std::str::from_utf8(&cursor[1..end - 2]).ok()?.parse().ok()?;
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
}
