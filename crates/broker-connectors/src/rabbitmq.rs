//! RabbitMQ AMQP 0-9-1 publisher sink.
//!
//! MQTT events become `Basic.Publish` method + content-header + body
//! frames: MQTT topic slashes translate to AMQP routing-key dots,
//! delivery mode / timestamp / content type ride the content header, and
//! MQTT topic, QoS, and timestamp repeat inside the headers table for
//! downstream consumers. The [`RabbitMqTransport`] boundary keeps unit
//! tests broker-free ([`MemoryAmqpTransport`]); [`TcpRabbitTransport`]
//! performs the real PLAIN handshake over TCP.

use super::{ConnectorError, Result, Sink};
use async_trait::async_trait;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex as AsyncMutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RabbitMqSinkConfig {
    pub endpoint: String,
    pub exchange: String,
    pub routing_key_template: String,
    pub delivery_mode: u8,
}

impl RabbitMqSinkConfig {
    pub fn validate(&self) -> Result<()> {
        if self.endpoint.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "rabbitmq endpoint must not be empty".to_string(),
            ));
        }
        if self.exchange.is_empty() || self.exchange.len() > 255 {
            return Err(ConnectorError::Dispatch(
                "rabbitmq exchange must be 1..=255 bytes".to_string(),
            ));
        }
        if self.routing_key_template.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "rabbitmq routing_key_template must not be empty".to_string(),
            ));
        }
        if self.delivery_mode != 1 && self.delivery_mode != 2 {
            return Err(ConnectorError::Dispatch(format!(
                "rabbitmq delivery_mode must be 1 or 2, got {}",
                self.delivery_mode
            )));
        }
        Ok(())
    }
}

/// Render `${topic}` then translate MQTT slashes to AMQP dots:
/// `sensor.${topic}` with `a/b` becomes `sensor.a.b`.
pub fn render_routing_key(template: &str, topic: &str) -> String {
    template.replace("${topic}", topic).replace('/', ".")
}

// ---------------------------------------------------------------------------
// AMQP 0-9-1 frame encoding (big-endian throughout, 0xCE frame end).
// ---------------------------------------------------------------------------

pub const FRAME_END: u8 = 0xCE;
pub const FRAME_METHOD: u8 = 1;
pub const FRAME_HEADER: u8 = 2;
pub const FRAME_BODY: u8 = 3;

/// Field-table value subset used for message headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldValue {
    Str(String),
    Bool(bool),
    I32(i32),
    Timestamp(u64),
}

fn encode_shortstr(s: &str, out: &mut Vec<u8>) -> Result<()> {
    if s.len() > 255 {
        return Err(ConnectorError::Dispatch(format!(
            "AMQP short string too long ({} bytes)",
            s.len()
        )));
    }
    out.push(s.len() as u8);
    out.extend_from_slice(s.as_bytes());
    Ok(())
}

fn encode_longstr(bytes: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Encode an AMQP field table: u32 length + entries of
/// `shortstr-name + type-octet + value`. Types: `S` shortstr, `t`
/// boolean, `I` int32, `T` u64 timestamp.
pub fn encode_field_table(entries: &[(String, FieldValue)]) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    for (name, value) in entries {
        encode_shortstr(name, &mut body)?;
        match value {
            FieldValue::Str(text) => {
                body.push(b'S');
                encode_longstr(text.as_bytes(), &mut body);
            }
            FieldValue::Bool(flag) => {
                body.push(b't');
                body.push(u8::from(*flag));
            }
            FieldValue::I32(number) => {
                body.push(b'I');
                body.extend_from_slice(&number.to_be_bytes());
            }
            FieldValue::Timestamp(ts) => {
                body.push(b'T');
                body.extend_from_slice(&ts.to_be_bytes());
            }
        }
    }
    let mut out = (body.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(&body);
    Ok(out)
}

/// One AMQP frame (method, content header, or body chunk).
#[derive(Debug, Clone)]
pub struct AmqpFrame {
    pub frame_type: u8,
    pub channel: u16,
    pub payload: Vec<u8>,
}

impl AmqpFrame {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(7 + self.payload.len() + 1);
        out.push(self.frame_type);
        out.extend_from_slice(&self.channel.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out.push(FRAME_END);
        out
    }
}

fn method_frame(channel: u16, class_id: u16, method_id: u16, args: &[u8]) -> AmqpFrame {
    let mut payload = Vec::with_capacity(4 + args.len());
    payload.extend_from_slice(&class_id.to_be_bytes());
    payload.extend_from_slice(&method_id.to_be_bytes());
    payload.extend_from_slice(args);
    AmqpFrame {
        frame_type: FRAME_METHOD,
        channel,
        payload,
    }
}

/// A publish ready for the wire: method + header + single body frame.
#[derive(Debug, Clone)]
pub struct AmqpPublish {
    pub exchange: String,
    pub routing_key: String,
    pub delivery_mode: u8,
    pub timestamp_secs: u64,
    pub headers: Vec<(String, FieldValue)>,
    pub body: Bytes,
}

/// Encode `Basic.Publish` (60,40) + content header + body. Property
/// flags `0xB040` carry content-type, headers table, delivery-mode, and
/// timestamp in flag order.
pub fn encode_basic_publish(publish: &AmqpPublish) -> Result<Vec<AmqpFrame>> {
    let mut method_args = Vec::new();
    method_args.extend_from_slice(&0u16.to_be_bytes()); // reserved-1
    encode_shortstr(&publish.exchange, &mut method_args)?;
    encode_shortstr(&publish.routing_key, &mut method_args)?;
    // In AMQP 0-9-1, consecutive bit fields (mandatory, immediate) are packed into a single octet.
    method_args.push(0u8);
    let method = method_frame(1, 60, 40, &method_args);

    let mut header_payload = Vec::new();
    header_payload.extend_from_slice(&60u16.to_be_bytes()); // class
    header_payload.extend_from_slice(&0u16.to_be_bytes()); // weight
    header_payload.extend_from_slice(&(publish.body.len() as u64).to_be_bytes());
    header_payload.extend_from_slice(&0xB040u16.to_be_bytes());
    encode_shortstr("application/json", &mut header_payload)?;
    let table_entries: Vec<(String, FieldValue)> = publish
        .headers
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    header_payload.extend_from_slice(&encode_field_table(&table_entries)?);
    header_payload.push(publish.delivery_mode);
    header_payload.extend_from_slice(&publish.timestamp_secs.to_be_bytes());
    let header = AmqpFrame {
        frame_type: FRAME_HEADER,
        channel: 1,
        payload: header_payload,
    };

    let body = AmqpFrame {
        frame_type: FRAME_BODY,
        channel: 1,
        payload: publish.body.to_vec(),
    };
    Ok(vec![method, header, body])
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Transports.
// ---------------------------------------------------------------------------

#[async_trait]
pub trait RabbitMqTransport: Send + Sync {
    async fn publish(&self, publish: AmqpPublish) -> Result<()>;
}

/// In-memory transport recording every publish (tests, dry runs).
#[derive(Debug, Default)]
pub struct MemoryAmqpTransport {
    publishes: parking_lot::Mutex<Vec<AmqpPublish>>,
}

impl MemoryAmqpTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn publishes(&self) -> Vec<AmqpPublish> {
        self.publishes.lock().clone()
    }
}

#[async_trait]
impl RabbitMqTransport for MemoryAmqpTransport {
    async fn publish(&self, publish: AmqpPublish) -> Result<()> {
        self.publishes.lock().push(publish);
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct AmqpEndpoint {
    host: String,
    port: u16,
    username: String,
    password: String,
    vhost: String,
}

/// Parse `amqp://[user[:pass]@]host[:port][/vhost]` (defaults guest /
/// guest, 5672, `/`; `%2f` decodes to `/` in the vhost).
fn parse_endpoint(endpoint: &str) -> Result<AmqpEndpoint> {
    let rest = endpoint.strip_prefix("amqp://").ok_or_else(|| {
        ConnectorError::Dispatch(format!(
            "rabbitmq endpoint must start with amqp://: {endpoint:?}"
        ))
    })?;
    let (authority, vhost_raw) = match rest.split_once('/') {
        Some((authority, vhost)) => (authority, vhost),
        None => (rest, ""),
    };
    let vhost = vhost_raw.replace("%2f", "/").replace("%2F", "/");
    let vhost = if vhost.is_empty() {
        "/".to_string()
    } else {
        vhost
    };
    let (credentials, hostport) = match authority.rsplit_once('@') {
        Some((credentials, hostport)) => (credentials, hostport),
        None => ("guest:guest", authority),
    };
    let (username, password) = match credentials.split_once(':') {
        Some((user, pass)) => (user.to_string(), pass.to_string()),
        None => (credentials.to_string(), String::new()),
    };
    if username.is_empty() {
        return Err(ConnectorError::Dispatch(
            "rabbitmq endpoint needs a username".to_string(),
        ));
    }
    let (host, port) = match hostport.rsplit_once(':') {
        Some((host, port)) => (
            host.to_string(),
            port.parse::<u16>().map_err(|_| {
                ConnectorError::Dispatch(format!("rabbitmq bad port in {endpoint:?}"))
            })?,
        ),
        None => (hostport.to_string(), 5672),
    };
    if host.is_empty() {
        return Err(ConnectorError::Dispatch(format!(
            "rabbitmq endpoint needs a host: {endpoint:?}"
        )));
    }
    Ok(AmqpEndpoint {
        host,
        port,
        username,
        password,
        vhost,
    })
}

struct RabbitConn {
    stream: TcpStream,
}

async fn read_frame(stream: &mut TcpStream) -> Result<(u8, u16, Vec<u8>)> {
    let mut header = [0u8; 7];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut header))
        .await
        .map_err(|_| ConnectorError::Connection("amqp read timeout".to_string()))?
        .map_err(|e| ConnectorError::Connection(format!("amqp read failed: {e}")))?;
    let size = u32::from_be_bytes([header[3], header[4], header[5], header[6]]) as usize;
    if size > 4 * 1024 * 1024 {
        return Err(ConnectorError::Connection(format!(
            "amqp frame too large: {size}"
        )));
    }
    let mut payload = vec![0u8; size];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut payload))
        .await
        .map_err(|_| ConnectorError::Connection("amqp read timeout".to_string()))?
        .map_err(|e| ConnectorError::Connection(format!("amqp read failed: {e}")))?;
    let mut end = [0u8; 1];
    stream
        .read_exact(&mut end)
        .await
        .map_err(|e| ConnectorError::Connection(format!("amqp read failed: {e}")))?;
    if end[0] != FRAME_END {
        return Err(ConnectorError::Connection(format!(
            "amqp bad frame end: {:#x}",
            end[0]
        )));
    }
    Ok((
        header[0],
        u16::from_be_bytes([header[1], header[2]]),
        payload,
    ))
}

async fn write_frame(stream: &mut TcpStream, frame: &AmqpFrame) -> Result<()> {
    stream
        .write_all(&frame.encode())
        .await
        .map_err(|e| ConnectorError::Connection(format!("amqp write failed: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| ConnectorError::Connection(format!("amqp flush failed: {e}")))?;
    Ok(())
}

async fn expect_method(stream: &mut TcpStream, class_id: u16, method_id: u16) -> Result<Vec<u8>> {
    let (frame_type, _channel, payload) = read_frame(stream).await?;
    if frame_type != FRAME_METHOD || payload.len() < 4 {
        return Err(ConnectorError::Connection(format!(
            "amqp expected method frame, got type {frame_type}"
        )));
    }
    let got_class = u16::from_be_bytes([payload[0], payload[1]]);
    let got_method = u16::from_be_bytes([payload[2], payload[3]]);
    if got_class != class_id || got_method != method_id {
        return Err(ConnectorError::Connection(format!(
            "amqp expected {class_id}/{method_id}, got {got_class}/{got_method}"
        )));
    }
    Ok(payload[4..].to_vec())
}

/// TCP transport with a minimal PLAIN handshake and a reused channel.
/// Connects lazily on first use; any I/O failure drops the connection
/// and retries once after a fresh handshake.
pub struct TcpRabbitTransport {
    endpoint: AmqpEndpoint,
    conn: AsyncMutex<Option<RabbitConn>>,
}

impl TcpRabbitTransport {
    pub fn new(endpoint: &str) -> Result<Self> {
        Ok(Self {
            endpoint: parse_endpoint(endpoint)?,
            conn: AsyncMutex::new(None),
        })
    }

    async fn handshake(&self, stream: &mut TcpStream) -> Result<()> {
        // Protocol header.
        stream
            .write_all(b"AMQP\x00\x00\x09\x01")
            .await
            .map_err(|e| ConnectorError::Connection(format!("amqp write failed: {e}")))?;
        stream
            .flush()
            .await
            .map_err(|e| ConnectorError::Connection(format!("amqp flush failed: {e}")))?;
        // Connection.Start -> Start-Ok (PLAIN).
        expect_method(stream, 10, 10).await?;
        let sasl = format!("\0{}\0{}", self.endpoint.username, self.endpoint.password);
        let mut args = Vec::new();
        encode_empty_table(&mut args);
        encode_shortstr("PLAIN", &mut args)?;
        encode_longstr(sasl.as_bytes(), &mut args);
        encode_shortstr("en_US", &mut args)?;
        write_frame(stream, &method_frame(0, 10, 11, &args)).await?;
        // Tune -> Tune-Ok (echo server values).
        let tune = expect_method(stream, 10, 30).await?;
        if tune.len() < 8 {
            return Err(ConnectorError::Connection(
                "truncated tune frame".to_string(),
            ));
        }
        let mut tune_ok = Vec::new();
        tune_ok.extend_from_slice(&tune[..8]);
        write_frame(stream, &method_frame(0, 10, 31, &tune_ok)).await?;
        // Open vhost.
        let mut open = Vec::new();
        encode_shortstr(&self.endpoint.vhost, &mut open)?;
        encode_shortstr("", &mut open)?;
        open.push(0u8);
        write_frame(stream, &method_frame(0, 10, 40, &open)).await?;
        expect_method(stream, 10, 41).await?;
        // Channel 1 open.
        let mut channel_open = Vec::new();
        encode_shortstr("", &mut channel_open)?;
        write_frame(stream, &method_frame(1, 20, 10, &channel_open)).await?;
        expect_method(stream, 20, 11).await?;
        Ok(())
    }

    async fn publish_once(&self, publish: &AmqpPublish) -> Result<()> {
        let mut guard = self.conn.lock().await;
        if guard.is_none() {
            let stream = tokio::time::timeout(
                Duration::from_secs(5),
                TcpStream::connect(format!("{}:{}", self.endpoint.host, self.endpoint.port)),
            )
            .await
            .map_err(|_| {
                ConnectorError::Connection(format!(
                    "amqp connect timeout: {}:{}",
                    self.endpoint.host, self.endpoint.port
                ))
            })?
            .map_err(|e| ConnectorError::Connection(format!("amqp connect failed: {e}")))?;
            let mut fresh = RabbitConn { stream };
            self.handshake(&mut fresh.stream).await?;
            *guard = Some(fresh);
        }
        let conn = guard.as_mut().expect("connected");
        for frame in encode_basic_publish(publish)? {
            write_frame(&mut conn.stream, &frame).await?;
        }
        Ok(())
    }
}

fn encode_empty_table(out: &mut Vec<u8>) {
    out.extend_from_slice(&0u32.to_be_bytes());
}

#[async_trait]
impl RabbitMqTransport for TcpRabbitTransport {
    async fn publish(&self, publish: AmqpPublish) -> Result<()> {
        match self.publish_once(&publish).await {
            Ok(()) => Ok(()),
            Err(_) => {
                // Drop the poisoned connection and retry once fresh.
                *self.conn.lock().await = None;
                self.publish_once(&publish).await
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Production transport on the maintained `lapin` driver.
// ---------------------------------------------------------------------------

/// Connect timeout for the driver handshake: 5 s matches the legacy
/// [`TcpRabbitTransport`] dial timeout (the protocol requirement is a
/// bounded handshake, not a specific value).
const LAPIN_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Publisher-confirm wait: 10 s matches the legacy `read_frame` timeout
/// on the same path.
const LAPIN_CONFIRM_TIMEOUT: Duration = Duration::from_secs(10);

/// Convert sink headers into a driver field table: `Str` rides as
/// `LongString`, `Bool` as `Boolean`, `I32` as `LongInt`, `Timestamp`
/// as `Timestamp`, mirroring the hand-rolled `encode_field_table`
/// types (`S`/`t`/`I`/`T`).
fn lapin_field_table(headers: &[(String, FieldValue)]) -> lapin::types::FieldTable {
    let mut table = lapin::types::FieldTable::default();
    for (name, value) in headers {
        let amqp_value = match value {
            FieldValue::Str(text) => lapin::types::AMQPValue::LongString(text.clone().into()),
            FieldValue::Bool(flag) => lapin::types::AMQPValue::Boolean(*flag),
            FieldValue::I32(number) => lapin::types::AMQPValue::LongInt(*number),
            FieldValue::Timestamp(ts) => lapin::types::AMQPValue::Timestamp(*ts),
        };
        table.insert(name.clone().into(), amqp_value);
    }
    table
}

/// Build the driver `BasicProperties` for one publish: content type,
/// headers table, delivery mode and timestamp ride the content header,
/// exactly as [`encode_basic_publish`] sets flag `0xB040` on the
/// hand-rolled path.
fn lapin_properties(publish: &AmqpPublish) -> lapin::BasicProperties {
    lapin::BasicProperties::default()
        .with_content_type("application/json".into())
        .with_headers(lapin_field_table(&publish.headers))
        .with_delivery_mode(publish.delivery_mode)
        .with_timestamp(publish.timestamp_secs)
}

struct LapinChannelState {
    connection: lapin::Connection,
    channel: lapin::Channel,
}

/// Production RabbitMQ transport on the maintained `lapin` driver
/// (MIT): AMQP 0-9-1 PLAIN handshake plus `Basic.Publish` with content
/// header/body frames through the driver. The legacy
/// [`TcpRabbitTransport`] stays for offline unit tests only;
/// production wiring uses this transport.
///
/// Bound: one shared connection and one multiplexed channel, created
/// lazily and reused; each `publish` is one driver `basic_publish`
/// plus one confirm await with no background queue. The sink's send
/// path runs behind the rule engine's bounded queue, so no benchmark
/// numbers are needed.
pub struct LapinRabbitTransport {
    amqp_url: String,
    state: AsyncMutex<Option<LapinChannelState>>,
}

impl LapinRabbitTransport {
    pub fn new(endpoint: &str) -> Result<Self> {
        // Validate the URL shape now so misconfiguration fails at
        // connector creation, never at first publish.
        parse_endpoint(endpoint)?;
        Ok(Self {
            amqp_url: endpoint.to_string(),
            state: AsyncMutex::new(None),
        })
    }

    async fn channel(&self) -> Result<lapin::Channel> {
        let mut guard = self.state.lock().await;
        if let Some(state) = guard.as_ref() {
            // The stored connection owns the TCP session for the shared
            // channel; touching it keeps the ownership load-bearing.
            let _ = &state.connection;
            return Ok(state.channel.clone());
        }
        let connection = tokio::time::timeout(
            LAPIN_CONNECT_TIMEOUT,
            lapin::Connection::connect(&self.amqp_url, lapin::ConnectionProperties::default()),
        )
        .await
        .map_err(|_| {
            ConnectorError::Connection(format!(
                "rabbitmq driver connect timeout: {}",
                self.amqp_url
            ))
        })?
        .map_err(|e| ConnectorError::Connection(format!("rabbitmq driver connect failed: {e}")))?;
        let channel = connection.create_channel().await.map_err(|e| {
            ConnectorError::Connection(format!("rabbitmq driver channel failed: {e}"))
        })?;
        let cloned = channel.clone();
        *guard = Some(LapinChannelState {
            connection,
            channel,
        });
        Ok(cloned)
    }

    async fn publish_once(&self, publish: &AmqpPublish) -> Result<()> {
        let channel = self.channel().await?;
        let confirm = channel
            .basic_publish(
                publish.exchange.clone().into(),
                publish.routing_key.clone().into(),
                lapin::options::BasicPublishOptions::default(),
                publish.body.as_ref(),
                lapin_properties(publish),
            )
            .await
            .map_err(|e| {
                ConnectorError::Connection(format!("rabbitmq driver publish failed: {e}"))
            })?;
        tokio::time::timeout(LAPIN_CONFIRM_TIMEOUT, confirm)
            .await
            .map_err(|_| ConnectorError::Connection("rabbitmq driver confirm timeout".to_string()))?
            .map_err(|e| {
                ConnectorError::Connection(format!("rabbitmq driver publish not confirmed: {e}"))
            })?;
        Ok(())
    }
}

#[async_trait]
impl RabbitMqTransport for LapinRabbitTransport {
    async fn publish(&self, publish: AmqpPublish) -> Result<()> {
        match self.publish_once(&publish).await {
            Ok(()) => Ok(()),
            Err(_) => {
                // Drop the poisoned connection/channel and retry once
                // fresh, mirroring the legacy transport's contract.
                *self.state.lock().await = None;
                self.publish_once(&publish).await
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Sink.
// ---------------------------------------------------------------------------

/// RabbitMQ publisher sink: renders routing keys, encodes
/// `Basic.Publish` frames, and dispatches through the transport.
pub struct RabbitMqSink {
    config: RabbitMqSinkConfig,
    transport: Arc<dyn RabbitMqTransport>,
    sent: AtomicU64,
}

impl RabbitMqSink {
    pub fn new(config: RabbitMqSinkConfig, transport: Arc<dyn RabbitMqTransport>) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            transport,
            sent: AtomicU64::new(0),
        })
    }

    pub fn config(&self) -> &RabbitMqSinkConfig {
        &self.config
    }

    pub fn sent_count(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl Sink for RabbitMqSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> super::Result<()> {
        let publish = AmqpPublish {
            exchange: self.config.exchange.clone(),
            routing_key: render_routing_key(&self.config.routing_key_template, topic.as_str()),
            delivery_mode: self.config.delivery_mode,
            timestamp_secs: now_secs(),
            headers: vec![
                (
                    "mqtt.topic".to_string(),
                    FieldValue::Str(topic.as_str().to_string()),
                ),
                (
                    "mqtt.qos".to_string(),
                    FieldValue::I32(u8::from(qos) as i32),
                ),
                (
                    "mqtt.timestamp".to_string(),
                    FieldValue::Timestamp(now_secs()),
                ),
            ],
            body: payload.clone(),
        };
        if publish.routing_key.len() > 255 {
            return Err(ConnectorError::Dispatch(format!(
                "rendered routing key too long ({} bytes)",
                publish.routing_key.len()
            )));
        }
        self.transport.publish(publish).await?;
        self.sent.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "rabbitmq"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> RabbitMqSinkConfig {
        RabbitMqSinkConfig {
            endpoint: "amqp://guest:guest@127.0.0.1:5672/%2f".to_string(),
            exchange: "telemetry".to_string(),
            routing_key_template: "sensor.${topic}".to_string(),
            delivery_mode: 2,
        }
    }

    #[test]
    fn test_config_validation() {
        let mut config = test_config();
        assert!(config.validate().is_ok());

        config.endpoint.clear();
        assert!(config.validate().is_err());
        config.endpoint = "amqp://h".to_string();

        config.exchange.clear();
        assert!(config.validate().is_err());
        config.exchange = "telemetry".to_string();

        config.delivery_mode = 3;
        assert!(config.validate().is_err());
        config.delivery_mode = 1;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_endpoint_parsing() {
        let endpoint = parse_endpoint("amqp://guest:guest@127.0.0.1:5672/%2f").expect("parses");
        assert_eq!(endpoint.host, "127.0.0.1");
        assert_eq!(endpoint.port, 5672);
        assert_eq!(endpoint.username, "guest");
        assert_eq!(endpoint.password, "guest");
        assert_eq!(endpoint.vhost, "/");

        let endpoint = parse_endpoint("amqp://broker").expect("defaults");
        assert_eq!(endpoint.port, 5672);
        assert_eq!(endpoint.username, "guest");
        assert_eq!(endpoint.vhost, "/");

        assert!(parse_endpoint("http://x").is_err());
        assert!(parse_endpoint("amqp://:nopass@h").is_err());
        assert!(parse_endpoint("amqp://h:notaport").is_err());
    }

    #[test]
    fn test_routing_key_translation() {
        assert_eq!(
            render_routing_key("sensor.${topic}", "a/b/c"),
            "sensor.a.b.c"
        );
        assert_eq!(render_routing_key("${topic}", "a/b"), "a.b");
        assert_eq!(render_routing_key("plain", "a/b"), "plain");
    }

    #[test]
    fn test_field_table_encoding() {
        let table = encode_field_table(&[
            ("mqtt.topic".to_string(), FieldValue::Str("a/b".to_string())),
            ("mqtt.qos".to_string(), FieldValue::I32(1)),
            ("flag".to_string(), FieldValue::Bool(true)),
            ("at".to_string(), FieldValue::Timestamp(1700000000)),
        ])
        .expect("encodes");
        // u32 length prefix, then entries.
        let len = u32::from_be_bytes([table[0], table[1], table[2], table[3]]) as usize;
        assert_eq!(4 + len, table.len());
        let body = &table[4..];
        assert!(body.windows(10).any(|w| w == b"mqtt.topic"));
        assert!(body.contains(&b'S'));
        assert!(body.contains(&b't'));
        assert!(body.contains(&b'I'));
        assert!(body.contains(&b'T'));
    }

    #[test]
    fn test_basic_publish_frame_structure() {
        let publish = AmqpPublish {
            exchange: "telemetry".to_string(),
            routing_key: "sensor.a.b".to_string(),
            delivery_mode: 2,
            timestamp_secs: 1700000000,
            headers: vec![("mqtt.topic".to_string(), FieldValue::Str("a/b".to_string()))],
            body: Bytes::from_static(b"{}"),
        };
        let frames = encode_basic_publish(&publish).expect("encodes");
        assert_eq!(frames.len(), 3);

        // Method frame: type 1, channel 1, class 60 method 40, end marker.
        let method = frames[0].encode();
        assert_eq!(method[0], FRAME_METHOD);
        assert_eq!(&method[1..3], &[0, 1]);
        assert_eq!(&method[7..11], &[0, 60, 0, 40]);
        assert!(method.windows(10).any(|w| w == b"sensor.a.b"));
        assert_eq!(*method.last().unwrap(), FRAME_END);

        // Header frame carries flags 0xB040, delivery mode, timestamp.
        let header = frames[1].encode();
        assert_eq!(header[0], FRAME_HEADER);
        let body_size = u64::from_be_bytes(header[7 + 2 + 2..7 + 2 + 2 + 8].try_into().unwrap());
        assert_eq!(body_size, 2);
        assert!(header.windows(2).any(|w| w == [0xB0, 0x40]));
        assert!(header.contains(&2u8));

        // Body frame carries the payload verbatim, then the frame end.
        let body = frames[2].encode();
        assert_eq!(body[0], FRAME_BODY);
        assert!(body.ends_with(&[b'}', FRAME_END]));
    }

    #[tokio::test]
    async fn test_sink_routes_through_memory_transport() {
        let transport = Arc::new(MemoryAmqpTransport::new());
        let sink = RabbitMqSink::new(test_config(), transport.clone()).expect("valid sink");
        sink.send(
            &Topic::new("a/b").unwrap(),
            &Bytes::from_static(b"{}"),
            QoS::AtLeastOnce,
        )
        .await
        .expect("delivers");
        assert_eq!(sink.sent_count(), 1);

        let publishes = transport.publishes();
        assert_eq!(publishes.len(), 1);
        assert_eq!(publishes[0].exchange, "telemetry");
        assert_eq!(publishes[0].routing_key, "sensor.a.b");
        assert_eq!(publishes[0].delivery_mode, 2);
    }

    /// In-process fake RabbitMQ broker: scripted PLAIN handshake, then
    /// captures the published frames for byte-level assertions.
    #[tokio::test]
    async fn test_tcp_transport_handshake_and_publish() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let captured = Arc::new(parking_lot::Mutex::new(Vec::<u8>::new()));
        let captured_rx = captured.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            // Protocol header.
            let mut header = [0u8; 8];
            stream.read_exact(&mut header).await.expect("proto header");
            assert_eq!(&header, b"AMQP\x00\x00\x09\x01");
            // Connection.Start with PLAIN + en_US offered.
            send_method(&mut stream, 0, 10, 10, &start_args()).await;
            let ((class, method), args) = read_method(&mut stream).await;
            assert_eq!((class, method), (10, 11));
            assert!(args.windows(5).any(|w| w == b"PLAIN"));
            // Tune, Open, channel open: canned oks.
            send_method(&mut stream, 0, 10, 30, &[0, 0, 0, 0, 0, 0, 0, 0]).await;
            let _ = read_method(&mut stream).await; // Tune-Ok
            let _ = read_method(&mut stream).await; // Open
            send_method(&mut stream, 0, 10, 41, &[0]).await; // Open-Ok
            let _ = read_method(&mut stream).await; // Channel.Open
            send_method(&mut stream, 1, 20, 11, &[0, 0, 0, 0]).await; // Open-Ok
                                                                      // Publish triple: capture raw bytes.
            for _ in 0..3 {
                let raw = read_raw_frame(&mut stream).await;
                captured_rx.lock().extend_from_slice(&raw);
            }
        });

        let transport =
            TcpRabbitTransport::new(&format!("amqp://guest:guest@127.0.0.1:{port}/%2f"))
                .expect("valid endpoint");
        let sink = RabbitMqSink::new(test_config(), Arc::new(transport)).expect("valid sink");
        sink.send(
            &Topic::new("a/b").unwrap(),
            &Bytes::from_static(br#"{ "v": 1 }"#),
            QoS::AtMostOnce,
        )
        .await
        .expect("publish over TCP");
        assert_eq!(sink.sent_count(), 1);

        let finished = {
            // The transport returns once bytes hit the kernel; poll until
            // the fake broker has consumed the publish triple.
            let mut done = false;
            for _ in 0..500 {
                if server.is_finished() {
                    done = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            done
        };
        assert!(finished, "fake broker never consumed the publish");
        server.await.expect("fake broker task");
        let wire = captured.lock().clone();
        assert!(
            wire.windows(10).any(|w| w == b"sensor.a.b"),
            "routing key dots"
        );
        let payload = br#"{ "v": 1 }"#;
        assert!(
            wire.windows(payload.len()).any(|w| w == payload),
            "body bytes"
        );
        assert!(wire.windows(10).any(|w| w == b"mqtt.topic"), "header table");
        assert!(
            wire.iter().filter(|b| **b == FRAME_END).count() >= 3,
            "frame ends"
        );
    }

    fn start_args() -> Vec<u8> {
        let mut args = Vec::new();
        args.extend_from_slice(&[0, 0]); // version
        args.extend_from_slice(&[0, 0, 0, 0]); // empty server properties
        args.extend_from_slice(&[0, 5, b'P', b'L', b'A', b'I', b'N']); // mechanisms
        args.extend_from_slice(&[0, 5, b'e', b'n', b'_', b'U', b'S']); // locales
        args
    }

    async fn send_method(
        stream: &mut TcpStream,
        channel: u16,
        class_id: u16,
        method_id: u16,
        args: &[u8],
    ) {
        let mut payload = Vec::new();
        payload.extend_from_slice(&class_id.to_be_bytes());
        payload.extend_from_slice(&method_id.to_be_bytes());
        payload.extend_from_slice(args);
        let frame = AmqpFrame {
            frame_type: FRAME_METHOD,
            channel,
            payload,
        };
        stream.write_all(&frame.encode()).await.expect("write");
    }

    async fn read_method(stream: &mut TcpStream) -> ((u16, u16), Vec<u8>) {
        let (frame_type, _channel, payload) = read_frame(stream).await.expect("read method");
        assert_eq!(frame_type, FRAME_METHOD);
        let class_id = u16::from_be_bytes([payload[0], payload[1]]);
        let method_id = u16::from_be_bytes([payload[2], payload[3]]);
        ((class_id, method_id), payload[4..].to_vec())
    }

    async fn read_raw_frame(stream: &mut TcpStream) -> Vec<u8> {
        let mut header = [0u8; 7];
        stream.read_exact(&mut header).await.expect("frame head");
        let size = u32::from_be_bytes([header[3], header[4], header[5], header[6]]) as usize;
        let mut rest = vec![0u8; size + 1];
        stream.read_exact(&mut rest).await.expect("frame tail");
        let mut raw = header.to_vec();
        raw.extend_from_slice(&rest);
        raw
    }

    #[test]
    fn test_driver_transport_rejects_bad_endpoint() {
        assert!(LapinRabbitTransport::new("http://x").is_err());
        assert!(LapinRabbitTransport::new("").is_err());
        assert!(LapinRabbitTransport::new("amqp://guest:guest@127.0.0.1:5672/%2f").is_ok());
    }

    #[test]
    fn test_driver_properties_carry_headers_mode_and_timestamp() {
        let publish = AmqpPublish {
            exchange: "telemetry".to_string(),
            routing_key: "sensor.a.b".to_string(),
            delivery_mode: 2,
            timestamp_secs: 1_700_000_000,
            headers: vec![
                ("mqtt.topic".to_string(), FieldValue::Str("a/b".to_string())),
                ("mqtt.qos".to_string(), FieldValue::I32(1)),
                ("flag".to_string(), FieldValue::Bool(true)),
                ("at".to_string(), FieldValue::Timestamp(1_700_000_000)),
            ],
            body: Bytes::from_static(b"{}"),
        };
        let table = lapin_field_table(&publish.headers);
        assert_eq!(table.inner().len(), 4);
        let props = lapin_properties(&publish);
        assert_eq!(*props.delivery_mode(), Some(2));
        assert_eq!(*props.timestamp(), Some(1_700_000_000));
        assert!(props.headers().is_some());
    }

    fn qual_env(name: &str) -> Option<String> {
        std::env::var(name).ok().filter(|v| !v.trim().is_empty())
    }

    /// Qualification against a real RabbitMQ server through the
    /// maintained `lapin` driver write path.
    ///
    /// Run with e.g.:
    /// `RABBITMQ_HOST=127.0.0.1 RABBITMQ_PORT=5672 RABBITMQ_USERNAME=qual \
    ///  RABBITMQ_PASSWORD=qualpass1 RABBITMQ_EXCHANGE=qual-b336 RABBITMQ_QUEUE=qual-b336 \
    ///  cargo test -p broker-connectors --lib rabbitmq::tests::test_qualify_driver_write_path -- --ignored --nocapture --test-threads=1`
    ///
    /// Declares the exchange (topic) and queue, binds with `#`, then
    /// streams 2000 routed messages through [`RabbitMqSink`] on
    /// [`LapinRabbitTransport`] via the shared
    /// [`crate::ConnectorManager`] path the broker uses (never
    /// `sink.send` directly), and asserts the bound queue delivers
    /// every payload exactly (duplicates tolerated, loss is not).
    /// A closed channel is then shown to surface an error. Panics
    /// when its environment is missing (fail closed, never skips).
    #[tokio::test]
    #[ignore = "needs a real RabbitMQ server (see RABBITMQ_* env)"]
    async fn test_qualify_driver_write_path() {
        use crate::ConnectorManager;
        use futures::StreamExt as _;
        use std::collections::HashSet;
        use std::time::{SystemTime, UNIX_EPOCH};

        const PUBLISHES: usize = 2000;

        let host = qual_env("RABBITMQ_HOST").unwrap_or_else(|| {
            panic!(
                "RABBITMQ_HOST must point at a real RabbitMQ server for qualification; \
                 failing closed instead of passing vacuously \
                 (e.g. RABBITMQ_HOST=127.0.0.1)"
            )
        });
        let port = qual_env("RABBITMQ_PORT").unwrap_or_else(|| {
            panic!("RABBITMQ_PORT must be set for qualification; failing closed")
        });
        let username = qual_env("RABBITMQ_USERNAME").unwrap_or_else(|| {
            panic!("RABBITMQ_USERNAME must be set for qualification; failing closed")
        });
        let password = qual_env("RABBITMQ_PASSWORD").unwrap_or_else(|| {
            panic!("RABBITMQ_PASSWORD must be set for qualification; failing closed")
        });
        let exchange = qual_env("RABBITMQ_EXCHANGE").unwrap_or_else(|| {
            panic!("RABBITMQ_EXCHANGE must be set for qualification; failing closed")
        });
        let queue = qual_env("RABBITMQ_QUEUE").unwrap_or_else(|| {
            panic!("RABBITMQ_QUEUE must be set for qualification; failing closed")
        });
        // Server version for the report comes from the qualification
        // image the gates start (rabbitmq:3.13.2-management); the
        // driver exposes no broker-version RPC here, so the endpoint
        // line below is the measured endpoint, never a substitute
        // version string.
        eprintln!(
            "qual server: image rabbitmq:3.13.2-management host={host} port={port} exchange={exchange} queue={queue}"
        );

        let amqp_url = format!("amqp://{username}:{password}@{host}:{port}/%2f");
        // 30s connect wait: the protocol requirement is a bounded
        // handshake, not a specific value; 30s tolerates a slow
        // container start while failing fast on a dead broker.
        let connection = tokio::time::timeout(
            Duration::from_secs(30),
            lapin::Connection::connect(&amqp_url, lapin::ConnectionProperties::default()),
        )
        .await
        .expect("qual connect timeout")
        .unwrap_or_else(|e| panic!("qual connect failed: {e:?}"));
        let admin = connection
            .create_channel()
            .await
            .unwrap_or_else(|e| panic!("qual admin channel failed: {e:?}"));

        admin
            .exchange_declare(
                exchange.as_str().into(),
                lapin::ExchangeKind::Topic,
                lapin::options::ExchangeDeclareOptions::default(),
                lapin::types::FieldTable::default(),
            )
            .await
            .unwrap_or_else(|e| panic!("qual exchange declare failed: {e:?}"));
        admin
            .queue_declare(
                queue.as_str().into(),
                lapin::options::QueueDeclareOptions::default(),
                lapin::types::FieldTable::default(),
            )
            .await
            .unwrap_or_else(|e| panic!("qual queue declare failed: {e:?}"));
        admin
            .queue_bind(
                queue.as_str().into(),
                exchange.as_str().into(),
                "#".into(),
                lapin::options::QueueBindOptions::default(),
                lapin::types::FieldTable::default(),
            )
            .await
            .unwrap_or_else(|e| panic!("qual queue bind failed: {e:?}"));
        admin
            .queue_purge(
                queue.as_str().into(),
                lapin::options::QueuePurgeOptions::default(),
            )
            .await
            .unwrap_or_else(|e| panic!("qual queue purge failed: {e:?}"));
        eprintln!("qual declared: exchange={exchange} (topic) queue={queue} binding=#");

        let config = RabbitMqSinkConfig {
            endpoint: amqp_url.clone(),
            exchange: exchange.clone(),
            routing_key_template: "${topic}".to_string(),
            delivery_mode: 2,
        };
        config.validate().expect("qual config validates");
        let transport = Arc::new(LapinRabbitTransport::new(&amqp_url).expect("qual transport"));
        let sink = Arc::new(RabbitMqSink::new(config, transport).expect("qual sink"));
        assert_eq!(sink.kind(), "rabbitmq");
        // The broker's path: rule actions deliver through the shared
        // connector manager (this is what `register_live_sink` fills
        // and what the rule engine's `ForwardConnector` action sends
        // through), so the qualification sends through it and never
        // `sink.send` directly.
        let manager = ConnectorManager::new();
        manager.register("qual-rabbit", sink.clone());
        manager.register("rabbitmq:qual-rabbit", sink.clone());

        for seq in 0..PUBLISHES {
            // Ingress slashes become routing-key dots
            // (`qual/3` -> `qual.3`), matched by the `#` binding.
            let ingress =
                Topic::new(format!("qual/{seq}")).unwrap_or_else(|e| panic!("qual topic: {e:?}"));
            let payload = Bytes::from(format!("qual-{seq:06}"));
            manager
                .send("qual-rabbit", &ingress, &payload, QoS::AtLeastOnce)
                .await
                .unwrap_or_else(|e| panic!("qual send seq={seq} failed: {e:?}"));
        }
        assert_eq!(sink.sent_count(), PUBLISHES as u64);
        eprintln!("qual rows sent: count={PUBLISHES} exchange={exchange}");

        // Bound-queue delivery assertion: at-least-once permits
        // duplicates, never loss, so every key must be present.
        let run_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let consumer_tag = format!("qual-b336-{run_nanos}");
        let mut consumer = admin
            .basic_consume(
                queue.as_str().into(),
                consumer_tag.as_str().into(),
                lapin::options::BasicConsumeOptions::default(),
                lapin::types::FieldTable::default(),
            )
            .await
            .unwrap_or_else(|e| panic!("qual consume failed: {e:?}"));
        let mut seen: HashSet<String> = HashSet::new();
        // 180s receive window for 2000 publishes: generous against
        // the 1800s gate timeout so a slow broker still converges,
        // while a stuck bridge fails instead of hanging the gate.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(180);
        while seen.len() < PUBLISHES {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                panic!(
                    "qual receive timeout: got {} of {PUBLISHES} distinct payloads",
                    seen.len()
                );
            }
            let delivery = tokio::time::timeout(remaining, consumer.next())
                .await
                .expect("qual recv timeout")
                .unwrap_or_else(|| panic!("qual consumer stream ended early"))
                .unwrap_or_else(|e| panic!("qual delivery failed: {e:?}"));
            let payload = String::from_utf8_lossy(&delivery.data).into_owned();
            seen.insert(payload);
            delivery
                .ack(lapin::options::BasicAckOptions::default())
                .await
                .unwrap_or_else(|e| panic!("qual ack failed: {e:?}"));
        }
        assert_eq!(seen.len(), PUBLISHES, "qual must receive all publishes");
        for seq in 0..PUBLISHES {
            let key = format!("qual-{seq:06}");
            assert!(seen.contains(&key), "qual missing payload {key}");
        }
        eprintln!("qual rows asserted: distinct={} binding=#", seen.len());

        // Channel close surfaces an error: publishing on a closed
        // channel must fail instead of silently dropping, whether the
        // driver reports it at publish time or at confirm time.
        let probe = connection
            .create_channel()
            .await
            .unwrap_or_else(|e| panic!("qual probe channel failed: {e:?}"));
        probe
            .close(200, "qual probe close".into())
            .await
            .unwrap_or_else(|e| panic!("qual probe close failed: {e:?}"));
        match probe
            .basic_publish(
                exchange.as_str().into(),
                "qual.probe".into(),
                lapin::options::BasicPublishOptions::default(),
                b"probe",
                lapin::BasicProperties::default(),
            )
            .await
        {
            Err(_) => {}
            Ok(confirm) => {
                let settled = tokio::time::timeout(Duration::from_secs(10), confirm).await;
                assert!(
                    settled.is_err() || settled.expect("confirm polled").is_err(),
                    "qual publishing on a closed channel must surface an error"
                );
            }
        }
        eprintln!("qual channel-close: publish on closed channel errored as required");

        // Cleanup: delete the queue and exchange created above, then
        // close the connection. The sink's shared connection closes
        // with the test process.
        let _ = admin
            .queue_delete(
                queue.as_str().into(),
                lapin::options::QueueDeleteOptions::default(),
            )
            .await;
        let _ = admin
            .exchange_delete(
                exchange.as_str().into(),
                lapin::options::ExchangeDeleteOptions::default(),
            )
            .await;
        let _ = connection.close(200, "qual done".into()).await;
        eprintln!("qual cleanup: deleted queue={queue} exchange={exchange}; connection closed");
    }
}
