//! Remote MQTT outbound bridge sink (INDRA-156).
//!
//! Forwards IndraMQTT events to an upstream MQTT broker (such as
//! HiveMQ, AWS IoT Core, or another IndraMQTT cluster) with topic remapping and clean-room MQTT
//! 3.1.1 / 5.0 PUBLISH framing. QoS and retain flags are preserved
//! unless overridden; packet identifiers cycle 1..=65535 per sink.
//!
//! Delivery is fire-and-forget per frame (no PUBACK tracking): the
//! QoS bits travel for downstream handling, while at-least-once
//! end-to-end needs an upstream session with retransmission. The TCP
//! transport dials, exchanges CONNECT/CONNACK, and writes frames;
//! `mqtts://` addresses parse for configuration portability but
//! connecting over TLS is rejected with a clear error until a TLS
//! backend lands (terminate TLS in a sidecar proxy meanwhile).

use async_trait::async_trait;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{now_millis, render_template, BackoffState, BatchQueue, ConnectorError, Result, Sink};

/// MQTT protocol version for wire framing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MqttBridgeProtocol {
    /// MQTT 3.1.1 framing.
    #[default]
    V311,
    /// MQTT 5.0 framing (PUBLISH with zero-length properties).
    V50,
}

/// Parsed bridge address: host, port and TLS intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeEndpoint {
    pub host: String,
    pub port: u16,
    /// True for `mqtts://` (TLS rejected at connect until a backend lands).
    pub tls: bool,
}

/// Parse `mqtt://host:1883`, `mqtts://host:8883`, `host:port` or bare
/// `host` (default port 1883, 8883 for `mqtts://`).
pub fn parse_bridge_address(address: &str) -> Result<BridgeEndpoint> {
    let address = address.trim();
    if address.is_empty() {
        return Err(ConnectorError::Dispatch(
            "mqtt bridge address must not be empty".to_string(),
        ));
    }
    let (tls, rest) = match address.split_once("://") {
        Some(("mqtt", rest)) => (false, rest),
        Some(("mqtts", rest)) => (true, rest),
        Some((scheme, _)) => {
            return Err(ConnectorError::Dispatch(format!(
                "mqtt bridge scheme must be mqtt:// or mqtts://, got {scheme:?}"
            )));
        }
        None => (false, address),
    };
    if rest.is_empty() || rest.contains('/') {
        return Err(ConnectorError::Dispatch(format!(
            "mqtt bridge address must be host[:port], got {address:?}"
        )));
    }
    let (host, port) = match rest.rsplit_once(':') {
        Some((host, port)) => {
            let port: u16 = port.parse().map_err(|_| {
                ConnectorError::Dispatch(format!("mqtt bridge bad port in {address:?}"))
            })?;
            if port == 0 {
                return Err(ConnectorError::Dispatch(format!(
                    "mqtt bridge port must be 1..=65535 in {address:?}"
                )));
            }
            (host, port)
        }
        None => (rest, if tls { 8883 } else { 1883 }),
    };
    if host.is_empty() {
        return Err(ConnectorError::Dispatch(format!(
            "mqtt bridge host must not be empty in {address:?}"
        )));
    }
    Ok(BridgeEndpoint {
        host: host.to_string(),
        port,
        tls,
    })
}

fn default_true() -> bool {
    true
}

fn default_keep_alive() -> u16 {
    60
}

fn default_max_inflight() -> Option<usize> {
    Some(10_000)
}

fn default_max_batch() -> Option<usize> {
    Some(100)
}

fn default_linger() -> Option<u64> {
    Some(10)
}

/// Remote MQTT bridge configuration. All depths are optional (`None`
/// = unbounded) with zero clamped ceilings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MqttBridgeSinkConfig {
    /// Remote `mqtt://host:1883`, `mqtts://host:8883` or `host:port`.
    pub broker_address: String,
    /// Client id with `${timestamp}` / `${seq}` substitution.
    pub client_id: String,
    /// MQTT clean start (default true).
    #[serde(default = "default_true")]
    pub clean_start: bool,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    /// Keep-alive seconds (default 60).
    #[serde(default = "default_keep_alive")]
    pub keep_alive_secs: u16,
    /// Prefix prepended to remapped topics (e.g. `edge/station1/`).
    #[serde(default)]
    pub topic_prefix: Option<String>,
    /// Remap template with `${topic}` (default identity).
    #[serde(default)]
    pub topic_template: Option<String>,
    /// Force outbound QoS (`None` preserves ingress).
    #[serde(default)]
    pub qos_override: Option<u8>,
    /// Force retain (`None` defaults to false: the `Sink` API carries
    /// no ingress retain flag).
    #[serde(default)]
    pub retain_override: Option<bool>,
    /// Max buffered rows before backpressure errors (default 10,000).
    #[serde(default = "default_max_inflight")]
    pub max_inflight: Option<usize>,
    /// Flush trigger row count (default 100).
    #[serde(default = "default_max_batch")]
    pub max_batch_size: Option<usize>,
    /// Linger flush window in ms (default 10).
    #[serde(default = "default_linger")]
    pub linger_ms: Option<u64>,
    /// Wire protocol version (default 3.1.1).
    #[serde(default)]
    pub protocol: MqttBridgeProtocol,
}

impl MqttBridgeSinkConfig {
    pub fn validate(&self) -> Result<()> {
        parse_bridge_address(&self.broker_address)?;
        if self.client_id.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "mqtt bridge client_id must not be empty".to_string(),
            ));
        }
        // Strict template checks with dummy values.
        self.resolve_client_id(0, 0)?;
        self.remap_topic("dummy/topic", QoS::AtMostOnce, 0)?;
        if let Some(qos) = self.qos_override {
            if qos > 2 {
                return Err(ConnectorError::Dispatch(format!(
                    "mqtt bridge qos_override must be 0..=2, got {qos}"
                )));
            }
        }
        if self.max_batch_size == Some(0) {
            return Err(ConnectorError::Dispatch(
                "mqtt bridge max_batch_size must be >= 1".to_string(),
            ));
        }
        Ok(())
    }

    pub fn endpoint(&self) -> Result<BridgeEndpoint> {
        parse_bridge_address(&self.broker_address)
    }

    pub fn effective_batch_size(&self) -> usize {
        self.max_batch_size.unwrap_or(usize::MAX).max(1)
    }

    pub fn effective_linger(&self) -> Duration {
        self.linger_ms
            .map(Duration::from_millis)
            .unwrap_or(Duration::MAX)
    }

    pub fn effective_inflight(&self) -> usize {
        self.max_inflight.unwrap_or(usize::MAX).max(1)
    }

    /// Render the client id for one event (`${timestamp}`, `${seq}`).
    pub fn resolve_client_id(&self, seq: u64, millis: i64) -> Result<String> {
        let vars = [
            ("timestamp".to_string(), millis.to_string()),
            ("seq".to_string(), seq.to_string()),
        ];
        let borrowed: Vec<(&str, String)> =
            vars.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
        let id = render_template(&self.client_id, &borrowed)?;
        if id.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "mqtt bridge client_id resolved empty".to_string(),
            ));
        }
        Ok(id)
    }

    /// Remap one ingress topic: template substitution, then prefix
    /// join. Concrete topics only: `+`/`#` in the result is rejected.
    pub fn remap_topic(&self, topic: &str, qos: QoS, millis: i64) -> Result<String> {
        let template = self.topic_template.as_deref().unwrap_or("${topic}");
        let vars = [
            ("topic".to_string(), topic.to_string()),
            ("qos".to_string(), u8::from(qos).to_string()),
            ("timestamp".to_string(), millis.to_string()),
        ];
        let borrowed: Vec<(&str, String)> =
            vars.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
        let mut mapped = render_template(template, &borrowed)?;
        if mapped.contains('+') || mapped.contains('#') {
            return Err(ConnectorError::Dispatch(format!(
                "mqtt bridge remapped topic must be concrete: {mapped:?}"
            )));
        }
        if let Some(prefix) = &self.topic_prefix {
            let prefix = prefix.trim_end_matches('/');
            if !prefix.is_empty() {
                mapped = format!("{prefix}/{mapped}");
            }
        }
        if mapped.is_empty() {
            return Err(ConnectorError::Dispatch(
                "mqtt bridge remapped topic is empty".to_string(),
            ));
        }
        Ok(mapped)
    }
}

// ---------------------------------------------------------------------------
// Wire codec: MQTT 3.1.1 / 5.0 PUBLISH (plus CONNECT/CONNACK for dial).
// ---------------------------------------------------------------------------

/// Encode the MQTT variable-byte integer (1..=4 bytes, max 268435455).
pub fn encode_remaining_length(mut value: usize, out: &mut Vec<u8>) -> Result<()> {
    if value > 268_435_455 {
        return Err(ConnectorError::Dispatch(
            "mqtt remaining length exceeds 268435455".to_string(),
        ));
    }
    loop {
        let mut byte = (value % 128) as u8;
        value /= 128;
        if value > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    Ok(())
}

/// Decode the variable-byte integer, returning (value, bytes used).
pub fn decode_remaining_length(frame: &[u8]) -> Result<(usize, usize)> {
    let mut multiplier = 1usize;
    let mut value = 0usize;
    for (index, byte) in frame.iter().take(4).enumerate() {
        value += ((byte & 0x7F) as usize) * multiplier;
        multiplier *= 128;
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
    }
    Err(ConnectorError::Connection(
        "mqtt malformed remaining length".to_string(),
    ))
}

/// Encode one PUBLISH frame. `packet_id` is used for QoS 1/2 (pass 0
/// for QoS 0). DUP is always clear on first transmission.
pub fn encode_publish(
    topic: &str,
    qos: u8,
    retain: bool,
    packet_id: u16,
    payload: &[u8],
    v50: bool,
) -> Result<Vec<u8>> {
    if qos > 2 {
        return Err(ConnectorError::Dispatch(format!("mqtt bad qos {qos}")));
    }
    if topic.is_empty() || topic.len() > u16::MAX as usize {
        return Err(ConnectorError::Dispatch(
            "mqtt topic must be 1..=65535 bytes".to_string(),
        ));
    }
    let mut body = Vec::new();
    body.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    body.extend_from_slice(topic.as_bytes());
    if qos > 0 {
        if packet_id == 0 {
            return Err(ConnectorError::Dispatch(
                "mqtt qos 1/2 requires a nonzero packet id".to_string(),
            ));
        }
        body.extend_from_slice(&packet_id.to_be_bytes());
    }
    if v50 {
        body.push(0x00); // property length: none
    }
    body.extend_from_slice(payload);
    let mut frame = vec![0x30 | (qos << 1) | (retain as u8)];
    encode_remaining_length(body.len(), &mut frame)?;
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Decoded PUBLISH frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedPublish {
    pub dup: bool,
    pub qos: u8,
    pub retain: bool,
    pub topic: String,
    pub packet_id: u16,
    pub payload: Vec<u8>,
}

/// Decode one PUBLISH frame (`v50` selects the properties field).
pub fn decode_publish(frame: &[u8], v50: bool) -> Result<DecodedPublish> {
    if frame.len() < 2 || frame[0] >> 4 != 0x03 {
        return Err(ConnectorError::Connection(
            "mqtt frame is not PUBLISH".to_string(),
        ));
    }
    let dup = frame[0] & 0x08 != 0;
    let qos = (frame[0] >> 1) & 0x03;
    let retain = frame[0] & 0x01 != 0;
    if qos == 3 {
        return Err(ConnectorError::Connection("mqtt bad qos 3".to_string()));
    }
    let (remaining, used) = decode_remaining_length(&frame[1..])?;
    let mut cursor = &frame[1 + used..];
    if cursor.len() < remaining {
        return Err(ConnectorError::Connection(
            "mqtt truncated publish frame".to_string(),
        ));
    }
    cursor = &cursor[..remaining];
    if cursor.len() < 2 {
        return Err(ConnectorError::Connection(
            "mqtt truncated topic length".to_string(),
        ));
    }
    let topic_len = u16::from_be_bytes([cursor[0], cursor[1]]) as usize;
    cursor = &cursor[2..];
    if cursor.len() < topic_len {
        return Err(ConnectorError::Connection(
            "mqtt truncated topic".to_string(),
        ));
    }
    let topic = std::str::from_utf8(&cursor[..topic_len])
        .map_err(|_| ConnectorError::Connection("mqtt topic not UTF-8".to_string()))?
        .to_string();
    cursor = &cursor[topic_len..];
    let packet_id = if qos > 0 {
        if cursor.len() < 2 {
            return Err(ConnectorError::Connection(
                "mqtt truncated packet id".to_string(),
            ));
        }
        let id = u16::from_be_bytes([cursor[0], cursor[1]]);
        cursor = &cursor[2..];
        if id == 0 {
            return Err(ConnectorError::Connection(
                "mqtt qos 1/2 with packet id 0".to_string(),
            ));
        }
        id
    } else {
        0
    };
    if v50 {
        let (properties_len, used) = decode_remaining_length(cursor)?;
        cursor = &cursor[used..];
        if cursor.len() < properties_len {
            return Err(ConnectorError::Connection(
                "mqtt truncated v5 properties".to_string(),
            ));
        }
        cursor = &cursor[properties_len..];
    }
    Ok(DecodedPublish {
        dup,
        qos,
        retain,
        topic,
        packet_id,
        payload: cursor.to_vec(),
    })
}

/// Build a CONNECT frame (3.1.1 `MQTT`/4; 5.0 `MQTT`/5 with zero properties).
fn encode_connect(
    client_id: &str,
    clean_start: bool,
    keep_alive_secs: u16,
    username: Option<&str>,
    password: Option<&str>,
    v50: bool,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x00, 0x04]);
    body.extend_from_slice(b"MQTT");
    body.push(if v50 { 5 } else { 4 });
    let mut flags = 0x02; // clean session/start
    if !clean_start {
        flags &= !0x02;
    }
    if username.is_some() {
        flags |= 0x80;
    }
    if password.is_some() {
        flags |= 0x40;
    }
    body.push(flags);
    body.extend_from_slice(&keep_alive_secs.to_be_bytes());
    if v50 {
        body.push(0x00); // connect properties: none
    }
    body.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
    body.extend_from_slice(client_id.as_bytes());
    if let Some(username) = username {
        body.extend_from_slice(&(username.len() as u16).to_be_bytes());
        body.extend_from_slice(username.as_bytes());
    }
    if let Some(password) = password {
        body.extend_from_slice(&(password.len() as u16).to_be_bytes());
        body.extend_from_slice(password.as_bytes());
    }
    let mut frame = vec![0x10];
    // CONNECT bodies are small; length always fits one byte here.
    frame.push(body.len() as u8);
    frame.extend_from_slice(&body);
    frame
}

// ---------------------------------------------------------------------------
// Transport.
// ---------------------------------------------------------------------------

/// One serialized outbound frame plus routing metadata. `bytes` is
/// the tree-framed PUBLISH (used by the offline `Tcp` transport and
/// the loopback tests); `payload` is the raw message body the
/// maintained driver transport publishes (it frames and assigns
/// packet ids itself).
#[derive(Debug, Clone)]
pub struct SerializedMqttPacket {
    pub bytes: Vec<u8>,
    pub topic: String,
    pub qos: u8,
    pub packet_id: u16,
    pub retain: bool,
    pub payload: Vec<u8>,
}

#[async_trait]
pub trait MqttBridgeTransport: Send + Sync {
    async fn connect(&self) -> Result<()>;
    async fn publish(&self, packet: &SerializedMqttPacket) -> Result<()>;
}

/// In-memory transport capturing every serialized frame (tests).
#[derive(Debug, Default)]
pub struct MemoryMqttBridgeTransport {
    packets: parking_lot::Mutex<Vec<SerializedMqttPacket>>,
    connected: AtomicBool,
    connect_calls: AtomicU64,
    publish_calls: AtomicU64,
}

impl MemoryMqttBridgeTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn packets(&self) -> Vec<SerializedMqttPacket> {
        self.packets.lock().clone()
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    pub fn connect_calls(&self) -> u64 {
        self.connect_calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl MqttBridgeTransport for MemoryMqttBridgeTransport {
    async fn connect(&self) -> Result<()> {
        self.connect_calls.fetch_add(1, Ordering::SeqCst);
        self.connected.store(true, Ordering::SeqCst);
        Ok(())
    }

    async fn publish(&self, packet: &SerializedMqttPacket) -> Result<()> {
        if !self.is_connected() {
            return Err(ConnectorError::Connection(
                "mqtt bridge not connected".to_string(),
            ));
        }
        self.publish_calls.fetch_add(1, Ordering::SeqCst);
        self.packets.lock().push(packet.clone());
        Ok(())
    }
}

/// TCP transport: dials, exchanges CONNECT/CONNACK, writes frames.
pub struct TcpMqttBridgeTransport {
    endpoint: BridgeEndpoint,
    client_id: String,
    clean_start: bool,
    username: Option<String>,
    password: Option<String>,
    keep_alive_secs: u16,
    v50: bool,
    stream: tokio::sync::Mutex<Option<tokio::net::TcpStream>>,
}

impl TcpMqttBridgeTransport {
    pub fn new(config: &MqttBridgeSinkConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            endpoint: config.endpoint()?,
            client_id: config.resolve_client_id(0, now_millis())?,
            clean_start: config.clean_start,
            username: config.username.clone(),
            password: config.password.clone(),
            keep_alive_secs: config.keep_alive_secs,
            v50: config.protocol == MqttBridgeProtocol::V50,
            stream: tokio::sync::Mutex::new(None),
        })
    }
}

#[async_trait]
impl MqttBridgeTransport for TcpMqttBridgeTransport {
    async fn connect(&self) -> Result<()> {
        if self.stream.lock().await.is_some() {
            return Ok(());
        }
        if self.endpoint.tls {
            return Err(ConnectorError::Dispatch(
                "mqtts TLS transport not enabled in this build; use mqtt:// \
                 or terminate TLS in a sidecar proxy"
                    .to_string(),
            ));
        }
        let addr = format!("{}:{}", self.endpoint.host, self.endpoint.port);
        let mut stream = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect(&addr),
        )
        .await
        .map_err(|_| ConnectorError::Connection(format!("mqtt bridge connect timeout: {addr}")))?
        .map_err(|e| ConnectorError::Connection(format!("mqtt bridge connect failed: {e}")))?;
        let connect = encode_connect(
            &self.client_id,
            self.clean_start,
            self.keep_alive_secs,
            self.username.as_deref(),
            self.password.as_deref(),
            self.v50,
        );
        stream.write_all(&connect).await.map_err(|e| {
            ConnectorError::Connection(format!("mqtt bridge connect write failed: {e}"))
        })?;
        let mut connack = [0u8; 4];
        stream.read_exact(&mut connack).await.map_err(|e| {
            ConnectorError::Connection(format!("mqtt bridge connack read failed: {e}"))
        })?;
        if connack[0] != 0x20 || connack[1] != 0x02 {
            return Err(ConnectorError::Connection(
                "mqtt bridge malformed CONNACK".to_string(),
            ));
        }
        if connack[3] != 0x00 {
            return Err(ConnectorError::Dispatch(format!(
                "mqtt bridge connection refused: 0x{:02x}",
                connack[3]
            )));
        }
        *self.stream.lock().await = Some(stream);
        Ok(())
    }

    async fn publish(&self, packet: &SerializedMqttPacket) -> Result<()> {
        let mut guard = self.stream.lock().await;
        let stream = guard
            .as_mut()
            .ok_or_else(|| ConnectorError::Connection("mqtt bridge not connected".to_string()))?;
        stream
            .write_all(&packet.bytes)
            .await
            .map_err(|e| ConnectorError::Connection(format!("mqtt bridge publish failed: {e}")))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Driver transport on the maintained `rumqttc` client.
// ---------------------------------------------------------------------------

/// rumqttc packet-id window for the CONNECT options: the protocol
/// packet id is a nonzero u16, so a larger sink-side cap cannot widen
/// the wire window; it only grows the local buffer.
fn driver_inflight_cap(config: &MqttBridgeSinkConfig) -> u16 {
    config.effective_inflight().clamp(1, u16::MAX as usize) as u16
}

/// rumqttc `AsyncClient::new` request-channel bound. The sink buffer
/// in front of it already bounds rows (`max_inflight`, default
/// 10,000); this second queue must also be finite when the sink is
/// configured unbounded, so it clamps to the same 10,000-row default
/// instead of growing without limit.
fn driver_channel_cap(config: &MqttBridgeSinkConfig) -> usize {
    config.effective_inflight().clamp(1, 10_000)
}

fn driver_qos_v311(qos: u8) -> Result<rumqttc::QoS> {
    match qos {
        0 => Ok(rumqttc::QoS::AtMostOnce),
        1 => Ok(rumqttc::QoS::AtLeastOnce),
        2 => Ok(rumqttc::QoS::ExactlyOnce),
        other => Err(ConnectorError::Dispatch(format!(
            "mqtt bridge bad qos {other}"
        ))),
    }
}

fn driver_qos_v50(qos: u8) -> Result<rumqttc::v5::mqttbytes::QoS> {
    match qos {
        0 => Ok(rumqttc::v5::mqttbytes::QoS::AtMostOnce),
        1 => Ok(rumqttc::v5::mqttbytes::QoS::AtLeastOnce),
        2 => Ok(rumqttc::v5::mqttbytes::QoS::ExactlyOnce),
        other => Err(ConnectorError::Dispatch(format!(
            "mqtt bridge bad qos {other}"
        ))),
    }
}

enum RumqttcInner {
    V311 {
        client: rumqttc::AsyncClient,
        _pump: tokio::task::JoinHandle<()>,
    },
    V50 {
        client: rumqttc::v5::AsyncClient,
        _pump: tokio::task::JoinHandle<()>,
    },
}

/// Production transport on the maintained `rumqttc` driver
/// (Apache-2.0): CONNECT auth, driver-owned packet-id tracking and
/// inflight cap, MQTT 3.1.1 or 5.0 framing by configuration. Plain
/// TCP only in this build (`rumqttc` without its TLS feature):
/// `mqtts://` endpoints fail closed with a clear error until a TLS
/// backend lands (terminate TLS in a sidecar proxy meanwhile).
/// The legacy [`TcpMqttBridgeTransport`] stays for offline unit
/// tests only; production wiring uses this transport.
///
/// Bound: one driver request channel of [`driver_channel_cap`]
/// entries plus the sink buffer in front of it; no background queue.
pub struct RumqttcMqttBridgeTransport {
    endpoint: BridgeEndpoint,
    client_id: String,
    clean_start: bool,
    username: Option<String>,
    password: Option<String>,
    keep_alive_secs: u16,
    v50: bool,
    inflight: u16,
    channel_cap: usize,
    state: tokio::sync::Mutex<Option<RumqttcInner>>,
}

impl RumqttcMqttBridgeTransport {
    pub fn new(config: &MqttBridgeSinkConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            endpoint: config.endpoint()?,
            client_id: config.resolve_client_id(0, now_millis())?,
            clean_start: config.clean_start,
            username: config.username.clone(),
            password: config.password.clone(),
            keep_alive_secs: config.keep_alive_secs,
            v50: config.protocol == MqttBridgeProtocol::V50,
            inflight: driver_inflight_cap(config),
            channel_cap: driver_channel_cap(config),
            state: tokio::sync::Mutex::new(None),
        })
    }
}

#[async_trait]
impl MqttBridgeTransport for RumqttcMqttBridgeTransport {
    async fn connect(&self) -> Result<()> {
        if self.state.lock().await.is_some() {
            return Ok(());
        }
        if self.endpoint.tls {
            return Err(ConnectorError::Dispatch(
                "mqtts TLS transport not enabled in this build; use mqtt:// \
                 or terminate TLS in a sidecar proxy"
                    .to_string(),
            ));
        }
        if self.v50 {
            let mut options = rumqttc::v5::MqttOptions::new(
                self.client_id.clone(),
                self.endpoint.host.clone(),
                self.endpoint.port,
            );
            options.set_keep_alive(Duration::from_secs(u64::from(self.keep_alive_secs)));
            options.set_clean_start(self.clean_start);
            if let Some(username) = &self.username {
                options
                    .set_credentials(username.clone(), self.password.clone().unwrap_or_default());
            }
            options.set_outgoing_inflight_upper_limit(self.inflight);
            let (client, mut eventloop) = rumqttc::v5::AsyncClient::new(options, self.channel_cap);
            // Drive CONNECT/CONNACK once inline so auth refusals and
            // unreachable brokers fail here instead of hiding behind
            // the background pump. 5s matches the legacy TCP dial
            // timeout: the protocol requirement is a bounded
            // handshake, not a specific value.
            tokio::time::timeout(Duration::from_secs(5), eventloop.poll())
                .await
                .map_err(|_| {
                    ConnectorError::Connection(format!(
                        "mqtt bridge connect timeout: {}:{}",
                        self.endpoint.host, self.endpoint.port
                    ))
                })?
                .map_err(|e| {
                    ConnectorError::Connection(format!("mqtt bridge connect failed: {e}"))
                })?;
            let pump = tokio::spawn(async move {
                loop {
                    if eventloop.poll().await.is_err() {
                        // 100ms reconnect pause: keeps a downed broker
                        // from hot-spinning the pump task at 100% CPU
                        // while staying well under any test timeout.
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            });
            *self.state.lock().await = Some(RumqttcInner::V50 {
                client,
                _pump: pump,
            });
        } else {
            let mut options = rumqttc::MqttOptions::new(
                self.client_id.clone(),
                self.endpoint.host.clone(),
                self.endpoint.port,
            );
            options.set_keep_alive(Duration::from_secs(u64::from(self.keep_alive_secs)));
            options.set_clean_session(self.clean_start);
            if let Some(username) = &self.username {
                options
                    .set_credentials(username.clone(), self.password.clone().unwrap_or_default());
            }
            options.set_inflight(self.inflight);
            let (client, mut eventloop) = rumqttc::AsyncClient::new(options, self.channel_cap);
            // Drive CONNECT/CONNACK once inline so auth refusals and
            // unreachable brokers fail here instead of hiding behind
            // the background pump. 5s matches the legacy TCP dial
            // timeout: the protocol requirement is a bounded
            // handshake, not a specific value.
            tokio::time::timeout(Duration::from_secs(5), eventloop.poll())
                .await
                .map_err(|_| {
                    ConnectorError::Connection(format!(
                        "mqtt bridge connect timeout: {}:{}",
                        self.endpoint.host, self.endpoint.port
                    ))
                })?
                .map_err(|e| {
                    ConnectorError::Connection(format!("mqtt bridge connect failed: {e}"))
                })?;
            let pump = tokio::spawn(async move {
                loop {
                    if eventloop.poll().await.is_err() {
                        // 100ms reconnect pause: keeps a downed broker
                        // from hot-spinning the pump task at 100% CPU
                        // while staying well under any test timeout.
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            });
            *self.state.lock().await = Some(RumqttcInner::V311 {
                client,
                _pump: pump,
            });
        }
        Ok(())
    }

    async fn publish(&self, packet: &SerializedMqttPacket) -> Result<()> {
        let guard = self.state.lock().await;
        let inner = guard
            .as_ref()
            .ok_or_else(|| ConnectorError::Connection("mqtt bridge not connected".to_string()))?;
        match inner {
            RumqttcInner::V311 { client, .. } => {
                let qos = driver_qos_v311(packet.qos)?;
                client
                    .publish(
                        packet.topic.clone(),
                        qos,
                        packet.retain,
                        packet.payload.clone(),
                    )
                    .await
                    .map_err(|e| {
                        ConnectorError::Connection(format!("mqtt bridge publish failed: {e}"))
                    })?;
                Ok(())
            }
            RumqttcInner::V50 { client, .. } => {
                let qos = driver_qos_v50(packet.qos)?;
                client
                    .publish(
                        packet.topic.clone(),
                        qos,
                        packet.retain,
                        packet.payload.clone(),
                    )
                    .await
                    .map_err(|e| {
                        ConnectorError::Connection(format!("mqtt bridge publish failed: {e}"))
                    })?;
                Ok(())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Sink.
// ---------------------------------------------------------------------------

/// One buffered row with its assigned packet id.
#[derive(Debug, Clone)]
struct BridgeRow {
    topic: String,
    payload: Vec<u8>,
    qos: u8,
    retain: bool,
    packet_id: u16,
}

/// MQTT bridge sink: buffers events, publishes encoded frames.
pub struct MqttBridgeSink {
    config: MqttBridgeSinkConfig,
    transport: Arc<dyn MqttBridgeTransport>,
    buffer: parking_lot::Mutex<BatchQueue<BridgeRow>>,
    backoff: parking_lot::Mutex<BackoffState>,
    packet_id: AtomicU32,
    sent_batches: AtomicU64,
    sent_records: AtomicU64,
}

impl MqttBridgeSink {
    pub fn new(
        config: MqttBridgeSinkConfig,
        transport: Arc<dyn MqttBridgeTransport>,
    ) -> Result<Self> {
        config.validate()?;
        let linger = config.effective_linger();
        Ok(Self {
            buffer: parking_lot::Mutex::new(BatchQueue::new(config.effective_batch_size(), linger)),
            config,
            transport,
            backoff: parking_lot::Mutex::new(BackoffState::default()),
            packet_id: AtomicU32::new(0),
            sent_batches: AtomicU64::new(0),
            sent_records: AtomicU64::new(0),
        })
    }

    pub fn config(&self) -> &MqttBridgeSinkConfig {
        &self.config
    }

    pub fn sent_batches(&self) -> u64 {
        self.sent_batches.load(Ordering::Relaxed)
    }

    pub fn sent_records(&self) -> u64 {
        self.sent_records.load(Ordering::Relaxed)
    }

    pub fn buffered_rows(&self) -> usize {
        self.buffer.lock().len()
    }

    /// Next packet id, cycling 1..=65535 and never yielding 0.
    pub fn next_packet_id(&self) -> u16 {
        (self.packet_id.fetch_add(1, Ordering::SeqCst) % 65_535 + 1) as u16
    }

    /// Flush buffered rows as encoded frames (no-op when empty).
    /// Connects lazily; any failure restores the buffer, engages
    /// backoff, and propagates.
    pub async fn flush(&self) -> Result<()> {
        self.backoff.lock().check()?;
        let (rows, oldest) = self.buffer.lock().take_batch();
        if rows.is_empty() {
            return Ok(());
        }
        let v50 = self.config.protocol == MqttBridgeProtocol::V50;
        let mut packets = Vec::with_capacity(rows.len());
        for row in &rows {
            let bytes = encode_publish(
                &row.topic,
                row.qos,
                row.retain,
                row.packet_id,
                &row.payload,
                v50,
            )?;
            packets.push(SerializedMqttPacket {
                bytes,
                topic: row.topic.clone(),
                qos: row.qos,
                packet_id: row.packet_id,
                retain: row.retain,
                payload: row.payload.clone(),
            });
        }
        let record_count = rows.len() as u64;
        let result = async {
            self.transport.connect().await?;
            for packet in &packets {
                self.transport.publish(packet).await?;
            }
            Ok::<(), ConnectorError>(())
        }
        .await;
        match result {
            Ok(()) => {
                self.backoff.lock().success();
                self.sent_batches.fetch_add(1, Ordering::Relaxed);
                self.sent_records.fetch_add(record_count, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                self.buffer.lock().restore(rows, oldest);
                self.backoff.lock().failure();
                Err(e)
            }
        }
    }

    /// Validate + buffer one event with remapping, overrides and a
    /// fresh packet id. Errors when the inflight cap is reached.
    fn buffer_row(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<bool> {
        if topic.as_str().is_empty() {
            return Err(ConnectorError::Dispatch(
                "mqtt bridge row requires a non-empty topic".to_string(),
            ));
        }
        if self.buffer.lock().len() >= self.config.effective_inflight() {
            return Err(ConnectorError::Connection(
                "mqtt bridge inflight limit reached".to_string(),
            ));
        }
        let millis = now_millis();
        let mapped = self.config.remap_topic(topic.as_str(), qos, millis)?;
        let out_qos = self.config.qos_override.unwrap_or_else(|| u8::from(qos));
        let retain = self.config.retain_override.unwrap_or(false);
        let packet_id = if out_qos > 0 {
            self.next_packet_id()
        } else {
            0
        };
        Ok(self.buffer.lock().push(BridgeRow {
            topic: mapped,
            payload: payload.to_vec(),
            qos: out_qos,
            retain,
            packet_id,
        }))
    }
}

#[async_trait]
impl Sink for MqttBridgeSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        if self.buffer_row(topic, payload, qos)? {
            self.flush().await?;
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "mqtt_bridge"
    }
}

/// Management connector handle pairing an id with a bridge sink.
pub struct MqttBridgeConnector {
    id: String,
    sink: Arc<MqttBridgeSink>,
}

impl MqttBridgeConnector {
    pub fn new(id: impl Into<String>, sink: Arc<MqttBridgeSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }
}

impl super::Connector for MqttBridgeConnector {
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

    fn test_config(address: &str) -> MqttBridgeSinkConfig {
        MqttBridgeSinkConfig {
            broker_address: address.to_string(),
            client_id: "indra-bridge-test".to_string(),
            clean_start: true,
            username: None,
            password: None,
            keep_alive_secs: 60,
            topic_prefix: None,
            topic_template: None,
            qos_override: None,
            retain_override: None,
            max_inflight: Some(10_000),
            max_batch_size: Some(100),
            linger_ms: Some(10),
            protocol: MqttBridgeProtocol::V311,
        }
    }

    fn test_sink(
        config: MqttBridgeSinkConfig,
    ) -> (Arc<MqttBridgeSink>, Arc<MemoryMqttBridgeTransport>) {
        let transport = Arc::new(MemoryMqttBridgeTransport::new());
        let sink = Arc::new(MqttBridgeSink::new(config, transport.clone()).unwrap());
        (sink, transport)
    }

    #[test]
    fn test_config_validation() {
        assert!(test_config("mqtt://127.0.0.1:1883").validate().is_ok());
        assert!(test_config("mqtts://iot.example.com:8883")
            .validate()
            .is_ok());
        assert!(test_config("127.0.0.1:1883").validate().is_ok());
        assert!(test_config("broker.local").validate().is_ok());

        assert!(test_config("").validate().is_err());
        assert!(test_config("http://127.0.0.1:1883").validate().is_err());
        assert!(test_config("mqtt://127.0.0.1:notaport").validate().is_err());
        assert!(test_config("mqtt://:1883").validate().is_err());

        let mut config = test_config("mqtt://127.0.0.1:1883");
        config.client_id = "  ".to_string();
        assert!(config.validate().is_err());
        config.client_id = "indra-bridge-test".to_string();

        config.qos_override = Some(3);
        assert!(config.validate().is_err());
        config.qos_override = Some(2);
        assert!(config.validate().is_ok());

        config.max_batch_size = Some(0);
        assert!(config.validate().is_err());
        // Unbounded + huge depths accepted: zero clamped ceilings.
        config.max_batch_size = None;
        config.max_inflight = Some(10_000_000);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_address_parsing() {
        assert_eq!(
            parse_bridge_address("mqtt://h:1883").unwrap(),
            BridgeEndpoint {
                host: "h".to_string(),
                port: 1883,
                tls: false
            }
        );
        assert_eq!(
            parse_bridge_address("mqtts://h").unwrap(),
            BridgeEndpoint {
                host: "h".to_string(),
                port: 8883,
                tls: true
            }
        );
        assert_eq!(parse_bridge_address("h:9999").unwrap().port, 9999);
        assert_eq!(
            parse_bridge_address("h").unwrap(),
            BridgeEndpoint {
                host: "h".to_string(),
                port: 1883,
                tls: false
            }
        );
    }

    #[test]
    fn test_topic_remapping() {
        let mut config = test_config("mqtt://h:1883");
        assert_eq!(
            config
                .remap_topic("sensors/t1", QoS::AtMostOnce, 0)
                .unwrap(),
            "sensors/t1"
        );

        config.topic_prefix = Some("edge/station1/".to_string());
        assert_eq!(
            config
                .remap_topic("sensors/t1", QoS::AtMostOnce, 0)
                .unwrap(),
            "edge/station1/sensors/t1"
        );

        config.topic_template = Some("upstream/${topic}".to_string());
        assert_eq!(
            config
                .remap_topic("sensors/t1", QoS::AtMostOnce, 0)
                .unwrap(),
            "edge/station1/upstream/sensors/t1"
        );

        // Wildcards in the mapped result are rejected.
        config.topic_template = Some("up/${topic}/#".to_string());
        assert!(config
            .remap_topic("sensors/t1", QoS::AtMostOnce, 0)
            .is_err());
    }

    #[test]
    fn test_publish_framing_shapes() {
        // QoS 0: 0x30, no packet id.
        let frame = encode_publish("a/b", 0, false, 0, b"hi", false).unwrap();
        assert_eq!(frame[0], 0x30);
        let decoded = decode_publish(&frame, false).unwrap();
        assert_eq!(decoded.topic, "a/b");
        assert_eq!(decoded.qos, 0);
        assert_eq!(decoded.packet_id, 0);
        assert!(!decoded.retain && !decoded.dup);
        assert_eq!(decoded.payload, b"hi");

        // QoS 1 + retain: 0x33, big-endian packet id.
        let frame = encode_publish("a/b", 1, true, 0x1234, b"hi", false).unwrap();
        assert_eq!(frame[0], 0x33);
        let decoded = decode_publish(&frame, false).unwrap();
        assert_eq!(decoded.packet_id, 0x1234);
        assert!(decoded.retain);

        // QoS 2: 0x34.
        let frame = encode_publish("a/b", 2, false, 7, b"", false).unwrap();
        assert_eq!(frame[0], 0x34);

        // v5.0 carries a zero property length after the packet id.
        let v311 = encode_publish("a/b", 1, false, 9, b"x", false).unwrap();
        let v50 = encode_publish("a/b", 1, false, 9, b"x", true).unwrap();
        assert_eq!(v50.len(), v311.len() + 1);
        let decoded = decode_publish(&v50, true).unwrap();
        assert_eq!(decoded.topic, "a/b");
        assert_eq!(decoded.packet_id, 9);
        assert_eq!(decoded.payload, b"x");

        assert!(encode_publish("a/b", 3, false, 1, b"", false).is_err());
        assert!(encode_publish("a/b", 1, false, 0, b"", false).is_err());
    }

    #[test]
    fn test_remaining_length_multibyte() {
        // 200-byte payload forces a 2-byte remaining length.
        let payload = vec![0xABu8; 200];
        let frame = encode_publish("t", 0, false, 0, &payload, false).unwrap();
        let (remaining, used) = decode_remaining_length(&frame[1..]).unwrap();
        assert_eq!(used, 2);
        assert_eq!(remaining, 2 + 1 + 200);
        assert_eq!(decode_publish(&frame, false).unwrap().payload, payload);

        // 20,000 bytes force a 3-byte remaining length.
        let payload = vec![0u8; 20_000];
        let frame = encode_publish("t", 0, false, 0, &payload, false).unwrap();
        let (_, used) = decode_remaining_length(&frame[1..]).unwrap();
        assert_eq!(used, 3);

        assert!(encode_remaining_length(268_435_456, &mut Vec::new()).is_err());
        assert!(decode_remaining_length(&[0xFF, 0xFF, 0xFF, 0xFF]).is_err());
    }

    #[test]
    fn test_packet_id_cycles_without_zero() {
        let (sink, _) = test_sink(test_config("mqtt://h:1883"));
        // Drive the counter to the wrap boundary deterministically.
        sink.packet_id.store(65_533, Ordering::SeqCst);
        assert_eq!(sink.next_packet_id(), 65_534);
        assert_eq!(sink.next_packet_id(), 65_535);
        assert_eq!(sink.next_packet_id(), 1);
        assert_eq!(sink.next_packet_id(), 2);
    }

    #[tokio::test]
    async fn test_memory_roundtrip_with_overrides() {
        let mut config = test_config("mqtt://h:1883");
        config.topic_prefix = Some("edge/".to_string());
        config.qos_override = Some(1);
        config.retain_override = Some(true);
        config.max_batch_size = Some(10);
        let (sink, transport) = test_sink(config);

        sink.send(
            &Topic::new("sensors/t1").unwrap(),
            &Bytes::from("on"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        sink.send(
            &Topic::new("sensors/t2").unwrap(),
            &Bytes::from("off"),
            QoS::AtLeastOnce,
        )
        .await
        .unwrap();
        sink.flush().await.unwrap();

        assert_eq!(transport.connect_calls(), 1);
        let packets = transport.packets();
        assert_eq!(packets.len(), 2);
        // Sequencing is per-sink and gapless from 1.
        assert_eq!(packets[0].packet_id, 1);
        assert_eq!(packets[1].packet_id, 2);
        for (packet, expected_topic, expected_payload) in [
            (&packets[0], "edge/sensors/t1", b"on".as_slice()),
            (&packets[1], "edge/sensors/t2", b"off".as_slice()),
        ] {
            assert_eq!(packet.topic, expected_topic);
            assert_eq!(packet.qos, 1);
            assert!(packet.retain);
            let decoded = decode_publish(&packet.bytes, false).unwrap();
            assert_eq!(decoded.topic, expected_topic);
            assert_eq!(decoded.qos, 1);
            assert!(decoded.retain);
            assert_eq!(decoded.payload, expected_payload);
        }
        assert_eq!(sink.sent_records(), 2);
    }

    #[tokio::test]
    async fn test_inflight_cap_backpressures() {
        let mut config = test_config("mqtt://h:1883");
        config.max_inflight = Some(1);
        config.max_batch_size = Some(100);
        let (sink, _) = test_sink(config);
        let topic = Topic::new("t").unwrap();
        sink.send(&topic, &Bytes::from("a"), QoS::AtMostOnce)
            .await
            .unwrap();
        let err = sink
            .send(&topic, &Bytes::from("b"), QoS::AtMostOnce)
            .await
            .expect_err("inflight cap must backpressure");
        assert!(matches!(err, ConnectorError::Connection(_)));
    }

    #[tokio::test]
    async fn test_tcp_loopback_connect_and_publish() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            // CONNECT: fixed header 0x10, single-byte length.
            let mut head = [0u8; 2];
            stream.read_exact(&mut head).await.expect("connect head");
            assert_eq!(head[0], 0x10);
            let mut body = vec![0u8; head[1] as usize];
            stream.read_exact(&mut body).await.expect("connect body");
            let needle = b"indra-bridge-loop";
            assert!(body.windows(needle.len()).any(|w| w == needle));
            // CONNACK accepted.
            stream
                .write_all(&[0x20, 0x02, 0x00, 0x00])
                .await
                .expect("connack");
            // One PUBLISH frame follows.
            let mut fixed = [0u8; 1];
            stream.read_exact(&mut fixed).await.expect("pub head");
            assert_eq!(fixed[0], 0x30);
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await.expect("pub len");
            let mut rest = vec![0u8; len_buf[0] as usize];
            stream.read_exact(&mut rest).await.expect("pub body");
            assert!(rest.windows(9).any(|w| w == b"loopback/"));
        });

        let mut config = test_config(&format!("mqtt://127.0.0.1:{port}"));
        config.client_id = "indra-bridge-loop".to_string();
        config.max_batch_size = Some(1);
        let transport = Arc::new(TcpMqttBridgeTransport::new(&config).unwrap());
        let sink = MqttBridgeSink::new(config, transport).unwrap();
        sink.send(
            &Topic::new("loopback/t").unwrap(),
            &Bytes::from("ping"),
            QoS::AtMostOnce,
        )
        .await
        .unwrap();
        assert_eq!(sink.sent_records(), 1);
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("server done")
            .expect("server task");
    }

    fn qual_env(name: &str) -> Option<String> {
        std::env::var(name).ok().filter(|v| !v.trim().is_empty())
    }

    /// Qualification against a real remote MQTT broker through the
    /// maintained `rumqttc` driver write path.
    ///
    /// Run with e.g.:
    /// `MQTT_BRIDGE_URL=mqtt://127.0.0.1:1883 MQTT_BRIDGE_TOPIC=qual/b327 \
    ///  MQTT_BRIDGE_CLIENT_ID=qual-bridge \
    ///  cargo test -p broker-connectors --lib mqtt_bridge::tests::test_qualify_bridge_write_path -- --ignored --nocapture --test-threads=1`
    ///
    /// Subscribes to a unique run topic first, then bridges 1000
    /// publishes through [`MqttBridgeSink`] on
    /// [`RumqttcMqttBridgeTransport`] via the shared
    /// [`crate::ConnectorManager`] path the broker uses (never
    /// `sink.send` directly), and asserts the subscriber receives
    /// every payload exactly (duplicates tolerated, loss is not)
    /// with QoS 1 preserved. A second bounded sink proves the
    /// inflight cap backpressures. Panics when its environment is
    /// missing (fail closed, never skips).
    #[tokio::test]
    #[ignore = "needs a real Remote MQTT bridge server (see MQTT_BRIDGE_* env)"]
    async fn test_qualify_bridge_write_path() {
        use crate::ConnectorManager;
        use std::collections::HashSet;
        use std::time::{SystemTime, UNIX_EPOCH};

        const PUBLISHES: usize = 1000;

        let url = qual_env("MQTT_BRIDGE_URL").unwrap_or_else(|| {
            panic!(
                "MQTT_BRIDGE_URL must point at a real Remote MQTT bridge server for qualification; \
                 failing closed instead of passing vacuously \
                 (e.g. MQTT_BRIDGE_URL=mqtt://127.0.0.1:1883)"
            )
        });
        let base_topic = qual_env("MQTT_BRIDGE_TOPIC").unwrap_or_else(|| {
            panic!("MQTT_BRIDGE_TOPIC must be set for qualification; failing closed")
        });
        let base_client = qual_env("MQTT_BRIDGE_CLIENT_ID").unwrap_or_else(|| {
            panic!("MQTT_BRIDGE_CLIENT_ID must be set for qualification; failing closed")
        });
        // Server version for the report comes from the qualification
        // image the gates start (eclipse-mosquitto:2.0.18); the driver
        // exposes no broker-version RPC here, so the endpoint line
        // below is the measured endpoint, never a substitute version
        // string.
        eprintln!(
            "qual server: image eclipse-mosquitto:2.0.18 url={url} topic={base_topic} client={base_client}"
        );
        let endpoint = parse_bridge_address(&url).expect("qual url parses");
        assert!(
            !endpoint.tls,
            "qual uses plaintext mqtt:// (mqtts fails closed in this build)"
        );

        let run_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let run_topic = format!("{base_topic}/run-{run_nanos}");
        let bridge_id = format!("{base_client}-{run_nanos}");
        let sub_id = format!("{base_client}-sub-{run_nanos}");

        // Subscriber first: with clean sessions a publish before the
        // SUBACK is lost, so the subscription must be active before
        // the bridge sends anything.
        let mut sub_options =
            rumqttc::MqttOptions::new(sub_id.clone(), endpoint.host.clone(), endpoint.port);
        sub_options.set_keep_alive(Duration::from_secs(10));
        sub_options.set_clean_session(true);
        let (sub_client, mut sub_eventloop) =
            rumqttc::AsyncClient::new(sub_options, PUBLISHES.clamp(10, 10_000));
        sub_client
            .subscribe(run_topic.clone(), rumqttc::QoS::AtLeastOnce)
            .await
            .expect("qual subscribe request");
        // 30s SUBACK wait: the protocol requirement is a bounded
        // handshake, not a specific value; 30s tolerates a slow
        // container start while failing fast on a dead broker.
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                match sub_eventloop.poll().await {
                    Ok(rumqttc::Event::Incoming(rumqttc::Packet::SubAck(_))) => break,
                    Ok(_) => continue,
                    Err(e) => panic!("qual subscribe failed: {e:?}"),
                }
            }
        })
        .await
        .expect("qual suback timeout");
        eprintln!("qual subscribed: topic={run_topic}");

        let seen: Arc<parking_lot::Mutex<HashSet<String>>> =
            Arc::new(parking_lot::Mutex::new(HashSet::new()));
        let qos_ok: Arc<std::sync::atomic::AtomicBool> =
            Arc::new(std::sync::atomic::AtomicBool::new(true));
        let collector_seen = seen.clone();
        let collector_qos = qos_ok.clone();
        let collector_topic = run_topic.clone();
        let collector = tokio::spawn(async move {
            loop {
                match sub_eventloop.poll().await {
                    Ok(rumqttc::Event::Incoming(rumqttc::Packet::Publish(publish))) => {
                        if publish.topic != collector_topic {
                            continue;
                        }
                        if publish.qos != rumqttc::QoS::AtLeastOnce {
                            collector_qos.store(false, std::sync::atomic::Ordering::SeqCst);
                        }
                        let payload = String::from_utf8_lossy(&publish.payload).into_owned();
                        collector_seen.lock().insert(payload);
                        if collector_seen.lock().len() >= PUBLISHES {
                            break;
                        }
                    }
                    Ok(_) => continue,
                    Err(e) => {
                        eprintln!("qual subscriber eventloop note: {e:?}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });

        let config = MqttBridgeSinkConfig {
            broker_address: url.clone(),
            client_id: bridge_id.clone(),
            clean_start: true,
            username: None,
            password: None,
            // 30s keep-alive: the protocol requirement is a bounded
            // liveness probe, not a specific value; 30s keeps the
            // 1000-publish run well inside one interval.
            keep_alive_secs: 30,
            topic_prefix: None,
            topic_template: Some(run_topic.clone()),
            qos_override: Some(1),
            retain_override: Some(false),
            max_inflight: Some(10_000),
            max_batch_size: Some(100),
            linger_ms: Some(10),
            protocol: MqttBridgeProtocol::V311,
        };
        config.validate().expect("qual config validates");
        let transport = Arc::new(RumqttcMqttBridgeTransport::new(&config).expect("qual transport"));
        let sink = Arc::new(MqttBridgeSink::new(config, transport).expect("qual sink"));
        assert_eq!(sink.kind(), "mqtt_bridge");
        // The broker's path: rule actions deliver through the shared
        // connector manager, so the qualification sends through it
        // and never `sink.send` directly.
        let manager = ConnectorManager::new();
        manager.register("qual-bridge", sink.clone());
        manager.register("mqtt_bridge:qual-bridge", sink.clone());

        let ingress = Topic::new("sensors/qual").expect("qual topic");
        for seq in 0..PUBLISHES {
            let payload = Bytes::from(format!("qual-{seq:04}"));
            manager
                .send("qual-bridge", &ingress, &payload, QoS::AtLeastOnce)
                .await
                .unwrap_or_else(|e| panic!("qual send seq={seq} failed: {e:?}"));
        }
        sink.flush().await.expect("qual flush");
        assert_eq!(sink.sent_records(), PUBLISHES as u64);
        eprintln!(
            "qual rows sent: records={} batches={}",
            sink.sent_records(),
            sink.sent_batches()
        );

        // 180s receive window for 1000 QoS 1 publishes: generous
        // against the 1800s gate timeout so a slow broker still
        // converges, while a stuck bridge fails instead of hanging
        // the gate.
        tokio::time::timeout(Duration::from_secs(180), collector)
            .await
            .expect("qual receive timeout")
            .expect("qual collector task");
        assert!(
            qos_ok.load(std::sync::atomic::Ordering::SeqCst),
            "qual QoS must be preserved as AtLeastOnce"
        );
        {
            let seen = seen.lock();
            assert_eq!(seen.len(), PUBLISHES, "qual must receive all publishes");
            for seq in 0..PUBLISHES {
                let key = format!("qual-{seq:04}");
                assert!(seen.contains(&key), "qual missing payload {key}");
            }
            eprintln!("qual rows asserted: distinct={} qos=1", seen.len());
        }
        let _ = sub_client.disconnect().await;

        // Inflight cap backpressures through the same sink code path.
        let mut cap_config = test_config(&url);
        cap_config.max_inflight = Some(1);
        cap_config.max_batch_size = Some(100);
        let (cap_sink, _) = test_sink(cap_config);
        let cap_topic = Topic::new("t").expect("qual cap topic");
        cap_sink
            .send(&cap_topic, &Bytes::from("a"), QoS::AtMostOnce)
            .await
            .expect("qual cap first send buffers");
        let err = cap_sink
            .send(&cap_topic, &Bytes::from("b"), QoS::AtMostOnce)
            .await
            .expect_err("inflight cap must backpressure");
        assert!(matches!(err, ConnectorError::Connection(_)));
        eprintln!("qual backpressure: inflight cap refused second row");

        eprintln!("qual cleanup: disconnected subscriber {sub_id}, bridge {bridge_id}; no retained state (retain=false)");
    }
}
