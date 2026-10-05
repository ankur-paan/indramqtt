//! MQTT connections that the kernel owns.
//!
//! One task for each client socket. The task decodes MQTT packets, makes
//! the same link frames that the edge makes, and gives them to
//! [`handle_inbound_frame_with`]. Frames that the kernel routes to the
//! connection are encoded as MQTT packets and written to the socket.
//! There is no second process and no link socket between the client and
//! the kernel logic.
//!
//! The connection uses the same session, routing and delivery code as a
//! connection of the edge. Only the transport is different.

use super::{
    decode_session_binding_full, detach, handle_inbound_frame_with, merge_egress_batch,
    BindRequest, BindWill, Shared, SERVER_V5_MAX_PACKET_SIZE,
};
use async_trait::async_trait;
use broker_protocol::wire::{self, kind, ConnackProperties, PublishOut, WireError};
use broker_session::SessionKey;
use brokerlink::{BrokerFrame, BrokerLinkError, BrokerLinkTransport, OpCode};
use bytes::{Bytes, BytesMut};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::unbounded_channel;
use tracing::{debug, info, warn};

/// Connection identifiers of kernel-owned connections start here. The
/// edge counts from 1, and the API WebSocket connections start at
/// `1 << 62`, thus the three ranges do not overlap.
const NATIVE_CONN_ID_BASE: u64 = 1 << 61;
static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(NATIVE_CONN_ID_BASE);

/// A client must send CONNECT in this time (the same value as the edge).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest number of frames in one write to the socket.
const EGRESS_BATCH_FRAMES: usize = 64;
/// Largest number of frame bytes in one write to the socket.
const EGRESS_BATCH_BYTES: usize = 64 * 1024;
/// Initial size of the read buffer of one connection. An idle
/// connection keeps only this much. The buffer grows for a larger packet.
const READ_BUFFER_BYTES: usize = 256;

/// Accepts MQTT clients on `bind` and runs one task for each of them.
pub(super) async fn serve_native_mqtt(
    bind: String,
    shared: Shared,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(&bind).await?;
    info!("Kernel MQTT listener on {}", bind);
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                warn!("Kernel MQTT accept error: {}", e);
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let _ = stream.set_nodelay(true);
        let shared = shared.clone();
        let conn_id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
        let task = run_connection(stream, peer.ip().to_string(), conn_id, shared);
        if conn_id == NATIVE_CONN_ID_BASE {
            info!(
                "Kernel MQTT connection task state: {} bytes",
                std::mem::size_of_val(&task)
            );
        }
        tokio::spawn(async move {
            if let Err(e) = task.await {
                debug!("Kernel MQTT connection {} ended: {}", conn_id, e);
            }
        });
    }
}

/// Collects the MQTT bytes for frames that the kernel sends to this
/// connection. [`handle_inbound_frame_with`] sends its replies through
/// the transport trait. This type encodes each reply at once and keeps
/// the bytes until the connection task writes them.
struct NativeSink {
    out: parking_lot::Mutex<Vec<u8>>,
    /// Negotiated protocol level (4 until CONNECT is decoded).
    level: AtomicU8,
    /// Set when a frame told the connection to close after the write.
    close: AtomicBool,
    /// Set when the kernel accepted the bind.
    accepted: AtomicBool,
}

impl NativeSink {
    fn new() -> Self {
        Self {
            out: parking_lot::Mutex::new(Vec::new()),
            level: AtomicU8::new(4),
            close: AtomicBool::new(false),
            accepted: AtomicBool::new(false),
        }
    }

    fn level(&self) -> u8 {
        self.level.load(Ordering::Relaxed)
    }

    fn encode(&self, frame: &BrokerFrame) {
        let level = self.level();
        let mut out = self.out.lock();
        match encode_frame(frame, level, &mut out) {
            FrameEffect::None => {}
            FrameEffect::Accepted => self.accepted.store(true, Ordering::Relaxed),
            FrameEffect::Close => self.close.store(true, Ordering::Relaxed),
        }
    }

    fn take(&self) -> Vec<u8> {
        std::mem::take(&mut *self.out.lock())
    }
}

#[async_trait]
impl BrokerLinkTransport for NativeSink {
    async fn send(&self, frame: BrokerFrame) -> brokerlink::Result<()> {
        self.encode(&frame);
        Ok(())
    }

    async fn recv(&self) -> brokerlink::Result<BrokerFrame> {
        // The connection task reads the socket. No caller uses this.
        Err(BrokerLinkError::ConnectionClosed)
    }
}

/// What one encoded frame means for the connection.
enum FrameEffect {
    None,
    /// The kernel accepted the bind.
    Accepted,
    /// Close the socket after the bytes are written.
    Close,
}

/// The return code of a CONNACK for protocol level 3 or 4.
fn connack_return_code(reason: u8) -> u8 {
    match reason {
        0..=5 => reason,
        0x84 => 1,
        0x85 => 2,
        0x86 => 4,
        0x87 | 0x8A => 5,
        _ => 3,
    }
}

/// The parts of a `PublishOut` frame metadata. The topic and the user
/// properties borrow from the frame.
struct PublishOutMeta<'a> {
    topic: &'a str,
    packet_id: u16,
    qos: u8,
    retain: bool,
    dup: bool,
    alias: u16,
    subscription_id: u32,
    payload_format: u8,
    message_expiry: u32,
    users: Vec<(Vec<u8>, Vec<u8>)>,
}

/// Decodes `TopicLen:16 | Topic | PacketId:16 | QoS | Retain | Dup`,
/// then optionally `Alias:16`, then optionally `SubId:32`, then
/// optionally `Format | Expiry:32 | UserCount:16 | pairs`.
fn decode_publish_out(meta: &[u8]) -> Option<PublishOutMeta<'_>> {
    if meta.len() < 7 {
        return None;
    }
    let topic_len = usize::from(u16::from_be_bytes([meta[0], meta[1]]));
    let head = 2 + topic_len + 5;
    if meta.len() < head {
        return None;
    }
    let topic = std::str::from_utf8(&meta[2..2 + topic_len]).ok()?;
    let base = 2 + topic_len;
    let mut parsed = PublishOutMeta {
        topic,
        packet_id: u16::from_be_bytes([meta[base], meta[base + 1]]),
        qos: meta[base + 2],
        retain: meta[base + 3] != 0,
        dup: meta[base + 4] != 0,
        alias: 0,
        subscription_id: 0,
        payload_format: 0,
        message_expiry: 0,
        users: Vec::new(),
    };
    let mut rest = &meta[head..];
    if rest.is_empty() {
        return Some(parsed);
    }
    if rest.len() < 2 {
        return None;
    }
    parsed.alias = u16::from_be_bytes([rest[0], rest[1]]);
    rest = &rest[2..];
    if rest.is_empty() {
        return Some(parsed);
    }
    if rest.len() < 4 {
        return None;
    }
    parsed.subscription_id = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
    rest = &rest[4..];
    if rest.is_empty() {
        return Some(parsed);
    }
    if rest.len() < 7 {
        return None;
    }
    parsed.payload_format = rest[0];
    parsed.message_expiry = u32::from_be_bytes([rest[1], rest[2], rest[3], rest[4]]);
    let count = usize::from(u16::from_be_bytes([rest[5], rest[6]]));
    rest = &rest[7..];
    for _ in 0..count {
        if rest.len() < 2 {
            return None;
        }
        let key_len = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
        if rest.len() < 2 + key_len + 2 {
            return None;
        }
        let key = rest[2..2 + key_len].to_vec();
        rest = &rest[2 + key_len..];
        let value_len = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
        if rest.len() < 2 + value_len {
            return None;
        }
        let value = rest[2..2 + value_len].to_vec();
        rest = &rest[2 + value_len..];
        parsed.users.push((key, value));
    }
    if !rest.is_empty() {
        return None;
    }
    Some(parsed)
}

/// Encodes one kernel frame as MQTT bytes for the client.
fn encode_frame(frame: &BrokerFrame, level: u8, out: &mut Vec<u8>) -> FrameEffect {
    let meta = &frame.metadata[..];
    match frame.header.opcode {
        OpCode::PublishOut => {
            let Some(publish) = decode_publish_out(meta) else {
                return FrameEffect::Close;
            };
            wire::encode_publish(
                &PublishOut {
                    dup: publish.dup,
                    qos: publish.qos,
                    retain: publish.retain,
                    topic: publish.topic,
                    packet_id: publish.packet_id,
                    alias: publish.alias,
                    subscription_id: publish.subscription_id,
                    payload_format: publish.payload_format,
                    message_expiry: publish.message_expiry,
                    user_properties: &publish.users,
                    payload: &frame.payload,
                },
                level,
                out,
            );
            FrameEffect::None
        }
        OpCode::SessionBinding => {
            let Some((_session_id, present, reason, alias_max, v5)) =
                decode_session_binding_full(meta)
            else {
                return FrameEffect::Close;
            };
            if level == 5 {
                let empty: Vec<(String, String)> = Vec::new();
                let mut props = ConnackProperties {
                    topic_alias_maximum: (alias_max >= 1).then_some(alias_max),
                    user_properties: &empty,
                    ..ConnackProperties::default()
                };
                if let Some(v5) = v5.as_ref() {
                    props.session_expiry = (v5.granted_expiry >= 1).then_some(v5.granted_expiry);
                    props.receive_maximum = (v5.server_recv_max >= 1).then_some(v5.server_recv_max);
                    props.maximum_packet_size =
                        (v5.server_max_pkt >= 1).then_some(v5.server_max_pkt);
                    props.reason_string = (!v5.reason.is_empty()).then_some(v5.reason.as_str());
                    props.user_properties = &v5.user_properties;
                }
                wire::encode_connack_v5(present, reason, &props, out);
            } else {
                wire::encode_connack(present, connack_return_code(reason), out);
            }
            if reason == 0 {
                FrameEffect::Accepted
            } else {
                FrameEffect::Close
            }
        }
        OpCode::SubAckOut => {
            if meta.len() < 2 {
                return FrameEffect::Close;
            }
            let packet_id = u16::from_be_bytes([meta[0], meta[1]]);
            wire::encode_suback(packet_id, &meta[2..], level, out);
            FrameEffect::None
        }
        OpCode::PubAckOut | OpCode::PubRecOut | OpCode::PubRelOut | OpCode::PubCompOut => {
            if meta.len() < 2 {
                return FrameEffect::Close;
            }
            let packet_id = u16::from_be_bytes([meta[0], meta[1]]);
            let reason = meta.get(2).copied().unwrap_or(0);
            let packet_kind = match frame.header.opcode {
                OpCode::PubAckOut => kind::PUBACK,
                OpCode::PubRecOut => kind::PUBREC,
                OpCode::PubRelOut => kind::PUBREL,
                _ => kind::PUBCOMP,
            };
            wire::encode_ack(packet_kind, packet_id, reason, level, out);
            FrameEffect::None
        }
        OpCode::ConnClose => {
            // An MQTT 5 client gets a DISCONNECT with the reason code
            // before the socket closes. A 3.1.1 client gets no packet.
            if level == 5 {
                if let Some(reason) = meta.first() {
                    wire::encode_disconnect_v5(*reason, out);
                }
            }
            FrameEffect::Close
        }
        _ => FrameEffect::None,
    }
}

/// Why the connection task stops.
enum Stop {
    /// The client sent DISCONNECT, or the kernel closed the connection.
    Clean,
    /// The socket closed, a timer ended or a packet was incorrect.
    Abnormal,
}

/// The state of one connection that is not in the kernel tables.
struct Conn {
    conn_id: u64,
    seq: u64,
    level: u8,
    client_id: String,
    connected: bool,
    keepalive: Option<Duration>,
    peer: String,
}

impl Conn {
    fn frame(&mut self, opcode: OpCode, meta: Vec<u8>, payload: Bytes) -> Option<BrokerFrame> {
        self.seq += 1;
        BrokerFrame::new(opcode, self.conn_id, self.seq, Bytes::from(meta), payload).ok()
    }

    fn id_meta(&self) -> Vec<u8> {
        let id = self.client_id.as_bytes();
        let mut meta = Vec::with_capacity(2 + id.len() + 1);
        meta.extend_from_slice(&(id.len() as u16).to_be_bytes());
        meta.extend_from_slice(id);
        meta
    }
}

fn bind_request(connect: wire::Connect, peer: &str) -> BindRequest {
    let props = connect.properties;
    BindRequest {
        client_id: connect.client_id,
        clean_start: connect.clean_start,
        keepalive_secs: connect.keepalive,
        username: connect.username,
        password: connect.password,
        peerhost: Some(peer.to_string()),
        client_alias_max: props
            .as_ref()
            .and_then(|p| p.topic_alias_maximum)
            .unwrap_or(0),
        will: connect.will.map(|will| BindWill {
            topic: will.topic,
            payload: Bytes::from(will.payload),
            qos: will.qos,
            retain: will.retain,
        }),
        cert_cn: None,
        cert_subject: None,
        cert_sans: Vec::new(),
        protocol_version: if connect.level == 5 { 5 } else { 4 },
        session_expiry: props.as_ref().and_then(|p| p.session_expiry).unwrap_or(0),
        receive_maximum: props
            .as_ref()
            .and_then(|p| p.receive_maximum)
            .unwrap_or(u16::MAX),
        max_packet_size: props
            .as_ref()
            .and_then(|p| p.maximum_packet_size)
            .unwrap_or(0),
        user_properties: props.map(|p| p.user_properties.into_iter().collect()),
    }
}

/// The metadata of a `PublishIn` frame for one decoded PUBLISH.
fn publish_in_meta(publish: &wire::Publish<'_>, level: u8) -> Vec<u8> {
    let topic = publish.topic.as_bytes();
    let has_props = publish.payload_format != 0
        || publish.message_expiry != 0
        || !publish.user_properties.is_empty();
    let mut meta = Vec::with_capacity(2 + topic.len() + 5 + 2 + 7);
    meta.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    meta.extend_from_slice(topic);
    meta.extend_from_slice(&publish.packet_id.to_be_bytes());
    meta.push(publish.qos);
    meta.push(u8::from(publish.retain));
    meta.push(u8::from(publish.dup));
    if level == 5 && has_props {
        meta.extend_from_slice(&publish.alias.unwrap_or(0).to_be_bytes());
        meta.push(publish.payload_format);
        meta.extend_from_slice(&publish.message_expiry.to_be_bytes());
        meta.extend_from_slice(&(publish.user_properties.len() as u16).to_be_bytes());
        for (key, value) in &publish.user_properties {
            meta.extend_from_slice(&(key.len() as u16).to_be_bytes());
            meta.extend_from_slice(key.as_bytes());
            meta.extend_from_slice(&(value.len() as u16).to_be_bytes());
            meta.extend_from_slice(value.as_bytes());
        }
    } else if let Some(alias) = publish.alias {
        // The alias section alone. An alias of 0 stays in the frame,
        // thus the kernel refuses it with reason code 0x94.
        meta.extend_from_slice(&alias.to_be_bytes());
    }
    meta
}

/// The metadata of a `SubscribeIn` frame.
fn subscribe_in_meta(client_id: &str, subscribe: &wire::Subscribe<'_>, level: u8) -> Vec<u8> {
    let id = client_id.as_bytes();
    let mut meta = Vec::with_capacity(6 + id.len() + subscribe.filters.len() * 16);
    meta.extend_from_slice(&subscribe.packet_id.to_be_bytes());
    meta.extend_from_slice(&(id.len() as u16).to_be_bytes());
    meta.extend_from_slice(id);
    meta.extend_from_slice(&(subscribe.filters.len() as u16).to_be_bytes());
    for (filter, options) in &subscribe.filters {
        meta.extend_from_slice(&(filter.len() as u16).to_be_bytes());
        meta.extend_from_slice(filter.as_bytes());
        meta.push(*options);
        if level == 5 {
            meta.extend_from_slice(&subscribe.subscription_id.to_be_bytes());
        }
    }
    meta
}

async fn run_connection(
    stream: TcpStream,
    peer: String,
    conn_id: u64,
    shared: Shared,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (mut reader, mut writer) = stream.into_split();
    let (tx, mut rx) = unbounded_channel::<BrokerFrame>();
    let waker = Arc::new(tokio::sync::Notify::new());
    let mut bound: Vec<(SessionKey, u64)> = Vec::new();
    let sink = NativeSink::new();
    let mut inbuf = BytesMut::with_capacity(READ_BUFFER_BYTES);
    let mut conn = Conn {
        conn_id,
        seq: 0,
        level: 4,
        client_id: String::new(),
        connected: false,
        keepalive: None,
        peer,
    };
    let started = Instant::now();
    let mut last_packet = Instant::now();

    let stop = loop {
        // One deadline: CONNECT in time, then the keepalive of the client.
        let deadline = if conn.connected {
            conn.keepalive.map(|keepalive| last_packet + keepalive)
        } else {
            Some(started + CONNECT_TIMEOUT)
        };
        let timer = async {
            match deadline {
                Some(at) => tokio::time::sleep_until(at.into()).await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            read = reader.read_buf(&mut inbuf) => {
                match read {
                    Ok(0) | Err(_) => break Stop::Abnormal,
                    Ok(_) => {}
                }
                last_packet = Instant::now();
                match drain_inbound(&mut inbuf, &mut conn, &shared, &tx, &sink, &mut bound, &waker).await {
                    Ok(None) => {}
                    Ok(Some(stop)) => {
                        let _ = flush(&sink, &mut writer).await;
                        break stop;
                    }
                    Err(_) => break Stop::Abnormal,
                }
                // Frames for this connection that the packets above
                // made (a client that subscribes to its own topic).
                collect_egress(&mut rx, &shared, conn.conn_id, &sink, &waker);
            }
            routed = rx.recv() => {
                let Some(frame) = routed else { break Stop::Abnormal };
                sink.encode(&frame);
                shared.metrics.inc_transport_sent_by(1);
                collect_egress(&mut rx, &shared, conn.conn_id, &sink, &waker);
            }
            () = waker.notified() => {
                collect_egress(&mut rx, &shared, conn.conn_id, &sink, &waker);
            }
            () = timer => break Stop::Abnormal,
        }
        if flush(&sink, &mut writer).await.is_err() {
            break Stop::Abnormal;
        }
        if sink.close.load(Ordering::Relaxed) {
            break Stop::Clean;
        }
    };

    // An abnormal end of an accepted connection is a disconnect without
    // DISCONNECT: the kernel publishes the will.
    if matches!(stop, Stop::Abnormal) && conn.connected {
        let meta = conn.id_meta();
        if let Some(frame) = conn.frame(OpCode::DisconnectIn, meta, Bytes::new()) {
            let _ =
                handle_inbound_frame_with(frame, &shared, &tx, &sink, &mut bound, &waker, None)
                    .await;
        }
    }
    detach(&bound, &shared, &tx);
    shared.conns.unregister(conn.conn_id);
    let _ = writer.shutdown().await;
    Ok(())
}

/// Writes the collected bytes to the socket in one write.
async fn flush(
    sink: &NativeSink,
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
) -> std::io::Result<()> {
    let bytes = sink.take();
    if bytes.is_empty() {
        return Ok(());
    }
    writer.write_all(&bytes).await
}

/// Encodes the frames that wait for this connection: the guaranteed
/// frames of the mailbox and the QoS 0 frames of the bounded queue, in
/// their order. When one pass uses its full budget, the task wakes
/// itself again, thus the remaining frames do not wait for a new event.
fn collect_egress(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<BrokerFrame>,
    shared: &Shared,
    conn_id: u64,
    sink: &NativeSink,
    waker: &tokio::sync::Notify,
) {
    let mut guaranteed = Vec::new();
    let mut bytes = 0usize;
    while guaranteed.len() < EGRESS_BATCH_FRAMES && bytes < EGRESS_BATCH_BYTES {
        match rx.try_recv() {
            Ok(frame) => {
                bytes += frame.total_frame_len();
                guaranteed.push(frame);
            }
            Err(_) => break,
        }
    }
    let qos0 = shared.conns.drain_qos0_with_budget(
        conn_id,
        EGRESS_BATCH_FRAMES.saturating_sub(guaranteed.len()),
        EGRESS_BATCH_BYTES.saturating_sub(bytes),
    );
    if guaranteed.is_empty() && qos0.is_empty() {
        return;
    }
    let batch = merge_egress_batch(guaranteed, qos0);
    let batch_bytes: usize = batch.iter().map(BrokerFrame::total_frame_len).sum();
    for frame in &batch {
        sink.encode(frame);
    }
    shared.metrics.inc_transport_sent_by(batch.len() as u64);
    if batch.len() >= EGRESS_BATCH_FRAMES || batch_bytes >= EGRESS_BATCH_BYTES {
        waker.notify_one();
    }
}

/// Handles each complete packet in the read buffer.
#[allow(clippy::too_many_arguments)]
async fn drain_inbound(
    inbuf: &mut BytesMut,
    conn: &mut Conn,
    shared: &Shared,
    tx: &tokio::sync::mpsc::UnboundedSender<BrokerFrame>,
    sink: &NativeSink,
    bound: &mut Vec<(SessionKey, u64)>,
    waker: &Arc<tokio::sync::Notify>,
) -> Result<Option<Stop>, WireError> {
    loop {
        let Some(header) = wire::fixed_header(inbuf)? else {
            return Ok(None);
        };
        if header.remaining > SERVER_V5_MAX_PACKET_SIZE as usize {
            return Err(WireError::Unsupported("packet is too large"));
        }
        if inbuf.len() < header.packet_len() {
            inbuf.reserve(header.packet_len() - inbuf.len());
            return Ok(None);
        }
        let packet = inbuf.split_to(header.packet_len()).freeze();
        let body = packet.slice(header.header_len..);
        if !conn.connected && header.kind != kind::CONNECT {
            return Err(WireError::Malformed("first packet is not CONNECT"));
        }
        let frame = match header.kind {
            kind::CONNECT => {
                if conn.connected || !conn.client_id.is_empty() {
                    return Err(WireError::Malformed("second CONNECT"));
                }
                let connect = wire::decode_connect(&body)?;
                conn.level = if connect.level == 5 { 5 } else { 4 };
                sink.level.store(conn.level, Ordering::Relaxed);
                conn.keepalive = (connect.keepalive > 0)
                    .then(|| Duration::from_millis(u64::from(connect.keepalive) * 1500));
                let request = bind_request(connect, &conn.peer);
                conn.client_id = request.client_id.clone();
                let Some(frame) = conn.frame(OpCode::BindConnection, Vec::new(), Bytes::new())
                else {
                    return Err(WireError::Malformed("frame"));
                };
                let handled = handle_inbound_frame_with(
                    frame,
                    shared,
                    tx,
                    sink,
                    bound,
                    waker,
                    Some(&request),
                )
                .await;
                if handled.is_err() {
                    return Ok(Some(Stop::Abnormal));
                }
                if sink.accepted.load(Ordering::Relaxed) {
                    conn.connected = true;
                } else {
                    // Refused: the CONNACK with the reason is in the sink.
                    return Ok(Some(Stop::Clean));
                }
                continue;
            }
            kind::PUBLISH => {
                let publish = wire::decode_publish(header.flags, &body, conn.level)?;
                let meta = publish_in_meta(&publish, conn.level);
                let payload = body.slice_ref(publish.payload);
                conn.frame(OpCode::PublishIn, meta, payload)
            }
            kind::SUBSCRIBE => {
                let subscribe = wire::decode_subscribe(&body, conn.level)?;
                let meta = subscribe_in_meta(&conn.client_id, &subscribe, conn.level);
                conn.frame(OpCode::SubscribeIn, meta, Bytes::new())
            }
            kind::PUBACK | kind::PUBREC | kind::PUBREL | kind::PUBCOMP => {
                let (packet_id, reason) = wire::decode_ack(&body, conn.level)?;
                let mut meta = packet_id.to_be_bytes().to_vec();
                if reason != 0 {
                    meta.push(reason);
                }
                let opcode = match header.kind {
                    kind::PUBACK => OpCode::PubAckIn,
                    kind::PUBREC => OpCode::PubRecIn,
                    kind::PUBREL => OpCode::PubRelIn,
                    _ => OpCode::PubCompIn,
                };
                conn.frame(opcode, meta, Bytes::new())
            }
            kind::PINGREQ => {
                shared.metrics.inc_pingreq_received();
                wire::encode_pingresp(&mut sink.out.lock());
                shared.metrics.inc_pingresp_sent();
                continue;
            }
            kind::DISCONNECT => {
                let reason = wire::decode_disconnect(&body, conn.level)?;
                let mut meta = conn.id_meta();
                if conn.level == 5 {
                    meta.push(reason);
                }
                if let Some(frame) = conn.frame(OpCode::UnbindConnection, meta, Bytes::new()) {
                    let _ =
                        handle_inbound_frame_with(frame, shared, tx, sink, bound, waker, None)
                            .await;
                }
                // The kernel handled the disconnect. The task must not
                // send a second one.
                conn.connected = false;
                return Ok(Some(Stop::Clean));
            }
            // UNSUBSCRIBE is not available in the kernel yet. The edge
            // closes the connection for it also.
            _ => return Err(WireError::Unsupported("packet type")),
        };
        let Some(frame) = frame else {
            return Err(WireError::Malformed("frame"));
        };
        if handle_inbound_frame_with(frame, shared, tx, sink, bound, waker, None)
            .await
            .is_err()
        {
            return Ok(Some(Stop::Abnormal));
        }
    }
}
