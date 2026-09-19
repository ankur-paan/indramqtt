//! MQTT-over-WebSocket bridge for the dashboard test console.
//!
//! A minimal MQTT 3.1.1 packet engine over WebSocket binary frames: the
//! browser console can CONNECT (with optional credentials), SUBSCRIBE,
//! PUBLISH (QoS 0/1), PINGREQ and DISCONNECT. Anonymous CONNECT is
//! rejected once MQTT users exist (same rule as the BrokerLink bind
//! path). Subscriptions register in
//! the shared router and mailboxes in the shared [`ConnTable`], so edge
//! publishes fan out to console clients and console publishes fan out to
//! edge clients through the same directory.
//!
//! Deliberate test-console boundaries (documented, not bugs): no
//! retained fetch/store, no rule execution, no cluster forwarding, no
//! offline queue (online-only delivery), no `$delayed` publishes, no
//! `$share` subscribes, no will execution. Production MQTT stays on the
//! BEAM edge + BrokerLink path.

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::Response,
};
use broker_auth::{Authenticator, Authorizer};
use broker_protocol::{QoS, Topic, TopicFilter};
use broker_router::Subscription;
use brokerlink::{BrokerFrame, OpCode};
use bytes::Bytes;
use tokio::sync::mpsc;

use super::ApiState;

// ---------------------------------------------------------------------------
// Minimal MQTT 3.1.1 codec (fixed header + the five console packets).
// ---------------------------------------------------------------------------

const MAX_PACKET_BYTES: usize = 268_435_460;

fn encode_remaining_length(mut n: usize, out: &mut Vec<u8>) {
    loop {
        let mut byte = (n % 128) as u8;
        n /= 128;
        if n > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if n == 0 {
            break;
        }
    }
}

fn decode_remaining_length(buf: &[u8]) -> Option<(usize, usize)> {
    let mut multiplier = 1usize;
    let mut length = 0usize;
    for (i, &byte) in buf.iter().enumerate().take(4) {
        length += ((byte & 0x7F) as usize) * multiplier;
        if byte & 0x80 == 0 {
            return Some((length, i + 1));
        }
        multiplier *= 128;
    }
    None
}

fn read_u16(buf: &[u8]) -> Option<(u16, &[u8])> {
    if buf.len() < 2 {
        return None;
    }
    Some((u16::from_be_bytes([buf[0], buf[1]]), &buf[2..]))
}

fn read_str(buf: &[u8]) -> Option<(&str, &[u8])> {
    let (len, rest) = read_u16(buf)?;
    if rest.len() < len as usize {
        return None;
    }
    let (raw, tail) = rest.split_at(len as usize);
    Some((std::str::from_utf8(raw).ok()?, tail))
}

fn encode_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u16).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn encode_connack(session_present: bool, return_code: u8) -> Vec<u8> {
    vec![0x20, 0x02, u8::from(session_present), return_code]
}

fn encode_suback(packet_id: u16, codes: &[u8]) -> Vec<u8> {
    let mut out = vec![0x90];
    encode_remaining_length(2 + codes.len(), &mut out);
    out.extend_from_slice(&packet_id.to_be_bytes());
    out.extend_from_slice(codes);
    out
}

fn encode_publish(topic: &str, packet_id: u16, qos: QoS, payload: &[u8]) -> Vec<u8> {
    let flags = (u8::from(qos) << 1) & 0x06;
    let mut body = Vec::new();
    encode_str(&mut body, topic);
    if qos != QoS::AtMostOnce {
        body.extend_from_slice(&packet_id.to_be_bytes());
    }
    body.extend_from_slice(payload);
    let mut out = vec![0x30 | flags];
    encode_remaining_length(body.len(), &mut out);
    out.extend_from_slice(&body);
    out
}

fn encode_puback(packet_id: u16) -> Vec<u8> {
    vec![0x40, 0x02, (packet_id >> 8) as u8, (packet_id & 0xFF) as u8]
}

fn encode_pingresp() -> Vec<u8> {
    vec![0xD0, 0x00]
}

#[derive(Debug)]
struct Connect {
    client_id: String,
    clean_start: bool,
    keepalive_secs: u16,
    username: Option<String>,
    password: Option<Vec<u8>>,
}

fn decode_connect(payload: &[u8], flags: u8) -> Option<Connect> {
    if flags & 0x01 != 0 {
        return None;
    }
    let (proto_name, rest) = read_str(payload)?;
    if proto_name != "MQTT" {
        return None;
    }
    let (&level, rest) = rest.split_first()?;
    if level != 4 {
        return None;
    }
    let (&conn_flags, rest) = rest.split_first()?;
    if conn_flags & 0x01 != 0 {
        return None;
    }
    if rest.len() < 2 {
        return None;
    }
    let keepalive_secs = u16::from_be_bytes([rest[0], rest[1]]);
    let mut rest = &rest[2..];
    let username_flag = conn_flags & 0x80 != 0;
    let password_flag = conn_flags & 0x40 != 0;
    let will_flag = conn_flags & 0x04 != 0;
    if password_flag && !username_flag {
        return None;
    }
    let (client_id, tail) = read_str(rest)?;
    if client_id.is_empty() {
        return None;
    }
    rest = tail;
    // Will topic + message are parsed past but never executed.
    for _ in 0..(if will_flag { 2 } else { 0 }) {
        let (_, tail) = read_str(rest)?;
        rest = tail;
    }
    let username = if username_flag {
        let (user, tail) = read_str(rest)?;
        rest = tail;
        Some(user.to_string())
    } else {
        None
    };
    let password = if password_flag {
        let (len, tail) = read_u16(rest)?;
        if tail.len() < len as usize {
            return None;
        }
        let (pass, _) = tail.split_at(len as usize);
        Some(pass.to_vec())
    } else {
        None
    };
    Some(Connect {
        client_id: client_id.to_string(),
        clean_start: conn_flags & 0x02 != 0,
        keepalive_secs,
        username,
        password,
    })
}

#[derive(Debug)]
struct SubscribeFilter {
    filter: String,
    qos: u8,
}

fn decode_subscribe(payload: &[u8]) -> Option<(u16, Vec<SubscribeFilter>)> {
    let (packet_id, mut rest) = read_u16(payload)?;
    if packet_id == 0 {
        return None;
    }
    let mut subs = Vec::new();
    while !rest.is_empty() {
        let (filter, tail) = read_str(rest)?;
        let (&qos, tail) = tail.split_first()?;
        subs.push(SubscribeFilter {
            filter: filter.to_string(),
            qos,
        });
        rest = tail;
    }
    if subs.is_empty() {
        return None;
    }
    Some((packet_id, subs))
}

#[derive(Debug)]
struct Publish {
    topic: String,
    packet_id: u16,
    qos: QoS,
    payload: Bytes,
}

fn decode_publish(payload: &[u8], flags: u8) -> Option<Publish> {
    let qos = QoS::try_from((flags & 0x06) >> 1).ok()?;
    let (topic, rest) = read_str(payload)?;
    if topic.is_empty() {
        return None;
    }
    let (packet_id, rest) = if qos == QoS::AtMostOnce {
        (0u16, rest)
    } else {
        let (pid, rest) = read_u16(rest)?;
        if pid == 0 {
            return None;
        }
        (pid, rest)
    };
    Topic::new(topic).ok()?;
    Some(Publish {
        topic: topic.to_string(),
        packet_id,
        qos,
        payload: Bytes::copy_from_slice(rest),
    })
}

/// Decode the BrokerLink PublishMeta layout (mirrors the BEAM contract)
/// to re-encode edge deliveries as MQTT for the browser.
fn decode_publish_meta(meta: &[u8]) -> Option<(String, u16, QoS, bool)> {
    if meta.len() < 7 {
        return None;
    }
    let topic_len = u16::from_be_bytes([meta[0], meta[1]]) as usize;
    if topic_len == 0 || meta.len() != 2 + topic_len + 5 {
        return None;
    }
    let topic = std::str::from_utf8(&meta[2..2 + topic_len]).ok()?;
    let base = 2 + topic_len;
    let packet_id = u16::from_be_bytes([meta[base], meta[base + 1]]);
    let qos = QoS::try_from(meta[base + 2]).ok()?;
    let retain = meta[base + 3] != 0;
    Some((topic.to_string(), packet_id, qos, retain))
}

// ---------------------------------------------------------------------------
// WebSocket handler.
// ---------------------------------------------------------------------------

/// Upgrade `GET /ws/mqtt` to an MQTT-over-WebSocket session.
pub async fn ws_mqtt_handler(ws: WebSocketUpgrade, State(state): State<ApiState>) -> Response {
    ws.on_upgrade(|socket| handle_socket(state, socket))
}

struct WsSession {
    client_id: String,
    subscriptions: Vec<TopicFilter>,
}

async fn handle_socket(state: ApiState, mut socket: WebSocket) {
    let conn_id = state.next_ws_conn_id();
    let (tx, mut rx) = mpsc::unbounded_channel::<BrokerFrame>();
    let mut session: Option<WsSession> = None;
    let mut carry: Vec<u8> = Vec::new();

    loop {
        tokio::select! {
            incoming = socket.recv() => {
                let msg = match incoming {
                    Some(Ok(msg)) => msg,
                    // Closed or transport error: unwind the session.
                    _ => break,
                };
                let Message::Binary(bytes) = msg else {
                    // Text frames are not MQTT: ignore, stay connected.
                    continue;
                };
                carry.extend_from_slice(&bytes);
                match drive_packets(&state, &mut socket, &mut session, conn_id, &tx, &mut carry).await {
                    Ok(()) => {}
                    Err(()) => break,
                }
                if session.is_none() && carry.is_empty() {
                    // CONNECT rejected and answered: fall through to close.
                    break;
                }
            }
            outbound = rx.recv() => {
                let Some(frame) = outbound else { break };
                if !forward_to_browser(&mut socket, &frame).await {
                    break;
                }
            }
        }
    }

    teardown_ws_session(&state, &session, conn_id, &tx).await;
}

/// Drain complete MQTT packets from the carry buffer. `Err(())` means a
/// protocol violation: the caller closes the socket.
async fn drive_packets(
    state: &ApiState,
    socket: &mut WebSocket,
    session: &mut Option<WsSession>,
    conn_id: u64,
    tx: &mpsc::UnboundedSender<BrokerFrame>,
    carry: &mut Vec<u8>,
) -> Result<(), ()> {
    loop {
        if carry.is_empty() {
            return Ok(());
        }
        if carry.len() > MAX_PACKET_BYTES {
            return Err(());
        }
        let flags = carry[0] & 0x0F;
        let packet_type = carry[0] >> 4;
        let (remaining, header_len) = decode_remaining_length(&carry[1..]).ok_or(())?;
        let total = 1 + header_len + remaining;
        if total > MAX_PACKET_BYTES || carry.len() < total {
            if carry.len() >= total {
                return Err(());
            }
            return Ok(());
        }
        let packet: Vec<u8> = carry.drain(..total).collect();
        let payload = &packet[1 + header_len..];
        handle_packet(
            state,
            socket,
            session,
            conn_id,
            tx,
            WsPacket {
                packet_type,
                flags,
                payload,
            },
        )
        .await?;
    }
}

async fn send_bin(socket: &mut WebSocket, bytes: Vec<u8>) -> bool {
    socket.send(Message::Binary(bytes)).await.is_ok()
}

/// One decoded dashboard-console frame for [`handle_packet`].
struct WsPacket<'a> {
    packet_type: u8,
    flags: u8,
    payload: &'a [u8],
}

async fn handle_packet(
    state: &ApiState,
    socket: &mut WebSocket,
    session: &mut Option<WsSession>,
    conn_id: u64,
    tx: &mpsc::UnboundedSender<BrokerFrame>,
    packet: WsPacket<'_>,
) -> Result<(), ()> {
    let WsPacket {
        packet_type,
        flags,
        payload,
    } = packet;
    match (session.is_none(), packet_type) {
        // First packet must be CONNECT.
        (true, 1) => {
            let conn = decode_connect(payload, flags).ok_or(())?;
            // A non-empty user store always wins: unauthenticated console
            // clients are rejected whenever users exist, exactly like the
            // BrokerLink bind path (0x87, not authorized).
            if conn.username.is_none() && state.auth.user_count() > 0 {
                send_bin(socket, encode_connack(false, 0x87)).await;
                return Err(());
            }
            if let Some(username) = conn.username.as_deref() {
                let password = conn.password.as_deref();
                if state
                    .auth
                    .authenticate(&conn.client_id, Some(username), password)
                    .await
                    .is_err()
                {
                    send_bin(socket, encode_connack(false, 0x86)).await;
                    return Err(());
                }
            }
            // Connection quotas apply to console clients exactly like
            // edge binds (release happens in teardown via unbind). The
            // liveness probe must precede get_or_create, which itself
            // marks resumed sessions connected.
            if let Some(username) = conn.username.as_deref() {
                let already_live = state
                    .sessions
                    .get(&conn.client_id)
                    .map(|stored| *stored.connected.read())
                    .unwrap_or(false);
                if already_live {
                    state.sessions.release_connection_slot(username);
                }
                let max = state
                    .auth
                    .get_quotas(username)
                    .and_then(|quotas| quotas.max_connections);
                if !state.sessions.acquire_connection_slot(username, max) {
                    send_bin(socket, encode_connack(false, 0x8B)).await;
                    return Err(());
                }
            }
            let (stored, present) = state
                .sessions
                .get_or_create(&conn.client_id, conn.clean_start);
            *stored.conn_id.write() = Some(conn_id);
            *stored.keepalive_secs.write() = conn.keepalive_secs;
            *stored.username.write() = conn.username.clone();
            state.metrics.inc_connections();
            state.conns.register(conn_id, tx.clone());
            *session = Some(WsSession {
                client_id: conn.client_id,
                subscriptions: Vec::new(),
            });
            if !send_bin(socket, encode_connack(present, 0)).await {
                return Err(());
            }
            Ok(())
        }
        (true, _) => Err(()),
        (false, 8) => handle_subscribe(state, socket, session, conn_id, flags, payload).await,
        (false, 3) => handle_publish(state, socket, session, flags, payload).await,
        (false, 12) => {
            if flags != 0 || !payload.is_empty() {
                return Err(());
            }
            if !send_bin(socket, encode_pingresp()).await {
                return Err(());
            }
            Ok(())
        }
        (false, 14) => {
            if flags != 0 || !payload.is_empty() {
                return Err(());
            }
            Err(())
        }
        (false, 4) => Ok(()),
        _ => Err(()),
    }
}

async fn handle_subscribe(
    state: &ApiState,
    socket: &mut WebSocket,
    session: &mut Option<WsSession>,
    conn_id: u64,
    flags: u8,
    payload: &[u8],
) -> Result<(), ()> {
    if flags != 0x02 {
        return Err(());
    }
    let (packet_id, subs) = decode_subscribe(payload).ok_or(())?;
    let sess = session.as_mut().ok_or(())?;
    let mut codes = Vec::with_capacity(subs.len());
    for sub in subs {
        let code = match TopicFilter::new(sub.filter.clone()) {
            Ok(filter) if sub.qos <= 2 => {
                if filter.as_str().starts_with("$delayed/") {
                    0x80
                } else if state
                    .auth
                    .authorize_subscribe(&sess.client_id, &filter)
                    .await
                    .is_err()
                {
                    0x87
                } else {
                    let qos = QoS::try_from(sub.qos).expect("validated above");
                    state.router.subscribe(
                        &filter,
                        Subscription {
                            client_id: sess.client_id.clone().into(),
                            conn_id,
                            qos,
                            group: None,
                        },
                    );
                    state
                        .sessions
                        .add_subscription(&sess.client_id, filter.clone(), qos);
                    sess.subscriptions.push(filter);
                    sub.qos
                }
            }
            _ => 0x80,
        };
        codes.push(code);
    }
    if !send_bin(socket, encode_suback(packet_id, &codes)).await {
        return Err(());
    }
    Ok(())
}

async fn handle_publish(
    state: &ApiState,
    socket: &mut WebSocket,
    session: &Option<WsSession>,
    flags: u8,
    payload: &[u8],
) -> Result<(), ()> {
    let publish = decode_publish(payload, flags).ok_or(())?;
    let sess = session.as_ref().ok_or(())?;
    if publish.topic.starts_with("$delayed/") {
        // Console boundary: delayed markers are dropped, never stored.
        tracing::warn!("WS console dropped $delayed publish (unsupported here)");
        if publish.qos == QoS::AtLeastOnce {
            send_bin(
                socket,
                vec![
                    0x40,
                    0x02,
                    (publish.packet_id >> 8) as u8,
                    (publish.packet_id & 0xFF) as u8,
                ],
            )
            .await;
        }
        return Ok(());
    }
    let topic = Topic::new(publish.topic.clone()).map_err(|_| ())?;
    if state
        .auth
        .authorize_publish(&sess.client_id, &topic)
        .await
        .is_err()
    {
        if publish.qos == QoS::AtLeastOnce {
            send_bin(socket, encode_puback(publish.packet_id)).await;
        }
        return Ok(());
    }
    state.metrics.inc_messages_received();
    let mut delivered = 0u64;
    for sub in state.router.matches(&topic) {
        let Some(target) = state.sessions.get(sub.client_id.as_ref()) else {
            continue;
        };
        if !*target.connected.read() {
            continue;
        }
        let Some(dest) = *target.conn_id.read() else {
            continue;
        };
        let effective = std::cmp::min(u8::from(publish.qos), u8::from(sub.qos));
        let downlink_id = if effective == 0 {
            0u16
        } else {
            target.next_packet_id()
        };
        let meta = publish_meta_bytes(&publish.topic, downlink_id, effective);
        if let Ok(frame) = BrokerFrame::new(
            OpCode::PublishOut,
            dest,
            0,
            Bytes::from(meta),
            publish.payload.clone(),
        ) {
            state.conns.route(dest, frame);
            delivered += 1;
        }
    }
    state.metrics.inc_messages_forwarded_by(delivered);
    if publish.qos == QoS::AtLeastOnce {
        send_bin(socket, encode_puback(publish.packet_id)).await;
    }
    Ok(())
}

/// Encode the BrokerLink PublishMeta layout (mirrors the BEAM contract):
/// `TopicLen:16be | Topic | PacketId:16be | QoS:8 | Retain:8 | Dup:8`.
fn publish_meta_bytes(topic: &str, packet_id: u16, qos: u8) -> Vec<u8> {
    let mut meta = Vec::with_capacity(2 + topic.len() + 5);
    meta.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    meta.extend_from_slice(topic.as_bytes());
    meta.extend_from_slice(&packet_id.to_be_bytes());
    meta.push(qos);
    meta.push(0u8);
    meta.push(0u8);
    meta
}

/// Re-encode an edge `PublishOut` frame as MQTT for the browser.
async fn forward_to_browser(socket: &mut WebSocket, frame: &BrokerFrame) -> bool {
    if frame.header.opcode != OpCode::PublishOut {
        return true;
    }
    let Some((topic, packet_id, qos, _retain)) = decode_publish_meta(&frame.metadata) else {
        return true;
    };
    send_bin(
        socket,
        encode_publish(&topic, packet_id, qos, &frame.payload),
    )
    .await
}

/// Unwind one WS session: detach, forget the mailbox, drop metrics and
/// tracked subscriptions.
async fn teardown_ws_session(
    state: &ApiState,
    session: &Option<WsSession>,
    conn_id: u64,
    tx: &mpsc::UnboundedSender<BrokerFrame>,
) {
    state.conns.prune_sender(tx);
    state.conns.unregister(conn_id);
    if let Some(sess) = session {
        state.sessions.unbind_connection(&sess.client_id, conn_id);
        state.metrics.dec_connections();
        for filter in &sess.subscriptions {
            state.router.unsubscribe(filter, &sess.client_id);
            state.sessions.remove_subscription(&sess.client_id, filter);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remaining_length_roundtrip() {
        for n in [
            0usize, 1, 127, 128, 321, 16383, 16384, 2097151, 2097152, 268435455,
        ] {
            let mut out = Vec::new();
            encode_remaining_length(n, &mut out);
            assert_eq!(decode_remaining_length(&out), Some((n, out.len())));
        }
        assert_eq!(decode_remaining_length(&[]), None);
        assert_eq!(decode_remaining_length(&[0xFF, 0xFF, 0xFF, 0x80]), None);
    }

    fn connect_bytes(client_id: &str, username: Option<&str>, password: Option<&[u8]>) -> Vec<u8> {
        let mut body = vec![0, 4, b'M', b'Q', b'T', b'T', 4];
        let mut flags = 0x02u8;
        if username.is_some() {
            flags |= 0x80;
        }
        if password.is_some() {
            flags |= 0x40;
        }
        body.push(flags);
        body.extend_from_slice(&60u16.to_be_bytes());
        encode_str(&mut body, client_id);
        if let Some(user) = username {
            encode_str(&mut body, user);
        }
        if let Some(pass) = password {
            body.extend_from_slice(&(pass.len() as u16).to_be_bytes());
            body.extend_from_slice(pass);
        }
        let mut packet = vec![0x10];
        encode_remaining_length(body.len(), &mut packet);
        packet.extend_from_slice(&body);
        packet
    }

    fn connect_payload(packet: &[u8]) -> (&[u8], u8) {
        let flags = packet[0] & 0x0F;
        let (len, header) = decode_remaining_length(&packet[1..]).unwrap();
        (&packet[1 + header..1 + header + len], flags)
    }

    #[test]
    fn test_decode_connect_vectors() {
        let packet = connect_bytes("ws-1", Some("alice"), Some(b"s3cret"));
        let (payload, flags) = connect_payload(&packet);
        let conn = decode_connect(payload, flags).expect("decodes");
        assert_eq!(conn.client_id, "ws-1");
        assert!(conn.clean_start);
        assert_eq!(conn.keepalive_secs, 60);
        assert_eq!(conn.username.as_deref(), Some("alice"));
        assert_eq!(conn.password, Some(b"s3cret".to_vec()));

        let packet = connect_bytes("anon", None, None);
        let (payload, flags) = connect_payload(&packet);
        let conn = decode_connect(payload, flags).expect("decodes");
        assert!(conn.username.is_none());
        assert!(conn.password.is_none());

        // Reserved flag set: rejected.
        let mut bad = connect_bytes("x", None, None);
        bad[0] |= 0x01;
        let (payload, flags) = connect_payload(&bad);
        assert!(decode_connect(payload, flags).is_none());

        // Empty client id: rejected.
        let packet = connect_bytes("", None, None);
        let (payload, flags) = connect_payload(&packet);
        assert!(decode_connect(payload, flags).is_none());
    }

    #[test]
    fn test_decode_subscribe_vectors() {
        let mut body = vec![0x00, 0x07, 0x00, 0x05];
        body.extend_from_slice(b"sport");
        body.push(0x01);
        let (pid, subs) = decode_subscribe(&body).expect("decodes");
        assert_eq!(pid, 7);
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].filter, "sport");
        assert_eq!(subs[0].qos, 1);

        assert!(decode_subscribe(&[0x00, 0x00]).is_none());
        assert!(decode_subscribe(&[0x00, 0x07]).is_none());
    }

    #[test]
    fn test_decode_publish_vectors() {
        // QoS 0: topic "t", payload "hi".
        let body = b"\x00\x01thi";
        let publish = decode_publish(body, 0x00).expect("decodes");
        assert_eq!(publish.topic, "t");
        assert_eq!(publish.packet_id, 0);
        assert_eq!(publish.qos, QoS::AtMostOnce);
        assert_eq!(publish.payload, Bytes::from_static(b"hi"));

        // QoS 1 with packet id.
        let body = b"\x00\x02ab\x00\x10Z";
        let publish = decode_publish(body, 0x02).expect("decodes");
        assert_eq!(publish.packet_id, 16);
        assert_eq!(publish.qos, QoS::AtLeastOnce);

        // Wildcard and empty topics rejected.
        assert!(decode_publish(b"\x00\x03a/#x", 0x00).is_none());
        assert!(decode_publish(b"\x00\x00", 0x00).is_none());
        // QoS 3 rejected.
        assert!(decode_publish(b"\x00\x01t", 0x06).is_none());
    }

    #[test]
    fn test_encode_vectors() {
        assert_eq!(encode_connack(false, 0), vec![0x20, 0x02, 0x00, 0x00]);
        assert_eq!(encode_connack(true, 0), vec![0x20, 0x02, 0x01, 0x00]);
        assert_eq!(
            encode_suback(9, &[0, 1]),
            vec![0x90, 0x04, 0x00, 0x09, 0x00, 0x01]
        );
        assert_eq!(
            encode_publish("t", 0, QoS::AtMostOnce, b"hi"),
            vec![0x30, 0x05, 0x00, 0x01, b't', b'h', b'i']
        );
    }
}
