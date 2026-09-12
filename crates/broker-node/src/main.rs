use async_trait::async_trait;
use broker_auth::{Authenticator, Authorizer, MemoryAuth};
use broker_cluster::{ClusterLicense, ClusterMessage, RoutingPlane};
use broker_observability::Metrics;
use broker_protocol::{QoS, Topic, TopicFilter};
use broker_router::{split_shared_filter, strip_delayed_prefix, ConnTable, Router, Subscription};
use broker_rules::{BackpressurePolicy, BrokerSink, RuleEngine};
use broker_session::{QueuedMessage, SessionManager};
use broker_storage::{MemoryStore, RetainedStore};
use brokerlink::{BrokerFrame, BrokerLinkTransport, FramedTransport, OpCode};
use bytes::Bytes;
use clap::Parser;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};
use tracing::{debug, info, warn};

#[derive(Parser, Debug)]
#[command(name = "indramqtt", version, about = "IndraMQTT Distributed Broker Kernel")]
struct Args {
    #[arg(short, long, default_value = "127.0.0.1:1883")]
    bind: String,

    /// BrokerLink IPC listen address for BEAM edge clients (TCP loopback).
    #[arg(long, default_value = "127.0.0.1:18883")]
    brokerlink_bind: String,

    /// Management REST API listen address. Empty disables the API
    /// (useful for test environments).
    #[arg(long, default_value = "127.0.0.1:18083")]
    api_bind: String,

    /// Enterprise commercial license key for multi-node clustering (or via INDRA_LICENSE_KEY env).
    #[arg(long)]
    license_key: Option<String>,

    /// Cluster seed nodes (e.g. 127.0.0.1:19883). Specifying enables distributed clustering.
    #[arg(long)]
    cluster_seeds: Option<String>,
}

/// Map an inbound frame to its synchronous reply, if any.
///
/// Contracts (mirrored in `beam/src/indra_brokerlink.erl`):
/// * `Ping` is answered immediately with a `Pong` carrying the identical
///   `conn_id` and `sequence_no`.
/// * `BindConnection` metadata is `ClientIdLen:16be | ClientId (UTF-8)
///   | Flags:8 (bit 0 = clean_start) | Keepalive:16be`. The canonical
///   session is resolved via `SessionManager::get_or_create` and answered
///   with `SessionBinding` metadata `SessionId:64be | Present:8
///   | ReturnCode:8` (RC 0 = accepted, 2 = identifier rejected).
///   Replies always mirror the request `conn_id` and `sequence_no`.
/// * All other opcodes have no synchronous reply yet and return `None`.
fn reply_for_frame(frame: &BrokerFrame, sessions: &SessionManager) -> Option<BrokerFrame> {
    match frame.header.opcode {
        OpCode::Ping => Some(BrokerFrame::pong(
            frame.header.conn_id,
            frame.header.sequence_no,
        )),
        OpCode::BindConnection => Some(bind_connection_reply(frame, sessions)),
        _ => None,
    }
}

/// Resolve one `BindConnection` frame into its `SessionBinding` reply.
///
/// Every `BindConnection` yields exactly one reply so the BEAM edge never
/// hangs waiting for CONNACK parameters: malformed metadata (or a
/// non-UTF-8 client id) is answered with return code 2, mirroring the
/// MQTT 3.1.1 CONNACK "identifier rejected" code.
fn bind_connection_reply(frame: &BrokerFrame, sessions: &SessionManager) -> BrokerFrame {
    let (session_id, present, return_code) = match decode_bind_meta(&frame.metadata) {
        Ok(req) => {
            let (session, present) = sessions.get_or_create(&req.client_id, req.clean_start);
            // Connection != Session: pin this edge connection to the session
            // so Unbind can later verify ownership before detaching.
            *session.conn_id.write() = Some(frame.header.conn_id);
            *session.keepalive_secs.write() = req.keepalive_secs;
            (session.id.0, present, 0u8)
        }
        Err(_) => (0u64, false, 2u8),
    };

    session_binding_reply(frame, session_id, present, return_code)
}

/// Build one `SessionBinding` reply frame.
fn session_binding_reply(
    frame: &BrokerFrame,
    session_id: u64,
    present: bool,
    return_code: u8,
) -> BrokerFrame {
    let mut meta = Vec::with_capacity(10);
    meta.extend_from_slice(&session_id.to_be_bytes());
    meta.push(u8::from(present));
    meta.push(return_code);

    BrokerFrame::new(
        OpCode::SessionBinding,
        frame.header.conn_id,
        frame.header.sequence_no,
        Bytes::from(meta),
        Bytes::new(),
    )
    .expect("SessionBinding reply within size bounds")
}

/// Authenticated bind for the live path: credentialed requests verify
/// against the auth store first (failure short-circuits to return code
/// `0x86`, bad username/password, with no session created), then the
/// per-user connection quota applies (overage short-circuits to `0x8B`),
/// then the standard session resolution applies.
async fn apply_bind(frame: &BrokerFrame, shared: &Shared) -> Option<BrokerFrame> {
    if let Ok(req) = decode_bind_meta(&frame.metadata) {
        if req.username.is_some() {
            let password = req.password.as_deref();
            if shared
                .auth
                .authenticate(&req.client_id, req.username.as_deref(), password)
                .await
                .is_err()
            {
                return Some(session_binding_reply(frame, 0, false, 0x86));
            }
            // Takeover pre-release: a live session for this client means
            // the previous holder was orphaned by this very bind.
            let already_live = shared
                .sessions
                .get(&req.client_id)
                .map(|session| *session.connected.read())
                .unwrap_or(false);
            if already_live {
                if let Some(username) = &req.username {
                    shared.sessions.release_connection_slot(username);
                }
            }
            if let Some(username) = &req.username {
                let max = shared
                    .auth
                    .get_quotas(username)
                    .and_then(|quotas| quotas.max_connections);
                if !shared.sessions.acquire_connection_slot(username, max) {
                    return Some(session_binding_reply(frame, 0, false, 0x8B));
                }
            }
        }
    }
    let reply = reply_for_frame(frame, &shared.sessions);
    // Stamp ownership for quota release and publish attribution.
    if let Ok(req) = decode_bind_meta(&frame.metadata) {
        if let (Some(session), Some(username)) =
            (shared.sessions.get(&req.client_id), &req.username)
        {
            *session.username.write() = Some(username.clone());
        }
    }
    reply
}

/// Decode `BindConnection` metadata.
///
/// Layout: `ClientIdLen:16be | ClientId | Flags:8 | Keepalive:16be`,
/// optionally followed by a credentials section `UserLen:16be | Username
/// | PassLen:16be | Password` (absent entirely when the client connects
/// anonymously). The keepalive is framing-validated here; supervision
/// lives on the edge.
struct BindRequest {
    client_id: String,
    clean_start: bool,
    keepalive_secs: u16,
    username: Option<String>,
    password: Option<Vec<u8>>,
}

fn decode_bind_meta(meta: &[u8]) -> Result<BindRequest, &'static str> {
    if meta.len() < 5 {
        return Err("bind meta too short");
    }
    let id_len = u16::from_be_bytes([meta[0], meta[1]]) as usize;
    if meta.len() < 2 + id_len + 1 + 2 {
        return Err("bind meta too short");
    }
    let id_bytes = &meta[2..2 + id_len];
    let flags = meta[2 + id_len];
    let keepalive_secs = u16::from_be_bytes([meta[3 + id_len], meta[4 + id_len]]);
    let client_id = std::str::from_utf8(id_bytes).map_err(|_| "client id not UTF-8")?;
    let rest = &meta[5 + id_len..];
    let (username, password) = decode_bind_credentials(rest)?;
    Ok(BindRequest {
        client_id: client_id.to_string(),
        clean_start: flags & 0x01 != 0,
        keepalive_secs,
        username,
        password,
    })
}

/// Decode the optional trailing credentials section: empty means
/// anonymous; otherwise exactly `UserLen | Username | PassLen | Password`.
fn decode_bind_credentials(
    rest: &[u8],
) -> Result<(Option<String>, Option<Vec<u8>>), &'static str> {
    if rest.is_empty() {
        return Ok((None, None));
    }
    if rest.len() < 2 {
        return Err("bind credentials truncated");
    }
    let user_len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
    if rest.len() < 2 + user_len + 2 {
        return Err("bind credentials truncated");
    }
    let username =
        std::str::from_utf8(&rest[2..2 + user_len]).map_err(|_| "username not UTF-8")?;
    let base = 2 + user_len;
    let pass_len = u16::from_be_bytes([rest[base], rest[base + 1]]) as usize;
    if rest.len() != base + 2 + pass_len {
        return Err("bind meta length mismatch");
    }
    let password = rest[base + 2..].to_vec();
    Ok((Some(username.to_string()), Some(password)))
}

/// State shared by every BrokerLink connection task on this node.
#[derive(Clone)]
struct Shared {
    sessions: Arc<SessionManager>,
    router: Arc<Router>,
    conns: Arc<ConnTable>,
    engine: Arc<RuleEngine>,
    sink: Arc<dyn BrokerSink>,
    retained: Arc<dyn RetainedStore>,
    /// Cluster routing plane. `None` runs standalone; `Some` announces
    /// local subscriptions and forwards each publish once per matching
    /// remote node (single forward per node; remotes fan out locally).
    cluster: Option<Arc<dyn RoutingPlane>>,
    metrics: Arc<Metrics>,
    auth: Arc<MemoryAuth>,
}

impl Shared {
    fn new() -> Self {
        let sessions = Arc::new(SessionManager::new());
        let router = Arc::new(Router::new());
        let conns = Arc::new(ConnTable::default());
        let engine = Arc::new(RuleEngine::new(1024, BackpressurePolicy::DropOldest));
        let metrics = Arc::new(Metrics::new());
        // NO MQTT LOOPBACK: rule republishes route straight into the local
        // router/mailboxes through this in-memory sink. The same sink
        // serves window-flush republish actions (INDRA-213).
        let sink: Arc<dyn BrokerSink> = Arc::new(InMemoryBrokerSink {
            router: router.clone(),
            sessions: sessions.clone(),
            conns: conns.clone(),
            metrics: metrics.clone(),
        });
        engine.set_broker_sink(sink.clone());
        Self {
            sessions,
            router,
            conns,
            engine,
            sink,
            retained: Arc::new(MemoryStore::new()),
            cluster: None,
            metrics,
            auth: Arc::new(MemoryAuth::new()),
        }
    }
}

/// [`BrokerSink`] that forwards rule output directly to local router
/// subscribers. Pure in-memory fan-out: no sockets, no MQTT loopback.
struct InMemoryBrokerSink {
    router: Arc<Router>,
    sessions: Arc<SessionManager>,
    conns: Arc<ConnTable>,
    metrics: Arc<Metrics>,
}

#[async_trait]
impl BrokerSink for InMemoryBrokerSink {
    async fn publish(
        &self,
        topic: Topic,
        payload: Bytes,
        qos: QoS,
        retain: bool,
    ) -> Result<(), broker_rules::RuleEngineError> {
        let deliveries =
            build_downlink_frames(&self.router, &self.sessions, &topic, qos, retain, &payload);
        self.metrics
            .inc_messages_forwarded_by(deliveries.len() as u64);
        for (conn_id, frame) in deliveries {
            self.conns.route(conn_id, frame);
        }
        Ok(())
    }
}

async fn handle_connection(
    stream: TcpStream,
    shared: Shared,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "<unknown>".to_string());
    debug!("BrokerLink IPC connection from {}", peer);

    let transport = FramedTransport::new(stream);
    // Mailbox for frames routed to this connection by other tasks
    // (e.g. PublishOut fan-out). The sender is registered under our
    // conn_id once the edge binds.
    let (tx, mut rx) = unbounded_channel::<BrokerFrame>();
    // Identity bound by the last BindConnection on this transport. Used
    // to detach the session when the socket dies without DISCONNECT.
    let mut bound: Option<(String, u64)> = None;

    loop {
        tokio::select! {
            inbound = transport.recv() => {
                let frame = match inbound {
                    Ok(frame) => frame,
                    Err(brokerlink::BrokerLinkError::ConnectionClosed) => {
                        debug!("BrokerLink IPC peer {} closed", peer);
                        detach(&bound, &shared, &tx);
                        return Ok(());
                    }
                    Err(e) => {
                        warn!("BrokerLink IPC error from {}: {}", peer, e);
                        detach(&bound, &shared, &tx);
                        return Err(Box::new(e));
                    }
                };

                debug!(
                    "BrokerLink recv opcode={:?} conn_id={} seq={}",
                    frame.header.opcode, frame.header.conn_id, frame.header.sequence_no
                );

                handle_inbound_frame(frame, &shared, &tx, &transport, &mut bound).await?;
            }
            outbound = rx.recv() => {
                match outbound {
                    Some(frame) => {
                        transport.send(frame).await?;
                    }
                    None => {
                        // All senders gone; nothing left to deliver.
                        detach(&bound, &shared, &tx);
                        return Ok(());
                    }
                }
            }
        }
    }
}

/// Detach a dead transport: forget its mailbox and mark its session
/// detached (durable sessions keep subscriptions + offline queue).
fn detach(
    bound: &Option<(String, u64)>,
    shared: &Shared,
    tx: &UnboundedSender<BrokerFrame>,
) {
    shared.conns.prune_sender(tx);
    if let Some((client_id, conn_id)) = bound {
        shared.sessions.unbind_connection(client_id, *conn_id);
        shared.metrics.dec_connections();
    }
}

/// Process one frame from the edge: direct replies go back on our own
/// transport, routed frames fan out through the connection table.
async fn handle_inbound_frame<S>(
    frame: BrokerFrame,
    shared: &Shared,
    tx: &UnboundedSender<BrokerFrame>,
    transport: &FramedTransport<S>,
    bound: &mut Option<(String, u64)>,
) -> Result<(), Box<dyn std::error::Error>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    match frame.header.opcode {
        OpCode::BindConnection => {
            if let Some(reply) = apply_bind(&frame, shared).await {
                transport.send(reply).await?;
                shared.conns.register(frame.header.conn_id, tx.clone());
                shared.metrics.inc_connections();
                // Remember who we serve so a dead socket detaches cleanly.
                if let Ok(req) = decode_bind_meta(&frame.metadata) {
                    *bound = Some((req.client_id, frame.header.conn_id));
                }
                let replayed = replay_offline(&frame, shared).await;
                shared.metrics.inc_messages_forwarded_by(replayed as u64);
            }
        }
        OpCode::SubscribeIn => match apply_subscribe(&frame, shared).await {
            (Some(reply), retained) => {
                transport.send(reply).await?;
                // SUBACK first, then retained state, per MQTT ordering.
                for held in &retained {
                    transport.send(held.clone()).await?;
                }
                shared
                    .metrics
                    .inc_messages_forwarded_by(retained.len() as u64);
            }
            (None, _) => {
                warn!(
                    "Dropping malformed SubscribeIn from conn {}",
                    frame.header.conn_id
                );
            }
        },
        OpCode::PublishIn => {
            let (ack, deliveries) = apply_publish(&frame, shared).await;
            if let Some(ack) = ack {
                transport.send(ack).await?;
            }
            shared
                .metrics
                .inc_messages_forwarded_by(deliveries.len() as u64);
            for (conn_id, routed) in deliveries {
                shared.conns.route(conn_id, routed);
            }
        }
        OpCode::UnbindConnection => {
            apply_unbind(&frame, shared);
        }
        _ => {
            if let Some(reply) = reply_for_frame(&frame, &shared.sessions) {
                transport.send(reply).await?;
            }
        }
    }
    Ok(())
}

/// Register the subscriptions of one `SubscribeIn` frame and build its
/// `SubAckOut` reply plus any retained messages for the new subscription.
/// Malformed framing yields `(None, empty)` (the edge treats a missing
/// SubAck as a hung request scoped to that connection).
///
/// Meta layout: `PacketId:16be | IdLen:16be | ClientId | N:16be |
/// (FilterLen:16be | Filter | QoS:8) * N`. Each granted code echoes the
/// requested QoS; invalid filters and ACL denials are answered with
/// `0x80` (not authorized) and `0x87` respectively and register nothing.
/// `$share/<group>/` prefixes are split before routing, ACL checks,
/// retained fetch, and cluster announce so every downstream stage sees
/// the plain inner filter. Retained deliveries carry `retain = true` at
/// `min(subscription QoS, stored QoS)`.
async fn apply_subscribe(
    frame: &BrokerFrame,
    shared: &Shared,
) -> (Option<BrokerFrame>, Vec<BrokerFrame>) {
    let (packet_id, client_id, subs) = match decode_subscribe_meta(&frame.metadata) {
        Some(parts) => parts,
        None => return (None, Vec::new()),
    };

    let mut codes = Vec::with_capacity(subs.len());
    let mut granted: Vec<(TopicFilter, u8)> = Vec::with_capacity(subs.len());
    for (filter_str, qos_raw) in subs {
        // Delayed topics are publish-only markers, never subscriptions.
        if strip_delayed_prefix(&filter_str).is_some() {
            codes.push(0x80);
            continue;
        }
        let parsed = TopicFilter::new(filter_str).ok().and_then(|filter| {
            QoS::try_from(qos_raw)
                .ok()
                .and_then(|qos| split_shared_filter(&filter).map(|(group, inner)| (inner, qos, group)))
        });
        let (filter, qos, group) = match parsed {
            Some(parts) => parts,
            None => {
                codes.push(0x80);
                continue;
            }
        };
        if shared
            .auth
            .authorize_subscribe(&client_id, &filter)
            .await
            .is_err()
        {
            // MQTT 5 style "Not Authorized"; registers nothing.
            codes.push(0x87);
            continue;
        }
        shared.router.subscribe(
            &filter,
            Subscription {
                client_id: client_id.clone().into(),
                conn_id: frame.header.conn_id,
                qos,
                group,
            },
        );
        // Mirror the grant on the session for observability (the router
        // stays the routing authority).
        shared
            .sessions
            .add_subscription(&client_id, filter.clone(), qos);
        granted.push((filter, qos_raw));
        codes.push(qos_raw);
    }

    let mut meta = Vec::with_capacity(2 + codes.len());
    meta.extend_from_slice(&packet_id.to_be_bytes());
    meta.extend_from_slice(&codes);
    let reply = BrokerFrame::new(
        OpCode::SubAckOut,
        frame.header.conn_id,
        frame.header.sequence_no,
        Bytes::from(meta),
        Bytes::new(),
    )
    .ok();

    // Clustered mode: publish our route summary (filter-level only, never
    // individual subscriptions) so peers forward matching publishes here.
    if let Some(cluster) = &shared.cluster {
        for (filter, _) in &granted {
            if let Err(e) = cluster.announce_filter(filter).await {
                warn!(
                    "Cluster announce failed for {}: {}",
                    filter.as_str(),
                    e
                );
            }
        }
    }

    // Retained state follows the SubAck on the same transport.
    let mut retained = Vec::new();
    let session = shared.sessions.get(&client_id);
    for (filter, sub_qos) in &granted {
        let matched = match shared.retained.find_matching(filter).await {
            Ok(matched) => matched,
            Err(e) => {
                warn!("Retained lookup failed for {}: {}", filter.as_str(), e);
                continue;
            }
        };
        for msg in matched {
            let effective = std::cmp::min(*sub_qos, u8::from(msg.qos));
            let downlink_id = if effective == 0 {
                0u16
            } else {
                match &session {
                    Some(session) => session.next_packet_id(),
                    None => 1u16,
                }
            };
            let topic_str = msg.topic.as_str();
            let mut meta = Vec::with_capacity(2 + topic_str.len() + 2 + 3);
            meta.extend_from_slice(&(topic_str.len() as u16).to_be_bytes());
            meta.extend_from_slice(topic_str.as_bytes());
            meta.extend_from_slice(&downlink_id.to_be_bytes());
            meta.push(effective);
            meta.push(1u8); // retain: replayed retained state
            meta.push(0u8);
            if let Ok(routed) = BrokerFrame::new(
                OpCode::PublishOut,
                frame.header.conn_id,
                0,
                Bytes::from(meta),
                msg.payload.clone(),
            ) {
                retained.push(routed);
            }
        }
    }

    (reply, retained)
}

/// Replay a resumed durable session's offline queue onto its new
/// connection. Runs after the `SessionBinding` reply so the edge always
/// observes binding before backlog. Returns the replayed frame count.
async fn replay_offline(frame: &BrokerFrame, shared: &Shared) -> usize {
    let req = match decode_bind_meta(&frame.metadata) {
        Ok(req) => req,
        Err(_) => return 0,
    };
    let session = match shared.sessions.get(&req.client_id) {
        Some(session) => session,
        None => return 0,
    };
    let mut replayed = 0;
    for queued in session.drain_offline() {
        let downlink_id = if queued.qos == QoS::AtMostOnce {
            0u16
        } else {
            session.next_packet_id()
        };
        let topic_str = queued.topic.as_str();
        let mut meta = Vec::with_capacity(2 + topic_str.len() + 2 + 3);
        meta.extend_from_slice(&(topic_str.len() as u16).to_be_bytes());
        meta.extend_from_slice(topic_str.as_bytes());
        meta.extend_from_slice(&downlink_id.to_be_bytes());
        meta.push(u8::from(queued.qos));
        meta.push(u8::from(queued.retain));
        meta.push(0u8);
        if let Ok(routed) = BrokerFrame::new(
            OpCode::PublishOut,
            frame.header.conn_id,
            0, // stamped per-destination by ConnTable::route
            Bytes::from(meta),
            queued.payload.clone(),
        ) {
            shared.conns.route(frame.header.conn_id, routed);
            replayed += 1;
        }
    }
    replayed
}

/// Route one `PublishIn` frame: an optional `PubAckOut` for the publisher
/// (QoS 1) plus one `PublishOut` per matching subscriber.
///
/// Ingress-only rule execution runs first on the receiving node; the
/// standard router fan-out follows. Delivery QoS is `min(publish QoS,
/// subscription QoS)`; QoS 1 deliveries draw their packet id from the
/// subscriber session so each downstream flow keeps an independent id
/// space. The raw payload bytes are forwarded untouched.
///
/// `$delayed/<secs>/<topic>` targets defer everything except the
/// publisher ack: after the delay the message re-enters through
/// [`ingress_pipeline`] with the inner topic (retained store, rules,
/// fan-out, cluster forward), so delayed delivery observes the same
/// semantics as immediate delivery, just later.
async fn apply_publish(
    frame: &BrokerFrame,
    shared: &Shared,
) -> (Option<BrokerFrame>, Vec<(u64, BrokerFrame)>) {
    let (topic_str, packet_id, qos_raw, retain) = match decode_publish_meta(&frame.metadata) {
        Some(parts) => parts,
        None => return (None, Vec::new()),
    };
    let topic = match Topic::new(topic_str.clone()) {
        Ok(topic) => topic,
        Err(_) => return (None, Vec::new()),
    };
    let qos = match QoS::try_from(qos_raw) {
        Ok(qos) => qos,
        Err(_) => return (None, Vec::new()),
    };
    shared.metrics.inc_messages_received();

    // ACL: the publisher is whoever owns this edge connection. Denied
    // publishes die here (QoS 1 still gets its PubAck, stamped 0x87).
    if let Some(publisher) = shared.sessions.client_id_for_conn(frame.header.conn_id) {
        if shared
            .auth
            .authorize_publish(&publisher, &topic)
            .await
            .is_err()
        {
            let ack = if qos == QoS::AtLeastOnce {
                pub_ack_reply(frame, packet_id, 0x87)
            } else {
                None
            };
            return (ack, Vec::new());
        }
    }

    // Rate policing (INDRA-128): token bucket per publishing client,
    // configured per user. Over quota the message dies here — QoS 0 is
    // dropped and counted, QoS 1 gets its PubAck stamped 0x97.
    if !check_publish_quota(frame, shared).await {
        shared.metrics.inc_messages_dropped();
        let ack = if qos == QoS::AtLeastOnce {
            pub_ack_reply(frame, packet_id, 0x97)
        } else {
            None
        };
        return (ack, Vec::new());
    }

    // Delayed delivery: ack now (the publisher must not stall), defer
    // everything else past the timer.
    if let Some((delay_secs, inner)) = strip_delayed_prefix(&topic_str) {
        return apply_delayed_publish(frame, shared, delay_secs, inner, qos, retain, packet_id)
            .await;
    }

    let ack = if qos == QoS::AtLeastOnce {
        pub_ack_reply(frame, packet_id, 0)
    } else {
        None
    };

    let deliveries = ingress_pipeline(shared, &topic, qos, retain, &frame.payload).await;
    forward_cluster(shared, &topic, qos, &frame.payload).await;

    (ack, deliveries)
}

/// Upper bound for `$delayed` deferrals: beyond a day the request is
/// dropped with a warning instead of pinning a task indefinitely.
const MAX_DELAYED_SECS: u64 = 86_400;

/// Handle a `$delayed/<secs>/<topic>` publish: immediate ack, deferred
/// pipeline. An unparseable inner topic or an over-limit delay drops the
/// message (it could never be delivered correctly).
async fn apply_delayed_publish(
    frame: &BrokerFrame,
    shared: &Shared,
    delay_secs: u64,
    inner: &str,
    qos: QoS,
    retain: bool,
    packet_id: u16,
) -> (Option<BrokerFrame>, Vec<(u64, BrokerFrame)>) {
    let inner_topic = match Topic::new(inner.to_string()) {
        Ok(topic) => topic,
        Err(e) => {
            warn!("Dropping delayed publish with bad inner topic: {}", e);
            return (None, Vec::new());
        }
    };
    if delay_secs > MAX_DELAYED_SECS {
        warn!(
            "Dropping delayed publish: {}s exceeds the {}s cap",
            delay_secs, MAX_DELAYED_SECS
        );
        return (None, Vec::new());
    }
    let ack = if qos == QoS::AtLeastOnce {
        pub_ack_reply(frame, packet_id, 0)
    } else {
        None
    };
    if delay_secs == 0 {
        let deliveries =
            ingress_pipeline(shared, &inner_topic, qos, retain, &frame.payload).await;
        forward_cluster(shared, &inner_topic, qos, &frame.payload).await;
        return (ack, deliveries);
    }
    let shared = shared.clone();
    let payload = frame.payload.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(delay_secs)).await;
        let deliveries =
            ingress_pipeline(&shared, &inner_topic, qos, retain, &payload).await;
        shared
            .metrics
            .inc_messages_forwarded_by(deliveries.len() as u64);
        for (conn_id, routed) in deliveries {
            shared.conns.route(conn_id, routed);
        }
        forward_cluster(&shared, &inner_topic, qos, &payload).await;
    });
    (ack, Vec::new())
}

/// The shared ingress pipeline: retained store/clear, rule execution,
/// and local fan-out. Used by immediate delivery and, after its timer,
/// by delayed delivery alike.
async fn ingress_pipeline(
    shared: &Shared,
    topic: &Topic,
    qos: QoS,
    retain: bool,
    payload: &Bytes,
) -> Vec<(u64, BrokerFrame)> {
    // Retained state tracks raw ingress: store (or clear on empty
    // payload) before rules and fan-out observe the message.
    if retain {
        if payload.is_empty() {
            if let Err(e) = shared.retained.clear_retained(topic).await {
                warn!("Retained clear failed for {}: {}", topic.as_str(), e);
            }
        } else if let Err(e) = shared
            .retained
            .set_retained(topic.clone(), qos, payload.clone())
            .await
        {
            warn!("Retained store failed for {}: {}", topic.as_str(), e);
        }
    }

    // Rules execute at ingress on this node, before local fan-out.
    // Republished output re-enters through the sink only, so rules can
    // never recurse through their own output.
    let rules_fired = shared
        .engine
        .dispatch_ingress(topic, payload, qos, &shared.sink)
        .await;
    shared.metrics.inc_rules_executed_by(rules_fired as u64);

    build_downlink_frames(
        &shared.router, &shared.sessions, topic, qos, retain, payload,
    )
}

/// Clustered mode: one forward per matching remote node; each remote
/// fans out locally.
async fn forward_cluster(shared: &Shared, topic: &Topic, qos: QoS, payload: &Bytes) {
    if let Some(cluster) = &shared.cluster {
        match cluster.resolve_route(topic).await {
            Ok(targets) => {
                for target in targets {
                    if let Err(e) = cluster.forward_message(&target, topic, payload, qos).await {
                        warn!("Cluster forward to {} failed: {}", target, e);
                    }
                }
            }
            Err(e) => {
                warn!("Cluster route resolution failed: {}", e);
            }
        }
    }
}

/// Build one `PublishOut` frame per router match. Shared by the standard
/// fan-out and the rule [`BrokerSink`] so both paths downgrade QoS and
/// allocate downlink packet ids identically.
///
/// Delivery targets the session's live connection: a detached durable
/// session buffers into its offline queue instead, and a detached clean
/// session drops. Sessions unknown to the manager fall back to the
/// router-registered conn_id.
fn build_downlink_frames(
    router: &Router,
    sessions: &SessionManager,
    topic: &Topic,
    qos: QoS,
    retain: bool,
    payload: &Bytes,
) -> Vec<(u64, BrokerFrame)> {
    let qos_raw = u8::from(qos);
    let topic_str = topic.as_str();
    let mut deliveries = Vec::new();
    for sub in router.matches(topic) {
        let effective = std::cmp::min(qos_raw, u8::from(sub.qos));
        match sessions.get(&sub.client_id) {
            Some(session) => {
                let connected = *session.connected.read();
                let live = *session.conn_id.read();
                match (connected, live) {
                    (true, Some(conn_id)) => {
                        let downlink_id = if effective == 0 {
                            0u16
                        } else {
                            session.next_packet_id()
                        };
                        if let Some(frame) = encode_publish_out(
                            conn_id,
                            topic_str,
                            downlink_id,
                            effective,
                            retain,
                            payload,
                        ) {
                            deliveries.push((conn_id, frame));
                        }
                    }
                    _ => {
                        // Detached (or half-bound) session: durable
                        // sessions buffer for replay, clean ones drop.
                        if !session.clean_start {
                            session.push_offline(QueuedMessage {
                                topic: topic.clone(),
                                qos: QoS::try_from(effective).unwrap_or(QoS::AtMostOnce),
                                retain,
                                payload: payload.clone(),
                            });
                        }
                    }
                }
            }
            None => {
                // No session on record: legacy fallback to the
                // router-registered conn_id.
                let downlink_id = if effective == 0 { 0u16 } else { 1u16 };
                if let Some(frame) = encode_publish_out(
                    sub.conn_id,
                    topic_str,
                    downlink_id,
                    effective,
                    retain,
                    payload,
                ) {
                    deliveries.push((sub.conn_id, frame));
                }
            }
        }
    }
    deliveries
}

/// Token-bucket gate for one publish (INDRA-128). Resolves the owning
/// client, looks up its user's rate quota, and consumes one token.
/// True means route; false means drop. Anonymous, unknown, and
/// unconfigured clients are unlimited.
async fn check_publish_quota(frame: &BrokerFrame, shared: &Shared) -> bool {
    let Some(client_id) = shared.sessions.client_id_for_conn(frame.header.conn_id) else {
        return true;
    };
    let Some(session) = shared.sessions.get(&client_id) else {
        return true;
    };
    let username = session.username.read().clone();
    let Some(username) = username else {
        return true;
    };
    let Some(quotas) = shared.auth.get_quotas(&username) else {
        return true;
    };
    let Some(rate) = quotas.max_publish_rate else {
        return true;
    };
    let burst = quotas.max_publish_burst.unwrap_or(rate);
    shared.sessions.check_publish_budget(&client_id, rate, burst)
}

/// Build one `PubAckOut` reply mirroring the request identity.
fn pub_ack_reply(frame: &BrokerFrame, packet_id: u16, return_code: u8) -> Option<BrokerFrame> {
    let mut meta = Vec::with_capacity(3);
    meta.extend_from_slice(&packet_id.to_be_bytes());
    meta.push(return_code);
    BrokerFrame::new(
        OpCode::PubAckOut,
        frame.header.conn_id,
        frame.header.sequence_no,
        Bytes::from(meta),
        Bytes::new(),
    )
    .ok()
}

/// Encode one `PublishOut` frame for `conn_id` (sequence stamped later
/// per-destination by `ConnTable::route`).
fn encode_publish_out(
    conn_id: u64,
    topic: &str,
    packet_id: u16,
    qos: u8,
    retain: bool,
    payload: &Bytes,
) -> Option<BrokerFrame> {
    let mut meta = Vec::with_capacity(2 + topic.len() + 2 + 3);
    meta.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    meta.extend_from_slice(topic.as_bytes());
    meta.extend_from_slice(&packet_id.to_be_bytes());
    meta.push(qos);
    meta.push(u8::from(retain));
    meta.push(0u8); // dup: fresh downstream delivery
    BrokerFrame::new(
        OpCode::PublishOut,
        conn_id,
        0, // stamped per-destination by ConnTable::route
        Bytes::from(meta),
        payload.clone(),
    )
    .ok()
}

/// Pump messages forwarded from peer nodes until the plane closes.
/// Inbound cluster traffic fans out locally only: only ingress paths
/// forward, so loops cannot form even though messages carry no history.
async fn run_cluster_inbox(shared: Shared) {
    let cluster = match &shared.cluster {
        Some(cluster) => cluster.clone(),
        None => return,
    };
    while let Some(msg) = cluster.recv_message().await {
        deliver_cluster_message(&shared, msg).await;
    }
    debug!("Cluster inbox closed");
}

/// Deliver one peer-forwarded message to local subscribers: pure fan-out
/// with no retained writes, no rule execution (both already happened at
/// the ingress node), and no re-forward.
async fn deliver_cluster_message(shared: &Shared, msg: ClusterMessage) {
    for (conn_id, frame) in build_downlink_frames(
        &shared.router,
        &shared.sessions,
        &msg.topic,
        msg.qos,
        false,
        &msg.payload,
    ) {
        shared.conns.route(conn_id, frame);
    }
}

/// Detach one edge connection: mark its session disconnected (ownership
/// verified against the bound conn_id) and forget its mailbox. Durable
/// subscriptions survive; redelivery is a later sprint.
fn apply_unbind(frame: &BrokerFrame, shared: &Shared) {    if let Some(client_id) = decode_unbind_meta(&frame.metadata) {
        shared
            .sessions
            .unbind_connection(&client_id, frame.header.conn_id);
    }
    shared.conns.unregister(frame.header.conn_id);
}

/// Decoded `(packet_id, client_id, [(filter, qos)])` subscription metadata.
type SubscribeMeta = (u16, String, Vec<(String, u8)>);

/// Decode `SubscribeMeta` into `(packet_id, client_id, [(filter, qos)])`.
fn decode_subscribe_meta(meta: &[u8]) -> Option<SubscribeMeta> {
    if meta.len() < 6 {
        return None;
    }
    let packet_id = u16::from_be_bytes([meta[0], meta[1]]);
    if packet_id == 0 {
        return None;
    }
    let id_len = u16::from_be_bytes([meta[2], meta[3]]) as usize;
    if meta.len() < 4 + id_len + 2 {
        return None;
    }
    let client_id = std::str::from_utf8(&meta[4..4 + id_len]).ok()?.to_string();
    let mut cursor = 4 + id_len;
    let count = u16::from_be_bytes([meta[cursor], meta[cursor + 1]]) as usize;
    cursor += 2;
    let mut subs = Vec::with_capacity(count);
    for _ in 0..count {
        if meta.len() < cursor + 3 {
            return None;
        }
        let filter_len = u16::from_be_bytes([meta[cursor], meta[cursor + 1]]) as usize;
        if filter_len == 0 || meta.len() < cursor + 2 + filter_len + 1 {
            return None;
        }
        let filter = std::str::from_utf8(&meta[cursor + 2..cursor + 2 + filter_len])
            .ok()?
            .to_string();
        let qos = meta[cursor + 2 + filter_len];
        subs.push((filter, qos));
        cursor += 2 + filter_len + 1;
    }
    if cursor != meta.len() {
        return None;
    }
    Some((packet_id, client_id, subs))
}

/// Decode `PublishMeta` into `(topic, packet_id, qos, retain)`.
fn decode_publish_meta(meta: &[u8]) -> Option<(String, u16, u8, bool)> {
    if meta.len() < 2 + 1 + 2 + 3 {
        return None;
    }
    let topic_len = u16::from_be_bytes([meta[0], meta[1]]) as usize;
    if topic_len == 0 || meta.len() != 2 + topic_len + 2 + 3 {
        return None;
    }
    let topic = std::str::from_utf8(&meta[2..2 + topic_len])
        .ok()?
        .to_string();
    let base = 2 + topic_len;
    let packet_id = u16::from_be_bytes([meta[base], meta[base + 1]]);
    let qos = meta[base + 2];
    let retain = meta[base + 3] != 0;
    Some((topic, packet_id, qos, retain))
}

/// Decode `UnbindMeta` into the client id.
fn decode_unbind_meta(meta: &[u8]) -> Option<String> {
    if meta.len() < 2 {
        return None;
    }
    let id_len = u16::from_be_bytes([meta[0], meta[1]]) as usize;
    if meta.len() != 2 + id_len {
        return None;
    }
    std::str::from_utf8(&meta[2..2 + id_len])
        .ok()
        .map(str::to_string)
    }

async fn serve_brokerlink(bind: &str, shared: Shared) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(bind).await?;
    info!("BrokerLink IPC listening on {}", bind);

    // Clustered mode pumps peer-forwarded messages alongside edge traffic.
    if shared.cluster.is_some() {
        tokio::spawn(run_cluster_inbox(shared.clone()));
    }

    loop {
        let (stream, addr) = listener.accept().await?;
        debug!("BrokerLink IPC accepted {}", addr);
        let shared = shared.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, shared).await {
                warn!("BrokerLink connection {} ended with error: {}", addr, e);
            }
        });
    }
}

/// Serve the management REST API on an already-bound listener.
async fn serve_api(
    listener: tokio::net::TcpListener,
    shared: Shared,
) -> std::io::Result<()> {
    let state = broker_api::ApiState::new(
        shared.engine.clone(),
        shared.sessions.clone(),
        shared.router.clone(),
        shared.metrics.clone(),
        shared.auth.clone(),
        shared.conns.clone(),
    );
    broker_api::serve(listener, state).await
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    broker_observability::init_tracing();
    let args = Args::parse();

    info!(
        "Starting IndraMQTT Kernel v{} on {}",
        env!("CARGO_PKG_VERSION"),
        args.bind
    );
    info!("BrokerLink IPC protocol initialized");
    info!("Clean-room architecture ready");

    if let Some(seeds) = &args.cluster_seeds {
        info!("Cluster mode enabled with seeds: {}", seeds);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let license_key = args
            .license_key
            .or_else(|| std::env::var("INDRA_LICENSE_KEY").ok());
        let status = ClusterLicense::evaluate(license_key.as_deref(), 1, now);
        ClusterLicense::log_status_banner(&status);
    }

    let shared = Shared::new();
    if !args.api_bind.is_empty() {
        let listener = tokio::net::TcpListener::bind(&args.api_bind).await?;
        info!("Management API listening on {}", args.api_bind);
        let api_shared = shared.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_api(listener, api_shared).await {
                warn!("Management API exited: {}", e);
            }
        });
    }

    serve_brokerlink(&args.brokerlink_bind, shared).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use broker_auth::{AclAction, AclRule};

    /// Encode `BindConnection` metadata (test mirror of the BEAM
    /// `indra_brokerlink:encode_bind_meta/3` contract).
    fn encode_bind_meta(client_id: &str, clean_start: bool, keepalive: u16) -> Bytes {
        let id = client_id.as_bytes();
        let mut meta = Vec::with_capacity(2 + id.len() + 1 + 2);
        meta.extend_from_slice(&(id.len() as u16).to_be_bytes());
        meta.extend_from_slice(id);
        meta.push(u8::from(clean_start));
        meta.extend_from_slice(&keepalive.to_be_bytes());
        Bytes::from(meta)
    }

    /// Decode `SessionBinding` metadata into `(session_id, present, rc)`.
    fn decode_session_binding_meta(meta: &[u8]) -> (u64, bool, u8) {
        assert_eq!(meta.len(), 10, "SessionBinding meta must be 10 bytes");
        let session_id = u64::from_be_bytes(meta[0..8].try_into().unwrap());
        (session_id, meta[8] != 0, meta[9])
    }

    fn bind_frame(conn_id: u64, seq: u64, meta: Bytes) -> BrokerFrame {
        BrokerFrame::new(OpCode::BindConnection, conn_id, seq, meta, Bytes::new())
            .expect("valid bind frame")
    }

    /// Encode `BindConnection` metadata with credentials (test mirror of
    /// the BEAM `indra_brokerlink:encode_bind_meta/4` contract).
    fn encode_bind_meta_creds(
        client_id: &str,
        clean_start: bool,
        keepalive: u16,
        username: &str,
        password: &[u8],
    ) -> Bytes {
        let mut meta = encode_bind_meta(client_id, clean_start, keepalive).to_vec();
        meta.extend_from_slice(&(username.len() as u16).to_be_bytes());
        meta.extend_from_slice(username.as_bytes());
        meta.extend_from_slice(&(password.len() as u16).to_be_bytes());
        meta.extend_from_slice(password);
        Bytes::from(meta)
    }

    /// Encode `SubscribeMeta` (test mirror of the BEAM contract).
    fn encode_subscribe_meta(packet_id: u16, client_id: &str, subs: &[(&str, u8)]) -> Bytes {
        let id = client_id.as_bytes();
        let mut meta = Vec::new();
        meta.extend_from_slice(&packet_id.to_be_bytes());
        meta.extend_from_slice(&(id.len() as u16).to_be_bytes());
        meta.extend_from_slice(id);
        meta.extend_from_slice(&(subs.len() as u16).to_be_bytes());
        for (filter, qos) in subs {
            meta.extend_from_slice(&(filter.len() as u16).to_be_bytes());
            meta.extend_from_slice(filter.as_bytes());
            meta.push(*qos);
        }
        Bytes::from(meta)
    }

    /// Encode `PublishMeta` (test mirror of the BEAM contract).
    fn encode_publish_meta(
        topic: &str,
        packet_id: u16,
        qos: u8,
        retain: bool,
        payload: &[u8],
    ) -> (Bytes, Bytes) {
        let mut meta = Vec::new();
        meta.extend_from_slice(&(topic.len() as u16).to_be_bytes());
        meta.extend_from_slice(topic.as_bytes());
        meta.extend_from_slice(&packet_id.to_be_bytes());
        meta.push(qos);
        meta.push(u8::from(retain));
        meta.push(0u8);
        (Bytes::from(meta), Bytes::from(payload.to_vec()))
    }

    fn decode_publish_meta_parts(meta: &[u8]) -> (String, u16, u8, bool) {
        let topic_len = u16::from_be_bytes([meta[0], meta[1]]) as usize;
        let topic = std::str::from_utf8(&meta[2..2 + topic_len])
            .unwrap()
            .to_string();
        let base = 2 + topic_len;
        let packet_id = u16::from_be_bytes([meta[base], meta[base + 1]]);
        (topic, packet_id, meta[base + 2], meta[base + 3] != 0)
    }

    fn subscribe_frame(conn_id: u64, seq: u64, meta: Bytes) -> BrokerFrame {
        BrokerFrame::new(OpCode::SubscribeIn, conn_id, seq, meta, Bytes::new())
            .expect("valid subscribe frame")
    }

    fn publish_frame(conn_id: u64, seq: u64, meta: Bytes, payload: Bytes) -> BrokerFrame {
        BrokerFrame::new(OpCode::PublishIn, conn_id, seq, meta, payload)
            .expect("valid publish frame")
    }

    fn test_shared() -> Shared {
        Shared::new()
    }

    #[test]
    fn ping_maps_to_matching_pong() {
        let sessions = SessionManager::new();
        let ping = BrokerFrame::ping(1234, 56);
        let reply = reply_for_frame(&ping, &sessions).expect("Ping must produce a reply");
        assert_eq!(reply.header.opcode, OpCode::Pong);
        assert_eq!(reply.header.conn_id, 1234);
        assert_eq!(reply.header.sequence_no, 56);
        assert!(reply.metadata.is_empty());
        assert!(reply.payload.is_empty());
    }

    #[test]
    fn ping_pong_preserves_max_ids() {
        let sessions = SessionManager::new();
        let ping = BrokerFrame::ping(u64::MAX, u64::MAX);
        let reply = reply_for_frame(&ping, &sessions).expect("Ping must produce a reply");
        assert_eq!(reply.header.conn_id, u64::MAX);
        assert_eq!(reply.header.sequence_no, u64::MAX);
    }

    #[test]
    fn non_handshake_frames_have_no_reply() {
        let sessions = SessionManager::new();
        for opcode in [
            OpCode::Pong,
            OpCode::SessionBinding,
            OpCode::UnbindConnection,
            OpCode::PublishIn,
            OpCode::PublishOut,
            OpCode::SubscribeIn,
            OpCode::DisconnectIn,
        ] {
            let frame = BrokerFrame::new(
                opcode,
                7,
                9,
                Bytes::from_static(b"meta"),
                Bytes::from_static(b"payload"),
            )
            .expect("valid frame");
            assert!(
                reply_for_frame(&frame, &sessions).is_none(),
                "opcode {:?} must not produce a sync reply",
                opcode
            );
        }
    }

    #[test]
    fn bind_connection_creates_session_without_present_flag() {
        let sessions = SessionManager::new();
        let frame = bind_frame(11, 1, encode_bind_meta("device-001", true, 60));

        let reply = reply_for_frame(&frame, &sessions).expect("Bind must produce a reply");
        assert_eq!(reply.header.opcode, OpCode::SessionBinding);
        assert_eq!(reply.header.conn_id, 11);
        assert_eq!(reply.header.sequence_no, 1);

        let (session_id, present, rc) = decode_session_binding_meta(&reply.metadata);
        assert_ne!(session_id, 0, "fresh session must have a nonzero id");
        assert!(!present, "first clean-start bind must report session_present=false");
        assert_eq!(rc, 0, "accepted bind must carry return code 0");
    }

    #[test]
    fn bind_connection_resumes_session_with_present_flag() {
        let sessions = SessionManager::new();
        let first = bind_frame(11, 1, encode_bind_meta("device-007", true, 60));
        let first_reply = reply_for_frame(&first, &sessions).expect("first bind replies");
        let (first_id, first_present, _) = decode_session_binding_meta(&first_reply.metadata);
        assert!(!first_present);

        let second = bind_frame(12, 1, encode_bind_meta("device-007", false, 60));
        let second_reply = reply_for_frame(&second, &sessions).expect("second bind replies");
        assert_eq!(second_reply.header.conn_id, 12, "reply mirrors requesting conn");
        let (second_id, second_present, rc) = decode_session_binding_meta(&second_reply.metadata);
        assert!(second_present, "resumed session must report session_present=true");
        assert_eq!(second_id, first_id, "resumed bind must reuse the session id");
        assert_eq!(rc, 0);
    }

    #[test]
    fn bind_connection_clean_start_replaces_session() {
        let sessions = SessionManager::new();
        let first = bind_frame(11, 1, encode_bind_meta("device-009", true, 60));
        let (first_id, _, _) =
            decode_session_binding_meta(&reply_for_frame(&first, &sessions).unwrap().metadata);

        let second = bind_frame(11, 2, encode_bind_meta("device-009", true, 60));
        let reply = reply_for_frame(&second, &sessions).expect("rebind replies");
        let (second_id, present, rc) = decode_session_binding_meta(&reply.metadata);
        assert_ne!(second_id, first_id, "clean start must mint a fresh session id");
        assert!(!present);
        assert_eq!(rc, 0);
    }

    #[test]
    fn bind_connection_rejects_garbage_meta_with_rc2() {
        let sessions = SessionManager::new();
        // Truncated meta: claims 5 id bytes but carries none of the tail.
        let bad = bind_frame(11, 3, Bytes::from(vec![0x00, 0x05, b'a', b'b']));
        let reply = reply_for_frame(&bad, &sessions).expect("malformed bind still replies");
        assert_eq!(reply.header.opcode, OpCode::SessionBinding);
        assert_eq!(reply.header.conn_id, 11);
        assert_eq!(reply.header.sequence_no, 3);
        let (_, present, rc) = decode_session_binding_meta(&reply.metadata);
        assert!(!present);
        assert_eq!(rc, 2, "malformed bind must carry return code 2");
    }

    #[test]
    fn bind_connection_rejects_non_utf8_client_id_with_rc2() {
        let sessions = SessionManager::new();
        // id_len=2, bytes 0xFF 0xFE are not valid UTF-8.
        let bad = bind_frame(
            11,
            4,
            Bytes::from(vec![0x00, 0x02, 0xFF, 0xFE, 0x01, 0x00, 0x3C]),
        );
        let reply = reply_for_frame(&bad, &sessions).expect("non-UTF8 bind still replies");
        let (_, _, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 2, "non-UTF8 client id must carry return code 2");
    }

    #[tokio::test]
    async fn ping_pong_round_trip_over_transport() {
        let sessions = SessionManager::new();
        let (client_io, server_io) = tokio::io::duplex(1024);
        let client = FramedTransport::new(client_io);
        let server = FramedTransport::new(server_io);

        let ping = BrokerFrame::ping(4242, 7);
        client.send(ping).await.expect("client send");

        let received = server.recv().await.expect("server recv");
        assert_eq!(received.header.opcode, OpCode::Ping);

        let reply = reply_for_frame(&received, &sessions).expect("server reply");
        server.send(reply).await.expect("server send");

        let pong = client.recv().await.expect("client recv");
        assert_eq!(pong.header.opcode, OpCode::Pong);
        assert_eq!(pong.header.conn_id, 4242);
        assert_eq!(pong.header.sequence_no, 7);
    }

    #[tokio::test]
    async fn server_replies_pong_to_ping_end_to_end() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            handle_connection(stream, Shared::new())
                .await
                .expect("handle");
        });

        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect");
        let client = FramedTransport::new(stream);
        client
            .send(BrokerFrame::ping(99, 100))
            .await
            .expect("send ping");
        let pong = client.recv().await.expect("recv pong");
        assert_eq!(pong.header.opcode, OpCode::Pong);
        assert_eq!(pong.header.conn_id, 99);
        assert_eq!(pong.header.sequence_no, 100);

        server_task.abort();
    }

    #[tokio::test]
    async fn server_binds_session_end_to_end() {        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            handle_connection(stream, Shared::new())
                .await
                .expect("handle");
        });

        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect");
        let client = FramedTransport::new(stream);
        client
            .send(bind_frame(55, 9, encode_bind_meta("e2e-device", true, 30)))
            .await
            .expect("send bind");
        let reply = client.recv().await.expect("recv binding");
        assert_eq!(reply.header.opcode, OpCode::SessionBinding);
        assert_eq!(reply.header.conn_id, 55);
        assert_eq!(reply.header.sequence_no, 9);
        let (session_id, present, rc) = decode_session_binding_meta(&reply.metadata);
        assert_ne!(session_id, 0);
        assert!(!present);
        assert_eq!(rc, 0);

        server_task.abort();
    }

    #[tokio::test]
    async fn subscribe_registers_and_replies_suback() {
        let shared = test_shared();
        let frame = subscribe_frame(
            21,
            4,
            encode_subscribe_meta(7, "sub-1", &[("sport/tennis", 1), ("news", 0)]),
        );

        let (reply, retained) = apply_subscribe(&frame, &shared).await;
        let reply = reply.expect("subscribe replies");
        assert!(retained.is_empty(), "no retained state stored yet");
        assert_eq!(reply.header.opcode, OpCode::SubAckOut);
        assert_eq!(reply.header.conn_id, 21);
        assert_eq!(reply.header.sequence_no, 4);
        assert_eq!(&reply.metadata[0..2], &7u16.to_be_bytes());
        assert_eq!(&reply.metadata[2..], &[1u8, 0u8]);

        let matches = shared
            .router
            .matches(&Topic::new("sport/tennis").unwrap());
        assert_eq!(matches.len(), 1);
        let sub = matches.iter().next().unwrap();
        assert_eq!(sub.client_id.as_ref(), "sub-1");
        assert_eq!(sub.conn_id, 21);
        assert_eq!(sub.qos, QoS::AtLeastOnce);
    }

    #[tokio::test]
    async fn subscribe_invalid_filter_gets_0x80_without_registering() {
        let shared = test_shared();
        let frame = subscribe_frame(
            21,
            4,
            encode_subscribe_meta(9, "sub-bad", &[("sport/#/bogus", 0)]),
        );

        let (reply, retained) = apply_subscribe(&frame, &shared).await;
        let reply = reply.expect("subscribe replies");
        assert!(retained.is_empty());
        assert_eq!(reply.header.opcode, OpCode::SubAckOut);
        assert_eq!(&reply.metadata[0..2], &9u16.to_be_bytes());
        assert_eq!(&reply.metadata[2..], &[0x80u8]);

        let matches = shared.router.matches(&Topic::new("sport/x").unwrap());
        assert!(matches.is_empty());
    }

    #[tokio::test]
    async fn subscribe_malformed_meta_yields_no_reply() {
        let shared = test_shared();
        let frame = subscribe_frame(21, 4, Bytes::from(vec![0x00, 0x07, 0xAA]));
        let (reply, retained) = apply_subscribe(&frame, &shared).await;
        assert!(reply.is_none());
        assert!(retained.is_empty());
    }

    #[tokio::test]
    async fn publish_qos1_fans_out_with_qos_downshift() {
        let shared = test_shared();
        // Subscriber A wants QoS 1 on an exact filter; B wants QoS 0 via wildcard.
        for (conn, client, filter, qos) in [
            (31u64, "fan-a", "sport/tennis", 1u8),
            (32u64, "fan-b", "sport/#", 0u8),
        ] {
            let frame = subscribe_frame(conn, 1, encode_subscribe_meta(1, client, &[(filter, qos)]));
            let (reply, _) = apply_subscribe(&frame, &shared).await;
            reply.expect("subscribe replies");
            // Sessions must exist and be bound for live delivery.
            let (session, _) = shared.sessions.get_or_create(client, true);
            *session.conn_id.write() = Some(conn);
        }

        let (meta, payload) = encode_publish_meta("sport/tennis", 5, 1, false, b"hello");
        let (ack, deliveries) = apply_publish(&publish_frame(40, 2, meta, payload), &shared).await;
        assert!(ack.is_some(), "QoS 1 needs a PubAck");

        assert_eq!(deliveries.len(), 2);
        let mut by_conn: std::collections::HashMap<u64, BrokerFrame> =
            deliveries.into_iter().collect();
        let for_a = by_conn.remove(&31).expect("exact subscriber routed");
        let for_b = by_conn.remove(&32).expect("wildcard subscriber routed");
        for frame in [&for_a, &for_b] {
            assert_eq!(frame.header.opcode, OpCode::PublishOut);
            assert_eq!(frame.payload, Bytes::from_static(b"hello"));
        }
        let (topic_a, pid_a, qos_a, _) = decode_publish_meta_parts(&for_a.metadata);
        assert_eq!(topic_a, "sport/tennis");
        assert_eq!(qos_a, 1, "subscriber QoS preserved under QoS 1 publish");
        assert_ne!(pid_a, 0, "QoS 1 downlink needs a packet id");
        let (_, pid_b, qos_b, _) = decode_publish_meta_parts(&for_b.metadata);
        assert_eq!(qos_b, 0, "delivery downshifted to min(pub, sub)");
        assert_eq!(pid_b, 0, "QoS 0 downlink carries no packet id");
    }

    #[tokio::test]
    async fn publish_qos1_acks_publisher_and_routes() {
        let shared = test_shared();
        let (session, _) = shared.sessions.get_or_create("q1-sub", true);
        *session.conn_id.write() = Some(51);
        let sub = subscribe_frame(51, 1, encode_subscribe_meta(3, "q1-sub", &[("t", 1)]));
        let (reply, _) = apply_subscribe(&sub, &shared).await;
        reply.expect("subscribe replies");

        let (meta, payload) = encode_publish_meta("t", 42, 1, false, b"data");
        let (ack, deliveries) = apply_publish(&publish_frame(52, 8, meta, payload), &shared).await;

        let ack = ack.expect("QoS 1 needs PubAck");
        assert_eq!(ack.header.opcode, OpCode::PubAckOut);
        assert_eq!(ack.header.conn_id, 52, "ack mirrors publisher conn");
        assert_eq!(ack.header.sequence_no, 8, "ack mirrors publisher seq");
        assert_eq!(&ack.metadata[..], &[0x00, 0x2A, 0x00]);

        assert_eq!(deliveries.len(), 1);
        assert_eq!(deliveries[0].0, 51);
        assert_eq!(deliveries[0].1.payload, Bytes::from_static(b"data"));
    }

    #[tokio::test]
    async fn publish_qos0_needs_no_ack() {
        let shared = test_shared();
        let (meta, payload) = encode_publish_meta("t", 0, 0, false, b"x");
        let (ack, deliveries) =
            apply_publish(&publish_frame(60, 1, meta, payload), &shared).await;
        assert!(ack.is_none(), "QoS 0 needs no PubAck");
        assert!(deliveries.is_empty(), "no subscribers, no deliveries");
    }

    #[tokio::test]
    async fn publish_malformed_meta_yields_nothing() {
        let shared = test_shared();
        let (ack, deliveries) = apply_publish(
            &publish_frame(60, 1, Bytes::from(vec![0xFF]), Bytes::new()),
            &shared,
        )
        .await;
        assert!(ack.is_none());
        assert!(deliveries.is_empty());
    }

    #[tokio::test]
    async fn unbind_detaches_connection_but_keeps_subscriptions() {
        let shared = test_shared();
        let bind = bind_frame(71, 1, encode_bind_meta("gone-1", true, 60));
        reply_for_frame(&bind, &shared.sessions).expect("bind replies");
        let sub = subscribe_frame(71, 2, encode_subscribe_meta(1, "gone-1", &[("t", 0)]));
        let (reply, _) = apply_subscribe(&sub, &shared).await;
        reply.expect("subscribe replies");

        let mut unbind_meta = vec![0x00u8, 0x06u8];
        unbind_meta.extend_from_slice(b"gone-1");
        let unbind = BrokerFrame::new(
            OpCode::UnbindConnection,
            71,
            3,
            Bytes::from(unbind_meta),
            Bytes::new(),
        )
        .expect("valid unbind frame");
        apply_unbind(&unbind, &shared);

        let session = shared.sessions.get("gone-1").expect("session survives unbind");
        assert!(!*session.connected.read());
        assert_eq!(*session.conn_id.read(), None);
        // Durable subscriptions survive the detach.
        assert_eq!(
            shared.router.matches(&Topic::new("t").unwrap()).len(),
            1
        );
    }

    #[tokio::test]
    async fn subscribe_then_publish_routes_to_subscriber_transport() {
        let shared = Shared::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");

        // Accept exactly two edge connections sharing one kernel.
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.expect("accept");
                let shared = shared.clone();
                tokio::spawn(async move {
                    handle_connection(stream, shared).await.expect("handle");
                });
            }
            // Park until the test aborts us; handlers are independent tasks.
            std::future::pending::<()>().await;
        });

        // Subscriber: bind as conn 101, subscribe with a wildcard.
        let sub_io = tokio::net::TcpStream::connect(addr).await.expect("connect sub");
        let sub = FramedTransport::new(sub_io);
        sub.send(bind_frame(101, 1, encode_bind_meta("route-me", true, 60)))
            .await
            .expect("bind");
        let binding = sub.recv().await.expect("recv binding");
        assert_eq!(binding.header.opcode, OpCode::SessionBinding);
        sub.send(subscribe_frame(
            101,
            2,
            encode_subscribe_meta(11, "route-me", &[("sport/+", 1)]),
        ))
        .await
        .expect("subscribe");
        let suback = sub.recv().await.expect("recv suback");
        assert_eq!(suback.header.opcode, OpCode::SubAckOut);
        assert_eq!(&suback.metadata[0..2], &11u16.to_be_bytes());
        assert_eq!(&suback.metadata[2..], &[1u8]);

        // Publisher: bind as conn 102, publish QoS 1.
        let pub_io = tokio::net::TcpStream::connect(addr).await.expect("connect pub");
        let publ = FramedTransport::new(pub_io);
        publ.send(bind_frame(102, 1, encode_bind_meta("writer", true, 60)))
            .await
            .expect("bind");
        let _ = publ.recv().await.expect("recv binding");
        let (meta, payload) = encode_publish_meta("sport/tennis", 77, 1, false, b"match-point");
        publ.send(publish_frame(102, 2, meta, payload))
            .await
            .expect("publish");

        // Publisher gets its PubAck on its own transport.
        let ack = publ.recv().await.expect("recv puback");
        assert_eq!(ack.header.opcode, OpCode::PubAckOut);
        assert_eq!(ack.header.conn_id, 102);
        assert_eq!(&ack.metadata[..], &[0x00, 0x4D, 0x00]);

        // Subscriber gets the routed PublishOut on its own transport.
        let routed = sub.recv().await.expect("recv publish");
        assert_eq!(routed.header.opcode, OpCode::PublishOut);
        assert_eq!(routed.header.conn_id, 101);
        assert_eq!(routed.payload, Bytes::from_static(b"match-point"));
        let (topic, _, qos, _) = decode_publish_meta_parts(&routed.metadata);
        assert_eq!(topic, "sport/tennis");
        assert_eq!(qos, 1);

        server.abort();
    }

    #[tokio::test]
    async fn rule_republish_reaches_alert_subscriber() {
        use broker_rules::RuleAction;

        let shared = Shared::new();
        // Ingress rule: anything under sensors/+ is republished to
        // alerts/critical. No MQTT loopback involved: delivery flows
        // engine -> in-memory sink -> subscriber mailbox.
        shared.engine.create_rule(
            "republish-temp".to_string(),
            TopicFilter::new("sensors/+").unwrap(),
            None,
            true,
            vec![RuleAction::Republish {
                topic: Topic::new("alerts/critical").unwrap(),
                qos: QoS::AtMostOnce,
            }],
        )
        .expect("rule creates");

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.expect("accept");
                let shared = shared.clone();
                tokio::spawn(async move {
                    handle_connection(stream, shared).await.expect("handle");
                });
            }
            std::future::pending::<()>().await;
        });

        // Client A subscribes to alerts/critical as conn 301.
        let sub_io = tokio::net::TcpStream::connect(addr).await.expect("connect sub");
        let sub = FramedTransport::new(sub_io);
        sub.send(bind_frame(301, 1, encode_bind_meta("alert-watcher", true, 60)))
            .await
            .expect("bind");
        let _ = sub.recv().await.expect("recv binding");
        sub.send(subscribe_frame(
            301,
            2,
            encode_subscribe_meta(5, "alert-watcher", &[("alerts/critical", 1)]),
        ))
        .await
        .expect("subscribe");
        let suback = sub.recv().await.expect("recv suback");
        assert_eq!(suback.header.opcode, OpCode::SubAckOut);

        // Client B publishes to sensors/temperature as conn 302.
        let pub_io = tokio::net::TcpStream::connect(addr).await.expect("connect pub");
        let publ = FramedTransport::new(pub_io);
        publ.send(bind_frame(302, 1, encode_bind_meta("thermometer", true, 60)))
            .await
            .expect("bind");
        let _ = publ.recv().await.expect("recv binding");
        let (meta, payload) = encode_publish_meta("sensors/temperature", 0, 0, false, b"21.5C");
        publ.send(publish_frame(302, 2, meta, payload))
            .await
            .expect("publish");

        // Client A receives the rule-republished message with the
        // identical payload on its own transport.
        let routed = sub.recv().await.expect("recv republished");
        assert_eq!(routed.header.opcode, OpCode::PublishOut);
        assert_eq!(routed.header.conn_id, 301);
        assert_eq!(routed.payload, Bytes::from_static(b"21.5C"));
        let (topic, _, qos, _) = decode_publish_meta_parts(&routed.metadata);
        assert_eq!(topic, "alerts/critical");
        assert_eq!(qos, 0);

        server.abort();
    }

    #[tokio::test]
    async fn rule_sql_transforms_payload_end_to_end() {
        use broker_rules::RuleAction;

        let shared = Shared::new();
        // Streaming SQL rule: project only `temperature` out of raw
        // payloads. The secret field must never reach subscribers.
        shared
            .engine
            .create_rule(
                "project-temp".to_string(),
                TopicFilter::new("raw/+").unwrap(),
                Some(r#"SELECT temperature FROM "raw/temp" WHERE temperature > 0"#.to_string()),
                true,
                vec![RuleAction::Republish {
                    topic: Topic::new("transformed/temp").unwrap(),
                    qos: QoS::AtMostOnce,
                }],
            )
            .expect("SQL rule creates");

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.expect("accept");
                let shared = shared.clone();
                tokio::spawn(async move {
                    handle_connection(stream, shared).await.expect("handle");
                });
            }
            std::future::pending::<()>().await;
        });

        // Client A subscribes to transformed/temp as conn 401.
        let sub_io = tokio::net::TcpStream::connect(addr).await.expect("connect sub");
        let sub = FramedTransport::new(sub_io);
        sub.send(bind_frame(401, 1, encode_bind_meta("dashboard", true, 60)))
            .await
            .expect("bind");
        let _ = sub.recv().await.expect("recv binding");
        sub.send(subscribe_frame(
            401,
            2,
            encode_subscribe_meta(5, "dashboard", &[("transformed/temp", 1)]),
        ))
        .await
        .expect("subscribe");
        let suback = sub.recv().await.expect("recv suback");
        assert_eq!(suback.header.opcode, OpCode::SubAckOut);

        // Client B publishes a wide payload to raw/temp as conn 402.
        let pub_io = tokio::net::TcpStream::connect(addr).await.expect("connect pub");
        let publ = FramedTransport::new(pub_io);
        publ.send(bind_frame(402, 1, encode_bind_meta("sensor-9", true, 60)))
            .await
            .expect("bind");
        let _ = publ.recv().await.expect("recv binding");
        let raw = br#"{ "temperature": 85.0, "secret": "hide_me" }"#;
        let (meta, payload) = encode_publish_meta("raw/temp", 0, 0, false, raw);
        publ.send(publish_frame(402, 2, meta, payload))
            .await
            .expect("publish");

        // Client A receives only the projected field over its transport.
        let routed = sub.recv().await.expect("recv transformed");
        assert_eq!(routed.header.opcode, OpCode::PublishOut);
        assert_eq!(routed.header.conn_id, 401);
        let (topic, _, _, _) = decode_publish_meta_parts(&routed.metadata);
        assert_eq!(topic, "transformed/temp");
        let body: serde_json::Value =
            serde_json::from_slice(&routed.payload).expect("payload is JSON");
        assert_eq!(body, serde_json::json!({ "temperature": 85.0 }));

        server.abort();
    }

    async fn bind_client(
        addr: std::net::SocketAddr,
        conn_id: u64,
        client_id: &str,
        clean_start: bool,
    ) -> FramedTransport<tokio::net::TcpStream> {
        let io = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect client");
        let client = FramedTransport::new(io);
        client
            .send(bind_frame(
                conn_id,
                1,
                encode_bind_meta(client_id, clean_start, 60),
            ))
            .await
            .expect("bind");
        let binding = client.recv().await.expect("recv binding");
        assert_eq!(binding.header.opcode, OpCode::SessionBinding);
        client
    }

    #[tokio::test]
    async fn retained_message_delivered_to_late_subscriber() {
        let shared = Shared::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            for _ in 0..3 {
                let (stream, _) = listener.accept().await.expect("accept");
                let shared = shared.clone();
                tokio::spawn(async move {
                    handle_connection(stream, shared).await.expect("handle");
                });
            }
            std::future::pending::<()>().await;
        });

        // Client A publishes retained state before anyone subscribes.
        let publ = bind_client(addr, 501, "sensor-a", true).await;
        let (meta, payload) =
            encode_publish_meta("device/state", 0, 0, true, b"{ \"status\": \"online\" }");
        publ.send(publish_frame(501, 2, meta, payload))
            .await
            .expect("publish retained");

        // Client B connects later and subscribes with a wildcard.
        let sub = bind_client(addr, 502, "watcher-b", true).await;
        sub.send(subscribe_frame(
            502,
            2,
            encode_subscribe_meta(7, "watcher-b", &[("device/+", 0)]),
        ))
        .await
        .expect("subscribe");
        let suback = sub.recv().await.expect("recv suback");
        assert_eq!(suback.header.opcode, OpCode::SubAckOut);

        // The retained message follows the SUBACK immediately.
        let held = sub.recv().await.expect("recv retained");
        assert_eq!(held.header.opcode, OpCode::PublishOut);
        assert_eq!(held.header.conn_id, 502);
        assert_eq!(held.payload, Bytes::from_static(b"{ \"status\": \"online\" }"));
        let (topic, _, qos, retain) = decode_publish_meta_parts(&held.metadata);
        assert_eq!(topic, "device/state");
        assert_eq!(qos, 0);
        assert!(retain, "replayed retained message must carry retain = true");

        // Clearing with an empty retained publish removes the state.
        let (meta, payload) = encode_publish_meta("device/state", 0, 0, true, b"");
        publ.send(publish_frame(501, 3, meta, payload))
            .await
            .expect("clear retained");

        // A later subscriber gets its SUBACK but no retained message.
        let late = bind_client(addr, 503, "watcher-c", true).await;
        late
            .send(subscribe_frame(
                503,
                2,
                encode_subscribe_meta(8, "watcher-c", &[("device/+", 0)]),
            ))
            .await
            .expect("subscribe");
        let suback = late.recv().await.expect("recv suback");
        assert_eq!(suback.header.opcode, OpCode::SubAckOut);
        let nothing = tokio::time::timeout(std::time::Duration::from_millis(400), late.recv()).await;
        assert!(
            nothing.is_err(),
            "cleared retained state must not be delivered"
        );

        server.abort();
    }

    #[tokio::test]
    async fn offline_queue_replays_on_durable_reconnect() {
        let shared = Shared::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            for _ in 0..3 {
                let (stream, _) = listener.accept().await.expect("accept");
                let shared = shared.clone();
                tokio::spawn(async move {
                    handle_connection(stream, shared).await.expect("handle");
                });
            }
            std::future::pending::<()>().await;
        });

        // Client A connects durably and subscribes.
        let sub = bind_client(addr, 601, "worker-a", false).await;
        sub.send(subscribe_frame(
            601,
            2,
            encode_subscribe_meta(3, "worker-a", &[("job/queue", 1)]),
        ))
        .await
        .expect("subscribe");
        let suback = sub.recv().await.expect("recv suback");
        assert_eq!(suback.header.opcode, OpCode::SubAckOut);

        // Unclean disconnect: TCP drops without DISCONNECT. Give the
        // server a beat to detach the session before publishing.
        drop(sub);
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;

        // Client B publishes QoS 1 while A is detached.
        let publ = bind_client(addr, 602, "producer-b", true).await;
        let (meta, payload) = encode_publish_meta("job/queue", 9, 1, false, b"work-item");
        publ.send(publish_frame(602, 2, meta, payload))
            .await
            .expect("publish");
        let ack = publ.recv().await.expect("recv puback");
        assert_eq!(ack.header.opcode, OpCode::PubAckOut);

        // Client A reconnects durably on a new connection.
        let io = tokio::net::TcpStream::connect(addr)
            .await
            .expect("reconnect");
        let resumed = FramedTransport::new(io);
        resumed
            .send(bind_frame(603, 1, encode_bind_meta("worker-a", false, 60)))
            .await
            .expect("rebind");
        let binding = resumed.recv().await.expect("recv binding");
        assert_eq!(binding.header.opcode, OpCode::SessionBinding);
        let (_, present, rc) = decode_session_binding_meta(&binding.metadata);
        assert!(present, "resumed session must report session_present");
        assert_eq!(rc, 0);

        // The queued message replays onto the new connection.
        let replayed = resumed.recv().await.expect("recv replay");
        assert_eq!(replayed.header.opcode, OpCode::PublishOut);
        assert_eq!(replayed.header.conn_id, 603);
        assert_eq!(replayed.payload, Bytes::from_static(b"work-item"));
        let (topic, packet_id, qos, _) = decode_publish_meta_parts(&replayed.metadata);
        assert_eq!(topic, "job/queue");
        assert_eq!(qos, 1);
        assert_ne!(packet_id, 0, "replayed QoS 1 needs a fresh packet id");

        server.abort();
    }

    #[tokio::test]
    async fn cluster_forwards_publish_to_subscribed_node() {
        use broker_cluster::{ChannelRoutingPlane, NodeId};

        // Two nodes meshed over in-process channels.
        let plane1 = ChannelRoutingPlane::new(NodeId::new("node-1"));
        let plane2 = ChannelRoutingPlane::new(NodeId::new("node-2"));
        ChannelRoutingPlane::link(&plane1, &plane2);

        let mut shared1 = Shared::new();
        shared1.cluster = Some(plane1.clone() as Arc<dyn RoutingPlane>);
        let mut shared2 = Shared::new();
        shared2.cluster = Some(plane2.clone() as Arc<dyn RoutingPlane>);

        // One BrokerLink listener + one inbox pump per node.
        async fn serve_one(
            shared: Shared,
        ) -> (
            std::net::SocketAddr,
            Vec<tokio::task::JoinHandle<()>>,
        ) {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("local addr");
            let accept = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.expect("accept");
                handle_connection(stream, shared).await.expect("handle");
            });
            (addr, vec![accept])
        }
        let (addr1, mut tasks) = serve_one(shared1.clone()).await;
        let (addr2, mut tasks2) = serve_one(shared2.clone()).await;
        tasks.push(tokio::spawn(run_cluster_inbox(shared1)));
        tasks2.push(tokio::spawn(run_cluster_inbox(shared2)));

        // Client A subscribes to metrics/# on node 1 as conn 701.
        let sub = bind_client(addr1, 701, "metrics-fan", true).await;
        sub.send(subscribe_frame(
            701,
            2,
            encode_subscribe_meta(3, "metrics-fan", &[("metrics/#", 1)]),
        ))
        .await
        .expect("subscribe");
        let suback = sub.recv().await.expect("recv suback");
        assert_eq!(suback.header.opcode, OpCode::SubAckOut);

        // Client B publishes to metrics/cpu on node 2 as conn 702.
        let publ = bind_client(addr2, 702, "cpu-sensor", true).await;
        let (meta, payload) = encode_publish_meta("metrics/cpu", 0, 0, false, b"42");
        publ.send(publish_frame(702, 2, meta, payload))
            .await
            .expect("publish");

        // Client A receives the single cross-node forward.
        let routed = sub.recv().await.expect("recv forwarded");
        assert_eq!(routed.header.opcode, OpCode::PublishOut);
        assert_eq!(routed.header.conn_id, 701);
        assert_eq!(routed.payload, Bytes::from_static(b"42"));
        let (topic, _, qos, _) = decode_publish_meta_parts(&routed.metadata);
        assert_eq!(topic, "metrics/cpu");
        assert_eq!(qos, 0);

        // A topic nobody subscribes to is not forwarded: silence proves
        // both no-match suppression and no duplicate delivery.
        let (meta, payload) = encode_publish_meta("unrelated/foo", 0, 0, false, b"zzz");
        publ.send(publish_frame(702, 3, meta, payload))
            .await
            .expect("publish unrelated");
        let silence = tokio::time::timeout(std::time::Duration::from_millis(400), sub.recv()).await;
        assert!(silence.is_err(), "unmatched topics must not cross nodes");

        for task in tasks.into_iter().chain(tasks2) {
            task.abort();
        }
    }

    async fn http_get_text(port: u16, path: &str) -> (u16, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect api");
        let req = format!("GET {path} HTTP/1.0\r\nHost: test\r\nConnection: close\r\n\r\n");
        stream.write_all(req.as_bytes()).await.expect("write api request");
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.expect("read api response");
        let text = String::from_utf8(buf).expect("api response is UTF-8");
        let (head, body) = text.split_once("\r\n\r\n").expect("header/body split");
        let status: u16 = head.lines().next().expect("status line")[9..12]
            .parse()
            .expect("status code");
        (status, body.to_string())
    }

    #[tokio::test]
    async fn api_serves_embedded_dashboard() {
        let shared = Shared::new();
        let api_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind api");
        let api_port = api_listener.local_addr().expect("api addr").port();
        let api_task = tokio::spawn(serve_api(api_listener, shared));

        // Root redirects to the console.
        let (status, _) = http_get_text(api_port, "/").await;
        assert_eq!(status, 303);

        // The console shell loads with its key regions.
        let (status, html) = http_get_text(api_port, "/dashboard").await;
        assert_eq!(status, 200);
        for marker in [
            "<title>IndraMQTT Console</title>",
            "Community Edition (MIT)",
            "id=\"metrics\"",
            "id=\"sql-studio\"",
            "id=\"console\"",
            "/ws/mqtt",
        ] {
            assert!(html.contains(marker), "dashboard missing {marker}");
        }

        api_task.abort();
    }

    #[tokio::test]
    async fn api_metrics_reflect_edge_traffic() {
        let shared = Shared::new();

        // Management API on an ephemeral port, sharing node state.
        let api_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind api");
        let api_port = api_listener.local_addr().expect("api addr").port();
        let api_task = tokio::spawn(serve_api(api_listener, shared.clone()));

        // One edge connection: bind, subscribe, publish.
        let bl_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let bl_addr = bl_listener.local_addr().expect("local addr");
        let edge_task = tokio::spawn(async move {
            let (stream, _) = bl_listener.accept().await.expect("accept");
            handle_connection(stream, shared).await.expect("handle");
        });

        let client = bind_client(bl_addr, 801, "metrics-probe", true).await;
        client
            .send(subscribe_frame(
                801,
                2,
                encode_subscribe_meta(3, "metrics-probe", &[("m/+", 0)]),
            ))
            .await
            .expect("subscribe");
        let suback = client.recv().await.expect("recv suback");
        assert_eq!(suback.header.opcode, OpCode::SubAckOut);
        let (meta, payload) = encode_publish_meta("m/1", 0, 0, false, b"x");
        client
            .send(publish_frame(801, 3, meta, payload))
            .await
            .expect("publish");
        // Drain our own delivery so the mailbox cannot back up the test.
        let delivered = client.recv().await.expect("recv delivery");
        assert_eq!(delivered.header.opcode, OpCode::PublishOut);

        let (status, body) = http_get_text(api_port, "/api/v1/metrics").await;
        assert_eq!(status, 200);
        assert!(body.contains("indramqtt_messages_received_total 1\n"));
        assert!(body.contains("indramqtt_messages_forwarded_total 1\n"));
        assert!(body.contains("indramqtt_connections_active 1\n"));

        let (status, body) = http_get_text(api_port, "/api/v1/clients").await;
        assert_eq!(status, 200);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).expect("clients is JSON"),
            serde_json::json!(["metrics-probe"])
        );

        edge_task.abort();
        api_task.abort();
    }

    #[tokio::test]
    async fn bind_auth_rejects_bad_password_with_0x86() {
        let shared = test_shared();
        shared.auth.add_user("alice", b"s3cret");

        let frame = bind_frame(
            81,
            1,
            encode_bind_meta_creds("dev-x", true, 60, "alice", b"wrong"),
        );
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        assert_eq!(reply.header.opcode, OpCode::SessionBinding);
        let (_, present, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0x86, "bad password must yield return code 0x86");
        assert!(!present);
        // Failed binds create no session.
        assert!(shared.sessions.get("dev-x").is_none());
    }

    #[tokio::test]
    async fn bind_auth_accepts_valid_and_anonymous() {
        let shared = test_shared();
        shared.auth.add_user("alice", b"s3cret");

        let frame = bind_frame(
            82,
            1,
            encode_bind_meta_creds("dev-y", true, 60, "alice", b"s3cret"),
        );
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        let (_, _, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0);

        // Anonymous binds stay open even with users configured.
        let frame = bind_frame(83, 1, encode_bind_meta("dev-z", true, 60));
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        let (_, _, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0);
    }

    #[tokio::test]
    async fn bind_quota_overage_returns_0x8b() {
        use broker_auth::UserQuotas;

        let shared = test_shared();
        shared.auth.add_user("capped-user", b"pw");
        assert!(shared.auth.set_quotas(
            "capped-user",
            UserQuotas {
                max_connections: Some(1),
                max_publish_rate: None,
                max_publish_burst: None,
            }
        ));

        // First connection admitted.
        let frame = bind_frame(
            84,
            1,
            encode_bind_meta_creds("dev-one", true, 60, "capped-user", b"pw"),
        );
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        let (_, _, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0);

        // Second concurrent connection for the same user: quota exceeded.
        let frame = bind_frame(
            85,
            1,
            encode_bind_meta_creds("dev-two", true, 60, "capped-user", b"pw"),
        );
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        let (_, present, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0x8B, "overage must yield return code 0x8B");
        assert!(!present);
        assert!(shared.sessions.get("dev-two").is_none());

        // Takeover by the same client reuses its slot instead of denying.
        let frame = bind_frame(
            86,
            1,
            encode_bind_meta_creds("dev-one", true, 60, "capped-user", b"pw"),
        );
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        let (_, _, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0);

        // The orphaned first connection detaching afterwards releases
        // nothing (ownership check): the retaken slot stays held.
        shared.sessions.unbind_connection("dev-one", 84);
        let frame = bind_frame(
            87,
            1,
            encode_bind_meta_creds("dev-three", true, 60, "capped-user", b"pw"),
        );
        let reply = apply_bind(&frame, &shared).await.expect("bind replies");
        let (_, _, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0x8B, "slot still held after orphan detach");
    }

    #[tokio::test]
    async fn publish_rate_overage_returns_0x97_and_drops() {
        use broker_auth::UserQuotas;

        let shared = test_shared();
        shared.auth.add_user("fast-user", b"pw");
        assert!(shared.auth.set_quotas(
            "fast-user",
            UserQuotas {
                max_connections: None,
                max_publish_rate: Some(2),
                max_publish_burst: Some(2),
            }
        ));

        // Subscriber soaks up whatever routes (proves the drop below).
        let (listener, _) = shared.sessions.get_or_create("sink", true);
        *listener.conn_id.write() = Some(96);
        let sub = subscribe_frame(96, 1, encode_subscribe_meta(1, "sink", &[("t/rate", 0)]));
        let (reply, _) = apply_subscribe(&sub, &shared).await;
        reply.expect("subscribe replies");

        // Publisher session owned by the capped user.
        let (publ, _) = shared.sessions.get_or_create("throttled", true);
        *publ.conn_id.write() = Some(97);
        *publ.username.write() = Some("fast-user".to_string());

        // Burst of 2 routes; the immediate third is over quota.
        for seq in 2..=3u64 {
            let (meta, payload) = encode_publish_meta("t/rate", seq as u16, 1, false, b"x");
            let (ack, deliveries) =
                apply_publish(&publish_frame(97, seq, meta, payload), &shared).await;
            assert!(ack.is_some());
            assert_eq!(deliveries.len(), 1, "burst publishes must route");
        }
        let (meta, payload) = encode_publish_meta("t/rate", 4, 1, false, b"x");
        let (ack, deliveries) =
            apply_publish(&publish_frame(97, 4, meta, payload), &shared).await;
        let ack = ack.expect("QoS 1 over-rate still gets a PubAck");
        assert_eq!(&ack.metadata[..], &[0x00, 0x04, 0x97u8]);
        assert!(deliveries.is_empty(), "over-rate publish must not fan out");

        // QoS 0 over-rate drops silently but counts.
        let (meta, payload) = encode_publish_meta("t/rate", 0, 0, false, b"x");
        let (ack, deliveries) =
            apply_publish(&publish_frame(97, 5, meta, payload), &shared).await;
        assert!(ack.is_none());
        assert!(deliveries.is_empty());
        // Both over-rate drops counted (QoS 1 above + this QoS 0).
        assert_eq!(shared.metrics.messages_dropped(), 2);
    }

    #[tokio::test]
    async fn subscribe_denied_yields_0x87_without_routing() {
        let shared = test_shared();
        shared
            .auth
            .add_rule(AclRule::new("boxed", AclAction::All, "#", false));

        let frame = subscribe_frame(91, 1, encode_subscribe_meta(1, "boxed", &[("t", 0)]));
        let (reply, retained) = apply_subscribe(&frame, &shared).await;
        let reply = reply.expect("suback replies");
        assert_eq!(&reply.metadata[2..], &[0x87u8]);
        assert!(retained.is_empty());
        // Denied subscriptions register nothing.
        assert!(shared.router.matches(&Topic::new("t").unwrap()).is_empty());
    }

    #[tokio::test]
    async fn publish_denied_yields_puback_0x87_and_drops() {
        let shared = test_shared();
        // A live listener proves the drop: it would receive otherwise.
        let (listener, _) = shared.sessions.get_or_create("listener", true);
        *listener.conn_id.write() = Some(93);
        let sub = subscribe_frame(93, 1, encode_subscribe_meta(1, "listener", &[("t", 0)]));
        let (reply, _) = apply_subscribe(&sub, &shared).await;
        reply.expect("subscribe replies");

        let (muted, _) = shared.sessions.get_or_create("muted", true);
        *muted.conn_id.write() = Some(92);
        shared
            .auth
            .add_rule(AclRule::new("muted", AclAction::Publish, "#", false));

        let (meta, payload) = encode_publish_meta("t", 5, 1, false, b"shh");
        let (ack, deliveries) =
            apply_publish(&publish_frame(92, 1, meta, payload), &shared).await;
        let ack = ack.expect("QoS 1 denied publish still gets a PubAck");
        assert_eq!(&ack.metadata[..], &[0x00, 0x05, 0x87u8]);
        assert!(deliveries.is_empty(), "denied publish must not fan out");
    }

    #[tokio::test]
    async fn bind_auth_failure_over_tcp_returns_0x86() {
        let shared = Shared::new();
        shared.auth.add_user("alice", b"s3cret");

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            handle_connection(stream, shared).await.expect("handle");
        });

        // Wrong password over a real transport: 0x86, no session.
        let io = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let client = FramedTransport::new(io);
        client
            .send(bind_frame(
                84,
                1,
                encode_bind_meta_creds("dev-bad", true, 60, "alice", b"nope"),
            ))
            .await
            .expect("bind");
        let reply = client.recv().await.expect("recv binding");
        assert_eq!(reply.header.opcode, OpCode::SessionBinding);
        let (_, present, rc) = decode_session_binding_meta(&reply.metadata);
        assert_eq!(rc, 0x86);
        assert!(!present);

        server.abort();
    }

    #[tokio::test]
    async fn shared_subscriptions_balance_across_workers() {
        let shared = Shared::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            for _ in 0..4 {
                let (stream, _) = listener.accept().await.expect("accept");
                let shared = shared.clone();
                tokio::spawn(async move {
                    handle_connection(stream, shared).await.expect("handle");
                });
            }
            std::future::pending::<()>().await;
        });

        // Two workers share one group; one plain subscriber listens too.
        let worker_a = bind_client(addr, 711, "worker-a", true).await;
        worker_a
            .send(subscribe_frame(
                711,
                2,
                encode_subscribe_meta(1, "worker-a", &[("$share/pool/work/jobs", 0)]),
            ))
            .await
            .expect("subscribe a");
        assert_eq!(worker_a.recv().await.expect("suback a").header.opcode, OpCode::SubAckOut);

        let worker_b = bind_client(addr, 712, "worker-b", true).await;
        worker_b
            .send(subscribe_frame(
                712,
                2,
                encode_subscribe_meta(1, "worker-b", &[("$share/pool/work/jobs", 0)]),
            ))
            .await
            .expect("subscribe b");
        assert_eq!(worker_b.recv().await.expect("suback b").header.opcode, OpCode::SubAckOut);

        let plain = bind_client(addr, 713, "plain-c", true).await;
        plain
            .send(subscribe_frame(
                713,
                2,
                encode_subscribe_meta(1, "plain-c", &[("work/jobs", 0)]),
            ))
            .await
            .expect("subscribe c");
        assert_eq!(plain.recv().await.expect("suback c").header.opcode, OpCode::SubAckOut);

        // Publisher emits two jobs.
        let publ = bind_client(addr, 714, "producer", true).await;
        for (seq, job) in [(3u64, "job-1"), (4u64, "job-2")] {
            let (meta, payload) = encode_publish_meta("work/jobs", 0, 0, false, job.as_bytes());
            publ.send(publish_frame(714, seq, meta, payload))
                .await
                .expect("publish job");
        }

        // Deterministic round-robin (members sort by client id): job-1
        // goes to worker-a, job-2 to worker-b, exactly one each.
        let first_a = worker_a.recv().await.expect("worker-a delivery");
        assert_eq!(first_a.header.conn_id, 711);
        assert_eq!(first_a.payload, Bytes::from_static(b"job-1"));
        let first_b = worker_b.recv().await.expect("worker-b delivery");
        assert_eq!(first_b.header.conn_id, 712);
        assert_eq!(first_b.payload, Bytes::from_static(b"job-2"));
        for (worker, name) in [(&worker_a, "a"), (&worker_b, "b")] {
            let extra =
                tokio::time::timeout(std::time::Duration::from_millis(300), worker.recv()).await;
            assert!(extra.is_err(), "worker {name} must receive exactly one job");
        }

        // The plain subscriber still gets the full fan-out: both jobs.
        for expected in [b"job-1".as_slice(), b"job-2".as_slice()] {
            let got = plain.recv().await.expect("plain delivery");
            assert_eq!(got.header.conn_id, 713);
            assert_eq!(got.payload, Bytes::from(expected));
        }

        server.abort();
    }

    #[tokio::test]
    async fn rule_sql_forwards_to_http_webhook() {
        use broker_connectors::HttpWebhookSink;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Minimal HTTP capture endpoint over raw TCP (keeps broker-node
        // free of HTTP server deps): records one POST body, answers 200.
        let hook_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind hook");
        let hook_port = hook_listener.local_addr().expect("addr").port();
        let captured: Arc<parking_lot::Mutex<Option<Vec<u8>>>> =
            Arc::new(parking_lot::Mutex::new(None));
        let captured_rx = captured.clone();
        let hook_task = tokio::spawn(async move {
            let (mut stream, _) = hook_listener.accept().await.expect("accept hook");
            let mut buf = Vec::new();
            loop {
                let mut chunk = [0u8; 1024];
                let n = stream.read(&mut chunk).await.expect("read head");
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let head_end = buf
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .expect("request head")
                + 4;
            let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
            let mut content_length = 0usize;
            for line in head.lines() {
                if let Some((key, value)) = line.split_once(':') {
                    if key.trim().eq_ignore_ascii_case("content-length") {
                        content_length = value.trim().parse().unwrap_or(0);
                    }
                }
            }
            while buf.len() < head_end + content_length {
                let mut chunk = [0u8; 1024];
                let n = stream.read(&mut chunk).await.expect("read body");
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            *captured_rx.lock() =
                Some(buf[head_end..head_end + content_length].to_vec());
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .expect("write hook response");
        });

        let shared = Shared::new();
        // Rule projects telemetry and forwards to the webhook sink: no
        // MQTT subscribers are involved at all.
        let sink = Arc::new(HttpWebhookSink::new(
            format!("http://127.0.0.1:{hook_port}/hook"),
            reqwest::header::HeaderMap::new(),
            reqwest::Client::new(),
        ));
        shared.engine.connectors().register("webhook-1", sink);
        shared
            .engine
            .create_rule(
                "telemetry-webhook".to_string(),
                TopicFilter::new("sensors/+").unwrap(),
                Some(
                    r#"SELECT temperature FROM "sensors/+" WHERE temperature > 0"#.to_string(),
                ),
                true,
                vec![broker_rules::RuleAction::ForwardConnector {
                    connector_id: "webhook-1".to_string(),
                }],
            )
            .expect("rule creates");

        // Edge client publishes wide telemetry as conn 901.
        let bl_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let bl_addr = bl_listener.local_addr().expect("local addr");
        let edge_task = tokio::spawn(async move {
            let (stream, _) = bl_listener.accept().await.expect("accept");
            handle_connection(stream, shared).await.expect("handle");
        });
        let publ = bind_client(bl_addr, 901, "sensor-x", true).await;
        let raw = br#"{ "temperature": 85.0, "secret": "hide_me" }"#;
        let (meta, payload) = encode_publish_meta("sensors/kitchen", 0, 0, false, raw);
        publ.send(publish_frame(901, 2, meta, payload))
            .await
            .expect("publish");

        // The webhook receives exactly the projected JSON.
        tokio::time::timeout(std::time::Duration::from_secs(5), hook_task)
            .await
            .expect("webhook fired")
            .expect("hook task");
        let body = captured.lock().clone().expect("captured body");
        let json: serde_json::Value =
            serde_json::from_slice(&body).expect("webhook body is JSON");
        assert_eq!(json, serde_json::json!({ "temperature": 85.0 }));

        edge_task.abort();
    }

    /// Drive one delayed publish through `apply_publish` with a live
    /// mailbox registered, returning the immediate reply.
    async fn delayed_setup(
        shared: &Shared,
    ) -> (
        tokio::sync::mpsc::UnboundedReceiver<BrokerFrame>,
        Option<BrokerFrame>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        shared.conns.register(951, tx);
        let (session, _) = shared.sessions.get_or_create("delayed-sub", true);
        *session.conn_id.write() = Some(951);
        let sub = subscribe_frame(951, 1, encode_subscribe_meta(1, "delayed-sub", &[("alerts", 0)]));
        let (reply, _) = apply_subscribe(&sub, shared).await;
        reply.expect("subscribe replies");
        let (meta, payload) = encode_publish_meta("$delayed/1/alerts", 0, 0, false, b"later");
        let ack = apply_publish(&publish_frame(952, 1, meta, payload), shared).await;
        (rx, ack.0)
    }

    #[tokio::test]
    async fn delayed_publish_defers_delivery_by_one_second() {
        let shared = test_shared();
        let start = std::time::Instant::now();
        let (mut rx, ack) = delayed_setup(&shared).await;
        // QoS 0: no ack, and crucially no immediate delivery.
        assert!(ack.is_none());
        let early = tokio::time::timeout(std::time::Duration::from_millis(300), rx.recv()).await;
        assert!(early.is_err(), "delayed message must not arrive early");

        // ...but it arrives after the delay with the inner topic.
        let routed = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .expect("delivery fires")
            .expect("mailbox open");
        assert_eq!(routed.header.opcode, OpCode::PublishOut);
        assert!(start.elapsed() >= std::time::Duration::from_millis(900));
        let (topic, _, _, _) = decode_publish_meta_parts(&routed.metadata);
        assert_eq!(topic, "alerts");
        assert_eq!(routed.payload, Bytes::from_static(b"later"));
    }

    #[tokio::test]
    async fn delayed_publish_rejects_garbage() {
        let shared = test_shared();
        // Non-numeric delay is not a delayed target at all: it publishes
        // literally (no subscribers exist for it here).
        let (meta, payload) = encode_publish_meta("$delayed/soon/t", 0, 0, false, b"x");
        let (ack, deliveries) =
            apply_publish(&publish_frame(953, 1, meta, payload), &shared).await;
        assert!(ack.is_none());
        assert!(deliveries.is_empty());

        // Absurd delays are dropped, not scheduled.
        let (meta, payload) =
            encode_publish_meta("$delayed/99999999/t", 0, 0, false, b"x");
        let (ack, deliveries) =
            apply_publish(&publish_frame(953, 2, meta, payload), &shared).await;
        assert!(ack.is_none());
        assert!(deliveries.is_empty());

        // Delayed markers are not subscribable.
        let sub = subscribe_frame(
            954,
            1,
            encode_subscribe_meta(1, "c", &[("$delayed/1/t", 0)]),
        );
        let (reply, _) = apply_subscribe(&sub, &shared).await;
        let reply = reply.expect("suback replies");
        assert_eq!(&reply.metadata[2..], &[0x80u8]);
    }

    #[tokio::test]
    async fn delayed_publish_end_to_end_over_tcp() {
        let shared = Shared::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.expect("accept");
                let shared = shared.clone();
                tokio::spawn(async move {
                    handle_connection(stream, shared).await.expect("handle");
                });
            }
            std::future::pending::<()>().await;
        });

        let sub = bind_client(addr, 961, "patient", true).await;
        sub.send(subscribe_frame(
            961,
            2,
            encode_subscribe_meta(4, "patient", &[("alerts", 0)]),
        ))
        .await
        .expect("subscribe");
        assert_eq!(sub.recv().await.expect("suback").header.opcode, OpCode::SubAckOut);

        let publ = bind_client(addr, 962, "procrastinator", true).await;
        let start = std::time::Instant::now();
        let (meta, payload) = encode_publish_meta("$delayed/1/alerts", 0, 0, false, b"finally");
        publ.send(publish_frame(962, 2, meta, payload))
            .await
            .expect("publish delayed");

        let routed = sub.recv().await.expect("recv delayed");
        assert_eq!(routed.header.opcode, OpCode::PublishOut);
        assert_eq!(routed.header.conn_id, 961);
        assert_eq!(routed.payload, Bytes::from_static(b"finally"));
        let (topic, _, _, _) = decode_publish_meta_parts(&routed.metadata);
        assert_eq!(topic, "alerts");
        assert!(
            start.elapsed() >= std::time::Duration::from_millis(900),
            "delivery must honor the 1s delay"
        );

        server.abort();
    }

    #[tokio::test]
    async fn shared_wires_broker_sink_into_engine() {
        // INDRA-213: window-flush republish actions resolve through the
        // same in-memory sink as inline dispatch (no loopback).
        let shared = Shared::new();
        assert!(
            shared.engine.broker_sink().is_some(),
            "Shared::new must install the flush sink"
        );
    }
}
