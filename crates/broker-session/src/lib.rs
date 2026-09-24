use broker_protocol::v5 as protocol_v5;
use broker_protocol::{QoS, Topic, TopicFilter};
use broker_storage::{OfflineQueueStore, OfflineRecord};
use bytes::Bytes;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub u64);

/// Granted subscription options mirrored on the session for the
/// management API. `qos` is the granted QoS; `nl`, `rap` and `rh` are
/// the subscription options from the SUBSCRIBE entry (all default to 0
/// for live MQTT and legacy callers that only carry a QoS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubscriptionOptions {
    pub qos: QoS,
    pub nl: u8,
    pub rap: u8,
    pub rh: u8,
}

impl SubscriptionOptions {
    pub fn new(qos: QoS, nl: u8, rap: u8, rh: u8) -> Self {
        Self { qos, nl, rap, rh }
    }
}

impl From<QoS> for SubscriptionOptions {
    fn from(qos: QoS) -> Self {
        Self {
            qos,
            nl: 0,
            rap: 0,
            rh: 0,
        }
    }
}

/// One client's last will (F1-01): published by the kernel when the
/// edge reports an ungraceful close (`DisconnectIn`), suppressed on a
/// clean `DISCONNECT` (unbind). Stored on the session because the session
/// is where the decision lives; the edge only detects the close.
///
/// Bound: one will per session; the topic is an MQTT string (<= 65535
/// bytes) and the payload rides the BrokerLink bind meta (<= 65535 bytes
/// of meta incl. topic and payload). Per-session will memory is therefore
/// bounded near 128 KiB by the wire limit, with no new config needed.
#[derive(Debug, Clone)]
pub struct StoredWill {
    pub topic: Topic,
    pub qos: QoS,
    pub retain: bool,
    pub payload: Bytes,
}

#[derive(Debug)]
pub struct Session {
    pub id: SessionId,
    pub client_id: String,
    pub clean_start: bool,
    pub connected: RwLock<bool>,
    pub conn_id: RwLock<Option<u64>>,
    pub subscriptions: RwLock<HashMap<TopicFilter, SubscriptionOptions>>,
    pub offline_queue: RwLock<VecDeque<QueuedMessage>>,
    /// Durable backing for the offline queue (B4-06, T-93). `None` (unit
    /// tests, stores never installed) keeps the previous memory-only
    /// behaviour exactly. `Some` (kernel boot with a data directory)
    /// write-throughs every buffered message to the per-client queue file
    /// before it enters the memory queue, truncates the file on drain,
    /// and rewrites it from the surviving snapshot on eviction. Cloned
    /// from the manager at session creation and on
    /// [`SessionManager::set_offline_store`]; read once per buffer/drain
    /// (one short lock, never held across file I/O or the queue lock).
    offline_store: RwLock<Option<Arc<OfflineQueueStore>>>,
    /// Serializes this session's durable queue file mutations (append,
    /// eviction rewrite, drain delete, confirm rewrite). Held across the
    /// file append, the memory push and any eviction rewrite so concurrent
    /// buffers for the same detached client keep file order equal to queue
    /// order; the queue lock itself is taken only for the memory section
    /// in between, never across file I/O, so queue readers never wait for
    /// an fsync. One mutex per session, detached-buffer path only; live
    /// deliveries to connected sessions never touch it or a file.
    offline_persist: std::sync::Mutex<()>,
    /// QoS 1 downlinks written toward the subscriber and not yet
    /// acknowledged (T-31). Held in delivery order so reconnect replay
    /// resends oldest-first with DUP set. Bounded per session by the
    /// configurable window ([`Session::max_inflight`], default
    /// [`DEFAULT_MAX_QOS1_INFLIGHT`]); the kernel (not the edge) owns
    /// this state.
    pub inflight: RwLock<VecDeque<InflightMessage>>,
    /// QoS 1 overflow beyond the in-memory window (B4-01). Entries are
    /// still delivered live once and ARE tracked here for redelivery, in
    /// arrival order, so reconnect replay resends window oldest-first
    /// then spill oldest-first, every entry with DUP set and its original
    /// packet id. Bounded per session by [`Session::max_spill`] (default
    /// [`DEFAULT_MAX_QOS1_SPILL`]); past it the newest downlink is
    /// delivered live once but left untracked (counted). Lock order is
    /// always `inflight` then `inflight_spill`; the fast publish path
    /// takes only the `inflight` lock and touches this deque solely on
    /// window overflow. The kernel (not the edge) owns this state.
    /// TODO(parity): coordinate spill backing with the durable offline
    /// queue once B4-06 lands (disk-backed replay surviving a restart);
    /// today spill is memory-backed and lost on restart like the window.
    pub inflight_spill: RwLock<VecDeque<InflightMessage>>,
    /// Lock-free fast-path guard for the spill buffer (B4-01 hot-path
    /// fix). Mirrors `inflight_spill.len()`: 0 means the spill is empty,
    /// so the publish fast path (within-window track), `next_packet_id`,
    /// the ack fast path (empty spill, no promotion) and reconnect replay
    /// skip the spill lock/scan/snapshot allocation entirely with one
    /// relaxed atomic load. Steady-state lock/alloc counts (spill empty,
    /// unchanged from before B4-01 except one atomic load): publish
    /// within window 1 atomic load + 1 write lock; `next_packet_id` 2
    /// read locks + 1 atomic load (no spill lock); ack of a window entry
    /// 1 write lock + 1 atomic load (no nested spill lock); replay with
    /// empty spill 1 window snapshot alloc (no spill snapshot alloc).
    /// Overflow/promotion/replay paths take the spill lock and do bounded
    /// deque work only when spill is non-empty (slow path: spill id scan
    /// is O(spill) with spill <= max_spill, ack promotion pops one entry,
    /// replay adds one spill snapshot alloc plus one frame alloc per
    /// spilled message). Before/after store throughputs (legacy
    /// `track_inflight` baseline vs spill-aware steady state, plus the
    /// spill-nonempty slow path) are printed by
    /// `test_qos1_inflight_hot_path_timings` into the gate output (no
    /// threshold asserts; the numbers are the measurement); broker
    /// publish-to-delivery before/after numbers are printed by
    /// `qos1_inflight_delivery_workload_timings` in broker-node.
    /// Maintained under the spill write lock wherever the deque mutates.
    spill_count: AtomicUsize,
    /// Configurable per-session QoS 1 window bound (B4-01). Read with one
    /// relaxed atomic load on the publish fast path; writes happen only
    /// via management/boot configuration, never per message.
    max_inflight: AtomicUsize,
    /// Configurable per-session QoS 1 spill bound (B4-01). Read only on
    /// window overflow (slow path), never on the fast path.
    max_spill: AtomicUsize,
    /// QoS 2 inbound publishes held between PUBLISH and PUBREL (D1-01).
    /// Keyed by the publisher's packet id so a repeat of the same id
    /// before PUBREL is recognised as a duplicate (PUBREC again, no
    /// second route). Bounded by [`MAX_QOS2_INBOUND`]; the kernel owns
    /// this state behind the same per-session lock family QoS 1 uses,
    /// never on the QoS 0 path.
    pub qos2_inbound: RwLock<HashMap<u16, Qos2InboundEntry>>,
    /// QoS 2 downlinks written toward the subscriber and not yet
    /// completed (D1-01). Held in delivery order so reconnect replay
    /// resends oldest-first. `rec_received` is false while waiting for
    /// PUBREC (message retained) and true while waiting for PUBCOMP
    /// (packet id retained, payload dropped). Bounded by
    /// [`MAX_QOS2_INFLIGHT`]; the kernel owns this state.
    pub qos2_outbound: RwLock<VecDeque<Qos2OutboundEntry>>,
    /// Inbound topic-alias table (B4-05, T-92): `alias -> topic` for
    /// publishes the client sends with an alias. Index 0 is always
    /// `None` (alias 0 is never valid); once an alias-carrying publish
    /// arrives the vector is sized to `max + 1`, so lookup is a bounded
    /// index with no per-message allocation on the hot path (alias 0
    /// returns before taking any lock, and publishes carrying no alias
    /// never touch this table). Until the first such publish the table
    /// stays empty, so connections that never use aliases pay no alias
    /// allocation. Owned by the kernel (this session); written on the
    /// PUBLISH event, bounded by [`Session::inbound_alias_max`]. The edge
    /// decodes the MQTT 5 alias properties (34/35) on the socket and
    /// forwards them in the BrokerLink publish meta; the kernel owns
    /// this table and writes it on the PUBLISH event.
    pub inbound_aliases: RwLock<Vec<Option<Topic>>>,
    /// Maximum alias the client may use (B4-05). Advertised in CONNACK;
    /// written on the CONNECT event from the manager default.
    inbound_alias_max: AtomicU16,
    /// Outbound topic-alias table (B4-05, T-92): `alias -> topic` for
    /// deliveries the kernel sends with an alias. Same layout and cost
    /// as the inbound table; reuse is a bounded linear scan
    /// (<= max entries, no map, no per-message allocation) so the table
    /// is reused rather than grown per message. Owned by the kernel
    /// (this session); written on the delivery event, bounded by
    /// [`Session::outbound_alias_max`].
    pub outbound_aliases: RwLock<Vec<Option<Topic>>>,
    /// Maximum alias the kernel may use toward the client (B4-05).
    /// Received in CONNECT; written on the CONNECT event. Zero means the
    /// client sent no maximum and the kernel never assigns an alias.
    outbound_alias_max: AtomicU16,
    /// MQTT keepalive seconds from CONNECT (0 = disabled). Maintained by
    /// the edge at bind time; surfaced read-only for observability.
    pub keepalive_secs: RwLock<u16>,
    /// Last will from CONNECT, if the client registered one. Written on
    /// the CONNECT (bind) event, consumed exactly once on disconnect:
    /// `DisconnectIn` takes and publishes it, `UnbindConnection` takes
    /// and drops it (clean `DISCONNECT` suppresses the will). The take is
    /// atomic, so an edge notice racing a kernel notice publishes once.
    /// Disconnect-path only (bind/disconnect events); the publish and
    /// delivery hot paths never touch this lock.
    /// TODO(parity): a transport-death detach preserves the will for a
    /// later rebind but never fires it, so a will is lost when the edge
    /// itself dies without sending `DisconnectIn`. The rulebook does not
    /// decide the transport-death policy; current choice avoids spurious
    /// publishes while the edge may still hold the socket.
    pub last_will: RwLock<Option<StoredWill>>,
    /// Authenticated username that owns this session, if any. Maintained
    /// by the edge at bind time; drives per-user quota accounting.
    pub username: RwLock<Option<String>>,
    /// Peer IP literal the edge saw on the client socket, if forwarded
    /// in the bind. Maintained by the kernel at bind time (only
    /// overwritten when a peer address arrives); drives `peerhost` and
    /// `peerhost_net` ban checks on the publish path.
    pub peerhost: RwLock<Option<String>>,
    /// Wall-clock time of the last connect/bind, as millis since the Unix
    /// epoch. Recorded where the session is already being written
    /// (creation, reconnect, bind); surfaced read-only for observability.
    /// `None` means the session predates timestamp recording; API reads
    /// must omit the field rather than substituting anything.
    pub connected_at_ms: RwLock<Option<u64>>,
    /// Per-client authorization decision cache for the management read
    /// (W2-01). Written on the publish/subscribe authorization event,
    /// read and cleared from the management plane only. The delivery
    /// fan-out path never touches this lock. Bounded by
    /// [`MAX_AUTHZ_DECISIONS_PER_CLIENT`] with oldest-first eviction.
    pub authz_cache: RwLock<VecDeque<AuthzDecision>>,
    next_packet_id: AtomicU16,
}

/// Current wall-clock time as millis since the Unix epoch. Read once per
/// queued message or session bind on the write path (offline buffering
/// and connects are rare), never per live delivery.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// One buffered message for a detached durable session (LOG + CURSOR
/// model: payloads live here until the session reattaches and replays).
#[derive(Debug, Clone)]
pub struct QueuedMessage {
    pub topic: Topic,
    pub qos: QoS,
    pub retain: bool,
    pub payload: Bytes,
    /// Publish time recorded where the message is already being written
    /// (offline queue insert), as millis since the Unix epoch.
    /// `None` means the entry predates timestamp recording; API reads
    /// must omit the field rather than substituting anything.
    pub publish_at_ms: Option<u64>,
}

/// One cached authorization decision for the per-client decision-cache
/// read (W2-01). `action` is `publish` or `subscribe`; `topic` is the
/// concrete publish topic or the subscription filter as requested;
/// `qos` is the publish QoS (or the granted QoS for subscribes);
/// `retain` is the publish retain flag (always false for subscribes);
/// `allow` is the decision; `updated_ms` is millis since the Unix epoch
/// recorded where the decision is written.
// TODO(parity): should subscribe decisions be cached at all, and if so
// with which `qos`/`retain` semantics? The rulebook does not decide the
// subscribe-cache shape; current choice records both with the granted QoS
// and `retain = false` so management reads observe every grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthzDecision {
    pub action: String,
    pub topic: String,
    pub qos: u8,
    pub retain: bool,
    pub allow: bool,
    pub updated_ms: u64,
}

/// One QoS 1 downlink held from the moment it is written toward a
/// subscriber until its PUBACK arrives (T-31). The packet id is the
/// downlink id on the wire; replay reuses it with DUP set, so resume
/// never allocates a colliding id.
#[derive(Debug, Clone)]
pub struct InflightMessage {
    pub packet_id: u16,
    pub topic: Topic,
    pub qos: QoS,
    pub retain: bool,
    pub payload: Bytes,
    /// Delivery instant for slow-subscriber ack latency (FX-02). Stamped
    /// once when the downlink is built; read once on PUBACK to compute
    /// `timespan`. One `Instant` per tracked entry, bounded by the
    /// existing window (`max_inflight`) plus spill (`max_spill`) caps, so
    /// no new unbounded state. Reason for `Instant` (monotonic) over
    /// wall-clock: ack latency must not jump on clock adjustments.
    pub enqueued_at: Instant,
}

/// Maximum unacknowledged QoS 1 downlinks held in the per-session
/// in-memory window (T-31, B4-01). Kept for backward compatibility;
/// prefer [`DEFAULT_MAX_QOS1_INFLIGHT`] for new code. At the window limit
/// the newest downlink spills to the per-session overflow buffer instead
/// of going untracked; only past the spill bound is a live delivery left
/// untracked (counted via `inflight_dropped`).
pub const MAX_QOS1_INFLIGHT: usize = 100;

/// Documented default per-session QoS 1 inflight window (B4-01): 100
/// unacknowledged downlinks. Rationale: caps per-session live unacked
/// state near 100 small frames so one stalled subscriber cannot balloon
/// the node, while absorbing a short ack stall without spilling; matches
/// the pre-B4-01 window so upgrades preserve behaviour. Configurable per
/// session via [`Session::set_max_inflight`] and per manager via
/// [`SessionManager::set_max_qos1_inflight`].
pub const DEFAULT_MAX_QOS1_INFLIGHT: usize = 100;

/// Documented default per-session QoS 1 spill bound (B4-01): 1,000
/// overflow downlinks past the window. Rationale: 10x the window absorbs
/// roughly a 1 s burst at 1k msg/s from a stalled acknowledger without
/// drops, while keeping per-session tracked memory bounded near 1,100
/// messages total (window + spill); each entry costs one shared payload
/// handle plus topic bytes, never N copies of the payload. Configurable
/// per session via [`Session::set_max_spill`] and per manager via
/// [`SessionManager::set_max_qos1_spill`].
/// TODO(parity): coordinate the spill backing store with B4-06 — whether
/// the overflow should live in the offline queue or on disk, and what
/// the durable bound and fsync policy should be, is still open.
pub const DEFAULT_MAX_QOS1_SPILL: usize = 1_000;

/// Outcome of [`Session::track_inflight_or_spill`]: where one QoS 1
/// downlink landed. `Tracked` is the fast path (inside the window);
/// `Spilled` means the window was full and the entry sits in the bounded
/// overflow buffer for DUP replay; `Dropped` means window and spill were
/// both full, so the frame still goes out live once but stays untracked
/// (counted by the caller).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InflightTrackOutcome {
    Tracked,
    Spilled,
    Dropped,
}

/// Default per-connection topic-alias bound in each direction (B4-05,
/// T-92): 10 aliases. Rationale: covers typical small-device use (a
/// handful of telemetry topics aliased to 1-byte handles) while capping
/// per-connection alias memory near 10 topic strings plus one small
/// index vector, so one peer cannot balloon the node. Configurable per
/// manager via [`SessionManager::set_max_topic_alias`] and per session
/// via [`Session::set_inbound_alias_max`] /
/// [`Session::set_outbound_alias_max`]. A maximum of 0 disables aliases
/// in that direction (fail closed: alias-carrying publishes are rejected
/// and no alias is ever assigned on delivery).
pub const DEFAULT_TOPIC_ALIAS_MAXIMUM: u16 = 10;

/// Maximum alias value the tables can ever index (wire `u16` range).
pub const MAX_TOPIC_ALIAS_VALUE: u16 = u16::MAX;

/// Rejection cause for one inbound alias use. Both map to reason code
/// `0x94` (Topic Alias Invalid) on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AliasReject {
    /// Alias 0 is never valid on the wire.
    Zero,
    /// Alias above the negotiated maximum (or any alias while the
    /// maximum is 0 / disabled).
    OverMaximum,
}

/// Maximum QoS 2 inbound publishes held per session between PUBLISH and
/// PUBREL (D1-01). At the limit a new packet id is refused (the kernel
/// sends no PUBREC, so the publisher retries); duplicates of held ids
/// are still answered. Bounds per-connection memory on the QoS 2 path;
/// the QoS 0 path never touches this map.
pub const MAX_QOS2_INBOUND: usize = 100;

/// Maximum uncompleted QoS 2 downlinks held per session (D1-01). Same
/// overflow policy as QoS 1: the newest downlink is still delivered live
/// once but left untracked (counted via `inflight_dropped`), so the live
/// rate never pays for the window.
pub const MAX_QOS2_INFLIGHT: usize = 100;

/// One QoS 2 inbound publish held between PUBLISH and PUBREL (D1-01).
/// Routed exactly once on PUBREL, then released.
#[derive(Debug, Clone)]
pub struct Qos2InboundEntry {
    pub topic: Topic,
    pub retain: bool,
    pub payload: Bytes,
}

/// One QoS 2 downlink held from the moment it is written toward a
/// subscriber until its PUBCOMP arrives (D1-01). `rec_received` is false
/// while waiting for PUBREC (full message retained) and true while
/// waiting for PUBCOMP (payload dropped, packet id retained for dedup).
/// Replay reuses the packet id in order; PUBLISH replays carry DUP set
/// while PUBREL replays carry the fixed PUBREL flags.
#[derive(Debug, Clone)]
pub struct Qos2OutboundEntry {
    pub packet_id: u16,
    pub topic: Topic,
    pub retain: bool,
    pub payload: Bytes,
    pub rec_received: bool,
}

/// Maximum cached authorization decisions per client for the
/// per-client decision-cache read (W2-01). Rationale: caps per-client
/// cache memory near 1024 small entries (topic string plus a few bytes)
/// so one chatty client cannot balloon the node, while holding a working
/// set of recent publish topics; the oldest entry is evicted past the cap
/// (LRU). The cache is enabled by default as a bounded map, never an
/// unbounded list.
pub const MAX_AUTHZ_DECISIONS_PER_CLIENT: usize = 1024;

/// Maximum buffered messages per detached session; beyond this the
/// oldest entry drops so one dead client cannot balloon the node.
pub const MAX_OFFLINE_QUEUE: usize = 1024;

/// Default offline queue cap for [`SessionManager::new`] (INDRA-215):
/// 10,000 messages per detached session, high enough for reconnect
/// storms without drops. Override per manager via
/// [`SessionManager::new_with_limits`], or pass `None` there for an
/// unbounded memory-backed queue.
pub const DEFAULT_MAX_OFFLINE_QUEUE: usize = 10_000;

/// Maximum rows snapshotted by one global subscription listing (W1-14).
/// The read clones at most this many `(client, filter)` rows under short
/// session locks, sorted for a deterministic order, then the W0 paging
/// helper slices the requested page. Per-connection state itself stays
/// bounded by live subscribe/unsubscribe writes. Management-plane only:
/// the delivery path never takes these locks and the router trie is
/// never touched by the list read.
pub const MAX_GLOBAL_SUBSCRIPTIONS: usize = 100_000;

/// One row of the global subscription index: owner plus the granted
/// filter and its options, as mirrored on the session by the subscribe
/// routes (same state the per-client list reads).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalSubscription {
    pub client_id: String,
    pub filter: TopicFilter,
    pub options: SubscriptionOptions,
}

/// Management-API detail row for one client session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientInfo {
    pub client_id: String,
    pub session_id: u64,
    pub conn_id: Option<u64>,
    pub keepalive_secs: u16,
    pub clean_start: bool,
    pub connected: bool,
    pub queued: usize,
    pub subscriptions: Vec<String>,
}

impl Session {
    pub fn new(id: SessionId, client_id: String, clean_start: bool) -> Self {
        Self {
            id,
            client_id,
            clean_start,
            connected: RwLock::new(true),
            conn_id: RwLock::new(None),
            subscriptions: RwLock::new(HashMap::new()),
            offline_queue: RwLock::new(VecDeque::new()),
            offline_store: RwLock::new(None),
            offline_persist: std::sync::Mutex::new(()),
            inflight: RwLock::new(VecDeque::new()),
            inflight_spill: RwLock::new(VecDeque::new()),
            spill_count: AtomicUsize::new(0),
            max_inflight: AtomicUsize::new(DEFAULT_MAX_QOS1_INFLIGHT),
            max_spill: AtomicUsize::new(DEFAULT_MAX_QOS1_SPILL),
            qos2_inbound: RwLock::new(HashMap::new()),
            qos2_outbound: RwLock::new(VecDeque::new()),
            // Inbound alias table starts empty (B4-05 hot path): sized to
            // `max + 1` on the first alias-carrying PUBLISH, so the
            // common no-alias connection pays no alias allocation here.
            // The bound is enforced by the `inbound_alias_max` range
            // check, never by the vector length.
            inbound_aliases: RwLock::new(Vec::new()),
            inbound_alias_max: AtomicU16::new(DEFAULT_TOPIC_ALIAS_MAXIMUM),
            outbound_aliases: RwLock::new(Vec::new()),
            outbound_alias_max: AtomicU16::new(0),
            keepalive_secs: RwLock::new(0),
            last_will: RwLock::new(None),
            username: RwLock::new(None),
            peerhost: RwLock::new(None),
            connected_at_ms: RwLock::new(Some(now_ms())),
            authz_cache: RwLock::new(VecDeque::new()),
            next_packet_id: AtomicU16::new(1),
        }
    }

    /// Configured QoS 1 window bound for this session (default
    /// [`DEFAULT_MAX_QOS1_INFLIGHT`]). One relaxed atomic load; safe on
    /// the publish fast path.
    pub fn max_inflight(&self) -> usize {
        self.max_inflight.load(Ordering::Relaxed).max(1)
    }

    /// Override the QoS 1 window bound for this session (floored at 1 so
    /// the window always holds at least one unacked downlink).
    /// Management/boot configuration only; never per message.
    pub fn set_max_inflight(&self, limit: usize) {
        self.max_inflight.store(limit.max(1), Ordering::Relaxed);
    }

    /// Configured QoS 1 spill bound for this session (default
    /// [`DEFAULT_MAX_QOS1_SPILL`]). Read only on window overflow.
    pub fn max_spill(&self) -> usize {
        self.max_spill.load(Ordering::Relaxed).max(1)
    }

    /// Override the QoS 1 spill bound for this session (floored at 1).
    /// Management/boot configuration only; never per message.
    pub fn set_max_spill(&self, limit: usize) {
        self.max_spill.store(limit.max(1), Ordering::Relaxed);
    }

    pub fn next_packet_id(&self) -> u16 {
        loop {
            let pid = self.next_packet_id.fetch_add(1, Ordering::SeqCst);
            if pid == 0 {
                continue;
            }
            // Never hand out an id already held inflight, in spill, or
            // QoS 2 outbound: a resumed session's unacked ids stay
            // reserved until their PUBACK/PUBCOMP. All stores are
            // bounded, so this scan always terminates. The spill scan
            // (one read lock + O(spill) linear scan, spill <= max_spill)
            // runs only when spill is non-empty (one relaxed atomic
            // load); steady-state with empty spill takes the same 2 read
            // locks as before B4-01. Spill-nonempty id-allocation
            // throughput is printed by
            // `test_qos1_inflight_hot_path_timings` (slow-path section).
            if self.inflight.read().iter().any(|m| m.packet_id == pid) {
                continue;
            }
            if self.spill_count.load(Ordering::Relaxed) != 0
                && self
                    .inflight_spill
                    .read()
                    .iter()
                    .any(|m| m.packet_id == pid)
            {
                continue;
            }
            if self.qos2_outbound.read().iter().any(|m| m.packet_id == pid) {
                continue;
            }
            return pid;
        }
    }

    /// Hold one QoS 1 downlink in the window for redelivery. True means
    /// tracked in the window; false means the per-session window was full
    /// (the caller should spill via [`Session::track_inflight_or_spill`],
    /// or still deliver live once and count `inflight_dropped`). Never
    /// grows past the configured window ([`Session::max_inflight`]).
    /// Fast path: one atomic load plus one bounded deque push under a
    /// single write lock, no allocation beyond the message itself.
    pub fn track_inflight(&self, message: InflightMessage) -> bool {
        let limit = self.max_inflight();
        let mut inflight = self.inflight.write();
        if inflight.len() >= limit {
            return false;
        }
        inflight.push_back(message);
        true
    }

    /// Hold one QoS 1 downlink for redelivery, spilling past the window
    /// into the bounded overflow buffer (B4-01). The fast path (inside
    /// the window) is exactly [`Session::track_inflight`]: one lock, one
    /// bounded push, no allocation beyond the message. The spill lock is
    /// touched solely on window overflow, so steady-state publish and
    /// deliver pay nothing for the bound. Never grows past
    /// `max_inflight + max_spill`; past both the caller still delivers
    /// live once and counts `inflight_dropped`. Before/after numbers: the
    /// store pair (legacy baseline vs this fast path) is printed by
    /// `test_qos1_inflight_hot_path_timings`; the broker
    /// publish-to-delivery pair is printed by
    /// `qos1_inflight_delivery_workload_timings` in broker-node.
    pub fn track_inflight_or_spill(&self, message: InflightMessage) -> InflightTrackOutcome {
        let limit = self.max_inflight();
        {
            let mut inflight = self.inflight.write();
            if inflight.len() < limit {
                inflight.push_back(message);
                return InflightTrackOutcome::Tracked;
            }
        }
        let spill_limit = self.max_spill();
        let mut spill = self.inflight_spill.write();
        if spill.len() >= spill_limit {
            return InflightTrackOutcome::Dropped;
        }
        spill.push_back(message);
        self.spill_count.fetch_add(1, Ordering::Relaxed);
        InflightTrackOutcome::Spilled
    }

    /// Release one downlink on its PUBACK, from the window or the spill.
    /// True when an entry was held in either store. When the window entry
    /// is released and spill holds older overflow, the oldest spilled
    /// entry is promoted into the window so the window always holds the
    /// oldest unacked downlinks and replay stays oldest-first. Ack path
    /// only: the publish fast path never takes both locks.
    pub fn ack_inflight(&self, packet_id: u16) -> bool {
        self.ack_inflight_timed(packet_id).is_some()
    }

    /// Release one downlink on its PUBACK and return the held entry so the
    /// caller can measure delivery-to-ack latency (FX-02). Same promotion
    /// and lock order as [`Session::ack_inflight`]; `None` for stale ids.
    /// Ack path only: the publish fast path never calls this.
    pub fn ack_inflight_timed(&self, packet_id: u16) -> Option<InflightMessage> {
        let mut inflight = self.inflight.write();
        if let Some(pos) = inflight.iter().position(|m| m.packet_id == packet_id) {
            let entry = inflight.remove(pos).expect("position checked");
            // Promote the oldest spill so the window stays the oldest
            // entries. Nested `inflight` -> `inflight_spill` order matches
            // the documented lock order; no other path nests in reverse.
            // The nested spill lock runs only when spill is non-empty
            // (one relaxed atomic load); steady-state ack with empty
            // spill holds exactly the 1 window write lock as before
            // B4-01. Spill-nonempty ack-with-promotion throughput is
            // printed by `test_qos1_inflight_hot_path_timings`
            // (slow-path section). A missed promotion under a concurrent
            // spill push only defers promotion to the next ack; replay
            // still covers window then spill oldest-first.
            if self.spill_count.load(Ordering::Relaxed) == 0 {
                return Some(entry);
            }
            let promoted = self.inflight_spill.write().pop_front();
            if let Some(promoted_entry) = promoted {
                self.spill_count.fetch_sub(1, Ordering::Relaxed);
                inflight.push_back(promoted_entry);
            }
            return Some(entry);
        }
        drop(inflight);
        let mut spill = self.inflight_spill.write();
        if let Some(pos) = spill.iter().position(|m| m.packet_id == packet_id) {
            let entry = spill.remove(pos).expect("position checked");
            self.spill_count.fetch_sub(1, Ordering::Relaxed);
            return Some(entry);
        }
        None
    }

    /// Ordered snapshot of unacked window downlinks for reconnect replay.
    /// Entries stay held: they remain inflight until their PUBACK, so a
    /// second reconnect without acks replays them again.
    pub fn inflight_snapshot(&self) -> Vec<InflightMessage> {
        self.inflight.read().iter().cloned().collect()
    }

    /// Ordered snapshot of spilled overflow for reconnect replay, oldest
    /// first. Entries stay held until their PUBACK, like the window.
    pub fn inflight_spill_snapshot(&self) -> Vec<InflightMessage> {
        self.inflight_spill.read().iter().cloned().collect()
    }

    pub fn inflight_len(&self) -> usize {
        self.inflight.read().len()
    }

    /// Number of overflow entries currently held past the window.
    pub fn inflight_spill_len(&self) -> usize {
        self.inflight_spill.read().len()
    }

    /// Lock-free fast-path check: true while spill holds entries.
    /// One relaxed atomic load; lets `next_packet_id`, ack promotion and
    /// reconnect replay skip the spill lock/scan/snapshot allocation when
    /// empty. Steady-state cost is one atomic load, no new lock.
    pub fn has_spill(&self) -> bool {
        self.spill_count.load(Ordering::Relaxed) != 0
    }

    /// Window plus spill: every QoS 1 downlink currently tracked for
    /// redelivery on this session.
    pub fn inflight_total_len(&self) -> usize {
        self.inflight.read().len() + self.inflight_spill.read().len()
    }

    pub fn clear_inflight(&self) {
        self.inflight.write().clear();
        self.inflight_spill.write().clear();
        self.spill_count.store(0, Ordering::Relaxed);
    }

    /// Store one QoS 2 inbound publish between PUBLISH and PUBREL.
    /// Returns false when the id is already held (duplicate: the caller
    /// must reply PUBREC without routing again) or when the per-session
    /// bound is full (the caller sends no PUBREC, so the publisher
    /// retries). True means newly stored.
    pub fn store_qos2_inbound(&self, packet_id: u16, entry: Qos2InboundEntry) -> bool {
        let mut inbound = self.qos2_inbound.write();
        if inbound.contains_key(&packet_id) {
            return false;
        }
        if inbound.len() >= MAX_QOS2_INBOUND {
            return false;
        }
        inbound.insert(packet_id, entry);
        true
    }

    /// Whether a QoS 2 inbound packet id is already held (duplicate
    /// PUBLISH before PUBREL).
    pub fn has_qos2_inbound(&self, packet_id: u16) -> bool {
        self.qos2_inbound.read().contains_key(&packet_id)
    }

    /// Take one QoS 2 inbound publish on PUBREL for exactly-once routing.
    /// `None` means unknown packet id (the caller answers nothing).
    pub fn take_qos2_inbound(&self, packet_id: u16) -> Option<Qos2InboundEntry> {
        self.qos2_inbound.write().remove(&packet_id)
    }

    /// Number of QoS 2 inbound publishes currently held.
    pub fn qos2_inbound_len(&self) -> usize {
        self.qos2_inbound.read().len()
    }

    /// Drop all QoS 2 inbound state (clean disconnect only).
    pub fn clear_qos2_inbound(&self) {
        self.qos2_inbound.write().clear();
    }

    /// Hold one QoS 2 downlink for the two-phase exchange. True means
    /// tracked; false means the per-session bound was full (the caller
    /// still delivers live once and counts `inflight_dropped`). Never
    /// grows past [`MAX_QOS2_INFLIGHT`].
    pub fn track_qos2_outbound(&self, entry: Qos2OutboundEntry) -> bool {
        let mut outbound = self.qos2_outbound.write();
        if outbound.len() >= MAX_QOS2_INFLIGHT {
            return false;
        }
        outbound.push_back(entry);
        true
    }

    /// Mark one QoS 2 downlink as PUBREC-received (waiting for PUBCOMP).
    /// Drops the retained payload; only the packet id is kept until
    /// PUBCOMP. True when an entry was waiting for PUBREC.
    pub fn complete_qos2_pubrec(&self, packet_id: u16) -> bool {
        let mut outbound = self.qos2_outbound.write();
        if let Some(entry) = outbound.iter_mut().find(|m| m.packet_id == packet_id) {
            if !entry.rec_received {
                entry.rec_received = true;
                entry.payload = Bytes::new();
                return true;
            }
        }
        false
    }

    /// Release one QoS 2 downlink on its PUBCOMP. True when an entry was
    /// held (in either phase).
    pub fn ack_qos2_pubcomp(&self, packet_id: u16) -> bool {
        let mut outbound = self.qos2_outbound.write();
        if let Some(pos) = outbound.iter().position(|m| m.packet_id == packet_id) {
            outbound.remove(pos);
            return true;
        }
        false
    }

    /// Ordered snapshot of uncompleted QoS 2 downlinks for reconnect
    /// replay. Entries stay held until their PUBCOMP, so a second
    /// reconnect without completion replays them again.
    pub fn qos2_outbound_snapshot(&self) -> Vec<Qos2OutboundEntry> {
        self.qos2_outbound.read().iter().cloned().collect()
    }

    /// Number of QoS 2 downlinks currently held.
    pub fn qos2_outbound_len(&self) -> usize {
        self.qos2_outbound.read().len()
    }

    /// Drop all QoS 2 outbound state (clean disconnect only).
    pub fn clear_qos2_outbound(&self) {
        self.qos2_outbound.write().clear();
    }

    /// Negotiated inbound alias maximum (aliases the client may send).
    /// One relaxed atomic load; the publish fast path checks `alias == 0`
    /// first and returns without a lock, so alias-disabled publishes pay
    /// one branch and nothing else.
    pub fn inbound_alias_max(&self) -> u16 {
        self.inbound_alias_max.load(Ordering::Relaxed)
    }

    /// Set the inbound alias maximum, resizing the table to `max + 1`
    /// (index 0 stays unused) when it already holds entries. A fresh
    /// (empty) table is left empty and sized on the first alias-carrying
    /// PUBLISH instead, so connections that never use aliases pay no
    /// alias allocation; the bound is enforced by the `max` range check,
    /// never by the vector length. Shrinking drops mappings above the new
    /// maximum (fail closed on next use). CONNECT event only; never per
    /// message.
    pub fn set_inbound_alias_max(&self, max: u16) {
        self.inbound_alias_max.store(max, Ordering::Relaxed);
        let mut table = self.inbound_aliases.write();
        if table.is_empty() {
            return;
        }
        let want = max as usize + 1;
        table.resize_with(want, || None);
        if table.len() > want {
            table.truncate(want);
        }
    }

    /// Negotiated outbound alias maximum (aliases the kernel may send).
    /// One relaxed atomic load; deliveries with max 0 skip the table
    /// without a lock.
    pub fn outbound_alias_max(&self) -> u16 {
        self.outbound_alias_max.load(Ordering::Relaxed)
    }

    /// Set the outbound alias maximum, resizing the table to `max + 1`.
    /// CONNECT event only; never per message.
    pub fn set_outbound_alias_max(&self, max: u16) {
        self.outbound_alias_max.store(max, Ordering::Relaxed);
        let mut table = self.outbound_aliases.write();
        let want = if max == 0 { 0 } else { max as usize + 1 };
        table.clear();
        table.resize_with(want, || None);
    }

    /// Register `alias -> topic` from a client publish carrying both.
    /// Overwrites the previous mapping for a valid alias (the documented
    /// behaviour). PUBLISH event only.
    pub fn register_inbound_alias(&self, alias: u16, topic: Topic) -> Result<(), AliasReject> {
        if alias == protocol_v5::NO_TOPIC_ALIAS {
            return Err(AliasReject::Zero);
        }
        let max = self.inbound_alias_max();
        if !protocol_v5::alias_in_range(alias, max) {
            return Err(AliasReject::OverMaximum);
        }
        let mut table = self.inbound_aliases.write();
        let want = max as usize + 1;
        if table.len() != want {
            table.resize_with(want, || None);
        }
        table[alias as usize] = Some(topic);
        Ok(())
    }

    /// Resolve one inbound alias to its topic. Hot path: alias 0 returns
    /// `None` with no lock; otherwise one read lock plus a bounded index,
    /// cloning the stored topic only on a hit.
    pub fn resolve_inbound_alias(&self, alias: u16) -> Option<Topic> {
        if alias == protocol_v5::NO_TOPIC_ALIAS {
            return None;
        }
        let max = self.inbound_alias_max.load(Ordering::Relaxed);
        if !protocol_v5::alias_in_range(alias, max) {
            return None;
        }
        self.inbound_aliases
            .read()
            .get(alias as usize)
            .cloned()
            .flatten()
    }

    /// Number of inbound alias mappings currently held (for boundedness
    /// assertions; management-plane only).
    pub fn inbound_alias_len(&self) -> usize {
        self.inbound_aliases.read().iter().flatten().count()
    }

    /// Outbound alias already assigned to `topic`, if any. Hot path:
    /// max 0 returns `None` with no lock; otherwise one read lock plus a
    /// bounded linear scan (<= max entries), no allocation.
    pub fn outbound_alias_for(&self, topic_str: &str) -> Option<u16> {
        let max = self.outbound_alias_max.load(Ordering::Relaxed);
        if max == protocol_v5::NO_TOPIC_ALIAS {
            return None;
        }
        let table = self.outbound_aliases.read();
        let end = (max as usize + 1).min(table.len());
        for (alias, slot) in table.iter().enumerate().take(end).skip(1) {
            if let Some(topic) = slot {
                if topic.as_str() == topic_str {
                    return Some(alias as u16);
                }
            }
        }
        None
    }

    /// Assign (or reuse) one outbound alias for `topic` on the delivery
    /// event. Reuses the existing alias when present; otherwise claims
    /// the smallest free alias <= max. `None` means no maximum negotiated
    /// or the table is full (the caller sends the full topic with alias
    /// 0, so the table never grows per message).
    pub fn assign_outbound_alias(&self, topic: &Topic) -> Option<u16> {
        let max = self.outbound_alias_max.load(Ordering::Relaxed);
        if max == protocol_v5::NO_TOPIC_ALIAS {
            return None;
        }
        let mut table = self.outbound_aliases.write();
        let want = max as usize + 1;
        if table.len() != want {
            table.resize_with(want, || None);
        }
        for (alias, slot) in table.iter().enumerate().skip(1) {
            if let Some(held) = slot {
                if held == topic {
                    return Some(alias as u16);
                }
            }
        }
        for (alias, slot) in table.iter_mut().enumerate().skip(1) {
            if slot.is_none() {
                *slot = Some(topic.clone());
                return Some(alias as u16);
            }
        }
        None
    }

    /// Number of outbound alias mappings currently held.
    pub fn outbound_alias_len(&self) -> usize {
        self.outbound_aliases.read().iter().flatten().count()
    }

    /// Drop both alias tables (per-connection state dies with the
    /// connection). Called on bind (new connection renegotiates) and on
    /// verified unbind.
    pub fn clear_aliases(&self) {
        for slot in self.inbound_aliases.write().iter_mut() {
            *slot = None;
        }
        for slot in self.outbound_aliases.write().iter_mut() {
            *slot = None;
        }
    }

    /// Record one authorization decision for the per-client decision-cache
    /// read (W2-01). `action` is `publish` or `subscribe`; `topic` is the
    /// concrete topic or filter; `qos`/`retain` ride with the entry so the
    /// management read can render them without consulting the hot path.
    /// A repeat of the same `(action, topic, qos, retain)` refreshes the
    /// decision and recency instead of duplicating; past
    /// [`MAX_AUTHZ_DECISIONS_PER_CLIENT`] the oldest entry is evicted.
    /// Called on the publish/subscribe authorization event only; the
    /// delivery fan-out path never touches this lock, and management
    /// reads take only this per-session lock.
    pub fn record_authz_decision(
        &self,
        action: &str,
        topic: &str,
        qos: u8,
        retain: bool,
        allow: bool,
    ) {
        let mut cache = self.authz_cache.write();
        if let Some(pos) = cache.iter().position(|e| {
            e.action == action && e.topic == topic && e.qos == qos && e.retain == retain
        }) {
            cache.remove(pos);
        }
        cache.push_back(AuthzDecision {
            action: action.to_string(),
            topic: topic.to_string(),
            qos,
            retain,
            allow,
            updated_ms: now_ms(),
        });
        while cache.len() > MAX_AUTHZ_DECISIONS_PER_CLIENT {
            cache.pop_front();
        }
    }

    /// Ordered snapshot of cached authorization decisions, oldest first.
    /// Management-plane read only; clones at most
    /// [`MAX_AUTHZ_DECISIONS_PER_CLIENT`] small entries under one short
    /// lock and never touches the delivery path.
    pub fn authz_cache_snapshot(&self) -> Vec<AuthzDecision> {
        self.authz_cache.read().iter().cloned().collect()
    }

    /// Evict every cached authorization decision for this client.
    /// Management-plane only (the clear route); a background map removal
    /// that never runs on the publish or deliver path.
    pub fn clear_authz_cache(&self) {
        self.authz_cache.write().clear();
    }

    /// Buffer one message for later replay, evicting the oldest entry
    /// past [`MAX_OFFLINE_QUEUE`]. Returns whether the entry was queued
    /// (false only when durable persist failed; see
    /// [`Session::push_offline_with_limit`]).
    pub fn push_offline(&self, message: QueuedMessage) -> bool {
        self.push_offline_with_limit(message, Some(MAX_OFFLINE_QUEUE))
    }

    /// Buffer one message with an explicit cap: `Some(n)` evicts the
    /// oldest entries past `n` (floored at holding one), `None` queues
    /// without bound (memory-bounded by the caller). The publish time is
    /// recorded here where the message is already being written: an entry
    /// arriving without one is stamped once, so the delivery hot path
    /// never takes a clock.
    ///
    /// Durable backing (B4-06): when an offline store is installed, the
    /// entry is appended to the per-client queue file (flushed, plus
    /// `sync_data` under the default fsync policy) before it enters the
    /// memory queue, so an acknowledged publish that buffered here has
    /// already reached stable storage. Evictions past the cap rewrite the
    /// file from the surviving snapshot (`O(cap)`, bounded by the cap,
    /// detached path only). The per-session persist mutex (not the queue
    /// lock) is held across the file append, the memory push and any
    /// eviction rewrite so concurrent buffers for the same detached client
    /// keep file order equal to queue order; the queue lock itself is taken
    /// only for the memory section in between, never across file I/O, so
    /// queue readers never wait for an fsync. Cross-client publishes never
    /// share either lock, and live deliveries to connected sessions never
    /// touch a file. A failed append queues nothing (fail closed): it is
    /// counted in the store and logged, the memory copy is dropped, and
    /// `false` is returned so the kernel publish path withholds the QoS 1
    /// ack and the publisher retries; a failed eviction rewrite is likewise
    /// counted, logged and reported as `false` (the capped memory queue is
    /// kept, the next restore re-caps the file).
    /// Returns `true` when the entry was queued, `false` when a durable
    /// write failed and nothing was queued (or the rewrite failed).
    pub fn push_offline_with_limit(&self, message: QueuedMessage, limit: Option<usize>) -> bool {
        let mut message = message;
        if message.publish_at_ms.is_none() {
            message.publish_at_ms = Some(now_ms());
        }
        let store = self.offline_store.read().clone();
        let Some(store) = store else {
            let mut queue = self.offline_queue.write();
            if let Some(limit) = limit {
                let limit = limit.max(1);
                while queue.len() >= limit {
                    queue.pop_front();
                }
            }
            queue.push_back(message);
            return true;
        };
        let record = OfflineRecord {
            topic: message.topic.clone(),
            qos: message.qos,
            retain: message.retain,
            payload: message.payload.clone(),
            publish_at_ms: message.publish_at_ms,
        };
        // One writer per client queue: the persist mutex stays held across
        // the file append, the memory push and any eviction rewrite, so a
        // concurrent buffer for the same client cannot append between the
        // snapshot and the file replace and be clobbered, matching
        // `confirm_offline_consumed`. The queue lock is taken only for the
        // memory section in between, never across file I/O.
        // Detached-buffer path only; live deliveries never touch either
        // lock or a file.
        let _persist = self
            .offline_persist
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Err(e) = store.append(&self.client_id, &record) {
            tracing::warn!("Offline queue persist failed for {}: {e}", self.client_id);
            return false;
        }
        let snapshot: Option<Vec<OfflineRecord>> = {
            let mut queue = self.offline_queue.write();
            let mut evicted = false;
            if let Some(limit) = limit {
                let limit = limit.max(1);
                while queue.len() >= limit {
                    queue.pop_front();
                    evicted = true;
                }
            }
            queue.push_back(message);
            if evicted {
                Some(
                    queue
                        .iter()
                        .map(|queued| OfflineRecord {
                            topic: queued.topic.clone(),
                            qos: queued.qos,
                            retain: queued.retain,
                            payload: queued.payload.clone(),
                            publish_at_ms: queued.publish_at_ms,
                        })
                        .collect(),
                )
            } else {
                None
            }
        };
        if let Some(snapshot) = snapshot {
            if let Err(e) = store.rewrite(&self.client_id, &snapshot) {
                tracing::warn!("Offline queue rewrite failed for {}: {e}", self.client_id);
                return false;
            }
        }
        true
    }

    /// Refill the memory queue from already-persisted records without
    /// writing them back (restart reload path). Enforces `limit` exactly
    /// like [`Session::push_offline_with_limit`] (oldest dropped past the
    /// cap) but never touches the store: the file already holds these
    /// entries in order. Preserves `publish_at_ms` as stored (`None` stays
    /// `None`): the reload must not invent history. Returns the number of
    /// entries dropped by the cap.
    pub fn push_restored_with_limit(
        &self,
        messages: Vec<QueuedMessage>,
        limit: Option<usize>,
    ) -> usize {
        let mut dropped = 0usize;
        let mut queue = self.offline_queue.write();
        for message in messages {
            if let Some(limit) = limit {
                let limit = limit.max(1);
                while queue.len() >= limit {
                    queue.pop_front();
                    dropped += 1;
                }
            }
            queue.push_back(message);
        }
        dropped
    }

    /// Point the session at the durable offline backing (`None` returns
    /// to memory-only buffering). Called by the manager for new sessions
    /// and when the kernel installs the store at boot; never per message.
    pub fn set_offline_store(&self, store: Option<Arc<OfflineQueueStore>>) {
        *self.offline_store.write() = store;
    }

    /// Take every buffered message, leaving the queue empty. When a
    /// durable store is installed the queue file is deleted alongside, so
    /// a restart after the handoff replays nothing (replay hands each
    /// entry to the new connection exactly once per drain, matching the
    /// previous memory-only semantics). The persist mutex is held across
    /// the memory drain and the file delete so a concurrent buffer cannot
    /// append between them and be lost; the queue lock itself is taken
    /// only for the drain.
    ///
    /// Only for paths where the handoff is already complete (tests,
    /// management drains). The reconnect-replay path must use
    /// [`Session::take_offline_retained`] plus
    /// [`Session::confirm_offline_consumed`] so the file survives until
    /// each entry has reached the new mailbox.
    pub fn drain_offline(&self) -> Vec<QueuedMessage> {
        let store = self.offline_store.read().clone();
        let Some(store) = store else {
            return self.offline_queue.write().drain(..).collect();
        };
        let _persist = self
            .offline_persist
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let drained: Vec<QueuedMessage> = self.offline_queue.write().drain(..).collect();
        if !drained.is_empty() {
            store.remove(&self.client_id);
        }
        drained
    }

    /// Drain the memory queue but retain the durable queue file (B4-06
    /// SLOP-1 fix). The reconnect-replay caller routes the returned
    /// entries first and then calls
    /// [`Session::confirm_offline_consumed`]: a crash between this drain
    /// and the confirm still finds the file on disk and replays
    /// at-least-once instead of losing the backlog (fail closed). Takes
    /// the persist mutex for the drain so the drain pairs with the
    /// confirm's rewrite under the same serialization as concurrent
    /// buffers; no file I/O happens here.
    pub fn take_offline_retained(&self) -> Vec<QueuedMessage> {
        if self.offline_store.read().is_some() {
            let _persist = self
                .offline_persist
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            return self.offline_queue.write().drain(..).collect();
        }
        self.offline_queue.write().drain(..).collect()
    }

    /// Complete a retained drain after routing (B4-06 SLOP-1 fix). Entries
    /// the caller could not route are passed back in `unrouted` (in drain
    /// order): they are prepended to the memory queue ahead of any
    /// concurrent arrivals and the file is rewritten from the resulting
    /// queue, so unrouted entries survive for the next replay. Entries
    /// that reached the new mailbox are dropped from both memory (already
    /// drained) and disk (the rewrite omits them). An empty queue
    /// rewrites to no file (delete), preserving the previous
    /// drain-deletes-the-file behaviour on the success path while keeping
    /// concurrent arrivals that buffered after the drain. Unroutable
    /// frames are already counted inside `ConnTable::route`
    /// (`unknown_conn_dropped` / `dead_mailbox_dropped`); this method only
    /// guarantees they are retained, never silently dropped.
    pub fn confirm_offline_consumed(&self, unrouted: Vec<QueuedMessage>) {
        let Some(store) = self.offline_store.read().clone() else {
            if !unrouted.is_empty() {
                let mut queue = self.offline_queue.write();
                let arrivals: Vec<QueuedMessage> = queue.drain(..).collect();
                queue.extend(unrouted);
                queue.extend(arrivals);
            }
            return;
        };
        // The persist mutex stays held across the merge and the file
        // rewrite so a concurrent `push_offline_with_limit` append cannot
        // slip between the snapshot and the file replace and be
        // clobbered. The queue lock is taken only for the merge and
        // snapshot, never across the rewrite. Detached-buffer path only;
        // live deliveries never touch either lock or a file.
        let _persist = self
            .offline_persist
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let snapshot: Vec<OfflineRecord> = {
            let mut queue = self.offline_queue.write();
            if !unrouted.is_empty() {
                let arrivals: Vec<QueuedMessage> = queue.drain(..).collect();
                queue.extend(unrouted);
                queue.extend(arrivals);
            }
            queue
                .iter()
                .map(|queued| OfflineRecord {
                    topic: queued.topic.clone(),
                    qos: queued.qos,
                    retain: queued.retain,
                    payload: queued.payload.clone(),
                    publish_at_ms: queued.publish_at_ms,
                })
                .collect()
        };
        if let Err(e) = store.rewrite(&self.client_id, &snapshot) {
            tracing::warn!(
                "Offline queue confirm rewrite failed for {}: {e}",
                self.client_id
            );
        }
    }

    pub fn offline_len(&self) -> usize {
        self.offline_queue.read().len()
    }

    /// Record the CONNECT last will, replacing any previous one. `None`
    /// (CONNECT without a will) clears the previous will: the will is
    /// per-connection state, so a reconnect without one registers none.
    /// CONNECT (bind) event only.
    pub fn set_last_will(&self, will: Option<StoredWill>) {
        *self.last_will.write() = will;
    }

    /// Take the stored will exactly once, leaving `None` behind. The
    /// first taker publishes (ungraceful close); a racing second taker
    /// observes `None` and publishes nothing. Disconnect events only.
    pub fn take_last_will(&self) -> Option<StoredWill> {
        self.last_will.write().take()
    }
}

/// In-memory token bucket for per-client publish rate limiting.
/// Starts full; refills lazily on each check so idle clients never pay
/// for a background task.
#[derive(Debug)]
pub struct TokenBucket {
    rate_per_sec: u32,
    burst: u32,
    tokens: f64,
    last_update: Instant,
}

impl TokenBucket {
    pub fn new(rate_per_sec: u32, burst: u32) -> Self {
        Self {
            rate_per_sec,
            burst,
            tokens: burst as f64,
            last_update: Instant::now(),
        }
    }

    /// Try to consume one token. False means the publish is over quota.
    pub fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.last_update = now;
        self.tokens =
            (self.tokens + elapsed * f64::from(self.rate_per_sec)).min(f64::from(self.burst));
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub struct SessionManager {
    sessions: RwLock<HashMap<String, Arc<Session>>>,
    next_session_id: AtomicU64,
    /// O(1) reverse map `conn_id -> client_id` (PERF-04). Populated by
    /// [`SessionManager::bind_session`], pruned by `unbind_connection`
    /// and by `get_or_create` on clean-start replacement. Lookups take a
    /// short read; bind/unbind a short write; the lock is never held
    /// across dispatch, routing, or I/O.
    conn_index: RwLock<HashMap<u64, String>>,
    /// Live connection count per username (INDRA-127 quotas). Anonymous
    /// binds bypass accounting entirely.
    conn_counts: RwLock<HashMap<String, AtomicU32>>,
    /// Publish token buckets per client id (INDRA-128 rate limits).
    /// Pruned on unbind so reconnects start full and state cannot grow
    /// without bound.
    buckets: RwLock<HashMap<String, TokenBucket>>,
    /// Live-session count for the management count endpoint (W1-13).
    /// Maintained by `get_or_create` (increment on a newly connected
    /// session) and `unbind_connection` (decrement on a verified detach),
    /// so the count endpoint reads one atomic instead of scanning the
    /// session map. Management-plane only; never touched on fan-out or
    /// fan-in.
    connected_count: AtomicU64,
    /// Offline queue cap applied by [`SessionManager::queue_offline`];
    /// `None` queues without bound.
    max_offline_queue: Option<usize>,
    /// Default QoS 1 window bound applied to sessions created after the
    /// last set (B4-01). One relaxed atomic load per new session; never
    /// touched on the publish fast path.
    max_qos1_inflight: AtomicUsize,
    /// Default QoS 1 spill bound applied to sessions created after the
    /// last set (B4-01). Read only when a session is created or
    /// reconfigured, never per message.
    max_qos1_spill: AtomicUsize,
    /// Default inbound topic-alias maximum applied to sessions created
    /// after the last set (B4-05). One relaxed atomic load per new
    /// session; never touched on the publish fast path.
    max_topic_alias: AtomicU16,
    /// Durable backing for every detached offline queue (B4-06, T-93).
    /// `None` (the default) keeps memory-only queues exactly as before.
    /// The kernel installs one store at boot (see
    /// [`SessionManager::set_offline_store`]); sessions created
    /// afterwards inherit it, and a restart rebuilds the memory queues
    /// from it via [`SessionManager::restore_offline_queues`]. One `Arc`
    /// clone at boot; the publish path never touches this lock (each
    /// session holds its own clone).
    offline_store: RwLock<Option<Arc<OfflineQueueStore>>>,
}

/// Outcome of [`SessionManager::restore_offline_queues`]: what the restart
/// reload rebuilt into the in-memory index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OfflineRestoreStats {
    /// Queued messages rebuilt into detached persistent sessions.
    pub messages: usize,
    /// Client ids with a queue file that produced at least one message.
    pub clients: usize,
    /// Queue files whose torn tail was truncated and never served.
    pub torn: u64,
    /// Rebuilt entries dropped because the file held more than the
    /// configured cap (oldest first, file rewritten to the survivors).
    pub capped_dropped: usize,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager {
    pub fn new() -> Self {
        Self::new_with_all_limits(
            Some(DEFAULT_MAX_OFFLINE_QUEUE),
            DEFAULT_MAX_QOS1_INFLIGHT,
            DEFAULT_MAX_QOS1_SPILL,
        )
    }

    /// Create a manager with an explicit offline queue cap: `Some(n)`
    /// evicts oldest past `n` per detached session (floored at 1, no
    /// ceiling), `None` queues without bound. The QoS 1 window and spill
    /// bounds take their documented defaults ([`DEFAULT_MAX_QOS1_INFLIGHT`],
    /// [`DEFAULT_MAX_QOS1_SPILL`]).
    pub fn new_with_limits(max_offline_queue: Option<usize>) -> Self {
        Self::new_with_all_limits(
            max_offline_queue,
            DEFAULT_MAX_QOS1_INFLIGHT,
            DEFAULT_MAX_QOS1_SPILL,
        )
    }

    /// Create a manager with explicit offline, QoS 1 window and QoS 1
    /// spill caps (B4-01). Window and spill floors hold at 1 so every
    /// session tracks at least one unacked downlink plus one spill slot.
    pub fn new_with_all_limits(
        max_offline_queue: Option<usize>,
        max_qos1_inflight: usize,
        max_qos1_spill: usize,
    ) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            next_session_id: AtomicU64::new(1),
            conn_index: RwLock::new(HashMap::new()),
            conn_counts: RwLock::new(HashMap::new()),
            buckets: RwLock::new(HashMap::new()),
            connected_count: AtomicU64::new(0),
            max_offline_queue: max_offline_queue.map(|limit| limit.max(1)),
            max_qos1_inflight: AtomicUsize::new(max_qos1_inflight.max(1)),
            max_qos1_spill: AtomicUsize::new(max_qos1_spill.max(1)),
            max_topic_alias: AtomicU16::new(DEFAULT_TOPIC_ALIAS_MAXIMUM),
            offline_store: RwLock::new(None),
        }
    }

    /// Durable offline backing installed by the kernel at boot (`None` =
    /// memory-only, the default). Installs the handle on every existing
    /// session as well as the manager, so sessions created before boot
    /// wiring still persist. Boot-time only; never per message.
    pub fn set_offline_store(&self, store: Arc<OfflineQueueStore>) {
        *self.offline_store.write() = Some(store.clone());
        let sessions: Vec<Arc<Session>> = self.sessions.read().values().cloned().collect();
        for session in sessions {
            session.set_offline_store(Some(store.clone()));
        }
    }

    /// Installed durable offline backing, if any.
    pub fn offline_store(&self) -> Option<Arc<OfflineQueueStore>> {
        self.offline_store.read().clone()
    }

    /// Rebuild the in-memory offline index from the durable store after a
    /// restart (B4-06). For every client id with a queue file, loads its
    /// records in order (truncating a torn tail with a counter, never
    /// served) and refills a detached persistent session: sessions that
    /// do not exist yet are created detached (`clean_start = false`,
    /// unconnected, invisible to the live-session count) and filled
    /// without writing back. Files holding more than the configured cap
    /// keep the newest entries and are rewritten to the survivors.
    /// Sessions that already exist are left untouched and their files are
    /// left for the next restart.
    /// TODO(parity): should a reload merge into an already-live session
    /// (e.g. a store installed after traffic started) instead of
    /// skipping it? The rulebook does not decide the merge order; current
    /// choice restores only unknown clients and keeps live state
    /// authoritative.
    pub fn restore_offline_queues(&self) -> OfflineRestoreStats {
        let Some(store) = self.offline_store.read().clone() else {
            return OfflineRestoreStats {
                messages: 0,
                clients: 0,
                torn: 0,
                capped_dropped: 0,
            };
        };
        let mut stats = OfflineRestoreStats {
            messages: 0,
            clients: 0,
            torn: 0,
            capped_dropped: 0,
        };
        for client_id in store.client_ids() {
            let (records, torn) = store.load(&client_id);
            stats.torn += torn;
            if records.is_empty() {
                if torn > 0 {
                    store.remove(&client_id);
                }
                continue;
            }
            if self.sessions.read().contains_key(&client_id) {
                continue;
            }
            let messages: Vec<QueuedMessage> = records
                .into_iter()
                .map(|record| QueuedMessage {
                    topic: record.topic,
                    qos: record.qos,
                    retain: record.retain,
                    payload: record.payload,
                    publish_at_ms: record.publish_at_ms,
                })
                .collect();
            let id = SessionId(self.next_session_id.fetch_add(1, Ordering::SeqCst));
            let session = Arc::new(Session::new(id, client_id.clone(), false));
            self.apply_qos1_limits(&session);
            self.apply_topic_alias_limits(&session);
            session.set_offline_store(Some(store.clone()));
            *session.connected.write() = false;
            let dropped = session.push_restored_with_limit(messages, self.max_offline_queue);
            stats.capped_dropped += dropped;
            if dropped > 0 {
                let snapshot: Vec<OfflineRecord> = session
                    .offline_queue
                    .read()
                    .iter()
                    .map(|queued| OfflineRecord {
                        topic: queued.topic.clone(),
                        qos: queued.qos,
                        retain: queued.retain,
                        payload: queued.payload.clone(),
                        publish_at_ms: queued.publish_at_ms,
                    })
                    .collect();
                if store.rewrite(&client_id, &snapshot).is_err() {
                    tracing::warn!("Offline restore rewrite failed for {client_id}");
                }
            }
            let restored = session.offline_len();
            self.sessions.write().insert(client_id, session);
            if restored > 0 {
                stats.messages += restored;
                stats.clients += 1;
            }
        }
        stats
    }

    /// Configured offline queue cap (`None` = unbounded).
    pub fn max_offline_queue(&self) -> Option<usize> {
        self.max_offline_queue
    }

    /// Default QoS 1 window bound for sessions created after the last
    /// set (default [`DEFAULT_MAX_QOS1_INFLIGHT`]).
    pub fn max_qos1_inflight(&self) -> usize {
        self.max_qos1_inflight.load(Ordering::Relaxed).max(1)
    }

    /// Override the default QoS 1 window bound for sessions created
    /// afterwards (floored at 1). Existing sessions keep their own bound
    /// unless reconfigured via [`Session::set_max_inflight`].
    pub fn set_max_qos1_inflight(&self, limit: usize) {
        self.max_qos1_inflight
            .store(limit.max(1), Ordering::Relaxed);
    }

    /// Default QoS 1 spill bound for sessions created after the last set
    /// (default [`DEFAULT_MAX_QOS1_SPILL`]).
    pub fn max_qos1_spill(&self) -> usize {
        self.max_qos1_spill.load(Ordering::Relaxed).max(1)
    }

    /// Override the default QoS 1 spill bound for sessions created
    /// afterwards (floored at 1).
    pub fn set_max_qos1_spill(&self, limit: usize) {
        self.max_qos1_spill.store(limit.max(1), Ordering::Relaxed);
    }

    /// Apply this manager's current QoS 1 bounds to one session (new
    /// sessions at creation; reconfiguration callers may re-apply to an
    /// existing session explicitly).
    pub fn apply_qos1_limits(&self, session: &Arc<Session>) {
        session.set_max_inflight(self.max_qos1_inflight());
        session.set_max_spill(self.max_qos1_spill());
    }

    /// Default inbound topic-alias maximum for sessions created after
    /// the last set (default [`DEFAULT_TOPIC_ALIAS_MAXIMUM`]).
    pub fn max_topic_alias(&self) -> u16 {
        self.max_topic_alias.load(Ordering::Relaxed)
    }

    /// Override the default inbound topic-alias maximum for sessions
    /// created afterwards. Existing sessions keep their own bound unless
    /// reconfigured via [`Session::set_inbound_alias_max`].
    pub fn set_max_topic_alias(&self, max: u16) {
        self.max_topic_alias.store(max, Ordering::Relaxed);
    }

    /// Apply this manager's current topic-alias bound to one session
    /// (new sessions at creation; reconfiguration callers may re-apply
    /// explicitly). Sizes the inbound table; the outbound table stays
    /// empty until CONNECT carries the client's maximum.
    pub fn apply_topic_alias_limits(&self, session: &Arc<Session>) {
        session.set_inbound_alias_max(self.max_topic_alias());
    }

    /// Buffer one message for a detached session, applying this
    /// manager's offline cap. False when the client has no session or when
    /// the durable persist failed and nothing was queued (fail closed).
    pub fn queue_offline(&self, client_id: &str, message: QueuedMessage) -> bool {
        match self.get(client_id) {
            Some(session) => session.push_offline_with_limit(message, self.max_offline_queue),
            None => false,
        }
    }

    pub fn get(&self, client_id: &str) -> Option<Arc<Session>> {
        self.sessions.read().get(client_id).cloned()
    }

    /// Reverse lookup: owner of a live edge connection, if bound.
    /// O(1) via the `conn_id -> client_id` index; falls back to the
    /// legacy scan only on a miss so sessions bound through direct
    /// `conn_id` writes (paths outside the indexed bind hook) still
    /// resolve exactly as before.
    pub fn client_id_for_conn(&self, conn_id: u64) -> Option<String> {
        if let Some(owner) = self.conn_index.read().get(&conn_id).cloned() {
            return Some(owner);
        }
        self.sessions
            .read()
            .iter()
            .find(|(_, session)| *session.conn_id.read() == Some(conn_id))
            .map(|(client_id, _)| client_id.clone())
    }

    /// Pin an edge connection to its session and record the reverse
    /// mapping. Replaces any previous `conn_id` for this client (the
    /// stale entry is removed) and overwrites a reused `conn_id` left
    /// by another client. Short locks only: session write, then index
    /// write; never held across dispatch, routing, or I/O. Records the
    /// bind instant as the session connect time where the session is
    /// already being written.
    pub fn bind_session(&self, session: &Arc<Session>, conn_id: u64) {
        let old = *session.conn_id.read();
        if old == Some(conn_id) {
            let present = self
                .conn_index
                .read()
                .get(&conn_id)
                .map(|owner| owner == &session.client_id)
                .unwrap_or(false);
            if present {
                return;
            }
            self.conn_index
                .write()
                .insert(conn_id, session.client_id.clone());
            return;
        }
        *session.conn_id.write() = Some(conn_id);
        *session.connected_at_ms.write() = Some(now_ms());
        let mut index = self.conn_index.write();
        if let Some(prev) = old {
            let owned = index
                .get(&prev)
                .map(|owner| owner == &session.client_id)
                .unwrap_or(false);
            if owned {
                index.remove(&prev);
            }
        }
        index.insert(conn_id, session.client_id.clone());
    }

    /// Sorted ids of currently connected clients (for the management API).
    pub fn active_client_ids(&self) -> Vec<String> {
        let sessions = self.sessions.read();
        let mut ids: Vec<String> = sessions
            .iter()
            .filter(|(_, session)| *session.connected.read())
            .map(|(client_id, _)| client_id.clone())
            .collect();
        ids.sort();
        ids
    }

    /// Snapshot every subscription in the system for the global list
    /// (W1-14). Reads the session mirror written by the subscribe
    /// routes, not the router trie, so list reads never block the
    /// routing path: one short read per session plus one short map read,
    /// no router lock, no work on fan-out or fan-in. Covers connected
    /// and detached durable sessions (clean disconnects already drain
    /// their rows). Sorted by `(client_id, filter)` for a deterministic
    /// page order and truncated to [`MAX_GLOBAL_SUBSCRIPTIONS`] so one
    /// list call cannot balloon the node. Management-plane only.
    pub fn global_subscriptions(&self) -> Vec<GlobalSubscription> {
        let sessions = self.sessions.read();
        let mut rows: Vec<GlobalSubscription> = Vec::new();
        for (client_id, session) in sessions.iter() {
            for (filter, options) in session.subscriptions.read().iter() {
                if rows.len() >= MAX_GLOBAL_SUBSCRIPTIONS {
                    break;
                }
                rows.push(GlobalSubscription {
                    client_id: client_id.clone(),
                    filter: filter.clone(),
                    options: *options,
                });
            }
            if rows.len() >= MAX_GLOBAL_SUBSCRIPTIONS {
                break;
            }
        }
        drop(sessions);
        rows.sort_by(|a, b| {
            (a.client_id.as_str(), a.filter.as_str())
                .cmp(&(b.client_id.as_str(), b.filter.as_str()))
        });
        if rows.len() > MAX_GLOBAL_SUBSCRIPTIONS {
            rows.truncate(MAX_GLOBAL_SUBSCRIPTIONS);
        }
        rows
    }

    /// Full detail row for one client, if known (for the management API).
    pub fn client_info(&self, client_id: &str) -> Option<ClientInfo> {
        self.get(client_id).map(|session| ClientInfo {
            client_id: session.client_id.clone(),
            session_id: session.id.0,
            conn_id: *session.conn_id.read(),
            keepalive_secs: *session.keepalive_secs.read(),
            clean_start: session.clean_start,
            connected: *session.connected.read(),
            queued: session.offline_len(),
            subscriptions: {
                let mut subs: Vec<String> = session
                    .subscriptions
                    .read()
                    .keys()
                    .map(|filter| filter.as_str().to_string())
                    .collect();
                subs.sort();
                subs
            },
        })
    }

    /// Track one granted subscription on the session (mirrors the router).
    /// Legacy and live-MQTT callers only carry a QoS; the subscription
    /// options default to `nl = 0, rap = 0, rh = 0`.
    pub fn add_subscription(&self, client_id: &str, filter: TopicFilter, qos: QoS) {
        self.add_subscription_with_options(client_id, filter, qos, 0, 0, 0);
    }

    /// Track one granted management subscription with its full options.
    /// Values are already validated by the caller (`nl <= 1`, `rap <= 1`,
    /// `rh <= 2`); re-subscribing the same filter replaces the entry.
    pub fn add_subscription_with_options(
        &self,
        client_id: &str,
        filter: TopicFilter,
        qos: QoS,
        nl: u8,
        rap: u8,
        rh: u8,
    ) {
        if let Some(session) = self.get(client_id) {
            session
                .subscriptions
                .write()
                .insert(filter, SubscriptionOptions::new(qos, nl, rap, rh));
        }
    }

    /// Forget one subscription (unsubscribe / connection teardown).
    pub fn remove_subscription(&self, client_id: &str, filter: &TopicFilter) {
        if let Some(session) = self.get(client_id) {
            session.subscriptions.write().remove(filter);
        }
    }

    pub fn get_or_create(&self, client_id: &str, clean_start: bool) -> (Arc<Session>, bool) {
        // Cloned up front so no branch nests the store lock inside the
        // session-map guard (see `set_offline_store` for the other order,
        // which runs only at boot before serving starts).
        let store = self.offline_store.read().clone();

        if clean_start {
            // A clean start discards previous durable state by definition.
            // The queue file goes before the replacement session is
            // visible: the map is crash-volatile, so remove-first is the
            // crash-consistent order (a crash between remove and insert
            // restarts with neither file nor session, i.e. discarded; the
            // old insert-first order revived the queue on the next
            // restore). File I/O never runs under the map guard. A
            // missing file is a no-op.
            if let Some(store) = store.clone() {
                store.remove(client_id);
            }
        }
        let mut map = self.sessions.write();

        if clean_start {
            // A fresh session supersedes any live binding: capture the old
            // conn_id now so its index entry can be pruned below (after
            // the map guard drops; index lock never nests inside it).
            // Capture the old connected flag too so the live-session
            // counter stays exact: replacing a connected session keeps the
            // count, replacing a disconnected (or absent) one increments.
            let stale_conn = map.get(client_id).and_then(|s| *s.conn_id.read());
            let stale_connected = map
                .get(client_id)
                .map(|s| *s.connected.read())
                .unwrap_or(false);
            let id = SessionId(self.next_session_id.fetch_add(1, Ordering::SeqCst));
            let session = Arc::new(Session::new(id, client_id.to_string(), clean_start));
            self.apply_qos1_limits(&session);
            self.apply_topic_alias_limits(&session);
            session.set_offline_store(store.clone());
            map.insert(client_id.to_string(), session.clone());
            drop(map);
            if !stale_connected {
                self.connected_count.fetch_add(1, Ordering::SeqCst);
            }
            if let Some(stale) = stale_conn {
                let mut index = self.conn_index.write();
                if index
                    .get(&stale)
                    .map(|owner| owner == client_id)
                    .unwrap_or(false)
                {
                    index.remove(&stale);
                }
            }
            (session, false)
        } else if let Some(existing) = map.get(client_id) {
            let was_connected = *existing.connected.read();
            if !was_connected {
                *existing.connected.write() = true;
                *existing.connected_at_ms.write() = Some(now_ms());
                self.connected_count.fetch_add(1, Ordering::SeqCst);
            }
            existing.set_offline_store(store);
            (existing.clone(), true)
        } else {
            let id = SessionId(self.next_session_id.fetch_add(1, Ordering::SeqCst));
            let session = Arc::new(Session::new(id, client_id.to_string(), clean_start));
            self.apply_qos1_limits(&session);
            self.apply_topic_alias_limits(&session);
            session.set_offline_store(store);
            map.insert(client_id.to_string(), session.clone());
            drop(map);
            self.connected_count.fetch_add(1, Ordering::SeqCst);
            (session, false)
        }
    }

    /// Constant-time live-session count for the management count endpoint.
    /// Reads one atomic maintained by `get_or_create`/`unbind_connection`;
    /// never scans the session map and never runs on the message path.
    pub fn connected_count(&self) -> u64 {
        self.connected_count.load(Ordering::SeqCst)
    }

    /// Snapshot the subscription filters of one session, if known.
    /// Used by the kernel to sweep stale router entries on a clean-start
    /// bind (which discards any previous state, even a persistent one).
    pub fn subscription_filters(&self, client_id: &str) -> Vec<TopicFilter> {
        match self.get(client_id) {
            Some(session) => session.subscriptions.read().keys().cloned().collect(),
            None => Vec::new(),
        }
    }

    /// Drain the subscriptions of a clean session, returning the removed
    /// filters. Persistent sessions are untouched (empty return). The
    /// returned list is bounded by that session's own subscription count;
    /// delivery never calls here, so the per-message cost is zero.
    pub fn take_clean_subscriptions(&self, client_id: &str) -> Vec<TopicFilter> {
        match self.get(client_id) {
            Some(session) => {
                if session.clean_start {
                    session
                        .subscriptions
                        .write()
                        .drain()
                        .map(|(f, _)| f)
                        .collect()
                } else {
                    Vec::new()
                }
            }
            None => Vec::new(),
        }
    }

    /// Detach one edge connection, returning the subscription filters to
    /// sweep from the router. Only a verified owner detach of a clean
    /// session yields filters: racing teardowns for a superseded conn_id
    /// and persistent sessions both yield empty (their subscriptions
    /// survive, which is what durable redelivery builds on).
    pub fn unbind_connection(&self, client_id: &str, conn_id: u64) -> Vec<TopicFilter> {
        let (username_to_release, swept, did_detach): (Option<String>, Vec<TopicFilter>, bool) = {
            let map = self.sessions.read();
            match map.get(client_id) {
                Some(session) => {
                    let mut current_conn = session.conn_id.write();
                    if *current_conn == Some(conn_id) {
                        let was_connected = *session.connected.read();
                        *current_conn = None;
                        *session.connected.write() = false;
                        // Clean sessions keep no inflight or QoS 2 state
                        // across a disconnect (T-31, D1-01); durable
                        // sessions keep theirs for reconnect replay.
                        // Alias tables are per-connection either way
                        // (B4-05): they die with the connection.
                        session.clear_aliases();
                        if session.clean_start {
                            session.clear_inflight();
                            session.clear_qos2_inbound();
                            session.clear_qos2_outbound();
                        }
                        let swept = if session.clean_start {
                            session
                                .subscriptions
                                .write()
                                .drain()
                                .map(|(f, _)| f)
                                .collect()
                        } else {
                            Vec::new()
                        };
                        (session.username.read().clone(), swept, was_connected)
                    } else {
                        (None, Vec::new(), false)
                    }
                }
                None => (None, Vec::new(), false),
            }
        };
        if did_detach {
            // Verified owner detach of a live session: one fewer connected
            // session. Racing teardowns (wrong conn_id, unknown client)
            // and detaches of an already-disconnected session change
            // nothing, so the counter never underflows.
            let _ = self
                .connected_count
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1));
        }
        if let Some(username) = username_to_release {
            self.release_connection_slot(&username);
        }
        // Every path that clears `session.conn_id` also prunes the index:
        // remove only entries owned by this client so a racing teardown
        // for a superseded conn_id never drops the fresh binding.
        {
            let mut index = self.conn_index.write();
            if index
                .get(&conn_id)
                .map(|owner| owner == client_id)
                .unwrap_or(false)
            {
                index.remove(&conn_id);
            }
        }
        // Reconnects start with a full bucket; abandoned entries vanish.
        self.buckets.write().remove(client_id);
        swept
    }

    /// Admit one connection for `username` under an optional cap
    /// (`None` = unlimited). Single-lock check-and-increment: at most
    /// `max` concurrent holders ever observe success.
    pub fn acquire_connection_slot(&self, username: &str, max: Option<u32>) -> bool {
        let Some(max) = max else {
            return true;
        };
        let mut counts = self.conn_counts.write();
        let count = counts
            .entry(username.to_string())
            .or_insert_with(|| AtomicU32::new(0));
        if count.load(Ordering::SeqCst) >= max {
            return false;
        }
        count.fetch_add(1, Ordering::SeqCst);
        true
    }

    /// Release one previously acquired slot (saturates at zero: double
    /// releases from racing teardowns can never underflow).
    pub fn release_connection_slot(&self, username: &str) {
        if let Some(count) = self.conn_counts.read().get(username) {
            let _ = count.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1));
        }
    }

    /// Token-bucket gate for one publish by `client_id`. Buckets are
    /// created lazily with the currently configured `(rate, burst)` and
    /// reset when the configuration changes, so quota edits apply to the
    /// very next publish.
    pub fn check_publish_budget(&self, client_id: &str, rate: u32, burst: u32) -> bool {
        let mut buckets = self.buckets.write();
        let bucket = buckets
            .entry(client_id.to_string())
            .or_insert_with(|| TokenBucket::new(rate, burst));
        if bucket.rate_per_sec != rate || bucket.burst != burst {
            *bucket = TokenBucket::new(rate, burst);
        }
        bucket.try_consume()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_offline_dir(label: &str) -> std::path::PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let slot = COUNTER.fetch_add(1, Ordering::SeqCst);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "indramqtt-session-offline-{label}-{}-{nanos}-{slot}",
            std::process::id()
        ))
    }

    #[test]
    fn test_offline_durable_buffer_drain_and_restore() {
        let dir = unique_offline_dir("restore");
        let store = Arc::new(OfflineQueueStore::open(&dir).expect("open offline store"));
        let manager = SessionManager::new();
        manager.set_offline_store(store.clone());

        // Buffer through the session entry point: the file follows.
        let (session, _) = manager.get_or_create("durable-restore-1", false);
        for i in 0..3u8 {
            session.push_offline(QueuedMessage {
                topic: Topic::new("job/queue").unwrap(),
                qos: QoS::AtLeastOnce,
                retain: false,
                payload: Bytes::from(vec![i]),
                publish_at_ms: None,
            });
        }
        assert_eq!(session.offline_len(), 3);
        assert_eq!(store.client_ids(), vec!["durable-restore-1".to_string()]);

        // A fresh manager on the same directory rebuilds the queue detached.
        let fresh = SessionManager::new();
        fresh.set_offline_store(Arc::new(
            OfflineQueueStore::open(&dir).expect("reopen offline store"),
        ));
        let stats = fresh.restore_offline_queues();
        assert_eq!(stats.messages, 3);
        assert_eq!(stats.clients, 1);
        assert_eq!(stats.torn, 0);
        let restored = fresh.get("durable-restore-1").expect("restored session");
        assert!(!restored.clean_start);
        assert!(!*restored.connected.read());
        assert_eq!(restored.offline_len(), 3);
        let drained = restored.drain_offline();
        assert_eq!(drained[0].payload, Bytes::from(vec![0u8]));
        assert_eq!(drained[2].payload, Bytes::from(vec![2u8]));
        // Draining deletes the file: a second restart replays nothing.
        let again = SessionManager::new();
        again.set_offline_store(Arc::new(
            OfflineQueueStore::open(&dir).expect("reopen offline store"),
        ));
        let stats = again.restore_offline_queues();
        assert_eq!(stats.messages, 0);

        // A clean start discards the previous durable queue by definition.
        manager.get_or_create("durable-restore-1", true);
        assert!(store.client_ids().is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_offline_concurrent_enqueue_evict_survives_restart() {
        // Lost-update guard: concurrent enqueue plus eviction for one
        // client, and for two clients at once, through the session API the
        // broker calls on deliver to an offline session
        // (`SessionManager::queue_offline` -> `push_offline_with_limit` on
        // the disconnect-buffer event). After the join every message not
        // deliberately evicted by the bound is present after a restart from
        // disk, by id, with no tolerance.
        use std::collections::HashSet;

        fn payload_id(id: u32) -> Bytes {
            Bytes::from(id.to_be_bytes().to_vec())
        }

        fn payload_to_id(payload: &Bytes) -> u32 {
            let bytes: [u8; 4] = payload.as_ref().try_into().expect("4-byte id payload");
            u32::from_be_bytes(bytes)
        }

        fn message(id: u32) -> QueuedMessage {
            QueuedMessage {
                topic: Topic::new("job/queue").unwrap(),
                qos: QoS::AtLeastOnce,
                retain: false,
                payload: payload_id(id),
                publish_at_ms: None,
            }
        }

        let dir = unique_offline_dir("concurrent");
        let store = Arc::new(OfflineQueueStore::open(&dir).expect("open offline store"));
        // Finite cap with its reason: one dead client cannot balloon the
        // node past `cap` entries (see DEFAULT_MAX_OFFLINE_QUEUE); the
        // small test cap forces eviction rewrites on every push past it.
        let cap = 100usize;
        let manager = Arc::new(SessionManager::new_with_limits(Some(cap)));
        manager.set_offline_store(store.clone());
        for client in ["conc-a", "conc-b"] {
            let (session, _) = manager.get_or_create(client, false);
            *session.connected.write() = false;
            *session.conn_id.write() = None;
        }

        // Distinct id spaces per client so a cross-client clobber is
        // visible as a missing or foreign id. Four writers per client race
        // appends and eviction rewrites for the same queue, while both
        // clients' rewrites race each other for temp files.
        let threads_per_client = 4usize;
        let per_thread = 50usize;
        std::thread::scope(|scope| {
            for (client_index, client) in ["conc-a", "conc-b"].iter().enumerate() {
                let base = (client_index as u32) * 100_000;
                for writer in 0..threads_per_client {
                    let manager = manager.clone();
                    let client = client.to_string();
                    scope.spawn(move || {
                        let start = base + (writer as u32) * (per_thread as u32);
                        for offset in 0..(per_thread as u32) {
                            assert!(manager.queue_offline(&client, message(start + offset)));
                        }
                    });
                }
            }
        });

        for (client_index, client) in ["conc-a", "conc-b"].iter().enumerate() {
            let base = (client_index as u32) * 100_000;
            let pushed: HashSet<u32> = (0..(threads_per_client * per_thread) as u32)
                .map(|offset| base + offset)
                .collect();
            let session = manager.get(client).expect("session known");
            assert_eq!(session.offline_len(), cap);
            let memory_ids: Vec<u32> = session
                .take_offline_retained()
                .iter()
                .map(|queued| payload_to_id(&queued.payload))
                .collect();
            // Restore the memory queue: the snapshot above is ground truth
            // for what the bound deliberately kept.
            for id in &memory_ids {
                session.push_restored_with_limit(vec![message(*id)], Some(cap));
            }
            assert_eq!(memory_ids.len(), cap);
            let memory_set: HashSet<u32> = memory_ids.iter().copied().collect();
            assert_eq!(memory_set.len(), cap, "survivors must be distinct");
            for id in &memory_ids {
                assert!(pushed.contains(id), "survivor {id} was never pushed");
            }
            // Restart from disk: the file must hold exactly the survivors
            // in order, with no torn tail and no lost update.
            let reopened = OfflineQueueStore::open(&dir).expect("reopen offline store");
            let (loaded, torn) = reopened.load(client);
            assert_eq!(torn, 0, "concurrent rewrites must not tear the file");
            let disk_ids: Vec<u32> = loaded
                .iter()
                .map(|record| payload_to_id(&record.payload))
                .collect();
            assert_eq!(disk_ids, memory_ids, "disk must match memory exactly");
        }

        // The manager restore path rebuilds the same survivors detached.
        let fresh = SessionManager::new_with_limits(Some(cap));
        fresh.set_offline_store(Arc::new(
            OfflineQueueStore::open(&dir).expect("reopen offline store"),
        ));
        let stats = fresh.restore_offline_queues();
        assert_eq!(stats.clients, 2);
        assert_eq!(stats.messages, 2 * cap);
        assert_eq!(stats.torn, 0);
        for client in ["conc-a", "conc-b"] {
            assert_eq!(fresh.get(client).expect("restored").offline_len(), cap);
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_last_will_takes_exactly_once() {
        use super::StoredWill;

        let manager = SessionManager::new();
        let (session, _) = manager.get_or_create("will-1", true);
        assert!(session.take_last_will().is_none());

        session.set_last_will(Some(StoredWill {
            topic: Topic::new("will/test").unwrap(),
            qos: broker_protocol::QoS::AtLeastOnce,
            retain: true,
            payload: Bytes::from_static(b"gone"),
        }));
        let taken = session.take_last_will().expect("will stored");
        assert_eq!(taken.topic.as_str(), "will/test");
        assert_eq!(taken.payload, Bytes::from_static(b"gone"));
        // Second take observes None: edge and kernel notices race safely.
        assert!(session.take_last_will().is_none());

        // Reconnect without a will clears the previous one.
        session.set_last_will(Some(StoredWill {
            topic: Topic::new("will/test").unwrap(),
            qos: broker_protocol::QoS::AtMostOnce,
            retain: false,
            payload: Bytes::from_static(b"x"),
        }));
        session.set_last_will(None);
        assert!(session.take_last_will().is_none());
    }

    #[test]
    fn test_session_lifecycle() {
        let manager = SessionManager::new();

        let (s1, present1) = manager.get_or_create("device-001", true);
        assert!(!present1);
        assert_eq!(s1.client_id, "device-001");

        let (s2, present2) = manager.get_or_create("device-001", false);
        assert!(present2);
        assert_eq!(s1.id, s2.id);

        let (s3, present3) = manager.get_or_create("device-001", true);
        assert!(!present3); // clean_start true creates fresh session
        assert_ne!(s1.id, s3.id);

        assert!(manager.get("device-001").is_some());
        assert!(manager.get("unknown-device").is_none());
    }

    #[test]
    fn test_active_client_ids_tracks_connections() {
        let manager = SessionManager::new();
        assert!(manager.active_client_ids().is_empty());

        manager.get_or_create("client-b", true);
        manager.get_or_create("client-a", true);
        assert_eq!(manager.active_client_ids(), vec!["client-a", "client-b"]);

        // Detaching removes the client from the active set.
        let (session, _) = manager.get_or_create("client-a", false);
        *session.conn_id.write() = Some(7);
        manager.unbind_connection("client-a", 7);
        assert_eq!(manager.active_client_ids(), vec!["client-b"]);
    }

    #[test]
    fn test_connected_count_tracks_connects_and_disconnects() {
        let manager = SessionManager::new();
        assert_eq!(manager.connected_count(), 0);

        // Two fresh sessions read as two without scanning.
        let (a, _) = manager.get_or_create("w1-13-a", true);
        manager.bind_session(&a, 13_101);
        let (b, _) = manager.get_or_create("w1-13-b", true);
        manager.bind_session(&b, 13_102);
        assert_eq!(manager.connected_count(), 2);
        assert_eq!(manager.active_client_ids().len(), 2);

        // Replacing a connected clean session keeps the count.
        manager.get_or_create("w1-13-a", true);
        assert_eq!(manager.connected_count(), 2);

        // The replacement drops the old binding: rebind before detaching.
        let fresh = manager.get("w1-13-a").expect("replaced session");
        manager.bind_session(&fresh, 13_103);
        assert_eq!(manager.connected_count(), 2);

        // One verified detach drops to one; racing teardowns change nothing.
        manager.unbind_connection("w1-13-a", 13_103);
        assert_eq!(manager.connected_count(), 1);
        manager.unbind_connection("w1-13-a", 13_103);
        manager.unbind_connection("w1-13-b", 999);
        assert_eq!(manager.connected_count(), 1);

        // Persistent reconnect of a detached session increments again.
        let (durable, _) = manager.get_or_create("w1-13-d", false);
        assert_eq!(manager.connected_count(), 2);
        *durable.conn_id.write() = Some(77);
        manager.unbind_connection("w1-13-d", 77);
        assert_eq!(manager.connected_count(), 1);
        manager.get_or_create("w1-13-d", false);
        assert_eq!(manager.connected_count(), 2);
    }

    #[test]
    fn test_client_info_and_subscription_tracking() {
        let manager = SessionManager::new();
        assert!(manager.client_info("ghost").is_none());

        let (session, _) = manager.get_or_create("detail-9", false);
        *session.conn_id.write() = Some(99);
        *session.keepalive_secs.write() = 30;
        manager.add_subscription(
            "detail-9",
            TopicFilter::new("sensors/+").unwrap(),
            broker_protocol::QoS::AtLeastOnce,
        );
        manager.add_subscription(
            "detail-9",
            TopicFilter::new("alerts").unwrap(),
            broker_protocol::QoS::AtMostOnce,
        );

        let info = manager.client_info("detail-9").expect("known client");
        assert_eq!(info.client_id, "detail-9");
        assert_eq!(info.session_id, session.id.0);
        assert_eq!(info.conn_id, Some(99));
        assert_eq!(info.keepalive_secs, 30);
        assert!(!info.clean_start);
        assert!(info.connected);
        assert_eq!(info.queued, 0);
        assert_eq!(
            info.subscriptions,
            vec!["alerts".to_string(), "sensors/+".to_string()]
        );

        manager.remove_subscription("detail-9", &TopicFilter::new("alerts").unwrap());
        let info = manager.client_info("detail-9").expect("still known");
        assert_eq!(info.subscriptions, vec!["sensors/+".to_string()]);

        // Unknown clients are no-ops, never panics.
        manager.add_subscription(
            "ghost",
            TopicFilter::new("a").unwrap(),
            broker_protocol::QoS::AtMostOnce,
        );
        manager.remove_subscription("ghost", &TopicFilter::new("a").unwrap());
    }

    #[test]
    fn test_offline_queue_buffers_and_drains() {
        use super::QueuedMessage;

        let manager = SessionManager::new();
        let (session, _) = manager.get_or_create("offline-1", false);

        assert_eq!(session.offline_len(), 0);
        assert!(session.drain_offline().is_empty());

        for i in 0..3u8 {
            session.push_offline(QueuedMessage {
                topic: Topic::new("job/queue").unwrap(),
                qos: broker_protocol::QoS::AtLeastOnce,
                retain: false,
                payload: Bytes::from(vec![i]),
                publish_at_ms: None,
            });
        }
        assert_eq!(session.offline_len(), 3);

        let drained = session.drain_offline();
        assert_eq!(drained.len(), 3);
        assert_eq!(drained[0].payload, Bytes::from(vec![0u8]));
        assert_eq!(drained[2].payload, Bytes::from(vec![2u8]));
        // Draining empties the queue.
        assert_eq!(session.offline_len(), 0);
        assert!(session.drain_offline().is_empty());
    }

    #[test]
    fn test_inflight_tracks_acks_and_stays_bounded() {
        use super::{InflightMessage, MAX_QOS1_INFLIGHT};

        fn inflight(pid: u16) -> InflightMessage {
            InflightMessage {
                packet_id: pid,
                topic: Topic::new("t").unwrap(),
                qos: broker_protocol::QoS::AtLeastOnce,
                retain: false,
                payload: Bytes::from(vec![pid as u8]),
                enqueued_at: Instant::now(),
            }
        }

        let manager = SessionManager::new();
        let (session, _) = manager.get_or_create("inflight-1", false);
        assert_eq!(session.inflight_len(), 0);

        // Track + ack round trip; stale acks are no-ops.
        assert!(session.track_inflight(inflight(7)));
        assert!(session.track_inflight(inflight(8)));
        assert_eq!(session.inflight_len(), 2);
        assert!(session.ack_inflight(7));
        assert!(!session.ack_inflight(7));
        assert_eq!(session.inflight_len(), 1);
        // Snapshot preserves order and keeps entries held for replay.
        assert!(session.track_inflight(inflight(9)));
        let snap = session.inflight_snapshot();
        assert_eq!(
            snap.iter().map(|m| m.packet_id).collect::<Vec<_>>(),
            vec![8, 9]
        );
        assert_eq!(session.inflight_len(), 2);

        // Fill to the bound: the next track refuses without growing.
        for pid in 10..(10 + MAX_QOS1_INFLIGHT as u16) {
            let _ = session.track_inflight(inflight(pid));
        }
        assert_eq!(session.inflight_len(), MAX_QOS1_INFLIGHT);
        assert!(!session.track_inflight(inflight(60000)));
        assert_eq!(session.inflight_len(), MAX_QOS1_INFLIGHT);

        // Packet ids skip held entries so resume never collides.
        let fresh = session.next_packet_id();
        assert!(
            !session
                .inflight_snapshot()
                .iter()
                .any(|m| m.packet_id == fresh),
            "fresh id must avoid inflight ids"
        );

        // Clean disconnect clears; durable disconnect keeps.
        let (clean, _) = manager.get_or_create("inflight-clean", true);
        assert!(clean.track_inflight(inflight(21)));
        *clean.conn_id.write() = Some(99);
        manager.unbind_connection("inflight-clean", 99);
        assert_eq!(clean.inflight_len(), 0);
        *session.conn_id.write() = Some(77);
        manager.unbind_connection("inflight-1", 77);
        assert_eq!(session.inflight_len(), MAX_QOS1_INFLIGHT);
        session.clear_inflight();
        assert_eq!(session.inflight_len(), 0);
        assert_eq!(session.inflight_spill_len(), 0);
    }

    #[test]
    fn test_inflight_spill_tracks_past_window_in_order() {
        use super::{InflightMessage, InflightTrackOutcome, DEFAULT_MAX_QOS1_INFLIGHT};

        fn inflight(pid: u16) -> InflightMessage {
            InflightMessage {
                packet_id: pid,
                topic: Topic::new("t").unwrap(),
                qos: broker_protocol::QoS::AtLeastOnce,
                retain: false,
                payload: Bytes::from(vec![pid as u8]),
                enqueued_at: Instant::now(),
            }
        }

        let manager = SessionManager::new();
        let (session, _) = manager.get_or_create("spill-1", false);
        assert_eq!(session.max_inflight(), DEFAULT_MAX_QOS1_INFLIGHT);

        // Fill the window: every entry tracks fast.
        for pid in 1..=(DEFAULT_MAX_QOS1_INFLIGHT as u16) {
            assert_eq!(
                session.track_inflight_or_spill(inflight(pid)),
                InflightTrackOutcome::Tracked
            );
        }
        assert_eq!(session.inflight_len(), DEFAULT_MAX_QOS1_INFLIGHT);
        assert_eq!(session.inflight_spill_len(), 0);

        // Past the window: still tracked, now in spill, oldest-first.
        assert_eq!(
            session.track_inflight_or_spill(inflight(1001)),
            InflightTrackOutcome::Spilled
        );
        assert_eq!(
            session.track_inflight_or_spill(inflight(1002)),
            InflightTrackOutcome::Spilled
        );
        assert_eq!(session.inflight_len(), DEFAULT_MAX_QOS1_INFLIGHT);
        assert_eq!(session.inflight_spill_len(), 2);
        assert_eq!(session.inflight_total_len(), DEFAULT_MAX_QOS1_INFLIGHT + 2);
        let spill = session.inflight_spill_snapshot();
        assert_eq!(
            spill.iter().map(|m| m.packet_id).collect::<Vec<_>>(),
            vec![1001, 1002]
        );

        // Ack one window entry: the oldest spill promotes so the window
        // stays the oldest entries and replay order holds.
        assert!(session.ack_inflight(1));
        assert_eq!(session.inflight_len(), DEFAULT_MAX_QOS1_INFLIGHT);
        assert_eq!(session.inflight_spill_len(), 1);
        let snap = session.inflight_snapshot();
        assert_eq!(snap.last().expect("window nonempty").packet_id, 1001);
        assert_eq!(session.inflight_spill_snapshot()[0].packet_id, 1002);

        // Ack a spilled id directly releases it.
        assert!(session.ack_inflight(1002));
        assert_eq!(session.inflight_spill_len(), 0);
        assert!(!session.ack_inflight(1002));

        // Packet ids skip both window and spill.
        let fresh = session.next_packet_id();
        assert!(
            !session
                .inflight_snapshot()
                .iter()
                .any(|m| m.packet_id == fresh)
                && !session
                    .inflight_spill_snapshot()
                    .iter()
                    .any(|m| m.packet_id == fresh),
            "fresh id must avoid window and spill ids"
        );
    }

    #[test]
    fn test_inflight_bound_configurable_and_spill_bounded() {
        use super::{InflightMessage, InflightTrackOutcome};

        fn inflight(pid: u16) -> InflightMessage {
            InflightMessage {
                packet_id: pid,
                topic: Topic::new("t").unwrap(),
                qos: broker_protocol::QoS::AtLeastOnce,
                retain: false,
                payload: Bytes::from(vec![pid as u8]),
                enqueued_at: Instant::now(),
            }
        }

        // Manager defaults apply to sessions created afterwards.
        let manager = SessionManager::new_with_all_limits(Some(10), 3, 2);
        assert_eq!(manager.max_qos1_inflight(), 3);
        assert_eq!(manager.max_qos1_spill(), 2);
        let (session, _) = manager.get_or_create("tiny-window", false);
        assert_eq!(session.max_inflight(), 3);
        assert_eq!(session.max_spill(), 2);

        for pid in 1..=3u16 {
            assert_eq!(
                session.track_inflight_or_spill(inflight(pid)),
                InflightTrackOutcome::Tracked
            );
        }
        for pid in [4u16, 5] {
            assert_eq!(
                session.track_inflight_or_spill(inflight(pid)),
                InflightTrackOutcome::Spilled
            );
        }
        // Window + spill full: the newest live delivery drops, counted by
        // the caller. The store never grows past 3 + 2.
        assert_eq!(
            session.track_inflight_or_spill(inflight(6)),
            InflightTrackOutcome::Dropped
        );
        assert_eq!(session.inflight_total_len(), 5);

        // Zero floors at one; per-session override works.
        manager.set_max_qos1_inflight(0);
        manager.set_max_qos1_spill(0);
        assert_eq!(manager.max_qos1_inflight(), 1);
        assert_eq!(manager.max_qos1_spill(), 1);
        session.set_max_inflight(0);
        session.set_max_spill(0);
        assert_eq!(session.max_inflight(), 1);
        assert_eq!(session.max_spill(), 1);
    }

    #[test]
    fn test_qos1_inflight_hot_path_timings() {
        // B4-01 timing record for the session store (RULEBOOK.md:70).
        // Before/after pair measured in this same run: BEFORE is the
        // legacy window-only `track_inflight` loop below (exactly the
        // pre-B4-01 publish fast path: one bounded push under a single
        // write lock per track, one write lock per ack, no spill work
        // ever); AFTER is the spill-aware `track_inflight_or_spill` loop
        // with the spill empty (the same work plus one relaxed atomic
        // guard load on the ack path). The delta between the two printed
        // rates is the measured cost of the bound on the hot path.
        // Broker publish-to-delivery before/after numbers (delivery rate
        // through `apply_publish`, plus `replay_offline` replay rate) are
        // printed by the broker-node test
        // `qos1_inflight_delivery_workload_timings`, which drives the real
        // publish-to-delivery and reconnect-replay events; the broker-node
        // spill/redelivery/config tests give functional cover. Loop counts
        // below are sample sizes chosen for stable timing on CI, not
        // throughput SLOs. Every section prints its measured ops/sec and
        // avg ns/op into the gate output with no threshold assert.
        use super::{InflightMessage, InflightTrackOutcome, DEFAULT_MAX_QOS1_INFLIGHT};
        use std::hint::black_box;
        use std::time::Instant;

        let manager = SessionManager::new();
        let (session, _) = manager.get_or_create("hot-path-timing", false);
        let topic = Topic::new("t").unwrap();
        let payload = Bytes::from_static(b"x");
        let mut pid: u16 = 1;
        let make = |pid: u16| InflightMessage {
            packet_id: pid,
            topic: topic.clone(),
            qos: broker_protocol::QoS::AtLeastOnce,
            retain: false,
            payload: payload.clone(),
            enqueued_at: Instant::now(),
        };

        // BEFORE baseline (pre-B4-01 window-only entry point): the legacy
        // `track_inflight`/`ack_inflight` loop on its own session. This is
        // exactly the work the publish fast path did before B4-01 (one
        // bounded deque push under a single write lock per track, one
        // write lock per ack, no spill atomic/lock/scan ever), measured in
        // this same run so the gate output holds a genuine before number
        // next to the after number below.
        let (baseline, _) = manager.get_or_create("hot-path-baseline", false);
        let mut base_pid: u16 = 1;
        let base_iters = 20_000usize;
        let base_start = Instant::now();
        for _ in 0..base_iters {
            if base_pid == 0 {
                base_pid = 1;
            }
            assert!(baseline.track_inflight(black_box(make(base_pid))));
            assert!(black_box(baseline.ack_inflight(black_box(base_pid))));
            base_pid = base_pid.wrapping_add(1);
        }
        let base_elapsed = base_start.elapsed();
        assert!(
            !baseline.has_spill(),
            "legacy window-only path must never touch the spill"
        );
        let base_ops = (base_iters * 2) as f64;
        let base_rate = base_ops / base_elapsed.as_secs_f64();
        let base_avg_ns = base_elapsed.as_nanos() as f64 / base_ops;
        println!(
            "qos1 inflight hot-path baseline pre-B4-01 (window-only track_inflight): {base_rate:.0} ops/sec, avg {base_avg_ns:.1} ns/op ({base_iters} track+ack rounds in {base_elapsed:?})"
        );

        // Warmup so locks and branch predictors settle.
        for _ in 0..1_000 {
            if pid == 0 {
                pid = 1;
            }
            assert_eq!(
                session.track_inflight_or_spill(make(pid)),
                InflightTrackOutcome::Tracked
            );
            assert!(session.ack_inflight(pid));
            pid = pid.wrapping_add(1);
        }
        assert!(
            !session.has_spill(),
            "warmup must leave the spill empty (steady state)"
        );

        // AFTER: steady-state track+ack throughput (spill empty) through
        // the spill-aware entry point: one relaxed atomic load + one
        // bounded deque push under a single write lock per track, one
        // write lock + one atomic load per ack, no spill
        // lock/scan/snapshot allocation. Compare with the BEFORE baseline
        // above; the delta is the measured hot-path cost of the bound.
        let iters = 20_000usize;
        let start = Instant::now();
        for _ in 0..iters {
            if pid == 0 {
                pid = 1;
            }
            assert_eq!(
                session.track_inflight_or_spill(black_box(make(pid))),
                InflightTrackOutcome::Tracked
            );
            assert!(black_box(session.ack_inflight(black_box(pid))));
            pid = pid.wrapping_add(1);
        }
        let elapsed = start.elapsed();
        assert!(
            !session.has_spill(),
            "steady-state loop must never touch the spill buffer"
        );
        let ops = (iters * 2) as f64;
        let rate = ops / elapsed.as_secs_f64();
        let avg_ns = elapsed.as_nanos() as f64 / ops;
        println!(
            "qos1 inflight hot-path steady-state (spill empty): {rate:.0} ops/sec, avg {avg_ns:.1} ns/op ({iters} track+ack rounds in {elapsed:?})"
        );

        // Steady-state packet-id allocation (spill empty): same 2 read
        // locks as before B4-01 plus one relaxed atomic guard load, no
        // spill read lock or O(spill) scan.
        let id_iters = 5_000usize;
        let id_start = Instant::now();
        for _ in 0..id_iters {
            black_box(session.next_packet_id());
        }
        let id_elapsed = id_start.elapsed();
        let id_rate = id_iters as f64 / id_elapsed.as_secs_f64();
        let id_avg_ns = id_elapsed.as_nanos() as f64 / id_iters as f64;
        println!(
            "qos1 next_packet_id steady-state (spill empty): {id_rate:.0} ids/sec, avg {id_avg_ns:.1} ns/id ({id_iters} ids in {id_elapsed:?})"
        );

        // Spill-nonempty (slow path) record on a separate session so the
        // steady-state session above stays empty. Window full plus 100
        // spilled entries: id allocation pays the O(spill) scan, ack of a
        // window entry pays the nested spill lock + one promotion, and
        // the spill snapshot pays one Vec alloc + clone of the spill.
        let (slow, _) = manager.get_or_create("hot-path-spill-slow", false);
        for p in 1..=(DEFAULT_MAX_QOS1_INFLIGHT as u16) {
            assert_eq!(
                slow.track_inflight_or_spill(make(p)),
                InflightTrackOutcome::Tracked
            );
        }
        for p in 1001..1101u16 {
            assert_eq!(
                slow.track_inflight_or_spill(make(p)),
                InflightTrackOutcome::Spilled
            );
        }
        assert!(slow.has_spill(), "slow-path section needs a nonempty spill");

        let slow_id_iters = 5_000usize;
        let slow_id_start = Instant::now();
        for _ in 0..slow_id_iters {
            black_box(slow.next_packet_id());
        }
        let slow_id_elapsed = slow_id_start.elapsed();
        let slow_id_rate = slow_id_iters as f64 / slow_id_elapsed.as_secs_f64();
        let slow_id_avg_ns = slow_id_elapsed.as_nanos() as f64 / slow_id_iters as f64;
        println!(
            "qos1 next_packet_id spill-nonempty (100 spilled): {slow_id_rate:.0} ids/sec, avg {slow_id_avg_ns:.1} ns/id ({slow_id_iters} ids in {slow_id_elapsed:?})"
        );

        let snap_iters = 1_000usize;
        let snap_start = Instant::now();
        for _ in 0..snap_iters {
            black_box(slow.inflight_spill_snapshot());
        }
        let snap_elapsed = snap_start.elapsed();
        let snap_rate = snap_iters as f64 / snap_elapsed.as_secs_f64();
        let snap_avg_ns = snap_elapsed.as_nanos() as f64 / snap_iters as f64;
        println!(
            "qos1 spill snapshot spill-nonempty (100 spilled): {snap_rate:.0} snaps/sec, avg {snap_avg_ns:.1} ns/snap ({snap_iters} snaps in {snap_elapsed:?})"
        );

        let ack_count = 50u16;
        let ack_start = Instant::now();
        for p in 1..=ack_count {
            assert!(black_box(slow.ack_inflight(black_box(p))));
        }
        let ack_elapsed = ack_start.elapsed();
        let ack_rate = f64::from(ack_count) / ack_elapsed.as_secs_f64();
        let ack_avg_ns = ack_elapsed.as_nanos() as f64 / f64::from(ack_count);
        println!(
            "qos1 ack-with-promotion spill-nonempty (100 spilled): {ack_rate:.0} acks/sec, avg {ack_avg_ns:.1} ns/ack ({ack_count} acks in {ack_elapsed:?})"
        );
        assert!(
            slow.has_spill(),
            "promotion batch must leave spill nonempty"
        );
    }

    #[test]
    fn test_offline_queue_evicts_oldest_past_cap() {
        use super::{QueuedMessage, MAX_OFFLINE_QUEUE};

        let manager = SessionManager::new();
        let (session, _) = manager.get_or_create("offline-2", false);

        for i in 0..(MAX_OFFLINE_QUEUE + 10) {
            session.push_offline(QueuedMessage {
                topic: Topic::new("t").unwrap(),
                qos: broker_protocol::QoS::AtMostOnce,
                retain: false,
                payload: Bytes::from((i as u32).to_be_bytes().to_vec()),
                publish_at_ms: None,
            });
        }
        assert_eq!(session.offline_len(), MAX_OFFLINE_QUEUE);
        // The first surviving entry is #10: the oldest ten dropped.
        let drained = session.drain_offline();
        assert_eq!(
            drained[0].payload,
            Bytes::from(10u32.to_be_bytes().to_vec())
        );
    }

    #[test]
    fn test_offline_queue_limit_configurable() {
        use super::{QueuedMessage, DEFAULT_MAX_OFFLINE_QUEUE};

        fn message(i: u32) -> QueuedMessage {
            QueuedMessage {
                topic: Topic::new("t").unwrap(),
                qos: broker_protocol::QoS::AtMostOnce,
                retain: false,
                payload: Bytes::from(i.to_be_bytes().to_vec()),
                publish_at_ms: None,
            }
        }

        // Default manager caps at 10,000.
        let manager = SessionManager::new();
        assert_eq!(manager.max_offline_queue(), Some(DEFAULT_MAX_OFFLINE_QUEUE));
        assert_eq!(DEFAULT_MAX_OFFLINE_QUEUE, 10_000);
        manager.get_or_create("capped", false);
        for i in 0..(DEFAULT_MAX_OFFLINE_QUEUE + 100) {
            assert!(manager.queue_offline("capped", message(i as u32)));
        }
        let session = manager.get("capped").unwrap();
        assert_eq!(session.offline_len(), DEFAULT_MAX_OFFLINE_QUEUE);
        assert_eq!(
            session.drain_offline()[0].payload,
            Bytes::from(100u32.to_be_bytes().to_vec())
        );

        // Unknown clients queue nothing.
        assert!(!manager.queue_offline("ghost", message(0)));

        // Custom small cap evicts oldest past the limit.
        let manager = SessionManager::new_with_limits(Some(3));
        assert_eq!(manager.max_offline_queue(), Some(3));
        manager.get_or_create("tiny", false);
        for i in 0..5u32 {
            assert!(manager.queue_offline("tiny", message(i)));
        }
        let session = manager.get("tiny").unwrap();
        assert_eq!(session.offline_len(), 3);
        let drained = session.drain_offline();
        assert_eq!(drained[0].payload, Bytes::from(2u32.to_be_bytes().to_vec()));

        // Zero floors at one; huge caps have no ceiling.
        assert_eq!(
            SessionManager::new_with_limits(Some(0)).max_offline_queue(),
            Some(1)
        );
        assert_eq!(
            SessionManager::new_with_limits(Some(10_000_000)).max_offline_queue(),
            Some(10_000_000)
        );

        // None queues without bound.
        let manager = SessionManager::new_with_limits(None);
        assert_eq!(manager.max_offline_queue(), None);
        manager.get_or_create("free", false);
        for i in 0..20_000u32 {
            assert!(manager.queue_offline("free", message(i)));
        }
        assert_eq!(manager.get("free").unwrap().offline_len(), 20_000);
    }

    #[test]
    fn test_connection_slots_enforce_max() {
        let manager = SessionManager::new();

        // Unlimited by default: always admitted.
        for _ in 0..10 {
            assert!(manager.acquire_connection_slot("free-user", None));
        }

        // Exactly max admissions, then denial: #101 of max 100 fails.
        for _ in 0..100 {
            assert!(manager.acquire_connection_slot("capped", Some(100)));
        }
        assert!(!manager.acquire_connection_slot("capped", Some(100)));

        // Releasing re-opens exactly one slot.
        manager.release_connection_slot("capped");
        assert!(manager.acquire_connection_slot("capped", Some(100)));
        assert!(!manager.acquire_connection_slot("capped", Some(100)));

        // Releases saturate at zero: unknown users and double releases
        // never underflow or panic.
        manager.release_connection_slot("ghost");
        manager.release_connection_slot("capped");
        manager.release_connection_slot("capped");

        // Unbind detaches and releases the owner's slot together.
        let (session, _) = manager.get_or_create("bound-client", true);
        *session.conn_id.write() = Some(11);
        *session.username.write() = Some("capped".to_string());
        assert!(manager.acquire_connection_slot("capped", Some(100)));
        manager.unbind_connection("bound-client", 11);
        assert!(!*session.connected.read());
        // Slot freed by the detach: a fresh bind is admitted again.
        assert!(manager.acquire_connection_slot("capped", Some(100)));

        // A racing teardown for a superseded conn_id releases nothing:
        // admission still succeeds exactly as before.
        manager.unbind_connection("bound-client", 999);
        assert!(manager.acquire_connection_slot("capped", Some(100)));
        assert!(!manager.acquire_connection_slot("capped", Some(100)));
    }

    #[test]
    fn test_token_bucket_burst_then_throttles() {
        let mut bucket = TokenBucket::new(10, 2);
        assert!(bucket.try_consume());
        assert!(bucket.try_consume());
        // Burst spent: immediate third consume fails.
        assert!(!bucket.try_consume());
    }

    #[tokio::test]
    async fn test_check_publish_budget_refills_over_time() {
        let manager = SessionManager::new();
        // Burst of 1 at 1000 msg/s: first passes, immediate second drops.
        assert!(manager.check_publish_budget("fast", 1000, 1));
        assert!(!manager.check_publish_budget("fast", 1000, 1));
        // After ~5ms the bucket refilled ~5 tokens: passes again.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        assert!(manager.check_publish_budget("fast", 1000, 1));

        // Reconfiguring quotas resets the bucket immediately (no sleep):
        // drain it first, then widen the burst and pass at once.
        assert!(!manager.check_publish_budget("fast", 1000, 1));
        assert!(manager.check_publish_budget("fast", 1000, 50));
        assert!(manager.check_publish_budget("fast", 1000, 50));
    }

    #[test]
    fn conn_id_index_tracks_bind_unbind() {
        let manager = SessionManager::new();
        let count = 32u64;
        let mut bound: Vec<(String, u64)> = Vec::new();
        for i in 0..count {
            let client_id = format!("perf-client-{i:03}");
            let (session, _) = manager.get_or_create(&client_id, true);
            let conn_id = 10_000 + i;
            manager.bind_session(&session, conn_id);
            bound.push((client_id, conn_id));
        }

        // O(1) lookup hits for every bound connection.
        for (client_id, conn_id) in &bound {
            assert_eq!(
                manager.client_id_for_conn(*conn_id),
                Some(client_id.clone()),
                "indexed lookup hits for {client_id}"
            );
        }
        // Unknown ids miss exactly like the old scan did.
        assert_eq!(manager.client_id_for_conn(999_999), None);

        // Unbind one: its entry is gone, the rest are intact.
        manager.unbind_connection(&bound[0].0, bound[0].1);
        assert_eq!(manager.client_id_for_conn(bound[0].1), None);
        for (client_id, conn_id) in bound.iter().skip(1) {
            assert_eq!(
                manager.client_id_for_conn(*conn_id),
                Some(client_id.clone())
            );
        }

        // Rebind the same client on a new conn_id: old id misses, new hits.
        let (session, _) = manager.get_or_create(&bound[0].0, false);
        manager.bind_session(&session, 77_000);
        assert_eq!(manager.client_id_for_conn(bound[0].1), None);
        assert_eq!(manager.client_id_for_conn(77_000), Some(bound[0].0.clone()));

        // Clean-start replacement evicts the stale binding.
        let stale = 77_000u64;
        let (fresh, _) = manager.get_or_create(&bound[0].0, true);
        assert_eq!(*fresh.conn_id.read(), None);
        assert_eq!(manager.client_id_for_conn(stale), None);
        manager.bind_session(&fresh, 77_001);
        assert_eq!(manager.client_id_for_conn(77_001), Some(bound[0].0.clone()));
    }

    #[test]
    fn test_unbind_prunes_publish_bucket() {
        let manager = SessionManager::new();
        let (session, _) = manager.get_or_create("pruned", true);
        *session.conn_id.write() = Some(21);

        // Spend the whole burst, then detach: the bucket is forgotten.
        assert!(manager.check_publish_budget("pruned", 1000, 1));
        assert!(!manager.check_publish_budget("pruned", 1000, 1));
        manager.unbind_connection("pruned", 21);

        // Reconnect starts full again without waiting for refill.
        assert!(manager.check_publish_budget("pruned", 1000, 1));
    }

    #[test]
    fn test_unbind_drains_clean_subscriptions_only() {
        // Clean session: detach returns its filters and empties the mirror.
        let manager = SessionManager::new();
        let (clean, _) = manager.get_or_create("tk04-clean", true);
        *clean.conn_id.write() = Some(81);
        manager.add_subscription(
            "tk04-clean",
            TopicFilter::new("tk04/ghost").unwrap(),
            broker_protocol::QoS::AtMostOnce,
        );
        assert_eq!(manager.subscription_filters("tk04-clean").len(), 1);
        let swept = manager.unbind_connection("tk04-clean", 81);
        assert_eq!(swept.len(), 1);
        assert_eq!(swept[0].as_str(), "tk04/ghost");
        assert!(manager.subscription_filters("tk04-clean").is_empty());

        // Persistent session: detach yields nothing and keeps the mirror.
        let (durable, _) = manager.get_or_create("tk04-durable", false);
        *durable.conn_id.write() = Some(91);
        manager.add_subscription(
            "tk04-durable",
            TopicFilter::new("tk04/kept").unwrap(),
            broker_protocol::QoS::AtMostOnce,
        );
        let swept = manager.unbind_connection("tk04-durable", 91);
        assert!(swept.is_empty());
        assert_eq!(manager.subscription_filters("tk04-durable").len(), 1);

        // Racing teardown for a superseded conn_id sweeps nothing.
        let swept = manager.unbind_connection("tk04-durable", 999);
        assert!(swept.is_empty());
        assert_eq!(manager.subscription_filters("tk04-durable").len(), 1);
    }

    #[test]
    fn topic_alias_inbound_register_resolve_reject() {
        let manager = SessionManager::new();
        let (session, _) = manager.get_or_create("alias-in-1", true);
        assert_eq!(session.inbound_alias_max(), DEFAULT_TOPIC_ALIAS_MAXIMUM);
        // Alias 0 is never valid.
        assert_eq!(
            session.register_inbound_alias(0, Topic::new("a/b").unwrap()),
            Err(AliasReject::Zero)
        );
        // Above the maximum is rejected.
        assert_eq!(
            session.register_inbound_alias(
                DEFAULT_TOPIC_ALIAS_MAXIMUM + 1,
                Topic::new("a/b").unwrap()
            ),
            Err(AliasReject::OverMaximum)
        );
        // Valid registration resolves.
        session
            .register_inbound_alias(1, Topic::new("sensors/temp").unwrap())
            .expect("alias 1 registers");
        assert_eq!(
            session
                .resolve_inbound_alias(1)
                .expect("alias 1 resolves")
                .as_str(),
            "sensors/temp"
        );
        assert_eq!(session.inbound_alias_len(), 1);
        // Re-registering the same alias overwrites (documented behaviour).
        session
            .register_inbound_alias(1, Topic::new("sensors/hum").unwrap())
            .expect("alias 1 re-registers");
        assert_eq!(
            session
                .resolve_inbound_alias(1)
                .expect("alias 1 resolves")
                .as_str(),
            "sensors/hum"
        );
        assert_eq!(session.inbound_alias_len(), 1);
        // Unknown aliases resolve to nothing (fail closed).
        assert!(session.resolve_inbound_alias(2).is_none());
        // Disabled maximum rejects everything.
        session.set_inbound_alias_max(0);
        assert_eq!(
            session.register_inbound_alias(1, Topic::new("a/b").unwrap()),
            Err(AliasReject::OverMaximum)
        );
        assert!(session.resolve_inbound_alias(1).is_none());
    }

    #[test]
    fn topic_alias_outbound_assign_reuses_and_bounds() {
        let manager = SessionManager::new();
        let (session, _) = manager.get_or_create("alias-out-1", true);
        // No client maximum yet: nothing is ever assigned.
        assert_eq!(session.outbound_alias_max(), 0);
        assert_eq!(
            session.assign_outbound_alias(&Topic::new("a/b").unwrap()),
            None
        );
        session.set_outbound_alias_max(2);
        // First assignment claims alias 1, repeat reuses it.
        let first = session
            .assign_outbound_alias(&Topic::new("sensors/temp").unwrap())
            .expect("alias assigned");
        assert_eq!(first, 1);
        assert_eq!(session.outbound_alias_for("sensors/temp"), Some(1));
        assert_eq!(
            session.assign_outbound_alias(&Topic::new("sensors/temp").unwrap()),
            Some(1)
        );
        assert_eq!(session.outbound_alias_len(), 1);
        // Second topic claims alias 2; the table is now full.
        assert_eq!(
            session.assign_outbound_alias(&Topic::new("sensors/hum").unwrap()),
            Some(2)
        );
        assert_eq!(session.outbound_alias_len(), 2);
        // Past the bound nothing is assigned (full topic is sent instead).
        assert_eq!(
            session.assign_outbound_alias(&Topic::new("sensors/x").unwrap()),
            None
        );
        assert_eq!(session.outbound_alias_len(), 2);
    }

    #[test]
    fn topic_alias_state_is_per_connection_and_bounded() {
        let manager = SessionManager::new();
        manager.set_max_topic_alias(3);
        assert_eq!(manager.max_topic_alias(), 3);
        let (a, _) = manager.get_or_create("alias-iso-a", true);
        let (b, _) = manager.get_or_create("alias-iso-b", true);
        assert_eq!(a.inbound_alias_max(), 3);
        assert_eq!(b.inbound_alias_max(), 3);
        a.register_inbound_alias(1, Topic::new("a/one").unwrap())
            .expect("a registers");
        b.register_inbound_alias(1, Topic::new("b/one").unwrap())
            .expect("b registers");
        assert_eq!(a.resolve_inbound_alias(1).unwrap().as_str(), "a/one");
        assert_eq!(b.resolve_inbound_alias(1).unwrap().as_str(), "b/one");
        // Verified unbind drops per-connection alias state.
        manager.bind_session(&a, 4101);
        manager.unbind_connection("alias-iso-a", 4101);
        assert!(a.resolve_inbound_alias(1).is_none());
        assert_eq!(a.inbound_alias_len(), 0);
        assert_eq!(b.resolve_inbound_alias(1).unwrap().as_str(), "b/one");
    }
}
