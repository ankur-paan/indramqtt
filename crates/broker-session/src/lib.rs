use broker_protocol::{QoS, Topic, TopicFilter};
use bytes::Bytes;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, Ordering};
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

#[derive(Debug)]
pub struct Session {
    pub id: SessionId,
    pub client_id: String,
    pub clean_start: bool,
    pub connected: RwLock<bool>,
    pub conn_id: RwLock<Option<u64>>,
    pub subscriptions: RwLock<HashMap<TopicFilter, SubscriptionOptions>>,
    pub offline_queue: RwLock<VecDeque<QueuedMessage>>,
    /// QoS 1 downlinks written toward the subscriber and not yet
    /// acknowledged (T-31). Held in delivery order so reconnect replay
    /// resends oldest-first with DUP set. Bounded per session by
    /// [`MAX_QOS1_INFLIGHT`]; the kernel (not the edge) owns this state.
    pub inflight: RwLock<VecDeque<InflightMessage>>,
    /// MQTT keepalive seconds from CONNECT (0 = disabled). Maintained by
    /// the edge at bind time; surfaced read-only for observability.
    pub keepalive_secs: RwLock<u16>,
    /// Authenticated username that owns this session, if any. Maintained
    /// by the edge at bind time; drives per-user quota accounting.
    pub username: RwLock<Option<String>>,
    next_packet_id: AtomicU16,
}

/// One buffered message for a detached durable session (LOG + CURSOR
/// model: payloads live here until the session reattaches and replays).
#[derive(Debug, Clone)]
pub struct QueuedMessage {
    pub topic: Topic,
    pub qos: QoS,
    pub retain: bool,
    pub payload: Bytes,
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
}

/// Maximum unacknowledged QoS 1 downlinks held per session (T-31).
/// At the limit the newest downlink is still delivered live once but is
/// NOT tracked for redelivery, and the kernel `inflight_dropped` counter
/// bumps once per untracked delivery. Rationale: dropping the live
/// delivery would hurt the v4 QoS 1 delivery rate (94-97%, must be 100%)
/// more than skipping its redelivery; keeping the oldest entries
/// preserves replay order for what is tracked.
pub const MAX_QOS1_INFLIGHT: usize = 100;

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
            inflight: RwLock::new(VecDeque::new()),
            keepalive_secs: RwLock::new(0),
            username: RwLock::new(None),
            next_packet_id: AtomicU16::new(1),
        }
    }

    pub fn next_packet_id(&self) -> u16 {
        loop {
            let pid = self.next_packet_id.fetch_add(1, Ordering::SeqCst);
            if pid == 0 {
                continue;
            }
            // Never hand out an id already held inflight: a resumed
            // session's unacked ids stay reserved until their PUBACK.
            // The store is bounded (<= MAX_QOS1_INFLIGHT of 65535 ids),
            // so this scan always terminates.
            if self.inflight.read().iter().any(|m| m.packet_id == pid) {
                continue;
            }
            return pid;
        }
    }

    /// Hold one QoS 1 downlink for redelivery. True means tracked; false
    /// means the per-session bound was full (the caller still delivers
    /// live once and counts `inflight_dropped`). Never grows past
    /// [`MAX_QOS1_INFLIGHT`].
    pub fn track_inflight(&self, message: InflightMessage) -> bool {
        let mut inflight = self.inflight.write();
        if inflight.len() >= MAX_QOS1_INFLIGHT {
            return false;
        }
        inflight.push_back(message);
        true
    }

    /// Release one downlink on its PUBACK. True when an entry was held.
    pub fn ack_inflight(&self, packet_id: u16) -> bool {
        let mut inflight = self.inflight.write();
        if let Some(pos) = inflight.iter().position(|m| m.packet_id == packet_id) {
            inflight.remove(pos);
            return true;
        }
        false
    }

    /// Ordered snapshot of unacked downlinks for reconnect replay.
    /// Entries stay held: they remain inflight until their PUBACK, so a
    /// second reconnect without acks replays them again.
    pub fn inflight_snapshot(&self) -> Vec<InflightMessage> {
        self.inflight.read().iter().cloned().collect()
    }

    pub fn inflight_len(&self) -> usize {
        self.inflight.read().len()
    }

    pub fn clear_inflight(&self) {
        self.inflight.write().clear();
    }

    /// Buffer one message for later replay, evicting the oldest entry
    /// past [`MAX_OFFLINE_QUEUE`].
    pub fn push_offline(&self, message: QueuedMessage) {
        self.push_offline_with_limit(message, Some(MAX_OFFLINE_QUEUE));
    }

    /// Buffer one message with an explicit cap: `Some(n)` evicts the
    /// oldest entries past `n` (floored at holding one), `None` queues
    /// without bound (memory-bounded by the caller).
    pub fn push_offline_with_limit(&self, message: QueuedMessage, limit: Option<usize>) {
        let mut queue = self.offline_queue.write();
        if let Some(limit) = limit {
            let limit = limit.max(1);
            while queue.len() >= limit {
                queue.pop_front();
            }
        }
        queue.push_back(message);
    }

    /// Take every buffered message, leaving the queue empty.
    pub fn drain_offline(&self) -> Vec<QueuedMessage> {
        self.offline_queue.write().drain(..).collect()
    }

    pub fn offline_len(&self) -> usize {
        self.offline_queue.read().len()
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
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager {
    pub fn new() -> Self {
        Self::new_with_limits(Some(DEFAULT_MAX_OFFLINE_QUEUE))
    }

    /// Create a manager with an explicit offline queue cap: `Some(n)`
    /// evicts oldest past `n` per detached session (floored at 1, no
    /// ceiling), `None` queues without bound.
    pub fn new_with_limits(max_offline_queue: Option<usize>) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            next_session_id: AtomicU64::new(1),
            conn_index: RwLock::new(HashMap::new()),
            conn_counts: RwLock::new(HashMap::new()),
            buckets: RwLock::new(HashMap::new()),
            connected_count: AtomicU64::new(0),
            max_offline_queue: max_offline_queue.map(|limit| limit.max(1)),
        }
    }

    /// Configured offline queue cap (`None` = unbounded).
    pub fn max_offline_queue(&self) -> Option<usize> {
        self.max_offline_queue
    }

    /// Buffer one message for a detached session, applying this
    /// manager's offline cap. False when the client has no session.
    pub fn queue_offline(&self, client_id: &str, message: QueuedMessage) -> bool {
        match self.get(client_id) {
            Some(session) => {
                session.push_offline_with_limit(message, self.max_offline_queue);
                true
            }
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
    /// write; never held across dispatch, routing, or I/O.
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
                self.connected_count.fetch_add(1, Ordering::SeqCst);
            }
            (existing.clone(), true)
        } else {
            let id = SessionId(self.next_session_id.fetch_add(1, Ordering::SeqCst));
            let session = Arc::new(Session::new(id, client_id.to_string(), clean_start));
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
        let (username_to_release, swept, did_detach): (
            Option<String>,
            Vec<TopicFilter>,
            bool,
        ) = {
            let map = self.sessions.read();
            match map.get(client_id) {
                Some(session) => {
                    let mut current_conn = session.conn_id.write();
                    if *current_conn == Some(conn_id) {
                        let was_connected = *session.connected.read();
                        *current_conn = None;
                        *session.connected.write() = false;
                        // Clean sessions keep no inflight state across a
                        // disconnect (T-31); durable sessions keep theirs
                        // for reconnect replay.
                        if session.clean_start {
                            session.clear_inflight();
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
            let _ = self.connected_count.fetch_update(
                Ordering::SeqCst,
                Ordering::SeqCst,
                |n| n.checked_sub(1),
            );
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
}
