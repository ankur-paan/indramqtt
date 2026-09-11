use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use broker_protocol::{QoS, Topic, TopicFilter};
use bytes::Bytes;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub u64);

#[derive(Debug)]
pub struct Session {
    pub id: SessionId,
    pub client_id: String,
    pub clean_start: bool,
    pub connected: RwLock<bool>,
    pub conn_id: RwLock<Option<u64>>,
    pub subscriptions: RwLock<HashMap<TopicFilter, broker_protocol::QoS>>,
    pub offline_queue: RwLock<VecDeque<QueuedMessage>>,
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

/// Maximum buffered messages per detached session; beyond this the
/// oldest entry drops so one dead client cannot balloon the node.
pub const MAX_OFFLINE_QUEUE: usize = 1024;

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
            keepalive_secs: RwLock::new(0),
            username: RwLock::new(None),
            next_packet_id: AtomicU16::new(1),
        }
    }

    pub fn next_packet_id(&self) -> u16 {
        loop {
            let pid = self.next_packet_id.fetch_add(1, Ordering::SeqCst);
            if pid != 0 {
                return pid;
            }
        }
    }

    /// Buffer one message for later replay, evicting the oldest entry
    /// past [`MAX_OFFLINE_QUEUE`].
    pub fn push_offline(&self, message: QueuedMessage) {
        let mut queue = self.offline_queue.write();
        while queue.len() >= MAX_OFFLINE_QUEUE {
            queue.pop_front();
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
        self.tokens = (self.tokens + elapsed * f64::from(self.rate_per_sec))
            .min(f64::from(self.burst));
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
    /// Live connection count per username (INDRA-127 quotas). Anonymous
    /// binds bypass accounting entirely.
    conn_counts: RwLock<HashMap<String, AtomicU32>>,
    /// Publish token buckets per client id (INDRA-128 rate limits).
    /// Pruned on unbind so reconnects start full and state cannot grow
    /// without bound.
    buckets: RwLock<HashMap<String, TokenBucket>>,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            next_session_id: AtomicU64::new(1),
            conn_counts: RwLock::new(HashMap::new()),
            buckets: RwLock::new(HashMap::new()),
        }
    }

    pub fn get(&self, client_id: &str) -> Option<Arc<Session>> {
        self.sessions.read().get(client_id).cloned()
    }

    /// Reverse lookup: owner of a live edge connection, if bound.
    pub fn client_id_for_conn(&self, conn_id: u64) -> Option<String> {
        self.sessions
            .read()
            .iter()
            .find(|(_, session)| *session.conn_id.read() == Some(conn_id))
            .map(|(client_id, _)| client_id.clone())
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
    pub fn add_subscription(&self, client_id: &str, filter: TopicFilter, qos: QoS) {
        if let Some(session) = self.get(client_id) {
            session.subscriptions.write().insert(filter, qos);
        }
    }

    /// Forget one subscription (unsubscribe / connection teardown).
    pub fn remove_subscription(&self, client_id: &str, filter: &TopicFilter) {
        if let Some(session) = self.get(client_id) {
            session.subscriptions.write().remove(filter);
        }
    }

    pub fn get_or_create(&self, client_id: &str, clean_start: bool) -> (Arc<Session>, bool) {        let mut map = self.sessions.write();

        if clean_start {
            let id = SessionId(self.next_session_id.fetch_add(1, Ordering::SeqCst));
            let session = Arc::new(Session::new(id, client_id.to_string(), clean_start));
            map.insert(client_id.to_string(), session.clone());
            (session, false)
        } else if let Some(existing) = map.get(client_id) {
            *existing.connected.write() = true;
            (existing.clone(), true)
        } else {
            let id = SessionId(self.next_session_id.fetch_add(1, Ordering::SeqCst));
            let session = Arc::new(Session::new(id, client_id.to_string(), clean_start));
            map.insert(client_id.to_string(), session.clone());
            (session, false)
        }
    }

    pub fn unbind_connection(&self, client_id: &str, conn_id: u64) {
        let username_to_release: Option<String> = {
            let map = self.sessions.read();
            match map.get(client_id) {
                Some(session) => {
                    let mut current_conn = session.conn_id.write();
                    if *current_conn == Some(conn_id) {
                        *current_conn = None;
                        *session.connected.write() = false;
                        session.username.read().clone()
                    } else {
                        None
                    }
                }
                None => None,
            }
        };
        if let Some(username) = username_to_release {
            self.release_connection_slot(&username);
        }
        // Reconnects start with a full bucket; abandoned entries vanish.
        self.buckets.write().remove(client_id);
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
            let _ = count.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                n.checked_sub(1)
            });
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
        assert_eq!(info.subscriptions, vec!["alerts".to_string(), "sensors/+".to_string()]);

        manager.remove_subscription("detail-9", &TopicFilter::new("alerts").unwrap());
        let info = manager.client_info("detail-9").expect("still known");
        assert_eq!(info.subscriptions, vec!["sensors/+".to_string()]);

        // Unknown clients are no-ops, never panics.
        manager.add_subscription("ghost", TopicFilter::new("a").unwrap(), broker_protocol::QoS::AtMostOnce);
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
}
