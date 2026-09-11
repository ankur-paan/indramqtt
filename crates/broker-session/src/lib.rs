use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::Arc;
use broker_protocol::{QoS, Topic, TopicFilter};
use bytes::Bytes;
use parking_lot::RwLock;

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

pub struct SessionManager {
    sessions: RwLock<HashMap<String, Arc<Session>>>,
    next_session_id: AtomicU64,
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
        let map = self.sessions.read();
        if let Some(session) = map.get(client_id) {
            let mut current_conn = session.conn_id.write();
            if *current_conn == Some(conn_id) {
                *current_conn = None;
                *session.connected.write() = false;
            }
        }
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
}
