pub mod offline;
pub mod stream;
pub use offline::{OfflineConfig, OfflineQueueStore, OfflineRecord};
pub use stream::{DurableStreamStore, FsyncPolicy, StreamConfig, StreamRecord};

use async_trait::async_trait;
use broker_protocol::{QoS, Topic, TopicFilter};
use bytes::Bytes;
use parking_lot::RwLock;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Message not found at offset: {0}")]
    NotFound(u64),

    #[error("Storage engine failure: {0}")]
    Engine(String),
}

pub type Result<T> = std::result::Result<T, StorageError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMessage {
    pub offset: u64,
    pub topic: Topic,
    pub qos: QoS,
    pub retain: bool,
    pub payload: Bytes,
    /// Publish time recorded where the message is already being written
    /// (retained store / append), as millis since the Unix epoch.
    /// `None` means the message predates timestamp recording; API reads
    /// must omit the field rather than substituting anything.
    pub publish_at_ms: Option<u64>,
}

/// Current wall-clock time as millis since the Unix epoch. Read once per
/// stored message on the write path (retained/appends are rare), never
/// on the delivery hot path.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[async_trait]
pub trait MessageStore: Send + Sync {
    async fn append(&self, topic: Topic, qos: QoS, retain: bool, payload: Bytes) -> Result<u64>;
    async fn get(&self, offset: u64) -> Result<StoredMessage>;
}

#[async_trait]
pub trait RetainedStore: Send + Sync {
    async fn set_retained(&self, topic: Topic, qos: QoS, payload: Bytes) -> Result<()>;
    async fn get_retained(&self, topic: &Topic) -> Result<Option<StoredMessage>>;
    async fn clear_retained(&self, topic: &Topic) -> Result<()>;
    /// All retained messages whose topic matches `filter`, ordered by
    /// topic for deterministic delivery to new subscribers.
    async fn find_matching(&self, filter: &TopicFilter) -> Result<Vec<StoredMessage>>;
}

#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn update_cursor(&self, session_id: u64, offset: u64) -> Result<()>;
    async fn get_cursor(&self, session_id: u64) -> Result<u64>;
}

/// Maximum retained topics held by [`MemoryStore`].
///
/// The map holds at most this many exact topics; inserts past the cap
/// keep delivery working but drop the new topic (existing topics may still
/// be replaced), so one client cannot balloon the node. Management-plane
/// reads clone at most one entry (single lookup) or a bounded page (list),
/// never scanning without a cap, and take only short read locks so they
/// never block delivery.
///
/// 100_000 entries cover the documented unlimited default (`0`) while
/// keeping per-entry memory (one shared topic string plus payload) under
/// control on the 12 GB test host.
pub const MAX_RETAINED_MESSAGES: usize = 100_000;

/// In-memory storage engine for local fast tests and zero-disk development.
#[derive(Default)]
pub struct MemoryStore {
    messages: RwLock<Vec<StoredMessage>>,
    retained: RwLock<HashMap<Topic, StoredMessage>>,
    cursors: RwLock<HashMap<u64, u64>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl MessageStore for MemoryStore {
    async fn append(&self, topic: Topic, qos: QoS, retain: bool, payload: Bytes) -> Result<u64> {
        let mut msgs = self.messages.write();
        let offset = msgs.len() as u64;
        msgs.push(StoredMessage {
            offset,
            topic,
            qos,
            retain,
            payload,
            publish_at_ms: Some(now_ms()),
        });
        Ok(offset)
    }

    async fn get(&self, offset: u64) -> Result<StoredMessage> {
        let msgs = self.messages.read();
        msgs.get(offset as usize)
            .cloned()
            .ok_or(StorageError::NotFound(offset))
    }
}

#[async_trait]
impl RetainedStore for MemoryStore {
    async fn set_retained(&self, topic: Topic, qos: QoS, payload: Bytes) -> Result<()> {
        let mut map = self.retained.write();
        if map.len() >= MAX_RETAINED_MESSAGES && !map.contains_key(&topic) {
            return Ok(());
        }
        map.insert(
            topic.clone(),
            StoredMessage {
                offset: 0,
                topic,
                qos,
                retain: true,
                payload,
                publish_at_ms: Some(now_ms()),
            },
        );
        Ok(())
    }

    async fn get_retained(&self, topic: &Topic) -> Result<Option<StoredMessage>> {
        let map = self.retained.read();
        Ok(map.get(topic).cloned())
    }

    async fn clear_retained(&self, topic: &Topic) -> Result<()> {
        let mut map = self.retained.write();
        map.remove(topic);
        Ok(())
    }

    async fn find_matching(&self, filter: &TopicFilter) -> Result<Vec<StoredMessage>> {
        let map = self.retained.read();
        let mut matched: Vec<StoredMessage> = map
            .values()
            .filter(|msg| filter.matches(&msg.topic))
            .cloned()
            .collect();
        matched.sort_by(|a, b| a.topic.as_str().cmp(b.topic.as_str()));
        Ok(matched)
    }
}

#[async_trait]
impl SessionStore for MemoryStore {
    async fn update_cursor(&self, session_id: u64, offset: u64) -> Result<()> {
        let mut cursors = self.cursors.write();
        cursors.insert(session_id, offset);
        Ok(())
    }

    async fn get_cursor(&self, session_id: u64) -> Result<u64> {
        let cursors = self.cursors.read();
        Ok(cursors.get(&session_id).copied().unwrap_or(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_store() {
        let store = MemoryStore::new();
        let topic = Topic::new("telemetry/temp").unwrap();
        let offset = store
            .append(
                topic.clone(),
                QoS::AtLeastOnce,
                false,
                Bytes::from_static(b"25.4"),
            )
            .await
            .unwrap();

        assert_eq!(offset, 0);
        let msg = store.get(offset).await.unwrap();
        assert_eq!(msg.payload, Bytes::from_static(b"25.4"));

        store.update_cursor(101, offset).await.unwrap();
        assert_eq!(store.get_cursor(101).await.unwrap(), offset);
    }

    #[tokio::test]
    async fn test_retained_set_get_clear() {
        let store = MemoryStore::new();
        let topic = Topic::new("device/state").unwrap();

        assert!(store.get_retained(&topic).await.unwrap().is_none());

        store
            .set_retained(
                topic.clone(),
                QoS::AtMostOnce,
                Bytes::from_static(b"online"),
            )
            .await
            .unwrap();
        let msg = store.get_retained(&topic).await.unwrap().expect("stored");
        assert_eq!(msg.payload, Bytes::from_static(b"online"));
        assert!(msg.retain);

        // Replace keeps only the latest value.
        store
            .set_retained(topic.clone(), QoS::AtLeastOnce, Bytes::from_static(b"away"))
            .await
            .unwrap();
        let msg = store.get_retained(&topic).await.unwrap().expect("replaced");
        assert_eq!(msg.payload, Bytes::from_static(b"away"));
        assert_eq!(msg.qos, QoS::AtLeastOnce);

        store.clear_retained(&topic).await.unwrap();
        assert!(store.get_retained(&topic).await.unwrap().is_none());

        // Clearing an absent topic is a no-op.
        store.clear_retained(&topic).await.unwrap();
    }

    #[tokio::test]
    async fn test_find_matching_exact_and_wildcards() {
        let store = MemoryStore::new();
        for (topic, payload) in [
            ("device/state", "online"),
            ("device/battery", "87"),
            ("sensors/temperature", "21.5"),
        ] {
            store
                .set_retained(
                    Topic::new(topic).unwrap(),
                    QoS::AtMostOnce,
                    Bytes::from(payload),
                )
                .await
                .unwrap();
        }

        // Exact filter matches one.
        let matched = store
            .find_matching(&TopicFilter::new("device/state").unwrap())
            .await
            .unwrap();
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].payload, Bytes::from_static(b"online"));

        // Single-level wildcard.
        let matched = store
            .find_matching(&TopicFilter::new("device/+").unwrap())
            .await
            .unwrap();
        assert_eq!(matched.len(), 2);
        // Deterministic topic order.
        assert_eq!(matched[0].topic.as_str(), "device/battery");
        assert_eq!(matched[1].topic.as_str(), "device/state");

        // Multi-level wildcard.
        let matched = store
            .find_matching(&TopicFilter::new("#").unwrap())
            .await
            .unwrap();
        assert_eq!(matched.len(), 3);

        // No match.
        let matched = store
            .find_matching(&TopicFilter::new("unknown/#").unwrap())
            .await
            .unwrap();
        assert!(matched.is_empty());

        // Cleared topics disappear from matching.
        store
            .clear_retained(&Topic::new("device/state").unwrap())
            .await
            .unwrap();
        let matched = store
            .find_matching(&TopicFilter::new("device/+").unwrap())
            .await
            .unwrap();
        assert_eq!(matched.len(), 1);
    }
}
