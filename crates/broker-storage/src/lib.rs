use async_trait::async_trait;
use bytes::Bytes;
use broker_protocol::{QoS, Topic};
use std::collections::HashMap;
use parking_lot::RwLock;
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
}

#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn update_cursor(&self, session_id: u64, offset: u64) -> Result<()>;
    async fn get_cursor(&self, session_id: u64) -> Result<u64>;
}

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
        map.insert(
            topic.clone(),
            StoredMessage {
                offset: 0,
                topic,
                qos,
                retain: true,
                payload,
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
            .append(topic.clone(), QoS::AtLeastOnce, false, Bytes::from_static(b"25.4"))
            .await
            .unwrap();

        assert_eq!(offset, 0);
        let msg = store.get(offset).await.unwrap();
        assert_eq!(msg.payload, Bytes::from_static(b"25.4"));

        store.update_cursor(101, offset).await.unwrap();
        assert_eq!(store.get_cursor(101).await.unwrap(), offset);
    }
}
