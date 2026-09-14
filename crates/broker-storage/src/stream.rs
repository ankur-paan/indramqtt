//! Durable Partitioned Stream Storage and Point-in-Time Replay for IndraMQTT.
//!
//! Provides durable streaming log capabilities for IndraMQTT streams:
//! - Partitioned append-only stream log per topic
//! - 64-bit monotonically increasing sequence offsets
//! - Nanosecond/millisecond timestamp indexing for fast historical seek
//! - `seek_offset` and `seek_timestamp` replay interfaces
//! - Configurable retention and historical replay iterators

use crate::{Result, StorageError};
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// A single immutable stream record stored in an append-only topic partition
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamRecord {
    pub offset: u64,
    pub timestamp_ms: u64,
    pub topic: Topic,
    pub qos: QoS,
    pub payload: Bytes,
    pub headers: HashMap<String, String>,
}

/// In-memory partition log for a single topic stream
#[derive(Debug, Default)]
struct TopicPartition {
    records: Vec<StreamRecord>,
    // Ordered index of (timestamp_ms, offset) for binary-search time seek
    time_index: Vec<(u64, u64)>,
    next_offset: u64,
}

impl TopicPartition {
    fn append(
        &mut self,
        topic: Topic,
        qos: QoS,
        payload: Bytes,
        headers: HashMap<String, String>,
        timestamp_ms: u64,
    ) -> u64 {
        let offset = self.next_offset;
        self.next_offset += 1;

        let record = StreamRecord {
            offset,
            timestamp_ms,
            topic,
            qos,
            payload,
            headers,
        };

        self.records.push(record);
        self.time_index.push((timestamp_ms, offset));
        offset
    }

    fn get(&self, offset: u64) -> Option<StreamRecord> {
        let idx = self
            .records
            .binary_search_by_key(&offset, |r| r.offset)
            .ok()?;
        self.records.get(idx).cloned()
    }

    fn seek_offset(&self, start_offset: u64, limit: usize) -> Vec<StreamRecord> {
        let start_idx = match self
            .records
            .binary_search_by_key(&start_offset, |r| r.offset)
        {
            Ok(idx) => idx,
            Err(idx) => idx,
        };

        if start_idx >= self.records.len() {
            return Vec::new();
        }

        self.records[start_idx..]
            .iter()
            .take(limit)
            .cloned()
            .collect()
    }

    fn seek_timestamp(&self, timestamp_ms: u64, limit: usize) -> Vec<StreamRecord> {
        if self.time_index.is_empty() {
            return Vec::new();
        }

        let start_idx = match self
            .time_index
            .binary_search_by_key(&timestamp_ms, |(ts, _)| *ts)
        {
            Ok(idx) => idx,
            Err(idx) => idx,
        };

        if start_idx >= self.records.len() {
            return Vec::new();
        }

        self.records[start_idx..]
            .iter()
            .take(limit)
            .cloned()
            .collect()
    }

    fn purge_before(&mut self, cutoff_ms: u64) -> usize {
        let split_idx = match self
            .time_index
            .binary_search_by_key(&cutoff_ms, |(ts, _)| *ts)
        {
            Ok(idx) => idx,
            Err(idx) => idx,
        };

        if split_idx == 0 {
            return 0;
        }

        self.records.drain(0..split_idx);
        self.time_index.drain(0..split_idx);
        split_idx
    }
}

/// Durable Stream Store coordinating partitioned topic logs
#[derive(Debug, Default)]
pub struct DurableStreamStore {
    partitions: Arc<RwLock<HashMap<String, TopicPartition>>>,
}

impl DurableStreamStore {
    pub fn new() -> Self {
        Self {
            partitions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn current_timestamp_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    /// Append a message to the durable stream partition for the topic.
    /// Returns the assigned 64-bit sequence offset.
    pub fn append(
        &self,
        topic: Topic,
        qos: QoS,
        payload: Bytes,
        headers: HashMap<String, String>,
    ) -> u64 {
        let ts = Self::current_timestamp_ms();
        self.append_with_timestamp(topic, qos, payload, headers, ts)
    }

    /// Append with explicit timestamp (useful for testing or event-time replay)
    pub fn append_with_timestamp(
        &self,
        topic: Topic,
        qos: QoS,
        payload: Bytes,
        headers: HashMap<String, String>,
        timestamp_ms: u64,
    ) -> u64 {
        let topic_str = topic.as_str().to_string();
        let mut parts = self.partitions.write();
        let partition = parts.entry(topic_str).or_default();
        partition.append(topic, qos, payload, headers, timestamp_ms)
    }

    /// Fetch a single stream record by offset
    pub fn get(&self, topic: &str, offset: u64) -> Result<StreamRecord> {
        let parts = self.partitions.read();
        let partition = parts.get(topic).ok_or(StorageError::NotFound(offset))?;
        partition.get(offset).ok_or(StorageError::NotFound(offset))
    }

    /// Point-in-time seek by sequence offset: returns up to `limit` records starting at `start_offset`
    pub fn seek_offset(
        &self,
        topic: &str,
        start_offset: u64,
        limit: usize,
    ) -> Result<Vec<StreamRecord>> {
        let parts = self.partitions.read();
        if let Some(partition) = parts.get(topic) {
            Ok(partition.seek_offset(start_offset, limit))
        } else {
            Ok(Vec::new())
        }
    }

    /// Point-in-time seek by timestamp: returns up to `limit` records occurring at or after `timestamp_ms`
    pub fn seek_timestamp(
        &self,
        topic: &str,
        timestamp_ms: u64,
        limit: usize,
    ) -> Result<Vec<StreamRecord>> {
        let parts = self.partitions.read();
        if let Some(partition) = parts.get(topic) {
            Ok(partition.seek_timestamp(timestamp_ms, limit))
        } else {
            Ok(Vec::new())
        }
    }

    /// Get total message count in a topic stream
    pub fn stream_len(&self, topic: &str) -> u64 {
        let parts = self.partitions.read();
        parts
            .get(topic)
            .map(|p| p.records.len() as u64)
            .unwrap_or(0)
    }

    /// Get earliest available offset in a topic stream
    pub fn earliest_offset(&self, topic: &str) -> Option<u64> {
        let parts = self.partitions.read();
        parts
            .get(topic)
            .and_then(|p| p.records.first().map(|r| r.offset))
    }

    /// Get latest available offset in a topic stream
    pub fn latest_offset(&self, topic: &str) -> Option<u64> {
        let parts = self.partitions.read();
        parts
            .get(topic)
            .and_then(|p| p.records.last().map(|r| r.offset))
    }

    /// Purge expired records before cutoff timestamp according to retention policy
    pub fn purge_retention(&self, topic: &str, cutoff_ms: u64) -> usize {
        let mut parts = self.partitions.write();
        if let Some(partition) = parts.get_mut(topic) {
            partition.purge_before(cutoff_ms)
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_durable_stream_append_and_seek_offset() {
        let store = DurableStreamStore::new();
        let topic = Topic::new("sensors/vibration").unwrap();

        // Append 100 messages
        for i in 0..100 {
            let payload = Bytes::from(format!("vibration_data_{i}"));
            let offset = store.append(topic.clone(), QoS::AtLeastOnce, payload, HashMap::new());
            assert_eq!(offset, i as u64);
        }

        assert_eq!(store.stream_len("sensors/vibration"), 100);
        assert_eq!(store.earliest_offset("sensors/vibration"), Some(0));
        assert_eq!(store.latest_offset("sensors/vibration"), Some(99));

        // Replay from offset 50 (limit 20)
        let replayed = store.seek_offset("sensors/vibration", 50, 20).unwrap();
        assert_eq!(replayed.len(), 20);
        assert_eq!(replayed[0].offset, 50);
        assert_eq!(
            replayed[0].payload,
            Bytes::from_static(b"vibration_data_50")
        );
        assert_eq!(replayed[19].offset, 69);
        assert_eq!(
            replayed[19].payload,
            Bytes::from_static(b"vibration_data_69")
        );
    }

    #[test]
    fn test_durable_stream_seek_timestamp_and_retention() {
        let store = DurableStreamStore::new();
        let topic = Topic::new("trades/btcusdt").unwrap();

        let base_time = 1_700_000_000_000u64;

        // Append messages with timestamps every 1000ms
        for i in 0..10 {
            let ts = base_time + (i * 1000);
            let payload = Bytes::from(format!("price_{}", 50000 + i));
            store.append_with_timestamp(
                topic.clone(),
                QoS::ExactlyOnce,
                payload,
                HashMap::new(),
                ts,
            );
        }

        // Seek from base_time + 4500ms -> should return records from base_time + 5000ms onwards
        let results = store
            .seek_timestamp("trades/btcusdt", base_time + 4500, 10)
            .unwrap();
        assert_eq!(results.len(), 5);
        assert_eq!(results[0].offset, 5);
        assert_eq!(results[0].timestamp_ms, base_time + 5000);

        // Purge records older than base_time + 3000ms
        let purged = store.purge_retention("trades/btcusdt", base_time + 3000);
        assert_eq!(purged, 3);
        assert_eq!(store.stream_len("trades/btcusdt"), 7);
        assert_eq!(store.earliest_offset("trades/btcusdt"), Some(3));
    }
}
