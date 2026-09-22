//! Partitioned stream log with point-in-time replay.
//!
//! Each topic maps to one append-only partition. A partition keeps an
//! in-memory offset and time index for fast replay, backed by segment
//! files on disk when the store is opened with [`DurableStreamStore::open`].
//!
//! # Durability contract (read this before relying on it)
//!
//! - [`DurableStreamStore::new`] is ephemeral: no directory, no files,
//!   everything is lost on drop. It exists for unit tests and is never
//!   durable. Its docs never claim otherwise.
//! - [`DurableStreamStore::open`] / [`open_with_config`](DurableStreamStore::open_with_config)
//!   persist every acknowledged append: the frame is written and flushed
//!   before `Ok(offset)` returns.
//! - [`FsyncPolicy::EveryWrite`] (the default) additionally calls
//!   `sync_data` per append before acknowledging. A crash then loses at
//!   most the single append racing the crash; a torn tail is discarded on
//!   recovery, never served. Cost: one `fsync` per append (typically
//!   0.1-1 ms, capping a single partition at roughly 1k-10k appends/s).
//! - [`FsyncPolicy::NoSync`] only flushes to the OS. A process crash keeps
//!   flushed data, but a power loss can lose everything still in the page
//!   cache. Use it only for benchmarks where losing the tail is acceptable.
//! - Direct `append` blocks on file I/O (including `fsync` under
//!   `EveryWrite`) and must never run on the publish hot path. The kernel
//!   journals through a bounded channel drained by a background task (see
//!   `broker-node`), so publishes pay one non-blocking `try_send` and the
//!   durability window is channel delay plus one `fsync` (usually well
//!   under 10 ms; records dropped when the channel is full are counted
//!   and never retried).
//!
//! Segment layout per topic directory `<dir>/<encoded-topic>/`:
//! `00000000.log`, `00000001.log`, ... plus a 12-byte `META` file holding
//! the next offset and next segment id so a fully-purged partition does
//! not reuse offsets after a restart. Each frame is
//! `[u32 len][record bytes][u32 crc32(record bytes)]` with all integers
//! little-endian. Recovery scans segments in order; the first truncated
//! frame, CRC mismatch, or decode error truncates that file at the last
//! good frame and deletes every later segment.

use crate::{Result, StorageError};
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Largest single frame accepted on recovery (`len` field plus slack).
///
/// 300 MB comfortably covers the largest legal MQTT payload
/// (~256 MB) plus topic and headers while bounding allocation on a
/// corrupt length prefix.
const MAX_FRAME_BYTES: usize = 300_000_000;
/// Smallest legal record encoding: two u64, one u8, three u32 lengths.
const MIN_RECORD_BYTES: usize = 8 + 8 + 1 + 4 + 4 + 4;
/// Longest topic accepted from a segment file (MQTT UTF-8 limit).
const MAX_TOPIC_BYTES: usize = 65_535;
/// Largest payload accepted from a segment file (MQTT remaining-length cap).
const MAX_PAYLOAD_BYTES: usize = 268_435_456;
/// Largest header block accepted from a segment file.
const MAX_HEADERS: usize = 10_000;
/// Longest single header key or value accepted from a segment file.
const MAX_HEADER_FIELD_BYTES: usize = 65_535;
/// Default segment roll threshold: 64 MB.
const DEFAULT_SEGMENT_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// When the store calls `fsync` (see the module docs for the trade-off).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FsyncPolicy {
    /// `write + flush + sync_data` before every acknowledged append.
    /// Smallest durability window at the cost of one `fsync` per append.
    #[default]
    EveryWrite,
    /// `write + flush` only; the OS decides when bytes reach disk.
    /// Faster, but a power loss can lose the whole page cache tail.
    NoSync,
}

/// Segment and fsync tuning for [`DurableStreamStore::open_with_config`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamConfig {
    /// Roll to a new segment once the active file would exceed this many
    /// bytes. Must be non-zero. Small values (a few KB) are intended for
    /// tests exercising rolls; production wants tens of MB.
    pub segment_max_bytes: u64,
    /// When bytes are forced to stable storage (see [`FsyncPolicy`]).
    pub fsync: FsyncPolicy,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            segment_max_bytes: DEFAULT_SEGMENT_MAX_BYTES,
            fsync: FsyncPolicy::EveryWrite,
        }
    }
}

impl StreamConfig {
    /// Override the segment roll threshold (must be non-zero, checked on open).
    pub fn with_segment_max_bytes(mut self, max: u64) -> Self {
        self.segment_max_bytes = max;
        self
    }

    /// Override the fsync policy.
    pub fn with_fsync(mut self, fsync: FsyncPolicy) -> Self {
        self.fsync = fsync;
        self
    }
}

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
    /// Next segment id to allocate; active segment is `next_segment_id - 1`
    /// once at least one segment exists.
    next_segment_id: u32,
}

impl TopicPartition {
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

    fn purge_split(&self, cutoff_ms: u64) -> usize {
        match self
            .time_index
            .binary_search_by_key(&cutoff_ms, |(ts, _)| *ts)
        {
            Ok(idx) => idx,
            Err(idx) => idx,
        }
    }
}

/// Stream store coordinating partitioned topic logs.
///
/// Ephemeral when built with [`new`](DurableStreamStore::new), durable
/// when built with [`open`](DurableStreamStore::open). See the module
/// docs for the exact durability contract.
#[derive(Debug)]
pub struct DurableStreamStore {
    partitions: Arc<RwLock<HashMap<String, TopicPartition>>>,
    dir: Option<PathBuf>,
    config: StreamConfig,
}

impl Default for DurableStreamStore {
    fn default() -> Self {
        Self::new()
    }
}

impl DurableStreamStore {
    /// Ephemeral store: no directory, no files, all data lost on drop.
    ///
    /// Intended for unit tests. For persistence use [`open`](DurableStreamStore::open).
    pub fn new() -> Self {
        Self {
            partitions: Arc::new(RwLock::new(HashMap::new())),
            dir: None,
            config: StreamConfig::default(),
        }
    }

    /// Open (or create) a durable store in `dir` with the default config
    /// (64 MB segments, fsync per append).
    ///
    /// Rebuilds the offset and time indexes from the segment files so
    /// replay works after a restart. A torn tail is truncated and later
    /// segments are deleted, never served.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_config(dir, StreamConfig::default())
    }

    /// Open (or create) a durable store in `dir` with `config`.
    ///
    /// Returns [`StorageError::Engine`] when `segment_max_bytes` is zero
    /// or the directory cannot be created or scanned.
    pub fn open_with_config(dir: impl AsRef<Path>, config: StreamConfig) -> Result<Self> {
        if config.segment_max_bytes == 0 {
            return Err(StorageError::Engine(
                "segment_max_bytes must be non-zero".to_string(),
            ));
        }
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir).map_err(|e| {
            StorageError::Engine(format!("cannot create stream dir {}: {e}", dir.display()))
        })?;
        let store = Self {
            partitions: Arc::new(RwLock::new(HashMap::new())),
            dir: Some(dir),
            config,
        };
        store.recover()?;
        Ok(store)
    }

    /// True once opened with a directory; false for [`new`](DurableStreamStore::new).
    pub fn is_persistent(&self) -> bool {
        self.dir.is_some()
    }

    /// Backing directory, if any.
    pub fn dir(&self) -> Option<&Path> {
        self.dir.as_deref()
    }

    /// Active segment/file tuning.
    pub fn config(&self) -> StreamConfig {
        self.config
    }

    fn current_timestamp_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    /// Append a message to the stream partition for the topic.
    ///
    /// On a durable store the frame is written and flushed (plus
    /// `sync_data` under [`FsyncPolicy::EveryWrite`]) before `Ok(offset)`
    /// is returned, so an acknowledged offset survives a restart unless it
    /// raced a crash. Returns [`StorageError::Engine`] on I/O failure with
    /// nothing acknowledged and no offset consumed.
    pub fn append(
        &self,
        topic: Topic,
        qos: QoS,
        payload: Bytes,
        headers: HashMap<String, String>,
    ) -> Result<u64> {
        let ts = Self::current_timestamp_ms();
        self.append_with_timestamp(topic, qos, payload, headers, ts)
    }

    /// Append with explicit timestamp (useful for testing or event-time replay).
    ///
    /// Same durability guarantee as [`append`](DurableStreamStore::append).
    pub fn append_with_timestamp(
        &self,
        topic: Topic,
        qos: QoS,
        payload: Bytes,
        headers: HashMap<String, String>,
        timestamp_ms: u64,
    ) -> Result<u64> {
        let topic_str = topic.as_str().to_string();
        // Hold the write guard across offset assignment, file I/O and the
        // in-memory insert so file order always matches offset order.
        // Appends serialize here; reads take the read lock and block only
        // for one flush/fsync. Direct appends never run on the publish hot
        // path (the kernel journals via a bounded channel instead).
        let mut parts = self.partitions.write();
        let (dir_opt, max_bytes, fsync) = (
            self.dir.clone(),
            self.config.segment_max_bytes,
            self.config.fsync,
        );
        let partition = parts.entry(topic_str.clone()).or_default();
        let offset = partition.next_offset;
        let record = StreamRecord {
            offset,
            timestamp_ms,
            topic,
            qos,
            payload,
            headers,
        };
        let frame = encode_frame(&encode_record(&record));
        if let Some(dir) = dir_opt {
            let topic_dir = dir.join(encode_topic(&topic_str));
            std::fs::create_dir_all(&topic_dir).map_err(|e| {
                StorageError::Engine(format!(
                    "cannot create topic dir {}: {e}",
                    topic_dir.display()
                ))
            })?;
            let segment_id = if partition.next_segment_id == 0 {
                0
            } else {
                let active = partition.next_segment_id - 1;
                let size = std::fs::metadata(topic_dir.join(segment_name(active)))
                    .map(|m| m.len())
                    .unwrap_or(0);
                if size > 0 && size + frame.len() as u64 > max_bytes {
                    active + 1
                } else {
                    active
                }
            };
            write_frame(&topic_dir, segment_id, &frame, fsync)?;
            if partition.next_segment_id <= segment_id {
                partition.next_segment_id = segment_id + 1;
            }
            partition.records.push(record.clone());
            partition
                .time_index
                .push((record.timestamp_ms, record.offset));
            partition.next_offset = offset + 1;
            Ok(offset)
        } else {
            partition.records.push(record.clone());
            partition
                .time_index
                .push((record.timestamp_ms, record.offset));
            partition.next_offset = offset + 1;
            Ok(offset)
        }
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

    /// Purge records with `timestamp_ms` before `cutoff_ms`.
    ///
    /// Memory is drained and, on a durable store, the segments are
    /// compacted so purged records stay gone after a restart. Returns the
    /// number of records removed. File I/O failures leave memory
    /// untouched and return [`StorageError::Engine`].
    pub fn purge_retention(&self, topic: &str, cutoff_ms: u64) -> Result<usize> {
        // Hold the write guard for the whole purge so a concurrent append
        // cannot slip between the file rewrite and the memory drain.
        let mut parts = self.partitions.write();
        let split = parts
            .get(topic)
            .map(|pt| pt.purge_split(cutoff_ms))
            .unwrap_or(0);
        if split == 0 {
            return Ok(0);
        }
        let Some(dir) = self.dir.clone() else {
            if let Some(partition) = parts.get_mut(topic) {
                partition.records.drain(0..split);
                partition.time_index.drain(0..split);
                return Ok(split);
            }
            return Ok(0);
        };
        let (kept, next_offset) = match parts.get(topic) {
            Some(pt) => (
                pt.records.get(split..).unwrap_or(&[]).to_vec(),
                pt.next_offset,
            ),
            None => return Ok(0),
        };
        let max_bytes = self.config.segment_max_bytes;
        let fsync = self.config.fsync;
        // File work while holding the guard (no nested locking: helpers
        // below are free functions). Purges are rare; appends and reads
        // wait briefly.
        let next_segment_id =
            rewrite_topic_segments(&dir, topic, &kept, next_offset, max_bytes, fsync)?;
        let partition = parts.get_mut(topic).ok_or_else(|| {
            StorageError::Engine(format!("stream partition {topic} vanished during purge"))
        })?;
        if split <= partition.records.len() {
            partition.records.drain(0..split);
            partition.time_index.drain(0..split);
        }
        partition.next_segment_id = next_segment_id;
        debug_assert_eq!(partition.records.len(), kept.len());
        Ok(split)
    }

    /// Scan every topic directory and rebuild the in-memory indexes.
    /// Torn tails are truncated at the last good frame with later segments
    /// deleted; they are never served.
    fn recover(&self) -> Result<()> {
        let Some(dir) = self.dir.clone() else {
            return Ok(());
        };
        let entries = std::fs::read_dir(&dir).map_err(|e| {
            StorageError::Engine(format!("cannot list stream dir {}: {e}", dir.display()))
        })?;
        for entry in entries {
            let entry = entry.map_err(|e| {
                StorageError::Engine(format!("cannot list stream dir {}: {e}", dir.display()))
            })?;
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let encoded = entry.file_name().to_string_lossy().into_owned();
            let Some(topic_str) = decode_topic(&encoded) else {
                continue;
            };
            if Topic::new(topic_str.clone()).is_err() {
                continue;
            }
            let topic_dir = dir.join(&encoded);
            let (meta_next_offset, meta_next_segment) = read_meta(&topic_dir);
            let segments = list_segments(&topic_dir);
            if segments.is_empty() {
                if meta_next_offset > 0 || meta_next_segment > 0 {
                    let mut parts = self.partitions.write();
                    let partition = parts.entry(topic_str).or_default();
                    partition.next_offset = meta_next_offset;
                    partition.next_segment_id = meta_next_segment;
                }
                continue;
            }
            let mut records: Vec<StreamRecord> = Vec::new();
            let mut time_index: Vec<(u64, u64)> = Vec::new();
            let mut expected: Option<u64> = None;
            let mut clean_through = segments.len();
            for (pos, (id, _)) in segments.iter().enumerate() {
                let path = topic_dir.join(segment_name(*id));
                let bytes = match std::fs::read(&path) {
                    Ok(b) => b,
                    Err(_) => {
                        clean_through = pos;
                        break;
                    }
                };
                let (mut recs, last_good, complete) = scan_segment(&bytes, expected);
                for r in recs.drain(..) {
                    expected = Some(r.offset + 1);
                    time_index.push((r.timestamp_ms, r.offset));
                    records.push(r);
                }
                if !complete {
                    // Truncated or corrupt tail inside this file:
                    // cut it at the last good frame.
                    truncate_to(&path, last_good as u64);
                    clean_through = pos + 1;
                    break;
                }
            }
            // Drop every segment after the first torn one: offsets past a
            // tear are not contiguous and must not resurrect.
            for (id, _) in segments.iter().skip(clean_through) {
                let path = topic_dir.join(segment_name(*id));
                std::fs::remove_file(&path).ok();
            }
            // Re-derive the segment watermark from the segments that
            // survived so the next append continues the sequence.
            let surviving: Vec<u32> = segments
                .iter()
                .take(clean_through)
                .map(|(id, _)| *id)
                .collect();
            let next_segment_id = surviving.iter().max().map(|m| m + 1).unwrap_or(0);
            let next_offset = expected.or(Some(meta_next_offset)).unwrap_or(0);
            let next_segment_id = next_segment_id.max(meta_next_segment);
            let mut parts = self.partitions.write();
            let partition = parts.entry(topic_str).or_default();
            partition.records = records;
            partition.time_index = time_index;
            partition.next_offset = next_offset;
            partition.next_segment_id = next_segment_id;
        }
        Ok(())
    }
}

/// Append one frame to `segment_id` inside `topic_dir`, flushing and
/// optionally `sync_data`-ing before returning.
fn write_frame(topic_dir: &Path, segment_id: u32, frame: &[u8], fsync: FsyncPolicy) -> Result<()> {
    use std::io::Write as _;
    let path = topic_dir.join(segment_name(segment_id));
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| {
            StorageError::Engine(format!("cannot open segment {}: {e}", path.display()))
        })?;
    file.write_all(frame).map_err(|e| {
        StorageError::Engine(format!("cannot append to segment {}: {e}", path.display()))
    })?;
    file.flush().map_err(|e| {
        StorageError::Engine(format!("cannot flush segment {}: {e}", path.display()))
    })?;
    if fsync == FsyncPolicy::EveryWrite {
        file.sync_data().map_err(|e| {
            StorageError::Engine(format!("cannot fsync segment {}: {e}", path.display()))
        })?;
    }
    drop(file);
    if fsync == FsyncPolicy::EveryWrite {
        sync_dir_best_effort(topic_dir);
    }
    Ok(())
}

/// Rewrite a topic's segments from `kept` (already in offset order),
/// packing frames back up to `max_bytes`. Writes `META` so a fully-purged
/// partition keeps its next offset across restarts. Returns the next
/// segment id to allocate.
fn rewrite_topic_segments(
    dir: &Path,
    topic: &str,
    kept: &[StreamRecord],
    next_offset: u64,
    max_bytes: u64,
    fsync: FsyncPolicy,
) -> Result<u32> {
    use std::io::Write as _;
    let topic_dir = dir.join(encode_topic(topic));
    std::fs::create_dir_all(&topic_dir).map_err(|e| {
        StorageError::Engine(format!(
            "cannot create topic dir {}: {e}",
            topic_dir.display()
        ))
    })?;
    for (id, _) in list_segments(&topic_dir) {
        let path = topic_dir.join(segment_name(id));
        std::fs::remove_file(&path).map_err(|e| {
            StorageError::Engine(format!("cannot remove segment {}: {e}", path.display()))
        })?;
    }
    let mut segment_id: u32 = 0;
    let mut current: Vec<u8> = Vec::new();
    let mut segments: Vec<(u32, Vec<u8>)> = Vec::new();
    for record in kept {
        let frame = encode_frame(&encode_record(record));
        if !current.is_empty() && current.len() as u64 + frame.len() as u64 > max_bytes {
            segments.push((segment_id, std::mem::take(&mut current)));
            segment_id += 1;
        }
        current.extend_from_slice(&frame);
    }
    if !current.is_empty() {
        segments.push((segment_id, std::mem::take(&mut current)));
        segment_id += 1;
    }
    for (id, bytes) in &segments {
        let path = topic_dir.join(segment_name(*id));
        let mut file = std::fs::File::create(&path).map_err(|e| {
            StorageError::Engine(format!("cannot rewrite segment {}: {e}", path.display()))
        })?;
        file.write_all(bytes).map_err(|e| {
            StorageError::Engine(format!("cannot rewrite segment {}: {e}", path.display()))
        })?;
        file.flush().map_err(|e| {
            StorageError::Engine(format!("cannot flush segment {}: {e}", path.display()))
        })?;
        if fsync == FsyncPolicy::EveryWrite {
            file.sync_data().map_err(|e| {
                StorageError::Engine(format!("cannot fsync segment {}: {e}", path.display()))
            })?;
        }
    }
    write_meta(&topic_dir, next_offset, segment_id, fsync)?;
    sync_dir_best_effort(&topic_dir);
    // Caller copies this into `next_segment_id` while holding the guard.
    Ok(segment_id)
}

fn segment_name(id: u32) -> String {
    format!("{id:08}.log")
}

fn encode_topic(topic: &str) -> String {
    let mut out = String::with_capacity(topic.len());
    for b in topic.bytes() {
        if matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn decode_topic(encoded: &str) -> Option<String> {
    let bytes = encoded.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return None;
            }
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok()?;
            let b = u8::from_str_radix(hex, 16).ok()?;
            out.push(b);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn list_segments(topic_dir: &Path) -> Vec<(u32, PathBuf)> {
    let mut ids: Vec<(u32, PathBuf)> = Vec::new();
    let Ok(entries) = std::fs::read_dir(topic_dir) else {
        return ids;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(stem) = name.strip_suffix(".log") {
            if let Ok(id) = stem.parse::<u32>() {
                ids.push((id, entry.path()));
            }
        }
    }
    ids.sort_by_key(|(id, _)| *id);
    ids
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            if crc & 1 == 1 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

fn encode_record(record: &StreamRecord) -> Vec<u8> {
    let mut keys: Vec<&String> = record.headers.keys().collect();
    keys.sort();
    let mut out = Vec::with_capacity(
        8 + 8 + 1 + 4 + record.topic.as_str().len() + 4 + record.payload.len() + 4,
    );
    out.extend_from_slice(&record.offset.to_le_bytes());
    out.extend_from_slice(&record.timestamp_ms.to_le_bytes());
    out.push(u8::from(record.qos));
    let topic = record.topic.as_str().as_bytes();
    out.extend_from_slice(&(topic.len() as u32).to_le_bytes());
    out.extend_from_slice(topic);
    out.extend_from_slice(&(record.payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&record.payload);
    out.extend_from_slice(&(keys.len() as u32).to_le_bytes());
    for key in keys {
        let value = &record.headers[key];
        out.extend_from_slice(&(key.len() as u32).to_le_bytes());
        out.extend_from_slice(key.as_bytes());
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        out.extend_from_slice(value.as_bytes());
    }
    out
}

fn encode_frame(record_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + record_bytes.len() + 4);
    out.extend_from_slice(&(record_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(record_bytes);
    out.extend_from_slice(&crc32(record_bytes).to_le_bytes());
    out
}

fn decode_record(bytes: &[u8]) -> Option<StreamRecord> {
    let mut pos = 0usize;
    let take = |pos: &mut usize, n: usize| -> Option<&[u8]> {
        if pos.saturating_add(n) > bytes.len() {
            return None;
        }
        let slice = &bytes[*pos..*pos + n];
        *pos += n;
        Some(slice)
    };
    let offset = u64::from_le_bytes(take(&mut pos, 8)?.try_into().ok()?);
    let timestamp_ms = u64::from_le_bytes(take(&mut pos, 8)?.try_into().ok()?);
    let qos_byte = *take(&mut pos, 1)?.first()?;
    let qos = QoS::try_from(qos_byte).ok()?;
    let topic_len = u32::from_le_bytes(take(&mut pos, 4)?.try_into().ok()?) as usize;
    if topic_len == 0 || topic_len > MAX_TOPIC_BYTES {
        return None;
    }
    let topic_bytes = take(&mut pos, topic_len)?;
    let topic_str = std::str::from_utf8(topic_bytes).ok()?;
    let topic = Topic::new(topic_str.to_string()).ok()?;
    let payload_len = u32::from_le_bytes(take(&mut pos, 4)?.try_into().ok()?) as usize;
    if payload_len > MAX_PAYLOAD_BYTES {
        return None;
    }
    let payload_bytes = take(&mut pos, payload_len)?;
    let payload = Bytes::copy_from_slice(payload_bytes);
    let header_count = u32::from_le_bytes(take(&mut pos, 4)?.try_into().ok()?) as usize;
    if header_count > MAX_HEADERS {
        return None;
    }
    let mut headers = HashMap::with_capacity(header_count.min(32));
    for _ in 0..header_count {
        let key_len = u32::from_le_bytes(take(&mut pos, 4)?.try_into().ok()?) as usize;
        if key_len > MAX_HEADER_FIELD_BYTES {
            return None;
        }
        let key_bytes = take(&mut pos, key_len)?;
        let key = std::str::from_utf8(key_bytes).ok()?.to_string();
        let val_len = u32::from_le_bytes(take(&mut pos, 4)?.try_into().ok()?) as usize;
        if val_len > MAX_HEADER_FIELD_BYTES {
            return None;
        }
        let val_bytes = take(&mut pos, val_len)?;
        let value = std::str::from_utf8(val_bytes).ok()?.to_string();
        headers.insert(key, value);
    }
    if pos != bytes.len() {
        return None;
    }
    Some(StreamRecord {
        offset,
        timestamp_ms,
        topic,
        qos,
        payload,
        headers,
    })
}

/// Scan one segment file's bytes. Returns the decoded records, the byte
/// offset of the last good frame end, and whether the file ends cleanly.
/// `Err(last_good)` means the first frame at `last_good` is torn.
/// Scan one segment file's bytes. Always returns the good prefix:
/// `(records, last_good_end, complete)`. A truncated frame, CRC mismatch,
/// decode error, or offset gap ends the prefix at the torn frame start
/// with `complete` false; the caller truncates there and drops later
/// segments. Never fails for torn data.
fn scan_segment(bytes: &[u8], mut expected: Option<u64>) -> (Vec<StreamRecord>, usize, bool) {
    let mut records = Vec::new();
    let mut pos = 0usize;
    while pos < bytes.len() {
        let frame_start = pos;
        if bytes.len() - pos < 4 {
            return (records, frame_start, false);
        }
        let len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap_or([0; 4])) as usize;
        if !(MIN_RECORD_BYTES..=MAX_FRAME_BYTES).contains(&len) {
            return (records, frame_start, false);
        }
        // Need `len` record bytes plus 4 CRC bytes.
        if bytes.len() - pos - 4 < len + 4 {
            return (records, frame_start, false);
        }
        pos += 4;
        let record_bytes = &bytes[pos..pos + len];
        pos += len;
        let stored = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap_or([0; 4]));
        pos += 4;
        if crc32(record_bytes) != stored {
            return (records, frame_start, false);
        }
        let Some(record) = decode_record(record_bytes) else {
            return (records, frame_start, false);
        };
        match expected {
            None => expected = Some(record.offset + 1),
            Some(next) => {
                if record.offset != next {
                    return (records, frame_start, false);
                }
                expected = Some(next + 1);
            }
        }
        records.push(record);
    }
    (records, pos, true)
}

fn truncate_to(path: &Path, len: u64) {
    if let Ok(file) = std::fs::OpenOptions::new().write(true).open(path) {
        file.set_len(len).ok();
    }
}

fn meta_path(topic_dir: &Path) -> PathBuf {
    topic_dir.join("META")
}

fn write_meta(
    topic_dir: &Path,
    next_offset: u64,
    next_segment: u32,
    fsync: FsyncPolicy,
) -> Result<()> {
    use std::io::Write as _;
    let path = meta_path(topic_dir);
    let mut buf = [0u8; 12];
    buf[..8].copy_from_slice(&next_offset.to_le_bytes());
    buf[8..12].copy_from_slice(&next_segment.to_le_bytes());
    let mut file = std::fs::File::create(&path)
        .map_err(|e| StorageError::Engine(format!("cannot write {}: {e}", path.display())))?;
    file.write_all(&buf)
        .map_err(|e| StorageError::Engine(format!("cannot write {}: {e}", path.display())))?;
    file.flush()
        .map_err(|e| StorageError::Engine(format!("cannot flush {}: {e}", path.display())))?;
    if fsync == FsyncPolicy::EveryWrite {
        file.sync_data()
            .map_err(|e| StorageError::Engine(format!("cannot fsync {}: {e}", path.display())))?;
    }
    Ok(())
}

fn read_meta(topic_dir: &Path) -> (u64, u32) {
    let path = meta_path(topic_dir);
    let Ok(bytes) = std::fs::read(&path) else {
        return (0, 0);
    };
    if bytes.len() < 12 {
        return (0, 0);
    }
    let next_offset = u64::from_le_bytes(bytes[..8].try_into().unwrap_or([0; 8]));
    let next_segment = u32::from_le_bytes(bytes[8..12].try_into().unwrap_or([0; 4]));
    (next_offset, next_segment)
}

fn sync_dir_best_effort(dir: &Path) {
    if let Ok(file) = std::fs::File::open(dir) {
        file.sync_all().ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_dir(label: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let slot = COUNTER.fetch_add(1, Ordering::SeqCst);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "indramqtt-stream-{label}-{}-{nanos}-{slot}",
            std::process::id()
        ))
    }

    #[test]
    fn test_durable_stream_append_and_seek_offset() {
        let store = DurableStreamStore::new();
        let topic = Topic::new("sensors/vibration").unwrap();

        // Append 100 messages
        for i in 0..100 {
            let payload = Bytes::from(format!("vibration_data_{i}"));
            let offset = store
                .append(topic.clone(), QoS::AtLeastOnce, payload, HashMap::new())
                .unwrap();
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
            store
                .append_with_timestamp(topic.clone(), QoS::ExactlyOnce, payload, HashMap::new(), ts)
                .unwrap();
        }

        // Seek from base_time + 4500ms -> should return records from base_time + 5000ms onwards
        let results = store
            .seek_timestamp("trades/btcusdt", base_time + 4500, 10)
            .unwrap();
        assert_eq!(results.len(), 5);
        assert_eq!(results[0].offset, 5);
        assert_eq!(results[0].timestamp_ms, base_time + 5000);

        // Purge records older than base_time + 3000ms
        let purged = store
            .purge_retention("trades/btcusdt", base_time + 3000)
            .unwrap();
        assert_eq!(purged, 3);
        assert_eq!(store.stream_len("trades/btcusdt"), 7);
        assert_eq!(store.earliest_offset("trades/btcusdt"), Some(3));
    }

    #[test]
    fn test_stream_restart_rebuilds_offsets_and_times() {
        let dir = unique_dir("restart");
        let base_time = 1_710_000_000_000u64;
        let topic_str = "factory/line1/vibration";
        {
            let store =
                DurableStreamStore::open_with_config(&dir, StreamConfig::default()).unwrap();
            assert!(store.is_persistent());
            let topic = Topic::new(topic_str).unwrap();
            for i in 0..50 {
                let mut headers = HashMap::new();
                headers.insert("seq".to_string(), i.to_string());
                let offset = store
                    .append_with_timestamp(
                        topic.clone(),
                        QoS::AtLeastOnce,
                        Bytes::from(format!("frame_{i}")),
                        headers.clone(),
                        base_time + i * 100,
                    )
                    .unwrap();
                assert_eq!(offset, i);
            }
            assert_eq!(store.stream_len(topic_str), 50);
        }
        // Drop and recreate from the same directory.
        let store = DurableStreamStore::open_with_config(&dir, StreamConfig::default()).unwrap();
        assert_eq!(store.stream_len(topic_str), 50);
        assert_eq!(store.earliest_offset(topic_str), Some(0));
        assert_eq!(store.latest_offset(topic_str), Some(49));
        for i in 0..50 {
            let record = store.get(topic_str, i).unwrap();
            assert_eq!(record.offset, i);
            assert_eq!(record.timestamp_ms, base_time + i * 100);
            assert_eq!(record.payload, Bytes::from(format!("frame_{i}")));
            assert_eq!(record.headers.get("seq"), Some(&i.to_string()));
        }
        let replayed = store.seek_offset(topic_str, 20, 10).unwrap();
        assert_eq!(replayed.len(), 10);
        assert_eq!(replayed[0].offset, 20);
        let timed = store
            .seek_timestamp(topic_str, base_time + 2450, 10)
            .unwrap();
        assert_eq!(timed[0].offset, 25);
        assert_eq!(timed[0].timestamp_ms, base_time + 2500);
        // New appends continue the offset sequence after recovery.
        let next = store
            .append_with_timestamp(
                Topic::new(topic_str).unwrap(),
                QoS::AtLeastOnce,
                Bytes::from_static(b"frame_50"),
                HashMap::new(),
                base_time + 5000,
            )
            .unwrap();
        assert_eq!(next, 50);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_stream_torn_tail_is_discarded_on_recovery() {
        let dir = unique_dir("torn");
        let base_time = 1_710_000_000_000u64;
        let topic_str = "sensors/torn";
        {
            let store =
                DurableStreamStore::open_with_config(&dir, StreamConfig::default()).unwrap();
            let topic = Topic::new(topic_str).unwrap();
            for i in 0..10 {
                store
                    .append_with_timestamp(
                        topic.clone(),
                        QoS::AtLeastOnce,
                        Bytes::from(format!("good_{i}")),
                        HashMap::new(),
                        base_time + i * 10,
                    )
                    .unwrap();
            }
        }
        // Truncate the single segment mid-record: cut 6 bytes off the end
        // so the last frame loses its CRC and part of its payload.
        let segment = dir.join(encode_topic(topic_str)).join("00000000.log");
        let len = std::fs::metadata(&segment).unwrap().len();
        assert!(len > 16);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&segment)
            .unwrap()
            .set_len(len - 6)
            .unwrap();
        let store = DurableStreamStore::open_with_config(&dir, StreamConfig::default()).unwrap();
        // Everything before the torn tail survives; the torn frame is gone.
        assert_eq!(store.stream_len(topic_str), 9);
        assert_eq!(store.latest_offset(topic_str), Some(8));
        for i in 0..9 {
            let record = store.get(topic_str, i).unwrap();
            assert_eq!(record.payload, Bytes::from(format!("good_{i}")));
        }
        assert!(store.get(topic_str, 9).is_err());
        // The store is writable again after the tear.
        let next = store
            .append_with_timestamp(
                Topic::new(topic_str).unwrap(),
                QoS::AtLeastOnce,
                Bytes::from_static(b"good_9b"),
                HashMap::new(),
                base_time + 90,
            )
            .unwrap();
        assert_eq!(next, 9);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_stream_segment_roll_keeps_time_index() {
        let dir = unique_dir("roll");
        let config = StreamConfig::default().with_segment_max_bytes(1024);
        let store = DurableStreamStore::open_with_config(&dir, config).unwrap();
        let topic_str = "sensors/roll";
        let topic = Topic::new(topic_str).unwrap();
        let base_time = 1_720_000_000_000u64;
        for i in 0..40 {
            store
                .append_with_timestamp(
                    topic.clone(),
                    QoS::AtMostOnce,
                    Bytes::from(vec![b'x'; 128]),
                    HashMap::new(),
                    base_time + i * 50,
                )
                .unwrap();
        }
        let segments = list_segments(&dir.join(encode_topic(topic_str)));
        assert!(
            segments.len() >= 2,
            "expected a roll, got {} segments",
            segments.len()
        );
        assert_eq!(store.stream_len(topic_str), 40);
        let timed = store.seek_timestamp(topic_str, base_time + 975, 5).unwrap();
        assert_eq!(timed.len(), 5);
        assert_eq!(timed[0].offset, 20);
        // Restart keeps the index accurate across the roll boundary.
        drop(store);
        let store = DurableStreamStore::open_with_config(&dir, config).unwrap();
        assert_eq!(store.stream_len(topic_str), 40);
        let timed = store.seek_timestamp(topic_str, base_time + 975, 5).unwrap();
        assert_eq!(timed.len(), 5);
        assert_eq!(timed[0].offset, 20);
        assert_eq!(timed[0].timestamp_ms, base_time + 1000);
        let replayed = store.seek_offset(topic_str, 0, 40).unwrap();
        assert_eq!(replayed.len(), 40);
        assert_eq!(replayed[39].offset, 39);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_stream_purge_stays_gone_after_restart() {
        let dir = unique_dir("purge");
        let store = DurableStreamStore::open_with_config(&dir, StreamConfig::default()).unwrap();
        let topic_str = "sensors/purge";
        let topic = Topic::new(topic_str).unwrap();
        let base_time = 1_730_000_000_000u64;
        for i in 0..10 {
            store
                .append_with_timestamp(
                    topic.clone(),
                    QoS::AtLeastOnce,
                    Bytes::from(format!("v{i}")),
                    HashMap::new(),
                    base_time + i * 1000,
                )
                .unwrap();
        }
        let purged = store.purge_retention(topic_str, base_time + 5000).unwrap();
        assert_eq!(purged, 5);
        drop(store);
        let store = DurableStreamStore::open_with_config(&dir, StreamConfig::default()).unwrap();
        assert_eq!(store.stream_len(topic_str), 5);
        assert_eq!(store.earliest_offset(topic_str), Some(5));
        let next = store
            .append(
                topic,
                QoS::AtLeastOnce,
                Bytes::from_static(b"v10"),
                HashMap::new(),
            )
            .unwrap();
        assert_eq!(next, 10);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_stream_open_rejects_empty_segment_config() {
        let dir = unique_dir("badcfg");
        let config = StreamConfig::default().with_segment_max_bytes(0);
        assert!(DurableStreamStore::open_with_config(&dir, config).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}
