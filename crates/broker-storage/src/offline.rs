//! Durable backing for the per-session offline queue.
//!
//! Each detached durable session buffers never-routed messages in memory
//! (see `broker-session`). This store keeps the same queue on disk so a
//! restart replays it in order instead of losing it. One append-only file
//! per `(tenant, client id)` pair lives under
//! `<dir>/<encoded-client>.log` for default-tenant queues (the pre-tenancy
//! layout, preserved so existing files keep loading) and
//! `<dir>/<encoded-tenant>+<encoded-client>.log` otherwise, so two
//! tenants sharing a client id never share or clobber one file. The `+`
//! separator is unambiguous because the encoder never emits a raw `+`
//! (a literal `+` encodes as `%2B`).
//!
//! # Durability contract (read this before relying on it)
//!
//! - [`OfflineQueueStore::open`] persists every acknowledged append: the
//!   frame is written and flushed before `Ok(())` returns.
//! - With [`FsyncPolicy::EveryWrite`] (the default) each acknowledged
//!   append additionally calls `sync_data` before returning. A crash then
//!   loses at most the single append racing the crash; a torn tail is
//!   truncated at the last good frame on the next load and counted, never
//!   served. Cost: one `fsync` per buffered message; the per-message cost
//!   is measured by the pipeline's disconnect-reconnect BENCH workload,
//!   never stated here.
//! - With [`FsyncPolicy::NoSync`] bytes are only flushed to the OS. A
//!   process crash keeps flushed data, but a power loss can lose the page
//!   cache tail. Use it only for benchmarks where losing the tail is
//!   acceptable.
//! - Appends run synchronously inside the session's offline-queue write
//!   (see `broker-session`), so an acknowledged publish that buffered for
//!   at least one detached durable session has already fsynced that entry
//!   before the publisher's reply is flushed. The durability window past
//!   the ack is therefore zero for buffered messages; messages that never
//!   entered a detached queue were never promised anything. Live fan-out
//!   to connected sessions pays nothing: no file is touched unless at
//!   least one matching session is detached and durable.
//! - The queue cap itself is enforced by the session layer (oldest dropped
//!   past the cap, counted). The file follows the memory queue: appends
//!   extend it, evictions and drains rewrite or delete it. With a cap
//!   `Some(n)` file size is therefore bounded by `n * max_record_bytes`;
//!   with `None` (explicit unbounded opt-in via `new_with_limits(None)`)
//!   queue and file both grow without bound by design. The production
//!   default is a `Some(10_000)` cap per detached session (high enough for
//!   reconnect storms without drops), so the default deployment is bounded.
//!
//! Frame layout per file: `[u32 len][record bytes][u32 crc32(record)]`,
//! all integers little-endian. Recovery scans in order; the first
//! truncated frame, CRC mismatch or decode error truncates the file at the
//! last good frame end. The torn tail is discarded with a counter and
//! never served.
//!
//! Per-message cost on the buffering path only (detached durable match):
//! one bounded record encode, one file append plus flush, one `sync_data`
//! under `EveryWrite`, and one directory sync (best effort). Eviction
//! past the cap additionally rewrites the file from the surviving queue
//! snapshot: `O(cap)` bytes, bounded by the configured cap, off the live
//! delivery path (detached sessions have no live traffic).
//!
//! Locking: the store itself holds no locks (each call opens, writes and
//! closes its file). Callers serialize per-session file mutations under
//! the session's own persist mutex so file order always matches queue
//! order; the per-session queue lock is taken only for the memory push or
//! snapshot, never held across file I/O. No new lock is added to the live
//! publish or deliver path: files are touched only for detached durable
//! matches, and live deliveries to connected sessions never touch a file
//! or either lock.
//!
//! Rewrite temps: every `rewrite` writes a unique `.<key>.<pid>.<seq>.tmp`
//! and renames it into place, so a crash between create and rename can
//! leave an orphan temp behind. `open_with_config` sweeps those orphans
//! (every `*.tmp` regular file in the directory, best effort) before
//! returning, so no orphan survives an open: the bound is zero orphan
//! temps after boot, and the sweep itself runs once per open (boot only,
//! one directory listing) instead of per message.

use super::stream::FsyncPolicy;
use crate::{Result, StorageError};
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Tenant id whose queues keep the pre-tenancy bare file layout. Matches
/// `broker-session`'s default tenant so the default queue and its file
/// resolve through the same name on both sides of the store boundary.
/// Reason for the literal here instead of a dependency: storage must not
/// depend on the session crate (the session crate depends on storage).
const DEFAULT_TENANT_ID: &str = "default";

/// Largest single frame accepted on recovery (`len` field plus slack).
///
/// 300 MB comfortably covers the largest legal payload (~256 MB) plus
/// topic and headers while bounding allocation on a corrupt length prefix.
const MAX_FRAME_BYTES: usize = 300_000_000;
/// Smallest legal record encoding: qos(1) + retain(1) + timestamp(8) +
/// topic_len(4) + payload_len(4), before topic and payload bytes.
const MIN_RECORD_BYTES: usize = 1 + 1 + 8 + 4 + 4;
/// Longest topic accepted from a queue file (protocol UTF-8 limit).
const MAX_TOPIC_BYTES: usize = 65_535;
/// Largest payload accepted from a queue file (remaining-length cap).
const MAX_PAYLOAD_BYTES: usize = 268_435_456;
/// Marker for "no timestamp" in the record encoding.
const NO_TIMESTAMP: u64 = u64::MAX;

/// Tuning for [`OfflineQueueStore::open_with_config`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OfflineConfig {
    /// When bytes are forced to stable storage (see [`FsyncPolicy`]).
    pub fsync: FsyncPolicy,
}

impl Default for OfflineConfig {
    fn default() -> Self {
        Self {
            fsync: FsyncPolicy::EveryWrite,
        }
    }
}

impl OfflineConfig {
    /// Override the fsync policy.
    pub fn with_fsync(mut self, fsync: FsyncPolicy) -> Self {
        self.fsync = fsync;
        self
    }
}

/// One buffered message for a detached durable session, in queue order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineRecord {
    pub topic: Topic,
    pub qos: QoS,
    pub retain: bool,
    pub payload: Bytes,
    /// Publish time as millis since the Unix epoch, if stamped.
    pub publish_at_ms: Option<u64>,
}

/// Durable per-session offline queue backing.
///
/// Opened on `<dir>` (created when missing). `None`-equivalent behaviour
/// (pure memory queues) is achieved by never installing a store on the
/// session layer, not by a flag here: every method on this type touches
/// the filesystem.
#[derive(Debug)]
pub struct OfflineQueueStore {
    dir: PathBuf,
    fsync: FsyncPolicy,
    recovery_torn: AtomicU64,
    persist_failed: AtomicU64,
    /// Monotonic writer nonce for unique rewrite temp files. Each
    /// `rewrite` claims one value and embeds it in its temp name alongside
    /// the client key, so two concurrent rewrites for one client (or two
    /// clients at once) never share a temp path and rename atomically into
    /// place. Unbounded in practice (u64); one increment per rewrite on the
    /// detached-buffer path only.
    tmp_seq: AtomicU64,
}

impl OfflineQueueStore {
    /// Open (or create) the store in `dir` with the default config
    /// (fsync per append). Rebuilds nothing eagerly: each client file is
    /// scanned lazily by [`load`](OfflineQueueStore::load) and
    /// [`client_ids`](OfflineQueueStore::client_ids) lists what is there.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_config(dir, OfflineConfig::default())
    }

    /// Open (or create) the store in `dir` with `config`. Sweeps orphan
    /// rewrite temps left by a crash (see the module docs) before
    /// returning so they cannot accumulate across restarts.
    pub fn open_with_config(dir: impl AsRef<Path>, config: OfflineConfig) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir).map_err(|e| {
            StorageError::Engine(format!("cannot create offline dir {}: {e}", dir.display()))
        })?;
        sweep_orphan_tmps(&dir);
        Ok(Self {
            dir,
            fsync: config.fsync,
            recovery_torn: AtomicU64::new(0),
            persist_failed: AtomicU64::new(0),
            tmp_seq: AtomicU64::new(0),
        })
    }

    /// Backing directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Torn tails discarded by [`load`](OfflineQueueStore::load) so far.
    pub fn recovery_torn(&self) -> u64 {
        self.recovery_torn.load(Ordering::Relaxed)
    }

    /// File writes that failed (append or rewrite). A failed append queues
    /// nothing: the entry is dropped from memory as well (fail closed) so
    /// a QoS 1 publisher is never acked for a message with no durable
    /// copy; see `broker-session` (`push_offline_with_limit` returns false)
    /// and the kernel publish path, which withholds the ack so the
    /// publisher retries. Failures are counted here, logged where they
    /// happen, and never served as durable state.
    /// TODO(parity): should a failed eviction rewrite also roll the memory
    /// queue back, or is keeping the capped memory queue (which the next
    /// restore re-caps) plus a publisher retry enough? The rulebook does
    /// not decide the rollback order; current choice keeps the capped
    /// memory queue and only guarantees the publisher retries.
    pub fn persist_failed(&self) -> u64 {
        self.persist_failed.load(Ordering::Relaxed)
    }

    /// Client ids with a legacy bare-layout queue file on disk, in sorted
    /// order: the default tenant's queues (written before tenancy or via
    /// the default-tenant shims below). Tenant-qualified files (stems
    /// containing the raw `+` separator) are skipped here and listed via
    /// [`queue_keys`](OfflineQueueStore::queue_keys) instead. Files whose
    /// names do not decode are skipped (never served, never counted: they
    /// were not written by this store).
    pub fn client_ids(&self) -> Vec<String> {
        let mut ids = Vec::new();
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return ids;
        };
        for entry in entries.flatten() {
            if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(stem) = name.strip_suffix(".log") else {
                continue;
            };
            if stem.contains('+') {
                continue;
            }
            if let Some(id) = decode_client(stem) {
                ids.push(id);
            }
        }
        ids.sort();
        ids
    }

    /// Every `(tenant, client id)` pair with a queue file on disk, in
    /// sorted order (MT-03): legacy bare-layout files decode to the
    /// default tenant, tenant-qualified files to their own tenant, so a
    /// restart rebuilds each tenant's sessions independently. Files whose
    /// names do not decode are skipped (never served, never counted).
    pub fn queue_keys(&self) -> Vec<(String, String)> {
        let mut keys = Vec::new();
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return keys;
        };
        for entry in entries.flatten() {
            if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(stem) = name.strip_suffix(".log") else {
                continue;
            };
            if let Some(key) = decode_key(stem) {
                keys.push(key);
            }
        }
        keys.sort();
        keys
    }

    /// Append one record for `client_id` in the default tenant, flushing
    /// (and fsyncing under `EveryWrite`) before returning. Default-tenant
    /// shim for [`append_in_tenant`](OfflineQueueStore::append_in_tenant);
    /// keeps the pre-tenancy bare file layout. Returns
    /// [`StorageError::Engine`] on I/O failure with nothing acknowledged.
    pub fn append(&self, client_id: &str, record: &OfflineRecord) -> Result<()> {
        self.append_in_tenant(DEFAULT_TENANT_ID, client_id, record)
    }

    /// Append one record for one `(tenant, client id)` pair (MT-03): the
    /// same client id in two tenants appends to two independent files, so
    /// one tenant's backlog never lands in another's. Flushes (and fsyncs
    /// under `EveryWrite`) before returning; I/O failure acknowledges
    /// nothing.
    pub fn append_in_tenant(
        &self,
        tenant: &str,
        client_id: &str,
        record: &OfflineRecord,
    ) -> Result<()> {
        use std::io::Write as _;
        let path = self.log_path_for(tenant, client_id)?;
        let frame = encode_frame(&encode_record(record));
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| {
                self.persist_failed.fetch_add(1, Ordering::Relaxed);
                StorageError::Engine(format!("cannot open offline log {}: {e}", path.display()))
            })?;
        file.write_all(&frame).map_err(|e| {
            self.persist_failed.fetch_add(1, Ordering::Relaxed);
            StorageError::Engine(format!(
                "cannot append to offline log {}: {e}",
                path.display()
            ))
        })?;
        file.flush().map_err(|e| {
            self.persist_failed.fetch_add(1, Ordering::Relaxed);
            StorageError::Engine(format!("cannot flush offline log {}: {e}", path.display()))
        })?;
        if self.fsync == FsyncPolicy::EveryWrite {
            file.sync_data().map_err(|e| {
                self.persist_failed.fetch_add(1, Ordering::Relaxed);
                StorageError::Engine(format!("cannot fsync offline log {}: {e}", path.display()))
            })?;
        }
        drop(file);
        if self.fsync == FsyncPolicy::EveryWrite {
            sync_dir_best_effort(&self.dir);
        }
        Ok(())
    }

    /// Load the default-tenant queue for `client_id` in order. Shim for
    /// [`load_in_tenant`](OfflineQueueStore::load_in_tenant). A torn tail
    /// is truncated at the last good frame, counted once per file that
    /// needed it, and never served. Missing files load as empty with no
    /// tear. Returns `(records, torn)` where `torn` is 0 or 1.
    pub fn load(&self, client_id: &str) -> (Vec<OfflineRecord>, u64) {
        self.load_in_tenant(DEFAULT_TENANT_ID, client_id)
    }

    /// Load one `(tenant, client id)` queue in order (MT-03): another
    /// tenant's namesake file is never consulted, so post-restart replay
    /// serves only the owning tenant's backlog. Same torn-tail contract
    /// as the default-tenant shim.
    pub fn load_in_tenant(&self, tenant: &str, client_id: &str) -> (Vec<OfflineRecord>, u64) {
        let Ok(path) = self.log_path_for(tenant, client_id) else {
            return (Vec::new(), 0);
        };
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (Vec::new(), 0),
            Err(_) => {
                self.recovery_torn.fetch_add(1, Ordering::Relaxed);
                return (Vec::new(), 1);
            }
        };
        let (records, last_good, complete) = scan_file(&bytes);
        if !complete {
            truncate_to(&path, last_good as u64);
            self.recovery_torn.fetch_add(1, Ordering::Relaxed);
            return (records, 1);
        }
        (records, 0)
    }

    /// Rewrite the default-tenant file for `client_id` from `records`
    /// (already in queue order). Shim for
    /// [`rewrite_in_tenant`](OfflineQueueStore::rewrite_in_tenant).
    /// Used after evictions past the cap so the file follows the
    /// memory queue, and after drains when the caller prefers a rewrite
    /// over a delete. An empty slice deletes the file instead. Atomic via
    /// temp plus rename; failures return [`StorageError::Engine`] and count
    /// toward [`persist_failed`](OfflineQueueStore::persist_failed).
    /// PERF(parity): eviction by head-offset watermark instead of a full
    /// rewrite would avoid the O(cap) copy on every drop past a full
    /// queue; current cost is bounded by the cap and runs only on the
    /// detached-buffer path.
    pub fn rewrite(&self, client_id: &str, records: &[OfflineRecord]) -> Result<()> {
        self.rewrite_in_tenant(DEFAULT_TENANT_ID, client_id, records)
    }

    /// Rewrite one `(tenant, client id)` file from `records` (MT-03):
    /// evictions and confirms rewrite only the owning tenant's file, so
    /// one tenant's cap enforcement never touches another tenant's
    /// backlog. Same atomic temp-plus-rename contract as the shim.
    pub fn rewrite_in_tenant(
        &self,
        tenant: &str,
        client_id: &str,
        records: &[OfflineRecord],
    ) -> Result<()> {
        if records.is_empty() {
            self.remove_in_tenant(tenant, client_id);
            return Ok(());
        }
        let Ok(path) = self.log_path_for(tenant, client_id) else {
            self.persist_failed.fetch_add(1, Ordering::Relaxed);
            return Err(StorageError::Engine(
                "cannot encode offline log name".to_string(),
            ));
        };
        let mut bytes = Vec::new();
        for record in records {
            bytes.extend_from_slice(&encode_frame(&encode_record(record)));
        }
        // Unique temp per write: client key plus a monotonic counter (and
        // pid so two processes on one directory never share a path).
        // Renamed atomically into place; fsynced before the rename under
        // `EveryWrite` so the durable queue never exposes a half-written
        // file. Temp names end in `.tmp`, never `.log`, so `client_ids`
        // never lists them; a crash between create and rename leaves an
        // orphan that the next `open_with_config` sweeps (see
        // `sweep_orphan_tmps`), so orphans cannot accumulate.
        let seq = self.tmp_seq.fetch_add(1, Ordering::SeqCst);
        let tmp = self.dir.join(format!(
            ".{}.{}.{}.{}.tmp",
            encode_client(tenant),
            encode_client(client_id),
            std::process::id(),
            seq
        ));
        let ok = (|| -> std::io::Result<()> {
            use std::io::Write as _;
            let mut handle = std::fs::File::create(&tmp)?;
            handle.write_all(&bytes)?;
            handle.flush()?;
            if self.fsync == FsyncPolicy::EveryWrite {
                handle.sync_data()?;
            }
            drop(handle);
            std::fs::rename(&tmp, &path)?;
            Ok(())
        })()
        .is_ok();
        if !ok {
            std::fs::remove_file(&tmp).ok();
            self.persist_failed.fetch_add(1, Ordering::Relaxed);
            return Err(StorageError::Engine(format!(
                "cannot rewrite offline log {}",
                path.display()
            )));
        }
        if self.fsync == FsyncPolicy::EveryWrite {
            sync_dir_best_effort(&self.dir);
        }
        Ok(())
    }

    /// Delete the default-tenant queue file for `client_id`. Shim for
    /// [`remove_in_tenant`](OfflineQueueStore::remove_in_tenant).
    /// Missing files are a no-op.
    /// Called on reconnect drains (the memory queue was handed to the new
    /// connection) and on clean-start replacement (previous durable state
    /// is discarded by definition).
    pub fn remove(&self, client_id: &str) {
        self.remove_in_tenant(DEFAULT_TENANT_ID, client_id);
    }

    /// Delete one `(tenant, client id)` queue file (MT-03): a drain or a
    /// clean start in one tenant deletes only its own file, never
    /// another tenant's namesake backlog.
    pub fn remove_in_tenant(&self, tenant: &str, client_id: &str) {
        let Ok(path) = self.log_path_for(tenant, client_id) else {
            return;
        };
        if let Err(e) = std::fs::remove_file(&path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                self.persist_failed.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Tenant-scoped file layout (MT-03): default-tenant queues keep the
    /// pre-tenancy bare `<encoded-client>.log` name so existing files keep
    /// loading without a migration; any other tenant uses
    /// `<encoded-tenant>+<encoded-client>.log`. The `+` separator is
    /// unambiguous because `encode_client` never emits a raw `+`.
    fn log_path_for(&self, tenant: &str, client_id: &str) -> Result<PathBuf> {
        if client_id.is_empty() {
            return Err(StorageError::Engine(
                "client id must not be empty".to_string(),
            ));
        }
        if tenant.is_empty() {
            return Err(StorageError::Engine(
                "tenant id must not be empty".to_string(),
            ));
        }
        if tenant == DEFAULT_TENANT_ID {
            return self.log_path(client_id);
        }
        Ok(self.dir.join(format!(
            "{}+{}.log",
            encode_client(tenant),
            encode_client(client_id)
        )))
    }

    fn log_path(&self, client_id: &str) -> Result<PathBuf> {
        if client_id.is_empty() {
            return Err(StorageError::Engine(
                "client id must not be empty".to_string(),
            ));
        }
        Ok(self.dir.join(format!("{}.log", encode_client(client_id))))
    }
}

fn encode_client(client_id: &str) -> String {
    let mut out = String::with_capacity(client_id.len());
    for b in client_id.bytes() {
        if matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn decode_client(encoded: &str) -> Option<String> {
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

/// Decode one queue-file stem into its `(tenant, client id)` pair
/// (MT-03): a bare stem is a legacy default-tenant queue, a stem with
/// one raw `+` is `<encoded-tenant>+<encoded-client>`. Returns `None`
/// for names this store never wrote (undecodable halves, extra `+`
/// separators). Each half must be non-empty and must itself decode, so
/// a separator-only or corrupt name is never served.
fn decode_key(stem: &str) -> Option<(String, String)> {
    match stem.split_once('+') {
        None => decode_client(stem).map(|client_id| (DEFAULT_TENANT_ID.to_string(), client_id)),
        Some((tenant_enc, client_enc)) => {
            if tenant_enc.is_empty() || client_enc.is_empty() {
                return None;
            }
            if client_enc.contains('+') {
                return None;
            }
            let tenant = decode_client(tenant_enc)?;
            let client_id = decode_client(client_enc)?;
            if tenant.is_empty() || client_id.is_empty() {
                return None;
            }
            Some((tenant, client_id))
        }
    }
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

fn encode_record(record: &OfflineRecord) -> Vec<u8> {
    let topic = record.topic.as_str().as_bytes();
    let mut out = Vec::with_capacity(MIN_RECORD_BYTES + topic.len() + record.payload.len());
    out.push(u8::from(record.qos));
    out.push(u8::from(record.retain));
    out.extend_from_slice(&record.publish_at_ms.unwrap_or(NO_TIMESTAMP).to_le_bytes());
    out.extend_from_slice(&(topic.len() as u32).to_le_bytes());
    out.extend_from_slice(topic);
    out.extend_from_slice(&(record.payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&record.payload);
    out
}

fn decode_record(bytes: &[u8]) -> Option<OfflineRecord> {
    let mut pos = 0usize;
    let take = |pos: &mut usize, n: usize| -> Option<&[u8]> {
        if pos.saturating_add(n) > bytes.len() {
            return None;
        }
        let slice = &bytes[*pos..*pos + n];
        *pos += n;
        Some(slice)
    };
    let qos_byte = *take(&mut pos, 1)?.first()?;
    let qos = QoS::try_from(qos_byte).ok()?;
    let retain_byte = *take(&mut pos, 1)?.first()?;
    if retain_byte > 1 {
        return None;
    }
    let stamp = u64::from_le_bytes(take(&mut pos, 8)?.try_into().ok()?);
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
    if pos != bytes.len() {
        return None;
    }
    Some(OfflineRecord {
        topic,
        qos,
        retain: retain_byte == 1,
        payload: Bytes::copy_from_slice(payload_bytes),
        publish_at_ms: if stamp == NO_TIMESTAMP {
            None
        } else {
            Some(stamp)
        },
    })
}

fn encode_frame(record_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + record_bytes.len() + 4);
    out.extend_from_slice(&(record_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(record_bytes);
    out.extend_from_slice(&crc32(record_bytes).to_le_bytes());
    out
}

/// Scan one queue file's bytes. Returns the decoded records, the byte
/// offset of the last good frame end, and whether the file ends cleanly.
/// A truncated frame, CRC mismatch, decode error or corrupt length ends
/// the prefix at the torn frame start with `complete` false. Never fails
/// for torn data.
fn scan_file(bytes: &[u8]) -> (Vec<OfflineRecord>, usize, bool) {
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
        records.push(record);
    }
    (records, pos, true)
}

fn truncate_to(path: &Path, len: u64) {
    if let Ok(file) = std::fs::OpenOptions::new().write(true).open(path) {
        file.set_len(len).ok();
    }
}

fn sync_dir_best_effort(dir: &Path) {
    if let Ok(file) = std::fs::File::open(dir) {
        file.sync_all().ok();
    }
}

/// Remove orphan rewrite temps (`*.tmp`) left when a crash landed
/// between temp create and rename. Best effort: unreadable directories
/// and per-file failures are ignored (the next open retries). Runs once
/// per open (boot only, one directory listing), never per message, so the
/// sweep itself is bounded and off the publish path.
fn sweep_orphan_tmps(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".tmp") {
            continue;
        }
        std::fs::remove_file(entry.path()).ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(i: u8) -> OfflineRecord {
        OfflineRecord {
            topic: Topic::new("sensors/temp").unwrap(),
            qos: QoS::AtLeastOnce,
            retain: false,
            payload: Bytes::from(vec![i]),
            publish_at_ms: Some(1_700_000_000_000 + u64::from(i)),
        }
    }

    fn unique_dir(label: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let slot = COUNTER.fetch_add(1, Ordering::SeqCst);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "indramqtt-offline-{label}-{}-{nanos}-{slot}",
            std::process::id()
        ))
    }

    #[test]
    fn offline_round_trip_survives_reopen_in_order() {
        let dir = unique_dir("roundtrip");
        {
            let store = OfflineQueueStore::open(&dir).unwrap();
            for i in 0..10u8 {
                store.append("device-1", &record(i)).unwrap();
            }
            assert_eq!(store.client_ids(), vec!["device-1".to_string()]);
        }
        let store = OfflineQueueStore::open(&dir).unwrap();
        let (loaded, torn) = store.load("device-1");
        assert_eq!(torn, 0);
        assert_eq!(loaded.len(), 10);
        for (i, rec) in loaded.iter().enumerate() {
            assert_eq!(rec.payload, Bytes::from(vec![i as u8]));
            assert_eq!(rec.publish_at_ms, Some(1_700_000_000_000 + i as u64));
        }
        assert_eq!(store.recovery_torn(), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn offline_torn_tail_is_discarded_and_counted() {
        let dir = unique_dir("torn");
        {
            let store = OfflineQueueStore::open(&dir).unwrap();
            for i in 0..10u8 {
                store.append("device-9", &record(i)).unwrap();
            }
        }
        let path = dir.join(format!("{}.log", encode_client("device-9")));
        let len = std::fs::metadata(&path).unwrap().len();
        assert!(len > 16);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(len - 6)
            .unwrap();
        let store = OfflineQueueStore::open(&dir).unwrap();
        let (loaded, torn) = store.load("device-9");
        assert_eq!(torn, 1);
        assert_eq!(store.recovery_torn(), 1);
        assert_eq!(loaded.len(), 9);
        for (i, rec) in loaded.iter().enumerate() {
            assert_eq!(rec.payload, Bytes::from(vec![i as u8]));
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn offline_rewrite_and_remove_follow_the_queue() {
        let dir = unique_dir("rewrite");
        let store = OfflineQueueStore::open(&dir).unwrap();
        for i in 0..5u8 {
            store.append("device-2", &record(i)).unwrap();
        }
        // Eviction of the oldest two: rewrite from the surviving snapshot.
        let kept: Vec<OfflineRecord> = store.load("device-2").0.into_iter().skip(2).collect();
        store.rewrite("device-2", &kept).unwrap();
        let (loaded, torn) = store.load("device-2");
        assert_eq!(torn, 0);
        assert_eq!(loaded.len(), 3);
        assert_eq!(loaded[0].payload, Bytes::from(vec![2u8]));
        // Drain deletes the file; the client disappears from the listing.
        store.remove("device-2");
        assert!(store.client_ids().is_empty());
        let (loaded, _) = store.load("device-2");
        assert!(loaded.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn offline_tenant_files_are_independent_per_client_pair() {
        // MT-03: the same client id in two tenants holds two independent
        // files. The default tenant keeps the bare layout; a named tenant
        // uses the `<tenant>+<client>` stem.
        let dir = unique_dir("tenant-keys");
        let store = OfflineQueueStore::open(&dir).unwrap();
        store
            .append_in_tenant("tenant-a", "dup", &record(1))
            .unwrap();
        store
            .append_in_tenant("tenant-b", "dup", &record(2))
            .unwrap();
        store.append("plain", &record(3)).unwrap();

        // Each pair loads only its own record.
        let (a, torn) = store.load_in_tenant("tenant-a", "dup");
        assert_eq!(torn, 0);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].payload, Bytes::from(vec![1u8]));
        let (b, torn) = store.load_in_tenant("tenant-b", "dup");
        assert_eq!(torn, 0);
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].payload, Bytes::from(vec![2u8]));
        let (plain, _) = store.load("plain");
        assert_eq!(plain.len(), 1);

        // The listing carries every pair; the bare listing carries only
        // the legacy default-tenant files.
        assert_eq!(
            store.queue_keys(),
            vec![
                ("default".to_string(), "plain".to_string()),
                ("tenant-a".to_string(), "dup".to_string()),
                ("tenant-b".to_string(), "dup".to_string()),
            ]
        );
        assert_eq!(store.client_ids(), vec!["plain".to_string()]);

        // Removal in one tenant leaves the namesake file alone.
        store.remove_in_tenant("tenant-a", "dup");
        assert!(store.load_in_tenant("tenant-a", "dup").0.is_empty());
        let (b, _) = store.load_in_tenant("tenant-b", "dup");
        assert_eq!(b.len(), 1);
        assert_eq!(
            store.queue_keys(),
            vec![
                ("default".to_string(), "plain".to_string()),
                ("tenant-b".to_string(), "dup".to_string()),
            ]
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
