//! Rotating local disk log sink (INDRA-200).
//!
//! Append-only edge storage for audit compliance, air-gapped plants
//! and telemetry logging: every event becomes one record (ndjson, raw
//! or CSV), the active segment rotates by size and/or age, rotated
//! segments optionally gzip, and retention prunes by count and/or age.
//! Rotation and retention decisions live in the sink and run on
//! synthetic timestamps in tests; only [`FileDiskLogWriter`] touches
//! real disks (tokio::fs), while [`MemoryDiskLogWriter`] keeps virtual
//! segments entirely in memory.

use async_trait::async_trait;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use flate2::write::GzEncoder;
use flate2::Compression as GzCompression;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use super::{now_millis, rfc3339_millis, ConnectorError, Result, Sink};

/// On-disk record encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DiskLogFormat {
    /// `{"timestamp":ms,"topic":..,"qos":n,"payload":json|string}` + LF.
    #[default]
    Ndjson,
    /// Raw payload bytes + LF (binary-safe).
    Raw,
    /// `timestamp,"topic",qos,"payload"` with RFC 4180 quoting + LF.
    Csv,
}

/// Rotated-segment compression.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DiskLogCompression {
    /// Keep rotated segments as-is.
    #[default]
    None,
    /// Compress rotated segments to `<name>.gz` (RFC 1952 gzip).
    Gzip,
}

/// Durability contract for the active segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase", tag = "mode")]
pub enum DiskSyncMode {
    /// `flush()` after every record (audit-safe, slowest).
    #[default]
    EveryBatch,
    /// `flush()` at most every `ms` milliseconds.
    Interval { ms: u64 },
    /// Never flush explicitly (OS page cache decides).
    OsDefault,
}

fn default_prefix() -> String {
    "indra".to_string()
}

fn default_extension() -> String {
    "log".to_string()
}

/// Disk log configuration. Rotation/retention bounds are optional:
/// `None` (or 0) disables that axis entirely — unbounded by default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskLogSinkConfig {
    /// Output directory (created on open for file writers).
    pub directory: String,
    /// Active segment name is `<prefix>.<extension>` (defaults
    /// `indra` / `log`).
    #[serde(default = "default_prefix")]
    pub filename_prefix: String,
    #[serde(default = "default_extension")]
    pub filename_extension: String,
    /// Record encoding (default ndjson).
    #[serde(default)]
    pub format: DiskLogFormat,
    /// Rotate when the active segment would exceed this many bytes
    /// (`None`/0 disables size rotation).
    #[serde(default)]
    pub max_file_size_bytes: Option<u64>,
    /// Rotate when the active segment is older than this many seconds
    /// (`None`/0 disables age rotation).
    #[serde(default)]
    pub max_file_age_secs: Option<u64>,
    /// Compress rotated segments (default none).
    #[serde(default)]
    pub compression: DiskLogCompression,
    /// Keep up to N rotated segments, pruning oldest (`None`/0 keeps all).
    #[serde(default)]
    pub max_backup_files: Option<usize>,
    /// Purge rotated segments older than N days (`None`/0 keeps all).
    #[serde(default)]
    pub max_retention_days: Option<u32>,
    /// Durability contract (default every batch).
    #[serde(default)]
    pub sync_mode: DiskSyncMode,
}

impl DiskLogSinkConfig {
    pub fn validate(&self) -> Result<()> {
        if self.directory.trim().is_empty() {
            return Err(ConnectorError::Dispatch(
                "disk log directory must not be empty".to_string(),
            ));
        }
        if self.filename_prefix.trim().is_empty() || self.filename_prefix.contains('/') || self.filename_prefix.contains('\\') {
            return Err(ConnectorError::Dispatch(format!(
                "disk log filename_prefix must be a bare name: {:?}",
                self.filename_prefix
            )));
        }
        if self.filename_extension.trim().is_empty()
            || self.filename_extension.contains('/')
            || self.filename_extension.contains('.')
        {
            return Err(ConnectorError::Dispatch(format!(
                "disk log filename_extension must be a bare extension: {:?}",
                self.filename_extension
            )));
        }
        if let DiskSyncMode::Interval { ms } = self.sync_mode {
            if ms == 0 {
                return Err(ConnectorError::Dispatch(
                    "disk log sync interval must be >= 1ms".to_string(),
                ));
            }
        }
        Ok(())
    }

    pub fn active_name(&self) -> String {
        format!("{}.{}", self.filename_prefix, self.filename_extension)
    }

    pub fn size_rotation_enabled(&self) -> bool {
        self.max_file_size_bytes.unwrap_or(0) > 0
    }

    pub fn age_rotation_enabled(&self) -> bool {
        self.max_file_age_secs.unwrap_or(0) > 0
    }

    pub fn backup_cap(&self) -> Option<usize> {
        match self.max_backup_files.unwrap_or(0) {
            0 => None,
            n => Some(n),
        }
    }

    pub fn retention_ms(&self) -> Option<i64> {
        match self.max_retention_days.unwrap_or(0) {
            0 => None,
            days => Some(i64::from(days).saturating_mul(86_400_000)),
        }
    }
}

/// One rotated segment known to a writer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupInfo {
    pub name: String,
    pub created_ms: i64,
}

#[async_trait]
pub trait DiskLogWriter: Send + Sync {
    /// Append one record (with its trailing newline) to the active segment.
    async fn write_record(&self, record: &[u8]) -> Result<()>;
    /// Rotate the active segment (no-op returning `None` when empty).
    /// Returns the backup name created.
    async fn rotate(&self) -> Result<Option<String>>;
    /// Persist the active segment per the durability contract.
    async fn flush(&self) -> Result<()>;
    /// List rotated segments, oldest first.
    async fn list_backups(&self) -> Result<Vec<BackupInfo>>;
    /// Delete one rotated segment by name (retention pruning).
    async fn delete_backup(&self, name: &str) -> Result<()>;
}

/// Virtual segment for the in-memory writer.
#[derive(Debug, Clone)]
struct MemorySegment {
    name: String,
    data: Vec<u8>,
    created_ms: i64,
}

struct MemoryState {
    current: Vec<u8>,
    current_created_ms: Option<i64>,
    backups: Vec<MemorySegment>,
    next_index: u64,
    flushes: u64,
}

/// In-memory writer: virtual segments and rotated files only.
pub struct MemoryDiskLogWriter {
    prefix: String,
    extension: String,
    compression: DiskLogCompression,
    state: parking_lot::Mutex<MemoryState>,
}

impl MemoryDiskLogWriter {
    pub fn new(config: &DiskLogSinkConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            prefix: config.filename_prefix.clone(),
            extension: config.filename_extension.clone(),
            compression: config.compression,
            state: parking_lot::Mutex::new(MemoryState {
                current: Vec::new(),
                current_created_ms: None,
                backups: Vec::new(),
                next_index: 1,
                flushes: 0,
            }),
        })
    }

    /// Active segment bytes (test inspection).
    pub fn current_bytes(&self) -> Vec<u8> {
        self.state.lock().current.clone()
    }

    /// Rotated segments oldest-first with raw (possibly gzipped) bytes.
    pub fn backup_blobs(&self) -> Vec<(String, Vec<u8>)> {
        self.state
            .lock()
            .backups
            .iter()
            .map(|segment| (segment.name.clone(), segment.data.clone()))
            .collect()
    }

    pub fn flush_count(&self) -> u64 {
        self.state.lock().flushes
    }

    fn backup_name(&self, index: u64) -> String {
        let mut name = format!("{}.{}.{index}", self.prefix, self.extension);
        if self.compression == DiskLogCompression::Gzip {
            name.push_str(".gz");
        }
        name
    }
}

#[async_trait]
impl DiskLogWriter for MemoryDiskLogWriter {
    async fn write_record(&self, record: &[u8]) -> Result<()> {
        let mut state = self.state.lock();
        if state.current_created_ms.is_none() {
            state.current_created_ms = Some(now_millis());
        }
        state.current.extend_from_slice(record);
        Ok(())
    }

    async fn rotate(&self) -> Result<Option<String>> {
        let mut state = self.state.lock();
        if state.current.is_empty() {
            return Ok(None);
        }
        let raw = std::mem::take(&mut state.current);
        let created = state.current_created_ms.take().unwrap_or_else(now_millis);
        let data = match self.compression {
            DiskLogCompression::None => raw,
            DiskLogCompression::Gzip => {
                let mut encoder = GzEncoder::new(Vec::new(), GzCompression::default());
                encoder.write_all(&raw).map_err(|e| {
                    ConnectorError::Dispatch(format!("disk log gzip failed: {e}"))
                })?;
                encoder.finish().map_err(|e| {
                    ConnectorError::Dispatch(format!("disk log gzip failed: {e}"))
                })?
            }
        };
        let name = self.backup_name(state.next_index);
        state.next_index += 1;
        state.backups.push(MemorySegment {
            name: name.clone(),
            data,
            created_ms: created,
        });
        Ok(Some(name))
    }

    async fn flush(&self) -> Result<()> {
        self.state.lock().flushes += 1;
        Ok(())
    }

    async fn list_backups(&self) -> Result<Vec<BackupInfo>> {
        Ok(self
            .state
            .lock()
            .backups
            .iter()
            .map(|segment| BackupInfo {
                name: segment.name.clone(),
                created_ms: segment.created_ms,
            })
            .collect())
    }

    async fn delete_backup(&self, name: &str) -> Result<()> {
        let mut state = self.state.lock();
        let before = state.backups.len();
        state.backups.retain(|segment| segment.name != name);
        if state.backups.len() == before {
            return Err(ConnectorError::Dispatch(format!(
                "disk log backup not found: {name:?}"
            )));
        }
        Ok(())
    }
}

/// Production writer over `tokio::fs`: `<dir>/<prefix>.<ext>` active
/// segment, numbered `<dir>/<prefix>.<ext>.<N>[.gz]` backups.
pub struct FileDiskLogWriter {
    dir: PathBuf,
    prefix: String,
    extension: String,
    compression: DiskLogCompression,
    file: tokio::sync::Mutex<tokio::fs::File>,
    next_index: parking_lot::Mutex<u64>,
}

impl FileDiskLogWriter {
    pub async fn open(config: &DiskLogSinkConfig) -> Result<Self> {
        config.validate()?;
        tokio::fs::create_dir_all(&config.directory)
            .await
            .map_err(|e| ConnectorError::Connection(format!("disk log mkdir failed: {e}")))?;
        let dir = PathBuf::from(&config.directory);
        let active = dir.join(config.active_name());
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&active)
            .await
            .map_err(|e| ConnectorError::Connection(format!("disk log open failed: {e}")))?;
        // Resume numbering past existing backups.
        let mut next_index = 1u64;
        if let Ok(mut entries) = tokio::fs::read_dir(&dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let name = entry.file_name().to_string_lossy().into_owned();
                if let Some(index) = backup_index(&config.filename_prefix, &config.filename_extension, &name) {
                    next_index = next_index.max(index + 1);
                }
            }
        }
        Ok(Self {
            dir,
            prefix: config.filename_prefix.clone(),
            extension: config.filename_extension.clone(),
            compression: config.compression,
            file: tokio::sync::Mutex::new(file),
            next_index: parking_lot::Mutex::new(next_index),
        })
    }

    fn backup_path(&self, index: u64) -> PathBuf {
        let mut name = format!("{}.{}.{index}", self.prefix, self.extension);
        if self.compression == DiskLogCompression::Gzip {
            name.push_str(".gz");
        }
        self.dir.join(name)
    }

    fn active_path(&self) -> PathBuf {
        self.dir.join(format!("{}.{}", self.prefix, self.extension))
    }
}

/// Parse the numeric index from `<prefix>.<ext>.<N>[.gz]`, if shaped so.
fn backup_index(prefix: &str, extension: &str, name: &str) -> Option<u64> {
    let stem = format!("{prefix}.{extension}.");
    let rest = name.strip_prefix(&stem)?;
    let rest = rest.strip_suffix(".gz").unwrap_or(rest);
    rest.parse::<u64>().ok()
}

#[async_trait]
impl DiskLogWriter for FileDiskLogWriter {
    async fn write_record(&self, record: &[u8]) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        self.file
            .lock()
            .await
            .write_all(record)
            .await
            .map_err(|e| ConnectorError::Connection(format!("disk log write failed: {e}")))?;
        Ok(())
    }

    async fn rotate(&self) -> Result<Option<String>> {
        use tokio::io::AsyncWriteExt;
        let mut file = self.file.lock().await;
        file.flush()
            .await
            .map_err(|e| ConnectorError::Connection(format!("disk log flush failed: {e}")))?;
        drop(file);
        let active = self.active_path();
        let meta = tokio::fs::metadata(&active)
            .await
            .map_err(|e| ConnectorError::Connection(format!("disk log stat failed: {e}")))?;
        if meta.len() == 0 {
            // Reopen (rotate is also the startup path) and report empty.
            let reopened = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&active)
                .await
                .map_err(|e| ConnectorError::Connection(format!("disk log reopen failed: {e}")))?;
            *self.file.lock().await = reopened;
            return Ok(None);
        }
        let index = {
            let mut next = self.next_index.lock();
            let index = *next;
            *next += 1;
            index
        };
        let mut name = format!("{}.{}.{index}", self.prefix, self.extension);
        let staged = self.dir.join(&name);
        tokio::fs::rename(&active, &staged)
            .await
            .map_err(|e| ConnectorError::Connection(format!("disk log rotate failed: {e}")))?;
        if self.compression == DiskLogCompression::Gzip {
            let raw = tokio::fs::read(&staged)
                .await
                .map_err(|e| ConnectorError::Connection(format!("disk log read failed: {e}")))?;
            let mut encoder = GzEncoder::new(Vec::new(), GzCompression::default());
            encoder.write_all(&raw).map_err(|e| {
                ConnectorError::Dispatch(format!("disk log gzip failed: {e}"))
            })?;
            let gzipped = encoder.finish().map_err(|e| {
                ConnectorError::Dispatch(format!("disk log gzip failed: {e}"))
            })?;
            let dest = self.backup_path(index);
            tokio::fs::write(&dest, gzipped)
                .await
                .map_err(|e| ConnectorError::Connection(format!("disk log gzip write failed: {e}")))?;
            tokio::fs::remove_file(&staged)
                .await
                .map_err(|e| ConnectorError::Connection(format!("disk log cleanup failed: {e}")))?;
            name = dest
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or(name);
        }
        let reopened = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&active)
            .await
            .map_err(|e| ConnectorError::Connection(format!("disk log reopen failed: {e}")))?;
        *self.file.lock().await = reopened;
        Ok(Some(name))
    }

    async fn flush(&self) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        let mut file = self.file.lock().await;
        file.flush()
            .await
            .map_err(|e| ConnectorError::Connection(format!("disk log flush failed: {e}")))?;
        file.sync_all()
            .await
            .map_err(|e| ConnectorError::Connection(format!("disk log sync failed: {e}")))?;
        Ok(())
    }

    async fn list_backups(&self) -> Result<Vec<BackupInfo>> {
        let mut backups = Vec::new();
        let mut entries = tokio::fs::read_dir(&self.dir)
            .await
            .map_err(|e| ConnectorError::Connection(format!("disk log scan failed: {e}")))?;
        while let Ok(Some(entry)) = entries.next_entry().await {
            let name = entry.file_name().to_string_lossy().into_owned();
            if backup_index(&self.prefix, &self.extension, &name).is_none() {
                continue;
            }
            let created_ms = entry
                .metadata()
                .await
                .ok()
                .and_then(|meta| meta.modified().ok())
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|elapsed| elapsed.as_millis().min(i64::MAX as u128) as i64)
                .unwrap_or(0);
            backups.push(BackupInfo { name, created_ms });
        }
        backups.sort_by(|a, b| a.created_ms.cmp(&b.created_ms).then(a.name.cmp(&b.name)));
        Ok(backups)
    }

    async fn delete_backup(&self, name: &str) -> Result<()> {
        if backup_index(&self.prefix, &self.extension, name).is_none() {
            return Err(ConnectorError::Dispatch(format!(
                "disk log refusing to delete non-backup: {name:?}"
            )));
        }
        tokio::fs::remove_file(self.dir.join(name))
            .await
            .map_err(|e| ConnectorError::Connection(format!("disk log delete failed: {e}")))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Record formatting.
// ---------------------------------------------------------------------------

/// Render one record (without timestamp injection for Raw).
fn format_record(format: DiskLogFormat, topic: &Topic, payload: &[u8], qos: QoS, millis: i64) -> Result<Vec<u8>> {
    match format {
        DiskLogFormat::Raw => {
            let mut record = payload.to_vec();
            record.push(b'\n');
            Ok(record)
        }
        DiskLogFormat::Ndjson => {
            let text = std::str::from_utf8(payload).map_err(|_| {
                ConnectorError::Dispatch("disk log ndjson payload must be UTF-8".to_string())
            })?;
            let value: serde_json::Value = serde_json::from_str(text)
                .unwrap_or_else(|_| serde_json::Value::String(text.to_string()));
            let mut record = serde_json::to_vec(&serde_json::json!({
                "timestamp": millis,
                "topic": topic.as_str(),
                "qos": u8::from(qos),
                "payload": value,
            }))
            .map_err(|e| ConnectorError::Dispatch(format!("disk log encode failed: {e}")))?;
            record.push(b'\n');
            Ok(record)
        }
        DiskLogFormat::Csv => {
            let text = std::str::from_utf8(payload).map_err(|_| {
                ConnectorError::Dispatch("disk log csv payload must be UTF-8".to_string())
            })?;
            Ok(format!(
                "{},\"{}\",{},\"{}\"\n",
                rfc3339_millis(millis),
                csv_escape(topic.as_str()),
                u8::from(qos),
                csv_escape(text),
            )
            .into_bytes())
        }
    }
}

/// RFC 4180 field escaping: `"` doubles; the caller wraps in quotes.
fn csv_escape(value: &str) -> String {
    value.replace('"', "\"\"")
}

// ---------------------------------------------------------------------------
// Sink.
// ---------------------------------------------------------------------------

struct DiskLogState {
    current_bytes: u64,
    current_created_ms: Option<i64>,
    backups: Vec<BackupInfo>,
    last_sync_ms: i64,
}

/// Rotating disk log sink: write-through records with rotation and
/// retention. Rotation checks run per record against the provided
/// timestamp, so tests drive time synthetically.
pub struct DiskLogSink {
    config: DiskLogSinkConfig,
    writer: Arc<dyn DiskLogWriter>,
    state: parking_lot::Mutex<DiskLogState>,
    written_records: AtomicU64,
    rotations: AtomicU64,
}

impl DiskLogSink {
    pub fn new(config: DiskLogSinkConfig, writer: Arc<dyn DiskLogWriter>) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            writer,
            state: parking_lot::Mutex::new(DiskLogState {
                current_bytes: 0,
                current_created_ms: None,
                backups: Vec::new(),
                last_sync_ms: 0,
            }),
            written_records: AtomicU64::new(0),
            rotations: AtomicU64::new(0),
        })
    }

    pub fn config(&self) -> &DiskLogSinkConfig {
        &self.config
    }

    pub fn written_records(&self) -> u64 {
        self.written_records.load(Ordering::Relaxed)
    }

    pub fn rotation_count(&self) -> u64 {
        self.rotations.load(Ordering::Relaxed)
    }

    pub fn current_bytes(&self) -> u64 {
        self.state.lock().current_bytes
    }

    pub fn backup_names(&self) -> Vec<String> {
        self.state.lock().backups.iter().map(|backup| backup.name.clone()).collect()
    }

    /// Rotate when the size or age policy trips at `now_ms`, then
    /// enforce count/age retention. Returns true when a rotation ran.
    pub async fn maybe_rotate_at(&self, now_ms: i64) -> Result<bool> {
        let (size_trip, age_trip) = {
            let state = self.state.lock();
            let size_trip = match self.config.max_file_size_bytes.unwrap_or(0) {
                0 => false,
                max => state.current_bytes >= max,
            };
            let age_trip = match self.config.max_file_age_secs.unwrap_or(0) {
                0 => false,
                max_secs => {
                    let max_ms = i64::try_from(max_secs).unwrap_or(i64::MAX).saturating_mul(1_000);
                    state
                        .current_created_ms
                        .is_some_and(|created| now_ms.saturating_sub(created) >= max_ms)
                }
            };
            (size_trip, age_trip)
        };
        if !(size_trip || age_trip) {
            return Ok(false);
        }
        // Would-rotate bookkeeping uses the segment start for the
        // backup timestamp.
        let created = self.state.lock().current_created_ms.unwrap_or(now_ms);
        if let Some(name) = self.writer.rotate().await? {
            let mut state = self.state.lock();
            state.backups.push(BackupInfo { name, created_ms: created });
            state.current_bytes = 0;
            state.current_created_ms = None;
            self.rotations.fetch_add(1, Ordering::Relaxed);
        }
        self.enforce_retention_at(now_ms).await?;
        Ok(true)
    }

    /// Prune backups past the count cap (oldest first) and past the
    /// retention age, oldest first.
    pub async fn enforce_retention_at(&self, now_ms: i64) -> Result<()> {
        let mut prune: Vec<String> = Vec::new();
        {
            let state = self.state.lock();
            if let Some(cap) = self.config.backup_cap() {
                if state.backups.len() > cap {
                    prune.extend(
                        state.backups[..state.backups.len() - cap]
                            .iter()
                            .map(|backup| backup.name.clone()),
                    );
                }
            }
            if let Some(retention_ms) = self.config.retention_ms() {
                prune.extend(
                    state
                        .backups
                        .iter()
                        .filter(|backup| now_ms.saturating_sub(backup.created_ms) > retention_ms)
                        .map(|backup| backup.name.clone()),
                );
            }
        }
        prune.sort();
        prune.dedup();
        for name in prune {
            self.writer.delete_backup(&name).await?;
            self.state.lock().backups.retain(|backup| backup.name != name);
        }
        Ok(())
    }

    /// Append one formatted record, rotating first when due and
    /// syncing per the durability contract.
    pub async fn append_at(
        &self,
        topic: &Topic,
        payload: &Bytes,
        qos: QoS,
        millis: i64,
    ) -> Result<()> {
        if topic.as_str().is_empty() {
            return Err(ConnectorError::Dispatch(
                "disk log row requires a non-empty topic".to_string(),
            ));
        }
        let record = format_record(self.config.format, topic, payload, qos, millis)?;
        // Size rotation looks ahead: rotate *before* the write that
        // would overflow the segment.
        let would_overflow = {
            let state = self.state.lock();
            match self.config.max_file_size_bytes.unwrap_or(0) {
                0 => false,
                max => state.current_bytes + record.len() as u64 > max && state.current_bytes > 0,
            }
        };
        if would_overflow {
            let created = self.state.lock().current_created_ms.unwrap_or(millis);
            if let Some(name) = self.writer.rotate().await? {
                let mut state = self.state.lock();
                state.backups.push(BackupInfo { name, created_ms: created });
                state.current_bytes = 0;
                state.current_created_ms = None;
                self.rotations.fetch_add(1, Ordering::Relaxed);
            }
            self.enforce_retention_at(millis).await?;
        } else {
            self.maybe_rotate_at(millis).await?;
        }
        self.writer.write_record(&record).await?;
        {
            let mut state = self.state.lock();
            if state.current_created_ms.is_none() {
                state.current_created_ms = Some(millis);
            }
            state.current_bytes += record.len() as u64;
        }
        self.written_records.fetch_add(1, Ordering::Relaxed);
        match self.config.sync_mode {
            DiskSyncMode::EveryBatch => self.writer.flush().await?,
            DiskSyncMode::Interval { ms } => {
                let due = {
                    let state = self.state.lock();
                    millis.saturating_sub(state.last_sync_ms) >= ms as i64
                };
                if due {
                    self.writer.flush().await?;
                    self.state.lock().last_sync_ms = millis;
                }
            }
            DiskSyncMode::OsDefault => {}
        }
        Ok(())
    }

    pub async fn flush(&self) -> Result<()> {
        self.writer.flush().await
    }
}

#[async_trait]
impl Sink for DiskLogSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        self.append_at(topic, payload, qos, now_millis()).await
    }

    fn kind(&self) -> &'static str {
        "disk_log"
    }
}

/// Management connector handle pairing an id with a disk log sink.
pub struct DiskLogConnector {
    id: String,
    sink: Arc<DiskLogSink>,
}

impl DiskLogConnector {
    pub fn new(id: impl Into<String>, sink: Arc<DiskLogSink>) -> Self {
        Self {
            id: id.into(),
            sink,
        }
    }
}

impl super::Connector for DiskLogConnector {
    fn connector_id(&self) -> &str {
        &self.id
    }

    fn kind(&self) -> &'static str {
        self.sink.kind()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::GzDecoder;
    use std::io::Read;

    fn test_config() -> DiskLogSinkConfig {
        DiskLogSinkConfig {
            directory: "memory://edge-logs".to_string(),
            filename_prefix: "telemetry".to_string(),
            filename_extension: "log".to_string(),
            format: DiskLogFormat::Ndjson,
            max_file_size_bytes: None,
            max_file_age_secs: None,
            compression: DiskLogCompression::None,
            max_backup_files: None,
            max_retention_days: None,
            sync_mode: DiskSyncMode::EveryBatch,
        }
    }

    fn test_sink(config: DiskLogSinkConfig) -> (Arc<DiskLogSink>, Arc<MemoryDiskLogWriter>) {
        let writer = Arc::new(MemoryDiskLogWriter::new(&config).unwrap());
        let sink = Arc::new(DiskLogSink::new(config, writer.clone()).unwrap());
        (sink, writer)
    }

    fn gunzip(data: &[u8]) -> Vec<u8> {
        let mut decoder = GzDecoder::new(data);
        let mut back = Vec::new();
        decoder.read_to_end(&mut back).unwrap();
        back
    }

    #[test]
    fn test_config_validation() {
        let mut config = test_config();
        assert!(config.validate().is_ok());
        assert_eq!(config.active_name(), "telemetry.log");

        config.directory.clear();
        assert!(config.validate().is_err());
        config.directory = "memory://edge-logs".to_string();

        config.filename_prefix = "a/b".to_string();
        assert!(config.validate().is_err());
        config.filename_prefix = "telemetry".to_string();

        config.filename_extension = "l.g".to_string();
        assert!(config.validate().is_err());
        config.filename_extension = "log".to_string();

        config.sync_mode = DiskSyncMode::Interval { ms: 0 };
        assert!(config.validate().is_err());
        // Disabled axes and huge caps accepted: zero clamped ceilings.
        config.sync_mode = DiskSyncMode::OsDefault;
        config.max_file_size_bytes = None;
        config.max_backup_files = Some(10_000_000);
        config.max_retention_days = None;
        assert!(config.validate().is_ok());
    }

    #[tokio::test]
    async fn test_ndjson_formatting() {
        let (sink, writer) = test_sink(test_config());
        sink.append_at(
            &Topic::new("sensors/t1").unwrap(),
            &Bytes::from(r#"{"v":1}"#),
            QoS::AtLeastOnce,
            1_789_211_889_123,
        )
        .await
        .unwrap();
        let current = String::from_utf8(writer.current_bytes()).unwrap();
        assert!(current.ends_with('\n'));
        let row: serde_json::Value = serde_json::from_str(current.trim_end()).unwrap();
        assert_eq!(row["timestamp"], 1_789_211_889_123i64);
        assert_eq!(row["topic"], "sensors/t1");
        assert_eq!(row["qos"], 1);
        assert_eq!(row["payload"], serde_json::json!({"v": 1}));
        assert_eq!(sink.written_records(), 1);
        assert_eq!(writer.flush_count(), 1);
    }

    #[tokio::test]
    async fn test_raw_and_csv_formatting() {
        // Raw is binary-safe: non-UTF8 payloads pass through + newline.
        let mut config = test_config();
        config.format = DiskLogFormat::Raw;
        let (sink, writer) = test_sink(config);
        sink.append_at(
            &Topic::new("t").unwrap(),
            &Bytes::from(vec![0xFF, 0xFE, 0x00]),
            QoS::AtMostOnce,
            0,
        )
        .await
        .unwrap();
        assert_eq!(writer.current_bytes(), vec![0xFF, 0xFE, 0x00, b'\n']);

        // CSV quotes fields and doubles embedded quotes.
        let mut config = test_config();
        config.format = DiskLogFormat::Csv;
        let (sink, writer) = test_sink(config);
        sink.append_at(
            &Topic::new("sensors/t1").unwrap(),
            &Bytes::from(r#"say "hi", ok"#),
            QoS::AtLeastOnce,
            1_789_211_889_123,
        )
        .await
        .unwrap();
        assert_eq!(
            String::from_utf8(writer.current_bytes()).unwrap(),
            "2026-09-12T11:18:09.123Z,\"sensors/t1\",1,\"say \"\"hi\"\", ok\"\n"
        );

        // Ndjson rejects non-UTF8 (raw exists for binary).
        let (sink, _) = test_sink(test_config());
        assert!(sink
            .append_at(&Topic::new("t").unwrap(), &Bytes::from(vec![0xFF]), QoS::AtMostOnce, 0)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_size_rotation_segments() {
        let mut config = test_config();
        config.max_file_size_bytes = Some(60);
        let (sink, writer) = test_sink(config);
        let topic = Topic::new("t").unwrap();
        for v in [1, 2, 3] {
            sink.append_at(&topic, &Bytes::from(format!("{{\"v\":{v}}}")), QoS::AtMostOnce, 1_000)
                .await
                .unwrap();
        }
        // Each ~50-byte row overflows the 60-byte segment: 2 rotations.
        assert_eq!(sink.rotation_count(), 2);
        assert_eq!(sink.backup_names(), vec!["telemetry.log.1", "telemetry.log.2"]);
        assert_eq!(writer.backup_blobs().len(), 2);
        let current = String::from_utf8(writer.current_bytes()).unwrap();
        assert_eq!(current.lines().count(), 1);
    }

    #[tokio::test]
    async fn test_gzip_rotation_magic_and_roundtrip() {
        let mut config = test_config();
        config.compression = DiskLogCompression::Gzip;
        config.max_file_size_bytes = Some(10);
        let (sink, writer) = test_sink(config);
        let topic = Topic::new("t").unwrap();
        sink.append_at(&topic, &Bytes::from("{}"), QoS::AtMostOnce, 1_000).await.unwrap();
        sink.append_at(&topic, &Bytes::from("{}"), QoS::AtMostOnce, 1_000).await.unwrap();
        assert_eq!(sink.rotation_count(), 1);
        let blobs = writer.backup_blobs();
        assert_eq!(blobs.len(), 1);
        assert_eq!(blobs[0].0, "telemetry.log.1.gz");
        assert_eq!(&blobs[0].1[..2], &[0x1f, 0x8b], "gzip magic");
        let back = String::from_utf8(gunzip(&blobs[0].1)).unwrap();
        assert_eq!(back.lines().count(), 1);
        let row: serde_json::Value = serde_json::from_str(back.trim_end()).unwrap();
        assert_eq!(row["topic"], "t");
    }

    #[tokio::test]
    async fn test_age_rotation_and_retention_days() {
        let mut config = test_config();
        config.max_file_age_secs = Some(60);
        config.max_retention_days = Some(1);
        let (sink, writer) = test_sink(config);
        let topic = Topic::new("t").unwrap();
        // Segment born at t=0; a write at t=61s rotates by age.
        sink.append_at(&topic, &Bytes::from("{}"), QoS::AtMostOnce, 0).await.unwrap();
        assert_eq!(sink.rotation_count(), 0);
        sink.append_at(&topic, &Bytes::from("{}"), QoS::AtMostOnce, 61_000).await.unwrap();
        assert_eq!(sink.rotation_count(), 1);
        assert_eq!(writer.backup_blobs().len(), 1);
        // A write at t=122s rotates again; both backups stay in retention.
        sink.append_at(&topic, &Bytes::from("{}"), QoS::AtMostOnce, 122_000).await.unwrap();
        assert_eq!(sink.rotation_count(), 2);
        assert_eq!(writer.backup_blobs().len(), 2);
        // A later write rotates once more and purges the two backups
        // older than a day while the fresh one survives.
        sink.append_at(&topic, &Bytes::from("{}"), QoS::AtMostOnce, 86_500_000)
            .await
            .unwrap();
        assert_eq!(sink.rotation_count(), 3);
        assert_eq!(writer.backup_blobs().len(), 1);
        assert_eq!(sink.backup_names().len(), 1);
    }

    #[tokio::test]
    async fn test_backup_count_retention_prunes_oldest() {
        let mut config = test_config();
        config.max_file_size_bytes = Some(10);
        config.max_backup_files = Some(2);
        let (sink, writer) = test_sink(config);
        let topic = Topic::new("t").unwrap();
        for _ in 0..4 {
            sink.append_at(&topic, &Bytes::from("{}"), QoS::AtMostOnce, 1_000).await.unwrap();
        }
        assert_eq!(sink.rotation_count(), 3);
        assert_eq!(sink.backup_names(), vec!["telemetry.log.2", "telemetry.log.3"]);
        assert_eq!(writer.backup_blobs().len(), 2);
    }

    #[tokio::test]
    async fn test_sync_modes() {
        // Interval: first write syncs (last_sync 0), then quiet, then due.
        let mut config = test_config();
        config.sync_mode = DiskSyncMode::Interval { ms: 1_000 };
        let (sink, writer) = test_sink(config);
        let topic = Topic::new("t").unwrap();
        sink.append_at(&topic, &Bytes::from("{}"), QoS::AtMostOnce, 0).await.unwrap();
        assert_eq!(writer.flush_count(), 0);
        sink.append_at(&topic, &Bytes::from("{}"), QoS::AtMostOnce, 500).await.unwrap();
        assert_eq!(writer.flush_count(), 0);
        sink.append_at(&topic, &Bytes::from("{}"), QoS::AtMostOnce, 1_000).await.unwrap();
        assert_eq!(writer.flush_count(), 1);

        // OsDefault never syncs explicitly.
        let mut config = test_config();
        config.sync_mode = DiskSyncMode::OsDefault;
        let (sink, writer) = test_sink(config);
        sink.append_at(&topic, &Bytes::from("{}"), QoS::AtMostOnce, 0).await.unwrap();
        assert_eq!(writer.flush_count(), 0);
    }
}
