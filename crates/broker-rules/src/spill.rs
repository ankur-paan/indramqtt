//! Bounded on-disk spill buffer behind [`BackpressurePolicy::SpillToDisk`](super::BackpressurePolicy).
//!
//! The in-memory rule ingress queue is small by design. When it fills,
//! the spill policy appends further rule-ingress events to segment files
//! in a dedicated directory instead of returning an overflow error, and
//! the consumer replays them in order once the pressure eases. A fresh
//! engine opened on the same directory recovers whatever survived.
//!
//! # Durability contract (read this before relying on it)
//!
//! - Every acknowledged spill (`Ok`) is `write + flush`ed to the OS
//!   before the sequence number returns. A **process crash loses
//!   nothing** acknowledged: the page cache survives the process.
//! - There is **no `fsync` on the spill path**, so a power loss can lose
//!   the tail still in the page cache. The active segment is synced on
//!   rotation and on [`SpillLog::sync`]; the at-risk window is therefore
//!   bounded by the segment fill time, not by the process lifetime.
//! - The trade-off is deliberate: one `fsync` per append costs on the
//!   order of 0.1-1 ms and would cap a single input at roughly 1k-10k
//!   spills/s while stalling the rule-ingress caller. Page-cache appends
//!   cost microseconds and never stall on disk.
//! - Delivery across a crash is **at-least-once**: a segment is deleted
//!   only after every frame in it has been replayed, so events replayed
//!   just before a crash replay again after recovery. Within one run
//!   delivery is exactly-once.
//! - One engine owns one spill directory. Two engines appending to the
//!   same directory interleave frames; recovery still discards torn
//!   tails, but ordering across the two writers is undefined.
//!
//! # File layout
//!
//! `<dir>/spill-00000001.log`, `spill-00000002.log`, ... Each frame is
//! `[magic u32 BE][body_len u32 BE][body][body_len u32 BE trailer]`.
//! The trailer duplicates the length so a torn write is detected even
//! when the length prefix itself survived. Recovery scans segments in
//! order; the first truncated frame, magic/length/trailer mismatch, or
//! undecodable body truncates that file at the last good frame, counts
//! one torn tail, and deletes every later segment (frames written after
//! a torn write cannot be trusted to be ordered or complete).
//!
//! # Bounds (every default stated with its reason)
//!
//! - [`DEFAULT_SPILL_SEGMENT_MAX_BYTES`] (1 MiB): a segment holds on the
//!   order of seven hundred typical 1.5 KB rule events, so rotation is
//!   rare at normal overflow rates, while a single file stays small
//!   enough that recovery scans and torn-tail loss are bounded to ~1 MB.
//! - [`DEFAULT_SPILL_MAX_BYTES`] (64 MiB): caps one input's disk use at
//!   roughly forty-five thousand typical events, enough to ride out a
//!   multi-second full-memory stall at high ingress without risking the
//!   host disk this project once filled.
//! - One event larger than the segment size is refused (counted drop,
//!   overflow error): it could never rotate cleanly and would pin the
//!   writer on a single unflushable segment.

use broker_protocol::Topic;
use bytes::Bytes;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use super::StreamEvent;

/// Frame magic identifying our segment files (`RSPL` in ASCII). A file
/// that does not start with it at the read cursor is treated as torn
/// from the cursor on, never as data.
const FRAME_MAGIC: u32 = 0x5253_504C;

/// Default segment roll threshold: 1 MiB. Reason: see the module docs.
pub const DEFAULT_SPILL_SEGMENT_MAX_BYTES: u64 = 1024 * 1024;
/// Default per-input disk cap: 64 MiB. Reason: see the module docs.
pub const DEFAULT_SPILL_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Longest topic accepted from a segment file: the protocol's UTF-8
/// topic limit. Bounds allocation on a corrupt length prefix.
const MAX_TOPIC_BYTES: usize = 65_535;
/// Largest payload accepted from a segment file: the protocol's
/// remaining-length cap. Bounds allocation on a corrupt length prefix.
const MAX_PAYLOAD_BYTES: usize = 268_435_456;
/// Longest client id accepted from a segment file. Client ids are
/// short strings in practice; the protocol allows far more, so this
/// generous cap only stops corrupt lengths from allocating.
const MAX_CLIENT_ID_BYTES: usize = 65_535;
/// Largest single frame body accepted on decode. Covers the largest
/// legal payload plus topic and headers while bounding allocation.
const MAX_FRAME_BODY_BYTES: usize = 270_000_000;

/// Segment file name prefix and suffix. Files not matching
/// `spill-<8 digits>.log` are foreign: ignored with a warning, never
/// read, truncated or deleted.
const SEGMENT_PREFIX: &str = "spill-";
const SEGMENT_SUFFIX: &str = ".log";

/// Segment and size policy for one spill directory.
#[derive(Debug, Clone)]
pub struct SpillConfig {
    /// Dedicated directory holding this input's segment files. Created
    /// (with parents) on open; must not be shared with another input.
    pub dir: PathBuf,
    /// Roll to a new segment once the active file would exceed this
    /// many bytes. Must be non-zero and at most `max_spill_bytes`
    /// (checked on open: the total must hold at least one segment).
    pub segment_max_bytes: u64,
    /// Cap on all segment bytes in the directory. A spill that would
    /// exceed it is refused (counted drop, overflow error): fail
    /// closed rather than filling the disk.
    pub max_spill_bytes: u64,
}

impl SpillConfig {
    /// Defaults for `dir`: 1 MiB segments under a 64 MiB total cap.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            segment_max_bytes: DEFAULT_SPILL_SEGMENT_MAX_BYTES,
            max_spill_bytes: DEFAULT_SPILL_MAX_BYTES,
        }
    }

    /// Override the segment roll threshold (checked on open).
    pub fn with_segment_max_bytes(mut self, max: u64) -> Self {
        self.segment_max_bytes = max;
        self
    }

    /// Override the total disk cap (checked on open).
    pub fn with_max_spill_bytes(mut self, max: u64) -> Self {
        self.max_spill_bytes = max;
        self
    }

    fn validate(&self) -> io::Result<()> {
        if self.segment_max_bytes == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "spill segment_max_bytes must be non-zero",
            ));
        }
        if self.max_spill_bytes == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "spill max_spill_bytes must be non-zero",
            ));
        }
        if self.segment_max_bytes > self.max_spill_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "spill segment_max_bytes must not exceed max_spill_bytes",
            ));
        }
        Ok(())
    }
}

/// Outcome counts for one spill directory. Plain data: the owner keeps
/// the authoritative atomics and mirrors them into the node metrics.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SpillOutcome {
    /// Events recovered from segment files when the directory opened.
    pub recovered: u64,
    /// Files whose torn tail was truncated (plus later segments
    /// discarded after a torn write).
    pub torn: u64,
}

/// Running outcome counts for one spill-backed input. Plain data
/// snapshot of the owner's atomics.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SpillStats {
    /// Events appended to disk instead of erroring.
    pub spilled: u64,
    /// Spilled events replayed to the consumer, in order.
    pub replayed: u64,
    /// Overflow events refused (no spill directory, oversize event,
    /// disk cap reached, I/O error): fail closed, counted, never
    /// silent.
    pub dropped: u64,
    /// Torn tails truncated plus later segments discarded, on recovery
    /// and on replay.
    pub torn_discarded: u64,
    /// Events found on disk when a directory opened (restart survival).
    pub recovered: u64,
}

/// Encode one rule-ingress event as a frame body (without magic,
/// lengths or trailer). Errors when a field exceeds its decode cap so
/// a corrupt-length allocation can never happen on the read side; the
/// caller counts the refusal as a drop.
fn encode_body(event: &StreamEvent) -> io::Result<Vec<u8>> {
    let topic = event.topic.as_str().as_bytes();
    if topic.len() > MAX_TOPIC_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "spill event topic exceeds 65535 bytes",
        ));
    }
    if event.payload.len() > MAX_PAYLOAD_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "spill event payload exceeds protocol cap",
        ));
    }
    let client = event.client_id.as_deref().unwrap_or("").as_bytes();
    if client.len() > MAX_CLIENT_ID_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "spill event client id exceeds 65535 bytes",
        ));
    }
    let mut body =
        Vec::with_capacity(4 + topic.len() + 4 + event.payload.len() + 8 + 1 + 4 + client.len());
    body.extend_from_slice(&(topic.len() as u32).to_be_bytes());
    body.extend_from_slice(topic);
    body.extend_from_slice(&(event.payload.len() as u32).to_be_bytes());
    body.extend_from_slice(&event.payload);
    body.extend_from_slice(&event.timestamp_millis.to_be_bytes());
    if event.client_id.is_some() {
        body.push(1);
        body.extend_from_slice(&(client.len() as u32).to_be_bytes());
        body.extend_from_slice(client);
    } else {
        body.push(0);
    }
    if body.len() > MAX_FRAME_BODY_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "spill event exceeds maximum frame body",
        ));
    }
    Ok(body)
}

/// Wrap a body in its frame (magic, length, body, length trailer).
fn frame_body(body: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(4 + 4 + body.len() + 4);
    frame.extend_from_slice(&FRAME_MAGIC.to_be_bytes());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(body);
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame
}

fn read_u32_be(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// Decode one frame body into an event. Every length is capped before
/// allocating, so corrupt bytes fail loudly instead of exhausting
/// memory. Invalid topics fail (we only ever write valid ones).
fn decode_body(body: &[u8]) -> io::Result<StreamEvent> {
    let mut cursor = 0usize;
    let take = |cursor: &mut usize, len: usize| -> io::Result<&[u8]> {
        let end = cursor.saturating_add(len);
        if end > body.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "spill frame body truncated",
            ));
        }
        let slice = &body[*cursor..end];
        *cursor = end;
        Ok(slice)
    };
    let topic_len = read_u32_be(take(&mut cursor, 4)?) as usize;
    if topic_len > MAX_TOPIC_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "spill frame topic length out of range",
        ));
    }
    let topic_bytes = take(&mut cursor, topic_len)?;
    let topic_str = std::str::from_utf8(topic_bytes).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "spill frame topic is not UTF-8")
    })?;
    let topic = Topic::new(topic_str).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("spill frame topic invalid: {e}"),
        )
    })?;
    let payload_len = read_u32_be(take(&mut cursor, 4)?) as usize;
    if payload_len > MAX_PAYLOAD_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "spill frame payload length out of range",
        ));
    }
    let payload = Bytes::copy_from_slice(take(&mut cursor, payload_len)?);
    let timestamp_millis = i64::from_be_bytes(
        take(&mut cursor, 8)?
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "spill timestamp short"))?,
    );
    let has_client = *take(&mut cursor, 1)?.first().unwrap_or(&0);
    let client_id = if has_client == 0 {
        None
    } else {
        let client_len = read_u32_be(take(&mut cursor, 4)?) as usize;
        if client_len > MAX_CLIENT_ID_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "spill frame client id length out of range",
            ));
        }
        let client_bytes = take(&mut cursor, client_len)?;
        Some(
            std::str::from_utf8(client_bytes)
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "spill frame client id is not UTF-8",
                    )
                })?
                .to_string(),
        )
    };
    if cursor != body.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "spill frame has trailing bytes",
        ));
    }
    Ok(StreamEvent {
        topic,
        payload,
        timestamp_millis,
        client_id,
    })
}

fn segment_name(id: u32) -> String {
    format!("{SEGMENT_PREFIX}{id:08}{SEGMENT_SUFFIX}")
}

fn parse_segment_id(name: &str) -> Option<u32> {
    let middle = name
        .strip_prefix(SEGMENT_PREFIX)?
        .strip_suffix(SEGMENT_SUFFIX)?;
    if middle.len() != 8 || !middle.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    middle.parse().ok()
}

fn segment_ids(dir: &Path) -> io::Result<Vec<u32>> {
    let mut ids = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(id) = parse_segment_id(&name) {
            ids.push(id);
        } else {
            tracing::warn!(
                file = %name,
                "spill directory holds a foreign file; ignored, never read or deleted"
            );
        }
    }
    ids.sort_unstable();
    Ok(ids)
}

/// Scan result for one segment file: good frames up to `good_bytes`,
/// and whether a torn tail (or corrupt frame) starts there.
struct Scan {
    good_events: u64,
    good_bytes: u64,
    torn: bool,
}

/// Read one frame header (magic + length) at the current position.
/// Callers only invoke this with bytes remaining, so any short read is
/// a torn tail, never a clean end.
fn read_header(file: &mut File) -> io::Result<u32> {
    let mut header = [0u8; 8];
    file.read_exact(&mut header).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "spill segment ends mid-header",
            )
        } else {
            e
        }
    })?;
    if read_u32_be(&header[0..4]) != FRAME_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "spill frame magic mismatch",
        ));
    }
    let len = read_u32_be(&header[4..8]);
    if len as usize > MAX_FRAME_BODY_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "spill frame length out of range",
        ));
    }
    Ok(len)
}

/// Scan one segment file from the start: count good frames, stop at
/// the first torn or corrupt frame. Never allocates beyond one frame.
fn scan_segment(path: &Path) -> io::Result<Scan> {
    let mut file = File::open(path)?;
    let total = file.seek(SeekFrom::End(0))?;
    file.seek(SeekFrom::Start(0))?;
    let mut good_events = 0u64;
    let mut good_bytes = 0u64;
    loop {
        let frame_start = file.stream_position()?;
        if frame_start == total {
            return Ok(Scan {
                good_events,
                good_bytes,
                torn: false,
            });
        }
        let len = match read_header(&mut file) {
            Ok(len) => len as u64,
            Err(_) => {
                return Ok(Scan {
                    good_events,
                    good_bytes,
                    torn: true,
                });
            }
        };
        // Body plus trailer must both be present and the trailer must
        // echo the length; afterwards the body must decode.
        let mut rest = vec![0u8; 0];
        let want = len.saturating_add(4);
        rest.try_reserve(want as usize)
            .map_err(|_| io::Error::new(io::ErrorKind::OutOfMemory, "spill frame too large"))?;
        rest.resize(want as usize, 0);
        if file.read_exact(&mut rest).is_err() {
            return Ok(Scan {
                good_events,
                good_bytes,
                torn: true,
            });
        }
        let (body, trailer) = rest.split_at(len as usize);
        if read_u32_be(trailer) != len as u32 || decode_body(body).is_err() {
            return Ok(Scan {
                good_events,
                good_bytes,
                torn: true,
            });
        }
        good_events += 1;
        good_bytes = file.stream_position()?;
    }
}

/// Truncate `path` to `len` and force it to stable storage. Rare path
/// (recovery only), so the sync cost is acceptable here.
fn truncate_segment(path: &Path, len: u64) -> io::Result<()> {
    let file = OpenOptions::new().write(true).open(path)?;
    file.set_len(len)?;
    file.sync_all()?;
    Ok(())
}

/// Append-only spill log over one directory. All methods expect the
/// caller to hold the owner's spill mutex; no internal locking, so the
/// fast path pays for exactly one mutex it already needed.
pub struct SpillLog {
    dir: PathBuf,
    segment_max_bytes: u64,
    max_spill_bytes: u64,
    segments: Vec<u32>,
    write_seg: u32,
    writer: File,
    write_seg_bytes: u64,
    read_seg: u32,
    read_off: u64,
    total_bytes: u64,
    backlog: u64,
    next_seq: u64,
}

impl SpillLog {
    /// Open (creating) `config.dir` and recover its segments. Returns
    /// the log plus the recovery outcome for the owner's counters.
    /// A bad directory or config fails loudly: fail closed, never
    /// silently memory-only.
    pub fn open(config: &SpillConfig) -> io::Result<(Self, SpillOutcome)> {
        config.validate()?;
        fs::create_dir_all(&config.dir)?;
        let mut segments = segment_ids(&config.dir)?;
        let mut recovered = 0u64;
        let mut torn = 0u64;
        let mut total_bytes = 0u64;
        // Scan in order; the first torn file truncates and discards
        // everything after it (see the module docs for why).
        let mut first_torn_pos: Option<usize> = None;
        for (pos, id) in segments.iter().enumerate() {
            let path = config.dir.join(segment_name(*id));
            let scan = scan_segment(&path)?;
            recovered += scan.good_events;
            if scan.torn {
                first_torn_pos = Some(pos);
                torn += 1;
                truncate_segment(&path, scan.good_bytes)?;
                break;
            }
            total_bytes += fs::metadata(&path)?.len();
        }
        if let Some(pos) = first_torn_pos {
            let dropped: Vec<u32> = segments.split_off(pos + 1);
            for id in &dropped {
                let path = config.dir.join(segment_name(*id));
                fs::remove_file(&path)?;
                // Discarded without a trustworthy scan: counted as torn.
                torn += 1;
            }
            total_bytes += fs::metadata(config.dir.join(segment_name(segments[pos])))?.len();
            tracing::warn!(
                dir = %config.dir.display(),
                torn_files = dropped.len() + 1,
                "spill recovery discarded a torn tail and later segments"
            );
        }
        let write_seg = segments.last().copied().unwrap_or(0);
        let (write_seg, writer, write_seg_bytes) = if write_seg == 0 {
            let id = 1u32;
            let path = config.dir.join(segment_name(id));
            let writer = OpenOptions::new().create(true).append(true).open(&path)?;
            segments.push(id);
            (id, writer, 0u64)
        } else {
            let path = config.dir.join(segment_name(write_seg));
            let len = fs::metadata(&path)?.len();
            let writer = OpenOptions::new().append(true).open(&path)?;
            (write_seg, writer, len)
        };
        let read_seg = segments.first().copied().unwrap_or(write_seg);
        Ok((
            Self {
                dir: config.dir.clone(),
                segment_max_bytes: config.segment_max_bytes,
                max_spill_bytes: config.max_spill_bytes,
                segments,
                write_seg,
                writer,
                write_seg_bytes,
                read_seg,
                read_off: 0,
                total_bytes,
                backlog: recovered,
                next_seq: 0,
            },
            SpillOutcome { recovered, torn },
        ))
    }

    /// Events on disk awaiting replay.
    pub fn backlog(&self) -> u64 {
        self.backlog
    }

    /// All segment bytes currently on disk.
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Next spill sequence number (one per acknowledged spill).
    pub fn next_sequence(&self) -> u64 {
        self.next_seq
    }

    /// Append one event: `write + flush` (page cache, never `fsync` on
    /// this path), rotate first when the segment would overflow. Returns
    /// the spill sequence number. Refusals (oversize event, disk cap,
    /// I/O error) are `Err`: fail closed, the caller counts the drop.
    pub fn spill(&mut self, event: &StreamEvent) -> io::Result<u64> {
        let body = encode_body(event)?;
        let frame = frame_body(&body);
        let frame_len = frame.len() as u64;
        if frame_len > self.segment_max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "spill event larger than the segment size",
            ));
        }
        if self.total_bytes.saturating_add(frame_len) > self.max_spill_bytes {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "spill disk cap reached",
            ));
        }
        if self.write_seg_bytes.saturating_add(frame_len) > self.segment_max_bytes {
            self.rotate()?;
        }
        self.writer.write_all(&frame)?;
        // Flush userspace buffers to the OS only: acknowledged spills
        // survive a process crash; the fsync window is documented above.
        self.writer.flush()?;
        self.write_seg_bytes += frame_len;
        self.total_bytes += frame_len;
        self.backlog += 1;
        let seq = self.next_seq;
        self.next_seq += 1;
        Ok(seq)
    }

    /// Roll to a fresh segment, syncing the closed one first so only
    /// the active tail is ever at risk from power loss.
    fn rotate(&mut self) -> io::Result<()> {
        self.writer.sync_data()?;
        let id = self.write_seg.checked_add(1).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "spill segment id exhausted")
        })?;
        let path = self.dir.join(segment_name(id));
        let writer = OpenOptions::new()
            .create_new(true)
            .append(true)
            .open(&path)?;
        self.writer = writer;
        self.write_seg = id;
        self.write_seg_bytes = 0;
        self.segments.push(id);
        Ok(())
    }

    /// Replay the oldest spilled event, advancing the cursor. A fully
    /// consumed closed segment is deleted (at-least-once across a
    /// crash, exactly-once within a run). Returns the event, or `None`
    /// with the torn count fixed on the way when the read side needed
    /// repair. Unreadable remainders are truncated away loudly and
    /// counted, never left to wedge the cursor: the cursor always moves
    /// forward or the backlog reaches zero.
    pub fn replay_one(&mut self) -> (Option<StreamEvent>, u64) {
        if self.backlog == 0 {
            return (None, 0);
        }
        // The read cursor always names a known segment: every rotation,
        // deletion and repair path below keeps `read_seg` inside
        // `segments` (or on the active tail, which is listed). A segment
        // file that vanished under us is operator error and is handled
        // loudly at the open below.
        let path = self.dir.join(segment_name(self.read_seg));
        let mut file = match File::open(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                tracing::warn!(
                    file = %path.display(),
                    "spill segment vanished; cursor advanced past it"
                );
                self.segments.retain(|id| *id != self.read_seg);
                self.advance_past_missing();
                self.recount();
                return (None, 1);
            }
            Err(e) => {
                tracing::warn!(
                    file = %path.display(),
                    error = %e,
                    "spill segment unreadable; remainder discarded"
                );
                return self.discard_unreadable();
            }
        };
        let file_len = match file.seek(SeekFrom::End(0)) {
            Ok(len) => len,
            Err(e) => {
                tracing::warn!(
                    file = %path.display(),
                    error = %e,
                    "spill segment unseekable; remainder discarded"
                );
                return self.discard_unreadable();
            }
        };
        if self.read_off >= file_len {
            // Cursor at end: a closed segment is fully consumed and can
            // go; the active tail simply has nothing more yet (a
            // disagreeing backlog is settled by the recount).
            if self.read_seg != self.write_seg {
                let _ = fs::remove_file(&path);
                self.total_bytes = self.total_bytes.saturating_sub(file_len);
                self.segments.retain(|id| *id != self.read_seg);
                if let Some(next) = self
                    .segments
                    .iter()
                    .find(|id| **id > self.read_seg)
                    .copied()
                {
                    self.read_seg = next;
                } else {
                    self.read_seg = self.write_seg;
                }
                self.read_off = 0;
                return self.replay_one();
            }
            self.recount();
            return (None, 0);
        }
        if file.seek(SeekFrom::Start(self.read_off)).is_err() {
            return self.discard_unreadable();
        }
        let frame_start = self.read_off;
        let len = match read_header(&mut file) {
            Ok(len) => len as u64,
            Err(_) => {
                return self.repair_torn(frame_start);
            }
        };
        let want = len.saturating_add(4) as usize;
        let mut rest = Vec::new();
        if rest.try_reserve(want).is_err() {
            return self.repair_torn(frame_start);
        }
        rest.resize(want, 0);
        if file.read_exact(&mut rest).is_err() {
            return self.repair_torn(frame_start);
        }
        let (body, trailer) = rest.split_at(len as usize);
        let event = decode_body(body).ok();
        if event.is_none() || read_u32_be(trailer) != len as u32 {
            return self.repair_torn(frame_start);
        }
        let consumed = 8u64.saturating_add(len).saturating_add(4);
        self.read_off = frame_start.saturating_add(consumed);
        self.backlog = self.backlog.saturating_sub(1);
        // Opportunistic cleanup: a closed segment drained to its end
        // leaves no bytes behind. A failed deletion is retried on the
        // next pass; the cursor still advances, so nothing wedges.
        if self.read_seg != self.write_seg
            && self.read_off >= file_len
            && fs::remove_file(&path).is_ok()
        {
            self.total_bytes = self.total_bytes.saturating_sub(file_len);
            self.segments.retain(|id| *id != self.read_seg);
            if let Some(next) = self
                .segments
                .iter()
                .find(|id| **id > self.read_seg)
                .copied()
            {
                self.read_seg = next;
            } else {
                self.read_seg = self.write_seg;
            }
            self.read_off = 0;
        }
        (event, 0)
    }

    /// Truncate the read segment at `good_off` (the torn tail starts
    /// there), drop every later *closed* segment, recount, and report
    /// one torn tail plus one per discarded segment. The active segment
    /// is never deleted (the writer holds it open with `O_APPEND`, so
    /// later appends land at the truncated end automatically); when it
    /// lies past a torn write its whole contents are suspect, so it is
    /// truncated back to empty instead. Failures fall back to
    /// [`SpillLog::discard_unreadable`] so the cursor always moves.
    fn repair_torn(&mut self, good_off: u64) -> (Option<StreamEvent>, u64) {
        let path = self.dir.join(segment_name(self.read_seg));
        if truncate_segment(&path, good_off).is_err() {
            return self.discard_unreadable();
        }
        let mut torn = 1u64;
        let pos = self
            .segments
            .iter()
            .position(|id| *id == self.read_seg)
            .unwrap_or(0);
        let later: Vec<u32> = self.segments.split_off(pos + 1);
        for id in &later {
            if *id == self.write_seg {
                // Suspect active tail: empty it in place rather than
                // deleting the file the writer holds. The lost
                // acknowledgements are counted below.
                let active = self.dir.join(segment_name(*id));
                if truncate_segment(&active, 0).is_ok() {
                    self.write_seg_bytes = 0;
                }
                torn += 1;
                continue;
            }
            let later_path = self.dir.join(segment_name(*id));
            let _ = fs::remove_file(&later_path);
            torn += 1;
        }
        if self.read_seg == self.write_seg {
            self.write_seg_bytes = good_off;
        }
        tracing::warn!(
            file = %path.display(),
            later_discarded = later.len(),
            "spill replay discarded a torn tail"
        );
        self.recount();
        (None, torn)
    }

    /// Last-resort repair for an unreadable read segment. The active
    /// tail is truncated at the cursor but never deleted; a closed
    /// segment is truncated, else deleted, else skipped in memory.
    /// Always recounts and reports one torn tail; the cursor always
    /// moves forward or the backlog reaches zero.
    fn discard_unreadable(&mut self) -> (Option<StreamEvent>, u64) {
        let path = self.dir.join(segment_name(self.read_seg));
        if self.read_seg == self.write_seg {
            // Never delete the file the writer holds: truncate at the
            // cursor (the tail after it is lost, counted). The `O_APPEND`
            // writer lands later appends at the truncated end on its
            // own. If even truncation fails, skip in memory and keep
            // serving the other segments.
            if truncate_segment(&path, self.read_off).is_ok() {
                self.write_seg_bytes = self.read_off;
            } else {
                tracing::warn!(
                    file = %path.display(),
                    "spill active tail persists unreadably; skipped in memory"
                );
                self.segments.retain(|id| *id != self.read_seg);
                self.advance_past_missing();
            }
        } else if truncate_segment(&path, self.read_off).is_ok() {
            // Closed segment repaired in place; stays listed, the
            // cursor continues past the torn tail.
        } else if fs::remove_file(&path).is_ok() {
            self.segments.retain(|id| *id != self.read_seg);
            self.advance_past_missing();
        } else {
            // The file can neither be truncated nor removed (permissions
            // changed under us): skip it in memory so delivery of every
            // other segment continues. The bytes stay on disk for the
            // operator, loudly logged.
            tracing::warn!(
                file = %path.display(),
                "spill segment persists unreadably; skipped in memory"
            );
            self.segments.retain(|id| *id != self.read_seg);
            self.advance_past_missing();
        }
        self.recount();
        (None, 1)
    }

    /// Move the read cursor past a missing segment id.
    fn advance_past_missing(&mut self) {
        if let Some(next) = self
            .segments
            .iter()
            .find(|id| **id > self.read_seg)
            .copied()
        {
            self.read_seg = next;
        } else {
            self.read_seg = self.write_seg;
        }
        self.read_off = 0;
    }

    /// Recompute `total_bytes` and `backlog` from the files on disk.
    /// Rare path only (repair and cursor trouble): scans are bounded by
    /// the disk cap.
    fn recount(&mut self) {
        let mut total = 0u64;
        let mut backlog = 0u64;
        for id in &self.segments {
            let path = self.dir.join(segment_name(*id));
            match scan_segment(&path) {
                Ok(scan) => {
                    total += fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                    // Frames before the read cursor in the read segment
                    // are already delivered.
                    if *id == self.read_seg {
                        let mut file = match File::open(&path) {
                            Ok(file) => file,
                            Err(_) => continue,
                        };
                        let mut off = 0u64;
                        let mut remaining = 0u64;
                        while off < scan.good_bytes {
                            if file.seek(SeekFrom::Start(off)).is_err() {
                                break;
                            }
                            let start = off;
                            let step = match read_header(&mut file) {
                                Ok(len) => 8u64.saturating_add(len as u64).saturating_add(4),
                                Err(_) => break,
                            };
                            off = start.saturating_add(step);
                            if off > self.read_off {
                                remaining += 1;
                            }
                        }
                        backlog += remaining;
                    } else {
                        backlog += scan.good_events;
                    }
                }
                Err(_) => {
                    total += fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                }
            }
        }
        self.total_bytes = total;
        self.backlog = backlog;
    }

    /// Force the active segment (and its directory entry) to stable
    /// storage. Call before an orderly shutdown or a restart test; the
    /// spill path itself never calls this.
    pub fn sync(&self) -> io::Result<()> {
        self.writer.sync_data()
    }
}

impl Drop for SpillLog {
    fn drop(&mut self) {
        // Best-effort narrowing of the power-loss window on a clean
        // shutdown. Failures cannot be reported loudly from `Drop`;
        // explicit `sync` is the loud path.
        let _ = self.writer.sync_data();
    }
}

#[cfg(test)]
mod spill_unit_tests {
    use super::*;

    fn test_event(topic: &str, payload: &[u8]) -> StreamEvent {
        StreamEvent {
            topic: Topic::new(topic).unwrap(),
            payload: Bytes::copy_from_slice(payload),
            timestamp_millis: 1700000000,
            client_id: Some("c1".to_string()),
        }
    }

    #[test]
    fn spill_frame_round_trips() {
        let event = test_event("sensors/temp", b"{\"t\": 23}");
        let body = encode_body(&event).expect("encodes");
        let back = decode_body(&body).expect("decodes");
        assert_eq!(back.topic, event.topic);
        assert_eq!(back.payload, event.payload);
        assert_eq!(back.timestamp_millis, event.timestamp_millis);
        assert_eq!(back.client_id, event.client_id);
    }

    #[test]
    fn spill_frame_without_client_round_trips() {
        let event = StreamEvent::new(Topic::new("a/b").unwrap(), Bytes::from_static(b"x"));
        let body = encode_body(&event).expect("encodes");
        let back = decode_body(&body).expect("decodes");
        assert_eq!(back.topic.as_str(), "a/b");
        assert_eq!(back.client_id, None);
    }
}
