//! Trace-session registry for the v5 management API.
//!
//! Covers `GET /trace` (list sessions), `POST /trace` (create one
//! session), `DELETE /trace` (clear all sessions),
//! `DELETE /trace/{name}` (drop one session),
//! `PUT /trace/{name}/stop` (halt capture for one session, keeping it
//! listed and its data readable),
//! `GET /trace/{name}/download` (serve one session's captured log as a
//! file download), `GET /trace/{name}/log` (paged inline read over the
//! same bounded capture buffer) and `GET /trace/{name}/log_detail`
//! (single-entry detail read over the same buffer by `position`).
//! Single-node, management-plane only for reads and writes:
//! nothing here runs on the per-message path, so reads, creates, clears,
//! single deletes, stops, downloads, log reads and detail reads never take a
//! delivery lock and no new buffering is added to fan-out or fan-in.
//! The packet path appends through [`TraceStore::capture_publish`], driven
//! by the kernel publish event (`ingress_pipeline_with_publisher` in
//! `crates/broker-node/src/main.rs`): one global-flag atomic load plus one
//! short read lock when no session matches, small bounded line clones only
//! for matching sessions (see [`MAX_TRACE_PAYLOAD_BYTES`]).
//!
//! Store bounds (both stated here and enforced below):
//! - at most [`MAX_TRACES`] sessions are kept; creates past the cap are
//!   rejected with `INVALID_PARAMS` instead of growing without limit;
//! - `name` is capped at 256 chars and must match
//!   `^[A-Za-z]+[A-Za-z0-9-_]*$`; filter values are capped at 512 chars,
//!   so one entry cannot balloon memory;
//! - every session is eight small fields plus one bounded filter string,
//!   so per-session memory is constant; listing copies at most the capped
//!   map once per request.
//! - per-session capture is capped at [`MAX_TRACE_LOG_BYTES`] bytes
//!   (256 KiB); appends past the cap drop the oldest bytes and keep the
//!   newest (newest-wins truncation, no rotation files). With at most
//!   [`MAX_TRACES`] sessions the whole capture buffer stays under 7.5 MiB.
//!   Appends from the packet path format one line per matching session
//!   (see [`MAX_TRACE_PAYLOAD_BYTES`]); downloads clone at most one capped
//!   buffer per request.
//! - a session starts empty: creation seeds no bytes, and reads serve only
//!   what the packet path captured (an empty session downloads as an empty
//!   body and lists as an empty page, never a synthesised header).
//! - log reads split the same capped buffer into newline-delimited entries
//!   and render only the requested W0 page (`page`/`limit` plus
//!   `meta { page, limit, count, hasnext }`), so one read cannot grow
//!   without bound.
//! - detail reads return the single entry at the same zero-based `position`
//!   the log list reports, so one line is rendered per request and the
//!   response stays small.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::RwLock;

use crate::errors::ApiError;
use crate::pagination::{meta_page, paginate, PageParams};
use crate::ApiState;

/// Upper bound for stored trace sessions. Creates past this size are
/// rejected instead of growing the map without limit.
pub const MAX_TRACES: usize = 30;
/// Per-session capture cap in bytes. Appends past this size drop the
/// oldest bytes and keep the newest, so one session can never grow
/// without limit. At [`MAX_TRACES`] sessions the whole buffer stays
/// under 7.5 MiB.
pub const MAX_TRACE_LOG_BYTES: usize = 256 * 1024;
/// Cap on the payload bytes rendered into one captured line.
/// Payloads on the wire can be megabytes; rendering all of one into every
/// matching session would put unbounded formatting work on the publish path.
/// Truncating to 1 KiB keeps one capture under ~1 KiB plus the small topic
/// and client-id fields, so a publish fanning into all [`MAX_TRACES`]
/// sessions formats at most ~30 KiB. The line notes truncation so a reader
/// never mistakes a clipped payload for the full one.
pub const MAX_TRACE_PAYLOAD_BYTES: usize = 1024;
/// Download content type served by `GET /trace/{name}/download`.
pub const TRACE_DOWNLOAD_CONTENT_TYPE: &str = "application/octet-stream";
/// Longest accepted session `name`.
const MAX_NAME_LEN: usize = 256;
/// Longest accepted filter value (`clientid`, `topic`, `ip_address`,
/// `ruleid`).
const MAX_FILTER_LEN: usize = 512;
/// Default capture window when `end_at` is absent: ten minutes.
const DEFAULT_WINDOW_SECS: u64 = 600;

/// Node name rendered in `log_size` (single node).
const NODE_NAME: &str = "indramqtt@127.0.0.1";

/// Trace condition types the create path accepts.
const VALID_TYPES: &[&str] = &["clientid", "topic", "ip_address", "ruleid"];
/// Payload encodings the create path accepts.
const VALID_PAYLOAD_ENCODES: &[&str] = &["hex", "text", "hidden"];
/// Log formatters the create path accepts.
const VALID_FORMATTERS: &[&str] = &["text", "json"];

/// One registered trace session: which filter on which kind is captured,
/// whether capture is enabled, how payloads are rendered, and the capture
/// window (`start_at`/`end_at`, epoch seconds).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceSession {
    pub name: String,
    pub trace_type: String,
    pub filter: String,
    pub enable: bool,
    pub payload_encode: String,
    pub formatter: String,
    pub start_at: u64,
    pub end_at: u64,
}

impl TraceSession {
    fn status(&self, now: u64) -> &'static str {
        if !self.enable {
            "stopped"
        } else if now < self.start_at {
            "waiting"
        } else if now >= self.end_at {
            "stopped"
        } else {
            "running"
        }
    }

    fn to_json(&self, now: u64, log_size: usize) -> serde_json::Value {
        let mut obj = serde_json::Map::new();
        obj.insert(
            "name".to_string(),
            serde_json::Value::String(self.name.clone()),
        );
        obj.insert(
            "type".to_string(),
            serde_json::Value::String(self.trace_type.clone()),
        );
        obj.insert(
            self.trace_type.clone(),
            serde_json::Value::String(self.filter.clone()),
        );
        obj.insert(
            "status".to_string(),
            serde_json::Value::String(self.status(now).to_string()),
        );
        obj.insert(
            "start_at".to_string(),
            serde_json::Value::String(epoch_to_rfc3339(self.start_at)),
        );
        obj.insert(
            "end_at".to_string(),
            serde_json::Value::String(epoch_to_rfc3339(self.end_at)),
        );
        obj.insert(
            "payload_encode".to_string(),
            serde_json::Value::String(self.payload_encode.clone()),
        );
        obj.insert(
            "formatter".to_string(),
            serde_json::Value::String(self.formatter.clone()),
        );
        obj.insert(
            "log_size".to_string(),
            serde_json::json!({ (NODE_NAME): log_size }),
        );
        serde_json::Value::Object(obj)
    }
}

/// Bounded in-memory trace registry keyed by session `name`, plus one
/// bounded capture buffer per session.
///
/// Single-node maps behind one lock; every method finishes quickly and
/// no delivery path touches them, so management reads never block
/// messaging. The capture buffer is newest-wins: appends past
/// [`MAX_TRACE_LOG_BYTES`] drop the oldest bytes (no rotation files).
struct TraceData {
    sessions: HashMap<String, TraceSession>,
    logs: HashMap<String, Vec<u8>>,
}

/// Bounded in-memory trace registry keyed by session `name`.
///
/// Single-node map behind one lock; every method finishes quickly and no
/// delivery path touches it, so management reads never block messaging.
pub struct TraceStore {
    inner: RwLock<TraceData>,
}

impl TraceStore {
    /// Empty registry.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(TraceData {
                sessions: HashMap::new(),
                logs: HashMap::new(),
            }),
        }
    }

    /// Snapshot of stored sessions sorted by `start_at` descending (newest
    /// first), ties broken by `name` for stable output.
    pub fn list(&self) -> Vec<TraceSession> {
        let data = self.inner.read().expect("trace store lock");
        let mut out: Vec<TraceSession> = data.sessions.values().cloned().collect();
        out.sort_by(|a, b| {
            b.start_at
                .cmp(&a.start_at)
                .then_with(|| a.name.cmp(&b.name))
        });
        out
    }

    /// Number of bytes currently captured for `name` (zero when unknown
    /// or nothing captured yet).
    pub fn log_len(&self, name: &str) -> usize {
        self.inner
            .read()
            .expect("trace store lock")
            .logs
            .get(name)
            .map_or(0, Vec::len)
    }

    /// Clone the captured bytes for `name`. Returns `None` when the
    /// session is unknown; returns an empty vector when the session
    /// exists but nothing has been captured yet.
    pub fn read_log(&self, name: &str) -> Option<Vec<u8>> {
        let data = self.inner.read().expect("trace store lock");
        if !data.sessions.contains_key(name) {
            return None;
        }
        Some(data.logs.get(name).cloned().unwrap_or_default())
    }

    /// Append capture bytes for `name` (management-plane hook for the
    /// capture path; never called while holding a delivery lock).
    /// Past [`MAX_TRACE_LOG_BYTES`] the oldest bytes are dropped and the
    /// newest are kept. Over-long single appends keep only their tail.
    /// Returns false when the session is unknown (bytes are dropped).
    pub fn append_log(&self, name: &str, bytes: &[u8]) -> bool {
        if bytes.is_empty() {
            return self
                .inner
                .read()
                .expect("trace store lock")
                .sessions
                .contains_key(name);
        }
        let mut data = self.inner.write().expect("trace store lock");
        if !data.sessions.contains_key(name) {
            return false;
        }
        let entry = data.logs.entry(name.to_string()).or_default();
        entry.extend_from_slice(bytes);
        if entry.len() > MAX_TRACE_LOG_BYTES {
            let tail = if bytes.len() >= MAX_TRACE_LOG_BYTES {
                bytes[bytes.len() - MAX_TRACE_LOG_BYTES..].to_vec()
            } else {
                entry[entry.len() - MAX_TRACE_LOG_BYTES..].to_vec()
            };
            *entry = tail;
        }
        true
    }

    /// True when no session is stored. One short read lock; the packet
    /// path uses this (via [`TraceStore::capture_publish`]) as its cheap
    /// no-tracing check with no allocation.
    pub fn is_empty(&self) -> bool {
        self.inner
            .read()
            .expect("trace store lock")
            .sessions
            .is_empty()
    }

    /// True when at least one stored session still has capture enabled.
    /// Management-plane only (session lifecycle bookkeeping for the global
    /// tracing flag); the packet path checks per-session state while
    /// matching instead of calling this.
    pub fn has_enabled(&self) -> bool {
        self.inner
            .read()
            .expect("trace store lock")
            .sessions
            .values()
            .any(|s| s.enable)
    }

    /// Append one publish to every running session whose filter matches.
    ///
    /// Driven by the kernel publish event with the publishing client id,
    /// its last-known peer address, the concrete topic and the raw payload.
    /// A session matches only while running (`enable` and `now` inside
    /// `[start_at, end_at)`): `clientid` compares the publisher id exactly,
    /// `topic` matches the concrete topic against the session filter with
    /// MQTT wildcards, `ip_address` compares the publisher peer address
    /// exactly. `ruleid` sessions never match here: rule identity is not
    /// carried on the publish path.
    /// TODO(parity): should `ruleid` sessions capture rule-engine input or
    /// output for their rule? Neither this rulebook nor the task spec
    /// decides; current choice is the conservative one (no capture) so a
    /// rule trace never invents packets.
    ///
    /// Cost: one short read lock plus a bounded scan (at most [`MAX_TRACES`]
    /// small comparisons, no allocation) when nothing matches; one small
    /// bounded line clone per matching session otherwise (see
    /// [`MAX_TRACE_PAYLOAD_BYTES`]). Appends reuse [`TraceStore::append_log`]
    /// so the per-session [`MAX_TRACE_LOG_BYTES`] cap always applies.
    pub fn capture_publish(
        &self,
        client_id: &str,
        peerhost: Option<&str>,
        topic: &str,
        payload: &[u8],
    ) {
        let now = now_epoch_secs();
        let lines: Vec<(String, Vec<u8>)> = {
            let data = self.inner.read().expect("trace store lock");
            if data.sessions.is_empty() {
                return;
            }
            let mut out = Vec::new();
            for session in data.sessions.values() {
                if !session.enable || now < session.start_at || now >= session.end_at {
                    continue;
                }
                if !session_matches(session, client_id, peerhost, topic) {
                    continue;
                }
                out.push((
                    session.name.clone(),
                    format_capture_line(session, topic, client_id, payload),
                ));
            }
            out
        };
        for (name, line) in &lines {
            self.append_log(name, line);
        }
    }

    /// Insert one session. Fails cleanly when `name` already exists
    /// (caller maps to `ALREADY_EXISTS`), when another session already
    /// captures the same type plus filter (caller maps to
    /// `DUPLICATE_CONDITION`), or when the store holds [`MAX_TRACES`]
    /// sessions (caller maps to `INVALID_PARAMS`). On success the session
    /// starts with an empty capture buffer: reads serve only what the
    /// packet path appends, never a synthesised header.
    pub fn insert(&self, session: TraceSession) -> Result<TraceSession, TraceInsertError> {
        let mut data = self.inner.write().expect("trace store lock");
        if data.sessions.contains_key(&session.name) {
            return Err(TraceInsertError::Duplicate);
        }
        if data
            .sessions
            .values()
            .any(|e| e.trace_type == session.trace_type && e.filter == session.filter)
        {
            return Err(TraceInsertError::DuplicateCondition);
        }
        if data.sessions.len() >= MAX_TRACES {
            return Err(TraceInsertError::Full);
        }
        data.logs.insert(session.name.clone(), Vec::new());
        data.sessions.insert(session.name.clone(), session.clone());
        Ok(session)
    }

    /// Remove every session and every capture buffer.
    pub fn clear(&self) {
        let mut data = self.inner.write().expect("trace store lock");
        data.sessions.clear();
        data.logs.clear();
    }

    /// Fetch one session by name (used by follow-up single-session tasks).
    pub fn get(&self, name: &str) -> Option<TraceSession> {
        self.inner
            .read()
            .expect("trace store lock")
            .sessions
            .get(name)
            .cloned()
    }

    /// Drop the named session and its capture buffer. Returns true when
    /// a session was removed.
    pub fn remove(&self, name: &str) -> bool {
        let mut data = self.inner.write().expect("trace store lock");
        data.logs.remove(name);
        data.sessions.remove(name).is_some()
    }

    /// Stop capture for the named session while keeping it listed.
    /// Returns the updated session, or `None` when unknown.
    pub fn stop(&self, name: &str) -> Option<TraceSession> {
        let mut data = self.inner.write().expect("trace store lock");
        let entry = data.sessions.get_mut(name)?;
        entry.enable = false;
        Some(entry.clone())
    }
}

/// True when one publish belongs in `session`: the publisher id for
/// `clientid`, MQTT filter match for `topic`, the publisher peer address
/// for `ip_address`. Unknown kinds and unparseable filters never match
/// (fail closed, never a guessed capture).
fn session_matches(
    session: &TraceSession,
    client_id: &str,
    peerhost: Option<&str>,
    topic: &str,
) -> bool {
    match session.trace_type.as_str() {
        "clientid" => session.filter == client_id,
        "topic" => {
            let Ok(filter) = broker_protocol::TopicFilter::new(session.filter.clone()) else {
                return false;
            };
            let Ok(concrete) = broker_protocol::Topic::new(topic.to_string()) else {
                return false;
            };
            filter.matches(&concrete)
        }
        "ip_address" => peerhost.is_some_and(|peer| peer == session.filter),
        _ => false,
    }
}

/// Render one captured publish line for `session`, honouring its payload
/// encoding and formatter. `text` lines read
/// `publish topic=<topic> clientid=<client> payload=<text>`; `json` lines
/// carry the same fields as a JSON object. `hidden` omits the payload so a
/// sensitive payload is never written into the capture buffer. Payloads
/// past [`MAX_TRACE_PAYLOAD_BYTES`] are truncated with a marker (see the
/// constant for why). Every line ends with `\n` so the log and detail
/// readers split entries the same way.
fn format_capture_line(
    session: &TraceSession,
    topic: &str,
    client_id: &str,
    payload: &[u8],
) -> Vec<u8> {
    let hidden = session.payload_encode == "hidden";
    let rendered: Option<String> = if hidden {
        None
    } else if session.payload_encode == "hex" {
        Some(render_hex_capped(payload))
    } else {
        Some(render_text_capped(payload))
    };
    if session.formatter == "json" {
        let mut obj = serde_json::Map::new();
        obj.insert(
            "topic".to_string(),
            serde_json::Value::String(topic.to_string()),
        );
        obj.insert(
            "clientid".to_string(),
            serde_json::Value::String(client_id.to_string()),
        );
        if let Some(text) = rendered {
            obj.insert("payload".to_string(), serde_json::Value::String(text));
        }
        let mut line = serde_json::Value::Object(obj).to_string();
        line.push('\n');
        line.into_bytes()
    } else {
        let mut line = format!("publish topic={topic} clientid={client_id}");
        if let Some(text) = rendered {
            line.push_str(" payload=");
            line.push_str(&text);
        }
        line.push('\n');
        line.into_bytes()
    }
}

/// Render at most [`MAX_TRACE_PAYLOAD_BYTES`] payload bytes as lossy text,
/// appending `...[truncated]` when clipped so a reader never mistakes a
/// clipped payload for the full one.
fn render_text_capped(payload: &[u8]) -> String {
    if payload.len() <= MAX_TRACE_PAYLOAD_BYTES {
        return String::from_utf8_lossy(payload).into_owned();
    }
    let mut end = MAX_TRACE_PAYLOAD_BYTES.min(payload.len());
    while end > 0 && end < payload.len() && (payload[end] & 0xC0) == 0x80 {
        end -= 1;
    }
    let mut text = String::from_utf8_lossy(&payload[..end]).into_owned();
    text.push_str("...[truncated]");
    text
}

/// Render at most [`MAX_TRACE_PAYLOAD_BYTES`] payload bytes as lowercase
/// hex, appending `...[truncated]` when clipped (same marker as text so
/// readers learn one convention).
fn render_hex_capped(payload: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let clipped = payload.len() > MAX_TRACE_PAYLOAD_BYTES;
    let slice = if clipped {
        &payload[..MAX_TRACE_PAYLOAD_BYTES]
    } else {
        payload
    };
    let mut out = String::with_capacity(slice.len() * 2 + 14);
    for byte in slice {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    if clipped {
        out.push_str("...[truncated]");
    }
    out
}

impl Default for TraceStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Why [`TraceStore::insert`] refused a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceInsertError {
    /// The `name` is already stored.
    Duplicate,
    /// Another session already captures the same type plus filter.
    DuplicateCondition,
    /// The store holds [`MAX_TRACES`] sessions.
    Full,
}

/// `GET /trace`: list sessions as a bare JSON array (newest first).
///
/// An empty registry reads as `[]`, never an error. One bounded snapshot
/// per request (at most [`MAX_TRACES`] small clones under a short lock);
/// delivery never waits on it and no new buffering is added to fan-out or
/// fan-in.
pub async fn list_traces(State(state): State<ApiState>) -> Response {
    let now = now_epoch_secs();
    let rows = state.traces.list();
    let data: Vec<serde_json::Value> = rows
        .iter()
        .map(|s| {
            let size = state.traces.log_len(&s.name);
            s.to_json(now, size)
        })
        .collect();
    (StatusCode::OK, Json(data)).into_response()
}

/// `POST /trace`: create one session from a filter plus name.
///
/// Returns the stored session with 200. Malformed bodies fail with
/// `INVALID_PARAMS`; an existing `name` fails with `ALREADY_EXISTS` and an
/// already-captured type plus filter fails with `DUPLICATE_CONDITION`
/// (both 409); a full registry fails with `INVALID_PARAMS`.
pub async fn create_trace(State(state): State<ApiState>, body: Bytes) -> Response {
    let value: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return invalid_params(format!("invalid trace body: {e}")),
    };
    let now = now_epoch_secs();
    let session = match parse_trace_request(&value, now) {
        Ok(s) => s,
        Err(msg) => return invalid_params(msg),
    };
    match state.traces.insert(session) {
        Ok(stored) => {
            // A stored session means capture is active: raise the global
            // packet-tracing flag so the kernel publish hook (which checks
            // the flag first) observes it without a restart. One atomic
            // store on the management plane; the per-message path pays one
            // atomic load.
            state.tracing.set_enabled(true);
            let now = now_epoch_secs();
            let size = state.traces.log_len(&stored.name);
            (StatusCode::OK, Json(stored.to_json(now, size))).into_response()
        }
        Err(TraceInsertError::Duplicate) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "code": "ALREADY_EXISTS",
                "message": "trace name already exists",
            })),
        )
            .into_response(),
        Err(TraceInsertError::DuplicateCondition) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "code": "DUPLICATE_CONDITION",
                "message": "trace condition already exists",
            })),
        )
            .into_response(),
        Err(TraceInsertError::Full) => invalid_params(
            "The number of traces created has reached the maximum please delete the useless ones first"
                .to_string(),
        ),
    }
}

/// `DELETE /trace`: drop every session and report success with 204.
/// Always succeeds, even when nothing is stored. Clearing the last session
/// lowers the global packet-tracing flag so the kernel publish hook
/// returns to its single-load off state.
pub async fn clear_traces(State(state): State<ApiState>) -> Response {
    state.traces.clear();
    state.tracing.set_enabled(false);
    StatusCode::NO_CONTENT.into_response()
}

/// `DELETE /trace/{name}`: drop one session and report success with 204.
///
/// Unknown names fail with `NOT_FOUND`. One bounded map removal per
/// request; delivery never waits on it and no new buffering is added to
/// fan-out or fan-in.
pub async fn delete_trace(State(state): State<ApiState>, Path(name): Path<String>) -> Response {
    if !state.traces.remove(&name) {
        return ApiError::NotFound("trace not found".to_string()).into_response();
    }
    // Dropping the last enabled session lowers the global flag so the
    // kernel publish hook returns to its single-load off state.
    if !state.traces.has_enabled() {
        state.tracing.set_enabled(false);
    }
    StatusCode::NO_CONTENT.into_response()
}

/// `PUT /trace/{name}/stop`: halt capture for one session, keeping it listed.
///
/// Flips `enable` off while keeping the session and its bounded capture
/// buffer, so `download` and `log` reads still serve the retained bytes.
/// Unknown names fail with `NOT_FOUND`. Stopping an already-stopped
/// session still succeeds. One bounded map write per request; delivery
/// never waits on it and no new buffering is added to fan-out or fan-in.
pub async fn stop_trace(State(state): State<ApiState>, Path(name): Path<String>) -> Response {
    let Some(stopped) = state.traces.stop(&name) else {
        return ApiError::NotFound("trace not found".to_string()).into_response();
    };
    // Stopping the last enabled session lowers the global flag so the
    // kernel publish hook returns to its single-load off state. Time-window
    // expiry is checked per packet, not here.
    if !state.traces.has_enabled() {
        state.tracing.set_enabled(false);
    }
    let now = now_epoch_secs();
    let size = state.traces.log_len(&stopped.name);
    (StatusCode::OK, Json(stopped.to_json(now, size))).into_response()
}

/// `GET /trace/{name}/download`: serve one session's captured log as a
/// file download.
///
/// Returns exactly the bounded per-session buffer the packet path appended
/// (possibly empty: an uncaptured session downloads as an empty body, never
/// a synthesised header) with
/// `application/octet-stream` and a `content-disposition` attachment
/// filename of `<name>.log`. Unknown sessions fail with `NOT_FOUND`.
/// Management-plane only: one capped clone per request (at most
/// [`MAX_TRACE_LOG_BYTES`] bytes); delivery never waits on it and no
/// new buffering is added to fan-out or fan-in.
pub async fn download_trace(State(state): State<ApiState>, Path(name): Path<String>) -> Response {
    let Some(session) = state.traces.get(&name) else {
        return ApiError::NotFound("trace not found".to_string()).into_response();
    };
    let bytes = state.traces.read_log(&session.name).unwrap_or_default();
    let filename = format!("attachment; filename=\"{}.log\"", session.name);
    (
        StatusCode::OK,
        [
            ("content-type", TRACE_DOWNLOAD_CONTENT_TYPE.to_string()),
            ("content-disposition", filename),
        ],
        bytes,
    )
        .into_response()
}

/// `GET /trace/{name}/log`: paged inline read over one session's captured
/// log.
///
/// Splits the same bounded per-session buffer the download serves (only
/// packet-path appended lines; an uncaptured session reads as an empty page,
/// never a synthesised header) into
/// newline-delimited entries and renders only the requested W0 page as
/// `data` plus `meta { page, limit, count, hasnext }`. Each entry is
/// `{ position, content }` where `position` is the zero-based line index
/// into the full entry list, so follow-up detail reads can reuse the same
/// positions. Unknown sessions fail with `NOT_FOUND`. Management-plane
/// only: one capped clone per request (at most [`MAX_TRACE_LOG_BYTES`]
/// bytes, split into lines); delivery never waits on it and no new
/// buffering is added to fan-out or fan-in.
pub async fn get_trace_log(
    State(state): State<ApiState>,
    Path(name): Path<String>,
    params: PageParams,
) -> Response {
    let Some(session) = state.traces.get(&name) else {
        return ApiError::NotFound("trace not found".to_string()).into_response();
    };
    let bytes = state.traces.read_log(&session.name).unwrap_or_default();
    let text = String::from_utf8_lossy(&bytes);
    let lines: Vec<String> = text.lines().map(str::to_string).collect();
    let total = lines.len();
    let start =
        ((u64::from(params.page.max(1)) - 1) * u64::from(params.limit)).min(total as u64) as usize;
    let page_items = paginate(&lines, params.page, params.limit);
    let data: Vec<serde_json::Value> = page_items
        .iter()
        .enumerate()
        .map(|(index, line)| {
            serde_json::json!({
                "position": start + index,
                "content": line,
            })
        })
        .collect();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "data": data,
            "meta": meta_page(params.page, params.limit, total),
        })),
    )
        .into_response()
}

/// `GET /trace/{name}/log_detail`: single-entry detail read over one
/// session's captured log.
///
/// Reads the same bounded per-session buffer the download and the paged
/// log read serve, splits it into newline-delimited entries exactly like
/// `get_trace_log`, and returns the one entry at the requested zero-based
/// `position` as `{ position, content }`. `position` arrives as the
/// `position` query parameter and must parse as a non-negative integer.
/// Unknown sessions and out-of-range positions fail with `NOT_FOUND`;
/// a missing or malformed `position` fails with `INVALID_PARAMS`.
/// Management-plane only: one capped clone per request (at most
/// [`MAX_TRACE_LOG_BYTES`] bytes, split into lines); delivery never waits
/// on it and no new buffering is added to fan-out or fan-in.
pub async fn get_trace_log_detail(
    State(state): State<ApiState>,
    Path(name): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let raw = match params.get("position") {
        Some(value) => value.clone(),
        None => return invalid_params("field `position` is required".to_string()),
    };
    let position: usize = match raw.trim().parse() {
        Ok(value) => value,
        Err(_) => {
            return invalid_params("field `position` must be a non-negative integer".to_string());
        }
    };
    let Some(session) = state.traces.get(&name) else {
        return ApiError::NotFound("trace not found".to_string()).into_response();
    };
    let bytes = state.traces.read_log(&session.name).unwrap_or_default();
    let text = String::from_utf8_lossy(&bytes);
    let lines: Vec<String> = text.lines().map(str::to_string).collect();
    let Some(content) = lines.get(position).cloned() else {
        return ApiError::NotFound("trace log position not found".to_string()).into_response();
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "position": position,
            "content": content,
        })),
    )
        .into_response()
}

fn invalid_params(reason: String) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "code": "INVALID_PARAMS",
            "message": reason,
        })),
    )
        .into_response()
}

/// Validate a create body into a stored session.
///
/// Required: `name` (letter-first, alphanumerics plus `-`/`_`, at most 256
/// chars) and `type` (one of `clientid`, `topic`, `ip_address`, `ruleid`)
/// plus the matching filter field. Optional: `payload_encode`
/// (`hex`/`text`/`hidden`, defaults to `text`), `formatter`
/// (`text`/`json`, defaults to `text`), `start_at` and `end_at` (epoch
/// seconds or RFC 3339; defaults are now and start plus ten minutes).
/// Unknown fields are ignored.
fn parse_trace_request(value: &serde_json::Value, now: u64) -> Result<TraceSession, String> {
    let obj = value
        .as_object()
        .ok_or_else(|| "trace body must be a JSON object".to_string())?;
    if obj.is_empty() {
        return Err("trace body must not be empty".to_string());
    }
    let name = obj
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "field `name` is required".to_string())?;
    validate_name(name)?;
    let trace_type = obj
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "field `type` is required".to_string())?;
    if !VALID_TYPES.contains(&trace_type) {
        return Err(
            "field `type` must be one of `clientid`, `topic`, `ip_address`, `ruleid`".to_string(),
        );
    }
    let filter = obj
        .get(trace_type)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("required {trace_type} field"))?;
    if filter.trim().is_empty() {
        return Err(format!("field `{trace_type}` must not be empty"));
    }
    if filter.len() > MAX_FILTER_LEN {
        return Err(format!("field `{trace_type}` is too long"));
    }
    validate_filter_shape(trace_type, filter)?;
    let payload_encode = match obj.get("payload_encode") {
        None => "text".to_string(),
        Some(v) => {
            let s = v
                .as_str()
                .ok_or_else(|| "field `payload_encode` must be a string".to_string())?;
            if !VALID_PAYLOAD_ENCODES.contains(&s) {
                return Err(
                    "field `payload_encode` must be one of `hex`, `text`, `hidden`".to_string(),
                );
            }
            s.to_string()
        }
    };
    let formatter = match obj.get("formatter") {
        None => "text".to_string(),
        Some(v) => {
            let s = v
                .as_str()
                .ok_or_else(|| "field `formatter` must be a string".to_string())?;
            if !VALID_FORMATTERS.contains(&s) {
                return Err("field `formatter` must be one of `text`, `json`".to_string());
            }
            s.to_string()
        }
    };
    let start_at = match obj.get("start_at") {
        None => now,
        Some(v) => parse_time_value(v)
            .ok_or_else(|| "field `start_at` must be epoch seconds or RFC 3339".to_string())?,
    };
    let end_at = match obj.get("end_at") {
        None => start_at.saturating_add(DEFAULT_WINDOW_SECS),
        Some(v) => parse_time_value(v)
            .ok_or_else(|| "field `end_at` must be epoch seconds or RFC 3339".to_string())?,
    };
    if end_at <= start_at {
        return Err("failed by start_at >= end_at".to_string());
    }
    if end_at <= now {
        return Err("end_at time has already passed".to_string());
    }
    Ok(TraceSession {
        name: name.to_string(),
        trace_type: trace_type.to_string(),
        filter: filter.to_string(),
        enable: true,
        payload_encode,
        formatter,
        start_at,
        end_at,
    })
}

fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err("Name Length must =< 256".to_string());
    }
    let mut chars = name.chars();
    let first = chars.next().unwrap_or('0');
    if !first.is_ascii_alphabetic() {
        return Err("Name should be ^[A-Za-z]+[A-Za-z0-9-_]*$".to_string());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err("Name should be ^[A-Za-z]+[A-Za-z0-9-_]*$".to_string());
    }
    Ok(())
}

fn validate_filter_shape(trace_type: &str, filter: &str) -> Result<(), String> {
    match trace_type {
        "topic" => {
            if broker_protocol::TopicFilter::new(filter).is_err() {
                return Err(format!("topic: {filter} invalid"));
            }
            Ok(())
        }
        "ip_address" => {
            if filter.parse::<std::net::IpAddr>().is_err() {
                return Err("ip address invalid".to_string());
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn parse_time_value(v: &serde_json::Value) -> Option<u64> {
    match v {
        serde_json::Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                Some(u)
            } else if let Some(i) = n.as_i64() {
                u64::try_from(i).ok()
            } else {
                None
            }
        }
        serde_json::Value::String(s) => {
            if let Ok(u) = s.trim().parse::<u64>() {
                return Some(u);
            }
            parse_rfc3339_to_epoch(s)
        }
        _ => None,
    }
}

fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Format epoch seconds as `YYYY-MM-DDTHH:MM:SS+00:00` (always UTC).
fn epoch_to_rfc3339(secs: u64) -> String {
    let (y, m, d, hh, mm, ss) = civil_from_epoch(secs);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}+00:00")
}

fn civil_from_epoch(secs: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (secs / 86_400) as i64;
    let sod = (secs % 86_400) as u32;
    let (y, m, d) = civil_from_days(days);
    (y, m, d, sod / 3600, (sod % 3600) / 60, sod % 60)
}

// Howard Hinnant's civil_from_days: days since 1970-01-01 to y/m/d.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = (m as u64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

/// Parse an RFC 3339 timestamp to epoch seconds. Accepts `Z` or numeric
/// offsets (`+08:00`, `+0800`, `+08`); fractional seconds are ignored.
fn parse_rfc3339_to_epoch(s: &str) -> Option<u64> {
    let s = s.trim();
    let (date_part, rest) = s.split_once(['T', 't', ' '])?;
    let (y, m, d) = parse_date(date_part)?;
    let (time_part, offset_secs) = split_timezone(rest)?;
    let (hh, mm, ss) = parse_time_of_day(time_part)?;
    let days = days_from_civil(y, m, d);
    let sod = hh as i64 * 3600 + mm as i64 * 60 + ss as i64 - offset_secs;
    let total = days * 86_400 + sod;
    if total < 0 {
        return None;
    }
    Some(total as u64)
}

fn parse_date(s: &str) -> Option<(i64, u32, u32)> {
    let mut it = s.split('-');
    let y: i64 = it.next()?.parse().ok()?;
    let m: u32 = it.next()?.parse().ok()?;
    let d: u32 = it.next()?.parse().ok()?;
    if it.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some((y, m, d))
}

fn split_timezone(s: &str) -> Option<(&str, i64)> {
    if let Some(t) = s.strip_suffix('Z').or_else(|| s.strip_suffix('z')) {
        return Some((t, 0));
    }
    let bytes = s.as_bytes();
    let mut pos = None;
    for (i, &b) in bytes.iter().enumerate() {
        if (b == b'+' || b == b'-') && i >= 8 {
            pos = Some(i);
        }
    }
    let i = pos?;
    let time_part = &s[..i];
    let off = &s[i..];
    Some((time_part, parse_tz_offset(off)?))
}

fn parse_tz_offset(s: &str) -> Option<i64> {
    let sign = match s.as_bytes().first()? {
        b'+' => 1i64,
        b'-' => -1i64,
        _ => return None,
    };
    let body = s[1..].replace(':', "");
    let (h, m) = match body.len() {
        2 => (body.parse::<i64>().ok()?, 0),
        4 => (
            body[..2].parse::<i64>().ok()?,
            body[2..].parse::<i64>().ok()?,
        ),
        _ => return None,
    };
    if h > 23 || m > 59 {
        return None;
    }
    Some(sign * (h * 3600 + m * 60))
}

fn parse_time_of_day(s: &str) -> Option<(u32, u32, u32)> {
    let time_only = s.split('.').next()?;
    let mut it = time_only.split(':');
    let hh: u32 = it.next()?.parse().ok()?;
    let mm: u32 = it.next()?.parse().ok()?;
    let ss: u32 = it.next().unwrap_or("0").parse().ok()?;
    if it.next().is_some() || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    Some((hh, mm, ss))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn standalone_state() -> ApiState {
        let engine = std::sync::Arc::new(broker_rules::RuleEngine::new(
            16,
            broker_rules::BackpressurePolicy::DropOldest,
        ));
        ApiState::standalone(engine)
    }

    async fn response_parts(response: Response) -> (StatusCode, serde_json::Value) {
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("trace body is small and readable");
        if bytes.is_empty() {
            return (status, serde_json::Value::Null);
        }
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("trace body is JSON");
        (status, body)
    }

    fn valid_body(name: &str) -> Bytes {
        Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "name": name,
                "type": "topic",
                "topic": "sensors/#",
            }))
            .expect("valid body is JSON"),
        )
    }

    #[test]
    fn empty_registry_lists_nothing() {
        let store = TraceStore::new();
        assert!(store.list().is_empty());
    }

    #[tokio::test]
    async fn create_list_clear_round_trip() {
        let state = standalone_state();
        let (status, body) = response_parts(list_traces(State(state.clone())).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, serde_json::json!([]));

        let (status, created) =
            response_parts(create_trace(State(state.clone()), valid_body("trace-one")).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(created["name"], serde_json::json!("trace-one"));
        assert_eq!(created["type"], serde_json::json!("topic"));
        assert_eq!(created["topic"], serde_json::json!("sensors/#"));

        let (status, listed) = response_parts(list_traces(State(state.clone())).await).await;
        assert_eq!(status, StatusCode::OK);
        let items = listed.as_array().expect("list is an array");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["name"], serde_json::json!("trace-one"));

        let (status, _) = response_parts(clear_traces(State(state.clone())).await).await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        let (status, body) = response_parts(list_traces(State(state.clone())).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, serde_json::json!([]));
    }

    #[tokio::test]
    async fn duplicate_name_is_rejected() {
        let state = standalone_state();
        let (status, _) =
            response_parts(create_trace(State(state.clone()), valid_body("dup-trace")).await).await;
        assert_eq!(status, StatusCode::OK);

        let (status, err) =
            response_parts(create_trace(State(state.clone()), valid_body("dup-trace")).await).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(err["code"], serde_json::json!("ALREADY_EXISTS"));

        let (status, listed) = response_parts(list_traces(State(state.clone())).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(listed.as_array().expect("list is array").len(), 1);
    }

    #[tokio::test]
    async fn duplicate_condition_is_rejected() {
        let state = standalone_state();
        let (status, _) =
            response_parts(create_trace(State(state.clone()), valid_body("first-one")).await).await;
        assert_eq!(status, StatusCode::OK);

        let second = Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "name": "second-one",
                "type": "topic",
                "topic": "sensors/#",
            }))
            .expect("second body is JSON"),
        );
        let (status, err) = response_parts(create_trace(State(state.clone()), second).await).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(err["code"], serde_json::json!("DUPLICATE_CONDITION"));
    }

    #[tokio::test]
    async fn bad_filters_are_rejected_without_applying() {
        let state = standalone_state();
        let now = now_epoch_secs();
        let bad_bodies = vec![
            serde_json::json!({}),
            serde_json::json!({"name": "bad-one"}),
            serde_json::json!({"type": "topic", "topic": "sensors/#"}),
            serde_json::json!({"name": "bad-one", "type": "topic"}),
            serde_json::json!({"name": "bad/one", "type": "topic", "topic": "a/#"}),
            serde_json::json!({"name": "1bad", "type": "topic", "topic": "a/#"}),
            serde_json::json!({"name": "bad-one", "type": "unknown", "unknown": "x"}),
            serde_json::json!({"name": "bad-one", "type": "topic", "topic": "a/#/x"}),
            serde_json::json!({"name": "bad-one", "type": "ip_address", "ip_address": "not-an-ip"}),
            serde_json::json!({"name": "bad-one", "type": "topic", "topic": "a/#", "payload_encode": "bad"}),
            serde_json::json!({"name": "bad-one", "type": "topic", "topic": "a/#", "formatter": "bad"}),
            serde_json::json!({"name": "bad-one", "type": "topic", "topic": "a/#", "start_at": now + 600, "end_at": now + 100}),
            serde_json::json!({"name": "bad-one", "type": "topic", "topic": "a/#", "end_at": now - 10}),
            serde_json::json!([]),
            serde_json::json!("topic"),
        ];
        for bad in bad_bodies {
            let body = Bytes::from(serde_json::to_vec(&bad).expect("bad body is JSON"));
            let (status, err) =
                response_parts(create_trace(State(state.clone()), body).await).await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "body {bad} must be rejected"
            );
            assert_eq!(err["code"], serde_json::json!("INVALID_PARAMS"));
        }
        let (status, body) = response_parts(list_traces(State(state.clone())).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, serde_json::json!([]), "failed writes must not apply");

        let (status, _) =
            response_parts(create_trace(State(state.clone()), Bytes::new()).await).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn every_filter_kind_round_trips() {
        for (trace_type, field, filter) in [
            ("clientid", "clientid", "device-001"),
            ("topic", "topic", "devices/+/temp"),
            ("ip_address", "ip_address", "192.168.0.5"),
            ("ruleid", "ruleid", "rule-1"),
        ] {
            let state = standalone_state();
            let body = Bytes::from(
                serde_json::to_vec(&serde_json::json!({
                    "name": format!("trace-{trace_type}"),
                    "type": trace_type,
                    field: filter,
                }))
                .expect("kind body is JSON"),
            );
            let (status, created) =
                response_parts(create_trace(State(state.clone()), body).await).await;
            assert_eq!(status, StatusCode::OK, "kind {trace_type} must create");
            assert_eq!(created["type"], serde_json::json!(trace_type));
            assert_eq!(created[field], serde_json::json!(filter));
            assert!(created["start_at"].is_string());
            assert!(created["end_at"].is_string());
            assert!(created["log_size"].is_object());
        }
    }

    #[test]
    fn full_registry_rejects_with_invalid_params() {
        let store = TraceStore::new();
        let now = now_epoch_secs();
        for i in 0..MAX_TRACES {
            let session = TraceSession {
                name: format!("trace-{i:02}"),
                trace_type: "topic".to_string(),
                filter: format!("sensors/{i:02}/#"),
                enable: true,
                payload_encode: "text".to_string(),
                formatter: "text".to_string(),
                start_at: now,
                end_at: now + 600,
            };
            assert!(store.insert(session).is_ok());
        }
        let extra = TraceSession {
            name: "trace-extra".to_string(),
            trace_type: "topic".to_string(),
            filter: "sensors/extra/#".to_string(),
            enable: true,
            payload_encode: "text".to_string(),
            formatter: "text".to_string(),
            start_at: now,
            end_at: now + 600,
        };
        assert_eq!(store.insert(extra), Err(TraceInsertError::Full));
        assert_eq!(store.list().len(), MAX_TRACES);
    }

    #[tokio::test]
    async fn delete_single_session_removes_it_and_misses_again() {
        let state = standalone_state();
        let (status, _) =
            response_parts(create_trace(State(state.clone()), valid_body("trace-gone")).await)
                .await;
        assert_eq!(status, StatusCode::OK);

        let (status, listed) = response_parts(list_traces(State(state.clone())).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(listed.as_array().expect("list is array").len(), 1);

        let response = delete_trace(State(state.clone()), Path("trace-gone".to_string())).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let (status, body) = response_parts(list_traces(State(state.clone())).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, serde_json::json!([]));

        let (status, err) = response_parts(
            delete_trace(State(state.clone()), Path("trace-gone".to_string())).await,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(err["code"], serde_json::json!("NOT_FOUND"));

        let (status, err) = response_parts(
            delete_trace(State(state.clone()), Path("never-stored".to_string())).await,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(err["code"], serde_json::json!("NOT_FOUND"));
    }

    #[test]
    fn stop_keeps_session_listed_but_stopped() {
        let store = TraceStore::new();
        let now = now_epoch_secs();
        let session = TraceSession {
            name: "stop-me".to_string(),
            trace_type: "topic".to_string(),
            filter: "sensors/#".to_string(),
            enable: true,
            payload_encode: "text".to_string(),
            formatter: "text".to_string(),
            start_at: now,
            end_at: now + 600,
        };
        store.insert(session).expect("insert works");
        let stopped = store.stop("stop-me").expect("stop works");
        assert!(!stopped.enable);
        let size = store.log_len("stop-me");
        assert_eq!(
            stopped.to_json(now, size)["status"],
            serde_json::json!("stopped")
        );
        assert!(store.get("stop-me").is_some());
        assert!(store.remove("stop-me"));
        assert!(store.get("stop-me").is_none());
    }

    #[tokio::test]
    async fn stop_halts_capture_but_keeps_data_readable() {
        let state = standalone_state();
        let (status, _) =
            response_parts(create_trace(State(state.clone()), valid_body("trace-stop")).await)
                .await;
        assert_eq!(status, StatusCode::OK);
        assert!(state
            .traces
            .append_log("trace-stop", b"publish sensors/temp {\"t\": 21}\n"));

        let (status, stopped) =
            response_parts(stop_trace(State(state.clone()), Path("trace-stop".to_string())).await)
                .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(stopped["name"], serde_json::json!("trace-stop"));
        assert_eq!(stopped["status"], serde_json::json!("stopped"));

        let (status, listed) = response_parts(list_traces(State(state.clone())).await).await;
        assert_eq!(status, StatusCode::OK);
        let items = listed.as_array().expect("list is an array");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["name"], serde_json::json!("trace-stop"));
        assert_eq!(items[0]["status"], serde_json::json!("stopped"));

        let response = download_trace(State(state.clone()), Path("trace-stop".to_string())).await;
        let (status, _, bytes) = download_parts(response).await;
        assert_eq!(status, StatusCode::OK);
        assert!(!bytes.is_empty(), "stopped session keeps its data");
        let text = String::from_utf8(bytes).expect("download is text");
        assert!(text.contains("publish sensors/temp"));

        let (status, body) = response_parts(
            get_trace_log(
                State(state.clone()),
                Path("trace-stop".to_string()),
                log_page_params(1, 100),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let entries = body["data"].as_array().expect("log has data");
        assert!(!entries.is_empty(), "stopped session keeps its log");

        let (status, again) =
            response_parts(stop_trace(State(state.clone()), Path("trace-stop".to_string())).await)
                .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(again["status"], serde_json::json!("stopped"));
    }

    #[tokio::test]
    async fn stop_unknown_is_not_found() {
        let state = standalone_state();
        let (status, err) = response_parts(
            stop_trace(State(state.clone()), Path("never-stored".to_string())).await,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(err["code"], serde_json::json!("NOT_FOUND"));
    }

    async fn download_parts(response: Response) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("download body is readable")
            .to_vec();
        (status, headers, bytes)
    }

    fn content_type_of(headers: &axum::http::HeaderMap) -> String {
        headers
            .get("content-type")
            .expect("download has a content type")
            .to_str()
            .expect("content type is ASCII")
            .to_string()
    }

    #[tokio::test]
    async fn download_serves_captured_bytes_and_misses_unknown() {
        let state = standalone_state();
        let (status, _) =
            response_parts(create_trace(State(state.clone()), valid_body("trace-dl")).await).await;
        assert_eq!(status, StatusCode::OK);

        // An uncaptured session downloads as an empty body, never a
        // synthesised header.
        let response = download_trace(State(state.clone()), Path("trace-dl".to_string())).await;
        let (status, _, bytes) = download_parts(response).await;
        assert_eq!(status, StatusCode::OK);
        assert!(bytes.is_empty(), "empty session must download empty");

        // Simulated captured traffic lands in the same bounded buffer the
        // download serves.
        assert!(state
            .traces
            .append_log("trace-dl", b"publish sensors/temp {\"t\": 21}\n"));

        let response = download_trace(State(state.clone()), Path("trace-dl".to_string())).await;
        let (status, headers, bytes) = download_parts(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(content_type_of(&headers), TRACE_DOWNLOAD_CONTENT_TYPE);
        let disposition = headers
            .get("content-disposition")
            .expect("download has a disposition")
            .to_str()
            .expect("disposition is ASCII")
            .to_string();
        assert!(
            disposition.contains("trace-dl.log"),
            "disposition must name the file, got {disposition}"
        );
        assert!(!bytes.is_empty(), "download must carry log bytes");
        let text = String::from_utf8(bytes).expect("download is text");
        assert!(
            text.contains("publish sensors/temp"),
            "download must carry appended traffic"
        );

        let (status, err) = response_parts(
            download_trace(State(state.clone()), Path("never-stored".to_string())).await,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(err["code"], serde_json::json!("NOT_FOUND"));
    }

    #[tokio::test]
    async fn download_after_delete_is_not_found() {
        let state = standalone_state();
        let (status, _) =
            response_parts(create_trace(State(state.clone()), valid_body("trace-dl-gone")).await)
                .await;
        assert_eq!(status, StatusCode::OK);

        let response = delete_trace(State(state.clone()), Path("trace-dl-gone".to_string())).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let (status, err) = response_parts(
            download_trace(State(state.clone()), Path("trace-dl-gone".to_string())).await,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(err["code"], serde_json::json!("NOT_FOUND"));
    }

    #[test]
    fn capture_buffer_is_bounded_and_keeps_newest() {
        let store = TraceStore::new();
        let now = now_epoch_secs();
        store
            .insert(TraceSession {
                name: "cap-me".to_string(),
                trace_type: "topic".to_string(),
                filter: "sensors/#".to_string(),
                enable: true,
                payload_encode: "text".to_string(),
                formatter: "text".to_string(),
                start_at: now,
                end_at: now + 600,
            })
            .expect("insert works");
        // A fresh session starts empty: reads serve only what the packet
        // path appends, never a synthesised header.
        assert_eq!(store.log_len("cap-me"), 0);

        // One over-long append keeps only its tail.
        let big = vec![b'x'; MAX_TRACE_LOG_BYTES + 1024];
        assert!(store.append_log("cap-me", &big));
        assert_eq!(store.log_len("cap-me"), MAX_TRACE_LOG_BYTES);
        let kept = store.read_log("cap-me").expect("log exists");
        assert!(kept.iter().all(|b| *b == b'x'));

        // Steady appends rotate oldest-first: the newest marker survives.
        assert!(store.append_log("cap-me", b"TAIL-MARKER\n"));
        let rotated = store.read_log("cap-me").expect("log exists");
        assert_eq!(rotated.len(), MAX_TRACE_LOG_BYTES);
        assert!(
            rotated.ends_with(b"TAIL-MARKER\n"),
            "newest bytes must survive rotation"
        );

        // Unknown sessions drop bytes and read as missing.
        assert!(!store.append_log("never-stored", b"data"));
        assert!(store.read_log("never-stored").is_none());
        assert_eq!(store.log_len("never-stored"), 0);
    }

    #[tokio::test]
    async fn log_size_reports_captured_bytes() {
        let state = standalone_state();
        let (status, created) =
            response_parts(create_trace(State(state.clone()), valid_body("trace-size")).await)
                .await;
        assert_eq!(status, StatusCode::OK);
        let initial = created["log_size"]["indramqtt@127.0.0.1"]
            .as_u64()
            .expect("log_size renders a byte count");
        assert_eq!(
            initial, 0,
            "fresh sessions start empty (no synthesised header)"
        );

        assert!(state.traces.append_log("trace-size", b"extra line\n"));
        let (status, listed) = response_parts(list_traces(State(state.clone())).await).await;
        assert_eq!(status, StatusCode::OK);
        let items = listed.as_array().expect("list is an array");
        assert_eq!(items.len(), 1);
        let reported = items[0]["log_size"]["indramqtt@127.0.0.1"]
            .as_u64()
            .expect("list renders a byte count");
        assert_eq!(reported, state.traces.log_len("trace-size") as u64);
        assert!(reported > initial);
    }

    #[tokio::test]
    async fn clear_drops_capture_buffers() {
        let state = standalone_state();
        let (status, _) =
            response_parts(create_trace(State(state.clone()), valid_body("trace-clear-dl")).await)
                .await;
        assert_eq!(status, StatusCode::OK);
        // A fresh session starts empty; the first append makes it non-empty.
        assert_eq!(state.traces.log_len("trace-clear-dl"), 0);
        assert!(state
            .traces
            .append_log("trace-clear-dl", b"publish a/b x\n"));
        assert!(state.traces.log_len("trace-clear-dl") > 0);

        let (status, _) = response_parts(clear_traces(State(state.clone())).await).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(state.traces.log_len("trace-clear-dl"), 0);

        let (status, err) = response_parts(
            download_trace(State(state.clone()), Path("trace-clear-dl".to_string())).await,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(err["code"], serde_json::json!("NOT_FOUND"));
    }

    fn log_page_params(page: u32, limit: u32) -> PageParams {
        PageParams { page, limit }
    }

    #[tokio::test]
    async fn trace_log_returns_entries_with_paging_and_misses_unknown() {
        let state = standalone_state();
        let (status, _) =
            response_parts(create_trace(State(state.clone()), valid_body("trace-log")).await).await;
        assert_eq!(status, StatusCode::OK);

        // An uncaptured session reads as an empty page, never a
        // synthesised header.
        let (status, empty) = response_parts(
            get_trace_log(
                State(state.clone()),
                Path("trace-log".to_string()),
                log_page_params(1, 100),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(empty["data"], serde_json::json!([]));
        assert_eq!(empty["meta"]["count"], serde_json::json!(0));

        // Simulated captured traffic lands in the same bounded buffer the
        // inline log read serves.
        assert!(state
            .traces
            .append_log("trace-log", b"publish sensors/temp {\"t\": 21}\n"));
        assert!(state
            .traces
            .append_log("trace-log", b"publish sensors/hum {\"h\": 55}\n"));

        let (status, body) = response_parts(
            get_trace_log(
                State(state.clone()),
                Path("trace-log".to_string()),
                log_page_params(1, 100),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let entries = body["data"].as_array().expect("log has data");
        assert_eq!(
            entries.len(),
            2,
            "log must carry exactly the appended traffic, got {entries:?}"
        );
        let joined = entries
            .iter()
            .map(|entry| entry["content"].as_str().unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            joined.contains("publish sensors/temp"),
            "log must carry appended traffic"
        );
        assert_eq!(body["meta"]["count"], serde_json::json!(entries.len()));
        assert_eq!(body["meta"]["page"], serde_json::json!(1));
        assert_eq!(body["meta"]["limit"], serde_json::json!(100));
        assert_eq!(body["meta"]["hasnext"], serde_json::json!(false));
        for (index, entry) in entries.iter().enumerate() {
            assert_eq!(
                entry["position"],
                serde_json::json!(index as u64),
                "positions must be zero-based line indexes"
            );
            assert!(
                entry["content"].is_string(),
                "every entry must carry text content"
            );
        }

        let (status, err) = response_parts(
            get_trace_log(
                State(state.clone()),
                Path("never-stored".to_string()),
                log_page_params(1, 100),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(err["code"], serde_json::json!("NOT_FOUND"));
    }

    #[tokio::test]
    async fn trace_log_paging_slices_after_filtering() {
        let state = standalone_state();
        let (status, _) =
            response_parts(create_trace(State(state.clone()), valid_body("trace-log-page")).await)
                .await;
        assert_eq!(status, StatusCode::OK);
        assert!(state
            .traces
            .append_log("trace-log-page", b"line-one\nline-two\nline-three\n"));

        let (status, first) = response_parts(
            get_trace_log(
                State(state.clone()),
                Path("trace-log-page".to_string()),
                log_page_params(1, 2),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(first["data"].as_array().expect("data").len(), 2);
        assert_eq!(first["meta"]["count"], serde_json::json!(3));
        assert_eq!(first["meta"]["hasnext"], serde_json::json!(true));
        assert_eq!(first["data"][0]["position"], serde_json::json!(0));
        assert_eq!(first["data"][1]["position"], serde_json::json!(1));

        let (status, second) = response_parts(
            get_trace_log(
                State(state.clone()),
                Path("trace-log-page".to_string()),
                log_page_params(2, 2),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(second["data"].as_array().expect("data").len(), 1);
        assert_eq!(second["meta"]["hasnext"], serde_json::json!(false));
        assert_eq!(second["data"][0]["position"], serde_json::json!(2));
        assert_ne!(first["data"][0]["content"], second["data"][0]["content"]);

        let (status, empty) = response_parts(
            get_trace_log(
                State(state.clone()),
                Path("trace-log-page".to_string()),
                log_page_params(3, 2),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(empty["data"], serde_json::json!([]));
        assert_eq!(empty["meta"]["count"], serde_json::json!(3));
        assert_eq!(empty["meta"]["hasnext"], serde_json::json!(false));
    }

    #[tokio::test]
    async fn trace_log_after_delete_is_not_found() {
        let state = standalone_state();
        let (status, _) =
            response_parts(create_trace(State(state.clone()), valid_body("trace-log-gone")).await)
                .await;
        assert_eq!(status, StatusCode::OK);

        let response = delete_trace(State(state.clone()), Path("trace-log-gone".to_string())).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let (status, err) = response_parts(
            get_trace_log(
                State(state.clone()),
                Path("trace-log-gone".to_string()),
                log_page_params(1, 100),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(err["code"], serde_json::json!("NOT_FOUND"));
    }

    fn log_detail_query(position: &str) -> Query<HashMap<String, String>> {
        let mut map = HashMap::new();
        map.insert("position".to_string(), position.to_string());
        Query(map)
    }

    fn empty_detail_query() -> Query<HashMap<String, String>> {
        Query(HashMap::new())
    }

    #[tokio::test]
    async fn trace_log_detail_returns_entry_and_misses_unknown() {
        let state = standalone_state();
        let (status, _) =
            response_parts(create_trace(State(state.clone()), valid_body("trace-detail")).await)
                .await;
        assert_eq!(status, StatusCode::OK);

        // Simulated captured traffic lands in the same bounded buffer the
        // detail read serves.
        assert!(state
            .traces
            .append_log("trace-detail", b"publish sensors/temp {\"t\": 21}\n"));
        assert!(state
            .traces
            .append_log("trace-detail", b"publish sensors/hum {\"h\": 55}\n"));

        let (status, first) = response_parts(
            get_trace_log_detail(
                State(state.clone()),
                Path("trace-detail".to_string()),
                log_detail_query("0"),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(first["position"], serde_json::json!(0));
        assert!(
            first["content"]
                .as_str()
                .unwrap_or_default()
                .contains("publish sensors/temp"),
            "detail at 0 must carry appended traffic, got {first:?}"
        );

        let (status, second) = response_parts(
            get_trace_log_detail(
                State(state.clone()),
                Path("trace-detail".to_string()),
                log_detail_query("1"),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(second["position"], serde_json::json!(1));
        assert!(
            second["content"]
                .as_str()
                .unwrap_or_default()
                .contains("publish sensors/hum"),
            "detail at 1 must carry appended traffic, got {second:?}"
        );

        let (status, missing_session) = response_parts(
            get_trace_log_detail(
                State(state.clone()),
                Path("never-stored".to_string()),
                log_detail_query("0"),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(missing_session["code"], serde_json::json!("NOT_FOUND"));

        let (status, missing_position) = response_parts(
            get_trace_log_detail(
                State(state.clone()),
                Path("trace-detail".to_string()),
                log_detail_query("999999"),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(missing_position["code"], serde_json::json!("NOT_FOUND"));
    }

    #[tokio::test]
    async fn trace_log_detail_rejects_missing_or_malformed_position() {
        let state = standalone_state();
        let (status, _) = response_parts(
            create_trace(State(state.clone()), valid_body("trace-detail-bad")).await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, err) = response_parts(
            get_trace_log_detail(
                State(state.clone()),
                Path("trace-detail-bad".to_string()),
                empty_detail_query(),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(err["code"], serde_json::json!("INVALID_PARAMS"));

        for bad in ["abc", "-1", "1.5", ""] {
            let (status, err) = response_parts(
                get_trace_log_detail(
                    State(state.clone()),
                    Path("trace-detail-bad".to_string()),
                    log_detail_query(bad),
                )
                .await,
            )
            .await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "position {bad} must be rejected"
            );
            assert_eq!(err["code"], serde_json::json!("INVALID_PARAMS"));
        }
    }

    #[tokio::test]
    async fn trace_log_detail_after_delete_is_not_found() {
        let state = standalone_state();
        let (status, _) = response_parts(
            create_trace(State(state.clone()), valid_body("trace-detail-gone")).await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Capture one line first: an uncaptured session has no position 0.
        assert!(state
            .traces
            .append_log("trace-detail-gone", b"publish sensors/temp x\n"));
        let (status, detail) = response_parts(
            get_trace_log_detail(
                State(state.clone()),
                Path("trace-detail-gone".to_string()),
                log_detail_query("0"),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(detail["position"], serde_json::json!(0));

        let response =
            delete_trace(State(state.clone()), Path("trace-detail-gone".to_string())).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let (status, err) = response_parts(
            get_trace_log_detail(
                State(state.clone()),
                Path("trace-detail-gone".to_string()),
                log_detail_query("0"),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(err["code"], serde_json::json!("NOT_FOUND"));
    }

    fn insert_running(
        store: &TraceStore,
        name: &str,
        trace_type: &str,
        filter: &str,
    ) -> TraceSession {
        let now = now_epoch_secs();
        let session = TraceSession {
            name: name.to_string(),
            trace_type: trace_type.to_string(),
            filter: filter.to_string(),
            enable: true,
            payload_encode: "text".to_string(),
            formatter: "text".to_string(),
            start_at: now,
            end_at: now + 600,
        };
        store.insert(session.clone()).expect("insert works");
        session
    }

    #[test]
    fn capture_publish_matches_topic_clientid_and_peerhost() {
        let store = TraceStore::new();
        insert_running(&store, "cap-topic", "topic", "sensors/#");
        insert_running(&store, "cap-client", "clientid", "device-1");
        insert_running(&store, "cap-ip", "ip_address", "10.0.0.9");

        store.capture_publish("device-1", Some("10.0.0.9"), "sensors/temp", b"hello");

        let topic_log = store.read_log("cap-topic").expect("log exists");
        let topic_text = String::from_utf8(topic_log).expect("text");
        assert!(
            topic_text.contains("sensors/temp") && topic_text.contains("hello"),
            "topic session must capture matching publish, got {topic_text:?}"
        );
        let client_log = store.read_log("cap-client").expect("log exists");
        let client_text = String::from_utf8(client_log).expect("text");
        assert!(
            client_text.contains("sensors/temp") && client_text.contains("device-1"),
            "clientid session must capture its publisher, got {client_text:?}"
        );
        let ip_log = store.read_log("cap-ip").expect("log exists");
        assert!(
            String::from_utf8(ip_log)
                .expect("text")
                .contains("sensors/temp"),
            "ip session must capture its peer address"
        );

        // Non-matching publishes capture nothing new.
        let before = store.log_len("cap-client");
        store.capture_publish("other-device", Some("10.0.0.10"), "other/topic", b"hello");
        assert_eq!(store.log_len("cap-client"), before);
        let topic_before = store.log_len("cap-topic");
        store.capture_publish("device-1", Some("10.0.0.9"), "other/topic", b"hello");
        assert_eq!(store.log_len("cap-topic"), topic_before);
    }

    #[test]
    fn capture_publish_skips_stopped_expired_and_ruleid() {
        let store = TraceStore::new();
        let now = now_epoch_secs();
        store
            .insert(TraceSession {
                name: "cap-stopped".to_string(),
                trace_type: "topic".to_string(),
                filter: "sensors/#".to_string(),
                enable: false,
                payload_encode: "text".to_string(),
                formatter: "text".to_string(),
                start_at: now,
                end_at: now + 600,
            })
            .expect("insert works");
        store
            .insert(TraceSession {
                name: "cap-expired".to_string(),
                trace_type: "topic".to_string(),
                filter: "expired/#".to_string(),
                enable: true,
                payload_encode: "text".to_string(),
                formatter: "text".to_string(),
                start_at: now.saturating_sub(1200),
                end_at: now.saturating_sub(600),
            })
            .expect("insert works");
        store
            .insert(TraceSession {
                name: "cap-rule".to_string(),
                trace_type: "ruleid".to_string(),
                filter: "rule-1".to_string(),
                enable: true,
                payload_encode: "text".to_string(),
                formatter: "text".to_string(),
                start_at: now,
                end_at: now + 600,
            })
            .expect("insert works");

        store.capture_publish("any", Some("10.0.0.1"), "sensors/temp", b"hello");
        store.capture_publish("any", Some("10.0.0.1"), "expired/x", b"hello");
        assert_eq!(store.log_len("cap-stopped"), 0);
        assert_eq!(store.log_len("cap-expired"), 0);
        assert_eq!(store.log_len("cap-rule"), 0);
    }

    #[test]
    fn capture_publish_respects_encoding_and_payload_bound() {
        let store = TraceStore::new();
        let now = now_epoch_secs();
        store
            .insert(TraceSession {
                name: "cap-hidden".to_string(),
                trace_type: "topic".to_string(),
                filter: "hidden/#".to_string(),
                enable: true,
                payload_encode: "hidden".to_string(),
                formatter: "text".to_string(),
                start_at: now,
                end_at: now + 600,
            })
            .expect("insert works");
        store
            .insert(TraceSession {
                name: "cap-hex".to_string(),
                trace_type: "topic".to_string(),
                filter: "hexed/#".to_string(),
                enable: true,
                payload_encode: "hex".to_string(),
                formatter: "text".to_string(),
                start_at: now,
                end_at: now + 600,
            })
            .expect("insert works");
        store
            .insert(TraceSession {
                name: "cap-big".to_string(),
                trace_type: "topic".to_string(),
                filter: "big/#".to_string(),
                enable: true,
                payload_encode: "text".to_string(),
                formatter: "text".to_string(),
                start_at: now,
                end_at: now + 600,
            })
            .expect("insert works");

        store.capture_publish("dev", None, "hidden/x", b"secret-bytes");
        let hidden = String::from_utf8(store.read_log("cap-hidden").expect("log")).expect("text");
        assert!(
            hidden.contains("hidden/x") && !hidden.contains("secret-bytes"),
            "hidden encoding must omit the payload, got {hidden:?}"
        );

        store.capture_publish("dev", None, "hexed/x", b"AB");
        let hexed = String::from_utf8(store.read_log("cap-hex").expect("log")).expect("text");
        assert!(
            hexed.contains("hexed/x") && hexed.contains("4142"),
            "hex encoding must render payload hex, got {hexed:?}"
        );

        let big = vec![b'z'; MAX_TRACE_PAYLOAD_BYTES + 64];
        store.capture_publish("dev", None, "big/x", &big);
        let kept = store.read_log("cap-big").expect("log");
        assert!(
            kept.len() < big.len() + 128,
            "one capture must stay near the payload cap, got {} bytes",
            kept.len()
        );
        assert!(
            String::from_utf8_lossy(&kept).contains("truncated"),
            "clipped payloads must say so"
        );
    }

    #[tokio::test]
    async fn trace_lifecycle_drives_the_global_flag() {
        let state = standalone_state();
        assert!(!state.tracing.is_enabled());
        let (status, _) =
            response_parts(create_trace(State(state.clone()), valid_body("trace-flag")).await)
                .await;
        assert_eq!(status, StatusCode::OK);
        assert!(state.tracing.is_enabled());
        let (status, _) =
            response_parts(stop_trace(State(state.clone()), Path("trace-flag".to_string())).await)
                .await;
        assert_eq!(status, StatusCode::OK);
        assert!(!state.tracing.is_enabled());
    }
}
