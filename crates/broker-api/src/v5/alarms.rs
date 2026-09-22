//! Active-alarm directory for the v5 management API.
//!
//! Covers `GET /alarms` (paged list of active alarms),
//! `DELETE /alarms` (clear all alarms) and `POST /alarms/force_deactivate`
//! (deactivate one named alarm, or all when no name is given).
//! Single-node, management-plane
//! only: nothing here runs on the per-message path, so delivery never
//! takes a management lock and no new buffering is added to fan-out or
//! fan-in.
//!
//! Store bounds (both stated here and enforced below):
//! - at most [`MAX_ALARMS`] active alarms and at most [`MAX_ALARMS`]
//!   deactivated records; activating past the cap evicts the oldest
//!   active entry (by activation time) instead of growing without limit;
//! - `name` is capped at 256 chars and `message` at 1024 chars, so one
//!   entry cannot balloon memory;
//! - `details` is always a JSON object (non-objects become `{}`), keeping
//!   per-entry memory small and the response shape stable.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use bytes::Bytes;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::RwLock;

use crate::pagination::{meta_page, paginate, PageParams};
use crate::ApiState;

/// Upper bound for stored alarms (active and deactivated each). Activating
/// past this size evicts the oldest active entry instead of growing the
/// map without limit.
pub const MAX_ALARMS: usize = 1000;
/// Longest accepted alarm `name`.
const MAX_NAME_LEN: usize = 256;
/// Longest accepted alarm `message`.
const MAX_MESSAGE_LEN: usize = 1024;

/// Node name rendered on every alarm row (single node).
const NODE_NAME: &str = "indramqtt@127.0.0.1";

/// One active alarm: identifier (`name`), human detail (`message`),
/// structured detail (`details`, always an object) and activation time
/// (`activate_at_us`, microseconds since the Unix epoch).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlarmEntry {
    pub name: String,
    pub message: String,
    pub details: serde_json::Value,
    pub activate_at_us: u64,
}

impl AlarmEntry {
    fn to_json(&self, now_us: u64) -> serde_json::Value {
        let duration = now_us.saturating_sub(self.activate_at_us);
        serde_json::json!({
            "node": NODE_NAME,
            "name": self.name,
            "message": self.message,
            "details": self.details,
            "duration": duration,
            "activate_at": micros_to_rfc3339(self.activate_at_us),
            "deactivate_at": "infinity",
        })
    }
}

/// One deactivated record: the alarm as it was plus when it cleared
/// (`deactivate_at_us`, microseconds since the Unix epoch). Kept so the
/// `activated=false` list has a stable shape for the follow-up task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeactivatedAlarm {
    pub name: String,
    pub message: String,
    pub details: serde_json::Value,
    pub activate_at_us: u64,
    pub deactivate_at_us: u64,
}

impl DeactivatedAlarm {
    fn to_json(&self) -> serde_json::Value {
        let duration = self.deactivate_at_us.saturating_sub(self.activate_at_us);
        serde_json::json!({
            "node": NODE_NAME,
            "name": self.name,
            "message": self.message,
            "details": self.details,
            "duration": duration,
            "activate_at": micros_to_rfc3339(self.activate_at_us),
            "deactivate_at": micros_to_rfc3339(self.deactivate_at_us),
        })
    }
}

/// In-memory alarm directory: active map plus deactivated history.
///
/// Single node behind two short locks; every method finishes quickly and
/// no delivery path touches it, so management reads never block messaging.
pub struct AlarmStore {
    active: RwLock<HashMap<String, AlarmEntry>>,
    deactivated: RwLock<HashMap<String, DeactivatedAlarm>>,
}

impl AlarmStore {
    /// Empty directory.
    pub fn new() -> Self {
        Self {
            active: RwLock::new(HashMap::new()),
            deactivated: RwLock::new(HashMap::new()),
        }
    }

    /// Raise (or return) the named active alarm. Idempotent: an already
    /// active name returns its stored entry without moving its activation
    /// time. A name with a deactivated record re-activates with a fresh
    /// activation time. Past [`MAX_ALARMS`] active entries the oldest
    /// entry is evicted first.
    pub fn activate(&self, name: &str, message: &str, details: serde_json::Value) -> AlarmEntry {
        let name = truncate(name.trim(), MAX_NAME_LEN).to_string();
        let message = truncate(message, MAX_MESSAGE_LEN).to_string();
        let details = normalise_details(details);
        let now = now_micros();
        let mut active = self.active.write().expect("alarm store lock");
        if let Some(existing) = active.get(&name) {
            return existing.clone();
        }
        if active.len() >= MAX_ALARMS {
            evict_oldest_active(&mut active);
        }
        // A fresh activation clears any stale deactivated record first so
        // the same name never sits in both tables at once.
        self.deactivated
            .write()
            .expect("alarm store lock")
            .remove(&name);
        let entry = AlarmEntry {
            name: name.clone(),
            message,
            details,
            activate_at_us: now,
        };
        active.insert(name, entry.clone());
        entry
    }

    /// Snapshot of active alarms sorted by `name` for stable pages.
    pub fn list_active(&self) -> Vec<AlarmEntry> {
        let map = self.active.read().expect("alarm store lock");
        let mut out: Vec<AlarmEntry> = map.values().cloned().collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// Snapshot of deactivated alarms sorted by `name` for stable pages.
    pub fn list_deactivated(&self) -> Vec<DeactivatedAlarm> {
        let map = self.deactivated.read().expect("alarm store lock");
        let mut out: Vec<DeactivatedAlarm> = map.values().cloned().collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// Drop every alarm, active and deactivated. Always succeeds, even
    /// when nothing is stored. Test/administrative helper only; the
    /// `DELETE /alarms` route calls [`Self::deactivate_all`] so cleared
    /// alarms remain visible under `?activated=false`.
    pub fn clear(&self) {
        self.active.write().expect("alarm store lock").clear();
        self.deactivated.write().expect("alarm store lock").clear();
    }

    /// Deactivate every active alarm into the deactivated history.
    /// Always succeeds, even when nothing is stored. Returns the number
    /// of alarms moved. Past [`MAX_ALARMS`] deactivated records the
    /// oldest is evicted first. This is what `DELETE /alarms` reports
    /// success for; history is preserved so `?activated=false` keeps
    /// reading it.
    pub fn deactivate_all(&self) -> usize {
        let now = now_micros();
        let entries: Vec<AlarmEntry> = {
            let mut active = self.active.write().expect("alarm store lock");
            active.drain().map(|(_, entry)| entry).collect()
        };
        let moved = entries.len();
        if moved == 0 {
            return 0;
        }
        let mut history = self.deactivated.write().expect("alarm store lock");
        for entry in entries {
            let record = DeactivatedAlarm {
                name: entry.name.clone(),
                message: entry.message,
                details: entry.details,
                activate_at_us: entry.activate_at_us,
                deactivate_at_us: now.max(entry.activate_at_us),
            };
            if history.len() >= MAX_ALARMS && !history.contains_key(&record.name) {
                evict_oldest_deactivated(&mut history);
            }
            history.insert(record.name.clone(), record);
        }
        moved
    }

    /// Move one active alarm to the deactivated history. Returns true when
    /// a live entry was moved, false when nothing was stored under `name`.
    /// Past [`MAX_ALARMS`] deactivated records the oldest is evicted first.
    /// Used by the force-deactivate route for a named alarm.
    pub fn deactivate(&self, name: &str) -> bool {
        let now = now_micros();
        let mut active = self.active.write().expect("alarm store lock");
        let Some(entry) = active.remove(name) else {
            return false;
        };
        drop(active);
        let record = DeactivatedAlarm {
            name: entry.name,
            message: entry.message,
            details: entry.details,
            activate_at_us: entry.activate_at_us,
            deactivate_at_us: now.max(entry.activate_at_us),
        };
        let mut history = self.deactivated.write().expect("alarm store lock");
        if history.len() >= MAX_ALARMS && !history.contains_key(&record.name) {
            evict_oldest_deactivated(&mut history);
        }
        history.insert(record.name.clone(), record);
        true
    }
}

impl Default for AlarmStore {
    fn default() -> Self {
        Self::new()
    }
}

fn evict_oldest_active(map: &mut HashMap<String, AlarmEntry>) {
    let oldest = map
        .iter()
        .min_by_key(|(_, e)| e.activate_at_us)
        .map(|(k, _)| k.clone());
    if let Some(key) = oldest {
        map.remove(&key);
    }
}

fn evict_oldest_deactivated(map: &mut HashMap<String, DeactivatedAlarm>) {
    let oldest = map
        .iter()
        .min_by_key(|(_, e)| e.deactivate_at_us)
        .map(|(k, _)| k.clone());
    if let Some(key) = oldest {
        map.remove(&key);
    }
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn normalise_details(value: serde_json::Value) -> serde_json::Value {
    if value.is_object() {
        value
    } else {
        serde_json::json!({})
    }
}

/// Documented list scope. Only `activated` narrows the read (`false`
/// selects the deactivated history); every other query key is ignored by
/// the extractors so new parameters degrade to the active page instead
/// of a 400.
#[derive(Deserialize, Default)]
pub struct AlarmListQuery {
    #[serde(default)]
    pub activated: Option<String>,
}

fn wants_deactivated(query: &AlarmListQuery) -> bool {
    match query.activated.as_deref() {
        Some(raw) => {
            let lower = raw.trim().to_ascii_lowercase();
            lower == "false" || lower == "0" || lower == "no"
        }
        None => false,
    }
}

/// `GET /alarms`: wrapped page (`data` plus `meta`). An empty store reads
/// as an empty page, never an error. `activated=false` selects the
/// deactivated history; unknown query keys are ignored and malformed
/// `page`/`limit` fall back to defaults via [`PageParams`].
pub async fn list_alarms(
    State(state): State<ApiState>,
    params: PageParams,
    Query(query): Query<AlarmListQuery>,
) -> Response {
    let now = now_micros();
    if wants_deactivated(&query) {
        let rows = state.alarms.list_deactivated();
        let total = rows.len();
        let page_items = paginate(&rows, params.page, params.limit);
        let data: Vec<serde_json::Value> =
            page_items.iter().map(DeactivatedAlarm::to_json).collect();
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "data": data,
                "meta": meta_page(params.page, params.limit, total),
            })),
        )
            .into_response();
    }
    let rows = state.alarms.list_active();
    let total = rows.len();
    let page_items = paginate(&rows, params.page, params.limit);
    let data: Vec<serde_json::Value> = page_items.iter().map(|e| e.to_json(now)).collect();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "data": data,
            "meta": meta_page(params.page, params.limit, total),
        })),
    )
        .into_response()
}

/// `DELETE /alarms`: deactivate every alarm (active entries move to the
/// deactivated history) and report success with 204. Always succeeds,
/// even when nothing is stored. History is preserved so a follow-up
/// `GET /alarms?activated=false` keeps reading what was cleared.
/// Query strings (including unknown keys) are ignored by design.
pub async fn clear_alarms(State(state): State<ApiState>) -> Response {
    state.alarms.deactivate_all();
    StatusCode::NO_CONTENT.into_response()
}

/// `POST /alarms/force_deactivate`: deactivate alarms unconditionally and
/// report success with 204, even when nothing is stored.
///
/// A JSON body holding a non-empty `name` deactivates just that alarm;
/// any other body (missing, empty, or without a usable `name`) deactivates
/// everything, mirroring `DELETE /alarms`. A named alarm that is absent or
/// already deactivated still reports success, so the call is idempotent.
/// Active entries move to the deactivated history, so a follow-up
/// `GET /alarms` reads empty while `GET /alarms?activated=false` keeps
/// what was cleared. Management-plane only: one short store lock, no work
/// on the per-message path and no new buffering.
pub async fn force_deactivate(State(state): State<ApiState>, body: Bytes) -> Response {
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&body) {
        if let Some(name) = value.get("name").and_then(|v| v.as_str()) {
            let name = name.trim();
            if !name.is_empty() {
                state.alarms.deactivate(name);
                return StatusCode::NO_CONTENT.into_response();
            }
        }
    }
    state.alarms.deactivate_all();
    StatusCode::NO_CONTENT.into_response()
}

fn now_micros() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

/// Format microseconds since the epoch as `YYYY-MM-DDTHH:MM:SS+00:00`
/// (always UTC, second precision like the ban store).
fn micros_to_rfc3339(us: u64) -> String {
    epoch_to_rfc3339(us / 1_000_000)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_store_lists_nothing() {
        let store = AlarmStore::new();
        assert!(store.list_active().is_empty());
        assert!(store.list_deactivated().is_empty());
    }

    #[test]
    fn activate_is_idempotent_and_sorted() {
        let store = AlarmStore::new();
        let first = store.activate("b-alarm", "second", serde_json::json!({}));
        let second = store.activate("a-alarm", "first", serde_json::json!({}));
        // Re-activating keeps the original activation time.
        let again = store.activate("a-alarm", "changed", serde_json::json!({"x": 1}));
        assert_eq!(again.activate_at_us, second.activate_at_us);
        assert_eq!(again.message, second.message);
        let names: Vec<String> = store.list_active().into_iter().map(|e| e.name).collect();
        assert_eq!(names, vec!["a-alarm".to_string(), "b-alarm".to_string()]);
        assert!(first.activate_at_us <= now_micros());
    }

    #[test]
    fn cap_evicts_oldest_active() {
        let store = AlarmStore::new();
        for i in 0..(MAX_ALARMS + 5) {
            store.activate(
                &format!("alarm-{i:05}"),
                "evict check",
                serde_json::json!({}),
            );
        }
        assert_eq!(store.list_active().len(), MAX_ALARMS);
    }

    #[test]
    fn deactivate_moves_to_history() {
        let store = AlarmStore::new();
        store.activate("gone", "bye", serde_json::json!({}));
        assert!(store.deactivate("gone"));
        assert!(store.list_active().is_empty());
        assert_eq!(store.list_deactivated().len(), 1);
        assert!(!store.deactivate("gone"));
        store.clear();
        assert!(store.list_deactivated().is_empty());
    }

    #[test]
    fn deactivate_all_moves_active_to_history() {
        let store = AlarmStore::new();
        assert_eq!(store.deactivate_all(), 0);
        store.activate("a-alarm", "first", serde_json::json!({}));
        store.activate("b-alarm", "second", serde_json::json!({}));
        assert_eq!(store.deactivate_all(), 2);
        assert!(store.list_active().is_empty());
        let history = store.list_deactivated();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].name, "a-alarm");
        assert_eq!(history[1].name, "b-alarm");
        for record in &history {
            assert!(record.deactivate_at_us >= record.activate_at_us);
            let rendered = record.to_json();
            assert_ne!(rendered["deactivate_at"], serde_json::json!("infinity"));
        }
        // Deactivating an empty store keeps history and still succeeds.
        assert_eq!(store.deactivate_all(), 0);
        assert_eq!(store.list_deactivated().len(), 2);
    }

    #[test]
    fn active_json_has_documented_shape() {
        let store = AlarmStore::new();
        let entry = store.activate(
            "shape-alarm",
            "shape message",
            serde_json::json!({"high_watermark": 70}),
        );
        let rendered = entry.to_json(entry.activate_at_us + 10);
        assert_eq!(rendered["node"], serde_json::json!(NODE_NAME));
        assert_eq!(rendered["name"], serde_json::json!("shape-alarm"));
        assert_eq!(rendered["message"], serde_json::json!("shape message"));
        assert_eq!(
            rendered["details"],
            serde_json::json!({"high_watermark": 70})
        );
        assert_eq!(rendered["duration"], serde_json::json!(10));
        assert!(rendered["activate_at"].is_string());
        assert_eq!(rendered["deactivate_at"], serde_json::json!("infinity"));
    }
}
