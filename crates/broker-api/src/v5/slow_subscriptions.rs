//! Slow-subscription recorder for the v5 management API.
//!
//! Covers `GET /slow_subscriptions` (paged list of recorded slow
//! deliveries) and `DELETE /slow_subscriptions` (drop every record).
//! Single-node, management-plane only: nothing here runs on the
//! per-message path, so reads and clears never take a delivery lock and
//! no new buffering is added to fan-out or fan-in.
//!
//! Store bounds (both stated here and enforced below):
//! - at most [`MAX_SLOW_SUBSCRIPTIONS`] records are kept; recording past
//!   the cap keeps the slowest entries and drops the fastest (or the new
//!   record when it is not slower than the slowest stored), instead of
//!   growing without limit;
//! - `clientid` is capped at 256 chars and `topic` at 512 chars, so one
//!   entry cannot balloon memory;
//! - every record is five small fields (`clientid`, `node`, `topic`,
//!   `timespan`, `last_update_time`), so per-record memory is constant;
//! - recorder writes are constant-time (one map lookup plus at most one
//!   bounded scan of the capped map for eviction); listing copies at most
//!   the capped buffer once per request.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::RwLock;

use crate::pagination::{meta_page, paginate, PageParams};
use crate::ApiState;

/// Upper bound for stored slow-subscription records. Recording past this
/// size keeps the slowest entries: the smallest `timespan` is evicted
/// first instead of growing the map without limit.
pub const MAX_SLOW_SUBSCRIPTIONS: usize = 1000;
/// Longest accepted `clientid`.
const MAX_CLIENTID_LEN: usize = 256;
/// Longest accepted `topic`.
const MAX_TOPIC_LEN: usize = 512;

/// Node name rendered on every slow-subscription row (single node).
const NODE_NAME: &str = "indramqtt@127.0.0.1";

/// One recorded slow delivery: which subscriber on which topic was slow,
/// by how much (`timespan`, milliseconds of delivery latency) and when
/// (`last_update_time`, milliseconds since the Unix epoch).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlowSubEntry {
    pub clientid: String,
    pub topic: String,
    pub timespan: u64,
    pub last_update_time: u64,
}

impl SlowSubEntry {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "clientid": self.clientid,
            "node": NODE_NAME,
            "topic": self.topic,
            "timespan": self.timespan,
            "last_update_time": self.last_update_time,
        })
    }
}

/// Bounded in-memory recorder behind one short lock.
///
/// Every method finishes quickly and no delivery path touches it, so
/// management reads never block messaging. Recording is constant-time
/// (bounded by [`MAX_SLOW_SUBSCRIPTIONS`]); listing copies at most the
/// capped buffer once per request.
pub struct SlowSubsStore {
    inner: RwLock<HashMap<(String, String), SlowSubEntry>>,
}

impl SlowSubsStore {
    /// Empty recorder.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Record one slow delivery.
    ///
    /// Truncates over-long `clientid`/`topic` to the documented caps.
    /// An existing `(clientid, topic)` pair only moves when the new
    /// `timespan` is larger (matching the ranked-table behaviour: the
    /// table keeps the worst latency per subscriber-topic). Past
    /// [`MAX_SLOW_SUBSCRIPTIONS`] records the smallest `timespan` is
    /// evicted first; a new record that is not slower than the slowest
    /// stored entry is dropped instead of growing the map.
    pub fn record(
        &self,
        clientid: &str,
        topic: &str,
        timespan: u64,
        last_update_time: u64,
    ) -> SlowSubEntry {
        let clientid = truncate(clientid.trim(), MAX_CLIENTID_LEN).to_string();
        let topic = truncate(topic.trim(), MAX_TOPIC_LEN).to_string();
        let key = (clientid.clone(), topic.clone());
        let mut map = self.inner.write().expect("slow-subs store lock");
        if let Some(existing) = map.get(&key) {
            if timespan <= existing.timespan {
                return existing.clone();
            }
        }
        if map.len() >= MAX_SLOW_SUBSCRIPTIONS && !map.contains_key(&key) {
            let smallest = map
                .iter()
                .min_by_key(|(_, entry)| entry.timespan)
                .map(|(key, _)| key.clone());
            if let Some(smallest_key) = smallest {
                let slowest_smallest = map
                    .get(&smallest_key)
                    .map(|entry| entry.timespan)
                    .unwrap_or(0);
                if timespan <= slowest_smallest {
                    // Not slower than anything stored: drop it without growing.
                    return SlowSubEntry {
                        clientid,
                        topic,
                        timespan,
                        last_update_time,
                    };
                }
                map.remove(&smallest_key);
            }
        }
        let entry = SlowSubEntry {
            clientid: clientid.clone(),
            topic: topic.clone(),
            timespan,
            last_update_time,
        };
        map.insert((clientid, topic), entry.clone());
        entry
    }

    /// Snapshot of stored records sorted by `timespan` descending (slowest
    /// first), ties broken by `clientid` then `topic` for stable pages.
    pub fn list(&self) -> Vec<SlowSubEntry> {
        let map = self.inner.read().expect("slow-subs store lock");
        let mut out: Vec<SlowSubEntry> = map.values().cloned().collect();
        out.sort_by(|a, b| {
            b.timespan
                .cmp(&a.timespan)
                .then_with(|| a.clientid.cmp(&b.clientid))
                .then_with(|| a.topic.cmp(&b.topic))
        });
        out
    }

    /// Drop every stored record. Always succeeds, even when nothing is
    /// stored.
    pub fn clear(&self) {
        self.inner.write().expect("slow-subs store lock").clear();
    }

    /// Number of stored records (never above [`MAX_SLOW_SUBSCRIPTIONS`]).
    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.read().expect("slow-subs store lock").len()
    }
}

impl Default for SlowSubsStore {
    fn default() -> Self {
        Self::new()
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

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

/// `GET /slow_subscriptions`: paged list of recorded slow deliveries.
///
/// Reads the whole recorder (already sorted slowest-first) and renders
/// only the requested page through the shared W0 paging helper (`page` /
/// `limit` plus `meta { page, limit, count, hasnext }`). Malformed
/// `page` / `limit` fall back to defaults via [`PageParams`]; an empty
/// recorder reads as an empty page, never an error. One bounded snapshot
/// per request (at most [`MAX_SLOW_SUBSCRIPTIONS`] small clones under a
/// short lock); delivery never waits on it and no new buffering is added
/// to fan-out or fan-in.
pub async fn list_slow_subscriptions(
    State(state): State<ApiState>,
    params: PageParams,
) -> Response {
    let rows = state.slow_subs.list();
    let total = rows.len();
    let page_items = paginate(&rows, params.page, params.limit);
    let data: Vec<serde_json::Value> = page_items.iter().map(SlowSubEntry::to_json).collect();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "data": data,
            "meta": meta_page(params.page, params.limit, total),
        })),
    )
        .into_response()
}

/// `DELETE /slow_subscriptions`: drop every recorded slow delivery and
/// report success with 204. Always succeeds, even when nothing is stored.
/// Query strings (including unknown keys) are ignored by design.
/// Management-plane only: one short store lock, no work on the
/// per-message path and no new buffering.
pub async fn clear_slow_subscriptions(State(state): State<ApiState>) -> Response {
    state.slow_subs.clear();
    StatusCode::NO_CONTENT.into_response()
}

/// Default slow-subscription thresholds, matching the documented defaults.
const DEFAULT_ENABLE: bool = false;
const DEFAULT_THRESHOLD: &str = "500ms";
const DEFAULT_TOP_K_NUM: u32 = 10;
const DEFAULT_EXPIRE_INTERVAL: &str = "300s";
const DEFAULT_STATS_TYPE: &str = "whole";

/// Smallest accepted `threshold`: only latencies above this are collected.
/// The documented minimum is 100ms.
const MIN_THRESHOLD_MS: u64 = 100;
/// `top_k_num` range: at least one row, at most the recorder cap.
const MIN_TOP_K_NUM: u32 = 1;
const MAX_TOP_K_NUM: u32 = 1000;
/// Latency calculation modes the write path accepts.
const VALID_STATS_TYPES: &[&str] = &["whole", "internal", "response"];

/// Validated slow-subscription thresholds.
///
/// One small struct behind a short lock; reads clone it per request and
/// never grow with connections or subscriptions. Management-plane only;
/// nothing on the per-message path touches it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlowSubsSettings {
    pub enable: bool,
    pub threshold: String,
    pub top_k_num: u32,
    pub expire_interval: String,
    pub stats_type: String,
}

impl Default for SlowSubsSettings {
    fn default() -> Self {
        Self {
            enable: DEFAULT_ENABLE,
            threshold: DEFAULT_THRESHOLD.to_string(),
            top_k_num: DEFAULT_TOP_K_NUM,
            expire_interval: DEFAULT_EXPIRE_INTERVAL.to_string(),
            stats_type: DEFAULT_STATS_TYPE.to_string(),
        }
    }
}

impl SlowSubsSettings {
    /// Render the full documented object.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "enable": self.enable,
            "threshold": self.threshold,
            "top_k_num": self.top_k_num,
            "expire_interval": self.expire_interval,
            "stats_type": self.stats_type,
        })
    }
}

/// Single validated settings object behind a short lock. Constant-time
/// reads and writes; readers take a snapshot clone so management reads
/// never block delivery and no delivery lock is ever taken here.
pub struct SlowSubsSettingsStore {
    inner: RwLock<SlowSubsSettings>,
}

impl SlowSubsSettingsStore {
    /// Default thresholds.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(SlowSubsSettings::default()),
        }
    }

    /// Snapshot the current thresholds.
    pub fn get(&self) -> SlowSubsSettings {
        self.inner.read().expect("slow-subs settings lock").clone()
    }

    /// Replace the thresholds after full validation. The caller validates
    /// first; this only swaps.
    fn replace(&self, next: SlowSubsSettings) {
        *self.inner.write().expect("slow-subs settings lock") = next;
    }
}

impl Default for SlowSubsSettingsStore {
    fn default() -> Self {
        Self::new()
    }
}

/// `GET /slow_subscriptions/settings`: current thresholds.
///
/// One short lock and one small JSON clone per request; no delivery
/// locks, no new buffering.
pub async fn get_slow_subs_settings(State(state): State<ApiState>) -> Response {
    let cfg = state.slow_subs_settings.get();
    (StatusCode::OK, Json(cfg.to_json())).into_response()
}

/// `PUT /slow_subscriptions/settings`: validated update.
///
/// The whole body is validated before anything is applied: one bad field
/// rejects the entire write with the documented `UPDATE_FAILED` shape
/// and leaves the stored thresholds untouched. Unknown fields are ignored
/// so newer settings degrade to the known subset instead of a 400.
pub async fn put_slow_subs_settings(State(state): State<ApiState>, body: Bytes) -> Response {
    let value: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(error) => return settings_update_failed(format!("invalid settings body: {error}")),
    };
    let obj = match value.as_object() {
        Some(map) => map.clone(),
        None => return settings_update_failed("settings body must be a JSON object".to_string()),
    };
    if obj.is_empty() {
        return settings_update_failed("settings body must not be empty".to_string());
    }
    let current = state.slow_subs_settings.get();
    let next = match apply_settings_update(current, &obj) {
        Ok(cfg) => cfg,
        Err(reason) => return settings_update_failed(reason),
    };
    state.slow_subs_settings.replace(next.clone());
    (StatusCode::OK, Json(next.to_json())).into_response()
}

fn settings_update_failed(reason: String) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "code": "UPDATE_FAILED",
            "message": reason,
        })),
    )
        .into_response()
}

/// Validate every supplied field and merge into `current` without
/// mutating it until all fields pass. Unknown fields are ignored.
/// `top_k` is the historic alias of `top_k_num` and `expire_time` the
/// historic alias of `expire_interval`; both write the same setting, with
/// the canonical name winning when both appear.
fn apply_settings_update(
    mut current: SlowSubsSettings,
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Result<SlowSubsSettings, String> {
    if let Some(value) = obj.get("enable") {
        let flag = value
            .as_bool()
            .ok_or_else(|| "field `enable` must be a boolean".to_string())?;
        current.enable = flag;
    }
    if let Some(value) = obj.get("threshold") {
        let text = value
            .as_str()
            .ok_or_else(|| "field `threshold` must be a string".to_string())?;
        validate_threshold(text)?;
        current.threshold = text.to_string();
    }
    // Alias first, canonical second so canonical wins when both appear.
    if let Some(value) = obj.get("top_k") {
        let num = parse_top_k(value)
            .ok_or_else(|| "field `top_k` must be an integer 1..=1000".to_string())?;
        validate_top_k_num(num)?;
        current.top_k_num = num;
    }
    if let Some(value) = obj.get("top_k_num") {
        let num = parse_top_k(value)
            .ok_or_else(|| "field `top_k_num` must be an integer 1..=1000".to_string())?;
        validate_top_k_num(num)?;
        current.top_k_num = num;
    }
    if let Some(value) = obj.get("expire_time") {
        let text = value
            .as_str()
            .ok_or_else(|| "field `expire_time` must be a string".to_string())?;
        validate_expire_interval(text)?;
        current.expire_interval = text.to_string();
    }
    if let Some(value) = obj.get("expire_interval") {
        let text = value
            .as_str()
            .ok_or_else(|| "field `expire_interval` must be a string".to_string())?;
        validate_expire_interval(text)?;
        current.expire_interval = text.to_string();
    }
    if let Some(value) = obj.get("stats_type") {
        let text = value
            .as_str()
            .ok_or_else(|| "field `stats_type` must be a string".to_string())?;
        if !VALID_STATS_TYPES.contains(&text) {
            return Err("field `stats_type` must be `whole`, `internal` or `response`".to_string());
        }
        current.stats_type = text.to_string();
    }
    Ok(current)
}

fn parse_top_k(value: &serde_json::Value) -> Option<u32> {
    if let Some(num) = value.as_u64() {
        u32::try_from(num).ok()
    } else if let Some(num) = value.as_i64() {
        u32::try_from(num).ok()
    } else {
        None
    }
}

fn validate_top_k_num(num: u32) -> Result<(), String> {
    if !(MIN_TOP_K_NUM..=MAX_TOP_K_NUM).contains(&num) {
        return Err("field `top_k_num` must be an integer 1..=1000".to_string());
    }
    Ok(())
}

/// Thresholds are durations like `500ms`, `1s` or `2m` and must be at
/// least 100ms (the documented minimum). Plain integers are rejected:
/// the documented shape is a string.
fn validate_threshold(text: &str) -> Result<(), String> {
    let millis = parse_duration_to_ms(text).ok_or_else(|| {
        "field `threshold` must be a duration like `500ms`, `1s` or `2m`".to_string()
    })?;
    if millis < MIN_THRESHOLD_MS {
        return Err("field `threshold` must be at least `100ms`".to_string());
    }
    Ok(())
}

/// Eviction delays are durations like `300s`, `5m` or `1h` and must be
/// positive. Plain integers are rejected: the documented shape is a string.
fn validate_expire_interval(text: &str) -> Result<(), String> {
    let millis = parse_duration_to_ms(text).ok_or_else(|| {
        "field `expire_interval` must be a duration like `300s`, `5m` or `1h`".to_string()
    })?;
    if millis == 0 {
        return Err("field `expire_interval` must be positive".to_string());
    }
    Ok(())
}

/// Parse `500ms`, `300s`, `5m`, `1h`, `1d` into milliseconds.
/// Returns `None` for malformed input. Case-insensitive, no spaces.
fn parse_duration_to_ms(text: &str) -> Option<u64> {
    let lower = text.trim().to_ascii_lowercase().replace(' ', "");
    if lower.is_empty() {
        return None;
    }
    let (num_part, mult): (&str, f64) = if lower.ends_with("ms") {
        (&lower[..lower.len() - 2], 1.0)
    } else if lower.ends_with('s') {
        (&lower[..lower.len() - 1], 1000.0)
    } else if lower.ends_with('m') {
        (&lower[..lower.len() - 1], 60_000.0)
    } else if lower.ends_with('h') {
        (&lower[..lower.len() - 1], 3_600_000.0)
    } else if lower.ends_with('d') {
        (&lower[..lower.len() - 1], 86_400_000.0)
    } else {
        return None;
    };
    if num_part.is_empty() {
        return None;
    }
    let num: f64 = num_part.parse().ok()?;
    if num < 0.0 || !num.is_finite() {
        return None;
    }
    Some((num * mult) as u64)
}

/// Record one slow delivery observed by the kernel (future delivery hook).
///
/// Thin wrapper over [`SlowSubsStore::record`] with a read of the wall
/// clock for `last_update_time`. Kept off the delivery hot path: the
/// kernel calls it asynchronously after delivery completes, never while
/// holding a delivery lock.
#[allow(dead_code)]
pub fn record_slow_delivery(
    store: &SlowSubsStore,
    clientid: &str,
    topic: &str,
    timespan: u64,
) -> SlowSubEntry {
    store.record(clientid, topic, timespan, now_millis())
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
            .expect("slow-subs body is small and readable");
        let body: serde_json::Value =
            serde_json::from_slice(&bytes).expect("slow-subs body is JSON");
        (status, body)
    }

    #[test]
    fn empty_store_lists_nothing() {
        let store = SlowSubsStore::new();
        assert!(store.list().is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn record_lists_slowest_first() {
        let store = SlowSubsStore::new();
        store.record("c-slow-1", "t/a", 120, 1_700_000_100_000);
        store.record("c-slow-2", "t/b", 450, 1_700_000_200_000);
        let rows = store.list();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].clientid, "c-slow-2");
        assert_eq!(rows[0].timespan, 450);
        assert_eq!(rows[1].clientid, "c-slow-1");
        let rendered = rows[0].to_json();
        assert_eq!(rendered["clientid"], serde_json::json!("c-slow-2"));
        assert_eq!(rendered["node"], serde_json::json!(NODE_NAME));
        assert_eq!(rendered["topic"], serde_json::json!("t/b"));
        assert_eq!(rendered["timespan"], serde_json::json!(450));
        assert_eq!(
            rendered["last_update_time"],
            serde_json::json!(1_700_000_200_000u64)
        );
    }

    #[test]
    fn same_pair_keeps_worst_timespan() {
        let store = SlowSubsStore::new();
        store.record("c-slow-1", "t/a", 300, 1_000);
        store.record("c-slow-1", "t/a", 100, 2_000);
        let rows = store.list();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].timespan, 300);
        assert_eq!(rows[0].last_update_time, 1_000);
        store.record("c-slow-1", "t/a", 500, 3_000);
        let rows = store.list();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].timespan, 500);
        assert_eq!(rows[0].last_update_time, 3_000);
    }

    #[test]
    fn cap_keeps_slowest_and_drops_fastest() {
        let store = SlowSubsStore::new();
        for i in 0..(MAX_SLOW_SUBSCRIPTIONS + 5) {
            store.record(
                &format!("c-slow-{i:05}"),
                &format!("t/{i:05}"),
                100 + i as u64,
                1_700_000_000_000 + i as u64,
            );
        }
        assert_eq!(store.len(), MAX_SLOW_SUBSCRIPTIONS);
        let rows = store.list();
        assert_eq!(rows.len(), MAX_SLOW_SUBSCRIPTIONS);
        // The five fastest records were evicted; the slowest remains first.
        assert_eq!(
            rows[0].timespan,
            100 + (MAX_SLOW_SUBSCRIPTIONS + 5) as u64 - 1
        );
        assert!(
            rows.iter().all(|entry| entry.timespan >= 105),
            "fastest five must be gone"
        );
    }

    #[tokio::test]
    async fn record_list_clear_flow_over_handlers() {
        let state = standalone_state();

        // Empty recorder reads as an empty page, never an error.
        let (status, body) = response_parts(
            list_slow_subscriptions(
                State(state.clone()),
                PageParams {
                    page: 1,
                    limit: 100,
                },
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"], serde_json::json!([]));
        assert_eq!(body["meta"]["count"], serde_json::json!(0));
        assert_eq!(body["meta"]["hasnext"], serde_json::json!(false));

        // Record one sample entry and list expecting it with all fields.
        state
            .slow_subs
            .record("conf-slow-1", "conf/slow/t1", 850, 1_700_000_300_000);
        let (status, body) = response_parts(
            list_slow_subscriptions(
                State(state.clone()),
                PageParams {
                    page: 1,
                    limit: 100,
                },
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["meta"]["count"], serde_json::json!(1));
        assert_eq!(body["meta"]["hasnext"], serde_json::json!(false));
        let row = &body["data"][0];
        assert_eq!(row["clientid"], serde_json::json!("conf-slow-1"));
        assert_eq!(row["node"], serde_json::json!(NODE_NAME));
        assert_eq!(row["topic"], serde_json::json!("conf/slow/t1"));
        assert_eq!(row["timespan"], serde_json::json!(850));
        assert_eq!(
            row["last_update_time"],
            serde_json::json!(1_700_000_300_000u64)
        );

        // W0 paging slices after sorting: page 1 of limit 1 has more.
        state
            .slow_subs
            .record("conf-slow-2", "conf/slow/t2", 950, 1_700_000_400_000);
        let (status, first) = response_parts(
            list_slow_subscriptions(State(state.clone()), PageParams { page: 1, limit: 1 }).await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(first["meta"]["count"], serde_json::json!(2));
        assert_eq!(first["meta"]["hasnext"], serde_json::json!(true));
        assert_eq!(first["data"].as_array().expect("data").len(), 1);
        assert_eq!(first["data"][0]["timespan"], serde_json::json!(950));
        let (status, second) = response_parts(
            list_slow_subscriptions(State(state.clone()), PageParams { page: 2, limit: 1 }).await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(second["meta"]["hasnext"], serde_json::json!(false));
        assert_eq!(second["data"].as_array().expect("data").len(), 1);
        assert_ne!(first["data"][0]["clientid"], second["data"][0]["clientid"]);

        // Clearing drops the records and the list reads empty again.
        let response = clear_slow_subscriptions(State(state.clone())).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let (status, body) = response_parts(
            list_slow_subscriptions(
                State(state.clone()),
                PageParams {
                    page: 1,
                    limit: 100,
                },
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"], serde_json::json!([]));
        assert_eq!(body["meta"]["count"], serde_json::json!(0));

        // Clearing an empty recorder still reports success.
        let response = clear_slow_subscriptions(State(state)).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn settings_round_trip_read_write_read() {
        let state = standalone_state();
        let (status, before) =
            response_parts(get_slow_subs_settings(State(state.clone())).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(before["enable"], serde_json::json!(false));
        assert_eq!(before["threshold"], serde_json::json!("500ms"));
        assert_eq!(before["top_k_num"], serde_json::json!(10));
        assert_eq!(before["expire_interval"], serde_json::json!("300s"));
        assert_eq!(before["stats_type"], serde_json::json!("whole"));

        let update = serde_json::json!({
            "enable": true,
            "threshold": "1s",
            "top_k_num": 20,
            "expire_interval": "5m",
            "stats_type": "internal",
        });
        let body = Bytes::from(serde_json::to_vec(&update).expect("update is JSON"));
        let (status, after) =
            response_parts(put_slow_subs_settings(State(state.clone()), body).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(after["enable"], serde_json::json!(true));
        assert_eq!(after["threshold"], serde_json::json!("1s"));
        assert_eq!(after["top_k_num"], serde_json::json!(20));
        assert_eq!(after["expire_interval"], serde_json::json!("5m"));
        assert_eq!(after["stats_type"], serde_json::json!("internal"));

        let (status, reread) =
            response_parts(get_slow_subs_settings(State(state.clone())).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reread, after);
    }

    #[tokio::test]
    async fn settings_invalid_update_is_rejected_without_applying() {
        let state = standalone_state();
        let (status, before) =
            response_parts(get_slow_subs_settings(State(state.clone())).await).await;
        assert_eq!(status, StatusCode::OK);

        for bad in [
            serde_json::json!({"enable": "yes"}),
            serde_json::json!({"threshold": "50ms"}),
            serde_json::json!({"threshold": "huge"}),
            serde_json::json!({"threshold": 500}),
            serde_json::json!({"top_k_num": 0}),
            serde_json::json!({"top_k_num": 1001}),
            serde_json::json!({"top_k_num": "many"}),
            serde_json::json!({"expire_interval": "never"}),
            serde_json::json!({"expire_interval": ""}),
            serde_json::json!({"stats_type": "average"}),
            serde_json::json!({}),
            serde_json::json!([]),
        ] {
            let body = Bytes::from(serde_json::to_vec(&bad).expect("bad body is JSON"));
            let (status, err) =
                response_parts(put_slow_subs_settings(State(state.clone()), body).await).await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "body {bad} must be rejected"
            );
            assert_eq!(err["code"], serde_json::json!("UPDATE_FAILED"));
        }

        let (status, reread) =
            response_parts(get_slow_subs_settings(State(state.clone())).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reread, before, "failed writes must not apply");
    }

    #[test]
    fn settings_duration_and_top_k_parsers_accept_documented_shapes() {
        assert_eq!(parse_duration_to_ms("500ms"), Some(500));
        assert_eq!(parse_duration_to_ms("1s"), Some(1000));
        assert_eq!(parse_duration_to_ms("5m"), Some(300_000));
        assert!(parse_duration_to_ms("huge").is_none());
        assert!(validate_threshold("500ms").is_ok());
        assert!(validate_threshold("50ms").is_err());
        assert!(validate_threshold("huge").is_err());
        assert!(validate_expire_interval("300s").is_ok());
        assert!(validate_expire_interval("").is_err());
        assert!(validate_top_k_num(10).is_ok());
        assert!(validate_top_k_num(0).is_err());
        assert!(validate_top_k_num(1001).is_err());
    }
}
