//! Sampled monitor history for the v5 management API.
//!
//! Covers `GET /monitor` (ordered history list), `DELETE /monitor`
//! (clear the history) and `GET /monitor/nodes/{node}` (same history
//! scoped to the one local node via the shared node helper).
//! Single-node, management-plane only: nothing here
//! runs on the per-message path, so reads and clears never take a
//! delivery lock and no new buffering is added to fan-out or fan-in.
//!
//! Store bounds (both stated here and enforced below):
//! - at most [`MAX_MONITOR_SAMPLES`] points are kept in a fixed
//!   ring (`VecDeque`); recording past the cap evicts the oldest point
//!   instead of growing without limit;
//! - every point is a fixed set of integer counters plus `time_stamp`
//!   (Unix seconds), so per-point memory is constant;
//! - recorder writes are constant-time (one push plus at most one pop);
//!   listing copies at most the capped buffer once per request.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use std::collections::VecDeque;
use std::sync::RwLock;

use crate::node_scope::resolve_node;
use crate::ApiState;

/// Single-node name rendered by `v5::nodes::list_nodes` and the other v5
/// rows (`alarms`, `monitoring`, `clients`). Accepted alongside
/// [`ApiState::node_id`] until every caller migrates to the configured id
/// (see `node_scope` docs); both name the same local node.
const LEGACY_NODE_NAME: &str = "indramqtt@127.0.0.1";

/// Upper bound for stored history points. Recording past this size evicts
/// the oldest point first instead of growing the buffer without limit.
/// 1440 points cover four hours at one sample per ten seconds; one point
/// holds nineteen integers, so the buffer stays well under one megabyte.
pub const MAX_MONITOR_SAMPLES: usize = 1440;

/// One sampled history point: the sampling instant (`time_stamp`, Unix
/// seconds) plus gauge and cumulative counters as plain integers.
///
/// Gauges (`connections`, `live_connections`, `topics`, `subscriptions`,
/// `subscriptions_durable`, `disconnected_durable_sessions`) describe the
/// node at sampling time. Cumulative counters (`received`, `sent`,
/// `dropped`, `persisted`, `validation_*`, `transformation_*`,
/// `rules_matched`, `actions_executed`, `actions_messages`) only move
/// forward within a run. Fields with no kernel tracking yet read zero so
/// the shape stays stable; they rise once their subsystem records them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorSample {
    pub time_stamp: u64,
    pub connections: u64,
    pub live_connections: u64,
    pub topics: u64,
    pub subscriptions: u64,
    pub subscriptions_durable: u64,
    pub disconnected_durable_sessions: u64,
    pub received: u64,
    pub sent: u64,
    pub dropped: u64,
    pub persisted: u64,
    pub validation_succeeded: u64,
    pub validation_failed: u64,
    pub transformation_succeeded: u64,
    pub transformation_failed: u64,
    pub rules_matched: u64,
    pub actions_executed: u64,
    pub actions_messages: u64,
}

/// Live counter values captured into one history point. Gauges come from
/// the session directory; cumulative counters come from the lock-free
/// metrics snapshot. Untracked fields stay zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LiveCounters {
    pub connections: u64,
    pub live_connections: u64,
    pub topics: u64,
    pub subscriptions: u64,
    pub received: u64,
    pub sent: u64,
    pub dropped: u64,
    pub rules_matched: u64,
}

impl MonitorSample {
    /// Build a point from live counters at `time_stamp`. Untracked fields
    /// (durable gauges, validation/transformation splits, persistence and
    /// action counters) read zero until their subsystem records them.
    pub fn from_live(time_stamp: u64, counters: LiveCounters) -> Self {
        Self {
            time_stamp,
            connections: counters.connections,
            live_connections: counters.live_connections,
            topics: counters.topics,
            subscriptions: counters.subscriptions,
            subscriptions_durable: 0,
            disconnected_durable_sessions: 0,
            received: counters.received,
            sent: counters.sent,
            dropped: counters.dropped,
            persisted: 0,
            validation_succeeded: 0,
            validation_failed: 0,
            transformation_succeeded: 0,
            transformation_failed: 0,
            rules_matched: counters.rules_matched,
            actions_executed: 0,
            actions_messages: 0,
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "time_stamp": self.time_stamp,
            "connections": self.connections,
            "live_connections": self.live_connections,
            "topics": self.topics,
            "subscriptions": self.subscriptions,
            "subscriptions_durable": self.subscriptions_durable,
            "disconnected_durable_sessions": self.disconnected_durable_sessions,
            "received": self.received,
            "sent": self.sent,
            "dropped": self.dropped,
            "persisted": self.persisted,
            "validation_succeeded": self.validation_succeeded,
            "validation_failed": self.validation_failed,
            "transformation_succeeded": self.transformation_succeeded,
            "transformation_failed": self.transformation_failed,
            "rules_matched": self.rules_matched,
            "actions_executed": self.actions_executed,
            "actions_messages": self.actions_messages,
        })
    }
}

/// Bounded history buffer behind one short lock.
///
/// Every method finishes quickly and no delivery path touches it, so
/// management reads never block messaging. Recording is constant-time;
/// listing copies at most [`MAX_MONITOR_SAMPLES`] points.
pub struct MonitorHistory {
    inner: RwLock<VecDeque<MonitorSample>>,
}

impl MonitorHistory {
    /// Empty history.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(VecDeque::new()),
        }
    }

    /// Record one point. Constant-time: a single push plus at most one
    /// pop of the oldest point when the buffer is full.
    pub fn record(&self, sample: MonitorSample) {
        let mut buffer = self.inner.write().expect("monitor store lock");
        if buffer.len() >= MAX_MONITOR_SAMPLES {
            buffer.pop_front();
        }
        buffer.push_back(sample);
    }

    /// Capture live counters into one point and record it. Constant-time,
    /// like [`Self::record`]. Returns the stored point.
    pub fn capture_live(&self, time_stamp: u64, counters: LiveCounters) -> MonitorSample {
        let sample = MonitorSample::from_live(time_stamp, counters);
        self.record(sample.clone());
        sample
    }

    /// Snapshot of stored points in ascending `time_stamp` order
    /// (oldest first). An empty store reads as an empty list. When
    /// `latest_secs` is set, only points sampled within the last
    /// `latest_secs` seconds (`time_stamp >= now - latest_secs`) are
    /// returned; otherwise every stored point is returned.
    pub fn list(&self, latest_secs: Option<u64>, now_secs: u64) -> Vec<MonitorSample> {
        let buffer = self.inner.read().expect("monitor store lock");
        let mut out: Vec<MonitorSample> = match latest_secs {
            Some(window) => {
                let cutoff = now_secs.saturating_sub(window);
                buffer
                    .iter()
                    .filter(|s| s.time_stamp >= cutoff)
                    .cloned()
                    .collect()
            }
            None => buffer.iter().cloned().collect(),
        };
        out.sort_by_key(|s| s.time_stamp);
        out
    }

    /// Drop every stored point. Always succeeds, even when nothing is
    /// stored.
    pub fn clear(&self) {
        self.inner.write().expect("monitor store lock").clear();
    }

    /// Newest stored point, if any. Constant-time: one short lock and
    /// one clone of the back of the ring. Points are recorded in time
    /// order, so the back is the newest; an empty store returns None.
    /// Management-plane only; never touched on the per-message path.
    pub fn latest(&self) -> Option<MonitorSample> {
        self.inner
            .read()
            .expect("monitor store lock")
            .back()
            .cloned()
    }

    /// Number of stored points (never above [`MAX_MONITOR_SAMPLES`]).
    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.read().expect("monitor store lock").len()
    }
}

impl Default for MonitorHistory {
    fn default() -> Self {
        Self::new()
    }
}

/// Documented list scope. Only `latest` narrows the read (last N seconds);
/// every other query key is ignored by the extractor so new parameters
/// degrade to the full history instead of a 400. A malformed `latest`
/// also falls back to the full history.
#[derive(Deserialize, Default)]
pub struct MonitorListQuery {
    #[serde(default)]
    pub latest: Option<String>,
}

fn parse_latest(query: &MonitorListQuery) -> Option<u64> {
    query
        .latest
        .as_deref()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
}

/// `GET /monitor`: ordered history array (oldest first). An empty store
/// reads as an empty array, never an error. `?latest=N` keeps only points
/// sampled within the last N seconds; unknown query keys are ignored and
/// a malformed `latest` falls back to the full history. Management-plane
/// only: one short store lock, no work on the per-message path.
pub async fn list_monitor(
    State(state): State<ApiState>,
    Query(query): Query<MonitorListQuery>,
) -> Response {
    let latest = parse_latest(&query);
    let now = now_epoch_secs();
    let rows = state.monitor.list(latest, now);
    let data: Vec<serde_json::Value> = rows.iter().map(MonitorSample::to_json).collect();
    (StatusCode::OK, Json(data)).into_response()
}

/// `DELETE /monitor`: drop every history point and report success with
/// 204. Always succeeds, even when nothing is stored. Query strings
/// (including unknown keys) are ignored by design.
pub async fn clear_monitor(State(state): State<ApiState>) -> Response {
    state.monitor.clear();
    StatusCode::NO_CONTENT.into_response()
}

/// `GET /monitor/nodes/{node}`: node-scoped read over the same bounded
/// history as `GET /monitor`.
///
/// Single node, management-plane only: the named node is checked with the
/// shared [`resolve_node`] helper against the configured [`ApiState::node_id`]
/// (falling back to the [`LEGACY_NODE_NAME`] literal the v5 rows render
/// today); an unknown name returns the helper's 404 `NOT_FOUND` shape
/// naming the node. A known name returns the same ordered array shape as
/// [`list_monitor`] (same `?latest=N` window, same unknown-query-keys
/// ignored, same empty-store empty array), with one short store lock and
/// no work on the per-message path.
pub async fn get_monitor_node(
    State(state): State<ApiState>,
    Path(node): Path<String>,
    Query(query): Query<MonitorListQuery>,
) -> Response {
    if resolve_node(&state.node_id, &node).is_err()
        && resolve_node(LEGACY_NODE_NAME, &node).is_err()
    {
        // Reuse the helper's error so the unknown-node shape stays exactly
        // the documented `{code: NOT_FOUND, message}` body.
        return resolve_node(&state.node_id, &node)
            .expect_err("node already checked as unknown")
            .into_response();
    }
    let latest = parse_latest(&query);
    let now = now_epoch_secs();
    let rows = state.monitor.list(latest, now);
    let data: Vec<serde_json::Value> = rows.iter().map(MonitorSample::to_json).collect();
    (StatusCode::OK, Json(data)).into_response()
}

fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_at(time_stamp: u64, connections: u64) -> MonitorSample {
        MonitorSample::from_live(
            time_stamp,
            LiveCounters {
                connections,
                live_connections: connections,
                topics: 1,
                subscriptions: 2,
                received: time_stamp,
                sent: time_stamp,
                dropped: 0,
                rules_matched: 0,
            },
        )
    }

    #[test]
    fn latest_returns_newest_or_none() {
        let store = MonitorHistory::new();
        assert!(store.latest().is_none());
        store.record(sample_at(1_700_000_100, 3));
        store.record(sample_at(1_700_000_200, 5));
        let newest = store.latest().expect("newest exists");
        assert_eq!(newest.time_stamp, 1_700_000_200);
        assert_eq!(newest.connections, 5);
    }

    #[test]
    fn empty_store_lists_nothing() {
        let store = MonitorHistory::new();
        assert!(store.list(None, 1_700_000_000).is_empty());
        assert!(store.list(Some(300), 1_700_000_000).is_empty());
    }

    #[test]
    fn record_two_samples_list_in_order_then_clear_empties() {
        let store = MonitorHistory::new();
        store.record(sample_at(1_700_000_100, 3));
        store.record(sample_at(1_700_000_200, 5));
        let rows = store.list(None, 1_700_000_300);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].time_stamp, 1_700_000_100);
        assert_eq!(rows[1].time_stamp, 1_700_000_200);
        assert_eq!(rows[0].connections, 3);
        assert_eq!(rows[1].connections, 5);
        store.clear();
        assert!(store.list(None, 1_700_000_300).is_empty());
        // Clearing an empty store still succeeds.
        store.clear();
        assert!(store.list(None, 1_700_000_300).is_empty());
    }

    #[test]
    fn cap_evicts_oldest_point() {
        let store = MonitorHistory::new();
        for i in 0..(MAX_MONITOR_SAMPLES + 5) {
            store.record(sample_at(1_700_000_000 + i as u64, i as u64));
        }
        assert_eq!(store.len(), MAX_MONITOR_SAMPLES);
        let rows = store.list(None, u64::MAX);
        assert_eq!(rows.len(), MAX_MONITOR_SAMPLES);
        // The five oldest points were evicted.
        assert_eq!(rows[0].time_stamp, 1_700_000_005);
    }

    #[test]
    fn latest_window_keeps_recent_points() {
        let store = MonitorHistory::new();
        store.record(sample_at(1_000, 1));
        store.record(sample_at(1_200, 2));
        store.record(sample_at(1_400, 3));
        let rows = store.list(Some(300), 1_500);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].time_stamp, 1_200);
        assert_eq!(rows[1].time_stamp, 1_400);
        let all = store.list(None, 1_500);
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn sample_json_has_documented_shape() {
        let sample = sample_at(1_700_000_100, 7);
        let rendered = sample.to_json();
        assert_eq!(rendered["time_stamp"], serde_json::json!(1_700_000_100));
        assert_eq!(rendered["connections"], serde_json::json!(7));
        assert_eq!(rendered["live_connections"], serde_json::json!(7));
        for field in [
            "topics",
            "subscriptions",
            "subscriptions_durable",
            "disconnected_durable_sessions",
            "received",
            "sent",
            "dropped",
            "persisted",
            "validation_succeeded",
            "validation_failed",
            "transformation_succeeded",
            "transformation_failed",
            "rules_matched",
            "actions_executed",
            "actions_messages",
        ] {
            assert!(rendered.get(field).is_some(), "missing field {field}");
            assert!(rendered[field].is_u64(), "field {field} must be an integer");
        }
    }

    #[test]
    fn capture_live_is_constant_time_and_bounded() {
        let store = MonitorHistory::new();
        let counters = LiveCounters {
            connections: 2,
            live_connections: 2,
            topics: 1,
            subscriptions: 1,
            received: 10,
            sent: 9,
            dropped: 1,
            rules_matched: 4,
        };
        let stored = store.capture_live(1_700_000_100, counters);
        assert_eq!(stored.time_stamp, 1_700_000_100);
        assert_eq!(stored.connections, 2);
        assert_eq!(stored.received, 10);
        assert_eq!(stored.rules_matched, 4);
        assert_eq!(store.len(), 1);
    }

    fn standalone_state() -> ApiState {
        let engine = std::sync::Arc::new(broker_rules::RuleEngine::new(
            16,
            broker_rules::BackpressurePolicy::DropOldest,
        ));
        ApiState::standalone(engine)
    }

    async fn node_response_body(response: Response) -> (StatusCode, serde_json::Value) {
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .expect("monitor body is small and readable");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("monitor body is JSON");
        (status, body)
    }

    #[tokio::test]
    async fn node_read_returns_same_shape_as_global() {
        let state = standalone_state();
        state.monitor.record(sample_at(1_700_000_100, 3));
        state.monitor.record(sample_at(1_700_000_200, 5));
        for known in [LEGACY_NODE_NAME, "indra-node-1"] {
            let response = get_monitor_node(
                State(state.clone()),
                Path(known.to_string()),
                Query(MonitorListQuery { latest: None }),
            )
            .await;
            let (status, body) = node_response_body(response).await;
            assert_eq!(status, StatusCode::OK, "known node {known}");
            let rows = body.as_array().expect("node history is an array");
            assert_eq!(rows.len(), 2, "known node {known}");
            assert_eq!(rows[0]["time_stamp"], serde_json::json!(1_700_000_100));
            assert_eq!(rows[1]["time_stamp"], serde_json::json!(1_700_000_200));
            assert_eq!(rows[0]["connections"], serde_json::json!(3));
            assert_eq!(rows[1]["connections"], serde_json::json!(5));
            for row in rows {
                for field in [
                    "time_stamp",
                    "connections",
                    "live_connections",
                    "topics",
                    "subscriptions",
                    "subscriptions_durable",
                    "disconnected_durable_sessions",
                    "received",
                    "sent",
                    "dropped",
                    "persisted",
                    "validation_succeeded",
                    "validation_failed",
                    "transformation_succeeded",
                    "transformation_failed",
                    "rules_matched",
                    "actions_executed",
                    "actions_messages",
                ] {
                    assert!(row.get(field).is_some(), "missing field {field}");
                    assert!(row[field].is_u64(), "field {field} must be an integer");
                }
            }
        }
    }

    #[tokio::test]
    async fn unknown_node_is_not_found() {
        let state = standalone_state();
        state.monitor.record(sample_at(1_700_000_100, 3));
        let response = get_monitor_node(
            State(state),
            Path("no-such-node".to_string()),
            Query(MonitorListQuery { latest: None }),
        )
        .await;
        let (status, body) = node_response_body(response).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["code"], serde_json::json!("NOT_FOUND"));
        let message = body["message"].as_str().expect("message is a string");
        assert!(
            message.contains("no-such-node"),
            "message names the unknown node: {body}"
        );
    }
}
