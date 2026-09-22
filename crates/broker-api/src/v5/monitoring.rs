//! Live observability, rate metrics, and alarm polling for the v5 REST API.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use crate::node_scope::resolve_node;
use crate::ApiState;

/// Single-node name rendered by `v5::nodes::list_nodes` and the other v5
/// rows (`alarms`, `monitoring`, `clients`). Accepted alongside
/// [`ApiState::node_id`] until every caller migrates to the configured id
/// (see `node_scope` docs); both name the same local node.
const LEGACY_NODE_NAME: &str = "indramqtt@127.0.0.1";

fn gather_stats(state: &ApiState) -> (usize, usize, usize, u64, u64) {
    let conns = state.metrics.connections_active().max(0) as usize;
    let active_ids = state.sessions.active_client_ids();
    let mut subs = 0;
    let mut topic_set = std::collections::HashSet::new();
    for cid in &active_ids {
        if let Some(s) = state.sessions.get(cid) {
            let map = s.subscriptions.read();
            subs += map.len();
            for f in map.keys() {
                topic_set.insert(f.as_str().to_string());
            }
        }
    }
    let topics = topic_set.len();
    let msgs_recv = state.metrics.messages_received();
    let msgs_sent = state.metrics.messages_forwarded();
    (conns, subs, topics, msgs_recv, msgs_sent)
}

/// Live gauges for the current snapshot, read from the session
/// directory and lock-free metrics. Management-plane only.
fn live_counters(state: &ApiState) -> crate::v5::monitor::LiveCounters {
    let conns = state.metrics.connections_active().max(0) as u64;
    let active_ids = state.sessions.active_client_ids();
    let mut subs: u64 = 0;
    let mut topic_set = std::collections::HashSet::new();
    for cid in &active_ids {
        if let Some(s) = state.sessions.get(cid) {
            let map = s.subscriptions.read();
            subs = subs.saturating_add(map.len() as u64);
            for f in map.keys() {
                topic_set.insert(f.as_str().to_string());
            }
        }
    }
    crate::v5::monitor::LiveCounters {
        connections: conns,
        live_connections: conns,
        topics: topic_set.len() as u64,
        subscriptions: subs,
        received: state.metrics.messages_received(),
        sent: state.metrics.messages_forwarded(),
        dropped: state.metrics.messages_dropped(),
        rules_matched: state.metrics.rules_executed(),
    }
}

fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Documented `GET /monitor_current` snapshot: the latest sample as a
/// single object with the same current-value fields as one `GET /monitor`
/// history point.
///
/// Every value is numeric. Gauges (`connections`, `live_connections`,
/// `topics`, `subscriptions`) and cumulative counters (`received`,
/// `sent`, `dropped`, `rules_matched`) are read live from the session
/// directory and lock-free metrics, so two reads with traffic in between
/// never move those counters backwards. Fields with no kernel tracking yet
/// (durable gauges, validation/transformation splits, persistence and
/// action counters) are carried over from the newest history point when one
/// exists, else zero, so the shape stays stable and the snapshot combines
/// live counters with history without doing any sampling work here.
///
/// Never paged; always succeeds when the node is up. The query string is
/// not read, so unknown query parameters are ignored instead of rejected.
/// Management-plane only: one metrics snapshot, one bounded session-directory
/// scan and one short history lock per request; nothing here runs on the
/// per-message path and no new buffering is added to fan-out or fan-in.
pub async fn monitor_current(State(state): State<ApiState>) -> Response {
    (StatusCode::OK, Json(current_snapshot_value(&state))).into_response()
}

/// Shared snapshot read for `GET /monitor_current` and its node-scoped
/// twin below. Combines live counters with the newest history point in
/// constant time; no sampling work is added to the message path.
fn current_snapshot_value(state: &ApiState) -> serde_json::Value {
    let now = now_epoch_secs();
    let live = live_counters(state);
    let mut sample = crate::v5::monitor::MonitorSample::from_live(now, live);
    if let Some(prev) = state.monitor.latest() {
        sample.subscriptions_durable = prev.subscriptions_durable;
        sample.disconnected_durable_sessions = prev.disconnected_durable_sessions;
        sample.persisted = prev.persisted;
        sample.validation_succeeded = prev.validation_succeeded;
        sample.validation_failed = prev.validation_failed;
        sample.transformation_succeeded = prev.transformation_succeeded;
        sample.transformation_failed = prev.transformation_failed;
        sample.actions_executed = prev.actions_executed;
        sample.actions_messages = prev.actions_messages;
    }
    sample.to_json()
}

/// `GET /monitor_current/nodes/{node}`: node-scoped read of the same
/// snapshot as `GET /monitor_current`.
///
/// Single node, management-plane only: the named node is checked with the
/// shared [`resolve_node`] helper against the configured [`ApiState::node_id`]
/// (falling back to the [`LEGACY_NODE_NAME`] literal the v5 rows render
/// today); an unknown name returns the helper's 404 `NOT_FOUND` shape
/// naming the node. A known name returns the same single-object shape as
/// [`monitor_current`] (same numeric fields, same history carry-over),
/// with one metrics snapshot, one bounded session-directory scan and one
/// short history lock per request and no work on the per-message path.
pub async fn monitor_current_node(
    State(state): State<ApiState>,
    Path(node): Path<String>,
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
    (StatusCode::OK, Json(current_snapshot_value(&state))).into_response()
}

pub async fn get_stats(State(state): State<ApiState>) -> Response {
    let node_name = "indramqtt@127.0.0.1";
    let (conns, subs, topics, _recv, _sent) = gather_stats(&state);

    (
        StatusCode::OK,
        Json(serde_json::json!([
            {
                "node": node_name,
                "connections.count": conns,
                "connections.max": conns.max(100),
                "live_connections.count": conns,
                "live_connections.max": conns.max(100),
                "subscriptions.count": subs,
                "subscriptions.max": subs.max(100),
                "subscriptions.shared.count": 0,
                "subscriptions.shared.max": 0,
                "topics.count": topics,
                "topics.max": topics.max(100),
                "retained.count": 0,
                "retained.max": 0
            }
        ])),
    )
        .into_response()
}

/// Shared snapshot read for `GET /nodes/{node}/stats`.
///
/// Copies the gauge-plus-high-water-mark store once per request
/// ([`broker_observability::StatsStore::snapshot`], eight atomic loads)
/// and renders the documented per-node stat names from that copy, so one
/// read costs a bounded copy of the gauge block and adds no work to the
/// per-message path. All `set_*` updates already happen at kernel
/// lifecycle points; this read only copies.
///
/// Mapping follows the documented names: `connections`, `live_connections`,
/// `channels`, `sessions` and `cluster_sessions` all read the connection
/// gauge (single node: one channel and one session per bound connection);
/// `suboptions` reads the subscription gauge (one options record per
/// subscription); `subscribers` is bounded by both gauges (distinct
/// subscriber clients can be neither more than bound connections nor more
/// than subscription entries under active-only counting); `delayed` and
/// `subscriptions.shared` read zero (no kernel tracking yet, shape stays
/// stable and they rise once their subsystem records them).
/// Management-plane only; never touched on fan-out or fan-in.
fn stats_snapshot_value(state: &ApiState) -> serde_json::Value {
    let snap = state.stats.snapshot();
    let conns = snap.connections;
    let conns_max = snap.connections_max;
    let subs = snap.subscriptions;
    let subs_max = snap.subscriptions_max;
    let topics = snap.topics;
    let topics_max = snap.topics_max;
    let retained = snap.retained;
    let retained_max = snap.retained_max;
    let subscribers = conns.min(subs);
    let subscribers_max = conns_max.min(subs_max);
    // Built as an explicit map instead of one large `json!` literal: the
    // macro recurses once per key and trips the compiler recursion limit
    // at this size, while a map insert per gauge stays flat.
    let mut body = serde_json::Map::with_capacity(24);
    body.insert("channels.count".to_string(), serde_json::Value::from(conns));
    body.insert(
        "channels.max".to_string(),
        serde_json::Value::from(conns_max),
    );
    body.insert(
        "connections.count".to_string(),
        serde_json::Value::from(conns),
    );
    body.insert(
        "connections.max".to_string(),
        serde_json::Value::from(conns_max),
    );
    body.insert("delayed.count".to_string(), serde_json::Value::from(0u64));
    body.insert("delayed.max".to_string(), serde_json::Value::from(0u64));
    body.insert(
        "live_connections.count".to_string(),
        serde_json::Value::from(conns),
    );
    body.insert(
        "live_connections.max".to_string(),
        serde_json::Value::from(conns_max),
    );
    body.insert(
        "cluster_sessions.count".to_string(),
        serde_json::Value::from(conns),
    );
    body.insert(
        "cluster_sessions.max".to_string(),
        serde_json::Value::from(conns_max),
    );
    body.insert(
        "retained.count".to_string(),
        serde_json::Value::from(retained),
    );
    body.insert(
        "retained.max".to_string(),
        serde_json::Value::from(retained_max),
    );
    body.insert("sessions.count".to_string(), serde_json::Value::from(conns));
    body.insert(
        "sessions.max".to_string(),
        serde_json::Value::from(conns_max),
    );
    body.insert(
        "suboptions.count".to_string(),
        serde_json::Value::from(subs),
    );
    body.insert(
        "suboptions.max".to_string(),
        serde_json::Value::from(subs_max),
    );
    body.insert(
        "subscribers.count".to_string(),
        serde_json::Value::from(subscribers),
    );
    body.insert(
        "subscribers.max".to_string(),
        serde_json::Value::from(subscribers_max),
    );
    body.insert(
        "subscriptions.count".to_string(),
        serde_json::Value::from(subs),
    );
    body.insert(
        "subscriptions.max".to_string(),
        serde_json::Value::from(subs_max),
    );
    body.insert(
        "subscriptions.shared.count".to_string(),
        serde_json::Value::from(0u64),
    );
    body.insert(
        "subscriptions.shared.max".to_string(),
        serde_json::Value::from(0u64),
    );
    body.insert("topics.count".to_string(), serde_json::Value::from(topics));
    body.insert(
        "topics.max".to_string(),
        serde_json::Value::from(topics_max),
    );
    serde_json::Value::Object(body)
}

/// `GET /nodes/{node}/stats`: node-scoped read of the documented
/// resource and session statistics.
///
/// Single node, management-plane only: the named node is checked with the
/// shared [`resolve_node`] helper against the configured [`ApiState::node_id`]
/// (falling back to the [`LEGACY_NODE_NAME`] literal the v5 rows render
/// today); an unknown name returns the helper's 404 `NOT_FOUND` shape
/// naming the node. A known name returns the single-object snapshot from
/// [`stats_snapshot_value`] over the shared gauge-plus-high-water-mark
/// store (one constant-time copy per request, kept exact by the kernel
/// lifecycle points), with every value numeric and no work on the
/// per-message path.
pub async fn get_stats_node(State(state): State<ApiState>, Path(node): Path<String>) -> Response {
    if resolve_node(&state.node_id, &node).is_err()
        && resolve_node(LEGACY_NODE_NAME, &node).is_err()
    {
        // Reuse the helper's error so the unknown-node shape stays exactly
        // the documented `{code: NOT_FOUND, message}` body.
        return resolve_node(&state.node_id, &node)
            .expect_err("node already checked as unknown")
            .into_response();
    }
    (StatusCode::OK, Json(stats_snapshot_value(&state))).into_response()
}

/// Shared snapshot read for `GET /metrics` and its node-scoped twin below.
///
/// Builds the documented flat object of named counters: every value is
/// numeric and counters only move forward within a run. Each field reads
/// a lock-free atomic (or a saturating sum of atomics) copied once per
/// request through the shared snapshot, so one scrape costs a bounded
/// copy of the counter block and adds no work to the per-message path.
/// All increments already happen on the message path; this read only copies.
///
/// Grouping follows the documented names: `bytes`, `packets`, `messages`,
/// `delivery`, `client` and `session`. Fields with no kernel tracking yet
/// (QoS 2 acknowledgement flows, unsubscribe/disconnect packet splits,
/// delayed/retained message stores, session lifecycle) read zero so the
/// shape stays stable; they rise once their subsystem records them.
/// Management-plane only; never touched on fan-out or fan-in.
fn metrics_snapshot_value(state: &ApiState) -> serde_json::Value {
    let snap = state.metrics.snapshot();
    let packets_received = snap
        .connect_received
        .saturating_add(snap.publish_received)
        .saturating_add(snap.subscribe_received)
        .saturating_add(snap.pingreq_received);
    let packets_sent = snap
        .connack_sent
        .saturating_add(snap.publish_sent)
        .saturating_add(snap.suback_sent)
        .saturating_add(snap.pingresp_sent);
    let delivery_dropped = snap
        .overload_dropped
        .saturating_add(snap.unknown_conn_dropped)
        .saturating_add(snap.dead_mailbox_dropped)
        .saturating_add(snap.detached_clean_dropped)
        .saturating_add(snap.offline_queue_evicted)
        .saturating_add(snap.inflight_dropped)
        .saturating_add(snap.egress_qos0_shed);
    let delivery_queue_full = snap
        .overload_dropped
        .saturating_add(snap.offline_queue_evicted)
        .saturating_add(snap.inflight_dropped);
    // Built as an explicit map instead of one large `json!` literal: the
    // macro recurses once per key and trips the compiler recursion limit
    // at this size, while a map insert per counter stays flat.
    let mut body = serde_json::Map::with_capacity(57);
    body.insert(
        "bytes.received".to_string(),
        serde_json::Value::from(snap.bytes_received),
    );
    body.insert(
        "bytes.sent".to_string(),
        serde_json::Value::from(snap.bytes_sent),
    );
    body.insert(
        "packets.received".to_string(),
        serde_json::Value::from(packets_received),
    );
    body.insert(
        "packets.sent".to_string(),
        serde_json::Value::from(packets_sent),
    );
    body.insert(
        "packets.connect.received".to_string(),
        serde_json::Value::from(snap.connect_received),
    );
    body.insert(
        "packets.connack.sent".to_string(),
        serde_json::Value::from(snap.connack_sent),
    );
    body.insert(
        "packets.connack.error".to_string(),
        serde_json::Value::from(snap.auth_failures),
    );
    body.insert(
        "packets.connack.auth_error".to_string(),
        serde_json::Value::from(snap.auth_failures),
    );
    body.insert(
        "packets.publish.received".to_string(),
        serde_json::Value::from(snap.publish_received),
    );
    body.insert(
        "packets.publish.sent".to_string(),
        serde_json::Value::from(snap.publish_sent),
    );
    body.insert(
        "packets.publish.error".to_string(),
        serde_json::Value::from(0u64),
    );
    body.insert(
        "packets.publish.auth_error".to_string(),
        serde_json::Value::from(0u64),
    );
    body.insert(
        "packets.puback.received".to_string(),
        serde_json::Value::from(0u64),
    );
    body.insert(
        "packets.puback.sent".to_string(),
        serde_json::Value::from(0u64),
    );
    body.insert(
        "packets.pubrec.received".to_string(),
        serde_json::Value::from(0u64),
    );
    body.insert(
        "packets.pubrec.sent".to_string(),
        serde_json::Value::from(0u64),
    );
    body.insert(
        "packets.pubrel.received".to_string(),
        serde_json::Value::from(0u64),
    );
    body.insert(
        "packets.pubrel.sent".to_string(),
        serde_json::Value::from(0u64),
    );
    body.insert(
        "packets.pubcomp.received".to_string(),
        serde_json::Value::from(0u64),
    );
    body.insert(
        "packets.pubcomp.sent".to_string(),
        serde_json::Value::from(0u64),
    );
    body.insert(
        "packets.subscribe.received".to_string(),
        serde_json::Value::from(snap.subscribe_received),
    );
    body.insert(
        "packets.suback.sent".to_string(),
        serde_json::Value::from(snap.suback_sent),
    );
    body.insert(
        "packets.unsubscribe.received".to_string(),
        serde_json::Value::from(0u64),
    );
    body.insert(
        "packets.unsuback.sent".to_string(),
        serde_json::Value::from(0u64),
    );
    body.insert(
        "packets.pingreq.received".to_string(),
        serde_json::Value::from(snap.pingreq_received),
    );
    body.insert(
        "packets.pingresp.sent".to_string(),
        serde_json::Value::from(snap.pingresp_sent),
    );
    body.insert(
        "packets.disconnect.received".to_string(),
        serde_json::Value::from(0u64),
    );
    body.insert(
        "packets.disconnect.sent".to_string(),
        serde_json::Value::from(0u64),
    );
    body.insert(
        "messages.received".to_string(),
        serde_json::Value::from(snap.messages_received),
    );
    body.insert(
        "messages.sent".to_string(),
        serde_json::Value::from(snap.delivered),
    );
    body.insert(
        "messages.dropped".to_string(),
        serde_json::Value::from(snap.messages_dropped),
    );
    body.insert(
        "messages.delivered".to_string(),
        serde_json::Value::from(snap.delivered),
    );
    body.insert("messages.acked".to_string(), serde_json::Value::from(0u64));
    body.insert(
        "messages.retained".to_string(),
        serde_json::Value::from(0u64),
    );
    body.insert(
        "messages.delayed".to_string(),
        serde_json::Value::from(0u64),
    );
    body.insert(
        "messages.qos0.received".to_string(),
        serde_json::Value::from(snap.qos0_received),
    );
    body.insert(
        "messages.qos1.received".to_string(),
        serde_json::Value::from(snap.qos1_received),
    );
    body.insert(
        "messages.qos2.received".to_string(),
        serde_json::Value::from(snap.qos2_received),
    );
    body.insert(
        "messages.qos0.sent".to_string(),
        serde_json::Value::from(0u64),
    );
    body.insert(
        "messages.qos1.sent".to_string(),
        serde_json::Value::from(0u64),
    );
    body.insert(
        "messages.qos2.sent".to_string(),
        serde_json::Value::from(0u64),
    );
    body.insert(
        "delivery.dropped".to_string(),
        serde_json::Value::from(delivery_dropped),
    );
    body.insert(
        "delivery.dropped.no_subscribers".to_string(),
        serde_json::Value::from(snap.detached_clean_dropped),
    );
    body.insert(
        "delivery.dropped.qos0_msg".to_string(),
        serde_json::Value::from(snap.egress_qos0_shed),
    );
    body.insert(
        "delivery.dropped.queue_full".to_string(),
        serde_json::Value::from(delivery_queue_full),
    );
    body.insert(
        "delivery.dropped.expired".to_string(),
        serde_json::Value::from(0u64),
    );
    body.insert(
        "client.connect".to_string(),
        serde_json::Value::from(snap.connect_received),
    );
    body.insert(
        "client.connack".to_string(),
        serde_json::Value::from(snap.connack_sent),
    );
    body.insert(
        "client.connected".to_string(),
        serde_json::Value::from(snap.connect_received),
    );
    body.insert(
        "client.disconnected".to_string(),
        serde_json::Value::from(0u64),
    );
    body.insert(
        "client.subscribe".to_string(),
        serde_json::Value::from(snap.subscribe_received),
    );
    body.insert(
        "client.unsubscribe".to_string(),
        serde_json::Value::from(0u64),
    );
    body.insert("session.created".to_string(), serde_json::Value::from(0u64));
    body.insert(
        "session.discarded".to_string(),
        serde_json::Value::from(0u64),
    );
    body.insert("session.resumed".to_string(), serde_json::Value::from(0u64));
    body.insert(
        "session.takenover".to_string(),
        serde_json::Value::from(0u64),
    );
    body.insert(
        "session.terminated".to_string(),
        serde_json::Value::from(0u64),
    );
    serde_json::Value::Object(body)
}

/// Documented `GET /metrics` snapshot: a flat object of named counters.
///
/// Every value is numeric and counters only move forward within a run:
/// one scrape costs a bounded copy of the counter block through the
/// shared snapshot and adds no work to the per-message path.
/// Management-plane only; never touched on fan-out or fan-in.
pub async fn get_metrics(State(state): State<ApiState>) -> Response {
    (StatusCode::OK, Json(metrics_snapshot_value(&state))).into_response()
}

/// `GET /nodes/{node}/metrics`: node-scoped read of the same snapshot
/// as `GET /metrics`.
///
/// Single node, management-plane only: the named node is checked with the
/// shared [`resolve_node`] helper against the configured [`ApiState::node_id`]
/// (falling back to the [`LEGACY_NODE_NAME`] literal the v5 rows render
/// today); an unknown name returns the helper's 404 `NOT_FOUND` shape
/// naming the node. A known name returns the same flat object of named
/// numeric counters as [`get_metrics`] (same documented names, same
/// monotonic counters), with one bounded counter-block copy per request
/// and no work on the per-message path.
pub async fn get_metrics_node(State(state): State<ApiState>, Path(node): Path<String>) -> Response {
    if resolve_node(&state.node_id, &node).is_err()
        && resolve_node(LEGACY_NODE_NAME, &node).is_err()
    {
        // Reuse the helper's error so the unknown-node shape stays exactly
        // the documented `{code: NOT_FOUND, message}` body.
        return resolve_node(&state.node_id, &node)
            .expect_err("node already checked as unknown")
            .into_response();
    }
    (StatusCode::OK, Json(metrics_snapshot_value(&state))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ApiState;

    fn standalone_state() -> ApiState {
        let engine = std::sync::Arc::new(broker_rules::RuleEngine::new(
            16,
            broker_rules::BackpressurePolicy::DropOldest,
        ));
        ApiState::standalone(engine)
    }

    async fn snapshot_body(response: Response) -> (StatusCode, serde_json::Value) {
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .expect("current snapshot body is small and readable");
        let body: serde_json::Value =
            serde_json::from_slice(&bytes).expect("current snapshot body is JSON");
        (status, body)
    }

    fn documented_fields() -> [&'static str; 18] {
        [
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
        ]
    }

    #[tokio::test]
    async fn current_snapshot_has_documented_numeric_fields() {
        let state = standalone_state();
        state.metrics.inc_messages_received();
        state.metrics.inc_messages_forwarded_by(2);
        state.metrics.inc_messages_dropped();
        state.metrics.inc_rules_executed();
        state.metrics.set_active_connections(1);

        let (status, body) = snapshot_body(monitor_current(State(state)).await).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.is_object(),
            "snapshot must be a single object, got: {body}"
        );
        for field in documented_fields() {
            assert!(body.get(field).is_some(), "missing field {field}: {body}");
            assert!(
                body[field].is_u64(),
                "field {field} must be numeric, got: {body}"
            );
        }
        assert!(body["time_stamp"].as_u64().expect("time stamp") > 0);
        assert_eq!(body["received"], serde_json::json!(1));
        assert_eq!(body["sent"], serde_json::json!(2));
        assert_eq!(body["dropped"], serde_json::json!(1));
        assert_eq!(body["rules_matched"], serde_json::json!(1));
    }

    #[tokio::test]
    async fn current_snapshot_counters_are_non_decreasing() {
        let state = standalone_state();

        let (_, first) = snapshot_body(monitor_current(State(state.clone())).await).await;
        state.metrics.inc_messages_received();
        state.metrics.inc_messages_forwarded_by(3);
        state.metrics.inc_rules_executed_by(2);
        let (_, second) = snapshot_body(monitor_current(State(state.clone())).await).await;

        for field in documented_fields() {
            assert!(second.get(field).is_some(), "missing field {field}");
            assert!(second[field].is_u64(), "field {field} must stay numeric");
        }
        for field in [
            "received",
            "sent",
            "dropped",
            "rules_matched",
            "connections",
            "live_connections",
            "topics",
            "subscriptions",
        ] {
            let before = first[field].as_u64().expect("first numeric");
            let after = second[field].as_u64().expect("second numeric");
            assert!(
                after >= before,
                "field {field} must not move backwards: {before} -> {after}"
            );
        }
        assert!(second["received"].as_u64().expect("received") >= 1);
        assert!(second["sent"].as_u64().expect("sent") >= 3);
        assert!(second["rules_matched"].as_u64().expect("rules") >= 2);
        assert!(
            second["time_stamp"].as_u64().expect("stamp")
                >= first["time_stamp"].as_u64().expect("first stamp")
        );
    }

    #[tokio::test]
    async fn current_snapshot_carries_newest_history_point() {
        let state = standalone_state();
        let prev = crate::v5::monitor::MonitorSample {
            time_stamp: 1_700_000_100,
            connections: 0,
            live_connections: 0,
            topics: 0,
            subscriptions: 0,
            subscriptions_durable: 4,
            disconnected_durable_sessions: 5,
            received: 0,
            sent: 0,
            dropped: 0,
            persisted: 6,
            validation_succeeded: 7,
            validation_failed: 8,
            transformation_succeeded: 9,
            transformation_failed: 10,
            rules_matched: 0,
            actions_executed: 11,
            actions_messages: 12,
        };
        state.monitor.record(prev);
        state.metrics.inc_messages_received();

        let (status, body) = snapshot_body(monitor_current(State(state)).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["received"], serde_json::json!(1));
        assert_eq!(body["subscriptions_durable"], serde_json::json!(4));
        assert_eq!(body["disconnected_durable_sessions"], serde_json::json!(5));
        assert_eq!(body["persisted"], serde_json::json!(6));
        assert_eq!(body["validation_succeeded"], serde_json::json!(7));
        assert_eq!(body["validation_failed"], serde_json::json!(8));
        assert_eq!(body["transformation_succeeded"], serde_json::json!(9));
        assert_eq!(body["transformation_failed"], serde_json::json!(10));
        assert_eq!(body["actions_executed"], serde_json::json!(11));
        assert_eq!(body["actions_messages"], serde_json::json!(12));
    }

    #[tokio::test]
    async fn node_snapshot_returns_same_shape_as_global() {
        let state = standalone_state();
        state.metrics.inc_messages_received();
        state.metrics.inc_messages_forwarded_by(2);
        state.metrics.inc_messages_dropped();
        state.metrics.inc_rules_executed();
        state.metrics.set_active_connections(1);
        let prev = crate::v5::monitor::MonitorSample {
            time_stamp: 1_700_000_100,
            connections: 0,
            live_connections: 0,
            topics: 0,
            subscriptions: 0,
            subscriptions_durable: 4,
            disconnected_durable_sessions: 5,
            received: 0,
            sent: 0,
            dropped: 0,
            persisted: 6,
            validation_succeeded: 7,
            validation_failed: 8,
            transformation_succeeded: 9,
            transformation_failed: 10,
            rules_matched: 0,
            actions_executed: 11,
            actions_messages: 12,
        };
        state.monitor.record(prev);
        let (_, global) = snapshot_body(monitor_current(State(state.clone())).await).await;
        for known in [LEGACY_NODE_NAME, "indra-node-1"] {
            let response =
                monitor_current_node(State(state.clone()), Path(known.to_string())).await;
            let (status, body) = snapshot_body(response).await;
            assert_eq!(status, StatusCode::OK, "known node {known}");
            assert!(
                body.is_object(),
                "node snapshot must be a single object, got: {body}"
            );
            for field in documented_fields() {
                assert!(body.get(field).is_some(), "missing field {field}: {body}");
                assert!(
                    body[field].is_u64(),
                    "field {field} must be numeric, got: {body}"
                );
            }
            // Same live counters and history carry-over as the global read.
            assert_eq!(body["received"], global["received"]);
            assert_eq!(body["sent"], global["sent"]);
            assert_eq!(body["dropped"], global["dropped"]);
            assert_eq!(body["rules_matched"], global["rules_matched"]);
            assert_eq!(body["subscriptions_durable"], serde_json::json!(4));
            assert_eq!(body["actions_messages"], serde_json::json!(12));
        }
    }

    #[tokio::test]
    async fn node_snapshot_unknown_node_is_not_found() {
        let state = standalone_state();
        state.metrics.inc_messages_received();
        let response = monitor_current_node(State(state), Path("no-such-node".to_string())).await;
        let (status, body) = snapshot_body(response).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["code"], serde_json::json!("NOT_FOUND"));
        let message = body["message"].as_str().expect("message is a string");
        assert!(
            message.contains("no-such-node"),
            "message names the unknown node: {body}"
        );
    }

    fn documented_metric_names() -> [&'static str; 28] {
        [
            "bytes.received",
            "bytes.sent",
            "packets.received",
            "packets.sent",
            "packets.connect.received",
            "packets.connack.sent",
            "packets.connack.error",
            "packets.connack.auth_error",
            "packets.publish.received",
            "packets.publish.sent",
            "packets.subscribe.received",
            "packets.suback.sent",
            "packets.pingreq.received",
            "packets.pingresp.sent",
            "messages.received",
            "messages.sent",
            "messages.dropped",
            "messages.delivered",
            "messages.qos0.received",
            "messages.qos1.received",
            "messages.qos2.received",
            "delivery.dropped",
            "delivery.dropped.no_subscribers",
            "delivery.dropped.queue_full",
            "client.connect",
            "client.connack",
            "client.connected",
            "client.subscribe",
        ]
    }

    #[tokio::test]
    async fn node_metrics_match_global_names_and_stay_numeric() {
        let state = standalone_state();
        state.metrics.inc_messages_received();
        state.metrics.inc_messages_forwarded();
        state.metrics.inc_messages_dropped();
        let (_, global) = snapshot_body(get_metrics(State(state.clone())).await).await;
        let global_map = global.as_object().expect("global metrics is a flat object");
        for known in [LEGACY_NODE_NAME, "indra-node-1"] {
            let response = get_metrics_node(State(state.clone()), Path(known.to_string())).await;
            let (status, body) = snapshot_body(response).await;
            assert_eq!(status, StatusCode::OK, "known node {known}");
            let node_map = body.as_object().expect("node metrics is a flat object");
            assert!(
                body.get("data").is_none(),
                "node metrics is not paged: {body}"
            );
            for name in documented_metric_names() {
                let value = node_map
                    .get(name)
                    .unwrap_or_else(|| panic!("missing {name} for node {known}"));
                assert!(value.is_number(), "{name} is numeric: {value:?}");
                assert_eq!(
                    value, &global_map[name],
                    "{name} matches the global read for node {known}"
                );
            }
        }
    }

    #[tokio::test]
    async fn node_metrics_unknown_node_is_not_found() {
        let state = standalone_state();
        state.metrics.inc_messages_received();
        let response = get_metrics_node(State(state), Path("no-such-node".to_string())).await;
        let (status, body) = snapshot_body(response).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["code"], serde_json::json!("NOT_FOUND"));
        let message = body["message"].as_str().expect("message is a string");
        assert!(
            message.contains("no-such-node"),
            "message names the unknown node: {body}"
        );
    }

    fn documented_stat_names() -> [&'static str; 24] {
        [
            "channels.count",
            "channels.max",
            "connections.count",
            "connections.max",
            "delayed.count",
            "delayed.max",
            "live_connections.count",
            "live_connections.max",
            "cluster_sessions.count",
            "cluster_sessions.max",
            "retained.count",
            "retained.max",
            "sessions.count",
            "sessions.max",
            "suboptions.count",
            "suboptions.max",
            "subscribers.count",
            "subscribers.max",
            "subscriptions.count",
            "subscriptions.max",
            "subscriptions.shared.count",
            "subscriptions.shared.max",
            "topics.count",
            "topics.max",
        ]
    }

    #[tokio::test]
    async fn node_stats_returns_documented_numeric_fields_from_store() {
        let state = standalone_state();
        state.stats.set_connections(3);
        state.stats.set_subscriptions(7);
        state.stats.set_topics(2);
        state.stats.set_retained(1);
        for known in [LEGACY_NODE_NAME, "indra-node-1"] {
            let response = get_stats_node(State(state.clone()), Path(known.to_string())).await;
            let (status, body) = snapshot_body(response).await;
            assert_eq!(status, StatusCode::OK, "known node {known}");
            assert!(
                body.is_object(),
                "node stats must be a single object, got: {body}"
            );
            assert!(
                body.get("data").is_none(),
                "node stats is not paged: {body}"
            );
            for name in documented_stat_names() {
                let value = body
                    .get(name)
                    .unwrap_or_else(|| panic!("missing {name} for node {known}"));
                assert!(value.is_number(), "{name} is numeric: {value:?}");
            }
            // Tracked gauges read the store snapshot exactly.
            assert_eq!(body["connections.count"], serde_json::json!(3));
            assert_eq!(body["live_connections.count"], serde_json::json!(3));
            assert_eq!(body["channels.count"], serde_json::json!(3));
            assert_eq!(body["sessions.count"], serde_json::json!(3));
            assert_eq!(body["cluster_sessions.count"], serde_json::json!(3));
            assert_eq!(body["subscriptions.count"], serde_json::json!(7));
            assert_eq!(body["suboptions.count"], serde_json::json!(7));
            assert_eq!(body["topics.count"], serde_json::json!(2));
            assert_eq!(body["retained.count"], serde_json::json!(1));
            assert_eq!(body["subscriptions.shared.count"], serde_json::json!(0));
            assert_eq!(body["delayed.count"], serde_json::json!(0));
            // High-water marks come from the store and never sit below
            // their gauge.
            for (count, max) in [
                ("connections.count", "connections.max"),
                ("live_connections.count", "live_connections.max"),
                ("subscriptions.count", "subscriptions.max"),
                ("topics.count", "topics.max"),
                ("retained.count", "retained.max"),
            ] {
                let current = body[count].as_u64().expect("count numeric");
                let peak = body[max].as_u64().expect("max numeric");
                assert!(
                    peak >= current,
                    "{max} ({peak}) must cover {count} ({current}): {body}"
                );
            }
        }
    }

    #[tokio::test]
    async fn node_stats_maxima_come_from_store_and_never_fall() {
        let state = standalone_state();
        state.stats.set_connections(5);
        state.stats.set_subscriptions(7);
        state.stats.set_topics(3);
        state.stats.set_retained(2);
        let response = get_stats_node(State(state.clone()), Path("indra-node-1".to_string())).await;
        let (_, peak) = snapshot_body(response).await;
        assert_eq!(peak["connections.max"], serde_json::json!(5));
        assert_eq!(peak["subscriptions.max"], serde_json::json!(7));
        // Gauges fall; maxima stay at the true peak from the store.
        state.stats.set_connections(2);
        state.stats.set_subscriptions(0);
        state.stats.set_topics(1);
        state.stats.set_retained(0);
        let response = get_stats_node(State(state), Path("indra-node-1".to_string())).await;
        let (status, body) = snapshot_body(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["connections.count"], serde_json::json!(2));
        assert_eq!(body["connections.max"], serde_json::json!(5));
        assert_eq!(body["subscriptions.count"], serde_json::json!(0));
        assert_eq!(body["subscriptions.max"], serde_json::json!(7));
        assert_eq!(body["topics.count"], serde_json::json!(1));
        assert_eq!(body["topics.max"], serde_json::json!(3));
        assert_eq!(body["retained.count"], serde_json::json!(0));
        assert_eq!(body["retained.max"], serde_json::json!(2));
    }

    #[tokio::test]
    async fn node_stats_unknown_node_is_not_found() {
        let state = standalone_state();
        state.stats.set_connections(1);
        let response = get_stats_node(State(state), Path("no-such-node".to_string())).await;
        let (status, body) = snapshot_body(response).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["code"], serde_json::json!("NOT_FOUND"));
        let message = body["message"].as_str().expect("message is a string");
        assert!(
            message.contains("no-such-node"),
            "message names the unknown node: {body}"
        );
    }
}
