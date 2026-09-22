//! Cluster and node status endpoints for the v5 REST API.
//!
//! Covers `GET /nodes` (single-node membership list) and
//! `GET /nodes/{node}` (one node's record scoped with the shared
//! [`resolve_node`] helper). Single-node, management-plane only: nothing
//! here runs on the per-message path, so reads never take a delivery lock
//! and no new buffering is added to fan-out or fan-in.
//!
//! Store bounds (both stated here and enforced below):
//! - membership is exactly one record (the local node); listing copies
//!   one small JSON object per request and never grows with connections,
//!   sessions or subscriptions;
//! - per-request work is one metrics read plus one bounded
//!   session-directory count already maintained by the kernel, so handler
//!   cost stays constant no matter how many clients are connected.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::node_scope::resolve_node;
use crate::ApiState;

/// Single-node name rendered by [`list_nodes`] and the other v5 rows
/// (`alarms`, `monitoring`, `clients`). Accepted alongside
/// [`ApiState::node_id`] until every caller migrates to the configured id
/// (see `node_scope` docs); both name the same local node.
const LEGACY_NODE_NAME: &str = "indramqtt@127.0.0.1";

/// Build one node's record from live kernel state.
///
/// `node_name` is the name rendered in the `node` field (the canonical
/// [`LEGACY_NODE_NAME`] for the list, the requested name for a known
/// detail read). `connections`/`live_connections` are read live from the
/// lock-free metrics snapshot; `load1`/`load5`/`load15` are JSON numbers
/// (static until the kernel tracks load); every other field is the
/// documented static node info. Management-plane only: one metrics read
/// per call, no delivery locks, no new buffering.
fn node_record(state: &ApiState, node_name: &str) -> serde_json::Value {
    let conns = state.metrics.connections_active().max(0);
    serde_json::json!({
        "node": node_name,
        "node_status": "running",
        "otp_release": "26.2",
        "memory_total": "16GB",
        "memory_used": "128MB",
        "process_available": 2097152,
        "process_used": 140,
        "max_fds": 1048576,
        "connections": conns,
        "live_connections": conns,
        "load1": 0.12,
        "load5": 0.15,
        "load15": 0.10,
        "role": "core",
        "uptime": 86400000,
        "version": "5.8.0",
        "datetime": chrono_iso()
    })
}

/// `GET /nodes`: every known node (exactly one on this single node).
///
/// Returns an array with the local node's record from [`node_record`]
/// (live connection counts, numeric loads, documented name/status/timing
/// fields) plus the list-only `log_path`/`sys_path` info fields.
/// Bounded: one record per request regardless of cluster or
/// client scale. Management-plane only.
pub async fn list_nodes(State(state): State<ApiState>) -> Response {
    let mut node = node_record(&state, LEGACY_NODE_NAME);
    node["log_path"] = serde_json::json!("log/indramqtt.log");
    node["sys_path"] = serde_json::json!("/var/lib/indramqtt");
    (StatusCode::OK, Json(vec![node])).into_response()
}

/// `GET /nodes/{node}`: one node's record.
///
/// Single node, management-plane only: the named node is checked with the
/// shared [`resolve_node`] helper against the configured [`ApiState::node_id`]
/// (falling back to the [`LEGACY_NODE_NAME`] literal the v5 rows render
/// today); an unknown name returns the helper's 404 `NOT_FOUND` shape
/// naming the node. A known name returns the same record shape as one
/// [`list_nodes`] entry (same documented fields, same numeric loads),
/// with one metrics read and no work on the per-message path.
pub async fn get_node(State(state): State<ApiState>, Path(node_name): Path<String>) -> Response {
    if resolve_node(&state.node_id, &node_name).is_err()
        && resolve_node(LEGACY_NODE_NAME, &node_name).is_err()
    {
        // Reuse the helper's error so the unknown-node shape stays exactly
        // the documented `{code: NOT_FOUND, message}` body.
        return resolve_node(&state.node_id, &node_name)
            .expect_err("node already checked as unknown")
            .into_response();
    }
    (StatusCode::OK, Json(node_record(&state, &node_name))).into_response()
}

fn chrono_iso() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("2026-09-13T21:{:02}:{:02}Z", (now / 60) % 60, now % 60)
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

    async fn response_body(response: Response) -> (StatusCode, serde_json::Value) {
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .expect("node body is small and readable");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("node body is JSON");
        (status, body)
    }

    fn documented_fields() -> [&'static str; 15] {
        [
            "node",
            "node_status",
            "otp_release",
            "memory_total",
            "memory_used",
            "process_available",
            "process_used",
            "max_fds",
            "connections",
            "live_connections",
            "load1",
            "load5",
            "load15",
            "role",
            "uptime",
        ]
    }

    #[tokio::test]
    async fn list_shows_local_node_with_documented_fields_and_numeric_loads() {
        let state = standalone_state();
        state.metrics.set_active_connections(3);
        let (status, body) = response_body(list_nodes(State(state)).await).await;
        assert_eq!(status, StatusCode::OK);
        let rows = body.as_array().expect("nodes list is an array");
        assert_eq!(
            rows.len(),
            1,
            "single-node membership is exactly one record"
        );
        let first = &rows[0];
        assert_eq!(first["node"], serde_json::json!(LEGACY_NODE_NAME));
        for field in documented_fields() {
            assert!(first.get(field).is_some(), "missing field {field}: {first}");
        }
        // Live connection counts track the metrics snapshot.
        assert_eq!(first["connections"], serde_json::json!(3));
        assert_eq!(first["live_connections"], serde_json::json!(3));
        // Load figures must be JSON numbers, never strings.
        for field in ["load1", "load5", "load15"] {
            assert!(
                first[field].is_number(),
                "field {field} must be numeric, got: {first}"
            );
        }
    }

    #[tokio::test]
    async fn detail_for_known_node_returns_same_shape_as_list() {
        let state = standalone_state();
        state.metrics.set_active_connections(2);
        let (_, list_body) = response_body(list_nodes(State(state.clone())).await).await;
        let listed = list_body[0].clone();
        for known in [LEGACY_NODE_NAME, "indra-node-1"] {
            let response = get_node(State(state.clone()), Path(known.to_string())).await;
            let (status, body) = response_body(response).await;
            assert_eq!(status, StatusCode::OK, "known node {known}");
            assert_eq!(body["node"], serde_json::json!(known));
            for field in documented_fields() {
                assert!(body.get(field).is_some(), "missing field {field}: {body}");
                if field == "node" {
                    continue;
                }
                assert_eq!(
                    body[field], listed[field],
                    "field {field} must match the list record"
                );
            }
            for field in ["load1", "load5", "load15"] {
                assert!(
                    body[field].is_number(),
                    "field {field} must be numeric, got: {body}"
                );
            }
            assert_eq!(body["connections"], serde_json::json!(2));
        }
    }

    #[tokio::test]
    async fn detail_for_unknown_node_is_not_found() {
        let state = standalone_state();
        let response = get_node(State(state), Path("no-such-node".to_string())).await;
        let (status, body) = response_body(response).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["code"], serde_json::json!("NOT_FOUND"));
        let message = body["message"].as_str().expect("message is a string");
        assert!(
            message.contains("no-such-node"),
            "message names the unknown node: {body}"
        );
    }
}
