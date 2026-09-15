//! Cluster and Node status endpoints for EMQX v5.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::ApiState;

pub async fn list_nodes(State(state): State<ApiState>) -> Response {
    let conns = state.metrics.connections_active().max(0);

    let node = serde_json::json!({
        "node": "indramqtt@127.0.0.1",
        "node_status": "running",
        "otp_release": "26.2",
        "memory_total": "16GB",
        "memory_used": "128MB",
        "process_available": 2097152,
        "process_used": 140,
        "max_fds": 1048576,
        "connections": conns,
        "live_connections": conns,
        "load1": "0.12",
        "load5": "0.15",
        "load15": "0.10",
        "log_path": "log/indramqtt.log",
        "role": "core",
        "uptime": 86400000,
        "version": "5.8.0",
        "sys_path": "/var/lib/indramqtt",
        "datetime": chrono_iso()
    });

    (StatusCode::OK, Json(vec![node])).into_response()
}

pub async fn get_node(State(state): State<ApiState>, Path(node_name): Path<String>) -> Response {
    let conns = state.metrics.connections_active().max(0);
    (
        StatusCode::OK,
        Json(serde_json::json!({
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
            "load1": "0.12",
            "load5": "0.15",
            "load15": "0.10",
            "role": "core",
            "uptime": 86400000,
            "version": "5.8.0",
            "datetime": chrono_iso()
        })),
    )
        .into_response()
}

fn chrono_iso() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("2026-09-13T21:{:02}:{:02}Z", (now / 60) % 60, now % 60)
}
