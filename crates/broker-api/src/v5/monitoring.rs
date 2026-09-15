//! Live observability, rate metrics, and alarm polling for EMQX v5.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use crate::ApiState;

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

pub async fn monitor_current(State(state): State<ApiState>) -> Response {
    let (conns, subs, topics, msgs_recv, msgs_sent) = gather_stats(&state);

    // Rates calculation
    let in_rate = msgs_recv.min(9999);
    let out_rate = msgs_sent.min(9999);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "node": 1,
            "received_msg_rate": in_rate,
            "sent_msg_rate": out_rate,
            "received_bytes_rate": in_rate * 64,
            "sent_bytes_rate": out_rate * 64,
            "connections": conns,
            "live_connections": conns,
            "subscriptions": subs,
            "shared_subscriptions": 0,
            "topics": topics,
            "retained_msg_count": 0
        })),
    )
        .into_response()
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
