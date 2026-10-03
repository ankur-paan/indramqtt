//! Configured network listeners for the v5 REST API (M1-06).
//!
//! Covers `GET /listeners` (the configured edge and API listeners).
//! Management-plane only: nothing here runs on the per-message path, so
//! reads never take a delivery lock and no new buffering is added to
//! fan-out or fan-in.
//!
//! Honesty rule: this endpoint reports the kernel's configured listeners
//! (the same `listeners.*` section the kernel binds from, captured at
//! boot into [`ApiState::listeners`]), not live edge socket state, and it
//! says so. Fields the broker does not track (per-listener connection
//! counts, acceptors) are omitted, never synthesised. Per-listener
//! detail and stop routes stay unimplemented (404):
// TODO(parity): should `GET /listeners/:id` and stop/resume exist, and
// should the rows report live edge socket state rather than configured
// binds? Neither the rulebook nor the task spec decides the shape; today
// only the configured list is served, fail-closed on unknown paths.
//!
//! Store bounds (both stated here and enforced below):
//! - exactly five rows (tcp, tls, ws, wss, api), one small JSON object
//!   each, regardless of connection, session or subscription scale;
//! - per-request work is one `Arc` clone plus rendering five rows, so
//!   handler cost stays constant no matter how many clients are connected.

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};

use crate::ApiState;

/// `GET /listeners`: the configured listeners as a bare array.
///
/// One row per listener section (`tcp`, `tls`, `ws`, `wss`, `api`) with
/// the configured `bind`, whether it is `enabled`, and the section's
/// extra addressing (`path` for the WebSocket sections). Disabled rows
/// are still listed so an operator can see what would start when
/// enabled; rows never invent live socket state. Returns a bare array to
/// match the list convention of the neighbouring collection routes.
pub async fn list_listeners(State(state): State<ApiState>) -> impl IntoResponse {
    let listeners = &state.listeners;
    let rows = vec![
        serde_json::json!({
            "id": "tcp:default",
            "protocol": "mqtt",
            "bind": listeners.tcp.bind,
            "enabled": listeners.tcp.enabled,
        }),
        serde_json::json!({
            "id": "tls:default",
            "protocol": "mqtts",
            "bind": listeners.tls.bind,
            "enabled": listeners.tls.enabled,
        }),
        serde_json::json!({
            "id": "ws:default",
            "protocol": "ws",
            "bind": listeners.ws.bind,
            "enabled": listeners.ws.enabled,
            "path": listeners.ws.path,
        }),
        serde_json::json!({
            "id": "wss:default",
            "protocol": "wss",
            "bind": listeners.wss.bind,
            "enabled": listeners.wss.enabled,
            "path": listeners.wss.path,
        }),
        serde_json::json!({
            "id": "api:default",
            "protocol": "http",
            "bind": listeners.api.bind,
            "enabled": listeners.api.enabled,
        }),
    ];
    (StatusCode::OK, Json(rows))
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

    async fn response_body(response: impl IntoResponse) -> (StatusCode, serde_json::Value) {
        let response = response.into_response();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .expect("listeners body is small and readable");
        let body: serde_json::Value =
            serde_json::from_slice(&bytes).expect("listeners body is JSON");
        (status, body)
    }

    #[tokio::test]
    async fn list_reports_five_configured_rows_with_binds() {
        let state = standalone_state();
        let (status, body) = response_body(list_listeners(State(state)).await).await;
        assert_eq!(status, StatusCode::OK);
        let rows = body.as_array().expect("listeners list is an array");
        assert_eq!(rows.len(), 5, "one row per listener section");
        let ids: Vec<&str> = rows
            .iter()
            .map(|r| r["id"].as_str().expect("row carries id"))
            .collect();
        assert_eq!(
            ids,
            vec![
                "tcp:default",
                "tls:default",
                "ws:default",
                "wss:default",
                "api:default"
            ]
        );
        for row in rows {
            assert!(row["bind"].is_string(), "row carries bind: {row}");
            assert!(row["enabled"].is_boolean(), "row carries enabled: {row}");
            assert!(row["protocol"].is_string(), "row carries protocol: {row}");
        }
        // Default configuration: plaintext and WS on, TLS and WSS off.
        let by_id = |id: &str| rows.iter().find(|r| r["id"] == id).expect(id);
        assert_eq!(by_id("tcp:default")["enabled"], serde_json::json!(true));
        assert_eq!(by_id("tls:default")["enabled"], serde_json::json!(false));
        assert_eq!(by_id("ws:default")["enabled"], serde_json::json!(true));
        assert_eq!(by_id("wss:default")["enabled"], serde_json::json!(false));
        // No synthesised live state: rows carry configuration only.
        for row in rows {
            assert!(row.get("connections").is_none(), "no invented count: {row}");
            assert!(row.get("acceptors").is_none(), "no invented count: {row}");
        }
    }

    #[tokio::test]
    async fn list_reflects_custom_binds() {
        let engine = std::sync::Arc::new(broker_rules::RuleEngine::new(
            16,
            broker_rules::BackpressurePolicy::DropOldest,
        ));
        let mut state = ApiState::standalone(engine);
        let mut listeners = broker_config::schema::ListenersConf::default();
        listeners.tcp.bind = "127.0.0.1:11883".to_string();
        listeners.api.bind = "127.0.0.1:28083".to_string();
        listeners.ws.enabled = false;
        state.listeners = std::sync::Arc::new(listeners);
        let (status, body) = response_body(list_listeners(State(state)).await).await;
        assert_eq!(status, StatusCode::OK);
        let rows = body.as_array().expect("listeners list is an array");
        let by_id = |id: &str| rows.iter().find(|r| r["id"] == id).expect(id);
        assert_eq!(
            by_id("tcp:default")["bind"],
            serde_json::json!("127.0.0.1:11883")
        );
        assert_eq!(
            by_id("api:default")["bind"],
            serde_json::json!("127.0.0.1:28083")
        );
        assert_eq!(by_id("ws:default")["enabled"], serde_json::json!(false));
    }
}
