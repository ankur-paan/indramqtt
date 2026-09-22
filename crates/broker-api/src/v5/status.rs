//! Node status endpoint for the v5 REST API.
//!
//! Covers `GET /status` (node readiness flag). Single-node,
//! management-plane only: nothing here runs on the per-message path, so
//! reads never take a delivery lock and no new buffering is added to
//! fan-out or fan-in.
//!
//! Store bounds (both stated here and enforced by construction):
//! - readiness is exactly one atomic bool shared with the kernel;
//!   listing copies one tiny JSON object per request and never grows with
//!   connections, sessions or subscriptions;
//! - per-request work is one relaxed atomic load, so handler cost stays
//!   constant no matter how many clients are connected.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use crate::ApiState;

/// Documented `up` value rendered while the node is ready.
const STATUS_UP: &str = "up";

/// Documented value rendered while the node is draining (not ready).
const STATUS_DOWN: &str = "down";

/// `GET /status`: node readiness flag.
///
/// Single node, management-plane only: one relaxed atomic load per
/// request, no delivery locks, no new buffering. While ready returns the
/// documented up value with 200; while draining returns the down value
/// with 503 so load balancers stop sending traffic. The query string is
/// not read, so unknown query parameters are ignored instead of rejected.
pub async fn get_status(State(state): State<ApiState>) -> Response {
    if state.readiness.is_ready() {
        (
            StatusCode::OK,
            Json(serde_json::json!({ "status": STATUS_UP })),
        )
            .into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "status": STATUS_DOWN })),
        )
            .into_response()
    }
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
            .expect("status body is small and readable");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("status body is JSON");
        (status, body)
    }

    #[tokio::test]
    async fn ready_node_reports_up_value() {
        let state = standalone_state();
        state.readiness.mark_ready();
        let (status, body) = response_body(get_status(State(state)).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, serde_json::json!({ "status": STATUS_UP }));
        assert_eq!(body["status"], serde_json::json!("up"));
    }

    #[tokio::test]
    async fn standalone_state_is_ready_by_default() {
        let state = standalone_state();
        assert!(
            state.readiness.is_ready(),
            "standalone state must be ready so the handler reports up"
        );
        let (status, body) = response_body(get_status(State(state)).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], serde_json::json!("up"));
    }

    #[tokio::test]
    async fn draining_node_reports_down_with_unavailable() {
        let state = standalone_state();
        state.readiness.mark_not_ready();
        let (status, body) = response_body(get_status(State(state)).await).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body, serde_json::json!({ "status": STATUS_DOWN }));
    }
}
