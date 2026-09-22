//! Packet-tracing enable flag for the v5 management API.
//!
//! Covers `GET /tracing` (read the flag) and `PUT /tracing` (flip the
//! flag). Single-node, management-plane only: nothing here runs on the
//! per-message path, so reads and writes never take a delivery lock and
//! no new buffering is added to fan-out or fan-in.
//!
//! Store bounds (both stated here and enforced by construction):
//! - the flag is exactly one atomic bool; reads are one relaxed load and
//!   writes are one relaxed store, so handler cost stays constant no
//!   matter how many clients are connected;
//! - responses clone one tiny JSON object per request and never grow with
//!   connections, sessions or subscriptions.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use bytes::Bytes;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::ApiState;

/// Boolean packet-tracing flag behind one atomic bool.
///
/// Disabled by default. Constant-time reads and writes; never touched on
/// the per-message path, so management reads never block delivery.
#[derive(Debug, Default)]
pub struct TracingFlagStore {
    inner: AtomicBool,
}

impl TracingFlagStore {
    /// Disabled flag.
    pub fn new() -> Self {
        Self {
            inner: AtomicBool::new(false),
        }
    }

    /// Snapshot the current flag.
    pub fn is_enabled(&self) -> bool {
        self.inner.load(Ordering::Relaxed)
    }

    /// Flip the flag. Constant-time single store.
    pub fn set_enabled(&self, enabled: bool) {
        self.inner.store(enabled, Ordering::Relaxed);
    }
}

/// `GET /tracing`: whether packet tracing is active.
///
/// One relaxed atomic load and one tiny JSON clone per request; no
/// delivery locks, no new buffering.
pub async fn get_tracing(State(state): State<ApiState>) -> Response {
    let enabled = state.tracing.is_enabled();
    (
        StatusCode::OK,
        Json(serde_json::json!({ "enable": enabled })),
    )
        .into_response()
}

/// `PUT /tracing`: flip the packet-tracing flag.
///
/// The body must be a non-empty JSON object containing a boolean
/// `enable` field. Unknown fields are ignored so newer clients degrade
/// to the known subset instead of a 400. Anything else is rejected with
/// the documented `UPDATE_FAILED` shape and leaves the stored flag
/// untouched.
pub async fn put_tracing(State(state): State<ApiState>, body: Bytes) -> Response {
    let value: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(error) => return tracing_update_failed(format!("invalid tracing body: {error}")),
    };
    let obj = match value.as_object() {
        Some(map) => map,
        None => {
            return tracing_update_failed("tracing body must be a JSON object".to_string());
        }
    };
    if obj.is_empty() {
        return tracing_update_failed("tracing body must not be empty".to_string());
    }
    let Some(raw) = obj.get("enable") else {
        return tracing_update_failed("field `enable` must be a boolean".to_string());
    };
    let Some(enabled) = raw.as_bool() else {
        return tracing_update_failed("field `enable` must be a boolean".to_string());
    };
    state.tracing.set_enabled(enabled);
    (
        StatusCode::OK,
        Json(serde_json::json!({ "enable": enabled })),
    )
        .into_response()
}

fn tracing_update_failed(reason: String) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "code": "UPDATE_FAILED",
            "message": reason,
        })),
    )
        .into_response()
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
            .expect("tracing body is small and readable");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("tracing body is JSON");
        (status, body)
    }

    #[tokio::test]
    async fn flag_round_trip_read_flip_read() {
        let state = standalone_state();
        let (status, before) = response_parts(get_tracing(State(state.clone())).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(before, serde_json::json!({ "enable": false }));

        let body = Bytes::from(
            serde_json::to_vec(&serde_json::json!({ "enable": true })).expect("update is JSON"),
        );
        let (status, after) = response_parts(put_tracing(State(state.clone()), body).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(after, serde_json::json!({ "enable": true }));

        let (status, reread) = response_parts(get_tracing(State(state.clone())).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reread, after);

        let body = Bytes::from(
            serde_json::to_vec(&serde_json::json!({ "enable": false })).expect("update is JSON"),
        );
        let (status, flipped) = response_parts(put_tracing(State(state.clone()), body).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(flipped, serde_json::json!({ "enable": false }));

        let (status, reread) = response_parts(get_tracing(State(state.clone())).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reread, flipped);
    }

    #[tokio::test]
    async fn malformed_body_is_rejected_without_applying() {
        let state = standalone_state();
        let (status, before) = response_parts(get_tracing(State(state.clone())).await).await;
        assert_eq!(status, StatusCode::OK);

        for bad in [
            serde_json::json!({"enable": "yes"}),
            serde_json::json!({"enable": 1}),
            serde_json::json!({"enable": 0}),
            serde_json::json!({"enable": null}),
            serde_json::json!({"enabled": true}),
            serde_json::json!({}),
            serde_json::json!([]),
            serde_json::json!("enable"),
        ] {
            let body = Bytes::from(serde_json::to_vec(&bad).expect("bad body is JSON"));
            let (status, err) = response_parts(put_tracing(State(state.clone()), body).await).await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "body {bad} must be rejected"
            );
            assert_eq!(err["code"], serde_json::json!("UPDATE_FAILED"));
        }

        // Empty bytes are not JSON at all.
        let (status, err) =
            response_parts(put_tracing(State(state.clone()), Bytes::new()).await).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(err["code"], serde_json::json!("UPDATE_FAILED"));

        let (status, reread) = response_parts(get_tracing(State(state.clone())).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reread, before, "failed writes must not apply");
    }

    #[tokio::test]
    async fn unknown_fields_are_ignored() {
        let state = standalone_state();
        let body = Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "enable": true,
                "future_field": "ignored",
            }))
            .expect("update is JSON"),
        );
        let (status, after) = response_parts(put_tracing(State(state.clone()), body).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(after, serde_json::json!({ "enable": true }));
    }

    #[test]
    fn store_defaults_to_disabled_and_flips() {
        let store = TracingFlagStore::new();
        assert!(!store.is_enabled());
        store.set_enabled(true);
        assert!(store.is_enabled());
        store.set_enabled(false);
        assert!(!store.is_enabled());
        let defaulted = TracingFlagStore::default();
        assert!(!defaulted.is_enabled());
    }
}
