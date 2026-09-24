//! Node-level authentication cache status and reset for the v5 API.
//!
//! Covers `GET /authentication/node_cache/status` (read) and
//! `POST /authentication/node_cache/reset` (evict) over the real
//! [`broker_auth::NodeAuthCache`]. Single-node, management-plane only:
//! handlers clone at most one small snapshot per request under a short
//! lock; the CONNECT path records one entry per successful credentialed
//! CONNECT and never takes a management lock beyond that; publish and
//! deliver never touch this store.
//!
//! Neither route is paged; unknown query parameters are ignored so new
//! spec filters degrade to the same read instead of a 400. Error
//! answers use the documented `{code, message}` shape.
// TODO(parity): which status fields plus reset shape does the spec require
// (enabled/size/bounds versus nested metrics, 204 versus 200)? The
// rulebook does not decide the exact shape; the current choice reports
// the honest enabled/size/bounds the broker can supply (`enabled`,
// `size`/`count`, `max_size`/`max_count` aliases) and omits rate
// counters the broker does not track.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use crate::ApiState;

/// `GET /authentication/node_cache/status`: whether the node cache is
/// enabled plus its current size and bounds over real state.
///
/// Returns 200 with `enabled`, `size` (plus `count` alias) and
/// `max_size` (plus `max_count` alias). An empty cache reads as size
/// zero, never an error. Unknown query keys are ignored: the handler
/// takes no paging params so extra keys never become a 400.
/// Management-plane read only: one short lock on the node cache, which
/// the delivery fan-out path never touches.
pub async fn node_cache_status(
    State(state): State<ApiState>,
    Query(_ignored): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let size = state.authn_node_cache.len();
    let enabled = state.authn_node_cache.is_enabled();
    let max = state.authn_node_cache.max_count();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "enabled": enabled,
            "size": size,
            "count": size,
            "max_size": max,
            "max_count": max,
        })),
    )
        .into_response()
}

/// `POST /authentication/node_cache/reset`: evict every cached entry.
///
/// Clearing an already-empty cache still succeeds (204 with no body).
/// Unknown query keys are ignored. A background map removal only: no
/// work on the publish or deliver path.
pub async fn node_cache_reset(
    State(state): State<ApiState>,
    Query(_ignored): Query<std::collections::HashMap<String, String>>,
) -> Response {
    state.authn_node_cache.reset();
    StatusCode::NO_CONTENT.into_response()
}
