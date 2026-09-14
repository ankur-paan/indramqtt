//! Retained and Delayed message endpoints for EMQX v5.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

pub async fn list_retained() -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "data": [],
            "meta": {
                "page": 1,
                "limit": 20,
                "count": 0,
                "hasnext": false
            }
        })),
    )
        .into_response()
}

pub async fn clear_retained() -> Response {
    StatusCode::NO_CONTENT.into_response()
}

pub async fn list_delayed_messages() -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "data": [],
            "meta": {
                "page": 1,
                "limit": 20,
                "count": 0,
                "hasnext": false
            }
        })),
    )
        .into_response()
}
