//! Global authentication settings for the v5 management API.
//!
//! Covers `GET /authentication/settings` (read) and
//! `PUT /authentication/settings` (validated full replace) over the real
//! [`broker_auth::AuthnSettingsStore`]. Single-node, management-plane
//! only: handlers clone one small snapshot per request under no delivery
//! lock; the CONNECT path loads one lock-free snapshot per connect to
//! observe the backend-failure flag (`crates/broker-node/src/main.rs`,
//! CONNECT handling, and the console CONNECT in `crate::ws`) and never
//! takes a management lock; publish and deliver never touch this store.
//!
//! Neither route is paged. Error answers use the documented
//! `{code, message}` shape.
//!
//! Only the built-in database executes in the parity waves; the
//! `ignore_backend_failures` flag is observed on CONNECT but the broker
//! stays fail-closed (an outage denies access and logs) until the checker
//! pins the intended behaviour.
// TODO(parity): which PUT success shape does the spec require (204 versus
// 200)? The rulebook does not decide the exact shape; the current choice
// answers PUT with 204 and reports the honest subset the broker can
// supply, omitting rate counters the broker does not track.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use bytes::Bytes;

use crate::errors::ApiError;
use crate::ApiState;
use broker_config::AuthnSettingsConf;

pub use broker_auth::{AuthnSettingsStore, SettingsSubscriber, SettingsUpdateError};

/// `GET /authentication/settings`: current global settings.
///
/// One lock-free snapshot and one small JSON clone per request; no
/// delivery locks, no new buffering. Unknown query keys are ignored: the
/// handler takes no paging params so extra keys never become a 400.
pub async fn get_authn_settings(
    State(state): State<ApiState>,
    Query(_ignored): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let snapshot = state.authn_settings.snapshot();
    match serde_json::to_value(&*snapshot) {
        Ok(body) => (StatusCode::OK, axum::Json(body)).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({
                "code": "INTERNAL_ERROR",
                "message": format!("cannot render authentication settings: {error}"),
            })),
        )
            .into_response(),
    }
}

/// `PUT /authentication/settings`: validated full replace.
///
/// The whole body is validated before anything is applied: one bad field
/// rejects the entire write with the documented `BAD_REQUEST` shape and
/// leaves the stored settings untouched. Unknown fields (top-level or
/// inside `node_cache`) are rejected fail-closed; they never degrade to
/// the known subset. Missing fields reset to their documented defaults:
/// the body replaces the stored settings, it never merges into them.
/// Unknown query parameters are rejected fail-closed. On success returns
/// 204 with no body and the settings persist across a restart through
/// the config registry; the node-cache subscriber applies the cache half
/// in place. Management-plane only: one snapshot swap per request; the
/// CONNECT path keeps reading its lock-free snapshot and publish/deliver
/// never touch this store.
pub async fn put_authn_settings(
    State(state): State<ApiState>,
    Query(query): Query<std::collections::HashMap<String, String>>,
    body: Bytes,
) -> Response {
    if !query.is_empty() {
        return ApiError::BadRequest(
            "authentication settings accepts no query parameters".to_string(),
        )
        .into_response();
    }
    if body.len() > AuthnSettingsStore::max_body_len() {
        return ApiError::BadRequest("authentication settings body is too large".to_string())
            .into_response();
    }
    let value: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(error) => {
            return ApiError::BadRequest(format!("invalid authentication settings body: {error}"))
                .into_response();
        }
    };
    let obj = match value.as_object() {
        Some(map) => map.clone(),
        None => {
            return ApiError::BadRequest(
                "authentication settings body must be a JSON object".to_string(),
            )
            .into_response();
        }
    };
    if obj.is_empty() {
        return ApiError::BadRequest("authentication settings body must not be empty".to_string())
            .into_response();
    }
    // Full replace: unknown fields are rejected by `deny_unknown_fields`
    // on the config struct, missing fields take their documented
    // defaults. Nothing is applied until the candidate validates.
    let candidate: AuthnSettingsConf = match serde_json::from_value(serde_json::Value::Object(obj))
    {
        Ok(candidate) => candidate,
        Err(error) => {
            return ApiError::BadRequest(format!("invalid authentication settings body: {error}"))
                .into_response();
        }
    };
    match state.authn_settings.replace(candidate) {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(SettingsUpdateError::Invalid(reason)) => ApiError::BadRequest(reason).into_response(),
        Err(SettingsUpdateError::Persist(reason)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({
                "code": "INTERNAL_ERROR",
                "message": format!("cannot persist authentication settings: {reason}"),
            })),
        )
            .into_response(),
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

    async fn response_parts(response: axum::response::Response) -> (StatusCode, serde_json::Value) {
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("settings body is small and readable");
        if bytes.is_empty() {
            return (status, serde_json::Value::Null);
        }
        let body: serde_json::Value =
            serde_json::from_slice(&bytes).expect("settings body is JSON");
        (status, body)
    }

    #[tokio::test]
    async fn settings_round_trip_read_write_read() {
        let state = standalone_state();
        let (status, before) = response_parts(
            get_authn_settings(State(state.clone()), Query(Default::default())).await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(before["ignore_backend_failures"], serde_json::json!(false));
        assert_eq!(before["node_cache"]["enable"], serde_json::json!(true));
        assert_eq!(
            before["builtin_record_count_refresh_interval"],
            serde_json::json!("1h")
        );

        // Full replace with every field set.
        let update = serde_json::json!({
            "ignore_backend_failures": true,
            "node_cache": {
                "enable": true,
                "cache_ttl": "30s",
                "cleanup_interval": "1m",
                "stat_update_interval": "5s",
                "max_count": 5000,
                "max_memory": "100MB",
            },
            "builtin_record_count_refresh_interval": "30m",
        });
        let body = Bytes::from(serde_json::to_vec(&update).expect("update is JSON"));
        let (status, _) = response_parts(
            put_authn_settings(State(state.clone()), Query(Default::default()), body).await,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        let (status, reread) = response_parts(
            get_authn_settings(State(state.clone()), Query(Default::default())).await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reread["ignore_backend_failures"], serde_json::json!(true));
        assert_eq!(reread["node_cache"]["max_count"], serde_json::json!(5000));
        assert_eq!(reread["node_cache"]["cache_ttl"], serde_json::json!("30s"));
        assert_eq!(
            reread["builtin_record_count_refresh_interval"],
            serde_json::json!("30m")
        );
    }

    #[tokio::test]
    async fn partial_body_replaces_missing_fields_with_defaults() {
        let state = standalone_state();
        // Move one field off its default first with a full body.
        let full = serde_json::json!({
            "ignore_backend_failures": false,
            "node_cache": {
                "enable": true,
                "cache_ttl": "1m",
                "cleanup_interval": "1m",
                "stat_update_interval": "5s",
                "max_count": 10000,
                "max_memory": "256MB",
            },
            "builtin_record_count_refresh_interval": "1h",
        });
        let body = Bytes::from(serde_json::to_vec(&full).expect("full is JSON"));
        let (status, _) = response_parts(
            put_authn_settings(State(state.clone()), Query(Default::default()), body).await,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // A partial body replaces: omitted fields reset to defaults
        // instead of merging with the stored values.
        let partial = serde_json::json!({
            "ignore_backend_failures": true,
        });
        let body = Bytes::from(serde_json::to_vec(&partial).expect("partial is JSON"));
        let (status, _) = response_parts(
            put_authn_settings(State(state.clone()), Query(Default::default()), body).await,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, reread) = response_parts(
            get_authn_settings(State(state.clone()), Query(Default::default())).await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reread["ignore_backend_failures"], serde_json::json!(true));
        assert_eq!(
            reread["node_cache"]["max_memory"],
            serde_json::json!("100MB"),
            "omitted fields must reset to defaults, not merge"
        );
        assert_eq!(
            reread["builtin_record_count_refresh_interval"],
            serde_json::json!("1h")
        );
    }

    #[tokio::test]
    async fn invalid_update_is_rejected_without_applying() {
        let state = standalone_state();
        let (status, before) = response_parts(
            get_authn_settings(State(state.clone()), Query(Default::default())).await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        for bad in [
            serde_json::json!({"ignore_backend_failures": "yes"}),
            serde_json::json!({"node_cache": {"enable": "yes"}}),
            serde_json::json!({"node_cache": {"cache_ttl": "soon"}}),
            serde_json::json!({"node_cache": {"max_count": 0}}),
            serde_json::json!({"node_cache": {"max_count": 2_000_000}}),
            serde_json::json!({"node_cache": {"max_count": "many"}}),
            serde_json::json!({"node_cache": {"max_memory": "huge"}}),
            serde_json::json!({"node_cache": "yes"}),
            serde_json::json!({"builtin_record_count_refresh_interval": "soon"}),
            serde_json::json!({"builtin_record_count_refresh_interval": 60}),
            serde_json::json!({"unknown_field": 1}),
            serde_json::json!({"node_cache": {"max_count": 5000, "bogus": true}}),
            serde_json::json!({}),
            serde_json::json!([]),
        ] {
            let body = Bytes::from(serde_json::to_vec(&bad).expect("bad body is JSON"));
            let (status, err) = response_parts(
                put_authn_settings(State(state.clone()), Query(Default::default()), body).await,
            )
            .await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "body {bad} must be rejected"
            );
            assert_eq!(err["code"], serde_json::json!("BAD_REQUEST"));
            assert!(err["message"].is_string());
        }

        // Unknown query parameters are rejected fail-closed.
        let mut query = std::collections::HashMap::new();
        query.insert("unknown_param".to_string(), "1".to_string());
        let body = Bytes::from(
            serde_json::to_vec(&serde_json::json!({"ignore_backend_failures": true}))
                .expect("body is JSON"),
        );
        let (status, err) =
            response_parts(put_authn_settings(State(state.clone()), Query(query), body).await)
                .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(err["code"], serde_json::json!("BAD_REQUEST"));

        let (status, reread) = response_parts(
            get_authn_settings(State(state.clone()), Query(Default::default())).await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reread, before, "failed writes must not apply");
    }

    #[test]
    fn documented_defaults_match_registry_source() {
        let defaults = AuthnSettingsConf::default();
        assert!(!defaults.ignore_backend_failures);
        assert!(defaults.node_cache.enable);
        assert_eq!(defaults.node_cache.cache_ttl, "1m");
        assert_eq!(defaults.node_cache.cleanup_interval, "1m");
        assert_eq!(defaults.node_cache.stat_update_interval, "5s");
        assert_eq!(
            defaults.node_cache.max_count,
            broker_config::DEFAULT_AUTHN_NODE_CACHE_MAX
        );
        assert_eq!(defaults.node_cache.max_memory, "100MB");
        assert_eq!(defaults.builtin_record_count_refresh_interval, "1h");
        defaults.validate().expect("documented defaults validate");
    }
}
