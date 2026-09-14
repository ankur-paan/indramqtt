//! License, Telemetry, Single Sign-On, and System Configuration endpoints for EMQX v5.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

pub async fn get_license() -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "edition": "enterprise",
            "customer_type": 10,
            "customer_name": "IndraMQTT Distributed Engine",
            "email": "core@indramqtt.io",
            "max_connections": 1000000,
            "max_rules": 1000,
            "start_at": "2026-01-01",
            "expiry_at": "2036-01-01",
            "valid": true,
            "nodes": [
                {
                    "node": "indramqtt@127.0.0.1",
                    "max_connections": 1000000
                }
            ]
        })),
    )
        .into_response()
}

pub async fn get_license_setting() -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "expiry_alarm_threshold": 30,
            "session_hwm_threshold": 80
        })),
    )
        .into_response()
}

pub async fn get_license_session_hwm_history() -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "data": [],
            "meta": {
                "period": "daily"
            }
        })),
    )
        .into_response()
}

pub async fn get_telemetry_status() -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "enabled": false
        })),
    )
        .into_response()
}

pub async fn get_sso_status() -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "enabled": false,
            "running": []
        })),
    )
        .into_response()
}

pub async fn get_configs() -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "zone": "default",
            "listeners": {
                "tcp": {
                    "default": {
                        "bind": "0.0.0.0:1883",
                        "max_connections": 1000000
                    }
                },
                "ws": {
                    "default": {
                        "bind": "0.0.0.0:8083"
                    }
                }
            },
            "brokerlink": {
                "bind": "127.0.0.1:18883"
            }
        })),
    )
        .into_response()
}

pub async fn list_api_keys() -> Response {
    (StatusCode::OK, Json(serde_json::json!([]))).into_response()
}

pub async fn get_api_key_scopes() -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "scopes": [
                "all",
                "rules",
                "connectors",
                "clients",
                "subscriptions"
            ]
        })),
    )
        .into_response()
}
