//! Informative placeholders for features not yet developed in IndraMQTT,
//! such as AI completion, AI connectors, Agent-to-Agent registry, and hot upgrades.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

pub async fn ai_not_developed() -> Response {
    (
        StatusCode::OK,
        [("X-Indra-Feature-Status", "not_developed")],
        Json(serde_json::json!([])),
    )
        .into_response()
}

pub async fn a2a_not_developed() -> Response {
    (
        StatusCode::OK,
        [("X-Indra-Feature-Status", "not_developed")],
        Json(serde_json::json!([])),
    )
        .into_response()
}

pub async fn a2a_config() -> Response {
    (
        StatusCode::OK,
        [("X-Indra-Feature-Status", "not_developed")],
        Json(serde_json::json!({
            "enable": false,
            "validate_schema": false
        })),
    )
        .into_response()
}

pub async fn feature_notice(feature_name: &'static str) -> Response {
    (
        StatusCode::OK,
        [("X-Indra-Feature-Status", "not_developed")],
        Json(serde_json::json!({
            "status": "not_developed",
            "feature": feature_name,
            "message": format!("Notice: {} is not yet developed in IndraMQTT and is scheduled for a future release.", feature_name),
            "data": []
        })),
    )
        .into_response()
}

/// Catalog of extra advanced features developed in IndraMQTT that are not in upstream EMQX.
pub async fn indramqtt_extra_features() -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "title": "IndraMQTT Native Kernel Differentiators & Advanced Features",
            "features": [
                {
                    "name": "BrokerLink IPC Protocol",
                    "description": "Multi-lane CPU-affinity binary IPC protocol bridging BEAM network edge to Rust kernel with zero-copy framing.",
                    "status": "active"
                },
                {
                    "name": "Radix Trie Lock-Free Routing",
                    "description": "Sub-microsecond lock-free Radix Trie topic routing with zero garbage collection pauses.",
                    "status": "active"
                },
                {
                    "name": "Durable Stream Store",
                    "description": "Partitioned append-only stream log with 64-bit offsets and point-in-time seek & replay over MQTT.",
                    "status": "active"
                },
                {
                    "name": "SWIM Gossip Cluster Engine",
                    "description": "Decentralized SWIM gossip clustering with failure detection and route summary broadcasts.",
                    "status": "active"
                },
                {
                    "name": "185-Function Analytical SQL Catalog",
                    "description": "High-throughput streaming SQL engine with 185 analytical and window functions.",
                    "status": "active"
                },
                {
                    "name": "Multi-Tenant Bandwidth Quota Limiter",
                    "description": "Token-bucket rate & burst limits with isolated tenant quotas.",
                    "status": "active"
                }
            ]
        })),
    )
        .into_response()
}
