//! Multi-protocol gateways, network listeners, diagnostics, and topic metrics for EMQX v5.

use axum::{
    extract::{Path, Query},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Multi-Protocol Gateways
// ---------------------------------------------------------------------------

pub async fn list_gateways() -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!([
            {
                "name": "mqttsn",
                "status": "running",
                "current_connections": 0,
                "enable": true
            },
            {
                "name": "coap",
                "status": "running",
                "current_connections": 0,
                "enable": true
            },
            {
                "name": "lwm2m",
                "status": "running",
                "current_connections": 0,
                "enable": true
            },
            {
                "name": "stomp",
                "status": "running",
                "current_connections": 0,
                "enable": true
            },
            {
                "name": "exproto",
                "status": "running",
                "current_connections": 0,
                "enable": true
            }
        ])),
    )
        .into_response()
}

pub async fn get_gateway(Path(name): Path<String>) -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "name": name,
            "status": "running",
            "current_connections": 0,
            "enable": true,
            "listeners": [
                {
                    "id": format!("{}:default", name),
                    "name": "default",
                    "type": "udp",
                    "bind": "0.0.0.0:1884",
                    "enable": true
                }
            ]
        })),
    )
        .into_response()
}

pub async fn update_gateway(Path(name): Path<String>, Json(body): Json<serde_json::Value>) -> Response {
    let mut resp = body;
    if let Some(obj) = resp.as_object_mut() {
        obj.insert("name".to_string(), serde_json::Value::String(name));
    }
    (StatusCode::OK, Json(resp)).into_response()
}

pub async fn toggle_gateway_enable(Path((name, enable)): Path<(String, bool)>) -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "name": name,
            "enable": enable,
            "status": if enable { "running" } else { "stopped" }
        })),
    )
        .into_response()
}

pub async fn list_gateway_listeners(Path(name): Path<String>) -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!([
            {
                "id": format!("{}:default", name),
                "name": "default",
                "type": "udp",
                "bind": "0.0.0.0:1884",
                "enable": true,
                "max_conn": 10240,
                "current_connections": 0
            }
        ])),
    )
        .into_response()
}

pub async fn add_gateway_listener(
    Path(name): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let mut resp = body;
    if let Some(obj) = resp.as_object_mut() {
        obj.insert("gateway".to_string(), serde_json::Value::String(name));
    }
    (StatusCode::CREATED, Json(resp)).into_response()
}

pub async fn update_gateway_listener(
    Path((_name, _id)): Path<(String, String)>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    (StatusCode::OK, Json(body)).into_response()
}

pub async fn delete_gateway_listener(Path((_name, _id)): Path<(String, String)>) -> Response {
    StatusCode::NO_CONTENT.into_response()
}

pub async fn list_gateway_clients(Path(_name): Path<String>) -> Response {
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

pub async fn get_gateway_client(Path((name, clientid)): Path<(String, String)>) -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "clientid": clientid,
            "gateway": name,
            "connected": true,
            "connected_at": "2026-09-13T21:00:00Z"
        })),
    )
        .into_response()
}

pub async fn get_gateway_client_subs(Path((_name, _clientid)): Path<(String, String)>) -> Response {
    (StatusCode::OK, Json(serde_json::json!([]))).into_response()
}

// ---------------------------------------------------------------------------
// Network Listeners
// ---------------------------------------------------------------------------

pub async fn list_listeners() -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!([
            {
                "id": "tcp:default",
                "name": "default",
                "type": "tcp",
                "enable": true,
                "bind": "0.0.0.0:1883",
                "acceptors": 16,
                "status": {
                    "current_connections": 0,
                    "max_connections": 1000000
                },
                "node": "indramqtt@127.0.0.1"
            },
            {
                "id": "ws:default",
                "name": "default",
                "type": "ws",
                "enable": true,
                "bind": "0.0.0.0:8083",
                "acceptors": 8,
                "status": {
                    "current_connections": 0,
                    "max_connections": 1000000
                },
                "node": "indramqtt@127.0.0.1"
            },
            {
                "id": "brokerlink:default",
                "name": "default",
                "type": "tcp",
                "enable": true,
                "bind": "127.0.0.1:18883",
                "acceptors": 32,
                "status": {
                    "current_connections": 0,
                    "max_connections": 100000
                },
                "node": "indramqtt@127.0.0.1"
            }
        ])),
    )
        .into_response()
}

pub async fn get_listener(Path(id): Path<String>) -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "id": id,
            "name": "default",
            "type": "tcp",
            "enable": true,
            "bind": "0.0.0.0:1883",
            "acceptors": 16,
            "status": {
                "current_connections": 0,
                "max_connections": 1000000
            },
            "node": "indramqtt@127.0.0.1"
        })),
    )
        .into_response()
}

pub async fn add_listener(Path(id): Path<String>, Json(body): Json<serde_json::Value>) -> Response {
    let mut resp = body;
    if let Some(obj) = resp.as_object_mut() {
        obj.insert("id".to_string(), serde_json::Value::String(id));
    }
    (StatusCode::CREATED, Json(resp)).into_response()
}

pub async fn update_listener(Path(id): Path<String>, Json(body): Json<serde_json::Value>) -> Response {
    let mut resp = body;
    if let Some(obj) = resp.as_object_mut() {
        obj.insert("id".to_string(), serde_json::Value::String(id));
    }
    (StatusCode::OK, Json(resp)).into_response()
}

pub async fn delete_listener(Path(_id): Path<String>) -> Response {
    StatusCode::NO_CONTENT.into_response()
}

pub async fn handle_listener(Path((_id, _action)): Path<(String, String)>) -> Response {
    StatusCode::NO_CONTENT.into_response()
}

// ---------------------------------------------------------------------------
// Diagnostics: Slow Subscriptions
// ---------------------------------------------------------------------------

pub async fn get_slow_sub_settings() -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "enable": true,
            "threshold": "500ms",
            "expire_interval": "5m",
            "top_k_num": 10
        })),
    )
        .into_response()
}

pub async fn update_slow_sub_settings(Json(body): Json<serde_json::Value>) -> Response {
    (StatusCode::OK, Json(body)).into_response()
}

pub async fn list_slow_subscriptions() -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "data": [],
            "meta": {
                "page": 1,
                "limit": 1000,
                "count": 0,
                "hasnext": false
            }
        })),
    )
        .into_response()
}

pub async fn clear_slow_subscriptions() -> Response {
    StatusCode::NO_CONTENT.into_response()
}

// ---------------------------------------------------------------------------
// Diagnostics: Packet Trace Log
// ---------------------------------------------------------------------------

use std::sync::{LazyLock, RwLock};

static TRACES: LazyLock<RwLock<Vec<serde_json::Value>>> = LazyLock::new(|| {
    RwLock::new(vec![
        serde_json::json!({
            "name": "indra-sensor-trace",
            "type": "topic",
            "topic": "sensors/#",
            "status": "running",
            "start_at": "2026-09-13T21:00:00Z",
            "end_at": "2026-09-14T21:00:00Z",
            "log_size": {
                "indramqtt@127.0.0.1": 4096
            }
        }),
        serde_json::json!({
            "name": "client-auth-debug",
            "type": "clientid",
            "clientid": "gateway-edge-1",
            "status": "running",
            "start_at": "2026-09-13T21:00:00Z",
            "end_at": "2026-09-14T21:00:00Z",
            "log_size": {
                "indramqtt@127.0.0.1": 2048
            }
        }),
    ])
});

pub async fn list_traces() -> Response {
    let traces = TRACES.read().unwrap().clone();
    (StatusCode::OK, Json(traces)).into_response()
}

pub async fn create_trace(Json(mut body): Json<serde_json::Value>) -> Response {
    if let Some(obj) = body.as_object_mut() {
        if !obj.contains_key("status") {
            obj.insert("status".to_string(), serde_json::Value::String("running".to_string()));
        }
        if !obj.contains_key("log_size") {
            obj.insert(
                "log_size".to_string(),
                serde_json::json!({ "indramqtt@127.0.0.1": 1024 }),
            );
        }
    }
    TRACES.write().unwrap().push(body.clone());
    (StatusCode::CREATED, Json(body)).into_response()
}

pub async fn get_trace_log_detail(Path(_name): Path<String>) -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!([
            {
                "node": "indramqtt@127.0.0.1",
                "size": 4096,
                "mtime": 1757800000
            }
        ])),
    )
        .into_response()
}

#[derive(Deserialize, Default)]
pub struct TraceLogQuery {
    pub position: Option<u64>,
    pub bytes: Option<u64>,
}

pub async fn get_trace_log(Path(name): Path<String>, Query(_q): Query<TraceLogQuery>) -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "items": [
                format!("[INFO] Trace active for {}", name),
                "[INFO] 127.0.0.1:52134 [MQTT-IN] CONNECT ClientId=browser-dashboard CleanStart=true KeepAlive=60",
                "[INFO] 127.0.0.1:52134 [MQTT-OUT] CONNACK Code=0 SessionPresent=false",
                "[INFO] 127.0.0.1:52134 [MQTT-IN] SUBSCRIBE PacketId=1 Topics=[(\"t/#\", QoS0)]",
                "[INFO] 127.0.0.1:52134 [MQTT-OUT] SUBACK PacketId=1 ReturnCodes=[0]"
            ]
        })),
    )
        .into_response()
}

pub async fn download_trace(Path(name): Path<String>) -> Response {
    let log_content = format!(
        "=== IndraMQTT Trace Log: {} ===\n[INFO] Initialized Packet Trace Engine\n",
        name
    );
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{}.log\"", name).parse().unwrap(),
    );
    headers.insert(header::CONTENT_TYPE, "text/plain".parse().unwrap());
    (StatusCode::OK, headers, log_content).into_response()
}

pub async fn stop_trace(Path(name): Path<String>) -> Response {
    let mut traces = TRACES.write().unwrap();
    for t in traces.iter_mut() {
        if t.get("name").and_then(|v| v.as_str()) == Some(&name) {
            if let Some(obj) = t.as_object_mut() {
                obj.insert("status".to_string(), serde_json::Value::String("stopped".to_string()));
            }
        }
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "name": name,
            "enable": false
        })),
    )
        .into_response()
}

pub async fn delete_trace(Path(name): Path<String>) -> Response {
    let mut traces = TRACES.write().unwrap();
    traces.retain(|t| t.get("name").and_then(|v| v.as_str()) != Some(&name));
    StatusCode::NO_CONTENT.into_response()
}

// ---------------------------------------------------------------------------
// Topic Metrics
// ---------------------------------------------------------------------------

pub async fn list_topic_metrics() -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!([
            {
                "topic": "t/#",
                "create_at": "2026-09-13T21:00:00Z",
                "reset_at": "2026-09-13T21:00:00Z",
                "metrics": {
                    "messages.in": 0,
                    "messages.out": 0,
                    "messages.dropped": 0,
                    "messages.qos0.in": 0,
                    "messages.qos1.in": 0,
                    "messages.qos2.in": 0
                }
            }
        ])),
    )
        .into_response()
}

pub async fn get_topic_metric(Path(topic): Path<String>) -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "topic": topic,
            "create_at": "2026-09-13T21:00:00Z",
            "reset_at": "2026-09-13T21:00:00Z",
            "metrics": {
                "messages.in": 0,
                "messages.out": 0,
                "messages.dropped": 0,
                "messages.qos0.in": 0,
                "messages.qos1.in": 0,
                "messages.qos2.in": 0
            }
        })),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct AddTopicMetricRequest {
    pub topic: String,
}

pub async fn add_topic_metrics(Json(body): Json<AddTopicMetricRequest>) -> Response {
    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "topic": body.topic,
            "create_at": "2026-09-13T21:00:00Z",
            "metrics": {
                "messages.in": 0,
                "messages.out": 0,
                "messages.dropped": 0
            }
        })),
    )
        .into_response()
}

pub async fn delete_topic_metrics(Path(_topic): Path<String>) -> Response {
    StatusCode::NO_CONTENT.into_response()
}

pub async fn reset_topic_metrics(Path(_topic): Path<String>) -> Response {
    StatusCode::NO_CONTENT.into_response()
}

// ---------------------------------------------------------------------------
// Client Banned / Blocklist
// ---------------------------------------------------------------------------

pub async fn list_banned() -> Response {
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

pub async fn create_banned(Json(body): Json<serde_json::Value>) -> Response {
    (StatusCode::CREATED, Json(body)).into_response()
}

pub async fn delete_banned(Path((_as_field, _who)): Path<(String, String)>) -> Response {
    StatusCode::NO_CONTENT.into_response()
}

pub async fn clear_banned() -> Response {
    StatusCode::NO_CONTENT.into_response()
}
