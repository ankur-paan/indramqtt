//! Client sessions, subscription trie inspection, and test publishing for EMQX v5.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use broker_protocol::{QoS, Topic, TopicFilter};
use broker_router::Subscription;
use bytes::Bytes;
use serde::Deserialize;

use crate::ApiState;

#[derive(Deserialize, Default)]
pub struct ClientQueryParams {
    #[serde(rename = "_page", default = "default_page")]
    pub page: usize,
    #[serde(rename = "_limit", default = "default_limit")]
    pub limit: usize,
    pub conn_state: Option<String>,
    pub clientid: Option<String>,
}

fn default_page() -> usize {
    1
}

fn default_limit() -> usize {
    20
}

pub async fn list_clients(
    State(state): State<ApiState>,
    Query(params): Query<ClientQueryParams>,
) -> Response {
    let all_client_ids = state.sessions.active_client_ids();
    let total = all_client_ids.len();

    let mut data = Vec::new();
    let start = (params.page.saturating_sub(1)) * params.limit;
    let page_ids: Vec<String> = all_client_ids
        .into_iter()
        .skip(start)
        .take(params.limit)
        .collect();

    for cid in page_ids {
        let session = state.sessions.get(&cid);
        let is_connected = session
            .as_ref()
            .map(|s| *s.connected.read())
            .unwrap_or(false);

        if let Some(state_filter) = &params.conn_state {
            if (state_filter == "connected" && !is_connected)
                || (state_filter == "disconnected" && is_connected)
            {
                continue;
            }
        }

        let keepalive = session
            .as_ref()
            .map(|s| *s.keepalive_secs.read())
            .unwrap_or(60);

        data.push(serde_json::json!({
            "clientid": cid,
            "username": session.as_ref().and_then(|s| s.username.read().clone()).unwrap_or_else(|| cid.clone()),
            "connected": is_connected,
            "ip_address": "127.0.0.1",
            "port": 54321,
            "keepalive": keepalive,
            "proto_type": "MQTT",
            "proto_ver": 5,
            "clean_start": true,
            "expiry_interval": 7200,
            "connected_at": "2026-09-13T21:00:00Z",
            "is_bridge": false,
            "inflight_cnt": 0,
            "awaiting_rel_cnt": 0,
            "mqueue_len": session.as_ref().map(|s| s.offline_len()).unwrap_or(0),
            "node": "indramqtt@127.0.0.1"
        }));
    }

    let hasnext = start + params.limit < total;

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "data": data,
            "meta": {
                "page": params.page,
                "limit": params.limit,
                "count": total,
                "hasnext": hasnext
            }
        })),
    )
        .into_response()
}

pub async fn get_client(State(state): State<ApiState>, Path(client_id): Path<String>) -> Response {
    let session = state.sessions.get(&client_id);
    let is_connected = session
        .as_ref()
        .map(|s| *s.connected.read())
        .unwrap_or(false);

    if session.is_none() && !is_connected {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "code": "CLIENT_NOT_FOUND",
                "message": "Client not found"
            })),
        )
            .into_response();
    }

    let keepalive = session
        .as_ref()
        .map(|s| *s.keepalive_secs.read())
        .unwrap_or(60);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "clientid": client_id,
            "username": session.as_ref().and_then(|s| s.username.read().clone()).unwrap_or_else(|| client_id.clone()),
            "connected": is_connected,
            "ip_address": "127.0.0.1",
            "port": 54321,
            "keepalive": keepalive,
            "proto_type": "MQTT",
            "proto_ver": 5,
            "clean_start": true,
            "expiry_interval": 7200,
            "connected_at": "2026-09-13T21:00:00Z",
            "is_bridge": false,
            "inflight_cnt": 0,
            "awaiting_rel_cnt": 0,
            "mqueue_len": session.as_ref().map(|s| s.offline_len()).unwrap_or(0),
            "node": "indramqtt@127.0.0.1"
        })),
    )
        .into_response()
}

pub async fn kick_client(State(state): State<ApiState>, Path(client_id): Path<String>) -> Response {
    if let Some(session) = state.sessions.get(&client_id) {
        if let Some(conn_id) = *session.conn_id.read() {
            state.conns.unregister(conn_id);
            state.sessions.unbind_connection(&client_id, conn_id);
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

pub async fn batch_kick_clients(
    State(state): State<ApiState>,
    Json(client_ids): Json<Vec<String>>,
) -> Response {
    for client_id in client_ids {
        if let Some(session) = state.sessions.get(&client_id) {
            if let Some(conn_id) = *session.conn_id.read() {
                state.conns.unregister(conn_id);
                state.sessions.unbind_connection(&client_id, conn_id);
            }
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

pub async fn get_client_subscriptions(
    State(state): State<ApiState>,
    Path(client_id): Path<String>,
) -> Response {
    let session = state.sessions.get(&client_id);
    let subs: Vec<serde_json::Value> = match session {
        Some(s) => s
            .subscriptions
            .read()
            .iter()
            .map(|(filter, qos)| {
                serde_json::json!({
                    "topic": filter.as_str(),
                    "qos": u8::from(*qos),
                    "node": "indramqtt@127.0.0.1",
                    "clientid": client_id
                })
            })
            .collect(),
        None => Vec::new(),
    };

    (StatusCode::OK, Json(subs)).into_response()
}

#[derive(Deserialize)]
pub struct SubscribeReq {
    pub topic: String,
    #[serde(default)]
    pub qos: u8,
}

pub async fn client_subscribe(
    State(state): State<ApiState>,
    Path(client_id): Path<String>,
    Json(req): Json<SubscribeReq>,
) -> Response {
    let filter = match TopicFilter::new(&req.topic) {
        Ok(f) => f,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "code": "BAD_REQUEST", "message": format!("Invalid filter: {e}") })),
            ).into_response();
        }
    };
    let qos = QoS::try_from(req.qos).unwrap_or(QoS::AtMostOnce);

    state
        .sessions
        .add_subscription(&client_id, filter.clone(), qos);

    let conn_id = state
        .sessions
        .get(&client_id)
        .and_then(|s| *s.conn_id.read())
        .unwrap_or(1);

    state
        .router
        .subscribe(&filter, Subscription::new(&*client_id, conn_id, qos));

    (
        StatusCode::CREATED,
        Json(serde_json::json!({ "result": "ok" })),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct UnsubscribeReq {
    pub topic: String,
}

pub async fn client_unsubscribe(
    State(state): State<ApiState>,
    Path(client_id): Path<String>,
    Json(req): Json<UnsubscribeReq>,
) -> Response {
    let filter = match TopicFilter::new(&req.topic) {
        Ok(f) => f,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "code": "BAD_REQUEST", "message": format!("Invalid filter: {e}") })),
            ).into_response();
        }
    };

    state.sessions.remove_subscription(&client_id, &filter);
    state.router.unsubscribe(&filter, &client_id);

    StatusCode::NO_CONTENT.into_response()
}

pub async fn get_client_mqueue(
    State(state): State<ApiState>,
    Path(client_id): Path<String>,
) -> Response {
    let mut data = Vec::new();
    if let Some(session) = state.sessions.get(&client_id) {
        for qm in session.offline_queue.read().iter() {
            data.push(serde_json::json!({
                "topic": qm.topic.as_str(),
                "qos": u8::from(qm.qos),
                "payload": String::from_utf8_lossy(&qm.payload),
                "publish_at": "2026-09-13T21:00:00Z"
            }));
        }
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "data": data,
            "meta": {
                "page": 1,
                "limit": 20,
                "count": data.len(),
                "hasnext": false
            }
        })),
    )
        .into_response()
}

pub async fn get_client_inflight(
    State(_state): State<ApiState>,
    Path(_client_id): Path<String>,
) -> Response {
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

pub async fn list_subscriptions(State(state): State<ApiState>) -> Response {
    let mut data = Vec::new();
    for cid in state.sessions.active_client_ids() {
        if let Some(s) = state.sessions.get(&cid) {
            for (filter, qos) in s.subscriptions.read().iter() {
                data.push(serde_json::json!({
                    "clientid": cid,
                    "topic": filter.as_str(),
                    "qos": u8::from(*qos),
                    "node": "indramqtt@127.0.0.1"
                }));
            }
        }
    }

    let count = data.len();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "data": data,
            "meta": {
                "page": 1,
                "limit": 100,
                "count": count,
                "hasnext": false
            }
        })),
    )
        .into_response()
}

pub async fn list_topics(State(state): State<ApiState>) -> Response {
    let mut topic_set = std::collections::HashSet::new();
    for cid in state.sessions.active_client_ids() {
        if let Some(s) = state.sessions.get(&cid) {
            for filter in s.subscriptions.read().keys() {
                topic_set.insert(filter.as_str().to_string());
            }
        }
    }

    let data: Vec<_> = topic_set
        .into_iter()
        .map(|t| {
            serde_json::json!({
                "topic": t,
                "node": "indramqtt@127.0.0.1",
                "msg_rate": 0
            })
        })
        .collect();

    let count = data.len();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "data": data,
            "meta": {
                "page": 1,
                "limit": 100,
                "count": count,
                "hasnext": false
            }
        })),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct PublishRequest {
    pub topic: String,
    #[serde(default)]
    pub qos: u8,
    #[serde(default)]
    pub retain: bool,
    pub payload: String,
}

pub async fn publish_message(
    State(state): State<ApiState>,
    Json(req): Json<PublishRequest>,
) -> Response {
    let topic = match Topic::new(&req.topic) {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "code": "BAD_REQUEST",
                    "message": format!("Invalid topic: {e}")
                })),
            )
                .into_response();
        }
    };

    let qos = match QoS::try_from(req.qos) {
        Ok(q) => q,
        Err(_) => QoS::AtMostOnce,
    };

    let payload = Bytes::from(req.payload.into_bytes());

    // Record metrics
    state.metrics.inc_messages_received();

    // Route message through Radix Trie
    let matches = state.router.matches(&topic);
    for sub in matches {
        let routed_frame = brokerlink::BrokerFrame::new(
            brokerlink::OpCode::PublishOut,
            sub.conn_id,
            0,
            Bytes::new(),
            payload.clone(),
        );
        if let Ok(frame) = routed_frame {
            state.conns.route(sub.conn_id, frame);
            state.metrics.inc_messages_forwarded();
        }
    }

    // Rules execute at ingress on this node, invoking live connector sinks
    struct ApiBrokerSink {
        router: std::sync::Arc<broker_router::Router>,
        conns: std::sync::Arc<broker_router::ConnTable>,
        metrics: std::sync::Arc<broker_observability::Metrics>,
    }

    #[async_trait::async_trait]
    impl broker_rules::BrokerSink for ApiBrokerSink {
        async fn publish(
            &self,
            topic: Topic,
            payload: Bytes,
            _qos: QoS,
            _retain: bool,
        ) -> Result<(), broker_rules::RuleEngineError> {
            let matches = self.router.matches(&topic);
            for sub in matches {
                let routed_frame = brokerlink::BrokerFrame::new(
                    brokerlink::OpCode::PublishOut,
                    sub.conn_id,
                    0,
                    Bytes::new(),
                    payload.clone(),
                );
                if let Ok(frame) = routed_frame {
                    self.conns.route(sub.conn_id, frame);
                    self.metrics.inc_messages_forwarded();
                }
            }
            Ok(())
        }
    }

    let sink: std::sync::Arc<dyn broker_rules::BrokerSink> = std::sync::Arc::new(ApiBrokerSink {
        router: state.router.clone(),
        conns: state.conns.clone(),
        metrics: state.metrics.clone(),
    });

    let rules_fired = state
        .engine
        .dispatch_ingress(&topic, &payload, qos, &sink)
        .await;
    state.metrics.inc_rules_executed_by(rules_fired as u64);

    (StatusCode::OK, Json(serde_json::json!({ "result": "ok" }))).into_response()
}
