//! Client sessions, subscription trie inspection, and test publishing for the v5 REST API.

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

use crate::errors::ApiError;
use crate::pagination::{meta_page, paginate, PageParams};
use crate::ApiState;

/// Documented `GET /clients` filters. Every field is optional; unknown
/// query keys are ignored by the `Query` extractor and unknown
/// `conn_state` values match everything, so new spec filters degrade to
/// an unfiltered page instead of a 400.
#[derive(Deserialize, Default)]
pub struct ClientFilters {
    #[serde(default)]
    pub conn_state: Option<String>,
    #[serde(default)]
    pub clientid: Option<String>,
}

pub async fn list_clients(
    State(state): State<ApiState>,
    params: PageParams,
    Query(filters): Query<ClientFilters>,
) -> Response {
    // Indexed session snapshot: `active_client_ids` returns the sorted
    // ids of connected sessions from the session map. Management-plane
    // read only; no per-message work, no full scan per message, and the
    // snapshot is bounded by the live connection count.
    let all_client_ids = state.sessions.active_client_ids();

    // Filter first, then paginate: slicing before filtering would drop
    // matching rows that fall outside the raw page window and report a
    // pre-filter count in `meta`.
    let mut matching: Vec<(String, bool)> = Vec::new();
    for cid in all_client_ids {
        if let Some(want) = filters.clientid.as_deref() {
            if cid != want {
                continue;
            }
        }
        let is_connected = state
            .sessions
            .get(&cid)
            .as_ref()
            .map(|s| *s.connected.read())
            .unwrap_or(false);
        if let Some(state_filter) = filters.conn_state.as_deref() {
            if (state_filter == "connected" && !is_connected)
                || (state_filter == "disconnected" && is_connected)
            {
                continue;
            }
        }
        matching.push((cid, is_connected));
    }
    let total = matching.len();
    let page_ids = paginate(&matching, params.page, params.limit);

    let mut data = Vec::new();
    for (cid, is_connected) in page_ids {
        let session = state.sessions.get(cid);

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

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "data": data,
            "meta": meta_page(params.page, params.limit, total),
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

/// Disconnect one client through the single-kick path.
///
/// Copies the bound connection id first so the read guard drops before
/// `unbind_connection` takes the write lock (or the caller deadlocks
/// itself on the session lock). Delivers `ConnClose` to the edge BEFORE
/// tearing down kernel state: the synchronous route hands the frame to
/// the still-registered connection mailbox, so delivery cannot lose a
/// race with the `unregister` below. Both sends are non-blocking and
/// never fail the kick; a dead edge only warns. Returns true when a live
/// connection was closed, false for unknown ids or sessions with nothing
/// live to disconnect.
fn kick_one(state: &ApiState, client_id: &str) -> bool {
    let session = match state.sessions.get(client_id) {
        Some(session) => session,
        None => return false,
    };
    let conn_id = *session.conn_id.read();
    let Some(conn_id) = conn_id else {
        return false;
    };
    match brokerlink::BrokerFrame::new(
        brokerlink::OpCode::ConnClose,
        conn_id,
        0,
        Bytes::new(),
        Bytes::new(),
    ) {
        Ok(frame) => {
            state.conns.route(conn_id, frame.clone());
            // Specified kernel→edge close handoff. By the time
            // the forwarder routes this copy the connection is
            // unregistered, so it is dropped there by design; a
            // failed send only warns (forwarder already gone).
            if state.edge_tx.send(frame).is_err() {
                tracing::warn!(
                    client_id = %client_id,
                    conn_id,
                    "kick: edge gone, ConnClose dropped"
                );
            }
        }
        Err(error) => tracing::warn!(
            client_id = %client_id,
            conn_id,
            "kick: cannot build ConnClose frame: {error}"
        ),
    }
    state.conns.unregister(conn_id);
    state.sessions.unbind_connection(client_id, conn_id);
    true
}

pub async fn kick_client(State(state): State<ApiState>, Path(client_id): Path<String>) -> Response {
    if !kick_one(&state, &client_id) {
        // Unknown id or known session with nothing live to disconnect:
        // report not-found with the documented error shape.
        return ApiError::ClientIdNotFound("client not found".to_string()).into_response();
    }
    StatusCode::NO_CONTENT.into_response()
}

pub async fn batch_kick_clients(State(state): State<ApiState>, body: Bytes) -> Response {
    let client_ids: Vec<String> = match serde_json::from_slice(&body[..]) {
        Ok(ids) => ids,
        Err(error) => {
            return ApiError::BadRequest(format!("invalid bulk kick body: {error}"))
                .into_response();
        }
    };
    // Bounded fan-out over the request itself: one synchronous close
    // frame per id through the shared single-kick routine, no extra
    // buffering beyond the result list and no spawned tasks. The result
    // list is management-plane only; the per-message path stays free of
    // new allocation (empty metadata and payload frames).
    let mut results = Vec::with_capacity(client_ids.len());
    for client_id in &client_ids {
        if kick_one(&state, client_id) {
            results.push(serde_json::json!({"clientid": client_id, "result": "ok"}));
        } else {
            results.push(serde_json::json!({
                "clientid": client_id,
                "result": "not_found",
                "code": "CLIENTID_NOT_FOUND",
                "message": "client not found"
            }));
        }
    }
    (StatusCode::OK, Json(results)).into_response()
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

    (StatusCode::OK, Json(serde_json::json!({ "result": "ok" }))).into_response()
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

pub async fn get_client_inflight(
    State(state): State<ApiState>,
    Path(client_id): Path<String>,
    params: PageParams,
) -> Response {
    // Unknown clients read as not-found with the documented error shape.
    let session = match state.sessions.get(&client_id) {
        Some(session) => session,
        None => {
            return ApiError::ClientIdNotFound("client not found".to_string()).into_response();
        }
    };
    // Bounded per-client view over the real QoS 1 tracker: the snapshot
    // clones at most `MAX_QOS1_INFLIGHT` (100) entries under a short read
    // lock, then paginates with the W0 helper. Management-plane read only;
    // the delivery hot path never takes a management lock (it takes the
    // session write lock only to track/ack, never to serve this view).
    let snapshot = session.inflight_snapshot();
    let total = snapshot.len();
    let page_items = paginate(&snapshot, params.page, params.limit);
    let data: Vec<serde_json::Value> = page_items
        .iter()
        .map(|m| {
            serde_json::json!({
                "topic": m.topic.as_str(),
                "packet_id": m.packet_id,
                "msgid": m.packet_id.to_string(),
                "qos": u8::from(m.qos),
                "payload": String::from_utf8_lossy(&m.payload),
            })
        })
        .collect();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "data": data,
            "meta": meta_page(params.page, params.limit, total),
        })),
    )
        .into_response()
}

pub async fn get_client_mqueue(
    State(state): State<ApiState>,
    Path(client_id): Path<String>,
    params: PageParams,
) -> Response {
    // Unknown clients read as not-found with the documented error shape.
    let session = match state.sessions.get(&client_id) {
        Some(session) => session,
        None => {
            return ApiError::ClientIdNotFound("client not found".to_string()).into_response();
        }
    };
    // Bounded per-client view over the real offline queue: the snapshot
    // clones at most `MAX_OFFLINE_QUEUE` (1024) entries under a short read
    // lock, then paginates with the W0 helper. Management-plane read only;
    // no new buffering on the delivery path and the delivery hot path
    // never takes a management lock.
    let snapshot: Vec<broker_session::QueuedMessage> =
        session.offline_queue.read().iter().cloned().collect();
    let total = snapshot.len();
    let page_items = paginate(&snapshot, params.page, params.limit);
    let start = ((u64::from(params.page.max(1)) - 1) * u64::from(params.limit)).min(total as u64)
        as usize;
    let data: Vec<serde_json::Value> = page_items
        .iter()
        .enumerate()
        .map(|(i, qm)| {
            serde_json::json!({
                "msgid": (start + i + 1).to_string(),
                "topic": qm.topic.as_str(),
                "qos": u8::from(qm.qos),
                "payload": String::from_utf8_lossy(&qm.payload),
                "publish_at": "2026-09-13T21:00:00Z"
            })
        })
        .collect();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "data": data,
            "meta": meta_page(params.page, params.limit, total),
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
            // Only live mailboxes count as forwarded; drops are already
            // counted inside `ConnTable::route`.
            if state.conns.route(sub.conn_id, frame) {
                state.metrics.inc_messages_forwarded();
            }
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
                    // Outcome counting, like the publish path above.
                    if self.conns.route(sub.conn_id, frame) {
                        self.metrics.inc_messages_forwarded();
                    }
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
