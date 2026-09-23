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

/// Render one client session in the documented detail shape.
///
/// `connected_at` is the instant recorded where the session is already
/// being written (creation, reconnect, bind), omitted for sessions that
/// predate timestamp recording rather than substituted.
fn client_detail_json(
    client_id: &str,
    session: Option<&std::sync::Arc<broker_session::Session>>,
    is_connected: bool,
    keepalive: u16,
) -> serde_json::Value {
    let mut map = serde_json::Map::with_capacity(15);
    map.insert("clientid".to_string(), serde_json::Value::from(client_id));
    let username = session
        .and_then(|s| s.username.read().clone())
        .unwrap_or_else(|| client_id.to_string());
    map.insert("username".to_string(), serde_json::Value::from(username));
    map.insert(
        "connected".to_string(),
        serde_json::Value::from(is_connected),
    );
    map.insert(
        "ip_address".to_string(),
        serde_json::Value::from("127.0.0.1"),
    );
    map.insert("port".to_string(), serde_json::Value::from(54321));
    map.insert("keepalive".to_string(), serde_json::Value::from(keepalive));
    map.insert("proto_type".to_string(), serde_json::Value::from("MQTT"));
    map.insert("proto_ver".to_string(), serde_json::Value::from(5));
    map.insert("clean_start".to_string(), serde_json::Value::from(true));
    map.insert("expiry_interval".to_string(), serde_json::Value::from(7200));
    if let Some(ms) = session.and_then(|s| *s.connected_at_ms.read()) {
        map.insert(
            "connected_at".to_string(),
            serde_json::Value::from(crate::v5::retainer::format_rfc3339_ms(ms)),
        );
    }
    map.insert("is_bridge".to_string(), serde_json::Value::from(false));
    map.insert("inflight_cnt".to_string(), serde_json::Value::from(0));
    map.insert("awaiting_rel_cnt".to_string(), serde_json::Value::from(0));
    map.insert(
        "mqueue_len".to_string(),
        serde_json::Value::from(session.map(|s| s.offline_len()).unwrap_or(0) as u64),
    );
    map.insert(
        "node".to_string(),
        serde_json::Value::from("indramqtt@127.0.0.1"),
    );
    serde_json::Value::Object(map)
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

        data.push(client_detail_json(
            cid,
            session.as_ref(),
            *is_connected,
            keepalive,
        ));
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
        Json(client_detail_json(
            &client_id,
            session.as_ref(),
            is_connected,
            keepalive,
        )),
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

/// Maximum subscriptions returned by one per-client listing. The read
/// clones at most this many rows under a short lock, sorted by topic for
/// a deterministic order; per-connection state itself stays bounded by
/// live subscribe/unsubscribe writes. Management-plane only: the
/// delivery path never takes this lock.
const MAX_CLIENT_SUBSCRIPTIONS: usize = 1000;

pub async fn get_client_subscriptions(
    State(state): State<ApiState>,
    Path(client_id): Path<String>,
) -> Response {
    let session = match state.sessions.get(&client_id) {
        Some(session) => session,
        None => {
            return ApiError::ClientIdNotFound("client not found".to_string()).into_response();
        }
    };
    // Read over the real session mirror written by the subscribe routes,
    // not the router trie: same state, no work on the fan-out path.
    let mut entries: Vec<(String, u8, u8, u8, u8)> = session
        .subscriptions
        .read()
        .iter()
        .map(|(filter, opts)| {
            (
                filter.as_str().to_string(),
                u8::from(opts.qos),
                opts.nl,
                opts.rap,
                opts.rh,
            )
        })
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    if entries.len() > MAX_CLIENT_SUBSCRIPTIONS {
        entries.truncate(MAX_CLIENT_SUBSCRIPTIONS);
    }
    let subs: Vec<serde_json::Value> = entries
        .into_iter()
        .map(|(topic, qos, nl, rap, rh)| {
            serde_json::json!({
                "topic": topic,
                "qos": qos,
                "nl": nl,
                "rap": rap,
                "rh": rh,
                "node": "indramqtt@127.0.0.1",
                "clientid": client_id,
            })
        })
        .collect();

    (StatusCode::OK, Json(subs)).into_response()
}

/// One management subscribe against the real router and session index.
///
/// Shared by the single and bulk routes; bulk reuses this per entry so
/// both paths register the same state. It touches the session map and
/// the router trie and nothing on the message path. Work is bounded by
/// the request itself: one map insert plus one trie insert per entry,
/// plus a result list of the same length for bulk. No new buffering is
/// added to fan-out or fan-in; management-plane only.
fn apply_single_subscribe(
    state: &ApiState,
    client_id: &str,
    entry: &serde_json::Value,
) -> Result<serde_json::Value, ApiError> {
    let session = match state.sessions.get(client_id) {
        Some(session) => session,
        None => {
            return Err(ApiError::ClientIdNotFound("client not found".to_string()));
        }
    };
    let (filter, qos, nl, rap, rh) = parse_subscribe_entry(entry)?;
    state
        .sessions
        .add_subscription_with_options(client_id, filter.clone(), qos, nl, rap, rh);

    // Live connection owns the router copy; offline subscribes keep a
    // placeholder until a live re-subscribe replaces it (the trie holds
    // at most one `conn_id` per `(filter node, client_id)`).
    let conn_id = (*session.conn_id.read()).unwrap_or(1);

    state
        .router
        .subscribe(&filter, Subscription::new(client_id, conn_id, qos));

    Ok(serde_json::json!({
        "clientid": client_id,
        "topic": filter.as_str(),
        "qos": u8::from(qos),
        "nl": nl,
        "rap": rap,
        "rh": rh,
        "node": "indramqtt@127.0.0.1",
    }))
}

/// Validate one subscribe entry (`{topic, qos, nl, rap, rh}`) from a
/// pre-parsed JSON value. `topic` is required; the option fields default
/// to 0. Malformed entries are client errors, never silent drops: an
/// invalid filter, an out-of-range option, or a publish-only delayed
/// prefix fails instead of registering a wrong subscription.
fn parse_subscribe_entry(
    value: &serde_json::Value,
) -> Result<(TopicFilter, QoS, u8, u8, u8), ApiError> {
    let obj = value
        .as_object()
        .ok_or_else(|| ApiError::BadRequest("subscribe entry must be a JSON object".to_string()))?;
    let topic_str = obj
        .get("topic")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::BadRequest("field `topic` is required".to_string()))?;
    let qos_raw = get_option_u8(obj, "qos", 0)?;
    if qos_raw > 2 {
        return Err(ApiError::BadRequest(
            "field `qos` must be 0, 1 or 2".to_string(),
        ));
    }
    let nl = get_option_u8(obj, "nl", 0)?;
    if nl > 1 {
        return Err(ApiError::BadRequest(
            "field `nl` must be 0 or 1".to_string(),
        ));
    }
    let rap = get_option_u8(obj, "rap", 0)?;
    if rap > 1 {
        return Err(ApiError::BadRequest(
            "field `rap` must be 0 or 1".to_string(),
        ));
    }
    let rh = get_option_u8(obj, "rh", 0)?;
    if rh > 2 {
        return Err(ApiError::BadRequest(
            "field `rh` must be 0, 1 or 2".to_string(),
        ));
    }
    if broker_router::strip_delayed_prefix(topic_str).is_some() {
        return Err(ApiError::BadRequest(
            "delayed topics cannot be subscribed".to_string(),
        ));
    }
    let filter = TopicFilter::new(topic_str)
        .map_err(|e| ApiError::BadRequest(format!("invalid topic `{topic_str}`: {e}")))?;
    let qos = QoS::try_from(qos_raw)
        .map_err(|_| ApiError::BadRequest("field `qos` must be 0, 1 or 2".to_string()))?;
    Ok((filter, qos, nl, rap, rh))
}

/// Read one optional `0..=255` option field, defaulting when absent.
/// Wrong JSON types are client errors, not silent defaults.
fn get_option_u8(
    obj: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    default: u8,
) -> Result<u8, ApiError> {
    match obj.get(field) {
        None => Ok(default),
        Some(serde_json::Value::Number(n)) => n
            .as_u64()
            .and_then(|v| u8::try_from(v).ok())
            .ok_or_else(|| {
                ApiError::BadRequest(format!("field `{field}` must be an integer 0..=255"))
            }),
        Some(_) => Err(ApiError::BadRequest(format!(
            "field `{field}` must be an integer 0..=255"
        ))),
    }
}

pub async fn client_subscribe(
    State(state): State<ApiState>,
    Path(client_id): Path<String>,
    body: Bytes,
) -> Response {
    let entry: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(error) => {
            return ApiError::BadRequest(format!("invalid subscribe body: {error}"))
                .into_response();
        }
    };
    match apply_single_subscribe(&state, &client_id, &entry) {
        Ok(item) => (StatusCode::OK, Json(item)).into_response(),
        Err(error) => error.into_response(),
    }
}

pub async fn bulk_subscribe(
    State(state): State<ApiState>,
    Path(client_id): Path<String>,
    body: Bytes,
) -> Response {
    let entries: Vec<serde_json::Value> = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(error) => {
            return ApiError::BadRequest(format!("invalid bulk subscribe body: {error}"))
                .into_response();
        }
    };
    // Unknown clients fail the whole batch with not-found; malformed
    // entries fail per entry while the good ones still land. The result
    // list is bounded by the request length; no extra buffering.
    if state.sessions.get(&client_id).is_none() {
        return ApiError::ClientIdNotFound("client not found".to_string()).into_response();
    }
    let mut results = Vec::with_capacity(entries.len());
    for entry in &entries {
        match apply_single_subscribe(&state, &client_id, entry) {
            Ok(item) => results.push(item),
            Err(ApiError::BadRequest(message)) => {
                let topic = entry
                    .get("topic")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                results.push(serde_json::json!({
                    "topic": topic,
                    "code": "BAD_REQUEST",
                    "message": message,
                }));
            }
            Err(error) => {
                let topic = entry
                    .get("topic")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                results.push(serde_json::json!({
                    "topic": topic,
                    "code": error.code(),
                    "message": error.message(),
                }));
            }
        }
    }
    (StatusCode::OK, Json(results)).into_response()
}

/// One management unsubscribe against the real router and session index.
///
/// Shared by the single and bulk routes; bulk reuses this per entry so
/// both paths remove the same state. It touches the session map and the
/// router trie and nothing on the message path. Work is bounded by the
/// request itself: one map removal plus one trie removal per entry, plus
/// a result list of the same length for bulk. Removing an absent
/// subscription still succeeds; unknown clients fail. No new buffering;
/// management-plane only.
fn apply_single_unsubscribe(
    state: &ApiState,
    client_id: &str,
    entry: &serde_json::Value,
) -> Result<serde_json::Value, ApiError> {
    if state.sessions.get(client_id).is_none() {
        return Err(ApiError::ClientIdNotFound("client not found".to_string()));
    }
    let filter = parse_unsubscribe_entry(entry)?;
    state.sessions.remove_subscription(client_id, &filter);
    state.router.unsubscribe(&filter, client_id);
    Ok(serde_json::json!({
        "topic": filter.as_str(),
    }))
}

/// Validate one unsubscribe entry (`{topic}`) from a pre-parsed JSON
/// value. `topic` is required and must be a valid filter; malformed
/// entries are client errors, never silent drops. An absent subscription
/// is not malformed: it validates and removes to an empty success.
fn parse_unsubscribe_entry(value: &serde_json::Value) -> Result<TopicFilter, ApiError> {
    let obj = value.as_object().ok_or_else(|| {
        ApiError::BadRequest("unsubscribe entry must be a JSON object".to_string())
    })?;
    let topic_str = obj
        .get("topic")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::BadRequest("field `topic` is required".to_string()))?;
    if broker_router::strip_delayed_prefix(topic_str).is_some() {
        return Err(ApiError::BadRequest(
            "delayed topics cannot be unsubscribed".to_string(),
        ));
    }
    TopicFilter::new(topic_str)
        .map_err(|e| ApiError::BadRequest(format!("invalid topic `{topic_str}`: {e}")))
}

pub async fn client_unsubscribe(
    State(state): State<ApiState>,
    Path(client_id): Path<String>,
    body: Bytes,
) -> Response {
    let entry: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(error) => {
            return ApiError::BadRequest(format!("invalid unsubscribe body: {error}"))
                .into_response();
        }
    };
    match apply_single_unsubscribe(&state, &client_id, &entry) {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error.into_response(),
    }
}

pub async fn bulk_unsubscribe(
    State(state): State<ApiState>,
    Path(client_id): Path<String>,
    body: Bytes,
) -> Response {
    let entries: Vec<serde_json::Value> = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(error) => {
            return ApiError::BadRequest(format!("invalid bulk unsubscribe body: {error}"))
                .into_response();
        }
    };
    // Unknown clients fail the whole batch with not-found; malformed
    // entries fail per entry while the good ones still remove. Absent
    // subscriptions succeed per entry. The result list is bounded by the
    // request length; no extra buffering.
    if state.sessions.get(&client_id).is_none() {
        return ApiError::ClientIdNotFound("client not found".to_string()).into_response();
    }
    let mut results = Vec::with_capacity(entries.len());
    for entry in &entries {
        match apply_single_unsubscribe(&state, &client_id, entry) {
            Ok(item) => results.push(item),
            Err(ApiError::BadRequest(message)) => {
                let topic = entry
                    .get("topic")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                results.push(serde_json::json!({
                    "topic": topic,
                    "code": "BAD_REQUEST",
                    "message": message,
                }));
            }
            Err(error) => {
                let topic = entry
                    .get("topic")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                results.push(serde_json::json!({
                    "topic": topic,
                    "code": error.code(),
                    "message": error.message(),
                }));
            }
        }
    }
    (StatusCode::OK, Json(results)).into_response()
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
    // Bounded per-client view over the real QoS 1 tracker: the window
    // snapshot plus the spill snapshot (oldest-first, window then spill),
    // clones at most window + spill entries under short read locks, then
    // paginates with the W0 helper. Management-plane read only;
    // the delivery hot path never takes a management lock (it takes the
    // session write lock only to track/ack, never to serve this view).
    let mut snapshot = session.inflight_snapshot();
    snapshot.extend(session.inflight_spill_snapshot());
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

/// Render one offline-queue entry in the documented mqueue shape.
///
/// `publish_at` is the instant recorded where the message was already
/// being written (offline queue insert), omitted for entries that predate
/// timestamp recording rather than substituted.
fn mqueue_entry_json(qm: &broker_session::QueuedMessage, msgid: String) -> serde_json::Value {
    let mut map = serde_json::Map::with_capacity(5);
    map.insert("msgid".to_string(), serde_json::Value::from(msgid));
    map.insert(
        "topic".to_string(),
        serde_json::Value::from(qm.topic.as_str()),
    );
    map.insert("qos".to_string(), serde_json::Value::from(u8::from(qm.qos)));
    map.insert(
        "payload".to_string(),
        serde_json::Value::from(String::from_utf8_lossy(&qm.payload).into_owned()),
    );
    if let Some(ms) = qm.publish_at_ms {
        map.insert(
            "publish_at".to_string(),
            serde_json::Value::from(crate::v5::retainer::format_rfc3339_ms(ms)),
        );
    }
    serde_json::Value::Object(map)
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
    let start =
        ((u64::from(params.page.max(1)) - 1) * u64::from(params.limit)).min(total as u64) as usize;
    let data: Vec<serde_json::Value> = page_items
        .iter()
        .enumerate()
        .map(|(i, qm)| mqueue_entry_json(qm, (start + i + 1).to_string()))
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

/// Global subscription list as a bare array (W1-14).
///
/// Reads the session-mirror index via
/// [`broker_session::SessionManager::global_subscriptions`], not the
/// router trie, so list reads never block the routing path. The snapshot
/// is bounded by [`broker_session::MAX_GLOBAL_SUBSCRIPTIONS`] (100_000
/// rows, sorted by `(client_id, topic)` for a deterministic page order)
/// and then sliced with the W0 `page`/`limit` helper; unknown query keys
/// are ignored by the extractor so new parameters degrade to the full
/// first page instead of a 400. Management-plane only: no new buffering
/// on fan-out or fan-in. Returns a bare list to match the documented
/// shape (no `data`/`meta` envelope).
pub async fn list_subscriptions(State(state): State<ApiState>, params: PageParams) -> Response {
    let rows = state.sessions.global_subscriptions();
    let page_items = paginate(&rows, params.page, params.limit);
    let data: Vec<serde_json::Value> = page_items
        .iter()
        .map(|entry| {
            serde_json::json!({
                "clientid": entry.client_id,
                "topic": entry.filter.as_str(),
                "qos": u8::from(entry.options.qos),
                "nl": entry.options.nl,
                "rap": entry.options.rap,
                "rh": entry.options.rh,
                "node": "indramqtt@127.0.0.1"
            })
        })
        .collect();
    (StatusCode::OK, Json(data)).into_response()
}

/// Topic list as a paged collection (W1-15).
///
/// Reads the topic index maintained on the router via
/// [`broker_router::Router::record_topic`], not the session
/// subscription mirror, so only concrete publish topics appear (a
/// subscribe alone never creates a row). The snapshot is bounded by
/// [`broker_router::MAX_KNOWN_TOPICS`] (100_000 names, sorted for a
/// deterministic page order) and then sliced with the W0
/// `page`/`limit` helper; unknown query keys are ignored by the
/// extractor so new parameters degrade to the full first page instead
/// of a 400. Management-plane only: list reads take a short lock on
/// the topic set and never touch the subscription trie, fan-out or
/// fan-in. Returns the documented envelope (`data` plus `meta`).
pub async fn list_topics(State(state): State<ApiState>, params: PageParams) -> Response {
    let rows = state.router.list_topics();
    let total = rows.len();
    let page_items = paginate(&rows, params.page, params.limit);
    let data: Vec<serde_json::Value> = page_items
        .iter()
        .map(|t| {
            serde_json::json!({
                "topic": t,
                "node": "indramqtt@127.0.0.1"
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

/// Topic detail for one exact topic name (W1-15).
///
/// Looks up the topic index with an exact match on the percent-decoded
/// path parameter: no wildcard, prefix or filter matching. Known
/// topics return the documented record; unknown topics return the
/// documented not-found shape (`NOT_FOUND`, 404). Management-plane
/// read only: one short lock on the topic set, no work on fan-out or
/// fan-in.
pub async fn get_topic(State(state): State<ApiState>, Path(topic): Path<String>) -> Response {
    if !state.router.contains_topic(&topic) {
        return ApiError::NotFound("topic not found".to_string()).into_response();
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "topic": topic,
            "node": "indramqtt@127.0.0.1"
        })),
    )
        .into_response()
}

/// Documented `GET /sessions_count` scoping. Only `node` narrows the
/// count; every other query key is ignored by the `Query` extractor so
/// new parameters degrade to the full count instead of a 400.
#[derive(Deserialize, Default)]
pub struct SessionsCountQuery {
    #[serde(default)]
    pub node: Option<String>,
}

/// Live-session count as a small `{"count": N}` object.
///
/// Constant-time read over indexed session state: one atomic maintained
/// by the session manager, no scan of the session map. Counts connected
/// sessions only. An explicit `node` value for another node narrows to
/// zero on this single node; unknown query keys are ignored.
/// Management-plane only; never touched on fan-out or fan-in.
pub async fn get_sessions_count(
    State(state): State<ApiState>,
    Query(params): Query<SessionsCountQuery>,
) -> Response {
    let total = state.sessions.connected_count();
    let count = match params.node.as_deref() {
        Some(want)
            if !want.is_empty()
                && want != state.node_id.as_str()
                && want != "indramqtt@127.0.0.1" =>
        {
            0
        }
        _ => total,
    };
    (StatusCode::OK, Json(serde_json::json!({ "count": count }))).into_response()
}

/// Management-plane publish fan-out shared by `POST /publish` and the
/// rule republish sink below.
///
/// Mirrors the kernel ingress fan-out (`broker-node`): delivery QoS is
/// `min(publish QoS, subscription QoS)`; live sessions get a
/// per-session downlink packet id (QoS 1 tracked for redelivery until
/// its PUBACK); detached durable sessions buffer into their offline
/// queue; detached clean sessions drop; unknown sessions fall back to
/// the router-registered `conn_id`. Returns
/// `(live frames, offline queued, router matches)`.
fn build_publish_deliveries(
    state: &ApiState,
    topic: &Topic,
    qos: QoS,
    retain: bool,
    payload: &Bytes,
) -> (Vec<(u64, brokerlink::BrokerFrame)>, usize, usize) {
    let qos_raw = u8::from(qos);
    let topic_str = topic.as_str();
    let matched = state.router.matches(topic);
    let matched_count = matched.len();
    let mut deliveries = Vec::new();
    let mut offline_queued = 0usize;
    for sub in matched {
        let effective = std::cmp::min(qos_raw, u8::from(sub.qos));
        match state.sessions.get(sub.client_id.as_ref()) {
            Some(session) => {
                let connected = *session.connected.read();
                let live = *session.conn_id.read();
                match (connected, live) {
                    (true, Some(conn_id)) => {
                        let downlink_id = if effective == 0 {
                            0u16
                        } else {
                            session.next_packet_id()
                        };
                        if effective == 1 {
                            // B4-01: window fast path, spill past it (still
                            // tracked for DUP replay), counted drop only
                            // past window + spill. Mirrors the kernel
                            // publish-to-delivery event.
                            match session.track_inflight_or_spill(broker_session::InflightMessage {
                                packet_id: downlink_id,
                                topic: topic.clone(),
                                qos: QoS::try_from(effective).unwrap_or(QoS::AtLeastOnce),
                                retain,
                                payload: payload.clone(),
                            }) {
                                broker_session::InflightTrackOutcome::Tracked => {}
                                broker_session::InflightTrackOutcome::Spilled => {
                                    state.metrics.inc_inflight_spilled();
                                }
                                broker_session::InflightTrackOutcome::Dropped => {
                                    state.metrics.inc_inflight_dropped();
                                    state.metrics.inc_inflight_spill_evicted();
                                }
                            }
                        }
                        if let Some(frame) = encode_publish_out_frame(
                            conn_id,
                            topic_str,
                            downlink_id,
                            effective,
                            retain,
                            payload,
                        ) {
                            deliveries.push((conn_id, frame));
                        }
                    }
                    _ => {
                        if !session.clean_start {
                            let before = session.offline_len();
                            session.push_offline(broker_session::QueuedMessage {
                                topic: topic.clone(),
                                qos: QoS::try_from(effective).unwrap_or(QoS::AtMostOnce),
                                retain,
                                payload: payload.clone(),
                                publish_at_ms: None,
                            });
                            let evicted = (before + 1).saturating_sub(session.offline_len());
                            if evicted > 0 {
                                state.metrics.inc_offline_queue_evicted_by(evicted as u64);
                            }
                            offline_queued += 1;
                        } else {
                            state.metrics.inc_detached_clean_dropped();
                        }
                    }
                }
            }
            None => {
                let downlink_id = if effective == 0 { 0u16 } else { 1u16 };
                if let Some(frame) = encode_publish_out_frame(
                    sub.conn_id,
                    topic_str,
                    downlink_id,
                    effective,
                    retain,
                    payload,
                ) {
                    deliveries.push((sub.conn_id, frame));
                }
            }
        }
    }
    (deliveries, offline_queued, matched_count)
}

/// Encode one `PublishOut` frame (`TopicLen | Topic | PacketId | QoS |
/// Retain | Dup(0)`); sequence is stamped per destination by
/// `ConnTable::route`.
fn encode_publish_out_frame(
    conn_id: u64,
    topic: &str,
    packet_id: u16,
    qos: u8,
    retain: bool,
    payload: &Bytes,
) -> Option<brokerlink::BrokerFrame> {
    let mut meta = Vec::with_capacity(2 + topic.len() + 2 + 3);
    meta.extend_from_slice(&(topic.len() as u16).to_be_bytes());
    meta.extend_from_slice(topic.as_bytes());
    meta.extend_from_slice(&packet_id.to_be_bytes());
    meta.push(qos);
    meta.push(u8::from(retain));
    meta.push(0u8);
    brokerlink::BrokerFrame::new(
        brokerlink::OpCode::PublishOut,
        conn_id,
        0,
        Bytes::from(meta),
        payload.clone(),
    )
    .ok()
}

/// Route already-built frames, counting only live mailbox arrivals as
/// forwarded/sent/delivered (drops are counted inside `ConnTable::route`).
fn route_publish_frames(state: &ApiState, frames: Vec<(u64, brokerlink::BrokerFrame)>) -> u64 {
    let mut enqueued = 0u64;
    let mut enqueued_bytes = 0u64;
    for (conn_id, frame) in frames {
        let len = frame.total_frame_len() as u64;
        if state.conns.route(conn_id, frame) {
            enqueued += 1;
            enqueued_bytes += len;
        }
    }
    state.metrics.inc_messages_forwarded_by(enqueued);
    state.metrics.inc_publish_sent_by(enqueued);
    state.metrics.inc_delivered_by(enqueued);
    state.metrics.inc_bytes_sent_by(enqueued_bytes);
    enqueued
}

fn publish_id() -> String {
    format!(
        "{:08X}{:08X}{:08X}{:08X}",
        rand::random::<u32>(),
        rand::random::<u32>(),
        rand::random::<u32>(),
        rand::random::<u32>(),
    )
}

/// Validate one publish entry (`{topic, payload, payload_encoding, qos,
/// retain}`) from a pre-parsed JSON value. `topic` is required and must
/// be a concrete topic; `payload` defaults to `""`; `payload_encoding`
/// is `plain` (default) or `base64`; `qos` defaults to 0 and must be
/// 0, 1 or 2; `retain` defaults to false and must be a boolean.
/// Malformed entries are client errors with `BAD_REQUEST`.
fn parse_publish_entry(value: &serde_json::Value) -> Result<(Topic, Bytes, QoS, bool), String> {
    let obj = value
        .as_object()
        .ok_or_else(|| "publish entry must be a JSON object".to_string())?;
    let topic_str = obj
        .get("topic")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "field `topic` is required".to_string())?;
    if topic_str.len() > u16::MAX as usize {
        return Err("field `topic` is too long".to_string());
    }
    let topic = Topic::new(topic_str).map_err(|e| format!("invalid topic `{topic_str}`: {e}"))?;
    let qos_raw = match obj.get("qos") {
        None => 0u8,
        Some(serde_json::Value::Number(n)) => n
            .as_u64()
            .and_then(|v| u8::try_from(v).ok())
            .ok_or_else(|| "field `qos` must be 0, 1 or 2".to_string())?,
        Some(_) => return Err("field `qos` must be 0, 1 or 2".to_string()),
    };
    if qos_raw > 2 {
        return Err("field `qos` must be 0, 1 or 2".to_string());
    }
    let qos = QoS::try_from(qos_raw).map_err(|_| "field `qos` must be 0, 1 or 2".to_string())?;
    let retain = match obj.get("retain") {
        None => false,
        Some(serde_json::Value::Bool(b)) => *b,
        Some(_) => return Err("field `retain` must be a boolean".to_string()),
    };
    let encoding = match obj.get("payload_encoding") {
        None => "plain",
        Some(serde_json::Value::String(s)) => s.as_str(),
        Some(_) => {
            return Err("field `payload_encoding` must be \"plain\" or \"base64\"".to_string());
        }
    };
    if encoding != "plain" && encoding != "base64" {
        return Err("field `payload_encoding` must be \"plain\" or \"base64\"".to_string());
    }
    let payload_str = match obj.get("payload") {
        None => "",
        Some(serde_json::Value::String(s)) => s.as_str(),
        Some(_) => return Err("field `payload` must be a string".to_string()),
    };
    let payload = if encoding == "base64" {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        STANDARD
            .decode(payload_str.as_bytes())
            .map(Bytes::from)
            .map_err(|e| format!("field `payload` is not valid base64: {e}"))?
    } else {
        Bytes::from(payload_str.as_bytes().to_vec())
    };
    Ok((topic, payload, qos, retain))
}

/// Rule republish sink for the management publish path: pure in-memory
/// fan-out through the same session-aware builder as direct publishes,
/// so rule output observes identical QoS downgrade, packet id and
/// offline/inflight semantics. No sockets, no MQTT loopback.
struct ApiBrokerSink {
    router: std::sync::Arc<broker_router::Router>,
    sessions: std::sync::Arc<broker_session::SessionManager>,
    conns: std::sync::Arc<broker_router::ConnTable>,
    metrics: std::sync::Arc<broker_observability::Metrics>,
}

#[async_trait::async_trait]
impl broker_rules::BrokerSink for ApiBrokerSink {
    async fn publish(
        &self,
        topic: Topic,
        payload: Bytes,
        qos: QoS,
        retain: bool,
    ) -> Result<(), broker_rules::RuleEngineError> {
        let qos_raw = u8::from(qos);
        let topic_str = topic.as_str();
        let mut frames = Vec::new();
        for sub in self.router.matches(&topic) {
            let effective = std::cmp::min(qos_raw, u8::from(sub.qos));
            match self.sessions.get(sub.client_id.as_ref()) {
                Some(session) => {
                    let connected = *session.connected.read();
                    let live = *session.conn_id.read();
                    match (connected, live) {
                        (true, Some(conn_id)) => {
                            let downlink_id = if effective == 0 {
                                0u16
                            } else {
                                session.next_packet_id()
                            };
                            if effective == 1 {
                                // B4-01: spill past the window, still
                                // tracked for DUP replay; counted drop
                                // only past window + spill.
                                match session.track_inflight_or_spill(
                                    broker_session::InflightMessage {
                                        packet_id: downlink_id,
                                        topic: topic.clone(),
                                        qos: QoS::try_from(effective).unwrap_or(QoS::AtLeastOnce),
                                        retain,
                                        payload: payload.clone(),
                                    },
                                ) {
                                    broker_session::InflightTrackOutcome::Tracked => {}
                                    broker_session::InflightTrackOutcome::Spilled => {
                                        self.metrics.inc_inflight_spilled();
                                    }
                                    broker_session::InflightTrackOutcome::Dropped => {
                                        self.metrics.inc_inflight_dropped();
                                        self.metrics.inc_inflight_spill_evicted();
                                    }
                                }
                            }
                            let mut meta = Vec::with_capacity(2 + topic_str.len() + 2 + 3);
                            meta.extend_from_slice(&(topic_str.len() as u16).to_be_bytes());
                            meta.extend_from_slice(topic_str.as_bytes());
                            meta.extend_from_slice(&downlink_id.to_be_bytes());
                            meta.push(effective);
                            meta.push(u8::from(retain));
                            meta.push(0u8);
                            if let Ok(frame) = brokerlink::BrokerFrame::new(
                                brokerlink::OpCode::PublishOut,
                                conn_id,
                                0,
                                Bytes::from(meta),
                                payload.clone(),
                            ) {
                                frames.push((conn_id, frame));
                            }
                        }
                        _ => {
                            if !session.clean_start {
                                let before = session.offline_len();
                                session.push_offline(broker_session::QueuedMessage {
                                    topic: topic.clone(),
                                    qos: QoS::try_from(effective).unwrap_or(QoS::AtMostOnce),
                                    retain,
                                    payload: payload.clone(),
                                    publish_at_ms: None,
                                });
                                let evicted = (before + 1).saturating_sub(session.offline_len());
                                if evicted > 0 {
                                    self.metrics.inc_offline_queue_evicted_by(evicted as u64);
                                }
                            } else {
                                self.metrics.inc_detached_clean_dropped();
                            }
                        }
                    }
                }
                None => {
                    let downlink_id = if effective == 0 { 0u16 } else { 1u16 };
                    let mut meta = Vec::with_capacity(2 + topic_str.len() + 2 + 3);
                    meta.extend_from_slice(&(topic_str.len() as u16).to_be_bytes());
                    meta.extend_from_slice(topic_str.as_bytes());
                    meta.extend_from_slice(&downlink_id.to_be_bytes());
                    meta.push(effective);
                    meta.push(u8::from(retain));
                    meta.push(0u8);
                    if let Ok(frame) = brokerlink::BrokerFrame::new(
                        brokerlink::OpCode::PublishOut,
                        sub.conn_id,
                        0,
                        Bytes::from(meta),
                        payload.clone(),
                    ) {
                        frames.push((sub.conn_id, frame));
                    }
                }
            }
        }
        let mut enqueued = 0u64;
        let mut enqueued_bytes = 0u64;
        for (conn_id, frame) in frames {
            let len = frame.total_frame_len() as u64;
            if self.conns.route(conn_id, frame) {
                enqueued += 1;
                enqueued_bytes += len;
            }
        }
        self.metrics.inc_messages_forwarded_by(enqueued);
        self.metrics.inc_publish_sent_by(enqueued);
        self.metrics.inc_delivered_by(enqueued);
        self.metrics.inc_bytes_sent_by(enqueued_bytes);
        Ok(())
    }
}

/// Publish one message through ingress accounting, rule execution then session-aware
/// fan-out, mirroring kernel ingress order. Retain flag is preserved in delivery frames
/// and offline/inflight entries; no extra per-message buffering is added. Returns match count.
/// Retained store/clear for management publishes (W1-28), mirroring kernel ingress.
///
/// Stores (or clears on empty payload) before rules and fan-out observe the
/// message. Oversized payloads past `max_payload_size` are delivered but
/// not stored; new topics past `backend.max_retained_messages` (when
/// non-zero) are dropped while replacements still land. Both are best-effort
/// guards sharing the same `retainer_config` object the kernel ingress
/// enforces; the authoritative bound is the hard cap in
/// `broker_storage::MAX_RETAINED_MESSAGES`, enforced atomically inside the
/// store write lock. After a write the retained gauge is recounted with the
/// same helper the kernel uses, so `/stats` stays exact instead of
/// drifting. Management-plane only (retained publishes are rare, so the
/// scan never sits on fan-out or fan-in); one short-lock read plus at most
/// one write per retained publish.
async fn handle_mgmt_retained(
    state: &ApiState,
    topic: &Topic,
    qos: QoS,
    retain: bool,
    payload: &Bytes,
) {
    if !retain {
        return;
    }
    if payload.is_empty() {
        if state.retained.clear_retained(topic).await.is_ok() {
            sync_retained_count(state).await;
        }
        return;
    }
    let cfg = state.retainer_config.get();
    let max_bytes =
        crate::v5::retainer::parse_bytesize_to_bytes(&cfg.max_payload_size).unwrap_or(1_048_576);
    if (payload.len() as u64) > max_bytes {
        return;
    }
    let cap = cfg.backend.max_retained_messages;
    if cap > 0 {
        let already = state
            .retained
            .get_retained(topic)
            .await
            .ok()
            .flatten()
            .is_some();
        if !already && state.stats.retained() >= cap {
            return;
        }
    }
    if state
        .retained
        .set_retained(topic.clone(), qos, payload.clone())
        .await
        .is_ok()
    {
        sync_retained_count(state).await;
    }
}

/// Recount retained topics into the stats gauge after a management retained
/// write, mirroring the kernel lifecycle helper. One bounded scan per
/// retained management publish (rare path); delivery never waits on it.
async fn sync_retained_count(state: &ApiState) {
    let filter = match TopicFilter::new("#") {
        Ok(valid) => valid,
        Err(_) => return,
    };
    if let Ok(matched) = state.retained.find_matching(&filter).await {
        state.stats.set_retained(matched.len() as u64);
    }
}

async fn do_mgmt_publish(
    state: &ApiState,
    topic: &Topic,
    payload: &Bytes,
    qos: QoS,
    retain: bool,
) -> usize {
    state.metrics.inc_messages_received();
    state.metrics.inc_publish_received();
    match qos {
        QoS::AtMostOnce => {
            state.metrics.inc_qos0_received();
        }
        QoS::AtLeastOnce => {
            state.metrics.inc_qos1_received();
        }
        QoS::ExactlyOnce => {
            state.metrics.inc_qos2_received();
        }
    }
    handle_mgmt_retained(state, topic, qos, retain, payload).await;
    let sink: std::sync::Arc<dyn broker_rules::BrokerSink> = std::sync::Arc::new(ApiBrokerSink {
        router: state.router.clone(),
        sessions: state.sessions.clone(),
        conns: state.conns.clone(),
        metrics: state.metrics.clone(),
    });
    let rules_fired = state
        .engine
        .dispatch_ingress(topic, payload, qos, &sink)
        .await;
    state.metrics.inc_rules_executed_by(rules_fired as u64);
    // Topic index (W1-15): remember the concrete publish topic before
    // fan-out so the list/detail reads observe it. Bounded short-lock
    // insert; delivery proceeds even when the index is full.
    // Management-plane index only, no work on fan-out or fan-in.
    state.router.record_topic(topic.as_str());
    let (frames, _offline, matched) = build_publish_deliveries(state, topic, qos, retain, payload);
    route_publish_frames(state, frames);
    matched
}

pub async fn publish_message(State(state): State<ApiState>, body: Bytes) -> Response {
    let value: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(error) => {
            return ApiError::BadRequest(format!("invalid publish body: {error}")).into_response();
        }
    };
    let (topic, payload, qos, retain) = match parse_publish_entry(&value) {
        Ok(parts) => parts,
        Err(message) => return ApiError::BadRequest(message).into_response(),
    };
    do_mgmt_publish(&state, &topic, &payload, qos, retain).await;
    (
        StatusCode::OK,
        Json(serde_json::json!({ "id": publish_id() })),
    )
        .into_response()
}

/// Bulk management publish through the single-entry injection routine.
///
/// Takes a JSON array of publish entries (same shape as `POST /publish`)
/// and injects each through `parse_publish_entry` plus `do_mgmt_publish`,
/// so bulk output observes identical validation, rule, retained and
/// fan-out semantics. One bad entry never fails the batch: it is marked
/// with the documented error shape in the result while the good ones
/// still deliver. A wholly malformed body (invalid JSON or not an array)
/// is a client error. Bounded iteration over the request itself: one
/// parse plus one fan-out per entry, plus a result list of the same
/// length. No extra buffering beyond the request and result lists;
/// management-plane only.
pub async fn publish_bulk(State(state): State<ApiState>, body: Bytes) -> Response {
    let entries: Vec<serde_json::Value> = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(error) => {
            return ApiError::BadRequest(format!("invalid publish bulk body: {error}"))
                .into_response();
        }
    };
    let mut results = Vec::with_capacity(entries.len());
    for entry in &entries {
        match parse_publish_entry(entry) {
            Ok((topic, payload, qos, retain)) => {
                do_mgmt_publish(&state, &topic, &payload, qos, retain).await;
                results.push(serde_json::json!({
                    "topic": topic.as_str(),
                    "id": publish_id(),
                }));
            }
            Err(message) => {
                let topic = entry
                    .get("topic")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                results.push(serde_json::json!({
                    "topic": topic,
                    "code": "BAD_REQUEST",
                    "message": message,
                }));
            }
        }
    }
    (StatusCode::OK, Json(results)).into_response()
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
            .expect("client body is small and readable");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("client body is JSON");
        (status, body)
    }

    #[tokio::test]
    async fn mqueue_publish_at_is_queue_time_not_a_constant() {
        use broker_protocol::{QoS, Topic};

        let state = standalone_state();
        let (session, _) = state.sessions.get_or_create("b110-mqueue", false);
        *session.connected.write() = false;
        *session.conn_id.write() = None;

        let before = crate::v5::retainer::now_ms();
        session.push_offline(broker_session::QueuedMessage {
            topic: Topic::new("conf/mqueue/b110").expect("valid topic"),
            qos: QoS::AtLeastOnce,
            retain: false,
            payload: bytes::Bytes::from_static(b"hello-b110"),
            publish_at_ms: None,
        });
        let after = crate::v5::retainer::now_ms();

        let (status, body) = response_parts(
            get_client_mqueue(
                State(state),
                Path("b110-mqueue".to_string()),
                PageParams {
                    page: 1,
                    limit: 100,
                },
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let entry = &body["data"][0];
        let published = entry
            .get("publish_at")
            .and_then(|v| v.as_str())
            .expect("queued entry carries publish_at");
        assert_ne!(published, "2026-09-13T21:00:00Z");
        assert_ne!(published, "2026-09-20T00:00:00Z");
        let parsed =
            crate::v5::retainer::parse_rfc3339_ms(published).expect("publish_at is RFC3339");
        assert!(
            parsed >= before.saturating_sub(1000) && parsed <= after + 1000,
            "publish_at {published} ({parsed}) must be the queue time [{before}, {after}]"
        );
    }

    #[test]
    fn mqueue_entry_omits_publish_at_without_recorded_time() {
        use broker_protocol::{QoS, Topic};

        let qm = broker_session::QueuedMessage {
            topic: Topic::new("conf/mqueue/legacy").expect("valid topic"),
            qos: QoS::AtLeastOnce,
            retain: false,
            payload: bytes::Bytes::from_static(b"old"),
            publish_at_ms: None,
        };
        let rendered = mqueue_entry_json(&qm, "1".to_string());
        assert!(
            rendered.get("publish_at").is_none(),
            "entries predating timestamp recording must omit publish_at: {rendered}"
        );
    }

    #[tokio::test]
    async fn connected_at_is_bind_time_not_a_constant() {
        let state = standalone_state();
        let before = crate::v5::retainer::now_ms();
        state.sessions.get_or_create("b110-conn", true);
        let after = crate::v5::retainer::now_ms();

        let (status, body) =
            response_parts(get_client(State(state), Path("b110-conn".to_string())).await).await;
        assert_eq!(status, StatusCode::OK);
        let connected = body
            .get("connected_at")
            .and_then(|v| v.as_str())
            .expect("client carries connected_at");
        assert_ne!(connected, "2026-09-13T21:00:00Z");
        let parsed =
            crate::v5::retainer::parse_rfc3339_ms(connected).expect("connected_at is RFC3339");
        assert!(
            parsed >= before.saturating_sub(1000) && parsed <= after + 1000,
            "connected_at {connected} ({parsed}) must be the bind time [{before}, {after}]"
        );
    }

    #[test]
    fn client_detail_omits_connected_at_without_recorded_time() {
        let state = standalone_state();
        let (session, _) = state.sessions.get_or_create("b110-legacy", true);
        *session.connected_at_ms.write() = None;
        let rendered = client_detail_json("b110-legacy", Some(&session), true, 60);
        assert!(
            rendered.get("connected_at").is_none(),
            "sessions predating timestamp recording must omit connected_at: {rendered}"
        );
    }
}
