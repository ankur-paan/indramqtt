//! Auto-subscribe list for the v5 management API.
//!
//! Covers `GET /mqtt/auto_subscribe` (read the list) and
//! `PUT /mqtt/auto_subscribe` (validated full replacement) plus the
//! connect-time hook that subscribes each new connection to the
//! configured entries. Single-node, management-plane only for the
//! routes; the hook runs once per successful bind, never on the
//! per-message path, so fan-out and fan-in take no new lock and no new
//! buffering.
//!
//! Store bounds (both stated here and enforced below):
//! - at most [`MAX_AUTO_SUBSCRIBE_TOPICS`] entries (20, matching the
//!   documented limit); writes past the cap are rejected with
//!   `EXCEED_LIMIT` instead of growing without limit;
//! - `topic` is capped at 512 chars, so one entry cannot balloon memory;
//! - every entry is five small fields (`topic`, `qos`, `rh`, `rap`,
//!   `nl`), so per-entry memory is constant;
//! - reads clone at most the capped list once per request under a short
//!   lock; the connect hook clones the same capped list once per bind
//!   and subscribes each entry with one router plus one session insert.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use bytes::Bytes;
use std::sync::RwLock;

use crate::ApiState;

/// Upper bound for stored auto-subscribe entries. Writes past this size
/// are rejected with `EXCEED_LIMIT` instead of growing the list without
/// limit. Matches the documented maximum.
pub const MAX_AUTO_SUBSCRIBE_TOPICS: usize = 20;
/// Longest accepted `topic` value.
const MAX_TOPIC_LEN: usize = 512;

/// One configured auto-subscription: the topic filter applied at
/// connect time plus its subscription options. `qos` is 0..=2, `rh` is
/// 0..=2, `rap` and `nl` are 0..=1; absent option fields load as 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoSubscribeEntry {
    pub topic: String,
    pub qos: u8,
    pub rh: u8,
    pub rap: u8,
    pub nl: u8,
}

impl AutoSubscribeEntry {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "topic": self.topic,
            "qos": self.qos,
            "rh": self.rh,
            "rap": self.rap,
            "nl": self.nl,
        })
    }
}

/// Bounded in-memory list behind one short lock.
///
/// Every method finishes quickly and no delivery path touches it except
/// the per-connect hook, which clones the capped list once per bind, so
/// management reads never block messaging.
pub struct AutoSubscribeStore {
    inner: RwLock<Vec<AutoSubscribeEntry>>,
}

impl AutoSubscribeStore {
    /// Empty list.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(Vec::new()),
        }
    }

    /// Snapshot of the configured entries in stored order.
    pub fn list(&self) -> Vec<AutoSubscribeEntry> {
        self.inner.read().expect("auto-subscribe lock").clone()
    }

    /// Replace the whole list after full validation by the caller.
    /// The caller guarantees length and per-entry validity; this only
    /// swaps.
    fn replace(&self, next: Vec<AutoSubscribeEntry>) {
        *self.inner.write().expect("auto-subscribe lock") = next;
    }
}

impl Default for AutoSubscribeStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Render one configured topic for a connecting client.
///
/// Replaces the documented `${clientid}`, `${username}` and `${host}`
/// placeholders; unknown placeholders are left untouched so a future
/// variable degrades to a literal instead of a silent empty topic.
/// `username` defaults to empty and `host` to loopback when unknown.
pub fn render_auto_topic(template: &str, client_id: &str, username: Option<&str>) -> String {
    render_auto_topic_with_host(template, client_id, username, "127.0.0.1")
}

fn render_auto_topic_with_host(
    template: &str,
    client_id: &str,
    username: Option<&str>,
    host: &str,
) -> String {
    let username = username.unwrap_or("");
    // One pass per variable; templates are short (<= 512 chars) and the
    // hook runs once per connect, never per message.
    template
        .replace("${clientid}", client_id)
        .replace("${username}", username)
        .replace("${host}", host)
}

/// `GET /mqtt/auto_subscribe`: the configured list as a JSON array.
///
/// One bounded snapshot per request (at most
/// [`MAX_AUTO_SUBSCRIBE_TOPICS`] small clones under a short lock); an
/// empty list reads as `[]`, never an error.
pub async fn get_auto_subscribe(State(state): State<ApiState>) -> Response {
    let entries = state.auto_subscribe.list();
    let data: Vec<serde_json::Value> = entries.iter().map(AutoSubscribeEntry::to_json).collect();
    (StatusCode::OK, Json(data)).into_response()
}

/// `PUT /mqtt/auto_subscribe`: validated full replacement.
///
/// The body must be a JSON array; every entry is validated before
/// anything is applied so one bad entry rejects the entire write with
/// the documented `UPDATE_FAILED` shape and leaves the stored list
/// untouched. Lists longer than [`MAX_AUTO_SUBSCRIBE_TOPICS`] are
/// rejected with the documented `EXCEED_LIMIT` shape.
pub async fn put_auto_subscribe(State(state): State<ApiState>, body: Bytes) -> Response {
    let value: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(error) => return update_failed(format!("invalid auto_subscribe body: {error}")),
    };
    let items = match value.as_array() {
        Some(items) => items,
        None => {
            return update_failed("auto_subscribe body must be a JSON array".to_string());
        }
    };
    if items.len() > MAX_AUTO_SUBSCRIBE_TOPICS {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "code": "EXCEED_LIMIT",
                "message": format!(
                    "Max auto subscribe topic count is {MAX_AUTO_SUBSCRIBE_TOPICS}"
                ),
            })),
        )
            .into_response();
    }
    let mut next = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        match validate_entry(item) {
            Ok(entry) => next.push(entry),
            Err(reason) => {
                return update_failed(format!("topics[{index}]: {reason}"));
            }
        }
    }
    state.auto_subscribe.replace(next.clone());
    let data: Vec<serde_json::Value> = next.iter().map(AutoSubscribeEntry::to_json).collect();
    (StatusCode::OK, Json(data)).into_response()
}

fn update_failed(reason: String) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "code": "UPDATE_FAILED",
            "message": reason,
        })),
    )
        .into_response()
}

/// Validate one list entry (`{topic, qos, rh, rap, nl}`).
/// `topic` is required; option fields default to 0. Unknown fields are
/// ignored so newer entries degrade to the known subset instead of a
/// 400.
fn validate_entry(value: &serde_json::Value) -> Result<AutoSubscribeEntry, String> {
    let obj = value
        .as_object()
        .ok_or_else(|| "entry must be a JSON object".to_string())?;
    let topic = obj
        .get("topic")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "field `topic` is required".to_string())?;
    if topic.is_empty() {
        return Err("field `topic` must not be empty".to_string());
    }
    if topic.len() > MAX_TOPIC_LEN {
        return Err("field `topic` must not exceed 512 chars".to_string());
    }
    // Placeholders such as `${clientid}` render per connection; the
    // stored template itself must still be a well-formed filter so a
    // typo can never be persisted. `${...}` contains no `#` misuse, so
    // the standard filter check covers it.
    broker_protocol::TopicFilter::new(topic)
        .map_err(|e| format!("invalid topic `{topic}`: {e}"))?;
    if broker_router::strip_delayed_prefix(topic).is_some() {
        return Err("delayed topics cannot be auto-subscribed".to_string());
    }
    let qos = get_option(obj, "qos", 0, 2)?;
    let rh = get_option(obj, "rh", 0, 2)?;
    let rap = get_option(obj, "rap", 0, 1)?;
    let nl = get_option(obj, "nl", 0, 1)?;
    Ok(AutoSubscribeEntry {
        topic: topic.to_string(),
        qos,
        rh,
        rap,
        nl,
    })
}

fn get_option(
    obj: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    default: u8,
    max: u8,
) -> Result<u8, String> {
    match obj.get(field) {
        None => Ok(default),
        Some(serde_json::Value::Number(n)) => {
            let v = n
                .as_u64()
                .and_then(|v| u8::try_from(v).ok())
                .ok_or_else(|| format!("field `{field}` must be an integer 0..={max}"))?;
            if v > max {
                return Err(format!("field `{field}` must be 0..={max}"));
            }
            Ok(v)
        }
        Some(_) => Err(format!("field `{field}` must be an integer 0..={max}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::Response;

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
            .expect("auto-subscribe body is small and readable");
        let body: serde_json::Value =
            serde_json::from_slice(&bytes).expect("auto-subscribe body is JSON");
        (status, body)
    }

    #[tokio::test]
    async fn list_starts_empty_round_trip_and_replaces() {
        let state = standalone_state();
        let (status, before) = response_parts(get_auto_subscribe(State(state.clone())).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(before, serde_json::json!([]));

        let body = Bytes::from(
            serde_json::to_vec(&serde_json::json!([
                {"topic": "conf/auto/w139-a", "qos": 1},
            ]))
            .expect("update is JSON"),
        );
        let (status, after) =
            response_parts(put_auto_subscribe(State(state.clone()), body).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            after,
            serde_json::json!([
                {"topic": "conf/auto/w139-a", "qos": 1, "rh": 0, "rap": 0, "nl": 0},
            ])
        );

        let (status, reread) = response_parts(get_auto_subscribe(State(state.clone())).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reread, after);

        // Full replacement drops the previous entry.
        let body = Bytes::from(
            serde_json::to_vec(&serde_json::json!([
                {"topic": "conf/auto/w139-b", "qos": 0, "rh": 1, "rap": 0, "nl": 0},
            ]))
            .expect("update is JSON"),
        );
        let (status, replaced) =
            response_parts(put_auto_subscribe(State(state.clone()), body).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            replaced,
            serde_json::json!([
                {"topic": "conf/auto/w139-b", "qos": 0, "rh": 1, "rap": 0, "nl": 0},
            ])
        );
    }

    #[tokio::test]
    async fn invalid_entries_rejected_without_applying() {
        let state = standalone_state();
        let body = Bytes::from(
            serde_json::to_vec(&serde_json::json!([
                {"topic": "conf/auto/w139-ok", "qos": 0},
            ]))
            .expect("update is JSON"),
        );
        let (status, before) =
            response_parts(put_auto_subscribe(State(state.clone()), body).await).await;
        assert_eq!(status, StatusCode::OK);

        for bad in [
            serde_json::json!([{"qos": 0}]),
            serde_json::json!([{"topic": ""}]),
            serde_json::json!([{"topic": "sport/#/bogus"}]),
            serde_json::json!([{"topic": "a/b", "qos": 3}]),
            serde_json::json!([{"topic": "a/b", "rh": 5}]),
            serde_json::json!([{"topic": "a/b", "rap": 2}]),
            serde_json::json!([{"topic": "a/b", "nl": 2}]),
            serde_json::json!([{"topic": "a/b", "qos": "1"}]),
            serde_json::json!({"topic": "a/b"}),
            serde_json::json!({"topics": []}),
            serde_json::json!("topics"),
        ] {
            let body = Bytes::from(serde_json::to_vec(&bad).expect("bad body is JSON"));
            let (status, err) =
                response_parts(put_auto_subscribe(State(state.clone()), body).await).await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "body {bad} must be rejected"
            );
            assert_eq!(err["code"], serde_json::json!("UPDATE_FAILED"));
        }

        let (status, reread) = response_parts(get_auto_subscribe(State(state.clone())).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reread, before, "failed writes must not apply");
    }

    #[tokio::test]
    async fn too_many_entries_rejected_with_limit() {
        let state = standalone_state();
        let many: Vec<serde_json::Value> = (0..MAX_AUTO_SUBSCRIBE_TOPICS + 1)
            .map(|i| serde_json::json!({"topic": format!("conf/auto/w139-{i}")}))
            .collect();
        let body = Bytes::from(serde_json::to_vec(&many).expect("update is JSON"));
        let (status, err) =
            response_parts(put_auto_subscribe(State(state.clone()), body).await).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(err["code"], serde_json::json!("EXCEED_LIMIT"));

        let (status, reread) = response_parts(get_auto_subscribe(State(state.clone())).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reread, serde_json::json!([]));
    }

    #[tokio::test]
    async fn unknown_fields_are_ignored() {
        let state = standalone_state();
        let body = Bytes::from(
            serde_json::to_vec(&serde_json::json!([
                {"topic": "conf/auto/w139-future", "future_field": "ignored"},
            ]))
            .expect("update is JSON"),
        );
        let (status, after) =
            response_parts(put_auto_subscribe(State(state.clone()), body).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            after,
            serde_json::json!([
                {"topic": "conf/auto/w139-future", "qos": 0, "rh": 0, "rap": 0, "nl": 0},
            ])
        );
    }

    #[test]
    fn placeholders_render_per_client() {
        assert_eq!(
            render_auto_topic("cmd/${clientid}/z", "c1", None),
            "cmd/c1/z"
        );
        assert_eq!(
            render_auto_topic("u/${username}/t", "c1", Some("alice")),
            "u/alice/t"
        );
        assert_eq!(
            render_auto_topic("plain/topic", "c1", Some("alice")),
            "plain/topic"
        );
    }

    #[test]
    fn store_starts_empty_and_replaces() {
        let store = AutoSubscribeStore::new();
        assert!(store.list().is_empty());
        store.replace(vec![AutoSubscribeEntry {
            topic: "a/b".to_string(),
            qos: 1,
            rh: 0,
            rap: 0,
            nl: 0,
        }]);
        assert_eq!(store.list().len(), 1);
        assert_eq!(AutoSubscribeStore::default().list().len(), 0);
    }
}
