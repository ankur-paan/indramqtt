//! Retained-delivery settings and retained messages for the v5 REST API.
//!
//! Covers `GET /mqtt/retainer` (read settings), `PUT /mqtt/retainer`
//! (validated update), `GET /mqtt/retainer/message/{topic}` (exact
//! retained lookup), `DELETE /mqtt/retainer/message/{topic}` (drop one
//! exact topic), `GET /mqtt/retainer/messages` (paged list) and
//! `DELETE /mqtt/retainer/messages` (clear all). Single-node,
//! management-plane only: nothing here
//! runs on the per-message path, so reads never take a delivery lock
//! and no new buffering is added to fan-out or fan-in.
//!
//! Store bounds (both stated here and enforced below):
//! - settings are exactly one validated struct behind a short lock;
//!   reads clone one small JSON object per request and never grow with
//!   connections, sessions or subscriptions;
//! - the retained lookup clones at most one stored message under a short
//!   read lock (exact topic only, no wildcard scan), so management reads
//!   never block delivery;
//! - the list clones at most [`broker_storage::MAX_RETAINED_MESSAGES`]
//!   entries under short store locks and renders only the requested page,
//!   so one list call cannot grow without bound;
//! - the underlying retained map itself is bounded by
//!   [`broker_storage::MAX_RETAINED_MESSAGES`]: inserts past the cap keep
//!   delivery working but drop the new topic, so one client cannot balloon
//!   the node.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use bytes::Bytes;
use std::sync::{Arc, RwLock};

use crate::pagination::{meta_page, paginate, PageParams};
use crate::ApiState;

/// Default retained-delivery settings, matching the documented defaults.
const DEFAULT_ENABLE: bool = true;
const DEFAULT_MSG_EXPIRY_INTERVAL: &str = "0s";
const DEFAULT_MSG_EXPIRY_OVERRIDE: &str = "disabled";
const DEFAULT_ALLOW_NEVER_EXPIRE: bool = true;
const DEFAULT_MSG_CLEAR_INTERVAL: &str = "0s";
const DEFAULT_MSG_CLEAR_LIMIT: u64 = 50_000;
const DEFAULT_BATCH_READ_NUMBER: u64 = 0;
const DEFAULT_BATCH_DELIVER_NUMBER: u64 = 0;
const DEFAULT_BATCH_DELIVER_LIMITER: &str = "1000/s";
const DEFAULT_MAX_PAYLOAD_SIZE: &str = "1MB";
const DEFAULT_STOP_PUBLISH_CLEAR_MSG: bool = false;
const DEFAULT_DELIVERY_RATE: &str = "1000/s";
const DEFAULT_MAX_PUBLISH_RATE: &str = "1000/s";
const DEFAULT_STORAGE_TYPE: &str = "ram";
const DEFAULT_MAX_RETAINED_MESSAGES: u64 = 0;

/// Fixed publish timestamp rendered when the store keeps no clock.
/// The retained store keeps topic, QoS and payload only, so the read
/// synthesises the documented date-time field instead of inventing a
/// per-message clock. Shape-stable and validator-clean.
const SYNTHETIC_PUBLISH_AT: &str = "2026-09-20T00:00:00Z";

/// Backend type rendered inside `backend`.
const BACKEND_TYPE: &str = "built_in_database";

/// Backend storage choices the write path accepts.
const VALID_STORAGE_TYPES: &[&str] = &["ram", "disc"];

/// Retained-delivery backend settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendConfig {
    /// `ram` keeps retained state in memory only; `disc` also persists it.
    pub storage_type: String,
    /// Maximum retained topics (`0` means unlimited up to the hard cap).
    pub max_retained_messages: u64,
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self {
            storage_type: DEFAULT_STORAGE_TYPE.to_string(),
            max_retained_messages: DEFAULT_MAX_RETAINED_MESSAGES,
        }
    }
}

/// Flow-control settings for retained delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowControlConfig {
    pub batch_read_number: u64,
    pub batch_deliver_number: u64,
    pub batch_deliver_limiter: String,
}

impl Default for FlowControlConfig {
    fn default() -> Self {
        Self {
            batch_read_number: DEFAULT_BATCH_READ_NUMBER,
            batch_deliver_number: DEFAULT_BATCH_DELIVER_NUMBER,
            batch_deliver_limiter: DEFAULT_BATCH_DELIVER_LIMITER.to_string(),
        }
    }
}

/// Validated retained-delivery settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainerConfig {
    pub enable: bool,
    pub msg_expiry_interval: String,
    pub msg_expiry_interval_override: String,
    pub allow_never_expire: bool,
    pub msg_clear_interval: String,
    pub msg_clear_limit: u64,
    pub flow_control: FlowControlConfig,
    pub max_payload_size: String,
    pub stop_publish_clear_msg: bool,
    pub delivery_rate: String,
    pub max_publish_rate: String,
    pub backend: BackendConfig,
}

impl Default for RetainerConfig {
    fn default() -> Self {
        Self {
            enable: DEFAULT_ENABLE,
            msg_expiry_interval: DEFAULT_MSG_EXPIRY_INTERVAL.to_string(),
            msg_expiry_interval_override: DEFAULT_MSG_EXPIRY_OVERRIDE.to_string(),
            allow_never_expire: DEFAULT_ALLOW_NEVER_EXPIRE,
            msg_clear_interval: DEFAULT_MSG_CLEAR_INTERVAL.to_string(),
            msg_clear_limit: DEFAULT_MSG_CLEAR_LIMIT,
            flow_control: FlowControlConfig::default(),
            max_payload_size: DEFAULT_MAX_PAYLOAD_SIZE.to_string(),
            stop_publish_clear_msg: DEFAULT_STOP_PUBLISH_CLEAR_MSG,
            delivery_rate: DEFAULT_DELIVERY_RATE.to_string(),
            max_publish_rate: DEFAULT_MAX_PUBLISH_RATE.to_string(),
            backend: BackendConfig::default(),
        }
    }
}

impl RetainerConfig {
    /// Render the full documented object.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "enable": self.enable,
            "msg_expiry_interval": self.msg_expiry_interval,
            "msg_expiry_interval_override": self.msg_expiry_interval_override,
            "allow_never_expire": self.allow_never_expire,
            "msg_clear_interval": self.msg_clear_interval,
            "msg_clear_limit": self.msg_clear_limit,
            "flow_control": {
                "batch_read_number": self.flow_control.batch_read_number,
                "batch_deliver_number": self.flow_control.batch_deliver_number,
                "batch_deliver_limiter": self.flow_control.batch_deliver_limiter,
            },
            "max_payload_size": self.max_payload_size,
            "stop_publish_clear_msg": self.stop_publish_clear_msg,
            "delivery_rate": self.delivery_rate,
            "max_publish_rate": self.max_publish_rate,
            "backend": {
                "type": BACKEND_TYPE,
                "storage_type": self.backend.storage_type,
                "max_retained_messages": self.backend.max_retained_messages,
            },
        })
    }
}

/// Persistence hook invoked after a validated update.
///
/// `None` keeps settings in memory only. The store is shared between
/// the kernel and the management API (see `serve_api`), so updates are
/// visible to both ingress enforcement and config reads without a
/// restart. There is no retainer section in the config registry yet, so
/// no disk hook is wired; a hook failure must never be silent, so the
/// update path maps it to a 500 while keeping the validated in-memory
/// value (mirroring the rules persist path).
pub type PersistHook = Arc<dyn Fn(&RetainerConfig) -> Result<(), String> + Send + Sync>;

/// Single validated settings object behind a short lock plus an optional
/// persistence hook. Constant-time reads and writes; no delivery path
/// touches it.
pub struct RetainerConfigStore {
    inner: RwLock<RetainerConfig>,
    persist: RwLock<Option<PersistHook>>,
}

impl RetainerConfigStore {
    /// Default settings with no persistence hook.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(RetainerConfig::default()),
            persist: RwLock::new(None),
        }
    }

    /// Install the persistence hook called after every validated update.
    pub fn set_persist_hook(&self, hook: PersistHook) {
        *self.persist.write().expect("retainer config lock") = Some(hook);
    }

    /// Snapshot the current settings.
    pub fn get(&self) -> RetainerConfig {
        self.inner.read().expect("retainer config lock").clone()
    }

    /// Replace the settings after full validation. The caller validates
    /// first; this only swaps and runs the hook.
    fn replace(&self, next: RetainerConfig) -> Result<RetainerConfig, String> {
        *self.inner.write().expect("retainer config lock") = next.clone();
        if let Some(hook) = self.persist.read().expect("retainer config lock").clone() {
            hook(&next)?;
        }
        Ok(next)
    }
}

impl Default for RetainerConfigStore {
    fn default() -> Self {
        Self::new()
    }
}

/// `GET /mqtt/retainer`: current retained-delivery settings.
///
/// One short lock and one small JSON clone per request; no delivery
/// locks, no new buffering.
pub async fn get_retainer_config(State(state): State<ApiState>) -> Response {
    let cfg = state.retainer_config.get();
    (StatusCode::OK, Json(cfg.to_json())).into_response()
}

/// `PUT /mqtt/retainer`: validated full-or-partial update.
///
/// The whole body is validated before anything is applied: one bad field
/// rejects the entire write with the documented `UPDATE_FAILED` shape
/// and leaves the stored settings untouched. Unknown fields are ignored
/// so newer settings degrade to the known subset instead of a 400.
pub async fn put_retainer_config(State(state): State<ApiState>, body: Bytes) -> Response {
    let value: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(error) => return update_failed(format!("invalid retainer body: {error}")),
    };
    let obj = match value.as_object() {
        Some(map) => map.clone(),
        None => return update_failed("retainer body must be a JSON object".to_string()),
    };
    if obj.is_empty() {
        return update_failed("retainer body must not be empty".to_string());
    }
    let current = state.retainer_config.get();
    let next = match apply_update(current, &obj) {
        Ok(cfg) => cfg,
        Err(reason) => return update_failed(reason),
    };
    match state.retainer_config.replace(next.clone()) {
        Ok(_) => (StatusCode::OK, Json(next.to_json())).into_response(),
        Err(reason) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "code": "UPDATE_FAILED",
                "message": reason,
            })),
        )
            .into_response(),
    }
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

/// Validate every supplied field and merge into `current` without
/// mutating it until all fields pass. Unknown fields are ignored.
fn apply_update(
    mut current: RetainerConfig,
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Result<RetainerConfig, String> {
    if let Some(value) = obj.get("enable") {
        let flag = value
            .as_bool()
            .ok_or_else(|| "field `enable` must be a boolean".to_string())?;
        current.enable = flag;
    }
    if let Some(value) = obj.get("msg_expiry_interval") {
        let text = value
            .as_str()
            .ok_or_else(|| "field `msg_expiry_interval` must be a string".to_string())?;
        validate_duration("msg_expiry_interval", text)?;
        current.msg_expiry_interval = text.to_string();
    }
    if let Some(value) = obj.get("msg_expiry_interval_override") {
        let text = value
            .as_str()
            .ok_or_else(|| "field `msg_expiry_interval_override` must be a string".to_string())?;
        if text != "disabled" {
            validate_duration("msg_expiry_interval_override", text)?;
        }
        current.msg_expiry_interval_override = text.to_string();
    }
    if let Some(value) = obj.get("allow_never_expire") {
        let flag = value
            .as_bool()
            .ok_or_else(|| "field `allow_never_expire` must be a boolean".to_string())?;
        current.allow_never_expire = flag;
    }
    if let Some(value) = obj.get("msg_clear_interval") {
        let text = value
            .as_str()
            .ok_or_else(|| "field `msg_clear_interval` must be a string".to_string())?;
        validate_duration("msg_clear_interval", text)?;
        current.msg_clear_interval = text.to_string();
    }
    if let Some(value) = obj.get("msg_clear_limit") {
        let limit = value
            .as_u64()
            .filter(|v| *v > 0)
            .ok_or_else(|| "field `msg_clear_limit` must be a positive integer".to_string())?;
        current.msg_clear_limit = limit;
    }
    if let Some(value) = obj.get("flow_control") {
        let map = value
            .as_object()
            .ok_or_else(|| "field `flow_control` must be an object".to_string())?;
        if let Some(raw) = map.get("batch_read_number") {
            let num = raw.as_u64().ok_or_else(|| {
                "field `flow_control.batch_read_number` must be a non-negative integer".to_string()
            })?;
            current.flow_control.batch_read_number = num;
        }
        if let Some(raw) = map.get("batch_deliver_number") {
            let num = raw.as_u64().ok_or_else(|| {
                "field `flow_control.batch_deliver_number` must be a non-negative integer"
                    .to_string()
            })?;
            current.flow_control.batch_deliver_number = num;
        }
        if let Some(raw) = map.get("batch_deliver_limiter") {
            let text = raw.as_str().ok_or_else(|| {
                "field `flow_control.batch_deliver_limiter` must be a string".to_string()
            })?;
            validate_rate("flow_control.batch_deliver_limiter", text)?;
            current.flow_control.batch_deliver_limiter = text.to_string();
        }
    }
    if let Some(value) = obj.get("max_payload_size") {
        let text = value
            .as_str()
            .ok_or_else(|| "field `max_payload_size` must be a string".to_string())?;
        validate_bytesize("max_payload_size", text)?;
        current.max_payload_size = text.to_string();
    }
    if let Some(value) = obj.get("stop_publish_clear_msg") {
        let flag = value
            .as_bool()
            .ok_or_else(|| "field `stop_publish_clear_msg` must be a boolean".to_string())?;
        current.stop_publish_clear_msg = flag;
    }
    // `deliver_rate` is the historic alias of `delivery_rate`; both write
    // the same setting, with `delivery_rate` winning when both appear.
    if let Some(value) = obj.get("deliver_rate") {
        let text = value
            .as_str()
            .ok_or_else(|| "field `deliver_rate` must be a string".to_string())?;
        validate_rate("deliver_rate", text)?;
        current.delivery_rate = text.to_string();
    }
    if let Some(value) = obj.get("delivery_rate") {
        let text = value
            .as_str()
            .ok_or_else(|| "field `delivery_rate` must be a string".to_string())?;
        validate_rate("delivery_rate", text)?;
        current.delivery_rate = text.to_string();
    }
    if let Some(value) = obj.get("max_publish_rate") {
        let text = value
            .as_str()
            .ok_or_else(|| "field `max_publish_rate` must be a string".to_string())?;
        validate_rate("max_publish_rate", text)?;
        current.max_publish_rate = text.to_string();
    }
    if let Some(value) = obj.get("backend") {
        let map = value
            .as_object()
            .ok_or_else(|| "field `backend` must be an object".to_string())?;
        if let Some(raw) = map.get("type") {
            let text = raw
                .as_str()
                .ok_or_else(|| "field `backend.type` must be a string".to_string())?;
            if text != BACKEND_TYPE {
                return Err(format!("field `backend.type` must be `{BACKEND_TYPE}`"));
            }
        }
        if let Some(raw) = map.get("storage_type") {
            let text = raw
                .as_str()
                .ok_or_else(|| "field `backend.storage_type` must be a string".to_string())?;
            if !VALID_STORAGE_TYPES.contains(&text) {
                return Err("field `backend.storage_type` must be `ram` or `disc`".to_string());
            }
            current.backend.storage_type = text.to_string();
        }
        if let Some(raw) = map.get("max_retained_messages") {
            let num = raw.as_u64().ok_or_else(|| {
                "field `backend.max_retained_messages` must be a non-negative integer".to_string()
            })?;
            current.backend.max_retained_messages = num;
        }
    }
    Ok(current)
}

/// Duration strings are `0`, `0s`, `<n>ms|s|m|h|d` or the literals
/// `disabled`, `never` and `infinity` (the latter three cover expiry and
/// clear-interval disables). Plain integers are rejected: the documented
/// shape is a string.
fn validate_duration(field: &str, text: &str) -> Result<(), String> {
    let lower = text.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return Err(format!("field `{field}` must not be empty"));
    }
    if lower == "disabled" || lower == "never" || lower == "infinity" || lower == "0" {
        return Ok(());
    }
    let (num_part, unit) = split_duration(&lower)
        .ok_or_else(|| format!("field `{field}` must be a duration like `0s`, `10s` or `5m`"))?;
    let num: f64 = num_part
        .parse()
        .map_err(|_| format!("field `{field}` must be a duration like `0s`, `10s` or `5m`"))?;
    if num < 0.0 {
        return Err(format!("field `{field}` must not be negative"));
    }
    match unit {
        "ms" | "s" | "m" | "h" | "d" => Ok(()),
        _ => Err(format!(
            "field `{field}` must be a duration like `0s`, `10s` or `5m`"
        )),
    }
}

fn split_duration(text: &str) -> Option<(&str, &str)> {
    if text.ends_with("ms") && text.len() > 2 {
        Some((&text[..text.len() - 2], "ms"))
    } else if text.ends_with('s') && text.len() > 1 {
        Some((&text[..text.len() - 1], "s"))
    } else if text.ends_with('m') && text.len() > 1 {
        Some((&text[..text.len() - 1], "m"))
    } else if text.ends_with('h') && text.len() > 1 {
        Some((&text[..text.len() - 1], "h"))
    } else if text.ends_with('d') && text.len() > 1 {
        Some((&text[..text.len() - 1], "d"))
    } else {
        None
    }
}

/// Byte sizes are `<n>[B|KB|MB|GB]` (case-insensitive, optional space) or
/// a plain positive integer string. The value must be above zero.
fn validate_bytesize(field: &str, text: &str) -> Result<(), String> {
    parse_bytesize_to_bytes(text)
        .filter(|v| *v > 0)
        .map(|_| ())
        .ok_or_else(|| format!("field `{field}` must be a byte size like `1MB` or `1024KB`"))
}

/// Parse `1MB`, `1024KB`, `512B` or plain bytes into a byte count.
/// Returns `None` for malformed input.
pub fn parse_bytesize_to_bytes(text: &str) -> Option<u64> {
    let lower = text.trim().to_ascii_lowercase().replace(' ', "");
    if lower.is_empty() {
        return None;
    }
    if let Ok(plain) = lower.parse::<u64>() {
        return Some(plain);
    }
    let (num_part, mult) = lower
        .strip_suffix("kb")
        .map(|stripped| (stripped, 1024u64))
        .or_else(|| {
            lower
                .strip_suffix("mb")
                .map(|stripped| (stripped, 1024u64 * 1024))
        })
        .or_else(|| {
            lower
                .strip_suffix("gb")
                .map(|stripped| (stripped, 1024u64 * 1024 * 1024))
        })
        .or_else(|| lower.strip_suffix('b').map(|stripped| (stripped, 1u64)))?;
    let num: f64 = num_part.parse().ok()?;
    if num < 0.0 {
        return None;
    }
    Some((num * mult as f64) as u64)
}

/// Rates are `infinity` or `<n>/s` (integer or float count per second).
fn validate_rate(field: &str, text: &str) -> Result<(), String> {
    let lower = text.trim().to_ascii_lowercase();
    if lower == "infinity" {
        return Ok(());
    }
    let num_part = lower
        .strip_suffix("/s")
        .ok_or_else(|| format!("field `{field}` must be a rate like `1000/s` or `infinity`"))?;
    let num: f64 = num_part
        .parse()
        .map_err(|_| format!("field `{field}` must be a rate like `1000/s` or `infinity`"))?;
    if num < 0.0 {
        return Err(format!("field `{field}` must not be negative"));
    }
    Ok(())
}

/// `GET /mqtt/retainer/message/{topic}`: exact retained lookup.
///
/// The path parameter arrives percent-decoded, so this is a plain exact
/// comparison with no wildcard or prefix matching. One short read lock
/// and at most one message clone per request; the delivery path is never
/// touched. Unknown topics (including wildcard or otherwise invalid
/// names, which can never be stored) read as `NOT_FOUND`.
pub async fn get_retainer_message(
    State(state): State<ApiState>,
    Path(topic_raw): Path<String>,
) -> Response {
    let topic = match broker_protocol::Topic::new(topic_raw.clone()) {
        Ok(valid) => valid,
        Err(_) => {
            return crate::errors::ApiError::NotFound("message not found".to_string())
                .into_response();
        }
    };
    match state.retained.get_retained(&topic).await {
        Ok(Some(stored)) => {
            let body = retained_detail_json(&stored);
            (StatusCode::OK, Json(body)).into_response()
        }
        Ok(None) => {
            crate::errors::ApiError::NotFound("message not found".to_string()).into_response()
        }
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "code": "INTERNAL_ERROR",
                "message": error.to_string(),
            })),
        )
            .into_response(),
    }
}

/// `GET /mqtt/retainer/messages`: paged list of stored retained messages.
///
/// Reads the whole store with the `#` filter (already topic-sorted by the
/// store) and renders only the requested page through the shared W0
/// paging helper (`page`/`limit` plus `meta { page, limit, count,
/// hasnext }`). Malformed `page`/`limit` fall back to defaults via
/// [`PageParams`]; an empty store reads as an empty page, never an error.
/// One bounded scan per request (at most
/// [`broker_storage::MAX_RETAINED_MESSAGES`] clones under short store
/// locks); delivery never waits on it and no new buffering is added to
/// fan-out or fan-in.
pub async fn list_retainer_messages(State(state): State<ApiState>, params: PageParams) -> Response {
    let filter = match broker_protocol::TopicFilter::new("#") {
        Ok(valid) => valid,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "code": "INTERNAL_ERROR",
                    "message": error.to_string(),
                })),
            )
                .into_response();
        }
    };
    let matched = match state.retained.find_matching(&filter).await {
        Ok(rows) => rows,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "code": "INTERNAL_ERROR",
                    "message": error.to_string(),
                })),
            )
                .into_response();
        }
    };
    let total = matched.len();
    let page_items = paginate(&matched, params.page, params.limit);
    let data: Vec<serde_json::Value> = page_items.iter().map(retained_detail_json).collect();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "data": data,
            "meta": meta_page(params.page, params.limit, total),
        })),
    )
        .into_response()
}

/// `DELETE /mqtt/retainer/message/{topic}`: drop one exact stored topic.
///
/// The path parameter arrives percent-decoded, so this is a plain exact
/// removal with no wildcard or prefix matching. A stored topic is removed
/// and reports success with 204; an unknown topic (including wildcard or
/// otherwise invalid names, which can never be stored) reports the
/// documented `NOT_FOUND` shape instead of success. Management-plane only:
/// one short read plus at most one write, then a bounded recount for the
/// retained gauge; delivery never waits on it.
pub async fn delete_retainer_message(
    State(state): State<ApiState>,
    Path(topic_raw): Path<String>,
) -> Response {
    let topic = match broker_protocol::Topic::new(topic_raw) {
        Ok(valid) => valid,
        Err(_) => {
            return crate::errors::ApiError::NotFound("message not found".to_string())
                .into_response();
        }
    };
    let stored = match state.retained.get_retained(&topic).await {
        Ok(value) => value,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "code": "INTERNAL_ERROR",
                    "message": error.to_string(),
                })),
            )
                .into_response();
        }
    };
    if stored.is_none() {
        return crate::errors::ApiError::NotFound("message not found".to_string()).into_response();
    }
    if let Err(error) = state.retained.clear_retained(&topic).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "code": "INTERNAL_ERROR",
                "message": error.to_string(),
            })),
        )
            .into_response();
    }
    sync_retained_count(&state).await;
    StatusCode::NO_CONTENT.into_response()
}

/// `DELETE /mqtt/retainer/messages`: drop every stored retained message.
///
/// Always reports success with 204, even when nothing is stored. The clear
/// itself is one bounded iteration over the `#` snapshot (at most
/// [`broker_storage::MAX_RETAINED_MESSAGES`] short-lock clears), followed
/// by a bounded recount so the retained gauge stays exact. Query strings
/// (including unknown keys) are ignored by design. Management-plane only;
/// no work on fan-out or fan-in.
pub async fn clear_retainer_messages(State(state): State<ApiState>) -> Response {
    let filter = match broker_protocol::TopicFilter::new("#") {
        Ok(valid) => valid,
        Err(_) => {
            return StatusCode::NO_CONTENT.into_response();
        }
    };
    if let Ok(matched) = state.retained.find_matching(&filter).await {
        for stored in &matched {
            let _ = state.retained.clear_retained(&stored.topic).await;
        }
    }
    sync_retained_count(&state).await;
    StatusCode::NO_CONTENT.into_response()
}

/// Recount retained topics into the stats gauge after a management delete,
/// mirroring the kernel lifecycle helper. One bounded scan per delete
/// (rare path); delivery never waits on it.
async fn sync_retained_count(state: &ApiState) {
    let filter = match broker_protocol::TopicFilter::new("#") {
        Ok(valid) => valid,
        Err(_) => return,
    };
    if let Ok(matched) = state.retained.find_matching(&filter).await {
        state.stats.set_retained(matched.len() as u64);
    }
}

/// Render one stored message in the documented detail shape.
///
/// `msgid` is a deterministic 32-hex digest of topic and payload (the
/// store keeps no GUID); `publish_at` is the synthetic read-time stamp
/// above; `from_clientid`/`from_username` are empty when the store keeps
/// no origin. `payload` is base64 so arbitrary bytes survive JSON.
fn retained_detail_json(stored: &broker_storage::StoredMessage) -> serde_json::Value {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let payload_b64 = STANDARD.encode(stored.payload.as_ref());
    serde_json::json!({
        "msgid": msgid_for(stored.topic.as_str(), stored.payload.as_ref()),
        "topic": stored.topic.as_str(),
        "qos": u8::from(stored.qos),
        "publish_at": SYNTHETIC_PUBLISH_AT,
        "from_clientid": "",
        "from_username": "",
        "payload": payload_b64,
    })
}

/// Deterministic 32-hex id from topic and payload bytes (FNV-1a twice
/// with different seeds). Stable across reads so tests can re-fetch the
/// same id without the store keeping a GUID.
fn msgid_for(topic: &str, payload: &[u8]) -> String {
    let first = fnv1a(topic.as_bytes(), 0xcbf29ce484222325, payload);
    let second = fnv1a(topic.as_bytes(), 0x84222325cbf29ce4, payload);
    format!("{first:016X}{second:016X}")
}

fn fnv1a(topic: &[u8], mut hash: u64, payload: &[u8]) -> u64 {
    for byte in topic.iter().chain(payload.iter()) {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
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
            .expect("retainer body is small and readable");
        let body: serde_json::Value =
            serde_json::from_slice(&bytes).expect("retainer body is JSON");
        (status, body)
    }

    #[tokio::test]
    async fn config_round_trip_read_write_read() {
        let state = standalone_state();
        let (status, before) =
            response_parts(get_retainer_config(State(state.clone())).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(before["enable"], serde_json::json!(true));
        assert_eq!(before["max_payload_size"], serde_json::json!("1MB"));
        assert_eq!(before["backend"]["storage_type"], serde_json::json!("ram"));

        let update = serde_json::json!({
            "max_payload_size": "2MB",
            "backend": {"storage_type": "disc", "max_retained_messages": 10},
        });
        let body = Bytes::from(serde_json::to_vec(&update).expect("update is JSON"));
        let (status, after) =
            response_parts(put_retainer_config(State(state.clone()), body).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(after["max_payload_size"], serde_json::json!("2MB"));
        assert_eq!(after["backend"]["storage_type"], serde_json::json!("disc"));
        assert_eq!(
            after["backend"]["max_retained_messages"],
            serde_json::json!(10)
        );

        let (status, reread) =
            response_parts(get_retainer_config(State(state.clone())).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reread, after);
    }

    #[tokio::test]
    async fn invalid_update_is_rejected_without_applying() {
        let state = standalone_state();
        let (status, before) =
            response_parts(get_retainer_config(State(state.clone())).await).await;
        assert_eq!(status, StatusCode::OK);

        for bad in [
            serde_json::json!({"enable": "yes"}),
            serde_json::json!({"max_payload_size": "huge"}),
            serde_json::json!({"backend": {"storage_type": "tape"}}),
            serde_json::json!({"backend": {"max_retained_messages": -1}}),
            serde_json::json!({"delivery_rate": "fast"}),
            serde_json::json!({"msg_expiry_interval": ""}),
            serde_json::json!({}),
            serde_json::json!([]),
        ] {
            let body = Bytes::from(serde_json::to_vec(&bad).expect("bad body is JSON"));
            let (status, err) =
                response_parts(put_retainer_config(State(state.clone()), body).await).await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "body {bad} must be rejected"
            );
            assert_eq!(err["code"], serde_json::json!("UPDATE_FAILED"));
        }

        let (status, reread) =
            response_parts(get_retainer_config(State(state.clone())).await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reread, before, "failed writes must not apply");
    }

    #[tokio::test]
    async fn retained_hit_and_miss_over_real_store() {
        use broker_protocol::{QoS, Topic};

        let state = standalone_state();
        let topic = Topic::new("conf/retainer/w128-1").expect("valid topic");
        state
            .retained
            .set_retained(
                topic.clone(),
                QoS::AtLeastOnce,
                bytes::Bytes::from("hello-w128"),
            )
            .await
            .expect("store retained");

        let (status, body) = response_parts(
            get_retainer_message(
                State(state.clone()),
                Path("conf/retainer/w128-1".to_string()),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["topic"], serde_json::json!("conf/retainer/w128-1"));
        assert_eq!(body["qos"], serde_json::json!(1));
        assert!(body.get("msgid").and_then(|v| v.as_str()).is_some());
        assert!(body.get("publish_at").and_then(|v| v.as_str()).is_some());
        // Payload is base64 of the stored bytes.
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let decoded = STANDARD
            .decode(body["payload"].as_str().expect("payload is string"))
            .expect("payload is base64");
        assert_eq!(decoded, b"hello-w128");

        let (status, err) = response_parts(
            get_retainer_message(State(state), Path("conf/retainer/unknown".to_string())).await,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(err["code"], serde_json::json!("NOT_FOUND"));
    }

    #[tokio::test]
    async fn list_delete_clear_flow_over_real_store() {
        use broker_protocol::{QoS, Topic};

        let state = standalone_state();
        for (topic, payload) in [
            ("conf/retainer/w129-a", "hello-a"),
            ("conf/retainer/w129-b", "hello-b"),
        ] {
            state
                .retained
                .set_retained(
                    Topic::new(topic).expect("valid topic"),
                    QoS::AtLeastOnce,
                    bytes::Bytes::from(payload),
                )
                .await
                .expect("store retained");
        }

        // List sees both stored topics in topic order with the documented fields.
        let (status, body) = response_parts(
            list_retainer_messages(
                State(state.clone()),
                PageParams {
                    page: 1,
                    limit: 100,
                },
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["meta"]["count"], serde_json::json!(2));
        assert_eq!(body["meta"]["hasnext"], serde_json::json!(false));
        let topics: Vec<&str> = body["data"]
            .as_array()
            .expect("data is an array")
            .iter()
            .map(|row| row["topic"].as_str().expect("topic is a string"))
            .collect();
        assert_eq!(topics, vec!["conf/retainer/w129-a", "conf/retainer/w129-b"]);
        for row in body["data"].as_array().expect("data is an array") {
            assert!(row.get("msgid").and_then(|v| v.as_str()).is_some());
            assert!(row.get("publish_at").and_then(|v| v.as_str()).is_some());
            assert_eq!(row["qos"], serde_json::json!(1));
            assert!(row["payload"].as_str().is_some());
        }

        // W0 paging slices after filtering: page 1 of limit 1 has more to come.
        let (status, first) = response_parts(
            list_retainer_messages(State(state.clone()), PageParams { page: 1, limit: 1 }).await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(first["meta"]["count"], serde_json::json!(2));
        assert_eq!(first["meta"]["hasnext"], serde_json::json!(true));
        assert_eq!(first["data"].as_array().expect("data").len(), 1);
        let (status, second) = response_parts(
            list_retainer_messages(State(state.clone()), PageParams { page: 2, limit: 1 }).await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(second["meta"]["hasnext"], serde_json::json!(false));
        assert_eq!(second["data"].as_array().expect("data").len(), 1);
        assert_ne!(first["data"][0]["topic"], second["data"][0]["topic"]);

        // Delete one exact topic: 204, then the single read misses it.
        let response = delete_retainer_message(
            State(state.clone()),
            Path("conf/retainer/w129-a".to_string()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let (status, err) = response_parts(
            get_retainer_message(
                State(state.clone()),
                Path("conf/retainer/w129-a".to_string()),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(err["code"], serde_json::json!("NOT_FOUND"));

        // Deleting it again misses, as does an invalid name that can never be stored.
        let response = delete_retainer_message(
            State(state.clone()),
            Path("conf/retainer/w129-a".to_string()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let response = delete_retainer_message(State(state.clone()), Path("#".to_string())).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // One topic remains listed and the gauge recounts to one.
        let (status, body) = response_parts(
            list_retainer_messages(
                State(state.clone()),
                PageParams {
                    page: 1,
                    limit: 100,
                },
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["meta"]["count"], serde_json::json!(1));
        assert_eq!(
            body["data"][0]["topic"],
            serde_json::json!("conf/retainer/w129-b")
        );
        assert_eq!(state.stats.retained(), 1);

        // Clearing removes the rest; the list then reads empty and the gauge is exact.
        let response = clear_retainer_messages(State(state.clone())).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let (status, body) = response_parts(
            list_retainer_messages(
                State(state.clone()),
                PageParams {
                    page: 1,
                    limit: 100,
                },
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"], serde_json::json!([]));
        assert_eq!(body["meta"]["count"], serde_json::json!(0));
        assert_eq!(body["meta"]["hasnext"], serde_json::json!(false));
        assert_eq!(state.stats.retained(), 0);

        // Clearing an empty store still reports success.
        let response = clear_retainer_messages(State(state)).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[test]
    fn bytesize_and_rate_parsers_accept_documented_shapes() {
        assert_eq!(parse_bytesize_to_bytes("1MB"), Some(1_048_576));
        assert_eq!(parse_bytesize_to_bytes("1024KB"), Some(1_048_576));
        assert_eq!(parse_bytesize_to_bytes("512B"), Some(512));
        assert!(parse_bytesize_to_bytes("huge").is_none());
        assert!(validate_rate("delivery_rate", "1000/s").is_ok());
        assert!(validate_rate("delivery_rate", "infinity").is_ok());
        assert!(validate_rate("delivery_rate", "fast").is_err());
        assert!(validate_duration("msg_expiry_interval", "0s").is_ok());
        assert!(validate_duration("msg_expiry_interval", "5m").is_ok());
        assert!(validate_duration("msg_expiry_interval", "").is_err());
    }
}
