//! Runtime configuration surface (M1-05): validate-whole, diff-first reload
//! with rollback, version history with restore, `explain`, and secret
//! redaction.
//!
//! Reload semantics: the candidate snapshot is validated whole first (every
//! offending setting named, running snapshot untouched). A diff
//! (setting, old value, new value) is computed against the running
//! snapshot. Each root is then applied to its live owner in order
//! (`mqtt_users` to the shared [`broker_auth::MemoryAuth`], `rules` to the
//! shared [`broker_rules::RuleEngine`], `admin_users` to the shared admin
//! store, `connectors` to the live connector directory for offline kinds
//! plus persistence for the rest). Any backend rejection rolls every
//! already-applied owner back to the previous snapshot and answers 500
//! with the registry untouched. Only after every owner accepts does the
//! registry commit whole (validate again, swap, version, persist
//! `state.toml` plus `config-history.json` in the kernel data directory).
//! A commit/save failure at that point rolls the live owners back too.
//!
//! The broker never writes into the operator config directory
//! (`indra.toml`, `conf.d/`): runtime state lives in the data directory
//! only. Nothing here takes a lock on the publish or deliver path; owners
//! hold read-optimised snapshots and this module takes only short
//! management-plane locks.
//!
//! Secrets (`file:` / `env:` references) are stored as references and
//! resolved at use time. Every response below renders them as
//! `<redacted:file:...>` / `<redacted:env:...>` markers naming the
//! reference, never the value.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use broker_config::{secrets, ConfigDiff, ConfigRegistry, FullSnapshot};
use serde::{Deserialize, Serialize};

use super::ApiState;

/// A candidate full snapshot plus who applies it and why.
#[derive(Debug, Deserialize)]
pub struct SnapshotBody {
    /// The desired full configuration (all roots).
    pub snapshot: FullSnapshot,
}

/// Reload body: candidate snapshot plus audit metadata.
#[derive(Debug, Deserialize)]
pub struct ReloadBody {
    /// The desired full configuration (all roots).
    pub snapshot: FullSnapshot,
    /// Who applies the change (defaults to `api`).
    #[serde(default)]
    pub actor: Option<String>,
    /// Short human summary stored with the version.
    #[serde(default)]
    pub summary: Option<String>,
}

/// Restore body: only audit metadata (the snapshot comes from history).
#[derive(Debug, Deserialize, Default)]
pub struct RestoreBody {
    /// Who applies the change (defaults to `api`).
    #[serde(default)]
    pub actor: Option<String>,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

fn bad_request(message: impl Into<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorBody {
            error: message.into(),
        }),
    )
        .into_response()
}

fn not_found(message: impl Into<String>) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorBody {
            error: message.into(),
        }),
    )
        .into_response()
}

fn apply_failed(message: impl Into<String>) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorBody {
            error: message.into(),
        }),
    )
        .into_response()
}

/// Validate a whole candidate snapshot without changing any state.
///
/// 200 `{"ok":true}` when the change set would apply entirely; 400 naming
/// every offending setting otherwise, with the running snapshot untouched.
pub async fn validate_config(
    State(state): State<ApiState>,
    Json(body): Json<SnapshotBody>,
) -> Response {
    match state.config.validate_whole_snapshot(&body.snapshot) {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response(),
        Err(err) => bad_request(err.to_string()),
    }
}

/// Show the diff a reload would apply, without applying it.
///
/// The candidate is validated whole first (400 on failure); the 200 shape
/// is `{"diff":[{"setting","old_value","new_value"}]}`, secret values
/// redacted on both sides.
pub async fn diff_config(
    State(state): State<ApiState>,
    Json(body): Json<SnapshotBody>,
) -> Response {
    if let Err(err) = state.config.validate_whole_snapshot(&body.snapshot) {
        return bad_request(err.to_string());
    }
    let previous = state.config.snapshot();
    let diff = state.config.diff(&previous, &body.snapshot);
    (StatusCode::OK, Json(serde_json::json!({"diff": diff}))).into_response()
}

/// Undo state for the live connector directory during one reload.
struct ConnectorLiveUndo {
    /// Sinks unregistered by this reload, held alive for rollback.
    removed: Vec<(String, Arc<dyn broker_connectors::Sink>)>,
    /// Console sinks registered by this reload, removed on rollback.
    added: Vec<String>,
}

/// Reload result: the recorded version plus connector kinds left
/// persist-only.
#[derive(Debug, Serialize)]
pub struct ReloadResult {
    version: u64,
    diff: Vec<ConfigDiff>,
    /// Added connector ids whose kind needs a networked transport: the
    /// snapshot is versioned and persisted (replayed by the boot probe),
    /// but no live sink was registered by this reload.
    pending_live: Vec<String>,
}

/// Ensure history is truncated to at most `max_len` versions.
/// Returns the actual length after truncation.
fn ensure_history_truncated(registry: &ConfigRegistry, max_len: usize) -> usize {
    registry.truncate_history_and_save(max_len).ok();
    // Verify truncation worked; if not, force it by calling truncate_to directly.
    let len = registry.history_list().len();
    if len > max_len {
        registry.history_truncate_to(max_len);
        registry.save_history_file().ok();
    }
    registry.history_list().len()
}

/// Apply one candidate snapshot end to end (reload path).
async fn apply_candidate(
    state: &ApiState,
    candidate: &FullSnapshot,
    actor: &str,
    summary: &str,
) -> Result<ReloadResult, Box<Response>> {
    // 1. Validate whole before anything applies; the running snapshot is
    // untouched on failure and every offending setting is named.
    if let Err(err) = state.config.validate_whole_snapshot(candidate) {
        return Err(Box::new(bad_request(err.to_string())));
    }
    let previous = state.config.snapshot();
    // An empty administrator list restores the default account and its
    // default password. Refuse a candidate that removes all the
    // administrators of an installation. Thus a reload or a restore
    // cannot open the default login again.
    if candidate.admin_users.users.is_empty() && !previous.admin_users.users.is_empty() {
        return Err(Box::new(bad_request(
            "admin_users.users must keep at least one administrator: an empty list would restore the default account (field `admin_users.users`)",
        )));
    }
    let diff = state.config.diff(&previous, candidate);

    // Capture history length after validation, before any live owner apply.
    let history_len_before = state.config.history_list().len();

    // 2. Apply live owners in order. None of these touches the registry,
    // so the persisted snapshot stays untouched until step 3.
    if let Err(err) = state.auth.apply_snapshot_conf(&candidate.mqtt_users) {
        let _ = ensure_history_truncated(&state.config, history_len_before);
        return Err(Box::new(apply_failed(format!(
            "mqtt_users backend refused: {err}"
        ))));
    }
    if let Err(err) = state.engine.apply_snapshot_conf(&candidate.rules) {
        let _ = state.auth.apply_snapshot_conf(&previous.mqtt_users);
        let _ = ensure_history_truncated(&state.config, history_len_before);
        return Err(Box::new(apply_failed(format!(
            "rules backend refused: {err}"
        ))));
    }
    if let Err(err) = state
        .admin_users
        .apply_snapshot_conf(&candidate.admin_users)
    {
        let _ = state.auth.apply_snapshot_conf(&previous.mqtt_users);
        let _ = state.engine.apply_snapshot_conf(&previous.rules);
        let _ = ensure_history_truncated(&state.config, history_len_before);
        return Err(Box::new(apply_failed(format!(
            "admin_users backend refused: {err}"
        ))));
    }
    let (connector_undo, pending_live) =
        apply_connectors_live(&state.engine, &previous, candidate).await;

    // 3. Single whole commit: validate again, swap, version, persist.
    // A failure rolls every live owner back to the previous snapshot.
    match state.config.commit_whole(candidate.clone(), actor, summary) {
        Ok(version) => {
            // Keep the observable v5 connector list in step with the
            // committed snapshot (reference form, redacted at read time);
            // removals drop, additions/updates upsert.
            super::v5::rules::reconcile_connectors_store(
                &previous.connectors,
                &candidate.connectors,
            )
            .await;
            Ok(ReloadResult {
                version,
                diff,
                pending_live,
            })
        }
        Err(err) => {
            let _ = state.auth.apply_snapshot_conf(&previous.mqtt_users);
            let _ = state.engine.apply_snapshot_conf(&previous.rules);
            let _ = state.admin_users.apply_snapshot_conf(&previous.admin_users);
            undo_connectors_live(&state.engine, &connector_undo);
            let _ = ensure_history_truncated(&state.config, history_len_before);
            Err(Box::new(apply_failed(format!(
                "config commit failed: {err}"
            ))))
        }
    }
}

/// Restore one recorded version end to end through the same validate-whole
/// path as a reload (validate, live apply, version, persist). The registry
/// commit goes through [`broker_config::ConfigRegistry::history_restore`]
/// so the restore path stays on the versioned history API.
async fn apply_restore(
    state: &ApiState,
    id: u64,
    actor: &str,
) -> Result<ReloadResult, Box<Response>> {
    let version = match state.config.history_get(id) {
        Some(version) => version,
        None => {
            return Err(Box::new(not_found(format!(
                "config version {id} does not exist"
            ))))
        }
    };
    let candidate = version.snapshot.clone();
    if let Err(err) = state.config.validate_whole_snapshot(&candidate) {
        return Err(Box::new(bad_request(err.to_string())));
    }
    let previous = state.config.snapshot();
    let diff = state.config.diff(&previous, &candidate);
    if let Err(err) = state.auth.apply_snapshot_conf(&candidate.mqtt_users) {
        return Err(Box::new(apply_failed(format!(
            "mqtt_users backend refused: {err}"
        ))));
    }
    if let Err(err) = state.engine.apply_snapshot_conf(&candidate.rules) {
        let _ = state.auth.apply_snapshot_conf(&previous.mqtt_users);
        return Err(Box::new(apply_failed(format!(
            "rules backend refused: {err}"
        ))));
    }
    if let Err(err) = state
        .admin_users
        .apply_snapshot_conf(&candidate.admin_users)
    {
        let _ = state.auth.apply_snapshot_conf(&previous.mqtt_users);
        let _ = state.engine.apply_snapshot_conf(&previous.rules);
        return Err(Box::new(apply_failed(format!(
            "admin_users backend refused: {err}"
        ))));
    }
    let (connector_undo, pending_live) =
        apply_connectors_live(&state.engine, &previous, &candidate).await;
    match state.config.history_restore(id, actor) {
        Ok(version) => {
            super::v5::rules::reconcile_connectors_store(
                &previous.connectors,
                &candidate.connectors,
            )
            .await;
            Ok(ReloadResult {
                version,
                diff,
                pending_live,
            })
        }
        Err(err) => {
            let _ = state.auth.apply_snapshot_conf(&previous.mqtt_users);
            let _ = state.engine.apply_snapshot_conf(&previous.rules);
            let _ = state.admin_users.apply_snapshot_conf(&previous.admin_users);
            undo_connectors_live(&state.engine, &connector_undo);
            Err(Box::new(apply_failed(format!(
                "config commit failed: {err}"
            ))))
        }
    }
}

/// Connector params for one snapshot entry: the stored JSON document when
/// it parses as an object, otherwise fail closed to `None` (the id stays
/// persist-only and `pending_live` names it) instead of substituting an
/// empty object that would lose a bare `file:`/`env:` reference and let
/// the live sink dial an invented default. An empty config still yields
/// `{}` (offline kinds need no params); a bare secret reference resolves
/// at use time (JSON object used verbatim, any other UTF-8 value exposed
/// as `url`). Secret references in string leaves resolve at use time; an
/// unresolvable secret fails closed to `None`.
fn resolve_connector_params(entry: &broker_config::ConnectorEntry) -> Option<serde_json::Value> {
    let trimmed = entry.config.trim();
    if trimmed.is_empty() {
        return Some(serde_json::json!({"id": entry.id}));
    }
    // Bare reference as the whole config (never parsed as JSON, never
    // replaced by `{}`): resolve at use time, fail closed when missing.
    if secrets::is_secret_ref(trimmed) {
        let resolved = secrets::resolve_secret(trimmed).ok()?;
        if let Ok(serde_json::Value::Object(mut map)) =
            serde_json::from_slice::<serde_json::Value>(&resolved)
        {
            map.entry("id")
                .or_insert(serde_json::Value::String(entry.id.clone()));
            let mut params = serde_json::Value::Object(map);
            if resolve_params_secrets_in_place(&mut params).is_err() {
                return None;
            }
            return Some(params);
        }
        // Resolved to a plain value (e.g. a webhook URL held as one
        // secret): expose it as `url` so the live sink dials the real
        // target instead of an invented default.
        let text = String::from_utf8(resolved).ok()?;
        if text.trim().is_empty() {
            return None;
        }
        return Some(serde_json::json!({"id": entry.id, "url": text}));
    }
    let mut params = serde_json::from_str::<serde_json::Value>(&entry.config)
        .ok()
        .filter(|value| value.is_object())?;
    if resolve_params_secrets_in_place(&mut params).is_err() {
        return None;
    }
    if let Some(obj) = params.as_object_mut() {
        obj.entry("id")
            .or_insert(serde_json::Value::String(entry.id.clone()));
    }
    Some(params)
}

fn resolve_params_secrets_in_place(
    value: &mut serde_json::Value,
) -> Result<(), broker_config::ConfigError> {
    match value {
        serde_json::Value::String(text) => {
            let trimmed = text.trim().to_string();
            if secrets::is_secret_ref(&trimmed) {
                let resolved = secrets::resolve_secret(&trimmed)?;
                match String::from_utf8(resolved) {
                    Ok(decoded) => *text = decoded,
                    Err(_) => *text = String::new(),
                }
            }
            Ok(())
        }
        serde_json::Value::Array(entries) => {
            for entry in entries {
                resolve_params_secrets_in_place(entry)?;
            }
            Ok(())
        }
        serde_json::Value::Object(map) => {
            for (_, entry) in map.iter_mut() {
                resolve_params_secrets_in_place(entry)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Apply the `connectors` root to the live directory.
///
/// Removed ids are unregistered (their sinks are held in `undo` for
/// rollback). Added ids go through the same probe-then-register path as
/// boot (`probe_connector_reachable` + `try_register_live_sink`): reachable
/// targets get a live sink immediately; unreachable ones stay
/// persist-only (versioned, replayed by the boot probe) and are reported
/// in `pending_live`. Secret references in the stored params resolve at
/// use time; an unresolvable secret fails closed into `pending_live`.
async fn apply_connectors_live(
    engine: &broker_rules::RuleEngine,
    previous: &Arc<FullSnapshot>,
    candidate: &FullSnapshot,
) -> (ConnectorLiveUndo, Vec<String>) {
    let mut undo = ConnectorLiveUndo {
        removed: Vec::new(),
        added: Vec::new(),
    };
    let mut pending_live = Vec::new();
    let previous_by_id: HashMap<&str, &broker_config::ConnectorEntry> = previous
        .connectors
        .connectors
        .iter()
        .map(|entry| (entry.id.as_str(), entry))
        .collect();
    let candidate_ids: HashSet<&str> = candidate
        .connectors
        .connectors
        .iter()
        .map(|entry| entry.id.as_str())
        .collect();
    for entry in &candidate.connectors.connectors {
        // Unchanged entries keep their live sink as is.
        if let Some(prev) = previous_by_id.get(entry.id.as_str()) {
            if *prev == entry {
                continue;
            }
            // Modified entry (same id, different type/enable/config):
            // remove the old live registration (plain id plus the
            // type-prefixed alias) so the new config can go live below.
            // Disabled entries stop here (no live sink).
            take_live_sink(engine, &entry.id, &prev.connector_type, &mut undo);
            take_live_sink_alias(engine, &entry.connector_type, &entry.id, &mut undo);
            if !entry.enable {
                continue;
            }
        } else {
            // Added entry: a disabled connector never goes live.
            if !entry.enable {
                continue;
            }
            // A live sink left over from a direct create with the same id
            // is reconciled to the registry below (removed first so the
            // probe registers the registry's config, not the stale one).
            if engine.connectors().get(&entry.id).is_some() {
                take_live_sink(engine, &entry.id, &entry.connector_type, &mut undo);
                take_live_sink_alias(engine, &entry.connector_type, &entry.id, &mut undo);
            }
        }
        let Some(params) = resolve_connector_params(entry) else {
            pending_live.push(entry.id.clone());
            continue;
        };
        if !super::v5::rules::probe_connector_reachable(&params).await {
            pending_live.push(entry.id.clone());
            continue;
        }
        // A disabled Cargo feature fails closed here: the entry stays
        // persist-only and the missing feature is logged naming it.
        if let Err(feature_error) = super::v5::rules::try_register_live_sink(
            engine,
            &entry.connector_type,
            &entry.id,
            &params,
        )
        .await
        {
            tracing::warn!(
                connector = %entry.id,
                kind = %entry.connector_type,
                "{feature_error}"
            );
            pending_live.push(entry.id.clone());
            continue;
        }
        if engine.connectors().get(&entry.id).is_some() {
            undo.added.push(entry.id.clone());
            undo.added
                .push(format!("{}:{}", entry.connector_type, entry.id));
        } else {
            pending_live.push(entry.id.clone());
        }
    }
    for entry in &previous.connectors.connectors {
        if candidate_ids.contains(entry.id.as_str()) {
            continue;
        }
        take_live_sink(engine, &entry.id, &entry.connector_type, &mut undo);
        // The alias may carry the same type (common case) or, when the
        // type changed before removal, the candidate type; both are
        // covered by taking the previous type alias here and letting the
        // added-path cleanup handle any leftover candidate alias.
        if let Some(candidate) = candidate
            .connectors
            .connectors
            .iter()
            .find(|c| c.id == entry.id)
        {
            take_live_sink_alias(engine, &candidate.connector_type, &entry.id, &mut undo);
        }
    }
    pending_live.sort();
    (undo, pending_live)
}

fn take_live_sink(
    engine: &broker_rules::RuleEngine,
    id: &str,
    connector_type: &str,
    undo: &mut ConnectorLiveUndo,
) {
    if let Some(sink) = engine.connectors().get(id) {
        undo.removed.push((id.to_string(), sink));
    }
    engine.connectors().unregister(id);
    let alias = format!("{connector_type}:{id}");
    if alias.as_str() != id {
        if let Some(sink) = engine.connectors().get(&alias) {
            undo.removed.push((alias.clone(), sink));
        }
        engine.connectors().unregister(&alias);
    }
}

fn take_live_sink_alias(
    engine: &broker_rules::RuleEngine,
    connector_type: &str,
    id: &str,
    undo: &mut ConnectorLiveUndo,
) {
    let alias = format!("{connector_type}:{id}");
    if alias.as_str() == id {
        return;
    }
    if let Some(sink) = engine.connectors().get(&alias) {
        undo.removed.push((alias.clone(), sink));
    }
    engine.connectors().unregister(&alias);
}

fn undo_connectors_live(engine: &broker_rules::RuleEngine, undo: &ConnectorLiveUndo) {
    for id in &undo.added {
        engine.connectors().unregister(id);
    }
    for (id, sink) in &undo.removed {
        engine.connectors().register(id.clone(), Arc::clone(sink));
    }
}

/// Reload the broker from a candidate snapshot: validate whole, show the
/// diff, apply every root, version the change, and persist.
///
/// 200 `{"version","diff","pending_live"}`; 400 when whole validation
/// fails (nothing changed, every offender named); 500 when a backend
/// rejects mid-apply (every owner rolled back to the previous snapshot).
pub async fn reload_config(
    State(state): State<ApiState>,
    Json(body): Json<ReloadBody>,
) -> Response {
    let actor = body.actor.as_deref().unwrap_or("api");
    let summary = body.summary.as_deref().unwrap_or("reload via API");
    match apply_candidate(&state, &body.snapshot, actor, summary).await {
        Ok(result) => (StatusCode::OK, Json(result)).into_response(),
        Err(response) => *response,
    }
}

/// List versions newest-first: who, when, what changed (no snapshots).
pub async fn list_history(State(state): State<ApiState>) -> Json<serde_json::Value> {
    let versions = state.config.history_list();
    Json(serde_json::json!({
        "versions": versions.iter().map(|version| serde_json::json!({
            "id": version.id,
            "actor": version.actor,
            "timestamp_secs": version.timestamp_secs,
            "summary": version.summary,
            "changes": version.changes,
        })).collect::<Vec<_>>(),
    }))
}

/// Fetch one version with its (redacted) snapshot.
pub async fn get_history_version(State(state): State<ApiState>, Path(id): Path<u64>) -> Response {
    match state.config.history_get(id) {
        Some(version) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "id": version.id,
                "actor": version.actor,
                "timestamp_secs": version.timestamp_secs,
                "summary": version.summary,
                "changes": version.changes,
                "snapshot": redact_snapshot(&version.snapshot),
            })),
        )
            .into_response(),
        None => not_found(format!("config version {id} does not exist")),
    }
}

/// Restore a recorded version through the same validate-whole path as a
/// reload (validate, diff, apply, version, persist).
pub async fn restore_history_version(
    State(state): State<ApiState>,
    Path(id): Path<u64>,
    Json(body): Json<RestoreBody>,
) -> Response {
    let actor = body.actor.as_deref().unwrap_or("api");
    match apply_restore(&state, id, actor).await {
        Ok(result) => (StatusCode::OK, Json(result)).into_response(),
        Err(response) => *response,
    }
}

/// Explain one setting: its effective value and exactly which layer set it.
///
/// Schema keys (e.g. `session.max_qos0_backlog`) resolve through the
/// startup layers (built-in defaults, `indra.toml`, the `conf.d` fragment
/// by file name, environment variable by name, flag) or report defaults
/// when no layer set them. Registry keys (`mqtt_users.users.<name>`,
/// `rules.rules.<id>`, `connectors.connectors.<id>`,
/// `admin_users.users.<name>`, `mqtt_users.acls`) report the current
/// runtime version. Secret values render as
/// `<redacted:file:...>` / `<redacted:env:...>` markers, never plaintext.
pub async fn explain_config(
    State(state): State<ApiState>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let Some(key) = query.get("key").map(|key| key.trim().to_string()) else {
        return bad_request("missing required query parameter `key`");
    };
    if key.is_empty() {
        return bad_request("missing required query parameter `key`");
    }
    if let Some(value) = explain_registry_key(&state, &key) {
        return (StatusCode::OK, Json(value)).into_response();
    }
    match explain_schema_key(&state, &key) {
        Some(value) => (StatusCode::OK, Json(value)).into_response(),
        None => not_found(format!("unknown setting `{key}`")),
    }
}

/// Latest recorded version id (0 is the boot snapshot).
fn latest_version_id(state: &ApiState) -> u64 {
    state
        .config
        .history_list()
        .first()
        .map(|version| version.id)
        .unwrap_or(0)
}

fn explain_registry_key(state: &ApiState, key: &str) -> Option<serde_json::Value> {
    let snapshot = state.config.snapshot();
    // Per-setting provenance: the newest version whose recorded diff last
    // touched this key; keys untouched since boot report version 0. Never
    // the latest version for every key.
    let version = version_for_registry_key(state, key);
    let layer = broker_config::layers::Layer::Runtime(version);
    let value = registry_value(&snapshot, key)?;
    Some(serde_json::json!({
        "key": key,
        "value": value,
        "layer": layer.describe(),
        "source": layer.describe(),
    }))
}

/// Newest version whose diff touched `key` (0 when untouched since boot).
/// Matches diff settings (`mqtt_users.users[alice]`) against explain keys
/// (`mqtt_users.users.alice`); `mqtt_users.acls` matches exactly.
fn version_for_registry_key(state: &ApiState, key: &str) -> u64 {
    let wanted = registry_key_to_diff_setting(key);
    for version in state.config.history_list() {
        if version
            .changes
            .iter()
            .any(|row| row.setting == wanted || row.setting.starts_with(&format!("{wanted}.")))
        {
            return version.id;
        }
        // A version whose snapshot first contains the key but predates
        // per-row diffs (boot) still owns it.
        if version.id == 0 {
            return 0;
        }
    }
    latest_version_id(state)
}

/// Map an explain key to the diff setting prefix it corresponds to.
fn registry_key_to_diff_setting(key: &str) -> String {
    for prefix in [
        "mqtt_users.users.",
        "rules.rules.",
        "connectors.connectors.",
        "admin_users.users.",
    ] {
        if let Some(name) = key.strip_prefix(prefix) {
            let root = prefix.trim_end_matches('.');
            return format!("{root}[{name}]");
        }
    }
    key.to_string()
}

/// Effective value of one registry key (redacted where secrets apply).
///
/// Values render as JSON of the stored entry (quotas, filters, kinds and
/// enable flags included); every `file:`/`env:` reference renders as its
/// `<redacted:...>` marker, never the value.
fn registry_value(snapshot: &Arc<FullSnapshot>, key: &str) -> Option<String> {
    if let Some(name) = key.strip_prefix("mqtt_users.users.") {
        let user = snapshot
            .mqtt_users
            .users
            .iter()
            .find(|entry| entry.username == name)?;
        let mut value = serde_json::to_value(user).ok()?;
        redact_json_in_place(&mut value);
        return serde_json::to_string(&value).ok();
    }
    if key == "mqtt_users.acls" {
        let mut value = serde_json::to_value(&snapshot.mqtt_users.acls).ok()?;
        redact_json_in_place(&mut value);
        return serde_json::to_string(&value).ok();
    }
    if let Some(id) = key.strip_prefix("rules.rules.") {
        let rule = snapshot.rules.rules.iter().find(|entry| entry.id == id)?;
        let mut value = serde_json::to_value(rule).ok()?;
        redact_json_in_place(&mut value);
        return serde_json::to_string(&value).ok();
    }
    if let Some(id) = key.strip_prefix("connectors.connectors.") {
        let connector = snapshot
            .connectors
            .connectors
            .iter()
            .find(|entry| entry.id == id)?;
        let mut value = serde_json::to_value(connector).ok()?;
        redact_json_in_place(&mut value);
        return serde_json::to_string(&value).ok();
    }
    if let Some(name) = key.strip_prefix("admin_users.users.") {
        let user = snapshot
            .admin_users
            .users
            .iter()
            .find(|entry| entry.username == name)?;
        let mut value = serde_json::to_value(user).ok()?;
        redact_json_in_place(&mut value);
        return serde_json::to_string(&value).ok();
    }
    None
}

fn explain_schema_key(state: &ApiState, key: &str) -> Option<serde_json::Value> {
    let guard = state.startup_config.read().expect("startup config lock");
    match guard.as_ref() {
        Some(layered) => {
            let (value, layer) = broker_config::runtime::explain_schema_key(
                layered.config(),
                layered.provenance(),
                key,
            )?;
            Some(serde_json::json!({
                "key": key,
                "value": value,
                "layer": layer.describe(),
                "source": layer.describe(),
            }))
        }
        None => {
            let defaults = broker_config::schema::BrokerConfig::default();
            let provenance: HashMap<String, broker_config::layers::Layer> = HashMap::new();
            let (value, layer) =
                broker_config::runtime::explain_schema_key(&defaults, &provenance, key)?;
            Some(serde_json::json!({
                "key": key,
                "value": value,
                "layer": layer.describe(),
                "source": layer.describe(),
            }))
        }
    }
}

/// Serialise a snapshot for API output, redacting every secret reference.
///
/// The stored snapshot keeps the `file:` / `env:` reference strings they
/// resolve through; observable output replaces each with its
/// `<redacted:...>` marker so scanning any response never finds a value.
fn redact_snapshot(snapshot: &FullSnapshot) -> serde_json::Value {
    let mut value = serde_json::to_value(snapshot).unwrap_or(serde_json::Value::Null);
    redact_json_in_place(&mut value);
    value
}

fn redact_json_in_place(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => {
            if secrets::is_secret_ref(text.trim()) {
                *text = secrets::redact_value(text.trim());
            }
        }
        serde_json::Value::Array(entries) => {
            for entry in entries {
                redact_json_in_place(entry);
            }
        }
        serde_json::Value::Object(map) => {
            for (_, entry) in map.iter_mut() {
                redact_json_in_place(entry);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use broker_auth::MemoryAuth;
    use broker_config::ConfigRegistry;
    use broker_observability::Metrics;
    use broker_router::{ConnTable, Router as SubscriptionRouter};
    use broker_rules::{BackpressurePolicy, RuleEngine};
    use broker_session::SessionManager;
    use brokerlink::BrokerFrame;
    use serde_json::{json, Value};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Lowercase hex SHA-256 (the persisted MQTT password-verifier form).
    fn hex_sha256(password: &[u8]) -> String {
        use sha2::Digest as _;
        let hash = sha2::Sha256::digest(password);
        let mut out = String::with_capacity(64);
        for byte in hash {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    fn unique_dir(prefix: &str) -> std::path::PathBuf {
        static SLOT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let slot = SLOT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "indramqtt-config-rt-{prefix}-{}-{nanos}-{slot}",
            std::process::id()
        ))
    }

    struct Harness {
        port: u16,
        task: tokio::task::JoinHandle<()>,
        state: ApiState,
    }

    impl Harness {
        async fn start() -> Self {
            Self::start_with_registry(ConfigRegistry::load(&unique_dir("data")).unwrap()).await
        }

        async fn start_with_registry(registry: ConfigRegistry) -> Self {
            let registry = Arc::new(registry);
            let engine = Arc::new(RuleEngine::new(16, BackpressurePolicy::DropOldest));
            let sessions = Arc::new(SessionManager::new());
            let sub_router = Arc::new(SubscriptionRouter::new());
            let metrics = Arc::new(Metrics::new());
            let auth = Arc::new(MemoryAuth::new());
            let conns = Arc::new(ConnTable::default());
            let (edge_tx, edge_rx) = tokio::sync::mpsc::unbounded_channel::<BrokerFrame>();
            drop(edge_rx);
            let state = ApiState::new(
                engine,
                sessions,
                sub_router,
                metrics,
                auth,
                conns,
                registry,
                "indra-node-1".to_string(),
                edge_tx,
            );
            let app = crate::router(state.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind test server");
            let port = listener.local_addr().expect("local addr").port();
            let task = tokio::spawn(async move {
                axum::serve(listener, app).await.expect("serve test app");
            });
            Self { port, task, state }
        }

        async fn send(
            &self,
            method: &str,
            path: &str,
            body: Option<Value>,
            token: Option<&str>,
        ) -> (u16, Value) {
            let mut head = format!("{method} {path} HTTP/1.0\r\nHost: test\r\n");
            if let Some(token) = token {
                head.push_str(&format!("Authorization: Bearer {token}\r\n"));
            }
            if let Some(body) = body {
                let raw = serde_json::to_string(&body).expect("encode body");
                head.push_str(&format!(
                    "Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{raw}",
                    raw.len()
                ));
            } else {
                head.push_str("Connection: close\r\n\r\n");
            }
            let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", self.port))
                .await
                .expect("connect test server");
            stream.write_all(head.as_bytes()).await.expect("write");
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).await.expect("read");
            let text = String::from_utf8(buf).expect("UTF-8");
            let (head, body) = text.split_once("\r\n\r\n").expect("header/body split");
            let status: u16 = head.lines().next().expect("status")[9..12]
                .parse()
                .expect("code");
            let body: Value = if body.trim().is_empty() {
                Value::Null
            } else {
                serde_json::from_str(body).expect("JSON body")
            };
            (status, body)
        }

        async fn post_auth(&self, path: &str, body: Value, token: &str) -> (u16, Value) {
            self.send("POST", path, Some(body), Some(token)).await
        }

        async fn get_auth(&self, path: &str, token: &str) -> (u16, Value) {
            self.send("GET", path, None, Some(token)).await
        }

        /// Fully-privileged bearer token via the default admin dance.
        async fn login_as_admin(&self) -> String {
            let (status, body) = self
                .send(
                    "POST",
                    "/api/v5/login",
                    Some(json!({"username": "admin", "password": "public"})),
                    None,
                )
                .await;
            assert_eq!(status, 200);
            let fresh = body["token"].as_str().expect("token").to_string();
            let (status, _) = self
                .send(
                    "PUT",
                    "/api/v5/users/admin/change_pwd",
                    Some(json!({"old_pwd": "public", "new_pwd": "Adm1n-test-pass!"})),
                    Some(&fresh),
                )
                .await;
            assert_eq!(status, 204);
            let (status, body) = self
                .send(
                    "POST",
                    "/api/v5/login",
                    Some(json!({"username": "admin", "password": "Adm1n-test-pass!"})),
                    None,
                )
                .await;
            assert_eq!(status, 200);
            body["token"].as_str().expect("token").to_string()
        }
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    fn log_rule(id: &str, filter: &str) -> broker_config::RuleEntry {
        broker_config::RuleEntry {
            id: id.to_string(),
            name: id.to_string(),
            topic_filter: filter.to_string(),
            sql_query: None,
            enabled: true,
            actions: vec![broker_config::RuleActionEntry::Log],
        }
    }

    fn mqtt_user(username: &str, password: &[u8]) -> broker_config::MqttUser {
        broker_config::MqttUser {
            username: username.to_string(),
            password_hash: hex_sha256(password),
            max_connections: None,
            max_publish_rate: None,
            max_publish_burst: None,
        }
    }

    /// M1-05: a valid change set applied through the API takes effect in
    /// the live broker (new credential authenticates on the CONNECT path,
    /// new rule evaluates at ingress), and the API reads never leak
    /// credential material.
    #[tokio::test]
    async fn reload_valid_change_applies_new_behaviour_through_broker() {
        let harness = Harness::start().await;
        let token = harness.login_as_admin().await;

        let mut snapshot = (*harness.state.config.snapshot()).clone();
        snapshot
            .mqtt_users
            .users
            .push(mqtt_user("alice", b"s3cret-pw"));
        snapshot.mqtt_users.acls.push(broker_config::AclConf {
            username: "alice".to_string(),
            topic: "sensors/#".to_string(),
            action: "all".to_string(),
            allow: true,
        });
        snapshot.rules.rules.push(log_rule("m105-r1", "sensors/#"));

        let (status, body) = harness
            .post_auth(
                "/api/v1/config/reload",
                json!({"snapshot": snapshot, "actor": "tester", "summary": "add alice and r1"}),
                &token,
            )
            .await;
        assert_eq!(status, 200, "valid reload applies: {body}");
        assert!(body["version"].is_number());
        let diff = body["diff"].as_array().expect("diff rows");
        assert!(
            diff.iter()
                .any(|row| row["setting"] == json!("mqtt_users.users[alice]")),
            "diff shows the added user first: {diff:?}"
        );

        // New behaviour through the broker: the CONNECT path accepts the
        // new credential and rejects a wrong one, and a publish through
        // ingress matches the new rule (not only a store list).
        use broker_auth::Authenticator as _;
        assert!(harness
            .state
            .auth
            .authenticate("device-1", Some("alice"), Some(b"s3cret-pw"))
            .await
            .is_ok());
        assert!(harness
            .state
            .auth
            .authenticate("device-1", Some("alice"), Some(b"wrong"))
            .await
            .is_err());
        // The new rule evaluates at publish ingress through the broker.
        struct NullSink;
        #[async_trait::async_trait]
        impl broker_rules::BrokerSink for NullSink {
            async fn publish(
                &self,
                _topic: broker_protocol::Topic,
                _payload: bytes::Bytes,
                _qos: broker_protocol::QoS,
                _retain: bool,
            ) -> Result<(), broker_rules::RuleEngineError> {
                Ok(())
            }
        }
        let sink: std::sync::Arc<dyn broker_rules::BrokerSink> = std::sync::Arc::new(NullSink);
        let matched = harness
            .state
            .engine
            .dispatch_ingress(
                &broker_protocol::Topic::new("sensors/temp").expect("topic"),
                &bytes::Bytes::from_static(b"{}"),
                broker_protocol::QoS::AtMostOnce,
                &sink,
            )
            .await;
        assert_eq!(
            matched, 1,
            "publish through ingress matches the reloaded rule"
        );
        let ids: Vec<String> = harness
            .state
            .engine
            .list_rules()
            .iter()
            .map(|rule| rule.id.clone())
            .collect();
        assert!(
            ids.contains(&"m105-r1".to_string()),
            "rule is live: {ids:?}"
        );

        // API reads of the same objects never leak the password.
        let (status, body) = harness.get_auth("/api/v1/auth/users", &token).await;
        assert_eq!(status, 200);
        let text = serde_json::to_string(&body).expect("encode");
        assert!(
            !text.contains("s3cret-pw"),
            "user list leaks password: {text}"
        );

        let dir = harness.state.config.dir().to_path_buf();
        std::fs::remove_dir_all(&dir).ok();
    }

    /// M1-05: an invalid change set names every offending setting and
    /// leaves the running snapshot untouched.
    #[tokio::test]
    async fn reload_invalid_change_set_names_every_offender_and_changes_nothing() {
        let harness = Harness::start().await;
        let token = harness.login_as_admin().await;
        let before = (*harness.state.config.snapshot()).clone();
        let history_len = harness.state.config.history_list().len();

        let mut snapshot = before.clone();
        snapshot.admin_users.users.push(broker_config::AdminUser {
            username: String::new(),
            password_hash: "hash".to_string(),
            role: "viewer".to_string(),
            description: String::new(),
            must_change_password: false,
        });
        snapshot
            .connectors
            .connectors
            .push(broker_config::ConnectorEntry {
                id: "bad-conn".to_string(),
                connector_type: "not-a-connector".to_string(),
                enable: true,
                config: String::new(),
            });
        snapshot.rules.rules.push(broker_config::RuleEntry {
            id: "dangling".to_string(),
            name: "dangling".to_string(),
            topic_filter: "a/#".to_string(),
            sql_query: None,
            enabled: true,
            actions: vec![broker_config::RuleActionEntry::ForwardConnector {
                connector_id: "missing-conn".to_string(),
            }],
        });

        let (status, body) = harness
            .post_auth(
                "/api/v1/config/reload",
                json!({"snapshot": snapshot}),
                &token,
            )
            .await;
        assert_eq!(status, 400, "invalid change set must not apply: {body}");
        let error = body["error"].as_str().unwrap_or("");
        assert!(
            error.contains("admin_users.users[1].username"),
            "got: {error}"
        );
        assert!(error.contains("connector_type"), "got: {error}");
        assert!(error.contains("connector_id"), "got: {error}");

        assert_eq!(
            *harness.state.config.snapshot(),
            before,
            "snapshot untouched"
        );
        assert!(harness.state.engine.list_rules().is_empty());
        assert_eq!(harness.state.config.history_list().len(), history_len);

        let dir = harness.state.config.dir().to_path_buf();
        std::fs::remove_dir_all(&dir).ok();
    }

    /// M1-05: a backend rejecting mid-apply rolls every owner back to the
    /// previous snapshot (registry, live auth store and live engine).
    #[tokio::test]
    async fn reload_mid_apply_failure_rolls_back_every_owner() {
        let harness = Harness::start().await;
        let token = harness.login_as_admin().await;

        // Baseline: one good rule plus one user, live and versioned. The
        // user keeps the auth store non-empty so the post-rollback
        // `authenticate` assertion is meaningful (an empty store is open
        // and allows everything).
        let mut baseline = (*harness.state.config.snapshot()).clone();
        baseline
            .mqtt_users
            .users
            .push(mqtt_user("baseline", b"base-pw"));
        baseline.rules.rules.push(log_rule("good-r1", "ok/#"));
        let (status, _) = harness
            .post_auth(
                "/api/v1/config/reload",
                json!({"snapshot": baseline}),
                &token,
            )
            .await;
        assert_eq!(status, 200);
        let history_len = harness.state.config.history_list().len();

        // Candidate: adds a user AND a rule whose filter passes registry
        // validation (non-empty) but the live engine rejects (`#` mid-filter).
        let mut candidate = (*harness.state.config.snapshot()).clone();
        candidate.mqtt_users.users.push(mqtt_user("mallory", b"pw"));
        candidate
            .rules
            .rules
            .push(log_rule("bad-r2", "sport/#/bogus"));
        let (status, body) = harness
            .post_auth(
                "/api/v1/config/reload",
                json!({"snapshot": candidate}),
                &token,
            )
            .await;
        assert_eq!(
            status, 500,
            "backend rejection must fail the reload: {body}"
        );
        assert!(
            body["error"]
                .as_str()
                .unwrap_or("")
                .contains("rules backend refused"),
            "error names the rejecting backend: {body}"
        );

        // Rollback: the engine holds only the previous rule, the auth store
        // has no trace of the new user, and no version was recorded. The
        // publish path confirms the rollback: ingress through the broker
        // matches only the previous rule.
        struct NullSink2;
        #[async_trait::async_trait]
        impl broker_rules::BrokerSink for NullSink2 {
            async fn publish(
                &self,
                _topic: broker_protocol::Topic,
                _payload: bytes::Bytes,
                _qos: broker_protocol::QoS,
                _retain: bool,
            ) -> Result<(), broker_rules::RuleEngineError> {
                Ok(())
            }
        }
        let sink2: std::sync::Arc<dyn broker_rules::BrokerSink> = std::sync::Arc::new(NullSink2);
        let matched = harness
            .state
            .engine
            .dispatch_ingress(
                &broker_protocol::Topic::new("ok/event").expect("topic"),
                &bytes::Bytes::from_static(b"{}"),
                broker_protocol::QoS::AtMostOnce,
                &sink2,
            )
            .await;
        assert_eq!(matched, 1, "ingress after rollback matches only good-r1");
        let ids: Vec<String> = harness
            .state
            .engine
            .list_rules()
            .iter()
            .map(|rule| rule.id.clone())
            .collect();
        assert_eq!(
            ids,
            vec!["good-r1".to_string()],
            "engine rolled back: {ids:?}"
        );
        assert!(!harness
            .state
            .auth
            .usernames()
            .contains(&"mallory".to_string()));
        assert!(harness
            .state
            .auth
            .usernames()
            .contains(&"baseline".to_string()));
        // Check the history length before exercising the live auth store:
        // a successful legacy SHA-256 verify migrates the hash in-place
        // (migrate_legacy_hash_gated → MemoryAuth::persist →
        // commit_mqtt_users → history.record), which would add a version
        // and is unrelated to the rollback under test.
        assert_eq!(harness.state.config.history_list().len(), history_len);
        use broker_auth::Authenticator as _;
        assert!(harness
            .state
            .auth
            .authenticate("device-9", Some("mallory"), Some(b"pw"))
            .await
            .is_err());
        assert!(harness
            .state
            .auth
            .authenticate("device-9", Some("baseline"), Some(b"base-pw"))
            .await
            .is_ok());
        assert_eq!(harness.state.config.snapshot().rules.rules.len(), 1);
        assert_eq!(harness.state.config.snapshot().mqtt_users.users.len(), 1);

        let dir = harness.state.config.dir().to_path_buf();
        std::fs::remove_dir_all(&dir).ok();
    }

    /// M1-05: history lists versions (who, when, what changed) and any of
    /// them restores through the same validate-whole path.
    #[tokio::test]
    async fn history_lists_versions_and_restores_an_older_one() {
        let harness = Harness::start().await;
        let token = harness.login_as_admin().await;

        let mut snap_a = (*harness.state.config.snapshot()).clone();
        snap_a.mqtt_users.users.push(mqtt_user("u1", b"pw1"));
        let (status, body) = harness
            .post_auth(
                "/api/v1/config/reload",
                json!({"snapshot": snap_a, "actor": "op-a", "summary": "add u1"}),
                &token,
            )
            .await;
        assert_eq!(status, 200);
        let version_a = body["version"].as_u64().expect("version");

        let mut snap_b = (*harness.state.config.snapshot()).clone();
        snap_b.mqtt_users.users.push(mqtt_user("u2", b"pw2"));
        let (status, body) = harness
            .post_auth(
                "/api/v1/config/reload",
                json!({"snapshot": snap_b, "actor": "op-b", "summary": "add u2"}),
                &token,
            )
            .await;
        assert_eq!(status, 200);
        assert!(body["version"].as_u64().unwrap() > version_a);

        // List: newest first, with actor, timestamp and per-setting changes.
        let (status, body) = harness.get_auth("/api/v1/config/history", &token).await;
        assert_eq!(status, 200);
        let versions = body["versions"].as_array().expect("versions");
        assert!(versions.len() >= 3, "boot plus two reloads: {versions:?}");
        assert_eq!(versions[0]["actor"], json!("op-b"));
        assert_eq!(versions[1]["actor"], json!("op-a"));
        assert!(versions[0]["timestamp_secs"].is_number());
        let changes = versions[0]["changes"].as_array().expect("changes");
        assert!(
            changes
                .iter()
                .any(|row| row["setting"] == json!("mqtt_users.users[u2]")),
            "history records what changed: {changes:?}"
        );

        // Restore the older version: u2 vanishes from auth and snapshot.
        let (status, body) = harness
            .post_auth(
                &format!("/api/v1/config/history/{version_a}/restore"),
                json!({}),
                &token,
            )
            .await;
        assert_eq!(status, 200, "restore applies: {body}");
        assert_eq!(harness.state.auth.usernames(), vec!["u1".to_string()]);
        assert_eq!(harness.state.config.snapshot().mqtt_users.users.len(), 1);

        // Unknown versions are 404, not 500.
        let (status, _) = harness
            .get_auth("/api/v1/config/history/999999", &token)
            .await;
        assert_eq!(status, 404);

        let dir = harness.state.config.dir().to_path_buf();
        std::fs::remove_dir_all(&dir).ok();
    }

    /// M1-05: `explain` names the exact layer behind a value for startup
    /// layers (file, fragment, environment, flag, defaults) and for the
    /// runtime version.
    #[tokio::test]
    async fn explain_names_the_layer_behind_each_value() {
        let harness = Harness::start().await;
        let token = harness.login_as_admin().await;

        let config_dir = unique_dir("explain-cfg");
        std::fs::create_dir_all(config_dir.join("conf.d")).expect("conf.d");
        std::fs::write(
            config_dir.join("indra.toml"),
            "[node]\nid = \"file-node\"\n[auth]\nallow_anonymous = true\n",
        )
        .expect("main file");
        std::fs::write(
            config_dir.join("conf.d").join("10-x.toml"),
            "[logging]\nlevel = \"debug\"\n",
        )
        .expect("fragment");
        let layered = broker_config::layers::load_layered_with_env(
            &config_dir,
            &[(
                "INDRA_SESSION__MAX_QOS0_BACKLOG".to_string(),
                "7".to_string(),
            )],
            &broker_config::layers::CliOverrides {
                node_id: Some("flag-node".to_string()),
                ..Default::default()
            },
        )
        .expect("layered config");
        *harness.state.startup_config.write().expect("startup lock") = Some(Arc::new(layered));

        // Flag wins over every lower layer and says so.
        let (status, body) = harness
            .get_auth("/api/v1/config/explain?key=node.id", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["value"], json!("\"flag-node\""));
        assert!(
            body["layer"].as_str().unwrap().contains("--node-id"),
            "got: {body}"
        );

        // Main file by path.
        let (status, body) = harness
            .get_auth("/api/v1/config/explain?key=auth.allow_anonymous", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["value"], json!("true"));
        assert!(
            body["layer"].as_str().unwrap().contains("indra.toml"),
            "got: {body}"
        );

        // Fragment by file name.
        let (status, body) = harness
            .get_auth("/api/v1/config/explain?key=logging.level", &token)
            .await;
        assert_eq!(status, 200);
        assert!(
            body["layer"].as_str().unwrap().contains("10-x.toml"),
            "got: {body}"
        );

        // Environment variable by name.
        let (status, body) = harness
            .get_auth(
                "/api/v1/config/explain?key=session.max_qos0_backlog",
                &token,
            )
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["value"], json!("7"));
        assert!(
            body["layer"]
                .as_str()
                .unwrap()
                .contains("INDRA_SESSION__MAX_QOS0_BACKLOG"),
            "got: {body}"
        );

        // Nothing set it: built-in defaults.
        let (status, body) = harness
            .get_auth(
                "/api/v1/config/explain?key=session.keep_alive_grace",
                &token,
            )
            .await;
        assert_eq!(status, 200);
        assert!(
            body["layer"]
                .as_str()
                .unwrap()
                .contains("built-in defaults"),
            "got: {body}"
        );

        // Runtime layer: reload a user, then explain names the version.
        let mut snapshot = (*harness.state.config.snapshot()).clone();
        snapshot
            .mqtt_users
            .users
            .push(mqtt_user("explained", b"pw"));
        let (status, reload) = harness
            .post_auth(
                "/api/v1/config/reload",
                json!({"snapshot": snapshot}),
                &token,
            )
            .await;
        assert_eq!(status, 200);
        let version = reload["version"].as_u64().expect("version");
        let (status, body) = harness
            .get_auth(
                "/api/v1/config/explain?key=mqtt_users.users.explained",
                &token,
            )
            .await;
        assert_eq!(status, 200, "registry key explains: {body}");
        assert!(
            body["layer"]
                .as_str()
                .unwrap()
                .contains(&format!("runtime version {version}")),
            "got: {body}"
        );

        // Unknown keys are 404.
        let (status, _) = harness
            .get_auth("/api/v1/config/explain?key=no.such.key", &token)
            .await;
        assert_eq!(status, 404);

        std::fs::remove_dir_all(&config_dir).ok();
        let dir = harness.state.config.dir().to_path_buf();
        std::fs::remove_dir_all(&dir).ok();
    }

    /// M1-05: secrets resolve at use time and never appear in plaintext in
    /// logs, exports, `explain` output or API responses (asserted by
    /// scanning the actual outputs).
    #[tokio::test]
    async fn secrets_resolve_at_use_and_never_leak_into_outputs() {
        const SECRET: &str = "topsecret-m105-7f2a";
        std::env::set_var("M105_TEST_SECRET", SECRET);
        let harness = Harness::start().await;
        let token = harness.login_as_admin().await;

        // A secret reference authenticates through the snapshot reload
        // path (not `add_user` directly): the CONNECT path resolves the
        // reference at use time.
        let mut secret_snapshot = (*harness.state.config.snapshot()).clone();
        secret_snapshot
            .mqtt_users
            .users
            .push(broker_config::MqttUser {
                username: "suser".to_string(),
                password_hash: "env:M105_TEST_SECRET".to_string(),
                max_connections: None,
                max_publish_rate: None,
                max_publish_burst: None,
            });
        let (status, reload_body) = harness
            .post_auth(
                "/api/v1/config/reload",
                json!({"snapshot": secret_snapshot}),
                &token,
            )
            .await;
        assert_eq!(
            status, 200,
            "secret-bearing user reload applies: {reload_body}"
        );
        use broker_auth::Authenticator as _;
        assert!(harness
            .state
            .auth
            .authenticate("device-1", Some("suser"), Some(SECRET.as_bytes()))
            .await
            .is_ok());
        assert!(harness
            .state
            .auth
            .authenticate("device-1", Some("suser"), Some(b"wrong"))
            .await
            .is_err());

        // Explain over a secret-typed setting shows the reference marker.
        let layered = broker_config::layers::load_layered_with_env(
            &unique_dir("explain-secret"),
            &[(
                "INDRA_LDAP__BIND_PASSWORD".to_string(),
                "env:M105_TEST_SECRET".to_string(),
            )],
            &broker_config::layers::CliOverrides::default(),
        )
        .expect("layered config");
        *harness.state.startup_config.write().expect("startup lock") = Some(Arc::new(layered));
        let (status, body) = harness
            .get_auth("/api/v1/config/explain?key=ldap.bind_password", &token)
            .await;
        assert_eq!(status, 200);
        let explain_text = serde_json::to_string(&body).expect("encode");

        // A connector holding a secret reference reloads, versions and
        // diffs without the value.
        let mut snapshot = (*harness.state.config.snapshot()).clone();
        snapshot
            .connectors
            .connectors
            .push(broker_config::ConnectorEntry {
                id: "c-secret".to_string(),
                connector_type: "webhook".to_string(),
                enable: false,
                config: "env:M105_TEST_SECRET".to_string(),
            });
        let (status, reload) = harness
            .post_auth(
                "/api/v1/config/reload",
                json!({"snapshot": snapshot}),
                &token,
            )
            .await;
        assert_eq!(status, 200, "secret-bearing reload applies: {reload}");
        let version = reload["version"].as_u64().expect("version");
        let (status, history) = harness
            .get_auth(&format!("/api/v1/config/history/{version}"), &token)
            .await;
        assert_eq!(status, 200);
        let history_text = serde_json::to_string(&history).expect("encode");
        let (status, diffed) = harness
            .post_auth(
                "/api/v1/config/diff",
                json!({"snapshot": (*harness.state.config.snapshot()).clone()}),
                &token,
            )
            .await;
        assert_eq!(status, 200);
        let diff_text = serde_json::to_string(&diffed).expect("encode");
        let (status, users) = harness.get_auth("/api/v1/auth/users", &token).await;
        assert_eq!(status, 200);
        let users_text = serde_json::to_string(&users).expect("encode");

        // The persisted registry file and the connector list are observable
        // exports too: neither may hold the value (the snapshot keeps the
        // reference form only).
        let data_dir = harness.state.config.dir().to_path_buf();
        let state_text = std::fs::read_to_string(data_dir.join(broker_config::STATE_FILE_NAME))
            .expect("state.toml readable");
        let (status, connectors) = harness.get_auth("/api/v5/connectors", &token).await;
        assert_eq!(status, 200);
        let connectors_text = serde_json::to_string(&connectors).expect("encode");
        // Boot-style log lines redact through the same helper the kernel
        // uses for directory secrets; the emitted line names the reference.
        let log_line = format!(
            "LDAP directory authentication enabled for ldap://127.0.0.1:389 (bind password {})",
            broker_config::secrets::redact_value("env:M105_TEST_SECRET")
        );

        for (name, text) in [
            ("explain", explain_text.as_str()),
            ("history", history_text.as_str()),
            ("diff", diff_text.as_str()),
            ("users", users_text.as_str()),
            ("state.toml", state_text.as_str()),
            ("connectors", connectors_text.as_str()),
            ("logs", log_line.as_str()),
        ] {
            assert!(
                !text.contains(SECRET),
                "{name} leaks the secret value: {text}"
            );
        }
        assert!(
            connectors_text.contains("redacted:env:M105_TEST_SECRET"),
            "connector list marks the reference: {connectors_text}"
        );
        assert!(
            explain_text.contains("redacted:env:M105_TEST_SECRET"),
            "explain marks the reference: {explain_text}"
        );
        assert!(
            history_text.contains("redacted"),
            "history marks the reference: {history_text}"
        );

        // A `file:` reference authenticates through the same broker reload
        // path (CONNECT-time authentication resolves the file at use time),
        // and no observable output holds the value.
        const FILE_SECRET: &str = "filesecret-m105-4b1c";
        let secret_dir = unique_dir("m105-file-secret");
        std::fs::create_dir_all(&secret_dir).expect("secret dir");
        let secret_path = secret_dir.join("pw");
        std::fs::write(&secret_path, format!("{FILE_SECRET}\n")).expect("write secret file");
        let file_reference = format!("file:{}", secret_path.display());
        let mut file_snapshot = (*harness.state.config.snapshot()).clone();
        file_snapshot
            .mqtt_users
            .users
            .push(broker_config::MqttUser {
                username: "fuser".to_string(),
                password_hash: file_reference.clone(),
                max_connections: None,
                max_publish_rate: None,
                max_publish_burst: None,
            });
        let (status, file_reload) = harness
            .post_auth(
                "/api/v1/config/reload",
                json!({"snapshot": file_snapshot}),
                &token,
            )
            .await;
        assert_eq!(
            status, 200,
            "file-backed secret reload applies through broker: {file_reload}"
        );
        assert!(harness
            .state
            .auth
            .authenticate("device-1", Some("fuser"), Some(FILE_SECRET.as_bytes()))
            .await
            .is_ok());
        assert!(harness
            .state
            .auth
            .authenticate("device-1", Some("fuser"), Some(b"wrong"))
            .await
            .is_err());
        let (status, users_after_file) = harness.get_auth("/api/v1/auth/users", &token).await;
        assert_eq!(status, 200);
        let users_file_text = serde_json::to_string(&users_after_file).expect("encode");
        assert!(
            !users_file_text.contains(FILE_SECRET),
            "user list leaks file secret: {users_file_text}"
        );
        let state_after_file =
            std::fs::read_to_string(data_dir.join(broker_config::STATE_FILE_NAME))
                .expect("state.toml readable");
        assert!(
            !state_after_file.contains(FILE_SECRET),
            "state.toml leaks file secret: {state_after_file}"
        );
        assert!(
            !state_after_file.contains(SECRET),
            "state.toml leaks env secret after file reload: {state_after_file}"
        );
        // Keep the file-backed secret readable for the validate-200 sanity
        // check below: the running snapshot still holds its `file:` reference
        // and whole-config validation fails closed on unreadable secrets, so
        // deleting the file first would make even the unchanged snapshot
        // fail validation. Cleanup happens at the end of the test.

        // A missing secret fails closed naming the reference, never the value:
        // both whole validation and the reload path reject it (never 200
        // with a locked account), and the direct password path does too.
        let missing = "env:M105_TEST_DEFINITELY_UNSET_9F3A";
        let (status, body) = harness
            .post_auth(
                "/api/v1/config/validate",
                json!({"snapshot": (*harness.state.config.snapshot()).clone()}),
                &token,
            )
            .await;
        assert_eq!(status, 200, "validate endpoint itself works: {body}");
        let mut missing_snapshot = (*harness.state.config.snapshot()).clone();
        missing_snapshot
            .mqtt_users
            .users
            .push(broker_config::MqttUser {
                username: "ghost".to_string(),
                password_hash: missing.to_string(),
                max_connections: None,
                max_publish_rate: None,
                max_publish_burst: None,
            });
        let (status, body) = harness
            .post_auth(
                "/api/v1/config/validate",
                json!({"snapshot": missing_snapshot}),
                &token,
            )
            .await;
        assert_eq!(status, 400, "validate must reject missing secret: {body}");
        assert!(
            body["error"].as_str().unwrap_or("").contains(missing),
            "validate error names the reference: {body}"
        );
        let (status, body) = harness
            .post_auth(
                "/api/v1/config/reload",
                json!({"snapshot": missing_snapshot}),
                &token,
            )
            .await;
        assert!(
            status == 400 || status == 500,
            "reload must fail closed on missing secret, got {status}: {body}"
        );
        assert!(
            serde_json::to_string(&body)
                .unwrap_or_default()
                .contains(missing),
            "reload error names the reference: {body}"
        );
        assert!(
            !harness
                .state
                .auth
                .usernames()
                .contains(&"ghost".to_string()),
            "missing secret must not leave a user behind"
        );
        let err = harness
            .state
            .auth
            .add_user("ghost", missing.as_bytes())
            .expect_err("missing secret must fail closed");
        assert!(err.to_string().contains(missing));

        std::env::remove_var("M105_TEST_SECRET");
        std::fs::remove_dir_all(&secret_dir).ok();
        let dir = harness.state.config.dir().to_path_buf();
        std::fs::remove_dir_all(&dir).ok();
    }

    /// M1-05: runtime changes persist in the kernel data directory; files
    /// under the operator config directory are never rewritten.
    #[tokio::test]
    async fn runtime_persists_in_data_dir_and_never_rewrites_operator_files() {
        let harness = Harness::start().await;
        let token = harness.login_as_admin().await;

        let config_dir = unique_dir("opfiles");
        std::fs::create_dir_all(config_dir.join("conf.d")).expect("conf.d");
        std::fs::write(config_dir.join("indra.toml"), "[node]\nid = \"op-node\"\n")
            .expect("main file");
        let mut before: Vec<String> = std::fs::read_dir(&config_dir)
            .expect("read config dir")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        before.sort();

        let mut snapshot = (*harness.state.config.snapshot()).clone();
        snapshot.rules.rules.push(log_rule("persist-r1", "p/#"));
        let (status, _) = harness
            .post_auth(
                "/api/v1/config/reload",
                json!({"snapshot": snapshot}),
                &token,
            )
            .await;
        assert_eq!(status, 200);

        // Operator files untouched: same names, same bytes.
        let mut after: Vec<String> = std::fs::read_dir(&config_dir)
            .expect("read config dir")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        after.sort();
        assert_eq!(after, before, "no file may be added or removed");
        assert_eq!(after, vec!["conf.d".to_string(), "indra.toml".to_string()]);
        assert_eq!(
            std::fs::read_to_string(config_dir.join("indra.toml")).expect("read back"),
            "[node]\nid = \"op-node\"\n"
        );

        // Runtime state lives beside the registry: reload survives a restart.
        let data_dir = harness.state.config.dir().to_path_buf();
        assert!(data_dir.join(broker_config::STATE_FILE_NAME).is_file());
        assert!(data_dir
            .join(broker_config::runtime::HISTORY_FILE_NAME)
            .is_file());
        let reloaded =
            ConfigRegistry::load(&data_dir).expect("data dir reloads after runtime change");
        assert_eq!(
            reloaded.snapshot().rules.rules.len(),
            1,
            "runtime change survives restart"
        );
        assert!(
            !reloaded.history_list().is_empty(),
            "history survives restart"
        );

        std::fs::remove_dir_all(&config_dir).ok();
        std::fs::remove_dir_all(&data_dir).ok();
    }
}
