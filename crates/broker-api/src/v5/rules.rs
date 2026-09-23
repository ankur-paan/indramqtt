//! Streaming SQL rules, data connectors, action sinks, and schema registry for the v5 REST API.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use std::sync::{Arc, LazyLock, RwLock};

use crate::ApiState;

// ---------------------------------------------------------------------------
// Streaming Rules
// ---------------------------------------------------------------------------

/// Projection of the stored [`broker_rules::Rule`] for `/api/v5/rules`.
/// Only real engine state: stored actions verbatim (empty stays empty),
/// no invented `description`/`created_at`, no connector-id coercion.
fn rule_to_v5(rule: &broker_rules::Rule) -> serde_json::Value {
    let topic = rule.topic_filter.as_str().to_string();
    let sql = rule
        .sql_query
        .clone()
        .unwrap_or_else(|| format!("SELECT * FROM \"{topic}\""));
    let actions = serde_json::to_value(&rule.actions).unwrap_or_else(|_| serde_json::json!([]));
    serde_json::json!({
        "id": rule.id,
        "name": rule.name,
        "sql": sql,
        "from": [topic],
        "enable": rule.enabled,
        "actions": actions,
    })
}

pub async fn list_rules(State(state): State<ApiState>) -> Response {
    let data: Vec<_> = state.engine.list_rules().iter().map(rule_to_v5).collect();

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
pub struct CreateRuleV5Request {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    pub sql: String,
    #[serde(default = "default_enable")]
    pub enable: bool,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub actions: Vec<serde_json::Value>,
}

fn default_enable() -> bool {
    true
}

/// Map a rule registry failure onto a 500: the in-memory mutation
/// applied but the commit or atomic save failed, so the loss must never
/// be silent. [`broker_rules::RuleEngineError::Persist`] already renders
/// as `cannot persist rules: ...`, so its display is reused verbatim.
fn rule_persist_error(error: broker_rules::RuleEngineError) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({ "code": "INTERNAL_ERROR", "message": error.to_string() })),
    )
        .into_response()
}

pub async fn create_rule(
    State(state): State<ApiState>,
    Json(req): Json<CreateRuleV5Request>,
) -> Response {
    let CreateRuleV5Request {
        id,
        name,
        sql,
        enable,
        description: _,
        actions: raw_actions,
    } = req;
    let name = match (name, id) {
        (Some(name), _) => name,
        (None, Some(id)) => id,
        (None, None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "code": "BAD_REQUEST",
                    "message": "rule id or name is required"
                })),
            )
                .into_response();
        }
    };
    let topic_str = if sql.contains("FROM \"") {
        sql.split("FROM \"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .unwrap_or("t/#")
    } else {
        "t/#"
    };

    let topic_filter = match broker_protocol::TopicFilter::new(topic_str) {
        Ok(filter) => {
            // The v5 rules projection treats bracket characters as invalid
            // filter characters (the spec's `t/[` example): the shared
            // `TopicFilter` accepts them, but a rule FROM-target containing
            // `[` or `]` is rejected here with 400 instead of going live.
            if topic_str.contains('[') || topic_str.contains(']') {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "code": "BAD_REQUEST",
                        "message": "invalid topic filter: bracket characters are not allowed",
                    })),
                )
                    .into_response();
            }
            filter
        }
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "code": "BAD_REQUEST",
                    "message": format!("invalid topic filter: {e}")
                })),
            )
                .into_response();
        }
    };

    let mut actions = Vec::new();
    for a in &raw_actions {
        if let Some(id_str) = a.as_str() {
            actions.push(broker_rules::RuleAction::ForwardConnector {
                connector_id: id_str.to_string(),
            });
        } else if let Some(obj) = a.as_object() {
            if let Some(conn_id) = obj
                .get("id")
                .or_else(|| obj.get("name"))
                .and_then(|v| v.as_str())
            {
                actions.push(broker_rules::RuleAction::ForwardConnector {
                    connector_id: conn_id.to_string(),
                });
            }
        }
    }

    let rule = state
        .engine
        .create_rule(name, topic_filter, Some(sql), enable, actions);

    match rule {
        Ok(r) => (StatusCode::CREATED, Json(rule_to_v5(&r))).into_response(),
        // A persist failure is a 500 (the in-memory rule stays but the
        // disk save failed); validation failures stay 400.
        Err(error @ broker_rules::RuleEngineError::Persist(_)) => rule_persist_error(error),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "code": "BAD_REQUEST",
                "message": format!("Rule creation failed: {e}")
            })),
        )
            .into_response(),
    }
}

pub async fn get_rule(State(state): State<ApiState>, Path(id): Path<String>) -> Response {
    match state.engine.get_rule(&id) {
        Some(r) => (StatusCode::OK, Json(rule_to_v5(&r))).into_response(),
        _ => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "code": "NOT_FOUND",
                "message": "Rule not found"
            })),
        )
            .into_response(),
    }
}

pub async fn update_rule(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if state.engine.get_rule(&id).is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "code": "NOT_FOUND",
                "message": "Rule not found"
            })),
        )
            .into_response();
    }
    if let Some(enable) = body.get("enable").and_then(|v| v.as_bool()) {
        // A persist failure must surface as a 500, never as a success:
        // the in-memory flag applied but the disk save failed.
        if let Err(error) = state.engine.set_rule_enabled(&id, enable) {
            return rule_persist_error(error);
        }
    }
    match state.engine.get_rule(&id) {
        Some(r) => (StatusCode::OK, Json(rule_to_v5(&r))).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "code": "NOT_FOUND",
                "message": "Rule not found"
            })),
        )
            .into_response(),
    }
}

pub async fn delete_rule(State(state): State<ApiState>, Path(id): Path<String>) -> Response {
    match state.engine.remove_rule(&id) {
        // Preserve the long-standing v5 contract (unconditional 204, even
        // for unknown ids); only a persist failure surfaces as a 500.
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        // A persist failure must surface as a 500, never as a success:
        // the in-memory removal applied but the disk save failed.
        Err(error) => rule_persist_error(error),
    }
}

pub async fn get_rule_metrics(State(state): State<ApiState>, Path(id): Path<String>) -> Response {
    let rules = state.engine.list_rules();
    let Some(r) = rules.iter().find(|r| r.id == id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "code": "NOT_FOUND",
                "message": "Rule not found"
            })),
        )
            .into_response();
    };
    let matched = r.matched_cnt.load(std::sync::atomic::Ordering::Relaxed);
    let passed = r.passed_cnt.load(std::sync::atomic::Ordering::Relaxed);
    let failed = r.failed_cnt.load(std::sync::atomic::Ordering::Relaxed);
    let actions_total = r
        .actions_total_cnt
        .load(std::sync::atomic::Ordering::Relaxed);
    let actions_success = r
        .actions_success_cnt
        .load(std::sync::atomic::Ordering::Relaxed);
    let actions_failed = r
        .actions_failed_cnt
        .load(std::sync::atomic::Ordering::Relaxed);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "id": id,
            "metrics": {
                "matched": matched,
                "passed": passed,
                "failed": failed,
                "actions.total": actions_total,
                "actions.success": actions_success,
                "actions.failed": actions_failed
            }
        })),
    )
        .into_response()
}

pub async fn reset_rule_metrics(State(state): State<ApiState>, Path(id): Path<String>) -> Response {
    let rules = state.engine.list_rules();
    let Some(r) = rules.iter().find(|r| r.id == id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "code": "NOT_FOUND",
                "message": "Rule not found"
            })),
        )
            .into_response();
    };
    r.matched_cnt.store(0, std::sync::atomic::Ordering::Relaxed);
    r.passed_cnt.store(0, std::sync::atomic::Ordering::Relaxed);
    r.failed_cnt.store(0, std::sync::atomic::Ordering::Relaxed);
    r.actions_total_cnt
        .store(0, std::sync::atomic::Ordering::Relaxed);
    r.actions_success_cnt
        .store(0, std::sync::atomic::Ordering::Relaxed);
    r.actions_failed_cnt
        .store(0, std::sync::atomic::Ordering::Relaxed);
    StatusCode::NO_CONTENT.into_response()
}

// ---------------------------------------------------------------------------
// Data Connectors
// ---------------------------------------------------------------------------

static CONNECTORS: LazyLock<RwLock<Vec<serde_json::Value>>> =
    LazyLock::new(|| RwLock::new(Vec::new()));

/// Serialises export-commit-save for connector mutations so concurrent
/// creates, updates and deletes cannot interleave into a lost update on
/// disk (mirrors the `save_lock` in `broker-auth` and `broker-rules`).
static CONNECTORS_SAVE_LOCK: LazyLock<std::sync::Mutex<()>> =
    LazyLock::new(|| std::sync::Mutex::new(()));

/// Map a connector registry failure onto a 500: the in-memory mutation
/// applied but the commit or atomic save failed, so the loss must never
/// be silent.
fn connector_persist_error(error: broker_config::ConfigError) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({
            "code": "INTERNAL_ERROR",
            "message": format!("cannot persist connectors: {error}")
        })),
    )
        .into_response()
}

/// Export the connector store as a validated config root: entries sorted
/// by id so the persisted file is deterministic. Each entry carries the
/// id, type, enable flag and the full connector params as a JSON
/// document (everything `create_connector` accepts, lossless). The
/// derived `status`/`node_status` display values are stripped: only
/// inputs are stored, display values are recomputed at read time.
fn export_connectors_conf() -> broker_config::ConnectorsConf {
    let store = CONNECTORS.read().unwrap();
    let mut entries: Vec<broker_config::ConnectorEntry> = store
        .iter()
        .map(|body| {
            let id = body
                .get("id")
                .and_then(|v| v.as_str())
                .or_else(|| body.get("name").and_then(|v| v.as_str()))
                .unwrap_or_default()
                .to_string();
            let connector_type = body
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("http")
                .to_string();
            let enable = body.get("enable").and_then(|v| v.as_bool()).unwrap_or(true);
            let mut params = body.clone();
            if let Some(obj) = params.as_object_mut() {
                obj.remove("status");
                obj.remove("node_status");
            }
            broker_config::ConnectorEntry {
                id,
                connector_type,
                enable,
                config: serde_json::to_string(&params).unwrap_or_else(|_| "{}".to_string()),
            }
        })
        .collect();
    entries.sort_by(|a, b| a.id.cmp(&b.id));
    broker_config::ConnectorsConf {
        connectors: entries,
    }
}

/// Commit the exported connectors root and atomically save it. Any
/// commit or save failure surfaces as [`broker_config::ConfigError`] so
/// callers answer 500 and the loss is never silent (the in-memory
/// mutation stays: commit precedes the atomic save).
fn persist_connectors(
    config: &Arc<broker_config::ConfigRegistry>,
) -> Result<(), broker_config::ConfigError> {
    let _guard = CONNECTORS_SAVE_LOCK.lock().unwrap();
    let conf = export_connectors_conf();
    config.commit_connectors(conf)?;
    config.save()?;
    Ok(())
}

/// Probe the connector target the way `create_connector` does: entries
/// without a `server`/`url`/… target never probe and count as reachable;
/// otherwise a 1.5 s TCP connect decides.
async fn probe_connector_reachable(body: &serde_json::Value) -> bool {
    match extract_target_host_port(body) {
        Some(target) => check_tcp_reachable(&target).await.is_ok(),
        None => true,
    }
}

/// Display status derived from reachability (recomputed at read time,
/// never persisted).
fn connector_status(reachable: bool) -> &'static str {
    if reachable {
        "connected"
    } else {
        "disconnected"
    }
}

/// Per-node display status for a connector entry (recomputed at read
/// time, never persisted).
fn connector_node_status(status: &str) -> serde_json::Value {
    serde_json::json!([{ "node": "indramqtt@127.0.0.1", "status": status }])
}

/// Required-field gate for connector registration (S1-01): no connector
/// may fall back to a built-in credential or an invented identity. Returns
/// the first missing required field's canonical name, or `None` when the
/// body supplies everything the live-sink builder needs. Callers answer
/// 400 naming that field; `register_live_sink` itself also fails closed
/// (returns without registering) so boot replay cannot invent values.
///
/// Only the six connector families that previously carried built-in
/// credentials or invented identities are gated here. Every other family
/// keeps its existing behaviour; see the marker on the fallback arm below.
fn missing_connector_field(conn_type: &str, body: &serde_json::Value) -> Option<&'static str> {
    fn present(body: &serde_json::Value, keys: &[&str]) -> bool {
        keys.iter().any(|k| {
            body.get(*k)
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.trim().is_empty())
        })
    }

    match conn_type {
        "gcp_iot" | "gcp_iot_core" => {
            // Credential first so a bare body names the credential, not an identity.
            if !present(body, &["private_key_pem", "private_key"]) {
                return Some("private_key_pem");
            }
            if !present(body, &["project_id", "project"]) {
                return Some("project_id");
            }
            if !present(body, &["cloud_region", "region"]) {
                return Some("cloud_region");
            }
            if !present(body, &["registry_id", "registry"]) {
                return Some("registry_id");
            }
            if !present(body, &["device_id", "device"]) {
                return Some("device_id");
            }
            None
        }
        "databricks" | "delta_lake" => {
            if !present(body, &["token", "api_key"]) {
                return Some("token");
            }
            if !present(body, &["host", "server", "endpoint"]) {
                return Some("host");
            }
            if !present(body, &["catalog"]) {
                return Some("catalog");
            }
            if !present(body, &["schema"]) {
                return Some("schema");
            }
            if !present(body, &["table", "table_template"]) {
                return Some("table");
            }
            None
        }
        "snowflake" => {
            if !present(body, &["private_key_pem", "private_key"]) {
                return Some("private_key_pem");
            }
            if !present(body, &["account"]) {
                return Some("account");
            }
            if !present(body, &["user", "username"]) {
                return Some("user");
            }
            if !present(body, &["database"]) {
                return Some("database");
            }
            if !present(body, &["schema"]) {
                return Some("schema");
            }
            if !present(body, &["table", "table_template"]) {
                return Some("table");
            }
            None
        }
        "tablestore" | "ots" => {
            if !present(body, &["access_key_id", "ak"]) {
                return Some("access_key_id");
            }
            if !present(body, &["access_key_secret", "sk"]) {
                return Some("access_key_secret");
            }
            if !present(body, &["instance_name", "instance"]) {
                return Some("instance_name");
            }
            if !present(body, &["table_name", "table"]) {
                return Some("table_name");
            }
            if !present(body, &["endpoint", "url"]) {
                return Some("endpoint");
            }
            None
        }
        "oci_streaming" | "oci" => {
            if !present(body, &["private_key_pem", "private_key"]) {
                return Some("private_key_pem");
            }
            if !present(body, &["stream_pool_id"]) {
                return Some("stream_pool_id");
            }
            if !present(body, &["stream_id"]) {
                return Some("stream_id");
            }
            if !present(body, &["tenancy_ocid"]) {
                return Some("tenancy_ocid");
            }
            if !present(body, &["user_ocid"]) {
                return Some("user_ocid");
            }
            if !present(body, &["fingerprint"]) {
                return Some("fingerprint");
            }
            if !present(body, &["endpoint", "url"]) {
                return Some("endpoint");
            }
            None
        }
        "confluent" => {
            if !present(body, &["api_key", "username"]) {
                return Some("api_key");
            }
            if !present(body, &["api_secret", "password"]) {
                return Some("api_secret");
            }
            None
        }
        "azure_eventhubs" | "azure_event_hubs" => {
            if !present(body, &["shared_access_key", "key"]) {
                return Some("shared_access_key");
            }
            None
        }
        "azure_iot" | "azure_iot_hub" => {
            if !present(body, &["shared_access_key", "key"]) {
                return Some("shared_access_key");
            }
            None
        }
        "aws_iot" | "aws_iot_core" => {
            // mTLS-only build (R1-01): client certificate + key come from
            // the operator. SigV4/WebSocket has no transport and is rejected
            // at construction; never invent test credentials here.
            // Accept flat fields and the nested `auth` object used by v1.
            let nested = body.get("auth").and_then(|v| v.as_object());
            let has = |keys: &[&str]| {
                if present(body, keys) {
                    return true;
                }
                if let Some(auth) = nested {
                    return keys.iter().any(|k| {
                        auth.get(*k)
                            .and_then(|v| v.as_str())
                            .is_some_and(|s| !s.trim().is_empty())
                    });
                }
                false
            };
            if !has(&["client_cert_pem", "client_cert", "certificate", "cert_pem"]) {
                return Some("client_cert_pem");
            }
            if !has(&["client_key_pem", "client_key", "private_key", "key_pem"]) {
                return Some("client_key_pem");
            }
            None
        }
        // TODO(parity): remaining `register_live_sink` families still invent
        // operational defaults (endpoints, tables, batch knobs); each needs
        // the same fail-closed gate once its service documentation is
        // checked for real defaults.
        _ => None,
    }
}

/// Boot replay for the connector store: merge the persisted snapshot
/// into the process-global store and re-register every live sink through
/// [`register_live_sink`], the same path `create_connector` uses, so a
/// restored connector actually connects instead of merely being listed.
///
/// Entries merge by id without clearing: on a fresh boot the store is
/// empty and the merge is a full load; on an in-process rebuild (tests)
/// entries created after the snapshot was taken are kept, which keeps
/// parallel test servers sharing the process-global store deterministic.
/// Stored `status`/`node_status` display values are recomputed with the
/// same probe `create_connector` runs; only the persisted inputs
/// round-trip.
///
/// An invalid snapshot or an unparsable stored params document fails boot
/// loudly instead of being skipped silently.
pub fn seed_connectors_from_registry(
    config: &Arc<broker_config::ConfigRegistry>,
    engine: &broker_rules::RuleEngine,
) {
    let snapshot = config.snapshot();
    if snapshot.connectors.connectors.is_empty() {
        return;
    }
    if let Err(error) = snapshot.connectors.validate() {
        panic!("invalid stored connectors snapshot: {error}");
    }
    let mut restored = Vec::with_capacity(snapshot.connectors.connectors.len());
    for entry in &snapshot.connectors.connectors {
        let params: serde_json::Value = serde_json::from_str(&entry.config).unwrap_or_else(|_| {
            panic!(
                "invalid stored connector params for {}: not a JSON document",
                entry.id
            )
        });
        restored.push((entry.id.clone(), entry.connector_type.clone(), params));
    }
    // `register_live_sink` is async (the `disk_log` arm opens its
    // directory) while boot callers are sync (`ApiState::new`), so the
    // replay runs on a dedicated thread with its own current-thread
    // runtime. The thread is joined: boot never completes with sinks
    // half restored.
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("connector boot runtime");
                runtime.block_on(async {
                    for (id, conn_type, mut params) in restored {
                        let reachable = probe_connector_reachable(&params).await;
                        let status = connector_status(reachable);
                        if let Some(obj) = params.as_object_mut() {
                            obj.insert(
                                "status".to_string(),
                                serde_json::Value::String(status.to_string()),
                            );
                            obj.insert("node_status".to_string(), connector_node_status(status));
                        }
                        let live_name = params
                            .get("id")
                            .and_then(|v| v.as_str())
                            .unwrap_or(&id)
                            .to_string();
                        {
                            let mut store = CONNECTORS.write().unwrap();
                            if let Some(pos) = store.iter().position(|c| {
                                c.get("id").and_then(|v| v.as_str()) == Some(live_name.as_str())
                                    || c.get("name").and_then(|v| v.as_str())
                                        == Some(live_name.as_str())
                            }) {
                                store[pos] = params.clone();
                            } else {
                                store.push(params.clone());
                            }
                        }
                        if reachable {
                            register_live_sink(engine, &conn_type, &live_name, &params).await;
                        }
                    }
                });
            })
            .join()
            .expect("connector boot thread");
    });
}

pub async fn list_connectors() -> Response {
    let list = CONNECTORS.read().unwrap().clone();
    (StatusCode::OK, Json(list)).into_response()
}

pub async fn get_connector(Path(id): Path<String>) -> Response {
    let clean_id = id.split(':').next_back().unwrap_or(&id);
    let connectors = CONNECTORS.read().unwrap();
    if let Some(conn) = connectors.iter().find(|c| {
        c.get("id").and_then(|v| v.as_str()) == Some(&id)
            || c.get("name").and_then(|v| v.as_str()) == Some(&id)
            || c.get("id").and_then(|v| v.as_str()) == Some(clean_id)
            || c.get("name").and_then(|v| v.as_str()) == Some(clean_id)
    }) {
        return (StatusCode::OK, Json(conn.clone())).into_response();
    }

    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "code": "NOT_FOUND",
            "message": "Connector not found"
        })),
    )
        .into_response()
}

async fn register_live_sink(
    engine: &broker_rules::RuleEngine,
    conn_type: &str,
    name: &str,
    body: &serde_json::Value,
) {
    match conn_type {
        "redis" => {
            let servers = body
                .get("servers")
                .or_else(|| body.get("server"))
                .and_then(|v| v.as_str())
                .unwrap_or("127.0.0.1:6379");
            let pass = body.get("password").and_then(|v| v.as_str()).unwrap_or("");
            let endpoint = if pass.is_empty() {
                format!("redis://{}", servers)
            } else {
                format!("redis://:{}@{}", pass, servers)
            };
            if let Ok(transport) = broker_connectors::redis::TcpRedisTransport::new(&endpoint) {
                let config = broker_connectors::redis::RedisSinkConfig {
                    endpoint,
                    command: broker_connectors::redis::RedisCommandKind::HSet {
                        key_template: "sensors:${topic}".to_string(),
                        field_template: "payload".to_string(),
                    },
                };
                if let Ok(sink) =
                    broker_connectors::redis::RedisSink::new(config, Arc::new(transport))
                {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine
                        .connectors()
                        .register(format!("redis:{}", name), sink);
                }
            }
        }
        "alloydb" => {
            let server = body
                .get("server")
                .or_else(|| body.get("servers"))
                .or_else(|| body.get("host"))
                .and_then(|v| v.as_str())
                .unwrap_or("127.0.0.1:5433");
            let clean_server = server
                .split("://")
                .last()
                .unwrap_or(server)
                .split('/')
                .next()
                .unwrap_or(server);
            let (host, port) = if let Some((h, p)) = clean_server.split_once(':') {
                (h.to_string(), p.parse::<u16>().unwrap_or(5433))
            } else {
                (clean_server.to_string(), 5433)
            };
            let database = body
                .get("database")
                .and_then(|v| v.as_str())
                .unwrap_or("telemetry");
            let table = body
                .get("table")
                .and_then(|v| v.as_str())
                .unwrap_or("sensor_events");
            let username = body
                .get("username")
                .and_then(|v| v.as_str())
                .unwrap_or("postgres");
            let password = body
                .get("password")
                .and_then(|v| v.as_str())
                .unwrap_or("password");
            let timeout_ms = body
                .get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .or_else(|| body.get("request_timeout_ms"))
                .and_then(|v| v.as_u64());
            let config = broker_connectors::alloydb::AlloydbConfig {
                host,
                port,
                database: database.to_string(),
                username: username.to_string(),
                auth: broker_connectors::alloydb::AlloydbAuth::Password {
                    password: password.to_string(),
                },
                table: table.to_string(),
                column_mappings: Vec::new(),
                batch_size: Some(1),
                buffer_capacity: None,
                timeout_ms,
                tls: None,
                ca_bundle_pem: None,
                tls_ca_file: None,
            };
            let transport = Arc::new(broker_connectors::alloydb::PgDriverAlloydbTransport::new(
                &config,
            ));
            if let Ok(sink) = broker_connectors::alloydb::AlloydbSink::new(config, transport) {
                let sink = Arc::new(sink);
                engine.connectors().register(name, sink.clone());
                engine
                    .connectors()
                    .register(format!("alloydb:{}", name), sink);
            }
        }
        "http" => {
            let url = body
                .get("url")
                .and_then(|v| v.as_str())
                .unwrap_or("http://127.0.0.1:8080");
            let sink = Arc::new(broker_connectors::HttpWebhookSink::new(
                url.to_string(),
                reqwest::header::HeaderMap::new(),
                reqwest::Client::new(),
            ));
            engine.connectors().register(name, sink.clone());
            engine.connectors().register(format!("http:{}", name), sink);
        }
        "kafka" => {
            let servers = body
                .get("bootstrap_hosts")
                .or_else(|| body.get("servers"))
                .and_then(|v| v.as_str())
                .unwrap_or("127.0.0.1:9092");
            if let Ok(transport) = broker_connectors::kafka::TcpKafkaTransport::new(
                servers,
                format!("indramqtt-{}", name),
                "1",
            ) {
                let config = broker_connectors::kafka::KafkaSinkConfig {
                    bootstrap_servers: servers.to_string(),
                    topic_template: "events-${topic}".to_string(),
                    partition_key_field: None,
                    partitions: 1,
                    client_id: format!("indramqtt-{}", name),
                    acks: "1".to_string(),
                    batch_max_records: 1,
                    batch_max_bytes: 65536,
                };
                if let Ok(sink) =
                    broker_connectors::kafka::KafkaSink::new(config, Arc::new(transport))
                {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine
                        .connectors()
                        .register(format!("kafka:{}", name), sink);
                }
            }
        }
        "pgsql" => {
            let server = body
                .get("server")
                .and_then(|v| v.as_str())
                .unwrap_or("127.0.0.1:5432");
            let database = body
                .get("database")
                .and_then(|v| v.as_str())
                .unwrap_or("postgres");
            let username = body
                .get("username")
                .and_then(|v| v.as_str())
                .unwrap_or("postgres");
            let password = body.get("password").and_then(|v| v.as_str()).unwrap_or("");
            let conn_url = format!(
                "postgres://{}:{}@{}/{}",
                username, password, server, database
            );
            if let Ok(transport) = broker_connectors::postgres::TcpPgTransport::new(&conn_url, 1) {
                let config = broker_connectors::postgres::PostgreSqlSinkConfig {
                    connection_url: conn_url,
                    sql_template: "INSERT INTO test_telemetry (clientid, topic, payload, timestamp) VALUES ('rule-engine', $1, $3, 0)".to_string(),
                    pool_size: 1,
                    batch_size: 1,
                    batch_timeout_ms: 10,
                };
                if let Ok(sink) =
                    broker_connectors::postgres::PostgreSqlSink::new(config, Arc::new(transport))
                {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine
                        .connectors()
                        .register(format!("pgsql:{}", name), sink);
                }
            }
        }
        "mysql" => {
            let server = body
                .get("server")
                .and_then(|v| v.as_str())
                .unwrap_or("127.0.0.1:3306");
            let database = body
                .get("database")
                .and_then(|v| v.as_str())
                .unwrap_or("test");
            let username = body
                .get("username")
                .and_then(|v| v.as_str())
                .unwrap_or("root");
            let password = body.get("password").and_then(|v| v.as_str()).unwrap_or("");
            let conn_url = if password.is_empty() {
                format!("mysql://{}@{}/{}", username, server, database)
            } else {
                format!("mysql://{}:{}@{}/{}", username, password, server, database)
            };
            if let Ok(transport) = broker_connectors::mysql::TcpMySqlTransport::new(&conn_url, 1) {
                let config = broker_connectors::mysql::MySqlSinkConfig {
                    connection_url: conn_url,
                    sql_template:
                        "INSERT INTO test_mqtt_events (topic, qos, payload) VALUES (?, ?, ?)"
                            .to_string(),
                    pool_size: 1,
                    batch_size: 1,
                    batch_timeout_ms: 10,
                };
                if let Ok(sink) =
                    broker_connectors::mysql::MySqlSink::new(config, Arc::new(transport))
                {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine
                        .connectors()
                        .register(format!("mysql:{}", name), sink);
                }
            }
        }
        "rabbitmq" => {
            let endpoint = body
                .get("server")
                .and_then(|v| v.as_str())
                .or_else(|| body.get("endpoint").and_then(|v| v.as_str()))
                .unwrap_or("127.0.0.1:5672");
            let username = body
                .get("username")
                .and_then(|v| v.as_str())
                .unwrap_or("guest");
            let password = body
                .get("password")
                .and_then(|v| v.as_str())
                .unwrap_or("guest");
            let full_endpoint = if endpoint.starts_with("amqp://") {
                endpoint.to_string()
            } else {
                format!("amqp://{}:{}@{}/", username, password, endpoint)
            };
            if let Ok(transport) =
                broker_connectors::rabbitmq::TcpRabbitTransport::new(&full_endpoint)
            {
                let config = broker_connectors::rabbitmq::RabbitMqSinkConfig {
                    endpoint: full_endpoint,
                    exchange: "amq.topic".to_string(),
                    routing_key_template: "sensor.${topic}".to_string(),
                    delivery_mode: 1,
                };
                if let Ok(sink) =
                    broker_connectors::rabbitmq::RabbitMqSink::new(config, Arc::new(transport))
                {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine
                        .connectors()
                        .register(format!("rabbitmq:{}", name), sink);
                }
            }
        }
        "clickhouse" => {
            let url = body
                .get("url")
                .and_then(|v| v.as_str())
                .or_else(|| body.get("server").and_then(|v| v.as_str()))
                .unwrap_or("http://127.0.0.1:8123");
            let endpoint = if url.starts_with("http://") || url.starts_with("https://") {
                url.to_string()
            } else {
                format!("http://{}", url)
            };
            let database = body
                .get("database")
                .and_then(|v| v.as_str())
                .unwrap_or("default");
            let table = body
                .get("table")
                .and_then(|v| v.as_str())
                .unwrap_or("test_mqtt_events");
            let request_timeout_ms = body
                .get("request_timeout_ms")
                .or_else(|| body.get("timeout_ms"))
                .or_else(|| body.get("timeout"))
                .and_then(|v| v.as_u64());
            let config = broker_connectors::clickhouse::ClickHouseSinkConfig {
                endpoint,
                database: database.to_string(),
                table: table.to_string(),
                format: "JSONEachRow".to_string(),
                batch_size: 1,
                batch_timeout_ms: 10,
                username: body
                    .get("username")
                    .or_else(|| body.get("user"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("default")
                    .to_string(),
                password: body
                    .get("password")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                request_timeout_ms,
            };
            if let Ok(driver) = broker_connectors::DriverClickHouseTransport::new(&config) {
                let transport: std::sync::Arc<dyn broker_connectors::ClickHouseTransport> =
                    std::sync::Arc::new(driver);
                if let Ok(sink) =
                    broker_connectors::clickhouse::ClickHouseSink::new(config, transport)
                {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine
                        .connectors()
                        .register(format!("clickhouse:{}", name), sink);
                }
            }
        }
        "mqtt_bridge" | "bridge" => {
            let server = body
                .get("server")
                .and_then(|v| v.as_str())
                .or_else(|| body.get("broker_address").and_then(|v| v.as_str()))
                .unwrap_or("127.0.0.1:1883");
            let client_id = body
                .get("client_id")
                .and_then(|v| v.as_str())
                .unwrap_or("indra-bridge");
            let username = body
                .get("username")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let password = body
                .get("password")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let config = broker_connectors::MqttBridgeSinkConfig {
                broker_address: server.to_string(),
                client_id: client_id.to_string(),
                clean_start: true,
                username,
                password,
                keep_alive_secs: 60,
                topic_prefix: None,
                topic_template: None,
                qos_override: None,
                retain_override: None,
                max_inflight: Some(1000),
                max_batch_size: Some(1),
                linger_ms: Some(10),
                protocol: broker_connectors::MqttBridgeProtocol::V311,
            };
            if let Ok(transport) = broker_connectors::TcpMqttBridgeTransport::new(&config) {
                if let Ok(sink) =
                    broker_connectors::MqttBridgeSink::new(config, Arc::new(transport))
                {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine
                        .connectors()
                        .register(format!("bridge:{}", name), sink.clone());
                    engine
                        .connectors()
                        .register(format!("mqtt_bridge:{}", name), sink);
                }
            }
        }
        "influxdb" => {
            let url = body
                .get("url")
                .and_then(|v| v.as_str())
                .or_else(|| body.get("server").and_then(|v| v.as_str()))
                .unwrap_or("http://127.0.0.1:8086");
            let endpoint = if url.starts_with("http://") || url.starts_with("https://") {
                url.to_string()
            } else {
                format!("http://{}", url)
            };
            let bucket = body
                .get("bucket")
                .and_then(|v| v.as_str())
                .unwrap_or("default");
            let org = body.get("org").and_then(|v| v.as_str()).unwrap_or("idacs");
            let token = body
                .get("token")
                .and_then(|v| v.as_str())
                .unwrap_or("idacs_test_token");
            let measurement = body
                .get("measurement")
                .and_then(|v| v.as_str())
                .or_else(|| body.get("measurement_template").and_then(|v| v.as_str()))
                .unwrap_or("mqtt_events");
            let request_timeout_ms = body
                .get("request_timeout_ms")
                .or_else(|| body.get("timeout_ms"))
                .or_else(|| body.get("timeout"))
                .and_then(|v| v.as_u64());
            let config = broker_connectors::InfluxDbSinkConfig {
                endpoint,
                bucket: bucket.to_string(),
                org: org.to_string(),
                token: token.to_string(),
                measurement_template: measurement.to_string(),
                precision: "ms".to_string(),
                batch_size: 1,
                batch_timeout_ms: 100,
                request_timeout_ms,
            };
            if let Ok(sink) = broker_connectors::InfluxDbSink::new(config, reqwest::Client::new()) {
                let sink = Arc::new(sink);
                engine.connectors().register(name, sink.clone());
                engine
                    .connectors()
                    .register(format!("influxdb:{}", name), sink);
            }
        }
        "mongodb" | "mongo" => {
            let server = body
                .get("server")
                .and_then(|v| v.as_str())
                .or_else(|| body.get("connection_string").and_then(|v| v.as_str()))
                .unwrap_or("127.0.0.1:27017");
            let conn_str =
                if server.starts_with("mongodb://") || server.starts_with("mongodb+srv://") {
                    server.to_string()
                } else {
                    format!("mongodb://{}", server)
                };
            let database = body
                .get("database")
                .and_then(|v| v.as_str())
                .unwrap_or("telemetry");
            let collection = body
                .get("collection")
                .and_then(|v| v.as_str())
                .or_else(|| body.get("collection_template").and_then(|v| v.as_str()))
                .unwrap_or("telemetry_${topic}");
            let timeout_ms = body
                .get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .or_else(|| body.get("request_timeout_ms"))
                .and_then(|v| v.as_u64());
            let config = broker_connectors::MongoDbSinkConfig {
                connection_string: conn_str,
                database: database.to_string(),
                collection_template: collection.to_string(),
                operation: broker_connectors::MongoOperation::InsertOne,
                batch_size: Some(1),
                batch_bytes: Some(4_194_304),
                linger_ms: Some(10),
                max_retries: Some(4),
                initial_backoff_ms: Some(100),
                max_backoff_ms: Some(3_000),
                timeout_ms,
            };
            if let Ok(transport) = broker_connectors::NativeMongoDbTransport::new(&config) {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::MongoDbSink::new(config, transport) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine
                        .connectors()
                        .register(format!("mongodb:{}", name), sink.clone());
                    engine
                        .connectors()
                        .register(format!("mongo:{}", name), sink);
                }
            }
        }
        "cassandra" | "scylla" | "scylladb" => {
            let server = body
                .get("server")
                .and_then(|v| v.as_str())
                .or_else(|| body.get("servers").and_then(|v| v.as_str()))
                .or_else(|| body.get("contact_points").and_then(|v| v.as_str()))
                .unwrap_or("127.0.0.1:9042");
            let contact_points: Vec<String> =
                server.split(',').map(|s| s.trim().to_string()).collect();
            let keyspace = body
                .get("keyspace")
                .and_then(|v| v.as_str())
                .unwrap_or("idacs");
            let table = body
                .get("table")
                .and_then(|v| v.as_str())
                .or_else(|| body.get("table_template").and_then(|v| v.as_str()))
                .unwrap_or("sensor_events");
            let username = body.get("username").and_then(|v| v.as_str());
            let password = body.get("password").and_then(|v| v.as_str());
            let auth = if let (Some(u), Some(p)) = (username, password) {
                broker_connectors::CassandraAuth::Password {
                    username: u.to_string(),
                    password: p.to_string(),
                }
            } else {
                broker_connectors::CassandraAuth::None
            };
            let timeout_ms = body
                .get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .or_else(|| body.get("request_timeout_ms"))
                .and_then(|v| v.as_u64());
            let cql = format!("INSERT INTO {}.{} (device_id, bucket_hour, event_time, payload) VALUES (?, ?, ?, ?)", keyspace, table);
            let config = broker_connectors::CassandraSinkConfig {
                contact_points,
                keyspace: keyspace.to_string(),
                table_template: table.to_string(),
                auth,
                consistency: broker_connectors::CqlConsistency::One,
                partition_key_template: "${client_id}".to_string(),
                cql_statement_template: cql,
                ttl_secs: None,
                batch_size: Some(1),
                batch_bytes: Some(1_048_576),
                linger_ms: Some(10),
                max_retries: Some(4),
                initial_backoff_ms: Some(100),
                max_backoff_ms: Some(2_000),
                timeout_ms,
            };
            if let Ok(transport) = broker_connectors::ScyllaCassandraTransport::new(&config) {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::CassandraSink::new(config, transport) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine
                        .connectors()
                        .register(format!("cassandra:{}", name), sink.clone());
                    engine
                        .connectors()
                        .register(format!("scylla:{}", name), sink);
                }
            }
        }
        "cockroachdb" | "cockroach" => {
            let conn_str = body
                .get("connection_string")
                .and_then(|v| v.as_str())
                .or_else(|| body.get("server").and_then(|v| v.as_str()))
                .or_else(|| body.get("url").and_then(|v| v.as_str()))
                .unwrap_or("postgresql://root@127.0.0.1:26257/idacs?sslmode=disable");
            let table = body
                .get("table")
                .and_then(|v| v.as_str())
                .unwrap_or("sensor_events");
            let timeout_ms = body
                .get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .or_else(|| body.get("request_timeout_ms"))
                .and_then(|v| v.as_u64());
            let config = broker_connectors::CockroachDbConfig {
                connection_string: conn_str.to_string(),
                table: table.to_string(),
                upsert_conflict_columns: Vec::new(),
                batch_size: Some(1),
                max_retry_attempts: 5,
                buffer_capacity: None,
                timeout_ms,
            };
            let transport = Arc::new(broker_connectors::PgDriverCockroachDbTransport::new(
                &config,
            ));
            if let Ok(sink) = broker_connectors::CockroachDbSink::new(config, transport) {
                let sink = Arc::new(sink);
                engine.connectors().register(name, sink.clone());
                engine
                    .connectors()
                    .register(format!("cockroachdb:{}", name), sink.clone());
                engine
                    .connectors()
                    .register(format!("cockroach:{}", name), sink);
            }
        }
        "couchbase" => {
            let server = body
                .get("server")
                .and_then(|v| v.as_str())
                .or_else(|| body.get("connection_string").and_then(|v| v.as_str()))
                .unwrap_or("couchbase://127.0.0.1:11210");
            let conn_str =
                if server.starts_with("couchbase://") || server.starts_with("couchbases://") {
                    server.to_string()
                } else {
                    format!("couchbase://{}", server)
                };
            let bucket = body
                .get("bucket")
                .and_then(|v| v.as_str())
                .unwrap_or("telemetry");
            let scope = body
                .get("scope")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let collection = body
                .get("collection")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let username = body
                .get("username")
                .and_then(|v| v.as_str())
                .unwrap_or("Administrator");
            let password = body
                .get("password")
                .and_then(|v| v.as_str())
                .unwrap_or("password");
            let timeout_ms = body
                .get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .or_else(|| body.get("request_timeout_ms"))
                .and_then(|v| v.as_u64());
            let config = broker_connectors::CouchbaseSinkConfig {
                connection_string: conn_str,
                bucket: bucket.to_string(),
                scope,
                collection,
                auth: broker_connectors::CouchbaseAuth {
                    username: username.to_string(),
                    password: password.to_string(),
                },
                doc_id_template: body
                    .get("doc_id_template")
                    .and_then(|v| v.as_str())
                    .unwrap_or("${client_id}::${timestamp}")
                    .to_string(),
                operation: broker_connectors::CouchbaseOperation::Upsert,
                expiry_secs: None,
                batch_size: Some(1),
                batch_bytes: Some(2_097_152),
                linger_ms: Some(10),
                max_retries: Some(3),
                initial_backoff_ms: Some(100),
                max_backoff_ms: Some(2_000),
                timeout_ms,
            };
            if let Ok(transport) = broker_connectors::NativeCouchbaseTransport::new(&config) {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::CouchbaseSink::new(config, transport) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine
                        .connectors()
                        .register(format!("couchbase:{}", name), sink);
                }
            }
        }
        "mssql" | "sqlserver" => {
            let server = body
                .get("server")
                .or_else(|| body.get("servers"))
                .or_else(|| body.get("host"))
                .and_then(|v| v.as_str())
                .unwrap_or("127.0.0.1:1433");
            let clean_server = server
                .split("://")
                .last()
                .unwrap_or(server)
                .split('/')
                .next()
                .unwrap_or(server);
            let (host, port) = if let Some((h, p)) = clean_server.split_once(':') {
                (h.to_string(), p.parse::<u16>().ok())
            } else {
                (clean_server.to_string(), None)
            };
            let database = body
                .get("database")
                .and_then(|v| v.as_str())
                .unwrap_or("telemetry");
            let table = body
                .get("table")
                .or_else(|| body.get("table_template"))
                .and_then(|v| v.as_str())
                .unwrap_or("dbo.SensorEvents");
            let username = body
                .get("username")
                .and_then(|v| v.as_str())
                .unwrap_or("sa");
            let password = body
                .get("password")
                .and_then(|v| v.as_str())
                .unwrap_or("secret");
            let timeout_ms = body
                .get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .or_else(|| body.get("request_timeout_ms"))
                .and_then(|v| v.as_u64());
            let config = broker_connectors::MssqlSinkConfig {
                host,
                port,
                database: database.to_string(),
                table_template: table.to_string(),
                auth: broker_connectors::MssqlAuth::SqlPassword {
                    username: username.to_string(),
                    password: password.to_string(),
                },
                query_mode: broker_connectors::MssqlQueryMode::InsertJson,
                trust_server_certificate: true,
                batch_size: Some(1),
                batch_bytes: Some(2_097_152),
                linger_ms: Some(10),
                max_retries: Some(3),
                initial_backoff_ms: Some(100),
                max_backoff_ms: Some(2_000),
                timeout_ms,
            };
            if let Ok(transport) = broker_connectors::NativeMssqlTransport::new(&config) {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::MssqlSink::new(config, transport) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine
                        .connectors()
                        .register(format!("mssql:{}", name), sink.clone());
                    engine
                        .connectors()
                        .register(format!("sqlserver:{}", name), sink);
                }
            }
        }
        "oracle" => {
            let url = body
                .get("url")
                .and_then(|v| v.as_str())
                .or_else(|| body.get("server").and_then(|v| v.as_str()))
                .unwrap_or("http://127.0.0.1:8080/ords/hr/_/sql");
            let schema = body.get("schema").and_then(|v| v.as_str()).unwrap_or("HR");
            let table = body
                .get("table")
                .and_then(|v| v.as_str())
                .unwrap_or("TELEMETRY");
            let username = body
                .get("username")
                .and_then(|v| v.as_str())
                .unwrap_or("c##appuser");
            let password = body
                .get("password")
                .and_then(|v| v.as_str())
                .unwrap_or("password");
            let timeout_ms = body
                .get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .or_else(|| body.get("request_timeout_ms"))
                .and_then(|v| v.as_u64());
            let config = broker_connectors::oracle::OracleSinkConfig {
                url: url.to_string(),
                schema: schema.to_string(),
                table: table.to_string(),
                username: username.to_string(),
                password: password.to_string(),
                custom_upsert: None,
                key_columns: vec!["device_id".to_string(), "client_id".to_string()],
                batch_size: Some(1),
                buffer_capacity: None,
                timeout_ms,
            };
            let transport = Arc::new(broker_connectors::oracle::HttpOracleTransport::new(&config));
            if let Ok(sink) = broker_connectors::oracle::OracleSink::new(config, transport) {
                let sink = Arc::new(sink);
                engine.connectors().register(name, sink.clone());
                engine
                    .connectors()
                    .register(format!("oracle:{}", name), sink);
            }
        }
        "tdengine" => {
            let server = body
                .get("server")
                .or_else(|| body.get("servers"))
                .or_else(|| body.get("url"))
                .or_else(|| body.get("endpoint"))
                .and_then(|v| v.as_str())
                .unwrap_or("http://127.0.0.1:6041/rest/sql");
            let endpoint = if server.starts_with("http://") || server.starts_with("https://") {
                server.to_string()
            } else {
                format!("http://{}", server)
            };
            let database = body
                .get("database")
                .and_then(|v| v.as_str())
                .unwrap_or("power");
            let stable = body
                .get("stable_name")
                .or_else(|| body.get("table"))
                .and_then(|v| v.as_str())
                .unwrap_or("meters");
            let subtable = body
                .get("subtable_template")
                .or_else(|| body.get("subtable"))
                .and_then(|v| v.as_str())
                .unwrap_or("d_meters");
            let username = body
                .get("username")
                .and_then(|v| v.as_str())
                .unwrap_or("root");
            let password = body
                .get("password")
                .and_then(|v| v.as_str())
                .unwrap_or("taosdata");
            let timeout_ms = body
                .get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .or_else(|| body.get("request_timeout_ms"))
                .and_then(|v| v.as_u64());

            let mut metrics_template = std::collections::HashMap::new();
            metrics_template.insert("temp".to_string(), "${payload.temperature}".to_string());
            let mut tags_template = std::collections::HashMap::new();
            tags_template.insert("location".to_string(), "room1".to_string());

            let config = broker_connectors::tdengine::TdengineSinkConfig {
                endpoint,
                database: database.to_string(),
                stable_name: stable.to_string(),
                subtable_template: subtable.to_string(),
                auth: broker_connectors::tdengine::TdengineAuth::Basic {
                    username: username.to_string(),
                    password: password.to_string(),
                },
                tags_template,
                metrics_template,
                batch_size: Some(1),
                batch_bytes: Some(1_048_576),
                linger_ms: Some(10),
                max_retries: Some(3),
                initial_backoff_ms: Some(100),
                max_backoff_ms: Some(2_000),
                timeout_ms,
            };
            let client = reqwest::Client::builder()
                .timeout(config.timeout())
                .build()
                .unwrap_or_default();
            if let Ok(transport) =
                broker_connectors::tdengine::HttpTdengineTransport::new(&config, client)
            {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::tdengine::TdengineSink::new(config, transport)
                {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine
                        .connectors()
                        .register(format!("tdengine:{}", name), sink);
                }
            }
        }
        "greptimedb" | "greptime" => {
            let server = body
                .get("endpoint")
                .or_else(|| body.get("server"))
                .or_else(|| body.get("servers"))
                .or_else(|| body.get("url"))
                .and_then(|v| v.as_str())
                .unwrap_or("http://127.0.0.1:4000/v1");
            let endpoint = if server.starts_with("http://") || server.starts_with("https://") {
                server.to_string()
            } else {
                format!("http://{}", server)
            };
            let database = body
                .get("database")
                .and_then(|v| v.as_str())
                .unwrap_or("public");
            let table = body
                .get("table")
                .or_else(|| body.get("table_template"))
                .and_then(|v| v.as_str())
                .unwrap_or("sensor_events");
            let username = body.get("username").and_then(|v| v.as_str());
            let password = body.get("password").and_then(|v| v.as_str());
            let auth = if let (Some(u), Some(p)) = (username, password) {
                Some(broker_connectors::greptimedb::GreptimeDbAuth {
                    username: u.to_string(),
                    password: p.to_string(),
                })
            } else {
                None
            };
            let timeout_ms = body
                .get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .or_else(|| body.get("request_timeout_ms"))
                .and_then(|v| v.as_u64());
            let config = broker_connectors::greptimedb::GreptimeDbConfig {
                endpoint,
                database: database.to_string(),
                auth,
                format: broker_connectors::greptimedb::GreptimeFormat::SqlInsert,
                table_template: table.to_string(),
                timestamp_precision: broker_connectors::greptimedb::GreptimePrecision::Millisecond,
                batch_size: Some(1),
                buffer_capacity: None,
                timeout_ms,
            };
            let transport = Arc::new(broker_connectors::greptimedb::HttpGreptimeDbTransport::new(
                &config,
            ));
            if let Ok(sink) = broker_connectors::greptimedb::GreptimeDbSink::new(config, transport)
            {
                let sink = Arc::new(sink);
                engine.connectors().register(name, sink.clone());
                engine
                    .connectors()
                    .register(format!("greptimedb:{}", name), sink.clone());
                engine
                    .connectors()
                    .register(format!("greptime:{}", name), sink);
            }
        }
        "iotdb" => {
            let server = body
                .get("endpoint")
                .or_else(|| body.get("server"))
                .or_else(|| body.get("servers"))
                .or_else(|| body.get("url"))
                .and_then(|v| v.as_str())
                .unwrap_or("http://127.0.0.1:6667/rest/v2");
            let endpoint = if server.starts_with("http://") || server.starts_with("https://") {
                server.to_string()
            } else {
                format!("http://{}", server)
            };
            let device_path = body
                .get("device_path_template")
                .or_else(|| body.get("device_path"))
                .and_then(|v| v.as_str())
                .unwrap_or("root.factory.${payload.plant_id}.${client_id}");
            let username = body
                .get("username")
                .and_then(|v| v.as_str())
                .unwrap_or("root");
            let password = body
                .get("password")
                .and_then(|v| v.as_str())
                .unwrap_or("root");
            let timeout_ms = body
                .get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .or_else(|| body.get("request_timeout_ms"))
                .and_then(|v| v.as_u64());

            let config = broker_connectors::iotdb::IotDbSinkConfig {
                endpoint,
                device_path_template: device_path.to_string(),
                auth: broker_connectors::iotdb::IotDbAuth {
                    username: username.to_string(),
                    password: password.to_string(),
                },
                is_aligned: false,
                measurements: vec!["temperature".to_string()],
                data_types: vec![broker_connectors::iotdb::IotDbDataType::Float],
                batch_size: Some(1),
                batch_bytes: Some(2_097_152),
                linger_ms: Some(10),
                max_retries: Some(3),
                initial_backoff_ms: Some(100),
                max_backoff_ms: Some(2_000),
                timeout_ms,
            };
            let client = reqwest::Client::builder()
                .timeout(config.timeout())
                .build()
                .unwrap_or_default();
            if let Ok(transport) =
                broker_connectors::iotdb::HttpIotDbTransport::new(&config, client)
            {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::iotdb::IotDbSink::new(config, transport) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine
                        .connectors()
                        .register(format!("iotdb:{}", name), sink);
                }
            }
        }
        "opentsdb" => {
            let server = body
                .get("endpoint")
                .or_else(|| body.get("server"))
                .or_else(|| body.get("servers"))
                .or_else(|| body.get("url"))
                .and_then(|v| v.as_str())
                .unwrap_or("http://127.0.0.1:4242");
            let endpoint = if server.starts_with("http://")
                || server.starts_with("https://")
                || server.starts_with("telnet://")
            {
                server.to_string()
            } else {
                format!("http://{}", server)
            };
            let metric_template = body
                .get("metric_template")
                .or_else(|| body.get("metric"))
                .and_then(|v| v.as_str())
                .unwrap_or("factory.telemetry");
            let value_field = body
                .get("value_field")
                .or_else(|| body.get("value"))
                .and_then(|v| v.as_str())
                .unwrap_or("temperature");
            let summary = body
                .get("summary")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let timeout_ms = body
                .get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .or_else(|| body.get("request_timeout_ms"))
                .and_then(|v| v.as_u64());

            let mut tag_mappings = std::collections::HashMap::new();
            if let Some(tags) = body
                .get("tag_mappings")
                .or_else(|| body.get("tags"))
                .and_then(|v| v.as_object())
            {
                for (k, v) in tags {
                    if let Some(s) = v.as_str() {
                        tag_mappings.insert(k.clone(), s.to_string());
                    }
                }
            } else {
                tag_mappings.insert("sensor".to_string(), "${payload.sensor}".to_string());
            }

            let config = broker_connectors::opentsdb::OpenTsdbConfig {
                endpoint,
                protocol: broker_connectors::opentsdb::OpenTsdbProtocol::Http,
                metric_template: metric_template.to_string(),
                tag_mappings,
                value_field: value_field.to_string(),
                summary,
                compression: broker_connectors::opentsdb::OpenTsdbCompression::None,
                batch_size: Some(1),
                buffer_capacity: None,
                timeout_ms,
            };
            let transport = Arc::new(broker_connectors::opentsdb::NetworkOpenTsdbTransport::new(
                &config,
            ));
            if let Ok(sink) = broker_connectors::opentsdb::OpenTsdbSink::new(config, transport) {
                let sink = Arc::new(sink);
                engine.connectors().register(name, sink.clone());
                engine
                    .connectors()
                    .register(format!("opentsdb:{}", name), sink);
            }
        }
        "doris" => {
            let server = body
                .get("server")
                .or_else(|| body.get("fe_host"))
                .or_else(|| body.get("host"))
                .or_else(|| body.get("endpoint"))
                .and_then(|v| v.as_str())
                .unwrap_or("127.0.0.1");
            let fe_host = server
                .trim_start_matches("http://")
                .trim_start_matches("https://")
                .split(':')
                .next()
                .unwrap_or("127.0.0.1")
                .to_string();
            let http_port = body
                .get("http_port")
                .or_else(|| body.get("port"))
                .and_then(|v| v.as_u64())
                .unwrap_or(8030) as u16;
            let database = body
                .get("database")
                .and_then(|v| v.as_str())
                .unwrap_or("telemetry")
                .to_string();
            let table = body
                .get("table_template")
                .or_else(|| body.get("table"))
                .and_then(|v| v.as_str())
                .unwrap_or("events")
                .to_string();
            let username = body
                .get("username")
                .and_then(|v| v.as_str())
                .unwrap_or("root")
                .to_string();
            let password = body
                .get("password")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let timeout_ms = body
                .get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .or_else(|| body.get("request_timeout_ms"))
                .and_then(|v| v.as_u64());

            let config = broker_connectors::doris::DorisSinkConfig {
                fe_host,
                http_port,
                database,
                table_template: table,
                auth: broker_connectors::doris::DorisAuth { username, password },
                format: broker_connectors::doris::DorisFormat::Json,
                jsonpaths: None,
                strip_outer_array: true,
                max_filter_ratio: Some(0.0),
                batch_size: Some(1),
                batch_bytes: Some(4_194_304),
                linger_ms: Some(10),
                max_retries: Some(3),
                initial_backoff_ms: Some(100),
                max_backoff_ms: Some(2_000),
                timeout_ms,
            };
            let client = reqwest::Client::builder()
                .timeout(config.timeout())
                .build()
                .unwrap_or_default();
            if let Ok(transport) =
                broker_connectors::doris::HttpDorisTransport::new(&config, client)
            {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::doris::DorisSink::new(config, transport) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine
                        .connectors()
                        .register(format!("doris:{}", name), sink);
                }
            }
        }
        "datalayers" => {
            let server = body
                .get("endpoint")
                .or_else(|| body.get("server"))
                .or_else(|| body.get("servers"))
                .or_else(|| body.get("url"))
                .and_then(|v| v.as_str())
                .unwrap_or("http://127.0.0.1:8360");
            let endpoint = if server.starts_with("http://") || server.starts_with("https://") {
                server.to_string()
            } else {
                format!("http://{}", server)
            };
            let database = body
                .get("database")
                .and_then(|v| v.as_str())
                .unwrap_or("factory_db")
                .to_string();
            let table = body
                .get("table")
                .or_else(|| body.get("measurement"))
                .and_then(|v| v.as_str())
                .unwrap_or("sensor_events")
                .to_string();
            let auth_token = body
                .get("auth_token")
                .or_else(|| body.get("token"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let timeout_ms = body
                .get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .or_else(|| body.get("request_timeout_ms"))
                .and_then(|v| v.as_u64());

            let config = broker_connectors::datalayers::DatalayersConfig {
                endpoint,
                database,
                table,
                auth_token,
                timestamp_field: Some("timestamp".to_string()),
                tag_columns: vec!["sensor".to_string(), "client_id".to_string()],
                field_columns: vec!["temperature".to_string()],
                batch_size: Some(1),
                buffer_capacity: None,
                timeout_ms,
            };
            let transport = Arc::new(broker_connectors::datalayers::HttpDatalayersTransport::new(
                &config,
            ));
            if let Ok(sink) = broker_connectors::datalayers::DatalayersSink::new(config, transport)
            {
                let sink = Arc::new(sink);
                engine.connectors().register(name, sink.clone());
                engine
                    .connectors()
                    .register(format!("datalayers:{}", name), sink);
            }
        }
        "elasticsearch" | "opensearch" => {
            let server = body
                .get("endpoint")
                .or_else(|| body.get("server"))
                .or_else(|| body.get("servers"))
                .or_else(|| body.get("url"))
                .and_then(|v| v.as_str())
                .unwrap_or("http://127.0.0.1:9200");
            let endpoint = if server.starts_with("http://") || server.starts_with("https://") {
                server.to_string()
            } else {
                format!("http://{}", server)
            };
            let index = body
                .get("index_template")
                .or_else(|| body.get("index"))
                .and_then(|v| v.as_str())
                .unwrap_or("sensor_events")
                .to_string();
            let username = body.get("username").and_then(|v| v.as_str());
            let password = body.get("password").and_then(|v| v.as_str());
            let auth = if let (Some(u), Some(p)) = (username, password) {
                broker_connectors::elasticsearch::ElasticsearchAuth::Basic {
                    username: u.to_string(),
                    password: p.to_string(),
                }
            } else {
                broker_connectors::elasticsearch::ElasticsearchAuth::None
            };
            let timeout_ms = body
                .get("request_timeout_ms")
                .or_else(|| body.get("timeout_ms"))
                .or_else(|| body.get("timeout"))
                .and_then(|v| v.as_u64());

            let config = broker_connectors::elasticsearch::ElasticsearchSinkConfig {
                endpoint,
                index_template: index,
                doc_id_template: None,
                auth,
                batch_size: 1,
                batch_timeout_ms: 10,
                max_retries: 3,
                request_timeout_ms: timeout_ms,
            };
            let client = reqwest::Client::builder()
                .timeout(config.timeout())
                .build()
                .unwrap_or_default();
            if let Ok(transport) =
                broker_connectors::elasticsearch::HttpElasticsearchTransport::new(&config, client)
            {
                let transport = Arc::new(transport);
                if let Ok(sink) =
                    broker_connectors::elasticsearch::ElasticsearchSink::new(config, transport)
                {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine
                        .connectors()
                        .register(format!("elasticsearch:{}", name), sink.clone());
                    engine
                        .connectors()
                        .register(format!("opensearch:{}", name), sink);
                }
            }
        }
        "pulsar" => {
            let server = body
                .get("service_url")
                .or_else(|| body.get("server"))
                .or_else(|| body.get("servers"))
                .or_else(|| body.get("endpoint"))
                .and_then(|v| v.as_str())
                .unwrap_or("pulsar://127.0.0.1:6650");
            let service_url = if server.starts_with("pulsar://")
                || server.starts_with("http://")
                || server.starts_with("https://")
            {
                server.to_string()
            } else {
                format!("pulsar://{}", server)
            };
            let topic = body
                .get("topic")
                .or_else(|| body.get("topic_template"))
                .and_then(|v| v.as_str())
                .unwrap_or("persistent://public/default/telemetry")
                .to_string();
            let tenant = body
                .get("tenant")
                .and_then(|v| v.as_str())
                .unwrap_or("public")
                .to_string();
            let namespace = body
                .get("namespace")
                .and_then(|v| v.as_str())
                .unwrap_or("default")
                .to_string();
            let token = body.get("token").and_then(|v| v.as_str());
            let auth = if let Some(t) = token {
                broker_connectors::pulsar::PulsarAuth::Token {
                    token: t.to_string(),
                }
            } else {
                broker_connectors::pulsar::PulsarAuth::None
            };
            let timeout_ms = body
                .get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .or_else(|| body.get("request_timeout_ms"))
                .and_then(|v| v.as_u64());

            let config = broker_connectors::pulsar::PulsarSinkConfig {
                service_url,
                tenant,
                namespace,
                topic,
                auth,
                partition_key_template: Some("${client_id}".to_string()),
                properties: std::collections::HashMap::new(),
                batch_size: Some(1),
                batch_bytes: Some(2_097_152),
                linger_ms: Some(10),
                max_retries: Some(3),
                initial_backoff_ms: Some(100),
                max_backoff_ms: Some(2_000),
                timeout_ms,
            };
            if let Ok(transport) = broker_connectors::pulsar::TcpPulsarTransport::new(&config) {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::pulsar::PulsarSink::new(config, transport) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine
                        .connectors()
                        .register(format!("pulsar:{}", name), sink);
                }
            }
        }
        "rocketmq" => {
            let server = body
                .get("endpoint")
                .or_else(|| body.get("endpoints"))
                .or_else(|| body.get("server"))
                .or_else(|| body.get("servers"))
                .and_then(|v| v.as_str())
                .unwrap_or("127.0.0.1:9876");
            let endpoint = server
                .trim_start_matches("http://")
                .trim_start_matches("tcp://")
                .to_string();
            let topic = body
                .get("topic")
                .and_then(|v| v.as_str())
                .unwrap_or("rocket-telemetry")
                .to_string();
            let access_key = body
                .get("access_key")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let secret_key = body
                .get("secret_key")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let timeout_ms = body
                .get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .or_else(|| body.get("request_timeout_ms"))
                .and_then(|v| v.as_u64());

            let config = broker_connectors::rocketmq::RocketMqSinkConfig {
                endpoints: vec![endpoint],
                topic,
                tag_template: None,
                keys_template: Some("${client_id}".to_string()),
                message_group_template: None,
                access_key,
                secret_key,
                batch_size: Some(1),
                buffer_capacity: None,
                linger_ms: Some(10),
                timeout_ms,
            };
            if let Ok(transport) = broker_connectors::rocketmq::TcpRocketMqTransport::new(&config) {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::rocketmq::RocketMqSink::new(config, transport)
                {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine
                        .connectors()
                        .register(format!("rocketmq:{}", name), sink);
                }
            }
        }
        "confluent" => {
            let server = body
                .get("bootstrap_servers")
                .or_else(|| body.get("bootstrap_hosts"))
                .or_else(|| body.get("server"))
                .or_else(|| body.get("servers"))
                .and_then(|v| v.as_str())
                .unwrap_or("127.0.0.1:9092");
            let bootstrap = server
                .trim_start_matches("http://")
                .trim_start_matches("tcp://")
                .to_string();
            let topic = body
                .get("topic_template")
                .or_else(|| body.get("topic"))
                .and_then(|v| v.as_str())
                .unwrap_or("telemetry-events")
                .to_string();
            // Fail closed (S1-01): API key and secret are operator-supplied;
            // the previous built-in placeholders are removed.
            let Some(api_key) = body
                .get("api_key")
                .or_else(|| body.get("username"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            else {
                return;
            };
            let Some(api_secret) = body
                .get("api_secret")
                .or_else(|| body.get("password"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            else {
                return;
            };
            let timeout_ms = body
                .get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .or_else(|| body.get("request_timeout_ms"))
                .and_then(|v| v.as_u64());

            let config = broker_connectors::confluent::ConfluentKafkaConfig {
                bootstrap_servers: vec![bootstrap],
                api_key: api_key.to_string(),
                api_secret: api_secret.to_string(),
                auth_mechanism: broker_connectors::confluent::SaslMechanism::Plain,
                topic_template: topic,
                partition_key_template: Some("${client_id}".to_string()),
                schema_registry: None,
                partitions: 1,
                batch_size: Some(1),
                buffer_capacity: None,
                timeout_ms,
            };
            if let Ok(transport) =
                broker_connectors::confluent::RdkafkaConfluentTransport::new(&config)
            {
                let transport = Arc::new(transport);
                if let Ok(sink) =
                    broker_connectors::confluent::ConfluentKafkaSink::new(config, transport)
                {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine
                        .connectors()
                        .register(format!("confluent:{}", name), sink);
                }
            }
        }
        "disk_log" | "disk" | "disklog" => {
            let dir = body
                .get("directory")
                .or_else(|| body.get("dir"))
                .or_else(|| body.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("./target/disk_logs");
            let prefix = body
                .get("filename_prefix")
                .or_else(|| body.get("prefix"))
                .and_then(|v| v.as_str())
                .unwrap_or("indra");
            let ext = body
                .get("filename_extension")
                .or_else(|| body.get("extension"))
                .and_then(|v| v.as_str())
                .unwrap_or("log");
            let timeout_ms = body
                .get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .or_else(|| body.get("request_timeout_ms"))
                .and_then(|v| v.as_u64());
            let config = broker_connectors::disk_log::DiskLogSinkConfig {
                directory: dir.to_string(),
                filename_prefix: prefix.to_string(),
                filename_extension: ext.to_string(),
                format: broker_connectors::disk_log::DiskLogFormat::Ndjson,
                max_file_size_bytes: None,
                max_file_age_secs: None,
                compression: broker_connectors::disk_log::DiskLogCompression::None,
                max_backup_files: None,
                max_retention_days: None,
                sync_mode: broker_connectors::disk_log::DiskSyncMode::EveryBatch,
                timeout_ms,
            };
            if let Ok(writer) = broker_connectors::disk_log::FileDiskLogWriter::open(&config).await
            {
                if let Ok(sink) =
                    broker_connectors::disk_log::DiskLogSink::new(config, Arc::new(writer))
                {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine
                        .connectors()
                        .register(format!("disk_log:{}", name), sink.clone());
                    engine.connectors().register(format!("disk:{}", name), sink);
                }
            }
        }
        "opc_ua" | "opcua" => {
            let endpoint_url = body
                .get("endpoint_url")
                .or_else(|| body.get("server"))
                .or_else(|| body.get("url"))
                .or_else(|| body.get("endpoint"))
                .and_then(|v| v.as_str())
                .unwrap_or("opc.tcp://127.0.0.1:4840");
            let endpoint_url = if endpoint_url.starts_with("opc.tcp://") {
                endpoint_url.to_string()
            } else {
                format!("opc.tcp://{}", endpoint_url.trim_start_matches("tcp://"))
            };
            let node_id = body
                .get("node_id")
                .and_then(|v| v.as_str())
                .unwrap_or("ns=1;i=1001");
            let timeout_ms = body
                .get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .or_else(|| body.get("request_timeout_ms"))
                .and_then(|v| v.as_u64());

            let config = broker_connectors::opc_ua::OpcUaSinkConfig {
                endpoint_url,
                security_policy: broker_connectors::opc_ua::OpcUaSecurityPolicy::None,
                security_mode: broker_connectors::opc_ua::OpcUaSecurityMode::None,
                auth: broker_connectors::opc_ua::OpcUaAuth::Anonymous,
                node_subscriptions: vec![broker_connectors::opc_ua::NodeSubscriptionConfig {
                    node_id: node_id.to_string(),
                    sampling_interval_ms: 1000,
                    publish_topic_template: "opcua/${node.sanitized_id}".to_string(),
                    write_topic_pattern: Some("#".to_string()),
                }],
                buffer_capacity: None,
                batch_size: Some(1),
                linger_ms: Some(10),
                timeout_ms,
            };
            if let Ok(transport) = broker_connectors::opc_ua::TcpOpcUaTransport::new(&config) {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::opc_ua::OpcUaSink::new(config, transport) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine
                        .connectors()
                        .register(format!("opc_ua:{}", name), sink.clone());
                    engine
                        .connectors()
                        .register(format!("opcua:{}", name), sink);
                }
            }
        }
        "sparkplug_b" | "sparkplug" => {
            let topic_prefix = body
                .get("topic_prefix")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let timeout_ms = body
                .get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .or_else(|| body.get("request_timeout_ms"))
                .and_then(|v| v.as_u64());

            let config = broker_connectors::sparkplug_b::SparkplugSinkConfig {
                topic_prefix,
                tier: broker_connectors::sparkplug_b::SPARKPLUG_TIER.to_string(),
                batch_size: Some(1),
                linger_ms: Some(10),
                timeout_ms,
            };
            let transport =
                Arc::new(broker_connectors::sparkplug_b::MemorySparkplugTransport::new());
            if let Ok(sink) = broker_connectors::sparkplug_b::SparkplugBSink::new(config, transport)
            {
                let sink = Arc::new(sink);
                engine.connectors().register(name, sink.clone());
                engine
                    .connectors()
                    .register(format!("sparkplug_b:{}", name), sink.clone());
                engine
                    .connectors()
                    .register(format!("sparkplug:{}", name), sink);
            }
        }
        "s3" | "minio" => {
            let endpoint = body
                .get("endpoint")
                .or_else(|| body.get("url"))
                .or_else(|| body.get("server"))
                .and_then(|v| v.as_str())
                .unwrap_or("http://127.0.0.1:9000");
            let bucket = body
                .get("bucket")
                .and_then(|v| v.as_str())
                .unwrap_or("telemetry");
            let region = body
                .get("region")
                .and_then(|v| v.as_str())
                .unwrap_or("us-east-1");
            let access_key_id = body
                .get("access_key_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let secret_access_key = body
                .get("secret_access_key")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let key_template = body
                .get("key_template")
                .and_then(|v| v.as_str())
                .unwrap_or("telemetry/${topic}_${seq}.ndjson");
            let timeout_ms = body
                .get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .or_else(|| body.get("request_timeout_ms"))
                .and_then(|v| v.as_u64());

            let config = broker_connectors::s3::S3SinkConfig {
                endpoint: endpoint.to_string(),
                bucket: bucket.to_string(),
                region: region.to_string(),
                access_key_id: access_key_id.to_string(),
                secret_access_key: secret_access_key.to_string(),
                key_template: key_template.to_string(),
                compression: broker_connectors::s3::S3Compression::None,
                batch_size: 1,
                batch_bytes: 5 * 1024 * 1024,
                batch_timeout_ms: 10,
                timeout_ms,
            };
            if let Ok(transport) =
                broker_connectors::s3::HttpS3Transport::new(&config, reqwest::Client::new())
            {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::s3::S3Sink::new(config, transport) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine
                        .connectors()
                        .register(format!("s3:{}", name), sink.clone());
                    engine
                        .connectors()
                        .register(format!("minio:{}", name), sink);
                }
            }
        }
        "s3_tables" | "s3tables" => {
            let arn = body
                .get("table_bucket_arn")
                .or_else(|| body.get("bucket_arn"))
                .or_else(|| body.get("arn"))
                .and_then(|v| v.as_str())
                .unwrap_or("arn:aws:s3tables:us-east-1:123456789012:bucket/telemetry");
            let namespace = body
                .get("namespace")
                .and_then(|v| v.as_str())
                .unwrap_or("production_iot");
            let table = body
                .get("table_name")
                .or_else(|| body.get("table"))
                .and_then(|v| v.as_str())
                .unwrap_or("device_events");
            let region = body
                .get("region")
                .and_then(|v| v.as_str())
                .unwrap_or("us-east-1");
            let access_key = body
                .get("access_key_id")
                .and_then(|v| v.as_str())
                .unwrap_or("test");
            let secret_key = body
                .get("secret_access_key")
                .and_then(|v| v.as_str())
                .unwrap_or("test");
            let endpoint = body
                .get("endpoint")
                .or_else(|| body.get("url"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let timeout_ms = body
                .get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .or_else(|| body.get("request_timeout_ms"))
                .and_then(|v| v.as_u64());

            let config = broker_connectors::s3_tables::S3TablesSinkConfig {
                table_bucket_arn: arn.to_string(),
                namespace: namespace.to_string(),
                table_name: table.to_string(),
                region: region.to_string(),
                access_key_id: access_key.to_string(),
                secret_access_key: secret_key.to_string(),
                session_token: None,
                endpoint,
                target_format: broker_connectors::s3_tables::S3TablesFormat::NdjsonCompressed,
                partition_spec: Vec::new(),
                batch_size: Some(1),
                buffer_capacity: None,
                linger_ms: Some(10),
                timeout_ms,
            };
            if let Ok(transport) = broker_connectors::s3_tables::HttpS3TablesTransport::new(
                &config,
                reqwest::Client::new(),
            ) {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::s3_tables::S3TablesSink::new(config, transport)
                {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine
                        .connectors()
                        .register(format!("s3_tables:{}", name), sink.clone());
                    engine
                        .connectors()
                        .register(format!("s3tables:{}", name), sink);
                }
            }
        }
        "kinesis" | "aws_kinesis" => {
            let stream = body
                .get("stream_name")
                .or_else(|| body.get("stream"))
                .and_then(|v| v.as_str())
                .unwrap_or("telemetry-stream");
            let region = body
                .get("region")
                .and_then(|v| v.as_str())
                .unwrap_or("us-east-1");
            let endpoint = body
                .get("endpoint")
                .or_else(|| body.get("url"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let access_key = body
                .get("access_key_id")
                .and_then(|v| v.as_str())
                .unwrap_or("test");
            let secret_key = body
                .get("secret_access_key")
                .and_then(|v| v.as_str())
                .unwrap_or("test");
            let timeout_ms = body
                .get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .or_else(|| body.get("request_timeout_ms"))
                .and_then(|v| v.as_u64());

            let config = broker_connectors::kinesis::KinesisSinkConfig {
                stream_name: stream.to_string(),
                region: region.to_string(),
                endpoint,
                access_key_id: access_key.to_string(),
                secret_access_key: secret_key.to_string(),
                session_token: None,
                partition_key_template: Some("${topic}".to_string()),
                explicit_hash_key: None,
                batch_size: Some(1),
                batch_bytes: Some(4_194_304),
                linger_ms: Some(10),
                max_retries: Some(3),
                initial_backoff_ms: Some(100),
                max_backoff_ms: Some(2_000),
                timeout_ms,
            };
            if let Ok(transport) = broker_connectors::kinesis::HttpKinesisTransport::new(
                &config,
                reqwest::Client::new(),
            ) {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::kinesis::KinesisSink::new(config, transport) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine
                        .connectors()
                        .register(format!("kinesis:{}", name), sink);
                }
            }
        }
        "dynamodb" | "dynamo" => {
            let table = body
                .get("table_name")
                .or_else(|| body.get("table"))
                .and_then(|v| v.as_str())
                .unwrap_or("sensor_events");
            let region = body
                .get("region")
                .and_then(|v| v.as_str())
                .unwrap_or("us-east-1");
            let endpoint = body
                .get("endpoint")
                .or_else(|| body.get("url"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let access_key = body
                .get("access_key_id")
                .and_then(|v| v.as_str())
                .unwrap_or("test");
            let secret_key = body
                .get("secret_access_key")
                .and_then(|v| v.as_str())
                .unwrap_or("test");
            let partition_key_name = body
                .get("partition_key")
                .and_then(|v| v.as_str())
                .unwrap_or("id");
            let timeout_ms = body
                .get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .or_else(|| body.get("request_timeout_ms"))
                .and_then(|v| v.as_u64());

            let config = broker_connectors::dynamodb::DynamoDbSinkConfig {
                table_name: table.to_string(),
                region: region.to_string(),
                endpoint,
                access_key_id: access_key.to_string(),
                secret_access_key: secret_key.to_string(),
                session_token: None,
                partition_key: broker_connectors::dynamodb::DynamoKeyConfig {
                    name: partition_key_name.to_string(),
                    template: "${timestamp}".to_string(),
                    key_type: "S".to_string(),
                },
                sort_key: None,
                ttl_attribute: None,
                ttl_secs: None,
                attributes_mapping: std::collections::HashMap::new(),
                batch_size: Some(1),
                batch_bytes: Some(1_048_576),
                linger_ms: Some(10),
                max_retries: Some(3),
                initial_backoff_ms: Some(100),
                max_backoff_ms: Some(2_000),
                timeout_ms,
            };
            if let Ok(transport) = broker_connectors::dynamodb::HttpDynamoDbTransport::new(
                &config,
                reqwest::Client::new(),
            ) {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::dynamodb::DynamoDbSink::new(config, transport)
                {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine
                        .connectors()
                        .register(format!("dynamodb:{}", name), sink);
                }
            }
        }
        "timestream" => {
            let database = body
                .get("database_name")
                .or_else(|| body.get("database"))
                .and_then(|v| v.as_str())
                .unwrap_or("telemetry_db");
            let table = body
                .get("table_name")
                .or_else(|| body.get("table"))
                .and_then(|v| v.as_str())
                .unwrap_or("metrics");
            let region = body
                .get("region")
                .and_then(|v| v.as_str())
                .unwrap_or("us-east-1");
            let endpoint = body
                .get("endpoint")
                .or_else(|| body.get("url"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let access_key = body
                .get("access_key_id")
                .and_then(|v| v.as_str())
                .unwrap_or("test");
            let secret_key = body
                .get("secret_access_key")
                .and_then(|v| v.as_str())
                .unwrap_or("test");
            let timeout_ms = body
                .get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .or_else(|| body.get("request_timeout_ms"))
                .and_then(|v| v.as_u64());

            let mut dimensions = std::collections::HashMap::new();
            dimensions.insert("device".to_string(), "${client_id}".to_string());
            let mut measures = std::collections::HashMap::new();
            measures.insert("temperature".to_string(), "DOUBLE".to_string());

            let config = broker_connectors::timestream::TimestreamSinkConfig {
                database_name: database.to_string(),
                table_name: table.to_string(),
                region: region.to_string(),
                endpoint,
                access_key_id: access_key.to_string(),
                secret_access_key: secret_key.to_string(),
                session_token: None,
                time_unit: broker_connectors::timestream::TimestreamTimeUnit::Milliseconds,
                measure_name_template: Some("${topic}".to_string()),
                dimensions,
                multi_measure_mappings: measures,
                batch_size: Some(1),
                batch_bytes: Some(1_048_576),
                linger_ms: Some(10),
                max_retries: Some(3),
                initial_backoff_ms: Some(100),
                max_backoff_ms: Some(2_000),
                timeout_ms,
            };
            if let Ok(transport) = broker_connectors::timestream::HttpTimestreamTransport::new(
                &config,
                reqwest::Client::new(),
            ) {
                let transport = Arc::new(transport);
                if let Ok(sink) =
                    broker_connectors::timestream::TimestreamSink::new(config, transport)
                {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine
                        .connectors()
                        .register(format!("timestream:{}", name), sink);
                }
            }
        }
        "redshift" => {
            let database = body
                .get("database")
                .and_then(|v| v.as_str())
                .unwrap_or("dev");
            let table = body
                .get("table_template")
                .or_else(|| body.get("table"))
                .and_then(|v| v.as_str())
                .unwrap_or("sensor_events");
            let workgroup = body
                .get("workgroup_name")
                .or_else(|| body.get("workgroup"))
                .and_then(|v| v.as_str())
                .unwrap_or("default");
            let region = body
                .get("region")
                .and_then(|v| v.as_str())
                .unwrap_or("us-east-1");
            let endpoint = body
                .get("endpoint")
                .or_else(|| body.get("url"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let access_key = body
                .get("access_key_id")
                .and_then(|v| v.as_str())
                .unwrap_or("test");
            let secret_key = body
                .get("secret_access_key")
                .and_then(|v| v.as_str())
                .unwrap_or("test");
            let timeout_ms = body
                .get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .or_else(|| body.get("request_timeout_ms"))
                .and_then(|v| v.as_u64());

            let config = broker_connectors::redshift::RedshiftSinkConfig {
                database: database.to_string(),
                table_template: table.to_string(),
                cluster_identifier: None,
                workgroup_name: Some(workgroup.to_string()),
                region: region.to_string(),
                endpoint,
                access_key_id: access_key.to_string(),
                secret_access_key: secret_key.to_string(),
                session_token: None,
                db_user: None,
                sql_template: None,
                batch_size: Some(1),
                batch_bytes: Some(1_048_576),
                linger_ms: Some(10),
                max_retries: Some(3),
                initial_backoff_ms: Some(100),
                max_backoff_ms: Some(2_000),
                timeout_ms,
            };
            if let Ok(transport) = broker_connectors::redshift::HttpRedshiftTransport::new(
                &config,
                reqwest::Client::new(),
            ) {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::redshift::RedshiftSink::new(config, transport)
                {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine
                        .connectors()
                        .register(format!("redshift:{}", name), sink);
                }
            }
        }
        "aws_iot" | "aws_iot_core" => {
            // Fail closed (S1-01 + R1-01): mTLS material is operator-supplied
            // from the request body (flat or nested `auth`), never invented.
            // A missing certificate or key registers nothing; SigV4 has no
            // transport in this build and is rejected at construction.
            let auth_obj = body.get("auth").and_then(|v| v.as_object());
            let field = |keys: &[&str]| -> Option<String> {
                for key in keys {
                    if let Some(value) = body.get(*key).and_then(|v| v.as_str()) {
                        if !value.trim().is_empty() {
                            return Some(value.to_string());
                        }
                    }
                    if let Some(auth) = auth_obj {
                        if let Some(value) = auth.get(*key).and_then(|v| v.as_str()) {
                            if !value.trim().is_empty() {
                                return Some(value.to_string());
                            }
                        }
                    }
                }
                None
            };
            let endpoint = field(&["endpoint", "url", "server"])
                .unwrap_or_else(|| "127.0.0.1:8883".to_string());
            let region = field(&["region"]).unwrap_or_else(|| "us-east-1".to_string());
            let client_id = field(&["client_id"]).unwrap_or_else(|| "indra-bridge".to_string());
            let Some(client_cert_pem) =
                field(&["client_cert_pem", "client_cert", "certificate", "cert_pem"])
            else {
                return;
            };
            let Some(client_key_pem) =
                field(&["client_key_pem", "client_key", "private_key", "key_pem"])
            else {
                return;
            };
            let ca_cert_pem = field(&["ca_cert_pem", "ca_cert", "ca_pem", "certificate_authority"])
                .unwrap_or_default();
            let ca_bundle_pem = field(&["ca_bundle_pem", "ca_bundle"]);
            let timeout_ms = body
                .get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .or_else(|| body.get("request_timeout_ms"))
                .and_then(|v| v.as_u64());
            let connect_timeout_ms = body.get("connect_timeout_ms").and_then(|v| v.as_u64());
            let handshake_timeout_ms = body.get("handshake_timeout_ms").and_then(|v| v.as_u64());

            let config = broker_connectors::aws_iot::AwsIotConfig {
                endpoint: endpoint.to_string(),
                region: region.to_string(),
                client_id: client_id.to_string(),
                auth: broker_connectors::aws_iot::AwsIotAuth::Mtls {
                    ca_cert_pem,
                    client_cert_pem,
                    client_key_pem,
                },
                topic_mappings: vec![broker_connectors::aws_iot::BridgeTopicMapping {
                    local_topic: "#".to_string(),
                    remote_topic: "aws/telemetry/${client_id}".to_string(),
                    direction: broker_connectors::aws_iot::BridgeDirection::LocalToRemote,
                }],
                shadow_sync: None,
                buffer_capacity: None,
                batch_size: Some(1),
                linger_ms: Some(10),
                max_retries: Some(3),
                timeout_ms,
                connect_timeout_ms,
                handshake_timeout_ms,
                ca_bundle_pem,
                alpn_protocols: None,
            };
            if let Ok(transport) = broker_connectors::aws_iot::TlsAwsIotTransport::new(&config) {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::aws_iot::AwsIotSink::new(config, transport) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine
                        .connectors()
                        .register(format!("aws_iot:{}", name), sink.clone());
                    engine
                        .connectors()
                        .register(format!("aws_iot_core:{}", name), sink);
                }
            }
        }
        "azure_blob" | "azure_blob_storage" => {
            let account_name = body
                .get("account_name")
                .and_then(|v| v.as_str())
                .unwrap_or("devstoreaccount1");
            let container_name = body
                .get("container_name")
                .or_else(|| body.get("container"))
                .and_then(|v| v.as_str())
                .unwrap_or("telemetry");
            let endpoint = body
                .get("endpoint")
                .or_else(|| body.get("url"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let blob_path = body
                .get("blob_path_template")
                .or_else(|| body.get("path_template"))
                .and_then(|v| v.as_str())
                .unwrap_or("telemetry/${batch_id}.json");
            let timeout_ms = body
                .get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .and_then(|v| v.as_u64());
            let auth = body
                .get("auth")
                .and_then(|v| {
                    serde_json::from_value::<broker_connectors::azure_blob::AzureBlobAuth>(
                        v.clone(),
                    )
                    .ok()
                })
                .or_else(|| {
                    body.get("account_key")
                        .or_else(|| body.get("accountKey"))
                        .and_then(|v| v.as_str())
                        .map(
                            |s| broker_connectors::azure_blob::AzureBlobAuth::SharedKey {
                                account_key: s.to_string(),
                            },
                        )
                })
                .or_else(|| {
                    body.get("auth").and_then(|v| v.as_object()).and_then(|o| {
                        o.get("account_key")
                            .or_else(|| o.get("accountKey"))
                            .and_then(|v| v.as_str())
                            .map(
                                |s| broker_connectors::azure_blob::AzureBlobAuth::SharedKey {
                                    account_key: s.to_string(),
                                },
                            )
                    })
                })
                .or_else(|| {
                    body.get("sas_token")
                        .or_else(|| body.get("sas"))
                        .and_then(|v| v.as_str())
                        .map(|s| broker_connectors::azure_blob::AzureBlobAuth::SasToken {
                            sas_token: s.to_string(),
                        })
                        .or_else(|| {
                            body.get("auth").and_then(|v| v.as_object()).and_then(|o| {
                                o.get("sas_token")
                                    .or_else(|| o.get("sas"))
                                    .and_then(|v| v.as_str())
                                    .map(|s| {
                                        broker_connectors::azure_blob::AzureBlobAuth::SasToken {
                                            sas_token: s.to_string(),
                                        }
                                    })
                            })
                        })
                })
                .or_else(|| {
                    body.get("token")
                        .or_else(|| body.get("bearer_token"))
                        .and_then(|v| v.as_str())
                        .map(
                            |s| broker_connectors::azure_blob::AzureBlobAuth::BearerToken {
                                token: s.to_string(),
                            },
                        )
                        .or_else(|| {
                            body.get("auth").and_then(|v| v.as_object()).and_then(|o| {
                                o.get("token")
                                    .or_else(|| o.get("bearer_token"))
                                    .and_then(|v| v.as_str())
                                    .map(|s| {
                                        broker_connectors::azure_blob::AzureBlobAuth::BearerToken {
                                            token: s.to_string(),
                                        }
                                    })
                            })
                        })
                });
            let Some(auth) = auth else {
                return;
            };

            let config = broker_connectors::azure_blob::AzureBlobSinkConfig {
                account_name: account_name.to_string(),
                container_name: container_name.to_string(),
                endpoint,
                auth,
                blob_path_template: blob_path.to_string(),
                compression: broker_connectors::azure_blob::AzureBlobCompression::None,
                max_records_per_blob: Some(1),
                max_bytes_per_blob: Some(1_048_576),
                flush_interval_secs: 1,
                buffer_capacity: None,
                timeout_ms,
            };
            if let Ok(transport) = broker_connectors::azure_blob::HttpAzureBlobTransport::new(
                &config,
                reqwest::Client::new(),
            ) {
                let transport = Arc::new(transport);
                if let Ok(sink) =
                    broker_connectors::azure_blob::AzureBlobSink::new(config, transport)
                {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine
                        .connectors()
                        .register(format!("azure_blob:{}", name), sink.clone());
                    engine
                        .connectors()
                        .register(format!("azure_blob_storage:{}", name), sink);
                }
            }
        }
        "azure_eventhubs" | "azure_event_hubs" => {
            let namespace = body
                .get("namespace")
                .and_then(|v| v.as_str())
                .unwrap_or("test-namespace");
            let event_hub = body
                .get("event_hub")
                .or_else(|| body.get("hub"))
                .and_then(|v| v.as_str())
                .unwrap_or("test-hub");
            let endpoint = body
                .get("endpoint")
                .or_else(|| body.get("url"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let shared_access_key_name = body
                .get("shared_access_key_name")
                .or_else(|| body.get("key_name"))
                .and_then(|v| v.as_str())
                .unwrap_or("SendPolicy");
            // Fail closed (S1-01): SAS key is operator-supplied; the previous
            // built-in test key is removed.
            let Some(shared_access_key) = body
                .get("shared_access_key")
                .or_else(|| body.get("key"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            else {
                return;
            };
            let timeout_ms = body
                .get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .and_then(|v| v.as_u64());

            let config = broker_connectors::azure_eventhubs::AzureEventHubsSinkConfig {
                namespace: namespace.to_string(),
                event_hub: event_hub.to_string(),
                endpoint,
                shared_access_key_name: shared_access_key_name.to_string(),
                shared_access_key: shared_access_key.to_string(),
                partition_key_template: None,
                user_properties: std::collections::HashMap::new(),
                token_ttl_secs: 3600,
                batch_size: Some(1),
                batch_bytes: Some(1_048_576),
                linger_ms: Some(10),
                max_retries: Some(3),
                initial_backoff_ms: Some(100),
                max_backoff_ms: Some(2_000),
                timeout_ms,
            };
            if let Ok(transport) =
                broker_connectors::azure_eventhubs::HttpAzureEventHubsTransport::new(
                    &config,
                    reqwest::Client::new(),
                )
            {
                let transport = Arc::new(transport);
                if let Ok(sink) =
                    broker_connectors::azure_eventhubs::AzureEventHubsSink::new(config, transport)
                {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine
                        .connectors()
                        .register(format!("azure_eventhubs:{}", name), sink.clone());
                    engine
                        .connectors()
                        .register(format!("azure_event_hubs:{}", name), sink);
                }
            }
        }
        "azure_iot" | "azure_iot_hub" => {
            let hub_name = body
                .get("iot_hub_name")
                .or_else(|| body.get("hub_name"))
                .or_else(|| body.get("server"))
                .or_else(|| body.get("endpoint"))
                .and_then(|v| v.as_str())
                .unwrap_or("127.0.0.1:8883");
            let device_id = body
                .get("device_id")
                .and_then(|v| v.as_str())
                .unwrap_or("device-01");
            // Fail closed (S1-01): SAS key is operator-supplied; the previous
            // built-in test key is removed.
            let Some(shared_access_key) = body
                .get("shared_access_key")
                .or_else(|| body.get("key"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            else {
                return;
            };
            let timeout_ms = body
                .get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .and_then(|v| v.as_u64());
            let module_id = body
                .get("module_id")
                .or_else(|| body.get("module"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let key_name = body
                .get("key_name")
                .or_else(|| body.get("shared_access_key_name"))
                .and_then(|v| v.as_str())
                .unwrap_or("device")
                .to_string();
            let api_version = body
                .get("api_version")
                .and_then(|v| v.as_str())
                .unwrap_or("2021-04-12")
                .to_string();
            let direct_methods_enabled = body
                .get("direct_methods_enabled")
                .or_else(|| body.get("direct_methods"))
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let twin_sync_enabled = body
                .get("twin_sync_enabled")
                .or_else(|| body.get("twin_sync"))
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let batch_size = body
                .get("batch_size")
                .and_then(|v| v.as_u64())
                .map(|v| v as usize)
                .or(Some(1));
            let buffer_capacity = body
                .get("buffer_capacity")
                .and_then(|v| v.as_u64())
                .map(|v| v as usize);
            let linger_ms = body.get("linger_ms").and_then(|v| v.as_u64()).or(Some(10));
            let max_retries = body
                .get("max_retries")
                .and_then(|v| v.as_u64())
                .map(|v| v as usize)
                .or(Some(3));
            let connect_timeout_ms = body.get("connect_timeout_ms").and_then(|v| v.as_u64());
            let handshake_timeout_ms = body.get("handshake_timeout_ms").and_then(|v| v.as_u64());
            let ca_bundle_pem = body
                .get("ca_bundle_pem")
                .or_else(|| body.get("ca_bundle"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let sas_ttl_secs = body
                .get("sas_ttl_secs")
                .or_else(|| body.get("sas_ttl"))
                .or_else(|| body.get("token_ttl_secs"))
                .and_then(|v| v.as_u64());

            let config = broker_connectors::azure_iot::AzureIotConfig {
                iot_hub_name: hub_name.to_string(),
                device_id: device_id.to_string(),
                module_id,
                auth: broker_connectors::azure_iot::AzureIotAuth::SharedAccessKey {
                    key: shared_access_key.to_string(),
                    key_name: Some(key_name),
                },
                api_version,
                direct_methods_enabled,
                twin_sync_enabled,
                batch_size,
                buffer_capacity,
                linger_ms,
                max_retries,
                timeout_ms,
                connect_timeout_ms,
                handshake_timeout_ms,
                ca_bundle_pem,
                sas_ttl_secs,
            };
            if let Ok(transport) = broker_connectors::azure_iot::TlsAzureIotTransport::new(&config)
            {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::azure_iot::AzureIotSink::new(config, transport)
                {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine
                        .connectors()
                        .register(format!("azure_iot:{}", name), sink.clone());
                    engine
                        .connectors()
                        .register(format!("azure_iot_hub:{}", name), sink);
                }
            }
        }
        "gcp_pubsub" | "pubsub" => {
            let project_id = body
                .get("project_id")
                .or_else(|| body.get("project"))
                .and_then(|v| v.as_str())
                .unwrap_or("test-project");
            let topic_id = body
                .get("topic_id")
                .or_else(|| body.get("topic"))
                .and_then(|v| v.as_str())
                .unwrap_or("test-topic");
            let endpoint = body
                .get("endpoint")
                .or_else(|| body.get("url"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let timeout_ms = body
                .get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .and_then(|v| v.as_u64());

            let config = broker_connectors::gcp_pubsub::GcpPubSubSinkConfig {
                project_id: project_id.to_string(),
                topic_id: topic_id.to_string(),
                endpoint,
                auth: broker_connectors::gcp_pubsub::GcpAuth::None,
                ordering_key_template: None,
                attributes: std::collections::HashMap::new(),
                batch_size: Some(1),
                batch_bytes: Some(1_048_576),
                linger_ms: Some(10),
                max_retries: Some(3),
                initial_backoff_ms: Some(100),
                max_backoff_ms: Some(2_000),
                timeout_ms,
            };
            if let Ok(transport) = broker_connectors::gcp_pubsub::HttpGcpPubSubTransport::new(
                &config,
                reqwest::Client::new(),
            ) {
                let transport = Arc::new(transport);
                if let Ok(sink) =
                    broker_connectors::gcp_pubsub::GcpPubSubSink::new(config, transport)
                {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine
                        .connectors()
                        .register(format!("gcp_pubsub:{}", name), sink.clone());
                    engine
                        .connectors()
                        .register(format!("pubsub:{}", name), sink);
                }
            }
        }
        "bigquery" => {
            let project_id = body
                .get("project_id")
                .or_else(|| body.get("project"))
                .and_then(|v| v.as_str())
                .unwrap_or("test-project");
            let dataset_id = body
                .get("dataset_id")
                .or_else(|| body.get("dataset"))
                .and_then(|v| v.as_str())
                .unwrap_or("test-dataset");
            let table = body
                .get("table")
                .or_else(|| body.get("table_template"))
                .and_then(|v| v.as_str())
                .unwrap_or("telemetry");
            let endpoint = body
                .get("endpoint")
                .or_else(|| body.get("url"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let timeout_ms = body
                .get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .and_then(|v| v.as_u64());
            // Batching / retry knobs are read from the request so management
            // configuration drives the sink; defaults preserve the previous
            // live-path behaviour (auto-flush every row).
            let ignore_unknown_values = body
                .get("ignore_unknown_values")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let skip_invalid_rows = body
                .get("skip_invalid_rows")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let template_suffix = body
                .get("template_suffix")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let batch_size = body
                .get("batch_size")
                .and_then(|v| v.as_u64())
                .map(|v| v as usize)
                .or(Some(1));
            let batch_bytes = body
                .get("batch_bytes")
                .and_then(|v| v.as_u64())
                .map(|v| v as usize)
                .or(Some(1_048_576));
            let linger_ms = body.get("linger_ms").and_then(|v| v.as_u64()).or(Some(10));
            let max_retries = body
                .get("max_retries")
                .and_then(|v| v.as_u64())
                .map(|v| v as usize)
                .or(Some(3));
            let initial_backoff_ms = body
                .get("initial_backoff_ms")
                .and_then(|v| v.as_u64())
                .or(Some(100));
            let max_backoff_ms = body
                .get("max_backoff_ms")
                .and_then(|v| v.as_u64())
                .or(Some(2_000));

            let config = broker_connectors::bigquery::BigQuerySinkConfig {
                project_id: project_id.to_string(),
                dataset_id: dataset_id.to_string(),
                table_template: table.to_string(),
                endpoint,
                auth: broker_connectors::gcp_pubsub::GcpAuth::None,
                ignore_unknown_values,
                skip_invalid_rows,
                template_suffix,
                batch_size,
                batch_bytes,
                linger_ms,
                max_retries,
                initial_backoff_ms,
                max_backoff_ms,
                timeout_ms,
            };
            if let Ok(transport) = broker_connectors::bigquery::SdkBigQueryTransport::new(
                &config,
                reqwest::Client::new(),
            ) {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::bigquery::BigQuerySink::new(config, transport)
                {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine
                        .connectors()
                        .register(format!("bigquery:{}", name), sink);
                }
            }
        }
        "gcp_iot" | "gcp_iot_core" => {
            // Kept: service-documented default endpoint
            // (`mqtt.googleapis.com:8883`, the Google Cloud IoT MQTT bridge;
            // same default as `GcpIotConfig::default_endpoint`).
            // The connector still fails closed without its required fields below.
            let endpoint = body
                .get("endpoint")
                .or_else(|| body.get("url"))
                .or_else(|| body.get("server"))
                .and_then(|v| v.as_str())
                .unwrap_or("mqtt.googleapis.com:8883");
            // Fail closed (S1-01): an operator-supplied project, region,
            // registry, device and key are required; nothing is invented.
            let Some(project_id) = body
                .get("project_id")
                .or_else(|| body.get("project"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            else {
                return;
            };
            let Some(cloud_region) = body
                .get("cloud_region")
                .or_else(|| body.get("region"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            else {
                return;
            };
            let Some(registry_id) = body
                .get("registry_id")
                .or_else(|| body.get("registry"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            else {
                return;
            };
            let Some(device_id) = body
                .get("device_id")
                .or_else(|| body.get("device"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            else {
                return;
            };
            let Some(private_key_pem) = body
                .get("private_key_pem")
                .or_else(|| body.get("private_key"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            else {
                return;
            };
            let timeout_ms = body
                .get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .and_then(|v| v.as_u64());

            let algorithm = match body.get("algorithm").and_then(|v| v.as_str()) {
                Some("ES256") | Some("es256") => broker_connectors::gcp_iot::GcpIotAlgorithm::Es256,
                _ => broker_connectors::gcp_iot::GcpIotAlgorithm::Rs256,
            };

            let config = broker_connectors::gcp_iot::GcpIotConfig {
                project_id: project_id.to_string(),
                cloud_region: cloud_region.to_string(),
                registry_id: registry_id.to_string(),
                device_id: device_id.to_string(),
                private_key_pem: private_key_pem.to_string(),
                algorithm,
                token_lifetime_secs: 3600,
                endpoint: endpoint.to_string(),
                batch_size: Some(1),
                buffer_capacity: None,
                linger_ms: Some(10),
                max_retries: Some(3),
                timeout_ms,
            };
            if let Ok(transport) = broker_connectors::gcp_iot::TcpGcpIotTransport::new(endpoint) {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::gcp_iot::GcpIotSink::new(config, transport) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine
                        .connectors()
                        .register(format!("gcp_iot:{}", name), sink.clone());
                    engine
                        .connectors()
                        .register(format!("gcp_iot_core:{}", name), sink);
                }
            }
        }
        "databricks" | "delta_lake" => {
            // Fail closed (S1-01): host, token, catalog, schema and table are
            // all operator-supplied; the previous mock token and invented
            // names are removed.
            let Some(host) = body
                .get("host")
                .or_else(|| body.get("server"))
                .or_else(|| body.get("endpoint"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            else {
                return;
            };
            let Some(token) = body
                .get("token")
                .or_else(|| body.get("api_key"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            else {
                return;
            };
            let Some(catalog) = body
                .get("catalog")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            else {
                return;
            };
            let Some(schema) = body
                .get("schema")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            else {
                return;
            };
            let Some(table) = body
                .get("table")
                .or_else(|| body.get("table_template"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            else {
                return;
            };
            let timeout_ms = body
                .get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .and_then(|v| v.as_u64());

            let config = broker_connectors::databricks::DatabricksSinkConfig {
                host: host.to_string(),
                token: token.to_string(),
                catalog: catalog.to_string(),
                schema: schema.to_string(),
                table_template: table.to_string(),
                http_path: None,
                partition_key_template: None,
                column_mappings: std::collections::HashMap::new(),
                batch_size: Some(1),
                batch_bytes: Some(2_097_152),
                linger_ms: Some(10),
                max_retries: Some(3),
                initial_backoff_ms: Some(100),
                max_backoff_ms: Some(2_000),
                timeout_ms,
            };
            if let Ok(transport) = broker_connectors::databricks::HttpDatabricksTransport::new(
                &config,
                reqwest::Client::new(),
            ) {
                let transport = Arc::new(transport);
                if let Ok(sink) =
                    broker_connectors::databricks::DatabricksSink::new(config, transport)
                {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine
                        .connectors()
                        .register(format!("databricks:{}", name), sink.clone());
                    engine
                        .connectors()
                        .register(format!("delta_lake:{}", name), sink);
                }
            }
        }
        "snowflake" => {
            // Fail closed (S1-01): account, user, database, schema, table and
            // key are all operator-supplied; the previous test names and
            // built-in key are removed.
            let Some(account) = body
                .get("account")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            else {
                return;
            };
            let Some(user) = body
                .get("user")
                .or_else(|| body.get("username"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            else {
                return;
            };
            let Some(database) = body
                .get("database")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            else {
                return;
            };
            let Some(schema) = body
                .get("schema")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            else {
                return;
            };
            let Some(table) = body
                .get("table")
                .or_else(|| body.get("table_template"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            else {
                return;
            };
            let endpoint = body
                .get("endpoint")
                .or_else(|| body.get("url"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let Some(private_key_pem) = body
                .get("private_key_pem")
                .or_else(|| body.get("private_key"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            else {
                return;
            };
            let timeout_ms = body
                .get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .and_then(|v| v.as_u64());

            let config = broker_connectors::snowflake::SnowflakeSinkConfig {
                account: account.to_string(),
                user: user.to_string(),
                database: database.to_string(),
                schema: schema.to_string(),
                table_template: table.to_string(),
                private_key_pem: private_key_pem.to_string(),
                endpoint,
                role: None,
                channel: "INDRA_CHANNEL".to_string(),
                column_mappings: std::collections::HashMap::new(),
                batch_size: Some(1),
                batch_bytes: Some(4_194_304),
                linger_ms: Some(10),
                max_retries: Some(3),
                initial_backoff_ms: Some(100),
                max_backoff_ms: Some(2_000),
                timeout_ms,
            };
            if let Ok(transport) = broker_connectors::snowflake::HttpSnowflakeTransport::new(
                &config,
                reqwest::Client::new(),
            ) {
                let transport = Arc::new(transport);
                if let Ok(sink) =
                    broker_connectors::snowflake::SnowflakeSink::new(config, transport)
                {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine
                        .connectors()
                        .register(format!("snowflake:{}", name), sink);
                }
            }
        }
        "tablestore" | "ots" => {
            // Fail closed (S1-01): endpoint, instance, table and both access
            // keys are all operator-supplied; no loopback default is invented
            // (Tablestore endpoints are instance-specific, so there is no
            // service-documented default to keep).
            let Some(endpoint) = body
                .get("endpoint")
                .or_else(|| body.get("url"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            else {
                return;
            };
            // Fail closed (S1-01): instance, table and both access keys are
            // operator-supplied; the previous test names and keys are removed.
            let Some(instance_name) = body
                .get("instance_name")
                .or_else(|| body.get("instance"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            else {
                return;
            };
            let Some(table_name) = body
                .get("table_name")
                .or_else(|| body.get("table"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            else {
                return;
            };
            let Some(access_key_id) = body
                .get("access_key_id")
                .or_else(|| body.get("ak"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            else {
                return;
            };
            let Some(access_key_secret) = body
                .get("access_key_secret")
                .or_else(|| body.get("sk"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            else {
                return;
            };
            let timeout_ms = body
                .get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .and_then(|v| v.as_u64());

            let config = broker_connectors::tablestore::TablestoreSinkConfig {
                endpoint: endpoint.to_string(),
                instance_name: instance_name.to_string(),
                table_name: table_name.to_string(),
                access_key_id: access_key_id.to_string(),
                access_key_secret: access_key_secret.to_string(),
                primary_keys: vec![broker_connectors::tablestore::PrimaryKeyMapping {
                    name: "device_id".to_string(),
                    source: "${client_id}".to_string(),
                    data_type: broker_connectors::tablestore::PrimaryKeyType::String,
                }],
                attribute_columns: vec![broker_connectors::tablestore::AttributeColumnMapping {
                    name: "temperature".to_string(),
                    source: "${payload.temperature}".to_string(),
                    data_type: broker_connectors::tablestore::AttributeColumnType::Double,
                }],
                batch_size: Some(1),
                buffer_capacity: None,
                linger_ms: Some(10),
                timeout_ms,
            };
            if let Ok(transport) = broker_connectors::tablestore::HttpTablestoreTransport::new(
                &config,
                reqwest::Client::new(),
            ) {
                let transport = Arc::new(transport);
                if let Ok(sink) =
                    broker_connectors::tablestore::TablestoreSink::new(config, transport)
                {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine
                        .connectors()
                        .register(format!("tablestore:{}", name), sink.clone());
                    engine.connectors().register(format!("ots:{}", name), sink);
                }
            }
        }
        "oci_streaming" | "oci" => {
            // Fail closed (S1-01): endpoint, OCIDs, fingerprint and key are
            // all operator-supplied; no loopback default is invented (OCI
            // Streaming endpoints are cell-specific, so there is no
            // service-documented default to keep).
            let Some(endpoint) = body
                .get("endpoint")
                .or_else(|| body.get("url"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            else {
                return;
            };
            // Fail closed (S1-01): OCIDs, fingerprint and key are
            // operator-supplied; the previous test OCIDs, test fingerprint
            // and built-in key are removed.
            let Some(stream_pool_id) = body
                .get("stream_pool_id")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            else {
                return;
            };
            let Some(stream_id) = body
                .get("stream_id")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            else {
                return;
            };
            let Some(tenancy_ocid) = body
                .get("tenancy_ocid")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            else {
                return;
            };
            let Some(user_ocid) = body
                .get("user_ocid")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            else {
                return;
            };
            let Some(fingerprint) = body
                .get("fingerprint")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            else {
                return;
            };
            let Some(private_key_pem) = body
                .get("private_key_pem")
                .or_else(|| body.get("private_key"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            else {
                return;
            };
            let timeout_ms = body
                .get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .and_then(|v| v.as_u64());

            let partition_key_template = body
                .get("partition_key_template")
                .or_else(|| body.get("partition_key"))
                .and_then(|v| v.as_str())
                .unwrap_or("${topic}");

            let config = broker_connectors::oci_streaming::OciStreamingSinkConfig {
                endpoint: endpoint.to_string(),
                stream_pool_id: stream_pool_id.to_string(),
                stream_id: stream_id.to_string(),
                tenancy_ocid: tenancy_ocid.to_string(),
                user_ocid: user_ocid.to_string(),
                fingerprint: fingerprint.to_string(),
                private_key_pem: private_key_pem.to_string(),
                partition_key_template: partition_key_template.to_string(),
                batch_size: Some(1),
                buffer_capacity: None,
                batch_bytes: Some(4_194_304),
                linger_ms: Some(10),
                max_retries: Some(3),
                initial_backoff_ms: Some(100),
                max_backoff_ms: Some(2_000),
                timeout_ms,
            };
            if let Ok(transport) = broker_connectors::oci_streaming::HttpOciStreamingTransport::new(
                &config,
                reqwest::Client::new(),
            ) {
                let transport = Arc::new(transport);
                if let Ok(sink) =
                    broker_connectors::oci_streaming::OciStreamingSink::new(config, transport)
                {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine
                        .connectors()
                        .register(format!("oci_streaming:{}", name), sink.clone());
                    engine.connectors().register(format!("oci:{}", name), sink);
                }
            }
        }
        _ => {}
    }
}

/// Whether a connector id already lives in the store, matching the
/// same `id`-or-`name` predicate the read and update paths use. Control
/// plane only: one linear scan per create, nothing on the message path.
fn connector_id_exists(name: &str) -> bool {
    CONNECTORS.read().unwrap().iter().any(|c| {
        c.get("id").and_then(|v| v.as_str()) == Some(name)
            || c.get("name").and_then(|v| v.as_str()) == Some(name)
    })
}

pub async fn create_connector(
    State(state): State<ApiState>,
    Json(mut body): Json<serde_json::Value>,
) -> Response {
    // The connector id is `name`, with `id` accepted as an alias: stored
    // entries carry both keys with the same value, and reads match either.
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .or_else(|| body.get("id").and_then(|v| v.as_str()))
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("connector-{}", rand::random::<u16>()));
    let raw_type = body.get("type").and_then(|v| v.as_str()).unwrap_or("");
    let conn_type = if !raw_type.is_empty() && raw_type != "http" {
        raw_type.to_string()
    } else if body.get("bootstrap_hosts").is_some() || name.contains("kafka") {
        "kafka".to_string()
    } else if (body.get("server").is_some()
        && body.get("database").is_some()
        && !body
            .get("server")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .contains("3306"))
        || name.contains("postgres")
        || name.contains("pgsql")
    {
        "pgsql".to_string()
    } else if (body.get("server").is_some() && body.get("database").is_some())
        || name.contains("mysql")
    {
        "mysql".to_string()
    } else if body.get("servers").is_some()
        || body.get("redis_type").is_some()
        || name.contains("redis")
    {
        "redis".to_string()
    } else if (body.get("url").is_some() && body.get("database").is_some())
        || name.contains("clickhouse")
    {
        "clickhouse".to_string()
    } else if raw_type == "http" || body.get("url").is_some() {
        "http".to_string()
    } else if !raw_type.is_empty() {
        raw_type.to_string()
    } else {
        "http".to_string()
    };

    // Reject a duplicate id before mutating anything: pushing it into
    // the store would poison every later connector POST/PUT/DELETE, whose
    // persistence export re-validates the whole store and fails on the
    // duplicated id. The documented conflict code is `ALREADY_EXISTS`.
    // This early read-check also skips the wasted probe and live-sink
    // registration below; the write-locked re-check before the push
    // closes the check-then-insert race for the in-memory store.
    if connector_id_exists(&name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "code": "ALREADY_EXISTS",
                "message": "Connector already exists."
            })),
        )
            .into_response();
    }

    // Fail closed (S1-01): a connector without its required credential or
    // identity is rejected here with the missing field named. It is never
    // stored in a degraded state, and `register_live_sink` below also
    // refuses to invent values.
    if let Some(missing) = missing_connector_field(&conn_type, &body) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "code": "BAD_REQUEST",
                "message": format!(
                    "missing required field: {missing} for connector type {conn_type}"
                ),
            })),
        )
            .into_response();
    }

    let is_reachable = probe_connector_reachable(&body).await;
    let status_str = connector_status(is_reachable);

    if let Some(obj) = body.as_object_mut() {
        obj.insert("id".to_string(), serde_json::Value::String(name.clone()));
        obj.insert("name".to_string(), serde_json::Value::String(name.clone()));
        obj.insert(
            "type".to_string(),
            serde_json::Value::String(conn_type.clone()),
        );
        obj.insert(
            "status".to_string(),
            serde_json::Value::String(status_str.to_string()),
        );
        if !obj.contains_key("enable") {
            obj.insert("enable".to_string(), serde_json::Value::Bool(true));
        }
        obj.insert("node_status".to_string(), connector_node_status(status_str));
    }

    if is_reachable {
        register_live_sink(&state.engine, &conn_type, &name, &body).await;
    }

    // Re-check under the write lock so two concurrent creates for the
    // same id cannot both pass the early check and push a duplicate pair.
    {
        let mut store = CONNECTORS.write().unwrap();
        if store.iter().any(|c| {
            c.get("id").and_then(|v| v.as_str()) == Some(name.as_str())
                || c.get("name").and_then(|v| v.as_str()) == Some(name.as_str())
        }) {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "code": "ALREADY_EXISTS",
                    "message": "Connector already exists."
                })),
            )
                .into_response();
        }
        store.push(body.clone());
    }

    // A persist failure is a 500 (the in-memory entry stays but the disk
    // save failed); the loss must never be silent.
    if let Err(error) = persist_connectors(&state.config) {
        return connector_persist_error(error);
    }

    (StatusCode::CREATED, Json(body)).into_response()
}

pub async fn update_connector(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(mut body): Json<serde_json::Value>,
) -> Response {
    let clean_id = id.split(':').next_back().unwrap_or(&id).to_string();
    let found = {
        let connectors = CONNECTORS.read().unwrap();
        connectors.iter().any(|c| {
            c.get("id").and_then(|v| v.as_str()) == Some(id.as_str())
                || c.get("name").and_then(|v| v.as_str()) == Some(id.as_str())
                || c.get("id").and_then(|v| v.as_str()) == Some(clean_id.as_str())
                || c.get("name").and_then(|v| v.as_str()) == Some(clean_id.as_str())
        })
    };
    if !found {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "code": "NOT_FOUND",
                "message": "Connector not found"
            })),
        )
            .into_response();
    }
    if let Some(obj) = body.as_object_mut() {
        obj.insert(
            "id".to_string(),
            serde_json::Value::String(clean_id.clone()),
        );
    }
    let conn_type = body
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("http")
        .to_string();
    // Fail closed (S1-01): same required-field gate as create; an update
    // that drops a credential or identity is rejected with the field named.
    if let Some(missing) = missing_connector_field(&conn_type, &body) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "code": "BAD_REQUEST",
                "message": format!(
                    "missing required field: {missing} for connector type {conn_type}"
                ),
            })),
        )
            .into_response();
    }
    register_live_sink(&state.engine, &conn_type, &clean_id, &body).await;

    {
        let mut connectors = CONNECTORS.write().unwrap();
        if let Some(pos) = connectors.iter().position(|c| {
            c.get("id").and_then(|v| v.as_str()) == Some(id.as_str())
                || c.get("name").and_then(|v| v.as_str()) == Some(id.as_str())
                || c.get("id").and_then(|v| v.as_str()) == Some(clean_id.as_str())
                || c.get("name").and_then(|v| v.as_str()) == Some(clean_id.as_str())
        }) {
            connectors[pos] = body.clone();
        }
    }
    // A persist failure is a 500 (the in-memory replacement stays but the
    // disk save failed); the loss must never be silent.
    if let Err(error) = persist_connectors(&state.config) {
        return connector_persist_error(error);
    }
    (StatusCode::OK, Json(body)).into_response()
}

pub async fn delete_connector(State(state): State<ApiState>, Path(id): Path<String>) -> Response {
    let clean_id = id.split(':').next_back().unwrap_or(&id);
    state.engine.connectors().unregister(&id);
    state.engine.connectors().unregister(clean_id);
    state
        .engine
        .connectors()
        .unregister(&format!("redis:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("http:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("kafka:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("pgsql:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("mysql:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("rabbitmq:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("clickhouse:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("influxdb:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("mongodb:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("cassandra:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("cockroachdb:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("couchbase:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("mssql:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("oracle:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("alloydb:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("tdengine:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("greptimedb:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("greptime:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("iotdb:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("opentsdb:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("doris:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("datalayers:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("elasticsearch:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("opensearch:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("pulsar:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("rocketmq:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("confluent:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("disk_log:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("disk:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("opc_ua:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("opcua:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("sparkplug_b:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("sparkplug:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("s3:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("minio:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("s3_tables:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("s3tables:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("kinesis:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("dynamodb:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("timestream:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("redshift:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("aws_iot:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("aws_iot_core:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("azure_blob:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("azure_blob_storage:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("azure_eventhubs:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("azure_event_hubs:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("azure_iot:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("azure_iot_hub:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("gcp_pubsub:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("pubsub:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("bigquery:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("gcp_iot:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("gcp_iot_core:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("databricks:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("delta_lake:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("snowflake:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("tablestore:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("ots:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("oci_streaming:{}", clean_id));
    state
        .engine
        .connectors()
        .unregister(&format!("oci:{}", clean_id));

    let removed = {
        let mut connectors = CONNECTORS.write().unwrap();
        let before = connectors.len();
        connectors.retain(|c| {
            c.get("id").and_then(|v| v.as_str()) != Some(&id)
                && c.get("name").and_then(|v| v.as_str()) != Some(&id)
                && c.get("id").and_then(|v| v.as_str()) != Some(clean_id)
                && c.get("name").and_then(|v| v.as_str()) != Some(clean_id)
        });
        connectors.len() != before
    };
    // Unknown ids persist nothing; a persist failure after a real removal
    // is a 500 (the in-memory removal stays but the disk save failed).
    if removed {
        if let Err(error) = persist_connectors(&state.config) {
            return connector_persist_error(error);
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

fn extract_target_host_port(body: &serde_json::Value) -> Option<String> {
    if let Some(s) = body.get("server").and_then(|v| v.as_str()) {
        let mut clean = s.trim();
        if let Some((_, rest)) = clean.split_once("://") {
            clean = rest;
        }
        let host_port = clean
            .split('@')
            .next_back()
            .unwrap_or(clean)
            .split('/')
            .next()
            .unwrap_or(clean)
            .split('?')
            .next()
            .unwrap_or(clean);
        if !host_port.is_empty() {
            return Some(host_port.to_string());
        }
    }
    if let Some(s) = body.get("servers").and_then(|v| v.as_str()) {
        let first = s.split(',').next().unwrap_or(s).trim();
        let mut clean = first;
        if let Some((_, rest)) = clean.split_once("://") {
            clean = rest;
        }
        let host_port = clean
            .split('@')
            .next_back()
            .unwrap_or(clean)
            .split('/')
            .next()
            .unwrap_or(clean)
            .split('?')
            .next()
            .unwrap_or(clean);
        if !host_port.is_empty() {
            return Some(host_port.to_string());
        }
    }
    if let Some(s) = body.get("endpoint").and_then(|v| v.as_str()) {
        let mut clean = s.trim();
        if let Some((_, rest)) = clean.split_once("://") {
            clean = rest;
        }
        let host_port = clean
            .split('@')
            .next_back()
            .unwrap_or(clean)
            .split('/')
            .next()
            .unwrap_or(clean)
            .split('?')
            .next()
            .unwrap_or(clean);
        if !host_port.is_empty() {
            return Some(host_port.to_string());
        }
    }
    if let Some(s) = body.get("endpoint_url").and_then(|v| v.as_str()) {
        let mut clean = s.trim();
        if let Some((_, rest)) = clean.split_once("://") {
            clean = rest;
        }
        let host_port = clean
            .split('@')
            .next_back()
            .unwrap_or(clean)
            .split('/')
            .next()
            .unwrap_or(clean)
            .split('?')
            .next()
            .unwrap_or(clean);
        if !host_port.is_empty() {
            return Some(host_port.to_string());
        }
    }
    if let Some(s) = body.get("bootstrap_hosts").and_then(|v| v.as_str()) {
        let first = s.split(',').next().unwrap_or(s).trim();
        if !first.is_empty() {
            return Some(first.to_string());
        }
    }
    if let Some(s) = body.get("connection_string").and_then(|v| v.as_str()) {
        let mut clean = s.trim();
        if let Some((_, rest)) = clean.split_once("://") {
            clean = rest;
        }
        let host_port = clean
            .split('@')
            .next_back()
            .unwrap_or(clean)
            .split('/')
            .next()
            .unwrap_or(clean)
            .split('?')
            .next()
            .unwrap_or(clean);
        if !host_port.is_empty() {
            return Some(host_port.to_string());
        }
    }
    if let Some(u) = body.get("url").and_then(|v| v.as_str()) {
        if let Ok(parsed) = reqwest::Url::parse(u) {
            let host = parsed.host_str().unwrap_or("127.0.0.1");
            let port = parsed.port_or_known_default().unwrap_or(80);
            return Some(format!("{}:{}", host, port));
        }
    }
    if let Some(h) = body.get("host").and_then(|v| v.as_str()) {
        let mut clean = h.trim();
        if let Some((_, rest)) = clean.split_once("://") {
            clean = rest;
        }
        let host_port = clean
            .split('@')
            .next_back()
            .unwrap_or(clean)
            .split('/')
            .next()
            .unwrap_or(clean)
            .split('?')
            .next()
            .unwrap_or(clean);
        if host_port.contains(':') {
            return Some(host_port.to_string());
        }
        let port = body.get("port").and_then(|v| v.as_u64()).unwrap_or(1433);
        return Some(format!("{}:{}", host_port, port));
    }
    None
}

async fn check_tcp_reachable(addr: &str) -> Result<(), String> {
    let target = if addr.contains(':') {
        addr.to_string()
    } else {
        format!("{}:80", addr)
    };
    match tokio::time::timeout(
        std::time::Duration::from_millis(1500),
        tokio::net::TcpStream::connect(&target),
    )
    .await
    {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(format!("Connection refused to {}: {}", target, e)),
        Err(_) => Err(format!("Connection to {} timed out after 1.5s", target)),
    }
}

pub async fn probe_connector(body: Option<Json<serde_json::Value>>) -> Response {
    let body = match body {
        Some(Json(b)) => b,
        None => {
            return (
                StatusCode::OK,
                Json(serde_json::json!({
                    "result": "ok",
                    "status": "connected"
                })),
            )
                .into_response();
        }
    };
    if let Some(target) = extract_target_host_port(&body) {
        match check_tcp_reachable(&target).await {
            Ok(()) => (
                StatusCode::OK,
                Json(serde_json::json!({
                    "result": "ok",
                    "status": "connected",
                    "message": format!("Target endpoint {} reachable", target)
                })),
            )
                .into_response(),
            Err(err) => (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "code": "TEST_FAILED",
                    "message": err
                })),
            )
                .into_response(),
        }
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "code": "BAD_REQUEST",
                "message": "Missing host/server in connector configuration"
            })),
        )
            .into_response()
    }
}

// ---------------------------------------------------------------------------
// Action Types & Probe (real catalogue/probe, kept)
// ---------------------------------------------------------------------------
pub async fn get_action_types() -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!([
            "kafka",
            "pgsql",
            "mysql",
            "redis",
            "mongodb",
            "clickhouse",
            "s3",
            "http"
        ])),
    )
        .into_response()
}

pub async fn probe_action(body: Option<Json<serde_json::Value>>) -> Response {
    if let Some(Json(b)) = body {
        if let Some(target) = extract_target_host_port(&b) {
            if let Err(err) = check_tcp_reachable(&target).await {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "code": "TEST_FAILED",
                        "message": err
                    })),
                )
                    .into_response();
            }
        }
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({ "result": "ok", "status": "connected" })),
    )
        .into_response()
}
