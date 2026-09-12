use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use broker_auth::{AclAction, AclRule, MemoryAuth};
use broker_observability::Metrics;
use broker_protocol::{QoS, Topic, TopicFilter};
use broker_router::{ConnTable, Router as SubscriptionRouter};
use broker_rules::{Rule, RuleAction, RuleEngine};
use broker_session::SessionManager;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

pub mod dashboard;
pub mod ws;

/// Shared node state injected into every management endpoint: the rule
/// engine (mutable via the rules API), session directory, subscription
/// router, delivery directory (shared with the BrokerLink plane so the
/// dashboard WebSocket console receives the same fan-out), and node
/// metrics.
#[derive(Clone)]
pub struct ApiState {
    pub engine: Arc<RuleEngine>,
    pub sessions: Arc<SessionManager>,
    pub router: Arc<SubscriptionRouter>,
    pub metrics: Arc<Metrics>,
    pub auth: Arc<MemoryAuth>,
    pub conns: Arc<ConnTable>,
    ws_conn_counter: Arc<AtomicU64>,
}

impl ApiState {
    pub fn new(
        engine: Arc<RuleEngine>,
        sessions: Arc<SessionManager>,
        router: Arc<SubscriptionRouter>,
        metrics: Arc<Metrics>,
        auth: Arc<MemoryAuth>,
        conns: Arc<ConnTable>,
    ) -> Self {
        Self {
            engine,
            sessions,
            router,
            metrics,
            auth,
            conns,
            ws_conn_counter: Arc::new(AtomicU64::new(1 << 62)),
        }
    }

    /// Standalone state for tests and tools (empty sessions/router).
    pub fn standalone(engine: Arc<RuleEngine>) -> Self {
        Self {
            engine,
            sessions: Arc::new(SessionManager::new()),
            router: Arc::new(SubscriptionRouter::new()),
            metrics: Arc::new(Metrics::new()),
            auth: Arc::new(MemoryAuth::new()),
            conns: Arc::new(ConnTable::default()),
            ws_conn_counter: Arc::new(AtomicU64::new(1 << 62)),
        }
    }

    /// Mint a collision-proof virtual connection id for a dashboard
    /// WebSocket client (far above BEAM's monotonic conn ids).
    pub fn next_ws_conn_id(&self) -> u64 {
        self.ws_conn_counter.fetch_add(1, Ordering::SeqCst)
    }
}

pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/", get(redirect_to_dashboard))
        .route("/dashboard", get(get_dashboard))
        .route("/ws/mqtt", get(ws::ws_mqtt_handler))
        .route("/healthz", get(|| async { "OK" }))
        .route("/api/v1/nodes", get(get_nodes))
        .route("/api/v1/clients", get(get_clients))
        .route("/api/v1/clients/:id", get(get_client))
        .route("/api/v1/metrics", get(get_metrics))
        .route("/api/v1/connectors", get(get_connectors).post(create_connector))
        .route("/api/v1/auth/users", get(list_users).post(create_user))
        .route("/api/v1/auth/acls", get(list_acls).post(create_acl))
        .route("/api/v1/rules", get(list_rules).post(create_rule))
        .route("/api/v1/rules/test", post(test_rule))
        .route("/api/v1/rules/functions", get(list_functions))
        .route(
            "/api/v1/rules/:id",
            get(get_rule).delete(delete_rule),
        )
        .with_state(state)
}

/// Serve the management API on an already-bound listener.
pub async fn serve(
    listener: tokio::net::TcpListener,
    state: ApiState,
) -> std::io::Result<()> {
    axum::serve(listener, router(state)).await
}

async fn redirect_to_dashboard() -> Response {
    (
        StatusCode::SEE_OTHER,
        [("location", "/dashboard")],
        "redirecting to /dashboard",
    )
        .into_response()
}

async fn get_dashboard() -> Response {
    (
        [("content-type", "text/html; charset=utf-8")],
        dashboard::DASHBOARD_HTML,
    )
        .into_response()
}

/// Creation payload: identifiers are assigned server-side (`rule-<n>`).
#[derive(Debug, Deserialize)]
struct CreateRuleRequest {
    name: String,
    topic_filter: String,
    #[serde(default)]
    sql_query: Option<String>,
    #[serde(default = "default_enabled")]
    enabled: bool,
    #[serde(default)]
    actions: Vec<ActionDto>,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum ActionDto {
    Republish { topic: String, qos: u8 },
    Log,
    ForwardConnector { connector_id: String },
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

fn not_found(id: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorBody {
            error: format!("rule not found: {id}"),
        }),
    )
        .into_response()
}

async fn create_rule(
    State(state): State<ApiState>,
    Json(req): Json<CreateRuleRequest>,
) -> Response {
    if req.name.trim().is_empty() {
        return bad_request("rule name must not be empty");
    }
    let topic_filter = match TopicFilter::new(req.topic_filter) {
        Ok(filter) => filter,
        Err(e) => return bad_request(format!("invalid topic_filter: {e}")),
    };
    let mut actions = Vec::with_capacity(req.actions.len());
    for dto in req.actions {
        match dto {
            ActionDto::Republish { topic, qos } => {
                let topic = match Topic::new(topic) {
                    Ok(topic) => topic,
                    Err(e) => return bad_request(format!("invalid republish topic: {e}")),
                };
                let qos = match QoS::try_from(qos) {
                    Ok(qos) => qos,
                    Err(e) => return bad_request(format!("invalid republish qos: {e}")),
                };
                actions.push(RuleAction::Republish { topic, qos });
            }
            ActionDto::Log => actions.push(RuleAction::Log),
            ActionDto::ForwardConnector { connector_id } => {
                if connector_id.trim().is_empty() {
                    return bad_request("connector_id must not be empty");
                }
                actions.push(RuleAction::ForwardConnector { connector_id });
            }
        }
    }

    let rule: Rule = match state.engine.create_rule(
        req.name,
        topic_filter,
        req.sql_query,
        req.enabled,
        actions,
    ) {
        Ok(rule) => rule,
        Err(e) => return bad_request(format!("invalid sql_query: {e}")),
    };
    (StatusCode::CREATED, Json(rule)).into_response()
}

async fn list_rules(State(state): State<ApiState>) -> Json<Vec<Rule>> {
    Json(state.engine.list_rules())
}

async fn get_rule(State(state): State<ApiState>, Path(id): Path<String>) -> Response {
    match state.engine.get_rule(&id) {
        Some(rule) => Json(rule).into_response(),
        None => not_found(&id),
    }
}

async fn delete_rule(State(state): State<ApiState>, Path(id): Path<String>) -> Response {
    match state.engine.remove_rule(&id) {
        true => StatusCode::NO_CONTENT.into_response(),
        false => not_found(&id),
    }
}

/// Dry-run payload for the SQL studio tester.
#[derive(Debug, Deserialize)]
struct TestRuleRequest {
    #[serde(default)]
    sql_query: Option<String>,
    #[serde(default)]
    topic_filter: Option<String>,
    topic: String,
    payload: serde_json::Value,
}

/// Evaluate SQL + filter over a sample payload without storing a rule.
async fn test_rule(
    State(_state): State<ApiState>,
    Json(req): Json<TestRuleRequest>,
) -> Response {
    match broker_rules::try_evaluate(
        req.sql_query.as_deref(),
        req.topic_filter.as_deref(),
        &req.topic,
        &req.payload,
    ) {
        Ok((matched, projected)) => Json(serde_json::json!({
            "matched": matched,
            "projected": projected,
        }))
        .into_response(),
        Err(error) => bad_request(error),
    }
}

/// The 185-function streaming-SQL catalog for the SQL studio.
async fn list_functions() -> Json<&'static [broker_rules::FunctionMeta]> {
    Json(broker_rules::builtin_function_metadata())
}

/// Creation payload for a user credential (password is write-only).
/// Quotas are optional per-field; omitted fields stay unlimited.
#[derive(Debug, Deserialize)]
struct CreateUserRequest {
    username: String,
    password: String,
    #[serde(default)]
    quotas: Option<QuotasDto>,
}

#[derive(Debug, Deserialize)]
struct QuotasDto {
    #[serde(default)]
    max_connections: Option<u32>,
    #[serde(default)]
    max_publish_rate: Option<u32>,
    #[serde(default)]
    max_publish_burst: Option<u32>,
}

/// Users with their quota bounds (passwords are write-only, never listed).
async fn list_users(State(state): State<ApiState>) -> Json<Vec<serde_json::Value>> {
    Json(
        state
            .auth
            .usernames()
            .iter()
            .map(|username| {
                serde_json::json!({
                    "username": username,
                    "quotas": state.auth.get_quotas(username),
                })
            })
            .collect(),
    )
}

async fn create_user(
    State(state): State<ApiState>,
    Json(req): Json<CreateUserRequest>,
) -> Response {
    if req.username.trim().is_empty() {
        return bad_request("username must not be empty");
    }
    if req.password.is_empty() {
        return bad_request("password must not be empty");
    }
    state.auth.add_user(req.username.clone(), req.password.as_bytes());
    if let Some(quotas) = req.quotas.map(|dto| broker_auth::UserQuotas {
        max_connections: dto.max_connections,
        max_publish_rate: dto.max_publish_rate,
        max_publish_burst: dto.max_publish_burst,
    }) {
        // The user was just created, so this always succeeds.
        state.auth.set_quotas(&req.username, quotas);
    }
    // Quotas always render as an object (all-null when unset) so GET
    // and POST share one shape.
    let stored = state.auth.get_quotas(&req.username);
    (
        StatusCode::CREATED,
        Json(serde_json::json!({ "username": req.username, "quotas": stored })),
    )
        .into_response()
}

/// Creation payload for one ordered ACL entry.
#[derive(Debug, Deserialize)]
struct CreateAclRequest {
    client_pattern: String,
    action: String,
    topic_pattern: String,
    allow: bool,
}

/// Ordered ACL snapshot (first match wins on evaluation).
async fn list_acls(State(state): State<ApiState>) -> Json<Vec<AclRule>> {
    Json(state.auth.acl_rules())
}

async fn create_acl(
    State(state): State<ApiState>,
    Json(req): Json<CreateAclRequest>,
) -> Response {
    if req.client_pattern.trim().is_empty() {
        return bad_request("client_pattern must not be empty");
    }
    let action = match AclAction::parse(&req.action) {
        Some(action) => action,
        None => return bad_request("action must be publish, subscribe, or all"),
    };
    if TopicFilter::new(req.topic_pattern.clone()).is_err() {
        return bad_request("topic_pattern must be a valid MQTT filter");
    }
    state.auth.add_rule(AclRule::new(
        req.client_pattern.clone(),
        action,
        req.topic_pattern.clone(),
        req.allow,
    ));
    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "client_pattern": req.client_pattern,
            "topic_pattern": req.topic_pattern,
            "allow": req.allow,
        })),
    )
        .into_response()
}

fn node_id() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "local".to_string())
}

/// Node status, version, live connection count, and rule count.
async fn get_nodes(State(state): State<ApiState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "node_id": node_id(),
        "status": "running",
        "version": env!("CARGO_PKG_VERSION"),
        "connections": state.metrics.connections_active(),
        "rules": state.engine.list_rules().len(),
    }))
}

/// Sorted ids of currently connected clients.
async fn get_clients(State(state): State<ApiState>) -> Json<Vec<String>> {
    Json(state.sessions.active_client_ids())
}

/// Full detail row for one client session.
async fn get_client(State(state): State<ApiState>, Path(id): Path<String>) -> Response {
    match state.sessions.client_info(&id) {
        Some(info) => Json(info).into_response(),
        None => not_found(&id),
    }
}

/// Registered connectors with kinds and tier tags for the dashboard.
async fn get_connectors(State(state): State<ApiState>) -> Json<Vec<serde_json::Value>> {
    Json(
        state
            .engine
            .connectors()
            .infos()
            .iter()
            .map(|info| {
                serde_json::json!({
                    "id": info.id,
                    "kind": info.kind,
                    "tier": broker_connectors::connector_tier(&info.kind),
                })
            })
            .collect(),
    )
}

/// Creation payload for a streaming connector. `kind` selects the sink
/// family; `config` carries that family's fields verbatim. Streaming
/// sinks connect lazily on first delivery, so creation never blocks on
/// external brokers.
#[derive(Debug, Deserialize)]
struct CreateConnectorRequest {
    id: String,
    kind: String,
    #[serde(default)]
    config: serde_json::Value,
}

async fn create_connector(
    State(state): State<ApiState>,
    Json(req): Json<CreateConnectorRequest>,
) -> Response {
    if req.id.trim().is_empty() {
        return bad_request("connector id must not be empty");
    }
    let built = build_connector(&req).await;
    match built {
        Ok((kind, sink)) => {
            state.engine.connectors().register(req.id.clone(), sink);
            (
                StatusCode::CREATED,
                Json(serde_json::json!({ "id": req.id, "kind": kind })),
            )
                .into_response()
        }
        Err(message) => bad_request(&message),
    }
}

/// Build one streaming connector from a creation request: parse the
/// kind-specific config, validate it, and wire the sink to its
/// transport. Pure construction except `disk_log`, which opens its
/// directory (hence async).
async fn build_connector(
    req: &CreateConnectorRequest,
) -> Result<(String, std::sync::Arc<dyn broker_connectors::Sink>), String> {
    let kind = req.kind.to_ascii_lowercase();
    match kind.as_str() {
            "kafka" => {
                let config: broker_connectors::KafkaSinkConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid kafka config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid kafka config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::TcpKafkaTransport::new(
                        config.bootstrap_servers.clone(),
                        config.client_id.clone(),
                        &config.acks,
                    )
                    .map_err(|e| format!("invalid kafka transport: {e}"))?,
                );
                let sink = broker_connectors::KafkaSink::new(config, transport)
                    .map_err(|e| format!("invalid kafka sink: {e}"))?;
                Ok(("kafka".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "rabbitmq" | "rabbit" | "amqp" => {
                let config: broker_connectors::RabbitMqSinkConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid rabbitmq config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid rabbitmq config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::TcpRabbitTransport::new(&config.endpoint)
                        .map_err(|e| format!("invalid rabbitmq transport: {e}"))?,
                );
                let sink = broker_connectors::RabbitMqSink::new(config, transport)
                    .map_err(|e| format!("invalid rabbitmq sink: {e}"))?;
                Ok(("rabbitmq".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "logger" | "console" => {
                let sink = broker_connectors::ConsoleLoggerSink::new(req.id.clone());
                Ok((
                    "console".to_string(),
                    std::sync::Arc::new(sink)
                        as std::sync::Arc<dyn broker_connectors::Sink>,
                ))
            }
            "postgres" | "postgresql" => {
                let config: broker_connectors::PostgreSqlSinkConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid postgres config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid postgres config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::TcpPgTransport::new(
                        &config.connection_url,
                        config.pool_size,
                    )
                    .map_err(|e| format!("invalid postgres transport: {e}"))?,
                );
                let sink = broker_connectors::PostgreSqlSink::new(config, transport)
                    .map_err(|e| format!("invalid postgres sink: {e}"))?;
                Ok(("postgres".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "redis" => {
                let config: broker_connectors::RedisSinkConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid redis config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid redis config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::TcpRedisTransport::new(&config.endpoint)
                        .map_err(|e| format!("invalid redis transport: {e}"))?,
                );
                let sink = broker_connectors::RedisSink::new(config, transport)
                    .map_err(|e| format!("invalid redis sink: {e}"))?;
                Ok(("redis".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "mysql" | "mariadb" => {
                let config: broker_connectors::MySqlSinkConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid mysql config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid mysql config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::TcpMySqlTransport::new(
                        &config.connection_url,
                        config.pool_size,
                    )
                    .map_err(|e| format!("invalid mysql transport: {e}"))?,
                );
                let sink = broker_connectors::MySqlSink::new(config, transport)
                    .map_err(|e| format!("invalid mysql sink: {e}"))?;
                Ok(("mysql".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "clickhouse" | "ch" => {
                let config: broker_connectors::ClickHouseSinkConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid clickhouse config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid clickhouse config: {e}"))?;
                let sink = broker_connectors::ClickHouseSink::new(config, reqwest::Client::new())
                    .map_err(|e| format!("invalid clickhouse sink: {e}"))?;
                Ok(("clickhouse".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "influxdb" | "influx" => {
                let config: broker_connectors::InfluxDbSinkConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid influxdb config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid influxdb config: {e}"))?;
                let sink = broker_connectors::InfluxDbSink::new(config, reqwest::Client::new())
                    .map_err(|e| format!("invalid influxdb sink: {e}"))?;
                Ok(("influxdb".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "s3" | "minio" => {
                let config: broker_connectors::S3SinkConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid s3 config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid s3 config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::HttpS3Transport::new(&config, reqwest::Client::new())
                        .map_err(|e| format!("invalid s3 transport: {e}"))?,
                );
                let sink = broker_connectors::S3Sink::new(config, transport)
                    .map_err(|e| format!("invalid s3 sink: {e}"))?;
                Ok(("s3".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "elasticsearch" | "elastic" | "es" | "opensearch" => {
                let config: broker_connectors::ElasticsearchSinkConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid elasticsearch config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid elasticsearch config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::HttpElasticsearchTransport::new(
                        &config,
                        reqwest::Client::new(),
                    )
                    .map_err(|e| format!("invalid elasticsearch transport: {e}"))?,
                );
                let sink = broker_connectors::ElasticsearchSink::new(config, transport)
                    .map_err(|e| format!("invalid elasticsearch sink: {e}"))?;
                Ok(("elasticsearch".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "timescaledb" | "timescale" => {
                let config: broker_connectors::TimescaleDbSinkConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid timescaledb config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid timescaledb config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::TcpTimescaleTransport::new(
                        &config.connection_url,
                        config.pool_size,
                    )
                    .map_err(|e| format!("invalid timescaledb transport: {e}"))?,
                );
                let sink = broker_connectors::TimescaleDbSink::new(config, transport)
                    .map_err(|e| format!("invalid timescaledb sink: {e}"))?;
                Ok(("timescaledb".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "webhook" | "http" | "rest" => {
                let config: broker_connectors::HttpSinkConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid webhook config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid webhook config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::ReqwestHttpTransport::new(&config, reqwest::Client::new())
                        .map_err(|e| format!("invalid webhook transport: {e}"))?,
                );
                let sink = broker_connectors::HttpSink::new(config, transport)
                    .map_err(|e| format!("invalid webhook sink: {e}"))?;
                Ok(("webhook".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "mqtt_bridge" | "mqtt-bridge" | "bridge" => {
                let config: broker_connectors::MqttBridgeSinkConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid mqtt_bridge config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid mqtt_bridge config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::TcpMqttBridgeTransport::new(&config)
                        .map_err(|e| format!("invalid mqtt_bridge transport: {e}"))?,
                );
                let sink = broker_connectors::MqttBridgeSink::new(config, transport)
                    .map_err(|e| format!("invalid mqtt_bridge sink: {e}"))?;
                Ok(("mqtt_bridge".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "disk_log" | "disklog" | "disk" => {
                let config: broker_connectors::DiskLogSinkConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid disk_log config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid disk_log config: {e}"))?;
                let writer = std::sync::Arc::new(
                    broker_connectors::FileDiskLogWriter::open(&config)
                        .await
                        .map_err(|e| format!("invalid disk_log writer: {e}"))?,
                );
                let sink = broker_connectors::DiskLogSink::new(config, writer)
                    .map_err(|e| format!("invalid disk_log sink: {e}"))?;
                Ok(("disk_log".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "sparkplug_b" | "sparkplug" | "spb" => {
                let config: broker_connectors::SparkplugSinkConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid sparkplug_b config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid sparkplug_b config: {e}"))?;
                // Frames are captured in-process; production MQTT
                // delivery rides the mqtt_bridge connector.
                let transport = std::sync::Arc::new(
                    broker_connectors::MemorySparkplugTransport::new(),
                );
                let sink = broker_connectors::SparkplugBSink::new(config, transport)
                    .map_err(|e| format!("invalid sparkplug_b sink: {e}"))?;
                Ok(("sparkplug_b".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "kinesis" | "aws_kinesis" => {
                let config: broker_connectors::KinesisSinkConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid kinesis config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid kinesis config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::HttpKinesisTransport::new(&config, reqwest::Client::new())
                        .map_err(|e| format!("invalid kinesis transport: {e}"))?,
                );
                let sink = broker_connectors::KinesisSink::new(config, transport)
                    .map_err(|e| format!("invalid kinesis sink: {e}"))?;
                Ok(("kinesis".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "gcp_pubsub" | "gcp" | "pubsub" => {
                let config: broker_connectors::GcpPubSubSinkConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid gcp_pubsub config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid gcp_pubsub config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::HttpGcpPubSubTransport::new(&config, reqwest::Client::new())
                        .map_err(|e| format!("invalid gcp_pubsub transport: {e}"))?,
                );
                let sink = broker_connectors::GcpPubSubSink::new(config, transport)
                    .map_err(|e| format!("invalid gcp_pubsub sink: {e}"))?;
                Ok(("gcp_pubsub".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "azure_eventhubs" | "azure" | "eventhubs" => {
                let config: broker_connectors::AzureEventHubsSinkConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid azure_eventhubs config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid azure_eventhubs config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::HttpAzureEventHubsTransport::new(
                        &config,
                        reqwest::Client::new(),
                    )
                    .map_err(|e| format!("invalid azure_eventhubs transport: {e}"))?,
                );
                let sink = broker_connectors::AzureEventHubsSink::new(config, transport)
                    .map_err(|e| format!("invalid azure_eventhubs sink: {e}"))?;
                Ok(("azure_eventhubs".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "pulsar" => {
                let config: broker_connectors::PulsarSinkConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid pulsar config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid pulsar config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::TcpPulsarTransport::new(&config)
                        .map_err(|e| format!("invalid pulsar transport: {e}"))?,
                );
                let sink = broker_connectors::PulsarSink::new(config, transport)
                    .map_err(|e| format!("invalid pulsar sink: {e}"))?;
                Ok(("pulsar".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "mongodb" | "mongo" | "documentdb" => {
                let config: broker_connectors::MongoDbSinkConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid mongodb config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid mongodb config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::NativeMongoDbTransport::new(&config)
                        .map_err(|e| format!("invalid mongodb transport: {e}"))?,
                );
                let sink = broker_connectors::MongoDbSink::new(config, transport)
                    .map_err(|e| format!("invalid mongodb sink: {e}"))?;
                Ok(("mongodb".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "mssql" | "sqlserver" | "azuresql" => {
                let config: broker_connectors::MssqlSinkConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid mssql config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid mssql config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::NativeMssqlTransport::new(&config)
                        .map_err(|e| format!("invalid mssql transport: {e}"))?,
                );
                let sink = broker_connectors::MssqlSink::new(config, transport)
                    .map_err(|e| format!("invalid mssql sink: {e}"))?;
                Ok(("mssql".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "cassandra" | "scylla" | "cql" => {
                let config: broker_connectors::CassandraSinkConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid cassandra config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid cassandra config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::NativeCassandraTransport::new(&config)
                        .map_err(|e| format!("invalid cassandra transport: {e}"))?,
                );
                let sink = broker_connectors::CassandraSink::new(config, transport)
                    .map_err(|e| format!("invalid cassandra sink: {e}"))?;
                Ok(("cassandra".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "couchbase" | "couch" | "cb" => {
                let config: broker_connectors::CouchbaseSinkConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid couchbase config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid couchbase config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::NativeCouchbaseTransport::new(&config)
                        .map_err(|e| format!("invalid couchbase transport: {e}"))?,
                );
                let sink = broker_connectors::CouchbaseSink::new(config, transport)
                    .map_err(|e| format!("invalid couchbase sink: {e}"))?;
                Ok(("couchbase".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "tdengine" | "td" | "taos" => {
                let config: broker_connectors::TdengineSinkConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid tdengine config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid tdengine config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::HttpTdengineTransport::new(&config, reqwest::Client::new())
                        .map_err(|e| format!("invalid tdengine transport: {e}"))?,
                );
                let sink = broker_connectors::TdengineSink::new(config, transport)
                    .map_err(|e| format!("invalid tdengine sink: {e}"))?;
                Ok(("tdengine".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "iotdb" | "iot_db" => {
                let config: broker_connectors::IotDbSinkConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid iotdb config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid iotdb config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::HttpIotDbTransport::new(&config, reqwest::Client::new())
                        .map_err(|e| format!("invalid iotdb transport: {e}"))?,
                );
                let sink = broker_connectors::IotDbSink::new(config, transport)
                    .map_err(|e| format!("invalid iotdb sink: {e}"))?;
                Ok(("iotdb".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "timestream" | "ts" | "aws_timestream" => {
                let config: broker_connectors::TimestreamSinkConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid timestream config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid timestream config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::HttpTimestreamTransport::new(&config, reqwest::Client::new())
                        .map_err(|e| format!("invalid timestream transport: {e}"))?,
                );
                let sink = broker_connectors::TimestreamSink::new(config, transport)
                    .map_err(|e| format!("invalid timestream sink: {e}"))?;
                Ok(("timestream".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "dynamodb" | "dynamo" | "ddb" => {
                let config: broker_connectors::DynamoDbSinkConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid dynamodb config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid dynamodb config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::HttpDynamoDbTransport::new(&config, reqwest::Client::new())
                        .map_err(|e| format!("invalid dynamodb transport: {e}"))?,
                );
                let sink = broker_connectors::DynamoDbSink::new(config, transport)
                    .map_err(|e| format!("invalid dynamodb sink: {e}"))?;
                Ok(("dynamodb".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "snowflake" | "snow" | "sf" => {
                let config: broker_connectors::SnowflakeSinkConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid snowflake config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid snowflake config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::HttpSnowflakeTransport::new(&config, reqwest::Client::new())
                        .map_err(|e| format!("invalid snowflake transport: {e}"))?,
                );
                let sink = broker_connectors::SnowflakeSink::new(config, transport)
                    .map_err(|e| format!("invalid snowflake sink: {e}"))?;
                Ok(("snowflake".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "databricks" | "databricks_sql" | "delta" => {
                let config: broker_connectors::DatabricksSinkConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid databricks config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid databricks config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::HttpDatabricksTransport::new(&config, reqwest::Client::new())
                        .map_err(|e| format!("invalid databricks transport: {e}"))?,
                );
                let sink = broker_connectors::DatabricksSink::new(config, transport)
                    .map_err(|e| format!("invalid databricks sink: {e}"))?;
                Ok(("databricks".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "doris" => {
                let config: broker_connectors::DorisSinkConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid doris config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid doris config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::HttpDorisTransport::new(&config, reqwest::Client::new())
                        .map_err(|e| format!("invalid doris transport: {e}"))?,
                );
                let sink = broker_connectors::DorisSink::new(config, transport)
                    .map_err(|e| format!("invalid doris sink: {e}"))?;
                Ok(("doris".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "bigquery" | "bq" | "gbq" => {
                let config: broker_connectors::BigQuerySinkConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid bigquery config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid bigquery config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::HttpBigQueryTransport::new(&config, reqwest::Client::new())
                        .map_err(|e| format!("invalid bigquery transport: {e}"))?,
                );
                let sink = broker_connectors::BigQuerySink::new(config, transport)
                    .map_err(|e| format!("invalid bigquery sink: {e}"))?;
                Ok(("bigquery".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "redshift" | "rs" | "aws_redshift" => {
                let config: broker_connectors::RedshiftSinkConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid redshift config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid redshift config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::HttpRedshiftTransport::new(&config, reqwest::Client::new())
                        .map_err(|e| format!("invalid redshift transport: {e}"))?,
                );
                let sink = broker_connectors::RedshiftSink::new(config, transport)
                    .map_err(|e| format!("invalid redshift sink: {e}"))?;
                Ok(("redshift".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            other => Err(format!(
                "unknown connector kind {other:?} (expected kafka, rabbitmq, postgres, redis, mysql, clickhouse, influxdb, s3, elasticsearch, timescaledb, webhook, mqtt_bridge, disk_log, sparkplug_b, kinesis, gcp_pubsub, azure_eventhubs, pulsar, mongodb, mssql, cassandra, couchbase, tdengine, iotdb, timestream, dynamodb, snowflake, databricks, doris, bigquery, redshift, or logger)"
            )),
        }
}

/// Prometheus text exposition of node counters and gauges.
async fn get_metrics(State(state): State<ApiState>) -> Response {
    (
        [("content-type", "text/plain; version=0.0.4")],
        state.metrics.render_prometheus_metrics(),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// In-process HTTP round-trip over loopback TCP: no extra crates, no
    /// daemons. The server is spawned per test and aborted at the end.
    struct TestServer {
        port: u16,
        task: tokio::task::JoinHandle<()>,
    }

    struct TestState {
        engine: Arc<RuleEngine>,
        sessions: Arc<SessionManager>,
        metrics: Arc<Metrics>,
        auth: Arc<MemoryAuth>,
    }

    impl TestServer {
        async fn start() -> (Self, TestState) {
            let engine = Arc::new(RuleEngine::new(
                16,
                broker_rules::BackpressurePolicy::DropOldest,
            ));
            let sessions = Arc::new(SessionManager::new());
            let sub_router = Arc::new(SubscriptionRouter::new());
            let metrics = Arc::new(Metrics::new());
            let auth = Arc::new(MemoryAuth::new());
            let conns = Arc::new(broker_router::ConnTable::default());
            let state = TestState {
                engine: engine.clone(),
                sessions: sessions.clone(),
                metrics: metrics.clone(),
                auth: auth.clone(),
            };
            let app = router(ApiState::new(
                engine, sessions, sub_router, metrics, auth, conns,
            ));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind test server");
            let port = listener.local_addr().expect("local addr").port();
            let task = tokio::spawn(async move {
                axum::serve(listener, app).await.expect("serve test app");
            });
            (Self { port, task }, state)
        }

        async fn request(&self, raw: &str) -> (u16, Value) {
            let (status, text) = self.request_raw(raw).await;
            let body: Value = if text.trim().is_empty() {
                Value::Null
            } else {
                serde_json::from_str(&text).expect("response body is JSON")
            };
            (status, body)
        }

        async fn request_raw(&self, raw: &str) -> (u16, String) {
            let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", self.port))
                .await
                .expect("connect test server");
            stream
                .write_all(raw.as_bytes())
                .await
                .expect("write request");
            // HTTP/1.0 + Connection: close => the server closes when done.
            let mut buf = Vec::new();
            stream
                .read_to_end(&mut buf)
                .await
                .expect("read response");
            let text = String::from_utf8(buf).expect("response is UTF-8");
            let (head, body) = text.split_once("\r\n\r\n").expect("header/body split");
            let status: u16 = head
                .lines()
                .next()
                .expect("status line")[9..12]
                .parse()
                .expect("status code");
            (status, body.to_string())
        }

        async fn post(&self, path: &str, body: Value) -> (u16, Value) {
            let raw_body = serde_json::to_string(&body).expect("encode body");
            self.request(&format!(
                "POST {path} HTTP/1.0\r\nHost: test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{raw_body}",
                raw_body.len()
            ))
            .await
        }

        async fn get(&self, path: &str) -> (u16, Value) {
            self.request(&format!(
                "GET {path} HTTP/1.0\r\nHost: test\r\nConnection: close\r\n\r\n"
            ))
            .await
        }

        async fn delete(&self, path: &str) -> (u16, Value) {
            self.request(&format!(
                "DELETE {path} HTTP/1.0\r\nHost: test\r\nConnection: close\r\n\r\n"
            ))
            .await
        }
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    #[tokio::test]
    async fn test_api_router_health() {
        let (server, _state) = TestServer::start().await;
        let (status, text) = server
            .request_raw("GET /healthz HTTP/1.0\r\nHost: test\r\nConnection: close\r\n\r\n")
            .await;
        assert_eq!(status, 200);
        assert_eq!(text, "OK");
    }

    #[tokio::test]
    async fn test_rules_crud_lifecycle() {
        let (server, _state) = TestServer::start().await;

        // Empty at first.
        let (status, body) = server.get("/api/v1/rules").await;
        assert_eq!(status, 200);
        assert_eq!(body, json!([]));

        // Create.
        let (status, created) = server
            .post(
                "/api/v1/rules",
                json!({
                    "name": "republish-temp",
                    "topic_filter": "sensors/+",
                    "enabled": true,
                    "actions": [{"type": "republish", "topic": "alerts/critical", "qos": 1}]
                }),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["name"], json!("republish-temp"));
        assert_eq!(created["topic_filter"], json!("sensors/+"));
        assert_eq!(created["actions"][0]["type"], json!("republish"));
        assert_eq!(created["actions"][0]["qos"], json!(1));
        let id = created["id"].as_str().expect("created rule has id").to_string();

        // List shows it.
        let (status, body) = server.get("/api/v1/rules").await;
        assert_eq!(status, 200);
        assert_eq!(body.as_array().expect("list").len(), 1);

        // Fetch it directly.
        let (status, fetched) = server.get(&format!("/api/v1/rules/{id}")).await;
        assert_eq!(status, 200);
        assert_eq!(fetched, created);

        // Unknown id is a 404.
        let (status, body) = server.get("/api/v1/rules/rule-999").await;
        assert_eq!(status, 404);
        assert!(body["error"].as_str().unwrap().contains("rule-999"));

        // Delete it.
        let (status, _) = server.delete(&format!("/api/v1/rules/{id}")).await;
        assert_eq!(status, 204);

        // Gone afterwards; second delete is a 404.
        let (status, _) = server.get(&format!("/api/v1/rules/{id}")).await;
        assert_eq!(status, 404);
        let (status, _) = server.delete(&format!("/api/v1/rules/{id}")).await;
        assert_eq!(status, 404);
    }

    #[tokio::test]
    async fn test_rules_create_rejects_invalid_input() {
        let (server, _state) = TestServer::start().await;

        // Bad topic filter.
        let (status, body) = server
            .post(
                "/api/v1/rules",
                json!({"name": "bad", "topic_filter": "sport/#/bogus", "actions": []}),
            )
            .await;
        assert_eq!(status, 400);
        assert!(body["error"].as_str().unwrap().contains("topic_filter"));

        // Bad republish QoS.
        let (status, body) = server
            .post(
                "/api/v1/rules",
                json!({"name": "bad", "topic_filter": "a/#",
                       "actions": [{"type": "republish", "topic": "b", "qos": 7}]}),
            )
            .await;
        assert_eq!(status, 400);
        assert!(body["error"].as_str().unwrap().contains("qos"));

        // Wildcard republish target is not a concrete topic.
        let (status, body) = server
            .post(
                "/api/v1/rules",
                json!({"name": "bad", "topic_filter": "a/#",
                       "actions": [{"type": "republish", "topic": "b/#", "qos": 0}]}),
            )
            .await;
        assert_eq!(status, 400);
        assert!(body["error"].as_str().unwrap().contains("topic"));

        // Empty name.
        let (status, _) = server
            .post(
                "/api/v1/rules",
                json!({"name": "  ", "topic_filter": "a/#", "actions": []}),
            )
            .await;
        assert_eq!(status, 400);

        // Nothing was stored by the failed creates.
        let (status, body) = server.get("/api/v1/rules").await;
        assert_eq!(status, 200);
        assert_eq!(body, json!([]));
    }

    #[tokio::test]
    async fn test_rules_create_with_sql_query() {
        let (server, _state) = TestServer::start().await;

        // Valid streaming SQL is accepted and echoed back verbatim.
        let (status, created) = server
            .post(
                "/api/v1/rules",
                json!({"name": "hot-temp",
                       "topic_filter": "sensors/+",
                       "sql_query": "SELECT * FROM \"sensors/+\" WHERE temperature > 50.0",
                       "enabled": true,
                       "actions": [{"type": "republish", "topic": "alerts/hot", "qos": 0}]}),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(
            created["sql_query"],
            json!("SELECT * FROM \"sensors/+\" WHERE temperature > 50.0")
        );
        let id = created["id"].as_str().expect("created rule has id").to_string();
        let (status, _) = server.get(&format!("/api/v1/rules/{id}")).await;
        assert_eq!(status, 200);

        // Broken SQL is a 400 and stores nothing.
        let (status, body) = server
            .post(
                "/api/v1/rules",
                json!({"name": "broken",
                       "topic_filter": "sensors/+",
                       "sql_query": "SELECT WHERE WHERE",
                       "actions": []}),
            )
            .await;
        assert_eq!(status, 400);
        assert!(body["error"].as_str().unwrap().contains("sql_query"));

        let (status, body) = server.get("/api/v1/rules").await;
        assert_eq!(status, 200);
        assert_eq!(body.as_array().expect("list").len(), 1);
    }

    #[tokio::test]
    async fn test_nodes_reports_status_version_connections() {
        let (server, state) = TestServer::start().await;
        state.metrics.set_active_connections(3);

        let (status, body) = server.get("/api/v1/nodes").await;
        assert_eq!(status, 200);
        assert_eq!(body["status"], json!("running"));
        assert_eq!(body["version"], json!(env!("CARGO_PKG_VERSION")));
        assert_eq!(body["connections"], json!(3));
        assert!(body["node_id"].is_string());
    }

    #[tokio::test]
    async fn test_clients_lists_connected_ids() {
        let (server, state) = TestServer::start().await;

        let (status, body) = server.get("/api/v1/clients").await;
        assert_eq!(status, 200);
        assert_eq!(body, json!([]));

        state.sessions.get_or_create("client-b", true);
        state.sessions.get_or_create("client-a", true);
        let (status, body) = server.get("/api/v1/clients").await;
        assert_eq!(status, 200);
        assert_eq!(body, json!(["client-a", "client-b"]));
    }

    #[tokio::test]
    async fn test_metrics_exposes_prometheus_counters() {
        let (server, state) = TestServer::start().await;
        state.metrics.inc_messages_received();
        state.metrics.inc_messages_forwarded_by(2);
        state.metrics.inc_rules_executed();
        state.metrics.set_active_connections(1);

        let (status, text) = server
            .request_raw("GET /api/v1/metrics HTTP/1.0\r\nHost: test\r\nConnection: close\r\n\r\n")
            .await;
        assert_eq!(status, 200);
        assert!(text.contains("indramqtt_messages_received_total 1\n"));
        assert!(text.contains("indramqtt_messages_forwarded_total 2\n"));
        assert!(text.contains("indramqtt_rules_executed_total 1\n"));
        assert!(text.contains("indramqtt_connections_active 1\n"));
    }

    #[tokio::test]
    async fn test_rules_create_with_forward_connector() {
        let (server, _state) = TestServer::start().await;

        let (status, created) = server
            .post(
                "/api/v1/rules",
                json!({"name": "to-webhook",
                       "topic_filter": "sensors/+",
                       "sql_query": "SELECT temperature FROM \"sensors/+\" WHERE temperature > 0",
                       "actions": [{"type": "forwardconnector", "connector_id": "webhook-1"}]}),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["actions"][0]["type"], json!("forwardconnector"));
        assert_eq!(created["actions"][0]["connector_id"], json!("webhook-1"));

        // Empty connector id is rejected.
        let (status, _) = server
            .post(
                "/api/v1/rules",
                json!({"name": "bad",
                       "topic_filter": "sensors/+",
                       "actions": [{"type": "forwardconnector", "connector_id": "  "}]}),
            )
            .await;
        assert_eq!(status, 400);
    }

    #[tokio::test]
    async fn test_auth_users_and_acls() {
        let (server, state) = TestServer::start().await;

        // Create a user.
        let (status, created) = server
            .post(
                "/api/v1/auth/users",
                json!({"username": "alice", "password": "s3cret"}),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["username"], json!("alice"));
        // Passwords are write-only: never echoed.
        assert!(created.get("password").is_none());
        assert_eq!(state.auth.user_count(), 1);

        // Empty username or password is rejected.
        let (status, _) = server
            .post(
                "/api/v1/auth/users",
                json!({"username": "", "password": "x"}),
            )
            .await;
        assert_eq!(status, 400);
        let (status, _) = server
            .post(
                "/api/v1/auth/users",
                json!({"username": "bob", "password": ""}),
            )
            .await;
        assert_eq!(status, 400);

        // Create an ACL rule.
        let (status, created) = server
            .post(
                "/api/v1/auth/acls",
                json!({"client_pattern": "alice",
                       "action": "publish",
                       "topic_pattern": "sensors/#",
                       "allow": true}),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["allow"], json!(true));

        // Invalid action, topic pattern, and client pattern rejected.
        for body in [
            json!({"client_pattern": "*", "action": "delete", "topic_pattern": "#", "allow": true}),
            json!({"client_pattern": "*", "action": "publish", "topic_pattern": "a/#/b", "allow": true}),
            json!({"client_pattern": "", "action": "all", "topic_pattern": "#", "allow": false}),
        ] {
            let (status, _) = server.post("/api/v1/auth/acls", body).await;
            assert_eq!(status, 400);
        }
    }

    #[tokio::test]
    async fn test_auth_lists_users_and_acls() {
        let (server, _state) = TestServer::start().await;

        let (status, body) = server.get("/api/v1/auth/users").await;
        assert_eq!(status, 200);
        assert_eq!(body, json!([]));
        let (status, body) = server.get("/api/v1/auth/acls").await;
        assert_eq!(status, 200);
        assert_eq!(body, json!([]));

        server
            .post(
                "/api/v1/auth/users",
                json!({"username": "alice", "password": "s3cret"}),
            )
            .await;
        server
            .post(
                "/api/v1/auth/acls",
                json!({"client_pattern": "alice",
                       "action": "subscribe",
                       "topic_pattern": "sensors/#",
                       "allow": true}),
            )
            .await;

        let (status, body) = server.get("/api/v1/auth/users").await;
        assert_eq!(status, 200);
        assert_eq!(
            body,
            json!([{"username": "alice", "quotas": {"max_connections": null, "max_publish_rate": null, "max_publish_burst": null}}])
        );
        let (status, body) = server.get("/api/v1/auth/acls").await;
        assert_eq!(status, 200);
        assert_eq!(body.as_array().expect("acls").len(), 1);
        assert_eq!(body[0]["client_pattern"], json!("alice"));
        assert_eq!(body[0]["action"], json!("subscribe"));
        assert_eq!(body[0]["allow"], json!(true));
    }

    #[tokio::test]
    async fn test_auth_users_quotas_roundtrip() {
        let (server, _state) = TestServer::start().await;

        // Create with quotas: every bound echoes back.
        let (status, created) = server
            .post(
                "/api/v1/auth/users",
                json!({"username": "capped",
                       "password": "pw",
                       "quotas": {"max_connections": 100,
                                  "max_publish_rate": 50,
                                  "max_publish_burst": 10}}),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["username"], json!("capped"));
        assert_eq!(created["quotas"]["max_connections"], json!(100));
        assert_eq!(created["quotas"]["max_publish_rate"], json!(50));
        assert_eq!(created["quotas"]["max_publish_burst"], json!(10));

        // Without quotas: all-null bounds object.
        let (status, created) = server
            .post(
                "/api/v1/auth/users",
                json!({"username": "plain", "password": "pw"}),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["quotas"]["max_connections"], serde_json::Value::Null);

        // Listing shows both shapes side by side.
        let (status, body) = server.get("/api/v1/auth/users").await;
        assert_eq!(status, 200);
        let users = body.as_array().expect("users list");
        assert_eq!(users.len(), 2);
        assert_eq!(users[0]["username"], json!("capped"));
        assert_eq!(users[0]["quotas"]["max_connections"], json!(100));
        assert_eq!(users[1]["username"], json!("plain"));
        assert_eq!(users[1]["quotas"]["max_publish_rate"], serde_json::Value::Null);
    }

    #[tokio::test]
    async fn test_dashboard_routes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (server, _state) = TestServer::start().await;

        // GET / redirects to the console.
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", server.port))
            .await
            .expect("connect");
        stream
            .write_all(b"GET / HTTP/1.0\r\nHost: test\r\nConnection: close\r\n\r\n")
            .await
            .expect("write");
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.expect("read");
        let text = String::from_utf8(buf).expect("UTF-8");
        // Hyper echoes the HTTP/1.0 request version in the status line.
        assert!(text.contains(" 303 "), "root must redirect, got: {text}");
        assert!(
            text.to_ascii_lowercase().contains("location: /dashboard"),
            "redirect must target /dashboard, got: {text}"
        );

        // GET /dashboard serves the SPA shell.
        let (status, html) = server
            .request_raw("GET /dashboard HTTP/1.0\r\nHost: test\r\nConnection: close\r\n\r\n")
            .await;
        assert_eq!(status, 200);
        for marker in [
            "<title>IndraMQTT Console</title>",
            "Community Edition (MIT)",
            "id=\"metrics\"",
            "id=\"clients\"",
            "id=\"sql-studio\"",
            "id=\"connectors\"",
            "id=\"auth\"",
            "id=\"console\"",
            "rule-tpl-math",
            "rule-tpl-tumbling",
            "value=\"mysql\"",
            "value=\"clickhouse\"",
            "value=\"influxdb\"",
            "value=\"s3\"",
            "value=\"elasticsearch\"",
            "value=\"timescaledb\"",
            "conn-mysql-url",
            "conn-ch-endpoint",
            "conn-influx-endpoint",
            "conn-s3-bucket",
            "conn-es-index",
            "conn-ts-hypertable",
            "value=\"webhook\"",
            "value=\"mqtt_bridge\"",
            "value=\"disk_log\"",
            "value=\"sparkplug_b",
            "value=\"kinesis\"",
            "value=\"gcp_pubsub\"",
            "value=\"azure_eventhubs\"",
            "value=\"pulsar\"",
            "value=\"mongodb\"",
            "value=\"mssql\"",
            "value=\"cassandra\"",
            "value=\"couchbase\"",
            "value=\"tdengine\"",
            "value=\"iotdb\"",
            "value=\"timestream\"",
            "value=\"dynamodb\"",
            "value=\"snowflake\"",
            "value=\"databricks\"",
            "value=\"doris\"",
            "value=\"bigquery\"",
            "value=\"redshift\"",
            "conn-hook-url",
            "conn-bridge-address",
            "conn-disk-dir",
            "conn-spb-prefix",
            "conn-kinesis-stream",
            "conn-gcp-project",
            "conn-azure-ns",
            "conn-pulsar-url",
            "conn-mongo-url",
            "conn-mssql-host",
            "conn-cass-contact",
            "conn-couch-url",
            "conn-td-endpoint",
            "conn-iotdb-device",
            "conn-ts-database",
            "conn-ddb-table",
            ".badge.community",
            ".badge.enterprise",
            "/ws/mqtt",
        ] {
            assert!(html.contains(marker), "dashboard missing {marker}");
        }
    }

    #[tokio::test]
    async fn test_clients_detail_endpoint() {
        let (server, state) = TestServer::start().await;

        let (session, _) = state.sessions.get_or_create("detail-1", false);
        *session.conn_id.write() = Some(4242);
        *session.keepalive_secs.write() = 60;
        state.sessions.add_subscription(
            "detail-1",
            TopicFilter::new("sensors/+").unwrap(),
            QoS::AtLeastOnce,
        );

        let (status, body) = server.get("/api/v1/clients/detail-1").await;
        assert_eq!(status, 200);
        let info: broker_session::ClientInfo =
            serde_json::from_value(body).expect("detail row decodes");
        assert_eq!(info.client_id, "detail-1");
        assert_eq!(info.conn_id, Some(4242));
        assert_eq!(info.keepalive_secs, 60);
        assert!(!info.clean_start);
        assert!(info.connected);
        assert_eq!(info.subscriptions, vec!["sensors/+".to_string()]);

        let (status, _) = server.get("/api/v1/clients/ghost").await;
        assert_eq!(status, 404);
    }

    #[tokio::test]
    async fn test_connectors_endpoint_lists_registered() {
        use broker_connectors::Sink;

        struct NullSink;
        #[async_trait::async_trait]
        impl Sink for NullSink {
            async fn send(
                &self,
                _topic: &Topic,
                _payload: &bytes::Bytes,
                _qos: QoS,
            ) -> Result<(), broker_connectors::ConnectorError> {
                Ok(())
            }

            fn kind(&self) -> &'static str {
                "test"
            }
        }

        let (server, state) = TestServer::start().await;
        let (status, body) = server.get("/api/v1/connectors").await;
        assert_eq!(status, 200);
        assert_eq!(body, json!([]));

        state
            .engine
            .connectors()
            .register("webhook-1", Arc::new(NullSink));
        let (status, body) = server.get("/api/v1/connectors").await;
        assert_eq!(status, 200);
        assert_eq!(body, json!([{"id": "webhook-1", "kind": "test", "tier": "community"}]));
    }

    #[tokio::test]
    async fn test_connectors_create_kafka_rabbitmq_logger() {
        let (server, _state) = TestServer::start().await;

        // Kafka sink: validated, lazily connected, listed with its kind.
        let (status, created) = server
            .post(
                "/api/v1/connectors",
                json!({"id": "kafka-sink-1",
                       "kind": "kafka",
                       "config": {"bootstrap_servers": "127.0.0.1:9092",
                                  "topic_template": "out-${topic}",
                                  "partition_key_field": "device_id",
                                  "partitions": 4,
                                  "client_id": "indra",
                                  "acks": "all"}}),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["id"], json!("kafka-sink-1"));
        assert_eq!(created["kind"], json!("kafka"));

        // RabbitMQ sink: slash translation config accepted.
        let (status, created) = server
            .post(
                "/api/v1/connectors",
                json!({"id": "rabbit-sink-1",
                       "kind": "rabbitmq",
                       "config": {"endpoint": "amqp://127.0.0.1:5672/%2f",
                                  "exchange": "telemetry",
                                  "routing_key_template": "sensor.${topic}",
                                  "delivery_mode": 2}}),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("rabbitmq"));

        // Logger sink needs no config at all.
        let (status, created) = server
            .post(
                "/api/v1/connectors",
                json!({"id": "diag", "kind": "logger", "config": {}}),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("console"));

        // Postgres sink: validated without touching any database.
        let (status, created) = server
            .post(
                "/api/v1/connectors",
                json!({"id": "pg-sink-1",
                       "kind": "postgres",
                       "config": {"connection_url": "postgresql://u:p@127.0.0.1:5432/db",
                                  "sql_template": "INSERT INTO t (topic, qos, payload) VALUES ($1, $2, $3)",
                                  "pool_size": 2,
                                  "batch_size": 50,
                                  "batch_timeout_ms": 25}}),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("postgres"));

        // Redis sink: XADD stream config accepted (command is flat).
        let (status, created) = server
            .post(
                "/api/v1/connectors",
                json!({"id": "redis-sink-1",
                       "kind": "redis",
                       "config": {"endpoint": "redis://127.0.0.1:6379",
                                  "command": "xadd",
                                  "stream_template": "events",
                                  "maxlen": 1000}}),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("redis"));

        // MySQL sink: validated without touching any database.
        let (status, created) = server
            .post(
                "/api/v1/connectors",
                json!({"id": "mysql-sink-1",
                       "kind": "mysql",
                       "config": {"connection_url": "mysql://u:p@127.0.0.1:3306/db",
                                  "sql_template": "INSERT INTO t (topic, qos, payload) VALUES (?, ?, ?)",
                                  "pool_size": 2,
                                  "batch_size": 50,
                                  "batch_timeout_ms": 25}}),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("mysql"));

        // ClickHouse sink: validated without touching any server.
        let (status, created) = server
            .post(
                "/api/v1/connectors",
                json!({"id": "ch-sink-1",
                       "kind": "clickhouse",
                       "config": {"endpoint": "http://127.0.0.1:8123",
                                  "database": "indra",
                                  "table": "mqtt_events",
                                  "format": "JSONEachRow",
                                  "batch_size": 100,
                                  "batch_timeout_ms": 50}}),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("clickhouse"));

        // InfluxDB sink: validated without touching any server.
        let (status, created) = server
            .post(
                "/api/v1/connectors",
                json!({"id": "influx-sink-1",
                       "kind": "influxdb",
                       "config": {"endpoint": "http://127.0.0.1:8086",
                                  "bucket": "mqtt",
                                  "org": "indra",
                                  "token": "secret",
                                  "measurement_template": "mqtt_events",
                                  "precision": "ms",
                                  "batch_size": 100,
                                  "batch_timeout_ms": 50}}),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("influxdb"));

        // S3 sink: validated without touching any object store.
        let (status, created) = server
            .post(
                "/api/v1/connectors",
                json!({"id": "s3-sink-1",
                       "kind": "s3",
                       "config": {"endpoint": "http://127.0.0.1:9000",
                                  "bucket": "telemetry-cold-store",
                                  "region": "us-east-1",
                                  "key_template": "telemetry/year=${YYYY}/month=${MM}/day=${DD}/${topic}_${seq}.ndjson",
                                  "compression": "none",
                                  "batch_size": 100,
                                  "batch_bytes": 65536,
                                  "batch_timeout_ms": 1000}}),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("s3"));

        // Elasticsearch sink: validated without touching any cluster.
        let (status, created) = server
            .post(
                "/api/v1/connectors",
                json!({"id": "es-sink-1",
                       "kind": "elasticsearch",
                       "config": {"endpoint": "http://127.0.0.1:9200",
                                  "index_template": "iot-telemetry-${YYYY.MM.dd}",
                                  "auth": {"type": "none"},
                                  "batch_size": 100,
                                  "batch_timeout_ms": 50,
                                  "max_retries": 3}}),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("elasticsearch"));

        // TimescaleDB sink: validated without touching any database.
        let (status, created) = server
            .post(
                "/api/v1/connectors",
                json!({"id": "ts-sink-1",
                       "kind": "timescaledb",
                       "config": {"connection_url": "postgresql://u:p@127.0.0.1:5432/timeseries",
                                  "hypertable": "sensor_metrics",
                                  "time_column": "time",
                                  "sql_template": "INSERT INTO sensor_metrics (time, device_id, topic, metrics) VALUES ($1, $2, $3, $4::jsonb) ON CONFLICT (time, device_id) DO UPDATE SET metrics = EXCLUDED.metrics",
                                  "pool_size": 2,
                                  "batch_size": 50,
                                  "batch_timeout_ms": 25}}),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("timescaledb"));

        // Webhook sink: validated without sending any request.
        let (status, created) = server
            .post(
                "/api/v1/connectors",
                json!({"id": "hook-1",
                       "kind": "webhook",
                       "config": {"url": "https://hooks.example.com/ingest/${topic}",
                                  "method": "post",
                                  "headers": {},
                                  "auth": {"type": "none"},
                                  "body_format": "rawjson",
                                  "batch_size": 50,
                                  "batch_bytes": 65536,
                                  "linger_ms": 25,
                                  "timeout_ms": 1000,
                                  "max_retries": 2,
                                  "initial_backoff_ms": 10,
                                  "max_backoff_ms": 100}}),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("webhook"));

        // MQTT bridge sink: validated without opening any socket.
        let (status, created) = server
            .post(
                "/api/v1/connectors",
                json!({"id": "bridge-1",
                       "kind": "mqtt_bridge",
                       "config": {"broker_address": "mqtt://127.0.0.1:1883",
                                  "client_id": "indra-bridge-test",
                                  "clean_start": true,
                                  "keep_alive_secs": 60,
                                  "max_inflight": 1000,
                                  "max_batch_size": 50,
                                  "linger_ms": 10,
                                  "protocol": "v311"}}),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("mqtt_bridge"));

        // Disk log sink: validated against an isolated temp directory.
        let disk_dir = std::env::temp_dir().join(format!("indra-test-disk-{}", std::process::id()));
        let (status, created) = server
            .post(
                "/api/v1/connectors",
                json!({"id": "disk-1",
                       "kind": "disk_log",
                       "config": {"directory": disk_dir.to_string_lossy(),
                                  "filename_prefix": "audit",
                                  "filename_extension": "log",
                                  "format": "ndjson",
                                  "compression": "none",
                                  "sync_mode": {"mode": "osdefault"}}}),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("disk_log"));
        std::fs::remove_dir_all(&disk_dir).ok();

        // Sparkplug B sink: enterprise tier validated without any broker.
        let (status, created) = server
            .post(
                "/api/v1/connectors",
                json!({"id": "spb-1",
                       "kind": "sparkplug_b",
                       "config": {"topic_prefix": "spBv1.0/plant1",
                                  "tier": "enterprise",
                                  "batch_size": 50,
                                  "linger_ms": 25}}),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("sparkplug_b"));

        // Kinesis sink: validated without touching AWS.
        let (status, created) = server
            .post(
                "/api/v1/connectors",
                json!({"id": "kinesis-1",
                       "kind": "kinesis",
                       "config": {"stream_name": "telemetry-stream",
                                  "region": "us-east-1",
                                  "access_key_id": "AKID",
                                  "secret_access_key": "secret",
                                  "partition_key_template": "${topic}",
                                  "batch_size": 100,
                                  "batch_bytes": 65536,
                                  "linger_ms": 20,
                                  "max_retries": 3,
                                  "initial_backoff_ms": 10,
                                  "max_backoff_ms": 100}}),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("kinesis"));

        // GCP Pub/Sub sink: validated without touching Google.
        let (status, created) = server
            .post(
                "/api/v1/connectors",
                json!({"id": "gcp-1",
                       "kind": "gcp_pubsub",
                       "config": {"project_id": "my-iot-project",
                                  "topic_id": "telemetry-events",
                                  "auth": {"type": "none"},
                                  "batch_size": 100,
                                  "batch_bytes": 65536,
                                  "linger_ms": 10,
                                  "max_retries": 2,
                                  "initial_backoff_ms": 10,
                                  "max_backoff_ms": 100}}),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("gcp_pubsub"));

        // Azure Event Hubs sink: validated without touching Azure.
        let (status, created) = server
            .post(
                "/api/v1/connectors",
                json!({"id": "azure-1",
                       "kind": "azure_eventhubs",
                       "config": {"namespace": "my-eventhub-ns",
                                  "event_hub": "telemetry-hub",
                                  "shared_access_key_name": "SendPolicy",
                                  "shared_access_key": "secret",
                                  "token_ttl_secs": 3600,
                                  "batch_size": 50,
                                  "batch_bytes": 65536,
                                  "linger_ms": 20,
                                  "max_retries": 2,
                                  "initial_backoff_ms": 10,
                                  "max_backoff_ms": 100}}),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("azure_eventhubs"));

        // Pulsar sink: validated without opening any socket.
        let (status, created) = server
            .post(
                "/api/v1/connectors",
                json!({"id": "pulsar-1",
                       "kind": "pulsar",
                       "config": {"service_url": "pulsar://127.0.0.1:6650",
                                  "tenant": "public",
                                  "namespace": "default",
                                  "topic": "iot-telemetry",
                                  "auth": {"type": "none"},
                                  "batch_size": 50,
                                  "batch_bytes": 65536,
                                  "linger_ms": 10,
                                  "max_retries": 2,
                                  "initial_backoff_ms": 10,
                                  "max_backoff_ms": 100}}),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("pulsar"));

        // MongoDB sink: validated without opening any socket.
        let (status, created) = server
            .post(
                "/api/v1/connectors",
                json!({"id": "mongo-1",
                       "kind": "mongodb",
                       "config": {"connection_string": "mongodb://u:p@127.0.0.1:27017",
                                  "database": "telemetry",
                                  "collection_template": "readings",
                                  "operation": {"type": "insert_one"},
                                  "batch_size": 50,
                                  "batch_bytes": 65536,
                                  "linger_ms": 20,
                                  "max_retries": 2,
                                  "initial_backoff_ms": 10,
                                  "max_backoff_ms": 100}}),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("mongodb"));

        // MSSQL sink: validated without opening any socket.
        let (status, created) = server
            .post(
                "/api/v1/connectors",
                json!({"id": "mssql-1",
                       "kind": "mssql",
                       "config": {"host": "127.0.0.1",
                                  "database": "telemetry",
                                  "table_template": "dbo.SensorEvents",
                                  "auth": {"type": "sql_password", "username": "sa", "password": "secret"},
                                  "query_mode": {"mode": "insertjson"},
                                  "trust_server_certificate": true,
                                  "batch_size": 50,
                                  "batch_bytes": 65536,
                                  "linger_ms": 20,
                                  "max_retries": 2,
                                  "initial_backoff_ms": 10,
                                  "max_backoff_ms": 100}}),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("mssql"));

        // Cassandra sink: validated without opening any socket.
        let (status, created) = server
            .post(
                "/api/v1/connectors",
                json!({"id": "cassandra-1",
                       "kind": "cassandra",
                       "config": {"contact_points": ["10.0.0.1:9042"],
                                  "keyspace": "telemetry",
                                  "table_template": "events",
                                  "auth": {"type": "none"},
                                  "consistency": "localquorum",
                                  "partition_key_template": "${topic}",
                                  "cql_statement_template": "INSERT INTO telemetry.events (device_id, bucket_hour, event_time, payload) VALUES (?, ?, ?, ?)",
                                  "batch_size": 50,
                                  "batch_bytes": 65536,
                                  "linger_ms": 10,
                                  "max_retries": 2,
                                  "initial_backoff_ms": 10,
                                  "max_backoff_ms": 100}}),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("cassandra"));

        // Couchbase sink: validated without opening any socket.
        let (status, created) = server
            .post(
                "/api/v1/connectors",
                json!({"id": "couchbase-1",
                       "kind": "couchbase",
                       "config": {"connection_string": "couchbase://127.0.0.1",
                                  "bucket": "telemetry",
                                  "auth": {"username": "Administrator", "password": "secret"},
                                  "doc_id_template": "${client_id}::${timestamp}",
                                  "operation": "upsert",
                                  "batch_size": 50,
                                  "batch_bytes": 65536,
                                  "linger_ms": 10,
                                  "max_retries": 2,
                                  "initial_backoff_ms": 10,
                                  "max_backoff_ms": 100}}),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("couchbase"));

        // TDengine sink: validated without touching any server.
        let (status, created) = server
            .post(
                "/api/v1/connectors",
                json!({"id": "tdengine-1",
                       "kind": "tdengine",
                       "config": {"endpoint": "http://127.0.0.1:6041/rest/sql",
                                  "database": "power",
                                  "stable_name": "meters",
                                  "subtable_template": "d_${client_id}",
                                  "auth": {"type": "basic", "username": "root", "password": "taosdata"},
                                  "tags_template": {},
                                  "metrics_template": {},
                                  "batch_size": 100,
                                  "batch_bytes": 65536,
                                  "linger_ms": 20,
                                  "max_retries": 2,
                                  "initial_backoff_ms": 10,
                                  "max_backoff_ms": 100}}),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("tdengine"));

        // IoTDB sink: validated without touching any server.
        let (status, created) = server
            .post(
                "/api/v1/connectors",
                json!({"id": "iotdb-1",
                       "kind": "iotdb",
                       "config": {"endpoint": "http://127.0.0.1:18080/rest/v2",
                                  "device_path_template": "root.factory.plant1",
                                  "auth": {"username": "root", "password": "root"},
                                  "is_aligned": false,
                                  "measurements": ["temperature"],
                                  "data_types": ["DOUBLE"],
                                  "batch_size": 50,
                                  "batch_bytes": 65536,
                                  "linger_ms": 10,
                                  "max_retries": 2,
                                  "initial_backoff_ms": 10,
                                  "max_backoff_ms": 100}}),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("iotdb"));

        // Timestream sink: validated without touching AWS.
        let (status, created) = server
            .post(
                "/api/v1/connectors",
                json!({"id": "timestream-1",
                       "kind": "timestream",
                       "config": {"database_name": "iot_database",
                                  "table_name": "telemetry",
                                  "region": "us-east-1",
                                  "access_key_id": "AKID",
                                  "secret_access_key": "secret",
                                  "dimensions": {},
                                  "time_unit": "milliseconds",
                                  "multi_measure_mappings": {"temperature": "DOUBLE"},
                                  "batch_size": 50,
                                  "batch_bytes": 65536,
                                  "linger_ms": 20,
                                  "max_retries": 2,
                                  "initial_backoff_ms": 10,
                                  "max_backoff_ms": 100}}),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("timestream"));

        // DynamoDB sink: validated without touching AWS.
        let (status, created) = server
            .post(
                "/api/v1/connectors",
                json!({"id": "dynamodb-1",
                       "kind": "dynamodb",
                       "config": {"table_name": "telemetry_table",
                                  "region": "us-east-1",
                                  "access_key_id": "AKID",
                                  "secret_access_key": "secret",
                                  "partition_key": {"name": "device_id", "template": "${client_id}", "key_type": "S"},
                                  "attributes_mapping": {},
                                  "batch_size": 25,
                                  "batch_bytes": 65536,
                                  "linger_ms": 10,
                                  "max_retries": 2,
                                  "initial_backoff_ms": 10,
                                  "max_backoff_ms": 100}}),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("dynamodb"));

        // Snowflake sink: key-pair validated without touching Snowflake.
        // Test-only RSA key (openssl-generated, never deployed).
        const SNOWFLAKE_TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCwQ2w63oB3FtHg\n7xysQK8MuX9S0WkbAVlxWpLHDNIdRVxA9Ra2gFFpKy8jX45UMSow6Yny7IvYWFzZ\nL4y9yoFiqu+LxhlJHIO6JO8+ZmeBoNwuDiIzgesbZwjyQiQ2M7p/4c18a2ffGPWF\nBETT7uVwVKJ3hTp97RN7Mc1/eFMimuT/TC11I+sFCZUHgrbhEG3L5Gg3RJ2MKbcX\nGEIxjFDJdLJ9RK0BopD6lxR1a4zeYr+iF/m3+JeJPAaS15yMD+sB1g5C7XZ1OIsB\nNBBnHWHpNhYO2IrCc9lZeSSzSkbRC6k1oqvTurFRzHWZqBKQGYnH8BftubIPSTBg\nU/BM4rR3AgMBAAECggEAHSRwmwUZoVb1CWcPSw2Aw65RtkwoQA5Hjv3GIcHlZXCH\n0beT80Wg8C3zI7qTSik8zAx4weDJOFJXu5LohqKaJMmVRHtSx+s+fkLICX2d5GlH\nrhepIPH8gLHW4VL9MLb5wVYAhu8tI845Ha54gL/RUHK1z+QHqTVO0MIJs2cd+6zx\nKsAtnqEQJMFpl1D0y0uutuboK4soHJMyRyrHBNWdgfzmTrCsngzu2zVM4aZh/gQY\nHcQgJ1rK6Wnen/GGPrNluwWU+bfLdlWO2qiXXwGLfhyx2H6cuROGdoU607BFJNpM\nkAudvEuLa0fOi1ym6lJ5pcJ6pSLkbeveW6+thkO2fQKBgQDXc2GiKx15vQHmdDmZ\nUJEiPJ+hSry5fjaowzrfgqJHyeNfUjnM/E9WlNn2AuxKDWGc3UNEr6jB9V7leKev\nQaPB2LAgXt0YVHmyim51/gTDguE9TOTGWqL4npZG9Nqh8xMxWt08ULvknkOQQOso\nzCoZQYlG4BHegAG7n0/5IN7HdQKBgQDRb/VbJ9iE0wtY/A3e3eWPbGfTF7AZREUu\n/mt94tFEWDDvedX1EPi4DJgPMqQ4eHnBZb3+G7jPcRdm6/KQzR5QiRMHSylfIQRH\nLqqfHBzZDDSZINLW1FMReC9xGfkRoG0Tlt2iQzXOy90+uE/9k5BGSbQNakfVDXJs\n3JAHDMy6uwKBgQCaazxC+xv5MRq3jf3qgPBE1aaj9+kkGe4bLzJ3GC4vveeVXl3H\nKd/DcpR12sp4mPapc3zPMgeGXNNTLRMiba1tNl2mFdfppEJFUSqyrwnDB39gbEhc\nUoIUJ7YVzVEWWh4bdcCzhjnlNfm+3oitiQdzaqF1hwvHqX+Udi7fpEuIMQKBgQC5\nu0bkQu7Rw/MRQ93tIe19ho6AdkZV8eREq52Z8vbQXEFxbiOfBCD93zVObQOTjMu1\nBcw6uEzpsgol3OKtJSpYE2eLlU0oLriDg9AN8DlpBljy31f66iqMmH/CFl16E0II\nGEeOqXnjXYlkIMHXR/CvVJdXOkRfnWA3SFZ12hUJFwKBgD8JlGTyrVfNsNMOaTDV\nNopoYnUQ6ljFmJi6TGmnkliCRXPuqBl+2hVxiKeWI2MprJ5Ya8qLbL6M56uCwAD2\nqEhvjEuatma5rJyE5NULOjAXA5tLw9qM1M9j1FNOaXnFC9/Yii2a49R8zu05wRB2\nH+dMMSDXQ4EHHYcKIFJjDbxn\n-----END PRIVATE KEY-----\n";
        let (status, created) = server
            .post(
                "/api/v1/connectors",
                json!({"id": "snowflake-1",
                       "kind": "snowflake",
                       "config": {"account": "xy12345.us-east-1",
                                  "user": "indra_loader",
                                  "database": "IOT",
                                  "schema": "PUBLIC",
                                  "table_template": "IOT_EVENTS",
                                  "private_key_pem": SNOWFLAKE_TEST_KEY,
                                  "channel": "INDRA_CHANNEL",
                                  "batch_size": 100,
                                  "batch_bytes": 65536,
                                  "linger_ms": 20,
                                  "max_retries": 2,
                                  "initial_backoff_ms": 10,
                                  "max_backoff_ms": 100}}),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("snowflake"));

        // Databricks sink: validated without touching any workspace.
        let (status, created) = server
            .post(
                "/api/v1/connectors",
                json!({"id": "databricks-1",
                       "kind": "databricks",
                       "config": {"host": "dbc-a1b2c3d4-e5f6.cloud.databricks.com",
                                  "token": "dapi-test",
                                  "catalog": "main",
                                  "schema": "default",
                                  "table_template": "sensor_readings",
                                  "batch_size": 50,
                                  "batch_bytes": 65536,
                                  "linger_ms": 10,
                                  "max_retries": 2,
                                  "initial_backoff_ms": 10,
                                  "max_backoff_ms": 100}}),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("databricks"));

        // Doris sink: validated without touching any cluster.
        let (status, created) = server
            .post(
                "/api/v1/connectors",
                json!({"id": "doris-1",
                       "kind": "doris",
                       "config": {"fe_host": "127.0.0.1",
                                  "http_port": 8030,
                                  "database": "telemetry",
                                  "table_template": "events",
                                  "auth": {"username": "root", "password": ""},
                                  "format": "json",
                                  "strip_outer_array": true,
                                  "batch_size": 100,
                                  "batch_bytes": 65536,
                                  "linger_ms": 10,
                                  "max_retries": 2,
                                  "initial_backoff_ms": 10,
                                  "max_backoff_ms": 100}}),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("doris"));

        // BigQuery sink: validated without touching Google.
        let (status, created) = server
            .post(
                "/api/v1/connectors",
                json!({"id": "bigquery-1",
                       "kind": "bigquery",
                       "config": {"project_id": "my-iot-project",
                                  "dataset_id": "telemetry",
                                  "table_template": "sensor_logs",
                                  "auth": {"type": "none"},
                                  "ignore_unknown_values": true,
                                  "skip_invalid_rows": false,
                                  "batch_size": 100,
                                  "batch_bytes": 65536,
                                  "linger_ms": 20,
                                  "max_retries": 2,
                                  "initial_backoff_ms": 10,
                                  "max_backoff_ms": 100}}),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("bigquery"));

        // Redshift sink: validated without touching AWS.
        let (status, created) = server
            .post(
                "/api/v1/connectors",
                json!({"id": "redshift-1",
                       "kind": "redshift",
                       "config": {"database": "analytics",
                                  "table_template": "sensor_logs",
                                  "workgroup_name": "iot-workgroup",
                                  "region": "us-east-1",
                                  "access_key_id": "AKID",
                                  "secret_access_key": "secret",
                                  "batch_size": 50,
                                  "batch_bytes": 65536,
                                  "linger_ms": 20,
                                  "max_retries": 2,
                                  "initial_backoff_ms": 10,
                                  "max_backoff_ms": 100}}),
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("redshift"));

        let (status, body) = server.get("/api/v1/connectors").await;
        assert_eq!(status, 200);
        assert_eq!(
            body,
            json!([{"id": "azure-1", "kind": "azure_eventhubs", "tier": "enterprise"},
                   {"id": "bigquery-1", "kind": "bigquery", "tier": "enterprise"},
                   {"id": "bridge-1", "kind": "mqtt_bridge", "tier": "community"},
                   {"id": "cassandra-1", "kind": "cassandra", "tier": "enterprise"},
                   {"id": "ch-sink-1", "kind": "clickhouse", "tier": "community"},
                   {"id": "couchbase-1", "kind": "couchbase", "tier": "enterprise"},
                   {"id": "databricks-1", "kind": "databricks", "tier": "enterprise"},
                   {"id": "diag", "kind": "console", "tier": "community"},
                   {"id": "disk-1", "kind": "disk_log", "tier": "community"},
                   {"id": "doris-1", "kind": "doris", "tier": "enterprise"},
                   {"id": "dynamodb-1", "kind": "dynamodb", "tier": "enterprise"},
                   {"id": "es-sink-1", "kind": "elasticsearch", "tier": "community"},
                   {"id": "gcp-1", "kind": "gcp_pubsub", "tier": "enterprise"},
                   {"id": "hook-1", "kind": "webhook", "tier": "community"},
                   {"id": "influx-sink-1", "kind": "influxdb", "tier": "community"},
                   {"id": "iotdb-1", "kind": "iotdb", "tier": "enterprise"},
                   {"id": "kafka-sink-1", "kind": "kafka", "tier": "community"},
                   {"id": "kinesis-1", "kind": "kinesis", "tier": "enterprise"},
                   {"id": "mongo-1", "kind": "mongodb", "tier": "enterprise"},
                   {"id": "mssql-1", "kind": "mssql", "tier": "enterprise"},
                   {"id": "mysql-sink-1", "kind": "mysql", "tier": "community"},
                   {"id": "pg-sink-1", "kind": "postgres", "tier": "community"},
                   {"id": "pulsar-1", "kind": "pulsar", "tier": "enterprise"},
                   {"id": "rabbit-sink-1", "kind": "rabbitmq", "tier": "community"},
                   {"id": "redis-sink-1", "kind": "redis", "tier": "community"},
                   {"id": "redshift-1", "kind": "redshift", "tier": "enterprise"},
                   {"id": "s3-sink-1", "kind": "s3", "tier": "community"},
                   {"id": "snowflake-1", "kind": "snowflake", "tier": "enterprise"},
                   {"id": "spb-1", "kind": "sparkplug_b", "tier": "enterprise"},
                   {"id": "tdengine-1", "kind": "tdengine", "tier": "enterprise"},
                   {"id": "timestream-1", "kind": "timestream", "tier": "enterprise"},
                   {"id": "ts-sink-1", "kind": "timescaledb", "tier": "community"}])
        );

        // Unknown kinds and invalid configs are 400s that store nothing.
        for payload in [
            json!({"id": "x", "kind": "pigeon", "config": {}}),
            json!({"id": "", "kind": "logger", "config": {}}),
            json!({"id": "bad-k", "kind": "kafka",
                   "config": {"bootstrap_servers": "", "topic_template": "t",
                              "client_id": "c", "acks": "all"}}),
            json!({"id": "bad-r", "kind": "rabbitmq",
                   "config": {"endpoint": "amqp://h", "exchange": "",
                              "routing_key_template": "k", "delivery_mode": 2}}),
            json!({"id": "bad-pg", "kind": "postgres",
                   "config": {"connection_url": "postgresql://h/db",
                              "sql_template": "INSERT INTO t VALUES ($9)"}}),
            json!({"id": "bad-redis", "kind": "redis",
                   "config": {"endpoint": "redis://h",
                              "command": {"command": "set", "key_template": ""}}}),
            json!({"id": "bad-mysql", "kind": "mysql",
                   "config": {"connection_url": "mysql://u:p@h/db",
                              "sql_template": "INSERT INTO t VALUES (?, ?)",
                              "pool_size": 1, "batch_size": 10, "batch_timeout_ms": 10}}),
            json!({"id": "bad-ch", "kind": "clickhouse",
                   "config": {"endpoint": "http://h:8123",
                              "database": "db; DROP TABLE x;",
                              "table": "t",
                              "format": "JSONEachRow",
                              "batch_size": 10, "batch_timeout_ms": 10}}),
            json!({"id": "bad-influx", "kind": "influxdb",
                   "config": {"endpoint": "http://h:8086",
                              "bucket": "b", "org": "o", "token": "",
                              "measurement_template": "m", "precision": "ms"}}),
            json!({"id": "bad-s3", "kind": "s3",
                   "config": {"endpoint": "http://h:9000",
                              "bucket": "UPPERCASE",
                              "key_template": "t/${topic}.ndjson"}}),
            json!({"id": "bad-es", "kind": "elasticsearch",
                   "config": {"endpoint": "http://h:9200",
                              "index_template": "-leading",
                              "auth": {"type": "none"}}}),
            json!({"id": "bad-ts", "kind": "timescaledb",
                   "config": {"connection_url": "postgresql://u:p@h/db",
                              "hypertable": "m",
                              "sql_template": "INSERT INTO m VALUES ($1, $2)"}}),
            json!({"id": "bad-hook", "kind": "webhook",
                   "config": {"url": "ftp://hooks.example.com/x"}}),
            json!({"id": "bad-bridge", "kind": "mqtt_bridge",
                   "config": {"broker_address": "mqtt://h:1883",
                              "client_id": "b",
                              "qos_override": 5}}),
            json!({"id": "bad-disk", "kind": "disk_log",
                   "config": {"directory": "",
                              "format": "ndjson"}}),
            json!({"id": "bad-spb", "kind": "sparkplug_b",
                   "config": {"tier": "community"}}),
            json!({"id": "bad-kinesis", "kind": "kinesis",
                   "config": {"stream_name": "",
                              "region": "us-east-1",
                              "access_key_id": "AKID",
                              "secret_access_key": "secret"}}),
            json!({"id": "bad-gcp", "kind": "gcp_pubsub",
                   "config": {"project_id": "UPPER",
                              "topic_id": "telemetry-events",
                              "auth": {"type": "none"}}}),
            json!({"id": "bad-azure", "kind": "azure_eventhubs",
                   "config": {"namespace": "my-eventhub-ns",
                              "event_hub": "telemetry-hub",
                              "shared_access_key_name": "",
                              "shared_access_key": "secret"}}),
            json!({"id": "bad-pulsar", "kind": "pulsar",
                   "config": {"service_url": "pulsar://127.0.0.1:6650",
                              "tenant": "public",
                              "namespace": "default",
                              "topic": "",
                              "auth": {"type": "none"}}}),
            json!({"id": "bad-mongo", "kind": "mongodb",
                   "config": {"connection_string": "mongodb://127.0.0.1:27017",
                              "database": "",
                              "collection_template": "readings",
                              "operation": {"type": "insert_one"}}}),
            json!({"id": "bad-mssql", "kind": "mssql",
                   "config": {"host": "",
                              "database": "telemetry",
                              "table_template": "dbo.T",
                              "auth": {"type": "integrated"},
                              "query_mode": {"mode": "insertjson"}}}),
            json!({"id": "bad-cassandra", "kind": "cassandra",
                   "config": {"contact_points": [],
                              "keyspace": "telemetry",
                              "table_template": "events",
                              "partition_key_template": "${topic}",
                              "cql_statement_template": "INSERT INTO t VALUES (?, ?, ?, ?)"}}),
            json!({"id": "bad-couchbase", "kind": "couchbase",
                   "config": {"connection_string": "couchbase://127.0.0.1",
                              "bucket": "telemetry",
                              "auth": {"username": "", "password": "secret"},
                              "doc_id_template": "k",
                              "operation": "upsert"}}),
            json!({"id": "bad-tdengine", "kind": "tdengine",
                   "config": {"endpoint": "http://127.0.0.1:6041/rest/sql",
                              "database": "has space",
                              "stable_name": "meters",
                              "subtable_template": "d_${client_id}"}}),
            json!({"id": "bad-iotdb", "kind": "iotdb",
                   "config": {"endpoint": "http://127.0.0.1:18080/rest/v2",
                              "device_path_template": "factory.plant1",
                              "auth": {"username": "root", "password": "root"},
                              "measurements": ["temperature"],
                              "data_types": ["DOUBLE"]}}),
            json!({"id": "bad-timestream", "kind": "timestream",
                   "config": {"database_name": "iot_database",
                              "table_name": "",
                              "region": "us-east-1",
                              "access_key_id": "AKID",
                              "secret_access_key": "secret"}}),
            json!({"id": "bad-dynamodb", "kind": "dynamodb",
                   "config": {"table_name": "telemetry_table",
                              "region": "us-east-1",
                              "access_key_id": "AKID",
                              "secret_access_key": "secret",
                              "partition_key": {"name": "", "template": "${client_id}", "key_type": "S"}}}),
            json!({"id": "bad-snowflake", "kind": "snowflake",
                   "config": {"account": "",
                              "user": "u",
                              "database": "IOT",
                              "schema": "PUBLIC",
                              "table_template": "T",
                              "private_key_pem": "not-a-key"}}),
            json!({"id": "bad-databricks", "kind": "databricks",
                   "config": {"host": "https://host/path",
                              "token": "tok",
                              "table_template": "t"}}),
            json!({"id": "bad-doris", "kind": "doris",
                   "config": {"fe_host": "127.0.0.1",
                              "database": "has space",
                              "table_template": "events",
                              "auth": {"username": "root", "password": ""}}}),
            json!({"id": "bad-bigquery", "kind": "bigquery",
                   "config": {"project_id": "my-iot-project",
                              "dataset_id": "telemetry",
                               "table_template": "9lives",
                               "auth": {"type": "none"}}}),
            json!({"id": "bad-redshift", "kind": "redshift",
                   "config": {"database": "analytics",
                              "table_template": "t",
                              "region": "us-east-1",
                               "access_key_id": "AKID",
                               "secret_access_key": "secret"}}),
        ] {
            let (status, _) = server.post("/api/v1/connectors", payload).await;
            assert_eq!(status, 400);
        }
        let (status, body) = server.get("/api/v1/connectors").await;
        assert_eq!(status, 200);
        assert_eq!(body.as_array().expect("list").len(), 32);
    }

    #[tokio::test]
    async fn test_rules_test_endpoint() {
        let (server, _state) = TestServer::start().await;

        // SQL match with projection.
        let (status, body) = server
            .post(
                "/api/v1/rules/test",
                json!({"sql_query": "SELECT temperature FROM \"sensors/+\" WHERE temperature > 0",
                       "topic_filter": "sensors/+",
                       "topic": "sensors/kitchen",
                       "payload": {"temperature": 72.5, "secret": "x"}}),
            )
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["matched"], json!(true));
        assert_eq!(body["projected"], json!({"temperature": 72.5}));

        // Predicate false.
        let (status, body) = server
            .post(
                "/api/v1/rules/test",
                json!({"sql_query": "SELECT * FROM \"sensors/+\" WHERE temperature > 100.0",
                       "topic": "sensors/kitchen",
                       "payload": {"temperature": 72.5}}),
            )
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["matched"], json!(false));

        // No SQL: passthrough.
        let (status, body) = server
            .post(
                "/api/v1/rules/test",
                json!({"topic": "a/b", "payload": {"v": 1}}),
            )
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["matched"], json!(true));
        assert_eq!(body["projected"], json!({"v": 1}));

        // Broken SQL is a 400.
        let (status, _) = server
            .post(
                "/api/v1/rules/test",
                json!({"sql_query": "SELECT WHERE WHERE",
                       "topic": "a/b",
                       "payload": {}}),
            )
            .await;
        assert_eq!(status, 400);
    }

    #[tokio::test]
    async fn test_rules_test_endpoint_batch() {
        let (server, _state) = TestServer::start().await;

        // Array payloads aggregate as one batch: one row per group.
        let (status, body) = server
            .post(
                "/api/v1/rules/test",
                json!({"sql_query": "SELECT sensor_id, avg(temperature) AS avg_temp FROM \"sensors/+\" GROUP BY sensor_id",
                       "topic": "sensors/kitchen",
                       "payload": [{"sensor_id": "a", "temperature": 10.0},
                                   {"sensor_id": "b", "temperature": 30.0},
                                   {"sensor_id": "a", "temperature": 20.0}]}),
            )
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["matched"], json!(true));
        let rows = body["projected"].as_array().expect("projected rows");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["sensor_id"], json!("a"));
        assert_eq!(rows[0]["avg_temp"], json!(15.0));
        assert_eq!(rows[1]["sensor_id"], json!("b"));
        assert_eq!(rows[1]["avg_temp"], json!(30.0));

        // Empty batches match nothing.
        let (status, body) = server
            .post(
                "/api/v1/rules/test",
                json!({"sql_query": "SELECT avg(temperature) AS a FROM \"sensors/+\"",
                       "topic": "sensors/kitchen",
                       "payload": []}),
            )
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["matched"], json!(false));
        assert_eq!(body["projected"], serde_json::Value::Null);
    }

    #[tokio::test]
    async fn test_rules_functions_catalog() {
        let (server, _state) = TestServer::start().await;

        let (status, body) = server.get("/api/v1/rules/functions").await;
        assert_eq!(status, 200);
        let catalog = body.as_array().expect("function array");
        assert_eq!(catalog.len(), 185);
        let sin = catalog
            .iter()
            .find(|entry| entry["name"] == json!("sin"))
            .expect("sin in catalog");
        assert_eq!(sin["category"], json!("math"));
        assert_eq!(sin["aggregate"], json!(false));
        let avg = catalog
            .iter()
            .find(|entry| entry["name"] == json!("avg"))
            .expect("avg in catalog");
        assert_eq!(avg["aggregate"], json!(true));
    }

    /// Minimal WebSocket client over raw TCP (no extra deps): HTTP
    /// upgrade with the RFC 6455 example key, masked binary sends, and
    /// server frame parsing.
    struct WsClient {
        stream: tokio::net::TcpStream,
        buf: Vec<u8>,
    }

    impl WsClient {
        async fn connect(port: u16) -> Self {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .expect("connect ws");
            // Fixed RFC example key -> fixed accept digest.
            let req = "GET /ws/mqtt HTTP/1.1\r\nHost: test\r\nUpgrade: websocket\r\n\
                       Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                       Sec-WebSocket-Version: 13\r\n\r\n";
            stream.write_all(req.as_bytes()).await.expect("write upgrade");
            let mut buf = Vec::new();
            loop {
                let mut chunk = [0u8; 512];
                let n = stream.read(&mut chunk).await.expect("read upgrade");
                assert!(n > 0, "upgrade response ended early");
                buf.extend_from_slice(&chunk[..n]);
                if let Some(pos) = find_crlf2(&buf) {
                    let head = String::from_utf8_lossy(&buf[..pos + 4]).to_string();
                    assert!(head.starts_with("HTTP/1.1 101"), "expected 101, got: {head}");
                    assert!(head.contains("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
                    let rest = buf[pos + 4..].to_vec();
                    return Self { stream, buf: rest };
                }
            }
        }

        async fn send_bin(&mut self, payload: &[u8]) {
            use tokio::io::AsyncWriteExt;
            let mut frame = vec![0x82u8];
            if payload.len() < 126 {
                frame.push(payload.len() as u8 | 0x80);
            } else if payload.len() < 65536 {
                frame.push(126 | 0x80);
                frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            } else {
                frame.push(127 | 0x80);
                frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
            }
            let mask = [0x11u8, 0x22, 0x33, 0x44];
            frame.extend_from_slice(&mask);
            for (i, byte) in payload.iter().enumerate() {
                frame.push(byte ^ mask[i % 4]);
            }
            self.stream.write_all(&frame).await.expect("write frame");
        }

        /// Next server message payload (`None` on clean EOF).
        async fn recv_msg(&mut self) -> Option<Vec<u8>> {
            use tokio::io::AsyncReadExt;
            loop {
                if let Some((payload, consumed)) = parse_ws_frame(&self.buf) {
                    self.buf.drain(..consumed);
                    return Some(payload);
                }
                let mut chunk = [0u8; 4096];
                match self.stream.read(&mut chunk).await.expect("read frame") {
                    0 => return None,
                    n => self.buf.extend_from_slice(&chunk[..n]),
                }
            }
        }
    }

    fn find_crlf2(buf: &[u8]) -> Option<usize> {
        buf.windows(4).position(|w| w == b"\r\n\r\n")
    }

    /// Parse one server frame (unmasked): `(payload, consumed)` or `None`
    /// when incomplete. Close frames surface as empty payloads.
    fn parse_ws_frame(buf: &[u8]) -> Option<(Vec<u8>, usize)> {
        if buf.len() < 2 || buf[1] & 0x80 != 0 {
            return None;
        }
        let opcode = buf[0] & 0x0F;
        let mut header = 2usize;
        let mut length = (buf[1] & 0x7F) as usize;
        if length == 126 {
            if buf.len() < 4 {
                return None;
            }
            length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
            header = 4;
        } else if length == 127 {
            if buf.len() < 10 {
                return None;
            }
            length = u64::from_be_bytes(buf[2..10].try_into().ok()?) as usize;
            header = 10;
        }
        if buf.len() < header + length {
            return None;
        }
        if opcode == 0x8 {
            return Some((Vec::new(), header + length));
        }
        if opcode != 0x1 && opcode != 0x2 {
            return None;
        }
        Some((buf[header..header + length].to_vec(), header + length))
    }

    // -- MQTT packet builders (mirror of the dashboard console) --

    fn mqtt_remaining(mut n: usize) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (n % 128) as u8;
            n /= 128;
            if n > 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if n == 0 {
                break;
            }
        }
        out
    }

    fn mqtt_str(out: &mut Vec<u8>, s: &str) {
        out.extend_from_slice(&(s.len() as u16).to_be_bytes());
        out.extend_from_slice(s.as_bytes());
    }

    fn mqtt_connect(client_id: &str, username: Option<&str>, password: Option<&[u8]>) -> Vec<u8> {
        let mut body = vec![0, 4, b'M', b'Q', b'T', b'T', 4];
        let mut flags = 0x02u8;
        if username.is_some() {
            flags |= 0x80;
        }
        if password.is_some() {
            flags |= 0x40;
        }
        body.push(flags);
        body.extend_from_slice(&60u16.to_be_bytes());
        mqtt_str(&mut body, client_id);
        if let Some(user) = username {
            mqtt_str(&mut body, user);
        }
        if let Some(pass) = password {
            body.extend_from_slice(&(pass.len() as u16).to_be_bytes());
            body.extend_from_slice(pass);
        }
        let mut packet = vec![0x10];
        packet.extend_from_slice(&mqtt_remaining(body.len()));
        packet.extend_from_slice(&body);
        packet
    }

    fn mqtt_subscribe(pid: u16, subs: &[(&str, u8)]) -> Vec<u8> {
        let mut body = pid.to_be_bytes().to_vec();
        for (filter, qos) in subs {
            mqtt_str(&mut body, filter);
            body.push(*qos);
        }
        let mut packet = vec![0x82];
        packet.extend_from_slice(&mqtt_remaining(body.len()));
        packet.extend_from_slice(&body);
        packet
    }

    fn mqtt_publish(topic: &str, pid: u16, qos: u8, payload: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        mqtt_str(&mut body, topic);
        if qos > 0 {
            body.extend_from_slice(&pid.to_be_bytes());
        }
        body.extend_from_slice(payload);
        let mut packet = vec![0x30 | (qos << 1)];
        packet.extend_from_slice(&mqtt_remaining(body.len()));
        packet.extend_from_slice(&body);
        packet
    }

    fn mqtt_packet_type(packet: &[u8]) -> u8 {
        packet[0] >> 4
    }

    #[tokio::test]
    async fn test_ws_mqtt_console_flow() {
        let (server, _state) = TestServer::start().await;

        // Subscriber console: CONNECT -> CONNACK, SUBSCRIBE -> SUBACK.
        let mut sub = WsClient::connect(server.port).await;
        sub.send_bin(&mqtt_connect("console-a", None, None)).await;
        let connack = sub.recv_msg().await.expect("connack");
        assert_eq!(mqtt_packet_type(&connack), 2);
        assert_eq!(connack[3], 0, "CONNACK return code must be 0");
        sub.send_bin(&mqtt_subscribe(7, &[("demo/#", 1)])).await;
        let suback = sub.recv_msg().await.expect("suback");
        assert_eq!(mqtt_packet_type(&suback), 9);
        assert_eq!(&suback[4..], &[1], "granted QoS 1");

        // Publisher console: QoS 1 publish lands on the subscriber.
        let mut publ = WsClient::connect(server.port).await;
        publ.send_bin(&mqtt_connect("console-b", None, None)).await;
        let connack = publ.recv_msg().await.expect("connack");
        assert_eq!(connack[3], 0);
        publ.send_bin(&mqtt_publish("demo/1", 42, 1, b"hi-ws")).await;
        // Publisher gets its PUBACK...
        let puback = publ.recv_msg().await.expect("puback");
        assert_eq!(mqtt_packet_type(&puback), 4);
        // ...and the subscriber gets the delivery with flags + payload.
        let delivery = sub.recv_msg().await.expect("delivery");
        assert_eq!(mqtt_packet_type(&delivery), 3);
        assert_eq!(delivery[0] & 0x06, 0x02, "downstream QoS 1");
        assert!(delivery
            .windows(b"demo/1".len())
            .any(|w| w == b"demo/1"));
        assert!(delivery.ends_with(b"hi-ws"));

        // PINGREQ -> PINGRESP on the same socket.
        publ.send_bin(&[0xC0, 0x00]).await;
        let pong = publ.recv_msg().await.expect("pingresp");
        assert_eq!(pong, vec![0xD0, 0x00]);
    }

    #[tokio::test]
    async fn test_ws_auth_rejected_with_0x86() {
        let (server, state) = TestServer::start().await;
        state.auth.add_user("alice", b"s3cret");

        let mut client = WsClient::connect(server.port).await;
        client
            .send_bin(&mqtt_connect("console-x", Some("alice"), Some(b"wrong")))
            .await;
        let connack = client.recv_msg().await.expect("connack");
        assert_eq!(mqtt_packet_type(&connack), 2);
        assert_eq!(connack[3], 0x86, "bad password must yield 0x86");
        // Socket closes right after the failed CONNACK.
        assert!(client.recv_msg().await.is_none());
        assert!(state.sessions.get("console-x").is_none());
    }

    #[tokio::test]
    async fn test_ws_subscribe_denied_with_0x87() {
        let (server, state) = TestServer::start().await;
        state.auth.add_rule(broker_auth::AclRule::new(
            "console-y",
            broker_auth::AclAction::All,
            "#",
            false,
        ));

        let mut client = WsClient::connect(server.port).await;
        client.send_bin(&mqtt_connect("console-y", None, None)).await;
        let connack = client.recv_msg().await.expect("connack");
        assert_eq!(connack[3], 0);

        client.send_bin(&mqtt_subscribe(3, &[("t", 0)])).await;
        let suback = client.recv_msg().await.expect("suback");
        assert_eq!(mqtt_packet_type(&suback), 9);
        assert_eq!(&suback[4..], &[0x87], "denied filter must yield 0x87");
    }
}
