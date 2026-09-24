use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use broker_auth::{AclAction, AclRule, MemoryAuth};
use broker_config::ConfigRegistry;
use broker_observability::{Metrics, NodeReadiness, StatsStore};
use broker_protocol::{QoS, Topic, TopicFilter};
use broker_router::{ConnTable, Router as SubscriptionRouter};
use broker_rules::{Rule, RuleAction, RuleEngine, RuleEngineError};
use broker_session::SessionManager;
use brokerlink::BrokerFrame;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;

use crate::admin_users::AdminUsers;
use crate::v5::auth::ApiTokens;

pub mod admin_users;
pub mod api_auth;
pub mod dashboard;
pub mod errors;
pub mod licence;
pub mod node_scope;
pub mod pagination;
pub mod swagger;
pub mod v5;
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
    pub admin_users: Arc<AdminUsers>,
    pub tokens: Arc<ApiTokens>,
    /// Kernel-owned configuration registry: lock-free snapshots of admin
    /// users, MQTT users/ACLs, rules and connectors.
    pub config: Arc<ConfigRegistry>,
    /// Local node name (`--node-id`): used by the node-scope helper for
    /// `/nodes/{node}/...` routes. Stored only until W1 wires it in.
    pub node_id: String,
    /// Kernel→edge close sender (W0-26): the kick path hands `ConnClose`
    /// frames here before tearing down kernel state. The sender type is
    /// the same `UnboundedSender<BrokerFrame>` the kernel uses for its
    /// per-connection edge mailboxes; sends are non-blocking and a
    /// failed send only warns (edge may already be gone). Guaranteed
    /// delivery rides the synchronous `ConnTable::route` in the kick
    /// path; the async `serve_api` forwarder routes this copy after the
    /// connection is unregistered and drops it by design.
    pub edge_tx: UnboundedSender<BrokerFrame>,
    /// Ban directory for `/api/v5/banned` (W1-01): bounded matcher map
    /// with lazy expiry. Management-plane only; never touched on the
    /// per-message path.
    pub bans: Arc<crate::v5::banned::BanStore>,
    /// Alarm directory for `/api/v5/alarms` (W1-16): bounded active map
    /// plus deactivated history. Management-plane only; never touched on
    /// the per-message path.
    pub alarms: Arc<crate::v5::alarms::AlarmStore>,
    /// Monitor history for `/api/v5/monitor` (W1-19): bounded ring of
    /// sampled points. Management-plane only; never touched on the
    /// per-message path.
    pub monitor: Arc<crate::v5::monitor::MonitorHistory>,
    /// Gauge-plus-high-water-mark store for `/api/v5/stats` and
    /// `/api/v5/nodes/{node}/stats` (W1-25): the kernel keeps it exact
    /// from connection/subscription/retained lifecycle points and the
    /// handlers below read one constant-time snapshot per request.
    /// Management-plane only; never touched on the per-message path.
    pub stats: Arc<StatsStore>,
    /// Node readiness flag for `GET /api/v5/status` (W1-27): single
    /// atomic bool shared with the kernel. The handler does one
    /// constant-time load per request and reports the documented up
    /// value while ready. Management-plane only; never touched on the
    /// per-message path.
    pub readiness: Arc<NodeReadiness>,
    /// Retained-delivery settings for `GET/PUT /api/v5/mqtt/retainer`
    /// (W1-28): single validated struct behind a short lock plus a
    /// persistence hook. Management-plane only; never touched on the
    /// per-message path.
    pub retainer_config: Arc<crate::v5::retainer::RetainerConfigStore>,
    /// Retained store for `GET /api/v5/mqtt/retainer/message/{topic}`
    /// (W1-28): shared with the kernel so management reads observe the
    /// same MQTT ingress state. Reads take only a short read lock and
    /// clone at most one message, so they never block delivery.
    /// Bounded by `broker_storage::MAX_RETAINED_MESSAGES`.
    pub retained: Arc<dyn broker_storage::RetainedStore>,
    /// Slow-subscription recorder for `GET/DELETE /api/v5/slow_subscriptions`
    /// (W1-30): bounded ranked table of slow deliveries. Management-plane
    /// only; never touched on the per-message path.
    pub slow_subs: Arc<crate::v5::slow_subscriptions::SlowSubsStore>,
    /// Slow-subscription thresholds for `GET/PUT
    /// /api/v5/slow_subscriptions/settings` (W1-31): single validated
    /// struct behind a short lock. Management-plane only; readers take a
    /// snapshot clone and never touch the per-message path.
    pub slow_subs_settings: Arc<crate::v5::slow_subscriptions::SlowSubsSettingsStore>,
    /// Packet-tracing flag for `GET/PUT /api/v5/tracing` (W1-32):
    /// single atomic bool. Session lifecycle raises it while a session
    /// exists and lowers it when none remains; the kernel publish event
    /// reads it first as its cheap off-state check (F1-04, T-74).
    pub tracing: Arc<crate::v5::tracing::TracingFlagStore>,
    /// Trace-session registry for `GET/POST/DELETE /api/v5/trace` (W1-33)
    /// plus `DELETE /api/v5/trace/{name}` (W1-34):
    /// bounded map of capture sessions. Reads and writes are
    /// management-plane only; the kernel publish event appends through
    /// `TraceStore::capture_publish` (F1-04, T-74).
    pub traces: Arc<crate::v5::trace::TraceStore>,
    /// Auto-subscribe list for `GET/PUT /api/v5/mqtt/auto_subscribe`
    /// (W1-39): bounded validated list plus the connect-time hook. The
    /// routes read one bounded snapshot per request; the kernel hook
    /// clones the same capped list once per bind, never per message.
    pub auto_subscribe: Arc<crate::v5::auto_subscribe::AutoSubscribeStore>,
    /// Licence request/install/status store for B2-04: cluster identity,
    /// stored token and trusted signing set. Management-plane only; never
    /// touched on the per-message path.
    pub licence: Arc<crate::licence::LicenceStore>,
    /// Ordered authenticator chain for `GET/POST /api/v5/authentication`
    /// (W2-02): bounded ordered list plus the CONNECT-time consult. The
    /// routes read one bounded snapshot per request; the kernel CONNECT
    /// path loads one lock-free snapshot per connect
    /// (`crates/broker-node/src/main.rs`, CONNECT handling) and never
    /// takes the chain write lock; publish and deliver never touch it.
    pub authn_chain: Arc<broker_auth::AuthnChain>,
    /// Node authentication cache for `GET
    /// /api/v5/authentication/node_cache/status` and `POST
    /// /api/v5/authentication/node_cache/reset` (W2-03): bounded
    /// per-username record of successful credentialed CONNECTs. The
    /// routes read one bounded snapshot per request; the kernel CONNECT
    /// path records one entry per success
    /// (`crates/broker-node/src/main.rs`, CONNECT handling, plus the
    /// console CONNECT in `crates/broker-api/src/ws.rs`); publish and
    /// deliver never touch it.
    pub authn_node_cache: Arc<broker_auth::NodeAuthCache>,
    /// Global authentication settings for `GET/PUT
    /// /api/v5/authentication/settings` (W2-05): single validated struct
    /// with registry persistence plus a lock-free CONNECT snapshot. The
    /// routes read one snapshot per request; the kernel CONNECT path
    /// loads one lock-free snapshot per connect
    /// (`crates/broker-node/src/main.rs`, CONNECT handling, plus the
    /// console CONNECT in `crates/broker-api/src/ws.rs`); publish and
    /// deliver never touch it.
    pub authn_settings: Arc<crate::v5::authn_settings::AuthnSettingsStore>,
    ws_conn_counter: Arc<AtomicU64>,
}

impl ApiState {
    // One handle per subsystem plus the config registry, node name and
    // the kernel→edge close sender; bundling them would hide the
    // construction sites without helping.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        engine: Arc<RuleEngine>,
        sessions: Arc<SessionManager>,
        router: Arc<SubscriptionRouter>,
        metrics: Arc<Metrics>,
        auth: Arc<MemoryAuth>,
        conns: Arc<ConnTable>,
        config: Arc<ConfigRegistry>,
        node_id: String,
        edge_tx: UnboundedSender<BrokerFrame>,
    ) -> Self {
        // Boot seeding (W0-21): route the loaded MQTT users/ACLs into the
        // very instance the caller shares (the kernel passes its BrokerLink
        // `MemoryAuth` here), so no second copy can diverge. An empty
        // snapshot is a no-op (today's empty behaviour).
        auth.seed_from_registry(&config);
        // Boot replay (W0-22): route the loaded rules into the very engine
        // instance the caller shares, through the same validated create
        // path as `RuleEngine::create_rule`. An empty snapshot is a no-op
        // (today's empty behaviour); an invalid stored rule fails boot
        // loudly instead of being skipped silently.
        if let Err(error) = engine.seed_from_registry(&config) {
            panic!("invalid stored rules snapshot: {error}");
        }
        // Rule spill accounting (B4-07): mirror the shared engine's
        // ingress spill counters into these metrics. First attach wins,
        // so a kernel-shared engine keeps the kernel's mirror while
        // standalone engines report here; memory-only inputs only ever
        // count refusals.
        engine.set_metrics(&metrics);
        // Boot replay (W0-23): merge the persisted connectors into the
        // v5 store and re-register every live sink through the same path
        // `create_connector` uses. An empty snapshot is a no-op (today's
        // empty behaviour); an invalid snapshot fails boot loudly
        // instead of being skipped silently.
        crate::v5::rules::seed_connectors_from_registry(&config, &engine);
        // Boot seeding (W2-02): route the loaded authenticator chain into
        // a shared chain instance so management reads and the CONNECT
        // consult observe the same order without a restart. An empty
        // snapshot is a no-op (today's empty behaviour).
        let authn_chain = Arc::new(broker_auth::AuthnChain::from_registry(&config));
        // Boot seeding (W2-03): route the loaded node-cache config into
        // a shared cache instance so management reads and the CONNECT
        // recorder observe the same enabled flag and cap without a
        // restart. Cached entries always start empty (memory-only).
        let authn_node_cache = Arc::new(broker_auth::NodeAuthCache::from_registry(&config));
        // Boot seeding (W2-05): route the loaded authentication
        // settings into a shared store so management reads and the
        // CONNECT consult observe the same snapshot without a restart.
        // The subscriber keeps the node cache's enabled flag and cap in
        // sync with the settings' cache half on every validated replace.
        let authn_settings = Arc::new(broker_auth::AuthnSettingsStore::from_registry(&config));
        {
            let cache = Arc::clone(&authn_node_cache);
            authn_settings.set_subscriber(Arc::new(
                move |next: &broker_config::AuthnSettingsConf| {
                    cache.apply_settings(next.node_cache.enable, next.node_cache.max_count);
                },
            ));
            let current = authn_settings.get();
            authn_node_cache
                .apply_settings(current.node_cache.enable, current.node_cache.max_count);
        }
        Self {
            engine,
            sessions,
            router,
            metrics,
            auth,
            conns,
            admin_users: Arc::new(AdminUsers::from_registry(&config)),
            tokens: Arc::new(ApiTokens::new()),
            config,
            node_id,
            edge_tx,
            bans: Arc::new(crate::v5::banned::BanStore::new()),
            alarms: Arc::new(crate::v5::alarms::AlarmStore::new()),
            monitor: Arc::new(crate::v5::monitor::MonitorHistory::new()),
            stats: Arc::new(StatsStore::new()),
            readiness: Arc::new(NodeReadiness::new()),
            retainer_config: Arc::new(crate::v5::retainer::RetainerConfigStore::new()),
            retained: Arc::new(broker_storage::MemoryStore::new()),
            slow_subs: Arc::new(crate::v5::slow_subscriptions::SlowSubsStore::new()),
            slow_subs_settings: Arc::new(
                crate::v5::slow_subscriptions::SlowSubsSettingsStore::new(),
            ),
            tracing: Arc::new(crate::v5::tracing::TracingFlagStore::new()),
            traces: Arc::new(crate::v5::trace::TraceStore::new()),
            auto_subscribe: Arc::new(crate::v5::auto_subscribe::AutoSubscribeStore::new()),
            licence: Arc::new(crate::licence::LicenceStore::new()),
            authn_chain,
            authn_node_cache,
            authn_settings,
            ws_conn_counter: Arc::new(AtomicU64::new(1 << 62)),
        }
    }

    /// Standalone state for tests and tools (empty sessions/router).
    /// Uses validated defaults without touching the kernel data dir.
    /// The kernel→edge sender is a throwaway channel whose receiver is
    /// immediately dropped, so kick sends fail silently there and keep
    /// today's unbind-only behaviour in unit tests.
    pub fn standalone(engine: Arc<RuleEngine>) -> Self {
        let (edge_tx, edge_rx) = tokio::sync::mpsc::unbounded_channel::<BrokerFrame>();
        drop(edge_rx);
        // Standalone settings store shares its subscriber with the very
        // node-cache instance below, so validated replaces keep the
        // cache's enabled flag and cap in sync without a restart.
        let authn_node_cache = Arc::new(broker_auth::NodeAuthCache::new());
        let authn_settings = Arc::new(broker_auth::AuthnSettingsStore::new());
        {
            let cache = Arc::clone(&authn_node_cache);
            authn_settings.set_subscriber(Arc::new(
                move |next: &broker_config::AuthnSettingsConf| {
                    cache.apply_settings(next.node_cache.enable, next.node_cache.max_count);
                },
            ));
        }
        Self {
            engine,
            sessions: Arc::new(SessionManager::new()),
            router: Arc::new(SubscriptionRouter::new()),
            metrics: Arc::new(Metrics::new()),
            auth: Arc::new(MemoryAuth::new()),
            conns: Arc::new(ConnTable::default()),
            admin_users: Arc::new(AdminUsers::with_default_admin()),
            tokens: Arc::new(ApiTokens::new()),
            config: defaults_registry(),
            node_id: "indra-node-1".to_string(),
            edge_tx,
            bans: Arc::new(crate::v5::banned::BanStore::new()),
            alarms: Arc::new(crate::v5::alarms::AlarmStore::new()),
            monitor: Arc::new(crate::v5::monitor::MonitorHistory::new()),
            stats: Arc::new(StatsStore::new()),
            readiness: Arc::new(NodeReadiness::new()),
            retainer_config: Arc::new(crate::v5::retainer::RetainerConfigStore::new()),
            retained: Arc::new(broker_storage::MemoryStore::new()),
            slow_subs: Arc::new(crate::v5::slow_subscriptions::SlowSubsStore::new()),
            slow_subs_settings: Arc::new(
                crate::v5::slow_subscriptions::SlowSubsSettingsStore::new(),
            ),
            tracing: Arc::new(crate::v5::tracing::TracingFlagStore::new()),
            traces: Arc::new(crate::v5::trace::TraceStore::new()),
            auto_subscribe: Arc::new(crate::v5::auto_subscribe::AutoSubscribeStore::new()),
            licence: Arc::new(crate::licence::LicenceStore::new()),
            authn_chain: Arc::new(broker_auth::AuthnChain::new()),
            authn_node_cache,
            authn_settings,
            ws_conn_counter: Arc::new(AtomicU64::new(1 << 62)),
        }
    }

    /// Mint a collision-proof virtual connection id for a dashboard
    /// WebSocket client (far above BEAM's monotonic conn ids).
    pub fn next_ws_conn_id(&self) -> u64 {
        self.ws_conn_counter.fetch_add(1, Ordering::SeqCst)
    }
}

/// Defaults-only registry for standalone state (tests and tools).
///
/// Loads from a unique scratch path that is never created, so `load`
/// yields validated empty roots with no filesystem writes and the
/// standalone state can never observe the kernel data dir.
fn defaults_registry() -> Arc<ConfigRegistry> {
    static SCRATCH_COUNTER: AtomicU64 = AtomicU64::new(0);
    let slot = SCRATCH_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!(
        "indramqtt-standalone-{nanos}-{}-{slot}",
        std::process::id()
    ));
    Arc::new(ConfigRegistry::load(&dir).expect("validated defaults always load"))
}

/// Public routes (dashboard assets, health, login, MQTT-over-WebSocket)
/// stay outside the authentication layer; every other route requires a
/// bearer token enforced by [`api_auth::require_api_auth`].
pub fn router(state: ApiState) -> Router {
    let protected: Router<ApiState> = Router::new()
        .route("/schemas", get(v5::schemas::list_schemas))
        .route("/schemas/:name", get(v5::schemas::get_schema))
        .nest("/api/v5", v5::protected_router())
        .route("/api/v1/nodes", get(get_nodes))
        .route("/api/v1/clients", get(get_clients))
        .route("/api/v1/clients/:id", get(get_client))
        .route("/api/v1/metrics", get(get_metrics))
        .route(
            "/api/v1/connectors",
            get(get_connectors).post(create_connector),
        )
        .route("/api/v1/auth/users", get(list_users).post(create_user))
        .route("/api/v1/auth/users/:username", delete(delete_user))
        .route("/api/v1/auth/acls", get(list_acls).post(create_acl))
        .route("/api/v1/auth/acls/:id", delete(delete_acl))
        .route("/api/v1/rules", get(list_rules).post(create_rule))
        .route("/api/v1/rules/test", post(test_rule))
        .route("/api/v1/rules/functions", get(list_functions))
        .route("/api/v1/rules/:id", get(get_rule).delete(delete_rule))
        .route("/api/v1/licence/request", get(licence::get_request))
        .route("/api/v1/licence/install", post(licence::install_licence))
        .route("/api/v1/licence/status", get(licence::get_status))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            api_auth::require_api_auth,
        ));
    let public: Router<ApiState> = Router::new()
        .route("/", get(redirect_to_dashboard))
        .route("/dashboard", get(get_dashboard))
        .route("/ui", get(get_modern_ui))
        .route("/swagger", get(get_swagger_ui))
        .route("/api-docs/openapi.json", get(get_openapi_spec))
        .route("/assets/*path", get(get_dashboard_asset))
        .route("/static/*path", get(get_dashboard_static_asset))
        .route("/favicon.ico", get(get_dashboard_favicon))
        .route("/version", get(get_dashboard_version))
        .route("/ws/mqtt", get(ws::ws_mqtt_handler))
        .route("/healthz", get(|| async { "OK" }))
        .nest("/api/v5", v5::public_router())
        .merge(protected);
    public.with_state(state)
}

/// Serve the management API on an already-bound listener.
pub async fn serve(listener: tokio::net::TcpListener, state: ApiState) -> std::io::Result<()> {
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
    for candidate in &["dashboard/dist/index.html", "../dashboard/dist/index.html"] {
        if let Ok(content) = tokio::fs::read_to_string(candidate).await {
            return ([("content-type", "text/html; charset=utf-8")], content).into_response();
        }
    }
    (
        [("content-type", "text/html; charset=utf-8")],
        dashboard::DASHBOARD_HTML,
    )
        .into_response()
}

async fn get_swagger_ui() -> Response {
    (
        [("content-type", "text/html; charset=utf-8")],
        swagger::swagger_ui_html(),
    )
        .into_response()
}

async fn get_openapi_spec() -> Response {
    (
        [("content-type", "application/json; charset=utf-8")],
        swagger::openapi_spec_json(),
    )
        .into_response()
}

async fn get_modern_ui() -> Response {
    for candidate in &["dashboard/dist/index.html", "../dashboard/dist/index.html"] {
        if let Ok(content) = tokio::fs::read_to_string(candidate).await {
            return ([("content-type", "text/html; charset=utf-8")], content).into_response();
        }
    }
    (
        [("content-type", "text/html; charset=utf-8")],
        dashboard::DASHBOARD_HTML,
    )
        .into_response()
}

async fn get_dashboard_asset(axum::extract::Path(path): axum::extract::Path<String>) -> Response {
    let clean = path.trim_start_matches('/').replace("..", "");
    for base in &["dashboard/dist/assets", "../dashboard/dist/assets"] {
        let p = std::path::PathBuf::from(base).join(&clean);
        if let Ok(bytes) = tokio::fs::read(&p).await {
            let mime = if clean.ends_with(".js") {
                "application/javascript"
            } else if clean.ends_with(".css") {
                "text/css"
            } else if clean.ends_with(".svg") {
                "image/svg+xml"
            } else if clean.ends_with(".png") {
                "image/png"
            } else if clean.ends_with(".ico") {
                "image/x-icon"
            } else {
                "application/octet-stream"
            };
            return (
                [
                    ("content-type", mime),
                    ("cache-control", "public, max-age=31536000, immutable"),
                ],
                bytes,
            )
                .into_response();
        }
    }
    (StatusCode::NOT_FOUND, "Asset not found").into_response()
}

async fn get_dashboard_static_asset(
    axum::extract::Path(path): axum::extract::Path<String>,
) -> Response {
    let clean = path.trim_start_matches('/').replace("..", "");
    for base in &["dashboard/dist/static", "../dashboard/dist/static"] {
        let p = std::path::PathBuf::from(base).join(&clean);
        if let Ok(bytes) = tokio::fs::read(&p).await {
            let mime = if clean.ends_with(".js") {
                "application/javascript"
            } else if clean.ends_with(".css") {
                "text/css"
            } else if clean.ends_with(".svg") {
                "image/svg+xml"
            } else if clean.ends_with(".png") {
                "image/png"
            } else if clean.ends_with(".ico") {
                "image/x-icon"
            } else if clean.ends_with(".woff2") {
                "font/woff2"
            } else if clean.ends_with(".woff") {
                "font/woff"
            } else if clean.ends_with(".ttf") {
                "font/ttf"
            } else if clean.ends_with(".json") {
                "application/json"
            } else {
                "application/octet-stream"
            };
            return (
                [
                    ("content-type", mime),
                    ("cache-control", "public, max-age=31536000, immutable"),
                ],
                bytes,
            )
                .into_response();
        }
    }
    (StatusCode::NOT_FOUND, "Static asset not found").into_response()
}

async fn get_dashboard_favicon() -> Response {
    for candidate in &[
        "dashboard/dist/favicon.ico",
        "../dashboard/dist/favicon.ico",
    ] {
        if let Ok(bytes) = tokio::fs::read(candidate).await {
            return ([("content-type", "image/x-icon")], bytes).into_response();
        }
    }
    StatusCode::NOT_FOUND.into_response()
}

async fn get_dashboard_version() -> Response {
    for candidate in &["dashboard/dist/version", "../dashboard/dist/version"] {
        if let Ok(content) = tokio::fs::read_to_string(candidate).await {
            return ([("content-type", "text/plain; charset=utf-8")], content).into_response();
        }
    }
    StatusCode::NOT_FOUND.into_response()
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

/// A registry commit or atomic save failed after the in-memory MQTT
/// user/ACL mutation applied: the loss must never be silent, so the
/// caller gets a 500 (mirrors the admin-users `Persist` mapping).
fn persist_error(error: broker_config::ConfigError) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorBody {
            error: format!("cannot persist MQTT users: {error}"),
        }),
    )
        .into_response()
}

/// A registry commit or atomic save failed after the in-memory rule
/// mutation applied: the loss must never be silent, so the caller gets
/// a 500. [`RuleEngineError::Persist`] already renders as
/// `cannot persist rules: ...`, so its display is reused verbatim
/// (never re-prefixed).
fn rule_persist_error(error: RuleEngineError) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorBody {
            error: error.to_string(),
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

    let rule: Rule =
        match state
            .engine
            .create_rule(req.name, topic_filter, req.sql_query, req.enabled, actions)
        {
            Ok(rule) => rule,
            // A persist failure is a 500 (the in-memory rule stays but the
            // disk save failed); validation failures stay 400.
            Err(error @ RuleEngineError::Persist(_)) => return rule_persist_error(error),
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
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => not_found(&id),
        Err(error) => rule_persist_error(error),
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
async fn test_rule(State(_state): State<ApiState>, Json(req): Json<TestRuleRequest>) -> Response {
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
    if let Err(error) = state
        .auth
        .add_user(req.username.clone(), req.password.as_bytes())
    {
        return persist_error(error);
    }
    if let Some(quotas) = req.quotas.map(|dto| broker_auth::UserQuotas {
        max_connections: dto.max_connections,
        max_publish_rate: dto.max_publish_rate,
        max_publish_burst: dto.max_publish_burst,
    }) {
        // The user was just created, so this always finds it; a persist
        // failure is still surfaced instead of silently dropped.
        if let Err(error) = state.auth.set_quotas(&req.username, quotas) {
            return persist_error(error);
        }
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

async fn create_acl(State(state): State<ApiState>, Json(req): Json<CreateAclRequest>) -> Response {
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
    if let Err(error) = state.auth.add_rule(AclRule::new(
        req.client_pattern.clone(),
        action,
        req.topic_pattern.clone(),
        req.allow,
    )) {
        return persist_error(error);
    }
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

async fn delete_user(
    State(state): State<ApiState>,
    axum::extract::Path(username): axum::extract::Path<String>,
) -> Response {
    match state.auth.remove_user(&username) {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => persist_error(error),
    }
}

async fn delete_acl(
    State(state): State<ApiState>,
    axum::extract::Path(id): axum::extract::Path<usize>,
) -> Response {
    match state.auth.remove_rule(id) {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => persist_error(error),
    }
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
                // Production write path on the maintained `rdkafka`
                // driver; the hand-written TCP framing stays for offline
                // unit tests only.
                let transport = std::sync::Arc::new(
                    broker_connectors::RdkafkaKafkaTransport::new(&config)
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
                // Production write path on the maintained `lapin`
                // driver; the hand-written TCP framing stays for offline
                // unit tests only.
                let transport = std::sync::Arc::new(
                    broker_connectors::LapinRabbitTransport::new(&config.endpoint)
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
                    broker_connectors::DriverPgTransport::new(
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
                    broker_connectors::DriverRedisTransport::new(&config.endpoint)
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
                    broker_connectors::DriverMySqlTransport::new(
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
                let transport = std::sync::Arc::new(
                    broker_connectors::DriverClickHouseTransport::new(&config)
                        .map_err(|e| format!("invalid clickhouse transport: {e}"))?,
                );
                let sink = broker_connectors::ClickHouseSink::new(config, transport)
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
                    broker_connectors::SdkS3Transport::new(&config)
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
                    broker_connectors::DriverElasticsearchTransport::new(&config)
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
                    broker_connectors::DriverTimescaleDbTransport::new(
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
                    broker_connectors::RumqttcMqttBridgeTransport::new(&config)
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
                let sink = broker_connectors::DiskLogSink::open(config, writer)
                    .await
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
                    broker_connectors::SdkGcpPubSubTransport::new(&config)
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
            "oci_streaming" | "oci" | "oracle_streaming" => {
                let config: broker_connectors::OciStreamingSinkConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid oci_streaming config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid oci_streaming config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::HttpOciStreamingTransport::new(
                        &config,
                        reqwest::Client::new(),
                    )
                    .map_err(|e| format!("invalid oci_streaming transport: {e}"))?,
                );
                let sink = broker_connectors::OciStreamingSink::new(config, transport)
                    .map_err(|e| format!("invalid oci_streaming sink: {e}"))?;
                Ok(("oci_streaming".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "aws_iot" | "aws_iot_core" => {
                let config: broker_connectors::AwsIotConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid aws_iot config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid aws_iot config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::TlsAwsIotTransport::new(&config)
                        .map_err(|e| format!("invalid aws_iot transport: {e}"))?,
                );
                let sink = broker_connectors::AwsIotSink::new(config, transport)
                    .map_err(|e| format!("invalid aws_iot sink: {e}"))?;
                Ok(("aws_iot".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "azure_iot" | "azure_iothub" | "iothub" => {
                let config: broker_connectors::AzureIotConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid azure_iot config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid azure_iot config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::TlsAzureIotTransport::new(&config)
                        .map_err(|e| format!("invalid azure_iot transport: {e}"))?,
                );
                let sink = broker_connectors::AzureIotSink::new(config, transport)
                    .map_err(|e| format!("invalid azure_iot sink: {e}"))?;
                Ok(("azure_iot".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "gcp_iot" | "gcp_iot_core" | "cloud_iot" => {
                let config: broker_connectors::GcpIotConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid gcp_iot config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid gcp_iot config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::TlsGcpIotTransport::new(&config)
                        .map_err(|e| format!("invalid gcp_iot transport: {e}"))?,
                );
                let sink = broker_connectors::GcpIotSink::new(config, transport)
                    .map_err(|e| format!("invalid gcp_iot sink: {e}"))?;
                Ok(("gcp_iot".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "opc_ua" | "opcua" => {
                let config: broker_connectors::OpcUaSinkConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid opc_ua config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid opc_ua config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::TcpOpcUaTransport::new(&config)
                        .map_err(|e| format!("invalid opc_ua transport: {e}"))?,
                );
                let sink = broker_connectors::OpcUaSink::new(config, transport)
                    .map_err(|e| format!("invalid opc_ua sink: {e}"))?;
                Ok(("opc_ua".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "azure_blob" | "azureblob" | "azblob" => {
                let config: broker_connectors::AzureBlobSinkConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid azure_blob config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid azure_blob config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::HttpAzureBlobTransport::new(&config, reqwest::Client::new())
                        .map_err(|e| format!("invalid azure_blob transport: {e}"))?,
                );
                let sink = broker_connectors::AzureBlobSink::new(config, transport)
                    .map_err(|e| format!("invalid azure_blob sink: {e}"))?;
                Ok(("azure_blob".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "tablestore" | "ots" | "alibaba_tablestore" => {
                let config: broker_connectors::TablestoreSinkConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid tablestore config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid tablestore config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::HttpTablestoreTransport::new(
                        &config,
                        reqwest::Client::new(),
                    )
                    .map_err(|e| format!("invalid tablestore transport: {e}"))?,
                );
                let sink = broker_connectors::TablestoreSink::new(config, transport)
                    .map_err(|e| format!("invalid tablestore sink: {e}"))?;
                Ok(("tablestore".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "s3_tables" | "s3tables" | "iceberg" => {
                let config: broker_connectors::S3TablesSinkConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid s3_tables config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid s3_tables config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::HttpS3TablesTransport::new(
                        &config,
                        reqwest::Client::new(),
                    )
                    .map_err(|e| format!("invalid s3_tables transport: {e}"))?,
                );
                let sink = broker_connectors::S3TablesSink::new(config, transport)
                    .map_err(|e| format!("invalid s3_tables sink: {e}"))?;
                Ok(("s3_tables".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "confluent" | "confluent_kafka" | "confluent_cloud" => {
                let config: broker_connectors::ConfluentKafkaConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid confluent config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid confluent config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::RdkafkaConfluentTransport::new(&config)
                        .map_err(|e| format!("invalid confluent transport: {e}"))?,
                );
                let sink = broker_connectors::ConfluentKafkaSink::new(config, transport)
                    .map_err(|e| format!("invalid confluent sink: {e}"))?;
                Ok(("confluent".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "rocketmq" | "rocket_mq" | "apache_rocketmq" => {
                let config: broker_connectors::RocketMqSinkConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid rocketmq config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid rocketmq config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::TcpRocketMqTransport::new(&config)
                        .map_err(|e| format!("invalid rocketmq transport: {e}"))?,
                );
                let sink = broker_connectors::RocketMqSink::new(config, transport)
                    .map_err(|e| format!("invalid rocketmq sink: {e}"))?;
                Ok(("rocketmq".to_string(), std::sync::Arc::new(sink)
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
                    broker_connectors::ScyllaCassandraTransport::new(&config)
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
                    broker_connectors::DriverCouchbaseTransport::new(&config)
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
                    broker_connectors::SdkDynamoDbTransport::new(&config)
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
                // No-redirect client: the transport replays auth + label
                // itself on the FE 307 -> BE hop (a stock client strips
                // Authorization when the BE is a different origin).
                let transport = std::sync::Arc::new(
                    broker_connectors::HttpDorisTransport::new(
                        &config,
                        broker_connectors::doris_http_client(config.timeout()),
                    )
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
                    broker_connectors::SdkBigQueryTransport::new(&config, reqwest::Client::new())
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
            "oracle" | "oracle_db" | "ords" => {
                let config: broker_connectors::OracleSinkConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid oracle config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid oracle config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::HttpOracleTransport::new(&config),
                );
                let sink = broker_connectors::OracleSink::new(config, transport)
                    .map_err(|e| format!("invalid oracle sink: {e}"))?;
                Ok(("oracle".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "cockroachdb" | "cockroach" | "crdb" => {
                let config: broker_connectors::CockroachDbConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid cockroachdb config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid cockroachdb config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::PgDriverCockroachDbTransport::new(&config),
                );
                let sink = broker_connectors::CockroachDbSink::new(config, transport)
                    .map_err(|e| format!("invalid cockroachdb sink: {e}"))?;
                Ok(("cockroachdb".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "alloydb" | "google_alloydb" | "alloy_db" => {
                let config: broker_connectors::AlloydbConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid alloydb config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid alloydb config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::PgDriverAlloydbTransport::new(&config),
                );
                let sink = broker_connectors::AlloydbSink::new(config, transport)
                    .map_err(|e| format!("invalid alloydb sink: {e}"))?;
                Ok(("alloydb".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "opentsdb" | "open_tsdb" | "tsdb" => {
                let config: broker_connectors::OpenTsdbConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid opentsdb config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid opentsdb config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::NetworkOpenTsdbTransport::new(&config),
                );
                let sink = broker_connectors::OpenTsdbSink::new(config, transport)
                    .map_err(|e| format!("invalid opentsdb sink: {e}"))?;
                Ok(("opentsdb".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "greptimedb" | "greptime" | "greptime_db" => {
                let config: broker_connectors::GreptimeDbConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid greptimedb config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid greptimedb config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::HttpGreptimeDbTransport::new(&config),
                );
                let sink = broker_connectors::GreptimeDbSink::new(config, transport)
                    .map_err(|e| format!("invalid greptimedb sink: {e}"))?;
                Ok(("greptimedb".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            "datalayers" | "data_layers" | "datalayers_db" => {
                let config: broker_connectors::DatalayersConfig =
                    serde_json::from_value(req.config.clone())
                        .map_err(|e| format!("invalid datalayers config: {e}"))?;
                config
                    .validate()
                    .map_err(|e| format!("invalid datalayers config: {e}"))?;
                let transport = std::sync::Arc::new(
                    broker_connectors::HttpDatalayersTransport::new(&config),
                );
                let sink = broker_connectors::DatalayersSink::new(config, transport)
                    .map_err(|e| format!("invalid datalayers sink: {e}"))?;
                Ok(("datalayers".to_string(), std::sync::Arc::new(sink)
                    as std::sync::Arc<dyn broker_connectors::Sink>))
            }
            other => Err(format!(
                "unknown connector kind {other:?} (expected kafka, rabbitmq, postgres, redis, mysql, clickhouse, influxdb, s3, elasticsearch, timescaledb, webhook, mqtt_bridge, disk_log, sparkplug_b, kinesis, gcp_pubsub, azure_eventhubs, pulsar, mongodb, mssql, cassandra, couchbase, tdengine, iotdb, timestream, dynamodb, snowflake, databricks, doris, bigquery, redshift, oracle, cockroachdb, alloydb, opentsdb, greptimedb, datalayers, or logger)"
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
    use broker_auth::Authenticator;
    use serde_json::{json, Value};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Serialises the connector tests that share the process-global v5
    /// connector store. Parallel creates/persists export the whole global
    /// into each test's own data dir, so one test's snapshot can resurrect
    /// another test's deleted entry on restart (e.g. w023-del-conn reads
    /// back 200 instead of 404). Holding this across the whole test keeps
    /// the create/delete/persist/seed sequence atomic. No production code
    /// depends on it; it only orders tests.
    static CONNECTOR_TEST_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// In-process HTTP round-trip over loopback TCP: no extra crates, no
    /// daemons. The server is spawned per test and aborted at the end.
    struct TestServer {
        port: u16,
        task: tokio::task::JoinHandle<()>,
    }

    struct TestState {
        engine: Arc<RuleEngine>,
        sessions: Arc<SessionManager>,
        router: Arc<SubscriptionRouter>,
        metrics: Arc<Metrics>,
        auth: Arc<MemoryAuth>,
        admin_users: Arc<crate::admin_users::AdminUsers>,
        tokens: Arc<crate::v5::auth::ApiTokens>,
        alarms: Arc<crate::v5::alarms::AlarmStore>,
        edge_rx: Arc<tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<BrokerFrame>>>,
    }

    impl TestServer {
        async fn start() -> (Self, TestState) {
            Self::start_with_registry(defaults_registry()).await
        }

        /// Start serving `ApiState` built on `registry`: pass a registry
        /// loaded from a temp `--data-dir` to simulate kernel restarts.
        async fn start_with_registry(registry: Arc<ConfigRegistry>) -> (Self, TestState) {
            let engine = Arc::new(RuleEngine::new(
                16,
                broker_rules::BackpressurePolicy::DropOldest,
            ));
            let sessions = Arc::new(SessionManager::new());
            let sub_router = Arc::new(SubscriptionRouter::new());
            let metrics = Arc::new(Metrics::new());
            let auth = Arc::new(MemoryAuth::new());
            let conns = Arc::new(broker_router::ConnTable::default());
            let (edge_tx, edge_rx) = tokio::sync::mpsc::unbounded_channel::<BrokerFrame>();
            let api_state = ApiState::new(
                engine.clone(),
                sessions.clone(),
                sub_router.clone(),
                metrics.clone(),
                auth.clone(),
                conns.clone(),
                registry,
                "indra-node-1".to_string(),
                edge_tx,
            );
            let state = TestState {
                engine: engine.clone(),
                sessions: sessions.clone(),
                router: sub_router.clone(),
                metrics: metrics.clone(),
                auth: auth.clone(),
                admin_users: api_state.admin_users.clone(),
                tokens: api_state.tokens.clone(),
                alarms: api_state.alarms.clone(),
                edge_rx: Arc::new(tokio::sync::Mutex::new(edge_rx)),
            };
            let app = router(api_state);
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
            stream.read_to_end(&mut buf).await.expect("read response");
            let text = String::from_utf8(buf).expect("response is UTF-8");
            let (head, body) = text.split_once("\r\n\r\n").expect("header/body split");
            let status: u16 = head.lines().next().expect("status line")[9..12]
                .parse()
                .expect("status code");
            (status, body.to_string())
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
                let raw_body = serde_json::to_string(&body).expect("encode body");
                head.push_str(&format!(
                    "Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{raw_body}",
                    raw_body.len()
                ));
            } else {
                head.push_str("Connection: close\r\n\r\n");
            }
            self.request(&head).await
        }

        async fn post(&self, path: &str, body: Value) -> (u16, Value) {
            self.send("POST", path, Some(body), None).await
        }

        async fn post_auth(&self, path: &str, body: Value, token: &str) -> (u16, Value) {
            self.send("POST", path, Some(body), Some(token)).await
        }

        async fn get(&self, path: &str) -> (u16, Value) {
            self.send("GET", path, None, None).await
        }

        async fn get_auth(&self, path: &str, token: &str) -> (u16, Value) {
            self.send("GET", path, None, Some(token)).await
        }

        async fn put_auth(&self, path: &str, body: Value, token: &str) -> (u16, Value) {
            self.send("PUT", path, Some(body), Some(token)).await
        }

        async fn delete_auth(&self, path: &str, token: &str) -> (u16, Value) {
            self.send("DELETE", path, None, Some(token)).await
        }

        /// Log in with the default admin and return its bearer token.
        /// The token still carries `must_change_password`; it only opens
        /// the login, logout, current_user and own-password-change routes.
        async fn admin_token(&self) -> String {
            let (status, body) = self
                .post(
                    "/api/v5/login",
                    json!({"username": "admin", "password": "public"}),
                )
                .await;
            assert_eq!(status, 200);
            body["token"].as_str().expect("login token").to_string()
        }

        /// Log in as `admin`, clear the default-password flag, log in
        /// again and return a fully-privileged bearer token for tests
        /// that call authenticated routes.
        async fn login_as_admin(&self) -> String {
            let fresh = self.admin_token().await;
            let (status, _) = self
                .put_auth(
                    "/api/v5/users/admin/change_pwd",
                    json!({"old_pwd": "public", "new_pwd": "Adm1n-test-pass!"}),
                    &fresh,
                )
                .await;
            assert_eq!(status, 204);
            let (status, body) = self
                .post(
                    "/api/v5/login",
                    json!({"username": "admin", "password": "Adm1n-test-pass!"}),
                )
                .await;
            assert_eq!(status, 200);
            assert_eq!(body["must_change_password"], json!(false));
            body["token"].as_str().expect("login token").to_string()
        }
    }

    /// Minimal SCRAM-SHA-256 client for the login tests (independent of the
    /// server's credential store).
    mod scram_client {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine;
        use sha2::{Digest, Sha256};

        fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
            let mut padded = [0u8; 64];
            if key.len() > 64 {
                let hash = Sha256::digest(key);
                padded[..32].copy_from_slice(&hash);
            } else {
                padded[..key.len()].copy_from_slice(key);
            }
            let mut ipad = [0x36u8; 64];
            let mut opad = [0x5cu8; 64];
            for i in 0..64 {
                ipad[i] ^= padded[i];
                opad[i] ^= padded[i];
            }
            let mut inner = Sha256::new();
            inner.update(ipad);
            inner.update(data);
            let inner_hash = inner.finalize();
            let mut outer = Sha256::new();
            outer.update(opad);
            outer.update(inner_hash);
            outer.finalize().into()
        }

        fn salted_password(password: &str, salt: &[u8], iterations: u32) -> [u8; 32] {
            let mut block = Vec::with_capacity(salt.len() + 4);
            block.extend_from_slice(salt);
            block.extend_from_slice(&1u32.to_be_bytes());
            let mut u = hmac(password.as_bytes(), &block);
            let mut result = u;
            for _ in 1..iterations {
                u = hmac(password.as_bytes(), &u);
                for (r, v) in result.iter_mut().zip(u.iter()) {
                    *r ^= *v;
                }
            }
            result
        }

        /// Returns `(client_proof_b64, server_signature_b64)`.
        pub(super) fn proof(
            password: &str,
            salt_b64: &str,
            iterations: u32,
            auth_message: &str,
        ) -> (String, String) {
            let salt = BASE64.decode(salt_b64).expect("challenge salt");
            let salted = salted_password(password, &salt, iterations);
            let client_key = hmac(&salted, b"Client Key");
            let stored_key: [u8; 32] = Sha256::digest(client_key).into();
            let client_sig = hmac(&stored_key, auth_message.as_bytes());
            let mut proof = [0u8; 32];
            for i in 0..32 {
                proof[i] = client_key[i] ^ client_sig[i];
            }
            let server_key = hmac(&salted, b"Server Key");
            let server_sig = hmac(&server_key, auth_message.as_bytes());
            (BASE64.encode(proof), BASE64.encode(server_sig))
        }
    }

    fn scram_auth_message(
        username: &str,
        client_nonce: &str,
        combined_nonce: &str,
        salt_b64: &str,
        iterations: u32,
    ) -> String {
        let escaped = username.replace('=', "=3D").replace(',', "=2C");
        format!(
            "n={escaped},r={client_nonce},r={combined_nonce},s={salt_b64},i={iterations},c=biws,r={combined_nonce}"
        )
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    #[test]
    fn standalone_needs_no_filesystem() {
        let engine = Arc::new(RuleEngine::new(
            16,
            broker_rules::BackpressurePolicy::DropOldest,
        ));
        let state = ApiState::standalone(engine);
        assert_eq!(
            *state.config.snapshot(),
            broker_config::FullSnapshot::default(),
            "standalone exposes validated defaults"
        );
        assert_eq!(state.node_id, "indra-node-1");
        assert!(
            !state.config.dir().exists(),
            "standalone must not create any directory, found: {}",
            state.config.dir().display()
        );
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
        let token = server.login_as_admin().await;

        // Empty at first.
        let (status, body) = server.get_auth("/api/v1/rules", &token).await;
        assert_eq!(status, 200);
        assert_eq!(body, json!([]));

        // Create.
        let (status, created) = server
            .post_auth(
                "/api/v1/rules",
                json!({
                    "name": "republish-temp",
                    "topic_filter": "sensors/+",
                    "enabled": true,
                    "actions": [{"type": "republish", "topic": "alerts/critical", "qos": 1}]
                }),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["name"], json!("republish-temp"));
        assert_eq!(created["topic_filter"], json!("sensors/+"));
        assert_eq!(created["actions"][0]["type"], json!("republish"));
        assert_eq!(created["actions"][0]["qos"], json!(1));
        let id = created["id"]
            .as_str()
            .expect("created rule has id")
            .to_string();

        // List shows it.
        let (status, body) = server.get_auth("/api/v1/rules", &token).await;
        assert_eq!(status, 200);
        assert_eq!(body.as_array().expect("list").len(), 1);

        // Fetch it directly.
        let (status, fetched) = server
            .get_auth(&format!("/api/v1/rules/{id}"), &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(fetched, created);

        // Unknown id is a 404.
        let (status, body) = server.get_auth("/api/v1/rules/rule-999", &token).await;
        assert_eq!(status, 404);
        assert!(body["error"].as_str().unwrap().contains("rule-999"));

        // Delete it.
        let (status, _) = server
            .delete_auth(&format!("/api/v1/rules/{id}"), &token)
            .await;
        assert_eq!(status, 204);

        // Gone afterwards; second delete is a 404.
        let (status, _) = server
            .get_auth(&format!("/api/v1/rules/{id}"), &token)
            .await;
        assert_eq!(status, 404);
        let (status, _) = server
            .delete_auth(&format!("/api/v1/rules/{id}"), &token)
            .await;
        assert_eq!(status, 404);
    }

    #[tokio::test]
    async fn test_rules_create_rejects_invalid_input() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        // Bad topic filter.
        let (status, body) = server
            .post_auth(
                "/api/v1/rules",
                json!({"name": "bad", "topic_filter": "sport/#/bogus", "actions": []}),
                &token,
            )
            .await;
        assert_eq!(status, 400);
        assert!(body["error"].as_str().unwrap().contains("topic_filter"));

        // Bad republish QoS.
        let (status, body) = server
            .post_auth(
                "/api/v1/rules",
                json!({"name": "bad", "topic_filter": "a/#",
                       "actions": [{"type": "republish", "topic": "b", "qos": 7}]}),
                &token,
            )
            .await;
        assert_eq!(status, 400);
        assert!(body["error"].as_str().unwrap().contains("qos"));

        // Wildcard republish target is not a concrete topic.
        let (status, body) = server
            .post_auth(
                "/api/v1/rules",
                json!({"name": "bad", "topic_filter": "a/#",
                       "actions": [{"type": "republish", "topic": "b/#", "qos": 0}]}),
                &token,
            )
            .await;
        assert_eq!(status, 400);
        assert!(body["error"].as_str().unwrap().contains("topic"));

        // Empty name.
        let (status, _) = server
            .post_auth(
                "/api/v1/rules",
                json!({"name": "  ", "topic_filter": "a/#", "actions": []}),
                &token,
            )
            .await;
        assert_eq!(status, 400);

        // Nothing was stored by the failed creates.
        let (status, body) = server.get_auth("/api/v1/rules", &token).await;
        assert_eq!(status, 200);
        assert_eq!(body, json!([]));
    }

    #[tokio::test]
    async fn test_rules_create_with_sql_query() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        // Valid streaming SQL is accepted and echoed back verbatim.
        let (status, created) = server
            .post_auth(
                "/api/v1/rules",
                json!({"name": "hot-temp",
                       "topic_filter": "sensors/+",
                       "sql_query": "SELECT * FROM \"sensors/+\" WHERE temperature > 50.0",
                       "enabled": true,
                       "actions": [{"type": "republish", "topic": "alerts/hot", "qos": 0}]}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(
            created["sql_query"],
            json!("SELECT * FROM \"sensors/+\" WHERE temperature > 50.0")
        );
        let id = created["id"]
            .as_str()
            .expect("created rule has id")
            .to_string();
        let (status, _) = server
            .get_auth(&format!("/api/v1/rules/{id}"), &token)
            .await;
        assert_eq!(status, 200);

        // Broken SQL is a 400 and stores nothing.
        let (status, body) = server
            .post_auth(
                "/api/v1/rules",
                json!({"name": "broken",
                       "topic_filter": "sensors/+",
                       "sql_query": "SELECT WHERE WHERE",
                       "actions": []}),
                &token,
            )
            .await;
        assert_eq!(status, 400);
        assert!(body["error"].as_str().unwrap().contains("sql_query"));

        let (status, body) = server.get_auth("/api/v1/rules", &token).await;
        assert_eq!(status, 200);
        assert_eq!(body.as_array().expect("list").len(), 1);
    }

    #[tokio::test]
    async fn test_nodes_reports_status_version_connections() {
        let (server, state) = TestServer::start().await;
        let token = server.login_as_admin().await;
        state.metrics.set_active_connections(3);

        let (status, body) = server.get_auth("/api/v1/nodes", &token).await;
        assert_eq!(status, 200);
        assert_eq!(body["status"], json!("running"));
        assert_eq!(body["version"], json!(env!("CARGO_PKG_VERSION")));
        assert_eq!(body["connections"], json!(3));
        assert!(body["node_id"].is_string());
    }

    #[tokio::test]
    async fn test_clients_lists_connected_ids() {
        let (server, state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        let (status, body) = server.get_auth("/api/v1/clients", &token).await;
        assert_eq!(status, 200);
        assert_eq!(body, json!([]));

        state.sessions.get_or_create("client-b", true);
        state.sessions.get_or_create("client-a", true);
        let (status, body) = server.get_auth("/api/v1/clients", &token).await;
        assert_eq!(status, 200);
        assert_eq!(body, json!(["client-a", "client-b"]));
    }

    #[tokio::test]
    async fn kick_sends_connclose_frame() {
        let (server, state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        // A connected fake session with kernel state bound.
        let conn_id = 4242u64;
        let (session, _) = state.sessions.get_or_create("kick-me", true);
        *session.conn_id.write() = Some(conn_id);
        *session.connected.write() = true;

        let (status, _) = server.delete_auth("/api/v5/clients/kick-me", &token).await;
        assert_eq!(status, 204);

        // The kernel→edge close for that connection arrives on the
        // channel receiver.
        let mut edge_rx = state.edge_rx.lock().await;
        let frame = tokio::time::timeout(std::time::Duration::from_secs(5), edge_rx.recv())
            .await
            .expect("ConnClose arrives on the channel receiver")
            .expect("channel stays open");
        assert_eq!(frame.header.opcode, brokerlink::OpCode::ConnClose);
        assert_eq!(frame.header.conn_id, conn_id);
        assert!(frame.metadata.is_empty());
        assert!(frame.payload.is_empty());

        // Kernel state is torn down as before.
        assert_eq!(*session.conn_id.read(), None);
        assert!(!*session.connected.read());
    }

    #[tokio::test]
    async fn clients_list_is_paged_with_envelope() {
        let (server, state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        state.sessions.get_or_create("w1-03-a", true);
        state.sessions.get_or_create("w1-03-b", true);
        state.sessions.get_or_create("w1-03-c", true);

        // Full list carries both clients plus paging metadata.
        let (status, body) = server.get_auth("/api/v5/clients", &token).await;
        assert_eq!(status, 200);
        let ids: Vec<&str> = body["data"]
            .as_array()
            .expect("data is a list")
            .iter()
            .map(|row| row["clientid"].as_str().expect("clientid"))
            .collect();
        assert_eq!(ids, vec!["w1-03-a", "w1-03-b", "w1-03-c"]);
        assert_eq!(body["meta"]["page"], json!(1));
        assert_eq!(body["meta"]["limit"], json!(100));
        assert_eq!(body["meta"]["count"], json!(3));
        assert_eq!(body["meta"]["hasnext"], json!(false));
        assert_eq!(body["data"][0]["connected"], json!(true));

        // Documented paging params are honoured.
        let (status, body) = server
            .get_auth("/api/v5/clients?page=1&limit=2", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["data"].as_array().expect("data").len(), 2);
        assert_eq!(body["meta"]["count"], json!(3));
        assert_eq!(body["meta"]["hasnext"], json!(true));
        let (status, body) = server
            .get_auth("/api/v5/clients?page=2&limit=2", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["data"].as_array().expect("data").len(), 1);
        assert_eq!(body["data"][0]["clientid"], json!("w1-03-c"));
        assert_eq!(body["meta"]["hasnext"], json!(false));

        // Unknown params are ignored gracefully, not rejected.
        let (status, body) = server
            .get_auth("/api/v5/clients?unknown_param=1", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["meta"]["count"], json!(3));

        // Malformed paging falls back to defaults, never 400.
        let (status, body) = server
            .get_auth("/api/v5/clients?page=abc&limit=xyz", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["meta"]["page"], json!(1));
        assert_eq!(body["meta"]["limit"], json!(100));
        assert_eq!(body["meta"]["count"], json!(3));
    }

    #[tokio::test]
    async fn clients_list_filters_before_paginating() {
        let (server, state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        state.sessions.get_or_create("w1-03-f1", true);
        state.sessions.get_or_create("w1-03-f2", true);

        // The documented id filter narrows the page and the count.
        let (status, body) = server
            .get_auth("/api/v5/clients?clientid=w1-03-f2", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["data"].as_array().expect("data").len(), 1);
        assert_eq!(body["data"][0]["clientid"], json!("w1-03-f2"));
        assert_eq!(body["meta"]["count"], json!(1));

        // Filtering applies before the page window: the match on the
        // second row is still found on the first page.
        let (status, body) = server
            .get_auth("/api/v5/clients?clientid=w1-03-f2&page=1&limit=1", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["data"].as_array().expect("data").len(), 1);
        assert_eq!(body["meta"]["count"], json!(1));
        assert_eq!(body["meta"]["hasnext"], json!(false));

        // A filter with no match yields an empty page, not an error.
        let (status, body) = server
            .get_auth("/api/v5/clients?clientid=no-such-client", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["data"], json!([]));
        assert_eq!(body["meta"]["count"], json!(0));
    }

    #[tokio::test]
    async fn clients_kick_removes_from_list() {
        let (server, state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        for (id, conn) in [("w1-03-k1", 9101u64), ("w1-03-k2", 9102u64)] {
            let (session, _) = state.sessions.get_or_create(id, true);
            *session.conn_id.write() = Some(conn);
            *session.connected.write() = true;
        }

        let (status, body) = server.get_auth("/api/v5/clients", &token).await;
        assert_eq!(status, 200);
        assert_eq!(body["meta"]["count"], json!(2));

        let (status, _) = server.delete_auth("/api/v5/clients/w1-03-k1", &token).await;
        assert_eq!(status, 204);

        let (status, body) = server.get_auth("/api/v5/clients", &token).await;
        assert_eq!(status, 200);
        assert_eq!(body["meta"]["count"], json!(1));
        assert_eq!(body["data"][0]["clientid"], json!("w1-03-k2"));
    }

    #[tokio::test]
    async fn kick_unknown_client_is_not_found() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        let (status, body) = server
            .delete_auth("/api/v5/clients/no-such-client", &token)
            .await;
        assert_eq!(status, 404);
        assert_eq!(body["code"], json!("CLIENTID_NOT_FOUND"));
        assert!(body["message"].is_string());
    }

    #[tokio::test]
    async fn bulk_kick_mixed_known_unknown_reports_per_client() {
        let (server, state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        for (id, conn) in [("w1-04-a", 9201u64), ("w1-04-b", 9202u64)] {
            let (session, _) = state.sessions.get_or_create(id, true);
            *session.conn_id.write() = Some(conn);
            *session.connected.write() = true;
        }

        let (status, body) = server
            .post_auth(
                "/api/v5/clients/kickout/bulk",
                json!(["w1-04-a", "w1-04-b", "w1-04-missing"]),
                &token,
            )
            .await;
        assert_eq!(status, 200);
        let results = body.as_array().expect("bulk result is a list");
        assert_eq!(results.len(), 3);
        assert_eq!(results[0]["clientid"], json!("w1-04-a"));
        assert_eq!(results[0]["result"], json!("ok"));
        assert_eq!(results[1]["clientid"], json!("w1-04-b"));
        assert_eq!(results[1]["result"], json!("ok"));
        assert_eq!(results[2]["clientid"], json!("w1-04-missing"));
        assert_eq!(results[2]["code"], json!("CLIENTID_NOT_FOUND"));
        assert!(results[2]["message"].is_string());

        // Both known clients are disconnected and gone from the list.
        let (status, body) = server.get_auth("/api/v5/clients", &token).await;
        assert_eq!(status, 200);
        assert_eq!(body["meta"]["count"], json!(0));
        assert_eq!(body["data"], json!([]));
    }

    #[tokio::test]
    async fn bulk_kick_malformed_body_is_bad_request() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        let (status, body) = server
            .post_auth(
                "/api/v5/clients/kickout/bulk",
                json!({"clientids": ["w1-04-a"]}),
                &token,
            )
            .await;
        assert_eq!(status, 400);
        assert_eq!(body["code"], json!("BAD_REQUEST"));
        assert!(body["message"].is_string());

        let (status, body) = server
            .post_auth("/api/v5/clients/kickout/bulk", json!([123]), &token)
            .await;
        assert_eq!(status, 400);
        assert_eq!(body["code"], json!("BAD_REQUEST"));
        assert!(body["message"].is_string());
    }

    #[tokio::test]
    async fn sessions_count_tracks_connects_and_disconnects() {
        let (server, state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        // Zero sessions read as zero, not an error.
        let (status, body) = server.get_auth("/api/v5/sessions_count", &token).await;
        assert_eq!(status, 200);
        assert_eq!(body, json!({"count": 0}));
        assert_eq!(state.sessions.connected_count(), 0);

        // Two connected sessions read as two via the atomic counter.
        for (id, conn) in [("w1-13-a", 13_101u64), ("w1-13-b", 13_102u64)] {
            let (session, _) = state.sessions.get_or_create(id, true);
            state.sessions.bind_session(&session, conn);
        }
        assert_eq!(state.sessions.connected_count(), 2);
        let (status, body) = server.get_auth("/api/v5/sessions_count", &token).await;
        assert_eq!(status, 200);
        assert_eq!(body, json!({"count": 2}));

        // After one verified detach the count drops to one.
        state.sessions.unbind_connection("w1-13-a", 13_101);
        assert_eq!(state.sessions.connected_count(), 1);
        let (status, body) = server.get_auth("/api/v5/sessions_count", &token).await;
        assert_eq!(status, 200);
        assert_eq!(body, json!({"count": 1}));

        // The documented node scope narrows: the local node keeps the
        // count, another node narrows to zero.
        let (status, body) = server
            .get_auth("/api/v5/sessions_count?node=indra-node-1", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body, json!({"count": 1}));
        let (status, body) = server
            .get_auth("/api/v5/sessions_count?node=indramqtt@127.0.0.1", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body, json!({"count": 1}));
        let (status, body) = server
            .get_auth("/api/v5/sessions_count?node=no-such-node", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body, json!({"count": 0}));

        // Unknown parameters are ignored, not rejected.
        let (status, body) = server
            .get_auth("/api/v5/sessions_count?unknown_param=1", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body, json!({"count": 1}));
    }

    #[tokio::test]
    async fn metrics_snapshot_is_flat_numeric_and_monotonic() {
        let (server, state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        // Documented counter names grouped as bytes, packets, messages,
        // delivery, client and session. Every value must stay numeric.
        let expected = [
            "bytes.received",
            "bytes.sent",
            "packets.received",
            "packets.sent",
            "packets.connect.received",
            "packets.connack.sent",
            "packets.connack.error",
            "packets.connack.auth_error",
            "packets.publish.received",
            "packets.publish.sent",
            "packets.subscribe.received",
            "packets.suback.sent",
            "packets.pingreq.received",
            "packets.pingresp.sent",
            "messages.received",
            "messages.sent",
            "messages.dropped",
            "messages.delivered",
            "messages.qos0.received",
            "messages.qos1.received",
            "messages.qos2.received",
            "delivery.dropped",
            "delivery.dropped.no_subscribers",
            "delivery.dropped.queue_full",
            "client.connect",
            "client.connack",
            "client.connected",
            "client.subscribe",
        ];

        // First read on a quiet node: flat object, no paging envelope.
        let (status, first) = server.get_auth("/api/v5/metrics", &token).await;
        assert_eq!(status, 200);
        let first_map = first.as_object().expect("metrics is a flat object");
        assert!(
            first.get("data").is_none(),
            "metrics is not paged: {first:?}"
        );
        assert!(
            first.get("meta").is_none(),
            "metrics has no meta: {first:?}"
        );
        for name in expected {
            let value = first_map
                .get(name)
                .unwrap_or_else(|| panic!("missing {name}"));
            assert!(value.is_number(), "{name} is numeric: {value:?}");
        }

        // Traffic between reads through the real counters: one connect,
        // one publish ingress and its fan-out, plus measured frame bytes.
        state.metrics.inc_connect_received();
        state.metrics.inc_connack_sent();
        state.metrics.inc_publish_received();
        state.metrics.inc_messages_received();
        state.metrics.inc_qos1_received();
        state.metrics.inc_bytes_received_by(128);
        state.metrics.inc_messages_forwarded();
        state.metrics.inc_publish_sent();
        state.metrics.inc_delivered();
        state.metrics.inc_bytes_sent_by(64);
        state.metrics.inc_subscribe_received();
        state.metrics.inc_suback_sent();
        state.metrics.inc_pingreq_received();
        state.metrics.inc_pingresp_sent();

        // Second read: every documented counter is non-decreasing.
        let (status, second) = server.get_auth("/api/v5/metrics", &token).await;
        assert_eq!(status, 200);
        let second_map = second.as_object().expect("metrics stays a flat object");
        for name in expected {
            let before = first_map[name]
                .as_u64()
                .unwrap_or_else(|| panic!("{name} numeric"));
            let after = second_map[name]
                .as_u64()
                .unwrap_or_else(|| panic!("{name} numeric"));
            assert!(after >= before, "{name} moves forward: {before} -> {after}");
        }
        assert!(second_map["messages.received"].as_u64().unwrap() >= 1);
        assert!(second_map["packets.publish.received"].as_u64().unwrap() >= 1);
        assert!(second_map["bytes.received"].as_u64().unwrap() >= 128);

        // Unknown parameters are ignored, not rejected.
        let (status, third) = server
            .get_auth("/api/v5/metrics?unknown_param=1", &token)
            .await;
        assert_eq!(status, 200);
        let third_map = third.as_object().expect("metrics with query stays flat");
        for name in expected {
            assert!(third_map.get(name).is_some(), "unknown query keeps {name}");
        }
    }

    #[tokio::test]
    async fn global_subscriptions_lists_both_with_paging_and_shrinks() {
        let (server, state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        // Empty system reads as a bare empty array, not an envelope.
        let (status, body) = server.get_auth("/api/v5/subscriptions", &token).await;
        assert_eq!(status, 200);
        let empty = body.as_array().expect("global list is a bare array");
        assert!(empty.is_empty(), "no subscriptions yet: {empty:?}");

        // Two clients subscribed through the real subscribe route.
        for (id, topic) in [("w1-14-a", "w1-14/first"), ("w1-14-b", "w1-14/second")] {
            state.sessions.get_or_create(id, true);
            let (status, _) = server
                .post_auth(
                    &format!("/api/v5/clients/{id}/subscribe"),
                    json!({"topic": topic, "qos": 1}),
                    &token,
                )
                .await;
            assert_eq!(status, 200);
        }

        // List shows both entries with the documented per-entry fields.
        let (status, body) = server.get_auth("/api/v5/subscriptions", &token).await;
        assert_eq!(status, 200);
        let subs = body.as_array().expect("global list is a bare array");
        assert_eq!(subs.len(), 2, "both subscriptions listed: {subs:?}");
        // Deterministic order by (clientid, topic).
        assert_eq!(subs[0]["clientid"], json!("w1-14-a"));
        assert_eq!(subs[0]["topic"], json!("w1-14/first"));
        assert_eq!(subs[1]["clientid"], json!("w1-14-b"));
        assert_eq!(subs[1]["topic"], json!("w1-14/second"));
        for entry in subs {
            assert_eq!(entry["qos"], json!(1));
            assert_eq!(entry["nl"], json!(0));
            assert_eq!(entry["rap"], json!(0));
            assert_eq!(entry["rh"], json!(0));
            assert_eq!(entry["node"], json!("indramqtt@127.0.0.1"));
            assert!(entry["clientid"].is_string());
            assert!(entry["topic"].is_string());
        }

        // Paging is honoured: one row per page.
        let (status, body) = server
            .get_auth("/api/v5/subscriptions?page=1&limit=1", &token)
            .await;
        assert_eq!(status, 200);
        let first = body.as_array().expect("paged list stays a bare array");
        assert_eq!(first.len(), 1, "first page holds one row: {first:?}");
        assert_eq!(first[0]["clientid"], json!("w1-14-a"));

        let (status, body) = server
            .get_auth("/api/v5/subscriptions?page=2&limit=1", &token)
            .await;
        assert_eq!(status, 200);
        let second = body.as_array().expect("paged list stays a bare array");
        assert_eq!(second.len(), 1, "second page holds one row: {second:?}");
        assert_eq!(second[0]["clientid"], json!("w1-14-b"));

        // After one unsubscribe the list shrinks to the survivor.
        let (status, _) = server
            .post_auth(
                "/api/v5/clients/w1-14-a/unsubscribe",
                json!({"topic": "w1-14/first"}),
                &token,
            )
            .await;
        assert_eq!(status, 204);

        let (status, body) = server.get_auth("/api/v5/subscriptions", &token).await;
        assert_eq!(status, 200);
        let subs = body.as_array().expect("global list is a bare array");
        assert_eq!(subs.len(), 1, "list shrinks after unsubscribe: {subs:?}");
        assert_eq!(subs[0]["clientid"], json!("w1-14-b"));
        assert_eq!(subs[0]["topic"], json!("w1-14/second"));
    }

    #[tokio::test]
    async fn topics_list_and_detail_round_trip() {
        let (server, state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        // Empty index reads as an empty page, not an error.
        let (status, body) = server.get_auth("/api/v5/topics", &token).await;
        assert_eq!(status, 200);
        assert_eq!(body["data"], json!([]));
        assert_eq!(body["meta"]["count"], json!(0));
        assert_eq!(body["meta"]["page"], json!(1));
        assert_eq!(body["meta"]["hasnext"], json!(false));

        // Subscribing alone never creates a topic row.
        state.sessions.get_or_create("w1-15-sub", true);
        let (status, _) = server
            .post_auth(
                "/api/v5/clients/w1-15-sub/subscribe",
                json!({"topic": "w1-15/filter", "qos": 0}),
                &token,
            )
            .await;
        assert_eq!(status, 200);
        let (status, body) = server.get_auth("/api/v5/topics", &token).await;
        assert_eq!(status, 200);
        assert_eq!(
            body["data"],
            json!([]),
            "subscribe must not index: {body:?}"
        );

        // Publish two concrete topics through the management publish path.
        for topic in ["w1-15/alpha", "w1-15/beta"] {
            let (status, _) = server
                .post_auth(
                    "/api/v5/publish",
                    json!({"topic": topic, "payload": "hi", "qos": 0}),
                    &token,
                )
                .await;
            assert_eq!(status, 200);
        }

        // List shows both entries with the documented per-entry fields.
        let (status, body) = server.get_auth("/api/v5/topics", &token).await;
        assert_eq!(status, 200);
        assert_eq!(body["meta"]["count"], json!(2));
        assert_eq!(body["meta"]["hasnext"], json!(false));
        let data = body["data"].as_array().expect("topics list has data");
        assert_eq!(data.len(), 2, "both topics listed: {data:?}");
        // Deterministic order: sorted by topic.
        assert_eq!(data[0]["topic"], json!("w1-15/alpha"));
        assert_eq!(data[1]["topic"], json!("w1-15/beta"));
        for entry in data {
            assert_eq!(entry["node"], json!("indramqtt@127.0.0.1"));
            assert!(entry["topic"].is_string());
        }

        // W0 paging is honoured: one row per page.
        let (status, first) = server
            .get_auth("/api/v5/topics?page=1&limit=1", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(first["meta"]["count"], json!(2));
        assert_eq!(first["meta"]["hasnext"], json!(true));
        assert_eq!(first["data"].as_array().unwrap().len(), 1);
        assert_eq!(first["data"][0]["topic"], json!("w1-15/alpha"));

        let (status, second) = server
            .get_auth("/api/v5/topics?page=2&limit=1", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(second["data"].as_array().unwrap().len(), 1);
        assert_eq!(second["data"][0]["topic"], json!("w1-15/beta"));

        // Unknown query keys do not break the list call.
        let (status, body) = server
            .get_auth("/api/v5/topics?unknown_param=1", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["meta"]["count"], json!(2));

        // Detail hit returns the documented record (slashed names arrive
        // percent-encoded and match exactly after decoding).
        let (status, body) = server
            .get_auth("/api/v5/topics/w1-15%2Falpha", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["topic"], json!("w1-15/alpha"));
        assert_eq!(body["node"], json!("indramqtt@127.0.0.1"));

        // Detail miss returns the documented not-found shape; prefix and
        // filter forms never match.
        for missing in ["w1-15%2Fmissing", "w1-15%2Falp", "w1-15%2Falpha%2Fx"] {
            let (status, body) = server
                .get_auth(&format!("/api/v5/topics/{missing}"), &token)
                .await;
            assert_eq!(status, 404, "unknown topic must 404: {missing}");
            assert_eq!(body["code"], json!("NOT_FOUND"));
            assert!(body["message"].is_string());
        }
    }

    #[tokio::test]
    async fn alarms_raise_list_clear_round_trip() {
        let (server, state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        // Empty store reads as an empty page, not an error.
        let (status, body) = server.get_auth("/api/v5/alarms", &token).await;
        assert_eq!(status, 200);
        assert_eq!(body["data"], json!([]));
        assert_eq!(body["meta"]["count"], json!(0));
        assert_eq!(body["meta"]["page"], json!(1));
        assert_eq!(body["meta"]["hasnext"], json!(false));

        // No deactivated history yet either.
        let (status, body) = server
            .get_auth("/api/v5/alarms?activated=false", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["data"], json!([]));
        assert_eq!(body["meta"]["count"], json!(0));

        // Raise two test alarms directly on the store (alarms have no
        // creation endpoint; the kernel raises them internally).
        state
            .alarms
            .activate("w1-16-b-alarm", "second alarm", serde_json::json!({}));
        state.alarms.activate(
            "w1-16-a-alarm",
            "first alarm",
            serde_json::json!({"high_watermark": 70}),
        );

        // Listing carries both entries with the documented per-alarm fields.
        let (status, body) = server.get_auth("/api/v5/alarms", &token).await;
        assert_eq!(status, 200);
        assert_eq!(body["meta"]["count"], json!(2));
        assert_eq!(body["meta"]["hasnext"], json!(false));
        let data = body["data"].as_array().expect("alarms list has data");
        assert_eq!(data.len(), 2, "both alarms listed: {data:?}");
        // Deterministic order: sorted by name.
        assert_eq!(data[0]["name"], json!("w1-16-a-alarm"));
        assert_eq!(data[1]["name"], json!("w1-16-b-alarm"));
        for entry in data {
            assert_eq!(entry["node"], json!("indramqtt@127.0.0.1"));
            assert!(entry["name"].is_string());
            assert!(entry["message"].is_string());
            assert!(entry["details"].is_object());
            assert!(entry["duration"].is_number());
            assert!(entry["activate_at"].is_string());
            assert!(entry["activate_at"]
                .as_str()
                .is_some_and(|s| s.contains('T')));
            assert_eq!(entry["deactivate_at"], json!("infinity"));
        }
        assert_eq!(data[0]["message"], json!("first alarm"));
        assert_eq!(data[0]["details"], json!({"high_watermark": 70}));

        // W0 paging is honoured: one row per page.
        let (status, first) = server
            .get_auth("/api/v5/alarms?page=1&limit=1", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(first["meta"]["count"], json!(2));
        assert_eq!(first["meta"]["hasnext"], json!(true));
        assert_eq!(first["data"].as_array().unwrap().len(), 1);
        assert_eq!(first["data"][0]["name"], json!("w1-16-a-alarm"));

        let (status, second) = server
            .get_auth("/api/v5/alarms?page=2&limit=1", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(second["data"].as_array().unwrap().len(), 1);
        assert_eq!(second["data"][0]["name"], json!("w1-16-b-alarm"));

        // Unknown query keys do not break the list call.
        let (status, body) = server
            .get_auth("/api/v5/alarms?unknown_param=1", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["meta"]["count"], json!(2));

        // Clearing deactivates everything; the next list is empty again
        // while the deactivated history keeps what was cleared.
        let (status, _) = server
            .delete_auth("/api/v5/alarms?unknown_param=1", &token)
            .await;
        assert_eq!(status, 204);
        let (status, body) = server.get_auth("/api/v5/alarms", &token).await;
        assert_eq!(status, 200);
        assert_eq!(body["data"], json!([]));
        assert_eq!(body["meta"]["count"], json!(0));
        let (status, body) = server
            .get_auth("/api/v5/alarms?activated=false", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["meta"]["count"], json!(2));
        let history = body["data"].as_array().expect("cleared alarms kept");
        assert_eq!(history.len(), 2);
        assert_eq!(history[0]["name"], json!("w1-16-a-alarm"));
        assert_ne!(history[0]["deactivate_at"], json!("infinity"));

        // Clearing an empty store still reports success.
        let (status, _) = server.delete_auth("/api/v5/alarms", &token).await;
        assert_eq!(status, 204);
    }

    #[tokio::test]
    async fn alarms_force_deactivate_round_trip() {
        let (server, state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        // With one active alarm, force-deactivate reports success and the
        // follow-up list reads empty.
        state.alarms.activate(
            "w1-17-alarm",
            "force me",
            serde_json::json!({"high_watermark": 70}),
        );
        let (status, body) = server.get_auth("/api/v5/alarms", &token).await;
        assert_eq!(status, 200);
        assert_eq!(body["meta"]["count"], json!(1));

        let (status, _) = server
            .post_auth("/api/v5/alarms/force_deactivate", json!({}), &token)
            .await;
        assert_eq!(status, 204);
        let (status, body) = server.get_auth("/api/v5/alarms", &token).await;
        assert_eq!(status, 200);
        assert_eq!(body["data"], json!([]));
        assert_eq!(body["meta"]["count"], json!(0));

        // Repeating with no alarms still reports success.
        let (status, _) = server
            .post_auth("/api/v5/alarms/force_deactivate", json!({}), &token)
            .await;
        assert_eq!(status, 204);

        // A named body deactivates just that alarm; the other stays listed.
        state
            .alarms
            .activate("w1-17-a-alarm", "first alarm", serde_json::json!({}));
        state
            .alarms
            .activate("w1-17-b-alarm", "second alarm", serde_json::json!({}));
        let (status, _) = server
            .post_auth(
                "/api/v5/alarms/force_deactivate",
                json!({"name": "w1-17-a-alarm"}),
                &token,
            )
            .await;
        assert_eq!(status, 204);
        let (status, body) = server.get_auth("/api/v5/alarms", &token).await;
        assert_eq!(status, 200);
        assert_eq!(body["meta"]["count"], json!(1));
        assert_eq!(body["data"][0]["name"], json!("w1-17-b-alarm"));

        // Deactivating an unknown name still reports success and changes
        // nothing; clearing the last alarm by empty body empties the list.
        let (status, _) = server
            .post_auth(
                "/api/v5/alarms/force_deactivate",
                json!({"name": "w1-17-missing"}),
                &token,
            )
            .await;
        assert_eq!(status, 204);
        let (status, body) = server.get_auth("/api/v5/alarms", &token).await;
        assert_eq!(status, 200);
        assert_eq!(body["meta"]["count"], json!(1));
        let (status, _) = server
            .post_auth("/api/v5/alarms/force_deactivate", json!({}), &token)
            .await;
        assert_eq!(status, 204);
        let (status, body) = server.get_auth("/api/v5/alarms", &token).await;
        assert_eq!(status, 200);
        assert_eq!(body["data"], json!([]));
    }

    #[tokio::test]
    async fn inflight_lists_staged_delivery_empty_and_unknown() {
        let (server, state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        state.sessions.get_or_create("w1-06-a", true);

        // Empty inflight reads as an empty page, not an error.
        let (status, body) = server
            .get_auth("/api/v5/clients/w1-06-a/inflight_messages", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["data"], json!([]));
        assert_eq!(body["meta"]["count"], json!(0));
        assert_eq!(body["meta"]["hasnext"], json!(false));

        // Stage one unacknowledged QoS 1 downlink over the real tracker.
        let session = state.sessions.get("w1-06-a").expect("known session");
        assert!(session.track_inflight(broker_session::InflightMessage {
            packet_id: 7,
            topic: Topic::new("conf/inflight/1").expect("valid topic"),
            qos: QoS::AtLeastOnce,
            retain: false,
            payload: bytes::Bytes::from_static(b"hello"),
            enqueued_at: std::time::Instant::now(),
        }));

        let (status, body) = server
            .get_auth("/api/v5/clients/w1-06-a/inflight_messages", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["meta"]["count"], json!(1));
        let entry = &body["data"][0];
        assert_eq!(entry["topic"], json!("conf/inflight/1"));
        assert_eq!(entry["qos"], json!(1));
        assert!(
            entry["packet_id"] == json!(7) || entry["msgid"] == json!("7"),
            "entry carries the packet identity: {entry}"
        );
        assert!(entry["payload"].is_string());

        // Unknown clients give not-found with the documented shape.
        let (status, body) = server
            .get_auth("/api/v5/clients/no-such-client/inflight_messages", &token)
            .await;
        assert_eq!(status, 404);
        assert_eq!(body["code"], json!("CLIENTID_NOT_FOUND"));
        assert!(body["message"].is_string());
    }

    #[tokio::test]
    async fn inflight_is_paged_with_w0_helper() {
        let (server, state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        state.sessions.get_or_create("w1-06-p", true);
        let session = state.sessions.get("w1-06-p").expect("known session");
        for pid in [11u16, 12, 13] {
            assert!(session.track_inflight(broker_session::InflightMessage {
                packet_id: pid,
                topic: Topic::new("conf/inflight/p").expect("valid topic"),
                qos: QoS::AtLeastOnce,
                retain: false,
                payload: bytes::Bytes::from_static(b"x"),
                enqueued_at: std::time::Instant::now(),
            }));
        }

        let (status, body) = server
            .get_auth(
                "/api/v5/clients/w1-06-p/inflight_messages?page=1&limit=2",
                &token,
            )
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["data"].as_array().expect("data").len(), 2);
        assert_eq!(body["meta"]["count"], json!(3));
        assert_eq!(body["meta"]["hasnext"], json!(true));

        let (status, body) = server
            .get_auth(
                "/api/v5/clients/w1-06-p/inflight_messages?page=2&limit=2",
                &token,
            )
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["data"].as_array().expect("data").len(), 1);
        assert_eq!(body["meta"]["hasnext"], json!(false));
    }

    #[tokio::test]
    async fn mqueue_lists_staged_offline_empty_and_unknown() {
        let (server, state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        state.sessions.get_or_create("w1-07-a", true);

        // Empty queue reads as an empty page, not an error.
        let (status, body) = server
            .get_auth("/api/v5/clients/w1-07-a/mqueue_messages", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["data"], json!([]));
        assert_eq!(body["meta"]["count"], json!(0));
        assert_eq!(body["meta"]["hasnext"], json!(false));

        // Hold one message for the offline client over the real queue.
        let session = state.sessions.get("w1-07-a").expect("known session");
        session.push_offline(broker_session::QueuedMessage {
            topic: Topic::new("conf/mqueue/1").expect("valid topic"),
            qos: QoS::AtLeastOnce,
            retain: false,
            payload: bytes::Bytes::from_static(b"hello"),
            publish_at_ms: None,
        });

        let (status, body) = server
            .get_auth("/api/v5/clients/w1-07-a/mqueue_messages", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["meta"]["count"], json!(1));
        let entry = &body["data"][0];
        assert_eq!(entry["topic"], json!("conf/mqueue/1"));
        assert_eq!(entry["qos"], json!(1));
        assert!(entry["payload"].is_string());
        assert!(
            entry["msgid"].is_string(),
            "entry carries the stored-message identity: {entry}"
        );

        // Unknown clients give not-found with the documented shape.
        let (status, body) = server
            .get_auth("/api/v5/clients/no-such-client/mqueue_messages", &token)
            .await;
        assert_eq!(status, 404);
        assert_eq!(body["code"], json!("CLIENTID_NOT_FOUND"));
        assert!(body["message"].is_string());
    }

    #[tokio::test]
    async fn mqueue_is_paged_with_w0_helper() {
        let (server, state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        state.sessions.get_or_create("w1-07-p", true);
        let session = state.sessions.get("w1-07-p").expect("known session");
        for i in 0..3u8 {
            session.push_offline(broker_session::QueuedMessage {
                topic: Topic::new("conf/mqueue/p").expect("valid topic"),
                qos: QoS::AtLeastOnce,
                retain: false,
                payload: bytes::Bytes::from(vec![i]),
                publish_at_ms: None,
            });
        }

        let (status, body) = server
            .get_auth(
                "/api/v5/clients/w1-07-p/mqueue_messages?page=1&limit=2",
                &token,
            )
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["data"].as_array().expect("data").len(), 2);
        assert_eq!(body["meta"]["count"], json!(3));
        assert_eq!(body["meta"]["hasnext"], json!(true));

        let (status, body) = server
            .get_auth(
                "/api/v5/clients/w1-07-p/mqueue_messages?page=2&limit=2",
                &token,
            )
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["data"].as_array().expect("data").len(), 1);
        assert_eq!(body["meta"]["hasnext"], json!(false));
    }

    #[tokio::test]
    async fn client_authz_cache_read_clear_round_trip() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        // Connect through the broker: the console CONNECT creates the
        // session, so the cache starts life empty. An empty cache reads
        // as an empty list.
        let mut subscriber = WsClient::connect(server.port).await;
        subscriber
            .send_bin(&mqtt_connect("w2-01-cache-1", None, None))
            .await;
        let connack = subscriber.recv_msg().await.expect("connack");
        assert_eq!(mqtt_packet_type(&connack), 2);
        assert_eq!(connack[3], 0);
        let (status, body) = server
            .get_auth("/api/v5/clients/w2-01-cache-1/authorization/cache", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body, json!([]));

        // Populate through normal authorized activity through the broker:
        // a console SUBSCRIBE (real subscribe authorization) plus a
        // console PUBLISH from a second connection (real publish
        // authorization) that delivers to the subscriber.
        subscriber
            .send_bin(&mqtt_subscribe(7, &[("conf/authz/1", 0)]))
            .await;
        let suback = subscriber.recv_msg().await.expect("suback");
        assert_eq!(mqtt_packet_type(&suback), 9);
        assert_eq!(&suback[4..], &[0]);
        let mut publisher = WsClient::connect(server.port).await;
        publisher
            .send_bin(&mqtt_connect("w2-01-cache-2", None, None))
            .await;
        let connack = publisher.recv_msg().await.expect("connack");
        assert_eq!(mqtt_packet_type(&connack), 2);
        assert_eq!(connack[3], 0);
        publisher
            .send_bin(&mqtt_publish("conf/authz/1", 0, 0, b"hi"))
            .await;
        // Deliver proves the publish rode the broker route path.
        let delivery = subscriber.recv_msg().await.expect("delivery");
        assert_eq!(mqtt_packet_type(&delivery), 3);

        // Read-hit shape: each decision present with per-entry fields.
        let (status, body) = server
            .get_auth("/api/v5/clients/w2-01-cache-1/authorization/cache", &token)
            .await;
        assert_eq!(status, 200);
        let entries = body.as_array().expect("cache is a bare list");
        assert_eq!(entries.len(), 1);
        let subscribe = entries
            .iter()
            .find(|e| e["topic"] == json!("conf/authz/1"))
            .expect("subscribe decision present");
        assert_eq!(subscribe["access"]["action_type"], json!("subscribe"));
        assert_eq!(subscribe["result"], json!("allow"));
        assert!(subscribe["updated_time"].is_number());
        let (status, body) = server
            .get_auth("/api/v5/clients/w2-01-cache-2/authorization/cache", &token)
            .await;
        assert_eq!(status, 200);
        let entries = body.as_array().expect("cache is a bare list");
        assert_eq!(entries.len(), 1);
        let publish = entries
            .iter()
            .find(|e| e["topic"] == json!("conf/authz/1"))
            .expect("publish decision present");
        assert_eq!(publish["access"]["action_type"], json!("publish"));
        assert_eq!(publish["result"], json!("allow"));
        assert!(publish["updated_time"].is_number());

        // Unknown query keys are ignored, not a 400.
        let (status, body) = server
            .get_auth(
                "/api/v5/clients/w2-01-cache-1/authorization/cache?unknown_param=1",
                &token,
            )
            .await;
        assert_eq!(status, 200);
        assert_eq!(body.as_array().expect("list").len(), 1);

        // Clear evicts; the next read is empty. Clearing again still
        // succeeds (204).
        let (status, _) = server
            .delete_auth("/api/v5/clients/w2-01-cache-1/authorization/cache", &token)
            .await;
        assert_eq!(status, 204);
        let (status, body) = server
            .get_auth("/api/v5/clients/w2-01-cache-1/authorization/cache", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body, json!([]));
        let (status, _) = server
            .delete_auth("/api/v5/clients/w2-01-cache-1/authorization/cache", &token)
            .await;
        assert_eq!(status, 204);

        // Unknown client ids are 404 with the documented error shape.
        let (status, body) = server
            .get_auth("/api/v5/clients/no-such-client/authorization/cache", &token)
            .await;
        assert_eq!(status, 404);
        assert_eq!(body["code"], json!("CLIENTID_NOT_FOUND"));
        assert!(body["message"].is_string());
        let (status, body) = server
            .delete_auth("/api/v5/clients/no-such-client/authorization/cache", &token)
            .await;
        assert_eq!(status, 404);
        assert_eq!(body["code"], json!("CLIENTID_NOT_FOUND"));
        assert!(body["message"].is_string());
    }

    #[tokio::test]
    async fn banned_create_list_clear_round_trip() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        // Empty store reads as an empty page, not an error.
        let (status, body) = server.get_auth("/api/v5/banned", &token).await;
        assert_eq!(status, 200);
        assert_eq!(body["data"], json!([]));
        assert_eq!(body["meta"]["count"], json!(0));
        assert_eq!(body["meta"]["hasnext"], json!(false));

        // Create one entry.
        let (status, created) = server
            .post_auth(
                "/api/v5/banned",
                json!({"as": "clientid", "who": "w1-01-c1", "reason": "round trip"}),
                &token,
            )
            .await;
        assert_eq!(status, 200);
        assert_eq!(created["as"], json!("clientid"));
        assert_eq!(created["who"], json!("w1-01-c1"));

        // Listing now carries the entry plus paging metadata.
        let (status, body) = server.get_auth("/api/v5/banned", &token).await;
        assert_eq!(status, 200);
        assert_eq!(body["meta"]["count"], json!(1));
        assert_eq!(body["data"][0]["who"], json!("w1-01-c1"));
        assert_eq!(body["data"][0]["as"], json!("clientid"));

        // Unknown query keys do not break the list call.
        let (status, body) = server
            .get_auth("/api/v5/banned?unknown_param=1", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["meta"]["count"], json!(1));

        // Clearing drops everything; the next list is empty again.
        let (status, _) = server
            .delete_auth("/api/v5/banned?unknown_param=1", &token)
            .await;
        assert_eq!(status, 204);
        let (status, body) = server.get_auth("/api/v5/banned", &token).await;
        assert_eq!(status, 200);
        assert_eq!(body["data"], json!([]));
        assert_eq!(body["meta"]["count"], json!(0));
    }

    #[tokio::test]
    async fn banned_malformed_create_is_bad_request() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        for bad in [
            json!({}),
            json!({"as": "clientid"}),
            json!({"who": "w1-01-x"}),
            json!({"as": "not-a-kind", "who": "w1-01-x"}),
            json!({"as": "clientid", "who": ""}),
            json!({"as": "peerhost", "who": "not-an-ip"}),
        ] {
            let (status, body) = server.post_auth("/api/v5/banned", bad, &token).await;
            assert_eq!(status, 400);
            assert_eq!(body["code"], json!("BAD_REQUEST"));
            assert!(body["message"].is_string());
        }

        // Nothing above may have stored anything.
        let (status, body) = server.get_auth("/api/v5/banned", &token).await;
        assert_eq!(status, 200);
        assert_eq!(body["data"], json!([]));
    }

    #[tokio::test]
    async fn banned_duplicate_create_reports_conflict() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        let (status, _) = server
            .post_auth(
                "/api/v5/banned",
                json!({"as": "username", "who": "w1-01-dup"}),
                &token,
            )
            .await;
        assert_eq!(status, 200);
        let (status, body) = server
            .post_auth(
                "/api/v5/banned",
                json!({"as": "username", "who": "w1-01-dup"}),
                &token,
            )
            .await;
        assert_eq!(status, 400);
        assert_eq!(body["code"], json!("ALREADY_EXISTS"));
        assert!(body["message"].is_string());
    }

    #[tokio::test]
    async fn banned_delete_one_present_absent_and_bad_kind() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        // Create one entry through the store.
        let (status, _) = server
            .post_auth(
                "/api/v5/banned",
                json!({"as": "clientid", "who": "w1-02-del", "reason": "delete one"}),
                &token,
            )
            .await;
        assert_eq!(status, 200);

        // Deleting it by kind/value reports no-content success.
        let (status, _) = server
            .delete_auth("/api/v5/banned/clientid/w1-02-del", &token)
            .await;
        assert_eq!(status, 204);

        // It is gone from the list afterwards.
        let (status, body) = server.get_auth("/api/v5/banned", &token).await;
        assert_eq!(status, 200);
        assert_eq!(body["data"], json!([]));

        // Deleting it again reports not-found, not success.
        let (status, body) = server
            .delete_auth("/api/v5/banned/clientid/w1-02-del", &token)
            .await;
        assert_eq!(status, 404);
        assert_eq!(body["code"], json!("NOT_FOUND"));
        assert!(body["message"].is_string());

        // An unknown kind is a client error with the documented shape.
        let (status, body) = server
            .delete_auth("/api/v5/banned/not-a-kind/w1-02-del", &token)
            .await;
        assert_eq!(status, 400);
        assert_eq!(body["code"], json!("BAD_REQUEST"));
        assert!(body["message"].is_string());
    }

    #[tokio::test]
    async fn test_metrics_exposes_prometheus_counters() {
        let (server, state) = TestServer::start().await;
        let token = server.login_as_admin().await;
        state.metrics.inc_messages_received();
        state.metrics.inc_messages_forwarded_by(2);
        state.metrics.inc_rules_executed();
        state.metrics.set_active_connections(1);

        let (status, text) = server
            .request_raw(&format!(
                "GET /api/v1/metrics HTTP/1.0\r\nHost: test\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
            ))
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
        let token = server.login_as_admin().await;

        let (status, created) = server
            .post_auth(
                "/api/v1/rules",
                json!({"name": "to-webhook",
                       "topic_filter": "sensors/+",
                       "sql_query": "SELECT temperature FROM \"sensors/+\" WHERE temperature > 0",
                       "actions": [{"type": "forwardconnector", "connector_id": "webhook-1"}]}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["actions"][0]["type"], json!("forwardconnector"));
        assert_eq!(created["actions"][0]["connector_id"], json!("webhook-1"));

        // Empty connector id is rejected.
        let (status, _) = server
            .post_auth(
                "/api/v1/rules",
                json!({"name": "bad",
                       "topic_filter": "sensors/+",
                       "actions": [{"type": "forwardconnector", "connector_id": "  "}]}),
                &token,
            )
            .await;
        assert_eq!(status, 400);
    }

    #[tokio::test]
    async fn rules_list_echoes_stored_actions_only() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        let (status, created) = server
            .post_auth(
                "/api/v5/rules",
                json!({"name": "no-actions",
                       "sql": "SELECT * FROM \"t/#\"",
                       "enable": true,
                       "actions": []}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["actions"], json!([]));
        assert!(created.get("description").is_none());
        assert!(created.get("created_at").is_none());

        let (status, body) = server.get_auth("/api/v5/rules", &token).await;
        assert_eq!(status, 200);
        let text = serde_json::to_string(&body).expect("encode list body");
        assert!(
            !text.contains("kafka:kafka-prod"),
            "list must not inject fallback actions, got: {text}"
        );
        let data = body["data"].as_array().expect("data is a list");
        assert_eq!(data.len(), 1);
        assert_eq!(data[0]["actions"], json!([]));
        assert!(data[0].get("description").is_none());
        assert!(data[0].get("created_at").is_none());
    }

    #[tokio::test]
    async fn rules_create_rejects_bad_filter() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        // Spec-literal invalid filter: `FROM "t/["` must be 400 (previously
        // silently coerced to `t/#`).
        let (status, body) = server
            .post_auth(
                "/api/v5/rules",
                json!({"name": "bad-filter",
                       "sql": "SELECT * FROM \"t/[\"",
                       "actions": []}),
                &token,
            )
            .await;
        assert_eq!(status, 400);
        assert_eq!(body["code"], json!("BAD_REQUEST"));

        // A misplaced `#` (mid-filter) is likewise rejected, not coerced.
        let (status, body) = server
            .post_auth(
                "/api/v5/rules",
                json!({"name": "bad-filter-hash",
                       "sql": "SELECT * FROM \"t/#/bogus\"",
                       "actions": []}),
                &token,
            )
            .await;
        assert_eq!(status, 400);
        assert_eq!(body["code"], json!("BAD_REQUEST"));

        let (status, _) = server
            .post_auth(
                "/api/v5/rules",
                json!({"sql": "SELECT * FROM \"t/#\"", "actions": []}),
                &token,
            )
            .await;
        assert_eq!(status, 400);
    }

    #[tokio::test]
    async fn rules_update_unknown_is_404() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        let (status, body) = server
            .put_auth("/api/v5/rules/nope", json!({"enable": false}), &token)
            .await;
        assert_eq!(status, 404);
        assert_eq!(body["code"], json!("NOT_FOUND"));
    }

    #[tokio::test]
    async fn test_auth_users_and_acls() {
        let (server, state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        // Create a user.
        let (status, created) = server
            .post_auth(
                "/api/v1/auth/users",
                json!({"username": "alice", "password": "s3cret"}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["username"], json!("alice"));
        // Passwords are write-only: never echoed.
        assert!(created.get("password").is_none());
        assert_eq!(state.auth.user_count(), 1);

        // Empty username or password is rejected.
        let (status, _) = server
            .post_auth(
                "/api/v1/auth/users",
                json!({"username": "", "password": "x"}),
                &token,
            )
            .await;
        assert_eq!(status, 400);
        let (status, _) = server
            .post_auth(
                "/api/v1/auth/users",
                json!({"username": "bob", "password": ""}),
                &token,
            )
            .await;
        assert_eq!(status, 400);

        // Create an ACL rule.
        let (status, created) = server
            .post_auth(
                "/api/v1/auth/acls",
                json!({"client_pattern": "alice",
                       "action": "publish",
                       "topic_pattern": "sensors/#",
                       "allow": true}),
                &token,
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
            let (status, _) = server.post_auth("/api/v1/auth/acls", body, &token).await;
            assert_eq!(status, 400);
        }
    }

    #[tokio::test]
    async fn test_auth_lists_users_and_acls() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        let (status, body) = server.get_auth("/api/v1/auth/users", &token).await;
        assert_eq!(status, 200);
        assert_eq!(body, json!([]));
        let (status, body) = server.get_auth("/api/v1/auth/acls", &token).await;
        assert_eq!(status, 200);
        assert_eq!(body, json!([]));

        server
            .post_auth(
                "/api/v1/auth/users",
                json!({"username": "alice", "password": "s3cret"}),
                &token,
            )
            .await;
        server
            .post_auth(
                "/api/v1/auth/acls",
                json!({"client_pattern": "alice",
                       "action": "subscribe",
                       "topic_pattern": "sensors/#",
                       "allow": true}),
                &token,
            )
            .await;

        let (status, body) = server.get_auth("/api/v1/auth/users", &token).await;
        assert_eq!(status, 200);
        assert_eq!(
            body,
            json!([{"username": "alice", "quotas": {"max_connections": null, "max_publish_rate": null, "max_publish_burst": null}}])
        );
        let (status, body) = server.get_auth("/api/v1/auth/acls", &token).await;
        assert_eq!(status, 200);
        assert_eq!(body.as_array().expect("acls").len(), 1);
        assert_eq!(body[0]["client_pattern"], json!("alice"));
        assert_eq!(body[0]["action"], json!("subscribe"));
        assert_eq!(body[0]["allow"], json!(true));
    }

    #[tokio::test]
    async fn test_auth_users_quotas_roundtrip() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        // Create with quotas: every bound echoes back.
        let (status, created) = server
            .post_auth(
                "/api/v1/auth/users",
                json!({"username": "capped",
                       "password": "pw",
                       "quotas": {"max_connections": 100,
                                  "max_publish_rate": 50,
                                  "max_publish_burst": 10}}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["username"], json!("capped"));
        assert_eq!(created["quotas"]["max_connections"], json!(100));
        assert_eq!(created["quotas"]["max_publish_rate"], json!(50));
        assert_eq!(created["quotas"]["max_publish_burst"], json!(10));

        // Without quotas: all-null bounds object.
        let (status, created) = server
            .post_auth(
                "/api/v1/auth/users",
                json!({"username": "plain", "password": "pw"}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(
            created["quotas"]["max_connections"],
            serde_json::Value::Null
        );

        // Listing shows both shapes side by side.
        let (status, body) = server.get_auth("/api/v1/auth/users", &token).await;
        assert_eq!(status, 200);
        let users = body.as_array().expect("users list");
        assert_eq!(users.len(), 2);
        assert_eq!(users[0]["username"], json!("capped"));
        assert_eq!(users[0]["quotas"]["max_connections"], json!(100));
        assert_eq!(users[1]["username"], json!("plain"));
        assert_eq!(
            users[1]["quotas"]["max_publish_rate"],
            serde_json::Value::Null
        );
    }

    #[tokio::test]
    async fn login_default_admin_requires_password_change() {
        let (server, _state) = TestServer::start().await;
        let (status, body) = server
            .post(
                "/api/v5/login",
                json!({"username": "admin", "password": "public"}),
            )
            .await;
        assert_eq!(status, 200);
        assert!(body["token"].as_str().is_some_and(|t| !t.is_empty()));
        assert_eq!(body["role"], json!("administrator"));
        assert_eq!(body["must_change_password"], json!(true));
    }

    #[tokio::test]
    async fn login_wrong_password_is_rejected_and_creates_nothing() {
        let (server, state) = TestServer::start().await;

        let (status, body) = server
            .post(
                "/api/v5/login",
                json!({"username": "admin", "password": "wrong-password"}),
            )
            .await;
        assert_eq!(status, 401);
        assert_eq!(body["code"], json!("NAME_PWD_ERROR"));

        // An unknown user is rejected and appears in neither store.
        let (status, _) = server
            .post(
                "/api/v5/login",
                json!({"username": "ghost", "password": "whatever-123"}),
            )
            .await;
        assert_eq!(status, 401);
        assert!(state.admin_users.get("ghost").is_none());
        assert_eq!(state.auth.user_count(), 0);
    }

    #[tokio::test]
    async fn scram_login_end_to_end() {
        let (server, _state) = TestServer::start().await;
        let client_nonce = "testclientnonce123";

        // Correct password: challenge, proof, verify.
        let (status, challenge) = server
            .post(
                "/api/v5/login/challenge",
                json!({"username": "admin", "client_nonce": client_nonce}),
            )
            .await;
        assert_eq!(status, 200);
        let challenge_id = challenge["challenge_id"].as_str().expect("challenge id");
        let server_nonce = challenge["server_nonce"].as_str().expect("server nonce");
        let salt_b64 = challenge["salt"].as_str().expect("salt");
        let iterations = challenge["iterations"].as_u64().expect("iterations") as u32;
        let combined = format!("{client_nonce}{server_nonce}");
        let auth_message =
            scram_auth_message("admin", client_nonce, &combined, salt_b64, iterations);
        let (proof_b64, server_sig_b64) =
            scram_client::proof("public", salt_b64, iterations, &auth_message);

        let (status, body) = server
            .post(
                "/api/v5/login/verify",
                json!({
                    "challenge_id": challenge_id,
                    "combined_nonce": combined,
                    "client_proof": proof_b64,
                }),
            )
            .await;
        assert_eq!(status, 200);
        assert!(body["token"].as_str().is_some_and(|t| !t.is_empty()));
        assert_eq!(body["server_signature"], json!(server_sig_b64));

        // Wrong password: a fresh challenge, then the proof is rejected.
        let (status, challenge) = server
            .post(
                "/api/v5/login/challenge",
                json!({"username": "admin", "client_nonce": client_nonce}),
            )
            .await;
        assert_eq!(status, 200);
        let challenge_id = challenge["challenge_id"].as_str().expect("challenge id");
        let salt_b64 = challenge["salt"].as_str().expect("salt");
        let iterations = challenge["iterations"].as_u64().expect("iterations") as u32;
        let auth_message =
            scram_auth_message("admin", client_nonce, &combined, salt_b64, iterations);
        let (bad_proof, _) =
            scram_client::proof("wrong-password", salt_b64, iterations, &auth_message);
        let (status, body) = server
            .post(
                "/api/v5/login/verify",
                json!({
                    "challenge_id": challenge_id,
                    "combined_nonce": combined,
                    "client_proof": bad_proof,
                }),
            )
            .await;
        assert_eq!(status, 401);
        assert_eq!(body["code"], json!("NAME_PWD_ERROR"));
    }

    #[tokio::test]
    async fn current_user_reflects_token() {
        let (server, _state) = TestServer::start().await;
        let admin_token = server.login_as_admin().await;

        // Create a viewer through the admin API.
        let (status, _) = server
            .post_auth(
                "/api/v5/users",
                json!({"username": "watcher", "password": "W4tcher-pass", "role": "viewer"}),
                &admin_token,
            )
            .await;
        assert_eq!(status, 200);

        let (status, body) = server
            .post(
                "/api/v5/login",
                json!({"username": "watcher", "password": "W4tcher-pass"}),
            )
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["role"], json!("viewer"));
        let viewer_token = body["token"].as_str().expect("viewer token").to_string();

        let (status, body) = server.get_auth("/api/v5/current_user", &viewer_token).await;
        assert_eq!(status, 200);
        assert_eq!(body["username"], json!("watcher"));
        assert_eq!(body["role"], json!("viewer"));

        // No token is a 401.
        let (status, body) = server.get("/api/v5/current_user").await;
        assert_eq!(status, 401);
        assert_eq!(body["code"], json!("UNAUTHORIZED"));
    }

    #[tokio::test]
    async fn change_pwd_flow() {
        let (server, _state) = TestServer::start().await;
        let admin_token = server.admin_token().await;
        // A second admin token that must die on password change.
        let (status, other) = server
            .post(
                "/api/v5/login",
                json!({"username": "admin", "password": "public"}),
            )
            .await;
        assert_eq!(status, 200);
        let other_token = other["token"].as_str().expect("second token").to_string();
        assert_ne!(admin_token, other_token);

        // Admin changes their own password from the default.
        let (status, _) = server
            .put_auth(
                "/api/v5/users/admin/change_pwd",
                json!({"old_pwd": "public", "new_pwd": "N3w-passw0rd!"}),
                &admin_token,
            )
            .await;
        assert_eq!(status, 204);

        // Flag cleared on the caller's surviving token.
        let (status, body) = server.get_auth("/api/v5/current_user", &admin_token).await;
        assert_eq!(status, 200);
        assert_eq!(body["must_change_password"], json!(false));

        // Old password no longer logs in; the other token is revoked.
        let (status, _) = server
            .post(
                "/api/v5/login",
                json!({"username": "admin", "password": "public"}),
            )
            .await;
        assert_eq!(status, 401);
        let (status, _) = server.get_auth("/api/v5/current_user", &other_token).await;
        assert_eq!(status, 401);

        // A viewer cannot change another user's password.
        let (status, _) = server
            .post_auth(
                "/api/v5/users",
                json!({"username": "watcher", "password": "W4tcher-pass", "role": "viewer"}),
                &admin_token,
            )
            .await;
        assert_eq!(status, 200);
        let (status, body) = server
            .post(
                "/api/v5/login",
                json!({"username": "watcher", "password": "W4tcher-pass"}),
            )
            .await;
        assert_eq!(status, 200);
        let viewer_token = body["token"].as_str().expect("viewer token").to_string();
        let (status, body) = server
            .put_auth(
                "/api/v5/users/admin/change_pwd",
                json!({"old_pwd": "N3w-passw0rd!", "new_pwd": "An0ther-pass!"}),
                &viewer_token,
            )
            .await;
        assert_eq!(status, 403);
        assert_eq!(body["code"], json!("FORBIDDEN"));
    }

    #[tokio::test]
    async fn change_pwd_accepts_post() {
        let (server, _state) = TestServer::start().await;
        let fresh = server.admin_token().await;
        let (status, _) = server
            .post_auth(
                "/api/v5/users/admin/change_pwd",
                json!({"old_pwd": "public", "new_pwd": "N3w-post-passw0rd!"}),
                &fresh,
            )
            .await;
        assert_eq!(status, 204);
        let (status, _) = server.get_auth("/api/v1/clients", &fresh).await;
        assert_eq!(status, 200);
    }

    #[tokio::test]
    async fn lowercase_bearer_scheme_is_accepted() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;
        let (status, body) = server
            .request(&format!(
                "GET /api/v5/current_user HTTP/1.0\r\nHost: test\r\nAuthorization: bearer {token}\r\nConnection: close\r\n\r\n"
            ))
            .await;
        assert_eq!(status, 200);
        assert!(body["username"].is_string());
    }

    #[tokio::test]
    async fn bare_token_without_scheme_is_rejected() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;
        let (status, body) = server
            .request(&format!(
                "GET /api/v5/current_user HTTP/1.0\r\nHost: test\r\nAuthorization: {token}\r\nConnection: close\r\n\r\n"
            ))
            .await;
        assert_eq!(status, 401);
        assert_eq!(body["code"], json!("UNAUTHORIZED"));
    }

    #[test]
    fn is_own_change_pwd_percent_decodes_username() {
        use crate::api_auth::is_own_change_pwd;
        let post = axum::http::Method::POST;
        assert!(is_own_change_pwd(
            &post,
            "/api/v5/users/ops.team-1%40site/change_pwd",
            "ops.team-1@site"
        ));
        assert!(!is_own_change_pwd(
            &post,
            "/api/v5/users/ops.team-1%4/change_pwd",
            "ops.team-1@site"
        ));
    }

    #[tokio::test]
    async fn admin_users_api_does_not_touch_mqtt_store() {
        let (server, state) = TestServer::start().await;
        let admin_token = server.login_as_admin().await;

        let (status, created) = server
            .post_auth(
                "/api/v5/users",
                json!({"username": "ops", "password": "Ops-passw0rd", "role": "viewer",
                       "description": "read-only"}),
                &admin_token,
            )
            .await;
        assert_eq!(status, 200);
        assert_eq!(created["username"], json!("ops"));
        assert_eq!(created["role"], json!("viewer"));
        assert_eq!(created["description"], json!("read-only"));
        assert_eq!(state.auth.user_count(), 0);

        // Listing serves the admin store with roles, sorted by username.
        let (status, body) = server.get_auth("/api/v5/users", &admin_token).await;
        assert_eq!(status, 200);
        let names: Vec<&str> = body
            .as_array()
            .expect("users array")
            .iter()
            .map(|u| u["username"].as_str().expect("username"))
            .collect();
        assert_eq!(names, vec!["admin", "ops"]);

        // Role/description update and delete stay out of the MQTT store.
        let (status, updated) = server
            .put_auth(
                "/api/v5/users/ops",
                json!({"role": "administrator", "description": "on-call"}),
                &admin_token,
            )
            .await;
        assert_eq!(status, 200);
        assert_eq!(updated["role"], json!("administrator"));
        assert_eq!(updated["description"], json!("on-call"));
        let (status, _) = server.delete_auth("/api/v5/users/ops", &admin_token).await;
        assert_eq!(status, 204);
        assert_eq!(state.auth.user_count(), 0);
    }

    #[tokio::test]
    async fn demoted_admin_token_loses_admin_rights() {
        let (server, _state) = TestServer::start().await;
        let admin_token = server.login_as_admin().await;

        let (status, _) = server
            .post_auth(
                "/api/v5/users",
                json!({"username": "b-admin", "password": "B-passw0rd!", "role": "administrator"}),
                &admin_token,
            )
            .await;
        assert_eq!(status, 200);

        let (status, body) = server
            .post(
                "/api/v5/login",
                json!({"username": "b-admin", "password": "B-passw0rd!"}),
            )
            .await;
        assert_eq!(status, 200);
        let b_token = body["token"].as_str().expect("b token").to_string();

        let (status, _) = server
            .post_auth(
                "/api/v5/users",
                json!({"username": "probe", "password": "Probe-pass1", "role": "viewer"}),
                &b_token,
            )
            .await;
        assert_eq!(status, 200);

        let (status, _) = server
            .put_auth(
                "/api/v5/users/b-admin",
                json!({"role": "viewer"}),
                &admin_token,
            )
            .await;
        assert_eq!(status, 200);

        let (status, body) = server
            .post_auth(
                "/api/v5/users",
                json!({"username": "probe2", "password": "Probe-pass1", "role": "viewer"}),
                &b_token,
            )
            .await;
        assert_eq!(status, 403);
        assert_eq!(body["code"], json!("FORBIDDEN"));
    }

    #[tokio::test]
    async fn deleted_user_token_is_rejected() {
        let (server, _state) = TestServer::start().await;
        let admin_token = server.login_as_admin().await;

        let (status, _) = server
            .post_auth(
                "/api/v5/users",
                json!({"username": "viewer-v", "password": "V-passw0rd!", "role": "viewer"}),
                &admin_token,
            )
            .await;
        assert_eq!(status, 200);

        let (status, body) = server
            .post(
                "/api/v5/login",
                json!({"username": "viewer-v", "password": "V-passw0rd!"}),
            )
            .await;
        assert_eq!(status, 200);
        let v_token = body["token"].as_str().expect("viewer token").to_string();

        let (status, _) = server.get_auth("/api/v5/current_user", &v_token).await;
        assert_eq!(status, 200);

        let (status, _) = server
            .delete_auth("/api/v5/users/viewer-v", &admin_token)
            .await;
        assert_eq!(status, 204);

        let (status, body) = server.get_auth("/api/v5/current_user", &v_token).await;
        assert_eq!(status, 401);
        assert_eq!(body["code"], json!("UNAUTHORIZED"));
    }

    /// Unique scratch data dir under the OS temp dir (no dev-dependency).
    fn unique_data_dir(prefix: &str) -> std::path::PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let slot = COUNTER.fetch_add(1, Ordering::SeqCst);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "indramqtt-w020-datadir-{prefix}-{}-{nanos}-{slot}",
            std::process::id()
        ))
    }

    #[tokio::test]
    async fn admin_users_survive_restart() {
        let dir = unique_data_dir("survive");
        let registry = Arc::new(ConfigRegistry::load(&dir).expect("fresh data dir loads defaults"));
        let (server, _state) = TestServer::start_with_registry(Arc::clone(&registry)).await;
        let admin_token = server.login_as_admin().await;

        // Create `w0keep` through the API, then change its password.
        let (status, _) = server
            .post_auth(
                "/api/v5/users",
                json!({"username": "w0keep", "password": "W0keep-pass1", "role": "viewer"}),
                &admin_token,
            )
            .await;
        assert_eq!(status, 200);
        let (status, _) = server
            .put_auth(
                "/api/v5/users/w0keep/change_pwd",
                json!({"new_pwd": "W0keep-new-pass2"}),
                &admin_token,
            )
            .await;
        assert_eq!(status, 204);
        drop(server);
        drop(registry);

        // Simulate a kernel restart: rebuild state from the same dir.
        let reloaded = Arc::new(ConfigRegistry::load(&dir).expect("reload data dir"));
        let (server, _state) = TestServer::start_with_registry(reloaded).await;

        // The new password logs in; the old one is rejected.
        let (status, body) = server
            .post(
                "/api/v5/login",
                json!({"username": "w0keep", "password": "W0keep-new-pass2"}),
            )
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["role"], json!("viewer"));
        let (status, body) = server
            .post(
                "/api/v5/login",
                json!({"username": "w0keep", "password": "W0keep-pass1"}),
            )
            .await;
        assert_eq!(status, 401);
        assert_eq!(body["code"], json!("NAME_PWD_ERROR"));
        drop(server);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn admin_users_delete_survives_restart() {
        let dir = unique_data_dir("delete");
        let registry = Arc::new(ConfigRegistry::load(&dir).expect("fresh data dir loads defaults"));
        let (server, _state) = TestServer::start_with_registry(registry).await;
        let admin_token = server.login_as_admin().await;

        let (status, _) = server
            .post_auth(
                "/api/v5/users",
                json!({"username": "w0keep", "password": "W0keep-pass1", "role": "viewer"}),
                &admin_token,
            )
            .await;
        assert_eq!(status, 200);
        // Sanity: the user logs in before the delete.
        let (status, _) = server
            .post(
                "/api/v5/login",
                json!({"username": "w0keep", "password": "W0keep-pass1"}),
            )
            .await;
        assert_eq!(status, 200);
        let (status, _) = server
            .delete_auth("/api/v5/users/w0keep", &admin_token)
            .await;
        assert_eq!(status, 204);
        drop(server);

        // Simulate a kernel restart: rebuild state from the same dir.
        let reloaded = Arc::new(ConfigRegistry::load(&dir).expect("reload data dir"));
        let (server, _state) = TestServer::start_with_registry(reloaded).await;

        // The deleted user can no longer log in ...
        let (status, _) = server
            .post(
                "/api/v5/login",
                json!({"username": "w0keep", "password": "W0keep-pass1"}),
            )
            .await;
        assert_eq!(status, 401);
        // ... and the reloaded list has no `w0keep`. The admin password
        // persisted too, so the rebooted node logs in with it.
        let (status, body) = server
            .post(
                "/api/v5/login",
                json!({"username": "admin", "password": "Adm1n-test-pass!"}),
            )
            .await;
        assert_eq!(status, 200);
        let admin_token = body["token"].as_str().expect("admin token").to_string();
        let (status, body) = server.get_auth("/api/v5/users", &admin_token).await;
        assert_eq!(status, 200);
        let names: Vec<&str> = body
            .as_array()
            .expect("users array")
            .iter()
            .map(|u| u["username"].as_str().expect("username"))
            .collect();
        assert!(
            !names.contains(&"w0keep"),
            "deleted user must stay deleted, got: {names:?}"
        );
        drop(server);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn mqtt_users_and_quotas_survive_restart() {
        let dir = unique_data_dir("mqtt-survive");
        let registry = Arc::new(ConfigRegistry::load(&dir).expect("fresh data dir loads defaults"));
        let (server, _state) = TestServer::start_with_registry(registry).await;
        let admin_token = server.login_as_admin().await;

        // Create MQTT users through the API, one with quotas.
        let (status, _) = server
            .post_auth(
                "/api/v1/auth/users",
                json!({"username": "capped", "password": "pw-capped",
                       "quotas": {"max_connections": 2,
                                  "max_publish_rate": 50,
                                  "max_publish_burst": 10}}),
                &admin_token,
            )
            .await;
        assert_eq!(status, 201);
        let (status, _) = server
            .post_auth(
                "/api/v1/auth/users",
                json!({"username": "plain", "password": "pw-plain"}),
                &admin_token,
            )
            .await;
        assert_eq!(status, 201);
        drop(server);

        // Simulate a kernel restart: rebuild state from the same dir.
        let reloaded = Arc::new(ConfigRegistry::load(&dir).expect("reload data dir"));
        let (server, _state) = TestServer::start_with_registry(reloaded).await;

        // The admin password persisted too, so the rebooted node logs in
        // with it; both MQTT users and the configured quotas are intact.
        let (status, body) = server
            .post(
                "/api/v5/login",
                json!({"username": "admin", "password": "Adm1n-test-pass!"}),
            )
            .await;
        assert_eq!(status, 200);
        let admin_token = body["token"].as_str().expect("admin token").to_string();
        let (status, body) = server.get_auth("/api/v1/auth/users", &admin_token).await;
        assert_eq!(status, 200);
        let users = body.as_array().expect("users list");
        assert_eq!(users.len(), 2);
        assert_eq!(users[0]["username"], json!("capped"));
        assert_eq!(users[0]["quotas"]["max_connections"], json!(2));
        assert_eq!(users[0]["quotas"]["max_publish_rate"], json!(50));
        assert_eq!(users[0]["quotas"]["max_publish_burst"], json!(10));
        assert_eq!(users[1]["username"], json!("plain"));
        assert_eq!(
            users[1]["quotas"]["max_publish_rate"],
            serde_json::Value::Null
        );
        drop(server);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn connectors_survive_restart() {
        let _connector_guard = CONNECTOR_TEST_SERIAL.lock().await;
        let dir = unique_data_dir("w023-conn-survive");
        let registry = Arc::new(ConfigRegistry::load(&dir).expect("fresh data dir loads defaults"));
        let (server, state) = TestServer::start_with_registry(Arc::clone(&registry)).await;
        let token = server.login_as_admin().await;

        // No `server`/`url` target: no probe runs, status is `connected`
        // and the create path registers a live `http` sink.
        let (status, created) = server
            .post_auth(
                "/api/v5/connectors",
                json!({"name": "w023-http-conn", "type": "http"}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert!(
            state.engine.connectors().get("w023-http-conn").is_some(),
            "create must register a live sink"
        );
        drop(server);
        drop(registry);

        // Simulate a kernel restart: rebuild state from the same dir.
        let reloaded = Arc::new(ConfigRegistry::load(&dir).expect("reload data dir"));
        let (server, state) = TestServer::start_with_registry(reloaded).await;
        // The admin password persisted too, so the rebooted node logs in
        // with the changed password (`login_as_admin` only fits fresh
        // servers still on the default password).
        let (status, body) = server
            .post(
                "/api/v5/login",
                json!({"username": "admin", "password": "Adm1n-test-pass!"}),
            )
            .await;
        assert_eq!(status, 200);
        let token = body["token"].as_str().expect("admin token").to_string();

        // The identical stored entry is back ...
        let (status, body) = server
            .get_auth("/api/v5/connectors/w023-http-conn", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(
            body, created,
            "restored connector must return the identical stored entry"
        );
        // ... and the restored connector actually connects, not just lists:
        // the live sink is re-registered through the same path create uses.
        assert!(
            state.engine.connectors().get("w023-http-conn").is_some(),
            "restored connector must re-register its live sink"
        );
        let (status, body) = server.get_auth("/api/v1/connectors", &token).await;
        assert_eq!(status, 200);
        assert!(
            body.as_array()
                .expect("connectors array")
                .iter()
                .any(|c| c["id"] == json!("w023-http-conn")),
            "restored connector must be live, got: {body}"
        );
        drop(server);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn connector_delete_survives_restart() {
        let _connector_guard = CONNECTOR_TEST_SERIAL.lock().await;
        let dir = unique_data_dir("w023-conn-delete");
        let registry = Arc::new(ConfigRegistry::load(&dir).expect("fresh data dir loads defaults"));
        let (server, _state) = TestServer::start_with_registry(Arc::clone(&registry)).await;
        let token = server.login_as_admin().await;

        for name in ["w023-del-conn", "w023-kept-conn"] {
            let (status, _) = server
                .post_auth(
                    "/api/v5/connectors",
                    json!({"name": name, "type": "http"}),
                    &token,
                )
                .await;
            assert_eq!(status, 201);
        }
        let (status, _) = server
            .delete_auth("/api/v5/connectors/w023-del-conn", &token)
            .await;
        assert_eq!(status, 204);
        let (status, _) = server
            .get_auth("/api/v5/connectors/w023-del-conn", &token)
            .await;
        assert_eq!(status, 404);
        // The delete must reach the snapshot on disk: the kept connector
        // is stored, the deleted one is gone.
        let snapshot = ConfigRegistry::load(&dir)
            .expect("reload data dir")
            .snapshot();
        let ids: Vec<&str> = snapshot
            .connectors
            .connectors
            .iter()
            .map(|c| c.id.as_str())
            .collect();
        assert!(
            ids.contains(&"w023-kept-conn"),
            "kept connector must be persisted, got: {ids:?}"
        );
        assert!(
            !ids.contains(&"w023-del-conn"),
            "deleted connector must stay deleted, got: {ids:?}"
        );
        drop(server);
        drop(registry);

        // Simulate a kernel restart: rebuild state from the same dir.
        let reloaded = Arc::new(ConfigRegistry::load(&dir).expect("reload data dir"));
        let (server, state) = TestServer::start_with_registry(reloaded).await;
        // The admin password persisted too, so the rebooted node logs in
        // with the changed password.
        let (status, body) = server
            .post(
                "/api/v5/login",
                json!({"username": "admin", "password": "Adm1n-test-pass!"}),
            )
            .await;
        assert_eq!(status, 200);
        let token = body["token"].as_str().expect("admin token").to_string();

        // The deleted connector stays deleted, and no sink comes back,
        // while the kept connector is back with its live sink.
        let (status, body) = server
            .get_auth("/api/v5/connectors/w023-del-conn", &token)
            .await;
        assert_eq!(status, 404);
        assert_eq!(body["code"], json!("NOT_FOUND"));
        assert!(
            state.engine.connectors().get("w023-del-conn").is_none(),
            "deleted connector must not re-register any sink"
        );
        let (status, body) = server
            .get_auth("/api/v5/connectors/w023-kept-conn", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["id"], json!("w023-kept-conn"));
        assert!(
            state.engine.connectors().get("w023-kept-conn").is_some(),
            "kept connector must re-register its live sink"
        );
        drop(server);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn connector_duplicate_create_rejected_without_poisoning() {
        let _connector_guard = CONNECTOR_TEST_SERIAL.lock().await;
        // TK-03: a duplicate create must be rejected with the documented
        // conflict code before the store is mutated, so later
        // POST/PUT/DELETE keep working (no poisoned persistence).
        let dir = unique_data_dir("tk03-conn-dup");
        let registry = Arc::new(ConfigRegistry::load(&dir).expect("fresh data dir loads defaults"));
        let (server, _state) = TestServer::start_with_registry(Arc::clone(&registry)).await;
        let token = server.login_as_admin().await;

        // No `server`/`url` target: no probe runs, status is `connected`.
        let (status, _) = server
            .post_auth(
                "/api/v5/connectors",
                json!({"name": "tk03-dup-conn", "type": "http"}),
                &token,
            )
            .await;
        assert_eq!(status, 201);

        // Duplicate by `name`: the documented conflict, not a 500.
        let (status, body) = server
            .post_auth(
                "/api/v5/connectors",
                json!({"name": "tk03-dup-conn", "type": "http"}),
                &token,
            )
            .await;
        assert_eq!(
            status, 400,
            "duplicate create must be rejected, got: {body}"
        );
        assert_eq!(body["code"], json!("ALREADY_EXISTS"));

        // Duplicate by `id`: the same connector under the other key.
        let (status, body) = server
            .post_auth(
                "/api/v5/connectors",
                json!({"id": "tk03-dup-conn", "type": "http"}),
                &token,
            )
            .await;
        assert_eq!(
            status, 400,
            "duplicate create by id must be rejected, got: {body}"
        );
        assert_eq!(body["code"], json!("ALREADY_EXISTS"));

        // The store is not poisoned: later POST/PUT/DELETE work normally.
        let (status, _) = server
            .post_auth(
                "/api/v5/connectors",
                json!({"name": "tk03-other-conn", "type": "http"}),
                &token,
            )
            .await;
        assert_eq!(
            status, 201,
            "create after a rejected duplicate must succeed"
        );
        let (status, _) = server
            .put_auth(
                "/api/v5/connectors/tk03-dup-conn",
                json!({"type": "http", "enable": true}),
                &token,
            )
            .await;
        assert_eq!(status, 200, "update of the existing id must keep working");
        let (status, _) = server
            .delete_auth("/api/v5/connectors/tk03-other-conn", &token)
            .await;
        assert_eq!(
            status, 204,
            "delete after a rejected duplicate must succeed"
        );
        let (status, body) = server
            .get_auth("/api/v5/connectors/tk03-dup-conn", &token)
            .await;
        assert_eq!(
            status, 200,
            "original connector must still be readable: {body}"
        );
        assert_eq!(body["id"], json!("tk03-dup-conn"));
        drop(server);
        std::fs::remove_dir_all(&dir).ok();
    }

    fn fill_pending_challenges(tokens: &crate::v5::auth::ApiTokens, count: usize) {
        for i in 0..count {
            let inserted = tokens.insert_challenge(
                format!("fill-{i}"),
                crate::v5::auth::ScramChallengeState::for_test("admin"),
            );
            assert!(inserted, "insert {i} should succeed");
        }
    }

    #[tokio::test]
    async fn challenge_cap_returns_429() {
        use crate::v5::auth::{ScramChallengeState, MAX_PENDING_CHALLENGES};
        let (server, state) = TestServer::start().await;
        fill_pending_challenges(&state.tokens, MAX_PENDING_CHALLENGES);
        assert!(
            !state.tokens.insert_challenge(
                "one-more".to_string(),
                ScramChallengeState::for_test("admin")
            ),
            "insert past the cap should fail"
        );
        let (status, body) = server
            .post(
                "/api/v5/login/challenge",
                json!({"username": "admin", "client_nonce": "nonce-123"}),
            )
            .await;
        assert_eq!(status, 429);
        assert_eq!(body["code"], json!("TOO_MANY_REQUESTS"));
    }

    #[tokio::test]
    async fn removed_authchain_authz_routes_return_404() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        for (method, path) in [
            ("GET", "/api/v5/authentication/x"),
            ("GET", "/api/v5/authorization/sources"),
            ("GET", "/api/v5/authorization/settings"),
            ("DELETE", "/api/v5/authorization/cache"),
        ] {
            let (status, _) = server
                .request_raw(&format!(
                    "{method} {path} HTTP/1.0\r\nHost: test\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
                ))
                .await;
            assert_eq!(status, 404, "{method} {path} must be gone");
        }
    }

    #[tokio::test]
    async fn authn_chain_list_create_round_trip() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        // Empty chain reads as an empty collection, not an error.
        let (status, body) = server.get_auth("/api/v5/authentication", &token).await;
        assert_eq!(status, 200);
        assert_eq!(body["data"], json!([]));
        assert_eq!(body["meta"]["count"], json!(0));

        // Create one built-in entry.
        let (status, created) = server
            .post_auth(
                "/api/v5/authentication",
                json!({"mechanism": "password_based", "backend": "built_in_database"}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["id"], json!("password_based:built_in_database"));
        assert_eq!(created["mechanism"], json!("password_based"));
        assert_eq!(created["backend"], json!("built_in_database"));
        assert_eq!(created["enable"], json!(true));
        // No invented fields: exactly the documented slot fields.
        let obj = created.as_object().expect("entry is an object");
        for key in obj.keys() {
            assert!(
                ["id", "mechanism", "backend", "enable", "config"].contains(&key.as_str()),
                "unexpected field {key} in chain entry"
            );
        }

        // List again: the entry is present in order.
        let (status, body) = server.get_auth("/api/v5/authentication", &token).await;
        assert_eq!(status, 200);
        let data = body["data"].as_array().expect("data is a list");
        assert_eq!(data.len(), 1);
        assert_eq!(data[0]["id"], json!("password_based:built_in_database"));
        assert_eq!(body["meta"]["count"], json!(1));

        // Re-creating the same id is a clean duplicate rejection, never
        // a silent overwrite.
        let (status, body) = server
            .post_auth(
                "/api/v5/authentication",
                json!({"mechanism": "password_based", "backend": "built_in_database"}),
                &token,
            )
            .await;
        assert_eq!(status, 400);
        assert_eq!(body["code"], json!("ALREADY_EXISTS"));
        assert!(body["message"].is_string());

        // Malformed bodies are client errors with the documented shape.
        let (status, body) = server
            .post_auth(
                "/api/v5/authentication",
                json!({"mechanism": "password_based"}),
                &token,
            )
            .await;
        assert_eq!(status, 400);
        assert_eq!(body["code"], json!("BAD_REQUEST"));
        assert!(body["message"].is_string());

        // Unknown backends are rejected, never stored.
        let (status, body) = server
            .post_auth(
                "/api/v5/authentication",
                json!({"mechanism": "password_based", "backend": "nope"}),
                &token,
            )
            .await;
        assert_eq!(status, 400);
        assert_eq!(body["code"], json!("BAD_REQUEST"));

        // Second entry keeps insertion order; paging slices after filtering.
        let (status, _) = server
            .post_auth(
                "/api/v5/authentication",
                json!({"mechanism": "password_based", "backend": "mysql"}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        let (status, body) = server
            .get_auth("/api/v5/authentication?page=2&limit=1", &token)
            .await;
        assert_eq!(status, 200);
        let data = body["data"].as_array().expect("data is a list");
        assert_eq!(data.len(), 1);
        assert_eq!(data[0]["id"], json!("password_based:mysql"));
        assert_eq!(body["meta"]["page"], json!(2));
        assert_eq!(body["meta"]["limit"], json!(1));
        assert_eq!(body["meta"]["count"], json!(2));
    }

    #[tokio::test]
    async fn authn_chain_drives_connect_and_survives_restart() {
        // Broker consult through the console CONNECT path: an empty chain
        // preserves today's open behaviour, while a chain with no live
        // backend fails closed without creating a session.
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;
        let mut anon = WsClient::connect(server.port).await;
        anon.send_bin(&mqtt_connect("w2-02-open", None, None)).await;
        let connack = anon.recv_msg().await.expect("connack");
        assert_eq!(mqtt_packet_type(&connack), 2);
        assert_eq!(connack[3], 0);
        let (status, _) = server
            .post_auth(
                "/api/v5/authentication",
                json!({"mechanism": "password_based", "backend": "mysql"}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        let mut refused = WsClient::connect(server.port).await;
        refused
            .send_bin(&mqtt_connect("w2-02-closed", None, None))
            .await;
        let connack = refused.recv_msg().await.expect("connack");
        assert_eq!(mqtt_packet_type(&connack), 2);
        assert_eq!(connack[3], 0x86);

        // Restart persistence through the config registry: the chain
        // survives a rebuild from the same data dir.
        let dir = unique_data_dir("authn-chain");
        let registry = Arc::new(ConfigRegistry::load(&dir).expect("fresh data dir loads defaults"));
        let (server, _state) = TestServer::start_with_registry(Arc::clone(&registry)).await;
        let token = server.login_as_admin().await;
        let (status, _) = server
            .post_auth(
                "/api/v5/authentication",
                json!({"mechanism": "password_based", "backend": "built_in_database"}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        drop(server);
        drop(registry);
        let reloaded = Arc::new(ConfigRegistry::load(&dir).expect("reload data dir"));
        let (server, _state) = TestServer::start_with_registry(reloaded).await;
        // The admin password persisted too, so the rebooted node logs in
        // with the changed password (`login_as_admin` only fits fresh
        // servers still on the default password).
        let (status, body) = server
            .post(
                "/api/v5/login",
                json!({"username": "admin", "password": "Adm1n-test-pass!"}),
            )
            .await;
        assert_eq!(status, 200);
        let token = body["token"].as_str().expect("admin token").to_string();
        let (status, body) = server.get_auth("/api/v5/authentication", &token).await;
        assert_eq!(status, 200);
        let data = body["data"].as_array().expect("data is a list");
        assert_eq!(data.len(), 1);
        assert_eq!(data[0]["id"], json!("password_based:built_in_database"));
        drop(server);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn authn_chain_order_replace_round_trip_and_rejects_unknown() {
        // Order-replace through the broker: create two entries, set an
        // explicit order, list expecting the new order; an unknown id
        // and a partial list are rejected with no change applied.
        // Management-plane only; publish and deliver never touch this
        // store, and the CONNECT path keeps reading its lock-free
        // snapshot.
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;
        let (status, _) = server
            .post_auth(
                "/api/v5/authentication",
                json!({"mechanism": "password_based", "backend": "built_in_database"}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        let (status, _) = server
            .post_auth(
                "/api/v5/authentication",
                json!({"mechanism": "password_based", "backend": "mysql"}),
                &token,
            )
            .await;
        assert_eq!(status, 201);

        // Explicit order applies: mysql first.
        let (status, _) = server
            .put_auth(
                "/api/v5/authentication/order",
                json!([{"id": "password_based:mysql"}, {"id": "password_based:built_in_database"}]),
                &token,
            )
            .await;
        assert_eq!(status, 204);
        let (status, body) = server.get_auth("/api/v5/authentication", &token).await;
        assert_eq!(status, 200);
        let data = body["data"].as_array().expect("data is a list");
        assert_eq!(data.len(), 2);
        assert_eq!(data[0]["id"], json!("password_based:mysql"));
        assert_eq!(data[1]["id"], json!("password_based:built_in_database"));

        // Unknown ids are rejected with the documented shape and apply
        // nothing.
        let (status, body) = server
            .put_auth(
                "/api/v5/authentication/order",
                json!([
                    {"id": "password_based:mysql"},
                    {"id": "password_based:built_in_database"},
                    {"id": "password_based:nowhere"},
                ]),
                &token,
            )
            .await;
        assert_eq!(status, 400);
        assert_eq!(body["code"], json!("BAD_REQUEST"));
        assert!(body["message"].is_string());
        let (status, body) = server.get_auth("/api/v5/authentication", &token).await;
        assert_eq!(status, 200);
        let data = body["data"].as_array().expect("data is a list");
        assert_eq!(data[0]["id"], json!("password_based:mysql"));
        assert_eq!(data[1]["id"], json!("password_based:built_in_database"));

        // Partial lists are rejected with no change applied.
        let (status, body) = server
            .put_auth(
                "/api/v5/authentication/order",
                json!([{"id": "password_based:mysql"}]),
                &token,
            )
            .await;
        assert_eq!(status, 400);
        assert_eq!(body["code"], json!("BAD_REQUEST"));
        let (status, body) = server.get_auth("/api/v5/authentication", &token).await;
        assert_eq!(status, 200);
        let data = body["data"].as_array().expect("data is a list");
        assert_eq!(data.len(), 2);
        assert_eq!(data[0]["id"], json!("password_based:mysql"));

        // Malformed bodies are client errors with the documented shape.
        let (status, body) = server
            .put_auth(
                "/api/v5/authentication/order",
                json!([{"not-id": "password_based:mysql"}]),
                &token,
            )
            .await;
        assert_eq!(status, 400);
        assert_eq!(body["code"], json!("BAD_REQUEST"));

        // Order persists across a restart through the config registry.
        let dir = unique_data_dir("authn-order");
        let registry = Arc::new(ConfigRegistry::load(&dir).expect("fresh data dir loads defaults"));
        let (server, _state) = TestServer::start_with_registry(Arc::clone(&registry)).await;
        let token = server.login_as_admin().await;
        let (status, _) = server
            .post_auth(
                "/api/v5/authentication",
                json!({"mechanism": "password_based", "backend": "built_in_database"}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        let (status, _) = server
            .post_auth(
                "/api/v5/authentication",
                json!({"mechanism": "password_based", "backend": "mysql"}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        let (status, _) = server
            .put_auth(
                "/api/v5/authentication/order",
                json!([{"id": "password_based:mysql"}, {"id": "password_based:built_in_database"}]),
                &token,
            )
            .await;
        assert_eq!(status, 204);
        drop(server);
        drop(registry);
        let reloaded = Arc::new(ConfigRegistry::load(&dir).expect("reload data dir"));
        let (server, _state) = TestServer::start_with_registry(reloaded).await;
        let (status, body) = server
            .post(
                "/api/v5/login",
                json!({"username": "admin", "password": "Adm1n-test-pass!"}),
            )
            .await;
        assert_eq!(status, 200);
        let token = body["token"].as_str().expect("admin token").to_string();
        let (status, body) = server.get_auth("/api/v5/authentication", &token).await;
        assert_eq!(status, 200);
        let data = body["data"].as_array().expect("data is a list");
        assert_eq!(data.len(), 2);
        assert_eq!(data[0]["id"], json!("password_based:mysql"));
        assert_eq!(data[1]["id"], json!("password_based:built_in_database"));
        drop(server);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn authn_entry_read_update_delete_round_trip() {
        // Per-id read/update/delete through the broker management plane
        // on the real chain store: create two entries, read one back,
        // update with a valid body and read again, delete then read 404,
        // delete unknown 404, invalid updates rejected without applying,
        // deleting the last entry refused, and delete-then-recreate of
        // the same id works. Management-plane only; the CONNECT path
        // keeps reading its lock-free snapshot and publish/deliver never
        // touch this store.
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;
        let (status, _) = server
            .post_auth(
                "/api/v5/authentication",
                json!({"mechanism": "password_based", "backend": "built_in_database"}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        let (status, _) = server
            .post_auth(
                "/api/v5/authentication",
                json!({"mechanism": "password_based", "backend": "mysql"}),
                &token,
            )
            .await;
        assert_eq!(status, 201);

        // Read one entry by id; the shape carries only the stored slot
        // fields, never invented measurements.
        let (status, body) = server
            .get_auth("/api/v5/authentication/password_based:mysql", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["id"], json!("password_based:mysql"));
        assert_eq!(body["mechanism"], json!("password_based"));
        assert_eq!(body["backend"], json!("mysql"));
        assert_eq!(body["enable"], json!(true));
        let obj = body.as_object().expect("entry is an object");
        for key in obj.keys() {
            assert!(
                ["id", "mechanism", "backend", "enable", "config"].contains(&key.as_str()),
                "unexpected field {key} in chain entry"
            );
        }

        // Unknown ids miss with the documented shape.
        let (status, body) = server
            .get_auth("/api/v5/authentication/password_based:nowhere", &token)
            .await;
        assert_eq!(status, 404);
        assert_eq!(body["code"], json!("NOT_FOUND"));
        assert!(body["message"].is_string());

        // Valid update replaces and reads back.
        let (status, body) = server
            .put_auth(
                "/api/v5/authentication/password_based:mysql",
                json!({"enable": false, "config": {"pool_size": 4}}),
                &token,
            )
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["id"], json!("password_based:mysql"));
        assert_eq!(body["enable"], json!(false));
        assert_eq!(body["config"], json!({"pool_size": 4}));
        let (status, body) = server
            .get_auth("/api/v5/authentication/password_based:mysql", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["enable"], json!(false));
        assert_eq!(body["config"], json!({"pool_size": 4}));

        // Invalid updates are client errors and apply nothing.
        for bad in [
            json!({"backend": "nope"}),
            json!({"mechanism": "nope"}),
            json!({"enable": "yes"}),
            json!({"config": "yes"}),
            json!({"id": "password_based:other"}),
            json!([1, 2]),
        ] {
            let (status, body) = server
                .put_auth("/api/v5/authentication/password_based:mysql", bad, &token)
                .await;
            assert_eq!(status, 400);
            assert_eq!(body["code"], json!("BAD_REQUEST"));
            assert!(body["message"].is_string());
        }
        // Unknown ids fail updates with 404 even for valid bodies.
        let (status, body) = server
            .put_auth(
                "/api/v5/authentication/password_based:nowhere",
                json!({"enable": false}),
                &token,
            )
            .await;
        assert_eq!(status, 404);
        assert_eq!(body["code"], json!("NOT_FOUND"));
        let (status, body) = server
            .get_auth("/api/v5/authentication/password_based:mysql", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["backend"], json!("mysql"));
        assert_eq!(body["enable"], json!(false));

        // Delete removes and reports; the deleted id reads 404 after.
        let (status, _) = server
            .delete_auth("/api/v5/authentication/password_based:mysql", &token)
            .await;
        assert_eq!(status, 204);
        let (status, body) = server
            .get_auth("/api/v5/authentication/password_based:mysql", &token)
            .await;
        assert_eq!(status, 404);
        assert_eq!(body["code"], json!("NOT_FOUND"));

        // Deleting an unknown id is 404.
        let (status, body) = server
            .delete_auth("/api/v5/authentication/password_based:nowhere", &token)
            .await;
        assert_eq!(status, 404);
        assert_eq!(body["code"], json!("NOT_FOUND"));

        // Deleting then re-creating the same id works (no tombstone).
        let (status, recreated) = server
            .post_auth(
                "/api/v5/authentication",
                json!({"mechanism": "password_based", "backend": "mysql"}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(recreated["id"], json!("password_based:mysql"));

        // Deleting the last remaining entry is refused instead of
        // leaving authentication open.
        let (status, _) = server
            .delete_auth(
                "/api/v5/authentication/password_based:built_in_database",
                &token,
            )
            .await;
        assert_eq!(status, 204);
        let (status, body) = server
            .delete_auth("/api/v5/authentication/password_based:mysql", &token)
            .await;
        assert_eq!(status, 400);
        assert_eq!(body["code"], json!("BAD_REQUEST"));
        assert!(body["message"].is_string());
        let (status, body) = server
            .get_auth("/api/v5/authentication/password_based:mysql", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["id"], json!("password_based:mysql"));
    }

    #[tokio::test]
    async fn authn_entry_update_delete_persist_across_restart() {
        // Per-id update/delete persist through the config registry: a
        // validated update and a removal survive a rebuild from the same
        // data dir. Management-plane only; publish and deliver never
        // touch this store.
        let dir = unique_data_dir("authn-entry");
        let registry = Arc::new(ConfigRegistry::load(&dir).expect("fresh data dir loads defaults"));
        let (server, _state) = TestServer::start_with_registry(Arc::clone(&registry)).await;
        let token = server.login_as_admin().await;
        let (status, _) = server
            .post_auth(
                "/api/v5/authentication",
                json!({"mechanism": "password_based", "backend": "built_in_database"}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        let (status, _) = server
            .post_auth(
                "/api/v5/authentication",
                json!({"mechanism": "password_based", "backend": "mysql"}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        let (status, _) = server
            .put_auth(
                "/api/v5/authentication/password_based:mysql",
                json!({"enable": false}),
                &token,
            )
            .await;
        assert_eq!(status, 200);
        let (status, _) = server
            .delete_auth("/api/v5/authentication/password_based:mysql", &token)
            .await;
        assert_eq!(status, 204);
        drop(server);
        drop(registry);
        let reloaded = Arc::new(ConfigRegistry::load(&dir).expect("reload data dir"));
        let (server, _state) = TestServer::start_with_registry(reloaded).await;
        let (status, body) = server
            .post(
                "/api/v5/login",
                json!({"username": "admin", "password": "Adm1n-test-pass!"}),
            )
            .await;
        assert_eq!(status, 200);
        let token = body["token"].as_str().expect("admin token").to_string();
        let (status, body) = server
            .get_auth(
                "/api/v5/authentication/password_based:built_in_database",
                &token,
            )
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["id"], json!("password_based:built_in_database"));
        let (status, _) = server
            .get_auth("/api/v5/authentication/password_based:mysql", &token)
            .await;
        assert_eq!(status, 404);
        drop(server);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn authn_node_cache_status_reset_round_trip() {
        // Status over real state plus a reset that actually evicts:
        // read the documented fields, populate the cache through
        // authentications through the broker, reset, then read an empty
        // cache. Management-plane only; publish and deliver never touch
        // the store.
        let (server, state) = TestServer::start().await;
        let token = server.login_as_admin().await;
        state
            .auth
            .add_user("w2-03-user", b"W2-03-pass!")
            .expect("test user persists");

        // Empty cache reads as size zero, never an error.
        let (status, body) = server
            .get_auth("/api/v5/authentication/node_cache/status", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["enabled"], json!(true));
        assert_eq!(body["size"], json!(0));
        assert_eq!(body["count"], json!(0));
        assert!(body["max_size"].is_number());
        assert!(body["max_count"].is_number());

        // Populate through a real credentialed CONNECT through the
        // broker (console path authenticates against the same store).
        let mut client = WsClient::connect(server.port).await;
        client
            .send_bin(&mqtt_connect(
                "w2-03-cache-1",
                Some("w2-03-user"),
                Some(b"W2-03-pass!"),
            ))
            .await;
        let connack = client.recv_msg().await.expect("connack");
        assert_eq!(mqtt_packet_type(&connack), 2);
        assert_eq!(connack[3], 0);
        let (status, body) = server
            .get_auth("/api/v5/authentication/node_cache/status", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["enabled"], json!(true));
        assert_eq!(body["size"], json!(1));
        assert_eq!(body["count"], json!(1));

        // Unknown query keys are ignored, not a 400.
        let (status, body) = server
            .get_auth(
                "/api/v5/authentication/node_cache/status?unknown_param=1",
                &token,
            )
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["size"], json!(1));

        // Reset evicts; the next read is empty. Resetting again still
        // succeeds (204).
        let (status, _) = server
            .post_auth("/api/v5/authentication/node_cache/reset", json!({}), &token)
            .await;
        assert_eq!(status, 204);
        let (status, body) = server
            .get_auth("/api/v5/authentication/node_cache/status", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["size"], json!(0));
        assert_eq!(body["count"], json!(0));
        let (status, _) = server
            .post_auth("/api/v5/authentication/node_cache/reset", json!({}), &token)
            .await;
        assert_eq!(status, 204);
    }

    #[tokio::test]
    async fn authn_settings_replace_round_trip_drives_connect_and_survives_restart() {
        // Settings round trip through the broker: GET defaults, PUT a
        // full valid update, GET expecting the update; a console CONNECT
        // still succeeds (the settings consult never breaks the open
        // broker) and a subscribe/publish/deliver flow proves publish
        // and deliver never touch this store. An invalid PUT is rejected
        // with no change; the node-cache subscriber keeps the status cap
        // in sync. Settings persist across a restart via the registry.
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        // Defaults read back with the documented fields.
        let (status, body) = server
            .get_auth("/api/v5/authentication/settings", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["ignore_backend_failures"], json!(false));
        assert_eq!(body["node_cache"]["enable"], json!(true));
        assert_eq!(body["node_cache"]["max_count"], json!(10000));
        assert_eq!(body["builtin_record_count_refresh_interval"], json!("1h"));

        // Full valid replace through the broker.
        let (status, _) = server
            .put_auth(
                "/api/v5/authentication/settings",
                json!({
                    "ignore_backend_failures": true,
                    "node_cache": {
                        "enable": true,
                        "cache_ttl": "30s",
                        "cleanup_interval": "1m",
                        "stat_update_interval": "5s",
                        "max_count": 5000,
                        "max_memory": "100MB",
                    },
                    "builtin_record_count_refresh_interval": "30m",
                }),
                &token,
            )
            .await;
        assert_eq!(status, 204);
        let (status, body) = server
            .get_auth("/api/v5/authentication/settings", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["ignore_backend_failures"], json!(true));
        assert_eq!(body["node_cache"]["max_count"], json!(5000));
        assert_eq!(body["node_cache"]["cache_ttl"], json!("30s"));
        assert_eq!(body["builtin_record_count_refresh_interval"], json!("30m"));

        // The subscriber keeps the node-cache status cap in sync with
        // the settings' cache half without a restart.
        let (status, body) = server
            .get_auth("/api/v5/authentication/node_cache/status", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["max_count"], json!(5000));

        // The CONNECT consult never breaks the open broker: a console
        // CONNECT still succeeds, and a subscribe/publish/deliver flow
        // proves publish and deliver never touch this store.
        let mut sub = WsClient::connect(server.port).await;
        sub.send_bin(&mqtt_connect("w2-05-sub", None, None)).await;
        let connack = sub.recv_msg().await.expect("connack");
        assert_eq!(mqtt_packet_type(&connack), 2);
        assert_eq!(connack[3], 0);
        sub.send_bin(&mqtt_subscribe(7, &[("w2-05/t", 1)])).await;
        let suback = sub.recv_msg().await.expect("suback");
        assert_eq!(mqtt_packet_type(&suback), 9);
        let mut publ = WsClient::connect(server.port).await;
        publ.send_bin(&mqtt_connect("w2-05-pub", None, None)).await;
        let connack = publ.recv_msg().await.expect("connack");
        assert_eq!(connack[3], 0);
        publ.send_bin(&mqtt_publish("w2-05/t", 42, 1, b"hi-w2-05"))
            .await;
        let puback = publ.recv_msg().await.expect("puback");
        assert_eq!(mqtt_packet_type(&puback), 4);
        let delivery = sub.recv_msg().await.expect("delivery");
        assert_eq!(mqtt_packet_type(&delivery), 3);
        assert!(delivery.ends_with(b"hi-w2-05"));

        // Unknown fields are rejected fail-closed with no change applied.
        let (status, body) = server
            .put_auth(
                "/api/v5/authentication/settings",
                json!({"ignore_backend_failures": true, "bogus": 1}),
                &token,
            )
            .await;
        assert_eq!(status, 400);
        assert_eq!(body["code"], json!("BAD_REQUEST"));
        let (status, body) = server
            .put_auth(
                "/api/v5/authentication/settings",
                json!({"node_cache": {"max_count": 0}}),
                &token,
            )
            .await;
        assert_eq!(status, 400);
        assert_eq!(body["code"], json!("BAD_REQUEST"));
        let (status, body) = server
            .get_auth("/api/v5/authentication/settings", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["node_cache"]["max_count"], json!(5000));

        // Partial bodies replace: missing fields reset to defaults.
        let (status, _) = server
            .put_auth(
                "/api/v5/authentication/settings",
                json!({"ignore_backend_failures": false}),
                &token,
            )
            .await;
        assert_eq!(status, 204);
        let (status, body) = server
            .get_auth("/api/v5/authentication/settings", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["ignore_backend_failures"], json!(false));
        assert_eq!(body["node_cache"]["max_count"], json!(10000));

        // Persistence across a restart through the config registry.
        let dir = unique_data_dir("authn-settings");
        let registry = Arc::new(ConfigRegistry::load(&dir).expect("fresh data dir loads defaults"));
        let (server, _state) = TestServer::start_with_registry(Arc::clone(&registry)).await;
        let token = server.login_as_admin().await;
        let (status, _) = server
            .put_auth(
                "/api/v5/authentication/settings",
                json!({
                    "ignore_backend_failures": true,
                    "node_cache": {
                        "enable": true,
                        "cache_ttl": "30s",
                        "cleanup_interval": "1m",
                        "stat_update_interval": "5s",
                        "max_count": 5000,
                        "max_memory": "100MB",
                    },
                    "builtin_record_count_refresh_interval": "30m",
                }),
                &token,
            )
            .await;
        assert_eq!(status, 204);
        drop(server);
        drop(registry);
        let reloaded = Arc::new(ConfigRegistry::load(&dir).expect("reload data dir"));
        let (server, _state) = TestServer::start_with_registry(reloaded).await;
        let (status, body) = server
            .post(
                "/api/v5/login",
                json!({"username": "admin", "password": "Adm1n-test-pass!"}),
            )
            .await;
        assert_eq!(status, 200);
        let token = body["token"].as_str().expect("admin token").to_string();
        let (status, body) = server
            .get_auth("/api/v5/authentication/settings", &token)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["ignore_backend_failures"], json!(true));
        assert_eq!(body["node_cache"]["max_count"], json!(5000));
        assert_eq!(body["builtin_record_count_refresh_interval"], json!("30m"));
        drop(server);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn api_rejects_requests_without_token() {
        let (server, _state) = TestServer::start().await;

        // Authenticated routes refuse anonymous callers.
        let (status, body) = server.get("/api/v1/clients").await;
        assert_eq!(status, 401);
        assert_eq!(body["code"], json!("UNAUTHORIZED"));
        let (status, body) = server.get("/api/v5/rules").await;
        assert_eq!(status, 401);
        assert_eq!(body["code"], json!("UNAUTHORIZED"));

        // Public routes stay open.
        let (status, _) = server
            .request_raw("GET /healthz HTTP/1.0\r\nHost: test\r\nConnection: close\r\n\r\n")
            .await;
        assert_eq!(status, 200);
        let (status, _) = server
            .request_raw("GET /dashboard HTTP/1.0\r\nHost: test\r\nConnection: close\r\n\r\n")
            .await;
        assert_eq!(status, 200);
    }

    #[tokio::test]
    async fn default_admin_must_change_password_first() {
        let (server, _state) = TestServer::start().await;
        let fresh = server.admin_token().await;

        // The default-password token is gated everywhere but the
        // password change, logout and current_user.
        let (status, body) = server.get_auth("/api/v1/clients", &fresh).await;
        assert_eq!(status, 403);
        assert_eq!(body["code"], json!("PASSWORD_CHANGE_REQUIRED"));
        let (status, _) = server.get_auth("/api/v5/current_user", &fresh).await;
        assert_eq!(status, 200);

        let (status, _) = server
            .put_auth(
                "/api/v5/users/admin/change_pwd",
                json!({"old_pwd": "public", "new_pwd": "Adm1n-test-pass!"}),
                &fresh,
            )
            .await;
        assert_eq!(status, 204);

        // After the change the same token opens the API.
        let (status, _) = server.get_auth("/api/v1/clients", &fresh).await;
        assert_eq!(status, 200);
    }

    #[tokio::test]
    async fn viewer_is_read_only() {
        let (server, _state) = TestServer::start().await;
        let admin = server.login_as_admin().await;

        let (status, _) = server
            .post_auth(
                "/api/v5/users",
                json!({"username": "ro-view", "password": "R0-viewer-pass", "role": "viewer"}),
                &admin,
            )
            .await;
        assert_eq!(status, 200);
        let (status, body) = server
            .post(
                "/api/v5/login",
                json!({"username": "ro-view", "password": "R0-viewer-pass"}),
            )
            .await;
        assert_eq!(status, 200);
        let viewer = body["token"].as_str().expect("viewer token").to_string();

        // Reads work; writes are forbidden.
        let (status, _) = server.get_auth("/api/v5/rules", &viewer).await;
        assert_eq!(status, 200);
        let (status, body) = server
            .post_auth(
                "/api/v1/rules",
                json!({"name": "x", "topic_filter": "a/#", "actions": []}),
                &viewer,
            )
            .await;
        assert_eq!(status, 403);
        assert_eq!(body["code"], json!("FORBIDDEN"));
    }

    #[tokio::test]
    async fn expired_token_is_rejected() {
        let (server, state) = TestServer::start().await;
        let stale = state
            .tokens
            .issue_expired("admin", crate::admin_users::AdminRole::Administrator);
        let (status, body) = server.get_auth("/api/v1/clients", &stale).await;
        assert_eq!(status, 401);
        assert_eq!(body["code"], json!("UNAUTHORIZED"));
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
            "value=\"azure_blob\"",
            "value=\"tablestore\"",
            "value=\"s3_tables\"",
            "value=\"confluent\"",
            "value=\"rocketmq\"",
            "value=\"oracle\"",
            "value=\"cockroachdb\"",
            "value=\"alloydb\"",
            "value=\"opentsdb\"",
            "value=\"greptimedb\"",
            "value=\"datalayers\"",
            "conn-azblob-account",
            "conn-ots-endpoint",
            "conn-s3t-arn",
            "conn-cfl-servers",
            "conn-rmq-endpoints",
            "conn-ora-url",
            "conn-crdb-url",
            "conn-alloy-host",
            "conn-otsdb-endpoint",
            "conn-grep-endpoint",
            "conn-dl-endpoint",
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
    async fn test_swagger_and_openapi_routes() {
        let (server, _state) = TestServer::start().await;

        // Test /swagger serves HTML
        let (status, html) = server
            .request_raw("GET /swagger HTTP/1.0\r\nHost: test\r\nConnection: close\r\n\r\n")
            .await;
        assert_eq!(status, 200);
        assert!(html.contains("SwaggerUIBundle"));
        assert!(html.contains("/api-docs/openapi.json"));

        // Test /api-docs/openapi.json serves valid OpenAPI 3.0 specification
        let (status, spec) = server.get("/api-docs/openapi.json").await;
        assert_eq!(status, 200);
        assert_eq!(spec["openapi"], "3.0.3");
        assert_eq!(spec["info"]["title"], "IndraMQTT Management API");
        assert!(spec["paths"]["/api/v1/nodes"]["get"].is_object());
        assert!(spec["paths"]["/api/v1/clients"]["get"].is_object());
        assert!(spec["paths"]["/api/v1/rules"]["get"].is_object());
        assert!(spec["paths"]["/api/v1/connectors"]["get"].is_object());
    }

    #[tokio::test]
    async fn test_modern_ui_routes() {
        let (server, _state) = TestServer::start().await;

        // Test /ui serves the modern React SPA (or fallback)
        let (status, html) = server
            .request_raw("GET /ui HTTP/1.0\r\nHost: test\r\nConnection: close\r\n\r\n")
            .await;
        assert_eq!(status, 200);
        assert!(html.len() > 100);
    }

    #[tokio::test]
    async fn test_clients_detail_endpoint() {
        let (server, state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        let (session, _) = state.sessions.get_or_create("detail-1", false);
        *session.conn_id.write() = Some(4242);
        *session.keepalive_secs.write() = 60;
        state.sessions.add_subscription(
            "detail-1",
            TopicFilter::new("sensors/+").unwrap(),
            QoS::AtLeastOnce,
        );

        let (status, body) = server.get_auth("/api/v1/clients/detail-1", &token).await;
        assert_eq!(status, 200);
        let info: broker_session::ClientInfo =
            serde_json::from_value(body).expect("detail row decodes");
        assert_eq!(info.client_id, "detail-1");
        assert_eq!(info.conn_id, Some(4242));
        assert_eq!(info.keepalive_secs, 60);
        assert!(!info.clean_start);
        assert!(info.connected);
        assert_eq!(info.subscriptions, vec!["sensors/+".to_string()]);

        let (status, _) = server.get_auth("/api/v1/clients/ghost", &token).await;
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
        let token = server.login_as_admin().await;
        let (status, body) = server.get_auth("/api/v1/connectors", &token).await;
        assert_eq!(status, 200);
        assert_eq!(body, json!([]));

        state
            .engine
            .connectors()
            .register("webhook-1", Arc::new(NullSink));
        let (status, body) = server.get_auth("/api/v1/connectors", &token).await;
        assert_eq!(status, 200);
        assert_eq!(
            body,
            json!([{"id": "webhook-1", "kind": "test", "tier": "community"}])
        );
    }

    #[tokio::test]
    async fn test_connectors_create_kafka_rabbitmq_logger() {
        let _connector_guard = CONNECTOR_TEST_SERIAL.lock().await;
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        // Fixed test RSA key for the OCI + GCP-IoT creation legs below
        // (openssl-generated, in-memory, never deployed).
        let test_pem = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCgQlU8hDdoMjP5
QU2fhr0g+2n5HQSvgQaDKkpZFftqbrMixmFg3pGQN+GZp9vIscT+BlNrJueigXpn
pRbhI0RRj8EvVl+4Or+0hdzeLDmfGl/9SIhnyiRsJ7YDeO3uZq/Cff2zMeXqqbk4
RgKwbQksnJPOOYgVOfPrLjHJdEkNcSxT44tyOVrhBVISYm+zUw4By4GSQXp4RoTa
8UFX/gHoa+31um/9yZfDf9ekzelBys+4iSBeJ6imdStCjt8K+71yxewMSMD6HiCj
2GWvp+mPixqf4GcwaiqoFgJj+IKspc3eyozqJY/+610aaSw/ooO2AFXfErJlJEBP
H5hITBUlAgMBAAECggEAErJqe1r5k+B3i9cAlWIE4royTOwDxe4JsnfWoLod0PcF
U0NNzR1qYicC3Qhmbe2/i9t1FAU/9QeiHkF2f+G7cMCSy1EKbdX807TiZdFHD7bm
CAjUUTeWNEAVziXnrG6yhsBoPuXNaylOALC6U5cFAP1riR3RMJjISmHjURuOAlFI
W8tlKq77I5a4L93IW+2/elDPTjhUYsQnSEtJPWG/BizSVihHSiHh2lAN0JLZChWk
6J2e2FaZYC28Swu/V+GLXLg0Ai8GkSZNYTqOf8HqnkB7X3G7+OMnLPW+0I5GPOh+
9aX9WXhGAI6gxJf6UjcD5axHV+mdfgQnxBsJY4HxqQKBgQDfUbtYzfLBxnnxk0H7
N+lhdiANA/YXiR4OljziTSTjnnSDdabktr3ubIofpEwjvAqKIdn5ruyqdT/9GOZt
/7sai0aqyIzGlQiLhkxHvHBIxGajRBbPq2BhLqQYBeL0Xy4oMcD5NjGoUuhcck0b
bw6h935CIJYzJQtx+K/U4I2DwwKBgQC3timBQPbq+wJx4yuyf+VOy4r9qW0/4DUM
pw3qo1tqOk1hKN6pZazov0qfrGEKIOG4Ws0rLCKgwKwocdfFfzPwTgg8srl5r5XM
k5r97mHNYqSlboAE2YIM+CziUmVqklkMqQ4Hs38jk3tswt6yY+syrfZbp/Rhh/XK
pVv1itr89wKBgQDBi1VihsNw+7IuE2Eo9/E1faoTfa5oAXdiTwUfYJqrB2aVlH77
VAHSRJGFEODIS62av/Hpepg0t3+ovE7hYLTpMXIii8OuS/Xm7pLnzUJHXqhRsa5P
d4kFUOX4yAlFn8QiI9TKaBSrfIdTr+Bx+VNmPlhXuWRTmTSNJ2pEhgU//wKBgAt7
Vxy88rG8/mofyJtfYvWJwyYXcLyNRsODrVr82rnI6w0ngMMVl7j0O7W/EFGRvInJ
IwmPuJpTcG8WrmWpjZV3SwyAHxd74eDnWMiGHZa4k5HDVjz3Wyl0WVnLzIrcmrQv
3LCeh1Ox5AToKQL9O7XvKXaRCLUPykzgCN9PzmABAoGAUW/AIrYerL0oU0KBRZ5B
6NX+5++R6jugN/spvVs4OLwPM5a6ud6Bq/+BA3aT7NWdfypVgybotEytsb/y1oe2
XdFhno110rcMp6WoQHM4dCWw3cmRNbMv2aleY2FrTZlpxEXeA47iF5/if1VHldmR
Y7LzJJ6LCjfUFy8dMINZC7M=
-----END PRIVATE KEY-----
"
        .to_string();

        // Kafka sink: validated, lazily connected, listed with its kind.
        let (status, created) = server
            .post_auth(
                "/api/v1/connectors",
                json!({"id": "kafka-sink-1",
                       "kind": "kafka",
                       "config": {"bootstrap_servers": "127.0.0.1:9092",
                                  "topic_template": "out-${topic}",
                                  "partition_key_field": "device_id",
                                  "partitions": 4,
                                  "client_id": "indra",
                                  "acks": "all"}}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["id"], json!("kafka-sink-1"));
        assert_eq!(created["kind"], json!("kafka"));

        // RabbitMQ sink: slash translation config accepted.
        let (status, created) = server
            .post_auth(
                "/api/v1/connectors",
                json!({"id": "rabbit-sink-1",
                       "kind": "rabbitmq",
                       "config": {"endpoint": "amqp://127.0.0.1:5672/%2f",
                                  "exchange": "telemetry",
                                  "routing_key_template": "sensor.${topic}",
                                  "delivery_mode": 2}}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("rabbitmq"));

        // Logger sink needs no config at all.
        let (status, created) = server
            .post_auth(
                "/api/v1/connectors",
                json!({"id": "diag", "kind": "logger", "config": {}}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("console"));

        // Postgres sink: validated without touching any database.
        let (status, created) = server
            .post_auth(
                "/api/v1/connectors",
                json!({"id": "pg-sink-1",
                       "kind": "postgres",
                       "config": {"connection_url": "postgresql://u:p@127.0.0.1:5432/db",
                                  "sql_template": "INSERT INTO t (topic, qos, payload) VALUES ($1, $2, $3)",
                                  "pool_size": 2,
                                  "batch_size": 50,
                                  "batch_timeout_ms": 25}}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("postgres"));

        // Redis sink: XADD stream config accepted (command is flat).
        let (status, created) = server
            .post_auth(
                "/api/v1/connectors",
                json!({"id": "redis-sink-1",
                       "kind": "redis",
                       "config": {"endpoint": "redis://127.0.0.1:6379",
                                  "command": "xadd",
                                  "stream_template": "events",
                                  "maxlen": 1000}}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("redis"));

        // MySQL sink: validated without touching any database.
        let (status, created) = server
            .post_auth(
                "/api/v1/connectors",
                json!({"id": "mysql-sink-1",
                       "kind": "mysql",
                       "config": {"connection_url": "mysql://u:p@127.0.0.1:3306/db",
                                  "sql_template": "INSERT INTO t (topic, qos, payload) VALUES (?, ?, ?)",
                                  "pool_size": 2,
                                  "batch_size": 50,
                                  "batch_timeout_ms": 25}}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("mysql"));

        // ClickHouse sink: validated without touching any server.
        let (status, created) = server
            .post_auth(
                "/api/v1/connectors",
                json!({"id": "ch-sink-1",
                       "kind": "clickhouse",
                       "config": {"endpoint": "http://127.0.0.1:8123",
                                  "database": "indra",
                                  "table": "mqtt_events",
                                  "format": "JSONEachRow",
                                  "batch_size": 100,
                                  "batch_timeout_ms": 50}}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("clickhouse"));

        // InfluxDB sink: validated without touching any server.
        let (status, created) = server
            .post_auth(
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
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("influxdb"));

        // S3 sink: validated without touching any object store.
        let (status, created) = server
            .post_auth(
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
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("s3"));

        // Elasticsearch sink: validated without touching any cluster.
        let (status, created) = server
            .post_auth(
                "/api/v1/connectors",
                json!({"id": "es-sink-1",
                       "kind": "elasticsearch",
                       "config": {"endpoint": "http://127.0.0.1:9200",
                                  "index_template": "iot-telemetry-${YYYY.MM.dd}",
                                  "auth": {"type": "none"},
                                  "batch_size": 100,
                                  "batch_timeout_ms": 50,
                                  "max_retries": 3}}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("elasticsearch"));

        // TimescaleDB sink: validated without touching any database.
        let (status, created) = server
            .post_auth(
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
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("timescaledb"));

        // Webhook sink: validated without sending any request.
        let (status, created) = server
            .post_auth(
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
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("webhook"));

        // MQTT bridge sink: validated without opening any socket.
        let (status, created) = server
            .post_auth(
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
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("mqtt_bridge"));

        // Disk log sink: validated against an isolated temp directory.
        let disk_dir = std::env::temp_dir().join(format!("indra-test-disk-{}", std::process::id()));
        let (status, created) = server
            .post_auth(
                "/api/v1/connectors",
                json!({"id": "disk-1",
                       "kind": "disk_log",
                       "config": {"directory": disk_dir.to_string_lossy(),
                                  "filename_prefix": "audit",
                                  "filename_extension": "log",
                                  "format": "ndjson",
                                  "compression": "none",
                                  "sync_mode": {"mode": "osdefault"}}}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("disk_log"));
        std::fs::remove_dir_all(&disk_dir).ok();

        // Sparkplug B sink: enterprise tier validated without any broker.
        let (status, created) = server
            .post_auth(
                "/api/v1/connectors",
                json!({"id": "spb-1",
                       "kind": "sparkplug_b",
                       "config": {"topic_prefix": "spBv1.0/plant1",
                                  "tier": "enterprise",
                                  "batch_size": 50,
                                  "linger_ms": 25}}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("sparkplug_b"));

        // Kinesis sink: validated without touching AWS.
        let (status, created) = server
            .post_auth(
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
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("kinesis"));

        // GCP Pub/Sub sink: validated without touching Google.
        let (status, created) = server
            .post_auth(
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
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("gcp_pubsub"));

        // Azure Event Hubs sink: validated without touching Azure.
        let (status, created) = server
            .post_auth(
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
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("azure_eventhubs"));

        // Pulsar sink: validated without opening any socket.
        let (status, created) = server
            .post_auth(
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
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("pulsar"));

        // MongoDB sink: validated without opening any socket.
        let (status, created) = server
            .post_auth(
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
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("mongodb"));

        // MSSQL sink: validated without opening any socket.
        let (status, created) = server
            .post_auth(
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
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("mssql"));

        // Cassandra sink: validated without opening any socket.
        let (status, created) = server
            .post_auth(
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
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("cassandra"));

        // Couchbase sink: validated without opening any socket.
        let (status, created) = server
            .post_auth(
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
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("couchbase"));

        // TDengine sink: validated without touching any server.
        let (status, created) = server
            .post_auth(
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
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("tdengine"));

        // IoTDB sink: validated without touching any server.
        let (status, created) = server
            .post_auth(
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
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("iotdb"));

        // Timestream sink: validated without touching AWS.
        let (status, created) = server
            .post_auth(
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
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("timestream"));

        // DynamoDB sink: validated without touching AWS.
        let (status, created) = server
            .post_auth(
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
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("dynamodb"));

        // Snowflake sink: key-pair validated without touching Snowflake.
        // Test-only RSA key (openssl-generated, never deployed).
        const SNOWFLAKE_TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCwQ2w63oB3FtHg\n7xysQK8MuX9S0WkbAVlxWpLHDNIdRVxA9Ra2gFFpKy8jX45UMSow6Yny7IvYWFzZ\nL4y9yoFiqu+LxhlJHIO6JO8+ZmeBoNwuDiIzgesbZwjyQiQ2M7p/4c18a2ffGPWF\nBETT7uVwVKJ3hTp97RN7Mc1/eFMimuT/TC11I+sFCZUHgrbhEG3L5Gg3RJ2MKbcX\nGEIxjFDJdLJ9RK0BopD6lxR1a4zeYr+iF/m3+JeJPAaS15yMD+sB1g5C7XZ1OIsB\nNBBnHWHpNhYO2IrCc9lZeSSzSkbRC6k1oqvTurFRzHWZqBKQGYnH8BftubIPSTBg\nU/BM4rR3AgMBAAECggEAHSRwmwUZoVb1CWcPSw2Aw65RtkwoQA5Hjv3GIcHlZXCH\n0beT80Wg8C3zI7qTSik8zAx4weDJOFJXu5LohqKaJMmVRHtSx+s+fkLICX2d5GlH\nrhepIPH8gLHW4VL9MLb5wVYAhu8tI845Ha54gL/RUHK1z+QHqTVO0MIJs2cd+6zx\nKsAtnqEQJMFpl1D0y0uutuboK4soHJMyRyrHBNWdgfzmTrCsngzu2zVM4aZh/gQY\nHcQgJ1rK6Wnen/GGPrNluwWU+bfLdlWO2qiXXwGLfhyx2H6cuROGdoU607BFJNpM\nkAudvEuLa0fOi1ym6lJ5pcJ6pSLkbeveW6+thkO2fQKBgQDXc2GiKx15vQHmdDmZ\nUJEiPJ+hSry5fjaowzrfgqJHyeNfUjnM/E9WlNn2AuxKDWGc3UNEr6jB9V7leKev\nQaPB2LAgXt0YVHmyim51/gTDguE9TOTGWqL4npZG9Nqh8xMxWt08ULvknkOQQOso\nzCoZQYlG4BHegAG7n0/5IN7HdQKBgQDRb/VbJ9iE0wtY/A3e3eWPbGfTF7AZREUu\n/mt94tFEWDDvedX1EPi4DJgPMqQ4eHnBZb3+G7jPcRdm6/KQzR5QiRMHSylfIQRH\nLqqfHBzZDDSZINLW1FMReC9xGfkRoG0Tlt2iQzXOy90+uE/9k5BGSbQNakfVDXJs\n3JAHDMy6uwKBgQCaazxC+xv5MRq3jf3qgPBE1aaj9+kkGe4bLzJ3GC4vveeVXl3H\nKd/DcpR12sp4mPapc3zPMgeGXNNTLRMiba1tNl2mFdfppEJFUSqyrwnDB39gbEhc\nUoIUJ7YVzVEWWh4bdcCzhjnlNfm+3oitiQdzaqF1hwvHqX+Udi7fpEuIMQKBgQC5\nu0bkQu7Rw/MRQ93tIe19ho6AdkZV8eREq52Z8vbQXEFxbiOfBCD93zVObQOTjMu1\nBcw6uEzpsgol3OKtJSpYE2eLlU0oLriDg9AN8DlpBljy31f66iqMmH/CFl16E0II\nGEeOqXnjXYlkIMHXR/CvVJdXOkRfnWA3SFZ12hUJFwKBgD8JlGTyrVfNsNMOaTDV\nNopoYnUQ6ljFmJi6TGmnkliCRXPuqBl+2hVxiKeWI2MprJ5Ya8qLbL6M56uCwAD2\nqEhvjEuatma5rJyE5NULOjAXA5tLw9qM1M9j1FNOaXnFC9/Yii2a49R8zu05wRB2\nH+dMMSDXQ4EHHYcKIFJjDbxn\n-----END PRIVATE KEY-----\n";
        let (status, created) = server
            .post_auth(
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
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("snowflake"));

        // Databricks sink: validated without touching any workspace.
        let (status, created) = server
            .post_auth(
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
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("databricks"));

        // Doris sink: validated without touching any cluster.
        let (status, created) = server
            .post_auth(
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
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("doris"));

        // BigQuery sink: validated without touching Google.
        let (status, created) = server
            .post_auth(
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
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("bigquery"));

        // Redshift sink: validated without touching AWS.
        let (status, created) = server
            .post_auth(
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
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("redshift"));

        // OCI Streaming sink: Cavage-signed, validated without touching OCI.
        let (status, created) = server
            .post_auth(
                "/api/v1/connectors",
                json!({"id": "oci-1",
                       "kind": "oci_streaming",
                       "config": {"endpoint": "https://cell-1.streaming.us-east-1.oci.oraclecloud.com",
                                  "stream_pool_id": "ocid1.streampool.oc1..testpool",
                                  "stream_id": "ocid1.stream.oc1..teststream",
                                  "tenancy_ocid": "ocid1.tenancy.oc1..test",
                                  "user_ocid": "ocid1.user.oc1..test",
                                  "fingerprint": "20:3b:97:13:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55",
                                  "private_key_pem": test_pem.clone(),
                                  "partition_key_template": "${client_id}",
                                  "batch_size": 500,
                                  "batch_bytes": 65536,
                                  "linger_ms": 100,
                                  "max_retries": 5,
                                  "initial_backoff_ms": 10,
                                  "max_backoff_ms": 100}}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("oci_streaming"));

        // AWS IoT Core sink: mTLS-only build, validated without opening any socket.
        // SigV4/WebSocket is intentionally not built (no licence-compliant
        // WebSocket client); SigV4 configs are rejected at registration.
        let (status, created) = server
            .post_auth(
                "/api/v1/connectors",
                json!({"id": "aws-iot-1",
                       "kind": "aws_iot",
                       "config": {"endpoint": "abc-ats.iot.us-east-1.amazonaws.com",
                                  "region": "us-east-1",
                                  "client_id": "indra-bridge-1",
                                  "auth": {"type": "mtls",
                                            "ca_cert_pem": include_str!("../../broker-connectors/testdata/ca-cert.pem"),
                                            "client_cert_pem": include_str!("../../broker-connectors/testdata/client-cert.pem"),
                                            "client_key_pem": include_str!("../../broker-connectors/testdata/client-key.pem")},
                                  "topic_mappings": [{"local_topic": "sensors/+",
                                                      "remote_topic": "indra/up",
                                                      "direction": "localtoremote"}],
                                  "batch_size": 200,
                                  "linger_ms": 50,
                                  "max_retries": 5}}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("aws_iot"));

        // Azure IoT Hub sink: validated without opening any socket.
        let (status, created) = server
            .post_auth(
                "/api/v1/connectors",
                json!({"id": "azure-iot-1",
                       "kind": "azure_iot",
                       "config": {"iot_hub_name": "e2e-hub",
                                  "device_id": "e2e-device",
                                  "module_id": null,
                                  "auth": {"type": "sharedaccesskey",
                                            "key": "c2VjcmV0",
                                            "key_name": "device"},
                                  "api_version": "2021-04-12",
                                  "direct_methods_enabled": false,
                                  "twin_sync_enabled": false,
                                  "batch_size": 200,
                                  "linger_ms": 50,
                                  "max_retries": 5}}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("azure_iot"));

        // GCP IoT Core sink: validated without opening any socket.
        let (status, created) = server
            .post_auth(
                "/api/v1/connectors",
                json!({"id": "gcp-iot-1",
                       "kind": "gcp_iot",
                       "config": {"project_id": "e2e-project",
                                  "cloud_region": "us-central1",
                                  "registry_id": "e2e-registry",
                                  "device_id": "e2e-device",
                                  "private_key_pem": test_pem,
                                  "algorithm": "RS256",
                                  "token_lifetime_secs": 3600,
                                  "endpoint": "mqtt.googleapis.com:8883",
                                  "batch_size": 200,
                                  "linger_ms": 50,
                                  "max_retries": 5}}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("gcp_iot"));

        // OPC-UA sink: validated without opening any socket.
        let (status, created) = server
            .post_auth(
                "/api/v1/connectors",
                json!({"id": "opcua-1",
                       "kind": "opc_ua",
                       "config": {"endpoint_url": "opc.tcp://127.0.0.1:4840",
                                  "security_policy": "None",
                                  "security_mode": "none",
                                  "auth": {"type": "anonymous"},
                                  "node_subscriptions": [{"node_id": "ns=2;s=Temperature",
                                                          "sampling_interval_ms": 1000,
                                                          "publish_topic_template": "opcua/temperature"}],
                                  "batch_size": 200,
                                  "linger_ms": 50}}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("opc_ua"));

        // Azure Blob sink: validated without touching Azure.
        let (status, created) = server
            .post_auth(
                "/api/v1/connectors",
                json!({"id": "azblob-1",
                       "kind": "azure_blob",
                       "config": {"account_name": "mydeviceblobs",
                                  "container_name": "telemetry",
                                  "auth": {"type": "sharedkey",
                                            "account_key": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="},
                                  "blob_path_template": "telemetry/year=${date.year}/${batch_id}.json",
                                  "compression": "none",
                                  "max_records_per_blob": 10000,
                                  "max_bytes_per_blob": 10485760,
                                  "flush_interval_secs": 60}}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("azure_blob"));

        // Tablestore sink: validated without touching Alibaba Cloud.
        let (status, created) = server
            .post_auth(
                "/api/v1/connectors",
                json!({"id": "ots-1",
                       "kind": "tablestore",
                       "config": {"endpoint": "https://test-instance.cn-hangzhou.ots.aliyuncs.com",
                                  "instance_name": "test-instance",
                                  "table_name": "telemetry",
                                  "access_key_id": "test-key-id",
                                  "access_key_secret": "test-secret",
                                  "primary_keys": [{"name": "device_id",
                                                    "source": "${client_id}",
                                                    "data_type": "string"}],
                                  "attribute_columns": [{"name": "temperature",
                                                         "source": "${payload.temperature}",
                                                         "data_type": "double"}],
                                  "batch_size": 200}}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("tablestore"));

        // S3 Tables sink: validated without touching AWS.
        let (status, created) = server
            .post_auth(
                "/api/v1/connectors",
                json!({"id": "s3t-1",
                       "kind": "s3_tables",
                       "config": {"table_bucket_arn": "arn:aws:s3tables:us-east-1:123456789012:bucket/telemetry-bucket",
                                  "namespace": "production_iot",
                                  "table_name": "device_events",
                                  "region": "us-east-1",
                                  "access_key_id": "AKID",
                                  "secret_access_key": "secret",
                                  "partition_spec": [{"source_name": "date", "transform": "day"}],
                                  "target_format": "ndjsoncompressed",
                                  "batch_size": 1000}}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("s3_tables"));

        // Confluent Cloud sink: validated without opening any socket.
        let (status, created) = server
            .post_auth(
                "/api/v1/connectors",
                json!({"id": "confluent-1",
                       "kind": "confluent",
                       "config": {"bootstrap_servers": ["pkc-test.us-east-1.aws.confluent.cloud:9092"],
                                  "api_key": "confluent-key",
                                  "api_secret": "confluent-secret",
                                  "auth_mechanism": "plain",
                                  "topic_template": "telemetry-${topic_segment_1}",
                                  "partition_key_template": "${client_id}",
                                  "partitions": 12,
                                  "batch_size": 500}}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("confluent"));

        // RocketMQ sink: validated without opening any socket.
        let (status, created) = server
            .post_auth(
                "/api/v1/connectors",
                json!({"id": "rmq-1",
                       "kind": "rocketmq",
                       "config": {"endpoints": ["127.0.0.1:8081"],
                                  "topic": "rocket-telemetry",
                                  "tag_template": "${topic_segment_2}",
                                  "access_key": "rocket-key",
                                  "secret_key": "rocket-secret",
                                  "batch_size": 128}}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("rocketmq"));

        // Oracle sink: validated without touching ORDS.
        let (status, created) = server
            .post_auth(
                "/api/v1/connectors",
                json!({"id": "oracle-1",
                       "kind": "oracle",
                       "config": {"url": "https://oracle-host:8080/ords/admin/_/sql",
                                  "schema": "ADMIN",
                                  "table": "telemetry",
                                  "username": "admin",
                                  "password": "secret",
                                  "key_columns": ["device_id"],
                                  "batch_size": 500}}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("oracle"));

        // CockroachDB sink: validated without touching CockroachDB.
        let (status, created) = server
            .post_auth(
                "/api/v1/connectors",
                json!({"id": "cockroach-1",
                       "kind": "cockroachdb",
                       "config": {"connection_string": "postgresql://root@127.0.0.1:26257/defaultdb",
                                  "table": "telemetry",
                                  "upsert_conflict_columns": ["device_id"],
                                  "batch_size": 500,
                                  "max_retry_attempts": 5}}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("cockroachdb"));

        // AlloyDB sink: validated without touching AlloyDB.
        let (status, created) = server
            .post_auth(
                "/api/v1/connectors",
                json!({"id": "alloydb-1",
                       "kind": "alloydb",
                       "config": {"host": "10.0.0.1",
                                  "port": 5432,
                                  "database": "telemetry",
                                  "username": "postgres",
                                  "auth": {"type": "password", "password": "secret"},
                                  "table": "readings",
                                  "batch_size": 1000}}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("alloydb"));

        // OpenTSDB sink: validated without touching OpenTSDB.
        let (status, created) = server
            .post_auth(
                "/api/v1/connectors",
                json!({"id": "opentsdb-1",
                       "kind": "opentsdb",
                       "config": {"endpoint": "http://127.0.0.1:4242",
                                  "protocol": "http",
                                  "metric_template": "sensor.temp",
                                  "value_field": "value",
                                  "summary": true,
                                  "compression": "none",
                                  "batch_size": 1000}}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("opentsdb"));

        // GreptimeDB sink: validated without touching GreptimeDB.
        let (status, created) = server
            .post_auth(
                "/api/v1/connectors",
                json!({"id": "greptimedb-1",
                       "kind": "greptimedb",
                       "config": {"endpoint": "http://127.0.0.1:4000",
                                  "database": "public",
                                  "format": "sql_insert",
                                  "table_template": "sensor_readings",
                                  "timestamp_precision": "millisecond",
                                  "batch_size": 1000}}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("greptimedb"));

        // Datalayers sink: validated without touching Datalayers.
        let (status, created) = server
            .post_auth(
                "/api/v1/connectors",
                json!({"id": "datalayers-1",
                       "kind": "datalayers",
                       "config": {"endpoint": "http://127.0.0.1:8360",
                                  "database": "telemetry",
                                  "table": "metrics",
                                  "auth_token": "secret-token",
                                  "batch_size": 500}}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created["kind"], json!("datalayers"));

        let (status, body) = server.get_auth("/api/v1/connectors", &token).await;
        assert_eq!(status, 200);
        assert_eq!(
            body,
            json!([{"id": "alloydb-1", "kind": "alloydb", "tier": "enterprise"},
                    {"id": "aws-iot-1", "kind": "aws_iot", "tier": "enterprise"},
                    {"id": "azblob-1", "kind": "azure_blob", "tier": "enterprise"},
                    {"id": "azure-1", "kind": "azure_eventhubs", "tier": "enterprise"},
                    {"id": "azure-iot-1", "kind": "azure_iot", "tier": "enterprise"},
                   {"id": "bigquery-1", "kind": "bigquery", "tier": "enterprise"},
                   {"id": "bridge-1", "kind": "mqtt_bridge", "tier": "community"},
                   {"id": "cassandra-1", "kind": "cassandra", "tier": "enterprise"},
                    {"id": "ch-sink-1", "kind": "clickhouse", "tier": "community"},
                    {"id": "cockroach-1", "kind": "cockroachdb", "tier": "enterprise"},
                    {"id": "confluent-1", "kind": "confluent", "tier": "enterprise"},
                   {"id": "couchbase-1", "kind": "couchbase", "tier": "enterprise"},
                   {"id": "databricks-1", "kind": "databricks", "tier": "enterprise"},
                   {"id": "datalayers-1", "kind": "datalayers", "tier": "enterprise"},
                   {"id": "diag", "kind": "console", "tier": "community"},
                   {"id": "disk-1", "kind": "disk_log", "tier": "community"},
                   {"id": "doris-1", "kind": "doris", "tier": "enterprise"},
                   {"id": "dynamodb-1", "kind": "dynamodb", "tier": "enterprise"},
                   {"id": "es-sink-1", "kind": "elasticsearch", "tier": "community"},
                    {"id": "gcp-1", "kind": "gcp_pubsub", "tier": "enterprise"},
                    {"id": "gcp-iot-1", "kind": "gcp_iot", "tier": "enterprise"},
                    {"id": "greptimedb-1", "kind": "greptimedb", "tier": "community"},
                   {"id": "hook-1", "kind": "webhook", "tier": "community"},
                   {"id": "influx-sink-1", "kind": "influxdb", "tier": "community"},
                   {"id": "iotdb-1", "kind": "iotdb", "tier": "enterprise"},
                   {"id": "kafka-sink-1", "kind": "kafka", "tier": "community"},
                   {"id": "kinesis-1", "kind": "kinesis", "tier": "enterprise"},
                   {"id": "mongo-1", "kind": "mongodb", "tier": "enterprise"},
                   {"id": "mssql-1", "kind": "mssql", "tier": "enterprise"},
                    {"id": "mysql-sink-1", "kind": "mysql", "tier": "community"},
                    {"id": "oci-1", "kind": "oci_streaming", "tier": "enterprise"},
                     {"id": "opcua-1", "kind": "opc_ua", "tier": "enterprise"},
                     {"id": "opentsdb-1", "kind": "opentsdb", "tier": "community"},
                     {"id": "oracle-1", "kind": "oracle", "tier": "enterprise"},
                     {"id": "ots-1", "kind": "tablestore", "tier": "enterprise"},
                    {"id": "pg-sink-1", "kind": "postgres", "tier": "community"},
                   {"id": "pulsar-1", "kind": "pulsar", "tier": "enterprise"},
                   {"id": "rabbit-sink-1", "kind": "rabbitmq", "tier": "community"},
                   {"id": "redis-sink-1", "kind": "redis", "tier": "community"},
                    {"id": "redshift-1", "kind": "redshift", "tier": "enterprise"},
                    {"id": "rmq-1", "kind": "rocketmq", "tier": "enterprise"},
                    {"id": "s3-sink-1", "kind": "s3", "tier": "community"},
                    {"id": "s3t-1", "kind": "s3_tables", "tier": "enterprise"},
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
            json!({"id": "bad-azblob", "kind": "azure_blob",
                   "config": {"account_name": "AB",
                              "container_name": "telemetry",
                              "auth": {"type": "sharedkey",
                                        "account_key": "a2V5"},
                              "blob_path_template": "t/${batch_id}.json"}}),
            json!({"id": "bad-ots", "kind": "tablestore",
                   "config": {"endpoint": "https://i.cn-hangzhou.ots.aliyuncs.com",
                              "instance_name": "i",
                              "table_name": "t",
                              "access_key_id": "k",
                              "access_key_secret": "s",
                              "primary_keys": []}}),
            json!({"id": "bad-s3t", "kind": "s3_tables",
                   "config": {"table_bucket_arn": "arn:aws:s3:::plain",
                              "namespace": "ns",
                              "table_name": "t",
                              "region": "us-east-1",
                              "access_key_id": "AKID",
                              "secret_access_key": "secret"}}),
            json!({"id": "bad-confluent", "kind": "confluent",
                   "config": {"bootstrap_servers": [],
                              "api_key": "k",
                              "api_secret": "s",
                              "topic_template": "t"}}),
            json!({"id": "bad-rmq", "kind": "rocketmq",
                   "config": {"endpoints": ["127.0.0.1:8081"],
                              "topic": ""}}),
            json!({"id": "bad-ora", "kind": "oracle",
                   "config": {"url": "https://oracle-host:8080/ords/admin/_/sql",
                              "schema": "",
                              "table": "telemetry",
                              "username": "admin",
                              "password": "secret",
                              "key_columns": ["device_id"]}}),
            json!({"id": "bad-crdb", "kind": "cockroachdb",
                   "config": {"connection_string": "postgresql://root@127.0.0.1:26257/defaultdb",
                              "table": "",
                              "upsert_conflict_columns": ["device_id"]}}),
            json!({"id": "bad-alloy", "kind": "alloydb",
                   "config": {"host": "",
                              "database": "telemetry",
                              "username": "postgres",
                              "table": "readings"}}),
            json!({"id": "bad-opentsdb", "kind": "opentsdb",
                   "config": {"endpoint": "",
                              "metric_template": "sensor.temp",
                              "value_field": "value"}}),
            json!({"id": "bad-greptimedb", "kind": "greptimedb",
                   "config": {"endpoint": "http://127.0.0.1:4000",
                              "database": "",
                              "table_template": "sensor_readings"}}),
            json!({"id": "bad-datalayers", "kind": "datalayers",
                   "config": {"endpoint": "",
                              "database": "telemetry",
                              "table": "metrics"}}),
        ] {
            let (status, _) = server
                .post_auth("/api/v1/connectors", payload, &token)
                .await;
            assert_eq!(status, 400);
        }
        let (status, body) = server.get_auth("/api/v1/connectors", &token).await;
        assert_eq!(status, 200);
        assert_eq!(body.as_array().expect("list").len(), 48);
    }

    #[tokio::test]
    async fn s101_no_default_credentials_rejects_and_accepts() {
        let _connector_guard = CONNECTOR_TEST_SERIAL.lock().await;
        let (server, state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        // Runtime-generated test RSA key (never stored, never deployed).
        // Test-only fixture; no shipped path can reach it (`#[cfg(test)]` only).
        // `rsa` 0.9 expects `rand_core` 0.6 while the workspace uses `rand`
        // 0.10: bridge the two with a thin adapter over the workspace RNG
        // (a CSPRNG, so marking it `CryptoRng` is sound).
        struct CompatRng(rand::rngs::ThreadRng);
        impl rsa::rand_core::RngCore for CompatRng {
            fn next_u32(&mut self) -> u32 {
                rand::Rng::next_u32(&mut self.0)
            }
            fn next_u64(&mut self) -> u64 {
                rand::Rng::next_u64(&mut self.0)
            }
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                rand::Rng::fill_bytes(&mut self.0, dest)
            }
            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
                rand::Rng::fill_bytes(&mut self.0, dest);
                Ok(())
            }
        }
        impl rsa::rand_core::CryptoRng for CompatRng {}
        let mut rng = CompatRng(rand::rng());
        let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("generate test RSA key");
        let test_pem =
            rsa::pkcs8::EncodePrivateKey::to_pkcs8_pem(&private_key, rsa::pkcs8::LineEnding::LF)
                .expect("encode test key")
                .to_string();

        // gcp_iot without a key is 400 naming the field, and registers nothing.
        let (status, body) = server
            .post_auth(
                "/api/v5/connectors",
                json!({"name": "s101-gcp-no-key", "type": "gcp_iot",
                       "project_id": "e2e-project", "cloud_region": "us-central1",
                       "registry_id": "e2e-registry", "device_id": "e2e-device"}),
                &token,
            )
            .await;
        assert_eq!(status, 400);
        assert!(
            body["message"]
                .as_str()
                .unwrap_or("")
                .contains("private_key_pem"),
            "missing key must be named, got: {body}"
        );
        assert!(state.engine.connectors().get("s101-gcp-no-key").is_none());

        // gcp_iot with a key is 201 and live.
        let (status, _) = server
            .post_auth(
                "/api/v5/connectors",
                json!({"name": "s101-gcp-1", "type": "gcp_iot",
                       "project_id": "e2e-project", "cloud_region": "us-central1",
                       "registry_id": "e2e-registry", "device_id": "e2e-device",
                       "private_key_pem": test_pem}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert!(state.engine.connectors().get("s101-gcp-1").is_some());

        // snowflake without a key is 400 naming the field.
        let (status, body) = server
            .post_auth(
                "/api/v5/connectors",
                json!({"name": "s101-snow-no-key", "type": "snowflake",
                       "account": "xy12345.us-east-1", "user": "indra_loader",
                       "database": "IOT", "schema": "PUBLIC", "table": "TELEMETRY"}),
                &token,
            )
            .await;
        assert_eq!(status, 400);
        assert!(
            body["message"]
                .as_str()
                .unwrap_or("")
                .contains("private_key_pem"),
            "missing key must be named, got: {body}"
        );
        assert!(state.engine.connectors().get("s101-snow-no-key").is_none());

        // snowflake with a key is 201 and live.
        let (status, _) = server
            .post_auth(
                "/api/v5/connectors",
                json!({"name": "s101-snow-1", "type": "snowflake",
                       "account": "xy12345.us-east-1", "user": "indra_loader",
                       "database": "IOT", "schema": "PUBLIC", "table": "TELEMETRY",
                       "private_key_pem": test_pem}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert!(state.engine.connectors().get("s101-snow-1").is_some());

        // oci without a key is 400 naming the field.
        let (status, body) = server
            .post_auth(
                "/api/v5/connectors",
                json!({"name": "s101-oci-no-key", "type": "oci_streaming",
                       "stream_pool_id": "ocid1.streampool.oc1..testpool",
                       "stream_id": "ocid1.stream.oc1..teststream",
                       "tenancy_ocid": "ocid1.tenancy.oc1..test",
                       "user_ocid": "ocid1.user.oc1..test",
                       "fingerprint": "20:3b:97:13:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55"}),
                &token,
            )
            .await;
        assert_eq!(status, 400);
        assert!(
            body["message"]
                .as_str()
                .unwrap_or("")
                .contains("private_key_pem"),
            "missing key must be named, got: {body}"
        );
        assert!(state.engine.connectors().get("s101-oci-no-key").is_none());

        // oci with a key is 201 and live (dummy loopback endpoint so the
        // reachability probe passes without touching any cloud).
        let oci_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind dummy");
        let oci_endpoint = format!(
            "http://127.0.0.1:{}",
            oci_listener.local_addr().expect("addr").port()
        );
        let (status, _) = server
            .post_auth(
                "/api/v5/connectors",
                json!({"name": "s101-oci-1", "type": "oci_streaming",
                       "stream_pool_id": "ocid1.streampool.oc1..testpool",
                       "stream_id": "ocid1.stream.oc1..teststream",
                       "tenancy_ocid": "ocid1.tenancy.oc1..test",
                       "user_ocid": "ocid1.user.oc1..test",
                       "fingerprint": "20:3b:97:13:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55",
                       "private_key_pem": test_pem,
                       "endpoint": oci_endpoint}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert!(state.engine.connectors().get("s101-oci-1").is_some());
        drop(oci_listener);

        // databricks without a token is 400 naming the field.
        let (status, body) = server
            .post_auth(
                "/api/v5/connectors",
                json!({"name": "s101-db-no-token", "type": "databricks",
                       "host": "my-workspace.cloud.databricks.com",
                       "catalog": "main", "schema": "default", "table": "events"}),
                &token,
            )
            .await;
        assert_eq!(status, 400);
        assert!(
            body["message"].as_str().unwrap_or("").contains("token"),
            "missing token must be named, got: {body}"
        );
        assert!(state.engine.connectors().get("s101-db-no-token").is_none());

        // databricks with a token is 201 and live (dummy loopback target so
        // the reachability probe passes without touching any workspace).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind dummy");
        let port = listener.local_addr().expect("addr").port();
        let host = format!("127.0.0.1:{port}");
        let (status, _) = server
            .post_auth(
                "/api/v5/connectors",
                json!({"name": "s101-db-1", "type": "databricks",
                       "host": host, "token": "dapi-test-token",
                       "catalog": "main", "schema": "default", "table": "events"}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert!(state.engine.connectors().get("s101-db-1").is_some());
        drop(listener);

        // tablestore without secrets is 400 naming the field.
        let (status, body) = server
            .post_auth(
                "/api/v5/connectors",
                json!({"name": "s101-ots-no-key", "type": "tablestore",
                       "instance_name": "test-instance-1", "table_name": "sensor_data",
                       "access_key_id": "test-ak-1"}),
                &token,
            )
            .await;
        assert_eq!(status, 400);
        assert!(
            body["message"]
                .as_str()
                .unwrap_or("")
                .contains("access_key_secret"),
            "missing secret must be named, got: {body}"
        );
        assert!(state.engine.connectors().get("s101-ots-no-key").is_none());

        // tablestore with secrets is 201 and live (dummy loopback endpoint
        // so the reachability probe passes without touching any cloud).
        let ots_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind dummy");
        let ots_endpoint = format!(
            "http://127.0.0.1:{}",
            ots_listener.local_addr().expect("addr").port()
        );
        let (status, _) = server
            .post_auth(
                "/api/v5/connectors",
                json!({"name": "s101-ots-1", "type": "tablestore",
                       "instance_name": "test-instance-1", "table_name": "sensor_data",
                       "access_key_id": "test-ak-1", "access_key_secret": "test-sk-1",
                       "endpoint": ots_endpoint}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert!(state.engine.connectors().get("s101-ots-1").is_some());
        drop(ots_listener);

        // confluent without credentials is 400 naming the field.
        let (status, body) = server
            .post_auth(
                "/api/v5/connectors",
                json!({"name": "s101-conf-no-key", "type": "confluent",
                       "bootstrap_servers": "127.0.0.1:9092",
                       "topic": "telemetry-events"}),
                &token,
            )
            .await;
        assert_eq!(status, 400);
        assert!(
            body["message"].as_str().unwrap_or("").contains("api_key"),
            "missing key must be named, got: {body}"
        );
        assert!(state.engine.connectors().get("s101-conf-no-key").is_none());

        // confluent with credentials is 201 and live.
        let (status, _) = server
            .post_auth(
                "/api/v5/connectors",
                json!({"name": "s101-conf-1", "type": "confluent",
                       "bootstrap_servers": "127.0.0.1:9092",
                       "topic": "telemetry-events",
                       "api_key": "s101-cc-key",
                       "api_secret": "s101-cc-secret"}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert!(state.engine.connectors().get("s101-conf-1").is_some());

        // azure_eventhubs without a key is 400 naming the field.
        let (status, body) = server
            .post_auth(
                "/api/v5/connectors",
                json!({"name": "s101-eh-no-key", "type": "azure_eventhubs",
                       "namespace": "s101ns", "event_hub": "s101hub"}),
                &token,
            )
            .await;
        assert_eq!(status, 400);
        assert!(
            body["message"]
                .as_str()
                .unwrap_or("")
                .contains("shared_access_key"),
            "missing key must be named, got: {body}"
        );
        assert!(state.engine.connectors().get("s101-eh-no-key").is_none());

        // azure_eventhubs with a key is 201 and live.
        let (status, _) = server
            .post_auth(
                "/api/v5/connectors",
                json!({"name": "s101-eh-1", "type": "azure_eventhubs",
                       "namespace": "s101ns", "event_hub": "s101hub",
                       "shared_access_key_name": "SendPolicy",
                       "shared_access_key": "dGVzdC1rZXktb3BlcmF0b3Itc3VwcGxpZWQ="}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert!(state.engine.connectors().get("s101-eh-1").is_some());

        // azure_iot without a key is 400 naming the field.
        let (status, body) = server
            .post_auth(
                "/api/v5/connectors",
                json!({"name": "s101-aiot-no-key", "type": "azure_iot",
                       "iot_hub_name": "127.0.0.1:8883",
                       "device_id": "s101-device"}),
                &token,
            )
            .await;
        assert_eq!(status, 400);
        assert!(
            body["message"]
                .as_str()
                .unwrap_or("")
                .contains("shared_access_key"),
            "missing key must be named, got: {body}"
        );
        assert!(state.engine.connectors().get("s101-aiot-no-key").is_none());

        // azure_iot with a key is 201 and live.
        let (status, _) = server
            .post_auth(
                "/api/v5/connectors",
                json!({"name": "s101-aiot-1", "type": "azure_iot",
                       "iot_hub_name": "127.0.0.1:8883",
                       "device_id": "s101-device",
                       "shared_access_key": "dGVzdC1rZXktb3BlcmF0b3Itc3VwcGxpZWQ="}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert!(state.engine.connectors().get("s101-aiot-1").is_some());
    }

    #[tokio::test]
    async fn rule_metrics_unknown_is_404_and_honest() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        let (status, body) = server
            .get_auth("/api/v5/rules/w0-13-no-such-rule/metrics", &token)
            .await;
        assert_eq!(status, 404);
        assert_eq!(body["code"], json!("NOT_FOUND"));

        let (status, body) = server
            .send(
                "PUT",
                "/api/v5/rules/w0-13-no-such-rule/metrics/reset",
                Some(json!({})),
                Some(&token),
            )
            .await;
        assert_eq!(status, 404);
        assert_eq!(body["code"], json!("NOT_FOUND"));

        let (status, created) = server
            .post_auth(
                "/api/v5/rules",
                json!({"name": "w0-13-metrics",
                       "sql": "SELECT * FROM \"t/w013\"",
                       "enable": true,
                       "actions": []}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        let rule_id = created["id"].as_str().expect("rule id").to_string();

        let (status, body) = server
            .get_auth(&format!("/api/v5/rules/{rule_id}/metrics"), &token)
            .await;
        assert_eq!(status, 200);
        let metrics = body["metrics"].as_object().expect("metrics object");
        let mut keys: Vec<&str> = metrics.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "actions.failed",
                "actions.success",
                "actions.total",
                "failed",
                "matched",
                "passed"
            ]
        );
        assert!(body.get("node_metrics").is_none());
        assert!(metrics.get("rate").is_none());
        assert!(metrics.get("rate_max").is_none());
        assert!(metrics.get("rate_last5m").is_none());
    }

    #[tokio::test]
    async fn connector_unknown_is_404() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        let (status, body) = server
            .get_auth("/api/v5/connectors/w0-13-no-such-connector", &token)
            .await;
        assert_eq!(status, 404);
        assert_eq!(body["code"], json!("NOT_FOUND"));
    }

    #[tokio::test]
    async fn removed_connector_operation_routes_return_404() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        let (status, _) = server
            .send(
                "PUT",
                "/api/v5/connectors/x/enable/true",
                None,
                Some(&token),
            )
            .await;
        assert_eq!(status, 404);
        let (status, _) = server
            .send("POST", "/api/v5/connectors/x/start", None, Some(&token))
            .await;
        assert_eq!(status, 404);
    }

    #[tokio::test]
    async fn test_rules_test_endpoint() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        // SQL match with projection.
        let (status, body) = server
            .post_auth(
                "/api/v1/rules/test",
                json!({"sql_query": "SELECT temperature FROM \"sensors/+\" WHERE temperature > 0",
                       "topic_filter": "sensors/+",
                       "topic": "sensors/kitchen",
                       "payload": {"temperature": 72.5, "secret": "x"}}),
                &token,
            )
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["matched"], json!(true));
        assert_eq!(body["projected"], json!({"temperature": 72.5}));

        // Predicate false.
        let (status, body) = server
            .post_auth(
                "/api/v1/rules/test",
                json!({"sql_query": "SELECT * FROM \"sensors/+\" WHERE temperature > 100.0",
                       "topic": "sensors/kitchen",
                       "payload": {"temperature": 72.5}}),
                &token,
            )
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["matched"], json!(false));

        // No SQL: passthrough.
        let (status, body) = server
            .post_auth(
                "/api/v1/rules/test",
                json!({"topic": "a/b", "payload": {"v": 1}}),
                &token,
            )
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["matched"], json!(true));
        assert_eq!(body["projected"], json!({"v": 1}));

        // Broken SQL is a 400.
        let (status, _) = server
            .post_auth(
                "/api/v1/rules/test",
                json!({"sql_query": "SELECT WHERE WHERE",
                       "topic": "a/b",
                       "payload": {}}),
                &token,
            )
            .await;
        assert_eq!(status, 400);
    }

    #[tokio::test]
    async fn test_rules_test_endpoint_batch() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        // Array payloads aggregate as one batch: one row per group.
        let (status, body) = server
            .post_auth(
                "/api/v1/rules/test",
                json!({"sql_query": "SELECT sensor_id, avg(temperature) AS avg_temp FROM \"sensors/+\" GROUP BY sensor_id",
                       "topic": "sensors/kitchen",
                       "payload": [{"sensor_id": "a", "temperature": 10.0},
                                   {"sensor_id": "b", "temperature": 30.0},
                                   {"sensor_id": "a", "temperature": 20.0}]}),
                &token,
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
            .post_auth(
                "/api/v1/rules/test",
                json!({"sql_query": "SELECT avg(temperature) AS a FROM \"sensors/+\"",
                       "topic": "sensors/kitchen",
                       "payload": []}),
                &token,
            )
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["matched"], json!(false));
        assert_eq!(body["projected"], serde_json::Value::Null);
    }

    #[tokio::test]
    async fn test_rules_functions_catalog() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        let (status, body) = server.get_auth("/api/v1/rules/functions", &token).await;
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
            stream
                .write_all(req.as_bytes())
                .await
                .expect("write upgrade");
            let mut buf = Vec::new();
            loop {
                let mut chunk = [0u8; 512];
                let n = stream.read(&mut chunk).await.expect("read upgrade");
                assert!(n > 0, "upgrade response ended early");
                buf.extend_from_slice(&chunk[..n]);
                if let Some(pos) = find_crlf2(&buf) {
                    let head = String::from_utf8_lossy(&buf[..pos + 4]).to_string();
                    assert!(
                        head.starts_with("HTTP/1.1 101"),
                        "expected 101, got: {head}"
                    );
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
        publ.send_bin(&mqtt_publish("demo/1", 42, 1, b"hi-ws"))
            .await;
        // Publisher gets its PUBACK...
        let puback = publ.recv_msg().await.expect("puback");
        assert_eq!(mqtt_packet_type(&puback), 4);
        // ...and the subscriber gets the delivery with flags + payload.
        let delivery = sub.recv_msg().await.expect("delivery");
        assert_eq!(mqtt_packet_type(&delivery), 3);
        assert_eq!(delivery[0] & 0x06, 0x02, "downstream QoS 1");
        assert!(delivery.windows(b"demo/1".len()).any(|w| w == b"demo/1"));
        assert!(delivery.ends_with(b"hi-ws"));

        // PINGREQ -> PINGRESP on the same socket.
        publ.send_bin(&[0xC0, 0x00]).await;
        let pong = publ.recv_msg().await.expect("pingresp");
        assert_eq!(pong, vec![0xD0, 0x00]);
    }

    #[tokio::test]
    async fn test_ws_auth_rejected_with_0x86() {
        let (server, state) = TestServer::start().await;
        state
            .auth
            .add_user("alice", b"s3cret")
            .expect("test user persists");

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
    async fn test_ws_anonymous_rejected_when_users_exist() {
        let (server, state) = TestServer::start().await;
        state
            .auth
            .add_user("alice", b"s3cret")
            .expect("test user persists");

        // No username while users exist: rejected with 0x87 even though
        // the console path has no `--allow-anonymous` flag.
        let mut client = WsClient::connect(server.port).await;
        client
            .send_bin(&mqtt_connect("console-anon", None, None))
            .await;
        let connack = client.recv_msg().await.expect("connack");
        assert_eq!(mqtt_packet_type(&connack), 2);
        assert_eq!(connack[3], 0x87, "anonymous must yield 0x87");
        // Socket closes right after the failed CONNACK.
        assert!(client.recv_msg().await.is_none());
        assert!(state.sessions.get("console-anon").is_none());

        // A valid credentialed console CONNECT in the same store gets 0.
        let mut client = WsClient::connect(server.port).await;
        client
            .send_bin(&mqtt_connect("console-ok", Some("alice"), Some(b"s3cret")))
            .await;
        let connack = client.recv_msg().await.expect("connack");
        assert_eq!(connack[3], 0);
    }

    #[tokio::test]
    async fn test_ws_subscribe_denied_with_0x87() {
        let (server, state) = TestServer::start().await;
        state
            .auth
            .add_rule(broker_auth::AclRule::new(
                "console-y",
                broker_auth::AclAction::All,
                "#",
                false,
            ))
            .expect("test rule persists");

        let mut client = WsClient::connect(server.port).await;
        client
            .send_bin(&mqtt_connect("console-y", None, None))
            .await;
        let connack = client.recv_msg().await.expect("connack");
        assert_eq!(connack[3], 0);

        client.send_bin(&mqtt_subscribe(3, &[("t", 0)])).await;
        let suback = client.recv_msg().await.expect("suback");
        assert_eq!(mqtt_packet_type(&suback), 9);
        assert_eq!(&suback[4..], &[0x87], "denied filter must yield 0x87");
    }

    #[tokio::test]
    async fn test_ws_subscribe_quota_denied_with_0x97() {
        // B4-08 bound: a full subscription table denies the console
        // subscribe fail closed with 0x97 Quota Exceeded and changes no
        // session state. Fills the shared router to MAX_SUBSCRIPTIONS
        // with three-level filters so each path copy stays small.
        let (server, state) = TestServer::start().await;
        for i in 0..broker_router::MAX_SUBSCRIPTIONS {
            let a = i / 10_000;
            let b = (i / 100) % 100;
            let c = i % 100;
            let filter = broker_protocol::TopicFilter::new(format!("quota/fill/{a}/{b:02}/{c:02}"))
                .expect("valid fill filter");
            assert!(
                state.router.subscribe(
                    &filter,
                    broker_router::Subscription::new(
                        format!("fill-{i}"),
                        i as u64,
                        broker_protocol::QoS::AtMostOnce
                    )
                ),
                "fill subscribe {i} must succeed"
            );
        }

        let mut client = WsClient::connect(server.port).await;
        client
            .send_bin(&mqtt_connect("console-q", None, None))
            .await;
        let connack = client.recv_msg().await.expect("connack");
        assert_eq!(connack[3], 0);

        client
            .send_bin(&mqtt_subscribe(9, &[("quota/probe", 0)]))
            .await;
        let suback = client.recv_msg().await.expect("suback");
        assert_eq!(mqtt_packet_type(&suback), 9);
        assert_eq!(
            &suback[4..],
            &[0x97],
            "quota denial must yield 0x97, not success"
        );

        // The failed subscribe registers nothing: no session mirror, no
        // router entry.
        let session = state.sessions.get("console-q").expect("session row");
        assert!(
            session
                .subscriptions
                .read()
                .keys()
                .all(|f| f.as_str() != "quota/probe"),
            "quota-denied subscribe must leave the session unchanged"
        );
        assert!(
            state
                .router
                .matches(&broker_protocol::Topic::new("quota/probe").expect("valid probe topic"))
                .is_empty(),
            "quota-denied subscribe must leave the router unchanged"
        );
    }

    #[tokio::test]
    async fn removed_gateway_routes_return_404() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;
        for path in [
            "/api/v5/gateways",
            "/api/v5/gateways/stomp",
            "/api/v5/gateways/stomp/clients/c1",
            "/api/v5/gateway",
        ] {
            let (status, _) = server
                .request_raw(&format!(
                    "GET {path} HTTP/1.0\r\nHost: test\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
                ))
                .await;
            assert_eq!(status, 404, "removed route {path} must be 404");
        }
    }

    #[tokio::test]
    async fn removed_listeners_routes_return_404() {
        // W1-01 restores `/api/v5/banned` on the real store, so only the
        // listener routes stay removed here; banned coverage lives with
        // the ban store tests below.
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;
        for raw in [
            "GET /api/v5/listeners HTTP/1.0\r\nHost: test\r\nAuthorization: Bearer TOKEN\r\nConnection: close\r\n\r\n",
            "GET /api/v5/listeners/tcp:default HTTP/1.0\r\nHost: test\r\nAuthorization: Bearer TOKEN\r\nConnection: close\r\n\r\n",
            "POST /api/v5/listeners/x/stop HTTP/1.0\r\nHost: test\r\nAuthorization: Bearer TOKEN\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
        ] {
            let raw = raw.replace("TOKEN", &token);
            let (status, _) = server.request_raw(&raw).await;
            assert_eq!(status, 404, "removed route must be 404: {raw}");
        }
    }

    #[tokio::test]
    async fn removed_trace_slowsub_topicmetrics_routes_return_404() {
        // W1-30 restores `GET`/`DELETE /api/v5/slow_subscriptions` on the
        // real recorder, W1-31 restores `GET`/`PUT
        // /api/v5/slow_subscriptions/settings` on the real thresholds and
        // W1-33 restores `GET`/`POST`/`DELETE /api/v5/trace` on the real
        // registry, so only the per-session trace reads and topic-metrics
        // routes stay removed here; trace create-list-clear coverage lives
        // with the registry tests.
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;
        for path in ["/api/v5/trace/x/log", "/api/v5/mqtt/topic_metrics"] {
            let (status, _) = server.get_auth(path, &token).await;
            assert_eq!(status, 404, "removed route {path} must be 404");
        }
        let (status, _) = server.get_auth("/api/v5/trace", &token).await;
        assert_eq!(status, 200, "kept route GET /api/v5/trace must be 200");
        let (status, _) = server.delete_auth("/api/v5/trace", &token).await;
        assert_eq!(status, 204, "kept route DELETE /api/v5/trace must be 204");
        let (status, _) = server.get_auth("/api/v5/slow_subscriptions", &token).await;
        assert_eq!(
            status, 200,
            "kept route GET /api/v5/slow_subscriptions must be 200"
        );
        let (status, _) = server
            .delete_auth("/api/v5/slow_subscriptions", &token)
            .await;
        assert_eq!(
            status, 204,
            "kept route DELETE /api/v5/slow_subscriptions must be 204"
        );
        let (status, _) = server
            .get_auth("/api/v5/slow_subscriptions/settings", &token)
            .await;
        assert_eq!(
            status, 200,
            "kept route GET /api/v5/slow_subscriptions/settings must be 200"
        );
        let (status, _) = server
            .put_auth(
                "/api/v5/slow_subscriptions/settings",
                json!({"threshold": "1s"}),
                &token,
            )
            .await;
        assert_eq!(
            status, 200,
            "kept route PUT /api/v5/slow_subscriptions/settings must be 200"
        );
    }

    #[tokio::test]
    async fn removed_action_routes_return_404() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;
        for path in [
            "/api/v5/actions",
            "/api/v5/actions/x",
            "/api/v5/actions/x/metrics",
            "/api/v5/actions_summary",
        ] {
            let (status, _) = server.get_auth(path, &token).await;
            assert_eq!(status, 404, "removed route {path} must be 404");
        }
        let (status, _) = server.post_auth("/api/v5/actions", json!({}), &token).await;
        assert_eq!(
            status, 404,
            "removed route POST /api/v5/actions must be 404"
        );
    }

    #[tokio::test]
    async fn removed_sources_rulenotest_routes_return_404() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;
        for path in ["/api/v5/sources", "/api/v5/rule_events"] {
            let (status, _) = server.get_auth(path, &token).await;
            assert_eq!(status, 404, "removed route {path} must be 404");
        }
        for path in [
            "/api/v5/sources_probe",
            "/api/v5/rule_test",
            "/api/v5/rules/abc/test",
        ] {
            let (status, _) = server.post_auth(path, json!({}), &token).await;
            assert_eq!(status, 404, "removed route POST {path} must be 404");
        }
    }

    #[tokio::test]
    async fn removed_schema_registry_routes_return_404() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;
        for path in [
            "/api/v5/schema_registry",
            "/api/v5/schema_registry/x",
            "/api/v5/schema_validations",
            "/api/v5/schema_validations/validation/x/metrics",
        ] {
            let (status, _) = server.get_auth(path, &token).await;
            assert_eq!(status, 404, "removed route {path} must be 404");
        }
    }

    #[tokio::test]
    async fn removed_unsupported_retained_routes_return_404() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;
        for path in [
            "/api/v5/mqtt/retained",
            "/api/v5/mqtt/delayed/messages",
            "/api/v5/ai/providers",
            "/api/v5/configs/a2a_registry",
            "/api/v5/indra/extra_features",
        ] {
            let (status, _) = server.get_auth(path, &token).await;
            assert_eq!(status, 404, "removed route {path} must be 404");
        }
        let (status, _) = server.delete_auth("/api/v5/mqtt/retained", &token).await;
        assert_eq!(
            status, 404,
            "removed route DELETE /api/v5/mqtt/retained must be 404"
        );
    }

    #[tokio::test]
    async fn removed_system_fake_routes_return_404() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;
        for path in [
            "/api/v5/license",
            "/api/v5/license/setting",
            "/api/v5/configs",
            "/api/v5/sso",
            "/api/v5/telemetry/status",
            "/api/v5/api_key",
        ] {
            let (status, _) = server.get_auth(path, &token).await;
            assert_eq!(status, 404, "removed route {path} must be 404");
        }
    }

    #[tokio::test]
    async fn removed_cluster_inflight_routes_return_404() {
        let (server, state) = TestServer::start().await;
        let token = server.login_as_admin().await;
        for path in ["/api/v5/cluster", "/api/v5/clients/any/inflight_messages"] {
            let (status, _) = server.get_auth(path, &token).await;
            assert_eq!(status, 404, "removed route GET {path} must be 404");
        }
        let (status, _) = server.get_auth("/api/v5/nodes", &token).await;
        assert_eq!(status, 200, "kept route GET /api/v5/nodes must be 200");
        state.sessions.get_or_create("mqueue-kept-1", true);
        let (status, _) = server
            .get_auth("/api/v5/clients/mqueue-kept-1/mqueue_messages", &token)
            .await;
        assert_eq!(
            status, 200,
            "kept route GET /api/v5/clients/:clientid/mqueue_messages must be 200"
        );
    }

    #[tokio::test]
    async fn removed_monitoring_fake_routes_return_404() {
        // W1-16 restores `/api/v5/alarms` on the real store, W1-17
        // restores `POST /api/v5/alarms/force_deactivate`, W1-18
        // restores `GET /api/v5/metrics` on the real counters and W1-19
        // restores `GET`/`DELETE /api/v5/monitor` on the history store,
        // so no monitoring route stays removed here; metrics, alarms and
        // monitor coverage lives with their store tests below.
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;
        for path in [
            "/api/v5/metrics",
            "/api/v5/monitor",
            "/api/v5/monitor_current",
            "/api/v5/stats",
        ] {
            let (status, _) = server.get_auth(path, &token).await;
            assert_eq!(status, 200, "kept route GET {path} must be 200");
        }
        let (status, _) = server.delete_auth("/api/v5/monitor", &token).await;
        assert_eq!(status, 204, "kept route DELETE /api/v5/monitor must be 204");
    }

    #[tokio::test]
    async fn login_response_has_no_invented_fields() {
        let (server, _state) = TestServer::start().await;
        let (status, body) = server
            .post(
                "/api/v5/login",
                json!({"username": "admin", "password": "public"}),
            )
            .await;
        assert_eq!(status, 200);
        assert!(body["token"].as_str().is_some_and(|t| !t.is_empty()));
        assert_eq!(body["role"], json!("administrator"));
        assert_eq!(body["must_change_password"], json!(true));
        assert!(
            body.get("version").is_none(),
            "login must not invent version"
        );
        assert!(
            body.get("license").is_none(),
            "login must not invent license"
        );
    }

    #[tokio::test]
    async fn authn_users_list_has_no_invented_fields() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;
        let (status, created) = server
            .post_auth(
                "/api/v5/authentication/password_based:built_in_database/users",
                json!({"user_id": "mqtt-alice", "password": "s3cret"}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        assert_eq!(created, json!({"user_id": "mqtt-alice"}));
        let (status, body) = server
            .get_auth(
                "/api/v5/authentication/password_based:built_in_database/users",
                &token,
            )
            .await;
        assert_eq!(status, 200);
        let data = body["data"].as_array().expect("data is a list");
        assert_eq!(data.len(), 1);
        assert_eq!(data[0], json!({"user_id": "mqtt-alice"}));
    }

    #[tokio::test]
    async fn authn_import_users_batch_round_trip_rejects_bad_and_duplicate() {
        // W2-07 failing test: import two users to a fresh authenticator,
        // list expecting both; re-import one duplicate expecting clean
        // rejection with the store intact. Before: 404 (no route).
        // Management-plane only: the import locks only the user map
        // (`crates/broker-auth/src/lib.rs`, `MemoryAuth::import_users`);
        // the broker event driving it is the management POST, and CONNECT
        // consults the same map
        // (`crates/broker-node/src/main.rs`, CONNECT handling).
        let (server, state) = TestServer::start().await;
        let token = server.login_as_admin().await;
        let (status, _) = server
            .post_auth(
                "/api/v5/authentication",
                json!({"mechanism": "password_based", "backend": "built_in_database"}),
                &token,
            )
            .await;
        assert_eq!(status, 201);

        let (status, body) = server
            .post_auth(
                "/api/v5/authentication/password_based:built_in_database/import_users",
                json!([
                    {"user_id": "w2-07-a", "password": "Imp0rt-a!"},
                    {"user_id": "w2-07-b", "password": "Imp0rt-b!"},
                ]),
                &token,
            )
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["total"], json!(2));
        assert_eq!(body["success"], json!(2));

        let (status, body) = server
            .get_auth(
                "/api/v5/authentication/password_based:built_in_database/users",
                &token,
            )
            .await;
        assert_eq!(status, 200);
        let data = body["data"].as_array().expect("data is a list");
        assert!(data.contains(&json!({"user_id": "w2-07-a"})));
        assert!(data.contains(&json!({"user_id": "w2-07-b"})));

        // The imported credentials authenticate through the broker state:
        // `MemoryAuth::authenticate` accepts the new password and refuses
        // a wrong one (the same call the kernel CONNECT path makes).
        assert!(state
            .auth
            .authenticate("w2-07-c1", Some("w2-07-a"), Some(b"Imp0rt-a!"))
            .await
            .is_ok());
        assert!(state
            .auth
            .authenticate("w2-07-c1", Some("w2-07-a"), Some(b"wrong"))
            .await
            .is_err());

        // Re-import with one duplicate: clean rejection, store intact.
        let (status, body) = server
            .post_auth(
                "/api/v5/authentication/password_based:built_in_database/import_users",
                json!([
                    {"user_id": "w2-07-b", "password": "Imp0rt-b!"},
                    {"user_id": "w2-07-c", "password": "Imp0rt-c!"},
                ]),
                &token,
            )
            .await;
        assert_eq!(status, 400);
        assert_eq!(body["code"], json!("ALREADY_EXISTS"));
        assert!(body["message"].is_string());
        let (status, body) = server
            .get_auth(
                "/api/v5/authentication/password_based:built_in_database/users",
                &token,
            )
            .await;
        assert_eq!(status, 200);
        let data = body["data"].as_array().expect("data is a list");
        assert_eq!(data.len(), 2);
        assert!(!data.contains(&json!({"user_id": "w2-07-c"})));

        // Duplicate within the batch is rejected the same way.
        let (status, body) = server
            .post_auth(
                "/api/v5/authentication/password_based:built_in_database/import_users",
                json!([
                    {"user_id": "w2-07-d", "password": "Imp0rt-d!"},
                    {"user_id": "w2-07-d", "password": "Imp0rt-d!"},
                ]),
                &token,
            )
            .await;
        assert_eq!(status, 400);
        assert_eq!(body["code"], json!("ALREADY_EXISTS"));

        // Malformed batches are client errors with the documented shape
        // and apply nothing.
        for bad in [
            json!([]),
            json!([{"user_id": "w2-07-e"}]),
            json!([{"user_id": "", "password": "Imp0rt-e!"}]),
            json!([{"user_id": "w2-07-e", "password": ""}]),
            json!({"not-users": []}),
        ] {
            let (status, body) = server
                .post_auth(
                    "/api/v5/authentication/password_based:built_in_database/import_users",
                    bad,
                    &token,
                )
                .await;
            assert_eq!(status, 400);
            assert_eq!(body["code"], json!("BAD_REQUEST"));
            assert!(body["message"].is_string());
        }
        let (status, body) = server
            .get_auth(
                "/api/v5/authentication/password_based:built_in_database/users",
                &token,
            )
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["data"].as_array().expect("data").len(), 2);

        // Unknown authenticator ids are 404 with the documented code,
        // not an empty body.
        let (status, body) = server
            .post_auth(
                "/api/v5/authentication/password_based:nowhere/import_users",
                json!([{"user_id": "w2-07-x", "password": "Imp0rt-x!"}]),
                &token,
            )
            .await;
        assert_eq!(status, 404);
        assert_eq!(body["code"], json!("NOT_FOUND"));
        assert!(body["message"].is_string());

        // Non-built-in backends cannot be imported into the built-in map.
        let (status, _) = server
            .post_auth(
                "/api/v5/authentication",
                json!({"mechanism": "password_based", "backend": "mysql"}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        let (status, body) = server
            .post_auth(
                "/api/v5/authentication/password_based:mysql/import_users",
                json!([{"user_id": "w2-07-y", "password": "Imp0rt-y!"}]),
                &token,
            )
            .await;
        assert_eq!(status, 400);
        assert_eq!(body["code"], json!("BAD_REQUEST"));
    }

    #[tokio::test]
    async fn authn_imported_users_connect_and_persist() {
        // Imported users persist across a restart and authenticate a real
        // broker CONNECT through the console path (connect, not only the
        // store): the imported credential gets CONNACK 0 over the live
        // WebSocket console, a wrong password does not.
        let dir = unique_data_dir("authn-import");
        let registry = Arc::new(ConfigRegistry::load(&dir).expect("fresh data dir loads defaults"));
        let (server, _state) = TestServer::start_with_registry(Arc::clone(&registry)).await;
        let token = server.login_as_admin().await;
        let (status, _) = server
            .post_auth(
                "/api/v5/authentication",
                json!({"mechanism": "password_based", "backend": "built_in_database"}),
                &token,
            )
            .await;
        assert_eq!(status, 201);
        let (status, _) = server
            .post_auth(
                "/api/v5/authentication/password_based:built_in_database/import_users",
                json!([
                    {"user_id": "w2-07-persist", "password": "Persist1!"},
                ]),
                &token,
            )
            .await;
        assert_eq!(status, 200);

        let mut ok = WsClient::connect(server.port).await;
        ok.send_bin(&mqtt_connect(
            "w2-07-persist-ok",
            Some("w2-07-persist"),
            Some(b"Persist1!"),
        ))
        .await;
        let connack = ok.recv_msg().await.expect("connack");
        assert_eq!(mqtt_packet_type(&connack), 2);
        assert_eq!(connack[3], 0);
        drop(ok);

        let mut bad = WsClient::connect(server.port).await;
        bad.send_bin(&mqtt_connect(
            "w2-07-persist-bad",
            Some("w2-07-persist"),
            Some(b"wrong"),
        ))
        .await;
        let connack = bad.recv_msg().await.expect("connack");
        assert_eq!(mqtt_packet_type(&connack), 2);
        assert_ne!(connack[3], 0);
        drop(bad);
        drop(server);
        drop(registry);

        let reloaded = Arc::new(ConfigRegistry::load(&dir).expect("reload data dir"));
        let (server, _state) = TestServer::start_with_registry(reloaded).await;
        let (status, body) = server
            .post(
                "/api/v5/login",
                json!({"username": "admin", "password": "Adm1n-test-pass!"}),
            )
            .await;
        assert_eq!(status, 200);
        let token = body["token"].as_str().expect("admin token").to_string();
        let (status, body) = server
            .get_auth(
                "/api/v5/authentication/password_based:built_in_database/users",
                &token,
            )
            .await;
        assert_eq!(status, 200);
        let data = body["data"].as_array().expect("data is a list");
        assert!(data.contains(&json!({"user_id": "w2-07-persist"})));
        drop(server);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn ui_schema_unknown_is_404() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;
        let (status, _) = server.get_auth("/api/v5/schemas/hotconf", &token).await;
        assert_eq!(status, 404, "unserved schema must be 404");
        let (status, _) = server.get_auth("/api/v5/schemas/sources", &token).await;
        assert_eq!(status, 404, "sources alias must be 404");
        for name in ["actions", "connectors"] {
            let (status, body) = server
                .get_auth(&format!("/api/v5/schemas/{name}"), &token)
                .await;
            assert_eq!(status, 200, "served schema {name} must be 200");
            assert!(body["components"]["schemas"].is_object());
        }
        let (status, body) = server.get_auth("/api/v5/schemas", &token).await;
        assert_eq!(status, 200);
        assert_eq!(body, json!(["actions", "connectors"]));
    }

    #[tokio::test]
    async fn node_loads_serialise_as_numbers() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;
        let (status, body) = server.get_auth("/api/v5/nodes", &token).await;
        assert_eq!(status, 200);
        let first = &body[0];
        for field in ["load1", "load5", "load15"] {
            assert!(
                first[field].is_number(),
                "{field} must be a JSON number, got: {}",
                first[field]
            );
        }
        let node = first["node"].as_str().expect("node name").to_string();
        let (status, single) = server
            .get_auth(&format!("/api/v5/nodes/{node}"), &token)
            .await;
        assert_eq!(status, 200);
        for field in ["load1", "load5", "load15"] {
            assert!(
                single[field].is_number(),
                "{field} must be a JSON number, got: {}",
                single[field]
            );
        }
    }

    #[tokio::test]
    async fn client_subscribe_returns_documented_status() {
        let (server, state) = TestServer::start().await;
        let token = server.login_as_admin().await;
        state.sessions.get_or_create("tk02-sub", true);
        let (status, _) = server
            .post_auth(
                "/api/v5/clients/tk02-sub/subscribe",
                json!({"topic": "tk02/sub", "qos": 0}),
                &token,
            )
            .await;
        assert_eq!(status, 200);
    }

    #[tokio::test]
    async fn subscribe_single_registers_and_lists() {
        let (server, state) = TestServer::start().await;
        let token = server.login_as_admin().await;
        state.sessions.get_or_create("w1-08-a", true);

        let (status, body) = server
            .post_auth(
                "/api/v5/clients/w1-08-a/subscribe",
                json!({"topic": "w1-08/single", "qos": 1}),
                &token,
            )
            .await;
        assert_eq!(status, 200);
        assert_eq!(body["clientid"], json!("w1-08-a"));
        assert_eq!(body["topic"], json!("w1-08/single"));
        assert_eq!(body["qos"], json!(1));
        assert_eq!(body["node"], json!("indramqtt@127.0.0.1"));

        let (status, body) = server
            .get_auth("/api/v5/clients/w1-08-a/subscriptions", &token)
            .await;
        assert_eq!(status, 200);
        let subs = body.as_array().expect("subscriptions list");
        assert!(
            subs.iter()
                .any(|s| s["topic"] == json!("w1-08/single") && s["qos"] == json!(1)),
            "single subscribe lands and reads back: {subs:?}"
        );
    }

    #[tokio::test]
    async fn subscribe_bulk_mixed_good_and_bad_reports_per_entry() {
        let (server, state) = TestServer::start().await;
        let token = server.login_as_admin().await;
        state.sessions.get_or_create("w1-08-b", true);

        let (status, body) = server
            .post_auth(
                "/api/v5/clients/w1-08-b/subscribe/bulk",
                json!([
                    {"topic": "w1-08/bulk/good", "qos": 0},
                    {"topic": "bad/#/topic", "qos": 0},
                ]),
                &token,
            )
            .await;
        assert_eq!(status, 200);
        let results = body.as_array().expect("bulk result is a list");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["topic"], json!("w1-08/bulk/good"));
        assert_eq!(results[0]["clientid"], json!("w1-08-b"));
        assert_eq!(results[1]["topic"], json!("bad/#/topic"));
        assert_eq!(results[1]["code"], json!("BAD_REQUEST"));
        assert!(results[1]["message"].is_string());

        let (status, body) = server
            .get_auth("/api/v5/clients/w1-08-b/subscriptions", &token)
            .await;
        assert_eq!(status, 200);
        let subs = body.as_array().expect("subscriptions list");
        assert!(
            subs.iter().any(|s| s["topic"] == json!("w1-08/bulk/good")),
            "bulk good entry lands: {subs:?}"
        );
        assert!(
            !subs.iter().any(|s| s["topic"] == json!("bad/#/topic")),
            "bulk bad entry never lands: {subs:?}"
        );
    }

    #[tokio::test]
    async fn subscribe_unknown_client_is_not_found() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        let (status, body) = server
            .post_auth(
                "/api/v5/clients/w1-08-missing/subscribe",
                json!({"topic": "w1-08/nowhere", "qos": 0}),
                &token,
            )
            .await;
        assert_eq!(status, 404);
        assert_eq!(body["code"], json!("CLIENTID_NOT_FOUND"));

        let (status, body) = server
            .post_auth(
                "/api/v5/clients/w1-08-missing/subscribe/bulk",
                json!([{"topic": "w1-08/nowhere", "qos": 0}]),
                &token,
            )
            .await;
        assert_eq!(status, 404);
        assert_eq!(body["code"], json!("CLIENTID_NOT_FOUND"));
    }

    #[tokio::test]
    async fn subscribe_malformed_body_is_bad_request() {
        let (server, state) = TestServer::start().await;
        let token = server.login_as_admin().await;
        state.sessions.get_or_create("w1-08-c", true);

        for bad in [
            json!({"qos": 0}),
            json!({"topic": "", "qos": 0}),
            json!({"topic": "bad/#/topic", "qos": 0}),
            json!({"topic": "w1-08/ok", "qos": 9}),
            json!({"topic": "w1-08/ok", "nl": 2}),
        ] {
            let (status, body) = server
                .post_auth("/api/v5/clients/w1-08-c/subscribe", bad, &token)
                .await;
            assert_eq!(status, 400);
            assert_eq!(body["code"], json!("BAD_REQUEST"));
            assert!(body["message"].is_string());
        }

        let (status, body) = server
            .post_auth(
                "/api/v5/clients/w1-08-c/subscribe/bulk",
                json!({"topic": "w1-08/ok"}),
                &token,
            )
            .await;
        assert_eq!(status, 400);
        assert_eq!(body["code"], json!("BAD_REQUEST"));
    }

    #[tokio::test]
    async fn publish_to_durable_subscriber_queues_offline() {
        let (server, state) = TestServer::start().await;
        let token = server.login_as_admin().await;
        state.sessions.get_or_create("w1-11-a", false);

        let (status, _) = server
            .post_auth(
                "/api/v5/clients/w1-11-a/subscribe",
                json!({"topic": "w1-11/delivery", "qos": 1}),
                &token,
            )
            .await;
        assert_eq!(status, 200);

        let (status, body) = server
            .post_auth(
                "/api/v5/publish",
                json!({"topic": "w1-11/delivery", "payload": "hello-w1-11", "qos": 1}),
                &token,
            )
            .await;
        assert_eq!(status, 200);
        assert!(body["id"].is_string(), "publish accepts with id: {body:?}");

        let (status, body) = server
            .get_auth("/api/v5/clients/w1-11-a/mqueue_messages", &token)
            .await;
        assert_eq!(status, 200);
        let data = body["data"].as_array().expect("mqueue data is a list");
        assert!(
            data.iter()
                .any(|m| m["topic"] == json!("w1-11/delivery")
                    && m["payload"] == json!("hello-w1-11")),
            "published message reaches detached durable queue: {data:?}"
        );
    }

    #[tokio::test]
    async fn publish_without_subscribers_still_accepts() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;
        let (status, body) = server
            .post_auth(
                "/api/v5/publish",
                json!({"topic": "w1-11/nobody-here", "payload": "hello", "qos": 0}),
                &token,
            )
            .await;
        assert_eq!(status, 200);
        assert!(body["id"].is_string());
    }

    #[tokio::test]
    async fn publish_malformed_body_is_bad_request() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        for bad in [
            json!({"payload": "x"}),
            json!({"topic": "", "payload": "x"}),
            json!({"topic": "bad/#/topic", "payload": "x"}),
            json!({"topic": "w1-11/ok", "qos": 9, "payload": "x"}),
            json!({"topic": "w1-11/ok", "payload": 42}),
            json!({"topic": "w1-11/ok", "payload": "x", "payload_encoding": "hex"}),
            json!({"topic": "w1-11/ok", "payload": "!!!", "payload_encoding": "base64"}),
            json!({"topic": "w1-11/ok", "retain": "yes", "payload": "x"}),
            json!({"topic": "w1-11/ok", "payload": "x", "payload_encoding": 42}),
            json!({"topic": "w1-11/ok", "payload": "x", "qos": "1"}),
        ] {
            let (status, body) = server.post_auth("/api/v5/publish", bad, &token).await;
            assert_eq!(status, 400);
            assert_eq!(body["code"], json!("BAD_REQUEST"));
            assert!(body["message"].is_string());
            let obj = body.as_object().expect("error body is an object");
            assert_eq!(
                obj.len(),
                2,
                "error shape is exactly code+message: {body:?}"
            );
        }
    }

    #[tokio::test]
    async fn publish_retain_flag_and_base64_honoured() {
        let (server, state) = TestServer::start().await;
        let token = server.login_as_admin().await;
        state.sessions.get_or_create("w1-11-b", false);

        let (status, _) = server
            .post_auth(
                "/api/v5/clients/w1-11-b/subscribe",
                json!({"topic": "w1-11/retained", "qos": 0}),
                &token,
            )
            .await;
        assert_eq!(status, 200);

        // "hi-w11" as base64 with retain flag set.
        let (status, body) = server
            .post_auth(
                "/api/v5/publish",
                json!({
                    "topic": "w1-11/retained",
                    "payload": "aGktdzEx",
                    "payload_encoding": "base64",
                    "qos": 0,
                    "retain": true,
                }),
                &token,
            )
            .await;
        assert_eq!(status, 200);
        assert!(body["id"].is_string());

        let (status, body) = server
            .get_auth("/api/v5/clients/w1-11-b/mqueue_messages", &token)
            .await;
        assert_eq!(status, 200);
        let data = body["data"].as_array().expect("mqueue data is a list");
        assert!(
            data.iter()
                .any(|m| m["topic"] == json!("w1-11/retained") && m["payload"] == json!("hi-w11")),
            "base64 payload decodes and retain flag delivers: {data:?}"
        );
    }

    #[tokio::test]
    async fn publish_bulk_mixed_good_and_bad_reports_per_entry() {
        let (server, state) = TestServer::start().await;
        let token = server.login_as_admin().await;
        state.sessions.get_or_create("w1-12-a", false);

        let (status, _) = server
            .post_auth(
                "/api/v5/clients/w1-12-a/subscribe",
                json!({"topic": "w1-12/bulk/good", "qos": 0}),
                &token,
            )
            .await;
        assert_eq!(status, 200);

        let (status, body) = server
            .post_auth(
                "/api/v5/publish/bulk",
                json!([
                    {"topic": "w1-12/bulk/good", "payload": "hello-w1-12", "qos": 0},
                    {"topic": "bad/#/topic", "payload": "x", "qos": 0},
                ]),
                &token,
            )
            .await;
        assert_eq!(status, 200);
        let results = body.as_array().expect("bulk result is a list");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["topic"], json!("w1-12/bulk/good"));
        assert!(
            results[0]["id"].is_string(),
            "bulk good entry accepts with id: {results:?}"
        );
        assert_eq!(results[1]["topic"], json!("bad/#/topic"));
        assert_eq!(results[1]["code"], json!("BAD_REQUEST"));
        assert!(results[1]["message"].is_string());

        let (status, body) = server
            .get_auth("/api/v5/clients/w1-12-a/mqueue_messages", &token)
            .await;
        assert_eq!(status, 200);
        let data = body["data"].as_array().expect("mqueue data is a list");
        assert!(
            data.iter()
                .any(|m| m["topic"] == json!("w1-12/bulk/good")
                    && m["payload"] == json!("hello-w1-12")),
            "bulk good entry delivers while bad entry fails: {data:?}"
        );
    }

    #[tokio::test]
    async fn publish_bulk_all_good_delivers_every_entry() {
        let (server, state) = TestServer::start().await;
        let token = server.login_as_admin().await;
        state.sessions.get_or_create("w1-12-b", false);

        for topic in ["w1-12/all/1", "w1-12/all/2"] {
            let (status, _) = server
                .post_auth(
                    "/api/v5/clients/w1-12-b/subscribe",
                    json!({"topic": topic, "qos": 0}),
                    &token,
                )
                .await;
            assert_eq!(status, 200);
        }

        let (status, body) = server
            .post_auth(
                "/api/v5/publish/bulk",
                json!([
                    {"topic": "w1-12/all/1", "payload": "one", "qos": 0},
                    {"topic": "w1-12/all/2", "payload": "two", "qos": 0},
                ]),
                &token,
            )
            .await;
        assert_eq!(status, 200);
        let results = body.as_array().expect("bulk result is a list");
        assert_eq!(results.len(), 2);
        for result in results {
            assert!(
                result["id"].is_string(),
                "every bulk entry accepts with id: {results:?}"
            );
            assert!(
                result.get("code").is_none(),
                "success entries carry no error code: {results:?}"
            );
        }

        let (status, body) = server
            .get_auth("/api/v5/clients/w1-12-b/mqueue_messages", &token)
            .await;
        assert_eq!(status, 200);
        let data = body["data"].as_array().expect("mqueue data is a list");
        assert!(
            data.iter()
                .any(|m| m["topic"] == json!("w1-12/all/1") && m["payload"] == json!("one")),
            "first bulk entry delivers: {data:?}"
        );
        assert!(
            data.iter()
                .any(|m| m["topic"] == json!("w1-12/all/2") && m["payload"] == json!("two")),
            "second bulk entry delivers: {data:?}"
        );
    }

    #[tokio::test]
    async fn publish_bulk_malformed_body_is_bad_request() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        let (status, body) = server
            .post_auth(
                "/api/v5/publish/bulk",
                json!({"topic": "w1-12/ok", "payload": "x"}),
                &token,
            )
            .await;
        assert_eq!(status, 400);
        assert_eq!(body["code"], json!("BAD_REQUEST"));
        assert!(body["message"].is_string());
        let obj = body.as_object().expect("error body is an object");
        assert_eq!(
            obj.len(),
            2,
            "error shape is exactly code+message: {body:?}"
        );
    }

    #[tokio::test]
    async fn unsubscribe_single_round_trip_removes_and_reads_empty() {
        let (server, state) = TestServer::start().await;
        let token = server.login_as_admin().await;
        state.sessions.get_or_create("w1-10-a", true);

        let (status, _) = server
            .post_auth(
                "/api/v5/clients/w1-10-a/subscribe",
                json!({"topic": "w1-10/single", "qos": 0}),
                &token,
            )
            .await;
        assert_eq!(status, 200);

        let (status, body) = server
            .get_auth("/api/v5/clients/w1-10-a/subscriptions", &token)
            .await;
        assert_eq!(status, 200);
        let subs = body.as_array().expect("subscriptions list");
        assert!(
            subs.iter().any(|s| s["topic"] == json!("w1-10/single")),
            "subscribed entry present before unsubscribe: {subs:?}"
        );

        let (status, _) = server
            .post_auth(
                "/api/v5/clients/w1-10-a/unsubscribe",
                json!({"topic": "w1-10/single"}),
                &token,
            )
            .await;
        assert_eq!(status, 204);

        let (status, body) = server
            .get_auth("/api/v5/clients/w1-10-a/subscriptions", &token)
            .await;
        assert_eq!(status, 200);
        let subs = body.as_array().expect("subscriptions list");
        assert!(
            !subs.iter().any(|s| s["topic"] == json!("w1-10/single")),
            "unsubscribed entry gone: {subs:?}"
        );

        // Removing an absent subscription still succeeds.
        let (status, _) = server
            .post_auth(
                "/api/v5/clients/w1-10-a/unsubscribe",
                json!({"topic": "w1-10/single"}),
                &token,
            )
            .await;
        assert_eq!(status, 204);
    }

    #[tokio::test]
    async fn unsubscribe_bulk_mixed_present_absent_reports_success() {
        let (server, state) = TestServer::start().await;
        let token = server.login_as_admin().await;
        state.sessions.get_or_create("w1-10-b", true);

        let (status, _) = server
            .post_auth(
                "/api/v5/clients/w1-10-b/subscribe",
                json!({"topic": "w1-10/bulk/present", "qos": 0}),
                &token,
            )
            .await;
        assert_eq!(status, 200);

        let (status, body) = server
            .post_auth(
                "/api/v5/clients/w1-10-b/unsubscribe/bulk",
                json!([
                    {"topic": "w1-10/bulk/present"},
                    {"topic": "w1-10/bulk/absent"},
                ]),
                &token,
            )
            .await;
        assert_eq!(status, 200);
        let results = body.as_array().expect("bulk result is a list");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["topic"], json!("w1-10/bulk/present"));
        assert!(
            results[0]["code"].is_null(),
            "present entry succeeds without code: {results:?}"
        );
        assert_eq!(results[1]["topic"], json!("w1-10/bulk/absent"));
        assert!(
            results[1]["code"].is_null(),
            "absent entry still succeeds: {results:?}"
        );

        let (status, body) = server
            .get_auth("/api/v5/clients/w1-10-b/subscriptions", &token)
            .await;
        assert_eq!(status, 200);
        let subs = body.as_array().expect("subscriptions list");
        assert!(
            !subs
                .iter()
                .any(|s| s["topic"] == json!("w1-10/bulk/present")),
            "bulk-removed entry gone: {subs:?}"
        );
    }

    #[tokio::test]
    async fn unsubscribe_unknown_client_is_not_found() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        let (status, body) = server
            .post_auth(
                "/api/v5/clients/w1-10-missing/unsubscribe",
                json!({"topic": "w1-10/nowhere"}),
                &token,
            )
            .await;
        assert_eq!(status, 404);
        assert_eq!(body["code"], json!("CLIENTID_NOT_FOUND"));

        let (status, body) = server
            .post_auth(
                "/api/v5/clients/w1-10-missing/unsubscribe/bulk",
                json!([{"topic": "w1-10/nowhere"}]),
                &token,
            )
            .await;
        assert_eq!(status, 404);
        assert_eq!(body["code"], json!("CLIENTID_NOT_FOUND"));
    }

    #[tokio::test]
    async fn unsubscribe_malformed_body_is_bad_request() {
        let (server, state) = TestServer::start().await;
        let token = server.login_as_admin().await;
        state.sessions.get_or_create("w1-10-c", true);

        for bad in [
            json!({"qos": 0}),
            json!({"topic": ""}),
            json!({"topic": "bad/#/topic"}),
        ] {
            let (status, body) = server
                .post_auth("/api/v5/clients/w1-10-c/unsubscribe", bad, &token)
                .await;
            assert_eq!(status, 400);
            assert_eq!(body["code"], json!("BAD_REQUEST"));
            assert!(body["message"].is_string());
        }

        let (status, body) = server
            .post_auth(
                "/api/v5/clients/w1-10-c/unsubscribe/bulk",
                json!({"topic": "w1-10/ok"}),
                &token,
            )
            .await;
        assert_eq!(status, 400);
        assert_eq!(body["code"], json!("BAD_REQUEST"));

        // One bad entry fails per entry while the good one still removes.
        let (status, _) = server
            .post_auth(
                "/api/v5/clients/w1-10-c/subscribe",
                json!({"topic": "w1-10/bulk/good", "qos": 0}),
                &token,
            )
            .await;
        assert_eq!(status, 200);

        let (status, body) = server
            .post_auth(
                "/api/v5/clients/w1-10-c/unsubscribe/bulk",
                json!([
                    {"topic": "w1-10/bulk/good"},
                    {"topic": "bad/#/topic"},
                ]),
                &token,
            )
            .await;
        assert_eq!(status, 200);
        let results = body.as_array().expect("bulk result is a list");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["topic"], json!("w1-10/bulk/good"));
        assert!(results[0]["code"].is_null());
        assert_eq!(results[1]["topic"], json!("bad/#/topic"));
        assert_eq!(results[1]["code"], json!("BAD_REQUEST"));
        assert!(results[1]["message"].is_string());
    }

    #[tokio::test]
    async fn client_subscriptions_empty_list_is_empty_not_error() {
        let (server, state) = TestServer::start().await;
        let token = server.login_as_admin().await;
        state.sessions.get_or_create("w1-09-empty", true);

        let (status, body) = server
            .get_auth("/api/v5/clients/w1-09-empty/subscriptions", &token)
            .await;
        assert_eq!(status, 200);
        let subs = body.as_array().expect("subscriptions list");
        assert!(subs.is_empty(), "unsubscribed client reads empty: {subs:?}");
    }

    #[tokio::test]
    async fn client_subscriptions_lists_subscribe_with_options() {
        let (server, state) = TestServer::start().await;
        let token = server.login_as_admin().await;
        state.sessions.get_or_create("w1-09-opts", true);

        let (status, _) = server
            .post_auth(
                "/api/v5/clients/w1-09-opts/subscribe",
                json!({"topic": "w1-09/with-opts", "qos": 1, "nl": 1, "rap": 0, "rh": 1}),
                &token,
            )
            .await;
        assert_eq!(status, 200);

        let (status, _) = server
            .post_auth(
                "/api/v5/clients/w1-09-opts/subscribe",
                json!({"topic": "w1-09/defaults", "qos": 0}),
                &token,
            )
            .await;
        assert_eq!(status, 200);

        let (status, body) = server
            .get_auth("/api/v5/clients/w1-09-opts/subscriptions", &token)
            .await;
        assert_eq!(status, 200);
        let subs = body.as_array().expect("subscriptions list");
        assert_eq!(subs.len(), 2, "both subscribes read back: {subs:?}");
        let entry = subs
            .iter()
            .find(|s| s["topic"] == json!("w1-09/with-opts"))
            .expect("subscribed entry present");
        assert_eq!(entry["qos"], json!(1));
        assert_eq!(entry["nl"], json!(1));
        assert_eq!(entry["rap"], json!(0));
        assert_eq!(entry["rh"], json!(1));
        assert_eq!(entry["node"], json!("indramqtt@127.0.0.1"));
        assert_eq!(entry["clientid"], json!("w1-09-opts"));
        let defaults = subs
            .iter()
            .find(|s| s["topic"] == json!("w1-09/defaults"))
            .expect("default entry present");
        assert_eq!(defaults["qos"], json!(0));
        assert_eq!(defaults["nl"], json!(0));
        assert_eq!(defaults["rap"], json!(0));
        assert_eq!(defaults["rh"], json!(0));
        assert_eq!(defaults["node"], json!("indramqtt@127.0.0.1"));
        assert_eq!(defaults["clientid"], json!("w1-09-opts"));
    }

    #[tokio::test]
    async fn client_subscriptions_unknown_is_not_found() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;

        let (status, body) = server
            .get_auth("/api/v5/clients/w1-09-missing/subscriptions", &token)
            .await;
        assert_eq!(status, 404);
        assert_eq!(body["code"], json!("CLIENTID_NOT_FOUND"));
    }

    #[tokio::test]
    async fn dashboard_user_create_returns_documented_status() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;
        let (status, created) = server
            .post_auth(
                "/api/v5/users",
                json!({"username": "tk02-user", "password": "Tk02-passw0rd!"}),
                &token,
            )
            .await;
        assert_eq!(status, 200);
        assert_eq!(created["username"], json!("tk02-user"));
    }

    #[tokio::test]
    async fn change_pwd_returns_documented_status() {
        let (server, _state) = TestServer::start().await;
        let fresh = server.admin_token().await;
        let (status, body) = server
            .put_auth(
                "/api/v5/users/admin/change_pwd",
                json!({"old_pwd": "public", "new_pwd": "Tk02-new-pass!"}),
                &fresh,
            )
            .await;
        assert_eq!(status, 204);
        assert_eq!(body, json!(null));
    }

    #[tokio::test]
    async fn probe_failures_report_documented_code() {
        let (server, _state) = TestServer::start().await;
        let token = server.login_as_admin().await;
        // Port 9 is closed, so the probe reaches its failure branch.
        for path in ["/api/v5/connectors_probe", "/api/v5/actions_probe"] {
            let (status, body) = server
                .post_auth(
                    path,
                    json!({"type": "http", "url": "http://127.0.0.1:9"}),
                    &token,
                )
                .await;
            assert_eq!(status, 400, "{path} failure must be 400");
            assert_eq!(body["code"], json!("TEST_FAILED"), "{path} code");
        }
    }
}
