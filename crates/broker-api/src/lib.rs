use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use broker_observability::Metrics;
use broker_protocol::{QoS, Topic, TopicFilter};
use broker_router::Router as SubscriptionRouter;
use broker_rules::{Rule, RuleAction, RuleEngine};
use broker_session::SessionManager;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Shared node state injected into every management endpoint: the rule
/// engine (mutable via the rules API), session directory, subscription
/// router, and node metrics.
#[derive(Clone)]
pub struct ApiState {
    pub engine: Arc<RuleEngine>,
    pub sessions: Arc<SessionManager>,
    pub router: Arc<SubscriptionRouter>,
    pub metrics: Arc<Metrics>,
}

impl ApiState {
    pub fn new(
        engine: Arc<RuleEngine>,
        sessions: Arc<SessionManager>,
        router: Arc<SubscriptionRouter>,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            engine,
            sessions,
            router,
            metrics,
        }
    }

    /// Standalone state for tests and tools (empty sessions/router).
    pub fn standalone(engine: Arc<RuleEngine>) -> Self {
        Self {
            engine,
            sessions: Arc::new(SessionManager::new()),
            router: Arc::new(SubscriptionRouter::new()),
            metrics: Arc::new(Metrics::new()),
        }
    }
}

pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "OK" }))
        .route("/api/v1/nodes", get(get_nodes))
        .route("/api/v1/clients", get(get_clients))
        .route("/api/v1/metrics", get(get_metrics))
        .route("/api/v1/rules", get(list_rules).post(create_rule))
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

fn node_id() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "local".to_string())
}

/// Node status, version, and live connection count.
async fn get_nodes(State(state): State<ApiState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "node_id": node_id(),
        "status": "running",
        "version": env!("CARGO_PKG_VERSION"),
        "connections": state.metrics.connections_active(),
    }))
}

/// Sorted ids of currently connected clients.
async fn get_clients(State(state): State<ApiState>) -> Json<Vec<String>> {
    Json(state.sessions.active_client_ids())
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
            let state = TestState {
                engine: engine.clone(),
                sessions: sessions.clone(),
                metrics: metrics.clone(),
            };
            let app = router(ApiState::new(engine, sessions, sub_router, metrics));
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
    async fn test_nodes_reports_status_version_connections() {        let (server, state) = TestServer::start().await;
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
}
