use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use broker_protocol::{QoS, Topic, TopicFilter};
use broker_rules::{Rule, RuleAction, RuleEngine};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Shared rule-engine handle injected into every rules endpoint.
#[derive(Clone)]
pub struct ApiState {
    pub engine: Arc<RuleEngine>,
}

impl ApiState {
    pub fn new(engine: Arc<RuleEngine>) -> Self {
        Self { engine }
    }
}

pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "OK" }))
        .route("/api/v1/metrics", get(|| async { "metrics_placeholder" }))
        .route("/api/v1/rules", get(list_rules).post(create_rule))
        .route(
            "/api/v1/rules/:id",
            get(get_rule).delete(delete_rule),
        )
        .with_state(state)
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
        }
    }

    let rule: Rule = state
        .engine
        .create_rule(req.name, topic_filter, req.sql_query, req.enabled, actions);
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

    impl TestServer {
        async fn start() -> (Self, Arc<RuleEngine>) {
            let engine = Arc::new(RuleEngine::new(
                16,
                broker_rules::BackpressurePolicy::DropOldest,
            ));
            let app = router(ApiState::new(engine.clone()));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind test server");
            let port = listener.local_addr().expect("local addr").port();
            let task = tokio::spawn(async move {
                axum::serve(listener, app).await.expect("serve test app");
            });
            (Self { port, task }, engine)
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
        let (server, _engine) = TestServer::start().await;
        let (status, text) = server
            .request_raw("GET /healthz HTTP/1.0\r\nHost: test\r\nConnection: close\r\n\r\n")
            .await;
        assert_eq!(status, 200);
        assert_eq!(text, "OK");
    }

    #[tokio::test]
    async fn test_rules_crud_lifecycle() {
        let (server, _engine) = TestServer::start().await;

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
        let (server, _engine) = TestServer::start().await;

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
}
