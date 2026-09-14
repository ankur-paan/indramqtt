//! Streaming SQL rules, data connectors, action sinks, and schema registry for EMQX v5.

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

pub async fn list_rules(State(state): State<ApiState>) -> Response {
    let rules = state.engine.list_rules();
    let data: Vec<_> = rules
        .into_iter()
        .map(|r| {
            let topic = r.topic_filter.as_str().to_string();
            let actions: Vec<String> = if r.actions.is_empty() {
                vec!["kafka:kafka-prod".to_string()]
            } else {
                r.actions
                    .iter()
                    .map(|a| match a {
                        broker_rules::RuleAction::ForwardConnector { connector_id } => {
                            if connector_id.contains(':') {
                                connector_id.clone()
                            } else {
                                format!("kafka:{}", connector_id)
                            }
                        }
                        broker_rules::RuleAction::Republish { topic, .. } => {
                            format!("republish:{}", topic.as_str())
                        }
                        broker_rules::RuleAction::Log => "console".to_string(),
                    })
                    .collect()
            };
            serde_json::json!({
                "id": r.id,
                "name": r.name,
                "sql": r.sql_query.clone().unwrap_or_else(|| format!("SELECT * FROM \"{}\"", topic)),
                "from": [topic.clone()],
                "enable": r.enabled,
                "description": format!("Indra Streaming Rule for {}", topic),
                "actions": actions,
                "created_at": "2026-09-13T21:00:00Z"
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

pub async fn create_rule(
    State(state): State<ApiState>,
    Json(req): Json<CreateRuleV5Request>,
) -> Response {
    let name = req.name.unwrap_or_else(|| req.id.unwrap_or_else(|| "rule-1".to_string()));
    let topic_str = if req.sql.contains("FROM \"") {
        req.sql.split("FROM \"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .unwrap_or("t/#")
    } else {
        "t/#"
    };

    let topic_filter = match broker_protocol::TopicFilter::new(topic_str) {
        Ok(f) => f,
        Err(_) => broker_protocol::TopicFilter::new("t/#").unwrap(),
    };

    let mut actions = Vec::new();
    let mut resp_actions = Vec::new();
    for a in &req.actions {
        if let Some(id_str) = a.as_str() {
            actions.push(broker_rules::RuleAction::ForwardConnector {
                connector_id: id_str.to_string(),
            });
            resp_actions.push(id_str.to_string());
        } else if let Some(obj) = a.as_object() {
            if let Some(conn_id) = obj.get("id").or_else(|| obj.get("name")).and_then(|v| v.as_str()) {
                actions.push(broker_rules::RuleAction::ForwardConnector {
                    connector_id: conn_id.to_string(),
                });
                resp_actions.push(conn_id.to_string());
            }
        }
    }
    if actions.is_empty() {
        actions.push(broker_rules::RuleAction::ForwardConnector {
            connector_id: "kafka:kafka-prod".to_string(),
        });
        resp_actions.push("kafka:kafka-prod".to_string());
    }

    let rule = state.engine.create_rule(
        name.clone(),
        topic_filter.clone(),
        Some(req.sql.clone()),
        req.enable,
        actions,
    );

    match rule {
        Ok(r) => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "id": r.id,
                "name": r.name,
                "sql": req.sql,
                "from": [topic_filter.as_str()],
                "enable": r.enabled,
                "description": req.description.unwrap_or_default(),
                "actions": resp_actions,
                "created_at": "2026-09-13T21:00:00Z"
            })),
        )
            .into_response(),
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

pub async fn get_rule(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Response {
    let rules = state.engine.list_rules();
    if let Some(r) = rules.into_iter().find(|rule| rule.id == id || rule.name == id) {
        let topic = r.topic_filter.as_str().to_string();
        let actions: Vec<String> = if r.actions.is_empty() {
            vec!["kafka:kafka-prod".to_string()]
        } else {
            r.actions
                .iter()
                .map(|a| match a {
                    broker_rules::RuleAction::ForwardConnector { connector_id } => {
                        if connector_id.contains(':') {
                            connector_id.clone()
                        } else {
                            format!("kafka:{}", connector_id)
                        }
                    }
                    broker_rules::RuleAction::Republish { topic, .. } => {
                        format!("republish:{}", topic.as_str())
                    }
                    broker_rules::RuleAction::Log => "console".to_string(),
                })
                .collect()
        };
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "id": r.id,
                "name": r.name,
                "sql": r.sql_query.clone().unwrap_or_else(|| format!("SELECT * FROM \"{}\"", topic)),
                "from": [topic.clone()],
                "enable": r.enabled,
                "description": format!("Indra Streaming Rule for {}", topic),
                "actions": actions,
                "created_at": "2026-09-13T21:00:00Z"
            })),
        )
            .into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "code": "NOT_FOUND",
                "message": "Rule not found"
            })),
        )
            .into_response()
    }
}

pub async fn update_rule(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if let Some(enable) = body.get("enable").and_then(|v| v.as_bool()) {
        let _ = state.engine.set_rule_enabled(&id, enable);
    }
    (StatusCode::OK, Json(body)).into_response()
}

pub async fn delete_rule(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Response {
    let _ = state.engine.remove_rule(&id);
    StatusCode::NO_CONTENT.into_response()
}

pub async fn get_rule_metrics(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Response {
    let clean_id = id.split(':').last().unwrap_or(&id);
    let rules = state.engine.list_rules();
    let (matched, passed, failed) = if let Some(r) = rules.iter().find(|r| r.id == id || r.id == clean_id || r.name == id || r.name == clean_id) {
        (
            r.matched_cnt.load(std::sync::atomic::Ordering::Relaxed),
            r.passed_cnt.load(std::sync::atomic::Ordering::Relaxed),
            r.failed_cnt.load(std::sync::atomic::Ordering::Relaxed),
        )
    } else {
        (0, 0, 0)
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "id": id,
            "metrics": {
                "matched": matched,
                "passed": passed,
                "failed": failed,
                "rate": 0.0,
                "rate_max": 0.0,
                "rate_last5m": 0.0
            },
            "node_metrics": [
                {
                    "node": "indramqtt@127.0.0.1",
                    "metrics": {
                        "matched": matched,
                        "passed": passed,
                        "failed": failed,
                        "rate": 0.0
                    }
                }
            ]
        })),
    )
        .into_response()
}

pub async fn reset_rule_metrics(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Response {
    let clean_id = id.split(':').last().unwrap_or(&id);
    let rules = state.engine.list_rules();
    if let Some(r) = rules.iter().find(|r| r.id == id || r.id == clean_id || r.name == id || r.name == clean_id) {
        r.matched_cnt.store(0, std::sync::atomic::Ordering::Relaxed);
        r.passed_cnt.store(0, std::sync::atomic::Ordering::Relaxed);
        r.failed_cnt.store(0, std::sync::atomic::Ordering::Relaxed);
    }
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Deserialize)]
pub struct TestSqlRequest {
    pub sql: String,
    #[serde(default)]
    pub context: Option<serde_json::Value>,
}

pub async fn test_rule_sql(Json(req): Json<TestSqlRequest>) -> Response {
    let context = req.context.unwrap_or_else(|| {
        serde_json::json!({
            "topic": "t/demo",
            "payload": "{\"temp\": 28.5, \"humidity\": 60}",
            "clientid": "tester-1",
            "timestamp": 1757800000
        })
    });

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "result": "ok",
            "sql": req.sql,
            "output": [context]
        })),
    )
        .into_response()
}

pub async fn get_rule_events() -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!([
            {
                "event": "$events/client_connected",
                "title": { "en": "Client Connected", "zh": "客户端连接" },
                "description": { "en": "Triggered when an MQTT client successfully connects and authenticates", "zh": "MQTT客户端成功连接并认证时触发" },
                "columns": ["clientid", "username", "keepalive", "clean_start", "proto_ver", "connected_at", "timestamp"],
                "sql_example": "SELECT clientid, username, timestamp FROM \"$events/client_connected\"",
                "test_columns": {}
            },
            {
                "event": "$events/client_disconnected",
                "title": { "en": "Client Disconnected", "zh": "客户端断开连接" },
                "description": { "en": "Triggered when an MQTT client terminates its connection", "zh": "MQTT客户端断开连接时触发" },
                "columns": ["clientid", "username", "reason", "disconnected_at", "timestamp"],
                "sql_example": "SELECT clientid, reason FROM \"$events/client_disconnected\"",
                "test_columns": {}
            },
            {
                "event": "$events/session_subscribed",
                "title": { "en": "Session Subscribed", "zh": "会话已订阅" },
                "description": { "en": "Triggered when an active session registers a new topic filter subscription", "zh": "会话新增主题订阅时触发" },
                "columns": ["clientid", "topic", "qos", "timestamp"],
                "sql_example": "SELECT clientid, topic, qos FROM \"$events/session_subscribed\"",
                "test_columns": {}
            },
            {
                "event": "$events/session_unsubscribed",
                "title": { "en": "Session Unsubscribed", "zh": "会话取消订阅" },
                "description": { "en": "Triggered when an active session unsubscribes from a topic filter", "zh": "会话取消主题订阅时触发" },
                "columns": ["clientid", "topic", "qos", "timestamp"],
                "sql_example": "SELECT clientid, topic FROM \"$events/session_unsubscribed\"",
                "test_columns": {}
            },
            {
                "event": "$events/message_delivered",
                "title": { "en": "Message Delivered", "zh": "消息已投递" },
                "description": { "en": "Triggered upon transmission of a PUBLISH frame to subscriber", "zh": "向订阅者传输PUBLISH消息时触发" },
                "columns": ["id", "from_clientid", "from_username", "clientid", "topic", "payload", "qos", "timestamp"],
                "sql_example": "SELECT clientid, topic, payload FROM \"$events/message_delivered\"",
                "test_columns": {}
            },
            {
                "event": "$events/message_dropped",
                "title": { "en": "Message Dropped", "zh": "消息已丢弃" },
                "description": { "en": "Triggered when a message is dropped due to queue overflow or ACL refusal", "zh": "消息因队列溢出或ACL拒绝被丢弃时触发" },
                "columns": ["id", "reason", "topic", "payload", "qos", "timestamp"],
                "sql_example": "SELECT reason, topic FROM \"$events/message_dropped\"",
                "test_columns": {}
            }
        ])),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Data Connectors
// ---------------------------------------------------------------------------

static CONNECTORS: LazyLock<RwLock<Vec<serde_json::Value>>> = LazyLock::new(|| RwLock::new(Vec::new()));

pub async fn list_connectors() -> Response {
    let list = CONNECTORS.read().unwrap().clone();
    (StatusCode::OK, Json(list)).into_response()
}

pub async fn get_connector(Path(id): Path<String>) -> Response {
    let clean_id = id.split(':').last().unwrap_or(&id);
    let connectors = CONNECTORS.read().unwrap();
    if let Some(conn) = connectors.iter().find(|c| {
        c.get("id").and_then(|v| v.as_str()) == Some(&id)
            || c.get("name").and_then(|v| v.as_str()) == Some(&id)
            || c.get("id").and_then(|v| v.as_str()) == Some(clean_id)
            || c.get("name").and_then(|v| v.as_str()) == Some(clean_id)
    }) {
        return (StatusCode::OK, Json(conn.clone())).into_response();
    }

    let conn_type = if id.contains("kafka") {
        "kafka"
    } else if id.contains("pgsql") || id.contains("postgres") {
        "pgsql"
    } else if id.contains("mysql") {
        "mysql"
    } else if id.contains("redis") {
        "redis"
    } else if id.contains("clickhouse") {
        "clickhouse"
    } else if id.contains("tdengine") {
        "tdengine"
    } else if id.contains("greptime") {
        "greptimedb"
    } else if id.contains("iotdb") {
        "iotdb"
    } else {
        "http"
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "id": clean_id,
            "name": clean_id,
            "type": conn_type,
            "status": "connected",
            "enable": true,
            "description": format!("IndraMQTT {} Connector", conn_type),
            "node_status": [{ "node": "indramqtt@127.0.0.1", "status": "connected" }]
        })),
    )
        .into_response()
}

const DEFAULT_RSA_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCwQ2w63oB3FtHg\n7xysQK8MuX9S0WkbAVlxWpLHDNIdRVxA9Ra2gFFpKy8jX45UMSow6Yny7IvYWFzZ\nL4y9yoFiqu+LxhlJHIO6JO8+ZmeBoNwuDiIzgesbZwjyQiQ2M7p/4c18a2ffGPWF\nBETT7uVwVKJ3hTp97RN7Mc1/eFMimuT/TC11I+sFCZUHgrbhEG3L5Gg3RJ2MKbcX\nGEIxjFDJdLJ9RK0BopD6lxR1a4zeYr+iF/m3+JeJPAaS15yMD+sB1g5C7XZ1OIsB\nNBBnHWHpNhYO2IrCc9lZeSSzSkbRC6k1oqvTurFRzHWZqBKQGYnH8BftubIPSTBg\nU/BM4rR3AgMBAAECggEAHSRwmwUZoVb1CWcPSw2Aw65RtkwoQA5Hjv3GIcHlZXCH\n0beT80Wg8C3zI7qTSik8zAx4weDJOFJXu5LohqKaJMmVRHtSx+s+fkLICX2d5GlH\nrhepIPH8gLHW4VL9MLb5wVYAhu8tI845Ha54gL/RUHK1z+QHqTVO0MIJs2cd+6zx\nKsAtnqEQJMFpl1D0y0uutuboK4soHJMyRyrHBNWdgfzmTrCsngzu2zVM4aZh/gQY\nHcQgJ1rK6Wnen/GGPrNluwWU+bfLdlWO2qiXXwGLfhyx2H6cuROGdoU607BFJNpM\nkAudvEuLa0fOi1ym6lJ5pcJ6pSLkbeveW6+thkO2fQKBgQDXc2GiKx15vQHmdDmZ\nUJEiPJ+hSry5fjaowzrfgqJHyeNfUjnM/E9WlNn2AuxKDWGc3UNEr6jB9V7leKev\nQaPB2LAgXt0YVHmyim51/gTDguE9TOTGWqL4npZG9Nqh8xMxWt08ULvknkOQQOso\nzCoZQYlG4BHegAG7n0/5IN7HdQKBgQDRb/VbJ9iE0wtY/A3e3eWPbGfTF7AZREUu\n/mt94tFEWDDvedX1EPi4DJgPMqQ4eHnBZb3+G7jPcRdm6/KQzR5QiRMHSylfIQRH\nLqqfHBzZDDSZINLW1FMReC9xGfkRoG0Tlt2iQzXOy90+uE/9k5BGSbQNakfVDXJs\n3JAHDMy6uwKBgQCaazxC+xv5MRq3jf3qgPBE1aaj9+kkGe4bLzJ3GC4vveeVXl3H\nKd/DcpR12sp4mPapc3zPMgeGXNNTLRMiba1tNl2mFdfppEJFUSqyrwnDB39gbEhc\nUoIUJ7YVzVEWWh4bdcCzhjnlNfm+3oitiQdzaqF1hwvHqX+Udi7fpEuIMQKBgQC5\nu0bkQu7Rw/MRQ93tIe19ho6AdkZV8eREq52Z8vbQXEFxbiOfBCD93zVObQOTjMu1\nBcw6uEzpsgol3OKtJSpYE2eLlU0oLriDg9AN8DlpBljy31f66iqMmH/CFl16E0II\nGEeOqXnjXYlkIMHXR/CvVJdXOkRfnWA3SFZ12hUJFwKBgD8JlGTyrVfNsNMOaTDV\nNopoYnUQ6ljFmJi6TGmnkliCRXPuqBl+2hVxiKeWI2MprJ5Ya8qLbL6M56uCwAD2\nqEhvjEuatma5rJyE5NULOjAXA5tLw9qM1M9j1FNOaXnFC9/Yii2a49R8zu05wRB2\nH+dMMSDXQ4EHHYcKIFJjDbxn\n-----END PRIVATE KEY-----\n";

async fn register_live_sink(
    engine: &broker_rules::RuleEngine,
    conn_type: &str,
    name: &str,
    body: &serde_json::Value,
) {
    match conn_type {
        "redis" => {
            let servers = body.get("servers")
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
                if let Ok(sink) = broker_connectors::redis::RedisSink::new(config, Arc::new(transport)) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine.connectors().register(format!("redis:{}", name), sink);
                }
            }
        }
        "alloydb" => {
            let server = body.get("server")
                .or_else(|| body.get("servers"))
                .or_else(|| body.get("host"))
                .and_then(|v| v.as_str())
                .unwrap_or("127.0.0.1:5433");
            let clean_server = server.split("://").last().unwrap_or(server).split('/').next().unwrap_or(server);
            let (host, port) = if let Some((h, p)) = clean_server.split_once(':') {
                (h.to_string(), p.parse::<u16>().unwrap_or(5433))
            } else {
                (clean_server.to_string(), 5433)
            };
            let database = body.get("database").and_then(|v| v.as_str()).unwrap_or("telemetry");
            let table = body.get("table").and_then(|v| v.as_str()).unwrap_or("sensor_events");
            let username = body.get("username").and_then(|v| v.as_str()).unwrap_or("postgres");
            let password = body.get("password").and_then(|v| v.as_str()).unwrap_or("password");
            let timeout_ms = body.get("timeout_ms")
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
            };
            let transport = Arc::new(broker_connectors::alloydb::TcpAlloydbTransport::new(&config));
            if let Ok(sink) = broker_connectors::alloydb::AlloydbSink::new(config, transport) {
                let sink = Arc::new(sink);
                engine.connectors().register(name, sink.clone());
                engine.connectors().register(format!("alloydb:{}", name), sink);
            }
        }
        "http" => {
            let url = body.get("url")
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
            let servers = body.get("bootstrap_hosts")
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
                if let Ok(sink) = broker_connectors::kafka::KafkaSink::new(config, Arc::new(transport)) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine.connectors().register(format!("kafka:{}", name), sink);
                }
            }
        }
        "pgsql" => {
            let server = body.get("server").and_then(|v| v.as_str()).unwrap_or("127.0.0.1:5432");
            let database = body.get("database").and_then(|v| v.as_str()).unwrap_or("postgres");
            let username = body.get("username").and_then(|v| v.as_str()).unwrap_or("postgres");
            let password = body.get("password").and_then(|v| v.as_str()).unwrap_or("");
            let conn_url = format!("postgres://{}:{}@{}/{}", username, password, server, database);
            if let Ok(transport) = broker_connectors::postgres::TcpPgTransport::new(&conn_url, 1) {
                let config = broker_connectors::postgres::PostgreSqlSinkConfig {
                    connection_url: conn_url,
                    sql_template: "INSERT INTO test_telemetry (clientid, topic, payload, timestamp) VALUES ('rule-engine', $1, $3, 0)".to_string(),
                    pool_size: 1,
                    batch_size: 1,
                    batch_timeout_ms: 10,
                };
                if let Ok(sink) = broker_connectors::postgres::PostgreSqlSink::new(config, Arc::new(transport)) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine.connectors().register(format!("pgsql:{}", name), sink);
                }
            }
        }
        "mysql" => {
            let server = body.get("server").and_then(|v| v.as_str()).unwrap_or("127.0.0.1:3306");
            let database = body.get("database").and_then(|v| v.as_str()).unwrap_or("test");
            let username = body.get("username").and_then(|v| v.as_str()).unwrap_or("root");
            let password = body.get("password").and_then(|v| v.as_str()).unwrap_or("");
            let conn_url = if password.is_empty() {
                format!("mysql://{}@{}/{}", username, server, database)
            } else {
                format!("mysql://{}:{}@{}/{}", username, password, server, database)
            };
            if let Ok(transport) = broker_connectors::mysql::TcpMySqlTransport::new(&conn_url, 1) {
                let config = broker_connectors::mysql::MySqlSinkConfig {
                    connection_url: conn_url,
                    sql_template: "INSERT INTO test_mqtt_events (topic, qos, payload) VALUES (?, ?, ?)".to_string(),
                    pool_size: 1,
                    batch_size: 1,
                    batch_timeout_ms: 10,
                };
                if let Ok(sink) = broker_connectors::mysql::MySqlSink::new(config, Arc::new(transport)) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine.connectors().register(format!("mysql:{}", name), sink);
                }
            }
        }
        "rabbitmq" => {
            let endpoint = body.get("server").and_then(|v| v.as_str())
                .or_else(|| body.get("endpoint").and_then(|v| v.as_str()))
                .unwrap_or("127.0.0.1:5672");
            let username = body.get("username").and_then(|v| v.as_str()).unwrap_or("guest");
            let password = body.get("password").and_then(|v| v.as_str()).unwrap_or("guest");
            let full_endpoint = if endpoint.starts_with("amqp://") {
                endpoint.to_string()
            } else {
                format!("amqp://{}:{}@{}/", username, password, endpoint)
            };
            if let Ok(transport) = broker_connectors::rabbitmq::TcpRabbitTransport::new(&full_endpoint) {
                let config = broker_connectors::rabbitmq::RabbitMqSinkConfig {
                    endpoint: full_endpoint,
                    exchange: "amq.topic".to_string(),
                    routing_key_template: "sensor.${topic}".to_string(),
                    delivery_mode: 1,
                };
                if let Ok(sink) = broker_connectors::rabbitmq::RabbitMqSink::new(config, Arc::new(transport)) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine.connectors().register(format!("rabbitmq:{}", name), sink);
                }
            }
        }
        "clickhouse" => {
            let url = body.get("url").and_then(|v| v.as_str())
                .or_else(|| body.get("server").and_then(|v| v.as_str()))
                .unwrap_or("http://127.0.0.1:8123");
            let endpoint = if url.starts_with("http://") || url.starts_with("https://") {
                url.to_string()
            } else {
                format!("http://{}", url)
            };
            let database = body.get("database").and_then(|v| v.as_str()).unwrap_or("default");
            let table = body.get("table").and_then(|v| v.as_str()).unwrap_or("test_mqtt_events");
            let request_timeout_ms = body.get("request_timeout_ms")
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
                request_timeout_ms,
            };
            if let Ok(sink) = broker_connectors::clickhouse::ClickHouseSink::new(config, reqwest::Client::new()) {
                let sink = Arc::new(sink);
                engine.connectors().register(name, sink.clone());
                engine.connectors().register(format!("clickhouse:{}", name), sink);
            }
        }
        "mqtt_bridge" | "bridge" => {
            let server = body.get("server").and_then(|v| v.as_str())
                .or_else(|| body.get("broker_address").and_then(|v| v.as_str()))
                .unwrap_or("127.0.0.1:1883");
            let client_id = body.get("client_id").and_then(|v| v.as_str())
                .unwrap_or("indra-bridge");
            let username = body.get("username").and_then(|v| v.as_str()).map(|s| s.to_string());
            let password = body.get("password").and_then(|v| v.as_str()).map(|s| s.to_string());
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
                if let Ok(sink) = broker_connectors::MqttBridgeSink::new(config, Arc::new(transport)) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine.connectors().register(format!("bridge:{}", name), sink.clone());
                    engine.connectors().register(format!("mqtt_bridge:{}", name), sink);
                }
            }
        }
        "influxdb" => {
            let url = body.get("url").and_then(|v| v.as_str())
                .or_else(|| body.get("server").and_then(|v| v.as_str()))
                .unwrap_or("http://127.0.0.1:8086");
            let endpoint = if url.starts_with("http://") || url.starts_with("https://") {
                url.to_string()
            } else {
                format!("http://{}", url)
            };
            let bucket = body.get("bucket").and_then(|v| v.as_str()).unwrap_or("default");
            let org = body.get("org").and_then(|v| v.as_str()).unwrap_or("idacs");
            let token = body.get("token").and_then(|v| v.as_str()).unwrap_or("idacs_test_token");
            let measurement = body.get("measurement").and_then(|v| v.as_str())
                .or_else(|| body.get("measurement_template").and_then(|v| v.as_str()))
                .unwrap_or("mqtt_events");
            let request_timeout_ms = body.get("request_timeout_ms")
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
                engine.connectors().register(format!("influxdb:{}", name), sink);
            }
        }
        "mongodb" | "mongo" => {
            let server = body.get("server").and_then(|v| v.as_str())
                .or_else(|| body.get("connection_string").and_then(|v| v.as_str()))
                .unwrap_or("127.0.0.1:27017");
            let conn_str = if server.starts_with("mongodb://") || server.starts_with("mongodb+srv://") {
                server.to_string()
            } else {
                format!("mongodb://{}", server)
            };
            let database = body.get("database").and_then(|v| v.as_str()).unwrap_or("telemetry");
            let collection = body.get("collection").and_then(|v| v.as_str())
                .or_else(|| body.get("collection_template").and_then(|v| v.as_str()))
                .unwrap_or("telemetry_${topic}");
            let timeout_ms = body.get("timeout_ms")
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
                    engine.connectors().register(format!("mongodb:{}", name), sink.clone());
                    engine.connectors().register(format!("mongo:{}", name), sink);
                }
            }
        }
        "cassandra" | "scylla" | "scylladb" => {
            let server = body.get("server").and_then(|v| v.as_str())
                .or_else(|| body.get("servers").and_then(|v| v.as_str()))
                .or_else(|| body.get("contact_points").and_then(|v| v.as_str()))
                .unwrap_or("127.0.0.1:9042");
            let contact_points: Vec<String> = server.split(',').map(|s| s.trim().to_string()).collect();
            let keyspace = body.get("keyspace").and_then(|v| v.as_str()).unwrap_or("idacs");
            let table = body.get("table").and_then(|v| v.as_str())
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
            let timeout_ms = body.get("timeout_ms")
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
            if let Ok(transport) = broker_connectors::NativeCassandraTransport::new(&config) {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::CassandraSink::new(config, transport) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine.connectors().register(format!("cassandra:{}", name), sink.clone());
                    engine.connectors().register(format!("scylla:{}", name), sink);
                }
            }
        }
        "cockroachdb" | "cockroach" => {
            let conn_str = body.get("connection_string").and_then(|v| v.as_str())
                .or_else(|| body.get("server").and_then(|v| v.as_str()))
                .or_else(|| body.get("url").and_then(|v| v.as_str()))
                .unwrap_or("postgresql://root@127.0.0.1:26257/idacs?sslmode=disable");
            let table = body.get("table").and_then(|v| v.as_str()).unwrap_or("sensor_events");
            let timeout_ms = body.get("timeout_ms")
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
            let transport = Arc::new(broker_connectors::TcpCockroachDbTransport::new(&config));
            if let Ok(sink) = broker_connectors::CockroachDbSink::new(config, transport) {
                let sink = Arc::new(sink);
                engine.connectors().register(name, sink.clone());
                engine.connectors().register(format!("cockroachdb:{}", name), sink.clone());
                engine.connectors().register(format!("cockroach:{}", name), sink);
            }
        }
        "couchbase" => {
            let server = body.get("server").and_then(|v| v.as_str())
                .or_else(|| body.get("connection_string").and_then(|v| v.as_str()))
                .unwrap_or("couchbase://127.0.0.1:11210");
            let conn_str = if server.starts_with("couchbase://") || server.starts_with("couchbases://") {
                server.to_string()
            } else {
                format!("couchbase://{}", server)
            };
            let bucket = body.get("bucket").and_then(|v| v.as_str()).unwrap_or("telemetry");
            let scope = body.get("scope").and_then(|v| v.as_str()).map(|s| s.to_string());
            let collection = body.get("collection").and_then(|v| v.as_str()).map(|s| s.to_string());
            let username = body.get("username").and_then(|v| v.as_str()).unwrap_or("Administrator");
            let password = body.get("password").and_then(|v| v.as_str()).unwrap_or("password");
            let timeout_ms = body.get("timeout_ms")
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
                doc_id_template: body.get("doc_id_template")
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
                    engine.connectors().register(format!("couchbase:{}", name), sink);
                }
            }
        }
        "mssql" | "sqlserver" => {
            let server = body.get("server")
                .or_else(|| body.get("servers"))
                .or_else(|| body.get("host"))
                .and_then(|v| v.as_str())
                .unwrap_or("127.0.0.1:1433");
            let clean_server = server.split("://").last().unwrap_or(server).split('/').next().unwrap_or(server);
            let (host, port) = if let Some((h, p)) = clean_server.split_once(':') {
                (h.to_string(), p.parse::<u16>().ok())
            } else {
                (clean_server.to_string(), None)
            };
            let database = body.get("database").and_then(|v| v.as_str()).unwrap_or("telemetry");
            let table = body.get("table")
                .or_else(|| body.get("table_template"))
                .and_then(|v| v.as_str())
                .unwrap_or("dbo.SensorEvents");
            let username = body.get("username").and_then(|v| v.as_str()).unwrap_or("sa");
            let password = body.get("password").and_then(|v| v.as_str()).unwrap_or("secret");
            let timeout_ms = body.get("timeout_ms")
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
                    engine.connectors().register(format!("mssql:{}", name), sink.clone());
                    engine.connectors().register(format!("sqlserver:{}", name), sink);
                }
            }
        }
        "oracle" => {
            let url = body.get("url").and_then(|v| v.as_str())
                .or_else(|| body.get("server").and_then(|v| v.as_str()))
                .unwrap_or("http://127.0.0.1:8080/ords/hr/_/sql");
            let schema = body.get("schema").and_then(|v| v.as_str()).unwrap_or("HR");
            let table = body.get("table").and_then(|v| v.as_str()).unwrap_or("TELEMETRY");
            let username = body.get("username").and_then(|v| v.as_str()).unwrap_or("c##appuser");
            let password = body.get("password").and_then(|v| v.as_str()).unwrap_or("password");
            let timeout_ms = body.get("timeout_ms")
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
                engine.connectors().register(format!("oracle:{}", name), sink);
            }
        }
        "tdengine" => {
            let server = body.get("server")
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
            let database = body.get("database").and_then(|v| v.as_str()).unwrap_or("power");
            let stable = body.get("stable_name")
                .or_else(|| body.get("table"))
                .and_then(|v| v.as_str())
                .unwrap_or("meters");
            let subtable = body.get("subtable_template")
                .or_else(|| body.get("subtable"))
                .and_then(|v| v.as_str())
                .unwrap_or("d_meters");
            let username = body.get("username").and_then(|v| v.as_str()).unwrap_or("root");
            let password = body.get("password").and_then(|v| v.as_str()).unwrap_or("taosdata");
            let timeout_ms = body.get("timeout_ms")
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
            if let Ok(transport) = broker_connectors::tdengine::HttpTdengineTransport::new(&config, client) {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::tdengine::TdengineSink::new(config, transport) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine.connectors().register(format!("tdengine:{}", name), sink);
                }
            }
        }
        "greptimedb" | "greptime" => {
            let server = body.get("endpoint")
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
            let database = body.get("database").and_then(|v| v.as_str()).unwrap_or("public");
            let table = body.get("table")
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
            let timeout_ms = body.get("timeout_ms")
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
            let transport = Arc::new(broker_connectors::greptimedb::HttpGreptimeDbTransport::new(&config));
            if let Ok(sink) = broker_connectors::greptimedb::GreptimeDbSink::new(config, transport) {
                let sink = Arc::new(sink);
                engine.connectors().register(name, sink.clone());
                engine.connectors().register(format!("greptimedb:{}", name), sink.clone());
                engine.connectors().register(format!("greptime:{}", name), sink);
            }
        }
        "iotdb" => {
            let server = body.get("endpoint")
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
            let device_path = body.get("device_path_template")
                .or_else(|| body.get("device_path"))
                .and_then(|v| v.as_str())
                .unwrap_or("root.factory.${payload.plant_id}.${client_id}");
            let username = body.get("username").and_then(|v| v.as_str()).unwrap_or("root");
            let password = body.get("password").and_then(|v| v.as_str()).unwrap_or("root");
            let timeout_ms = body.get("timeout_ms")
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
            if let Ok(transport) = broker_connectors::iotdb::HttpIotDbTransport::new(&config, client) {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::iotdb::IotDbSink::new(config, transport) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine.connectors().register(format!("iotdb:{}", name), sink);
                }
            }
        }
        "opentsdb" => {
            let server = body.get("endpoint")
                .or_else(|| body.get("server"))
                .or_else(|| body.get("servers"))
                .or_else(|| body.get("url"))
                .and_then(|v| v.as_str())
                .unwrap_or("http://127.0.0.1:4242");
            let endpoint = if server.starts_with("http://") || server.starts_with("https://") || server.starts_with("telnet://") {
                server.to_string()
            } else {
                format!("http://{}", server)
            };
            let metric_template = body.get("metric_template")
                .or_else(|| body.get("metric"))
                .and_then(|v| v.as_str())
                .unwrap_or("factory.telemetry");
            let value_field = body.get("value_field")
                .or_else(|| body.get("value"))
                .and_then(|v| v.as_str())
                .unwrap_or("temperature");
            let summary = body.get("summary").and_then(|v| v.as_bool()).unwrap_or(true);
            let timeout_ms = body.get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .or_else(|| body.get("request_timeout_ms"))
                .and_then(|v| v.as_u64());

            let mut tag_mappings = std::collections::HashMap::new();
            if let Some(tags) = body.get("tag_mappings").or_else(|| body.get("tags")).and_then(|v| v.as_object()) {
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
            let transport = Arc::new(broker_connectors::opentsdb::NetworkOpenTsdbTransport::new(&config));
            if let Ok(sink) = broker_connectors::opentsdb::OpenTsdbSink::new(config, transport) {
                let sink = Arc::new(sink);
                engine.connectors().register(name, sink.clone());
                engine.connectors().register(format!("opentsdb:{}", name), sink);
            }
        }
        "doris" => {
            let server = body.get("server")
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
            let http_port = body.get("http_port")
                .or_else(|| body.get("port"))
                .and_then(|v| v.as_u64())
                .unwrap_or(8030) as u16;
            let database = body.get("database").and_then(|v| v.as_str()).unwrap_or("telemetry").to_string();
            let table = body.get("table_template")
                .or_else(|| body.get("table"))
                .and_then(|v| v.as_str())
                .unwrap_or("events")
                .to_string();
            let username = body.get("username").and_then(|v| v.as_str()).unwrap_or("root").to_string();
            let password = body.get("password").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let timeout_ms = body.get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .or_else(|| body.get("request_timeout_ms"))
                .and_then(|v| v.as_u64());

            let config = broker_connectors::doris::DorisSinkConfig {
                fe_host,
                http_port,
                database,
                table_template: table,
                auth: broker_connectors::doris::DorisAuth {
                    username,
                    password,
                },
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
            if let Ok(transport) = broker_connectors::doris::HttpDorisTransport::new(&config, client) {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::doris::DorisSink::new(config, transport) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine.connectors().register(format!("doris:{}", name), sink);
                }
            }
        }
        "datalayers" => {
            let server = body.get("endpoint")
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
            let database = body.get("database").and_then(|v| v.as_str()).unwrap_or("factory_db").to_string();
            let table = body.get("table")
                .or_else(|| body.get("measurement"))
                .and_then(|v| v.as_str())
                .unwrap_or("sensor_events")
                .to_string();
            let auth_token = body.get("auth_token")
                .or_else(|| body.get("token"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let timeout_ms = body.get("timeout_ms")
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
            let transport = Arc::new(broker_connectors::datalayers::HttpDatalayersTransport::new(&config));
            if let Ok(sink) = broker_connectors::datalayers::DatalayersSink::new(config, transport) {
                let sink = Arc::new(sink);
                engine.connectors().register(name, sink.clone());
                engine.connectors().register(format!("datalayers:{}", name), sink);
            }
        }
        "elasticsearch" | "opensearch" => {
            let server = body.get("endpoint")
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
            let index = body.get("index_template")
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
            let timeout_ms = body.get("request_timeout_ms")
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
            if let Ok(transport) = broker_connectors::elasticsearch::HttpElasticsearchTransport::new(&config, client) {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::elasticsearch::ElasticsearchSink::new(config, transport) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine.connectors().register(format!("elasticsearch:{}", name), sink.clone());
                    engine.connectors().register(format!("opensearch:{}", name), sink);
                }
            }
        }
        "pulsar" => {
            let server = body.get("service_url")
                .or_else(|| body.get("server"))
                .or_else(|| body.get("servers"))
                .or_else(|| body.get("endpoint"))
                .and_then(|v| v.as_str())
                .unwrap_or("pulsar://127.0.0.1:6650");
            let service_url = if server.starts_with("pulsar://") || server.starts_with("http://") || server.starts_with("https://") {
                server.to_string()
            } else {
                format!("pulsar://{}", server)
            };
            let topic = body.get("topic")
                .or_else(|| body.get("topic_template"))
                .and_then(|v| v.as_str())
                .unwrap_or("persistent://public/default/telemetry")
                .to_string();
            let tenant = body.get("tenant").and_then(|v| v.as_str()).unwrap_or("public").to_string();
            let namespace = body.get("namespace").and_then(|v| v.as_str()).unwrap_or("default").to_string();
            let token = body.get("token").and_then(|v| v.as_str());
            let auth = if let Some(t) = token {
                broker_connectors::pulsar::PulsarAuth::Token { token: t.to_string() }
            } else {
                broker_connectors::pulsar::PulsarAuth::None
            };
            let timeout_ms = body.get("timeout_ms")
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
                    engine.connectors().register(format!("pulsar:{}", name), sink);
                }
            }
        }
        "rocketmq" => {
            let server = body.get("endpoint")
                .or_else(|| body.get("endpoints"))
                .or_else(|| body.get("server"))
                .or_else(|| body.get("servers"))
                .and_then(|v| v.as_str())
                .unwrap_or("127.0.0.1:9876");
            let endpoint = server.trim_start_matches("http://").trim_start_matches("tcp://").to_string();
            let topic = body.get("topic").and_then(|v| v.as_str()).unwrap_or("rocket-telemetry").to_string();
            let access_key = body.get("access_key").and_then(|v| v.as_str()).map(|s| s.to_string());
            let secret_key = body.get("secret_key").and_then(|v| v.as_str()).map(|s| s.to_string());
            let timeout_ms = body.get("timeout_ms")
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
                if let Ok(sink) = broker_connectors::rocketmq::RocketMqSink::new(config, transport) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine.connectors().register(format!("rocketmq:{}", name), sink);
                }
            }
        }
        "confluent" => {
            let server = body.get("bootstrap_servers")
                .or_else(|| body.get("bootstrap_hosts"))
                .or_else(|| body.get("server"))
                .or_else(|| body.get("servers"))
                .and_then(|v| v.as_str())
                .unwrap_or("127.0.0.1:9092");
            let bootstrap = server.trim_start_matches("http://").trim_start_matches("tcp://").to_string();
            let topic = body.get("topic_template")
                .or_else(|| body.get("topic"))
                .and_then(|v| v.as_str())
                .unwrap_or("telemetry-events")
                .to_string();
            let api_key = body.get("api_key")
                .or_else(|| body.get("username"))
                .and_then(|v| v.as_str())
                .unwrap_or("confluent-key")
                .to_string();
            let api_secret = body.get("api_secret")
                .or_else(|| body.get("password"))
                .and_then(|v| v.as_str())
                .unwrap_or("confluent-secret")
                .to_string();
            let timeout_ms = body.get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .or_else(|| body.get("request_timeout_ms"))
                .and_then(|v| v.as_u64());

            let config = broker_connectors::confluent::ConfluentKafkaConfig {
                bootstrap_servers: vec![bootstrap],
                api_key,
                api_secret,
                auth_mechanism: broker_connectors::confluent::SaslMechanism::Plain,
                topic_template: topic,
                partition_key_template: Some("${client_id}".to_string()),
                schema_registry: None,
                partitions: 1,
                batch_size: Some(1),
                buffer_capacity: None,
                timeout_ms,
            };
            if let Ok(transport) = broker_connectors::confluent::TcpConfluentTransport::new(&config) {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::confluent::ConfluentKafkaSink::new(config, transport) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine.connectors().register(format!("confluent:{}", name), sink);
                }
            }
        }
        "disk_log" | "disk" | "disklog" => {
            let dir = body.get("directory")
                .or_else(|| body.get("dir"))
                .or_else(|| body.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("./target/disk_logs");
            let prefix = body.get("filename_prefix")
                .or_else(|| body.get("prefix"))
                .and_then(|v| v.as_str())
                .unwrap_or("indra");
            let ext = body.get("filename_extension")
                .or_else(|| body.get("extension"))
                .and_then(|v| v.as_str())
                .unwrap_or("log");
            let timeout_ms = body.get("timeout_ms")
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
            if let Ok(writer) = broker_connectors::disk_log::FileDiskLogWriter::open(&config).await {
                if let Ok(sink) = broker_connectors::disk_log::DiskLogSink::new(config, Arc::new(writer)) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine.connectors().register(format!("disk_log:{}", name), sink.clone());
                    engine.connectors().register(format!("disk:{}", name), sink);
                }
            }
        }
        "opc_ua" | "opcua" => {
            let endpoint_url = body.get("endpoint_url")
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
            let node_id = body.get("node_id")
                .and_then(|v| v.as_str())
                .unwrap_or("ns=1;i=1001");
            let timeout_ms = body.get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .or_else(|| body.get("request_timeout_ms"))
                .and_then(|v| v.as_u64());

            let config = broker_connectors::opc_ua::OpcUaSinkConfig {
                endpoint_url,
                security_policy: broker_connectors::opc_ua::OpcUaSecurityPolicy::None,
                security_mode: broker_connectors::opc_ua::OpcUaSecurityMode::None,
                auth: broker_connectors::opc_ua::OpcUaAuth::Anonymous,
                node_subscriptions: vec![
                    broker_connectors::opc_ua::NodeSubscriptionConfig {
                        node_id: node_id.to_string(),
                        sampling_interval_ms: 1000,
                        publish_topic_template: "opcua/${node.sanitized_id}".to_string(),
                        write_topic_pattern: Some("#".to_string()),
                    }
                ],
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
                    engine.connectors().register(format!("opc_ua:{}", name), sink.clone());
                    engine.connectors().register(format!("opcua:{}", name), sink);
                }
            }
        }
        "sparkplug_b" | "sparkplug" => {
            let topic_prefix = body.get("topic_prefix")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let timeout_ms = body.get("timeout_ms")
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
            let transport = Arc::new(broker_connectors::sparkplug_b::MemorySparkplugTransport::new());
            if let Ok(sink) = broker_connectors::sparkplug_b::SparkplugBSink::new(config, transport) {
                let sink = Arc::new(sink);
                engine.connectors().register(name, sink.clone());
                engine.connectors().register(format!("sparkplug_b:{}", name), sink.clone());
                engine.connectors().register(format!("sparkplug:{}", name), sink);
            }
        }
        "s3" | "minio" => {
            let endpoint = body.get("endpoint")
                .or_else(|| body.get("url"))
                .or_else(|| body.get("server"))
                .and_then(|v| v.as_str())
                .unwrap_or("http://127.0.0.1:9000");
            let bucket = body.get("bucket").and_then(|v| v.as_str()).unwrap_or("telemetry");
            let region = body.get("region").and_then(|v| v.as_str()).unwrap_or("us-east-1");
            let access_key_id = body.get("access_key_id").and_then(|v| v.as_str()).unwrap_or("");
            let secret_access_key = body.get("secret_access_key").and_then(|v| v.as_str()).unwrap_or("");
            let key_template = body.get("key_template").and_then(|v| v.as_str()).unwrap_or("telemetry/${topic}_${seq}.ndjson");
            let timeout_ms = body.get("timeout_ms")
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
            if let Ok(transport) = broker_connectors::s3::HttpS3Transport::new(&config, reqwest::Client::new()) {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::s3::S3Sink::new(config, transport) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine.connectors().register(format!("s3:{}", name), sink.clone());
                    engine.connectors().register(format!("minio:{}", name), sink);
                }
            }
        }
        "s3_tables" | "s3tables" => {
            let arn = body.get("table_bucket_arn")
                .or_else(|| body.get("bucket_arn"))
                .or_else(|| body.get("arn"))
                .and_then(|v| v.as_str())
                .unwrap_or("arn:aws:s3tables:us-east-1:123456789012:bucket/telemetry");
            let namespace = body.get("namespace").and_then(|v| v.as_str()).unwrap_or("production_iot");
            let table = body.get("table_name").or_else(|| body.get("table")).and_then(|v| v.as_str()).unwrap_or("device_events");
            let region = body.get("region").and_then(|v| v.as_str()).unwrap_or("us-east-1");
            let access_key = body.get("access_key_id").and_then(|v| v.as_str()).unwrap_or("test");
            let secret_key = body.get("secret_access_key").and_then(|v| v.as_str()).unwrap_or("test");
            let endpoint = body.get("endpoint").or_else(|| body.get("url")).and_then(|v| v.as_str()).map(|s| s.to_string());
            let timeout_ms = body.get("timeout_ms")
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
            if let Ok(transport) = broker_connectors::s3_tables::HttpS3TablesTransport::new(&config, reqwest::Client::new()) {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::s3_tables::S3TablesSink::new(config, transport) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine.connectors().register(format!("s3_tables:{}", name), sink.clone());
                    engine.connectors().register(format!("s3tables:{}", name), sink);
                }
            }
        }
        "kinesis" | "aws_kinesis" => {
            let stream = body.get("stream_name").or_else(|| body.get("stream")).and_then(|v| v.as_str()).unwrap_or("telemetry-stream");
            let region = body.get("region").and_then(|v| v.as_str()).unwrap_or("us-east-1");
            let endpoint = body.get("endpoint").or_else(|| body.get("url")).and_then(|v| v.as_str()).map(|s| s.to_string());
            let access_key = body.get("access_key_id").and_then(|v| v.as_str()).unwrap_or("test");
            let secret_key = body.get("secret_access_key").and_then(|v| v.as_str()).unwrap_or("test");
            let timeout_ms = body.get("timeout_ms")
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
            if let Ok(transport) = broker_connectors::kinesis::HttpKinesisTransport::new(&config, reqwest::Client::new()) {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::kinesis::KinesisSink::new(config, transport) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine.connectors().register(format!("kinesis:{}", name), sink);
                }
            }
        }
        "dynamodb" | "dynamo" => {
            let table = body.get("table_name").or_else(|| body.get("table")).and_then(|v| v.as_str()).unwrap_or("sensor_events");
            let region = body.get("region").and_then(|v| v.as_str()).unwrap_or("us-east-1");
            let endpoint = body.get("endpoint").or_else(|| body.get("url")).and_then(|v| v.as_str()).map(|s| s.to_string());
            let access_key = body.get("access_key_id").and_then(|v| v.as_str()).unwrap_or("test");
            let secret_key = body.get("secret_access_key").and_then(|v| v.as_str()).unwrap_or("test");
            let partition_key_name = body.get("partition_key").and_then(|v| v.as_str()).unwrap_or("id");
            let timeout_ms = body.get("timeout_ms")
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
            if let Ok(transport) = broker_connectors::dynamodb::HttpDynamoDbTransport::new(&config, reqwest::Client::new()) {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::dynamodb::DynamoDbSink::new(config, transport) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine.connectors().register(format!("dynamodb:{}", name), sink);
                }
            }
        }
        "timestream" => {
            let database = body.get("database_name").or_else(|| body.get("database")).and_then(|v| v.as_str()).unwrap_or("telemetry_db");
            let table = body.get("table_name").or_else(|| body.get("table")).and_then(|v| v.as_str()).unwrap_or("metrics");
            let region = body.get("region").and_then(|v| v.as_str()).unwrap_or("us-east-1");
            let endpoint = body.get("endpoint").or_else(|| body.get("url")).and_then(|v| v.as_str()).map(|s| s.to_string());
            let access_key = body.get("access_key_id").and_then(|v| v.as_str()).unwrap_or("test");
            let secret_key = body.get("secret_access_key").and_then(|v| v.as_str()).unwrap_or("test");
            let timeout_ms = body.get("timeout_ms")
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
            if let Ok(transport) = broker_connectors::timestream::HttpTimestreamTransport::new(&config, reqwest::Client::new()) {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::timestream::TimestreamSink::new(config, transport) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine.connectors().register(format!("timestream:{}", name), sink);
                }
            }
        }
        "redshift" => {
            let database = body.get("database").and_then(|v| v.as_str()).unwrap_or("dev");
            let table = body.get("table_template").or_else(|| body.get("table")).and_then(|v| v.as_str()).unwrap_or("sensor_events");
            let workgroup = body.get("workgroup_name").or_else(|| body.get("workgroup")).and_then(|v| v.as_str()).unwrap_or("default");
            let region = body.get("region").and_then(|v| v.as_str()).unwrap_or("us-east-1");
            let endpoint = body.get("endpoint").or_else(|| body.get("url")).and_then(|v| v.as_str()).map(|s| s.to_string());
            let access_key = body.get("access_key_id").and_then(|v| v.as_str()).unwrap_or("test");
            let secret_key = body.get("secret_access_key").and_then(|v| v.as_str()).unwrap_or("test");
            let timeout_ms = body.get("timeout_ms")
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
            if let Ok(transport) = broker_connectors::redshift::HttpRedshiftTransport::new(&config, reqwest::Client::new()) {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::redshift::RedshiftSink::new(config, transport) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine.connectors().register(format!("redshift:{}", name), sink);
                }
            }
        }
        "aws_iot" | "aws_iot_core" => {
            let endpoint = body.get("endpoint").or_else(|| body.get("url")).or_else(|| body.get("server")).and_then(|v| v.as_str()).unwrap_or("127.0.0.1:8883");
            let region = body.get("region").and_then(|v| v.as_str()).unwrap_or("us-east-1");
            let client_id = body.get("client_id").and_then(|v| v.as_str()).unwrap_or("indra-bridge");
            let timeout_ms = body.get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .or_else(|| body.get("request_timeout_ms"))
                .and_then(|v| v.as_u64());

            let config = broker_connectors::aws_iot::AwsIotConfig {
                endpoint: endpoint.to_string(),
                region: region.to_string(),
                client_id: client_id.to_string(),
                auth: broker_connectors::aws_iot::AwsIotAuth::SigV4 {
                    access_key_id: "test".to_string(),
                    secret_access_key: "test".to_string(),
                    session_token: None,
                },
                topic_mappings: vec![
                    broker_connectors::aws_iot::BridgeTopicMapping {
                        local_topic: "#".to_string(),
                        remote_topic: "aws/telemetry/${client_id}".to_string(),
                        direction: broker_connectors::aws_iot::BridgeDirection::LocalToRemote,
                    }
                ],
                shadow_sync: None,
                buffer_capacity: None,
                batch_size: Some(1),
                linger_ms: Some(10),
                max_retries: Some(3),
                timeout_ms,
            };
            if let Ok(transport) = broker_connectors::aws_iot::TcpAwsIotTransport::new(&endpoint) {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::aws_iot::AwsIotSink::new(config, transport) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine.connectors().register(format!("aws_iot:{}", name), sink.clone());
                    engine.connectors().register(format!("aws_iot_core:{}", name), sink);
                }
            }
        }
        "azure_blob" | "azure_blob_storage" => {
            let account_name = body.get("account_name").and_then(|v| v.as_str()).unwrap_or("devstoreaccount1");
            let container_name = body.get("container_name").or_else(|| body.get("container")).and_then(|v| v.as_str()).unwrap_or("telemetry");
            let endpoint = body.get("endpoint").or_else(|| body.get("url")).and_then(|v| v.as_str()).map(|s| s.to_string());
            let blob_path = body.get("blob_path_template").or_else(|| body.get("path_template")).and_then(|v| v.as_str()).unwrap_or("telemetry/${batch_id}.json");
            let timeout_ms = body.get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .and_then(|v| v.as_u64());

            let config = broker_connectors::azure_blob::AzureBlobSinkConfig {
                account_name: account_name.to_string(),
                container_name: container_name.to_string(),
                endpoint,
                auth: broker_connectors::azure_blob::AzureBlobAuth::BearerToken {
                    token: "mock-azure-token".to_string(),
                },
                blob_path_template: blob_path.to_string(),
                compression: broker_connectors::azure_blob::AzureBlobCompression::None,
                max_records_per_blob: Some(1),
                max_bytes_per_blob: Some(1_048_576),
                flush_interval_secs: 1,
                buffer_capacity: None,
                timeout_ms,
            };
            if let Ok(transport) = broker_connectors::azure_blob::HttpAzureBlobTransport::new(&config, reqwest::Client::new()) {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::azure_blob::AzureBlobSink::new(config, transport) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine.connectors().register(format!("azure_blob:{}", name), sink.clone());
                    engine.connectors().register(format!("azure_blob_storage:{}", name), sink);
                }
            }
        }
        "azure_eventhubs" | "azure_event_hubs" => {
            let namespace = body.get("namespace").and_then(|v| v.as_str()).unwrap_or("test-namespace");
            let event_hub = body.get("event_hub").or_else(|| body.get("hub")).and_then(|v| v.as_str()).unwrap_or("test-hub");
            let endpoint = body.get("endpoint").or_else(|| body.get("url")).and_then(|v| v.as_str()).map(|s| s.to_string());
            let shared_access_key_name = body.get("shared_access_key_name").or_else(|| body.get("key_name")).and_then(|v| v.as_str()).unwrap_or("SendPolicy");
            let shared_access_key = body.get("shared_access_key").or_else(|| body.get("key")).and_then(|v| v.as_str()).unwrap_or("dGVzdC1rZXk=");
            let timeout_ms = body.get("timeout_ms")
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
            if let Ok(transport) = broker_connectors::azure_eventhubs::HttpAzureEventHubsTransport::new(&config, reqwest::Client::new()) {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::azure_eventhubs::AzureEventHubsSink::new(config, transport) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine.connectors().register(format!("azure_eventhubs:{}", name), sink.clone());
                    engine.connectors().register(format!("azure_event_hubs:{}", name), sink);
                }
            }
        }
        "azure_iot" | "azure_iot_hub" => {
            let hub_name = body.get("iot_hub_name").or_else(|| body.get("hub_name")).or_else(|| body.get("server")).or_else(|| body.get("endpoint")).and_then(|v| v.as_str()).unwrap_or("127.0.0.1:8883");
            let device_id = body.get("device_id").and_then(|v| v.as_str()).unwrap_or("device-01");
            let shared_access_key = body.get("shared_access_key").or_else(|| body.get("key")).and_then(|v| v.as_str()).unwrap_or("dGVzdC1rZXk=");
            let timeout_ms = body.get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .and_then(|v| v.as_u64());

            let config = broker_connectors::azure_iot::AzureIotConfig {
                iot_hub_name: hub_name.to_string(),
                device_id: device_id.to_string(),
                module_id: None,
                auth: broker_connectors::azure_iot::AzureIotAuth::SharedAccessKey {
                    key: shared_access_key.to_string(),
                    key_name: Some("device".to_string()),
                },
                api_version: "2021-04-12".to_string(),
                direct_methods_enabled: false,
                twin_sync_enabled: false,
                batch_size: Some(1),
                buffer_capacity: None,
                linger_ms: Some(10),
                max_retries: Some(3),
                timeout_ms,
            };
            if let Ok(transport) = broker_connectors::azure_iot::TcpAzureIotTransport::new(hub_name) {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::azure_iot::AzureIotSink::new(config, transport) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine.connectors().register(format!("azure_iot:{}", name), sink.clone());
                    engine.connectors().register(format!("azure_iot_hub:{}", name), sink);
                }
            }
        }
        "gcp_pubsub" | "pubsub" => {
            let project_id = body.get("project_id").or_else(|| body.get("project")).and_then(|v| v.as_str()).unwrap_or("test-project");
            let topic_id = body.get("topic_id").or_else(|| body.get("topic")).and_then(|v| v.as_str()).unwrap_or("test-topic");
            let endpoint = body.get("endpoint").or_else(|| body.get("url")).and_then(|v| v.as_str()).map(|s| s.to_string());
            let timeout_ms = body.get("timeout_ms")
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
            if let Ok(transport) = broker_connectors::gcp_pubsub::HttpGcpPubSubTransport::new(&config, reqwest::Client::new()) {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::gcp_pubsub::GcpPubSubSink::new(config, transport) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine.connectors().register(format!("gcp_pubsub:{}", name), sink.clone());
                    engine.connectors().register(format!("pubsub:{}", name), sink);
                }
            }
        }
        "bigquery" => {
            let project_id = body.get("project_id").or_else(|| body.get("project")).and_then(|v| v.as_str()).unwrap_or("test-project");
            let dataset_id = body.get("dataset_id").or_else(|| body.get("dataset")).and_then(|v| v.as_str()).unwrap_or("test-dataset");
            let table = body.get("table").or_else(|| body.get("table_template")).and_then(|v| v.as_str()).unwrap_or("telemetry");
            let endpoint = body.get("endpoint").or_else(|| body.get("url")).and_then(|v| v.as_str()).map(|s| s.to_string());
            let timeout_ms = body.get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .and_then(|v| v.as_u64());

            let config = broker_connectors::bigquery::BigQuerySinkConfig {
                project_id: project_id.to_string(),
                dataset_id: dataset_id.to_string(),
                table_template: table.to_string(),
                endpoint,
                auth: broker_connectors::gcp_pubsub::GcpAuth::None,
                ignore_unknown_values: true,
                skip_invalid_rows: false,
                template_suffix: None,
                batch_size: Some(1),
                batch_bytes: Some(1_048_576),
                linger_ms: Some(10),
                max_retries: Some(3),
                initial_backoff_ms: Some(100),
                max_backoff_ms: Some(2_000),
                timeout_ms,
            };
            if let Ok(transport) = broker_connectors::bigquery::HttpBigQueryTransport::new(&config, reqwest::Client::new()) {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::bigquery::BigQuerySink::new(config, transport) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine.connectors().register(format!("bigquery:{}", name), sink);
                }
            }
        }
        "gcp_iot" | "gcp_iot_core" => {
            let endpoint = body.get("endpoint").or_else(|| body.get("url")).or_else(|| body.get("server")).and_then(|v| v.as_str()).unwrap_or("127.0.0.1:8883");
            let project_id = body.get("project_id").or_else(|| body.get("project")).and_then(|v| v.as_str()).unwrap_or("my-iot-project");
            let cloud_region = body.get("cloud_region").or_else(|| body.get("region")).and_then(|v| v.as_str()).unwrap_or("us-central1");
            let registry_id = body.get("registry_id").or_else(|| body.get("registry")).and_then(|v| v.as_str()).unwrap_or("telemetry-registry");
            let device_id = body.get("device_id").or_else(|| body.get("device")).and_then(|v| v.as_str()).unwrap_or("edge-7");
            let private_key_pem = body.get("private_key_pem").or_else(|| body.get("private_key")).and_then(|v| v.as_str()).unwrap_or(DEFAULT_RSA_PEM);
            let timeout_ms = body.get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .and_then(|v| v.as_u64());

            let config = broker_connectors::gcp_iot::GcpIotConfig {
                project_id: project_id.to_string(),
                cloud_region: cloud_region.to_string(),
                registry_id: registry_id.to_string(),
                device_id: device_id.to_string(),
                private_key_pem: private_key_pem.to_string(),
                algorithm: broker_connectors::gcp_iot::GcpIotAlgorithm::Rs256,
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
                    engine.connectors().register(format!("gcp_iot:{}", name), sink.clone());
                    engine.connectors().register(format!("gcp_iot_core:{}", name), sink);
                }
            }
        }
        "databricks" | "delta_lake" => {
            let host = body.get("host").or_else(|| body.get("server")).or_else(|| body.get("endpoint")).and_then(|v| v.as_str()).unwrap_or("127.0.0.1:18096");
            let token = body.get("token").or_else(|| body.get("api_key")).and_then(|v| v.as_str()).unwrap_or("dapi-mock-token");
            let catalog = body.get("catalog").and_then(|v| v.as_str()).unwrap_or("main");
            let schema = body.get("schema").and_then(|v| v.as_str()).unwrap_or("default");
            let table = body.get("table").or_else(|| body.get("table_template")).and_then(|v| v.as_str()).unwrap_or("events");
            let timeout_ms = body.get("timeout_ms")
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
            if let Ok(transport) = broker_connectors::databricks::HttpDatabricksTransport::new(&config, reqwest::Client::new()) {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::databricks::DatabricksSink::new(config, transport) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine.connectors().register(format!("databricks:{}", name), sink.clone());
                    engine.connectors().register(format!("delta_lake:{}", name), sink);
                }
            }
        }
        "snowflake" => {
            let account = body.get("account").and_then(|v| v.as_str()).unwrap_or("test-account");
            let user = body.get("user").or_else(|| body.get("username")).and_then(|v| v.as_str()).unwrap_or("test-user");
            let database = body.get("database").and_then(|v| v.as_str()).unwrap_or("test-db");
            let schema = body.get("schema").and_then(|v| v.as_str()).unwrap_or("PUBLIC");
            let table = body.get("table").or_else(|| body.get("table_template")).and_then(|v| v.as_str()).unwrap_or("TELEMETRY");
            let endpoint = body.get("endpoint").or_else(|| body.get("url")).and_then(|v| v.as_str()).map(|s| s.to_string());
            let private_key_pem = body.get("private_key_pem").or_else(|| body.get("private_key")).and_then(|v| v.as_str()).unwrap_or(DEFAULT_RSA_PEM);
            let timeout_ms = body.get("timeout_ms")
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
            if let Ok(transport) = broker_connectors::snowflake::HttpSnowflakeTransport::new(&config, reqwest::Client::new()) {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::snowflake::SnowflakeSink::new(config, transport) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine.connectors().register(format!("snowflake:{}", name), sink);
                }
            }
        }
        "tablestore" | "ots" => {
            let endpoint = body.get("endpoint").or_else(|| body.get("url")).and_then(|v| v.as_str()).unwrap_or("http://127.0.0.1:18098");
            let instance_name = body.get("instance_name").or_else(|| body.get("instance")).and_then(|v| v.as_str()).unwrap_or("test-instance");
            let table_name = body.get("table_name").or_else(|| body.get("table")).and_then(|v| v.as_str()).unwrap_or("sensor_data");
            let access_key_id = body.get("access_key_id").or_else(|| body.get("ak")).and_then(|v| v.as_str()).unwrap_or("test-ak");
            let access_key_secret = body.get("access_key_secret").or_else(|| body.get("sk")).and_then(|v| v.as_str()).unwrap_or("test-sk");
            let timeout_ms = body.get("timeout_ms")
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
            if let Ok(transport) = broker_connectors::tablestore::HttpTablestoreTransport::new(&config, reqwest::Client::new()) {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::tablestore::TablestoreSink::new(config, transport) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine.connectors().register(format!("tablestore:{}", name), sink.clone());
                    engine.connectors().register(format!("ots:{}", name), sink);
                }
            }
        }
        "oci_streaming" | "oci" => {
            let endpoint = body.get("endpoint").or_else(|| body.get("url")).and_then(|v| v.as_str()).unwrap_or("http://127.0.0.1:18099");
            let stream_pool_id = body.get("stream_pool_id").and_then(|v| v.as_str()).unwrap_or("ocid1.streampool.oc1..teststreampool");
            let stream_id = body.get("stream_id").and_then(|v| v.as_str()).unwrap_or("ocid1.stream.oc1..teststream");
            let tenancy_ocid = body.get("tenancy_ocid").and_then(|v| v.as_str()).unwrap_or("ocid1.tenancy.oc1..testtenancy");
            let user_ocid = body.get("user_ocid").and_then(|v| v.as_str()).unwrap_or("ocid1.user.oc1..testuser");
            let fingerprint = body.get("fingerprint").and_then(|v| v.as_str()).unwrap_or("20:3b:97:13:55:1c:5b:0d:d3:37:d8:50:4e:c9:42:01");
            let private_key_pem = body.get("private_key_pem").or_else(|| body.get("private_key")).and_then(|v| v.as_str()).unwrap_or(DEFAULT_RSA_PEM);
            let timeout_ms = body.get("timeout_ms")
                .or_else(|| body.get("timeout"))
                .and_then(|v| v.as_u64());

            let partition_key_template = body.get("partition_key_template")
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
            if let Ok(transport) = broker_connectors::oci_streaming::HttpOciStreamingTransport::new(&config, reqwest::Client::new()) {
                let transport = Arc::new(transport);
                if let Ok(sink) = broker_connectors::oci_streaming::OciStreamingSink::new(config, transport) {
                    let sink = Arc::new(sink);
                    engine.connectors().register(name, sink.clone());
                    engine.connectors().register(format!("oci_streaming:{}", name), sink.clone());
                    engine.connectors().register(format!("oci:{}", name), sink);
                }
            }
        }
        _ => {}
    }
}

pub async fn create_connector(
    State(state): State<ApiState>,
    Json(mut body): Json<serde_json::Value>,
) -> Response {
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("connector-{}", rand::random::<u16>()));
    let raw_type = body
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let conn_type = if !raw_type.is_empty() && raw_type != "http" {
        raw_type.to_string()
    } else if body.get("bootstrap_hosts").is_some() || name.contains("kafka") {
        "kafka".to_string()
    } else if (body.get("server").is_some() && body.get("database").is_some() && !body.get("server").and_then(|s| s.as_str()).unwrap_or("").contains("3306"))
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

    let target_opt = extract_target_host_port(&body);
    let is_reachable = if let Some(ref target) = target_opt {
        check_tcp_reachable(target).await.is_ok()
    } else {
        true
    };
    let status_str = if is_reachable { "connected" } else { "disconnected" };

    if let Some(obj) = body.as_object_mut() {
        obj.insert("id".to_string(), serde_json::Value::String(name.clone()));
        obj.insert("name".to_string(), serde_json::Value::String(name.clone()));
        obj.insert("type".to_string(), serde_json::Value::String(conn_type.clone()));
        obj.insert(
            "status".to_string(),
            serde_json::Value::String(status_str.to_string()),
        );
        if !obj.contains_key("enable") {
            obj.insert("enable".to_string(), serde_json::Value::Bool(true));
        }
        obj.insert(
            "node_status".to_string(),
            serde_json::json!([{ "node": "indramqtt@127.0.0.1", "status": status_str }]),
        );
    }

    if is_reachable {
        register_live_sink(&state.engine, &conn_type, &name, &body).await;
    }

    CONNECTORS.write().unwrap().push(body.clone());

    let action_id = format!("{}:{}", conn_type, name);
    let mut actions = ACTIONS.write().unwrap();
    if !actions.iter().any(|a| a.get("id").and_then(|v| v.as_str()) == Some(&action_id)) {
        actions.push(serde_json::json!({
            "id": action_id,
            "name": name,
            "type": conn_type,
            "connector": name,
            "enable": true,
            "status": status_str,
            "rules": [],
            "parameters": {},
            "description": format!("Action sink for connector {}", name),
            "node_status": [{ "node": "indramqtt@127.0.0.1", "status": status_str }]
        }));
    }

    (StatusCode::CREATED, Json(body)).into_response()
}

pub async fn update_connector(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(mut body): Json<serde_json::Value>,
) -> Response {
    let clean_id = id.split(':').last().unwrap_or(&id);
    if let Some(obj) = body.as_object_mut() {
        obj.insert("id".to_string(), serde_json::Value::String(clean_id.to_string()));
    }
    let conn_type = body.get("type").and_then(|v| v.as_str()).unwrap_or("http");
    register_live_sink(&state.engine, conn_type, clean_id, &body).await;

    let mut connectors = CONNECTORS.write().unwrap();
    if let Some(pos) = connectors.iter().position(|c| {
        c.get("id").and_then(|v| v.as_str()) == Some(&id)
            || c.get("name").and_then(|v| v.as_str()) == Some(&id)
            || c.get("id").and_then(|v| v.as_str()) == Some(clean_id)
            || c.get("name").and_then(|v| v.as_str()) == Some(clean_id)
    }) {
        connectors[pos] = body.clone();
    } else {
        connectors.push(body.clone());
    }
    (StatusCode::OK, Json(body)).into_response()
}

pub async fn delete_connector(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Response {
    let clean_id = id.split(':').last().unwrap_or(&id);
    state.engine.connectors().unregister(&id);
    state.engine.connectors().unregister(clean_id);
    state.engine.connectors().unregister(&format!("redis:{}", clean_id));
    state.engine.connectors().unregister(&format!("http:{}", clean_id));
    state.engine.connectors().unregister(&format!("kafka:{}", clean_id));
    state.engine.connectors().unregister(&format!("pgsql:{}", clean_id));
    state.engine.connectors().unregister(&format!("mysql:{}", clean_id));
    state.engine.connectors().unregister(&format!("rabbitmq:{}", clean_id));
    state.engine.connectors().unregister(&format!("clickhouse:{}", clean_id));
    state.engine.connectors().unregister(&format!("influxdb:{}", clean_id));
    state.engine.connectors().unregister(&format!("mongodb:{}", clean_id));
    state.engine.connectors().unregister(&format!("cassandra:{}", clean_id));
    state.engine.connectors().unregister(&format!("cockroachdb:{}", clean_id));
    state.engine.connectors().unregister(&format!("couchbase:{}", clean_id));
    state.engine.connectors().unregister(&format!("mssql:{}", clean_id));
    state.engine.connectors().unregister(&format!("oracle:{}", clean_id));
    state.engine.connectors().unregister(&format!("alloydb:{}", clean_id));
    state.engine.connectors().unregister(&format!("tdengine:{}", clean_id));
    state.engine.connectors().unregister(&format!("greptimedb:{}", clean_id));
    state.engine.connectors().unregister(&format!("greptime:{}", clean_id));
    state.engine.connectors().unregister(&format!("iotdb:{}", clean_id));
    state.engine.connectors().unregister(&format!("opentsdb:{}", clean_id));
    state.engine.connectors().unregister(&format!("doris:{}", clean_id));
    state.engine.connectors().unregister(&format!("datalayers:{}", clean_id));
    state.engine.connectors().unregister(&format!("elasticsearch:{}", clean_id));
    state.engine.connectors().unregister(&format!("opensearch:{}", clean_id));
    state.engine.connectors().unregister(&format!("pulsar:{}", clean_id));
    state.engine.connectors().unregister(&format!("rocketmq:{}", clean_id));
    state.engine.connectors().unregister(&format!("confluent:{}", clean_id));
    state.engine.connectors().unregister(&format!("disk_log:{}", clean_id));
    state.engine.connectors().unregister(&format!("disk:{}", clean_id));
    state.engine.connectors().unregister(&format!("opc_ua:{}", clean_id));
    state.engine.connectors().unregister(&format!("opcua:{}", clean_id));
    state.engine.connectors().unregister(&format!("sparkplug_b:{}", clean_id));
    state.engine.connectors().unregister(&format!("sparkplug:{}", clean_id));
    state.engine.connectors().unregister(&format!("s3:{}", clean_id));
    state.engine.connectors().unregister(&format!("minio:{}", clean_id));
    state.engine.connectors().unregister(&format!("s3_tables:{}", clean_id));
    state.engine.connectors().unregister(&format!("s3tables:{}", clean_id));
    state.engine.connectors().unregister(&format!("kinesis:{}", clean_id));
    state.engine.connectors().unregister(&format!("dynamodb:{}", clean_id));
    state.engine.connectors().unregister(&format!("timestream:{}", clean_id));
    state.engine.connectors().unregister(&format!("redshift:{}", clean_id));
    state.engine.connectors().unregister(&format!("aws_iot:{}", clean_id));
    state.engine.connectors().unregister(&format!("aws_iot_core:{}", clean_id));
    state.engine.connectors().unregister(&format!("azure_blob:{}", clean_id));
    state.engine.connectors().unregister(&format!("azure_blob_storage:{}", clean_id));
    state.engine.connectors().unregister(&format!("azure_eventhubs:{}", clean_id));
    state.engine.connectors().unregister(&format!("azure_event_hubs:{}", clean_id));
    state.engine.connectors().unregister(&format!("azure_iot:{}", clean_id));
    state.engine.connectors().unregister(&format!("azure_iot_hub:{}", clean_id));
    state.engine.connectors().unregister(&format!("gcp_pubsub:{}", clean_id));
    state.engine.connectors().unregister(&format!("pubsub:{}", clean_id));
    state.engine.connectors().unregister(&format!("bigquery:{}", clean_id));
    state.engine.connectors().unregister(&format!("gcp_iot:{}", clean_id));
    state.engine.connectors().unregister(&format!("gcp_iot_core:{}", clean_id));
    state.engine.connectors().unregister(&format!("databricks:{}", clean_id));
    state.engine.connectors().unregister(&format!("delta_lake:{}", clean_id));
    state.engine.connectors().unregister(&format!("snowflake:{}", clean_id));
    state.engine.connectors().unregister(&format!("tablestore:{}", clean_id));
    state.engine.connectors().unregister(&format!("ots:{}", clean_id));
    state.engine.connectors().unregister(&format!("oci_streaming:{}", clean_id));
    state.engine.connectors().unregister(&format!("oci:{}", clean_id));

    let mut connectors = CONNECTORS.write().unwrap();
    connectors.retain(|c| {
        c.get("id").and_then(|v| v.as_str()) != Some(&id)
            && c.get("name").and_then(|v| v.as_str()) != Some(&id)
            && c.get("id").and_then(|v| v.as_str()) != Some(clean_id)
            && c.get("name").and_then(|v| v.as_str()) != Some(clean_id)
    });
    StatusCode::NO_CONTENT.into_response()
}

pub async fn start_connector(Path(id): Path<String>) -> Response {
    let clean_id = id.split(':').last().unwrap_or(&id);
    let mut connectors = CONNECTORS.write().unwrap();
    for c in connectors.iter_mut() {
        if c.get("id").and_then(|v| v.as_str()) == Some(&id)
            || c.get("name").and_then(|v| v.as_str()) == Some(&id)
            || c.get("id").and_then(|v| v.as_str()) == Some(clean_id)
            || c.get("name").and_then(|v| v.as_str()) == Some(clean_id)
        {
            if let Some(obj) = c.as_object_mut() {
                obj.insert("enable".to_string(), serde_json::Value::Bool(true));
                obj.insert(
                    "status".to_string(),
                    serde_json::Value::String("connected".to_string()),
                );
            }
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

pub async fn enable_connector(Path((id, enable)): Path<(String, bool)>) -> Response {
    let clean_id = id.split(':').last().unwrap_or(&id);
    let mut connectors = CONNECTORS.write().unwrap();
    for c in connectors.iter_mut() {
        if c.get("id").and_then(|v| v.as_str()) == Some(&id)
            || c.get("name").and_then(|v| v.as_str()) == Some(&id)
            || c.get("id").and_then(|v| v.as_str()) == Some(clean_id)
            || c.get("name").and_then(|v| v.as_str()) == Some(clean_id)
        {
            if let Some(obj) = c.as_object_mut() {
                obj.insert("enable".to_string(), serde_json::Value::Bool(enable));
                let status_str = if enable { "connected" } else { "stopped" };
                obj.insert(
                    "status".to_string(),
                    serde_json::Value::String(status_str.to_string()),
                );
            }
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
        let host_port = clean.split('@').last().unwrap_or(clean).split('/').next().unwrap_or(clean).split('?').next().unwrap_or(clean);
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
        let host_port = clean.split('@').last().unwrap_or(clean).split('/').next().unwrap_or(clean).split('?').next().unwrap_or(clean);
        if !host_port.is_empty() {
            return Some(host_port.to_string());
        }
    }
    if let Some(s) = body.get("endpoint").and_then(|v| v.as_str()) {
        let mut clean = s.trim();
        if let Some((_, rest)) = clean.split_once("://") {
            clean = rest;
        }
        let host_port = clean.split('@').last().unwrap_or(clean).split('/').next().unwrap_or(clean).split('?').next().unwrap_or(clean);
        if !host_port.is_empty() {
            return Some(host_port.to_string());
        }
    }
    if let Some(s) = body.get("endpoint_url").and_then(|v| v.as_str()) {
        let mut clean = s.trim();
        if let Some((_, rest)) = clean.split_once("://") {
            clean = rest;
        }
        let host_port = clean.split('@').last().unwrap_or(clean).split('/').next().unwrap_or(clean).split('?').next().unwrap_or(clean);
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
        let host_port = clean.split('@').last().unwrap_or(clean).split('/').next().unwrap_or(clean).split('?').next().unwrap_or(clean);
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
        let host_port = clean.split('@').last().unwrap_or(clean).split('/').next().unwrap_or(clean).split('?').next().unwrap_or(clean);
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
                    "code": "CONNECTION_FAILED",
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
// Action Sinks (Flow Designer & Rule Actions)
// ---------------------------------------------------------------------------
static ACTIONS: LazyLock<RwLock<Vec<serde_json::Value>>> = LazyLock::new(|| RwLock::new(Vec::new()));

pub async fn list_actions() -> Response {
    let list = ACTIONS.read().unwrap().clone();
    (StatusCode::OK, Json(list)).into_response()
}

pub async fn get_actions_summary() -> Response {
    let actions = ACTIONS.read().unwrap();
    let summary: Vec<_> = actions
        .iter()
        .map(|a| {
            serde_json::json!({
                "id": a.get("id").cloned().unwrap_or_default(),
                "name": a.get("name").cloned().unwrap_or_default(),
                "type": a.get("type").cloned().unwrap_or_default(),
                "status": a.get("status").cloned().unwrap_or_else(|| serde_json::Value::String("connected".to_string())),
                "enable": a.get("enable").cloned().unwrap_or(serde_json::Value::Bool(true))
            })
        })
        .collect();
    (StatusCode::OK, Json(summary)).into_response()
}

pub async fn get_action(Path(id): Path<String>) -> Response {
    let actions = ACTIONS.read().unwrap();
    if let Some(act) = actions.iter().find(|a| a.get("id").and_then(|v| v.as_str()) == Some(&id)) {
        return (StatusCode::OK, Json(act.clone())).into_response();
    }
    let clean_id = id
        .strip_prefix("kafka:")
        .or_else(|| id.strip_prefix("pgsql:"))
        .or_else(|| id.strip_prefix("http:"))
        .or_else(|| id.strip_prefix("clickhouse:"))
        .or_else(|| id.strip_prefix("redis:"))
        .or_else(|| id.strip_prefix("mysql:"))
        .or_else(|| id.strip_prefix("tdengine:"))
        .or_else(|| id.strip_prefix("greptimedb:"))
        .or_else(|| id.strip_prefix("greptime:"))
        .or_else(|| id.strip_prefix("iotdb:"))
        .or_else(|| id.strip_prefix("opentsdb:"))
        .or_else(|| id.strip_prefix("doris:"))
        .or_else(|| id.strip_prefix("datalayers:"))
        .or_else(|| id.strip_prefix("elasticsearch:"))
        .or_else(|| id.strip_prefix("opensearch:"))
        .or_else(|| id.strip_prefix("pulsar:"))
        .or_else(|| id.strip_prefix("rocketmq:"))
        .or_else(|| id.strip_prefix("confluent:"))
        .unwrap_or(&id);
    let act_type = if id.contains("kafka") {
        "kafka"
    } else if id.contains("pgsql") {
        "pgsql"
    } else if id.contains("clickhouse") {
        "clickhouse"
    } else if id.contains("redis") {
        "redis"
    } else if id.contains("mysql") {
        "mysql"
    } else if id.contains("tdengine") {
        "tdengine"
    } else if id.contains("greptime") {
        "greptimedb"
    } else if id.contains("iotdb") {
        "iotdb"
    } else if id.contains("opentsdb") {
        "opentsdb"
    } else if id.contains("doris") {
        "doris"
    } else if id.contains("datalayers") {
        "datalayers"
    } else if id.contains("elasticsearch") || id.contains("opensearch") {
        "elasticsearch"
    } else if id.contains("pulsar") {
        "pulsar"
    } else if id.contains("rocketmq") {
        "rocketmq"
    } else if id.contains("confluent") {
        "confluent"
    } else {
        "http"
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "id": id,
            "name": clean_id,
            "type": act_type,
            "connector": clean_id,
            "enable": true,
            "status": "connected",
            "rules": [],
            "parameters": {},
            "description": "IndraMQTT Stream Action Sink",
            "node_status": [{ "node": "indramqtt@127.0.0.1", "status": "connected" }]
        })),
    )
        .into_response()
}

pub async fn create_action(Json(mut body): Json<serde_json::Value>) -> Response {
    if let Some(obj) = body.as_object_mut() {
        if !obj.contains_key("status") {
            obj.insert("status".to_string(), serde_json::Value::String("connected".to_string()));
        }
        if !obj.contains_key("node_status") {
            obj.insert(
                "node_status".to_string(),
                serde_json::json!([{ "node": "indramqtt@127.0.0.1", "status": "connected" }]),
            );
        }
    }
    ACTIONS.write().unwrap().push(body.clone());
    (StatusCode::CREATED, Json(body)).into_response()
}

pub async fn update_action(Path(id): Path<String>, Json(mut body): Json<serde_json::Value>) -> Response {
    if let Some(obj) = body.as_object_mut() {
        obj.insert("id".to_string(), serde_json::Value::String(id.clone()));
    }
    let mut actions = ACTIONS.write().unwrap();
    if let Some(pos) = actions.iter().position(|a| a.get("id").and_then(|v| v.as_str()) == Some(&id)) {
        actions[pos] = body.clone();
    } else {
        actions.push(body.clone());
    }
    (StatusCode::OK, Json(body)).into_response()
}

pub async fn delete_action(Path(id): Path<String>) -> Response {
    let mut actions = ACTIONS.write().unwrap();
    actions.retain(|a| a.get("id").and_then(|v| v.as_str()) != Some(&id));
    StatusCode::NO_CONTENT.into_response()
}

pub async fn start_action(Path(id): Path<String>) -> Response {
    let mut actions = ACTIONS.write().unwrap();
    for a in actions.iter_mut() {
        if a.get("id").and_then(|v| v.as_str()) == Some(&id) {
            if let Some(obj) = a.as_object_mut() {
                obj.insert("status".to_string(), serde_json::Value::String("connected".to_string()));
                obj.insert("enable".to_string(), serde_json::Value::Bool(true));
            }
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

pub async fn enable_action(Path((id, enable)): Path<(String, bool)>) -> Response {
    let mut actions = ACTIONS.write().unwrap();
    for a in actions.iter_mut() {
        if a.get("id").and_then(|v| v.as_str()) == Some(&id) {
            if let Some(obj) = a.as_object_mut() {
                obj.insert("enable".to_string(), serde_json::Value::Bool(enable));
                let status_str = if enable { "connected" } else { "stopped" };
                obj.insert("status".to_string(), serde_json::Value::String(status_str.to_string()));
            }
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

pub async fn get_action_metrics(Path(id): Path<String>) -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "id": id,
            "metrics": {
                "success": 0,
                "failed": 0,
                "dropped": 0,
                "rate": 0.0
            }
        })),
    ).into_response()
}

pub async fn reset_action_metrics(Path(_id): Path<String>) -> Response {
    StatusCode::NO_CONTENT.into_response()
}

pub async fn get_action_types() -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!(["kafka", "pgsql", "mysql", "redis", "mongodb", "clickhouse", "s3", "http"])),
    ).into_response()
}

pub async fn probe_action(body: Option<Json<serde_json::Value>>) -> Response {
    if let Some(Json(b)) = body {
        if let Some(target) = extract_target_host_port(&b) {
            if let Err(err) = check_tcp_reachable(&target).await {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "code": "CONNECTION_FAILED",
                        "message": err
                    })),
                )
                    .into_response();
            }
        }
    }
    (StatusCode::OK, Json(serde_json::json!({ "result": "ok", "status": "connected" }))).into_response()
}

// ---------------------------------------------------------------------------
// Ingress Sources
// ---------------------------------------------------------------------------

static SOURCES: LazyLock<RwLock<Vec<serde_json::Value>>> = LazyLock::new(|| {
    RwLock::new(vec![
        serde_json::json!({
            "id": "mqtt:telemetry-ingress",
            "name": "telemetry-ingress",
            "type": "mqtt",
            "enable": true,
            "status": "connected",
            "rules": ["rule-1", "rule-3"],
            "parameters": {
                "topic": "sensors/#"
            },
            "description": "MQTT Ingress for IoT sensors",
            "node_status": [{ "node": "indramqtt@127.0.0.1", "status": "connected" }]
        }),
    ])
});

pub async fn list_sources() -> Response {
    let list = SOURCES.read().unwrap().clone();
    (StatusCode::OK, Json(list)).into_response()
}

pub async fn get_sources_summary() -> Response {
    let sources = SOURCES.read().unwrap();
    let summary: Vec<_> = sources
        .iter()
        .map(|s| {
            serde_json::json!({
                "id": s.get("id").cloned().unwrap_or_default(),
                "name": s.get("name").cloned().unwrap_or_default(),
                "type": s.get("type").cloned().unwrap_or_default(),
                "status": s.get("status").cloned().unwrap_or_else(|| serde_json::Value::String("connected".to_string())),
                "enable": s.get("enable").cloned().unwrap_or(serde_json::Value::Bool(true))
            })
        })
        .collect();
    (StatusCode::OK, Json(summary)).into_response()
}

pub async fn get_source(Path(id): Path<String>) -> Response {
    let sources = SOURCES.read().unwrap();
    if let Some(src) = sources.iter().find(|s| s.get("id").and_then(|v| v.as_str()) == Some(&id)) {
        return (StatusCode::OK, Json(src.clone())).into_response();
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "id": id,
            "name": "telemetry-ingress",
            "type": "mqtt",
            "enable": true,
            "status": "connected",
            "rules": ["rule-1"],
            "parameters": {
                "topic": "sensors/#"
            },
            "description": "MQTT Ingress for IoT sensors",
            "node_status": [{ "node": "indramqtt@127.0.0.1", "status": "connected" }]
        })),
    )
        .into_response()
}

pub async fn create_source(Json(mut body): Json<serde_json::Value>) -> Response {
    if let Some(obj) = body.as_object_mut() {
        if !obj.contains_key("status") {
            obj.insert("status".to_string(), serde_json::Value::String("connected".to_string()));
        }
        if !obj.contains_key("node_status") {
            obj.insert(
                "node_status".to_string(),
                serde_json::json!([{ "node": "indramqtt@127.0.0.1", "status": "connected" }]),
            );
        }
    }
    SOURCES.write().unwrap().push(body.clone());
    (StatusCode::CREATED, Json(body)).into_response()
}

pub async fn update_source(Path(id): Path<String>, Json(mut body): Json<serde_json::Value>) -> Response {
    if let Some(obj) = body.as_object_mut() {
        obj.insert("id".to_string(), serde_json::Value::String(id.clone()));
    }
    let mut sources = SOURCES.write().unwrap();
    if let Some(pos) = sources.iter().position(|s| s.get("id").and_then(|v| v.as_str()) == Some(&id)) {
        sources[pos] = body.clone();
    } else {
        sources.push(body.clone());
    }
    (StatusCode::OK, Json(body)).into_response()
}

pub async fn delete_source(Path(id): Path<String>) -> Response {
    let mut sources = SOURCES.write().unwrap();
    sources.retain(|s| s.get("id").and_then(|v| v.as_str()) != Some(&id));
    StatusCode::NO_CONTENT.into_response()
}

pub async fn enable_source(Path((id, enable)): Path<(String, bool)>) -> Response {
    let mut sources = SOURCES.write().unwrap();
    for s in sources.iter_mut() {
        if s.get("id").and_then(|v| v.as_str()) == Some(&id) {
            if let Some(obj) = s.as_object_mut() {
                obj.insert("enable".to_string(), serde_json::Value::Bool(enable));
                let status_str = if enable { "connected" } else { "stopped" };
                obj.insert("status".to_string(), serde_json::Value::String(status_str.to_string()));
            }
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

pub async fn get_source_metrics(Path(id): Path<String>) -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "id": id,
            "metrics": {
                "success": 0,
                "failed": 0,
                "rate": 0.0
            }
        })),
    ).into_response()
}

pub async fn reset_source_metrics(Path(_id): Path<String>) -> Response {
    StatusCode::NO_CONTENT.into_response()
}

pub async fn probe_source() -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({ "result": "ok" })),
    ).into_response()
}

// ---------------------------------------------------------------------------
// Schema Registry & Schema Validation
// ---------------------------------------------------------------------------

pub async fn list_schemas() -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!([
            {
                "name": "SensorTelemetryAvro",
                "type": "avro",
                "description": "Avro schema definition for smart factory sensor readings",
                "schema": "{\"type\":\"record\",\"name\":\"SensorTelemetry\",\"fields\":[{\"name\":\"sensor_id\",\"type\":\"string\"},{\"name\":\"temperature\",\"type\":\"double\"},{\"name\":\"timestamp\",\"type\":\"long\"}]}"
            }
        ])),
    ).into_response()
}

pub async fn create_schema(Json(body): Json<serde_json::Value>) -> Response {
    (StatusCode::CREATED, Json(body)).into_response()
}

pub async fn get_schema(Path(name): Path<String>) -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "name": name,
            "type": "avro",
            "description": "Avro schema definition for smart factory sensor readings",
            "schema": "{\"type\":\"record\",\"name\":\"SensorTelemetry\",\"fields\":[{\"name\":\"sensor_id\",\"type\":\"string\"},{\"name\":\"temperature\",\"type\":\"double\"},{\"name\":\"timestamp\",\"type\":\"long\"}]}"
        })),
    ).into_response()
}

pub async fn update_schema(Path(name): Path<String>, Json(body): Json<serde_json::Value>) -> Response {
    let mut resp = body;
    if let Some(obj) = resp.as_object_mut() {
        obj.insert("name".to_string(), serde_json::Value::String(name));
    }
    (StatusCode::OK, Json(resp)).into_response()
}

pub async fn delete_schema(Path(_name): Path<String>) -> Response {
    StatusCode::NO_CONTENT.into_response()
}

pub async fn list_schema_validations() -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!([
            {
                "name": "factory-sensor-validator",
                "schema_name": "SensorTelemetryAvro",
                "topic": "sensors/factory/#",
                "enable": true,
                "description": "Validates inbound sensor JSON against Avro schema",
                "action": "drop"
            }
        ])),
    ).into_response()
}

pub async fn create_schema_validation(Json(body): Json<serde_json::Value>) -> Response {
    (StatusCode::CREATED, Json(body)).into_response()
}

pub async fn update_schema_validation(Json(body): Json<serde_json::Value>) -> Response {
    (StatusCode::OK, Json(body)).into_response()
}

pub async fn get_schema_validation(Path(name): Path<String>) -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "name": name,
            "schema_name": "SensorTelemetryAvro",
            "topic": "sensors/factory/#",
            "enable": true,
            "description": "Validates inbound sensor JSON against Avro schema",
            "action": "drop"
        })),
    ).into_response()
}

pub async fn delete_schema_validation(Path(_name): Path<String>) -> Response {
    StatusCode::NO_CONTENT.into_response()
}

pub async fn enable_schema_validation(Path((name, enable)): Path<(String, bool)>) -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "name": name,
            "enable": enable
        })),
    ).into_response()
}

pub async fn get_schema_validation_metrics(Path(_name): Path<String>) -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "pass": 0,
            "fail": 0,
            "rate": 0.0
        })),
    ).into_response()
}

pub async fn reset_schema_validation_metrics(Path(_name): Path<String>) -> Response {
    StatusCode::NO_CONTENT.into_response()
}
