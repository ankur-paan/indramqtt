//! Schema generator for v5 OpenAPI/JSON schemas used by the Dashboard UI
//! for rendering dynamic forms in Connector and Rule Engine Action dialogs.

use axum::{
    extract::Path,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use std::sync::LazyLock;

fn str_prop(default: &str) -> Value {
    json!({
        "type": "string",
        "default": default
    })
}

fn pwd_prop() -> Value {
    json!({
        "type": "string",
        "format": "password",
        "default": ""
    })
}

fn int_prop(default: i64) -> Value {
    json!({
        "type": "integer",
        "default": default
    })
}

fn bool_prop(default: bool) -> Value {
    json!({
        "type": "boolean",
        "default": default
    })
}

fn enum_prop(symbols: &[&str], default: &str) -> Value {
    json!({
        "type": "string",
        "enum": symbols,
        "default": default
    })
}

fn ssl_prop() -> Value {
    json!({
        "type": "object",
        "properties": {
            "enable": { "type": "boolean", "default": false },
            "verify": { "type": "string", "enum": ["verify_none", "verify_peer"], "default": "verify_none" },
            "server_name_indication": { "type": "string", "default": "disable" },
            "cacertfile": { "type": "string", "default": "" },
            "certfile": { "type": "string", "default": "" },
            "keyfile": { "type": "string", "default": "" }
        }
    })
}

fn obj_schema_with_type(conn_type: &str, properties: Value, required: &[&str]) -> Value {
    let mut props = properties;
    if let Some(map) = props.as_object_mut() {
        if !map.contains_key("type") {
            map.insert("type".to_string(), str_prop(conn_type));
        }
        if !map.contains_key("name") {
            map.insert("name".to_string(), str_prop(""));
        }
        if !map.contains_key("enable") {
            map.insert("enable".to_string(), bool_prop(true));
        }
        if !map.contains_key("description") {
            map.insert("description".to_string(), str_prop(""));
        }
    }
    json!({
        "type": "object",
        "properties": props,
        "required": required
    })
}

fn obj_schema(properties: Value, required: &[&str]) -> Value {
    obj_schema_with_type("http", properties, required)
}

static CONNECTORS_SCHEMA: LazyLock<Value> = LazyLock::new(|| {
    let mut schemas = serde_json::Map::new();

    // 1. Redis
    schemas.insert(
        "redis.post_connector".to_string(),
        obj_schema_with_type(
            "redis",
            json!({
                "redis_type": enum_prop(&["single", "sentinel", "cluster"], "single"),
                "servers": str_prop("127.0.0.1:6379"),
                "password": pwd_prop(),
                "database": int_prop(0),
                "pool_size": int_prop(8),
                "ssl": ssl_prop()
            }),
            &["name", "servers"],
        ),
    );

    // 2. Kafka Producer
    schemas.insert("bridge_kafka.post_connector".to_string(), obj_schema_with_type("kafka", json!({
        "bootstrap_hosts": str_prop("127.0.0.1:9092"),
        "connect_timeout": str_prop("5s"),
        "authentication": json!({
            "type": "object",
            "properties": {
                "mechanism": enum_prop(&["none", "plain", "scram_sha_256", "scram_sha_512"], "none"),
                "username": str_prop(""),
                "password": pwd_prop()
            }
        }),
        "health_check_topic": str_prop("emqx_health_check"),
        "allow_auto_topic_creation": bool_prop(true),
        "ssl": ssl_prop()
    }), &["name", "bootstrap_hosts"]));

    // 3. Kafka Consumer
    schemas.insert(
        "kafka_consumer.post_connector".to_string(),
        obj_schema(
            json!({
                "bootstrap_hosts": str_prop("127.0.0.1:9092"),
                "topic": str_prop("mqtt_ingress"),
                "connect_timeout": str_prop("5s"),
                "ssl": ssl_prop()
            }),
            &["name", "bootstrap_hosts"],
        ),
    );

    // 4. PostgreSQL (pgsql)
    schemas.insert(
        "connector_postgres.post_connector".to_string(),
        obj_schema_with_type(
            "pgsql",
            json!({
                "server": str_prop("127.0.0.1:5432"),
                "database": str_prop("postgres"),
                "username": str_prop("postgres"),
                "password": pwd_prop(),
                "pool_size": int_prop(8),
                "ssl": ssl_prop()
            }),
            &["name", "server", "database", "username"],
        ),
    );

    // 5. MySQL
    schemas.insert(
        "bridge_mysql.post_connector".to_string(),
        obj_schema_with_type(
            "mysql",
            json!({
                "server": str_prop("127.0.0.1:3306"),
                "database": str_prop("mysql"),
                "username": str_prop("root"),
                "password": pwd_prop(),
                "pool_size": int_prop(8),
                "ssl": ssl_prop()
            }),
            &["name", "server", "database", "username"],
        ),
    );

    // 6. HTTP Webhook
    schemas.insert(
        "bridge_http.post_connector".to_string(),
        obj_schema_with_type(
            "http",
            json!({
                "url": str_prop("http://127.0.0.1:8080"),
                "headers": json!({
                    "type": "object",
                    "default": { "content-type": "application/json" }
                }),
                "connect_timeout": str_prop("5s"),
                "enable_pipelining": bool_prop(true),
                "pool_size": int_prop(8),
                "ssl": ssl_prop()
            }),
            &["name", "url"],
        ),
    );

    // 7. ClickHouse
    schemas.insert(
        "bridge_clickhouse.post_connector".to_string(),
        obj_schema_with_type(
            "clickhouse",
            json!({
                "url": str_prop("http://127.0.0.1:8123"),
                "database": str_prop("default"),
                "username": str_prop("default"),
                "password": pwd_prop(),
                "pool_size": int_prop(8),
                "ssl": ssl_prop()
            }),
            &["name", "url", "database"],
        ),
    );

    // 8. MQTT Broker Bridge
    schemas.insert(
        "connector_mqtt.post_connector".to_string(),
        obj_schema_with_type(
            "mqtt",
            json!({
                "server": str_prop("127.0.0.1:1883"),
                "clientid_prefix": str_prop("indramqtt_bridge_"),
                "username": str_prop(""),
                "password": pwd_prop(),
                "keepalive": int_prop(60),
                "proto_ver": enum_prop(&["v3.1.1", "v5.0"], "v5.0"),
                "clean_start": bool_prop(true),
                "ssl": ssl_prop()
            }),
            &["name", "server"],
        ),
    );

    // 9. MongoDB
    schemas.insert(
        "bridge_mongodb.post_connector".to_string(),
        obj_schema_with_type(
            "mongodb",
            json!({
                "mongo_type": enum_prop(&["single", "rs", "sharded"], "single"),
                "server": str_prop("127.0.0.1:27017"),
                "database": str_prop("test"),
                "username": str_prop(""),
                "password": pwd_prop(),
                "auth_source": str_prop("admin"),
                "pool_size": int_prop(8),
                "ssl": ssl_prop()
            }),
            &["name", "server", "database"],
        ),
    );

    // 10. Cassandra
    schemas.insert(
        "bridge_cassa.post_connector".to_string(),
        obj_schema(
            json!({
                "servers": str_prop("127.0.0.1:9042"),
                "keyspace": str_prop("test"),
                "username": str_prop(""),
                "password": pwd_prop(),
                "ssl": ssl_prop()
            }),
            &["name", "servers", "keyspace"],
        ),
    );

    // 11. RabbitMQ
    schemas.insert(
        "rabbitmq.post".to_string(),
        obj_schema(
            json!({
                "server": str_prop("127.0.0.1:5672"),
                "virtual_host": str_prop("/"),
                "username": str_prop("guest"),
                "password": pwd_prop(),
                "ssl": ssl_prop()
            }),
            &["name", "server"],
        ),
    );

    // 12. Pulsar
    schemas.insert(
        "pulsar.post".to_string(),
        obj_schema(
            json!({
                "servers": str_prop("pulsar://127.0.0.1:6650"),
                "ssl": ssl_prop()
            }),
            &["name", "servers"],
        ),
    );

    // 13. Amazon S3
    schemas.insert(
        "bridge_s3.post_connector".to_string(),
        obj_schema(
            json!({
                "endpoint": str_prop("https://s3.amazonaws.com"),
                "bucket": str_prop("my-bucket"),
                "region": str_prop("us-east-1"),
                "access_key_id": str_prop(""),
                "secret_access_key": pwd_prop()
            }),
            &["name", "bucket"],
        ),
    );

    // 14. Azure Blob Storage
    schemas.insert(
        "connector_azure_blob_storage.post_connector".to_string(),
        obj_schema(
            json!({
                "account_name": str_prop(""),
                "account_key": pwd_prop(),
                "container": str_prop("data")
            }),
            &["name", "account_name", "container"],
        ),
    );

    // 15. InfluxDB
    schemas.insert(
        "bridge_influxdb.post_connector".to_string(),
        obj_schema(
            json!({
                "server": str_prop("http://127.0.0.1:8086"),
                "version": enum_prop(&["v1", "v2"], "v2"),
                "org": str_prop(""),
                "bucket": str_prop(""),
                "token": pwd_prop()
            }),
            &["name", "server"],
        ),
    );

    // 16. TimescaleDB
    schemas.insert(
        "bridge_timescale.post_connector".to_string(),
        obj_schema(
            json!({
                "server": str_prop("127.0.0.1:5432"),
                "database": str_prop("timeseries"),
                "username": str_prop("postgres"),
                "password": pwd_prop(),
                "pool_size": int_prop(8),
                "ssl": ssl_prop()
            }),
            &["name", "server", "database"],
        ),
    );

    // 17. TDengine
    schemas.insert(
        "tdengine_connector.post".to_string(),
        obj_schema(
            json!({
                "server": str_prop("127.0.0.1:6041"),
                "database": str_prop("db"),
                "username": str_prop("root"),
                "password": pwd_prop()
            }),
            &["name", "server", "database"],
        ),
    );

    // 18. OpenTSDB
    schemas.insert(
        "opents_connector.post".to_string(),
        obj_schema(
            json!({
                "server": str_prop("http://127.0.0.1:4242"),
                "summary": str_prop("")
            }),
            &["name", "server"],
        ),
    );

    // 19. IoTDB
    schemas.insert(
        "iotdb.post_restapi".to_string(),
        obj_schema(
            json!({
                "base_url": str_prop("http://127.0.0.1:18080"),
                "username": str_prop("root"),
                "password": pwd_prop()
            }),
            &["name", "base_url"],
        ),
    );
    schemas.insert(
        "iotdb.post_thrift".to_string(),
        obj_schema(
            json!({
                "server": str_prop("127.0.0.1:6667"),
                "username": str_prop("root"),
                "password": pwd_prop()
            }),
            &["name", "server"],
        ),
    );

    // 20. GreptimeDB
    schemas.insert(
        "bridge_greptimedb.post_connector".to_string(),
        obj_schema(
            json!({
                "server": str_prop("127.0.0.1:4002"),
                "dbname": str_prop("public"),
                "username": str_prop(""),
                "password": pwd_prop()
            }),
            &["name", "server", "dbname"],
        ),
    );

    // 21. Elasticsearch
    schemas.insert(
        "elasticsearch.post".to_string(),
        obj_schema(
            json!({
                "server": str_prop("http://127.0.0.1:9200"),
                "username": str_prop("elastic"),
                "password": pwd_prop(),
                "ssl": ssl_prop()
            }),
            &["name", "server"],
        ),
    );

    // 22. DynamoDB
    schemas.insert(
        "bridge_dynamodb.post_connector".to_string(),
        obj_schema(
            json!({
                "url": str_prop("https://dynamodb.us-east-1.amazonaws.com"),
                "region": str_prop("us-east-1"),
                "access_key_id": str_prop(""),
                "secret_access_key": pwd_prop()
            }),
            &["name", "url"],
        ),
    );

    // 23. Kinesis
    schemas.insert(
        "bridge_kinesis.post_connector".to_string(),
        obj_schema(
            json!({
                "endpoint": str_prop("https://kinesis.us-east-1.amazonaws.com"),
                "region": str_prop("us-east-1"),
                "access_key_id": str_prop(""),
                "secret_access_key": pwd_prop()
            }),
            &["name", "endpoint"],
        ),
    );

    // 24. Confluent
    schemas.insert(
        "confluent.post_connector".to_string(),
        obj_schema(
            json!({
                "bootstrap_hosts": str_prop(""),
                "ssl": ssl_prop()
            }),
            &["name", "bootstrap_hosts"],
        ),
    );

    // 25. Redshift
    schemas.insert(
        "connector_redshift.post_connector".to_string(),
        obj_schema(
            json!({
                "server": str_prop("127.0.0.1:5439"),
                "database": str_prop("dev"),
                "username": str_prop("awsuser"),
                "password": pwd_prop(),
                "ssl": ssl_prop()
            }),
            &["name", "server", "database"],
        ),
    );

    // 26. BigQuery
    schemas.insert(
        "connector_bigquery.post_connector".to_string(),
        obj_schema(
            json!({
                "gcp_project_id": str_prop(""),
                "service_account_json": pwd_prop()
            }),
            &["name", "gcp_project_id"],
        ),
    );

    // 27. Couchbase
    schemas.insert(
        "connector_couchbase.post_connector".to_string(),
        obj_schema(
            json!({
                "servers": str_prop("127.0.0.1:11210"),
                "bucket": str_prop("default"),
                "username": str_prop(""),
                "password": pwd_prop()
            }),
            &["name", "servers", "bucket"],
        ),
    );

    // 28. RocketMQ
    schemas.insert(
        "rocketmq.post_connector".to_string(),
        obj_schema(
            json!({
                "servers": str_prop("127.0.0.1:9876"),
                "access_key": str_prop(""),
                "secret_key": pwd_prop()
            }),
            &["name", "servers"],
        ),
    );

    // 29. Oracle
    schemas.insert(
        "bridge_oracle.post_connector".to_string(),
        obj_schema(
            json!({
                "server": str_prop("127.0.0.1:1521"),
                "service_name": str_prop("XE"),
                "username": str_prop("system"),
                "password": pwd_prop()
            }),
            &["name", "server", "service_name"],
        ),
    );

    // 30. Microsoft SQL Server
    schemas.insert(
        "bridge_mssql.post_connector".to_string(),
        obj_schema(
            json!({
                "server": str_prop("127.0.0.1:1433"),
                "database": str_prop("master"),
                "username": str_prop("sa"),
                "password": pwd_prop(),
                "ssl": ssl_prop()
            }),
            &["name", "server", "database"],
        ),
    );
    schemas.insert(
        "bridge_sqlserver.post_connector".to_string(),
        obj_schema(
            json!({
                "server": str_prop("127.0.0.1:1433"),
                "database": str_prop("master"),
                "username": str_prop("sa"),
                "password": pwd_prop(),
                "ssl": ssl_prop()
            }),
            &["name", "server", "database"],
        ),
    );

    // 31. CockroachDB
    schemas.insert(
        "connector_cockroachdb.post_connector".to_string(),
        obj_schema(
            json!({
                "server": str_prop("127.0.0.1:26257"),
                "database": str_prop("defaultdb"),
                "username": str_prop("root"),
                "password": pwd_prop(),
                "ssl": ssl_prop()
            }),
            &["name", "server", "database"],
        ),
    );

    // 32. Doris
    schemas.insert(
        "connector_doris.post_connector".to_string(),
        obj_schema(
            json!({
                "server": str_prop("127.0.0.1:9030"),
                "database": str_prop("doris_db"),
                "username": str_prop("root"),
                "password": pwd_prop()
            }),
            &["name", "server", "database"],
        ),
    );

    // 33. Tablestore
    schemas.insert(
        "bridge_tablestore.post_connector".to_string(),
        obj_schema(
            json!({
                "endpoint": str_prop(""),
                "instance_name": str_prop(""),
                "access_key_id": str_prop(""),
                "access_key_secret": pwd_prop()
            }),
            &["name", "endpoint", "instance_name"],
        ),
    );

    // 34. Amazon Timestream
    schemas.insert(
        "connector_aws_timestream.post_connector".to_string(),
        obj_schema(
            json!({
                "region": str_prop("us-east-1"),
                "database": str_prop(""),
                "access_key_id": str_prop(""),
                "secret_access_key": pwd_prop()
            }),
            &["name", "database"],
        ),
    );

    // 35. GCP Pub/Sub
    schemas.insert(
        "gcp_pubsub_producer.post_connector".to_string(),
        obj_schema(
            json!({
                "gcp_project_id": str_prop(""),
                "service_account_json": pwd_prop()
            }),
            &["name", "gcp_project_id"],
        ),
    );
    schemas.insert(
        "gcp_pubsub_consumer.post_connector".to_string(),
        obj_schema(
            json!({
                "gcp_project_id": str_prop(""),
                "service_account_json": pwd_prop()
            }),
            &["name", "gcp_project_id"],
        ),
    );

    // 36. Azure Event Hubs
    schemas.insert(
        "bridge_azure_event_hub.post_connector".to_string(),
        obj_schema(
            json!({
                "connection_string": pwd_prop()
            }),
            &["name", "connection_string"],
        ),
    );

    // 37. Snowflake
    schemas.insert(
        "connector_snowflake_aggregated.post_connector".to_string(),
        obj_schema(
            json!({
                "account": str_prop(""),
                "database": str_prop(""),
                "schema": str_prop(""),
                "username": str_prop(""),
                "password": pwd_prop()
            }),
            &["name", "account", "database"],
        ),
    );
    schemas.insert(
        "connector_snowflake_streaming.post_connector".to_string(),
        obj_schema(
            json!({
                "account": str_prop(""),
                "database": str_prop(""),
                "schema": str_prop(""),
                "username": str_prop(""),
                "password": pwd_prop()
            }),
            &["name", "account", "database"],
        ),
    );

    // 38. AlloyDB
    schemas.insert(
        "connector_alloydb.post_connector".to_string(),
        obj_schema(
            json!({
                "server": str_prop("127.0.0.1:5432"),
                "database": str_prop("postgres"),
                "username": str_prop("postgres"),
                "password": pwd_prop(),
                "ssl": ssl_prop()
            }),
            &["name", "server", "database"],
        ),
    );

    // 39. Disk Log
    schemas.insert(
        "connector_disk_log.post_connector".to_string(),
        obj_schema(
            json!({
                "file": str_prop("data/disk_log.txt")
            }),
            &["name", "file"],
        ),
    );

    // 40. S3 Tables
    schemas.insert(
        "connector_s3tables.post_connector".to_string(),
        obj_schema(
            json!({
                "table_bucket_arn": str_prop(""),
                "namespace": str_prop("default"),
                "access_key_id": str_prop(""),
                "secret_access_key": pwd_prop()
            }),
            &["name", "table_bucket_arn"],
        ),
    );

    // 41. Datalayers
    schemas.insert(
        "bridge_datalayers.post_connector".to_string(),
        obj_schema(
            json!({
                "server": str_prop("127.0.0.1:8360"),
                "database": str_prop("iot"),
                "username": str_prop("root"),
                "password": pwd_prop()
            }),
            &["name", "server", "database"],
        ),
    );

    // 42. SysKeeper
    schemas.insert(
        "syskeeper_forwarder.post".to_string(),
        obj_schema(
            json!({
                "server": str_prop("127.0.0.1:9000")
            }),
            &["name", "server"],
        ),
    );
    schemas.insert(
        "connector_syskeeper_proxy.post".to_string(),
        obj_schema(
            json!({
                "listen": str_prop("0.0.0.0:9000"),
                "acceptors": int_prop(16),
                "handshake_timeout": str_prop("15s")
            }),
            &["name", "listen"],
        ),
    );

    json!({
        "title": "Connectors Schema",
        "version": "0.2.0",
        "components": {
            "schemas": Value::Object(schemas)
        }
    })
});

static ACTIONS_SCHEMA: LazyLock<Value> = LazyLock::new(|| {
    let mut schemas = serde_json::Map::new();

    // Redis action
    schemas.insert(
        "redis.post_bridge_v2".to_string(),
        obj_schema_with_type(
            "redis",
            json!({
                "connector": str_prop(""),
                "command": json!({
                    "type": "array",
                    "items": { "type": "string" },
                    "default": ["HSET", "${clientid}", "${payload.key}", "${payload.value}"]
                })
            }),
            &["name", "connector"],
        ),
    );

    // Kafka action
    schemas.insert(
        "bridge_kafka.post_bridge_v2".to_string(),
        obj_schema_with_type(
            "kafka",
            json!({
                "connector": str_prop(""),
                "kafka_topic": str_prop("iot_telemetry"),
                "payload": str_prop("${payload}")
            }),
            &["name", "connector", "kafka_topic"],
        ),
    );

    // HTTP action
    schemas.insert(
        "bridge_http.post_bridge_v2".to_string(),
        obj_schema_with_type(
            "http",
            json!({
                "connector": str_prop(""),
                "body": str_prop("${payload}"),
                "method": enum_prop(&["post", "put", "get"], "post")
            }),
            &["name", "connector"],
        ),
    );

    // PostgreSQL action
    schemas.insert("bridge_pgsql.post_bridge_v2".to_string(), obj_schema_with_type("pgsql", json!({
        "connector": str_prop(""),
        "sql": str_prop("INSERT INTO telemetry(clientid, topic, payload, timestamp) VALUES (${clientid}, ${topic}, ${payload}, ${timestamp})")
    }), &["name", "connector", "sql"]));

    // MySQL action
    schemas.insert("bridge_mysql.post_bridge_v2".to_string(), obj_schema_with_type("mysql", json!({
        "connector": str_prop(""),
        "sql": str_prop("INSERT INTO telemetry(clientid, topic, payload, timestamp) VALUES (${clientid}, ${topic}, ${payload}, ${timestamp})")
    }), &["name", "connector", "sql"]));

    // ClickHouse action
    schemas.insert("bridge_clickhouse.post_bridge_v2".to_string(), obj_schema_with_type("clickhouse", json!({
        "connector": str_prop(""),
        "sql": str_prop("INSERT INTO telemetry VALUES (${clientid}, ${topic}, ${payload}, now())")
    }), &["name", "connector", "sql"]));

    // MQTT action
    schemas.insert(
        "bridge_mqtt_publisher.post_bridge_v2".to_string(),
        obj_schema_with_type(
            "mqtt",
            json!({
                "connector": str_prop(""),
                "topic": str_prop("forward/${topic}"),
                "payload": str_prop("${payload}"),
                "qos": int_prop(1)
            }),
            &["name", "connector", "topic"],
        ),
    );

    json!({
        "title": "Actions Schema",
        "version": "0.2.0",
        "components": {
            "schemas": Value::Object(schemas)
        }
    })
});

pub async fn get_schema(Path(name): Path<String>) -> Response {
    let body = match name.as_str() {
        "connectors" => CONNECTORS_SCHEMA.clone(),
        "actions" => ACTIONS_SCHEMA.clone(),
        _ => {
            return (StatusCode::NOT_FOUND, Json(json!({ "code": "NOT_FOUND" }))).into_response();
        }
    };

    (
        StatusCode::OK,
        [("content-type", "application/json")],
        Json(body),
    )
        .into_response()
}

pub async fn list_schemas() -> Response {
    (StatusCode::OK, Json(json!(["actions", "connectors"]))).into_response()
}
