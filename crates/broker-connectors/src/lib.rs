#![allow(unknown_lints)]
#![allow(clippy::chunks_exact_to_as_chunks)]

use async_trait::async_trait;
use broker_protocol::{QoS, Topic};
use bytes::Bytes;
use reqwest::header::{HeaderMap, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;

pub mod alloydb;
pub mod aws_iot;
pub mod azure_blob;
pub mod azure_eventhubs;
pub mod azure_iot;
pub mod bigquery;
pub mod cassandra;
pub mod clickhouse;
pub mod cloud_tls;
pub mod cockroachdb;
pub mod confluent;
pub mod couchbase;
pub mod databricks;
pub mod datalayers;
pub mod disk_log;
pub mod doris;
pub mod dynamodb;
pub mod elasticsearch;
pub mod gcp_iot;
pub mod gcp_pubsub;
pub mod greptimedb;
pub mod http;
pub mod influxdb;
pub mod iotdb;
pub mod kafka;
pub mod kinesis;
pub mod mongodb;
pub mod mqtt_bridge;
pub mod mssql;
pub mod mysql;
pub mod oci_streaming;
pub mod opc_ua;
pub mod opentsdb;
pub mod oracle;
pub mod postgres;
pub mod pulsar;
pub mod rabbitmq;
pub mod redis;
pub mod redshift;
pub mod rocketmq;
pub mod s3;
pub mod s3_tables;
pub mod snowflake;
pub mod sparkplug_b;
pub mod tablestore;
pub mod tdengine;
pub mod timescaledb;
pub mod timestream;

pub use alloydb::{
    alloydb_connect_config, alloydb_value_to_boxed, build_alloydb_insert_query,
    classify_alloydb_error, extract_alloydb_row, map_driver_error, resolve_alloydb_password,
    AlloydbAuth, AlloydbColumnMapping, AlloydbConfig, AlloydbConnector, AlloydbErrorClassification,
    AlloydbQueryResult, AlloydbRow, AlloydbSink, AlloydbTransport, AlloydbValue,
    CapturedAlloydbExecution, MockAlloydbTransport, PgDriverAlloydbTransport, TcpAlloydbTransport,
};
pub use aws_iot::{
    shadow_update_document, sign_websocket_url, sigv4_signature_via_sdk, sigv4_signing_key_manual,
    sigv4_signing_key_via_sdk, AwsIotAuth, AwsIotConfig, AwsIotConnector, AwsIotFrame, AwsIotSink,
    AwsIotTransport, BridgeDirection, BridgeTopicMapping, MockAwsIotOutcome, MockAwsIotTransport,
    ShadowSyncConfig, ShadowTopics, TlsAwsIotTransport,
};
pub use azure_blob::{
    azure_error_code, canonicalized_resource, classify_blob_status, container_string_to_sign,
    shared_key_authorization, string_to_sign as azure_blob_string_to_sign, AzureBlobAuth,
    AzureBlobCompression, AzureBlobOutcome, AzureBlobPut, AzureBlobSink, AzureBlobSinkConfig,
    AzureBlobTransport, HttpAzureBlobTransport, MockAzureBlobTransport, AZURE_STORAGE_VERSION,
};
pub use azure_eventhubs::{
    render_batch_body as render_azure_batch_body, sas_token, AzureEventHubsConnector,
    AzureEventHubsSink, AzureEventHubsSinkConfig, AzureEventHubsTransport, AzureEventItem,
    CapturedAzureBatch, HttpAzureEventHubsTransport, MockAzureEventHubsTransport, MockAzureOutcome,
};
pub use azure_iot::{
    d2c_topic, parse_property_bag, sas_expiry, sas_token as azure_iot_sas_token, AzureIotAuth,
    AzureIotConfig, AzureIotConnectTransport, AzureIotPublish, AzureIotSink, AzureIotTransport,
    CapturedAzureIotPublish, MockAzureIotOutcome, MockAzureIotTransport, TlsAzureIotTransport,
    TwinTopics,
};
pub use bigquery::{
    classify_driver_response, classify_insert_errors, driver_insert_request,
    render_insert_body as render_bigquery_body, BigQueryConnector, BigQueryInsertResponse,
    BigQueryRowEntry, BigQuerySink, BigQuerySinkConfig, BigQueryTransport, CapturedBigQueryInsert,
    HttpBigQueryTransport, MockBigQueryOutcome, MockBigQueryTransport, SdkBigQueryTransport,
};
pub use cassandra::{
    decode_frame as decode_cql_frame, encode_batch as encode_cql_batch, murmur3_token,
    parse_contact_point, CapturedCqlBatch, CassandraAuth, CassandraConnector, CassandraSink,
    CassandraSinkConfig, CassandraTransport, CqlBoundStatement, CqlConsistency, CqlError,
    CqlResultKind, MockCassandraOutcome, MockCassandraTransport, NativeCassandraTransport,
    ScyllaCassandraTransport,
};
pub use clickhouse::{
    CapturedClickHouseBatch, ClickHouseConnector, ClickHouseRow, ClickHouseSink,
    ClickHouseSinkConfig, ClickHouseTransport, DriverClickHouseTransport, HttpClickHouseTransport,
    MockClickHouseOutcome, MockClickHouseTransport,
};
pub use cockroachdb::{
    build_native_upsert_query, build_on_conflict_upsert_query, classify_cockroach_sqlstate,
    cockroach_connect_config, cockroach_use_tls, cockroach_value_to_boxed, extract_cockroach_row,
    map_cockroach_driver_error, CapturedCockroachExecution, CockroachDbConfig,
    CockroachDbConnector, CockroachDbSink, CockroachDbTransport, CockroachErrorClassification,
    CockroachQueryResult, CockroachRow, CockroachValue, MockCockroachDbTransport,
    PgDriverCockroachDbTransport, TcpCockroachDbTransport,
};
pub use confluent::{
    classify_driver_error, classify_kafka_error, frame_schema_registry, is_terminal_driver_message,
    parse_scram_server_first, rdkafka_client_config, registry_subject_for_topic,
    resolve_key as resolve_confluent_key, resolve_template as resolve_confluent_template,
    resolve_topic as resolve_confluent_topic, sasl_plain_payload, schema_registry_basic_auth,
    scram_client_first_message, scram_client_proof as scram_confluent_client_proof, scram_hi,
    scram_nonce, scram_server_signature, split_schema_registry, ConfluentKafkaConfig,
    ConfluentKafkaConnector, ConfluentKafkaSink, ConfluentOutcome, ConfluentRecord,
    ConfluentSchemaRegistryConfig, ConfluentTransport, MemoryConfluentTransport,
    RdkafkaConfluentTransport, RegistrySchemaClient, SaslMechanism, ScramHash, ScramServerFirst,
    TcpConfluentTransport,
};
pub use couchbase::{
    decode_response as decode_kv_response, encode_mutation as encode_kv_mutation,
    parse_connection_string as parse_couchbase_connection_string, CapturedCouchbaseBatch,
    CouchbaseAuth, CouchbaseConnector, CouchbaseDocItem, CouchbaseEndpoint, CouchbaseOperation,
    CouchbaseSink, CouchbaseSinkConfig, CouchbaseTransport, DriverCouchbaseTransport, KvResponse,
    MockCouchbaseOutcome, MockCouchbaseTransport, NativeCouchbaseTransport,
};
pub use databricks::{
    parse_result_rows, parse_statement_id, parse_statement_response, parse_statement_state,
    render_statement_body, statement_status_url, CapturedDatabricksStatement, DatabricksConnector,
    DatabricksParam, DatabricksSink, DatabricksSinkConfig, DatabricksTransport,
    HttpDatabricksTransport, MockDatabricksOutcome, MockDatabricksTransport, StatementState,
};
pub use datalayers::{
    extract_datalayers_record, extract_microsecond_timestamp, parse_count_result, DatalayersConfig,
    DatalayersConnector, DatalayersRecord, DatalayersSink, DatalayersTransport,
    DatalayersWriteRequest, HttpDatalayersTransport, MockDatalayersTransport,
};
pub use disk_log::{
    BackupInfo, DiskLogCompression, DiskLogConnector, DiskLogFormat, DiskLogSink,
    DiskLogSinkConfig, DiskLogWriter, DiskSyncMode, FileDiskLogWriter, MemoryDiskLogWriter,
};
pub use doris::{
    classify_status as classify_doris_status, doris_http_client, parse_load_result,
    render_body as render_doris_body, CapturedDorisLoad, DorisAuth, DorisConnector, DorisFormat,
    DorisHeaders, DorisLoadResult, DorisSink, DorisSinkConfig, DorisTransport, HttpDorisTransport,
    MockDorisOutcome, MockDorisTransport,
};
pub use dynamodb::{
    attribute_value_from_dynamodb_json, build_item_body, dynamodb_attribute,
    item_body_to_attribute_map, parse_unprocessed, render_batch_body as render_dynamodb_batch_body,
    DynamoDbBatchWriteRequest, DynamoDbConnector, DynamoDbItem, DynamoDbSink, DynamoDbSinkConfig,
    DynamoDbTransport, DynamoKeyConfig, HttpDynamoDbTransport, MockDynamoDbOutcome,
    MockDynamoDbTransport, SdkDynamoDbTransport, DYNAMODB_CONTENT_TYPE, DYNAMODB_TARGET,
};
pub use elasticsearch::{
    BulkOutcome, CapturedBulk, DriverElasticsearchTransport, ElasticsearchAuth,
    ElasticsearchConnector, ElasticsearchSink, ElasticsearchSinkConfig, ElasticsearchTransport,
    HttpElasticsearchTransport, MockElasticsearchTransport,
};
pub use gcp_iot::{
    build_jwt as build_gcp_iot_jwt, next_refresh_ms, parse_telemetry_topic, route_downlink,
    state_topic, telemetry_topic, validate_state_snapshot, CapturedGcpIotPublish, DownlinkRoute,
    GcpIotAlgorithm, GcpIotConfig, GcpIotConnector, GcpIotSink, GcpIotTokenCache, GcpIotTransport,
    MockGcpIotOutcome, MockGcpIotTransport, TcpGcpIotTransport, TlsGcpIotTransport,
};
pub use gcp_pubsub::{
    build_jwt_assertion, driver_message_for, parse_publish_response, render_publish_body,
    CapturedGcpPublish, GcpAuth, GcpPubSubConnector, GcpPubSubMessage, GcpPubSubSink,
    GcpPubSubSinkConfig, GcpPubSubTransport, GcpTokenCache, HttpGcpPubSubTransport, MockGcpOutcome,
    MockGcpPubSubTransport, SdkGcpPubSubTransport, GCP_PUBSUB_SCOPE, GCP_TOKEN_URL,
};
pub use greptimedb::{
    build_greptime_sql_insert, build_influx_line_protocol, extract_greptime_record,
    resolve_table_name as resolve_greptime_table, GreptimeDbAuth, GreptimeDbConfig,
    GreptimeDbConnector, GreptimeDbSink, GreptimeDbTransport, GreptimeFormat, GreptimePrecision,
    GreptimeRecord, GreptimeValue, HttpGreptimeDbTransport, MockGreptimeDbTransport,
};
pub use http::{
    CapturedHttpRequest, HmacAlgorithm, HmacEncoding, HttpAuth, HttpBodyFormat, HttpConnector,
    HttpHmacSignature, HttpMethod, HttpRequest, HttpResponse, HttpSink, HttpSinkConfig,
    HttpTransport, MockHttpOutcome, MockHttpTransport, ReqwestHttpTransport,
};
pub use influxdb::{InfluxDbConnector, InfluxDbSink, InfluxDbSinkConfig};
pub use iotdb::{
    render_tablet_body, CapturedIotDbTablet, HttpIotDbTransport, IotDbAuth, IotDbConnector,
    IotDbDataType, IotDbSink, IotDbSinkConfig, IotDbTabletRequest, IotDbTransport,
    MockIotDbOutcome, MockIotDbTransport,
};
pub use kafka::{
    classify_driver_error as classify_kafka_driver_error,
    is_terminal_driver_message as is_kafka_terminal_driver_message,
    rdkafka_client_config as rdkafka_kafka_client_config, KafkaRecord, KafkaSink, KafkaSinkConfig,
    KafkaTransport, MemoryKafkaTransport, RdkafkaKafkaTransport, TcpKafkaTransport,
};
pub use kinesis::{
    HttpKinesisTransport, KinesisConnector, KinesisPutRecordsRequest, KinesisPutRecordsResponse,
    KinesisRecordEntry, KinesisRecordResult, KinesisSink, KinesisSinkConfig, KinesisTransport,
    MockKinesisOutcome, MockKinesisTransport, KINESIS_CONTENT_TYPE, KINESIS_TARGET,
};
pub use mongodb::{
    decode_op_msg, encode_op_msg, generate_object_id, json_to_bson, parse_connection_string,
    scram_client_proof, BsonDocument, BsonValue, CapturedMongoBulk, MockMongoDbTransport,
    MockMongoOutcome, MongoDbConnector, MongoDbDocumentItem, MongoDbSink, MongoDbSinkConfig,
    MongoDbTransport, MongoEndpoint, MongoOperation, NativeMongoDbTransport,
};
pub use mqtt_bridge::{
    decode_publish, decode_remaining_length, encode_publish, encode_remaining_length,
    parse_bridge_address, BridgeEndpoint, DecodedPublish, MemoryMqttBridgeTransport,
    MqttBridgeConnector, MqttBridgeProtocol, MqttBridgeSink, MqttBridgeSinkConfig,
    MqttBridgeTransport, RumqttcMqttBridgeTransport, SerializedMqttPacket, TcpMqttBridgeTransport,
};
pub use mssql::{
    days_from_civil, encode_datetimeoffset, encode_executesql, obscure_password,
    parse_reply_tokens, CapturedMssqlBatch, MockMssqlOutcome, MockMssqlTransport, MssqlAuth,
    MssqlConnector, MssqlQueryMode, MssqlRowItem, MssqlSink, MssqlSinkConfig, MssqlTransport,
    NativeMssqlTransport, TdsReply,
};
pub use mysql::{
    DriverMySqlTransport, MemoryMySqlTransport, MySqlBatch, MySqlSink, MySqlSinkConfig,
    MySqlTransport, TcpMySqlTransport,
};
pub use oci_streaming::{
    authorization_header, content_sha256_b64, failed_positions, parse_rsa_key, render_put_messages,
    rfc1123_date, rsa_sign, signing_string, HttpOciStreamingTransport, MockOciOutcome,
    MockOciPutMessages, MockOciStreamingTransport, OciAuthHeaders, OciMessage,
    OciStreamingConnector, OciStreamingSink, OciStreamingSinkConfig, OciStreamingTransport,
};
pub use opc_ua::{
    datetime_from_millis, datetime_to_rfc3339, decode_chunk, decode_data_value, decode_variant,
    encode_chunk, encode_data_value, encode_variant, encode_write_request, notification_to_json,
    MemoryOpcUaTransport, NodeSubscriptionConfig, OpcUaAuth, OpcUaChannelFrame, OpcUaConnector,
    OpcUaDataValue, OpcUaHello, OpcUaNodeId, OpcUaNodeIdValue, OpcUaSecurityMode,
    OpcUaSecurityPolicy, OpcUaSeverity, OpcUaSink, OpcUaSinkConfig, OpcUaStatus, OpcUaTransport,
    OpcUaVariant, OpcUaVariantKind, OpcUaWriteFrame, TcpOpcUaTransport,
};
pub use opentsdb::{
    extract_opentsdb_point, sanitize_opentsdb_string, serialize_telnet_lines,
    MockOpenTsdbTransport, NetworkOpenTsdbTransport, OpenTsdbCompression, OpenTsdbConfig,
    OpenTsdbConnector, OpenTsdbDataPoint, OpenTsdbProtocol, OpenTsdbSink, OpenTsdbSummaryResponse,
    OpenTsdbTransport,
};
pub use oracle::{
    build_merge_sql, classify_ora_error, extract_oracle_row, CapturedOracleExecution,
    HttpOracleTransport, MockOracleTransport, OraErrorClassification, OracleBindParam,
    OracleConnector, OracleResponse, OracleRow, OracleSink, OracleSinkConfig, OracleTransport,
    OracleValue,
};
pub use postgres::{
    DriverPgTransport, MemoryPgTransport, PgBatch, PgTransport, PostgreSqlSink,
    PostgreSqlSinkConfig, TcpPgTransport,
};
pub use pulsar::{
    crc32c, decode_frame, decode_metadata, encode_message_frame, parse_service_url,
    CapturedProduce, DecodedMetadata, MemoryPulsarTransport, PulsarAuth, PulsarConnector,
    PulsarEndpoint, PulsarMessage, PulsarSink, PulsarSinkConfig, PulsarTransport,
    TcpPulsarTransport,
};
pub use rabbitmq::{
    AmqpFrame, LapinRabbitTransport, MemoryAmqpTransport, RabbitMqSink, RabbitMqSinkConfig,
    RabbitMqTransport, TcpRabbitTransport,
};
pub use redis::{
    DriverRedisTransport, MemoryRedisTransport, RedisCommand, RedisCommandKind, RedisReply,
    RedisSink, RedisSinkConfig, RedisTransport, TcpRedisTransport,
};
pub use redshift::{
    default_insert as redshift_default_insert, render_batch_body as render_redshift_batch_body,
    render_statement as render_redshift_statement, HttpRedshiftTransport, MockRedshiftOutcome,
    MockRedshiftTransport, RedshiftBatchRequest, RedshiftBatchResponse, RedshiftConnector,
    RedshiftSink, RedshiftSinkConfig, RedshiftTransport,
};
pub use rocketmq::{
    authorization_header as rocketmq_authorization,
    build_system_properties as build_rocketmq_properties,
    classify_status as classify_rocketmq_status, decode_envelope as decode_rocketmq_envelope,
    encode_envelope as encode_rocketmq_envelope, fifo_partition, fnv1a_32,
    md5_hex as rocketmq_md5_hex, resolve_system_field as resolve_rocketmq_field,
    signing_string as rocketmq_signing_string, MockRocketMqTransport, RocketMqConnector,
    RocketMqEnvelope, RocketMqEnvelopeMessage, RocketMqMessage, RocketMqOutcome, RocketMqSink,
    RocketMqSinkConfig, RocketMqStatus, RocketMqSystemProperties, RocketMqTransport,
    TcpRocketMqTransport, ENVELOPE_VERSION,
};
pub use s3::{
    HttpS3Transport, MockS3Transport, S3Compression, S3Connector, S3Put, S3Sink, S3SinkConfig,
    S3Transport, SdkS3Transport, SigV4Request,
};
pub use s3_tables::{
    apply_partition_transform, classify_put_status as classify_s3tables_status, data_file_path,
    parse_table_bucket_arn, partition_path, render_snapshot, s3tables_authorization,
    HttpS3TablesTransport, IcebergPartitionField, IcebergTransform, MockS3TablesTransport,
    S3TablesConnector, S3TablesFormat, S3TablesOutcome, S3TablesPut, S3TablesSigning, S3TablesSink,
    S3TablesSinkConfig, S3TablesTransport, SnapshotFile, TableBucketArn,
};
pub use snowflake::{
    build_jwt_assertion as build_snowflake_jwt, render_rows_body as render_snowflake_rows,
    CapturedSnowflakeInsert, HttpSnowflakeTransport, MockSnowflakeOutcome, MockSnowflakeTransport,
    SnowflakeConnector, SnowflakeRowItem, SnowflakeSink, SnowflakeSinkConfig, SnowflakeTransport,
};
pub use sparkplug_b::{
    decode_metric, decode_payload, decode_varint, encode_metric, encode_payload, encode_varint,
    payload_from_json, payload_to_json, tier, MemorySparkplugTransport, SparkplugBConnector,
    SparkplugBSink, SparkplugFrame, SparkplugMessageType, SparkplugSinkConfig,
    SparkplugStateMachine, SparkplugTopic, SparkplugTransport, SpbAnomaly, SpbDataType,
    SpbIngestOutcome, SpbMetric, SpbPayload, SpbValue, SPARKPLUG_TIER,
};
pub use tablestore::{
    classify_error_code as classify_ots_error_code,
    classify_http_status as classify_ots_http_status, content_md5_b64,
    failed_positions as tablestore_failed_positions, ots_authorization,
    render_batch_body as render_ots_batch_body, string_to_sign as ots_string_to_sign,
    AttributeColumnMapping, AttributeColumnType, HttpTablestoreTransport, MockTablestoreOutcome,
    MockTablestoreTransport, OtsOutcome, OtsRow, OtsRowFailure, OtsValue, PrimaryKeyMapping,
    PrimaryKeyType, TablestoreAuth, TablestoreConnector, TablestoreSink, TablestoreSinkConfig,
    TablestoreTransport, BATCH_WRITE_ROW_PATH, OTS_API_VERSION,
};
pub use tdengine::{
    parse_rest_response, render_insert, CapturedTdengineSql, HttpTdengineTransport,
    MockTdengineOutcome, MockTdengineTransport, TdengineAuth, TdengineConnector, TdengineResponse,
    TdengineRow, TdengineSink, TdengineSinkConfig, TdengineTransport,
};
pub use timescaledb::{
    DriverTimescaleDbTransport, MockTimescaleTransport, TcpTimescaleTransport, TimescaleBatch,
    TimescaleDbConnector, TimescaleDbSink, TimescaleDbSinkConfig, TimescaleDbTransport,
};
pub use timestream::{
    render_write_records_body, HttpTimestreamTransport, MockTimestreamOutcome,
    MockTimestreamTransport, TimestreamConnector, TimestreamRecord, TimestreamSink,
    TimestreamSinkConfig, TimestreamTimeUnit, TimestreamTransport, TimestreamWriteRequest,
    TimestreamWriteResponse, TIMESTREAM_CONTENT_TYPE, TIMESTREAM_TARGET,
};

#[derive(Error, Debug)]
pub enum ConnectorError {
    #[error("Connector dispatch failure: {0}")]
    Dispatch(String),

    #[error("Connector connection error: {0}")]
    Connection(String),

    #[error("Unknown connector: {0}")]
    UnknownConnector(String),
}

pub type Result<T> = std::result::Result<T, ConnectorError>;

/// Unified outbound boundary: every streaming sink implements `Sink`.
#[async_trait]
pub trait Sink: Send + Sync {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()>;
    /// Stable kind name for management display (`webhook`, `console`,
    /// `kafka`, `rabbitmq`, ...).
    fn kind(&self) -> &'static str;
}

/// Unified connector identity: a registered, addressable sink.
pub trait Connector: Send + Sync {
    fn connector_id(&self) -> &str;
    fn kind(&self) -> &'static str;
}

/// Management view of one registered connector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorInfo {
    pub id: String,
    pub kind: String,
}

/// Open-core tier tag for a connector kind: the multi-cloud
/// streaming bridges, Sparkplug B, the enterprise databases, the
/// industrial time-series stores, the lakehouse sinks, the cloud
/// object/wide-column stores and the enterprise messaging bridges are
/// Enterprise; everything else is Community.
pub fn connector_tier(kind: &str) -> &'static str {
    match kind {
        "kinesis" | "gcp_pubsub" | "azure_eventhubs" | "pulsar" | "sparkplug_b" | "mongodb"
        | "mssql" | "cassandra" | "couchbase" | "tdengine" | "iotdb" | "timestream"
        | "dynamodb" | "snowflake" | "databricks" | "doris" | "bigquery" | "redshift"
        | "oci_streaming" | "aws_iot" | "azure_iot" | "gcp_iot" | "opc_ua" | "azure_blob"
        | "tablestore" | "s3_tables" | "confluent" | "rocketmq" | "oracle" | "cockroachdb"
        | "alloydb" | "datalayers" => "enterprise",
        _ => "community",
    }
}

/// Manager-side handle pairing an id with its sink.
pub struct RegisteredConnector {
    id: String,
    sink: Arc<dyn Sink>,
}

impl RegisteredConnector {
    fn new(id: String, sink: Arc<dyn Sink>) -> Self {
        Self { id, sink }
    }
}

impl Connector for RegisteredConnector {
    fn connector_id(&self) -> &str {
        &self.id
    }

    fn kind(&self) -> &'static str {
        self.sink.kind()
    }
}

/// Default per-request timeout for webhook delivery.
pub const DEFAULT_WEBHOOK_TIMEOUT: Duration = Duration::from_secs(5);

/// HTTP webhook sink: POSTs the raw event payload to a URL.
///
/// The payload bytes travel untouched as the request body (already JSON
/// after SQL projection); topic and QoS ride along as `X-MQTT-Topic` /
/// `X-MQTT-QoS` headers plus any configured custom headers. The shared
/// `reqwest::Client` owns connection pooling. Non-2xx responses are
/// dispatch failures; transport errors are connection failures.
pub struct HttpWebhookSink {
    url: String,
    headers: HeaderMap,
    client: reqwest::Client,
    timeout: Duration,
    sent: AtomicU64,
}

impl HttpWebhookSink {
    pub fn new(url: String, headers: HeaderMap, client: reqwest::Client) -> Self {
        Self {
            url,
            headers,
            client,
            timeout: DEFAULT_WEBHOOK_TIMEOUT,
            sent: AtomicU64::new(0),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn sent_count(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl Sink for HttpWebhookSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        let response = self
            .client
            .post(&self.url)
            .headers(self.headers.clone())
            .header(CONTENT_TYPE, "application/json")
            .header("X-MQTT-Topic", topic.as_str())
            .header("X-MQTT-QoS", u8::from(qos).to_string())
            .body(payload.to_vec())
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| ConnectorError::Connection(e.to_string()))?;

        let status = response.status();
        if !status.is_success() {
            return Err(ConnectorError::Dispatch(format!(
                "webhook {} answered {}",
                self.url, status
            )));
        }
        self.sent.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "webhook"
    }
}

/// Formatted diagnostic sink: traces every event at INFO with a payload
/// preview (full payload when UTF-8 and short). Counts deliveries for
/// tests and health reporting.
pub struct ConsoleLoggerSink {
    name: String,
    max_preview_bytes: usize,
    logged: AtomicU64,
}

impl ConsoleLoggerSink {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            max_preview_bytes: 256,
            logged: AtomicU64::new(0),
        }
    }

    pub fn logged_count(&self) -> u64 {
        self.logged.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl Sink for ConsoleLoggerSink {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        let preview = match std::str::from_utf8(payload) {
            Ok(text) if text.len() <= self.max_preview_bytes => text.into(),
            Ok(text) => format!(
                "{}…<{} bytes total>",
                &text[..self.max_preview_bytes],
                payload.len()
            ),
            Err(_) => format!("<{} non-UTF8 bytes>", payload.len()),
        };
        tracing::info!(
            connector = %self.name,
            topic = %topic,
            qos = u8::from(qos),
            payload = %preview,
            "connector event"
        );
        self.logged.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "console"
    }
}

/// Registry of live outbound connectors by id.
#[derive(Default)]
pub struct ConnectorManager {
    connectors: parking_lot::RwLock<HashMap<String, RegisteredConnector>>,
}

impl ConnectorManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, id: impl Into<String>, sink: Arc<dyn Sink>) {
        let id = id.into();
        self.connectors
            .write()
            .insert(id.clone(), RegisteredConnector::new(id, sink));
    }

    pub fn unregister(&self, id: &str) -> bool {
        self.connectors.write().remove(id).is_some()
    }

    pub fn get(&self, id: &str) -> Option<Arc<dyn Sink>> {
        self.connectors
            .read()
            .get(id)
            .map(|entry| entry.sink.clone())
    }

    pub fn ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.connectors.read().keys().cloned().collect();
        ids.sort();
        ids
    }

    /// Ordered management view (`id` + `kind`) for the dashboard.
    pub fn infos(&self) -> Vec<ConnectorInfo> {
        let mut infos: Vec<ConnectorInfo> = self
            .connectors
            .read()
            .values()
            .map(|entry| ConnectorInfo {
                id: entry.connector_id().to_string(),
                kind: entry.kind().to_string(),
            })
            .collect();
        infos.sort_by(|a, b| a.id.cmp(&b.id));
        infos
    }

    /// Deliver one event through the named connector.
    pub async fn send(&self, id: &str, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
        match self.get(id) {
            Some(sink) => sink.send(topic, payload, qos).await,
            None => Err(ConnectorError::UnknownConnector(id.to_string())),
        }
    }
}

/// Size- and linger-bounded row buffer shared by batching sinks
/// (Postgres, MySQL, ClickHouse, InfluxDB). Rows accumulate until the
/// batch is full or the oldest row outlives the linger window; failures
/// restore rows in order instead of dropping them.
pub(crate) struct BatchQueue<T> {
    rows: Vec<T>,
    oldest: Option<Instant>,
    max_rows: usize,
    linger: Duration,
}

impl<T> BatchQueue<T> {
    pub(crate) fn new(max_rows: usize, linger: Duration) -> Self {
        Self {
            rows: Vec::new(),
            oldest: None,
            max_rows: max_rows.max(1),
            linger,
        }
    }

    /// Push one row; true means flush now (full or stale).
    pub(crate) fn push(&mut self, row: T) -> bool {
        if self.is_empty() {
            self.oldest = Some(Instant::now());
        }
        self.rows.push(row);
        self.rows.len() >= self.max_rows || self.is_stale()
    }

    pub(crate) fn is_stale(&self) -> bool {
        self.oldest
            .map(|oldest| oldest.elapsed() >= self.linger)
            .unwrap_or(false)
    }

    pub(crate) fn len(&self) -> usize {
        self.rows.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Take all rows, resetting the linger clock. Callers restore via
    /// [`BatchQueue::restore`] when the transport fails.
    pub(crate) fn take_batch(&mut self) -> (Vec<T>, Option<Instant>) {
        let rows = std::mem::take(&mut self.rows);
        let oldest = self.oldest.take();
        (rows, oldest)
    }

    /// Restore a failed batch at the front, preserving order and the
    /// original linger clock.
    pub(crate) fn restore(&mut self, mut rows: Vec<T>, oldest: Option<Instant>) {
        rows.append(&mut self.rows);
        self.rows = rows;
        if self.oldest.is_none() {
            self.oldest = oldest;
        }
    }
}

/// Exponential backoff state (2s, 4s, 8s ... capped at 30s) for failing
/// transports. While backing off, flushes fail fast without touching
/// the transport.
#[derive(Default)]
pub(crate) struct BackoffState {
    consecutive_errors: u32,
    retry_after: Option<Instant>,
}

impl BackoffState {
    pub(crate) fn check(&self) -> Result<()> {
        if let Some(retry_after) = self.retry_after {
            if Instant::now() < retry_after {
                return Err(ConnectorError::Connection(
                    "sink backing off after errors".to_string(),
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn success(&mut self) {
        self.consecutive_errors = 0;
        self.retry_after = None;
    }

    pub(crate) fn failure(&mut self) {
        self.consecutive_errors += 1;
        let secs = 2u64.saturating_pow(self.consecutive_errors.min(5)).min(30);
        self.retry_after = Some(Instant::now() + Duration::from_secs(secs));
    }
}

/// Strict `${name}` template renderer shared by the object-storage and
/// search sinks (S3 keys, Elasticsearch indices/doc ids). Every
/// `${...}` must close and must name a key present in `vars`; anything
/// else is a dispatch error, so typos fail loudly at buffer time
/// instead of silently producing wrong object names.
pub(crate) fn render_template(template: &str, vars: &[(&str, String)]) -> Result<String> {
    let mut out = String::with_capacity(template.len() + 32);
    let bytes = template.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            let start = i + 2;
            let mut end = start;
            while end < bytes.len() && bytes[end] != b'}' {
                end += 1;
            }
            if end >= bytes.len() {
                return Err(ConnectorError::Dispatch(format!(
                    "unclosed template variable in {template:?}"
                )));
            }
            let name = &template[start..end];
            if name.is_empty() {
                return Err(ConnectorError::Dispatch(format!(
                    "empty template variable in {template:?}"
                )));
            }
            let value = vars
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.clone());
            match value {
                Some(value) => out.push_str(&value),
                None => {
                    return Err(ConnectorError::Dispatch(format!(
                        "unknown template variable {name:?} in {template:?}"
                    )))
                }
            }
            i = end + 1;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    Ok(out)
}

/// Wall-clock milliseconds since the Unix epoch (saturating at zero).
pub(crate) fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}

/// Split Unix millis into civil (year, month, day) via Howard Hinnant's
/// days-from-civil inverse (proleptic Gregorian, UTC). Negative inputs
/// clamp to the epoch so templates never render year 1969 surprises.
pub(crate) fn ymd_from_millis(millis: i64) -> (i32, u32, u32) {
    let days = millis.max(0).div_euclid(86_400_000);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    if m <= 2 {
        y += 1;
    }
    (y as i32, m, d)
}

/// Split Unix millis into (hour, minute, second, milli) UTC time of day.
pub(crate) fn hms_milli_from_millis(millis: i64) -> (u32, u32, u32, u32) {
    let day_millis = millis.max(0).rem_euclid(86_400_000) as u64;
    let secs = day_millis / 1_000;
    (
        (secs / 3_600) as u32,
        ((secs / 60) % 60) as u32,
        (secs % 60) as u32,
        (day_millis % 1_000) as u32,
    )
}

/// RFC 3339 UTC timestamp with millis (`2026-09-12T11:18:09.123Z`).
pub(crate) fn rfc3339_millis(millis: i64) -> String {
    let (y, mo, d) = ymd_from_millis(millis);
    let (h, mi, s, ms) = hms_milli_from_millis(millis);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{ms:03}Z")
}

// ---------------------------------------------------------------------------
// AWS Signature Version 4 core (shared by the S3 and Kinesis signers).
// ---------------------------------------------------------------------------

/// HMAC-SHA256 on the maintained `hmac` + `sha2` crates (shared by
/// the S3 and Kinesis signers and the Azure SharedKey/SAS signers).
pub(crate) fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    use hmac::Mac;
    let mut mac =
        hmac::Hmac::<sha2::Sha256>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

/// Lowercase hex SHA-256 of `data`.
pub(crate) fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// HMAC-SHA1 on the maintained `hmac` + `sha1` crates. Shared by
/// the Alibaba Tablestore and RocketMQ signers.
pub(crate) fn hmac_sha1(key: &[u8], message: &[u8]) -> Vec<u8> {
    use hmac::Mac;
    let mut mac =
        hmac::Hmac::<sha1::Sha1>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

/// SigV4 `x-amz-date` timestamp (`YYYYMMDDTHHMMSSZ`, UTC).
pub(crate) fn amz_date(millis: i64) -> String {
    let (year, month, day) = ymd_from_millis(millis);
    let (hour, minute, second, _) = hms_milli_from_millis(millis);
    format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z")
}

/// SigV4 percent-encoding for canonical URIs: every byte except
/// unreserved marks and the `/` path separator becomes `%XX`.
pub(crate) fn aws_encode_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~' | b'/') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Inputs to [`sigv4_authorization`]. Header names must already be
/// lowercase; values trimmed. The signer sorts headers by name.
pub(crate) struct SigV4Signing<'a> {
    pub method: &'a str,
    pub canonical_uri: String,
    pub canonical_query: String,
    pub headers: Vec<(String, String)>,
    pub payload_hash: String,
    pub access_key_id: &'a str,
    pub secret_access_key: &'a str,
    pub region: &'a str,
    pub service: &'a str,
    pub millis: i64,
}

/// Build an AWS Signature Version 4 `Authorization` header value.
pub(crate) fn sigv4_authorization(signing: &SigV4Signing<'_>) -> String {
    let date = amz_date(signing.millis);
    let short_date = &date[..8];
    let mut headers = signing.headers.clone();
    headers.sort_by(|a, b| a.0.cmp(&b.0));
    let mut canonical_headers = String::new();
    let mut signed_names = Vec::with_capacity(headers.len());
    for (name, value) in &headers {
        canonical_headers.push_str(name);
        canonical_headers.push(':');
        canonical_headers.push_str(value.trim());
        canonical_headers.push('\n');
        signed_names.push(name.clone());
    }
    let signed_headers = signed_names.join(";");
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        signing.method,
        signing.canonical_uri,
        signing.canonical_query,
        canonical_headers,
        signed_headers,
        signing.payload_hash
    );
    let scope = format!(
        "{short_date}/{}/{}/aws4_request",
        signing.region, signing.service
    );
    let canonical_hash = sha256_hex(canonical_request.as_bytes());
    let string_to_sign = format!("AWS4-HMAC-SHA256\n{date}\n{scope}\n{canonical_hash}");
    let mut key = hmac_sha256(
        format!("AWS4{}", signing.secret_access_key).as_bytes(),
        short_date.as_bytes(),
    );
    for part in [signing.region, signing.service, "aws4_request"] {
        key = hmac_sha256(&key, part.as_bytes());
    }
    // NOTE: the signature is hex(HMAC(key, string_to_sign)) — the
    // HMAC output is raw bytes, hexed directly (never hashed again).
    let signature = signing_hex(&key, &string_to_sign);
    format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={signed_headers}, Signature={signature}",
        signing.access_key_id, scope
    )
}

/// Hex of HMAC-SHA256(key, message): the SigV4 signature.
fn signing_hex(key: &[u8], string_to_sign: &str) -> String {
    hmac_sha256(key, string_to_sign.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Test-only RSA keypair (generated with openssl, never deployed).
/// Shared by the GCP/Snowflake/BigQuery JWT tests so the PEMs live in
/// exactly one place.
#[cfg(test)]
pub(crate) mod test_rsa_keys {
    pub const PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCwQ2w63oB3FtHg\n7xysQK8MuX9S0WkbAVlxWpLHDNIdRVxA9Ra2gFFpKy8jX45UMSow6Yny7IvYWFzZ\nL4y9yoFiqu+LxhlJHIO6JO8+ZmeBoNwuDiIzgesbZwjyQiQ2M7p/4c18a2ffGPWF\nBETT7uVwVKJ3hTp97RN7Mc1/eFMimuT/TC11I+sFCZUHgrbhEG3L5Gg3RJ2MKbcX\nGEIxjFDJdLJ9RK0BopD6lxR1a4zeYr+iF/m3+JeJPAaS15yMD+sB1g5C7XZ1OIsB\nNBBnHWHpNhYO2IrCc9lZeSSzSkbRC6k1oqvTurFRzHWZqBKQGYnH8BftubIPSTBg\nU/BM4rR3AgMBAAECggEAHSRwmwUZoVb1CWcPSw2Aw65RtkwoQA5Hjv3GIcHlZXCH\n0beT80Wg8C3zI7qTSik8zAx4weDJOFJXu5LohqKaJMmVRHtSx+s+fkLICX2d5GlH\nrhepIPH8gLHW4VL9MLb5wVYAhu8tI845Ha54gL/RUHK1z+QHqTVO0MIJs2cd+6zx\nKsAtnqEQJMFpl1D0y0uutuboK4soHJMyRyrHBNWdgfzmTrCsngzu2zVM4aZh/gQY\nHcQgJ1rK6Wnen/GGPrNluwWU+bfLdlWO2qiXXwGLfhyx2H6cuROGdoU607BFJNpM\nkAudvEuLa0fOi1ym6lJ5pcJ6pSLkbeveW6+thkO2fQKBgQDXc2GiKx15vQHmdDmZ\nUJEiPJ+hSry5fjaowzrfgqJHyeNfUjnM/E9WlNn2AuxKDWGc3UNEr6jB9V7leKev\nQaPB2LAgXt0YVHmyim51/gTDguE9TOTGWqL4npZG9Nqh8xMxWt08ULvknkOQQOso\nzCoZQYlG4BHegAG7n0/5IN7HdQKBgQDRb/VbJ9iE0wtY/A3e3eWPbGfTF7AZREUu\n/mt94tFEWDDvedX1EPi4DJgPMqQ4eHnBZb3+G7jPcRdm6/KQzR5QiRMHSylfIQRH\nLqqfHBzZDDSZINLW1FMReC9xGfkRoG0Tlt2iQzXOy90+uE/9k5BGSbQNakfVDXJs\n3JAHDMy6uwKBgQCaazxC+xv5MRq3jf3qgPBE1aaj9+kkGe4bLzJ3GC4vveeVXl3H\nKd/DcpR12sp4mPapc3zPMgeGXNNTLRMiba1tNl2mFdfppEJFUSqyrwnDB39gbEhc\nUoIUJ7YVzVEWWh4bdcCzhjnlNfm+3oitiQdzaqF1hwvHqX+Udi7fpEuIMQKBgQC5\nu0bkQu7Rw/MRQ93tIe19ho6AdkZV8eREq52Z8vbQXEFxbiOfBCD93zVObQOTjMu1\nBcw6uEzpsgol3OKtJSpYE2eLlU0oLriDg9AN8DlpBljy31f66iqMmH/CFl16E0II\nGEeOqXnjXYlkIMHXR/CvVJdXOkRfnWA3SFZ12hUJFwKBgD8JlGTyrVfNsNMOaTDV\nNopoYnUQ6ljFmJi6TGmnkliCRXPuqBl+2hVxiKeWI2MprJ5Ya8qLbL6M56uCwAD2\nqEhvjEuatma5rJyE5NULOjAXA5tLw9qM1M9j1FNOaXnFC9/Yii2a49R8zu05wRB2\nH+dMMSDXQ4EHHYcKIFJjDbxn\n-----END PRIVATE KEY-----\n";
    pub const PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsENsOt6AdxbR4O8crECv\nDLl/UtFpGwFZcVqSxwzSHUVcQPUWtoBRaSsvI1+OVDEqMOmJ8uyL2Fhc2S+MvcqB\nYqrvi8YZSRyDuiTvPmZngaDcLg4iM4HrG2cI8kIkNjO6f+HNfGtn3xj1hQRE0+7l\ncFSid4U6fe0TezHNf3hTIprk/0wtdSPrBQmVB4K24RBty+RoN0SdjCm3FxhCMYxQ\nyXSyfUStAaKQ+pcUdWuM3mK/ohf5t/iXiTwGktecjA/rAdYOQu12dTiLATQQZx1h\n6TYWDtiKwnPZWXkks0pG0QupNaKr07qxUcx1magSkBmJx/AX7bmyD0kwYFPwTOK0\ndwIDAQAB\n-----END PUBLIC KEY-----\n";
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{extract::State, http::StatusCode, routing::post, Router};
    use std::sync::Mutex as StdMutex;
    use tokio::net::TcpListener;

    #[derive(Debug, Default)]
    struct RecordingSink {
        events: StdMutex<Vec<(String, Vec<u8>, u8)>>,
    }

    #[async_trait]
    impl Sink for RecordingSink {
        async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<()> {
            self.events.lock().unwrap().push((
                topic.as_str().to_string(),
                payload.to_vec(),
                u8::from(qos),
            ));
            Ok(())
        }

        fn kind(&self) -> &'static str {
            "test"
        }
    }

    #[tokio::test]
    async fn test_connector_manager_registry() {
        let manager = ConnectorManager::new();
        assert!(manager.ids().is_empty());
        assert!(manager.get("missing").is_none());

        let sink: Arc<dyn Sink> = Arc::new(RecordingSink::default());
        manager.register("rec", sink);
        assert_eq!(manager.ids(), vec!["rec".to_string()]);

        let topic = Topic::new("a/b").unwrap();
        manager
            .send("rec", &topic, &Bytes::from_static(b"hi"), QoS::AtLeastOnce)
            .await
            .unwrap();
        let err = manager
            .send(
                "missing",
                &topic,
                &Bytes::from_static(b"hi"),
                QoS::AtMostOnce,
            )
            .await
            .expect_err("unknown connector must fail");
        assert!(matches!(err, ConnectorError::UnknownConnector(_)));

        assert!(manager.unregister("rec"));
        assert!(!manager.unregister("rec"));
    }

    #[test]
    fn test_connector_tier_tags() {
        // Enterprise bridges (cloud, Sparkplug, databases, time-series,
        // lakehouse, IoT hubs, cloud stores, enterprise messaging).
        for kind in [
            "kinesis",
            "gcp_pubsub",
            "azure_eventhubs",
            "pulsar",
            "sparkplug_b",
            "mongodb",
            "mssql",
            "cassandra",
            "couchbase",
            "tdengine",
            "iotdb",
            "timestream",
            "dynamodb",
            "snowflake",
            "databricks",
            "doris",
            "bigquery",
            "redshift",
            "oci_streaming",
            "aws_iot",
            "azure_iot",
            "gcp_iot",
            "opc_ua",
            "azure_blob",
            "tablestore",
            "s3_tables",
            "confluent",
            "rocketmq",
        ] {
            assert_eq!(
                connector_tier(kind),
                "enterprise",
                "{kind} must be enterprise"
            );
        }
        // Everything else is community (including unknown kinds).
        for kind in ["kafka", "postgres", "redis", "webhook", "logger", "nope"] {
            assert_eq!(
                connector_tier(kind),
                "community",
                "{kind} must be community"
            );
        }
    }

    #[tokio::test]
    async fn test_console_logger_counts_deliveries() {
        let sink = ConsoleLoggerSink::new("diag");
        let topic = Topic::new("a/b").unwrap();
        sink.send(&topic, &Bytes::from_static(b"hello"), QoS::AtMostOnce)
            .await
            .unwrap();
        sink.send(&topic, &Bytes::from(vec![0xFF, 0xFE]), QoS::AtLeastOnce)
            .await
            .unwrap();
        assert_eq!(sink.logged_count(), 2);
    }

    /// Captured webhook deliveries for the in-process HTTP test.
    #[derive(Debug, Default)]
    struct CapturedPosts {
        bodies: StdMutex<Vec<Vec<u8>>>,
        topics: StdMutex<Vec<String>>,
    }

    async fn capture_handler(
        State(state): State<Arc<CapturedPosts>>,
        headers: axum::http::HeaderMap,
        body: Bytes,
    ) -> StatusCode {
        if let Some(topic) = headers.get("X-MQTT-Topic").and_then(|v| v.to_str().ok()) {
            state.topics.lock().unwrap().push(topic.to_string());
        }
        state.bodies.lock().unwrap().push(body.to_vec());
        StatusCode::OK
    }

    /// In-process HTTP test: an ephemeral Axum server receives exactly
    /// what the webhook sink posts — byte-identical JSON included.
    #[tokio::test]
    async fn test_http_webhook_posts_exact_payload() {
        let captured = Arc::new(CapturedPosts::default());
        let app = Router::new()
            .route("/hook", post(capture_handler))
            .with_state(captured.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("webhook client");
        let mut headers = HeaderMap::new();
        headers.insert("X-Tenant", "acme".parse().unwrap());
        let sink = HttpWebhookSink::new(format!("http://127.0.0.1:{port}/hook"), headers, client);
        assert_eq!(sink.sent_count(), 0);

        let payload = Bytes::from_static(br#"{ "temperature": 85.0 }"#);
        sink.send(&Topic::new("raw/temp").unwrap(), &payload, QoS::AtMostOnce)
            .await
            .expect("webhook delivery");
        assert_eq!(sink.sent_count(), 1);

        assert_eq!(
            captured.bodies.lock().unwrap().as_slice(),
            &[br#"{ "temperature": 85.0 }"#.to_vec()]
        );
        assert_eq!(
            captured.topics.lock().unwrap().as_slice(),
            &["raw/temp".to_string()]
        );
        server.abort();
    }

    #[tokio::test]
    async fn test_http_webhook_reports_http_errors() {
        let app = Router::new().route(
            "/boom",
            post(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "nope") }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        let sink = HttpWebhookSink::new(
            format!("http://127.0.0.1:{port}/boom"),
            HeaderMap::new(),
            reqwest::Client::new(),
        );
        let err = sink
            .send(
                &Topic::new("a").unwrap(),
                &Bytes::from_static(b"{}"),
                QoS::AtMostOnce,
            )
            .await
            .expect_err("5xx must fail");
        assert!(matches!(err, ConnectorError::Dispatch(_)));
        assert_eq!(sink.sent_count(), 0);

        // Unroutable port: connection failure, not dispatch failure.
        let dead = HttpWebhookSink::new(
            "http://127.0.0.1:1/hook".to_string(),
            HeaderMap::new(),
            reqwest::Client::new(),
        )
        .with_timeout(Duration::from_millis(500));
        let err = dead
            .send(
                &Topic::new("a").unwrap(),
                &Bytes::from_static(b"{}"),
                QoS::AtMostOnce,
            )
            .await
            .expect_err("refused port must fail");
        assert!(matches!(err, ConnectorError::Connection(_)));

        server.abort();
    }

    #[test]
    fn test_render_template_strict() {
        let vars = vec![
            ("topic", "sensors/t1".to_string()),
            ("YYYY", "2026".to_string()),
        ];
        assert_eq!(
            render_template("a/${topic}/${YYYY}.ndjson", &vars).unwrap(),
            "a/sensors/t1/2026.ndjson"
        );
        assert_eq!(render_template("plain", &vars).unwrap(), "plain");
        assert!(render_template("a/${nope}", &vars).is_err());
        assert!(render_template("a/${topic", &vars).is_err());
        assert!(render_template("a/${}", &vars).is_err());
        assert!(render_template("price: $5", &vars).is_ok());
    }

    #[test]
    fn test_ymd_and_rfc3339_vectors() {
        assert_eq!(ymd_from_millis(0), (1970, 1, 1));
        // 2024-02-29T00:00:00Z (leap day) and 2026-09-12T11:18:09.123Z.
        assert_eq!(ymd_from_millis(1_709_164_800_000), (2024, 2, 29));
        assert_eq!(ymd_from_millis(1_789_211_889_123), (2026, 9, 12));
        assert_eq!(hms_milli_from_millis(1_789_211_889_123), (11, 18, 9, 123));
        assert_eq!(
            rfc3339_millis(1_789_211_889_123),
            "2026-09-12T11:18:09.123Z"
        );
        assert_eq!(ymd_from_millis(-1), (1970, 1, 1));
    }
}
