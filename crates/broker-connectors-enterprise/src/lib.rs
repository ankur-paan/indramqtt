#![allow(unknown_lints)]
#![allow(clippy::chunks_exact_to_as_chunks)]

//! Enterprise connectors for IndraMQTT: multi-cloud streaming bridges,
//! Sparkplug B, enterprise databases, industrial time-series stores,
//! lakehouse sinks, cloud object/wide-column stores and enterprise
//! messaging bridges.
//!
//! This crate depends on the community `broker-connectors` crate for the
//! shared sink traits, the connector registry, the SigV4 / template /
//! batching helpers and the MQTT codec --- never the reverse. `Sink::kind()`
//! strings, management `connector_type` values and stored configuration
//! shapes are identical to before the split, so existing registrations
//! keep working.
//!
//! Licence: MIT OR Apache-2.0, as the other crates of this repository.
//!
//! Default build (no features): every module except the X1-09 first half
//! is compiled in. The gated kinds are absent from the build and the
//! binary unless their Cargo feature is enabled: `aws_iot` (feature
//! `aws_iot`), `azure_blob` (feature `azure_blob`), `azure_eventhubs`
//! (feature `azure_eventhubs`), `azure_iot` (feature `azure_iot`),
//! `bigquery` (feature `bigquery`), `dynamodb` (feature `dynamodb`),
//! `gcp_iot` (feature `gcp_iot`). Unresolvable kinds under a disabled
//! feature fail registration closed with an error naming the missing
//! feature.

pub mod alloydb;
#[cfg(feature = "aws_iot")]
pub mod aws_iot;
#[cfg(feature = "azure_blob")]
pub mod azure_blob;
#[cfg(feature = "azure_eventhubs")]
pub mod azure_eventhubs;
#[cfg(feature = "azure_iot")]
pub mod azure_iot;
#[cfg(feature = "bigquery")]
pub mod bigquery;
pub mod cassandra;
pub mod cockroachdb;
pub mod confluent;
pub mod couchbase;
pub mod databricks;
pub mod datalayers;
pub mod doris;
#[cfg(feature = "dynamodb")]
pub mod dynamodb;
#[cfg(feature = "gcp_iot")]
pub mod gcp_iot;
pub mod gcp_pubsub;
pub mod iotdb;
pub mod kinesis;
pub mod mongodb;
pub mod mssql;
pub mod oci_streaming;
pub mod opc_ua;
pub mod oracle;
pub mod pulsar;
pub mod redshift;
pub mod rocketmq;
pub mod s3_tables;
pub mod snowflake;
pub mod sparkplug_b;
pub mod tablestore;
pub mod tdengine;
pub mod timestream;

pub use alloydb::{
    alloydb_connect_config, alloydb_value_to_boxed, build_alloydb_insert_query,
    classify_alloydb_error, extract_alloydb_row, map_driver_error, resolve_alloydb_password,
    AlloydbAuth, AlloydbColumnMapping, AlloydbConfig, AlloydbConnector, AlloydbErrorClassification,
    AlloydbQueryResult, AlloydbRow, AlloydbSink, AlloydbTransport, AlloydbValue,
    CapturedAlloydbExecution, MockAlloydbTransport, PgDriverAlloydbTransport, TcpAlloydbTransport,
};
#[cfg(feature = "aws_iot")]
pub use aws_iot::{
    shadow_update_document, sign_websocket_url, sigv4_signature_via_sdk, sigv4_signing_key_manual,
    sigv4_signing_key_via_sdk, AwsIotAuth, AwsIotConfig, AwsIotConnector, AwsIotFrame, AwsIotSink,
    AwsIotTransport, BridgeDirection, BridgeTopicMapping, MockAwsIotOutcome, MockAwsIotTransport,
    ShadowSyncConfig, ShadowTopics, TlsAwsIotTransport,
};
#[cfg(feature = "azure_blob")]
pub use azure_blob::{
    azure_error_code, canonicalized_resource, classify_blob_status, container_string_to_sign,
    shared_key_authorization, string_to_sign as azure_blob_string_to_sign, AzureBlobAuth,
    AzureBlobCompression, AzureBlobOutcome, AzureBlobPut, AzureBlobSink, AzureBlobSinkConfig,
    AzureBlobTransport, HttpAzureBlobTransport, MockAzureBlobTransport, AZURE_STORAGE_VERSION,
};
#[cfg(feature = "azure_eventhubs")]
pub use azure_eventhubs::{
    render_batch_body as render_azure_batch_body, sas_token, AzureEventHubsConnector,
    AzureEventHubsSink, AzureEventHubsSinkConfig, AzureEventHubsTransport, AzureEventItem,
    CapturedAzureBatch, HttpAzureEventHubsTransport, MockAzureEventHubsTransport, MockAzureOutcome,
};
#[cfg(feature = "azure_iot")]
pub use azure_iot::{
    d2c_topic, parse_property_bag, sas_expiry, sas_token as azure_iot_sas_token, AzureIotAuth,
    AzureIotConfig, AzureIotConnectTransport, AzureIotPublish, AzureIotSink, AzureIotTransport,
    CapturedAzureIotPublish, MockAzureIotOutcome, MockAzureIotTransport, TlsAzureIotTransport,
    TwinTopics,
};
#[cfg(feature = "bigquery")]
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
    ConfluentSchemaRegistryConfig, ConfluentSecurityProtocol, ConfluentTransport,
    MemoryConfluentTransport, RdkafkaConfluentTransport, RegistrySchemaClient, SaslMechanism,
    ScramHash, ScramServerFirst, TcpConfluentTransport,
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
pub use doris::{
    classify_status as classify_doris_status, doris_http_client, parse_load_result,
    render_body as render_doris_body, CapturedDorisLoad, DorisAuth, DorisConnector, DorisFormat,
    DorisHeaders, DorisLoadResult, DorisSink, DorisSinkConfig, DorisTransport, HttpDorisTransport,
    MockDorisOutcome, MockDorisTransport,
};
#[cfg(feature = "dynamodb")]
pub use dynamodb::{
    attribute_value_from_dynamodb_json, build_item_body, dynamodb_attribute,
    item_body_to_attribute_map, parse_unprocessed, render_batch_body as render_dynamodb_batch_body,
    DynamoDbBatchWriteRequest, DynamoDbConnector, DynamoDbItem, DynamoDbSink, DynamoDbSinkConfig,
    DynamoDbTransport, DynamoKeyConfig, HttpDynamoDbTransport, MockDynamoDbOutcome,
    MockDynamoDbTransport, SdkDynamoDbTransport, DYNAMODB_CONTENT_TYPE, DYNAMODB_TARGET,
};
#[cfg(feature = "gcp_iot")]
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
pub use iotdb::{
    render_tablet_body, CapturedIotDbTablet, HttpIotDbTransport, IotDbAuth, IotDbConnector,
    IotDbDataType, IotDbSink, IotDbSinkConfig, IotDbTabletRequest, IotDbTransport,
    MockIotDbOutcome, MockIotDbTransport,
};
pub use kinesis::{
    HttpKinesisTransport, KinesisConnector, KinesisPutRecordsRequest, KinesisPutRecordsResponse,
    KinesisRecordEntry, KinesisRecordResult, KinesisSink, KinesisSinkConfig, KinesisTransport,
    MockKinesisOutcome, MockKinesisTransport, SdkKinesisTransport, KINESIS_CONTENT_TYPE,
    KINESIS_TARGET,
};
pub use mongodb::{
    decode_op_msg, encode_op_msg, generate_object_id, json_to_bson, parse_connection_string,
    scram_client_proof, BsonDocument, BsonValue, CapturedMongoBulk, DriverMongoDbTransport,
    MockMongoDbTransport, MockMongoOutcome, MongoDbConnector, MongoDbDocumentItem, MongoDbSink,
    MongoDbSinkConfig, MongoDbTransport, MongoEndpoint, MongoOperation, NativeMongoDbTransport,
};
pub use mssql::{
    days_from_civil, encode_datetimeoffset, encode_executesql, obscure_password,
    parse_reply_tokens, CapturedMssqlBatch, DriverMssqlTransport, MockMssqlOutcome,
    MockMssqlTransport, MssqlAuth, MssqlConnector, MssqlQueryMode, MssqlRowItem, MssqlSink,
    MssqlSinkConfig, MssqlTransport, NativeMssqlTransport, TdsReply,
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
pub use oracle::{
    build_merge_sql, classify_ora_error, extract_oracle_row, CapturedOracleExecution,
    HttpOracleTransport, MockOracleTransport, OraErrorClassification, OracleBindParam,
    OracleConnector, OracleResponse, OracleRow, OracleSink, OracleSinkConfig, OracleTransport,
    OracleValue,
};
pub use pulsar::{
    crc32c, decode_frame, decode_metadata, encode_message_frame, parse_service_url,
    CapturedProduce, DecodedMetadata, MemoryPulsarTransport, PulsarAuth, PulsarConnector,
    PulsarEndpoint, PulsarMessage, PulsarSink, PulsarSinkConfig, PulsarTransport,
    TcpPulsarTransport,
};
pub use redshift::{
    default_insert as redshift_default_insert, render_batch_body as render_redshift_batch_body,
    render_statement as render_redshift_statement, HttpRedshiftTransport, MockRedshiftOutcome,
    MockRedshiftTransport, RedshiftBatchRequest, RedshiftBatchResponse, RedshiftConnector,
    RedshiftSink, RedshiftSinkConfig, RedshiftTransport, SdkRedshiftTransport,
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
pub use s3_tables::{
    apply_partition_transform, classify_put_status as classify_s3tables_status, data_file_path,
    parse_table_bucket_arn, partition_path, render_snapshot, s3tables_authorization,
    HttpS3TablesTransport, IcebergPartitionField, IcebergTransform, MockS3TablesTransport,
    S3TablesConnector, S3TablesFormat, S3TablesOutcome, S3TablesPut, S3TablesSigning, S3TablesSink,
    S3TablesSinkConfig, S3TablesTransport, SnapshotFile, TableBucketArn,
};
pub use snowflake::{
    build_jwt_assertion as build_snowflake_jwt,
    render_create_table_sql as render_snowflake_create_table,
    render_insert_sql as render_snowflake_insert, render_rows_body as render_snowflake_rows,
    CapturedSnowflakeInsert, HttpSnowflakeTransport, MockSnowflakeOutcome, MockSnowflakeTransport,
    SnowflakeConnector, SnowflakeRowItem, SnowflakeSink, SnowflakeSinkConfig, SnowflakeTransport,
};
pub use sparkplug_b::{
    decode_metric, decode_payload, decode_payload_prost, decode_varint, encode_metric,
    encode_payload, encode_payload_prost, encode_varint, payload_from_json, payload_to_json, tier,
    MemorySparkplugTransport, ProtoMetric, ProtoPayload, RumqttcSparkplugTransport,
    SparkplugBConnector, SparkplugBSink, SparkplugFrame, SparkplugMessageType, SparkplugSinkConfig,
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
    parse_rest_response, render_insert, CapturedTdengineSql, DriverTdengineTransport,
    HttpTdengineTransport, MockTdengineOutcome, MockTdengineTransport, TdengineAuth,
    TdengineConnector, TdengineResponse, TdengineRow, TdengineSink, TdengineSinkConfig,
    TdengineTransport,
};
pub use timestream::{
    render_write_records_body, HttpTimestreamTransport, MockTimestreamOutcome,
    MockTimestreamTransport, TimestreamConnector, TimestreamRecord, TimestreamSink,
    TimestreamSinkConfig, TimestreamTimeUnit, TimestreamTransport, TimestreamWriteRequest,
    TimestreamWriteResponse, TIMESTREAM_CONTENT_TYPE, TIMESTREAM_TARGET,
};

/// Tier delegate: identical to `broker_connectors::connector_tier`.
/// Re-exported here so enterprise call sites resolve without reaching
/// into the community crate directly.
pub use broker_connectors::connector_tier;
pub use broker_connectors::ConnectorError;
pub use broker_connectors::Result;
pub use broker_connectors::Sink;

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
    use super::{connector_tier, KinesisSink, KinesisSinkConfig, MockKinesisTransport};
    use broker_connectors::{
        HttpAuth, HttpBodyFormat, HttpMethod, HttpSink, HttpSinkConfig, MockHttpTransport,
        Sink as _,
    };
    use broker_protocol::{QoS, Topic, TopicFilter};
    use broker_rules::{BackpressurePolicy, BrokerSink, RuleEngine, RuleEngineError};
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex as StdMutex};

    #[derive(Debug, Default)]
    struct RecordingSink {
        published: StdMutex<Vec<(Topic, Bytes, QoS, bool)>>,
    }

    #[async_trait::async_trait]
    impl BrokerSink for RecordingSink {
        async fn publish(
            &self,
            topic: Topic,
            payload: Bytes,
            qos: QoS,
            retain: bool,
        ) -> Result<(), RuleEngineError> {
            self.published
                .lock()
                .unwrap()
                .push((topic, payload, qos, retain));
            Ok(())
        }
    }

    fn base64_decode(input: &str) -> Vec<u8> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(input)
            .unwrap()
    }

    /// Split evidence (community half): a stateless community webhook
    /// rule still dispatches through the rule engine after the move,
    /// with the same tier tag as before.
    #[tokio::test]
    async fn test_split_community_webhook_through_rule_engine() {
        let engine = RuleEngine::new(65_536, BackpressurePolicy::DropOldest);
        let hook_transport = Arc::new(MockHttpTransport::new());
        let hook = Arc::new(
            HttpSink::new(
                HttpSinkConfig {
                    url: "https://hooks.example.com/ingest/${topic}".to_string(),
                    method: HttpMethod::Post,
                    headers: HashMap::new(),
                    auth: HttpAuth::None,
                    body_format: HttpBodyFormat::RawJson,
                    signature: None,
                    batch_size: Some(1),
                    batch_bytes: None,
                    linger_ms: None,
                    timeout_ms: Some(5_000),
                    max_retries: Some(3),
                    initial_backoff_ms: Some(1),
                    max_backoff_ms: Some(2),
                    buffer_capacity: Some(10_000),
                },
                hook_transport.clone(),
            )
            .expect("valid sink"),
        );
        assert_eq!(hook.kind(), "webhook");
        assert_eq!(broker_connectors::connector_tier(hook.kind()), "community");
        engine.connectors().register("hook-split", hook.clone());
        engine
            .create_rule(
                "hook-split-rule".to_string(),
                TopicFilter::new("sensors/+").unwrap(),
                Some(
                    r#"SELECT client_id, temp FROM "sensors/+" WHERE temp > 20.0 INTO connector("hook-split")"#.to_string(),
                ),
                true,
                vec![],
            )
            .expect("rule creates");
        let sink: Arc<dyn BrokerSink> = Arc::new(RecordingSink::default());
        engine
            .dispatch_ingress(
                &Topic::new("sensors/kitchen").unwrap(),
                &Bytes::from_static(br#"{ "client_id": "device-42", "temp": 22.5 }"#),
                QoS::AtMostOnce,
                &sink,
            )
            .await;
        let captured = hook_transport.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&captured[0].body).unwrap(),
            serde_json::json!({"client_id": "device-42", "temp": 22.5})
        );
    }

    /// Split evidence (enterprise half): a Kinesis rule dispatches
    /// through the same rule path with identical framing to before
    /// the move, and the tier tag is unchanged.
    #[tokio::test]
    async fn test_split_enterprise_kinesis_through_rule_engine() {
        let engine = RuleEngine::new(65_536, BackpressurePolicy::DropOldest);
        let kinesis_transport = Arc::new(MockKinesisTransport::new());
        let kinesis = Arc::new(
            KinesisSink::new(
                KinesisSinkConfig {
                    stream_name: "telemetry-stream".to_string(),
                    region: "us-east-1".to_string(),
                    endpoint: None,
                    access_key_id: "AKID".to_string(),
                    secret_access_key: "secret".to_string(),
                    session_token: None,
                    partition_key_template: Some("${client_id}".to_string()),
                    explicit_hash_key: None,
                    batch_size: Some(1),
                    batch_bytes: None,
                    linger_ms: Some(20),
                    max_retries: Some(5),
                    initial_backoff_ms: Some(1),
                    max_backoff_ms: Some(2),
                    timeout_ms: None,
                },
                kinesis_transport.clone(),
            )
            .expect("valid sink"),
        );
        assert_eq!(kinesis.kind(), "kinesis");
        assert_eq!(connector_tier(kinesis.kind()), "enterprise");
        engine
            .connectors()
            .register("kinesis-split", kinesis.clone());
        engine
            .create_rule(
                "kinesis-split-rule".to_string(),
                TopicFilter::new("sensors/+").unwrap(),
                Some(
                    r#"SELECT client_id, temp FROM "sensors/+" WHERE temp > 20.0 INTO connector("kinesis-split")"#.to_string(),
                ),
                true,
                vec![],
            )
            .expect("rule creates");
        let sink: Arc<dyn BrokerSink> = Arc::new(RecordingSink::default());
        engine
            .dispatch_ingress(
                &Topic::new("sensors/kitchen").unwrap(),
                &Bytes::from_static(br#"{ "client_id": "device-42", "temp": 22.5 }"#),
                QoS::AtMostOnce,
                &sink,
            )
            .await;
        let captured = kinesis_transport.captured();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].stream_name, "telemetry-stream");
        assert_eq!(captured[0].records.len(), 1);
        assert_eq!(captured[0].records[0].partition_key, "device-42");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&base64_decode(
                &captured[0].records[0].data_b64
            ))
            .unwrap(),
            serde_json::json!({"client_id": "device-42", "temp": 22.5})
        );
    }
}
