# Connector capability table (B1-05)

One row per sink module in `crates/broker-connectors/src` (every file
except `lib.rs`). Each row was derived from the module source and its
`#[cfg(test)]` tests. No row claims a live-server run: every test in
this crate passes offline with `cargo test -p broker-connectors`.

Method:

- `Speaks` is what the sink actually puts on the wire today: `native`
  wire protocol over TCP, `vendor HTTP API` via `reqwest`, `line`
  protocol, `local file`, or `in-memory only`.
- `Tested against` is what the proving test actually runs against:
  `mock transport` (in-memory `Mock*`/`Memory*`), or `loopback fake`
  (an in-process `TcpListener` on `127.0.0.1:0` or ephemeral `axum`
  server scripted for one exchange). Neither is the vendor's real
  server.
- `Proving test` names one test by path. All paths are
  `crates/broker-connectors/src/<module>.rs`.

Dependency note: `crates/broker-connectors/Cargo.toml` pulls in no
maintained vendor driver (`tokio-postgres`, `mysql_async`, `rdkafka`,
`redis`, `mongodb`, cloud SDKs). Every TCP sink is hand-written over
`tokio::net::TcpStream`; the AWS IoT and Azure IoT sinks upgrade that
socket with `tokio-rustls`/`rustls` (platform roots plus a configured
CA bundle); every cloud sink is otherwise hand-written over
`reqwest`. The `dev-dependency` is only `axum` for the loopback fakes.

Counts: 47 sink modules. 19 speak a native wire protocol over TCP
(alloydb, aws_iot, azure_iot, cassandra, cockroachdb, confluent, couchbase,
gcp_iot, kafka, mongodb, mqtt_bridge, mssql, mysql, opc_ua, postgres,
pulsar, rabbitmq, redis, timescaledb). 0 have been run against a real
vendor server in-tree. 47 have only mock or loopback-fake coverage.

| Sink | Speaks | Tested against | Proving test |
|------|--------|----------------|--------------|
| alloydb | native PG-compatible wire over TCP (`TcpAlloydbTransport`, startup + cleartext password, Simple Query) | mock transport | `crates/broker-connectors/src/alloydb.rs:1120 test_alloydb_sink_loopback_success` (`MockAlloydbTransport`; no `TcpListener`) |
| aws_iot | native MQTT over TLS with mutual X.509 (`TlsAwsIotTransport` via `mqtt_bridge::encode_publish` + CONNECT/CONNACK; SigV4 URL signer, CA bundle + ALPN `mqtt`, connect/handshake timeouts) | loopback TLS fake (in-process `TcpListener` + `tokio-rustls` server requiring client cert, CONNECT/CONNACK/PUBLISH; plus `MockAwsIotTransport`) | `crates/broker-connectors/src/aws_iot.rs:test_tls_handshake_and_publish` |
| azure_blob | vendor HTTP API (`HttpAzureBlobTransport` PUT block-blob with `x-ms-blob-type`, `x-ms-version`, SharedKey/SAS/Bearer) | loopback fake (ephemeral `axum` PUT capture; plus `MockAzureBlobTransport`) | `crates/broker-connectors/src/azure_blob.rs:1042 test_loopback_put_headers` |
| azure_eventhubs | vendor HTTP API (`HttpAzureEventHubsTransport` POST `...servicebus.windows.net/.../messages` with SAS token) | mock transport | `crates/broker-connectors/src/azure_eventhubs.rs:851 test_batch_framing_and_partition_routing` (`MockAzureEventHubsTransport`; no `TcpListener`) |
| azure_iot | native MQTT over TLS (`TlsAzureIotTransport` D2C/twin topics via `mqtt_bridge::encode_publish` + CONNECT/CONNACK; SAS as MQTT password with configurable TTL or X.509 client cert, CA bundle, connect/handshake timeouts) | loopback TLS fake (in-process `TcpListener` + `tokio-rustls` server for SAS and X.509 paths; plus `MockAzureIotTransport`) | `crates/broker-connectors/src/azure_iot.rs:test_tls_handshake_with_sas_password` |
| bigquery | vendor HTTP API (`HttpBigQueryTransport` POST `insertAll` with Bearer token) | mock transport | `crates/broker-connectors/src/bigquery.rs:990 test_insert_flow_and_ids` (`MockBigQueryTransport`; no `TcpListener`) |
| cassandra | native CQL binary v4 over TCP (`NativeCassandraTransport`, STARTUP/AUTH/USE/UNLOGGED BATCH, password auth) | loopback fake (in-process `TcpListener` scripting startup/auth/batch; plus `MockCassandraTransport`) | `crates/broker-connectors/src/cassandra.rs:1498 test_tcp_loopback_startup_auth_use_batch` |
| clickhouse | vendor HTTP API (`reqwest` POST `?query=INSERT ... FORMAT JSONEachRow`; no dedicated transport struct) | loopback fake (ephemeral `axum` capture via `serve_captured`) | `crates/broker-connectors/src/clickhouse.rs:376 test_batch_posts_json_each_row` |
| cockroachdb | native PG-compatible wire over TCP (`TcpCockroachDbTransport`, startup + Simple Query, UPSERT/ON CONFLICT) | mock transport (despite `loopback` in name, uses `MockCockroachDbTransport`; no `TcpListener`) | `crates/broker-connectors/src/cockroachdb.rs:1179 test_cockroach_sink_loopback_success` |
| confluent | native Kafka wire over TCP (`TcpConfluentTransport`, ApiVersions + SASL PLAIN/SCRAM + Produce v3 RecordBatch-v2) | loopback fake (in-process fake broker `TcpListener`; plus `MemoryConfluentTransport`) | `crates/broker-connectors/src/confluent.rs:1446 test_tcp_plain_produce_against_fake_broker` |
| couchbase | native KV binary over TCP (`NativeCouchbaseTransport`, SET/ADD/REPLACE opcodes + SASL PLAIN, pipelined opaque) | loopback fake (in-process `TcpListener` for SASL + batch; plus `MockCouchbaseTransport`) | `crates/broker-connectors/src/couchbase.rs:1219 test_tcp_loopback_sasl_and_pipelined_batch` |
| databricks | vendor HTTP API (`HttpDatabricksTransport` POST `/api/2.0/sql/statements` with Bearer) | mock transport | `crates/broker-connectors/src/databricks.rs:1053 test_insert_flow_and_bearer` (`MockDatabricksTransport`; no `TcpListener`) |
| datalayers | vendor HTTP API (`HttpDatalayersTransport` POST `/api/v1/write?db=` JSON) | mock transport | `crates/broker-connectors/src/datalayers.rs:529 test_datalayers_sink_loopback_success` (`MockDatalayersTransport`; no `TcpListener` despite name) |
| disk_log | local file (append/rotate/gzip/retention via `tokio::fs`; `FileDiskLogWriter` real, `MemoryDiskLogWriter` virtual) | mock transport (`memory://` writer only; no real directory exercised) | `crates/broker-connectors/src/disk_log.rs:909 test_ndjson_formatting` |
| doris | vendor HTTP API (`HttpDorisTransport` PUT `/_stream_load` with Basic auth, label, 307 handling) | loopback fake for redirect only (ephemeral `axum` 307; others use `MockDorisTransport`) | `crates/broker-connectors/src/doris.rs:1039 test_307_redirect_loopback` |
| dynamodb | vendor HTTP API (`HttpDynamoDbTransport` POST `BatchWriteItem` JSON with SigV4) | mock transport | `crates/broker-connectors/src/dynamodb.rs:1180 test_unprocessed_requeues_selectively` (`MockDynamoDbTransport`; no `TcpListener`) |
| elasticsearch | vendor HTTP API (`HttpElasticsearchTransport` POST `/_bulk` NDJSON, Basic/ApiKey) | mock transport | `crates/broker-connectors/src/elasticsearch.rs:1003 test_bulk_framing` (`MockElasticsearchTransport`; no `TcpListener`) |
| gcp_iot | native MQTT framing over TCP (`TcpGcpIotTransport` via `mqtt_bridge::encode_publish`; JWT via `jsonwebtoken`, RS256/ES256) | loopback fake (in-process `TcpListener` + `decode_publish`; plus `MockGcpIotTransport`) | `crates/broker-connectors/src/gcp_iot.rs:947 test_loopback_telemetry_framing` |
| gcp_pubsub | vendor HTTP API (`HttpGcpPubSubTransport` POST `:publish` base64 JSON; token cache POSTs form to token URL) | loopback fake for token cache only (ephemeral `axum` `/token`; publish path uses `MockGcpPubSubTransport`) | `crates/broker-connectors/src/gcp_pubsub.rs:1000 test_token_cache_caches_and_refreshes` |
| greptimedb | vendor HTTP API + line protocol over HTTP (`HttpGreptimeDbTransport` POST `/sql` form and `/influxdb/api/v2/write` text) | mock transport (despite `loopback` in name, uses `MockGreptimeDbTransport`; no `TcpListener`) | `crates/broker-connectors/src/greptimedb.rs:918 test_greptime_sink_sql_loopback` |
| http | generic vendor HTTP API (webhook via `ReqwestHttpTransport`, POST/PUT/PATCH, Basic/Bearer/ApiKey + HMAC) | mock transport (`MockHttpTransport`; dummy `127.0.0.1:1` never bound) | `crates/broker-connectors/src/http.rs:1101 test_batch_array_wrapping` |
| influxdb | line protocol over HTTP, vendor HTTP API (`reqwest` POST `/api/v2/write?org=&bucket=` text/plain, Token auth; no transport trait) | loopback fake (ephemeral `axum` capture via `serve_captured`) | `crates/broker-connectors/src/influxdb.rs:443 test_batch_posts_line_protocol` |
| iotdb | vendor HTTP API (`HttpIotDbTransport` POST `/insertTablet` JSON, Basic auth) | mock transport | `crates/broker-connectors/src/iotdb.rs:927 test_tablet_grouping_and_types` (`MockIotDbTransport`; no `TcpListener`) |
| kafka | native Kafka wire over TCP, no auth (`TcpKafkaTransport` Produce v3/ApiVersions, RecordBatch-v2, murmur2; acks only) | loopback fake (in-process fake broker `TcpListener`; plus `MemoryKafkaTransport`) | `crates/broker-connectors/src/kafka.rs:985 test_tcp_transport_produce_against_fake_broker` |
| kinesis | vendor HTTP API (`HttpKinesisTransport` POST `PutRecords` JSON with SigV4) | mock transport | `crates/broker-connectors/src/kinesis.rs:996 test_partial_failure_retries_only_failed` (`MockKinesisTransport`; no `TcpListener`) |
| mongodb | native OP_MSG over TCP with SCRAM-SHA-256 (`NativeMongoDbTransport`, pbkdf2 + HMAC) | mock transport (grouping only; no `TcpListener`) | `crates/broker-connectors/src/mongodb.rs:1718 test_grouping_by_collection` |
| mqtt_bridge | native MQTT 3.1.1/5.0 over TCP (`TcpMqttBridgeTransport`, CONNECT/CONNACK/PUBLISH framing, user/password; TLS rejected) | loopback fake (in-process `TcpListener` connect + publish) | `crates/broker-connectors/src/mqtt_bridge.rs:1069 test_tcp_loopback_connect_and_publish` |
| mssql | native TDS over TCP (`NativeMssqlTransport`, PRELOGIN + LOGIN7 + `sp_executesql`, typed params) | loopback fake (in-process `TcpListener` scripting prelogin/login/batch) | `crates/broker-connectors/src/mssql.rs:1370 test_tcp_loopback_prelogin_login_batch` |
| mysql | native MySQL client protocol over TCP (`TcpMySqlTransport`, handshake + `mysql_native_password`, COM_STMT_PREPARE/EXECUTE) | loopback fake (in-process `TcpListener` scripting handshake/prepare/batch; plus `MemoryMySqlTransport`) | `crates/broker-connectors/src/mysql.rs:1192 test_tcp_handshake_prepare_and_batch_params` |
| oci_streaming | vendor HTTP API (`HttpOciStreamingTransport` POST `/20180418/streams/.../messages` with OCI RSA-SHA256 signature) | loopback fake (ephemeral `axum` signed-PUT capture) | `crates/broker-connectors/src/oci_streaming.rs:1188 test_loopback_signed_put` |
| opc_ua | native OPC-UA TCP framing (`TcpOpcUaTransport`, HEL/ACK + OPN/CLO chunks, Variant/DataValue codec; Anonymous/Username/Certificate) | loopback fake (in-process `TcpListener` hello/ack + datachange) | `crates/broker-connectors/src/opc_ua.rs:1640 test_loopback_hello_ack_and_datachange` |
| opentsdb | vendor HTTP API; telnet line protocol stubbed (`NetworkOpenTsdbTransport::put_http` POST `/api/put`; `put_telnet` returns terminal error, `serialize_telnet_lines` only formats) | mock transport (despite `loopback` in name, uses `MockOpenTsdbTransport`; no `TcpListener`) | `crates/broker-connectors/src/opentsdb.rs:762 test_opentsdb_sink_http_loopback` |
| oracle | vendor HTTP API, not TNS: POSTs JSON `{statementText, binds}` (MERGE ... USING DUAL) to Oracle REST Data Services with Basic auth (`HttpOracleTransport`). The module name implies the Oracle wire protocol; it does not speak TNS. | mock transport (despite `loopback` in name, uses `MockOracleTransport`; no `TcpListener`) | `crates/broker-connectors/src/oracle.rs:696 test_oracle_sink_loopback_success` |
| postgres | native PG extended protocol over TCP (`TcpPgTransport`, SSLRequest + startup + MD5/SCRAM-SHA-256, Parse/Bind/Describe/Execute/Sync) | loopback fake (in-process `TcpListener` scripting MD5/SCRAM + batch; plus `MemoryPgTransport`) | `crates/broker-connectors/src/postgres.rs:1281 test_tcp_md5_auth_and_batch_params` |
| pulsar | native Pulsar binary over TCP (framing + CRC32C + Connect/Producer/Send, JWT or none via `TcpPulsarTransport`) | loopback fake (in-process `TcpListener` handshake + send) | `crates/broker-connectors/src/pulsar.rs:1490 test_tcp_loopback_handshake_and_send` |
| rabbitmq | native AMQP 0-9-1 over TCP (`TcpRabbitTransport`, PLAIN handshake + Basic.Publish + content header/body frames) | loopback fake (in-process `TcpListener` handshake + publish; plus `MemoryAmqpTransport`) | `crates/broker-connectors/src/rabbitmq.rs:699 test_tcp_transport_handshake_and_publish` |
| redis | native RESP over TCP (`TcpRedisTransport`, AUTH + SELECT + pipelined commands) | loopback fake (in-process `TcpListener` with canned replies; plus `MemoryRedisTransport`) | `crates/broker-connectors/src/redis.rs:742 test_tcp_auth_select_and_pipelining` |
| redshift | vendor HTTP API (`HttpRedshiftTransport` POST `BatchExecuteStatement` with SigV4) | mock transport | `crates/broker-connectors/src/redshift.rs:948 test_batch_flow_and_targeting` (`MockRedshiftTransport`; no `TcpListener`) |
| rocketmq | custom length-prefixed JSON envelope over TCP (`TcpRocketMqTransport`, `[0x01][u32 len][JSON SendMessage]`, HMAC-SHA1). This is not the vendor Remoting/gRPC protocol; the module name implies RocketMQ wire compatibility it does not have. | loopback fake (in-process `TcpListener` envelope check + `{"code":0}` ack) | `crates/broker-connectors/src/rocketmq.rs:1135 test_tcp_loopback_envelope` |
| s3 | vendor HTTP API (`HttpS3Transport` PUT object ndjson/gzip with SigV4) | mock transport (framing only; no `TcpListener`) | `crates/broker-connectors/src/s3.rs:766 test_ndjson_framing` |
| s3_tables | vendor HTTP API (`HttpS3TablesTransport` PUT data + JSON snapshot with SigV4) | loopback fake (ephemeral `axum` signed-PUT capture) | `crates/broker-connectors/src/s3_tables.rs:1197 test_loopback_put_signed` |
| snowflake | vendor HTTP API (`HttpSnowflakeTransport` POST streaming `/rows` with RS256 JWT Bearer) | mock transport | `crates/broker-connectors/src/snowflake.rs:900 test_row_building_and_uppercase_tables` (`MockSnowflakeTransport`; no `TcpListener`) |
| sparkplug_b | in-memory only: clean-room Tahu Protobuf codec + state machine (`MemorySparkplugTransport::publish`); no `TcpStream`, no `reqwest`, no file transport | mock transport (codec vectors + memory publish only) | `crates/broker-connectors/src/sparkplug_b.rs:1724 test_sink_encodes_normalized_documents` |
| tablestore | vendor HTTP API (`HttpTablestoreTransport` POST `BatchWriteRow` with HMAC-SHA1 + MD5) | loopback fake (ephemeral `axum` `/api/BatchWriteRow` capture) | `crates/broker-connectors/src/tablestore.rs:1220 test_loopback_headers_and_body` |
| tdengine | vendor HTTP API (`HttpTdengineTransport` POST SQL `INSERT INTO ... USING ... TAGS...` with Basic/Taosd auth) | mock transport (rendering only; no `TcpListener`) | `crates/broker-connectors/src/tdengine.rs:895 test_insert_rendering` |
| timescaledb | native PG-compatible wire over TCP (hypertable via shared `TcpPgTransport::execute_batch`; no Timescale-specific framing) | mock transport (binding only; no `TcpListener`, no live Postgres in this module) | `crates/broker-connectors/src/timescaledb.rs:419 test_hypertable_parameter_binding` |
| timestream | vendor HTTP API (`HttpTimestreamTransport` POST `WriteRecords` with SigV4) | mock transport | `crates/broker-connectors/src/timestream.rs:1163 test_partial_rejection_requeues_selectively` (`MockTimestreamTransport`; no `TcpListener`) |
