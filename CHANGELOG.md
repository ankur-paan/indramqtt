# Changelog

All notable changes to **IndraMQTT** ([indramqtt.com](https://indramqtt.com)) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased] - Sprint 20

### Added
- **Amazon Kinesis Sink (`INDRA-197`)**: High-throughput `PutRecords` batch ingestion with SigV4 signing, dynamic partition key derivation, and partial-failure exponential retry.
- **Google Cloud Pub/Sub Sink (`INDRA-199`)**: `v1.publisher.publish` batch sink with ordering keys, dynamic attributes, and OAuth2/JWT authentication.
- **Azure Event Hubs Sink (`INDRA-198`)**: Batch event ingestion with Shared Access Signature (SAS) token generation and partition key hashing.
- **Apache Pulsar Producer Sink (`INDRA-153`)**: Multi-tenant (`tenant/namespace/topic`) partitioned producer with keyed routing and sequence tracking.
- **Cloud Streaming Studio (`INDRA-218`)**: REST API and Web Dashboard forms for all 4 cloud bridges.

### Changed
- **Kafka connector `health_check_topic` default**: the schema default is now `indramqtt_health_check`. Anyone who set the topic explicitly is unaffected; to keep the previous topic, set `health_check_topic` explicitly in the connector configuration.

---

## [0.1.0-sprint19] - 2026-09-12 (Commit `a09eb88`)

### Added
- **Enterprise HTTP Webhook Sink (`INDRA-192`)**: Dedicated REST connector module with templated URL/headers, Basic/Bearer/ApiKey auth, RawJson/JsonBatchArray/FormUrlEncoded formats, and HMAC-SHA256/SHA1 body signatures.
- **Remote MQTT Outbound Bridge Sink (`INDRA-156`)**: Clean-room MQTT 3.1.1 & 5.0 PUBLISH wire encoder, cyclical 1–65535 packet IDs, topic prefix/template remapping with wildcard rejection, QoS/retain overrides, and inflight backpressure queue.
- **Rotating Local Disk Log Sink (`INDRA-202`)**: NDJSON, CSV, and Raw log formatters, size-based and age-based file rotation, gzip compression of rotated segments, retention pruning, and configurable fsync modes.
- **Sparkplug B Protocol Codec & State Machine (`INDRA-200`)**: Complete topic namespace parser (all 9 types + `STATE`), clean-room Protobuf wire codec, bidirectional JSON ↔ Protobuf translation for embedded streaming SQL (`metrics.Temperature > 80.0`), and Edge Node/Device state tracker.
- **Industrial Connectors Studio (`INDRA-217`)**: REST API kinds for webhook, mqtt_bridge, disk_log, sparkplug_b, and Web Dashboard forms with Enterprise tier badging.
- Total automated tests: **388 passing** (265 Rust + 123 EUnit).

---

## [0.1.0-sprint18] - 2026-09-12 (Commit `6b8af81`)

### Added
- **Amazon S3 & MinIO Sink (`INDRA-188`)**: Partitioned key templates (`${topic/YYYY/MM/DD/seq/uuid}`), path sanitization, NDJSON bodies, gzip compression, count/byte/linger flush triggers, and AWS SigV4 signing.
- **Elasticsearch & OpenSearch Sink (`INDRA-184`)**: `_bulk` newline JSON action framing, date-shorthand index resolution, doc-id templates, and 429/503 retry with backoff.
- **TimescaleDB Hypertable Sink (`INDRA-171`)**: 4-column hypertable rows, strict `$1..$4` UPSERT validation, and shared PostgreSQL connection pool.
- **Zero-Limit Scale Hardening (`INDRA-215`)**: Removed hardcoded `WINDOW_CHANNEL_DEPTH` and `MAX_OFFLINE_QUEUE` constants; exposed fully configurable, unbounded capacity options across all queues and buffers.
- Total automated tests: **352 passing** (229 Rust + 123 EUnit).

---

## [0.1.0-sprint17] - 2026-09-12 (Commit `82a41fe`)

### Added
- **MySQL & MariaDB Sink (`INDRA-162`)**: Full wire handshake, `mysql_native_password` authentication, prepared execute batching, and TCP connection pool.
- **ClickHouse Sink (`INDRA-181`)**: Vectorized `JSONEachRow` insertion via HTTP POST with SQL injection whitelisting and backpressure.
- **InfluxDB Sink (`INDRA-172`)**: Line Protocol v2 serializer with Token authentication and `${topic}` measurement templates.
- **Shared Helpers**: Extracted `BatchQueue` and `BackoffState` in `crates/broker-connectors/src/lib.rs`.
- Total automated tests: **326 passing** (203 Rust + 123 EUnit).

---

## [0.1.0-sprint16] - 2026-09-12 (Commit `8a0e930`)

### Added
- **Full `rekuiper` Stream Processing Engine (`INDRA-210` - `INDRA-214`)**:
  - 185 scalar functions validated through the real MQTT ingress hot-path.
  - Stateful window operators (`TUMBLINGWINDOW`, `HOPPINGWINDOW`, `SLIDINGWINDOW`, `COUNTWINDOW`) on dedicated Tokio worker tasks.
  - Multi-event aggregations (`avg`, `sum`, `count`, `min`, `max`, `stddev`, `percentile`) with interval bounds (`window_start()`, `window_end()`).
  - Open-Core tier classification (`RuleTier::Community` vs `RuleTier::Enterprise`).
- Total automated tests: **309 passing** (186 Rust + 123 EUnit).

---

## [0.1.0-sprint15] - 2026-09-11 (Commit `e6c4c6c`)

### Added
- **PostgreSQL Sink (`INDRA-161`)**: Connection-pooled JSONB batching with SCRAM/MD5 authentication.
- **Redis Sink (`INDRA-163`)**: RESP pipeline with support for `SET`, `HSET`, `LPUSH`, `PUBLISH`, and Redis Streams `XADD`.
- **SQL INTO Bridge**: Native `SELECT ... INTO connector("id")` routing.

---

## [0.1.0-sprint14] - 2026-09-11 (Commit `6d77579`)

### Added
- **Apache Kafka Sink (`INDRA-151`)**: Zero-copy partition producer with RecordBatch-v2 framing and Murmur2 key hashing.
- **RabbitMQ Sink (`INDRA-155`)**: AMQP 0-9-1 publisher sink with exchange routing.
- **Unified Sink & Connector Traits**: `Sink::send` and `Connector::connector_id`.
- **Multi-Tenant Quotas (`INDRA-12.1`)**: Per-user connection quotas (`max_connections`) and token-bucket rate limiters (`max_publish_rate`).

---

## [0.1.0-sprint12] - 2026-09-10 (Commit `57b1fc0`)

### Added
- **Embedded Web Dashboard SPA**: Dark-mode management console at `http://localhost:18083/dashboard`.
- **Live SVG Metrics**: Real-time throughput deltas and cluster health cards.
- **Binary MQTT-over-WebSocket**: Listener and browser test console at `ws://localhost:8083/ws/mqtt`.
- **SQL Studio & Auth Console**: In-browser rule authoring and ACL administration.

---

## [0.1.0-sprint11] - 2026-09-09 (Commit `c33c75a`)

### Added
- **Core Restart Immunity**: BEAM edge socket preservation (<200 ms rebind with zero client TCP drops on core upgrade).
- **TLS Edge Listener**: MQTTS on `:8883`.
- **Delayed Messages**: Native `$delayed/<sec>/<topic>` timer queues.
- **Enterprise License Scaffolding**: Cryptographic Ed25519 verification engine.
