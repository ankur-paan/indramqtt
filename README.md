# IndraMQTT

[![Website](https://img.shields.io/badge/Website-indramqtt.com-blue?style=flat&logo=google-chrome&logoColor=white)](https://indramqtt.com)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-APACHE)
[![Enterprise Edition](https://img.shields.io/badge/Enterprise-Commercial%20%2F%20Eval-gold.svg)](LICENSE-ENTERPRISE)
[![Rust Version](https://img.shields.io/badge/Rust-1.80%2B-orange.svg)](https://www.rust-lang.org)
[![OTP Version](https://img.shields.io/badge/Erlang%2FOTP-26%2B-red.svg)](https://www.erlang.org)
[![Automated Tests](https://img.shields.io/badge/Tests-388%20Passing%20(100%25)-brightgreen.svg)](https://indramqtt.com)

**Official Website**: [indramqtt.com](https://indramqtt.com) | **Documentation**: [indramqtt.com/docs](https://indramqtt.com/docs)

[Architecture](ARCHITECTURE.md) • [Benchmarks](BENCHMARKS.md) • [Roadmap](ROADMAP.md) • [Changelog](CHANGELOG.md) • [Contributing](CONTRIBUTING.md) • [Docker](#one-click-evaluation-with-docker)

**IndraMQTT** is an ultra-fast, lightweight, and highly concurrent dual-licensed distributed MQTT messaging and streaming platform designed from first principles for mission-critical IoT, industrial edge, and hyper-scale cloud deployments.

---

## Router & Rule Engine Microbenchmarks

All figures below are grounded in reproducible, multi-sample automated benchmark gates defined in [`crates/broker-node/benches/broker_throughput.rs`](crates/broker-node/benches/broker_throughput.rs).

### Measured Microbenchmark Performance

| Subsystem / Benchmark | Measured Throughput (Release) | What Is Measured | Profile & Methodology |
| :--- | :--- | :--- | :--- |
| **Radix Trie Router (Hit-Path)** | **~3.0M ± 0.1M msg/sec** | In-process lookup matching 3 subscriber targets across 1,000 installed topic filters | Single-threaded in-memory function call, `ahash` + zero-allocation `Arc<str>` tokens |
| **Radix Trie Router (Fast-Miss)** | **~7.8M ± 0.2M msg/sec** | Walk-only trie branch evaluation on non-matching topic prefix | Single-threaded in-memory branch walk |
| **Streaming SQL Ingress Engine** | **~4.7M ± 0.1M events/sec** | In-process JSON parsing + SQL `WHERE` filter + `SELECT` field projection | Single-threaded, **100% verified delivered to sink** (0 drops), `Block` backpressure |
| **Idle Base Memory Footprint** | **< 15 MB RSS** | Standalone Rust Core daemon idle resident memory footprint | Zero client connections, baseline Tokio runtime + Router |

> [!IMPORTANT]
> **Scope Note**: The table above measures purely in-process, function-level microbenchmarks (radix trie matching and streaming SQL expression evaluation). It does **not** represent end-to-end network throughput over TCP/TLS sockets. For architectural comparison targets, competitor network baselines (EMQX, HiveMQ, VerneMQ, Mosquitto), and literature citations, see [BENCHMARKS.md](BENCHMARKS.md).

---

## Key Architecture

IndraMQTT decouples the network edge from the broker kernel through a clean, resilient separation of concerns:

```
                     MQTT CLIENTS
                          │
             TCP / TLS / WebSocket / MQTT
                          │
              ┌──────────────────────┐
              │     BEAM EDGE        │
              │     Erlang/OTP       │
              │                      │
              │ socket ownership     │
              │ MQTT framing/codec   │
              │ keepalive/timers     │
              │ connection process   │
              │ packet-id handling   │
              │ QoS hot-state mirror │
              └──────────┬───────────┘
                         │
                 BrokerLink Protocol
                 UDS / binary frames
                         │
      ┌──────────────────▼───────────────────┐
      │              RUST CORE               │
      │                                      │
      │ Session Engine                       │
      │ Subscription Router (Radix Trie)     │
      │ AuthN / AuthZ Engine                 │
      │ Quotas / Rate limits                 │
      │ Retained Message Store               │
      │ Durable Sessions (Log + Cursor)      │
      │ Shared Subscriptions ($share)        │
      │ Delayed Messages                     │
      │ rekuiper Stream Engine (Embedded)    │
      │ Connectors / Bridges                 │
      │ Cluster Control Plane (Raft)         │
      │ Cluster Routing Plane (QUIC)         │
      │ Management REST API (Axum)           │
      │ Metrics & OpenTelemetry              │
      │ WASM Extensions (Component Model)    │
      └─────────┬──────────────────┬─────────┘
                │                  │
          Rust Cluster       Rust Storage
             QUIC               engine
                │
         ┌──────▼──────┐
         │ other nodes │
         └─────────────┘
```

### 1. Connection != Session
* **BEAM Network Appliance**: The Erlang/OTP layer is strictly a lightweight, high-concurrency network appliance. It owns sockets, TLS handshakes, MQTT framing, keepalive timers, and socket backpressure. It has no business logic, no distributed database, and no rule engine.
* **Rust Canonical Session**: Rust owns the canonical MQTT session, subscription registrations, QoS inflight tracking, offline message cursors, and expiry timers.
* **Core Restart Immunity**: If the Rust broker kernel restarts or performs a rolling upgrade, the BEAM edge keeps client sockets alive and re-binds active sessions upon core resumption—resulting in zero TCP disconnects for edge devices.

### 2. Zero-Copy BrokerLink IPC
The BEAM edge communicates with the Rust kernel over **BrokerLink**, a dedicated high-throughput, multi-lane binary IPC protocol:
* **Multi-Lane Affinity**: Erlang routes connection traffic across $N$ parallel IPC lanes using consistent hashing on connection ID (`conn_id % num_lanes`), eliminating cross-connection head-of-line blocking while guaranteeing strict per-client message ordering.
* **Opaque Payloads**: Payloads remain untouched opaque byte slices. Deserialization only occurs if an embedded streaming SQL rule explicitly inspects payload fields.
* **Micro-Batching & Credit Backpressure**: Prevents buffer bloating during massive ingress surges.

### 3. Native Stream Processing with Embedded rekuiper
IndraMQTT embeds [rekuiper](https://github.com/ankur-paan/rekuiper) directly in-process:
* **Zero Network Loopback**: Republishing actions publish directly to the internal Rust subscription router in memory.
* **Deterministic Backpressure**: Ingress events are governed by explicit memory-bounded policies (`Block`, `DropNewest`, `DropOldest`, `SpillToDisk`, `RejectPublisher`).
* **Single Execution per Message**: Rules execute on the ingress node prior to cluster fanout, preventing duplicate sink dispatches across the cluster.

### 4. High-Efficiency Storage & Persistence
* **Log + Cursor Architecture**: Durable messages are appended once to an append-only segmented log. Sessions advance individual cursors rather than duplicating messages per offline subscriber.
* **Pure Rust Backends**: High-performance LSM and transactional storage engines (Fjall, Redb).

### 5. Independent Cluster Planes
* **Membership**: Gossip-based SWIM protocol for rapid, low-overhead node discovery and failure detection.
* **Metadata Consensus**: Distributed Raft (OpenRaft) strictly for cluster configuration, user credentials, ACLs, listener bindings, and stream rules.
* **Data & Routing Plane**: Multiplexed QUIC streams with topic-filter summaries (`TopicFilter -> NodeSet`). Messages are transmitted once per destination broker node, which then executes local client fanout.

---

## Open-Core Licensing Model

IndraMQTT is engineered with a transparent **Open-Core** architecture designed to guarantee permanent freedom for edge and single-server deployments while offering enterprise-grade clustering, industrial protocols, and multi-cloud streaming capabilities:

| Feature Dimension | Community Edition (Free & Open Source) | Enterprise Edition (Commercial / Free Eval) |
| :--- | :--- | :--- |
| **Licensing** | **Permissive MIT OR Apache-2.0** ([`LICENSE-MIT`](LICENSE-MIT) / [`LICENSE-APACHE`](LICENSE-APACHE)) | **Commercial Subscription** ([`LICENSE-ENTERPRISE`](LICENSE-ENTERPRISE)) |
| **License Enforcement** | **Zero license key required**. Free forever for production. | Cryptographic Ed25519 node authorization. Free Community Evaluation mode for local dev/testing. |
| **Broker Kernel** | High-performance Rust Core (`>3M msg/sec`, `<15 MB RSS`) | High-performance Rust Core (`>3M msg/sec`, `<15 MB RSS`) |
| **Network Edge** | Erlang/OTP 26+ BEAM Edge with Core Restart Immunity | Erlang/OTP 26+ BEAM Edge with Core Restart Immunity |
| **Protocols Supported** | MQTT v3.1.1 & v5.0, TLS (`:8883`), WebSocket (`:8083`) | MQTT v3.1.1 & v5.0, TLS (`:8883`), WebSocket (`:8083`), Sparkplug B, OPC-UA |
| **Routing & Sessions** | Zero-allocation Radix Trie, QoS 0/1/2, Shared Subscriptions (`$share`), Delayed Messages (`$delayed`), Retained Store | Radix Trie, QoS 0/1/2, Shared Subscriptions, Delayed Messages, Retained Store |
| **Scale Limits** | **Zero artificial limits**. Unbounded channels, queues, and connection limits. | **Zero artificial limits**. Unbounded channels, queues, and connection limits. |
| **Clustering** | Single-Node Standalone / Edge Appliance | **Distributed QUIC Data Plane**, SWIM Gossip Membership, Distributed Raft Consensus |
| **Stream Processing** | Embedded `rekuiper` Stateless SQL (all 185 scalar functions, `WHERE`, `SELECT`, `CASE`, math, trig, bitwise, string, date/time) | Embedded `rekuiper` Stateful Windowing (`TUMBLINGWINDOW`, `HOPPINGWINDOW`, `SLIDINGWINDOW`, `COUNTWINDOW`), multi-event aggregations (`avg`, `sum`, `count`, `min`, `max`, `stddev`, `percentile`) |
| **Data Sinks & Bridges** | PostgreSQL, MySQL, Redis, ClickHouse, InfluxDB, TimescaleDB, Amazon S3 / MinIO, Elasticsearch / OpenSearch, RabbitMQ, HTTP Webhook, Remote MQTT Bridge, Rotating Local Disk Log | Apache Kafka, Sparkplug B, Amazon Kinesis, Google Cloud Pub/Sub, Azure Event Hubs, Apache Pulsar, Snowflake, BigQuery, AI/LLM Bridges (OpenAI, Claude, Gemini, MCP) |
| **Management & UI** | Embedded Web Dashboard SPA (`:18083`), REST Management API, Prometheus `/api/v1/metrics` | Embedded Web Dashboard SPA (`:18083`), REST Management API, Prometheus `/api/v1/metrics`, Enterprise Studio Badging |
| **Multi-Tenancy** | Connection quotas (`max_connections`) & Publish rate limiter (`max_publish_rate`) | Connection quotas & Publish rate limiter with cluster-wide quota synchronization |

For enterprise licensing, multi-node clustering subscriptions, or commercial support, visit [indramqtt.com](https://indramqtt.com) or contact [sales@i-dacs.com](mailto:sales@i-dacs.com).

---

## Core Capabilities & Features

### 1. Ultra-Low-Latency Message Router
- **Radix Trie Architecture**: Evaluates exact and wildcard topic filters (`+`, `#`, `$SYS/`, `$share/<group>/<topic>`, `$delayed/<sec>/<topic>`) in a single lock-free pass using `ahash` and zero-allocation `Arc<str>` segments.
- **Microsecond Routing**: Sustains **3.05M msg/sec** on hit-path evaluation and **7.80M msg/sec** fast-miss traversal.

### 2. Embedded Streaming SQL Engine (`rekuiper`)
- **185-Function Scalar Catalog**: Full trigonometry (`sin`, `cos`, `atan2`), arithmetic, bitwise operators, string manipulation, datetime transformations (`now()`, `format_date()`), conditionals (`CASE WHEN ... THEN ... ELSE ... END`), and null coalescing.
- **Stateless Ingress Hot-Path**: Evaluates SQL filters in-memory at **4.77M events/sec** with zero network loopback.
- **Stateful Window Operators**: Enterprise tumbling, hopping, sliding, and count windows executing on dedicated background Tokio workers with interval timestamp injection (`window_start()`, `window_end()`).
- **SQL `INTO connector("id")`**: Native SQL syntax for declarative routing directly into downstream streaming bridges and databases.

### 3. Comprehensive Data Sinks & Bridges Suite
- **Message Streaming**: Apache Kafka (RecordBatch v2, murmur2 hashing), RabbitMQ (AMQP 0-9-1), Remote MQTT Outbound Bridge (clean-room 3.1.1/5.0 wire encoder).
- **Relational & KV Databases**: PostgreSQL (connection-pooled JSONB batching, SCRAM/MD5), MySQL / MariaDB (native handshake & authentication, prepared batching), Redis (RESP pipeline, Streams `XADD`, `LPUSH`, `PUBLISH`).
- **Analytics & Time-Series**: ClickHouse (vectorized `JSONEachRow` HTTP POST, SQL injection whitelisting), InfluxDB (Line Protocol v2 with Token auth), TimescaleDB (hypertable chunking and parametrized `$1..$4` upsert).
- **Object Storage & Search**: Amazon S3 / MinIO (buffer-and-flush micro-batching, partitioned key templates, ndjson/gzip, full AWS SigV4 signing), Elasticsearch / OpenSearch (`_bulk` newline JSON with dynamic date-indices and 429/503 retry).
- **Industrial Edge & Webhooks**: Advanced HTTP Webhook (URL/header templates, HMAC-SHA256/SHA1 payload signing, jittered retry), Rotating Local Disk Log (NDJSON/CSV/Raw formats, byte-size and age rotation, gzip compression, retention purge), Sparkplug B (Eclipse Tahu Protobuf codec, namespace parser, metric alias cache, Edge Node/Device state tracker).

### 4. Embedded Web Dashboard SPA & Management REST API
- **Dark-Mode Web Dashboard**: Served directly from the broker kernel at `http://localhost:18083/dashboard`.
- **Live SVG Metrics**: Real-time cluster connection counters, ingress/egress message rates, and throughput delta sparklines.
- **SQL Studio & Rule Tester**: Interactive query editor with batch evaluation (`POST /api/v1/rules/test`), function catalog browser (`GET /api/v1/rules/functions`), and Community/Enterprise tier badges.
- **Connectors Studio**: Visual registration forms for streaming, relational, analytical, object storage, and industrial sinks.
- **MQTT-over-WebSocket Test Console**: Integrated binary MQTT test client connecting over `ws://localhost:8083/ws/mqtt`.
- **Auth & ACL Manager**: Runtime credential and topic access policy configuration.

### 5. Resilience & Zero-Limit Scale Architecture
- **Core Restart Immunity**: Decoupled BEAM edge maintains client TCP/TLS sockets during broker core restarts or rolling upgrades, re-binding sessions in `<200 ms` with zero client reconnect storms.
- **Zero Hardcoded Limits**: Buffer depths (`window_channel_depth`), offline session queues (`max_offline_queue`), batch sizes, and pool capacities are unconstrained and fully configurable.
- **Multi-Tenant Protection**: Per-client and per-user connection quotas (`max_connections` -> RC `0x8B`) and token-bucket publish rate limiters (`max_publish_rate` -> RC `0x97`).

---

## Repository Structure

```
indramqtt/
├── beam/                         # BEAM Network Edge Appliance (Erlang/OTP)
│   ├── src/
│   │   ├── indra_edge_app.erl    # Application entrypoint
│   │   ├── indra_edge_sup.erl    # Root supervision tree
│   │   ├── indra_listener.erl    # TCP/TLS/WS socket acceptor
│   │   ├── indra_conn.erl        # Per-connection state machine
│   │   ├── indra_brokerlink.erl  # Multi-lane BrokerLink client
│   │   └── indra_mqtt_codec.erl  # Zero-allocation MQTT packet framing
│   └── rebar.config
│
├── proto/                        # BrokerLink IPC Protocol (Protobuf specifications)
│   └── brokerlink.proto
│
├── crates/
│   ├── brokerlink/               # Shared IPC framing, codec, and transport abstractions
│   ├── broker-protocol/          # MQTT 3.1.1 & 5.0 protocol primitives
│   ├── broker-router/            # Radix trie subscription router
│   ├── broker-session/           # Canonical session engine & QoS tracking
│   ├── broker-storage/           # Segmented log and cursor persistence
│   ├── broker-auth/              # Authentication & ACL authorization
│   ├── broker-rules/             # Embedded rekuiper stream processing engine
│   ├── broker-cluster/           # SWIM membership, Raft consensus, QUIC data plane (Enterprise)
│   ├── broker-connectors/        # Unified stream sources & enterprise sinks
│   ├── broker-api/               # Axum REST management API & embedded Web Dashboard
│   ├── broker-observability/     # Prometheus metrics and OpenTelemetry tracing
│   └── broker-node/              # Main broker daemon binary & throughput benches
└── tests/                        # Conformance, chaos, and integration suites
```

---

## Getting Started

### One-Click Evaluation with Docker
Get IndraMQTT and the embedded Web Dashboard running in 5 seconds:

```bash
# Clone the repository
git clone https://github.com/ankur-paan/indramqtt.git && cd indramqtt

# Start broker and dashboard in background
docker compose up -d

# Open the Web Dashboard
# -> http://localhost:18083/dashboard
```

### Local Build & Development

#### Prerequisites
* **Rust**: `1.80+`
* **Erlang/OTP**: `26+`
* **Rebar3**: `3.22+`

#### Building & Running Locally

```bash
# 1. Build the Rust broker kernel
cargo build --workspace --release

# 2. Run the complete automated test suite (388 tests, 100% green)
cargo test --workspace

# 3. Build the BEAM network edge
cd beam && rebar3 compile && cd ..

# 4. Launch the IndraMQTT standalone broker daemon
cargo run --release -p broker-node -- --api-bind 127.0.0.1:18083

# 5. Access the Web Dashboard
# Open http://localhost:18083/dashboard in your browser
```

---

## License & Commercial Terms

IndraMQTT is distributed under a dual-licensing structure:

1. **Community Edition (Open Source)**:
   - Licensed under the **MIT License** ([`LICENSE-MIT`](LICENSE-MIT)) OR **Apache License, Version 2.0** ([`LICENSE-APACHE`](LICENSE-APACHE)).
   - Covers all core broker crates, BEAM edge, BrokerLink IPC, session engine, storage engine, embedded stateless SQL rules, and Community connectors.
2. **Enterprise Edition (Commercial / Free Community Evaluation)**:
   - Governed by the **Indra Enterprise Commercial License** ([`LICENSE-ENTERPRISE`](LICENSE-ENTERPRISE)).
   - Covers distributed QUIC clustering (`crates/broker-cluster`), stateful windowed stream processing, and specialized enterprise/industrial connectors.
   - Royalty-free for personal, development, testing, and evaluation purposes. Production deployments require a commercial subscription.

For commercial licensing, enterprise clustering support, and cloud subscriptions:
🌐 **Website**: [indramqtt.com](https://indramqtt.com) | ✉️ **Contact**: [sales@i-dacs.com](mailto:sales@i-dacs.com)
