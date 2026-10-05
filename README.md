# IndraMQTT

[![Website](https://img.shields.io/badge/Website-indramqtt.com-blue?style=flat&logo=google-chrome&logoColor=white)](https://indramqtt.com)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-APACHE)
[![Enterprise Edition](https://img.shields.io/badge/Enterprise-Commercial%20%2F%20Eval-gold.svg)](LICENSE-ENTERPRISE)
[![Rust Version](https://img.shields.io/badge/Rust-1.80%2B-orange.svg)](https://www.rust-lang.org)
[![OTP Version](https://img.shields.io/badge/Erlang%2FOTP-26%2B-red.svg)](https://www.erlang.org)
[![Automated Tests](https://img.shields.io/badge/Tests-automated-brightgreen.svg)](https://indramqtt.com/docs)

**Official Website**: [indramqtt.com](https://indramqtt.com) | **Documentation**: upcoming

[Architecture](ARCHITECTURE.md) • [Benchmarks](BENCHMARKS.md) • [Roadmap](ROADMAP.md) • [Changelog](CHANGELOG.md) • [Contributing](CONTRIBUTING.md) • [Docker](#one-click-evaluation-with-docker)

**IndraMQTT** is a dual-licensed distributed MQTT messaging and streaming platform for IoT, industrial edge, and cloud deployments.

---

## Broker Comparison at 1 CPU and 1 GB

Highest load that each broker holds for 180 s with 1 CPU and 1 GB of memory, with no lost message, no backlog, latency below 1 s and level memory. MQTT 5, payload 256 bytes, one broker at a time on the same server, measured on 2026-10-05. The method, the tool, the broker settings, the MQTT 3.1.1 results and the raw data are in [`benchmark/`](benchmark/README.md).

| Scenario | IndraMQTT | EMQX Enterprise 6.3.0 | rumqttd 0.19.0 |
| :--- | :--- | :--- | :--- |
| Point-to-point QoS 0 | **100,000 msg/s** | 20,000 msg/s | none: memory increases |
| Point-to-point QoS 1 | **30,000 msg/s** | 7,500 msg/s | none: memory increases |
| Fan-in QoS 0 (N publishers, 1 subscriber) | 40,000 msg/s | 10,000 msg/s | **80,000 msg/s** |
| Fan-out QoS 0 (1 publisher, N subscribers) | **160,000 deliveries/s** | 20,000 deliveries/s | 80,000 deliveries/s |
| 10,000 idle connections, memory | **283 MiB** | 720 MiB | 638 MiB (161 clients not connected) |
| Memory with no clients | 76 MiB | 322 MiB | **1.5 MiB** |

> [!IMPORTANT]
> **Limits of this comparison**: each result is one search and one 180 s run on a shared server, without TLS, and the load generator runs on the same server. IndraMQTT is behind rumqttd in the fan-in scenario and in the memory with no clients. With MQTT 3.1.1, IndraMQTT uses more memory for each connection than EMQX (21 KiB and 18 KiB). The IndraMQTT numbers use the MQTT listener of the kernel (`listeners.tcp.native = true`). This listener is off by default at this time: the default path through the Erlang edge holds approximately 5,000 msg/s in the point-to-point scenario. See [Direction: One Rust Process](#direction-one-rust-process). See [`benchmark/README.md`](benchmark/README.md) for all conditions and for the cases where a broker has no sustained load.

---

## Direction: One Rust Process

IndraMQTT started with two processes: an Erlang/OTP edge that holds the client sockets, and a Rust kernel that does the routing, the sessions and the rules. We measured the two paths on the same server with 1 CPU and 1 GB:

| Path for MQTT clients | Point-to-point QoS 0, highest sustained load | Status |
| :--- | :--- | :--- |
| Erlang edge, then the kernel through an IPC link (the default today) | approximately 5,000 msg/s | Works with all listeners. It will be deprecated. |
| MQTT listener of the kernel, Rust only (`listeners.tcp.native = true`) | 100,000 msg/s | New. It is the path of the comparison table above. |

Because of these results, IndraMQTT moves to one Rust process:

1. The kernel listener gets the functions that only the edge has today: WebSocket, secure WebSocket, PSK and client certificates.
2. The full end-to-end test suite moves to the kernel listener.
3. The kernel listener becomes the default.
4. The Erlang edge is deprecated and then removed in a later release.

### Connections during a restart

With the Erlang edge, a client stays connected when the kernel restarts. This is a property of the Erlang path only. The MQTT listener of the kernel does not have it at this time: when the kernel restarts, its clients connect again.

The plan for the Rust process keeps this property without work on the message path:

| Case | Plan | What a client sees |
| :--- | :--- | :--- |
| Planned restart (upgrade, change of the configuration) | The old process gives each open socket and a small record of the connection to the new process. | A short pause. No new connection. |
| Crash of the process | A small process holds a copy of each socket and gives the sockets to a new broker process. It does not touch the messages. | Most clients stay connected. A client that was in the middle of a packet connects again. |

Limits of this plan: it is for Linux. TLS connections stay connected only when the encryption runs in the Linux kernel (kTLS). QUIC connections connect again. Session state that is only in memory is lost in a crash, as it is today.

This work starts after the kernel listener is the default. Its order is: planned restart for TCP and WebSocket, then the crash case, then TLS.

Until step 3, a broker that starts with the default settings uses the Erlang edge and has the lower load of the first row. To get the load of the comparison table, set `listeners.tcp.native = true`. The value for the Erlang edge is from a run of 2026-10-04 with a smaller load generator. The sections below that describe the Erlang edge show the default path of today.

---

## Roadmap

- The target for the first full stable release (1.0) is April 2027.
- All stable releases of IndraMQTT will be open source.
- We are working with our team on the transition from the current licence format (community edition and enterprise edition) to MIT OR Apache-2.0 for the project. The transition is planned for the time when this repository has 1,000 GitHub stars. Until then, the licence files in this repository apply as they are.

The plan for each period is in [ROADMAP.md](ROADMAP.md).

---

## Router & Rule Engine Microbenchmarks

All figures below are grounded in reproducible, multi-sample automated benchmark gates defined in [`crates/broker-node/benches/broker_throughput.rs`](crates/broker-node/benches/broker_throughput.rs).

### Measured Microbenchmark Performance

| Subsystem / Benchmark | Measured Throughput (Release) | What Is Measured | Profile & Methodology |
| :--- | :--- | :--- | :--- |
| **Radix Trie Router (Hit-Path)** | **~3.05M ± 0.10M msg/sec** | In-process microbenchmark `bench_router_match_throughput`: lookup matching 3 subscriber targets across 1,000 installed topic filters | Single-threaded in-memory function call, `ahash` + zero-allocation `Arc<str>` tokens; hardware-dependent (re-run locally with `cargo test --release --bench broker_throughput -- --nocapture`); not end-to-end network throughput |
| **Radix Trie Router (Fast-Miss)** | **~7.80M ± 0.20M msg/sec** | In-process microbenchmark `bench_router_match_throughput`: walk-only trie branch evaluation on non-matching topic prefix | Single-threaded in-memory branch walk; hardware-dependent (re-run locally with `cargo test --release --bench broker_throughput -- --nocapture`); not end-to-end network throughput |
| **Streaming SQL Ingress Engine** | **~4.77M ± 0.10M events/sec** | In-process microbenchmark `bench_sql_ingress_throughput`: JSON parsing + SQL `WHERE` filter + `SELECT` field projection | Single-threaded, **100% verified delivered to sink** (0 drops), `Block` backpressure; hardware-dependent (re-run locally with `cargo test --release --bench broker_throughput -- --nocapture`); not end-to-end network throughput |

> [!IMPORTANT]
> **Scope Note**: The table above measures purely in-process, function-level microbenchmarks (radix trie matching and streaming SQL expression evaluation). It does **not** represent end-to-end network throughput over TCP/TLS sockets. The figures are hardware-dependent: no machine is cited because the rate varies by CPU and build flags, so re-run `cargo test --release --bench broker_throughput -- --nocapture` on your own hardware instead of comparing across machines. End-to-end loopback measurements (with delivery percentages and RSS under load, plus the CPU, memory, OS and network in the `environment` block) live in `benchmark_suite/benchmark_results_v5.json`. No idle-RSS benchmark is committed in-tree, so no idle footprint figure is claimed here. For architectural comparison targets, externally published network baselines, and literature citations, see [BENCHMARKS.md](BENCHMARKS.md) (none of those are IndraMQTT measurements).

---

## Key Architecture

IndraMQTT decouples the network edge from the broker kernel through a clean, resilient separation of concerns:

```
                     MQTT CLIENTS
                          │
             TCP / TLS / MQTT v3.1.1
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
* **Core Restart Immunity (Erlang edge only, single-connection test)**: If the Rust broker kernel restarts, the BEAM edge holds the client socket in `await_core` and rebinds on resumption without a disconnect, proven only for one loopback connection against a fake core by `core_restart_zero_disconnect_test` in `beam/test/indra_chaos_tests.erl` (500 ms budget); not a multi-client production claim.

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
| **License Enforcement** | **Zero license key required**. Free forever for production. | Hardware-rooted ECDSA P-256 licence verification against a configured key set. Free Community Evaluation mode for local dev/testing. |
| **Broker Kernel** | High-performance Rust Core (router microbenchmark `bench_router_match_throughput` ~3.05M lookups/sec single-threaded, hardware-dependent, 1,000 filters with 3 targets; not network throughput; no idle-RSS figure claimed) | High-performance Rust Core (router microbenchmark `bench_router_match_throughput` ~3.05M lookups/sec single-threaded, hardware-dependent, 1,000 filters with 3 targets; not network throughput; no idle-RSS figure claimed) |
| **Network Edge** | Erlang/OTP 26+ BEAM Edge with Core Restart Immunity (to be deprecated), or the MQTT listener of the kernel | Erlang/OTP 26+ BEAM Edge with Core Restart Immunity (to be deprecated), or the MQTT listener of the kernel |
| **Protocols Supported** | MQTT v3.1.1 only on every edge listener (TCP, TLS, `ws`, `wss`): v5 CONNECT rejected as `unsupported_protocol` in `beam/src/indra_mqtt_codec.erl:decode_connect`; v5 not supported yet. Plaintext `ws` edge listener enabled by default (`0.0.0.0:8083`, configurable path; `beam/src/indra_ws_listener.erl`, proven by `beam/test/indra_ws_tests.erl`). Opt-in `wss` edge listener disabled by default (needs cert/key or it fails closed at startup; `beam/test/indra_wss_tests.erl`). TLS via edge `ssl` transport (`beam/test/indra_listener_tests.erl:tls_connect_connack_test`). MQTT-over-WebSocket test console on the API port (`/ws/mqtt` in `crates/broker-api/src/ws.rs`) is a test console only | MQTT v3.1.1 only on every edge listener (v5 not supported yet), `ws` edge listener, opt-in `wss` edge listener, TLS via edge `ssl` transport, MQTT-over-WebSocket test console on the API port (`/ws/mqtt`), Sparkplug B, OPC-UA |
| **Routing & Sessions** | Zero-allocation Radix Trie, QoS 0/1/2, Shared Subscriptions (`$share`), Delayed Messages (`$delayed`), Retained Store | Radix Trie, QoS 0/1/2, Shared Subscriptions, Delayed Messages, Retained Store |
| **Scale Limits** | **Configurable bounds with finite defaults**. Queue and pool capacities are bounded by default (for example `session.max_qos0_backlog` 1000, `session.max_offline_queue` 50000, `rules_engine.window_channel_depth` 65536 in `indramqtt.example.toml` and `crates/broker-config/src/schema.rs`); unbounded is only an explicit operator opt-in, never the default. | **Configurable bounds with finite defaults** (same defaults as Community); unbounded only as an explicit operator opt-in. |
| **Clustering** | Single-Node Standalone / Edge Appliance | **Distributed QUIC Data Plane**, SWIM Gossip Membership, Distributed Raft Consensus |
| **Stream Processing** | Embedded `rekuiper` Stateless SQL (all 185 scalar functions, `WHERE`, `SELECT`, `CASE`, math, trig, bitwise, string, date/time) | Embedded `rekuiper` Stateful Windowing (`TUMBLINGWINDOW`, `HOPPINGWINDOW`, `SLIDINGWINDOW`, `COUNTWINDOW`), multi-event aggregations (`avg`, `sum`, `count`, `min`, `max`, `stddev`, `percentile`) |
| **Data Sinks & Bridges** | PostgreSQL, MySQL, Redis, ClickHouse, InfluxDB, TimescaleDB, Amazon S3 / MinIO, Elasticsearch / OpenSearch, RabbitMQ, HTTP Webhook, Remote MQTT Bridge, Rotating Local Disk Log | Apache Kafka, Sparkplug B, Amazon Kinesis, Google Cloud Pub/Sub, Azure Event Hubs, Apache Pulsar, Snowflake, BigQuery, AI/LLM Bridges (OpenAI, Claude, Gemini, MCP) |
| **Management & UI** | Embedded Web Dashboard SPA (`:18083`), REST Management API, Prometheus `/api/v1/metrics` | Embedded Web Dashboard SPA (`:18083`), REST Management API, Prometheus `/api/v1/metrics`, Enterprise Studio Badging |
| **Multi-Tenancy** | Connection quotas (`max_connections`) & Publish rate limiter (`max_publish_rate`) | Connection quotas & Publish rate limiter with cluster-wide quota synchronization |

For enterprise licensing, multi-node clustering subscriptions, or commercial support, visit [indramqtt.com](https://indramqtt.com) or contact [sales@i-dacs.com](mailto:sales@i-dacs.com).

---

## Core Capabilities & Features

### 1. Message Router
- **Radix Trie Architecture**: Evaluates exact and wildcard topic filters (`+`, `#`, `$SYS/`, `$share/<group>/<topic>`, `$delayed/<sec>/<topic>`) in a single lock-free pass using `ahash` and zero-allocation `Arc<str>` segments.
- **In-process routing throughput (microbenchmark, hardware-dependent)**: `bench_router_match_throughput` in `crates/broker-node/benches/broker_throughput.rs` sustains **~3.05M ± 0.10M lookups/sec** on hit-path evaluation (1,000 filters, 3 targets) and **~7.80M ± 0.20M lookups/sec** fast-miss traversal, single-threaded; re-run locally with `cargo test --release --bench broker_throughput -- --nocapture`; not end-to-end network throughput.

### 2. Embedded Streaming SQL Engine (`rekuiper`)
- **185-Function Scalar Catalog** (count asserted by `test_function_catalog_has_185_entries` in `crates/broker-rules/src/lib.rs`): Full trigonometry (`sin`, `cos`, `atan2`), arithmetic, bitwise operators, string manipulation, datetime transformations (`now()`, `format_date()`), conditionals (`CASE WHEN ... THEN ... ELSE ... END`), and null coalescing.
- **Stateless Ingress Hot-Path (microbenchmark, hardware-dependent)**: `bench_sql_ingress_throughput` in `crates/broker-node/benches/broker_throughput.rs` evaluates SQL filters in-memory at **~4.77M ± 0.10M events/sec** with zero network loopback (`Block` backpressure, 100 percent sink delivery); re-run locally with `cargo test --release --bench broker_throughput -- --nocapture`; not end-to-end network throughput.
- **Stateful Window Operators**: Enterprise tumbling, hopping, sliding, and count windows executing on dedicated background Tokio workers with interval timestamp injection (`window_start()`, `window_end()`).
- **SQL `INTO connector("id")`**: Native SQL syntax for declarative routing directly into downstream streaming bridges and databases.

### 3. Comprehensive Data Sinks & Bridges Suite
- **Message Streaming**: Apache Kafka (RecordBatch v2, murmur2 hashing), RabbitMQ (AMQP 0-9-1), Remote MQTT Outbound Bridge (clean-room 3.1.1/5.0 PUBLISH wire encoder for outbound bridging only; edge ingress remains MQTT 3.1.1).
- **Relational & KV Databases**: PostgreSQL (connection-pooled JSONB batching, SCRAM/MD5), MySQL / MariaDB (native handshake & authentication, prepared batching), Redis (RESP pipeline, Streams `XADD`, `LPUSH`, `PUBLISH`).
- **Analytics & Time-Series**: ClickHouse (vectorized `JSONEachRow` HTTP POST, SQL injection whitelisting), InfluxDB (Line Protocol v2 with Token auth), TimescaleDB (hypertable chunking and parametrized `$1..$4` upsert).
- **Object Storage & Search**: Amazon S3 / MinIO (buffer-and-flush micro-batching, partitioned key templates, ndjson/gzip, full AWS SigV4 signing), Elasticsearch / OpenSearch (`_bulk` newline JSON with dynamic date-indices and 429/503 retry).
- **Industrial Edge & Webhooks**: Advanced HTTP Webhook (URL/header templates, HMAC-SHA256/SHA1 payload signing, jittered retry), Rotating Local Disk Log (NDJSON/CSV/Raw formats, byte-size and age rotation, gzip compression, retention purge), Sparkplug B (Eclipse Tahu Protobuf codec, namespace parser, metric alias cache, Edge Node/Device state tracker).
- **Capability & Qualification**: See `crates/broker-connectors/CAPABILITY.md` for what each sink actually speaks and what it was tested against; no sink in this tree has been qualified against a real vendor server.

### 4. Embedded Web Dashboard SPA & Management REST API
- **Dark-Mode Web Dashboard**: Served directly from the broker kernel at `http://localhost:18083/dashboard`.
- **Live SVG Metrics**: Real-time cluster connection counters, ingress/egress message rates, and throughput delta sparklines.
- **SQL Studio & Rule Tester**: Interactive query editor with batch evaluation (`POST /api/v1/rules/test`), function catalog browser (`GET /api/v1/rules/functions`), and Community/Enterprise tier badges.
- **Connectors Studio**: Visual registration forms for streaming, relational, analytical, object storage, and industrial sinks.
- **MQTT-over-WebSocket Test Console**: Integrated binary MQTT 3.1.1 test client connecting over `ws://localhost:18083/ws/mqtt` on the API port (test console only: no retained fetch/store, no rule execution, no offline queue, per `crates/broker-api/src/ws.rs`); production `ws`/`wss` clients use the edge listeners (`beam/src/indra_ws_listener.erl`, proven by `beam/test/indra_ws_tests.erl` and `beam/test/indra_wss_tests.erl`).
- **Auth & ACL Manager**: Runtime credential and topic access policy configuration.

### 5. Resilience & Bounded Scale Architecture
- **Core Restart Immunity (Erlang edge only, single-connection test)**: Decoupled BEAM edge holds the client socket in `await_core` and rebinds after a core restart without a disconnect, proven only for one loopback connection against a fake core by `core_restart_zero_disconnect_test` in `beam/test/indra_chaos_tests.erl` (500 ms recovery budget); not a multi-client production restart measurement. No end-to-end restart throughput or multi-client recovery rate is claimed.
- **Zero Hardcoded Limits, Finite Defaults**: Buffer depths (`window_channel_depth`, default 65536), offline session queues (`max_offline_queue`, default 50000), per-subscriber QoS 0 backlog (`max_qos0_backlog`, default 1000), batch sizes, and pool capacities are configurable with finite defaults (see `indramqtt.example.toml` and `crates/broker-config/src/schema.rs`); unbounded is only an explicit operator opt-in, never the default.
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
│   ├── broker-protocol/          # MQTT 3.1.1 protocol primitives
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

# 2. Run the complete automated test suite (no hardcoded count: the suite changes, so no total is claimed here)
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
   - **Free for commercial and production use**, including inside revenue-generating products and services. No subscription, license key or registration, now or later. The MIT and Apache-2.0 terms are the only conditions.
2. **Enterprise Edition (Commercial / Free Community Evaluation)**:
   - Governed by the **Indra Enterprise Commercial License** ([`LICENSE-ENTERPRISE`](LICENSE-ENTERPRISE)).
   - Covers distributed QUIC clustering (`crates/broker-cluster`) and any other components that the license explicitly designates.
   - Royalty-free for personal, development, testing, educational and internal evaluation use. A commercial subscription is required only to run **these components** in production, and does not affect anything in the Community Edition.

For commercial licensing, enterprise clustering support, and cloud subscriptions:
🌐 **Website**: [indramqtt.com](https://indramqtt.com) | ✉️ **Contact**: [sales@i-dacs.com](mailto:sales@i-dacs.com)
