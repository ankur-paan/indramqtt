# IndraMQTT Architecture Specification

**IndraMQTT** ([indramqtt.com](https://indramqtt.com)) is a distributed, ultra-concurrent MQTT messaging and streaming platform designed for hyper-scale cloud deployments and mission-critical industrial edge systems.

This document details the internal design, concurrency models, data flows, and layer decoupling that enable IndraMQTT to achieve **>3M msg/sec** routing throughput, **<15 MB RSS** idle memory footprint, and **zero TCP disconnects** across kernel restarts.

---

## 1. High-Level Architecture Overview

IndraMQTT separates the networking edge from the broker kernel through a clean 3-tier decoupled model:

```mermaid
graph TB
    subgraph Clients[MQTT Edge Clients]
        TCP_CLI[MQTT Clients :1883]
        TLS_CLI[MQTTS Clients :8883]
        WS_CLI[WebSocket Clients :8083]
    end

    subgraph BEAM[Layer 1: BEAM Network Appliance - Erlang/OTP 26+]
        ACCEPTOR[Socket Acceptors & TLS Term]
        FRAMING[MQTT Framing & Packet Codec]
        KEEPALIVE[Keep-Alive Timers & Backpressure]
        STATE_MIRROR[Hot QoS Mirror]
        REBIND[Core Re-bind State Machine]
    end

    subgraph IPC[Layer 2: Multi-Lane BrokerLink IPC]
        UDS[Unix Domain Socket / Memory Stream]
        LANE_HASH[Consistent Hashing: conn_id % num_lanes]
        PROTO_FRAMING[Zero-Copy Binary Framing]
    end

    subgraph Core[Layer 3: Rust Core Engine - Community MIT / Apache-2.0]
        ROUTER[Radix Trie Router - ahash / Arc str]
        SESSION[Canonical Session Manager]
        STORAGE[Segmented Log & Cursor Persistence]
        AUTH[AuthN & ACL Rule Engine]
        QUOTA[Multi-Tenant Quotas & Rate Limiter]
        SQL[Embedded rekuiper Streaming SQL Engine]
        CONNECTORS[Unified Connectors: Kafka, PG, Redis, S3, ES, Webhook]
        REST[Axum REST API & Web Dashboard :18083]
    end

    subgraph Enterprise[Layer 4: Distributed Clustering - Enterprise LICENSE]
        QUIC[QUIC Multiplexed Data Plane]
        SWIM[SWIM Gossip Failure Detection]
        RAFT[Raft Metadata Consensus]
        WINDOWS[Stateful rekuiper Window Operators]
        INDUSTRIAL[Industrial Protocols: Sparkplug B, OPC-UA]
    end

    Clients --> BEAM
    BEAM --> IPC
    IPC --> Core
    Core --> Enterprise
```

---

## 2. Core Architectural Invariants

### 1. Connection != Session (Core Restart Immunity)
In legacy brokers (e.g., EMQX, HiveMQ, VerneMQ), a broker node restart or software upgrade tears down all client TCP sockets, triggering massive "reconnect storms" and thundering-herd issues on downstream authentication backends.

In IndraMQTT:
- The **BEAM Network Appliance** (Erlang/OTP) owns client sockets, TLS sessions, packet framing, and keepalives. It has no business logic, no distributed database, and no rule engine.
- The **Rust Core Engine** owns the canonical session, subscription state, inflight QoS tracking, offline queues, and rule engines.
- If the Rust core restarts or upgrades, the BEAM edge buffers uncommitted frames, maintains open client TCP/TLS sockets, and re-binds active sessions in **< 200 ms** upon core resumption. **Result: Zero client disconnects.**

```mermaid
sequenceDiagram
    autonumber
    participant Client as MQTT Client
    participant BEAM as BEAM Edge Appliance
    participant Rust as Rust Broker Kernel

    Client->>BEAM: TCP Handshake + TLS
    Client->>BEAM: CONNECT
    BEAM->>Rust: BrokerLink::Connect(client_id, clean_start)
    Rust-->>BEAM: BrokerLink::ConnAck(SessionPresent=false, RC=0)
    BEAM-->>Client: CONNACK (200 OK)

    Note over Rust: Kernel Upgrade / Restart Initiated
    Rust->>Rust: Process Exits
    Note over BEAM: Sockets held open; edge enters await_core state
    Client->>BEAM: PUBLISH (QoS 1)
    BEAM->>BEAM: Buffer frame in edge ring buffer

    Note over Rust: Rust Kernel Resumed (<200 ms)
    BEAM->>Rust: BrokerLink::RebindAllSessions()
    Rust-->>BEAM: BrokerLink::RebindAck()
    BEAM->>Rust: Flush buffered PUBLISH frames
    Rust-->>BEAM: BrokerLink::PubAck
    BEAM-->>Client: PUBACK
```

---

### 2. Multi-Lane BrokerLink IPC
Communication between the BEAM edge and Rust core occurs over **BrokerLink**, a custom high-performance binary protocol:
* **Multi-Lane Affinity**: Erlang hashes connection IDs across $N$ parallel IPC lanes (`conn_id % num_lanes`). This guarantees strict per-client FIFO message ordering while completely eliminating cross-client head-of-line blocking.
* **Opaque Payloads**: Payloads remain zero-copy opaque byte buffers until evaluated by the rules engine.
* **Credit-Based Flow Control**: Prevents memory exhaustion during massive ingress spikes.

---

### 3. Lock-Free Radix Trie Subscription Router
The subscription router in `crates/broker-router` is optimized for zero memory allocations on hit paths:
* **Segment Tokens**: Subscription filters (`device/+/temperature`, `sensors/#`, `$share/group1/data`) are parsed into token slices stored with zero-allocation `Arc<str>` and fast hashing (`ahash`).
* **Fast-Miss Traversal**: Walk-only branch evaluation sustains **7.80M msg/sec** on fast-miss lookups.
* **Hit-Path Saturation**: Evaluates exact and wildcard subscriptions at **3.05M msg/sec** under 1,000 active concurrent topic filters.

---

### 4. Embedded Streaming SQL Engine (`rekuiper`)
IndraMQTT embeds the [`rekuiper-sql`](https://github.com/ankur-paan/rekuiper) stream processing engine directly in-process:

```mermaid
graph LR
    MQTT_PUB[MQTT Ingress Publish] --> EVAL{Rule Engine}
    EVAL -->|Stateless Rule| HOTPATH[Inline Evaluator - 4.77M events/sec]
    EVAL -->|Stateful Window| WORKER[Background WindowWorker Tokio Task]
    
    HOTPATH --> DISPATCH[Action Dispatcher]
    WORKER -->|Interval / Count Flush| DISPATCH

    DISPATCH --> REPUBLISH[In-Memory Topic Republish]
    DISPATCH --> CONNECTORS[Outbound Sinks: Kafka, S3, ES, Webhook, DB]
```

* **Stateless Rules (Community Tier)**:
  - 185 scalar functions (trigonometry, math, bitwise, string, datetime, conditionals).
  - Evaluated inline on the ingress thread with zero task spawns and zero network loopback at **>4.77M events/sec**.
* **Stateful Window Operators (Enterprise Tier)**:
  - `TUMBLINGWINDOW`, `HOPPINGWINDOW`, `SLIDINGWINDOW`, `COUNTWINDOW`.
  - Dedicated background Tokio worker tasks with interval bounds injection (`window_start()`, `window_end()`).
  - Multi-event aggregations (`avg`, `sum`, `count`, `min`, `max`, `stddev`, `percentile`).
* **Declarative SQL Routing**:
  - Supports SQL `INTO connector("id")` syntax:
    ```sql
    SELECT clientid, temperature * 1.8 + 32 AS temp_f 
    FROM "factory/+/sensors" 
    WHERE temperature > 40.0 
    INTO connector("kafka-edge")
    ```

---

### 5. Outbound Connectors & Streaming Bridges
Outbound integrations implement the unified `Sink` trait in `crates/broker-connectors`:
```rust
#[async_trait]
pub trait Sink: Send + Sync {
    async fn send(&self, topic: &Topic, payload: &Bytes, qos: QoS) -> Result<(), ConnectorError>;
    fn kind(&self) -> &'static str;
}
```

* **Micro-Batching & Backoff**: Standardized using shared `BatchQueue` and `BackoffState` helpers.
* **Zero External Dependencies in Tests**: All unit and integration tests execute against in-memory mock transports (`MemoryKafkaTransport`, `MockS3Transport`, `MockHttpTransport`, `MemoryDiskLogWriter`, etc.).

---

### 6. Zero-Limit Scale Architecture
IndraMQTT does not contain hardcoded or clamped limits:
* `window_channel_depth`: Fully configurable on `RuleEngine` (default 65,536, unbounded capable).
* `max_offline_queue`: Fully configurable on `SessionManager` (default 10,000, `None` = unbounded).
* Connection pools, batch limits, and rotation thresholds are unconstrained.

For full benchmarks and deployment configurations, visit [indramqtt.com](https://indramqtt.com).
