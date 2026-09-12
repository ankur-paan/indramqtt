# IndraMQTT Benchmark Methodology & Literature Bibliography

This document provides the full empirical methodology, test harness specifications, literature citations, and step-by-step reproducibility instructions for all performance metrics reported by **IndraMQTT** ([indramqtt.com](https://indramqtt.com)).

---

## 1. Important Scope Distinction: Microbenchmarks vs. Network Services

> [!IMPORTANT]
> **Methodology Clarification**:
> The internal benchmarks currently implemented in [`crates/broker-node/benches/broker_throughput.rs`](crates/broker-node/benches/broker_throughput.rs) are **in-process function-level microbenchmarks**. They measure the algorithmic efficiency of:
> 1. Radix Trie topic filter matching in memory (`Router::matches`).
> 2. Streaming SQL expression evaluation and projection in memory (`RuleEngine::dispatch_ingress`).
>
> They do **not** measure full network stack delivery (TCP/TLS socket I/O, packet serialization, kernel syscalls, or client fan-out). The competitor figures cited in Section 3 are end-to-end network service measurements. They are provided as reference baselines and architectural targets for the upcoming end-to-end test harness (Section 4).

---

## 2. Internal Microbenchmark Methodology & Results

All microbenchmarks run via `cargo test --release --bench broker_throughput -- --nocapture` using compiler dead-code elimination guards (`std::hint::black_box`) and multi-sample variance reporting:

### 1. Router Matching (`bench_router_match_throughput`)
- **What It Measures**: Single-threaded in-process Radix Trie lookup (`router.matches(topic)`).
- **Topology**: Production-shaped routing table with **1,000 installed topic filters** (`device/{1000..2000}/state`) plus overlapping wildcard filters (`device/7/+`, `device/#`) and exact match (`device/7/state`).
- **Sampling & Methodology**:
  - 10,000 warmup iterations to prime branch predictors and cache lines.
  - 5 independent measurement passes of 50,000 lookups each.
  - Computes sample mean ($\mu$) and standard deviation ($\sigma$).
- **Measured Results**:
  - **Hit-Path Lookups**: **~3.05M ± 0.10M lookups/sec** (evaluating 3 matched subscriber targets per publication using zero-allocation `Arc<str>` tokens and `ahash`).
  - **Fast-Miss Traversal**: **~7.80M ± 0.20M lookups/sec** (walk-only branch traversal when topic prefix has no matching subscribers).

### 2. Streaming SQL Ingress Evaluation (`bench_sql_ingress_throughput`)
- **What It Measures**: Single-threaded in-memory JSON payload parsing, SQL `WHERE` expression filtering, `SELECT` field projection, and delivery to the broker sink.
- **Rule Evaluated**:
  ```sql
  SELECT temperature, humidity FROM "sensors/+" WHERE temperature > 40.0
  ```
- **Sampling & Sink Delivery Assertion**:
  - 2,000 warmup iterations.
  - Counter reset to zero to guarantee zero uncounted warmup events.
  - 5 measurement passes across 20,000 total iterations under `BackpressurePolicy::Block`.
  - **Crucial Assertion**: Asserts `sink.count == 20,000` to verify that **100% of evaluated events were received by the sink**, guaranteeing the measured rate is not an artifact of queue dropping.
- **Measured Results**:
  - **Throughput**: **~4.77M ± 0.10M events/sec**.

---

## 3. Competitor Reference Baselines & Literature Citations

The following baselines represent published end-to-end network performance figures for existing enterprise MQTT brokers, provided as context and architectural targets:

- <a id="ref-emqx"></a>**[1] EMQX Official Performance Reference**: [EMQX v5.1.6 Performance Reference](https://docs.emqx.com/en/emqx/latest/performance/performance-reference.html) and [eMQTT-Bench Tool](https://github.com/emqx/emqtt-bench). Documents single-node 4-vCPU (Intel Xeon Platinum 8378A @ 3.0GHz, 8 GiB RAM) sustained throughput of 40,000 – 60,000 TPS at 75% CPU load for QoS 0/1 symmetric workloads, 50,000 TPS fan-out, and base memory usage of 500+ MB before client ingress.
- <a id="ref-abb"></a>**[2] ABB Corporate Research / ECSA 2020 Comparative Study**: Heiko Koziolek, Sten Grüner, Julius Rückert. *"A Comparison of MQTT Brokers for Distributed IoT Edge Computing"*, European Conference on Software Architecture ([Preprint PDF](http://www.koziolek.de/docs/Koziolek2020-ECSA-preprint.pdf), [DOI: 10.1007/978-3-030-58923-3_25](https://doi.org/10.1007/978-3-030-58923-3_25)). Experiment data, Kubernetes manifests, and MZBench BDL scripts are published at [hkoziolek/ECSA2020-experiment-data](https://github.com/hkoziolek/ECSA2020-experiment-data). The study benchmarks EMQX, VerneMQ, and HiveMQ on identical bare-metal edge cluster hardware, measuring multi-core saturation plateaus (500k–800k msg/sec on 16-thread hardware under subscriber fanout) and memory growth.
- <a id="ref-arxiv"></a>**[3] Academic Multi-Broker Benchmark / arXiv**: Jasenka Dizdarevic, Marc Michalke, Admela Jukan. *"Engineering and Experimentally Benchmarking Open Source MQTT Broker Implementations"* ([arXiv:2305.13893](https://arxiv.org/abs/2305.13893), [DOI: 10.48550/arXiv.2305.13893](https://doi.org/10.48550/arXiv.2305.13893)). Evaluates Mosquitto, EMQX, RabbitMQ, VerneMQ, and HiveMQ on AMD64 and ARM64 platforms under varying payload sizes and network conditions.
- <a id="ref-hivemq"></a>**[4] HiveMQ Platform & Memory Architecture**: [HiveMQ Community Edition](https://github.com/hivemq/hivemq-community-edition) and [HiveMQ Platform](https://www.hivemq.com/). Enterprise Java deployment guidelines require minimum `-Xms512m` to `-Xms1g` initial heap allocation, yielding 500 MB – 1.2 GB base RSS footprint to avoid garbage collection pauses.
- <a id="ref-vernemq"></a>**[5] VerneMQ Documentation & Runtime Baselines**: [VerneMQ Documentation](https://docs.vernemq.com/) and [VerneMQ MZBench Test Harness](https://github.com/vernemq/vmq_mzbench). Documents the Erlang BEAM memory footprint (200–400 MB baseline RSS per node with Mnesia/clustering metadata initialized).
- <a id="ref-mosquitto"></a>**[6] Eclipse Mosquitto**: [Eclipse Mosquitto Documentation](https://mosquitto.org/). Demonstrates low memory overhead (~5–10 MB) as a single-threaded C broker, but lacks native clustering.

---

## 4. Roadmap: End-to-End Network Benchmark Suite

To complement our function-level microbenchmarks with rigorous, defensible end-to-end network figures, we are building an automated end-to-end benchmark harness using `mqtt-benchmark` and `eMQTT-bench`:

* **Target Workload**:
  - Full TCP socket listener (`:1883`) backed by BEAM network edge.
  - Multi-lane BrokerLink binary IPC transport to Rust core.
  - Real MQTT v3.1.1 and v5.0 packet parsing, QoS 0 and QoS 1 framing, and network socket fan-out.
* **Realistic Target Baseline**: **~80k – 150k msg/sec** on single-core network loopback.
* **Hardware Standardization**: Benchmarks will report exact CPU model, core/thread count, memory, OS kernel version, and network configuration.

---

## 5. Reproducing Microbenchmarks Locally

```bash
# Run release throughput benchmarks with stdout reporting
cargo test --release --bench broker_throughput -- --nocapture
```
