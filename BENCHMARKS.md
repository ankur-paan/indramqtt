# IndraMQTT Benchmark Methodology & Literature Bibliography

This document provides the full empirical methodology, test harness specifications, academic literature citations, and step-by-step reproducibility instructions for all performance metrics reported by **IndraMQTT** ([indramqtt.com](https://indramqtt.com)).

---

## 1. Authoritative External Data Sources & Baselines

All baseline comparison metrics for competitor brokers reported in the project documentation are grounded in official documentation, vendor benchmark specifications, and peer-reviewed empirical studies:

- <a id="ref-emqx"></a>**[1] EMQX Official Performance Reference**: [EMQX v5.1.6 Performance Reference](https://docs.emqx.com/en/emqx/latest/performance/performance-reference.html) and [eMQTT-Bench Tool](https://github.com/emqx/emqtt-bench). Documents single-node 4-vCPU (Intel Xeon Platinum 8378A @ 3.0GHz, 8 GiB RAM) sustained throughput of 40,000 – 60,000 TPS at 75% CPU load for QoS 0/1 symmetric workloads, 50,000 TPS fan-out, and base memory usage of 500+ MB before client ingress.
- <a id="ref-abb"></a>**[2] ABB Corporate Research / ECSA 2020 Comparative Study**: Heiko Koziolek, Sten Grüner, Julius Rückert. *"A Comparison of MQTT Brokers for Distributed IoT Edge Computing"*, European Conference on Software Architecture ([Preprint PDF](http://www.koziolek.de/docs/Koziolek2020-ECSA-preprint.pdf), [DOI: 10.1007/978-3-030-58923-3_25](https://doi.org/10.1007/978-3-030-58923-3_25)). Experiment data, Kubernetes manifests, and MZBench BDL scripts are published at [hkoziolek/ECSA2020-experiment-data](https://github.com/hkoziolek/ECSA2020-experiment-data). The study directly benchmarks EMQX, VerneMQ, and HiveMQ on identical bare-metal edge cluster hardware, measuring multi-core saturation plateaus (500k–800k msg/sec on 16-thread hardware under subscriber fanout) and memory growth.
- <a id="ref-arxiv"></a>**[3] Academic Multi-Broker Benchmark / arXiv**: Jasenka Dizdarevic, Marc Michalke, Admela Jukan. *"Engineering and Experimentally Benchmarking Open Source MQTT Broker Implementations"* ([arXiv:2305.13893](https://arxiv.org/abs/2305.13893), [DOI: 10.48550/arXiv.2305.13893](https://doi.org/10.48550/arXiv.2305.13893)). Evaluates Mosquitto, EMQX, RabbitMQ, VerneMQ, and HiveMQ on AMD64 and ARM64 platforms under varying payload sizes and network conditions.
- <a id="ref-hivemq"></a>**[4] HiveMQ Platform & Memory Architecture**: [HiveMQ Community Edition](https://github.com/hivemq/hivemq-community-edition) and [HiveMQ Platform](https://www.hivemq.com/). Enterprise Java deployment guidelines require minimum `-Xms512m` to `-Xms1g` initial heap allocation, yielding 500 MB – 1.2 GB base RSS footprint to avoid high-frequency garbage collection pauses during message bursts.
- <a id="ref-vernemq"></a>**[5] VerneMQ Documentation & Runtime Baselines**: [VerneMQ Documentation](https://docs.vernemq.com/) and [VerneMQ MZBench Test Harness](https://github.com/vernemq/vmq_mzbench). Documents the Erlang BEAM memory footprint (200–400 MB baseline RSS per node with Mnesia/clustering metadata initialized prior to client connection ingress) and routing table lookup characteristics.
- <a id="ref-mosquitto"></a>**[6] Eclipse Mosquitto**: [Eclipse Mosquitto Documentation](https://mosquitto.org/). Demonstrates low memory overhead (~5–10 MB) as a single-threaded C broker, but lacks native clustering and multi-core parallel routing.
- <a id="ref-tools"></a>**[7] Standard Benchmark Harnesses**: Synthetic workload generation verified using [krylovsk/mqtt-benchmark](https://github.com/krylovsk/mqtt-benchmark) and [inovex/mqtt-stresser](https://github.com/inovex/mqtt-stresser).

---

## 2. Benchmark Methodology & Test Harness

All benchmarks are grounded in [`crates/broker-node/benches/broker_throughput.rs`](crates/broker-node/benches/broker_throughput.rs) and executed on standard x86_64 hardware:

### 1. Router Matching (`bench_router_match_throughput`)
- **Topology**: Production-shaped routing table with **1,000 installed topic filters** (`device/{1000..2000}/state`) plus overlapping wildcard filters (`device/7/+`, `device/#`) and exact match (`device/7/state`).
- **Evaluation**: Each publication to `device/7/state` traverses the Radix Trie, matches 3 separate subscriber targets across exact and wildcard segments, and constructs a cloned subscriber destination set using zero-allocation `Arc<str>` keys and `ahash`.
- **Measurement**: 200,000 iterations post-warmup using `std::hint::black_box` to prevent compiler dead-code elimination.
- **Results**:
  - **3.05M msg/sec** hit-path throughput.
  - **7.80M msg/sec** fast-miss traversal.

### 2. Streaming SQL Ingress (`bench_sql_ingress_throughput`)
- **Query**: Embedded [`rekuiper-sql`](https://github.com/ankur-paan/rekuiper) rule:
  ```sql
  SELECT temperature, humidity FROM "sensors/+" WHERE temperature > 40.0
  ```
- **Workload**: Ingests JSON payloads (`{ "temperature": 72.5, "humidity": 40.0, "sensor_id": "t1" }`), evaluates the streaming expression filter in-process, projects the selected fields in deterministic key order, and dispatches directly to the broker sink without touching network loopback.
- **Measurement**: 20,000 iterations post-warmup on a single-threaded Tokio runtime.
- **Result**: **4.77M events/sec** ingress evaluation throughput.

---

## 3. Reproducing the Benchmarks Locally

To reproduce and verify these performance gates locally on your own hardware:

```bash
# Run release throughput benchmarks with stdout reporting
cargo test --release --bench broker_throughput -- --nocapture
```

Sample benchmark output:
```text
running 2 tests
router match throughput [hit]: 3051428 msg/sec (600000 total hits)
router match throughput [miss]: 7812500 msg/sec
test bench_router_match_throughput ... ok
SQL ingress throughput: 4768310 events/sec
test bench_sql_ingress_throughput ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

For more benchmarks and multi-node scaling reports, visit [indramqtt.com](https://indramqtt.com).
