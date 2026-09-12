# Contributing to IndraMQTT

Thank you for your interest in contributing to **IndraMQTT** ([indramqtt.com](https://indramqtt.com))!

IndraMQTT is a dual-licensed, ultra-high-performance distributed MQTT broker and stream processing engine. We welcome contributions from the community—whether fixing a bug, adding a new connector, optimizing throughput, or improving documentation.

---

## 1. Engineering Principles & Ground Rules

All contributions must adhere to our core architectural invariants:

### Rule 1: Zero External Daemons in Automated Tests
All automated tests must run clean-room in-process using mock transports (`MemoryKafkaTransport`, `MemoryPgTransport`, `MockS3Transport`, `MockHttpTransport`, etc.). **Never introduce external Docker or database daemon requirements into the test suites.**

### Rule 2: Zero Hardcoded Limits
IndraMQTT is engineered for arbitrary scale. Never clamp, cap, or hardcode scale parameters (buffer queues, channel depths, batch sizes, retry counts, pool limits). Every capacity or timeout limit must be exposed as a configurable option, defaulting to sensible values with `None` or unbounded options.

### Rule 3: Surgical Changes & Code Simplicity
Touch only what you must. Match existing codebase style. Avoid speculative abstractions, unnecessary generic indirection, or dead code. Every changed line should trace directly to a concrete requirement.

### Rule 4: Open-Core Tier Boundaries
- **Community Edition**: Core MQTT broker, BEAM network edge, BrokerLink IPC, storage engine, embedded stateless SQL rules, community connectors (HTTP, PostgreSQL, MySQL, Redis, S3, ClickHouse, InfluxDB, TimescaleDB, RabbitMQ, Disk Log, Remote MQTT Bridge).
- **Enterprise Edition**: Distributed clustering (`crates/broker-cluster`), stateful stream window operators (`TUMBLINGWINDOW`, `HOPPINGWINDOW`, `SLIDINGWINDOW`, `COUNTWINDOW`), industrial protocols (Sparkplug B, OPC-UA), and hyperscaler cloud bridges.

---

## 2. Development Environment Setup

### Prerequisites
* **Rust**: `1.80+` ([rustup.rs](https://rustup.rs/))
* **Erlang/OTP**: `26+` ([erlang.org](https://www.erlang.org/))
* **Rebar3**: `3.22+` ([rebar3.org](https://www.rebar3.org/))

### Cloning & Building
```bash
git clone https://github.com/ankur-paan/indramqtt.git
cd indramqtt

# Build the Rust broker workspace
cargo build --workspace

# Run all Rust unit and integration tests
cargo test --workspace

# Check for compiler warnings and clippy lints
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings

# Build and test the Erlang BEAM edge
cd beam
rebar3 compile
rebar3 eunit
cd ..
```

---

## 3. Pull Request Guidelines

1. **Create a branch**: Use descriptive branch names (e.g. `feat/pulsar-sink` or `fix/session-expiry`).
2. **Follow Conventional Commits**:
   - `feat(streaming): add Apache Pulsar producer sink`
   - `fix(router): resolve wildcard match corner case`
   - `perf(trie): reduce allocation on topic filter deletion`
   - `docs(readme): update deployment quickstart`
3. **Ensure Zero Warnings & 100% Tests Green**:
   - `cargo check --workspace --all-targets` must report 0 warnings.
   - `cargo clippy --workspace --all-targets` must be clean.
   - All automated tests must pass.
4. **Clean Build Cache**: Run `cargo clean` locally before submitting large PRs to verify disk hygiene.

---

## 4. Code of Conduct
Please review and adhere to our [Code of Conduct](CODE_OF_CONDUCT.md).

For questions and RFC discussions, join [GitHub Discussions](https://github.com/ankur-paan/indramqtt/discussions) or reach out via [indramqtt.com](https://indramqtt.com).
