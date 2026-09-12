# Multi-Stage Dockerfile for IndraMQTT
# Official Website: https://indramqtt.com

# -----------------------------------------------------------------------------
# Stage 1: Rust & Edge Builder
# -----------------------------------------------------------------------------
FROM rust:1.80-slim-bullseye AS builder

WORKDIR /usr/src/indramqtt

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace manifests
COPY Cargo.toml Cargo.lock ./
COPY proto ./proto
COPY crates ./crates

# Compile release binaries
RUN cargo build --release -p broker-node

# -----------------------------------------------------------------------------
# Stage 2: Production Minimal Runtime
# -----------------------------------------------------------------------------
FROM debian:bullseye-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root indra user
RUN groupadd -r indra && useradd -r -g indra -m -d /var/lib/indramqtt indra

WORKDIR /var/lib/indramqtt

# Copy binary from builder
COPY --from=builder /usr/src/indramqtt/target/release/broker-node /usr/local/bin/indramqtt

# Setup directories and permissions
RUN mkdir -p /etc/indramqtt /var/log/indramqtt /var/lib/indramqtt/data \
    && chown -R indra:indra /etc/indramqtt /var/log/indramqtt /var/lib/indramqtt

USER indra

# Expose MQTT, MQTTS, WS, and Dashboard / REST ports
EXPOSE 1883 8883 8083 18083

ENV RUST_LOG=info
ENV INDRA_API_BIND=0.0.0.0:18083

ENTRYPOINT ["/usr/local/bin/indramqtt"]
CMD ["--api-bind", "0.0.0.0:18083"]
