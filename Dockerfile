# IndraMQTT single-node image: the Rust kernel, the `indra` operator CLI
# and the Erlang edge that holds the MQTT, TLS and WebSocket sockets.
#
# Build from the repository root:   docker build -t indramqtt/indramqtt:0.1.0 .
# Size target: under 250 MB uncompressed. The runtime stage carries the
# two binaries, the compiled edge and a minimal Erlang runtime (no
# compiler, no docs, no build tools).

# -----------------------------------------------------------------------------
# Stage 1: kernel and operator CLI
# -----------------------------------------------------------------------------
FROM rust:1.98-slim-bookworm AS kernel

WORKDIR /usr/src/indramqtt

# Native build inputs: OpenSSL headers, and cmake plus perl for the
# bundled C libraries some drivers compile (Kafka, TLS, client-side
# field encryption).
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    libssl-dev \
    perl \
    pkg-config \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# The workspace manifest names test and bench targets under tests/, so
# cargo needs that directory present to load the manifest.
COPY Cargo.toml Cargo.lock ./
COPY proto ./proto
COPY crates ./crates
COPY tests ./tests

RUN cargo build --release --locked -p broker-node --bin indramqtt --bin indra

# -----------------------------------------------------------------------------
# Stage 2: edge
# -----------------------------------------------------------------------------
FROM erlang:25-slim AS edge

WORKDIR /usr/src/edge
COPY beam/src ./src
RUN mkdir ebin \
    && erlc -o ebin src/*.erl \
    && cp src/indra_edge.app.src ebin/indra_edge.app

# -----------------------------------------------------------------------------
# Stage 3: runtime
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# Erlang runtime applications the edge uses (TLS listeners need ssl and
# its dependencies), plus curl for the health check.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    erlang-base \
    erlang-crypto \
    erlang-public-key \
    erlang-asn1 \
    erlang-ssl \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Non-root user. The data directory is the image's one mutable path.
RUN groupadd -r indra && useradd -r -g indra -m -d /var/lib/indramqtt indra \
    && mkdir -p /etc/indramqtt /var/lib/indramqtt/data \
    && chown -R indra:indra /etc/indramqtt /var/lib/indramqtt

COPY --from=kernel /usr/src/indramqtt/target/release/indramqtt /usr/local/bin/indramqtt
COPY --from=kernel /usr/src/indramqtt/target/release/indra /usr/local/bin/indra
COPY --from=edge /usr/src/edge/ebin /usr/lib/indramqtt/edge/ebin
COPY deploy/docker/entrypoint.sh /usr/local/bin/indramqtt-start
RUN chmod 0755 /usr/local/bin/indramqtt-start

# The image's own indra.toml: inside a container the management API has
# to listen beyond loopback to be reachable through a published port,
# and state belongs on the volume. Mounting your own indra.toml over this
# file replaces it whole (the compose and Helm examples do).
COPY deploy/docker/indra.toml /etc/indramqtt/indra.toml

USER indra
WORKDIR /var/lib/indramqtt

# MQTT, MQTT over TLS, WebSocket, secure WebSocket, management API.
EXPOSE 1883 8883 8083 8084 18083

VOLUME ["/var/lib/indramqtt"]

HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -fsS http://127.0.0.1:18083/healthz || exit 1

# Configuration comes from /etc/indramqtt/indra.toml, conf.d fragments
# beside it and INDRA_* variables. Arguments given to the container are
# passed to the kernel as flags and win over all of them.
ENTRYPOINT ["/usr/local/bin/indramqtt-start"]
