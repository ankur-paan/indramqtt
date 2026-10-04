# IndraMQTT image for one node.
#
# The image contains the Rust kernel, the `indra` operator CLI and the
# Erlang edge. The edge holds the MQTT, TLS and WebSocket sockets.
#
# Build from the repository root:
#   docker build -t indramqtt/indramqtt:0.1.0 .
#
# Size target: less than 250 MB uncompressed. The runtime stage contains
# the two binaries, the compiled edge and a minimum Erlang runtime. It
# does not contain a compiler, documents or build tools.

# -----------------------------------------------------------------------------
# Stage 1: kernel and operator CLI
# -----------------------------------------------------------------------------
FROM rust:1.98-slim-bookworm AS kernel

WORKDIR /usr/src/indramqtt

# Build inputs: the OpenSSL headers, and cmake and perl. Some drivers
# compile C libraries that need cmake and perl.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    libssl-dev \
    perl \
    pkg-config \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# The workspace manifest refers to targets in tests/. Cargo cannot read
# the manifest if that directory is absent.
COPY Cargo.toml Cargo.lock ./
COPY proto ./proto
COPY crates ./crates
COPY tests ./tests

# The image contains all connector kinds.
RUN cargo build --release --locked -p broker-node --features full --bin indramqtt --bin indra

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

# The Erlang applications that the edge uses. The TLS listeners need
# `ssl` and the applications that `ssl` uses. The health check uses curl.
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

# The broker runs as a user that is not root. The data directory is the
# only path that the broker writes.
RUN groupadd -r indra && useradd -r -g indra -m -d /var/lib/indramqtt indra \
    && mkdir -p /etc/indramqtt /var/lib/indramqtt/data \
    && chown -R indra:indra /etc/indramqtt /var/lib/indramqtt

COPY --from=kernel /usr/src/indramqtt/target/release/indramqtt /usr/local/bin/indramqtt
COPY --from=kernel /usr/src/indramqtt/target/release/indra /usr/local/bin/indra
COPY --from=edge /usr/src/edge/ebin /usr/lib/indramqtt/edge/ebin
COPY deploy/docker/entrypoint.sh /usr/local/bin/indramqtt-start
RUN chmod 0755 /usr/local/bin/indramqtt-start

# The indra.toml of the image. It makes the management API available
# through a published port, and it puts the state on the volume. If you
# mount your own indra.toml at this path, your file replaces this file.
# The compose and Helm examples do that.
COPY deploy/docker/indra.toml /etc/indramqtt/indra.toml

USER indra
WORKDIR /var/lib/indramqtt

# MQTT, MQTT with TLS, WebSocket, secure WebSocket, management API.
EXPOSE 1883 8883 8083 8084 18083

VOLUME ["/var/lib/indramqtt"]

HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -fsS http://127.0.0.1:18083/healthz || exit 1

# The configuration comes from /etc/indramqtt/indra.toml, the conf.d
# fragments and the INDRA_* variables. The start script gives the
# container arguments to the kernel as flags. A flag overrides all of them.
ENTRYPOINT ["/usr/local/bin/indramqtt-start"]
