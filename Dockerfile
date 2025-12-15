# NLAG Multi-stage Dockerfile
# Builds all three binaries: nlag (agent), nlag-edge, nlag-control

# ============ Build Stage ============
FROM rust:1.83-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy workspace files
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY clippy.toml rustfmt.toml ./

# Create crate directories
RUN mkdir -p crates/nlag-agent/src \
             crates/nlag-edge/src \
             crates/nlag-control/src \
             crates/nlag-common/src

# Copy Cargo.toml files
COPY crates/nlag-agent/Cargo.toml crates/nlag-agent/
COPY crates/nlag-edge/Cargo.toml crates/nlag-edge/
COPY crates/nlag-control/Cargo.toml crates/nlag-control/
COPY crates/nlag-common/Cargo.toml crates/nlag-common/

# Create dummy source files to cache dependencies
RUN echo "fn main() {}" > crates/nlag-agent/src/main.rs && \
    echo "fn main() {}" > crates/nlag-edge/src/main.rs && \
    echo "fn main() {}" > crates/nlag-control/src/main.rs && \
    echo "" > crates/nlag-common/src/lib.rs

# Build dependencies only (this layer is cached)
RUN cargo build --release 2>/dev/null || true

# Remove dummy sources
RUN rm -rf crates/*/src

# Copy actual source code
COPY crates/nlag-agent/src crates/nlag-agent/src
COPY crates/nlag-edge/src crates/nlag-edge/src
COPY crates/nlag-control/src crates/nlag-control/src
COPY crates/nlag-common/src crates/nlag-common/src

# Build all binaries
RUN cargo build --release

# ============ Edge Server Image ============
FROM debian:bookworm-slim AS edge

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/nlag-edge /usr/local/bin/nlag-edge

# Create config directory
RUN mkdir -p /etc/nlag

# Default configuration
ENV NLAG_EDGE__AGENT_LISTEN_ADDR=0.0.0.0:4443
ENV NLAG_EDGE__PUBLIC_LISTEN_ADDR=0.0.0.0:8080
ENV NLAG_EDGE__METRICS_LISTEN_ADDR=0.0.0.0:9090
ENV NLAG_EDGE__INSPECT_LISTEN_ADDR=0.0.0.0:4040

EXPOSE 4443/udp 8080 9090 4040

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:4040/health || exit 1

ENTRYPOINT ["nlag-edge"]
CMD ["--config", "/etc/nlag/edge.toml"]

# ============ Control Plane Image ============
FROM debian:bookworm-slim AS control

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/nlag-control /usr/local/bin/nlag-control

# Create config directory
RUN mkdir -p /etc/nlag /var/lib/nlag

ENV NLAG_CONTROL__LISTEN_ADDR=0.0.0.0:3000
ENV NLAG_CONTROL__DATABASE_PATH=/var/lib/nlag/nlag.db

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

ENTRYPOINT ["nlag-control"]
CMD ["--config", "/etc/nlag/control.toml"]

# ============ Agent Image ============
FROM debian:bookworm-slim AS agent

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/nlag /usr/local/bin/nlag

ENTRYPOINT ["nlag"]
