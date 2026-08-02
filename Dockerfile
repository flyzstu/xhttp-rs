# syntax=docker/dockerfile:1

# --- Build stage ------------------------------------------------------
FROM rust:1-bookworm AS builder
WORKDIR /build

# boring-sys builds its bundled BoringSSL tree with CMake and generates
# bindings through libclang.
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake libclang-dev \
    && rm -rf /var/lib/apt/lists/*

# Cache dependency compilation separately from source changes.
COPY Cargo.toml Cargo.lock ./
COPY .cargo ./.cargo
RUN mkdir -p src benches \
    && echo "fn main() {}" > src/main.rs \
    && echo "" > src/lib.rs \
    && echo "fn main() {}" > benches/dns.rs \
    && cargo build --release --bin xhttp \
    && rm -rf src benches

COPY src ./src
COPY benches ./benches
RUN touch src/main.rs src/lib.rs \
    && cargo build --release --bin xhttp

# --- Runtime stage ----------------------------------------------------
# The Linux TUN control plane invokes iproute2, nftables and iptables.
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        iproute2 \
        iptables \
        nftables \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/xhttp /usr/local/bin/xhttp

ENTRYPOINT ["/usr/local/bin/xhttp"]
