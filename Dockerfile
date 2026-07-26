# syntax=docker/dockerfile:1

# --- Build stage ------------------------------------------------------
FROM rust:1-bookworm AS builder
WORKDIR /build

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

# --- Runtime stage ------------------------------------------------------
# distroless debug variant: keeps a busybox shell for interactive
# debugging while remaining minimal compared to a full distro image.
FROM gcr.io/distroless/cc-debian12:debug

COPY --from=builder /build/target/release/xhttp /usr/local/bin/xhttp

ENTRYPOINT ["/usr/local/bin/xhttp"]
