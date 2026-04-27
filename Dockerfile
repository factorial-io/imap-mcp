# Stage 1: Build
FROM rust:latest AS builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src/ src/

RUN cargo build --release && strip target/release/imap-mcp

# Stage 2: Runtime
FROM debian:bookworm-slim
LABEL org.opencontainers.image.source="https://github.com/factorial-io/imap-mcp"

RUN apt-get update && apt-get install -y ca-certificates libssl3 antiword && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home appuser

COPY --from=builder /app/target/release/imap-mcp /usr/local/bin/imap-mcp

USER appuser
EXPOSE 8080
ENV RUST_LOG=info
CMD ["imap-mcp"]
