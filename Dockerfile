# Build stage
FROM rust:1.79-slim as builder

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Create dummy source to cache dependencies
RUN mkdir -p src && echo "fn main() {}" > src/main.rs
RUN cargo build --release --all-features 2>/dev/null || true

# Copy actual source
COPY src ./src

# Build application
RUN cargo build --release --all-features

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/false -u 1000 rw_secstore

# Copy binary
COPY --from=builder /app/target/release/rw_secstore /usr/local/bin/rw_secstore

# Create config directory
RUN mkdir -p /etc/rw_secstore /var/lib/rw_secstore /var/log/rw_secstore \
    && chown -R rw_secstore:rw_secstore /etc/rw_secstore /var/lib/rw_secstore /var/log/rw_secstore

# Copy default config
COPY config.example.toml /etc/rw_secstore/config.toml

USER rw_secstore

EXPOSE 8443

VOLUME ["/var/lib/rw_secstore", "/var/log/rw_secstore"]

ENTRYPOINT ["rw_secstore"]
CMD ["serve"]