# Multi-stage build for optimal image size
FROM rust:latest as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
  pkg-config \
  libssl-dev \
  && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src

# Build for release
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
  ca-certificates \
  libssl3 \
  && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd --create-home --shell /bin/bash app

# Copy the binary from builder stage
COPY --from=builder /app/target/release/rtce2ee-whisper /usr/local/bin/

# Change ownership of the binary
RUN chown app:app /usr/local/bin/rtce2ee-whisper

# Switch to app user
USER app

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

# Set default environment variables
ENV RUST_LOG=info
ENV PORT=8080

# Run the binary
CMD ["rtce2ee-whisper"]
