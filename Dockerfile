# Multi-stage Dockerfile for OpenPorts
# Builds on ARM64 (Raspberry Pi) and AMD64

# Stage 1: Builder
FROM python:3.13-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY setup.py .
COPY openports/ ./openports/
RUN pip install --no-cache-dir -e ".[full]"

# Stage 2: Runtime
FROM python:3.13-slim as runtime

WORKDIR /app

# Install runtime dependency for lsof fallback
RUN apt-get update && apt-get install -y --no-install-recommends \
    lsof \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Copy installed package from builder
COPY --from=builder /usr/local/lib/python3.13/site-packages/ /usr/local/lib/python3.13/site-packages/
COPY --from=builder /usr/local/bin/openports /usr/local/bin/
COPY --from=builder /usr/local/bin/list-ports /usr/local/bin/

# Non-root user for security
RUN useradd -m -u 1000 openports && chown -R openports:openports /app
USER openports

ENTRYPOINT ["openports"]
CMD []
