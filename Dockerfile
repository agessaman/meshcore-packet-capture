# Use Python 3.11 slim image for smaller size
FROM python:3.11-slim AS base

# Install system dependencies for BLE, serial communication
# Use --no-install-recommends to minimize package size
RUN apt-get update && apt-get install -y --no-install-recommends \
    bluez \
    libbluetooth-dev \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Set working directory
WORKDIR /app

# Create non-root user for security (do this early to avoid permission issues)
RUN useradd -m -u 1000 meshcore

# Install Node.js via nvm and meshcore-decoder for auth token support
ENV NVM_DIR=/opt/nvm
ENV NODE_VERSION=lts/*

RUN mkdir -p "$NVM_DIR" && \
    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash \
    && . "$NVM_DIR/nvm.sh" \
    && nvm install $NODE_VERSION \
    && nvm use $NODE_VERSION \
    && npm install -g @michaelhart/meshcore-decoder \
    && ln -s "$NVM_DIR/versions/node/$(ls $NVM_DIR/versions/node | head -1)/bin/"* /usr/local/bin/

# Application package and TOML defaults (env vars still override at runtime)
COPY --chown=meshcore:meshcore pyproject.toml README.md ./
COPY --chown=meshcore:meshcore src ./src
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir . \
    && pip cache purge
RUN mkdir -p /etc/meshcore-packet-capture/config.d
COPY --chown=root:root config.toml.example /etc/meshcore-packet-capture/config.toml
COPY presets/letsmesh.toml /etc/meshcore-packet-capture/config.d/10-letsmesh.toml

# Create data directory for output files
RUN mkdir -p /app/data && chown -R meshcore:meshcore /app

# Switch to non-root user
USER meshcore

# Set default environment variables
# Note: These are defaults - override in docker-compose.yml or .env.local
ENV PACKETCAPTURE_CONNECTION_TYPE=serial \
    PACKETCAPTURE_DATA_DIR=/app/data \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import meshcore; print('OK')" || exit 1

# Default command
CMD ["python", "-m", "meshcore_packet_capture"]
