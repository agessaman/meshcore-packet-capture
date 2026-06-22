# Use Python 3.11 slim image for smaller size
FROM python:3.11-slim AS base

# Install system dependencies for BLE, serial communication
# Use --no-install-recommends to minimize package size
RUN apt-get update && apt-get install -y --no-install-recommends \
    bluez \
    libbluetooth-dev \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Set working directory
WORKDIR /app

# Create non-root user for security (do this early to avoid permission issues)
RUN useradd -m -u 1000 meshcore

# JWT auth tokens are signed in pure Python via pynacl (a declared dependency),
# matching the native installer. The legacy Node.js meshcore-decoder fallback
# (AUTH_TOKEN_METHOD=meshcore-decoder) is intentionally not bundled in the image.

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
# Note: These are defaults - override via the mounted /etc/meshcore-packet-capture
# config (config.d/*.toml), docker-compose.yml env, or a legacy .env.local bind-mount.
ENV PACKETCAPTURE_CONNECTION_TYPE=serial \
    PACKETCAPTURE_DATA_DIR=/app/data \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import meshcore; print('OK')" || exit 1

# Default command
CMD ["python", "-m", "meshcore_packet_capture"]
