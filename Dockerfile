# Use Python 3.11 slim image for smaller size
FROM python:3.11-slim as base

# Install system dependencies for BLE and serial communication
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

# Copy requirements first for better Docker layer caching
COPY requirements.txt .

# Install Python dependencies with optimizations
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && pip cache purge

# Copy only necessary files (use .dockerignore to exclude unnecessary files)
COPY --chown=meshcore:meshcore packet_capture.py .
COPY --chown=meshcore:meshcore enums.py .
COPY --chown=meshcore:meshcore auth_token.py .
COPY --chown=meshcore:meshcore ble_pairing_helper.py .
COPY --chown=meshcore:meshcore ble_scan_helper.py .
COPY --chown=meshcore:meshcore config.ini .

# Create data directory for output files
RUN mkdir -p /app/data && chown -R meshcore:meshcore /app

# Switch to non-root user
USER meshcore

# Set default environment variables
ENV PACKETCAPTURE_CONNECTION_TYPE=ble \
    PACKETCAPTURE_TIMEOUT=30 \
    PACKETCAPTURE_MAX_CONNECTION_RETRIES=5 \
    PACKETCAPTURE_CONNECTION_RETRY_DELAY=5 \
    PACKETCAPTURE_HEALTH_CHECK_INTERVAL=30 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import meshcore; print('OK')" || exit 1

# Default command
CMD ["python", "packet_capture.py"]
