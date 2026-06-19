# Use node base image because installing it afterwards is hell
FROM node:22-bookworm-slim

# Install system dependencies for BLE, serial communication
# gcc, make and libffi-dev are required to build certain python packages
# on architectures not shipped as wheels
# Use --no-install-recommends to minimize package size
RUN apt-get update && apt-get install -y --no-install-recommends \
    bluez \
    libbluetooth-dev \
    curl \
    gcc \
    make \
    libffi-dev \
    python3 \
    python3-dev \
    python3-pip \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Set working directory
WORKDIR /app

# Copy requirements first for better Docker layer caching
COPY requirements.txt .

# Install Python dependencies with optimizations
RUN pip install --break-system-packages --no-cache-dir -r requirements.txt

# Install meshcore decoder node package
RUN npm install -g @michaelhart/meshcore-decoder

# Copy application files
COPY --chown=1000:1000 packet_capture.py enums.py auth_token.py ./

# Create data directory for output files
RUN mkdir -p /app/data && chown -R 1000:1000 /app

# Switch to non-root user
USER 1000

# Set default environment variables
# Note: These are defaults - override in docker-compose.yml or .env.local
ENV PACKETCAPTURE_CONNECTION_TYPE=serial \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import meshcore; print('OK')" || exit 1

# Default command
ENTRYPOINT ["/usr/bin/python3"]
CMD ["packet_capture.py"]
