# Use Python 3.11 slim image for smaller size
FROM python:3.11-slim

# Install system dependencies for BLE and serial communication
RUN apt-get update && apt-get install -y \
    bluez \
    libbluetooth-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better Docker layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire project
COPY . .

# meshcore is now installed from PyPI via requirements.txt

# Create non-root user for security
RUN useradd -m -u 1000 meshcore && chown -R meshcore:meshcore /app
USER meshcore

# Create data directory for output files
RUN mkdir -p /app/data

# Expose any ports if needed (MQTT typically uses 1883, but this app is a client)
# EXPOSE 1883

# Set default environment variables
ENV PACKETCAPTURE_CONNECTION_TYPE=ble
ENV PACKETCAPTURE_TIMEOUT=30
ENV PACKETCAPTURE_MAX_CONNECTION_RETRIES=5
ENV PACKETCAPTURE_CONNECTION_RETRY_DELAY=5
ENV PACKETCAPTURE_HEALTH_CHECK_INTERVAL=30

# Default command
CMD ["python", "packet_capture.py"]
