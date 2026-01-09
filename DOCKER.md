# Docker Deployment Guide

## Prerequisites

- Docker and Docker Compose installed
- Linux host system (recommended for BLE and serial support)

## Quick Start

1. **Download configuration files**:
   ```bash
   # Download docker-compose.yml and .env.local.example
   curl -O https://raw.githubusercontent.com/agessaman/meshcore-packet-capture/main/docker-compose.yml
   curl -O https://raw.githubusercontent.com/agessaman/meshcore-packet-capture/main/.env.local.example
   ```

2. **Configure**:
   ```bash
   # Copy example configuration
   cp .env.local.example .env.local
   # Edit .env.local with your settings (IATA code, MQTT broker, etc.)
   ```

3. **Start the container**:
   ```bash
   docker compose up -d
   ```

4. **View logs**:
   ```bash
   docker compose logs -f meshcore-capture
   ```

## Connection Types

### Serial Connection (Default)

The default configuration uses serial connection with `privileged: false` for improved security.

1. **Find your device**:
   ```bash
   sudo ls -la /dev/serial/by-id/
   ```

2. **Mount device in docker-compose.yml**:
   ```yaml
   devices:
     - /dev/serial/by-id/usb-Heltec_HT-n5262_3D3B4D4A4D776001-if00:/dev/ttyUSB0
   ```

3. **Configure serial port** (if not using `/dev/ttyUSB0`):
   ```yaml
   environment:
     - PACKETCAPTURE_SERIAL_PORTS=/dev/ttyUSB0
   ```

The container path defaults to `/dev/ttyUSB0`, so no additional configuration is needed if using the standard path.

### BLE Connection

1. **Enable privileged mode** in `docker-compose.yml`:
   ```yaml
   privileged: true
   ```

2. **Set connection type**:
   ```yaml
   environment:
     - PACKETCAPTURE_CONNECTION_TYPE=ble
   ```

3. **Optionally specify BLE device**:
   ```yaml
   environment:
     - PACKETCAPTURE_BLE_ADDRESS=AA:BB:CC:DD:EE:FF
     # or
     - PACKETCAPTURE_BLE_DEVICE_NAME=MeshCore Device
   ```

4. **Enable host networking** (may be required for BLE discovery):
   ```yaml
   network_mode: host
   ```

## Configuration

Configuration is provided via:

1. **Environment variables** in `docker-compose.yml`
2. **`.env.local` file** mounted as a volume (recommended)

The `.env.local` file supports all configuration options. See `.env.local.example` for available settings.

### Required Settings

- `PACKETCAPTURE_IATA`: 3-letter airport code (e.g., `SEA`, `LAX`)
- `PACKETCAPTURE_MQTT1_SERVER`: MQTT broker address
- `PACKETCAPTURE_MQTT1_PORT`: MQTT broker port

### MQTT Authentication

**Username/Password**:
```bash
PACKETCAPTURE_MQTT1_USERNAME=your_username
PACKETCAPTURE_MQTT1_PASSWORD=your_password
```

**Auth Token (JWT)**:
```bash
PACKETCAPTURE_MQTT1_USE_AUTH_TOKEN=true
PACKETCAPTURE_MQTT1_TOKEN_AUDIENCE=mqtt.example.com
PACKETCAPTURE_PRIVATE_KEY=your_private_key_hex
```

## Container Management

**Start**:
```bash
docker compose up -d
```

**Stop**:
```bash
docker compose down
```

**Restart**:
```bash
docker compose restart meshcore-capture
```

**View logs**:
```bash
docker compose logs -f meshcore-capture
```

**View status**:
```bash
docker compose ps
```

**Execute commands in container**:
```bash
docker compose exec meshcore-capture /bin/bash
```

## Data Storage

Packet data is stored in the `./data` directory, which is mounted as a volume. Data persists across container restarts.

### Separate Logs Directory

To store logs separately from packet data, uncomment the logs volume mount in `docker-compose.yml`:

```yaml
volumes:
  - ./logs:/app/logs
```

Create the logs directory before starting:
```bash
mkdir -p logs
```

Container logs are also available via Docker:
```bash
docker compose logs -f meshcore-capture > logs/container.log
```

## Troubleshooting

### Serial Device Not Found

**Check device exists**:
```bash
ls -la /dev/serial/by-id/
```

**Check device permissions**:
```bash
sudo chmod 666 /dev/ttyUSB0
# Or add user to dialout group
sudo usermod -a -G dialout $USER
# Then log out and back in
```

**Verify device mount**:
```bash
docker compose exec meshcore-capture ls -la /dev/ttyUSB0
```

### BLE Connection Issues

**Enable host networking**:
```yaml
network_mode: host
```

**Check Bluetooth adapter**:
```bash
docker compose exec meshcore-capture hciconfig
```

**Verify privileged mode**:
```bash
docker compose exec meshcore-capture cat /proc/self/status | grep CapEff
```

### MQTT Connection Issues

**Test network connectivity**:
```bash
docker compose exec meshcore-capture ping mqtt-broker
```

**Check MQTT configuration**:
```bash
docker compose exec meshcore-capture env | grep MQTT
```

**View connection logs**:
```bash
docker compose logs meshcore-capture | grep -i mqtt
```

### Container Won't Start

**Check logs**:
```bash
docker compose logs meshcore-capture
```

**Verify configuration**:
```bash
docker compose config
```

**Check image**:
```bash
docker pull ghcr.io/agessaman/meshcore-packet-capture:latest
```

## Building from Source

To build the image locally instead of using the pre-built image:

1. **Comment out image line** in `docker-compose.yml`:
   ```yaml
   # image: ghcr.io/agessaman/meshcore-packet-capture:latest
   ```

2. **Uncomment build line**:
   ```yaml
   build: .
   ```

3. **Build and start**:
   ```bash
   docker compose up -d --build
   ```

## Platform Notes

- **Linux**: Full support for both BLE and serial connections
- **macOS**: Serial connections work; BLE may require host networking
- **Windows**: Serial connections work with proper device mounting; BLE support is limited
