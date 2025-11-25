# MeshCore Packet Capture

A standalone Python script for capturing and analyzing packets from **MeshCore Companion radios only**. The script connects to MeshCore Companion devices via Bluetooth Low Energy (BLE), serial, or TCP connection, captures incoming packets, and outputs structured data to console, file, and MQTT broker.

> **⚠️ IMPORTANT: This package is for Companion radios only!**
> 
> - **For Repeaters and RoomServers**: Use [meshcoretomqtt](https://github.com/Cisien/meshcoretomqtt) instead
> - **For Companion radios**: Use this package (meshcore-packet-capture)

Based on the original [meshcoretomqtt](https://github.com/Cisien/meshcoretomqtt) project by [Cisien](https://github.com/Cisien) and uses the official [meshcore](https://github.com/meshcore-dev/meshcore_py) Python package.

## Device Compatibility

### ✅ **Companion Radios** - Use this package
- **meshcore-packet-capture** is designed specifically for Companion radios
- Supports BLE, serial, and TCP connections
- Captures packets from Companion devices without the need for custom firmware

### ❌ **Repeaters and RoomServers** - Use meshcoretomqtt instead
- **Repeaters**: Use [meshcoretomqtt](https://github.com/Cisien/meshcoretomqtt) for repeater packet capture
- **RoomServers**: Use [meshcoretomqtt](https://github.com/Cisien/meshcoretomqtt) for roomserver packet capture
- These devices have different connection requirements and packet formats

## Quick Start

### Install
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/agessaman/meshcore-packet-capture/main/install.sh)
```

### Uninstall
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/agessaman/meshcore-packet-capture/main/uninstall.sh)
```

## Features

- **Companion Radio Packet Capture**: Captures incoming packets from MeshCore Companion devices
- **Connection Types**: Supports BLE, serial, and TCP connections to Companion radios
- **Packet Analysis**: Parses packet headers, routes, payloads, and metadata
- **RF Data**: Captures signal quality metrics (SNR, RSSI)
- **Status Telemetry Stats**:  MQTT status messages optionally contain battery/uptime/radio metrics
- **Multi-Broker MQTT**: Supports up to 4 MQTT brokers simultaneously
- **Auth Token Authentication**: JWT-based authentication using device private key
- **TLS/WebSocket Support**: Secure connections with TLS/SSL and WebSocket transport
- **Topic Templates**: Per-broker topic templates
- **Device Information**: Includes model, firmware version, and radio configuration in status messages

## Requirements

- Python 3.7+
- `meshcore` package (official MeshCore Python library) version 2.2.2 or later (required for stats support)
- `paho-mqtt` package (for MQTT functionality)

**Note**: For Docker deployment, this application is best deployed on Linux systems due to Bluetooth Low Energy (BLE) and serial device access requirements. While Docker containers can run on macOS and Windows, BLE functionality may be limited or require additional configuration.

## Installation

### Local Installation

```bash
pip install meshcore paho-mqtt
```

### Docker Installation

The project includes Docker support for easy deployment:

```bash
# Build the Docker image
docker build -t meshcore-capture .

# Run with Docker Compose (recommended)
docker-compose up -d

# Or run directly with Docker
docker run --privileged --device=/dev/ttyUSB0 \
  -v $(pwd)/data:/app/data \
  -e PACKETCAPTURE_CONNECTION_TYPE=serial \
  meshcore-capture
```

See the [Docker Deployment](#docker-deployment) section below for detailed instructions.

## Configuration

The script uses environment files for configuration.

### Environment Files

The script loads configuration from:
1. `.env` - Default configuration (committed to repository)
2. `.env.local` - Local overrides (not committed, for your specific setup)

All environment variables are prefixed with `PACKETCAPTURE_`. See the `.env` file for all available options.

### Configuration Variables

Configuration is handled via environment variables and `.env` files. The installer will create a `.env.local` file with your settings.


### Environment Variables

#### Connection Settings
- `PACKETCAPTURE_CONNECTION_TYPE`: `ble`, `serial`, or `tcp`
- `PACKETCAPTURE_BLE_ADDRESS`: Specific BLE device address (optional)
- `PACKETCAPTURE_BLE_DEVICE_NAME`: BLE device name to scan for (optional)
- `PACKETCAPTURE_SERIAL_PORTS`: Comma-separated list of serial ports to try
- `PACKETCAPTURE_TCP_HOST`: TCP host address (default: localhost)
- `PACKETCAPTURE_TCP_PORT`: TCP port number (default: 5000)
- `PACKETCAPTURE_TIMEOUT`: Connection timeout in seconds
- `PACKETCAPTURE_MAX_CONNECTION_RETRIES`: Maximum MeshCore connection retry attempts (0 = infinite)
- `PACKETCAPTURE_CONNECTION_RETRY_DELAY`: Delay between MeshCore reconnection attempts (seconds)
- `PACKETCAPTURE_HEALTH_CHECK_INTERVAL`: How often to check connection health (seconds)

#### Logging Settings
- `PACKETCAPTURE_LOG_LEVEL`: Log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`) - default: `INFO`
  - Command line arguments (`--debug`, `--verbose`) override this setting

#### Status Telemetry / Stats
- `PACKETCAPTURE_STATS_IN_STATUS_ENABLED`: Toggle stat collection in status payloads (default: `true`)
- `PACKETCAPTURE_STATS_REFRESH_INTERVAL`: Seconds between stat refreshes/status republishes (default: `300`, i.e. 5 minutes)

When enabled, status messages published to MQTT include a `stats` object with battery, uptime, queue depth, and radio runtime metrics refreshed at the configured cadence.

#### MQTT Settings
The script supports up to 4 MQTT brokers (MQTT1, MQTT2, MQTT3, MQTT4). Each broker can be configured independently:

**Broker 1 (Primary):**
- `PACKETCAPTURE_MQTT1_ENABLED`: Enable/disable MQTT broker 1
- `PACKETCAPTURE_MQTT1_SERVER`: MQTT broker address
- `PACKETCAPTURE_MQTT1_PORT`: MQTT broker port
- `PACKETCAPTURE_MQTT1_USERNAME`/`PACKETCAPTURE_MQTT1_PASSWORD`: Authentication credentials
- `PACKETCAPTURE_MQTT1_TRANSPORT`: Transport type (`tcp` or `websockets`)
- `PACKETCAPTURE_MQTT1_USE_TLS`: Enable TLS/SSL encryption
- `PACKETCAPTURE_MQTT1_TLS_VERIFY`: Verify TLS certificates (default: true)
- `PACKETCAPTURE_MQTT1_USE_AUTH_TOKEN`: Use auth token authentication
- `PACKETCAPTURE_MQTT1_TOKEN_AUDIENCE`: Token audience for auth token
- `PACKETCAPTURE_MQTT1_CLIENT_ID_PREFIX`: Client ID prefix
- `PACKETCAPTURE_MQTT1_QOS`: Quality of Service level
- `PACKETCAPTURE_MQTT1_RETAIN`: Retain messages
- `PACKETCAPTURE_MQTT1_KEEPALIVE`: Keep-alive interval

**Brokers 2-4:** Same pattern with `MQTT2_`, `MQTT3_`, `MQTT4_` prefixes

**Global MQTT Settings:**
- `PACKETCAPTURE_MAX_MQTT_RETRIES`: Maximum MQTT connection retry attempts (0 = infinite)
- `PACKETCAPTURE_MQTT_RETRY_DELAY`: Delay between MQTT reconnection attempts (seconds)
- `PACKETCAPTURE_EXIT_ON_RECONNECT_FAIL`: Exit when reconnection attempts fail (default: true)

**Private Key Settings:**
- `PACKETCAPTURE_PRIVATE_KEY`: Device private key for auth token authentication (hex string)
- `PACKETCAPTURE_PRIVATE_KEY_FILE`: Path to file containing device private key

**Note**: Private keys can be provided via environment variable, file path, or `.env.local` file.

#### Topic Templates
Topics support template variables:
- `{IATA}`: Replaced with your IATA code in uppercase (e.g., "SEA")
- `{IATA_lower}`: Replaced with your IATA code in lowercase (e.g., "sea")
- `{PUBLIC_KEY}`: Replaced with device public key

Examples:
- `meshcore/{IATA}/packets` becomes `meshcore/SEA/packets`
- `meshcore/{IATA_lower}/packets` becomes `meshcore/sea/packets`

#### Authentication Methods

**Username/Password Authentication:**
```bash
PACKETCAPTURE_MQTT1_USERNAME=your_username
PACKETCAPTURE_MQTT1_PASSWORD=your_password
```

**Auth Token Authentication (JWT):**
```bash
PACKETCAPTURE_MQTT1_USE_AUTH_TOKEN=true
PACKETCAPTURE_MQTT1_TOKEN_AUDIENCE=mqtt.example.com
PACKETCAPTURE_PRIVATE_KEY=your_private_key_here
# OR
PACKETCAPTURE_PRIVATE_KEY_FILE=/path/to/private_key_file
```
**Note**: Auth token authentication requires the device's private key.

**Transport Options:**
- `tcp`: Standard TCP connection
- `websockets`: WebSocket connection (useful for web applications)

**TLS/SSL Security:**
```bash
PACKETCAPTURE_MQTT1_USE_TLS=true
PACKETCAPTURE_MQTT1_TLS_VERIFY=true  # Verify certificates
```

#### Exit Behavior

The script handles MQTT disconnections by continuing to run and attempting reconnection. On reconnection failure, it exits after maximum retry attempts (configurable).

For BLE connections where disconnections may be transient:

```bash
# Exit when reconnection attempts fail (recommended for BLE)
PACKETCAPTURE_EXIT_ON_RECONNECT_FAIL=true

# Never exit, keep trying indefinitely
PACKETCAPTURE_EXIT_ON_RECONNECT_FAIL=false
PACKETCAPTURE_MAX_MQTT_RETRIES=0
```

#### Advert Settings
- `PACKETCAPTURE_ADVERT_INTERVAL_HOURS`: Send flood adverts at this interval (0 = disabled, default = 11 hours)

#### Packet Type Filtering
- `PACKETCAPTURE_UPLOAD_PACKET_TYPES`: Comma-separated list of packet type numbers to upload to MQTT (default: upload all types)

This setting allows you to filter which packet types are uploaded to MQTT brokers. Packets are still captured and written to files/console, but only specified packet types will be uploaded to MQTT.

**Available Packet Types:**
- `0` = REQ (Request)
- `1` = RESPONSE
- `2` = TXT_MSG (Text Message)
- `3` = ACK (Acknowledgment)
- `4` = ADVERT (Advertisement)
- `5` = GRP_TXT (Group Text)
- `6` = GRP_DATA (Group Data)
- `7` = ANON_REQ (Anonymous Request)
- `8` = PATH
- `9` = TRACE
- `10` = MULTIPART
- `11-14` = Reserved
- `15` = RAW_CUSTOM

**Examples:**
```bash
# Upload only text messages and advertisements
PACKETCAPTURE_UPLOAD_PACKET_TYPES=2,4

# Upload only requests, responses, and text messages
PACKETCAPTURE_UPLOAD_PACKET_TYPES=0,1,2

# Upload all types (default behavior - leave unset or empty)
# PACKETCAPTURE_UPLOAD_PACKET_TYPES=
```

**Note:** If this setting is not configured or is empty, all packet types will be uploaded.

## Usage

### Local Usage

```bash
# Basic usage
python packet_capture.py

# Save output to file
python packet_capture.py --output packets.json

# Disable MQTT publishing
python packet_capture.py --no-mqtt

# Enable verbose output (shows JSON packet data)
python packet_capture.py --verbose

# Enable debug output (shows all detailed debugging info)
python packet_capture.py --debug
```

## Docker Deployment

The project includes Docker support for deployment.

### Prerequisites

- Docker and Docker Compose installed
- Linux host system (recommended for BLE support)

### Quick Start with Docker Compose

1. **Clone and configure**:
   ```bash
   git clone <repository-url>
   cd meshcore-packet-capture
   ```

2. **Create configuration** (optional):
   ```bash
   # Create .env.local file with your settings
   cp .env.example .env.local
   # Edit .env.local with your configuration
   ```

3. **Start the service**:
   ```bash
   docker-compose up -d
   ```

4. **View logs**:
   ```bash
   docker-compose logs -f meshcore-capture
   ```

### Docker Compose Configuration

The `docker-compose.yml` file includes privileged mode for device access, volume mounts for data storage, and environment variable configuration.

### Manual Docker Commands

```bash
# Build the image
docker build -t meshcore-capture .

# Run with BLE connection
docker run --privileged \
  -v $(pwd)/data:/app/data \
  -e PACKETCAPTURE_CONNECTION_TYPE=ble \
  -e PACKETCAPTURE_MQTT1_SERVER=your-mqtt-broker \
  meshcore-capture

# Run with serial connection
docker run --privileged \
  --device=/dev/ttyUSB0:/dev/ttyUSB0 \
  -v $(pwd)/data:/app/data \
  -e PACKETCAPTURE_CONNECTION_TYPE=serial \
  -e PACKETCAPTURE_SERIAL_PORTS=/dev/ttyUSB0 \
  meshcore-capture

# Run with TCP connection
docker run \
  -v $(pwd)/data:/app/data \
  -e PACKETCAPTURE_CONNECTION_TYPE=tcp \
  -e PACKETCAPTURE_TCP_HOST=your-tcp-server \
  -e PACKETCAPTURE_TCP_PORT=5000 \
  meshcore-capture
```

### Configuration in Docker

Configuration can be provided via environment variables or volume-mounted `.env.local` files.

### Platform Considerations

- **Linux**: Full BLE and serial support
- **macOS**: Full BLE and serial support, limited BLE support in containers
- **Windows**: Limited BLE support (currently untested), serial connections work with proper device mounting

### Troubleshooting Docker Deployment

**BLE Connection Issues**:
```bash
# Try host networking for BLE discovery
docker run --privileged --network=host meshcore-capture
```

**Serial Device Access**:
```bash
# Ensure device permissions
sudo chmod 666 /dev/ttyUSB0
# Or add user to dialout group
sudo usermod -a -G dialout $USER
```

**MQTT Connection Issues**:
```bash
# Check network connectivity
docker exec -it meshcore-capture ping mqtt-broker
# View container logs
docker logs meshcore-capture
```

## Output Levels

The script supports three output levels:

- **Normal (default)**: Shows minimal packet info line only
- **--verbose**: Adds JSON packet data output  
- **--debug**: Adds all detailed debugging information

## Output Format

Captured packets are output in JSON format with the following structure:

```json
{
  "origin": "Device Name",
  "origin_id": "device_public_key",
  "timestamp": "2024-01-01T12:00:00.000000",
  "type": "PACKET",
  "direction": "rx",
  "time": "12:00:00",
  "date": "01/01/2024",
  "len": "45",
  "packet_type": "4",
  "route": "F",
  "payload_len": "32",
  "raw": "F5930103807E5F1EDE680070B9F3FCF238AA6B64BDEA8B4FDC4E2A",
  "SNR": "12.5",
  "RSSI": "-65",
  "hash": "A1B2C3D4E5F67890"
}
```

## MQTT Topics

- `meshcore/status`: Device online/offline status
- `meshcore/packets`: Full packet data
- `meshcore/raw`: Raw packet data (required for map.w0z.is)
## Troubleshooting

### Connection Issues

**Script stops receiving packets but doesn't reconnect:**
- The script now includes automatic reconnection logic
- Check the logs for connection health check messages
- Adjust `health_check_interval` in config to check more frequently
- Increase `max_connection_retries` if you want more retry attempts

**BLE connection keeps dropping:**
- Ensure the MeshCore device is within range
- Check for interference from other Bluetooth devices
- Try increasing `connection_retry_delay` to give the device more time to recover
- Set `max_connection_retries = 0` for infinite retry attempts

**MQTT connection issues:**
- Verify MQTT broker settings in config
- Check network connectivity to MQTT broker
- The script will automatically retry MQTT connections on failure
- Adjust `mqtt_retry_delay` if reconnection attempts are too frequent

### Debugging

Enable debug mode for detailed logging:
```bash
python packet_capture.py --debug
```

This will show:
- Connection health check results
- Reconnection attempts and results
- Detailed packet parsing information
- MQTT connection status

## Files

- `packet_capture.py`: Main capture script
- `enums.py`: Packet type and flag definitions
- `install.sh`: Installation script
- `uninstall.sh`: Uninstallation script
- `scan_meshcore_network.py`: Network scanner for MeshCore nodes
- `.env`: Default configuration template
- `.env.local`: Local configuration (created by installer)

## Contributing

Contributions are welcome! Please open GitHub issues for bug reports and feature requests, or submit pull requests for improvements.

## Credits

This project is based on the original [meshcoretomqtt](https://github.com/Cisien/meshcoretomqtt) project by [Cisien](https://github.com/Cisien), which provides a foundation for MeshCore packet capture and MQTT integration. The project uses the official [meshcore](https://github.com/meshcore-dev/meshcore_py) Python package for device communication.
