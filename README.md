# MeshCore Packet Capture

A standalone Python script for capturing and analyzing packets from MeshCore companion radios. The script connects to MeshCore devices via Bluetooth Low Energy (BLE) or serial connection, captures incoming packets, and outputs structured data to console, file, and MQTT broker.

Based on the original [meshcoretomqtt](https://github.com/Cisien/meshcoretomqtt) project by [Cisien](https://github.com/Cisien) and uses the official [meshcore](https://github.com/meshcore-dev/meshcore_py) Python package.

## Features

- **Packet Capture**: Captures incoming packets from MeshCore devices
- **Multiple Output Formats**: Console output, file logging, and MQTT publishing
- **Connection Types**: Supports both BLE and serial connections
- **Packet Analysis**: Parses packet headers, routes, payloads, and metadata
- **RF Data**: Captures signal quality metrics (SNR, RSSI)
- **Multi-Broker MQTT**: Supports up to 4 MQTT brokers simultaneously
- **Auth Token Authentication**: JWT-based authentication using device private keys
- **TLS/WebSocket Support**: Secure connections with TLS/SSL and WebSocket transport
- **Topic Templates**: Dynamic topic resolution with IATA and device key placeholders
- **Automatic Reconnection**: Handles disconnections gracefully with configurable retry logic
- **Connection Monitoring**: Continuous health checks to detect and recover from connection issues
- **Environment Configuration**: Modern .env/.env.local configuration files

## Requirements

- Python 3.7+
- `meshcore` package (official MeshCore Python library)
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

The script uses environment files for configuration. This modern approach is more secure, container-friendly, and follows industry best practices.

### Environment Files

The script loads configuration from:
1. `.env` - Default configuration (committed to repository)
2. `.env.local` - Local overrides (not committed, for your specific setup)

All environment variables are prefixed with `PACKETCAPTURE_`. See the `.env` file for all available options.

### Configuration Variables

To migrate from `config.ini` to environment files:

```bash
python3 migrate_config.py
```

This will create a `.env.local` file with your current settings.

### Environment Variables

#### Connection Settings
- `PACKETCAPTURE_CONNECTION_TYPE`: `ble` or `serial`
- `PACKETCAPTURE_BLE_ADDRESS`: Specific BLE device address (optional)
- `PACKETCAPTURE_BLE_DEVICE_NAME`: BLE device name to scan for (optional)
- `PACKETCAPTURE_SERIAL_PORTS`: Comma-separated list of serial ports to try
- `PACKETCAPTURE_TIMEOUT`: Connection timeout in seconds
- `PACKETCAPTURE_MAX_CONNECTION_RETRIES`: Maximum MeshCore connection retry attempts (0 = infinite)
- `PACKETCAPTURE_CONNECTION_RETRY_DELAY`: Delay between MeshCore reconnection attempts (seconds)
- `PACKETCAPTURE_HEALTH_CHECK_INTERVAL`: How often to check connection health (seconds)

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

**Note**: You can provide the private key in multiple ways:
1. Environment variable: `PACKETCAPTURE_PRIVATE_KEY=your_key_here`
2. File path: `PACKETCAPTURE_PRIVATE_KEY_FILE=/path/to/key_file`
3. `.env.local` file: Create a `.env.local` file with `PACKETCAPTURE_PRIVATE_KEY=your_key_here`

The `.env.local` file is automatically ignored by git and is perfect for local development.

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
**Note**: Auth token authentication requires the device's private key. You can provide the private key manually via environment variable, file, or `.env.local` file.

**Transport Options:**
- `tcp`: Standard TCP connection
- `websockets`: WebSocket connection (useful for web applications)

**TLS/SSL Security:**
```bash
PACKETCAPTURE_MQTT1_USE_TLS=true
PACKETCAPTURE_MQTT1_TLS_VERIFY=true  # Verify certificates
```

#### Exit Behavior

The script handles MQTT disconnections intelligently:

- **On Disconnect**: Script continues running and attempts reconnection
- **On Reconnection Failure**: Script exits after maximum retry attempts (configurable)

This approach is ideal for BLE connections where disconnections may be transient:

```bash
# Exit when reconnection attempts fail (recommended for BLE)
PACKETCAPTURE_EXIT_ON_RECONNECT_FAIL=true

# Never exit, keep trying indefinitely
PACKETCAPTURE_EXIT_ON_RECONNECT_FAIL=false
PACKETCAPTURE_MAX_MQTT_RETRIES=0
```

#### Legacy config.ini Settings
- `connection_type`: `ble` or `serial`
- `ble_address`: Specific BLE device address (optional)
- `ble_device_name`: BLE device name to scan for (optional)
- `serial_port`: Serial port path (for serial connections)
- `timeout`: Connection timeout in seconds
- `max_connection_retries`: Maximum MeshCore connection retry attempts (0 = infinite)
- `connection_retry_delay`: Delay between MeshCore reconnection attempts (seconds)
- `health_check_interval`: How often to check connection health (seconds)

### MQTT Settings
- `server`: MQTT broker address
- `port`: MQTT broker port
- `username`/`password`: Authentication credentials
- `topics`: MQTT topic structure for different data types
- `max_mqtt_retries`: Maximum MQTT connection retry attempts (0 = infinite)
- `mqtt_retry_delay`: Delay between MQTT reconnection attempts (seconds)

### Advert Settings
- `advert_interval_hours`: Send flood adverts at this interval (0 = disabled, default = 11 hours)

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

The project includes Docker support for easy deployment and scaling. Docker deployment is recommended for production environments and provides better isolation and management.

### Prerequisites

- Docker and Docker Compose installed
- Linux host system (recommended for full BLE support)
- MeshCore device accessible via BLE or serial connection

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

The `docker-compose.yml` file includes:

- **Privileged mode**: Required for BLE and device access
- **Device mounting**: Serial port access (`/dev/ttyUSB0`, etc.)
- **Volume mounts**: Persistent data storage and configuration
- **Environment variables**: All configuration options
- **Network configuration**: Bridge network for MQTT connectivity

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
```

### Configuration in Docker

Configuration can be provided via:

1. **Environment variables** (recommended):
   ```bash
   -e PACKETCAPTURE_MQTT1_SERVER=mqtt.example.com
   -e PACKETCAPTURE_MQTT1_USERNAME=user
   -e PACKETCAPTURE_MQTT1_PASSWORD=pass
   ```

2. **Volume-mounted .env.local file**:
   ```bash
   -v $(pwd)/.env.local:/app/.env.local:ro
   ```

3. **Docker Compose environment section**:
   ```yaml
   environment:
     - PACKETCAPTURE_MQTT1_SERVER=mqtt.example.com
   ```

### Platform Considerations

- **Linux**: Full support for BLE and serial connections
- **macOS**: Limited BLE support in containers, may require host networking
- **Windows**: Limited BLE support, serial connections work with proper device mounting

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
- `meshcore/decoded`: Decoded packet content
- `meshcore/debug`: Debug information (only when --debug flag is used)

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
- `config.ini`: Configuration file (auto-generated)

## Contributing

Contributions are welcome! I welcome pull requests and feature requests. Here are some ways you can contribute:

- **Bug Reports**: Found an issue? Please open a GitHub issue with details about the problem
- **Feature Requests**: Have an idea for a new feature? Open an issue to discuss it
- **Pull Requests**: Submit PRs for bug fixes, new features, or improvements
- **Documentation**: Help improve the README, add examples, or clarify usage instructions

## Credits

This project is based on the original [meshcoretomqtt](https://github.com/Cisien/meshcoretomqtt) project by [Cisien](https://github.com/Cisien), which provides a foundation for MeshCore packet capture and MQTT integration. The project uses the official [meshcore](https://github.com/meshcore-dev/meshcore_py) Python package for device communication.
