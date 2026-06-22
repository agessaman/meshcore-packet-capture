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

### Install the app (recommended)

Install the CLI from PyPI with [pipx](https://pipx.pypa.io) (keeps it in its own isolated environment):

```bash
pipx install meshcore-packet-capture
meshcore-packet-capture --help
```

This gives you the `meshcore-packet-capture` command for manual runs and development.
It does **not** create a background service — see below to run it as a managed
systemd/launchd service.

### Install as a managed service (systemd / launchd)

For a turnkey install that creates a service account, installs a systemd (Linux) or
launchd (macOS) unit, and writes config under `/etc`, use the bootstrap installer.
It installs system-wide (under `/opt` and `/etc`) and so must run as root:

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/agessaman/meshcore-packet-capture/main/install.sh)"
```

> **Note:** use the bootstrap installer when you want a systemwide managed
> service. The PyPI/pipx install is for CLI/manual runs and does not create
> service files or write system configuration.
>
> **macOS + BLE:** because macOS grants Bluetooth permission per-user (not to
> root daemons), a BLE install is set up as a per-user LaunchAgent that runs in
> your login session. Serial/TCP installs use a system LaunchDaemon.

### Windows (manual / development only)

Windows has no systemd/launchd integration, so `install.ps1` is a manual/dev-only
path: it installs files and a venv for a manual run (no auto-start service) and
writes configuration as a legacy `.env.local` file rather than the TOML
`config.d` model used on Linux/macOS. `.env.local` is still honored at runtime
(TOML config overrides it where present), so this is intentional. BLE support on
Windows is limited and currently untested — serial/TCP are the expected
transports there.

```powershell
.\install.ps1
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
- **Multi-Broker MQTT**: Supports any number of sequentially numbered MQTT brokers
- **Auth Token Authentication**: JWT-based authentication using device private key
- **TLS/WebSocket Support**: Secure connections with TLS/SSL and WebSocket transport
- **Topic Templates**: Per-broker topic templates
- **Device Information**: Includes model, firmware version, and radio configuration in status messages

## Requirements

- Python 3.11+ (installer and recommended runtime)
- `meshcore` package (official MeshCore Python library) version 2.2.31 or later (required for multi-byte path support and stats)
- `paho-mqtt` package (for MQTT functionality)

**Note**: For Docker deployment, this application is best deployed on Linux systems due to Bluetooth Low Energy (BLE) and serial device access requirements. While Docker containers can run on macOS and Windows, BLE functionality may be limited or require additional configuration.

## Installation

### From PyPI (CLI/manual use)

```bash
# Isolated CLI install (recommended)
pipx install meshcore-packet-capture

# …or into the current environment
pip install meshcore-packet-capture
```

This installs the `meshcore-packet-capture` command and all dependencies. Use this for
manual runs, development, or when you manage the process yourself. To run it as a
managed background service, use the bootstrap installer (see [Quick Start](#quick-start)
and [Managed-service installer](#managed-service-installer-linux-and-macos) below).

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

**TOML under `/etc/meshcore-packet-capture/` is the primary configuration source**, matching [meshcoretomqtt](https://github.com/Cisien/meshcoretomqtt). Configuration is resolved with this precedence (highest first):

1. **Process environment** — `PACKETCAPTURE_*` variables already set in the environment (e.g. from a systemd unit, Docker `-e`, or your shell) always win.
2. **TOML**: `/etc/meshcore-packet-capture/config.toml` plus every `*.toml` in `/etc/meshcore-packet-capture/config.d/` (sorted). Broker entries use the same `[[broker]]` shape as meshcoretomqtt. See `config.toml.example` and bundled `presets/letsmesh.toml` (LetsMesh Packet Analyzer defaults). With **`--config PATH`** (repeatable) only those files are merged, in order, and the automatic `/etc` scan is skipped.
3. **Legacy `.env` / `.env.local`** (see below) — a development/manual-install convenience, loaded from the working directory. These are overridden by TOML, so they only take effect for keys the TOML config does not set.

Values are applied as `PACKETCAPTURE_*` environment variables. See `config.toml.example` for every TOML key, or `.env` for the equivalent flat variable names.

### Managed-service installer (Linux and macOS)

Use the bootstrap installer when you want a systemwide managed background service
rather than just the CLI: it installs under `/opt/meshcore-packet-capture`, writes
configuration under `/etc/meshcore-packet-capture`, creates a Linux service
account, and installs a systemd (Linux) or launchd (macOS) unit. During setup it
also configures the Companion connection (BLE, serial, or TCP) and offers bundled
broker presets (default selection: LetsMesh).

From a repo checkout (requires root):

```bash
export LOCAL_INSTALL=/path/to/meshcore-packet-capture
sudo bash install.sh
```

Or bootstrap via curl (downloads the branch and runs `python3 -m installer install`).

#### Upgrading legacy service installs

Older installers placed the app and `.env.local` configuration under
`~/.meshcore-packet-capture` and created a `meshcore-capture.service` unit. Run the
managed-service installer to upgrade that layout. It detects the legacy directory,
converts `.env` / `.env.local` into
`/etc/meshcore-packet-capture/config.d/99-user.toml`, stops and removes the old
service unit after the TOML file is written, then continues with the new
systemwide `/opt` install.

The old `~/.meshcore-packet-capture` directory is left in place for rollback or
manual cleanup. Standalone `python3 -m installer migrate` only migrates
configuration and service units; use the full installer when you want the new
application files and service installed too.

### Legacy environment files (local development)

For development and manual installs, two flat key/value files are still read from the
working directory (repo root, `/opt/meshcore-packet-capture`, or `/app` in Docker):

1. `.env` - Default configuration (committed to repository)
2. `.env.local` - Local overrides (not committed, for your specific setup; `.env.local` wins over `.env`)

All logical keys use the `PACKETCAPTURE_` prefix. These files are **legacy**: the TOML
config under `/etc/meshcore-packet-capture/` takes precedence over them. For service
installs, configure via TOML (`config.d/99-user.toml`) instead.

### Configuration Variables

For systemd installs, prefer editing `/etc/meshcore-packet-capture/config.d/99-user.toml`. Legacy `~/.meshcore-packet-capture` installs can be migrated with `sudo python3 -m installer migrate` from a checkout.

### Unit tests

```bash
pip install -r requirements-dev.txt
pytest
```

Tests live under `tests/`. Legacy experiments belong in `old/` (gitignored). Optional developer scripts are in `devtools/`.


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
- `PACKETCAPTURE_DRAIN_MESSAGES`: When `true` (default), run meshcore auto message fetch so the device message queue is drained; set to `false` for RF packet capture only without pulling stored messages

#### Logging Settings
- `PACKETCAPTURE_LOG_LEVEL`: Log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`) - default: `INFO`
  - Command line arguments (`--debug`, `--verbose`) override this setting

#### Status Telemetry / Stats
- `PACKETCAPTURE_STATS_IN_STATUS_ENABLED`: Toggle stat collection in status payloads (default: `true`)
- `PACKETCAPTURE_STATS_REFRESH_INTERVAL`: Seconds between stat refreshes/status republishes (default: `300`, i.e. 5 minutes)

When enabled, status messages published to MQTT include a `stats` object with battery, uptime, queue depth, and radio runtime metrics refreshed at the configured cadence.

#### MQTT Settings
Brokers are discovered sequentially starting at `MQTT1` and continue until `PACKETCAPTURE_MQTT<n>_ENABLED` is no longer defined — there is no fixed upper limit. (Via TOML, add as many `[[broker]]` blocks as you need; they are flattened to these `MQTT<n>_*` variables.) Each broker can be configured independently:

**Broker 1 (Primary):**
- `PACKETCAPTURE_MQTT1_ENABLED`: Enable/disable MQTT broker 1
- `PACKETCAPTURE_MQTT1_NAME`: Optional human-readable broker label for logs (TOML `[[broker]]` `name` is exported automatically; when unset, logs use `SERVER`)
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

**Additional brokers:** Use the same pattern with `MQTT2_`, `MQTT3_`, and higher sequential prefixes as needed

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

#### Per-Broker Topic Overrides
Topics can be set globally (under `[topics]`) or overridden per broker. A broker's own
topic takes precedence over the global value; brokers without an override fall back to
the global topic. The same template variables apply.

In TOML, set them under the broker's `[broker.topics]` table:
```toml
[[broker]]
name = "analyzer"
enabled = true
server = "mqtt.example.com"

[broker.topics]
# This broker's packets go to a custom topic; status/raw fall back to [topics].
packets = "custom/{IATA}/{PUBLIC_KEY}/packets"

[topics]
packets = "meshcore/{IATA}/{PUBLIC_KEY}/packets"
status  = "meshcore/{IATA}/{PUBLIC_KEY}/status"
```
These flatten to `PACKETCAPTURE_MQTT<n>_TOPIC_<NAME>` (per broker) and
`PACKETCAPTURE_TOPIC_<NAME>` (global fallback) — supported names: `STATUS`,
`PACKETS`, `DECODED`, `DEBUG`, `RAW`.

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
- `PACKETCAPTURE_ADVERT_INTERVAL_HOURS`: Send flood adverts at this interval (0 = disabled, default = 47 hours)

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
- `11` = CONTROL
- `12-14` = Reserved
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
# Basic usage (after: pip install -e .  or  PYTHONPATH=src)
python -m meshcore_packet_capture

# From repo root without install:
python packet_capture.py

# Save output to file
python -m meshcore_packet_capture --output packets.json

# Disable MQTT publishing
python -m meshcore_packet_capture --no-mqtt

# Verbose / debug
python -m meshcore_packet_capture --verbose
python -m meshcore_packet_capture --debug
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

2. **Configure** (optional): edit the `environment:` block in `docker-compose.yml`
   (the recommended approach — `PACKETCAPTURE_*` variables), or bind-mount a TOML
   config directory at `/etc/meshcore-packet-capture` (uncomment the
   `./meshcore-etc:/etc/meshcore-packet-capture:ro` volume). A legacy `.env.local`
   bind-mount is also supported — copy the committed `.env` as a starting point:
   ```bash
   cp .env .env.local
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

Configuration can be provided three ways, in precedence order: `PACKETCAPTURE_*`
environment variables (`-e` / the compose `environment:` block) win, then a
volume-mounted TOML config at `/etc/meshcore-packet-capture` (recommended for
non-trivial setups), then a legacy volume-mounted `.env.local`.

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

Default topic templates (from the shipped `config.toml`):

- `meshcore/{IATA}/{PUBLIC_KEY}/status`: Device online/offline status (plus optional stats)
- `meshcore/{IATA}/{PUBLIC_KEY}/packets`: Full packet data
- `meshcore/{IATA}/{PUBLIC_KEY}/raw`: Raw packet data (commented out by default; enable it for e.g. map.w0z.is)

These are configurable globally or per broker — see [Topic Templates](#topic-templates)
and [Per-Broker Topic Overrides](#per-broker-topic-overrides). The classic flat form
(`meshcore/status`, `meshcore/packets`, `meshcore/raw`) still works if you set the
topics explicitly.

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
python -m meshcore_packet_capture --debug
```

This will show:
- Connection health check results
- Reconnection attempts and results
- Detailed packet parsing information
- MQTT connection status

## Layout

- `src/meshcore_packet_capture/`: Installable Python package (run with `python -m meshcore_packet_capture`)
- `packet_capture.py`: Repo-root launcher (adds `src` to `PYTHONPATH` for quick runs)
- `pyproject.toml`: Package metadata and dependencies
- `packaging/`: systemd and launchd unit templates
- `devtools/`: Optional BLE/network debugging helpers (not installed to `/opt` by default)
- `config.toml.example`: Annotated reference for the TOML config under `/etc`
- `presets/`: Bundled `[[broker]]` presets installed to `config.d/10-*.toml`
- `install.sh` / `install.ps1` / `uninstall.sh`: Installation scripts
- `.env`: Legacy default configuration template (TOML takes precedence)
- `.env.local`: Legacy local configuration (for dev or Docker bind-mount)

## Contributing

Contributions are welcome! Please open GitHub issues for bug reports and feature requests, or submit pull requests for improvements.

## Credits

This project is based on the original [meshcoretomqtt](https://github.com/Cisien/meshcoretomqtt) project by [Cisien](https://github.com/Cisien), which provides a foundation for MeshCore packet capture and MQTT integration. The project uses the official [meshcore](https://github.com/meshcore-dev/meshcore_py) Python package for device communication.
