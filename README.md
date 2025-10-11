# MeshCore Packet Capture

A standalone Python script for capturing and analyzing packets from MeshCore companion radios. The script connects to MeshCore devices via Bluetooth Low Energy (BLE) or serial connection, captures incoming packets, and outputs structured data to console, file, and MQTT broker.

Based on the original [meshcoretomqtt](https://github.com/Cisien/meshcoretomqtt) project by [Cisien](https://github.com/Cisien) and uses the official [meshcore](https://github.com/meshcore-dev/meshcore_py) Python package.

## Features

- **Packet Capture**: Captures incoming packets from MeshCore devices
- **Multiple Output Formats**: Console output, file logging, and MQTT publishing
- **Connection Types**: Supports both BLE and serial connections
- **Packet Analysis**: Parses packet headers, routes, payloads, and metadata
- **RF Data**: Captures signal quality metrics (SNR, RSSI)
- **MQTT Integration**: Publishes packet data to MQTT topics for integration with other systems
- **Automatic Reconnection**: Handles disconnections gracefully with configurable retry logic
- **Connection Monitoring**: Continuous health checks to detect and recover from connection issues

## Requirements

- Python 3.7+
- `meshcore` package (official MeshCore Python library)
- `paho-mqtt` package (for MQTT functionality)

## Installation

```bash
pip install meshcore paho-mqtt
```

## Configuration

The script uses a `config.ini` file for configuration. A default configuration file is created automatically on first run.

### Connection Settings
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

## Usage

```bash
# Basic usage with default config
python packet_capture.py

# Specify custom config file
python packet_capture.py --config my_config.ini

# Save output to file
python packet_capture.py --output packets.json

# Disable MQTT publishing
python packet_capture.py --no-mqtt

# Enable verbose output (shows JSON packet data)
python packet_capture.py --verbose

# Enable debug output (shows all detailed debugging info)
python packet_capture.py --debug
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
- `meshcore/raw`: Raw packet data
- `meshcore/decoded`: Decoded packet content

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
