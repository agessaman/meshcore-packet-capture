#!/usr/bin/env python3
"""
MeshCore Packet Capture Tool

Captures packets from MeshCore radios and outputs to console, file, and MQTT.
Compatible with both serial and BLE connections.

Usage:
    python packet_capture.py [--config config.ini] [--output output.json] [--verbose] [--debug] [--no-mqtt]

Options:
    --config     Configuration file (default: config.ini)
    --output     Output file for packet data
    --verbose    Show JSON packet data
    --debug      Show detailed debugging info
    --no-mqtt    Disable MQTT publishing

The script captures packet metadata including SNR, RSSI, route type, payload type,
and raw hex data. MQTT topics are configurable in the config file.
"""

import asyncio
import json
import logging
import hashlib
import time
import re
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
import argparse
import configparser

# Import the official meshcore package
import meshcore
from meshcore import EventType

# Import our enums for packet parsing
from enums import AdvertFlags, PayloadType, PayloadVersion, RouteType, DeviceRole

# Import MQTT client
try:
    import paho.mqtt.client as mqtt
except ImportError:
    print("Error: paho-mqtt not installed. Install with:")
    print("pip install paho-mqtt")
    exit(1)


class PacketCapture:
    """Standalone packet capture using meshcore package"""
    
    def __init__(self, config_file: str = "config.ini", output_file: Optional[str] = None, verbose: bool = False, debug: bool = False, enable_mqtt: bool = True):
        self.config_file = config_file
        self.output_file = output_file
        self.verbose = verbose
        self.debug = debug
        self.enable_mqtt = enable_mqtt
        self.config = configparser.ConfigParser()
        self.load_config()
        
        # Setup logging
        self.setup_logging()
        
        # Connection
        self.meshcore = None
        self.connected = False
        self.connection_retry_count = 0
        self.max_connection_retries = self.config.getint('connection', 'max_connection_retries', fallback=5)
        self.connection_retry_delay = self.config.getint('connection', 'connection_retry_delay', fallback=5)
        self.health_check_interval = self.config.getint('connection', 'health_check_interval', fallback=30)
        
        # MQTT connection
        self.mqtt_client = None
        self.mqtt_connected = False
        self.mqtt_retry_count = 0
        self.max_mqtt_retries = self.config.getint('mqtt', 'max_mqtt_retries', fallback=5)
        self.mqtt_retry_delay = self.config.getint('mqtt', 'mqtt_retry_delay', fallback=5)
        
        # Packet correlation cache
        self.rf_data_cache = {}
        self.packet_count = 0
        
        # Opted-in IDs for advert filtering (mirroring mctomqtt.py)
        self.opted_in_ids = []
        
        # Device information
        self.device_name = None
        self.device_public_key = None
        
        # Output file handle
        self.output_handle = None
        if self.output_file:
            self.output_handle = open(self.output_file, 'w')
            self.logger.info(f"Output will be written to: {self.output_file}")
    
    def load_config(self):
        """Load configuration from file"""
        if not Path(self.config_file).exists():
            self.create_default_config()
        
        self.config.read(self.config_file)
    
    def create_default_config(self):
        """Create default configuration file"""
        default_config = """[connection]
# Connection type: serial or ble or tcp
connection_type = ble

# Serial port (for serial connection)
serial_port = /dev/ttyUSB0

# BLE address (for BLE connection) - format: "12:34:56:78:90:AB" or "78212A67-3FF9-83AD-D3F0-3B432DDEB5F9"
#ble_address = 12:34:56:78:90:AB

# BLE device name (for BLE connection) - will scan and match by name
#ble_device_name = MeshCore-HOWL

# TCP socket format: "hostname:port"
#tcp_socket = localhost:5000

# Connection timeout in seconds
timeout = 30

# Reconnection settings
# Maximum number of connection retry attempts (0 = infinite)
max_connection_retries = 5
# Delay between connection retry attempts in seconds
connection_retry_delay = 5
# Connection health check interval in seconds
health_check_interval = 30

[mqtt]
# MQTT broker settings
server = localhost
port = 1883
username = 
password = 
client_id_prefix = meshcore_
qos = 0
retain = true

# MQTT reconnection settings
# Maximum number of MQTT retry attempts (0 = infinite)
max_mqtt_retries = 5
# Delay between MQTT retry attempts in seconds
mqtt_retry_delay = 5

[topics]
# MQTT topic structure (mirroring mctomqtt.py)
status = meshcore/status
raw = meshcore/raw
decoded = meshcore/decoded
packets = meshcore/packets
debug = meshcore/debug

[packetcapture]
# Origin identifier for captured packets (fallback when device name unavailable)
origin = PacketCapture Nodes
# Manual origin_id override (fallback when device public key unavailable)
#origin_id = your_custom_origin_id_here

"""
        with open(self.config_file, 'w') as f:
            f.write(default_config)
        print(f"Created default config file: {self.config_file}")
    
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        self.logger = logging.getLogger('PacketCapture')
    
    async def check_connection_health(self) -> bool:
        """Check if the MeshCore connection is still healthy"""
        try:
            if not self.meshcore or not self.meshcore.is_connected:
                self.logger.warning("MeshCore connection is not active")
                return False
            
            # Try to get device info as a health check
            if hasattr(self.meshcore, 'self_info') and self.meshcore.self_info:
                self.logger.debug("Connection health check passed")
                return True
            else:
                self.logger.warning("Connection health check failed - no device info")
                return False
                
        except Exception as e:
            self.logger.warning(f"Connection health check failed: {e}")
            return False
    
    async def connect(self) -> bool:
        """Connect to MeshCore node using official package"""
        try:
            self.logger.info("Connecting to MeshCore node...")
            
            # Get connection type from config
            connection_type = self.config.get('connection', 'connection_type', fallback='ble').lower()
            self.logger.info(f"Using connection type: {connection_type}")
            
            if connection_type == 'serial':
                # Create serial connection
                serial_port = self.config.get('connection', 'serial_port', fallback='/dev/ttyUSB0')
                self.logger.info(f"Connecting via serial port: {serial_port}")
                self.meshcore = await meshcore.MeshCore.create_serial(serial_port, debug=False)
            elif connection_type == 'tcp':
                # Create tcp connection
                tcp_socket = self.config.get('connection', 'tcp_socket', fallback='localhost:5000')
                host, _, port = tcp_socket.partition(':')
                port = int(port) if port else 5000
                self.logger.info(f"Connecting via tcp: {host}:{port}")
                self.meshcore = await meshcore.MeshCore.create_tcp(host, port, debug=False)
            else:
                # Create BLE connection (default)
                ble_address = self.config.get('connection', 'ble_address', fallback=None)
                ble_device_name = self.config.get('connection', 'ble_device_name', fallback=None)
                
                if ble_address:
                    # Direct address connection
                    self.logger.info(f"Connecting via BLE to address: {ble_address}")
                    self.meshcore = await meshcore.MeshCore.create_ble(ble_address, debug=False)
                elif ble_device_name:
                    # Try to find device by name - the meshcore library handles name matching internally
                    self.logger.info(f"Scanning for BLE device with name: {ble_device_name}")
                    try:
                        # The meshcore library will automatically find devices by name during scanning
                        self.meshcore = await meshcore.MeshCore.create_ble(ble_device_name, debug=False)
                    except Exception as e:
                        self.logger.error(f"Error connecting to device '{ble_device_name}': {e}")
                        # Fallback to general scan
                        self.logger.info("Falling back to general BLE scan...")
                        self.meshcore = await meshcore.MeshCore.create_ble(debug=False)
                else:
                    # No specific device, just scan and connect to first available
                    self.logger.info("Scanning for available BLE devices...")
                    self.meshcore = await meshcore.MeshCore.create_ble(debug=False)
            
            if self.meshcore.is_connected:
                self.connected = True
                self.logger.info(f"Connected to: {self.meshcore.self_info}")
                
                # Store device information for origin field
                if self.meshcore.self_info:
                    self.device_name = self.meshcore.self_info.get('name', 'Unknown')
                    self.device_public_key = self.meshcore.self_info.get('public_key', 'Unknown')
                    self.logger.info(f"Device name: {self.device_name}")
                    self.logger.info(f"Device public key: {self.device_public_key}")
                
                return True
            else:
                self.logger.error("Failed to connect to MeshCore node")
                return False
                
        except Exception as e:
            self.logger.error(f"Connection failed: {e}")
            return False
    
    async def reconnect_meshcore(self) -> bool:
        """Attempt to reconnect to MeshCore device with retry logic"""
        if self.max_connection_retries > 0 and self.connection_retry_count >= self.max_connection_retries:
            self.logger.error(f"Maximum connection retry attempts ({self.max_connection_retries}) reached")
            return False
        
        self.connection_retry_count += 1
        self.logger.info(f"Attempting MeshCore reconnection (attempt {self.connection_retry_count}/{self.max_connection_retries if self.max_connection_retries > 0 else '∞'})...")
        
        # Clean up existing connection
        if self.meshcore:
            try:
                await self.meshcore.disconnect()
            except Exception as e:
                self.logger.debug(f"Error disconnecting during reconnect: {e}")
            self.meshcore = None
        
        # Wait before retrying
        if self.connection_retry_delay > 0:
            self.logger.info(f"Waiting {self.connection_retry_delay} seconds before retry...")
            await asyncio.sleep(self.connection_retry_delay)
        
        # Attempt to reconnect
        success = await self.connect()
        if success:
            self.connection_retry_count = 0  # Reset counter on successful connection
            self.logger.info("MeshCore reconnection successful")
        else:
            self.logger.warning(f"MeshCore reconnection attempt {self.connection_retry_count} failed")
        
        return success
    
    async def connection_monitor(self):
        """Monitor connection health and attempt reconnection if needed"""
        self.logger.info(f"Starting connection monitoring (health check every {self.health_check_interval} seconds)")
        
        while self.connected:
            try:
                await asyncio.sleep(self.health_check_interval)
                
                if not self.connected:
                    break
                
                # Check MeshCore connection health
                if not await self.check_connection_health():
                    self.logger.warning("MeshCore connection health check failed, attempting reconnection...")
                    
                    # Attempt to reconnect without changing self.connected
                    if await self.reconnect_meshcore():
                        self.logger.info("MeshCore reconnection successful, resuming packet capture")
                        
                        # Re-setup event handlers after reconnection
                        await self.setup_event_handlers()
                        await self.meshcore.start_auto_message_fetching()
                    else:
                        self.logger.error("MeshCore reconnection failed, will retry on next health check")
                
            except asyncio.CancelledError:
                self.logger.debug("Connection monitoring cancelled")
                break
            except Exception as e:
                self.logger.error(f"Error in connection monitoring: {e}")
                await asyncio.sleep(5)  # Wait before retrying monitoring
    
    def sanitize_client_id(self, name):
        """Convert device name to valid MQTT client ID"""
        client_id = self.config.get("mqtt", "client_id_prefix", fallback="meshcore_client_") + name.replace(" ", "_")
        client_id = re.sub(r"[^a-zA-Z0-9_-]", "", client_id)
        return client_id[:23]
    
    def on_mqtt_connect(self, client, userdata, flags, rc, properties=None):
        if rc == 0:
            self.mqtt_connected = True
            self.logger.info("Connected to MQTT broker")
            # Publish online status once on connection
            self.publish_status("online")
        else:
            self.mqtt_connected = False
            self.logger.error(f"MQTT connection failed with code {rc}")

    def on_mqtt_disconnect(self, client, userdata, disconnect_flags, reason_code, properties):
        self.mqtt_connected = False
        self.logger.warning(f"Disconnected from MQTT broker (code: {reason_code}; flags: {disconnect_flags}; userdata: {userdata}; properties: {properties})")
        
        # Schedule MQTT reconnection attempt
        if reason_code != 0:  # Only attempt reconnection for unexpected disconnections
            asyncio.create_task(self.reconnect_mqtt())
        else:
            self.logger.info("MQTT disconnected normally, continuing packet capture...")

    def connect_mqtt(self):
        """Connect to MQTT broker"""
        if not self.device_name:
            self.logger.error("Cannot connect to MQTT without device name")
            return False

        client_id = self.sanitize_client_id(self.device_public_key or self.device_name)
        self.logger.info(f"Using MQTT client ID: {client_id}")
        
        self.mqtt_client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=client_id,
            clean_session=False
        )
        
        # Set username/password if configured
        username = self.config.get("mqtt", "username", fallback="")
        password = self.config.get("mqtt", "password", fallback="")
        if username:
            self.mqtt_client.username_pw_set(username, password)
        
        # Set Last Will and Testament
        lwt_topic = self.config.get("topics", "status")
        lwt_payload = json.dumps({
            "status": "offline",
            "timestamp": datetime.now().isoformat(),
            "device": self.device_name,
            "device_id": self.device_public_key
        })
        lwt_qos = self.config.getint("mqtt", "qos", fallback=1)
        lwt_retain = self.config.getboolean("mqtt", "retain", fallback=True)
        
        self.mqtt_client.will_set(
            lwt_topic,
            lwt_payload,
            qos=lwt_qos,
            retain=lwt_retain
        )
        
        self.logger.debug(f"Set LWT for topic: {lwt_topic}, payload: {lwt_payload}, QoS: {lwt_qos}, retain: {lwt_retain}")
        
        # Set callbacks
        self.mqtt_client.on_connect = self.on_mqtt_connect
        self.mqtt_client.on_disconnect = self.on_mqtt_disconnect
        
        # Connect to broker
        try:
            self.mqtt_client.loop_stop()
            self.mqtt_client.connect(
                self.config.get("mqtt", "server"),
                self.config.getint("mqtt", "port"),
                keepalive=30
            )

            self.mqtt_client.loop_start()
            self.logger.debug("MQTT loop started")
            return True
        except Exception as e:
            self.logger.error(f"MQTT connection error: {str(e)}")
            return False
    
    async def reconnect_mqtt(self):
        """Attempt to reconnect to MQTT broker with retry logic"""
        if self.max_mqtt_retries > 0 and self.mqtt_retry_count >= self.max_mqtt_retries:
            self.logger.error(f"Maximum MQTT retry attempts ({self.max_mqtt_retries}) reached")
            return False
        
        self.mqtt_retry_count += 1
        self.logger.info(f"Attempting MQTT reconnection (attempt {self.mqtt_retry_count}/{self.max_mqtt_retries if self.max_mqtt_retries > 0 else '∞'})...")
        
        # Wait before retrying
        if self.mqtt_retry_delay > 0:
            self.logger.info(f"Waiting {self.mqtt_retry_delay} seconds before MQTT retry...")
            await asyncio.sleep(self.mqtt_retry_delay)
        
        # Attempt to reconnect
        success = self.connect_mqtt()
        if success:
            self.mqtt_retry_count = 0  # Reset counter on successful connection
            self.logger.info("MQTT reconnection successful")
        else:
            self.logger.warning(f"MQTT reconnection attempt {self.mqtt_retry_count} failed")
        
        return success
    
    def publish_status(self, status):
        """Publish status with additional information"""
        status_msg = {
            "status": status,
            "timestamp": datetime.now().isoformat(),
            "device": self.device_name,
            "device_id": self.device_public_key
        }
        if self.safe_publish(self.config.get("topics", "status"), json.dumps(status_msg), retain=True):
            self.logger.debug(f"Published status: {status}")

    def safe_publish(self, topic, payload, retain=False):
        """Safely publish to MQTT broker"""
        if not self.mqtt_connected:
            self.logger.warning(f"Not connected - skipping publish to {topic}")
            return False

        try:
            qos = self.config.getint("mqtt", "qos", fallback=1)
            result = self.mqtt_client.publish(topic, payload, qos=qos, retain=retain)
            if result.rc != mqtt.MQTT_ERR_SUCCESS:
                self.logger.error(f"Publish failed to {topic}: {mqtt.error_string(result.rc)}")
                return False
            self.logger.debug(f"Published to {topic}: {payload}")
            return True
        except Exception as e:
            self.logger.error(f"Publish error to {topic}: {str(e)}")
            return False
    
    def parse_advert(self, payload):
        """Parse advert payload - matches C++ AdvertDataHelpers.h implementation"""
        try:
            # Validate minimum payload size
            if len(payload) < 101:
                self.logger.error(f"ADVERT payload too short: {len(payload)} bytes")
                return {}
            
            # advert header
            pub_key = payload[0:32]
            timestamp = int.from_bytes(payload[32:32+4], "little")
            signature = payload[36:36+64]

            # appdata - parse according to C++ AdvertDataParser
            app_data = payload[100:]
            if len(app_data) == 0:
                self.logger.error("ADVERT has no app data")
                return {}
            
            flags_byte = app_data[0]
            
            # Log the full flag byte for debugging
            self.logger.debug(f"ADVERT flags: 0x{flags_byte:02X} (binary: {flags_byte:08b})")
            
            # Create flags object with the full byte value
            flags = AdvertFlags(flags_byte)
            
            advert = {
                "public_key": pub_key.hex(),
                "advert_time": timestamp,
                "signature": signature.hex(),
            }

            # Extract type from lower 4 bits (matches C++ getType())
            adv_type = flags_byte & 0x0F
            if adv_type == AdvertFlags.ADV_TYPE_CHAT:
                advert.update({"mode": DeviceRole.Companion.name})
            elif adv_type == AdvertFlags.ADV_TYPE_REPEATER:
                advert.update({"mode": DeviceRole.Repeater.name})
            elif adv_type == AdvertFlags.ADV_TYPE_ROOM:
                advert.update({"mode": DeviceRole.RoomServer.name})
            elif adv_type == AdvertFlags.ADV_TYPE_SENSOR:
                advert.update({"mode": "Sensor"})
            else:
                advert.update({"mode": f"Type{adv_type}"})

            # Parse data according to C++ AdvertDataParser logic
            i = 1  # Start after flags byte
            
            # Parse location data if present (matches C++ hasLatLon())
            if AdvertFlags.ADV_LATLON_MASK in flags:
                if len(app_data) < i + 8:
                    self.logger.error(f"ADVERT with location flag too short: {len(app_data)} bytes")
                    return advert
                
                lat = int.from_bytes(app_data[i:i+4], 'little', signed=True)
                lon = int.from_bytes(app_data[i+4:i+8], 'little', signed=True)
                advert.update({"lat": round(lat / 1000000.0, 6), "lon": round(lon / 1000000.0, 6)})
                i += 8
            
            # Parse feat1 data if present
            if AdvertFlags.ADV_FEAT1_MASK in flags:
                if len(app_data) < i + 2:
                    self.logger.error(f"ADVERT with feat1 flag too short: {len(app_data)} bytes")
                    return advert
                feat1 = int.from_bytes(app_data[i:i+2], 'little')
                advert.update({"feat1": feat1})
                i += 2
            
            # Parse feat2 data if present
            if AdvertFlags.ADV_FEAT2_MASK in flags:
                if len(app_data) < i + 2:
                    self.logger.error(f"ADVERT with feat2 flag too short: {len(app_data)} bytes")
                    return advert
                feat2 = int.from_bytes(app_data[i:i+2], 'little')
                advert.update({"feat2": feat2})
                i += 2
            
            # Parse name data if present (matches C++ hasName())
            if AdvertFlags.ADV_NAME_MASK in flags:
                if len(app_data) >= i:
                    name_len = len(app_data) - i
                    if name_len > 0:
                        try:
                            # Decode name and handle potential null terminators
                            name = app_data[i:].decode('utf-8', errors='ignore').rstrip('\x00')
                            advert.update({"name": name})
                        except Exception as e:
                            self.logger.warning(f"Failed to decode ADVERT name: {e}")

            return advert
            
        except Exception as e:
            self.logger.error(f"Error parsing ADVERT payload: {e}", exc_info=True)
            return {}

    def decode_and_publish_message(self, raw_data):
        """Decode message - matches Packet.cpp exactly"""
        self.logger.debug(f"raw_data to parse: {raw_data}")
        byte_data = bytes.fromhex(raw_data)
        try:
            # Validate minimum packet size
            if len(byte_data) < 2:
                self.logger.error(f"Packet too short: {len(byte_data)} bytes")
                return None
            
            header = byte_data[0]

            # Extract route type
            route_type = RouteType(header & 0x03)
            has_transport = route_type in [RouteType.TRANSPORT_FLOOD, RouteType.TRANSPORT_DIRECT]
            
            # Calculate path length offset based on presence of transport codes
            offset = 1
            if has_transport:
                offset += 4
            
            # Check if we have enough data for path_len
            if len(byte_data) <= offset:
                self.logger.error(f"Packet too short for path_len at offset {offset}: {len(byte_data)} bytes")
                return None
            
            path_len = byte_data[offset]
            offset += 1
            
            # Check if we have enough data for the full path
            if len(byte_data) < offset + path_len:
                self.logger.error(f"Packet too short for path (need {offset + path_len}, have {len(byte_data)})")
                return None
            
            # Extract path
            path = byte_data[offset:offset + path_len].hex()
            offset += path_len
            
            # Remaining data is payload
            payload = byte_data[offset:]
            
            # Extract payload version (bits 6-7)
            payload_version = PayloadVersion((header >> 6) & 0x03)
            
            # Only accept VER_1 (version 0)
            if payload_version != PayloadVersion.VER_1:
                self.logger.warning(f"Encountered an unknown packet version. Version: {payload_version.value} RAW: {raw_data}")
                return None

            # Extract payload type (bits 2-5)
            payload_type = PayloadType((header >> 2) & 0x0F)

            # Convert path to list of hex values
            path_values = []
            i = 0
            while i < len(path):
                path_values.append(path[i:i+2])
                i += 2
            
            message = {
                "payload_type": payload_type.name,
                "payload_type_value": payload_type.value,
                "payload_version": payload_version.name,
                "route_type": route_type.name,
                "path": path_values
            }
        
            payload_value = {}
            if payload_type is PayloadType.ADVERT:
                payload_value = self.parse_advert(payload)
            
            if payload_type is PayloadType.ADVERT:
                key_prefix = payload_value["public_key"][:2]
                if payload_value["name"].endswith("^"):
                    message.update(payload_value)
                elif key_prefix not in self.opted_in_ids:
                    self.opted_in_ids.append(key_prefix)
            else:
                message.update(payload_value)
                
            self.logger.debug(f"Successfully decoded: route={message['route_type']}, type={message['payload_type']}")
            return message
            
        except Exception as e:
            # Log as ERROR not DEBUG so we can see what's failing
            self.logger.error(f"Error decoding packet (len={len(byte_data)}): {e}", exc_info=True)
            self.logger.error(f"Failed packet hex: {raw_data}")
            return None
    
    def calculate_packet_hash(self, raw_hex: str, payload_type: int = None) -> str:
        """Calculate hash for packet identification - based on packet.cpp"""
        try:
            # Parse the packet to extract payload type and payload data
            byte_data = bytes.fromhex(raw_hex)
            header = byte_data[0]
            
            # Get payload type from header (bits 2-5)
            if payload_type is None:
                payload_type = (header >> 2) & 0x0F
            
            # Check if transport codes are present
            route_type = header & 0x03
            has_transport = route_type in [0x00, 0x03]  # TRANSPORT_FLOOD or TRANSPORT_DIRECT
            
            # Calculate path length offset dynamically based on transport codes
            offset = 1  # After header
            if has_transport:
                offset += 4  # Skip 4 bytes of transport codes
            
            # Read path_len (1 byte on wire, but stored as uint16_t in C++)
            path_len = byte_data[offset]
            offset += 1
            
            # Skip past the path to get to payload
            payload_start = offset + path_len
            payload_data = byte_data[payload_start:]
            
            # Calculate hash exactly like MeshCore Packet::calculatePacketHash():
            # 1. Payload type (1 byte)
            # 2. Path length (2 bytes as uint16_t, little-endian) - ONLY for TRACE packets (type 9)
            # 3. Payload data
            hash_obj = hashlib.sha256()
            hash_obj.update(bytes([payload_type]))
            
            if payload_type == 9:  # PAYLOAD_TYPE_TRACE
                # C++ does: sha.update(&path_len, sizeof(path_len))
                # path_len is uint16_t, so sizeof(path_len) = 2 bytes
                # Convert path_len to 2-byte little-endian uint16_t
                hash_obj.update(path_len.to_bytes(2, byteorder='little'))
            
            hash_obj.update(payload_data)
            
            # Return first 16 hex characters (8 bytes) in uppercase
            return hash_obj.hexdigest()[:16].upper()
        except Exception as e:
            self.logger.debug(f"Error calculating hash: {e}")
            return "0000000000000000"
    
    def format_packet_data(self, raw_hex: str, rf_data: Optional[Dict] = None) -> Dict[str, Any]:
        """Format packet data to match mctomqtt.py exactly"""
        current_time = datetime.now()
        timestamp = current_time.isoformat()
        
        # Decode packet using the same logic as mctomqtt.py
        decoded_message = self.decode_and_publish_message(raw_hex)
        
        # Extract basic info
        packet_len = len(raw_hex) // 2  # Convert hex string to byte count
        
        # Get route type from decoded message
        route = "U"  # Default
        packet_type = "0"  # Default
        payload_len = "0"  # Default
        
        # Initialize firmware payload length early
        firmware_payload_len = None
        if rf_data:
            firmware_payload_len = rf_data.get('payload_length')
        
        if decoded_message:
            # Map route type names to single letters like mctomqtt.py
            route_map = {
                "TRANSPORT_FLOOD": "F",
                "FLOOD": "F", 
                "DIRECT": "D",
                "TRANSPORT_DIRECT": "T"
            }
            route = route_map.get(decoded_message.get('route_type', ''), "U")
            
            # Get payload type as string - now matches C++ definitions exactly
            payload_type_map = {
                "REQ": "0",
                "RESPONSE": "1", 
                "TXT_MSG": "2",
                "ACK": "3",
                "ADVERT": "4",
                "GRP_TXT": "5",
                "GRP_DATA": "6",
                "ANON_REQ": "7",
                "PATH": "8",
                "TRACE": "9",
                "MULTIPART": "10",
                "Type11": "11",
                "Type12": "12",
                "Type13": "13",
                "Type14": "14",
                "RAW_CUSTOM": "15"
            }
            packet_type = payload_type_map.get(decoded_message.get('payload_type', ''), "0")
            
            # Use firmware-provided payload length if available, otherwise calculate
            if firmware_payload_len is not None:
                payload_len = str(firmware_payload_len)
            else:
                # Fallback calculation if firmware doesn't provide it
                if decoded_message and 'path' in decoded_message:
                    # Calculate actual payload length from the raw data
                    # Total bytes - header(1) - transport(4 if present) - path_length(1) - path_bytes
                    path_len_bytes = len(decoded_message['path']) // 2  # Convert hex chars to bytes
                    has_transport = decoded_message.get('route_type') in ['TRANSPORT_FLOOD', 'TRANSPORT_DIRECT']
                    transport_bytes = 4 if has_transport else 0
                    payload_len = str(max(0, packet_len - 1 - transport_bytes - 1 - path_len_bytes))
                else:
                    # Fallback calculation
                    payload_len = str(max(0, packet_len - 1))
        
        # Get origin_id (use device info if available, otherwise use config or generate)
        origin_id = None
        if self.device_public_key and self.device_public_key != 'Unknown':
            origin_id = self.device_public_key
        else:
            # Try to get from config as fallback
            origin_id = self.config.get('packetcapture', 'origin_id', fallback=None)
            if not origin_id:
                # Generate a hash from device name as last resort
                device_name = self.device_name or 'Unknown'
                origin_id = hashlib.sha256(device_name.encode()).hexdigest()
                self.logger.warning(f"Using generated origin_id from device name: {origin_id}")
        
        # Extract RF data if available
        snr = "Unknown"
        rssi = "Unknown"
        
        if rf_data:
            snr = str(rf_data.get('snr', 'Unknown'))
            rssi = str(rf_data.get('rssi', 'Unknown'))
        
        # Build the packet data structure to match mctomqtt.py exactly
        packet_data = {
            "origin": self.device_name or self.config.get('packetcapture', 'origin', fallback='Unknown'),
            "origin_id": origin_id,
            "timestamp": timestamp,
            "type": "PACKET",
            "direction": "rx",
            "time": current_time.strftime("%H:%M:%S"),
            "date": current_time.strftime("%d/%m/%Y"),
            "len": str(packet_len),
            "packet_type": packet_type,
            "route": route,
            "payload_len": payload_len,
            "raw": raw_hex.upper(),
            "SNR": snr,
            "RSSI": rssi,
            "hash": self.calculate_packet_hash(raw_hex, decoded_message.get('payload_type_value') if decoded_message else None)
        }
        
        # Add path for route=D like mctomqtt.py
        if route == "D" and decoded_message and 'path' in decoded_message:
            packet_data["path"] = ",".join(decoded_message['path'])
        
        return packet_data
    
    async def handle_rf_log_data(self, event):
        """Handle RF log data events to cache SNR/RSSI information and process packets"""
        try:
            payload = event.payload
            
            if 'snr' in payload:
                # Try to get packet data - prefer 'payload' field, fallback to 'raw_hex'
                raw_hex = None
                
                # First, try the 'payload' field (already stripped of framing bytes)
                if 'payload' in payload and payload['payload']:
                    raw_hex = payload['payload']
                    self.logger.debug(f"Using 'payload' field from RF data")
                # Fallback to raw_hex with first 2 bytes stripped
                elif 'raw_hex' in payload and payload['raw_hex']:
                    raw_hex = payload['raw_hex'][4:]  # Skip first 2 bytes (4 hex chars)
                    self.logger.debug(f"Using 'raw_hex' field (stripped) from RF data")
                
                if raw_hex:
                    packet_prefix = raw_hex[:32]
                    
                    rf_data = {
                        'snr': payload.get('snr'),
                        'rssi': payload.get('rssi'),
                        'timestamp': time.time(),
                        'raw_hex': raw_hex,
                        'payload_length': payload.get('payload_length')
                    }
                    
                    self.rf_data_cache[packet_prefix] = rf_data
                    
                    # Clean up old cache entries
                    current_time = time.time()
                    timeout = self.config.getfloat('PacketCapture', 'rf_data_timeout', fallback=15.0)
                    self.rf_data_cache = {
                        k: v for k, v in self.rf_data_cache.items()
                        if current_time - v['timestamp'] < timeout
                    }
                    
                    self.logger.debug(f"Cached RF data for packet: {packet_prefix[:16]}...")
                    
                    # Process the packet
                    await self.process_packet_from_rf_data(raw_hex, rf_data)
                else:
                    self.logger.warning(f"RF log data missing both 'payload' and 'raw_hex' fields: {payload.keys()}")
                        
        except Exception as e:
            self.logger.error(f"Error handling RF log data: {e}", exc_info=True)
    
    async def process_packet_from_rf_data(self, raw_hex: str, rf_data: dict):
        """Process packet data from RF log data"""
        try:
            # Format packet data
            packet_data = self.format_packet_data(raw_hex, rf_data)
            
            # Output the packet data
            self.output_packet(packet_data)
            
            self.packet_count += 1
            self.logger.info(f"📦 Captured packet #{self.packet_count}: {packet_data['route']} type {packet_data['packet_type']}, {packet_data['len']} bytes, SNR: {packet_data['SNR']}, RSSI: {packet_data['RSSI']}, hash: {packet_data['hash']}")
            
            # Output full packet data structure in verbose or debug mode
            if self.verbose or self.debug:
                self.logger.info("📋 Full packet data structure:")
                import json
                self.logger.info(json.dumps(packet_data, indent=2))
            
        except Exception as e:
            self.logger.error(f"Error processing packet from RF data: {e}")
    
    async def handle_raw_data(self, event):
        """Handle raw data events (full packet data)"""
        try:
            payload = event.payload
            self.logger.info(f"📦 RAW_DATA EVENT RECEIVED")
            
            # Extract raw hex data
            raw_hex = None
            if hasattr(payload, 'data'):
                raw_hex = payload.data
            elif 'data' in payload:
                raw_hex = payload['data']
            elif 'raw_hex' in payload:
                raw_hex = payload['raw_hex']
            
            if raw_hex:
                # Remove 0x prefix if present
                if raw_hex.startswith('0x'):
                    raw_hex = raw_hex[2:]
                
                # Find corresponding RF data
                packet_prefix = raw_hex[:32]
                rf_data = self.rf_data_cache.get(packet_prefix)
                
                # Format packet data
                packet_data = self.format_packet_data(raw_hex, rf_data)
                
                # Output the packet data
                self.output_packet(packet_data)
                
                self.packet_count += 1
                self.logger.info(f"Captured packet #{self.packet_count}: {packet_data['route']} type {packet_data['packet_type']}, {packet_data['len']} bytes")
                
        except Exception as e:
            self.logger.error(f"Error handling raw data event: {e}")
    
    def output_packet(self, packet_data: Dict[str, Any]):
        """Output packet data to console, file, and MQTT"""
        # Convert to JSON
        json_data = json.dumps(packet_data, indent=2)
        
        # Output to console only in verbose or debug mode
        if self.verbose or self.debug:
            print("=" * 80)
            print(json_data)
            print("=" * 80)
        
        # Output to file if specified
        if self.output_handle:
            self.output_handle.write(json_data + "\n")
            self.output_handle.flush()
        
        # Publish to MQTT if enabled
        if self.enable_mqtt:
            self.safe_publish(self.config.get("topics", "packets"), json.dumps(packet_data))
            
            # Also publish raw data if available
            if 'raw' in packet_data:
                raw_message = {
                    "origin": packet_data.get("origin"),
                    "origin_id": packet_data.get("origin_id"),
                    "timestamp": packet_data.get("timestamp"),
                    "type": "RAW",
                    "data": packet_data.get("raw")
                }
                self.safe_publish(self.config.get("topics", "raw"), json.dumps(raw_message))
                
                # Try to decode and publish decoded message
                try:
                    decoded_message = self.decode_and_publish_message(packet_data.get("raw"))
                    if decoded_message is not None:
                        self.safe_publish(self.config.get("topics", "decoded"), json.dumps(decoded_message))
                except Exception as e:
                    self.logger.debug(f"Error decoding packet for MQTT: {e}")
    
    async def setup_event_handlers(self):
        """Setup event handlers for packet capture"""
        # Handle RF log data for SNR/RSSI information
        async def on_rf_data(event):
            self.logger.debug(f"RF_DATA event received: {event}")
            await self.handle_rf_log_data(event)
        
        # Handle raw data events (full packet data)
        async def on_raw_data(event):
            self.logger.debug(f"RAW_DATA event received: {event}")
            await self.handle_raw_data(event)
        
        # Handle status response events
        async def on_status_response(event):
            self.logger.debug(f"STATUS_RESPONSE event received: {event}")
            # Log the status data to see what's available
            if hasattr(event, 'payload') and event.payload:
                self.logger.info(f"Status data: {event.payload}")
        
        # Subscribe to events
        self.meshcore.subscribe(EventType.RX_LOG_DATA, on_rf_data)
        self.meshcore.subscribe(EventType.RAW_DATA, on_raw_data)
        self.meshcore.subscribe(EventType.STATUS_RESPONSE, on_status_response)
        
        self.logger.info("Event handlers setup complete")
        
        # Note: Packet capture mode is automatically enabled when subscribing to events
        self.logger.info("Packet capture mode enabled via event subscriptions")
    
    async def start(self):
        """Start packet capture"""
        self.logger.info("Starting MeshCore Packet Capture...")
        
        # Connect to MeshCore node
        if not await self.connect():
            self.logger.error("Failed to connect to MeshCore node")
            return
        
        # Connect to MQTT broker if enabled
        if self.enable_mqtt:
            if not self.connect_mqtt():
                self.logger.warning("Failed to connect to MQTT broker, continuing without MQTT...")
        else:
            self.logger.info("MQTT disabled, skipping MQTT connection")
        
        # Setup event handlers
        await self.setup_event_handlers()
        
        # Start auto message fetching
        await self.meshcore.start_auto_message_fetching()
        
        self.logger.info("Packet capture is running. Press Ctrl+C to stop.")
        self.logger.info("Waiting for packets...")
        
        # Start connection monitoring task
        monitoring_task = asyncio.create_task(self.connection_monitor())
        
        try:
            while self.connected:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Received interrupt signal")
        finally:
            monitoring_task.cancel()
            try:
                await monitoring_task
            except asyncio.CancelledError:
                pass
            await self.stop()
    
    async def stop(self):
        """Stop packet capture"""
        self.logger.info("Stopping packet capture...")
        self.connected = False
        
        # Publish offline status
        if self.enable_mqtt and self.mqtt_connected:
            self.publish_status("offline")
        
        if self.meshcore:
            await self.meshcore.disconnect()
        
        if self.mqtt_client:
            self.mqtt_client.disconnect()
            self.mqtt_client.loop_stop()
        
        if self.output_handle:
            self.output_handle.close()
        
        self.logger.info(f"Packet capture stopped. Total packets captured: {self.packet_count}")


async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='MeshCore Packet Capture Script')
    parser.add_argument('--config', default='config.ini', help='Configuration file path')
    parser.add_argument('--output', help='Output file path (optional)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output (shows JSON packet data)')
    parser.add_argument('--debug', action='store_true', help='Enable debug output (shows all detailed debugging info)')
    parser.add_argument('--no-mqtt', action='store_true', help='Disable MQTT publishing')
    
    args = parser.parse_args()
    
    # Create packet capture instance
    capture = PacketCapture(
        config_file=args.config, 
        output_file=args.output, 
        verbose=args.verbose,
        debug=args.debug,
        enable_mqtt=not args.no_mqtt
    )
    
    if args.debug:
        capture.logger.setLevel(logging.DEBUG)
    elif args.verbose:
        capture.logger.setLevel(logging.INFO)
    
    try:
        await capture.start()
    except KeyboardInterrupt:
        print("\nShutting down...")
    except Exception as e:
        print(f"Error: {e}")
        await capture.stop()


if __name__ == "__main__":
    asyncio.run(main())
