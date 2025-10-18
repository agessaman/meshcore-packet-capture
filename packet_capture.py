#!/usr/bin/env python3
"""
MeshCore Packet Capture Tool

Captures packets from MeshCore radios and outputs to console, file, and MQTT.
Compatible with both serial and BLE connections.

Usage:
    python packet_capture.py [--output output.json] [--verbose] [--debug] [--no-mqtt]

Options:
    --output     Output file for packet data
    --verbose    Show JSON packet data
    --debug      Show detailed debugging info
    --no-mqtt    Disable MQTT publishing

The script captures packet metadata including SNR, RSSI, route type, payload type,
and raw hex data. Configuration is done via environment variables and .env files.
"""

import asyncio
import json
import logging
import hashlib
import time
import re
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
import argparse

# Import meshcore from PyPI
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

# Import auth token module
try:
    from auth_token import create_auth_token, read_private_key_file
except ImportError:
    print("Warning: auth_token.py not found - auth token authentication will not be available")
    create_auth_token = None
    read_private_key_file = None

# Private key functionality using meshcore_py library


def load_env_files():
    """Load environment variables from .env and .env.local files"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    env_file = os.path.join(script_dir, '.env')
    env_local_file = os.path.join(script_dir, '.env.local')
    
    def parse_env_file(filepath):
        """Parse a .env file and return a dictionary"""
        env_vars = {}
        if not os.path.exists(filepath):
            return env_vars
        
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue
                # Parse KEY=VALUE
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    # Remove quotes if present
                    if value and value[0] in ('"', "'") and value[-1] == value[0]:
                        value = value[1:-1]
                    env_vars[key] = value
        return env_vars
    
    # Load .env first (defaults)
    env_vars = parse_env_file(env_file)
    
    # Load .env.local (overrides)
    local_vars = parse_env_file(env_local_file)
    env_vars.update(local_vars)
    
    # Set environment variables
    for key, value in env_vars.items():
        if key not in os.environ:
            os.environ[key] = value
    
    return env_vars


# Load environment configuration
load_env_files()


class PacketCapture:
    """Standalone packet capture using meshcore package"""
    
    def __init__(self, output_file: Optional[str] = None, verbose: bool = False, debug: bool = False, enable_mqtt: bool = True):
        self.output_file = output_file
        self.verbose = verbose
        self.debug = debug
        self.enable_mqtt = enable_mqtt
        
        # Setup logging
        self.setup_logging()
        
        # Global IATA for template resolution
        self.global_iata = os.getenv('PACKETCAPTURE_IATA', 'LOC').lower()
        
        # Connection
        self.meshcore = None
        self.connected = False
        self.connection_retry_count = 0
        self.max_connection_retries = self.get_env_int('MAX_CONNECTION_RETRIES', 5)
        self.connection_retry_delay = self.get_env_int('CONNECTION_RETRY_DELAY', 5)
        self.health_check_interval = self.get_env_int('HEALTH_CHECK_INTERVAL', 30)
        
        # MQTT connection
        self.mqtt_clients = []  # List of MQTT client info dictionaries
        self.mqtt_connected = False
        self.mqtt_retry_count = 0
        self.max_mqtt_retries = self.get_env_int('MAX_MQTT_RETRIES', 5)
        self.mqtt_retry_delay = self.get_env_int('MQTT_RETRY_DELAY', 5)
        self.should_exit = False  # Flag to exit when reconnection attempts fail
        self.exit_on_reconnect_fail = self.get_env_bool('EXIT_ON_RECONNECT_FAIL', True)
        
        # Packet correlation cache
        self.rf_data_cache = {}
        self.packet_count = 0
        
        # Opted-in IDs for advert filtering (mirroring mctomqtt.py)
        self.opted_in_ids = []
        
        # Device information
        self.device_name = None
        self.device_public_key = None
        self.device_private_key = None
        
        # Private key export capability
        self.private_key_export_available = False
        
        # JWT token management
        self.jwt_tokens = {}  # Store tokens per broker: {broker_num: {'token': str, 'expires_at': float}}
        self.jwt_renewal_interval = self.get_env_int('JWT_RENEWAL_INTERVAL', 3600)  # Check every hour
        self.jwt_renewal_threshold = self.get_env_int('JWT_RENEWAL_THRESHOLD', 300)  # Renew 5 minutes before expiry
        
        # Advert settings
        self.advert_interval_hours = self.get_env_int('ADVERT_INTERVAL_HOURS', 1)
        self.last_advert_time = 0
        self.advert_task = None
        
        # JWT renewal task
        self.jwt_renewal_task = None
        
        # Output file handle
        self.output_handle = None
        if self.output_file:
            self.output_handle = open(self.output_file, 'w')
            self.logger.info(f"Output will be written to: {self.output_file}")
    
    
    def setup_logging(self):
        """Setup logging configuration"""
        # Clear any existing handlers to avoid conflicts
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
        
        # Create a custom formatter with timestamp
        formatter = logging.Formatter(
            fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Create console handler with the formatter
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        
        # Configure root logger
        logging.basicConfig(
            level=logging.INFO,
            handlers=[console_handler],
            force=True
        )
        
        self.logger = logging.getLogger('PacketCapture')
        
        # Test the logging format
        self.logger.info("Logging initialized with timestamp format")
    
    def get_env(self, key, fallback=''):
        """Get environment variable with fallback (all vars are PACKETCAPTURE_ prefixed)"""
        full_key = f"PACKETCAPTURE_{key}"
        return os.getenv(full_key, fallback)
    
    def get_env_bool(self, key, fallback=False):
        """Get boolean environment variable"""
        value = self.get_env(key, str(fallback)).lower()
        return value in ('true', '1', 'yes', 'on')
    
    def get_env_int(self, key, fallback=0):
        """Get integer environment variable"""
        try:
            return int(self.get_env(key, str(fallback)))
        except ValueError:
            return fallback
    
    def get_env_float(self, key, fallback=0.0):
        """Get float environment variable"""
        try:
            return float(self.get_env(key, str(fallback)))
        except ValueError:
            return fallback
    
    def base64url_encode(self, data: bytes) -> str:
        """Base64url encode without padding"""
        import base64
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')
    
    def resolve_topic_template(self, template, broker_num=None):
        """Resolve topic template with {IATA}, {IATA_lower}, and {PUBLIC_KEY} placeholders"""
        if not template:
            return template
        
        # Get IATA - broker-specific or global
        iata = self.global_iata
        if broker_num:
            broker_iata = self.get_env(f'MQTT{broker_num}_IATA', '')
            if broker_iata:
                iata = broker_iata.lower()
        
        # Replace template variables
        resolved = template.replace('{IATA}', iata.upper())  # Uppercase variant
        resolved = resolved.replace('{IATA_lower}', iata.lower())  # Lowercase variant
        resolved = resolved.replace('{PUBLIC_KEY}', self.device_public_key if self.device_public_key and self.device_public_key != 'Unknown' else 'DEVICE')
        return resolved
    
    def get_topic(self, topic_type, broker_num=None):
        """Get topic with template resolution, checking broker-specific override first"""
        topic_type_upper = topic_type.upper()
        
        # Check broker-specific topic override
        if broker_num:
            broker_topic = self.get_env(f'MQTT{broker_num}_TOPIC_{topic_type_upper}', '')
            if broker_topic:
                return self.resolve_topic_template(broker_topic, broker_num)
        
        # Fall back to global topic
        global_topic = self.get_env(f'TOPIC_{topic_type_upper}', '')
        if global_topic:
            return self.resolve_topic_template(global_topic, broker_num)
        
        # For RAW topic, don't provide a default - only publish if explicitly configured
        if topic_type_upper == 'RAW':
            if self.debug:
                self.logger.debug(f"No RAW topic configured for broker {broker_num}, skipping RAW publish")
            return None
        
        # CRITICAL FIX: Always provide a valid default topic for other types
        default_topics = {
            'STATUS': 'meshcore/status',
            'DECODED': 'meshcore/decoded',
            'PACKETS': 'meshcore/packets',
            'DEBUG': 'meshcore/debug'
        }
        
        default_topic = default_topics.get(topic_type_upper, f'meshcore/{topic_type.lower()}')
        resolved = self.resolve_topic_template(default_topic, broker_num)
        
        # Log if we're using default
        if self.debug:
            self.logger.debug(f"Using default topic for {topic_type}: {resolved}")
        return resolved
    
    async def fetch_private_key_from_device(self) -> bool:
        """Fetch private key from device using meshcore library"""
        try:
            self.logger.info("Fetching private key from device...")
            
            if not self.meshcore or not self.meshcore.is_connected:
                self.logger.error("Cannot fetch private key - not connected to device")
                return False
            
            # Use meshcore library to export private key
            result = await self.meshcore.commands.export_private_key()
            
            if result.type == EventType.PRIVATE_KEY:
                self.device_private_key = result.payload["private_key"]
                self.logger.info("✓ Private key fetched successfully from device")
                self.private_key_export_available = True
                return True
            elif result.type == EventType.DISABLED:
                self.logger.warning("Private key export is disabled on this device")
                self.logger.info("This feature requires:")
                self.logger.info("  - Companion radio firmware")
                self.logger.info("  - ENABLE_PRIVATE_KEY_EXPORT=1 compile-time flag")
                self.private_key_export_available = False
                return False
            elif result.type == EventType.ERROR:
                self.logger.error(f"Error fetching private key: {result.payload}")
                self.private_key_export_available = False
                return False
            else:
                self.logger.error(f"Unexpected response when fetching private key: {result.type}")
                self.private_key_export_available = False
                return False
                
        except Exception as e:
            self.logger.error(f"Error fetching private key from device: {e}")
            self.private_key_export_available = False
            return False
    
    
    
    async def create_jwt_with_private_key(self, audience: str = None) -> Optional[str]:
        """Create JWT using private key from device"""
        try:
            if not self.device_private_key or not create_auth_token:
                return None
            
            # Convert bytearray to hex string if needed
            private_key = self.device_private_key
            if isinstance(private_key, (bytes, bytearray)):
                private_key = private_key.hex()
            
            # Use the existing auth_token method
            claims = {}
            if audience:
                claims['aud'] = audience
            
            jwt_token = create_auth_token(self.device_public_key, private_key, **claims)
            self.logger.info("✓ JWT created using private key from device")
            return jwt_token
            
        except Exception as e:
            self.logger.error(f"Error creating JWT with private key: {e}")
            return None
    
    async def create_auth_token_jwt(self, audience: str = None, broker_num: int = None) -> Optional[str]:
        """Create JWT token using private key from device"""
        # Use private key method (fetched from device)
        jwt_token = await self.create_jwt_with_private_key(audience)
        if jwt_token:
            if audience and ('mqtt' in audience.lower() or 'letsmesh' in audience.lower()):
                self.logger.info("✓ JWT created using private key from device for MQTT authentication")
            else:
                self.logger.info("✓ JWT created using private key from device")
            
            # Store token with expiry time if broker_num is provided
            if broker_num is not None:
                import time
                import json
                import base64
                
                # Parse token to get expiry time
                try:
                    parts = jwt_token.split('.')
                    if len(parts) == 3:
                        # Decode payload to get expiry
                        payload_data = base64.urlsafe_b64decode(parts[1] + '==')
                        payload = json.loads(payload_data)
                        expires_at = payload.get('exp', time.time() + 86400)  # Default 24h if not found
                        
                        self.jwt_tokens[broker_num] = {
                            'token': jwt_token,
                            'expires_at': expires_at,
                            'audience': audience
                        }
                        
                        if self.debug:
                            self.logger.debug(f"JWT token stored for broker {broker_num}, expires at {expires_at}")
                except Exception as e:
                    self.logger.warning(f"Could not parse JWT expiry: {e}")
            
            return jwt_token
        
        self.logger.error("Failed to create JWT with private key from device")
        return None
    
    def is_jwt_token_expired(self, broker_num: int) -> bool:
        """Check if JWT token for broker is expired or near expiry"""
        if broker_num not in self.jwt_tokens:
            return True
        
        import time
        current_time = time.time()
        token_info = self.jwt_tokens[broker_num]
        expires_at = token_info['expires_at']
        
        # Check if token is expired or within renewal threshold
        return current_time >= (expires_at - self.jwt_renewal_threshold)
    
    async def renew_jwt_token(self, broker_num: int) -> bool:
        """Renew JWT token for a specific broker"""
        try:
            if broker_num not in self.jwt_tokens:
                self.logger.warning(f"No existing JWT token for broker {broker_num}")
                return False
            
            token_info = self.jwt_tokens[broker_num]
            audience = token_info.get('audience')
            
            self.logger.info(f"Renewing JWT token for broker {broker_num}...")
            
            # Create new token
            new_token = await self.create_auth_token_jwt(audience, broker_num)
            if new_token:
                self.logger.info(f"✓ JWT token renewed for broker {broker_num}")
                return True
            else:
                self.logger.error(f"Failed to renew JWT token for broker {broker_num}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error renewing JWT token for broker {broker_num}: {e}")
            return False
    
    async def check_and_renew_jwt_tokens(self):
        """Check all JWT tokens and renew if needed"""
        try:
            for broker_num in list(self.jwt_tokens.keys()):
                if self.is_jwt_token_expired(broker_num):
                    self.logger.info(f"JWT token for broker {broker_num} needs renewal")
                    
                    # Renew the token first
                    renewal_success = await self.renew_jwt_token(broker_num)
                    if not renewal_success:
                        self.logger.error(f"Failed to renew JWT token for broker {broker_num}, skipping reconnection")
                        continue
                    
                    # Only reconnect if token renewal was successful
                    self.logger.info(f"Reconnecting MQTT broker {broker_num} with new token...")
                    reconnection_success = await self.reconnect_mqtt_broker_with_new_token(broker_num)
                    if reconnection_success:
                        self.logger.info(f"✓ MQTT broker {broker_num} successfully reconnected with new JWT token")
                    else:
                        self.logger.error(f"Failed to reconnect MQTT broker {broker_num} with new token")
                    
        except Exception as e:
            self.logger.error(f"Error checking JWT token renewals: {e}")
    
    async def reconnect_mqtt_broker_with_new_token(self, broker_num: int):
        """Reconnect MQTT broker with renewed JWT token"""
        try:
            # Find the broker in our client list
            broker_info = None
            for client_info in self.mqtt_clients:
                if client_info['broker_num'] == broker_num:
                    broker_info = client_info
                    break
            
            if not broker_info:
                self.logger.warning(f"Broker {broker_num} not found in client list")
                return False
            
            # Check if broker uses auth tokens
            use_auth_token = self.get_env_bool(f'MQTT{broker_num}_USE_AUTH_TOKEN', False)
            if not use_auth_token:
                self.logger.debug(f"Broker {broker_num} doesn't use auth tokens, skipping renewal")
                return True
            
            # Get new token
            if broker_num not in self.jwt_tokens:
                self.logger.error(f"No JWT token available for broker {broker_num}")
                return False
            
            new_token = self.jwt_tokens[broker_num]['token']
            audience = self.jwt_tokens[broker_num].get('audience', '')
            
            # Disconnect existing client
            mqtt_client = broker_info['client']
            if mqtt_client.is_connected():
                mqtt_client.loop_stop()
                mqtt_client.disconnect()
            
            # Create new client with new token
            username = f"v1_{self.device_public_key.upper()}"
            mqtt_client.username_pw_set(username, new_token)
            
            # Reconnect
            server = self.get_env(f'MQTT{broker_num}_SERVER', "")
            port = self.get_env_int(f'MQTT{broker_num}_PORT', 1883)
            keepalive = self.get_env_int(f'MQTT{broker_num}_KEEPALIVE', 60)
            
            # Connect and wait for connection to establish
            result = mqtt_client.connect(server, port, keepalive=keepalive)
            if result != mqtt.MQTT_ERR_SUCCESS:
                self.logger.error(f"Failed to initiate connection to MQTT{broker_num}: {mqtt.error_string(result)}")
                return False
            
            mqtt_client.loop_start()
            
            # Wait for connection to establish (with timeout)
            connection_timeout = 10  # seconds
            start_time = time.time()
            while not mqtt_client.is_connected() and (time.time() - start_time) < connection_timeout:
                await asyncio.sleep(0.1)
            
            if mqtt_client.is_connected():
                self.logger.info(f"✓ MQTT broker {broker_num} reconnected with new JWT token")
                return True
            else:
                self.logger.error(f"MQTT broker {broker_num} connection timeout after {connection_timeout}s")
                return False
            
        except Exception as e:
            self.logger.error(f"Error reconnecting MQTT broker {broker_num} with new token: {e}")
            return False
    
    
    

    async def check_connection_health(self) -> bool:
        """Check if the MeshCore connection is still healthy"""
        try:
            if not self.meshcore or not self.meshcore.is_connected:
                self.logger.warning("MeshCore connection is not active")
                return False
            
            # Primary health check: Verify device info is still available
            if hasattr(self.meshcore, 'self_info') and self.meshcore.self_info:
                if self.debug:
                    self.logger.debug("Connection health check passed (device info available)")
                return True
            
            # Secondary health check: Try a simple device query command
            if self.debug:
                self.logger.debug("Testing device connection health with device query...")
            try:
                result = await self.meshcore.commands.send_device_query()
                if result and hasattr(result, 'type') and result.type != EventType.ERROR:
                    if self.debug:
                        self.logger.debug("Connection health check passed (device query successful)")
                    return True
                else:
                    if self.debug:
                        self.logger.debug(f"Health check device query failed: {result}")
            except Exception as query_error:
                if self.debug:
                    self.logger.debug(f"Health check device query failed: {query_error}")
            
            # If we get here, the connection is not healthy
            self.logger.warning("Connection health check failed - no device info or query failed")
            return False
                
        except Exception as e:
            self.logger.warning(f"Connection health check failed: {e}")
            return False
    
    async def connect(self) -> bool:
        """Connect to MeshCore node using official package"""
        try:
            self.logger.info("Connecting to MeshCore node...")
            
            # Get connection type from environment
            connection_type = self.get_env('CONNECTION_TYPE', 'ble').lower()
            self.logger.info(f"Using connection type: {connection_type}")
            
            if connection_type == 'serial':
                # Create serial connection
                serial_port = self.get_env('SERIAL_PORTS', '/dev/ttyUSB0')
                # Handle comma-separated ports (take first one for now)
                if ',' in serial_port:
                    serial_port = serial_port.split(',')[0].strip()
                self.logger.info(f"Connecting via serial port: {serial_port}")
                self.meshcore = await meshcore.MeshCore.create_serial(serial_port, debug=False)
            elif connection_type == 'tcp':
                # Create TCP connection
                tcp_host = self.get_env('TCP_HOST', 'localhost')
                tcp_port = self.get_env_int('TCP_PORT', 5000)
                self.logger.info(f"Connecting via TCP to {tcp_host}:{tcp_port}")
                self.meshcore = await meshcore.MeshCore.create_tcp(tcp_host, tcp_port, debug=False)
            else:
                # Create BLE connection (default)
                # Support both BLE_ADDRESS and BLE_DEVICE for MAC address
                ble_address = self.get_env('BLE_ADDRESS', None) or self.get_env('BLE_DEVICE', None)
                # Support both BLE_DEVICE_NAME and BLE_NAME for device name
                ble_device_name = self.get_env('BLE_DEVICE_NAME', None) or self.get_env('BLE_NAME', None)
                
                if self.debug:
                    self.logger.debug(f"BLE connection config - Address: {ble_address}, Name: {ble_device_name}")
                    self.logger.debug(f"Environment check - BLE_ADDRESS: {self.get_env('BLE_ADDRESS', None)}, BLE_DEVICE: {self.get_env('BLE_DEVICE', None)}")
                    self.logger.debug(f"Environment check - BLE_DEVICE_NAME: {self.get_env('BLE_DEVICE_NAME', None)}, BLE_NAME: {self.get_env('BLE_NAME', None)}")
                
                if ble_address:
                    # Direct address connection
                    self.logger.info(f"Connecting via BLE to address: {ble_address}")
                    if self.debug:
                        self.logger.debug(f"Using BLE address from environment: {ble_address}")
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
                    # Normalize public key to uppercase
                    if self.device_public_key != 'Unknown':
                        self.device_public_key = self.device_public_key.upper()
                    self.logger.info(f"Device name: {self.device_name}")
                    self.logger.info(f"Device public key: {self.device_public_key}")
                    
                    # Setup JWT authentication using private key from device
                    self.logger.info("Setting up JWT authentication...")
                    
                    # Try to fetch private key from device first
                    private_key_fetch_success = await self.fetch_private_key_from_device()
                    
                    # Fallback: Try to get private key from environment variable
                    if not private_key_fetch_success:
                        env_private_key = self.get_env('PRIVATE_KEY', '')
                        if env_private_key:
                            self.device_private_key = env_private_key
                            self.logger.info(f"Device private key: {self.device_private_key[:4]}... (from environment)")
                        # Try to read from private key file
                        elif read_private_key_file:
                            private_key_file = self.get_env('PRIVATE_KEY_FILE', '')
                            if private_key_file and Path(private_key_file).exists():
                                try:
                                    self.device_private_key = read_private_key_file(private_key_file)
                                    self.logger.info(f"Device private key: {self.device_private_key[:4]}... (from file: {private_key_file})")
                                except Exception as e:
                                    self.logger.warning(f"Failed to read private key from file {private_key_file}: {e}")
                    
                    # Log authentication method status
                    if private_key_fetch_success:
                        self.logger.info("✓ JWT authentication: Private key from device")
                    elif self.device_private_key:
                        self.logger.info("✓ JWT authentication: Private key from environment/file")
                    else:
                        self.logger.info("❌ JWT authentication: Not available")
                        self.logger.info("To enable JWT authentication:")
                        self.logger.info("  1. Ensure device supports private key export (ENABLE_PRIVATE_KEY_EXPORT=1), or")
                        self.logger.info("  2. Set PACKETCAPTURE_PRIVATE_KEY environment variable, or")
                        self.logger.info("  3. Set PACKETCAPTURE_PRIVATE_KEY_FILE to point to a private key file, or")
                        self.logger.info("  4. Create a .env.local file with PACKETCAPTURE_PRIVATE_KEY=your_private_key_here")
                
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
        if self.debug:
            self.logger.debug(f"Starting connection monitoring (health check every {self.health_check_interval} seconds)")
        
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
                
                # Check MQTT connection health
                if self.enable_mqtt:
                    await self.check_mqtt_reconnection()
                
                # JWT token renewal is now handled proactively in safe_publish()
                # and by the dedicated jwt_renewal_scheduler task
                
            except asyncio.CancelledError:
                if self.debug:
                    self.logger.debug("Connection monitoring cancelled")
                break
            except Exception as e:
                self.logger.error(f"Error in connection monitoring: {e}")
                await asyncio.sleep(5)  # Wait before retrying monitoring
    
    def sanitize_client_id(self, name):
        """Convert device name to valid MQTT client ID"""
        client_id = self.get_env("CLIENT_ID_PREFIX", "meshcore_client_") + name.replace(" ", "_")
        client_id = re.sub(r"[^a-zA-Z0-9_-]", "", client_id)
        return client_id[:23]
    
    def on_mqtt_connect(self, client, userdata, flags, rc, properties=None):
        broker_name = userdata.get('name', 'unknown') if userdata else 'unknown'
        broker_num = userdata.get('broker_num', None) if userdata else None
        if rc == 0:
            self.mqtt_connected = True
            self.logger.info(f"Connected to MQTT broker: {broker_name}")
            # Publish online status once on connection
            self.publish_status("online", client, broker_num)
        else:
            self.logger.error(f"MQTT connection failed for {broker_name} with code {rc}")

    def on_mqtt_disconnect(self, client, userdata, disconnect_flags, reason_code, properties):
        broker_name = userdata.get('name', 'unknown') if userdata else 'unknown'
        
        # Provide more specific logging for different disconnect reasons
        if reason_code == mqtt.MQTT_ERR_KEEPALIVE:
            self.logger.warning(f"Disconnected from MQTT broker {broker_name} (code: Keep alive timeout)")
            self.logger.info("This may be due to network latency or firewall timeouts. Connection will be retried.")
        elif reason_code == mqtt.MQTT_ERR_NETWORK_ERROR:
            self.logger.warning(f"Disconnected from MQTT broker {broker_name} (code: Network error)")
        else:
            self.logger.warning(f"Disconnected from MQTT broker {broker_name} (code: {reason_code})")
        
        # Check if any brokers are still connected (excluding the one that just disconnected)
        connected_brokers = []
        for info in self.mqtt_clients:
            if info['client'] != client and info['client'].is_connected():
                connected_brokers.append(info)
        
        if not connected_brokers:
            self.mqtt_connected = False
            self.logger.warning("All MQTT brokers disconnected. Will attempt reconnection...")
            # Don't exit immediately - let reconnection logic handle it
        else:
            self.logger.info(f"Still connected to {len(connected_brokers)} broker(s)")

    async def connect_mqtt_broker(self, broker_num):
        """Connect to a single MQTT broker"""
        if not self.device_name:
            self.logger.error("Cannot connect to MQTT without device name")
            return None

        # Check if broker is enabled
        if not self.get_env_bool(f'MQTT{broker_num}_ENABLED', False):
            self.logger.debug(f"MQTT broker {broker_num} is disabled, skipping")
            return None

        try:
            # Create client ID
            client_id = self.sanitize_client_id(self.device_public_key or self.device_name)
            if broker_num > 1:
                client_id += f"_{broker_num}"
            
            self.logger.info(f"Connecting to MQTT{broker_num} with client ID: {client_id}")
            
            # Get transport type
            transport = self.get_env(f'MQTT{broker_num}_TRANSPORT', 'tcp')
            
            mqtt_client = mqtt.Client(
                mqtt.CallbackAPIVersion.VERSION2,
                client_id=client_id,
                clean_session=False,
                transport=transport
            )
            
            # Set user data for callbacks
            mqtt_client.user_data_set({
                'name': f"MQTT{broker_num}",
                'broker_num': broker_num
            })
            
            # Handle authentication
            use_auth_token = self.get_env_bool(f'MQTT{broker_num}_USE_AUTH_TOKEN', False)
            
            if use_auth_token:
                # Check if we have any JWT authentication method available
                if not self.private_key_export_available and not self.device_private_key:
                    self.logger.error(f"MQTT{broker_num}: No JWT authentication method available (private key from device or environment)")
                    return None
                
                try:
                    username = f"v1_{self.device_public_key.upper()}"
                    audience = self.get_env(f'MQTT{broker_num}_TOKEN_AUDIENCE', "")
                    
                    if audience:
                        self.logger.info(f"MQTT{broker_num}: Using JWT authentication [aud: {audience}]")
                    else:
                        self.logger.info(f"MQTT{broker_num}: Using JWT authentication")
                    
                    # Use the JWT creation method with private key from device
                    password = await self.create_auth_token_jwt(audience, broker_num)
                    if not password:
                        self.logger.error(f"MQTT{broker_num}: Failed to generate JWT token")
                        return None
                    
                    # Log JWT details for debugging if debug mode is enabled
                    if self.debug:
                        self.logger.debug(f"MQTT{broker_num}: Generated JWT: {password}")
                        try:
                            import base64
                            parts = password.split('.')
                            if len(parts) == 3:
                                header = base64.urlsafe_b64decode(parts[0] + '==').decode('utf-8')
                                payload = base64.urlsafe_b64decode(parts[1] + '==').decode('utf-8')
                                self.logger.debug(f"MQTT{broker_num}: JWT Header: {header}")
                                self.logger.debug(f"MQTT{broker_num}: JWT Payload: {payload}")
                                self.logger.debug(f"MQTT{broker_num}: JWT Signature length: {len(base64.urlsafe_b64decode(parts[2] + '=='))} bytes")
                        except Exception as e:
                            self.logger.debug(f"Could not decode JWT for inspection: {e}")
                    
                    mqtt_client.username_pw_set(username, password)
                except Exception as e:
                    self.logger.error(f"MQTT{broker_num}: Failed to generate auth token: {e}")
                    return None
            else:
                # Username/password authentication
                username = self.get_env(f'MQTT{broker_num}_USERNAME', "")
                password = self.get_env(f'MQTT{broker_num}_PASSWORD', "")
                if username:
                    mqtt_client.username_pw_set(username, password)
            
            # Set Last Will and Testament
            lwt_topic = self.get_topic("status", broker_num)
            lwt_payload = json.dumps({
                "status": "offline",
                "timestamp": datetime.now().isoformat(),
                "origin": self.device_name,
                "origin_id": self.device_public_key
            })
            lwt_qos = self.get_env_int(f'MQTT{broker_num}_QOS', 0)
            lwt_retain = self.get_env_bool(f'MQTT{broker_num}_RETAIN', True)
            
            mqtt_client.will_set(lwt_topic, lwt_payload, qos=lwt_qos, retain=lwt_retain)
            
            # Set callbacks
            mqtt_client.on_connect = self.on_mqtt_connect
            mqtt_client.on_disconnect = self.on_mqtt_disconnect
            
            # Get connection parameters
            server = self.get_env(f'MQTT{broker_num}_SERVER', "")
            if not server:
                self.logger.error(f"MQTT{broker_num}: Server not configured")
                return None
                
            port = self.get_env_int(f'MQTT{broker_num}_PORT', 1883)
            
            # Handle TLS/SSL
            use_tls = self.get_env_bool(f'MQTT{broker_num}_USE_TLS', False)
            if use_tls:
                import ssl
                tls_verify = self.get_env_bool(f'MQTT{broker_num}_TLS_VERIFY', True)
                
                if tls_verify:
                    mqtt_client.tls_set(cert_reqs=ssl.CERT_REQUIRED)
                    mqtt_client.tls_insecure_set(False)
                else:
                    mqtt_client.tls_set(cert_reqs=ssl.CERT_NONE)
                    mqtt_client.tls_insecure_set(True)
                    self.logger.warning(f"MQTT{broker_num}: TLS certificate verification disabled (insecure)")
            
            # Handle WebSocket transport
            if transport == "websockets":
                mqtt_client.ws_set_options(
                    path="/",
                    headers=None
                )
            
            # Connect with adaptive keep-alive based on transport type
            if transport == "websockets":
                # WebSocket connections need longer keep-alive to handle network latency
                keepalive = self.get_env_int(f'MQTT{broker_num}_KEEPALIVE', 120)
            else:
                # TCP connections can use shorter keep-alive
                keepalive = self.get_env_int(f'MQTT{broker_num}_KEEPALIVE', 60)
            
            mqtt_client.connect(server, port, keepalive=keepalive)
            mqtt_client.loop_start()
            
            self.logger.info(f"Connected to MQTT{broker_num} at {server}:{port} (transport={transport}, tls={use_tls})")
            return {
                'client': mqtt_client,
                'broker_num': broker_num
            }
            
        except Exception as e:
            self.logger.error(f"MQTT connection error for MQTT{broker_num}: {str(e)}")
            return None

    async def connect_mqtt(self):
        """Connect to all configured MQTT brokers"""
        # Try to connect to MQTT1, MQTT2, MQTT3, MQTT4 (can expand if needed)
        for broker_num in range(1, 5):
            client_info = await self.connect_mqtt_broker(broker_num)
            if client_info:
                self.mqtt_clients.append(client_info)
        
        if len(self.mqtt_clients) == 0:
            self.logger.error("Failed to connect to any MQTT broker")
            return False
        
        self.logger.info(f"Connected to {len(self.mqtt_clients)} MQTT broker(s)")
        return True
    
    def disconnect_mqtt(self):
        """Disconnect from all MQTT brokers and clean up connections"""
        if self.mqtt_clients:
            self.logger.info(f"Disconnecting from {len(self.mqtt_clients)} MQTT broker(s)...")
            
            for client_info in self.mqtt_clients:
                try:
                    mqtt_client = client_info['client']
                    broker_num = client_info['broker_num']
                    
                    if mqtt_client.is_connected():
                        mqtt_client.loop_stop()
                        mqtt_client.disconnect()
                        self.logger.debug(f"Disconnected from MQTT{broker_num}")
                    
                except Exception as e:
                    self.logger.warning(f"Error disconnecting from MQTT{broker_num}: {e}")
            
            # Clear the clients list
            self.mqtt_clients.clear()
            self.mqtt_connected = False
    
    async def stop(self):
        """Stop packet capture and clean up resources"""
        self.logger.info("Stopping packet capture...")
        self.connected = False
        self.should_exit = True
        
        # Disconnect from MQTT brokers
        self.disconnect_mqtt()
        
        # Disconnect from MeshCore device
        if self.meshcore:
            try:
                await self.meshcore.disconnect()
            except Exception as e:
                self.logger.warning(f"Error disconnecting from MeshCore device: {e}")
        
        # Private key cleanup (no separate instance to clean up)
        
        self.logger.info("Packet capture stopped")
    
    async def reconnect_mqtt(self):
        """Attempt to reconnect to MQTT broker with retry logic"""
        if self.max_mqtt_retries > 0 and self.mqtt_retry_count >= self.max_mqtt_retries:
            self.logger.error(f"Maximum MQTT retry attempts ({self.max_mqtt_retries}) reached")
            if self.exit_on_reconnect_fail:
                self.logger.error("Exiting due to failed MQTT reconnection attempts")
                self.should_exit = True
            return False
        
        self.mqtt_retry_count += 1
        self.logger.info(f"Attempting MQTT reconnection (attempt {self.mqtt_retry_count}/{self.max_mqtt_retries if self.max_mqtt_retries > 0 else '∞'})...")
        
        # Wait before retrying
        if self.mqtt_retry_delay > 0:
            self.logger.info(f"Waiting {self.mqtt_retry_delay} seconds before MQTT retry...")
            await asyncio.sleep(self.mqtt_retry_delay)
        
        # Clean up existing connections before reconnecting
        self.disconnect_mqtt()
        
        # Attempt to reconnect
        success = await self.connect_mqtt()
        if success:
            self.mqtt_retry_count = 0  # Reset counter on successful connection
            self.logger.info("MQTT reconnection successful")
        else:
            self.logger.warning(f"MQTT reconnection attempt {self.mqtt_retry_count} failed")
        
        return success
    
    async def check_mqtt_reconnection(self):
        """Check if MQTT reconnection is needed and attempt it"""
        if self.mqtt_clients:
            # Check if any brokers are actually connected
            connected_brokers = [info for info in self.mqtt_clients if info['client'].is_connected()]
            disconnected_brokers = [info for info in self.mqtt_clients if not info['client'].is_connected()]
            
            # Update global connection status
            if connected_brokers:
                self.mqtt_connected = True
            else:
                self.mqtt_connected = False
            
            # If we have disconnected brokers, attempt reconnection
            if disconnected_brokers:
                self.logger.info(f"{len(disconnected_brokers)} MQTT broker(s) disconnected, attempting reconnection...")
                await self.reconnect_mqtt()
    
    def publish_status(self, status, client=None, broker_num=None):
        """Publish status with additional information"""
        status_msg = {
            "status": status,
            "timestamp": datetime.now().isoformat(),
            "origin": self.device_name,
            "origin_id": self.device_public_key
        }
        if client:
            self.safe_publish(None, json.dumps(status_msg), retain=True, client=client, broker_num=broker_num, topic_type="status")
        else:
            self.safe_publish(None, json.dumps(status_msg), retain=True, topic_type="status")
        if self.debug:
            self.logger.debug(f"Published status: {status}")

    def safe_publish(self, topic, payload, retain=False, client=None, broker_num=None, topic_type=None):
        """Publish to one or all MQTT brokers and return publish metrics."""
        metrics = {"attempted": 0, "succeeded": 0}

        if not self.mqtt_connected:
            self.logger.warning(f"Not connected - skipping publish to {topic or topic_type}")
            return metrics
        
        # Proactively check for expired tokens before publishing
        if self.enable_mqtt:
            try:
                # Check if any tokens are expired and need renewal
                expired_brokers = []
                for broker_num in list(self.jwt_tokens.keys()):
                    if self.is_jwt_token_expired(broker_num):
                        expired_brokers.append(broker_num)
                
                if expired_brokers:
                    self.logger.warning(f"Detected expired JWT tokens for brokers: {expired_brokers}")
                    # Schedule renewal (don't await here to avoid blocking publish)
                    asyncio.create_task(self.check_and_renew_jwt_tokens())
            except Exception as e:
                self.logger.debug(f"Error checking token expiry before publish: {e}")

        if client:
            clients_to_publish = [info for info in self.mqtt_clients if info['client'] == client]
        else:
            clients_to_publish = self.mqtt_clients

        for mqtt_client_info in clients_to_publish:
            current_broker_num = mqtt_client_info['broker_num']
            try:
                mqtt_client = mqtt_client_info['client']

                # Check individual client connection status
                if not mqtt_client.is_connected():
                    self.logger.warning(f"MQTT{current_broker_num} client not connected - skipping publish")
                    continue

                # CRITICAL FIX: Resolve topic properly
                if topic_type:
                    resolved_topic = self.get_topic(topic_type, current_broker_num)
                    if self.debug:
                        self.logger.debug(f"Resolved topic for MQTT{current_broker_num} {topic_type}: {resolved_topic}")
                elif topic:
                    resolved_topic = topic
                else:
                    self.logger.error("Neither topic nor topic_type provided to safe_publish")
                    continue

                # Skip publishing if topic is None (e.g., RAW topic not configured)
                if resolved_topic is None:
                    if self.debug:
                        self.logger.debug(f"Skipping publish to MQTT{current_broker_num} - topic not configured for {topic_type}")
                    continue

                # Validate topic before publishing
                if not resolved_topic:
                    self.logger.error(f"Failed to resolve topic (type={topic_type}, topic={topic})")
                    continue

                qos = self.get_env_int(f'MQTT{current_broker_num}_QOS', 0)
                # Force QoS 1 to 0 to prevent retry storms (like mctomqtt.py)
                if qos == 1:
                    qos = 0

                # Only count as attempted if we actually try to publish
                metrics["attempted"] += 1
                result = mqtt_client.publish(resolved_topic, payload, qos=qos, retain=retain)
                if result.rc != mqtt.MQTT_ERR_SUCCESS:
                    self.logger.error(f"Publish failed to {resolved_topic} on MQTT{current_broker_num}: {mqtt.error_string(result.rc)}")
                else:
                    if self.verbose:
                        self.logger.info(f"✓ Published to {resolved_topic} on MQTT{current_broker_num} (len={len(payload)})")
                    metrics["succeeded"] += 1
            except Exception as e:
                self.logger.error(f"Publish error on MQTT{current_broker_num}: {str(e)}", exc_info=True)

        return metrics
    
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
            if self.debug:
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
                
            if self.debug:
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
            # Try to get from environment as fallback
            origin_id = self.get_env('ORIGIN_ID', None)
            if not origin_id:
                # Generate a hash from device name as last resort
                device_name = self.device_name or 'Unknown'
                origin_id = hashlib.sha256(device_name.encode()).hexdigest()
                self.logger.warning(f"Using generated origin_id from device name: {origin_id}")
        
        # Normalize origin_id to uppercase
        if origin_id and origin_id != 'Unknown':
            origin_id = origin_id.upper()
        
        # Extract RF data if available
        snr = "Unknown"
        rssi = "Unknown"
        
        if rf_data:
            snr = str(rf_data.get('snr', 'Unknown'))
            rssi = str(rf_data.get('rssi', 'Unknown'))
        
        # Build the packet data structure to match mctomqtt.py exactly
        packet_data = {
            "origin": self.device_name or self.get_env('ORIGIN', 'MeshCore Device'),
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
                # Fallback to raw_hex with first 2 bytes stripped
                elif 'raw_hex' in payload and payload['raw_hex']:
                    raw_hex = payload['raw_hex'][4:]  # Skip first 2 bytes (4 hex chars)
                
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
                    timeout = self.get_env_float('RF_DATA_TIMEOUT', 15.0)
                    self.rf_data_cache = {
                        k: v for k, v in self.rf_data_cache.items()
                        if current_time - v['timestamp'] < timeout
                    }
                    
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
            publish_metrics = self.output_packet(packet_data)
            
            self.packet_count += 1
            # Standard log line format for both modes
            self.logger.info(f"📦 Captured packet #{self.packet_count}: {packet_data['route']} type {packet_data['packet_type']}, {packet_data['len']} bytes, SNR: {packet_data['SNR']}, RSSI: {packet_data['RSSI']}, hash: {packet_data['hash']} (MQTT: {publish_metrics['succeeded']}/{publish_metrics['attempted']})")
            
            # Output full packet data structure in debug mode only
            if self.debug:
                self.logger.debug("📋 Full packet data structure:")
                import json
                self.logger.debug(json.dumps(packet_data, indent=2))
            
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
                publish_metrics = self.output_packet(packet_data)
                
                self.packet_count += 1
                self.logger.info(f"📦 Captured packet #{self.packet_count}: {packet_data['route']} type {packet_data['packet_type']}, {packet_data['len']} bytes, SNR: {packet_data['SNR']}, RSSI: {packet_data['RSSI']}, hash: {packet_data['hash']} (MQTT: {publish_metrics['succeeded']}/{publish_metrics['attempted']})")
                
        except Exception as e:
            self.logger.error(f"Error handling raw data event: {e}")
    
    def output_packet(self, packet_data: Dict[str, Any]):
        """Output packet data to console, file, and MQTT"""
        # Convert to JSON
        json_data = json.dumps(packet_data, indent=2)
        
        # Output JSON packet data to console only in verbose mode
        if self.verbose:
            self.logger.info("=" * 80)
            self.logger.info(json_data)
            self.logger.info("=" * 80)
        
        # Output to file if specified
        if self.output_handle:
            self.output_handle.write(json_data + "\n")
            self.output_handle.flush()
        
        # Publish to MQTT if enabled
        publish_metrics = {"attempted": 0, "succeeded": 0}
        if self.enable_mqtt:
            # Publish full packet data
            packet_metrics = self.safe_publish(None, json.dumps(packet_data), topic_type="packets")
            
            # Publish raw data only to brokers that have RAW topic explicitly configured
            raw_data = {
                "origin": packet_data["origin"],
                "origin_id": packet_data["origin_id"],
                "timestamp": packet_data["timestamp"],
                "type": "RAW",
                "data": packet_data["raw"]
            }
            raw_metrics = self.safe_publish(None, json.dumps(raw_data), topic_type="raw")
            
            # Combine metrics: sum up all successful publishes across all brokers
            # Each broker publishes to its configured topics independently
            publish_metrics["attempted"] = packet_metrics["attempted"] + raw_metrics["attempted"]
            publish_metrics["succeeded"] = packet_metrics["succeeded"] + raw_metrics["succeeded"]

        return publish_metrics
    
    async def setup_event_handlers(self):
        """Setup event handlers for packet capture"""
        # Handle RF log data for SNR/RSSI information
        async def on_rf_data(event):
            if self.debug:
                self.logger.debug(f"RF_DATA event received: {event}")
            await self.handle_rf_log_data(event)
        
        # Handle raw data events (full packet data)
        async def on_raw_data(event):
            if self.debug:
                self.logger.debug(f"RAW_DATA event received: {event}")
            await self.handle_raw_data(event)
        
        # Handle status response events
        async def on_status_response(event):
            if self.debug:
                self.logger.debug(f"STATUS_RESPONSE event received: {event}")
                # Log the status data to see what's available
                if hasattr(event, 'payload') and event.payload:
                    self.logger.debug(f"Status data: {event.payload}")
        
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
            if not await self.connect_mqtt():
                self.logger.warning("Failed to connect to MQTT broker, continuing without MQTT...")
        else:
            self.logger.info("MQTT disabled, skipping MQTT connection")
        
        # Setup event handlers
        await self.setup_event_handlers()
        
        # Start auto message fetching
        await self.meshcore.start_auto_message_fetching()
        
        self.logger.info("Packet capture is running. Press Ctrl+C to stop.")
        self.logger.info("Waiting for packets...")
        
        # Start connection monitoring task (delay to allow MQTT connections to stabilize)
        await asyncio.sleep(5)  # Give MQTT connections time to fully establish
        monitoring_task = asyncio.create_task(self.connection_monitor())
        
        # Start advert scheduler task
        if self.advert_interval_hours > 0:
            self.advert_task = asyncio.create_task(self.advert_scheduler())
        
        # Start JWT renewal scheduler task
        if self.jwt_renewal_interval > 0:
            self.jwt_renewal_task = asyncio.create_task(self.jwt_renewal_scheduler())
        
        try:
            mqtt_check_interval = 10  # Check MQTT reconnection every 10 seconds
            last_mqtt_check = 0
            
            while self.connected and not self.should_exit:
                current_time = time.time()
                
                # Check MQTT reconnection periodically
                if current_time - last_mqtt_check >= mqtt_check_interval:
                    await self.check_mqtt_reconnection()
                    last_mqtt_check = current_time
                
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Received interrupt signal")
        finally:
            monitoring_task.cancel()
            if self.advert_task:
                self.advert_task.cancel()
            if self.jwt_renewal_task:
                self.jwt_renewal_task.cancel()
            try:
                await monitoring_task
            except asyncio.CancelledError:
                pass
            if self.advert_task:
                try:
                    await self.advert_task
                except asyncio.CancelledError:
                    pass
            if self.jwt_renewal_task:
                try:
                    await self.jwt_renewal_task
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
        
        # Handle BLE disconnection if using BLE connection
        if self.meshcore and self.get_env('CONNECTION_TYPE', 'ble').lower() == 'ble':
            try:
                self.logger.info("Disconnecting BLE device...")
                await self.meshcore.disconnect()
                
                # Additional BLE disconnection using bluetoothctl on Linux
                import platform
                if platform.system() == 'Linux':
                    try:
                        import subprocess
                        ble_device = self.get_env('BLE_DEVICE', '') or self.get_env('BLE_ADDRESS', '')
                        if ble_device and ble_device != 'Unknown':
                            self.logger.info(f"Force disconnecting BLE device {ble_device}...")
                            subprocess.run(['bluetoothctl', 'disconnect', ble_device], 
                                         capture_output=True, timeout=10)
                            await asyncio.sleep(1)  # Give time for disconnection
                    except Exception as e:
                        self.logger.debug(f"Could not force BLE disconnect via bluetoothctl: {e}")
            except Exception as e:
                self.logger.warning(f"Error during BLE disconnection: {e}")
        elif self.meshcore:
            await self.meshcore.disconnect()
        
        for mqtt_client_info in self.mqtt_clients:
            try:
                mqtt_client_info['client'].disconnect()
                mqtt_client_info['client'].loop_stop()
            except:
                pass
        
        if self.output_handle:
            self.output_handle.close()
        
        self.logger.info(f"Packet capture stopped. Total packets captured: {self.packet_count}")
    
    async def send_advert(self):
        """Send a flood advert using meshcore commands"""
        try:
            if not self.meshcore or not self.meshcore.is_connected:
                self.logger.warning("Cannot send advert - not connected to MeshCore")
                return False
            
            self.logger.info("Sending flood advert...")
            await self.meshcore.commands.send_advert(flood=True)
            self.last_advert_time = time.time()
            self.logger.info("Flood advert sent successfully!")
            return True
            
        except Exception as e:
            self.logger.error(f"Error sending flood advert: {e}")
            return False
    
    async def advert_scheduler(self):
        """Background task to send adverts at configured intervals"""
        if self.advert_interval_hours <= 0:
            if self.debug:
                self.logger.debug("Advert scheduling disabled (interval = 0)")
            return
        
        if self.debug:
            self.logger.debug(f"Starting advert scheduler with {self.advert_interval_hours} hour interval")
        
        while self.connected:
            try:
                # Calculate seconds until next advert
                current_time = time.time()
                time_since_last = current_time - self.last_advert_time
                interval_seconds = self.advert_interval_hours * 3600
                
                if time_since_last >= interval_seconds:
                    # Time to send an advert
                    await self.send_advert()
                    # Sleep for the full interval to avoid rapid-fire adverts
                    await asyncio.sleep(interval_seconds)
                else:
                    # Sleep until it's time for the next advert
                    sleep_time = interval_seconds - time_since_last
                    if self.debug:
                        self.logger.debug(f"Next advert in {sleep_time/3600:.1f} hours")
                    await asyncio.sleep(sleep_time)
                    
            except asyncio.CancelledError:
                if self.debug:
                    self.logger.debug("Advert scheduler cancelled")
                break
            except Exception as e:
                self.logger.error(f"Error in advert scheduler: {e}")
                await asyncio.sleep(60)  # Wait 1 minute before retrying
    
    async def jwt_renewal_scheduler(self):
        """Background task to check and renew JWT tokens"""
        if self.jwt_renewal_interval <= 0:
            if self.debug:
                self.logger.debug("JWT renewal scheduling disabled (interval = 0)")
            return
        
        if self.debug:
            self.logger.debug(f"Starting JWT renewal scheduler with {self.jwt_renewal_interval} second interval")
        
        while self.connected:
            try:
                await asyncio.sleep(self.jwt_renewal_interval)
                
                if not self.connected:
                    break
                
                # Check and renew JWT tokens
                await self.check_and_renew_jwt_tokens()
                    
            except asyncio.CancelledError:
                if self.debug:
                    self.logger.debug("JWT renewal scheduler cancelled")
                break
            except Exception as e:
                self.logger.error(f"Error in JWT renewal scheduler: {e}")
                await asyncio.sleep(60)  # Wait 1 minute before retrying


async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='MeshCore Packet Capture Script')
    parser.add_argument('--output', help='Output file path (optional)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output (shows JSON packet data)')
    parser.add_argument('--debug', action='store_true', help='Enable debug output (shows all detailed debugging info)')
    parser.add_argument('--no-mqtt', action='store_true', help='Disable MQTT publishing')
    
    args = parser.parse_args()
    
    # Create packet capture instance
    capture = PacketCapture(
        output_file=args.output, 
        verbose=args.verbose,
        debug=args.debug,
        enable_mqtt=not args.no_mqtt
    )
    
    if args.debug:
        capture.logger.setLevel(logging.DEBUG)
    elif args.verbose:
        capture.logger.setLevel(logging.INFO)
    
    # Setup signal handlers for graceful shutdown
    import signal
    
    def signal_handler(signum, frame):
        capture.logger.info(f"Received signal {signum}, shutting down gracefully...")
        capture.should_exit = True
    
    # Register signal handlers
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        await capture.start()
    except KeyboardInterrupt:
        print("\nShutting down...")
        await capture.stop()
    except Exception as e:
        print(f"Error: {e}")
        await capture.stop()


if __name__ == "__main__":
    asyncio.run(main())
