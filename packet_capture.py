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


def enable_tcp_keepalive(transport, idle=10, interval=5, count=3):
    """Enable TCP keepalive on the transport's socket"""
    import socket
    try:
        sock = transport.get_extra_info('socket')
        if sock:
            # Enable TCP keepalive
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            
            # Platform-specific keepalive settings
            if hasattr(socket, 'TCP_KEEPIDLE'):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, idle)
            if hasattr(socket, 'TCP_KEEPINTVL'):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval)
            if hasattr(socket, 'TCP_KEEPCNT'):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, count)
            
            return True
    except Exception as e:
        # Log but don't fail the connection
        print(f"Warning: Could not enable TCP keepalive: {e}")
        return False
    return False


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
                    # Remove inline comments (everything after #)
                    if '#' in value:
                        value = value.split('#')[0].strip()
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
    
    def __init__(self, output_file: Optional[str] = None, verbose: bool = False, debug: bool = False, enable_mqtt: bool = True, shutdown_event=None):
        self.output_file = output_file
        self.verbose = verbose
        self.debug = debug
        self.enable_mqtt = enable_mqtt
        self.shutdown_event = shutdown_event
        
        # Setup logging
        self.setup_logging()
        
        # Global IATA for template resolution
        self.global_iata = os.getenv('PACKETCAPTURE_IATA', 'LOC').lower()
        
        # Connection
        self.meshcore = None
        self.connected = False
        self.connection_type = None  # Track connection type for health checks
        self.connection_retry_count = 0
        self.max_connection_retries = self.get_env_int('MAX_CONNECTION_RETRIES', 5)
        self.connection_retry_delay = self.get_env_int('CONNECTION_RETRY_DELAY', 5)
        self.connection_retry_delay_max = self.get_env_int('CONNECTION_RETRY_DELAY_MAX', 300)  # 5 minutes max
        self.connection_retry_backoff_multiplier = self.get_env_float('CONNECTION_RETRY_BACKOFF_MULTIPLIER', 2.0)
        self.connection_retry_jitter = self.get_env_bool('CONNECTION_RETRY_JITTER', True)
        self.health_check_interval = self.get_env_int('HEALTH_CHECK_INTERVAL', 30)
        
        # MQTT connection
        self.mqtt_clients = []  # List of MQTT client info dictionaries
        self.mqtt_connected = False
        self.should_exit = False  # Flag to exit when reconnection attempts fail
        
        # Service-level failure tracking for systemd restart
        self.service_failure_count = 0
        self.max_service_failures = self.get_env_int('MAX_SERVICE_FAILURES', 3)
        self.service_failure_window = self.get_env_int('SERVICE_FAILURE_WINDOW', 300)  # 5 minutes
        self.last_service_failure = 0
        self.critical_failure_threshold = self.get_env_int('CRITICAL_FAILURE_THRESHOLD', 5)
        
        # Track consecutive failures for more intelligent failure detection
        self.consecutive_connection_failures = 0
        self.consecutive_mqtt_failures = 0
        self.max_consecutive_failures = self.get_env_int('MAX_CONSECUTIVE_FAILURES', 3)
        
        # Packet correlation cache
        self.rf_data_cache = {}
        self.packet_count = 0
        
        # Opted-in IDs for advert filtering (mirroring mctomqtt.py)
        self.opted_in_ids = []
        
        # Device information
        self.device_name = None
        self.device_public_key = None
        self.device_private_key = None
        self.radio_info = None
        self.cached_firmware_info = None  # Cache firmware info to avoid queries during shutdown
        
        # Private key export capability
        self.private_key_export_available = False
        
        # JWT token management
        self.jwt_tokens = {}  # Store tokens per broker: {broker_num: {'token': str, 'expires_at': float}}
        self.jwt_renewal_interval = self.get_env_int('JWT_RENEWAL_INTERVAL', 3600)  # Check every hour
        self.jwt_renewal_threshold = self.get_env_int('JWT_RENEWAL_THRESHOLD', 300)  # Renew 5 minutes before expiry
        
        # Advert settings
        self.advert_interval_hours = self.get_env_int('ADVERT_INTERVAL_HOURS', 11)
        self.last_advert_time = 0
        self.advert_task = None
        
        
        # JWT renewal task
        self.jwt_renewal_task = None
        
        # Task tracking to prevent duplicate tasks
        self.active_tasks = set()
        self.jwt_renewal_in_progress = False
        
        # TCP keepalive settings
        self.tcp_keepalive_enabled = self.get_env_bool('TCP_KEEPALIVE_ENABLED', True)
        self.tcp_keepalive_idle = self.get_env_int('TCP_KEEPALIVE_IDLE', 10)
        self.tcp_keepalive_interval = self.get_env_int('TCP_KEEPALIVE_INTERVAL', 5)
        self.tcp_keepalive_count = self.get_env_int('TCP_KEEPALIVE_COUNT', 3)
        
        # Circuit breaker for JWT failures
        self.jwt_failure_count = 0
        self.max_jwt_failures = 5
        self.jwt_circuit_breaker_timeout = 300  # 5 minutes
        self.jwt_circuit_breaker_reset_time = 0
        
        # Resource monitoring
        self.max_active_tasks = 100  # Prevent task explosion
        self.task_monitoring_interval = 60  # Check every minute
        self.last_task_check = 0
        
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
        
        # Get log level from environment variable
        log_level_str = self.get_env('LOG_LEVEL', 'INFO').upper()
        log_level_map = {
            'DEBUG': logging.DEBUG,
            'INFO': logging.INFO,
            'WARNING': logging.WARNING,
            'ERROR': logging.ERROR,
            'CRITICAL': logging.CRITICAL
        }
        log_level = log_level_map.get(log_level_str, logging.INFO)
        
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
            level=log_level,
            handlers=[console_handler],
            force=True
        )
        
        self.logger = logging.getLogger('PacketCapture')
        
        # Test the logging format
        self.logger.info(f"Logging initialized with level: {log_level_str}")
    
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
    
    
    def calculate_connection_retry_delay(self, attempt: int) -> float:
        """Calculate exponential backoff delay with jitter for connection retries"""
        import random
        
        # Calculate exponential backoff: base_delay * (multiplier ^ (attempt - 1))
        delay = self.connection_retry_delay * (self.connection_retry_backoff_multiplier ** (attempt - 1))
        
        # Cap at maximum delay
        delay = min(delay, self.connection_retry_delay_max)
        
        # Add jitter to prevent thundering herd (random factor between 0.5 and 1.5)
        if self.connection_retry_jitter:
            jitter_factor = random.uniform(0.5, 1.5)
            delay *= jitter_factor
        
        return max(1.0, delay)  # Minimum 1 second delay
    
    def track_service_failure(self, failure_type: str, details: str = ""):
        """Track service-level failures and determine if we should exit for systemd restart"""
        import time
        
        current_time = time.time()
        
        # Reset failure count if outside the failure window
        if current_time - self.last_service_failure > self.service_failure_window:
            self.service_failure_count = 0
        
        self.service_failure_count += 1
        self.last_service_failure = current_time
        
        self.logger.error(f"Service failure #{self.service_failure_count}: {failure_type}")
        if details:
            self.logger.error(f"Failure details: {details}")
        
        # Check if we should exit for systemd restart
        if self.service_failure_count >= self.max_service_failures:
            self.logger.critical(f"Maximum service failures ({self.max_service_failures}) reached within {self.service_failure_window}s window")
            self.logger.critical("Exiting to allow systemd to restart the service with fresh state")
            self.should_exit = True
            return True
        
        return False
    
    def track_consecutive_failure(self, failure_type: str) -> bool:
        """Track consecutive failures and determine if they warrant a service failure"""
        if failure_type == "connection":
            self.consecutive_connection_failures += 1
            self.consecutive_mqtt_failures = 0  # Reset other type
        elif failure_type == "mqtt":
            self.consecutive_mqtt_failures += 1
            self.consecutive_connection_failures = 0  # Reset other type
        
        # Check if consecutive failures warrant a service failure
        if (self.consecutive_connection_failures >= self.max_consecutive_failures or 
            self.consecutive_mqtt_failures >= self.max_consecutive_failures):
            
            failure_details = f"Consecutive {failure_type} failures: {self.consecutive_connection_failures if failure_type == 'connection' else self.consecutive_mqtt_failures}"
            return self.track_service_failure(f"Consecutive {failure_type} failures", failure_details)
        
        return False
    
    def reset_consecutive_failures(self, failure_type: str):
        """Reset consecutive failure count when connection is restored"""
        if failure_type == "connection":
            self.consecutive_connection_failures = 0
        elif failure_type == "mqtt":
            self.consecutive_mqtt_failures = 0
    
    async def wait_with_shutdown(self, timeout: float) -> bool:
        """Wait for specified time but return immediately if shutdown is requested"""
        if self.shutdown_event:
            try:
                await asyncio.wait_for(self.shutdown_event.wait(), timeout=timeout)
                return True  # Shutdown was requested
            except asyncio.TimeoutError:
                return False  # Timeout reached, no shutdown
        else:
            await asyncio.sleep(timeout)
            return False

    def should_exit_for_systemd_restart(self) -> bool:
        """Determine if we should exit to allow systemd restart"""
        import time
        
        # Check for critical failure threshold
        if self.service_failure_count >= self.critical_failure_threshold:
            self.logger.critical(f"Critical failure threshold ({self.critical_failure_threshold}) reached")
            return True
        
        # Check for recent failure pattern
        current_time = time.time()
        if (current_time - self.last_service_failure) < self.service_failure_window:
            if self.service_failure_count >= self.max_service_failures:
                self.logger.critical(f"Too many failures ({self.service_failure_count}) in {self.service_failure_window}s")
                return True
        
        return False
    
    def _load_client_version(self):
        """Load client version from .version_info file"""
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            version_file = os.path.join(script_dir, '.version_info')
            if os.path.exists(version_file):
                with open(version_file, 'r') as f:
                    version_data = json.load(f)
                    installer_ver = version_data.get('installer_version', 'unknown')
                    git_hash = version_data.get('git_hash', 'unknown')
                    return f"meshcore-packet-capture/{installer_ver}-{git_hash}"
        except Exception as e:
            self.logger.debug(f"Could not load version info: {e}")
        return "meshcore-packet-capture/unknown"
    
    async def get_firmware_info(self):
        """Get firmware information from meshcore device using send_device_query()"""
        try:
            # Return cached info if available and device is not connected (e.g., during shutdown)
            if self.cached_firmware_info and (not self.meshcore or not self.meshcore.is_connected):
                self.logger.debug("Using cached firmware info")
                return self.cached_firmware_info
            
            if not self.meshcore or not self.meshcore.is_connected:
                self.logger.debug("Cannot get firmware info - not connected to device")
                return {"model": "unknown", "version": "unknown"}
            
            self.logger.debug("Querying device for firmware info...")
            # Use send_device_query() to get firmware version
            result = await self.meshcore.commands.send_device_query()
            
            self.logger.debug(f"Device query result type: {result.type}")
            self.logger.debug(f"Device query result: {result}")
            
            if result.type == EventType.ERROR:
                self.logger.debug(f"Device query failed: {result}")
                return {"model": "unknown", "version": "unknown"}
            
            if result.payload:
                payload = result.payload
                self.logger.debug(f"Device query payload: {payload}")
                
                # Check firmware version format
                fw_ver = payload.get('fw ver', 0)
                self.logger.debug(f"Firmware version number: {fw_ver}")
                
                if fw_ver >= 3:
                    # For newer firmware versions (v3+)
                    model = payload.get('model', 'Unknown')
                    version = payload.get('ver', 'Unknown')
                    build_date = payload.get('fw_build', 'Unknown')
                    # Remove 'v' prefix from version if it already has one
                    if version.startswith('v'):
                        version = version[1:]
                    version_str = f"v{version} (Build: {build_date})"
                    self.logger.debug(f"New firmware format - Model: {model}, Version: {version_str}")
                    firmware_info = {"model": model, "version": version_str}
                    self.cached_firmware_info = firmware_info  # Cache the result
                    return firmware_info
                else:
                    # For older firmware versions
                    version_str = f"v{fw_ver}"
                    self.logger.debug(f"Old firmware format - Model: unknown, Version: {version_str}")
                    firmware_info = {"model": "unknown", "version": version_str}
                    self.cached_firmware_info = firmware_info  # Cache the result
                    return firmware_info
            
            self.logger.debug("No payload in device query result")
            return {"model": "unknown", "version": "unknown"}
            
        except Exception as e:
            self.logger.debug(f"Error getting firmware info: {e}")
            return {"model": "unknown", "version": "unknown"}
    
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
    
    async def set_radio_clock(self) -> bool:
        """Set radio clock only if device time is earlier than current system time"""
        try:
            if not self.meshcore or not self.meshcore.is_connected:
                self.logger.warning("Cannot set radio clock - not connected to device")
                return False
            
            # Get current device time
            self.logger.info("Checking device time...")
            time_result = await self.meshcore.commands.get_time()
            if time_result.type == EventType.ERROR:
                self.logger.warning("Device does not support time commands")
                return False
            
            device_time = time_result.payload.get('time', 0)
            current_time = int(time.time())
            
            self.logger.info(f"Device time: {device_time}, System time: {current_time}")
            
            # Only set time if device time is earlier than current time
            if device_time < current_time:
                time_diff = current_time - device_time
                self.logger.info(f"Device time is {time_diff} seconds behind, updating...")
                
                result = await self.meshcore.commands.set_time(current_time)
                if result.type == EventType.OK:
                    self.logger.info(f"✓ Radio clock updated to: {current_time}")
                    self.last_clock_sync_time = current_time
                    return True
                else:
                    self.logger.warning(f"Failed to update radio clock: {result}")
                    return False
            else:
                self.logger.info("Device time is current or ahead - no update needed")
                return True
                
        except Exception as e:
            self.logger.warning(f"Error checking/setting radio clock: {e}")
            return False

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
                # Reset failure count on success
                self.jwt_failure_count = 0
                return True
            else:
                self.logger.error(f"Failed to renew JWT token for broker {broker_num}")
                # Increment failure count
                self.jwt_failure_count += 1
                self.jwt_circuit_breaker_reset_time = time.time()
                return False
                
        except Exception as e:
            self.logger.error(f"Error renewing JWT token for broker {broker_num}: {e}")
            # Increment failure count
            self.jwt_failure_count += 1
            self.jwt_circuit_breaker_reset_time = time.time()
            return False
    
    async def check_jwt_renewal_for_broker(self, broker_num: int):
        """Check and renew JWT token for a specific broker if needed"""
        try:
            if broker_num not in self.jwt_tokens:
                return
            
            if self.is_jwt_token_expired(broker_num):
                self.logger.info(f"JWT token for broker {broker_num} needs renewal")
                
                # Renew the token
                renewal_success = await self.renew_jwt_token(broker_num)
                if renewal_success:
                    # Find the broker client and update credentials
                    for client_info in self.mqtt_clients:
                        if client_info['broker_num'] == broker_num:
                            mqtt_client = client_info['client']
                            new_token = self.jwt_tokens[broker_num]['token']
                            username = f"v1_{self.device_public_key.upper()}"
                            
                            # Update credentials and reconnect
                            mqtt_client.username_pw_set(username, new_token)
                            mqtt_client.reconnect()
                            
                            self.logger.info(f"✓ Updated credentials for MQTT broker {broker_num}")
                            break
                else:
                    self.logger.error(f"Failed to renew JWT token for broker {broker_num}")
                    
        except Exception as e:
            self.logger.error(f"Error checking JWT renewal for broker {broker_num}: {e}")

    async def check_and_renew_jwt_tokens(self):
        """Check all JWT tokens and renew if needed"""
        try:
            for broker_num in list(self.jwt_tokens.keys()):
                await self.check_jwt_renewal_for_broker(broker_num)
                    
        except Exception as e:
            self.logger.error(f"Error checking JWT token renewals: {e}")
    
    
    
    

    async def check_connection_health(self) -> bool:
        """Enhanced health check with network validation"""
        try:
            # 1. Check if meshcore object exists and reports connected
            if not self.meshcore or not self.meshcore.is_connected:
                self.logger.warning("MeshCore reports not connected")
                return False
            
            # 2. For TCP connections, verify socket state
            if self.connection_type == 'tcp':
                if hasattr(self.meshcore, '_connection') and hasattr(self.meshcore._connection, 'transport'):
                    transport = self.meshcore._connection.transport
                    if not transport or transport.is_closing():
                        self.logger.warning("TCP transport is closed or closing")
                        return False
            
            # 3. Try a lightweight command with timeout
            try:
                result = await asyncio.wait_for(
                    self.meshcore.commands.send_device_query(),
                    timeout=5.0  # Shorter timeout for faster detection
                )
                if result and hasattr(result, 'type') and result.type != EventType.ERROR:
                    if self.debug:
                        self.logger.debug("Connection health check passed (device query successful)")
                    return True
                else:
                    if self.debug:
                        self.logger.debug(f"Health check device query failed: {result}")
                    return False
            except asyncio.TimeoutError:
                self.logger.warning("Health check timed out")
                return False
            except Exception as e:
                self.logger.warning(f"Health check command failed: {e}")
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
            self.connection_type = connection_type  # Store for health checks
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
                
                # Enable TCP keepalive if configured
                if self.tcp_keepalive_enabled and hasattr(self.meshcore, 'transport'):
                    try:
                        if enable_tcp_keepalive(
                            self.meshcore.transport, 
                            idle=self.tcp_keepalive_idle,
                            interval=self.tcp_keepalive_interval,
                            count=self.tcp_keepalive_count
                        ):
                            self.logger.info(f"TCP keepalive enabled (idle={self.tcp_keepalive_idle}s, interval={self.tcp_keepalive_interval}s, count={self.tcp_keepalive_count})")
                        else:
                            self.logger.warning("Failed to enable TCP keepalive")
                    except Exception as e:
                        self.logger.warning(f"Could not enable TCP keepalive: {e}")
                elif not self.tcp_keepalive_enabled:
                    self.logger.debug("TCP keepalive disabled by configuration")
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
                    
                    # Extract radio information
                    radio_freq = self.meshcore.self_info.get('radio_freq', 0)
                    radio_bw = self.meshcore.self_info.get('radio_bw', 0)
                    radio_sf = self.meshcore.self_info.get('radio_sf', 0)
                    radio_cr = self.meshcore.self_info.get('radio_cr', 0)
                    self.radio_info = f"{radio_freq},{radio_bw},{radio_sf},{radio_cr}"
                    
                    self.logger.info(f"Device name: {self.device_name}")
                    self.logger.info(f"Device public key: {self.device_public_key}")
                    self.logger.info(f"Radio info: {self.radio_info}")
                    
                    # Set radio clock to current system time
                    await self.set_radio_clock()
                    
                    # Don't publish status here - wait for MQTT connections
                    # Status will be published after MQTT connections are established
                    
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
        """Attempt to reconnect to MeshCore device with exponential backoff retry logic"""
        if self.max_connection_retries > 0 and self.connection_retry_count >= self.max_connection_retries:
            self.logger.error(f"Maximum connection retry attempts ({self.max_connection_retries}) reached")
            
            # Track service failure for systemd restart decision
            if self.track_service_failure("MeshCore connection exhausted", 
                                        f"Failed {self.connection_retry_count} reconnection attempts"):
                return False
            
            return False
        
        self.connection_retry_count += 1
        
        # Calculate exponential backoff delay
        delay = self.calculate_connection_retry_delay(self.connection_retry_count)
        
        self.logger.info(f"Attempting MeshCore reconnection (attempt {self.connection_retry_count}/{self.max_connection_retries if self.max_connection_retries > 0 else '∞'}) with {delay:.1f}s delay...")
        
        # Clean up existing connection
        if self.meshcore:
            try:
                await self.meshcore.disconnect()
            except Exception as e:
                self.logger.debug(f"Error disconnecting during reconnect: {e}")
            self.meshcore = None
        
        # Wait before retrying with exponential backoff
        if delay > 0:
            self.logger.info(f"Waiting {delay:.1f} seconds before retry (exponential backoff)...")
            if await self.wait_with_shutdown(delay):
                return False  # Shutdown was requested during delay
        
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
        if self.health_check_interval <= 0:
            if self.debug:
                self.logger.debug("Connection monitoring disabled (health_check_interval <= 0)")
            return
        
        if self.debug:
            self.logger.debug(f"Starting connection monitoring (health check every {self.health_check_interval} seconds)")
        
        while not self.should_exit:
            try:
                if await self.wait_with_shutdown(self.health_check_interval):
                    break  # Shutdown was requested
                
                # Check if we need to reconnect (either disconnected or health check failed)
                needs_reconnection = not self.connected or not await self.check_connection_health()
                
                if needs_reconnection:
                    if not self.connected:
                        self.logger.info("Connection is disconnected, attempting reconnection...")
                    else:
                        self.logger.warning("MeshCore connection health check failed, attempting reconnection...")
                    
                    # Attempt to reconnect
                    if await self.reconnect_meshcore():
                        self.logger.info("MeshCore reconnection successful, resuming packet capture")
                        
                        # Reset consecutive failures on successful reconnection
                        self.reset_consecutive_failures("connection")
                        
                        # Re-setup event handlers after reconnection
                        await self.setup_event_handlers()
                        await self.meshcore.start_auto_message_fetching()
                    else:
                        self.logger.error("MeshCore reconnection failed, will retry on next health check")
                        # Track consecutive failures for more intelligent failure detection
                        if self.track_consecutive_failure("connection"):
                            return  # Exit if service failure threshold reached
                
                
                # JWT token renewal is now handled proactively in safe_publish()
                # and by the dedicated jwt_renewal_scheduler task
                
            except asyncio.CancelledError:
                if self.debug:
                    self.logger.debug("Connection monitoring cancelled")
                break
            except Exception as e:
                self.logger.error(f"Error in connection monitoring: {e}")
                if await self.wait_with_shutdown(5):
                    break  # Shutdown was requested
    
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
            
            # JWT renewal is handled by the dedicated JWT renewal scheduler
            # No need to check here as it will be handled proactively
            
            # Don't publish status here - it will be published after device connection
            # This callback fires when MQTT connects, but device might not be ready yet
            self.logger.debug(f"MQTT broker {broker_name} connected, waiting for device connection...")
        else:
            self.logger.error(f"MQTT connection failed for {broker_name} with code {rc}")

    def on_mqtt_disconnect(self, client, userdata, disconnect_flags, reason_code, properties):
        broker_name = userdata.get('name', 'unknown') if userdata else 'unknown'
        
        # Handle both integer and ReasonCode object types
        if hasattr(reason_code, 'value'):
            # ReasonCode object - get the integer value
            reason_code_int = reason_code.value
        else:
            # Integer or other type
            reason_code_int = int(reason_code) if reason_code is not None else 0
        
        # Provide more specific logging for different disconnect reasons
        if reason_code_int == mqtt.MQTT_ERR_KEEPALIVE:
            self.logger.warning(f"Disconnected from MQTT broker {broker_name} (code: Keep alive timeout)")
            self.logger.info("This may be due to network latency or firewall timeouts. Connection will be retried.")
        elif reason_code_int == mqtt.MQTT_ERR_CONN_LOST:
            self.logger.warning(f"Disconnected from MQTT broker {broker_name} (code: Connection lost)")
            self.logger.info("Network connection was lost. Connection will be retried.")
        elif reason_code_int == mqtt.MQTT_ERR_CONN_REFUSED:
            self.logger.warning(f"Disconnected from MQTT broker {broker_name} (code: Connection refused)")
            self.logger.info("Server refused the connection. Check credentials and server configuration.")
        elif reason_code_int == mqtt.MQTT_ERR_AUTH:
            self.logger.warning(f"Disconnected from MQTT broker {broker_name} (code: Authentication failed)")
            self.logger.info("Authentication failed. Check username/password or auth token.")
        elif reason_code_int == mqtt.MQTT_ERR_ACL_DENIED:
            self.logger.warning(f"Disconnected from MQTT broker {broker_name} (code: ACL denied)")
            self.logger.info("Access denied. Check topic permissions and broker ACL settings.")
        elif reason_code_int == mqtt.MQTT_ERR_TLS:
            self.logger.warning(f"Disconnected from MQTT broker {broker_name} (code: TLS error)")
            self.logger.info("TLS/SSL error occurred. Check certificate configuration.")
        else:
            # Map numeric codes to human-readable names
            error_names = {
                0: "Success",
                1: "Out of memory", 
                2: "Protocol error",
                3: "Invalid arguments",
                4: "Not connected",
                5: "Connection refused",
                6: "Not found",
                7: "Connection lost",
                8: "TLS error",
                9: "Payload too large",
                10: "Not supported",
                11: "Authentication failed",
                12: "ACL denied",
                13: "Unknown error",
                14: "System error",
                15: "Queue size exceeded",
                16: "Keepalive timeout"
            }
            error_name = error_names.get(reason_code_int, f"Unknown error code {reason_code_int}")
            self.logger.warning(f"Disconnected from MQTT broker {broker_name} (code: {reason_code_int} - {error_name})")
        
        # Check if any brokers are still connected (excluding the one that just disconnected)
        connected_brokers = []
        for info in self.mqtt_clients:
            if info['client'] != client and info['client'].is_connected():
                connected_brokers.append(info)
        
        if not connected_brokers:
            self.mqtt_connected = False
            # Only attempt reconnection if we're not shutting down
            if not self.should_exit:
                self.logger.warning("All MQTT brokers disconnected. Will attempt reconnection...")
                # Don't exit immediately - let reconnection logic handle it
            else:
                self.logger.info("All MQTT brokers disconnected during shutdown")
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
                clean_session=True,
                transport=transport
            )
            
            # Enable paho-mqtt's built-in reconnection
            mqtt_client.enable_logger(self.logger)
            mqtt_client.reconnect_delay_set(min_delay=1, max_delay=120)
            
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
                "origin_id": self.device_public_key.upper() if self.device_public_key and self.device_public_key != 'Unknown' else 'DEVICE'
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
        
        # Publish initial status with firmware version now that MQTT is connected
        if self.enable_mqtt:
            await asyncio.sleep(1)  # Give MQTT connections a moment to stabilize
            await self.publish_status("online")
        
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
    
    

    async def publish_status(self, status, client=None, broker_num=None):
        """Publish status with additional information"""
        firmware_info = await self.get_firmware_info()
        status_msg = {
            "status": status,
            "timestamp": datetime.now().isoformat(),
            "origin": self.device_name,
            "origin_id": self.device_public_key.upper() if self.device_public_key and self.device_public_key != 'Unknown' else 'DEVICE',
            "model": firmware_info.get('model', 'unknown'),
            "firmware_version": firmware_info.get('version', 'unknown'),
            "radio": self.radio_info or "unknown",
            "client_version": self._load_client_version()
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
                    # Check circuit breaker before attempting JWT renewal
                    current_time = time.time()
                    if (current_time - self.jwt_circuit_breaker_reset_time) > self.jwt_circuit_breaker_timeout:
                        self.jwt_failure_count = 0  # Reset circuit breaker
                    
                    if self.jwt_failure_count >= self.max_jwt_failures:
                        self.logger.warning(f"JWT circuit breaker open - too many failures ({self.jwt_failure_count}). Skipping JWT renewal.")
                        return metrics
                    
                    # Schedule renewal only if not already in progress (prevent task explosion)
                    if not self.jwt_renewal_in_progress:
                        self.jwt_renewal_in_progress = True
                        task = asyncio.create_task(self.check_and_renew_jwt_tokens())
                        self.active_tasks.add(task)
                        task.add_done_callback(lambda t: (self.active_tasks.discard(t), setattr(self, 'jwt_renewal_in_progress', False)))
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
    
    async def setup_disconnect_handler(self):
        """Set up handler for disconnect events from meshcore"""
        async def on_disconnect(event):
            reason = event.payload.get('reason', 'unknown')
            self.logger.warning(f"Disconnect event received: {reason}")
            
            if reason == 'tcp_no_response':
                self.logger.error("Disconnected due to no TCP responses - possible WiFi issue")
            elif reason == 'tcp_disconnect':
                self.logger.error("TCP connection closed by remote - possible radio reset")
            elif reason == 'ble_disconnect':
                self.logger.error("BLE connection lost - device may have moved out of range")
            elif reason == 'serial_disconnect':
                self.logger.error("Serial connection lost - cable may be disconnected")
            else:
                self.logger.warning(f"Disconnected for unknown reason: {reason}")
            
            # Update connection status - connection monitor will handle reconnection
            self.connected = False
            self.logger.info("Connection status updated - connection monitor will handle reconnection")
        
        self.meshcore.subscribe(EventType.DISCONNECTED, on_disconnect)
        self.logger.debug("Disconnect event handler registered")

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
        
        # Setup disconnect handler
        await self.setup_disconnect_handler()
        
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
            while not self.should_exit:
                current_time = time.time()
                
                # Check if we should exit for systemd restart
                if self.should_exit_for_systemd_restart():
                    self.logger.critical("Service failure threshold reached - exiting for systemd restart")
                    self.should_exit = True
                
                # Monitor active tasks to prevent explosion
                if current_time - self.last_task_check >= self.task_monitoring_interval:
                    active_count = len(self.active_tasks)
                    if active_count > self.max_active_tasks:
                        self.logger.warning(f"Too many active tasks ({active_count}), cleaning up...")
                        # Cancel excess tasks
                        tasks_to_cancel = list(self.active_tasks)[self.max_active_tasks:]
                        for task in tasks_to_cancel:
                            task.cancel()
                            self.active_tasks.discard(task)
                    self.last_task_check = current_time
                
                # Use shutdown-aware waiting
                if await self.wait_with_shutdown(5):
                    break  # Shutdown was requested
        except KeyboardInterrupt:
            self.logger.info("Received interrupt signal")
        finally:
            # Cancel all active tasks
            monitoring_task.cancel()
            if self.advert_task:
                self.advert_task.cancel()
            if self.jwt_renewal_task:
                self.jwt_renewal_task.cancel()
            
            # Cancel all tracked active tasks
            for task in self.active_tasks.copy():
                task.cancel()
            
            # Wait for all tasks to complete
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
            
            # Wait for all active tasks to complete
            if self.active_tasks:
                await asyncio.gather(*self.active_tasks, return_exceptions=True)
            
            await self.stop()
    
    async def stop(self):
        """Stop packet capture with timeout"""
        self.logger.info("Stopping packet capture...")
        self.connected = False
        
        try:
            # Publish offline status with timeout
            if self.enable_mqtt and self.mqtt_connected:
                await asyncio.wait_for(self.publish_status("offline"), timeout=5.0)
        except asyncio.TimeoutError:
            self.logger.warning("Timeout publishing offline status")
        except Exception as e:
            self.logger.warning(f"Error publishing offline status: {e}")
        
        # Handle BLE disconnection if using BLE connection
        if self.meshcore and self.get_env('CONNECTION_TYPE', 'ble').lower() == 'ble':
            try:
                self.logger.info("Disconnecting BLE device...")
                await asyncio.wait_for(self.meshcore.disconnect(), timeout=10.0)
                
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
            except asyncio.TimeoutError:
                self.logger.warning("Timeout disconnecting BLE device")
            except Exception as e:
                self.logger.warning(f"Error during BLE disconnection: {e}")
        elif self.meshcore:
            try:
                await asyncio.wait_for(self.meshcore.disconnect(), timeout=5.0)
            except asyncio.TimeoutError:
                self.logger.warning("Timeout disconnecting MeshCore device")
            except Exception as e:
                self.logger.warning(f"Error disconnecting MeshCore device: {e}")
        
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
        
        while not self.should_exit:
            try:
                # Calculate seconds until next advert
                current_time = time.time()
                time_since_last = current_time - self.last_advert_time
                interval_seconds = self.advert_interval_hours * 3600
                
                if time_since_last >= interval_seconds:
                    # Time to send an advert
                    await self.send_advert()
                    # Sleep for the full interval to avoid rapid-fire adverts
                    if await self.wait_with_shutdown(interval_seconds):
                        break  # Shutdown was requested
                else:
                    # Sleep until it's time for the next advert
                    sleep_time = interval_seconds - time_since_last
                    if self.debug:
                        self.logger.debug(f"Next advert in {sleep_time/3600:.1f} hours")
                    if await self.wait_with_shutdown(sleep_time):
                        break  # Shutdown was requested
                    
            except asyncio.CancelledError:
                if self.debug:
                    self.logger.debug("Advert scheduler cancelled")
                break
            except Exception as e:
                self.logger.error(f"Error in advert scheduler: {e}")
                if await self.wait_with_shutdown(60):
                    break  # Shutdown was requested
    
    async def jwt_renewal_scheduler(self):
        """Background task to check and renew JWT tokens"""
        if self.jwt_renewal_interval <= 0:
            if self.debug:
                self.logger.debug("JWT renewal scheduling disabled (interval = 0)")
            return
        
        if self.debug:
            self.logger.debug(f"Starting JWT renewal scheduler with {self.jwt_renewal_interval} second interval")
        
        while not self.should_exit:
            try:
                if await self.wait_with_shutdown(self.jwt_renewal_interval):
                    break  # Shutdown was requested
                
                # Check and renew JWT tokens
                await self.check_and_renew_jwt_tokens()
                    
            except asyncio.CancelledError:
                if self.debug:
                    self.logger.debug("JWT renewal scheduler cancelled")
                break
            except Exception as e:
                self.logger.error(f"Error in JWT renewal scheduler: {e}")
                if await self.wait_with_shutdown(60):
                    break  # Shutdown was requested



async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='MeshCore Packet Capture Script')
    parser.add_argument('--output', help='Output file path (optional)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output (shows JSON packet data)')
    parser.add_argument('--debug', action='store_true', help='Enable debug output (shows all detailed debugging info)')
    parser.add_argument('--no-mqtt', action='store_true', help='Disable MQTT publishing')
    
    args = parser.parse_args()
    
    # Command line arguments will be handled after PacketCapture instantiation
    
    # Setup signal handlers for graceful shutdown
    import signal
    
    # Global shutdown event for immediate response
    shutdown_event = asyncio.Event()
    
    def signal_handler(signum, frame):
        capture.logger.info(f"Received signal {signum}, initiating immediate shutdown...")
        capture.should_exit = True
        shutdown_event.set()  # Wake up all waiting tasks immediately
    
    # Register signal handlers
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    # Create packet capture instance with shutdown event
    capture = PacketCapture(
        output_file=args.output, 
        verbose=args.verbose,
        debug=args.debug,
        enable_mqtt=not args.no_mqtt,
        shutdown_event=shutdown_event
    )
    
    # Command line arguments override environment variable
    if args.debug:
        capture.logger.setLevel(logging.DEBUG)
    elif args.verbose:
        capture.logger.setLevel(logging.INFO)
    # If neither debug nor verbose specified, use environment variable (already set in setup_logging)
    
    try:
        # Start the capture in a task so we can wait on shutdown event
        capture_task = asyncio.create_task(capture.start())
        
        # Wait for either completion or shutdown signal
        done, pending = await asyncio.wait(
            [capture_task, asyncio.create_task(shutdown_event.wait())],
            return_when=asyncio.FIRST_COMPLETED
        )
        
        # Cancel any pending tasks
        for task in pending:
            task.cancel()
        
        # If shutdown was triggered, stop the capture
        if shutdown_event.is_set():
            capture.logger.info("Shutdown signal received, stopping capture...")
            await capture.stop()
            
    except KeyboardInterrupt:
        print("\nShutting down...")
        await capture.stop()
    except Exception as e:
        print(f"Error: {e}")
        await capture.stop()


if __name__ == "__main__":
    asyncio.run(main())
