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
import inspect
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
    from auth_token import create_auth_token, create_auth_token_async, read_private_key_file
except ImportError:
    print("Warning: auth_token.py not found - auth token authentication will not be available")
    create_auth_token = None
    create_auth_token_async = None
    read_private_key_file = None

# Private key functionality using meshcore_py library


def get_transport(meshcore_instance):
    """Get transport from meshcore instance using the documented API structure.
    
    Based on meshcore library structure:
    - MeshCore.cx is a ConnectionManager
    - ConnectionManager.connection is the actual connection (TCPConnection, BLEConnection, etc.)
    - TCPConnection.transport is the asyncio transport object
    
    Returns the transport object or None if not available.
    
    Note: This function only returns a reference to the existing transport object
    owned by the meshcore instance. It does not create new objects or store references.
    Transport objects are cleaned up automatically when meshcore.disconnect() is called
    or when the meshcore instance is garbage collected.
    """
    if not meshcore_instance:
        return None
    
    try:
        # MeshCore.cx is a ConnectionManager
        if hasattr(meshcore_instance, 'cx'):
            connection_manager = meshcore_instance.cx
            # ConnectionManager.connection is the actual connection object
            if hasattr(connection_manager, 'connection'):
                connection = connection_manager.connection
                # TCPConnection has a transport attribute
                if hasattr(connection, 'transport'):
                    transport = connection.transport
                    if transport is not None:
                        return transport
    except Exception:
        pass
    
    return None


def enable_tcp_keepalive(transport, idle=10, interval=5, count=3):
    """Enable TCP keepalive on the transport's socket.
    
    Supports multiple transport types:
    - asyncio transport with get_extra_info('socket')
    - Direct socket objects
    - Objects with _socket attribute
    """
    import socket
    
    sock = None
    
    # Try to get socket from transport using get_extra_info
    if hasattr(transport, 'get_extra_info'):
        try:
            sock = transport.get_extra_info('socket')
        except Exception:
            pass
    
    # If not found, check if transport is a socket directly
    if sock is None:
        if isinstance(transport, socket.socket):
            sock = transport
        elif hasattr(transport, '_socket'):
            try:
                sock = transport._socket
            except Exception:
                pass
    
    if sock is None:
        return False
    
    try:
        # Enable TCP keepalive
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        
        # Platform-specific keepalive settings
        # Linux and some BSD systems
        if hasattr(socket, 'TCP_KEEPIDLE'):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, idle)
        # macOS uses different constant names
        elif hasattr(socket, 'TCP_KEEPALIVE'):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPALIVE, idle)
        
        if hasattr(socket, 'TCP_KEEPINTVL'):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval)
        if hasattr(socket, 'TCP_KEEPCNT'):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, count)
        
        return True
    except Exception as e:
        # Log but don't fail the connection
        print(f"Warning: Could not enable TCP keepalive: {e}")
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


# Binary command codes
CMD_APP_START = 1
CMD_SEND_TXT_MSG = 2
CMD_SEND_CHANNEL_TXT_MSG = 3
CMD_GET_CONTACTS = 4
CMD_GET_DEVICE_TIME = 5
CMD_SET_DEVICE_TIME = 6
CMD_SEND_SELF_ADVERT = 7
CMD_SET_ADVERT_NAME = 8
CMD_ADD_UPDATE_CONTACT = 9
CMD_SYNC_NEXT_MESSAGE = 10
CMD_SET_RADIO_PARAMS = 11
CMD_SET_RADIO_TX_POWER = 12
CMD_RESET_PATH = 13
CMD_SET_ADVERT_LATLON = 14
CMD_REMOVE_CONTACT = 15
CMD_SHARE_CONTACT = 16
CMD_EXPORT_CONTACT = 17
CMD_IMPORT_CONTACT = 18
CMD_REBOOT = 19
CMD_GET_BATT_AND_STORAGE = 20
CMD_SET_TUNING_PARAMS = 21
CMD_DEVICE_QUERY = 22
CMD_EXPORT_PRIVATE_KEY = 23
CMD_IMPORT_PRIVATE_KEY = 24
CMD_SEND_RAW_DATA = 25
CMD_SEND_LOGIN = 26
CMD_SEND_STATUS_REQ = 27
CMD_HAS_CONNECTION = 28
CMD_LOGOUT = 29
CMD_GET_CONTACT_BY_KEY = 30
CMD_GET_CHANNEL = 31
CMD_SET_CHANNEL = 32
CMD_SIGN_START = 33
CMD_SIGN_DATA = 34
CMD_SIGN_FINISH = 35
CMD_SEND_TRACE_PATH = 36
CMD_SET_DEVICE_PIN = 37
CMD_SET_OTHER_PARAMS = 38
CMD_SEND_TELEMETRY_REQ = 39
CMD_GET_CUSTOM_VARS = 40
CMD_SET_CUSTOM_VAR = 41
CMD_GET_ADVERT_PATH = 42
CMD_GET_TUNING_PARAMS = 43
CMD_SEND_BINARY_REQ = 50
CMD_FACTORY_RESET = 51
CMD_SEND_PATH_DISCOVERY_REQ = 52
CMD_SET_FLOOD_SCOPE = 54
CMD_SEND_CONTROL_DATA = 55
CMD_GET_STATS = 56

# Response codes
RESP_CODE_OK = 1
RESP_CODE_ERR = 0
RESP_CODE_CONTACTS_START = 2
RESP_CODE_CONTACT = 3
RESP_CODE_END_OF_CONTACTS = 4
RESP_CODE_SELF_INFO = 5
RESP_CODE_SENT = 6
RESP_CODE_CONTACT_MSG_RECV = 7
RESP_CODE_CHANNEL_MSG_RECV = 8
RESP_CODE_CURR_TIME = 9
RESP_CODE_NO_MORE_MESSAGES = 10
RESP_CODE_EXPORT_CONTACT = 11
RESP_CODE_BATT_AND_STORAGE = 12
RESP_CODE_DEVICE_INFO = 13
RESP_CODE_PRIVATE_KEY = 14
RESP_CODE_DISABLED = 15
RESP_CODE_CONTACT_MSG_RECV_V3 = 16
RESP_CODE_CHANNEL_MSG_RECV_V3 = 17
RESP_CODE_CHANNEL_INFO = 18
RESP_CODE_SIGN_START = 19
RESP_CODE_SIGNATURE = 20
RESP_CODE_CUSTOM_VARS = 21
RESP_CODE_ADVERT_PATH = 22
RESP_CODE_TUNING_PARAMS = 23
RESP_CODE_STATS = 24

# Push notification codes
PUSH_CODE_ADVERT = 0x80
PUSH_CODE_PATH_UPDATED = 0x81
PUSH_CODE_SEND_CONFIRMED = 0x82
PUSH_CODE_MSG_WAITING = 0x83
PUSH_CODE_RAW_DATA = 0x84
PUSH_CODE_LOGIN_SUCCESS = 0x85
PUSH_CODE_LOGIN_FAIL = 0x86
PUSH_CODE_STATUS_RESPONSE = 0x87
PUSH_CODE_LOG_RX_DATA = 0x88
PUSH_CODE_TRACE_DATA = 0x89
PUSH_CODE_NEW_ADVERT = 0x8A
PUSH_CODE_TELEMETRY_RESPONSE = 0x8B
PUSH_CODE_BINARY_RESPONSE = 0x8C
PUSH_CODE_PATH_DISCOVERY_RESPONSE = 0x8D
PUSH_CODE_CONTROL_DATA = 0x8E

# Blocked commands (app lifecycle commands that would disrupt packet capture)
BLOCKED_COMMANDS = {
    CMD_APP_START,
    CMD_LOGOUT,
    CMD_REBOOT,
    CMD_FACTORY_RESET
}


class BinaryCommandProxy:
    """TCP server that proxies binary commands from companion apps to the radio"""
    
    # Framing protocol constants (ArduinoSerialInterface)
    FRAME_HEADER_IN = 0x3C  # '<' - incoming frames (companion → radio)
    FRAME_HEADER_OUT = 0x3E  # '>' - outgoing frames (radio → companion)
    
    def __init__(self, meshcore_instance, logger, enabled=True, host='0.0.0.0', port=5000):
        self.meshcore = meshcore_instance
        self.logger = logger
        self.enabled = enabled
        self.host = host
        self.port = port
        self.server = None
        self.clients = set()  # Set of connected client writers
        self.running = False
        self.command_connection = None  # Secondary connection for command forwarding (TCP only)
        self.command_reader = None
        self.command_writer = None
        self.pending_responses = {}  # Map of cmd_code to list of (writer, response_event, response_data, timestamp, timed_out)
        self.response_handlers = {}  # Map of EventType to handler functions
        self.response_lock = asyncio.Lock()  # Lock for pending_responses access
        self.event_subscriptions = []  # Track event subscriptions for cleanup

        # Phase 3: Event buffering for race condition handling
        self.buffered_events = {}  # Map of cmd_code to list of (resp_code, event, timestamp)
        self.event_buffer_timeout = 2.0  # Buffer events for 2 seconds
        self.event_buffer_cleanup_task = None

        # Phase 5: Statistics and monitoring
        self.command_stats = {}  # Map of cmd_code to {success: int, timeout: int, error: int, total_time: float}
        self.stats_lock = asyncio.Lock()
        self.last_stats_log_time = 0
        self.stats_log_interval = 60  # Log statistics every 60 seconds
    
    def wrap_frame(self, data: bytes) -> bytes:
        """Wrap data with outgoing frame protocol: '>' + 2-byte LE length + payload"""
        length = len(data)
        frame = bytes([self.FRAME_HEADER_OUT])  # '>'
        frame += length.to_bytes(2, 'little')  # 2-byte little-endian length
        frame += data  # Payload
        return frame
    
    def unwrap_frame(self, data: bytes) -> tuple[bytes, int]:
        """
        Parse incoming frame protocol: '<' + 2-byte LE length + payload
        Returns: (payload, bytes_consumed)
        Raises ValueError if frame is malformed
        """
        if len(data) < 3:
            raise ValueError(f"Frame too short: {len(data)} bytes (need at least 3)")
        
        if data[0] != self.FRAME_HEADER_IN:
            raise ValueError(f"Invalid frame header: 0x{data[0]:02X} (expected 0x{self.FRAME_HEADER_IN:02X})")
        
        # Read 2-byte little-endian length
        length = int.from_bytes(data[1:3], 'little')
        
        # Check if we have enough data
        if len(data) < 3 + length:
            raise ValueError(f"Incomplete frame: have {len(data)} bytes, need {3 + length} bytes")
        
        # Extract payload
        payload = data[3:3 + length]
        bytes_consumed = 3 + length
        
        return payload, bytes_consumed
        
    async def start(self):
        """Start the TCP server"""
        if not self.enabled:
            self.logger.debug("Binary interface proxy disabled")
            return
        
        if self.running:
            self.logger.warning("Binary interface proxy already running")
            return
        
        self.logger.info(f"Initializing binary interface proxy on {self.host}:{self.port}")
        
        # Setup event handlers to intercept responses
        await self.setup_event_handlers()
        
        # Setup command forwarding connection if radio is connected via TCP
        await self.setup_command_connection()
        
        try:
            self.logger.debug(f"Creating TCP server on {self.host}:{self.port}")
            self.server = await asyncio.start_server(
                self.handle_client,
                self.host,
                self.port
            )
            self.running = True
            addr = self.server.sockets[0].getsockname()
            self.logger.info(f"Binary interface proxy listening on {addr[0]}:{addr[1]}")
        except OSError as e:
            if e.errno == 48:  # Address already in use
                self.logger.error(f"Port {self.port} is already in use. Another process may be using it.")
            else:
                self.logger.error(f"Failed to start binary interface proxy: {e}")
            self.running = False
            raise
        except Exception as e:
            self.logger.error(f"Failed to start binary interface proxy: {e}", exc_info=True)
            self.running = False
            raise
    
    async def setup_command_connection(self):
        """Setup a secondary connection to the radio for command forwarding (TCP only)"""
        if not self.meshcore or not self.meshcore.is_connected:
            return
        
        # Try to determine connection type
        connection_type = None
        tcp_host = None
        tcp_port = None
        
        try:
            if hasattr(self.meshcore, 'cx') and hasattr(self.meshcore.cx, 'connection'):
                conn = self.meshcore.cx.connection
                conn_type_str = str(type(conn)).lower()
                if 'tcp' in conn_type_str:
                    connection_type = 'tcp'
                    # Try to get host/port from connection
                    if hasattr(conn, 'host') and hasattr(conn, 'port'):
                        tcp_host = conn.host
                        tcp_port = conn.port
                    elif hasattr(conn, '_host') and hasattr(conn, '_port'):
                        tcp_host = conn._host
                        tcp_port = conn._port
                elif 'ble' in conn_type_str:
                    connection_type = 'ble'
                elif 'serial' in conn_type_str:
                    connection_type = 'serial'
        except Exception as e:
            self.logger.debug(f"Could not determine connection type: {e}")
        
        # Only create secondary connection for TCP if we have host/port
        # Note: This may not work if the radio only accepts one connection
        if connection_type == 'tcp' and tcp_host and tcp_port:
            try:
                # Create secondary TCP connection for command forwarding
                self.command_reader, self.command_writer = await asyncio.wait_for(
                    asyncio.open_connection(tcp_host, tcp_port),
                    timeout=5.0
                )
                # Start response reader task
                asyncio.create_task(self.read_command_responses())
                self.logger.info(f"Command forwarding connection established to {tcp_host}:{tcp_port}")
            except asyncio.TimeoutError:
                self.logger.warning("Timeout creating secondary command connection - radio may only accept one connection")
                self.logger.info("Command forwarding will use primary connection transport (if accessible)")
            except Exception as e:
                self.logger.warning(f"Could not create secondary command connection: {e}")
                self.logger.info("Command forwarding will use primary connection transport (if accessible)")
        else:
            self.logger.info(f"Command forwarding for {connection_type} connections will use meshcore command interface where possible")
    
    async def setup_event_handlers(self):
        """Setup event handlers to intercept command responses"""
        if not self.meshcore:
            return
        
        # Map EventType to response codes and command codes
        async def handle_device_info(event):
            """Handle DEVICE_INFO event (response to CMD_DEVICE_QUERY)"""
            self.logger.debug(f"DEVICE_INFO event received in handler")
            await self.handle_response_event(CMD_DEVICE_QUERY, RESP_CODE_DEVICE_INFO, event)
        
        async def handle_batt_storage(event):
            """Handle battery/storage event (response to CMD_GET_BATT_AND_STORAGE)"""
            await self.handle_response_event(CMD_GET_BATT_AND_STORAGE, RESP_CODE_BATT_AND_STORAGE, event)
        
        async def handle_ok(event):
            """Handle OK event (generic success response)"""
            # Try to match to any pending command
            async with self.response_lock:
                # Find oldest pending command without a specific event type
                for cmd_code in list(self.pending_responses.keys()):
                    if self.pending_responses[cmd_code]:
                        await self.send_response_to_pending(cmd_code, RESP_CODE_OK, b'')
                        break
        
        async def handle_error(event):
            """Handle ERROR event (generic error response)"""
            # Try to match to any pending command
            async with self.response_lock:
                for cmd_code in list(self.pending_responses.keys()):
                    if self.pending_responses[cmd_code]:
                        error_code = 1  # ERR_CODE_UNSUPPORTED_CMD
                        if hasattr(event, 'payload') and event.payload:
                            # Try to extract error code from payload
                            if isinstance(event.payload, dict) and 'error_code' in event.payload:
                                error_code = event.payload['error_code']
                        error_response = bytes([RESP_CODE_ERR, error_code])
                        await self.send_response_to_pending(cmd_code, None, error_response)
                        break
        
        # Subscribe to events
        try:
            self.meshcore.subscribe(EventType.DEVICE_INFO, handle_device_info)
            self.event_subscriptions.append((EventType.DEVICE_INFO, handle_device_info))

            # Try to subscribe to BATTERY event (may not exist in all versions)
            try:
                if hasattr(EventType, 'BATTERY'):
                    self.meshcore.subscribe(EventType.BATTERY, handle_batt_storage)
                    self.event_subscriptions.append((EventType.BATTERY, handle_batt_storage))
                    self.logger.debug("Subscribed to BATTERY event")
                elif hasattr(EventType, 'BATT_AND_STORAGE'):
                    self.meshcore.subscribe(EventType.BATT_AND_STORAGE, handle_batt_storage)
                    self.event_subscriptions.append((EventType.BATT_AND_STORAGE, handle_batt_storage))
                    self.logger.debug("Subscribed to BATT_AND_STORAGE event")
                else:
                    self.logger.debug("No battery event type available")
            except Exception as e:
                self.logger.debug(f"Could not subscribe to battery events: {e}")

            self.meshcore.subscribe(EventType.OK, handle_ok)
            self.event_subscriptions.append((EventType.OK, handle_ok))
            self.meshcore.subscribe(EventType.ERROR, handle_error)
            self.event_subscriptions.append((EventType.ERROR, handle_error))
            self.logger.debug("Event handlers registered for binary interface")
        except Exception as e:
            self.logger.warning(f"Could not register all event handlers: {e}")
    
    async def handle_response_event(self, cmd_code, resp_code, event):
        """Handle a response event and send it to pending command"""
        # Phase 1: Add detailed event handler logging
        event_start_time = time.time()
        async with self.response_lock:
            pending_count = len(self.pending_responses.get(cmd_code, []))
            if cmd_code not in self.pending_responses or not self.pending_responses[cmd_code]:
                # Phase 3: Buffer event for possible late-arriving pending response
                self.logger.debug(f"Event handler: No pending command {cmd_code} for {resp_code} response - buffering event (total pending commands: {len(self.pending_responses)})")

                if cmd_code not in self.buffered_events:
                    self.buffered_events[cmd_code] = []

                self.buffered_events[cmd_code].append((resp_code, event, time.time()))
                self.logger.debug(f"Event handler: Buffered event for cmd_code {cmd_code}, buffer now has {len(self.buffered_events[cmd_code])} event(s)")
                return

            self.logger.debug(f"Event handler: Found {pending_count} pending command(s) for {cmd_code}, converting event to binary")

            # Pop the pending entry (we're already holding the lock)
            pending_entry = self.pending_responses[cmd_code].pop(0)
            if not self.pending_responses[cmd_code]:
                del self.pending_responses[cmd_code]

            if len(pending_entry) == 5:
                writer, response_event, _, queued_time, timed_out = pending_entry
            else:
                writer, response_event, _, queued_time = pending_entry
                timed_out = False

        # Release lock before doing I/O
        wait_time = time.time() - queued_time
        self.logger.debug(f"Event handler: Sending response for command {cmd_code} (waited {wait_time:.3f}s in queue)")

        # Convert event to binary response
        response_data = self.event_to_binary(resp_code, event)

        # Build final response
        if len(response_data) > 0 and response_data[0] == resp_code:
            final_response = response_data
        else:
            final_response = bytes([resp_code]) + response_data

        # Send response
        try:
            wrapped_response = self.wrap_frame(final_response)
            self.logger.debug(f"Event handler: Sending wrapped response ({len(wrapped_response)} bytes, payload {len(final_response)} bytes): {wrapped_response.hex()}")
            writer.write(wrapped_response)
            await writer.drain()
            response_event.set()
        except Exception as e:
            self.logger.error(f"Event handler: Error sending response for command {cmd_code}: {e}", exc_info=True)

        event_duration = time.time() - event_start_time
        self.logger.debug(f"Event handler: Processed {resp_code} event for command {cmd_code} in {event_duration:.3f}s")
    
    def event_to_binary(self, resp_code, event):
        """Convert meshcore_py event to binary response format"""
        response = bytes([resp_code])
        
        if resp_code == RESP_CODE_DEVICE_INFO:
            # Format from MyMesh.cpp lines 828-845:
            # [0] RESP_CODE_DEVICE_INFO (13)
            # [1] FIRMWARE_VER_CODE (1 byte) - firmware version code
            # [2] MAX_CONTACTS / 2 (1 byte) - max contacts (divided by 2)
            # [3] MAX_GROUP_CHANNELS (1 byte) - max channels
            # [4-7] BLE PIN (4 bytes, little-endian)
            # [8-19] FIRMWARE_BUILD_DATE (12 bytes, null-terminated string)
            # [20-59] Manufacturer name (40 bytes, null-terminated string)
            # [60-79] FIRMWARE_VERSION (20 bytes, null-terminated string)
            payload = event.payload if hasattr(event, 'payload') else {}
            
            # Debug: log the actual event structure
            self.logger.debug(f"DEVICE_INFO event payload type: {type(payload)}, content: {payload}")
            if hasattr(event, '__dict__'):
                self.logger.debug(f"DEVICE_INFO event attributes: {event.__dict__}")
            
            # Extract fields from payload (using actual keys from meshcore_py)
            if isinstance(payload, dict):
                fw_ver = payload.get('fw ver', payload.get('firmware_version', payload.get('fw_version', 8)))
                max_contacts = payload.get('max_contacts', 350)
                max_channels = payload.get('max_channels', 40)
                ble_pin = payload.get('ble_pin', 0)
                fw_build = payload.get('fw_build', payload.get('firmware_build', '30 Nov 2025'))
                manufacturer = payload.get('model', payload.get('manufacturer', payload.get('manufacturer_name', '')))
                fw_version_str = payload.get('ver', payload.get('version', payload.get('firmware_version_str', 'v1.11.0')))
            else:
                # Try to access as attributes
                fw_ver = getattr(payload, 'fw_ver', getattr(payload, 'firmware_version', 8)) if payload else 8
                max_contacts = getattr(payload, 'max_contacts', 350) if payload else 350
                max_channels = getattr(payload, 'max_channels', 40) if payload else 40
                ble_pin = getattr(payload, 'ble_pin', 0) if payload else 0
                fw_build = getattr(payload, 'fw_build', '30 Nov 2025') if payload else '30 Nov 2025'
                manufacturer = getattr(payload, 'model', getattr(payload, 'manufacturer', '')) if payload else ''
                fw_version_str = getattr(payload, 'ver', getattr(payload, 'version', 'v1.11.0')) if payload else 'v1.11.0'
            
            # Ensure values are correct types
            try:
                fw_ver = int(fw_ver) if fw_ver else 8
            except (ValueError, TypeError):
                fw_ver = 8
            try:
                max_contacts = int(max_contacts) if max_contacts else 350
            except (ValueError, TypeError):
                max_contacts = 350
            try:
                max_channels = int(max_channels) if max_channels else 40
            except (ValueError, TypeError):
                max_channels = 40
            try:
                ble_pin = int(ble_pin) if ble_pin else 0
            except (ValueError, TypeError):
                ble_pin = 0
            
            # Build response according to radio format
            # [0] RESP_CODE_DEVICE_INFO (already in response)
            # [1] FIRMWARE_VER_CODE (1 byte)
            response += bytes([fw_ver])
            
            # [2] MAX_CONTACTS / 2 (1 byte) - note: divided by 2!
            response += bytes([max_contacts // 2])
            
            # [3] MAX_GROUP_CHANNELS (1 byte)
            response += bytes([max_channels])
            
            # [4-7] BLE PIN (4 bytes, little-endian)
            response += ble_pin.to_bytes(4, 'little')
            
            # [8-19] FIRMWARE_BUILD_DATE (12 bytes, null-terminated)
            fw_build_bytes = str(fw_build).encode('utf-8')[:11]  # Max 11 bytes + null terminator
            response += fw_build_bytes.ljust(12, b'\x00')
            
            # [20-59] Manufacturer name (40 bytes, null-terminated)
            manufacturer_bytes = str(manufacturer).encode('utf-8')[:39]  # Max 39 bytes + null terminator
            response += manufacturer_bytes.ljust(40, b'\x00')
            
            # [60-79] FIRMWARE_VERSION (20 bytes, null-terminated)
            fw_version_bytes = str(fw_version_str).encode('utf-8')[:19]  # Max 19 bytes + null terminator
            response += fw_version_bytes.ljust(20, b'\x00')
            
            self.logger.debug(f"Built DEVICE_INFO response: {len(response)} bytes, fw_ver={fw_ver}, contacts={max_contacts//2}, channels={max_channels}, pin={ble_pin}, build={fw_build}, mfg={manufacturer}, ver={fw_version_str}")
            
        elif resp_code == RESP_CODE_BATT_AND_STORAGE:
            # Format from MyMesh.cpp lines 1215-1225:
            # [0] RESP_CODE_BATT_AND_STORAGE (12)
            # [1-2] battery_millivolts (2 bytes, little-endian)
            # [3-6] storage_used (4 bytes, little-endian)
            # [7-10] storage_total (4 bytes, little-endian)
            payload = event.payload if hasattr(event, 'payload') else {}
            
            # Debug: log the actual event structure
            self.logger.debug(f"BATT_AND_STORAGE event payload type: {type(payload)}, content: {payload}")
            
            # Extract fields from payload
            if isinstance(payload, dict):
                battery_mv = payload.get('battery_millivolts', payload.get('battery_mv', payload.get('battery', 0)))
                storage_used = payload.get('storage_used', payload.get('storageUsed', 0))
                storage_total = payload.get('storage_total', payload.get('storageTotal', 0))
            else:
                battery_mv = getattr(payload, 'battery_millivolts', getattr(payload, 'battery_mv', 0)) if payload else 0
                storage_used = getattr(payload, 'storage_used', getattr(payload, 'storageUsed', 0)) if payload else 0
                storage_total = getattr(payload, 'storage_total', getattr(payload, 'storageTotal', 0)) if payload else 0
            
            # Ensure values are integers
            try:
                battery_mv = int(battery_mv) if battery_mv else 0
            except (ValueError, TypeError):
                battery_mv = 0
            try:
                storage_used = int(storage_used) if storage_used else 0
            except (ValueError, TypeError):
                storage_used = 0
            try:
                storage_total = int(storage_total) if storage_total else 0
            except (ValueError, TypeError):
                storage_total = 0
            
            # Battery millivolts (2 bytes, little-endian)
            response += battery_mv.to_bytes(2, 'little')
            
            # Storage used (4 bytes, little-endian)
            response += storage_used.to_bytes(4, 'little')
            
            # Storage total (4 bytes, little-endian)
            response += storage_total.to_bytes(4, 'little')
            
            self.logger.debug(f"Built BATT_AND_STORAGE response: {len(response)} bytes, battery_mv={battery_mv}, storage_used={storage_used}, storage_total={storage_total}")
        
        elif resp_code == RESP_CODE_OK:
            # Just the response code, no additional data
            pass
        
        return response
    
    async def send_response_to_pending(self, cmd_code, resp_code, response_data):
        """Send response to pending command and remove from pending list"""
        # Phase 1: Track response timing
        response_start_time = time.time()

        # CRITICAL: Acquire lock before accessing pending_responses
        async with self.response_lock:
            if cmd_code not in self.pending_responses:
                self.logger.debug(f"send_response_to_pending: No pending responses for command {cmd_code}")
                return

            pending_list = self.pending_responses[cmd_code]
            if not pending_list:
                self.logger.debug(f"send_response_to_pending: Pending list empty for command {cmd_code}")
                return

            # Get the first pending command (FIFO)
            # Handle both old format (4 elements) and new format (5 elements with timed_out flag)
            pending_entry = pending_list.pop(0)
            if len(pending_entry) == 5:
                writer, response_event, _, queued_time, timed_out = pending_entry
            else:
                writer, response_event, _, queued_time = pending_entry
                timed_out = False

            wait_time = time.time() - queued_time
            if timed_out:
                self.logger.warning(f"send_response_to_pending: Sending late response for command {cmd_code} (waited {wait_time:.3f}s - was timed out)")
            else:
                self.logger.debug(f"send_response_to_pending: Sending response for command {cmd_code} (waited {wait_time:.3f}s in queue)")

            # If no more pending, remove the entry
            if not pending_list:
                del self.pending_responses[cmd_code]
        
        # Build final response if resp_code provided
        if resp_code is not None:
            if len(response_data) > 0 and response_data[0] == resp_code:
                # Response already has correct code
                final_response = response_data
            else:
                # Prepend response code
                final_response = bytes([resp_code]) + response_data
        else:
            final_response = response_data
        
        # Wrap and send
        try:
            wrapped_response = self.wrap_frame(final_response)
            # Debug: log the wrapped frame for inspection
            if self.logger.isEnabledFor(logging.DEBUG):
                self.logger.debug(f"Wrapped response for command {cmd_code}: {len(wrapped_response)} bytes total (payload: {len(final_response)} bytes)")
                # Verify frame header and length
                if len(wrapped_response) >= 3:
                    header = wrapped_response[0]
                    length_lsb = wrapped_response[1]
                    length_msb = wrapped_response[2]
                    calculated_length = length_lsb | (length_msb << 8)
                    self.logger.debug(f"Frame header: 0x{header:02X} (expected 0x{self.FRAME_HEADER_OUT:02X}), length: {calculated_length} (expected {len(final_response)})")
                    if header != self.FRAME_HEADER_OUT:
                        self.logger.warning(f"Invalid frame header: 0x{header:02X} (expected 0x{self.FRAME_HEADER_OUT:02X})")
                    if calculated_length != len(final_response):
                        self.logger.warning(f"Length mismatch: {calculated_length} != {len(final_response)}")
                if len(wrapped_response) <= 100:
                    self.logger.debug(f"Wrapped frame hex: {wrapped_response.hex()}")
                else:
                    self.logger.debug(f"Wrapped frame hex (first 100 bytes): {wrapped_response[:100].hex()}...")
            
            writer.write(wrapped_response)
            await writer.drain()
            # Ensure the data is fully sent
            if hasattr(writer, 'flush'):
                await writer.flush() if inspect.iscoroutinefunction(writer.flush) else writer.flush()
            self.logger.debug(f"Sent response to command {cmd_code}: {len(final_response)} bytes payload, {len(wrapped_response)} bytes total (wrapped)")
        except Exception as e:
            self.logger.warning(f"Error sending response to command {cmd_code}: {e}", exc_info=True)
        finally:
            # Signal the event to unblock waiting command
            response_event.set()
    
    async def read_command_responses(self):
        """Read push notifications from command forwarding connection"""
        # This task only handles push notifications (0x80-0x8E)
        # Regular command responses are handled synchronously in forward_command
        try:
            while self.running and self.command_reader:
                # Peek at next byte to see if it's a push notification
                # Note: This is simplified - in practice we'd need proper framing
                # For now, we'll read and check
                try:
                    response_code = await asyncio.wait_for(
                        self.command_reader.read(1),
                        timeout=1.0
                    )
                    if not response_code:
                        break
                    
                    code = response_code[0]
                    
                    # Only handle push notifications here
                    # Regular responses are handled in forward_command
                    if 0x80 <= code <= 0x8E:
                        # Push notification - forward to all clients
                        # Read remaining data
                        remaining = await asyncio.wait_for(
                            self.command_reader.read(1024),
                            timeout=1.0
                        )
                        await self.forward_push_notification(code, remaining)
                    else:
                        # This is a regular response that should have been handled
                        # in forward_command. Put it back if possible, or log warning
                        self.logger.warning(f"Unexpected response code {code} in push notification reader")
                        # Read and discard (or we could try to handle it)
                        await asyncio.wait_for(
                            self.command_reader.read(1024),
                            timeout=0.1
                        )
                except asyncio.TimeoutError:
                    # No data available, continue loop
                    continue
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.logger.error(f"Error reading push notifications: {e}", exc_info=True)
    
    async def stop(self):
        """Stop the TCP server"""
        if not self.running:
            return
        
        self.running = False
        
        # Close command forwarding connection
        if self.command_writer:
            try:
                self.command_writer.close()
                await self.command_writer.wait_closed()
            except Exception:
                pass
            self.command_writer = None
            self.command_reader = None
        
        # Close all client connections
        for writer in self.clients.copy():
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        self.clients.clear()
        
        # Close server
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.logger.info("Binary interface proxy stopped")
    
    async def handle_client(self, reader, writer):
        """Handle a new client connection"""
        try:
            client_addr = writer.get_extra_info('peername')
            self.logger.info(f"Binary interface client connected from {client_addr}")
        except Exception:
            client_addr = "unknown"
            self.logger.info(f"Binary interface client connected from {client_addr}")
        self.clients.add(writer)
        
        try:
            while self.running:
                # Read frame header (expect '<' 0x3C)
                frame_header = await reader.read(1)
                if not frame_header:
                    break
                
                if frame_header[0] != self.FRAME_HEADER_IN:
                    self.logger.warning(f"Invalid frame header from {client_addr}: 0x{frame_header[0]:02X} (expected 0x{self.FRAME_HEADER_IN:02X})")
                    # Try to send error response (wrapped in frame)
                    try:
                        error_response = bytes([RESP_CODE_ERR, 1])  # ERR_CODE_UNSUPPORTED_CMD
                        wrapped_error = self.wrap_frame(error_response)
                        writer.write(wrapped_error)
                        await writer.drain()
                    except Exception:
                        pass
                    break
                
                # Read 2-byte little-endian length
                length_bytes = await reader.read(2)
                if len(length_bytes) < 2:
                    self.logger.warning(f"Incomplete length field from {client_addr}")
                    break
                
                length = int.from_bytes(length_bytes, 'little')
                
                # Validate length (reasonable maximum)
                if length > 4096:
                    self.logger.warning(f"Frame length too large from {client_addr}: {length} bytes")
                    # Try to send error response
                    try:
                        error_response = bytes([RESP_CODE_ERR, 1])  # ERR_CODE_UNSUPPORTED_CMD
                        wrapped_error = self.wrap_frame(error_response)
                        writer.write(wrapped_error)
                        await writer.drain()
                    except Exception:
                        pass
                    break
                
                # Read exactly 'length' bytes of payload
                payload = b''
                while len(payload) < length:
                    chunk = await reader.read(length - len(payload))
                    if not chunk:
                        self.logger.warning(f"Incomplete frame payload from {client_addr}: got {len(payload)}/{length} bytes")
                        break
                    payload += chunk
                
                if len(payload) < length:
                    # Incomplete payload - skip this frame
                    continue
                
                # Extract command code from payload (first byte)
                if not payload:
                    self.logger.warning(f"Empty payload from {client_addr}")
                    continue
                
                cmd_code = payload[0]
                command_data = payload  # Full payload is the command

                # Phase 1: Add timing for command reception
                cmd_received_time = time.time()

                # Log the full command for debugging
                if self.logger.isEnabledFor(logging.DEBUG):
                    self.logger.debug(f"[T+0.000s] Received framed command {cmd_code} (0x{cmd_code:02X}) with {len(payload)} bytes payload from {client_addr}")
                    if len(command_data) <= 64:
                        self.logger.debug(f"Full command data: {command_data.hex()}")
                    else:
                        self.logger.debug(f"Command data (first 64 bytes): {command_data[:64].hex()}...")

                # Handle the command (pass unwrapped payload)
                await self.process_command(writer, cmd_code, command_data)

                # Phase 1: Log total command handling time
                cmd_duration = time.time() - cmd_received_time
                self.logger.debug(f"[T+{cmd_duration:.3f}s] Command {cmd_code} (0x{cmd_code:02X}) processing complete")
                
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.logger.error(f"Error handling client {client_addr}: {e}", exc_info=True)
        finally:
            self.clients.discard(writer)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            self.logger.info(f"Binary interface client {client_addr} disconnected")
    
    def cleanup_event_subscriptions(self):
        """Clean up event subscriptions"""
        if not self.meshcore:
            return

        for event_type, handler in self.event_subscriptions:
            try:
                self.meshcore.unsubscribe(event_type, handler)
            except Exception as e:
                self.logger.debug(f"Error unsubscribing from {event_type}: {e}")

        self.event_subscriptions.clear()

    async def record_command_result(self, cmd_code, result_type, duration):
        """Phase 5: Record command statistics"""
        async with self.stats_lock:
            if cmd_code not in self.command_stats:
                self.command_stats[cmd_code] = {
                    'success': 0,
                    'timeout': 0,
                    'error': 0,
                    'total_time': 0.0,
                    'count': 0
                }

            stats = self.command_stats[cmd_code]
            stats[result_type] += 1
            stats['count'] += 1
            stats['total_time'] += duration

            # Log statistics periodically
            current_time = time.time()
            if current_time - self.last_stats_log_time >= self.stats_log_interval:
                self.log_statistics()
                self.last_stats_log_time = current_time

    def log_statistics(self):
        """Phase 5: Log command statistics"""
        if not self.command_stats:
            return

        self.logger.info("=== Binary Interface Command Statistics ===")
        for cmd_code, stats in self.command_stats.items():
            total = stats['count']
            if total == 0:
                continue

            success_rate = (stats['success'] / total) * 100
            timeout_rate = (stats['timeout'] / total) * 100
            error_rate = (stats['error'] / total) * 100
            avg_time = stats['total_time'] / total

            self.logger.info(
                f"  Cmd {cmd_code} (0x{cmd_code:02X}): "
                f"{total} total, "
                f"{stats['success']} success ({success_rate:.1f}%), "
                f"{stats['timeout']} timeout ({timeout_rate:.1f}%), "
                f"{stats['error']} error ({error_rate:.1f}%), "
                f"avg time: {avg_time:.3f}s"
            )

            # Warn if timeout rate is high
            if timeout_rate > 20:
                self.logger.warning(f"High timeout rate for command {cmd_code}: {timeout_rate:.1f}%")
    
    async def process_command(self, writer, cmd_code, command_data):
        """Process a command from a client"""
        if cmd_code in BLOCKED_COMMANDS:
            # Block app lifecycle commands and simulate success
            self.logger.debug(f"Blocked command {cmd_code} (app lifecycle command)")
            await self.send_blocked_response(writer, cmd_code)
        else:
            # Forward command to radio
            await self.forward_command(writer, cmd_code, command_data)
    
    async def send_blocked_response(self, writer, cmd_code):
        """Send a simulated success response for a blocked command (wrapped in frame protocol)"""
        if cmd_code == CMD_APP_START:
            # CMD_APP_START expects RESP_CODE_OK followed by RESP_CODE_SELF_INFO
            # Send OK response (wrapped in frame)
            ok_response = bytes([RESP_CODE_OK])
            wrapped_ok = self.wrap_frame(ok_response)
            self.logger.debug(f"CMD_APP_START: Sending RESP_CODE_OK frame: {wrapped_ok.hex()}")
            writer.write(wrapped_ok)
            await writer.drain()
            
            # Send self_info response (wrapped in frame)
            if self.meshcore and self.meshcore.self_info:
                self_info = self.meshcore.self_info
                # Build RESP_CODE_SELF_INFO per spec (58+ bytes + null-terminated name)
                # See: local-docs/companion_radio_binary_commands.md lines 178-199

                # Extract fields from self_info
                name = self_info.get('name', '').encode('utf-8') + b'\x00'  # null-terminated
                public_key_hex = self_info.get('public_key', '')
                try:
                    public_key_bytes = bytes.fromhex(public_key_hex) if public_key_hex else bytes(32)
                except Exception:
                    public_key_bytes = bytes(32)

                # Build response frame per spec
                response = bytes([RESP_CODE_SELF_INFO])  # 0: response_code
                response += bytes([self_info.get('advert_type', 1)])  # 1: advert_type (1=ADV_TYPE_CHAT)
                response += bytes([self_info.get('tx_power', 22)])  # 2: tx_power_dbm
                response += bytes([self_info.get('max_tx_power', 22)])  # 3: max_tx_power
                response += public_key_bytes  # 4-35: public_key (32 bytes)

                # Lat/lon as int32 little-endian (multiplied by 1e6)
                lat = int(self_info.get('latitude', 0) * 1e6)
                lon = int(self_info.get('longitude', 0) * 1e6)
                response += lat.to_bytes(4, 'little', signed=True)  # 36-39: latitude
                response += lon.to_bytes(4, 'little', signed=True)  # 40-43: longitude

                response += bytes([self_info.get('multi_acks', 0)])  # 44: multi_acks
                response += bytes([self_info.get('advert_loc_policy', 0)])  # 45: advert_loc_policy
                response += bytes([self_info.get('telemetry_mode', 0)])  # 46: telemetry_mode
                response += bytes([self_info.get('manual_add_contacts', 0)])  # 47: manual_add_contacts

                # Radio params as uint32 little-endian (divided by 1000)
                freq = int(self_info.get('frequency', 915000000) / 1000)
                bw = int(self_info.get('bandwidth', 500000) / 1000)
                response += freq.to_bytes(4, 'little')  # 48-51: freq
                response += bw.to_bytes(4, 'little')  # 52-55: bw

                response += bytes([self_info.get('spreading_factor', 9)])  # 56: sf
                response += bytes([self_info.get('coding_rate', 7)])  # 57: cr
                response += name  # 58+: node_name (null-terminated)

                self.logger.debug(f"CMD_APP_START: SELF_INFO payload ({len(response)} bytes): name='{name[:-1].decode('utf-8', errors='ignore')}', public_key={public_key_bytes.hex()[:16]}...")

                # Wrap in frame protocol
                wrapped_response = self.wrap_frame(response)
                self.logger.debug(f"CMD_APP_START: Sending RESP_CODE_SELF_INFO frame: {wrapped_response.hex()}")
                writer.write(wrapped_response)
                await writer.drain()
            else:
                # Fallback: send minimal self_info per spec
                name = b'PacketCapture\x00'  # null-terminated
                response = bytes([RESP_CODE_SELF_INFO])  # 0: response_code
                response += bytes([1])  # 1: advert_type (1=ADV_TYPE_CHAT)
                response += bytes([22])  # 2: tx_power_dbm (22 dBm default)
                response += bytes([22])  # 3: max_tx_power
                response += bytes(32)  # 4-35: empty public_key
                response += bytes(8)  # 36-43: lat/lon (zeros)
                response += bytes([0])  # 44: multi_acks
                response += bytes([0])  # 45: advert_loc_policy
                response += bytes([0])  # 46: telemetry_mode
                response += bytes([0])  # 47: manual_add_contacts
                response += int(915000).to_bytes(4, 'little')  # 48-51: freq (915MHz)
                response += int(500).to_bytes(4, 'little')  # 52-55: bw (500kHz)
                response += bytes([9])  # 56: sf (SF9)
                response += bytes([7])  # 57: cr (4/7)
                response += name  # 58+: node_name

                self.logger.warning(f"CMD_APP_START: No self_info available, using fallback ({len(response)} bytes)")

                # Wrap in frame protocol
                wrapped_response = self.wrap_frame(response)
                self.logger.debug(f"CMD_APP_START: Sending fallback RESP_CODE_SELF_INFO frame: {wrapped_response.hex()}")
                writer.write(wrapped_response)
                await writer.drain()
        else:
            # Other blocked commands just get RESP_CODE_OK (wrapped in frame)
            ok_response = bytes([RESP_CODE_OK])
            wrapped_ok = self.wrap_frame(ok_response)
            writer.write(wrapped_ok)
            await writer.drain()
    
    async def forward_command(self, writer, cmd_code, command_data):
        """Forward a command to the radio and relay the response (wrapped in frame protocol)"""
        if not self.meshcore or not self.meshcore.is_connected:
            # Radio not connected, send error response (wrapped in frame)
            error_response = bytes([RESP_CODE_ERR, 4])  # ERR_CODE_BAD_STATE
            wrapped_error = self.wrap_frame(error_response)
            writer.write(wrapped_error)
            await writer.drain()
            return

        # Phase 4: Detect connection type early for BLE-specific optimizations
        connection_type = "unknown"
        is_ble = False
        try:
            if hasattr(self.meshcore, 'cx') and hasattr(self.meshcore.cx, 'connection'):
                conn = self.meshcore.cx.connection
                conn_type_str = str(type(conn).__name__).lower()
                connection_type = conn_type_str
                is_ble = 'ble' in conn_type_str
                self.logger.debug(f"Connection type detected: {connection_type}, is_BLE: {is_ble}")
        except Exception as e:
            self.logger.debug(f"Could not detect connection type: {e}")
        
        # First, try to use meshcore command interface for commands that support it
        # This is more reliable than raw binary for triggering events
        if cmd_code == CMD_DEVICE_QUERY and hasattr(self.meshcore.commands, 'send_device_query'):
            self.logger.debug("Using meshcore command interface for CMD_DEVICE_QUERY")
            # Register pending response before sending command
            buffered_event_found = False
            async with self.response_lock:
                if cmd_code not in self.pending_responses:
                    self.pending_responses[cmd_code] = []

                response_event = asyncio.Event()
                self.pending_responses[cmd_code].append((writer, response_event, None, time.time(), False))

                # Phase 3: Check if there's a buffered event for this command
                if cmd_code in self.buffered_events and self.buffered_events[cmd_code]:
                    resp_code_buf, event_buf, event_time = self.buffered_events[cmd_code].pop(0)
                    event_age = time.time() - event_time
                    self.logger.debug(f"Found buffered event for cmd_code {cmd_code} (age: {event_age:.3f}s) - using it immediately")

                    # Clean up buffer if empty
                    if not self.buffered_events[cmd_code]:
                        del self.buffered_events[cmd_code]

                    # Process buffered event immediately
                    response_data = self.event_to_binary(resp_code_buf, event_buf)
                    await self.send_response_to_pending(cmd_code, resp_code_buf, response_data)
                    buffered_event_found = True

            # If we found and used a buffered event, return early
            if buffered_event_found:
                self.logger.debug(f"CMD_DEVICE_QUERY satisfied from buffered event")
                return
            
            # Send command via meshcore interface
            try:
                start_time = time.time()
                # Add timeout to prevent hanging indefinitely (BLE can be slow, allow 5 seconds)
                try:
                    result = await asyncio.wait_for(
                        self.meshcore.commands.send_device_query(),
                        timeout=5.0
                    )
                    query_time = time.time() - start_time
                    self.logger.debug(f"send_device_query() returned in {query_time:.3f}s: type={type(result)}, has_type={hasattr(result, 'type') if result else False}")
                except asyncio.TimeoutError:
                    query_time = time.time() - start_time
                    self.logger.error(f"send_device_query() TIMED OUT after {query_time:.3f}s - meshcore library did not respond")

                    # Send error response immediately - don't wait for event
                    await self.record_command_result(cmd_code, 'timeout', query_time)

                    # Remove from pending
                    async with self.response_lock:
                        if cmd_code in self.pending_responses:
                            pending_list = self.pending_responses[cmd_code]
                            self.pending_responses[cmd_code] = [
                                entry for entry in pending_list
                                if entry[0] != writer
                            ]
                            if not self.pending_responses[cmd_code]:
                                del self.pending_responses[cmd_code]

                    # Send error response to client
                    error_response = bytes([RESP_CODE_ERR, 1])
                    wrapped_error = self.wrap_frame(error_response)
                    writer.write(wrapped_error)
                    await writer.drain()
                    self.logger.info(f"CMD_DEVICE_QUERY error response sent after meshcore timeout")
                    return

                # Phase 0 Fix: Check result IMMEDIATELY before waiting for event
                # For BLE connections, the result contains valid data but events may not fire
                # Phase 4: Add comprehensive result validation
                if result:
                    has_type = hasattr(result, 'type')
                    has_payload = hasattr(result, 'payload')
                    type_matches = has_type and result.type == EventType.DEVICE_INFO

                    self.logger.debug(f"Result validation: has_type={has_type}, has_payload={has_payload}, type_matches={type_matches}")

                    if type_matches:
                        # We have valid result data - check if event handler already sent response
                        self.logger.debug(f"Direct result available for CMD_DEVICE_QUERY (connection_type={connection_type})")

                        try:
                            # Check if pending response still exists (event handler may have consumed it)
                            response_already_sent = False
                            async with self.response_lock:
                                if cmd_code not in self.pending_responses or not self.pending_responses[cmd_code]:
                                    # Event handler already consumed and sent response
                                    response_already_sent = True
                                    self.logger.debug(f"Event handler already sent response for CMD_DEVICE_QUERY")

                            if response_already_sent:
                                # Event handler won the race - that's fine, response was sent
                                response_time = time.time() - start_time
                                self.logger.info(f"CMD_DEVICE_QUERY response sent via event handler in {response_time:.3f}s (connection: {connection_type})")
                                await self.record_command_result(cmd_code, 'success', response_time)
                                return

                            # We won the race - send response from direct result
                            self.logger.debug(f"Using direct result for CMD_DEVICE_QUERY (event handler hasn't fired yet)")
                            response_data = self.event_to_binary(RESP_CODE_DEVICE_INFO, result)

                            # Clean up pending response and send directly (we have writer in scope)
                            async with self.response_lock:
                                if cmd_code in self.pending_responses and self.pending_responses[cmd_code]:
                                    # Remove our pending entry since we're handling it now
                                    self.pending_responses[cmd_code].pop(0)
                                    if not self.pending_responses[cmd_code]:
                                        del self.pending_responses[cmd_code]
                                else:
                                    # Race condition - event handler just consumed it
                                    self.logger.debug(f"Event handler consumed pending response between checks - skipping send")
                                    return

                            # Send response directly using writer we already have
                            wrapped_response = self.wrap_frame(response_data)
                            self.logger.debug(f"Writing wrapped response ({len(wrapped_response)} bytes) via direct result")
                            writer.write(wrapped_response)
                            await writer.drain()

                            response_time = time.time() - start_time
                            self.logger.info(f"CMD_DEVICE_QUERY response sent via direct result in {response_time:.3f}s (connection: {connection_type})")

                            # Phase 5: Record success
                            await self.record_command_result(cmd_code, 'success', response_time)
                            return
                        except Exception as e:
                            self.logger.error(f"Error converting result to binary: {e}", exc_info=True)
                            # Fall through to event waiting
                    else:
                        self.logger.debug(f"Result not usable: result_type={type(result)}, attributes={dir(result) if result else 'None'}")
                else:
                    self.logger.debug("send_device_query() returned None")

                # Fallback: If result is invalid or doesn't have expected data, wait for event
                # This preserves backward compatibility if events do fire
                self.logger.debug(f"Result not immediately usable, waiting for DEVICE_INFO event")
                await asyncio.sleep(0.1)  # Give event handler a chance to fire

                try:
                    await asyncio.wait_for(response_event.wait(), timeout=4.9)
                    # Response was sent by event handler
                    response_time = time.time() - start_time
                    self.logger.debug(f"Response sent via event handler for command {cmd_code} in {response_time:.3f}s")
                    return
                except asyncio.TimeoutError:
                    # Event didn't fire and result was unusable
                    timeout_duration = time.time() - start_time
                    self.logger.warning(f"Event handler timeout and no valid result for CMD_DEVICE_QUERY after {timeout_duration:.3f}s")

                    # Phase 5: Record timeout
                    await self.record_command_result(cmd_code, 'timeout', timeout_duration)

                    # Remove from pending
                    async with self.response_lock:
                        if cmd_code in self.pending_responses:
                            pending_list = self.pending_responses[cmd_code]
                            self.pending_responses[cmd_code] = [
                                entry for entry in pending_list
                                if entry[0] != writer
                            ]
                            if not self.pending_responses[cmd_code]:
                                del self.pending_responses[cmd_code]

                    error_response = bytes([RESP_CODE_ERR, 1])
                    wrapped_error = self.wrap_frame(error_response)
                    writer.write(wrapped_error)
                    await writer.drain()
                    return
            except Exception as e:
                self.logger.error(f"Error executing command via meshcore interface: {e}", exc_info=True)
                # Remove from pending
                async with self.response_lock:
                    if cmd_code in self.pending_responses:
                        pending_list = self.pending_responses[cmd_code]
                        self.pending_responses[cmd_code] = [
                            (w, e, d, t) for w, e, d, t in pending_list
                            if w != writer
                        ]
                        if not self.pending_responses[cmd_code]:
                            del self.pending_responses[cmd_code]
                
                error_response = bytes([RESP_CODE_ERR, 1])
                wrapped_error = self.wrap_frame(error_response)
                writer.write(wrapped_error)
                await writer.drain()
                return
        
        # Register pending response BEFORE sending (in case event fires quickly)
        # This is for commands that will trigger events
        response_event = None
        async with self.response_lock:
            if cmd_code not in self.pending_responses:
                self.pending_responses[cmd_code] = []
            
            response_event = asyncio.Event()
            self.pending_responses[cmd_code].append((writer, response_event, None, time.time()))
        
        # Try to send command via meshcore_py's connection.send()
        # IMPORTANT: connection.send() automatically wraps data with frame protocol (0x3C + length + data)
        # So we pass the unwrapped command_data, and it will be wrapped correctly
        try:
            connection = None
            if hasattr(self.meshcore, 'cx') and hasattr(self.meshcore.cx, 'connection'):
                connection = self.meshcore.cx.connection
            
            sent = False
            
            # Method 1: Use connection.send() - this automatically wraps with frame protocol
            # This is the correct way - meshcore_py handles framing for us
            if connection and hasattr(connection, 'send'):
                try:
                    await connection.send(command_data)
                    sent = True
                    self.logger.debug(f"Command {cmd_code} sent via connection.send() (auto-wrapped with frame)")
                except Exception as e:
                    self.logger.debug(f"Could not send via connection.send(): {e}")
            
            # Method 2: Fallback - try transport.write() for TCP (but we need to wrap it ourselves)
            # This is only for cases where connection.send() doesn't work
            if not sent:
                transport = get_transport(self.meshcore)
                if transport and hasattr(transport, 'write'):
                    try:
                        # Manually wrap with frame protocol (0x3C + length + data)
                        # This matches what connection.send() does internally
                        size = len(command_data)
                        wrapped_cmd = b"\x3c" + size.to_bytes(2, byteorder="little") + command_data
                        transport.write(wrapped_cmd)
                        sent = True
                        self.logger.debug(f"Command {cmd_code} sent via transport.write() (manually wrapped)")
                    except Exception as e:
                        self.logger.debug(f"Could not send via transport.write(): {e}")
            
            if sent:
                # Command was sent, wait for event-based response
                # (response_event was already registered above)
                try:
                    await asyncio.wait_for(response_event.wait(), timeout=5.0)
                    # Response was sent by event handler
                    self.logger.debug(f"Response received via event handler for command {cmd_code}")
                    return
                except asyncio.TimeoutError:
                    # Timeout - remove from pending and send error
                    async with self.response_lock:
                        if cmd_code in self.pending_responses:
                            # Remove this specific pending entry
                            pending_list = self.pending_responses[cmd_code]
                            self.pending_responses[cmd_code] = [
                                entry for entry in pending_list
                                if entry[0] != writer
                            ]
                            if not self.pending_responses[cmd_code]:
                                del self.pending_responses[cmd_code]
                    
                    self.logger.warning(f"Timeout waiting for response to command {cmd_code}")
                    error_response = bytes([RESP_CODE_ERR, 1])  # ERR_CODE_UNSUPPORTED_CMD
                    wrapped_error = self.wrap_frame(error_response)
                    writer.write(wrapped_error)
                    await writer.drain()
                    return
                
                # Try to read response directly from connection (fallback)
                # For BLE/serial, we need to access the connection's reader if available
                response = None
                
                if connection:
                    try:
                        # Try to access the underlying reader/stream
                        # Check various possible attributes where the raw stream might be
                        raw_reader = None
                        for attr_name in ['_reader', 'reader', '_stream', 'stream', '_socket', 'socket']:
                            if hasattr(connection, attr_name):
                                attr = getattr(connection, attr_name)
                                # Check if it's a StreamReader or similar
                                if hasattr(attr, 'read'):
                                    raw_reader = attr
                                    break
                        
                        # If we found a raw reader, try to read from it
                        if raw_reader:
                            try:
                                # Read response code first
                                response_code = await asyncio.wait_for(raw_reader.read(1), timeout=5.0)
                                if response_code:
                                    code = response_code[0]
                                    # Check if this is a push notification (shouldn't be in command response)
                                    if 0x80 <= code <= 0x8E:
                                        # Push notification - forward it and read next byte
                                        remaining = await asyncio.wait_for(raw_reader.read(1024), timeout=1.0)
                                        await self.forward_push_notification(code, remaining)
                                        # Try reading next byte as actual response
                                        response_code = await asyncio.wait_for(raw_reader.read(1), timeout=5.0)
                                        if not response_code:
                                            self.logger.debug("No response after push notification")
                                            response = None
                                        else:
                                            code = response_code[0]
                                            remaining = await asyncio.wait_for(raw_reader.read(1024), timeout=1.0)
                                            response = response_code + remaining
                                    else:
                                        # Regular response
                                        remaining = await asyncio.wait_for(raw_reader.read(1024), timeout=1.0)
                                        response = response_code + remaining
                                    if response:
                                        self.logger.debug(f"Read response from raw reader: {len(response)} bytes, code={code}")
                            except asyncio.TimeoutError:
                                self.logger.debug("Timeout reading from raw reader")
                            except Exception as e:
                                self.logger.debug(f"Could not read from raw reader: {e}")
                        
                        # If that didn't work, try transport-level access for TCP
                        if not response:
                            transport = get_transport(self.meshcore)
                            if transport and hasattr(transport, 'get_extra_info'):
                                try:
                                    # Try to get the socket and create a reader from it
                                    sock = transport.get_extra_info('socket')
                                    if sock:
                                        # For TCP, we could theoretically read from the socket
                                        # But this is complex and may interfere with meshcore_py
                                        # For now, we'll skip this approach
                                        pass
                                except Exception as e:
                                    self.logger.debug(f"Could not access transport socket: {e}")
                        
                    except Exception as e:
                        self.logger.debug(f"Error trying to read response: {e}")
                
                # If we got a response, forward it (wrapped in frame)
                if response:
                    self.logger.debug(f"Received response to command {cmd_code}: {len(response)} bytes")
                    wrapped_response = self.wrap_frame(response)
                    writer.write(wrapped_response)
                    await writer.drain()
                    return
                else:
                    # No response received - this is expected for raw binary commands
                    # because meshcore_py uses an event-based system and raw binary commands
                    # sent via connection.send() may not trigger events
                    # 
                    # The fundamental limitation is that meshcore_py abstracts away the binary protocol
                    # and we're trying to bypass that abstraction. For proper command forwarding,
                    # we would need either:
                    # 1. A secondary TCP connection (which we try to create)
                    # 2. Direct access to the underlying transport (which may not be available)
                    # 3. To use meshcore_py's command interface and convert to/from binary
                    #
                    # For now, we'll send an error response indicating the command couldn't be processed
                    self.logger.warning(
                        f"Command {cmd_code} (0x{cmd_code:02X}) sent but no response received. "
                        f"Raw binary command forwarding is limited - responses come through meshcore_py's event system "
                        f"which doesn't work for raw binary commands. Consider using a secondary TCP connection or "
                        f"mapping commands to meshcore_py's command interface."
                    )
                    # Send error response (wrapped in frame)
                    error_response = bytes([RESP_CODE_ERR, 1])  # ERR_CODE_UNSUPPORTED_CMD
                    wrapped_error = self.wrap_frame(error_response)
                    writer.write(wrapped_error)
                    await writer.drain()
                    return
        except Exception as e:
            self.logger.debug(f"Error attempting to send raw binary: {e}")
        
        # Fallback: Try secondary connection if available (skip for BLE - it doesn't support secondary connections)
        if self.command_writer and not is_ble:
            try:
                # Send command to radio via secondary connection
                self.command_writer.write(command_data)
                await self.command_writer.drain()
                
                # Read response directly (synchronous)
                try:
                    # Read response code first
                    response_code = await asyncio.wait_for(
                        self.command_reader.read(1),
                        timeout=5.0
                    )
                    if not response_code:
                        error_response = bytes([RESP_CODE_ERR, 1])
                        wrapped_error = self.wrap_frame(error_response)
                        writer.write(wrapped_error)
                        await writer.drain()
                        return
                    
                    code = response_code[0]
                    
                    # Skip push notifications (they're handled by background task)
                    if 0x80 <= code <= 0x8E:
                        # This shouldn't happen in command response, but handle it
                        await self.forward_push_notification(code, await self.command_reader.read(1024))
                        # Try reading next byte as actual response
                        response_code = await asyncio.wait_for(
                            self.command_reader.read(1),
                            timeout=5.0
                        )
                        if not response_code:
                            error_response = bytes([RESP_CODE_ERR, 1])
                            wrapped_error = self.wrap_frame(error_response)
                            writer.write(wrapped_error)
                            await writer.drain()
                            return
                        code = response_code[0]
                    
                    # Read remaining data
                    remaining = await asyncio.wait_for(
                        self.command_reader.read(1024),
                        timeout=1.0
                    )
                    
                    full_response = response_code + remaining
                    # Wrap response in frame protocol
                    wrapped_response = self.wrap_frame(full_response)
                    writer.write(wrapped_response)
                    await writer.drain()
                    return
                except asyncio.TimeoutError:
                    error_response = bytes([RESP_CODE_ERR, 1])
                    wrapped_error = self.wrap_frame(error_response)
                    writer.write(wrapped_error)
                    await writer.drain()
                    return
                except Exception as e:
                    self.logger.error(f"Error reading response: {e}")
                    error_response = bytes([RESP_CODE_ERR, 1])
                    writer.write(error_response)
                    await writer.drain()
                    return
            except Exception as e:
                self.logger.error(f"Error forwarding command via secondary connection: {e}")
                # Fall through to meshcore interface
        
        # Phase 2: Removed duplicate CMD_DEVICE_QUERY handling block
        # The primary handler at the beginning of forward_command() now handles all CMD_DEVICE_QUERY requests
        # with the Phase 0 fix (immediate result check)

        # If we reach here, the command couldn't be forwarded via any available method
        connection_type = "unknown"
        if hasattr(self.meshcore, 'cx') and hasattr(self.meshcore.cx, 'connection'):
            conn = self.meshcore.cx.connection
            connection_type = str(type(conn).__name__)

        self.logger.warning(
            f"Command {cmd_code} (0x{cmd_code:02X}) cannot be forwarded - "
            f"connection type: {connection_type}, "
            f"secondary connection: {self.command_writer is not None}"
        )
        self.logger.debug(
            f"Command {cmd_code} data: {command_data.hex() if len(command_data) <= 32 else command_data[:32].hex() + '...'}"
        )

        # Send error response (wrapped in frame)
        error_response = bytes([RESP_CODE_ERR, 1])  # ERR_CODE_UNSUPPORTED_CMD
        wrapped_error = self.wrap_frame(error_response)
        writer.write(wrapped_error)
        await writer.drain()
    
    async def forward_push_notification(self, push_code, data):
        """Forward a push notification to all connected clients (wrapped in frame protocol)"""
        if not self.running:
            return
        
        # Build push notification payload: [push_code] + [data]
        payload = bytes([push_code]) + data
        
        # Wrap in frame protocol: '>' + 2-byte LE length + payload
        wrapped_frame = self.wrap_frame(payload)
        
        # Send to all clients
        disconnected = set()
        for writer in self.clients:
            try:
                writer.write(wrapped_frame)
                await writer.drain()
            except Exception:
                disconnected.add(writer)
        
        # Remove disconnected clients
        for writer in disconnected:
            self.clients.discard(writer)
            try:
                writer.close()
            except Exception:
                pass


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
        
        # Health check grace period for BLE connections
        self.health_check_grace_period = self.get_env_int('HEALTH_CHECK_GRACE_PERIOD', 2)  # Allow 2 consecutive failures
        self.health_check_failure_count = 0  # Track consecutive health check failures
        
        # Retry configuration
        self.default_retry_limit = self.get_env_int('DEVICE_COMMAND_RETRY_LIMIT', 3)  # Default retries for device commands
        self.ble_retry_limit = self.get_env_int('BLE_COMMAND_RETRY_LIMIT', 3)  # Retries for BLE connections
        self.tcp_retry_limit = self.get_env_int('TCP_COMMAND_RETRY_LIMIT', 2)  # Retries for TCP connections
        self.health_check_retry_limit = self.get_env_int('HEALTH_CHECK_RETRY_LIMIT', None)  # Override for health checks (None = use connection-specific)
        self.stats_retry_limit = self.get_env_int('STATS_RETRY_LIMIT', 2)  # Retries for stats queries (non-critical)
        self.device_info_retry_limit = self.get_env_int('DEVICE_INFO_RETRY_LIMIT', 2)  # Retries for device info queries
        
        # MQTT connection
        self.mqtt_clients = []  # List of MQTT client info dictionaries
        self.mqtt_connected = False
        self.should_exit = False  # Flag to exit when reconnection attempts fail
        
        # Stats/status publishing
        self.stats_status_enabled = self.get_env_bool('STATS_IN_STATUS_ENABLED', True)
        self.stats_refresh_interval = self.get_env_int('STATS_REFRESH_INTERVAL', 300)  # seconds
        self.latest_stats = None
        self.last_stats_fetch = 0
        self.stats_supported = False
        self.stats_capability_state = None
        self.stats_update_task = None
        self.stats_fetch_lock = asyncio.Lock()
        
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
        
        # MQTT failure tracking with grace period
        self.mqtt_health_check_interval = self.get_env_int('MQTT_HEALTH_CHECK_INTERVAL', 60)  # Check every minute
        self.mqtt_grace_period = self.get_env_int('MQTT_GRACE_PERIOD', 180)  # 3 minutes grace before counting failures
        self.mqtt_disconnect_timestamps = {}  # Track when brokers disconnected: {broker_num: timestamp}
        
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
        self.advert_interval_hours = self.get_env_int('ADVERT_INTERVAL_HOURS', 47)
        self.last_advert_time = 0
        self.advert_task = None
        
        # Load persisted advert state
        self.last_advert_time = self._load_advert_state()
        
        # Packet type filtering for uploads
        upload_types_str = self.get_env('UPLOAD_PACKET_TYPES', '').strip()
        if upload_types_str:
            self.allowed_upload_types = set(t.strip() for t in upload_types_str.split(','))
            self.logger.info(f"Packet type upload filter enabled: {sorted(self.allowed_upload_types)}")
        else:
            self.allowed_upload_types = None  # None means upload all (default)
        
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
        
        # SDK auto-reconnect settings for TCP
        self.tcp_sdk_auto_reconnect_enabled = self.get_env_bool('TCP_SDK_AUTO_RECONNECT_ENABLED', True)
        self.tcp_sdk_max_reconnect_attempts = self.get_env_int('TCP_SDK_MAX_RECONNECT_ATTEMPTS', 100)
        self.sdk_reconnect_exhausted = False  # Track if SDK auto-reconnect has given up (TCP only)
        
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
        
        # Binary interface proxy (only created if enabled)
        binary_interface_enabled = self.get_env_bool('BINARY_INTERFACE_ENABLED', True)
        if binary_interface_enabled:
            binary_interface_host = self.get_env('BINARY_INTERFACE_HOST', '0.0.0.0')
            binary_interface_port = self.get_env_int('BINARY_INTERFACE_PORT', 5000)

            # Debug: Log the configuration being used
            print(f"DEBUG: Binary interface config - host={binary_interface_host}, port={binary_interface_port}")
            print(f"DEBUG: Env var PACKETCAPTURE_BINARY_INTERFACE_PORT={os.getenv('PACKETCAPTURE_BINARY_INTERFACE_PORT', 'NOT SET')}")

            self.binary_proxy = BinaryCommandProxy(
                None,  # Will be set when meshcore connects
                self.logger,
                enabled=True,
                host=binary_interface_host,
                port=binary_interface_port
            )
        else:
            self.binary_proxy = None
    
    
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
    
    def _get_state_file_path(self):
        """Get the path to the state file for persisting last_advert_time.
        
        Works across all installation methods:
        - Docker: Uses /app/data/ (mounted volume)
        - NixOS: Uses cfg.dataDir (working directory)
        - Systemd: Uses script directory or data subdirectory
        """
        script_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Try data subdirectory first (works for Docker and if created)
        data_dir = os.path.join(script_dir, 'data')
        if os.path.exists(data_dir) and os.path.isdir(data_dir):
            return os.path.join(data_dir, 'advert_state.json')
        
        # Fall back to script directory (works for all installation methods)
        return os.path.join(script_dir, 'advert_state.json')
    
    def _load_advert_state(self):
        """Load last_advert_time from persistent state file.
        
        Returns the timestamp if found, otherwise returns 0.
        """
        state_file = self._get_state_file_path()
        
        if not os.path.exists(state_file):
            if self.debug:
                self.logger.debug(f"Advert state file not found: {state_file}")
            return 0
        
        try:
            with open(state_file, 'r') as f:
                state = json.load(f)
                last_time = state.get('last_advert_time', 0)
                
                # Validate the timestamp is reasonable (not in the future, not too old)
                current_time = time.time()
                if last_time > current_time:
                    # Timestamp is in the future, ignore it
                    if self.debug:
                        self.logger.debug(f"Advert state timestamp is in the future, ignoring: {last_time}")
                    return 0
                
                # If timestamp is more than 1 year old, treat as invalid
                if current_time - last_time > 31536000:  # 1 year in seconds
                    if self.debug:
                        self.logger.debug(f"Advert state timestamp is too old, ignoring: {last_time}")
                    return 0
                
                if self.debug:
                    self.logger.debug(f"Loaded last_advert_time from state file: {last_time} ({datetime.fromtimestamp(last_time).isoformat()})")
                return last_time
                
        except (json.JSONDecodeError, IOError, OSError) as e:
            self.logger.warning(f"Failed to load advert state from {state_file}: {e}")
            return 0
    
    def _save_advert_state(self):
        """Save last_advert_time to persistent state file."""
        state_file = self._get_state_file_path()
        state_dir = os.path.dirname(state_file)
        
        try:
            # Create directory if it doesn't exist (for data subdirectory case)
            if state_dir and not os.path.exists(state_dir):
                os.makedirs(state_dir, mode=0o755, exist_ok=True)
            
            state = {
                'last_advert_time': self.last_advert_time,
                'updated_at': time.time()
            }
            
            # Write atomically using a temporary file
            temp_file = state_file + '.tmp'
            with open(temp_file, 'w') as f:
                json.dump(state, f, indent=2)
            
            # Atomic rename
            os.replace(temp_file, state_file)
            
            if self.debug:
                self.logger.debug(f"Saved last_advert_time to state file: {self.last_advert_time} ({datetime.fromtimestamp(self.last_advert_time).isoformat()})")
                
        except (IOError, OSError) as e:
            self.logger.warning(f"Failed to save advert state to {state_file}: {e}")
    
    
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
    
    async def retryable_device_command(self, command_func, command_name: str, 
                                       timeout: float = 10.0, max_retries: int = None,
                                       retry_delay: float = 0.2, backoff_multiplier: float = 1.5):
        """
        Execute a device command with timeout and retry logic.
        
        Args:
            command_func: Async function that returns a meshcore Event
            command_name: Name of the command for logging
            timeout: Timeout in seconds for each attempt
            max_retries: Maximum number of retry attempts (including initial attempt)
                        If None, uses connection-specific default from environment variables
            retry_delay: Initial delay between retries in seconds
            backoff_multiplier: Multiplier for exponential backoff
        
        Returns:
            Event object from the command, or None if all retries failed
        """
        if not self._ensure_connected(command_name, "debug"):
            return None
        
        # Use connection-specific default if max_retries not specified
        if max_retries is None:
            if self.connection_type == 'ble':
                max_retries = self.ble_retry_limit
            elif self.connection_type == 'tcp':
                max_retries = self.tcp_retry_limit
            else:
                max_retries = self.default_retry_limit
        
        last_error = None
        current_delay = retry_delay
        
        for attempt in range(max_retries):
            try:
                # Add small delay between retries (except first attempt)
                if attempt > 0:
                    await asyncio.sleep(current_delay)
                    current_delay *= backoff_multiplier  # Exponential backoff
                
                # Execute command with timeout
                result = await asyncio.wait_for(
                    command_func(),
                    timeout=timeout
                )
                
                # Check if result is an error
                if result and hasattr(result, 'type'):
                    if result.type == EventType.ERROR:
                        error_payload = result.payload if hasattr(result, 'payload') else {}
                        error_reason = error_payload.get('reason', 'unknown')
                        
                        # Check if it's a transient error that we should retry
                        if error_reason == 'no_event_received' and attempt < max_retries - 1:
                            last_error = f"{command_name} failed: {error_reason}"
                            if self.debug:
                                self.logger.debug(f"{last_error} (attempt {attempt + 1}/{max_retries})")
                            continue
                        else:
                            # Permanent error or last attempt
                            self.logger.debug(f"{command_name} failed: {error_payload}")
                            return result
                    else:
                        # Success - return the result
                        if attempt > 0:
                            self.logger.debug(f"{command_name} succeeded on attempt {attempt + 1}")
                        return result
                else:
                    # Unexpected result format
                    self.logger.debug(f"{command_name} returned unexpected result format")
                    return result
                    
            except asyncio.TimeoutError:
                last_error = f"{command_name} timed out after {timeout}s"
                if attempt < max_retries - 1:
                    if self.debug:
                        self.logger.debug(f"{last_error} (attempt {attempt + 1}/{max_retries})")
                    continue
                else:
                    self.logger.debug(f"{last_error} (all {max_retries} attempts exhausted)")
                    return None
            except Exception as e:
                last_error = f"{command_name} raised exception: {e}"
                if attempt < max_retries - 1:
                    if self.debug:
                        self.logger.debug(f"{last_error} (attempt {attempt + 1}/{max_retries})")
                    continue
                else:
                    self.logger.debug(f"{last_error} (all {max_retries} attempts exhausted)")
                    return None
        
        # All retries failed
        if last_error:
            self.logger.debug(f"{command_name} failed after {max_retries} attempts: {last_error}")
        return None

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
        """Load client version from .version_info file or git"""
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            version_file = os.path.join(script_dir, '.version_info')
            
            # First try to load from .version_info file (created by installer)
            if os.path.exists(version_file):
                with open(version_file, 'r') as f:
                    version_data = json.load(f)
                    installer_ver = version_data.get('installer_version', 'unknown')
                    git_hash = version_data.get('git_hash', 'unknown')
                    return f"meshcore-packet-capture/{installer_ver}-{git_hash}"
            
            # Fallback: try to get git information directly
            try:
                import subprocess
                result = subprocess.run(['git', 'rev-parse', '--short', 'HEAD'], 
                                      cwd=script_dir, capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    git_hash = result.stdout.strip()
                    return f"meshcore-packet-capture/dev-{git_hash}"
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                pass
                
        except Exception as e:
            self.logger.debug(f"Could not load version info: {e}")
        
        # Final fallback
        return "meshcore-packet-capture/unknown"
    
    async def get_firmware_info(self):
        """Get firmware information from meshcore device using send_device_query()"""
        try:
            # During shutdown, always use cached info - don't query the device
            if self.should_exit:
                if self.cached_firmware_info:
                    self.logger.debug("Using cached firmware info (shutdown in progress)")
                    return self.cached_firmware_info
                else:
                    self.logger.debug("No cached firmware info available during shutdown")
                    return {"model": "unknown", "version": "unknown"}
            
            # Return cached info if available and device is not connected
            if self.cached_firmware_info and (not self.meshcore or not self.meshcore.is_connected):
                self.logger.debug("Using cached firmware info")
                return self.cached_firmware_info
            
            if not self._ensure_connected("get_firmware_info", "debug"):
                return {"model": "unknown", "version": "unknown"}
            
            self.logger.debug("Querying device for firmware info...")
            # Use send_device_query() to get firmware version with retry logic
            # Use connection-specific retry limit
            result = await self.retryable_device_command(
                lambda: self.meshcore.commands.send_device_query(),
                "send_device_query",
                timeout=10.0,
                max_retries=None  # Use connection-specific default
            )
            
            if result is None:
                self.logger.debug("Device query failed after retries")
                return {"model": "unknown", "version": "unknown"}
            
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
    
    def is_letsmesh_broker(self, broker_num=None) -> bool:
        """Detect if the given broker is a Let's Mesh Analyzer broker by hostname or token audience."""
        server = None
        audience = None
        if broker_num:
            server = self.get_env(f'MQTT{broker_num}_SERVER', '')
            audience = self.get_env(f'MQTT{broker_num}_TOKEN_AUDIENCE', '')
        if not server:
            server = self.get_env('MQTT1_SERVER', '')
        if not audience:
            audience = self.get_env('MQTT1_TOKEN_AUDIENCE', '')
        host = (server or '').lower()
        aud = (audience or '').lower()
        return ('letsmesh.net' in host) or ('letsmesh.net' in aud)

    def has_configured_iata(self, broker_num=None) -> bool:
        """Return True if a non-default IATA code is configured (not 'LOC')."""
        iata = self.global_iata or ''
        if broker_num:
            broker_iata = self.get_env(f'MQTT{broker_num}_IATA', '')
            if broker_iata:
                iata = broker_iata.lower()
        return bool(iata) and iata.lower() != 'loc'

    def broker_requires_iata(self, broker_num) -> bool:
        """Check if a broker requires IATA configuration.
        Returns True if:
        - It's a Let's Mesh Analyzer broker, OR
        - It has explicitly configured topics that use IATA placeholders"""
        # Check if it's a Let's Mesh broker
        if self.is_letsmesh_broker(broker_num):
            return True
        
        # Check if any configured topics use IATA placeholders
        topic_types = ['STATUS', 'PACKETS', 'DECODED', 'DEBUG', 'RAW']
        for topic_type in topic_types:
            # Check broker-specific topic
            broker_topic = self.get_env(f'MQTT{broker_num}_TOPIC_{topic_type}', '')
            if broker_topic and ('{IATA}' in broker_topic or '{IATA_lower}' in broker_topic):
                return True
            
            # Check global topic (only if no broker-specific topic)
            if not broker_topic:
                global_topic = self.get_env(f'TOPIC_{topic_type}', '')
                if global_topic and ('{IATA}' in global_topic or '{IATA_lower}' in global_topic):
                    return True
        
        return False

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
        
        # Defaulting policy adjustment:
        # - Never use classic defaults (meshcore/status, meshcore/packets, etc.) for Let's Mesh Analyzer brokers
        # - Prefer IATA-based defaults when IATA is configured
        # - Only on custom brokers without IATA configured, fall back to classic defaults

        is_letsmesh = self.is_letsmesh_broker(broker_num)
        iata_configured = self.has_configured_iata(broker_num)

        iata_defaults = {
            'STATUS': 'meshcore/{IATA}/{PUBLIC_KEY}/status',
            'PACKETS': 'meshcore/{IATA}/{PUBLIC_KEY}/packets',
            'DECODED': 'meshcore/{IATA}/{PUBLIC_KEY}/decoded',
            'DEBUG': 'meshcore/{IATA}/{PUBLIC_KEY}/debug'
        }
        classic_defaults = {
            'STATUS': 'meshcore/status',
            'PACKETS': 'meshcore/packets',
            'DECODED': 'meshcore/decoded',
            'DEBUG': 'meshcore/debug'
        }

        if iata_configured:
            chosen_default = iata_defaults.get(topic_type_upper, f"meshcore/{{IATA}}/{{PUBLIC_KEY}}/{topic_type.lower()}")
        else:
            if is_letsmesh:
                if self.debug:
                    self.logger.debug(f"Skipping default '{topic_type}' topic for Let's Mesh broker {broker_num} because IATA is not configured")
                return None
            chosen_default = classic_defaults.get(topic_type_upper, f'meshcore/{topic_type.lower()}')

        resolved = self.resolve_topic_template(chosen_default, broker_num)
        if self.debug:
            self.logger.debug(f"Using default topic for {topic_type}: {resolved}")
        return resolved
    
    async def set_radio_clock(self) -> bool:
        """Set radio clock only if device time is earlier than current system time"""
        try:
            if not self._ensure_connected("set_radio_clock", "warning"):
                return False
            
            # Get current device time with retry logic
            self.logger.info("Checking device time...")
            time_result = await self.retryable_device_command(
                lambda: self.meshcore.commands.get_time(),
                "get_time",
                timeout=8.0,
                max_retries=self.device_info_retry_limit,  # Use device info retry limit
                retry_delay=0.2
            )
            if time_result is None or time_result.type == EventType.ERROR:
                self.logger.warning("Device does not support time commands")
                return False
            
            device_time = time_result.payload.get('time', 0)
            current_time = int(time.time())
            
            self.logger.info(f"Device time: {device_time}, System time: {current_time}")
            
            # Only set time if device time is earlier than current time
            if device_time < current_time:
                time_diff = current_time - device_time
                self.logger.info(f"Device time is {time_diff} seconds behind, updating...")
                
                result = await self.retryable_device_command(
                    lambda: self.meshcore.commands.set_time(current_time),
                    "set_time",
                    timeout=8.0,
                    max_retries=self.device_info_retry_limit,  # Use device info retry limit
                    retry_delay=0.2
                )
                if result and result.type == EventType.OK:
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
            
            if not self._ensure_connected("fetch_private_key_from_device", "error"):
                return False
            
            # Use meshcore library to export private key with retry logic
            # Use connection-specific retry limit (defaults to 3 for BLE, 2 for TCP)
            result = await self.retryable_device_command(
                lambda: self.meshcore.commands.export_private_key(),
                "export_private_key",
                timeout=10.0,
                max_retries=None,  # Use connection-specific default
                retry_delay=0.3  # Slightly longer delay for private key operations
            )
            
            if result is None:
                self.logger.error("Error fetching private key: command failed after retries")
                self.private_key_export_available = False
                return False
            
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
        """Create JWT using on-device signing (preferred) or private key from device"""
        try:
            if not create_auth_token_async and not create_auth_token:
                return None
            
            # Build claims
            claims = {}
            if audience:
                claims['aud'] = audience
            
            # Add optional owner public key if configured
            owner_public_key = os.getenv('PACKETCAPTURE_OWNER_PUBLIC_KEY', '').strip()
            if owner_public_key:
                # Validate it's a valid hex string of correct length (64 hex chars = 32 bytes)
                if len(owner_public_key) == 64 and all(c in '0123456789ABCDEFabcdef' for c in owner_public_key):
                    claims['owner'] = owner_public_key.upper()
                else:
                    self.logger.warning(f"Invalid owner public key format (expected 64 hex characters): {owner_public_key[:16]}...")
            
            # Add optional email if configured
            email = os.getenv('PACKETCAPTURE_OWNER_EMAIL', '').strip()
            if email:
                # Normalize to lowercase
                email = email.lower()
                # Validate email format using a simple regex
                import re
                email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
                if re.match(email_pattern, email):
                    claims['email'] = email
                else:
                    self.logger.warning(f"Invalid email format: {email}")
            
            # Add optional client agent/version if configured, otherwise use default from status message
            client_agent = os.getenv('PACKETCAPTURE_CLIENT_AGENT', '').strip()
            if not client_agent:
                # Default to the same value used in status messages
                client_agent = self._load_client_version()
            if client_agent:
                claims['client'] = client_agent
            
            # Prefer on-device signing if meshcore instance is available and connected
            if (create_auth_token_async and 
                self.meshcore and 
                self.meshcore.is_connected and
                os.getenv('AUTH_TOKEN_METHOD', '').lower().strip() not in ('python', 'meshcore-decoder')):
                try:
                    # Use on-device signing (no private key needed)
                    # Don't pass private_key_hex so auth_token.py will fail fast if device signing fails
                    jwt_token = await create_auth_token_async(
                        self.device_public_key,
                        meshcore_instance=self.meshcore,
                        **claims
                    )
                    self.logger.info("✓ JWT created using on-device signing")
                    return jwt_token
                except Exception as e:
                    # Device signing failed - fall back to private key if available
                    self.logger.debug(f"On-device signing failed: {e}, attempting private key fallback...")
            
            # Fallback to private key signing (skip if device-only mode is enabled)
            device_only = os.getenv('AUTH_TOKEN_DEVICE_ONLY', '').lower().strip() == 'true'
            if device_only:
                self.logger.error("Device-only signing mode enabled but device signing failed or not available")
                return None
            
            # Fallback to private key signing - load from env/file first, then try device if needed
            if not self.device_private_key:
                # Try to load from environment variable first
                env_private_key = self.get_env('PRIVATE_KEY', '')
                if env_private_key:
                    self.device_private_key = env_private_key
                    self.logger.info("Device signing failed, using private key from environment")
                # Try to read from private key file
                elif read_private_key_file:
                    private_key_file = self.get_env('PRIVATE_KEY_FILE', '')
                    if private_key_file and Path(private_key_file).exists():
                        try:
                            self.device_private_key = read_private_key_file(private_key_file)
                            self.logger.info(f"Device signing failed, using private key from file: {private_key_file}")
                        except Exception as e:
                            self.logger.warning(f"Failed to read private key from file {private_key_file}: {e}")
                
                # If still no private key, try fetching from device
                if not self.device_private_key:
                    self.logger.info("Device signing not available, fetching private key from device for fallback...")
                    private_key_fetch_success = await self.fetch_private_key_from_device()
                    if not private_key_fetch_success:
                        self.logger.warning("Cannot create JWT: device signing failed and private key not available from device or environment")
                        return None
            
            # Convert bytearray to hex string if needed
            private_key = self.device_private_key
            if isinstance(private_key, (bytes, bytearray)):
                private_key = private_key.hex()
            
            # Use async version if available (for consistency), otherwise sync version
            if create_auth_token_async:
                jwt_token = await create_auth_token_async(
                    self.device_public_key,
                    private_key_hex=private_key,
                    **claims
                )
            else:
                jwt_token = create_auth_token(self.device_public_key, private_key, **claims)
            
            self.logger.info("✓ JWT created using private key from device")
            return jwt_token
            
        except Exception as e:
            device_only = os.getenv('AUTH_TOKEN_DEVICE_ONLY', '').lower().strip() == 'true'
            if device_only:
                self.logger.error(f"Device-only signing mode: JWT creation failed: {e}")
            else:
                self.logger.error(f"Error creating JWT: {e}", exc_info=True)
            return None
    
    async def create_auth_token_jwt(self, audience: str = None, broker_num: int = None) -> Optional[str]:
        """Create JWT token using on-device signing or private key from device"""
        # Use on-device signing (preferred) or private key method (fallback)
        # The create_jwt_with_private_key() method already logs which method was used
        jwt_token = await self.create_jwt_with_private_key(audience)
        if jwt_token:
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
    
    
    
    

    def _is_tcp_sdk_auto_reconnect_active(self) -> bool:
        """
        Check if TCP SDK auto-reconnect is active and handling reconnection.
        
        Returns:
            True if TCP connection with SDK auto-reconnect enabled and not exhausted
        """
        return (self.connection_type == 'tcp' and 
                self.tcp_sdk_auto_reconnect_enabled and 
                not self.sdk_reconnect_exhausted)
    
    def _get_connection_timeout_config(self, default_timeout: float = 5.0, default_retries: int = None):
        """
        Get timeout and retry configuration based on connection type.
        
        Args:
            default_timeout: Default timeout for connections without special handling
            default_retries: Default number of retries (None = use connection-specific default)
        
        Returns:
            Tuple of (timeout, retries) appropriate for the current connection type
        """
        if self.connection_type == 'ble':
            retries = self.health_check_retry_limit if self.health_check_retry_limit is not None else self.ble_retry_limit
            return (12.0, retries)  # Longer timeout and more retries for BLE on Linux
        elif self._is_tcp_sdk_auto_reconnect_active():
            retries = self.health_check_retry_limit if self.health_check_retry_limit is not None else self.tcp_retry_limit
            return (8.0, retries)  # Longer timeout for TCP with SDK auto-reconnect
        else:
            retries = self.health_check_retry_limit if self.health_check_retry_limit is not None else (default_retries or self.default_retry_limit)
            return (default_timeout, retries)
    
    def _ensure_connected(self, command_name: str = "command", log_level: str = "debug") -> bool:
        """
        Check if device is connected, logging appropriately if not.
        
        Args:
            command_name: Name of the command being executed (for logging)
            log_level: Log level to use ("debug", "warning", "error")
        
        Returns:
            True if connected, False otherwise
        """
        if not self.meshcore or not self.meshcore.is_connected:
            message = f"Cannot execute {command_name} - not connected to device"
            if log_level == "error":
                self.logger.error(message)
            elif log_level == "warning":
                self.logger.warning(message)
            else:
                self.logger.debug(message)
            return False
        return True
    
    def _reset_connection_state(self):
        """
        Reset all connection-related state variables after successful connection/reconnection.
        This includes health check counters, SDK reconnect flags, and consecutive failure counts.
        """
        self.connected = True
        self.health_check_failure_count = 0
        if self.connection_type == 'tcp':
            self.sdk_reconnect_exhausted = False
        self.reset_consecutive_failures("connection")
    
    async def _setup_after_reconnection(self):
        """
        Perform all setup tasks required after a successful reconnection.
        This includes cleaning up old subscriptions, setting up event handlers,
        and starting auto message fetching.
        """
        # Clean up old subscriptions before re-setting up handlers
        # (SDK may have recreated the instance, leaving old subscriptions orphaned)
        self.cleanup_event_subscriptions()
        # Re-setup event handlers after reconnection
        await self.setup_event_handlers()
        await self.meshcore.start_auto_message_fetching()
    
    def _check_ble_grace_period(self, failure_reason: str = "failed") -> bool:
        """
        Check if BLE health check failure should be allowed under grace period.
        
        Args:
            failure_reason: Description of why the health check failed (for logging)
        
        Returns:
            True if failure is within grace period and should be allowed, False otherwise
        """
        if self.connection_type == 'ble' and self.meshcore and self.meshcore.is_connected:
            self.health_check_failure_count += 1
            if self.health_check_failure_count <= self.health_check_grace_period:
                if self.debug:
                    self.logger.debug(
                        f"Health check {failure_reason} but BLE connection appears active "
                        f"(grace period: {self.health_check_failure_count}/{self.health_check_grace_period})"
                    )
                return True  # Allow grace period for BLE
            else:
                self.logger.warning(
                    f"Health check {failure_reason} {self.health_check_failure_count} times consecutively - "
                    "connection may be degraded"
                )
                return False
        return False
    
    async def check_connection_health(self) -> bool:
        """Enhanced health check with network validation"""
        try:
            # 1. Check if meshcore object exists and reports connected
            if not self.meshcore or not self.meshcore.is_connected:
                # For TCP with SDK auto-reconnect, don't log warning if SDK is still trying
                if self._is_tcp_sdk_auto_reconnect_active():
                    if self.debug:
                        self.logger.debug("MeshCore reports not connected, but SDK auto-reconnect is active")
                    return False
                self.logger.warning("MeshCore reports not connected")
                return False
            
            # 2. For TCP connections, verify socket state
            if self.connection_type == 'tcp':
                transport = get_transport(self.meshcore)
                if transport:
                    if transport.is_closing():
                        # For TCP with SDK auto-reconnect, SDK will handle reconnection
                        if self.tcp_sdk_auto_reconnect_enabled and not self.sdk_reconnect_exhausted:
                            if self.debug:
                                self.logger.debug("TCP transport is closing, but SDK auto-reconnect is active")
                            return False
                        self.logger.warning("TCP transport is closed or closing")
                        return False
            
            # 3. Try a lightweight command with timeout and retry
            # Use longer timeout for BLE connections (Linux BLE can be slow) and TCP with SDK auto-reconnect
            health_check_timeout, health_check_retries = self._get_connection_timeout_config()
            
            try:
                result = await self.retryable_device_command(
                    lambda: self.meshcore.commands.send_device_query(),
                    "send_device_query (health check)",
                    timeout=health_check_timeout,
                    max_retries=health_check_retries,  # Uses connection-specific or health_check_retry_limit override
                    retry_delay=0.3  # Slightly longer delay for health checks
                )
                if result and hasattr(result, 'type') and result.type != EventType.ERROR:
                    # Success - reset failure count
                    self.health_check_failure_count = 0
                    return True
                else:
                    if self.debug:
                        self.logger.debug(f"Health check device query failed: {result}")
                    # For BLE, if is_connected is True, we might still consider it healthy
                    # (BLE can have slow responses but connection might still be valid)
                    if self._check_ble_grace_period("query failed"):
                        return True
                    return False
            except asyncio.TimeoutError:
                # For TCP with SDK auto-reconnect, timeout might just mean device is busy
                # SDK will handle reconnection if needed, so don't log as warning
                if self._is_tcp_sdk_auto_reconnect_active():
                    if self.debug:
                        self.logger.debug("Health check timed out, but SDK auto-reconnect is active")
                    return False
                
                # For BLE, allow grace period even on timeout if connection appears active
                if self._check_ble_grace_period("timed out"):
                    return True
                
                self.logger.warning("Health check timed out")
                return False
            except Exception as e:
                # For TCP with SDK auto-reconnect, errors might be temporary
                if self._is_tcp_sdk_auto_reconnect_active():
                    if self.debug:
                        error_type = type(e).__name__
                        self.logger.debug(f"Health check command failed ({error_type}), but SDK auto-reconnect is active")
                    return False
                
                # Log detailed error information for debugging
                error_type = type(e).__name__
                error_msg = str(e)
                # Check if it's an errno error (common on macOS/Linux)
                errno_value = getattr(e, 'errno', None)
                if errno_value is not None:
                    import errno
                    try:
                        errno_name = errno.errorcode.get(errno_value, f"UNKNOWN({errno_value})")
                        self.logger.warning(f"Health check command failed: {error_type} [{errno_name}]: {error_msg}")
                    except (AttributeError, KeyError):
                        self.logger.warning(f"Health check command failed: {error_type} [errno={errno_value}]: {error_msg}")
                else:
                    self.logger.warning(f"Health check command failed: {error_type}: {error_msg}")
                return False
        
        except Exception as e:
            # For TCP with SDK auto-reconnect, don't log as warning if SDK is handling it
            if self._is_tcp_sdk_auto_reconnect_active():
                if self.debug:
                    self.logger.debug(f"Connection health check failed ({type(e).__name__}), but SDK auto-reconnect is active")
                return False
            self.logger.warning(f"Connection health check failed: {e}")
            return False
    
    def check_mqtt_health(self) -> bool:
        """Check MQTT broker health with grace period before counting failures"""
        import time
        
        if not self.enable_mqtt or not self.mqtt_clients:
            return True  # MQTT not enabled or no brokers configured
        
        current_time = time.time()
        connected_brokers = 0
        failed_brokers = 0
        total_brokers = len(self.mqtt_clients)
        
        # Check each broker's connection status
        for client_info in self.mqtt_clients:
            broker_num = client_info['broker_num']
            mqtt_client = client_info['client']
            
            if mqtt_client.is_connected():
                # Broker is connected - clear any disconnect timestamp
                if broker_num in self.mqtt_disconnect_timestamps:
                    disconnect_duration = current_time - self.mqtt_disconnect_timestamps[broker_num]
                    self.logger.info(f"MQTT{broker_num} reconnected after {disconnect_duration:.1f} seconds")
                    del self.mqtt_disconnect_timestamps[broker_num]
                    # Reset consecutive failures on successful reconnection
                    self.reset_consecutive_failures("mqtt")
                connected_brokers += 1
            else:
                # Broker is disconnected
                # Record disconnect timestamp if not already recorded
                if broker_num not in self.mqtt_disconnect_timestamps:
                    self.mqtt_disconnect_timestamps[broker_num] = current_time
                    self.logger.debug(f"MQTT{broker_num} disconnected - grace period started")
                
                # Check if grace period has elapsed
                disconnect_time = self.mqtt_disconnect_timestamps[broker_num]
                time_disconnected = current_time - disconnect_time
                
                if time_disconnected >= self.mqtt_grace_period:
                    # Grace period elapsed - this broker has persistently failed
                    failed_brokers += 1
                    if self.debug:
                        self.logger.debug(f"MQTT{broker_num} disconnected for {time_disconnected:.1f}s (grace period: {self.mqtt_grace_period}s) - persistent failure")
        
        # If all enabled brokers have been disconnected past grace period, this is a failure
        # We require ALL brokers to be failed, not just one, to avoid false positives with multiple brokers
        all_brokers_failed = (failed_brokers == total_brokers and total_brokers > 0)
        
        if all_brokers_failed:
            if self.debug:
                self.logger.debug(f"All {total_brokers} MQTT broker(s) have persistent failures")
        
        return not all_brokers_failed
    
    async def connect(self) -> bool:
        """Connect to MeshCore node using official package"""
        try:
            self.logger.info("Connecting to MeshCore node...")
            
            # Clean up any existing connection before attempting new one
            # This prevents pending tasks from interfering with new connections
            if self.meshcore:
                try:
                    self.cleanup_event_subscriptions()
                    self.meshcore.stop()
                    await self.meshcore.disconnect()
                except Exception as cleanup_error:
                    self.logger.debug(f"Error cleaning up existing connection before reconnect: {cleanup_error}")
                self.meshcore = None
                # Brief delay to ensure cleanup completes
                await asyncio.sleep(0.2)
            
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
                # Create TCP connection with SDK auto-reconnect if enabled
                tcp_host = self.get_env('TCP_HOST', 'localhost')
                tcp_port = self.get_env_int('TCP_PORT', 5000)
                self.logger.info(f"Connecting via TCP to {tcp_host}:{tcp_port}")
                
                # Enable SDK auto-reconnect for TCP connections
                create_kwargs = {'debug': False}
                if self.tcp_sdk_auto_reconnect_enabled:
                    create_kwargs['auto_reconnect'] = True
                    create_kwargs['max_reconnect_attempts'] = self.tcp_sdk_max_reconnect_attempts
                    self.logger.info(f"SDK auto-reconnect enabled with max {self.tcp_sdk_max_reconnect_attempts} attempts")
                else:
                    self.logger.info("SDK auto-reconnect disabled - using custom reconnect logic")
                
                self.meshcore = await meshcore.MeshCore.create_tcp(tcp_host, tcp_port, **create_kwargs)
                
                # Reset SDK reconnect exhaustion flag on new connection
                self.sdk_reconnect_exhausted = False
                
                # Enable TCP keepalive if configured
                # Access transport via: meshcore.cx.connection.transport
                # (MeshCore.cx is ConnectionManager, connection is TCPConnection)
                if self.tcp_keepalive_enabled:
                    transport = get_transport(self.meshcore)
                    
                    if transport:
                        try:
                            if enable_tcp_keepalive(
                                transport, 
                                idle=self.tcp_keepalive_idle,
                                interval=self.tcp_keepalive_interval,
                                count=self.tcp_keepalive_count
                            ):
                                self.logger.info(f"TCP keepalive enabled (idle={self.tcp_keepalive_idle}s, interval={self.tcp_keepalive_interval}s, count={self.tcp_keepalive_count})")
                            else:
                                self.logger.warning("Failed to enable TCP keepalive")
                        except Exception as e:
                            self.logger.warning(f"Could not enable TCP keepalive: {e}")
                    else:
                        if self.debug:
                            # Only log as debug to avoid noise if transport is genuinely not accessible
                            self.logger.debug("Could not access transport for TCP keepalive configuration (transport may not be exposed by meshcore library)")
                        else:
                            # Log as info since this is a known limitation, not a critical error
                            self.logger.info("TCP keepalive configuration skipped (transport not accessible)")
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
                        # Clean up any partial connection
                        if self.meshcore:
                            try:
                                self.meshcore.stop()
                                await self.meshcore.disconnect()
                            except:
                                pass
                            self.meshcore = None
                        # Fallback to general scan
                        self.logger.info("Falling back to general BLE scan...")
                        self.meshcore = await meshcore.MeshCore.create_ble(debug=False)
                else:
                    # No specific device, just scan and connect to first available
                    self.logger.info("Scanning for available BLE devices...")
                    self.meshcore = await meshcore.MeshCore.create_ble(debug=False)
            
            # Wait a brief moment for connection to fully establish (especially for BLE)
            if self.meshcore and self.connection_type == 'ble':
                await asyncio.sleep(0.5)
                # Retry connection check a few times in case it's still establishing
                for attempt in range(3):
                    if self.meshcore.is_connected:
                        break
                    if attempt < 2:
                        await asyncio.sleep(0.5)
            
            if self.meshcore and self.meshcore.is_connected:
                self._reset_connection_state()
                self.logger.info(f"Connected to: {self.meshcore.self_info}")
                
                # Update binary proxy with meshcore instance (if enabled)
                if self.binary_proxy:
                    self.binary_proxy.meshcore = self.meshcore
                
                # Wait for self_info to be populated (it may be empty initially, especially for serial)
                # Check if self_info has actual content (not just empty dict)
                max_wait_attempts = 10
                wait_interval = 0.5
                self_info_populated = False
                
                for attempt in range(max_wait_attempts):
                    if self.meshcore.self_info and (
                        self.meshcore.self_info.get('name') or 
                        self.meshcore.self_info.get('public_key')
                    ):
                        self_info_populated = True
                        break
                    if attempt < max_wait_attempts - 1:
                        self.logger.debug(f"Waiting for device info to populate (attempt {attempt + 1}/{max_wait_attempts})...")
                        await asyncio.sleep(wait_interval)
                
                # Try to trigger device info by sending a query (for serial connections especially)
                if not self_info_populated and hasattr(self.meshcore, 'commands'):
                    try:
                        self.logger.debug("Attempting to query device info...")
                        result = await self.retryable_device_command(
                            lambda: self.meshcore.commands.send_device_query(),
                            "send_device_query (device info)",
                            timeout=3.0,
                            max_retries=self.device_info_retry_limit,  # Use device info retry limit
                            retry_delay=0.2
                        )
                        # Wait a bit more after query
                        await asyncio.sleep(0.5)
                        if self.meshcore.self_info and (
                            self.meshcore.self_info.get('name') or 
                            self.meshcore.self_info.get('public_key')
                        ):
                            self_info_populated = True
                    except Exception as e:
                        self.logger.debug(f"Device query failed (non-critical): {e}")
                
                # Store device information for origin field
                if self_info_populated and self.meshcore.self_info:
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
                else:
                    # Fallback: Use configured origin or default
                    self.logger.warning("Device info not available from connection, using fallback")
                    self.device_name = self.get_env('ORIGIN', 'MeshCore Device')
                    self.device_public_key = 'Unknown'
                    self.radio_info = "0,0,0,0"
                    self.logger.info(f"Using fallback device name: {self.device_name}")
                    self.logger.info("You can set PACKETCAPTURE_ORIGIN in .env.local to customize the device name")
                
                # Set radio clock to current system time
                await self.set_radio_clock()
                
                # Don't publish status here - wait for MQTT connections
                # Status will be published after MQTT connections are established
                
                # Setup JWT authentication - will use on-device signing (preferred)
                # Private key fallback will be loaded lazily only if device signing fails
                self.logger.info("Setting up JWT authentication...")
                self.logger.info("✓ JWT authentication: Will use on-device signing")
                
                return True
            else:
                self.logger.error("Failed to connect to MeshCore node")
                # Clean up failed connection attempt to prevent pending tasks
                if self.meshcore:
                    try:
                        self.cleanup_event_subscriptions()
                        self.meshcore.stop()
                        await self.meshcore.disconnect()
                    except Exception as cleanup_error:
                        self.logger.debug(f"Error cleaning up failed connection: {cleanup_error}")
                    self.meshcore = None
                return False
                
        except Exception as e:
            self.logger.error(f"Connection failed: {e}")
            # Clean up any partial connection on exception
            if self.meshcore:
                try:
                    self.cleanup_event_subscriptions()
                    self.meshcore.stop()
                    await self.meshcore.disconnect()
                except Exception as cleanup_error:
                    self.logger.debug(f"Error cleaning up failed connection: {cleanup_error}")
                self.meshcore = None
            return False
    
    def cleanup_event_subscriptions(self):
        """Clean up all event subscriptions before disconnecting to prevent pending tasks"""
        if not self.meshcore:
            return
        
        try:
            # Use meshcore.unsubscribe() method which is the proper API
            if hasattr(self.meshcore, "dispatcher") and hasattr(self.meshcore.dispatcher, "subscriptions"):
                subscription_count = len(self.meshcore.dispatcher.subscriptions)
                if subscription_count > 0:
                    self.logger.debug(f"Cleaning up {subscription_count} event subscriptions")
                    # Create a copy of the list to avoid modification during iteration
                    for subscription in list(self.meshcore.dispatcher.subscriptions):
                        try:
                            # Use meshcore.unsubscribe() - the proper API method
                            self.meshcore.unsubscribe(subscription)
                        except Exception as e:
                            self.logger.debug(f"Error unsubscribing: {e}")
                    self.logger.debug(f"Cleared {subscription_count} event subscriptions")
        except Exception as e:
            self.logger.debug(f"Error cleaning up subscriptions: {e}")

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
        # Capture BLE address before disconnecting (needed for bluetoothctl cleanup)
        ble_device = None
        if self.meshcore and self.connection_type == 'ble':
            # Try to get BLE address from meshcore object before disconnecting
            try:
                # Check if meshcore has address attribute (BLE connections often do)
                if hasattr(self.meshcore, 'address') and self.meshcore.address:
                    ble_device = self.meshcore.address
            except Exception:
                pass
            # Fallback to environment variables
            if not ble_device:
                ble_device = self.get_env('BLE_DEVICE', '') or self.get_env('BLE_ADDRESS', '')
        
        if self.meshcore:
            try:
                # Clean up event subscriptions BEFORE stopping/disconnecting to prevent pending tasks
                self.cleanup_event_subscriptions()
                # Stop the event dispatcher task synchronously to prevent "Task was destroyed" errors
                try:
                    self.meshcore.stop()
                except Exception as e:
                    self.logger.debug(f"Error stopping meshcore event dispatcher: {e}")
                # Disconnect the connection
                await self.meshcore.disconnect()
            except Exception as e:
                self.logger.debug(f"Error disconnecting during reconnect: {e}")
            self.meshcore = None
            # For BLE connections, ensure full cleanup including OS-level disconnect
            if self.connection_type == 'ble':
                # On Linux, force disconnect via bluetoothctl to ensure clean state
                import platform
                if platform.system() == 'Linux':
                    try:
                        import subprocess
                        if ble_device and ble_device != 'Unknown':
                            self.logger.debug(f"Force disconnecting BLE device {ble_device} via bluetoothctl...")
                            subprocess.run(['bluetoothctl', 'disconnect', ble_device], 
                                         capture_output=True, timeout=10)
                            await asyncio.sleep(1)  # Give time for disconnection
                    except Exception as e:
                        self.logger.debug(f"Could not force BLE disconnect via bluetoothctl: {e}")
                else:
                    # On non-Linux systems, add a short delay to ensure BLE cleanup completes
                    await asyncio.sleep(0.5)
        
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
        
        # Track last MQTT health check time separately
        last_mqtt_check = 0
        
        while not self.should_exit:
            try:
                if await self.wait_with_shutdown(self.health_check_interval):
                    break  # Shutdown was requested
                
                # Check if we need to reconnect (either disconnected or health check failed)
                # For TCP with SDK auto-reconnect, only check health if SDK has exhausted
                if self._is_tcp_sdk_auto_reconnect_active():
                    # SDK is handling reconnection - just check if it succeeded
                    if self.meshcore and self.meshcore.is_connected:
                        if not self.connected:
                            # SDK reconnected - update our state
                            self._reset_connection_state()
                            self.logger.info("SDK auto-reconnect succeeded - connection restored")
                            await self._setup_after_reconnection()
                    # Skip health check and reconnect logic - let SDK handle it
                    continue
                
                # For other connection types or after SDK has exhausted, do normal health check
                health_check_passed = await self.check_connection_health()
                needs_reconnection = not self.connected or not health_check_passed
                
                if needs_reconnection:
                    
                    # For non-TCP connections, or TCP after SDK has exhausted, use custom reconnect
                    if not self.connected:
                        self.logger.info("Connection is disconnected, attempting reconnection...")
                    else:
                        self.logger.warning("MeshCore connection health check failed, attempting reconnection...")
                    
                    # Attempt to reconnect
                    if await self.reconnect_meshcore():
                        self.logger.info("MeshCore reconnection successful, resuming packet capture")
                        self._reset_connection_state()
                        await self._setup_after_reconnection()
                    else:
                        self.logger.error("MeshCore reconnection failed, will retry on next health check")
                        # Track consecutive failures for more intelligent failure detection
                        if self.track_consecutive_failure("connection"):
                            return  # Exit if service failure threshold reached
                
                # Check MQTT health periodically (separate interval to avoid being too aggressive)
                import time
                current_time = time.time()
                if self.enable_mqtt and (current_time - last_mqtt_check) >= self.mqtt_health_check_interval:
                    last_mqtt_check = current_time
                    mqtt_healthy = self.check_mqtt_health()
                    
                    if not mqtt_healthy:
                        # All brokers have been disconnected past grace period - this is a persistent failure
                        self.logger.warning("MQTT health check failed - all brokers disconnected past grace period")
                        # Track consecutive failures for more intelligent failure detection
                        if self.track_consecutive_failure("mqtt"):
                            return  # Exit if service failure threshold reached
                    elif self.debug:
                        self.logger.debug("MQTT health check passed")
                
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
            
            # Clear disconnect timestamp if this was a reconnection
            if broker_num and broker_num in self.mqtt_disconnect_timestamps:
                import time
                disconnect_duration = time.time() - self.mqtt_disconnect_timestamps[broker_num]
                self.logger.info(f"MQTT{broker_num} reconnected after {disconnect_duration:.1f} seconds")
                del self.mqtt_disconnect_timestamps[broker_num]
                # Reset consecutive failures on successful reconnection
                self.reset_consecutive_failures("mqtt")
            
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
            # Record disconnect timestamp for each disconnected broker (will be tracked in health check)
            import time
            for info in self.mqtt_clients:
                if info['client'] == client and info['broker_num'] not in self.mqtt_disconnect_timestamps:
                    self.mqtt_disconnect_timestamps[info['broker_num']] = time.time()
                    self.logger.debug(f"MQTT{info['broker_num']} disconnect recorded - grace period started")
            
            # Only attempt reconnection if we're not shutting down
            if not self.should_exit:
                self.logger.warning("All MQTT brokers disconnected. paho-mqtt will attempt reconnection automatically...")
                self.logger.info(f"Grace period: {self.mqtt_grace_period}s before counting as persistent failure")
                # Don't exit immediately - let reconnection logic and health check handle it
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

        # Validate IATA configuration for brokers that require it
        if self.broker_requires_iata(broker_num) and not self.has_configured_iata(broker_num):
            server = self.get_env(f'MQTT{broker_num}_SERVER', 'unknown')
            self.logger.warning(
                f"WARNING: MQTT broker {broker_num} ({server}) requires IATA configuration but IATA code is not set.\n"
                f"  This broker will be DISABLED during startup.\n"
                f"  To fix this issue:\n"
                f"    1. Set a global IATA code: PACKETCAPTURE_IATA=<airport_code>\n"
                f"    2. Or set a broker-specific IATA: PACKETCAPTURE_MQTT{broker_num}_IATA=<airport_code>\n"
                f"    3. Valid IATA codes are 3-letter airport identifiers (e.g., JFK, LAX, SFO)\n"
                f"    4. Restart the packet capture service after setting the IATA code"
            )
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
    
    

    async def publish_status(self, status, client=None, broker_num=None, refresh_stats=True):
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
        
        # Attach stats (online status only) if supported and enabled
        if (
            status.lower() == "online"
            and self.stats_status_enabled
        ):
            stats_payload = None
            if refresh_stats:
                # Always force refresh stats right before publishing to ensure fresh data
                stats_payload = await self.refresh_stats(force=True)
                if not stats_payload:
                    self.logger.debug("Stats refresh returned no data - stats will not be included in status message")
            elif self.latest_stats:
                stats_payload = dict(self.latest_stats)
            
            if stats_payload:
                status_msg["stats"] = stats_payload
            elif self.debug:
                self.logger.debug("No stats payload available - status message will not include stats")
        
        if client:
            self.safe_publish(None, json.dumps(status_msg), retain=True, client=client, broker_num=broker_num, topic_type="status")
        else:
            self.safe_publish(None, json.dumps(status_msg), retain=True, topic_type="status")
        if self.debug:
            self.logger.debug(f"Published status: {status}")

    def stats_commands_available(self) -> bool:
        """Detect whether the connected meshcore build exposes stats commands."""
        if not self.meshcore or not hasattr(self.meshcore, "commands"):
            return False
        
        commands = self.meshcore.commands
        required = ["get_stats_core", "get_stats_radio"]
        available = all(callable(getattr(commands, attr, None)) for attr in required)
        state = "available" if available else "missing"
        if state != self.stats_capability_state:
            if available:
                self.logger.info("MeshCore stats commands detected - status messages will include device stats")
            else:
                self.logger.info("MeshCore stats commands not available - skipping stats in status messages")
            self.stats_capability_state = state
        self.stats_supported = available
        return available

    async def refresh_stats(self, force: bool = False):
        """Fetch stats from the radio and cache them for status publishing."""
        if not self.stats_status_enabled:
            if self.debug:
                self.logger.debug("Stats refresh skipped: stats_status_enabled is False")
            return None
        
        if not self._ensure_connected("refresh_stats", "debug"):
            return None
        
        if self.stats_refresh_interval <= 0:
            if self.debug:
                self.logger.debug("Stats refresh skipped: stats_refresh_interval is 0 or negative")
            return None
        
        if not self.stats_commands_available():
            if self.debug:
                self.logger.debug("Stats refresh skipped: stats commands not available")
            return None
        
        now = time.time()
        if (
            not force
            and self.latest_stats
            and (now - self.last_stats_fetch) < max(60, self.stats_refresh_interval // 2)
        ):
            return dict(self.latest_stats)
        
        async with self.stats_fetch_lock:
            # Another coroutine may have completed the refresh while we waited
            if (
                not force
                and self.latest_stats
                and (time.time() - self.last_stats_fetch) < max(60, self.stats_refresh_interval // 2)
            ):
                return dict(self.latest_stats)
            
            stats_payload = {}
            try:
                core_result = await self.retryable_device_command(
                    lambda: self.meshcore.commands.get_stats_core(),
                    "get_stats_core",
                    timeout=8.0,
                    max_retries=self.stats_retry_limit,  # Use stats retry limit
                    retry_delay=0.2
                )
                if core_result and core_result.type == EventType.STATS_CORE and core_result.payload:
                    stats_payload.update(core_result.payload)
                elif core_result and core_result.type == EventType.ERROR:
                    self.logger.debug(f"Core stats unavailable: {core_result.payload}")
            except Exception as exc:
                self.logger.debug(f"Error fetching core stats: {exc}")
            
            try:
                radio_result = await self.retryable_device_command(
                    lambda: self.meshcore.commands.get_stats_radio(),
                    "get_stats_radio",
                    timeout=8.0,
                    max_retries=self.stats_retry_limit,  # Use stats retry limit
                    retry_delay=0.2
                )
                if radio_result and radio_result.type == EventType.STATS_RADIO and radio_result.payload:
                    stats_payload.update(radio_result.payload)
                elif radio_result and radio_result.type == EventType.ERROR:
                    self.logger.debug(f"Radio stats unavailable: {radio_result.payload}")
            except Exception as exc:
                self.logger.debug(f"Error fetching radio stats: {exc}")
            
            if stats_payload:
                self.latest_stats = stats_payload
                self.last_stats_fetch = time.time()
                if self.debug:
                    self.logger.debug(f"Updated stats cache: {self.latest_stats}")
            elif self.debug:
                self.logger.debug("Stats refresh completed but returned no data")
        
        return dict(self.latest_stats) if self.latest_stats else None

    async def stats_refresh_scheduler(self):
        """Periodically refresh stats and publish them via MQTT."""
        if self.stats_refresh_interval <= 0 or not self.stats_status_enabled:
            return
        
        while not self.should_exit:
            try:
                # Only fetch stats when we're about to publish status
                if self.enable_mqtt and self.mqtt_connected:
                    await self.publish_status("online", refresh_stats=True)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                self.logger.debug(f"Stats refresh error: {exc}")
            
            if await self.wait_with_shutdown(self.stats_refresh_interval):
                break

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
        
        # Filter by packet type if configured (only affects MQTT upload, not file/console output)
        if self.allowed_upload_types is not None:
            packet_type = packet_data.get('packet_type')
            if packet_type not in self.allowed_upload_types:
                # Skip MQTT upload but already wrote to file/console above
                if self.debug:
                    self.logger.debug(f"Filtered out packet type {packet_type} from upload (not in allowed types: {sorted(self.allowed_upload_types)})")
                # Return zero metrics since we didn't upload
                return {"attempted": 0, "succeeded": 0}
        
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
            
            # For TCP connections with SDK auto-reconnect, this event means SDK has exhausted its attempts
            if self.connection_type == 'tcp' and self.tcp_sdk_auto_reconnect_enabled:
                self.sdk_reconnect_exhausted = True
                self.logger.info("SDK auto-reconnect has exhausted - custom reconnect logic will take over")
            
            # Update connection status - connection monitor will handle reconnection
            self.connected = False
            self.logger.info("Connection status updated - connection monitor will handle reconnection")
        
        self.meshcore.subscribe(EventType.DISCONNECTED, on_disconnect)
        self.logger.debug("Disconnect event handler registered")

    async def setup_event_handlers(self):
        """Setup event handlers for packet capture"""
        # Clean up any existing subscriptions before setting up new ones
        # This prevents orphaned EventDispatcher tasks when reconnecting
        self.cleanup_event_subscriptions()
        
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
        
        # Hook into meshcore events to forward responses to binary interface clients
        # This is needed because raw binary commands sent via connection.send() won't
        # trigger meshcore events, but we can still try to intercept any events that do come through
        if self.binary_proxy:
            # Set up event forwarding for binary interface
            # Note: This is limited - raw binary commands may not generate events
            async def forward_event_to_binary_interface(event):
                """Forward meshcore events to binary interface clients if they match pending commands"""
                # This would need to match events to pending commands
                # For now, we'll log it for debugging
                if self.debug:
                    self.logger.debug(f"Event received that might be response: {event}")
            
            # Subscribe to all event types to catch responses
            # This is a workaround - ideally we'd have direct access to responses
            # But meshcore_py's event system doesn't easily support this for raw binary commands
        
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
        
        # Start binary interface proxy (if enabled)
        if self.binary_proxy:
            try:
                self.logger.info("Starting binary interface proxy...")
                await self.binary_proxy.start()
                self.logger.info("Binary interface proxy started successfully")
            except Exception as e:
                self.logger.error(f"Failed to start binary interface proxy: {e}", exc_info=True)
        else:
            self.logger.debug("Binary interface proxy not enabled or not initialized")
        
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
        
        # Start stats refresh scheduler
        if self.stats_status_enabled and self.stats_refresh_interval > 0:
            self.stats_update_task = asyncio.create_task(self.stats_refresh_scheduler())
        
        
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
            if self.stats_update_task:
                self.stats_update_task.cancel()
            
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
            if self.stats_update_task:
                try:
                    await self.stats_update_task
                except asyncio.CancelledError:
                    pass
            
            # Wait for all active tasks to complete
            if self.active_tasks:
                await asyncio.gather(*self.active_tasks, return_exceptions=True)
            
            # Stop binary interface proxy (if enabled)
            if self.binary_proxy:
                await self.binary_proxy.stop()
            
            await self.stop()
    
    async def stop(self):
        """Stop packet capture with timeout"""
        self.logger.info("Stopping packet capture...")
        self.connected = False
        
        # Stop binary interface proxy (if enabled)
        if self.binary_proxy:
            await self.binary_proxy.stop()
        
        try:
            # Publish offline status with timeout
            if self.enable_mqtt and self.mqtt_connected:
                await asyncio.wait_for(self.publish_status("offline", refresh_stats=False), timeout=5.0)
        except asyncio.TimeoutError:
            self.logger.warning("Timeout publishing offline status")
        except Exception as e:
            self.logger.warning(f"Error publishing offline status: {e}")
        
        # Handle BLE disconnection if using BLE connection
        if self.meshcore and self.get_env('CONNECTION_TYPE', 'ble').lower() == 'ble':
            try:
                self.logger.info("Disconnecting BLE device...")
                # Clean up event subscriptions BEFORE stopping/disconnecting to prevent pending tasks
                self.cleanup_event_subscriptions()
                # Stop the event dispatcher task synchronously to prevent "Task was destroyed" errors
                try:
                    self.meshcore.stop()
                except Exception as e:
                    self.logger.debug(f"Error stopping meshcore event dispatcher: {e}")
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
                else:
                    # On non-Linux systems, add a short delay to ensure BLE cleanup completes
                    await asyncio.sleep(0.5)
            except asyncio.TimeoutError:
                self.logger.warning("Timeout disconnecting BLE device")
            except Exception as e:
                self.logger.warning(f"Error during BLE disconnection: {e}")
        elif self.meshcore:
            try:
                # Clean up event subscriptions BEFORE stopping/disconnecting to prevent pending tasks
                self.cleanup_event_subscriptions()
                # Stop the event dispatcher task synchronously to prevent "Task was destroyed" errors
                try:
                    self.meshcore.stop()
                except Exception as e:
                    self.logger.debug(f"Error stopping meshcore event dispatcher: {e}")
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
            if not self._ensure_connected("send_advert", "warning"):
                return False
            
            self.logger.info("Sending flood advert...")
            await self.meshcore.commands.send_advert(flood=True)
            self.last_advert_time = time.time()
            self._save_advert_state()  # Persist the timestamp
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
