#!/usr/bin/env python3
"""
Test client for binary interface proxy
Sends CMD_APP_START and CMD_DEVICE_QUERY to test responses
"""

import socket
import sys

# Constants from packet_capture.py
FRAME_HEADER_IN = 0x3C  # '<'
FRAME_HEADER_OUT = 0x3E  # '>'
CMD_APP_START = 0x01
CMD_DEVICE_QUERY = 0x16
RESP_CODE_OK = 0x01
RESP_CODE_SELF_INFO = 0x05
RESP_CODE_DEVICE_INFO = 0x0D

def wrap_frame(data):
    """Wrap data with incoming frame protocol: '<' + 2-byte LE length + payload"""
    length = len(data)
    frame = bytes([FRAME_HEADER_IN])  # '<'
    frame += length.to_bytes(2, 'little')  # 2-byte little-endian length
    frame += data  # Payload
    return frame

def unwrap_frame(sock):
    """Read and unwrap a response frame"""
    # Read frame header (expect '>')
    header = sock.recv(1)
    if not header:
        return None

    if header[0] != FRAME_HEADER_OUT:
        print(f"ERROR: Invalid frame header: 0x{header[0]:02X} (expected 0x{FRAME_HEADER_OUT:02X})")
        return None

    # Read 2-byte length
    length_bytes = sock.recv(2)
    if len(length_bytes) < 2:
        print(f"ERROR: Incomplete length field")
        return None

    length = int.from_bytes(length_bytes, 'little')
    print(f"  Frame length: {length} bytes")

    # Read payload
    payload = b''
    while len(payload) < length:
        chunk = sock.recv(length - len(payload))
        if not chunk:
            print(f"ERROR: Incomplete payload: got {len(payload)}/{length} bytes")
            return None
        payload += chunk

    return payload

def test_connection(host='127.0.0.1', port=5001):
    """Test the binary interface proxy"""
    print(f"Connecting to {host}:{port}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10.0)

    try:
        sock.connect((host, port))
        print(f"✓ Connected to {host}:{port}")
        print()

        # Test 1: Send CMD_APP_START
        print("=" * 60)
        print("TEST 1: CMD_APP_START")
        print("=" * 60)
        cmd_data = bytes([CMD_APP_START])
        frame = wrap_frame(cmd_data)
        print(f"Sending CMD_APP_START frame: {frame.hex()}")
        sock.send(frame)

        # Expect RESP_CODE_OK
        print("\nWaiting for RESP_CODE_OK...")
        payload1 = unwrap_frame(sock)
        if payload1:
            print(f"  Response payload: {payload1.hex()}")
            if payload1[0] == RESP_CODE_OK:
                print(f"  ✓ Got RESP_CODE_OK")
            else:
                print(f"  ✗ Expected RESP_CODE_OK (0x{RESP_CODE_OK:02X}), got 0x{payload1[0]:02X}")

        # Expect RESP_CODE_SELF_INFO
        print("\nWaiting for RESP_CODE_SELF_INFO...")
        payload2 = unwrap_frame(sock)
        if payload2:
            print(f"  Response payload ({len(payload2)} bytes): {payload2.hex()}")
            if payload2[0] == RESP_CODE_SELF_INFO:
                print(f"  ✓ Got RESP_CODE_SELF_INFO")
                # Format: [RESP_CODE][name_len][name][32-byte public_key]
                name_len = payload2[1]
                name = payload2[2:2+name_len].decode('utf-8', errors='ignore')
                public_key = payload2[2+name_len:2+name_len+32].hex()
                print(f"    Name length: {name_len}")
                print(f"    Name: '{name}' ({len(name)} bytes)")
                print(f"    Public key: {public_key}")
            else:
                print(f"  ✗ Expected RESP_CODE_SELF_INFO (0x{RESP_CODE_SELF_INFO:02X}), got 0x{payload2[0]:02X}")

        print()

        # Test 2: Send CMD_DEVICE_QUERY
        print("=" * 60)
        print("TEST 2: CMD_DEVICE_QUERY")
        print("=" * 60)
        cmd_data = bytes([CMD_DEVICE_QUERY])
        frame = wrap_frame(cmd_data)
        print(f"Sending CMD_DEVICE_QUERY frame: {frame.hex()}")
        sock.send(frame)

        # Expect RESP_CODE_DEVICE_INFO
        print("\nWaiting for RESP_CODE_DEVICE_INFO...")
        payload3 = unwrap_frame(sock)
        if payload3:
            print(f"  Response payload ({len(payload3)} bytes): {payload3.hex()}")
            if payload3[0] == RESP_CODE_DEVICE_INFO:
                print(f"  ✓ Got RESP_CODE_DEVICE_INFO")
                if len(payload3) >= 80:
                    fw_version = payload3[1]
                    max_contacts = payload3[2] * 2
                    max_channels = payload3[3]
                    ble_pin = int.from_bytes(payload3[4:8], 'little')
                    fw_build = payload3[8:20].rstrip(b'\x00').decode('utf-8', errors='ignore')
                    manufacturer = payload3[20:60].rstrip(b'\x00').decode('utf-8', errors='ignore')
                    fw_ver_str = payload3[60:80].rstrip(b'\x00').decode('utf-8', errors='ignore')

                    print(f"    Firmware version: {fw_version}")
                    print(f"    Max contacts: {max_contacts}")
                    print(f"    Max channels: {max_channels}")
                    print(f"    BLE PIN: {ble_pin}")
                    print(f"    Firmware build: '{fw_build}'")
                    print(f"    Manufacturer: '{manufacturer}'")
                    print(f"    Firmware version string: '{fw_ver_str}'")
                else:
                    print(f"  ✗ Payload too short (expected >= 80 bytes, got {len(payload3)})")
            else:
                print(f"  ✗ Expected RESP_CODE_DEVICE_INFO (0x{RESP_CODE_DEVICE_INFO:02X}), got 0x{payload3[0]:02X}")

        print()
        print("=" * 60)
        print("✓ All tests complete!")
        print("=" * 60)

    except socket.timeout:
        print("✗ Connection timed out")
        return 1
    except ConnectionRefusedError:
        print(f"✗ Connection refused - is the proxy running on {host}:{port}?")
        return 1
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        sock.close()

    return 0

if __name__ == '__main__':
    host = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5001

    sys.exit(test_connection(host, port))
