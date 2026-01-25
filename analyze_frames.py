#!/usr/bin/env python3
"""
Analyze MeshCore binary frames from hex dumps
"""

def analyze_frame(hex_string):
    """Analyze a frame and print its structure"""
    # Remove spaces and convert to bytes
    hex_clean = hex_string.replace(' ', '').replace('\n', '')
    data = bytes.fromhex(hex_clean)

    print(f"Total length: {len(data)} bytes")
    print(f"Hex: {data.hex()}")
    print()

    if len(data) < 3:
        print("Frame too short!")
        return

    # Parse frame header
    header = data[0]
    print(f"Frame header: 0x{header:02X}", end="")
    if header == 0x3E:
        print(" (outgoing - radio to app '>')")
    elif header == 0x3C:
        print(" (incoming - app to radio '<')")
    else:
        print(" (UNKNOWN)")

    # Parse length
    length = int.from_bytes(data[1:3], 'little')
    print(f"Payload length: {length} bytes (from header)")
    print(f"Actual payload: {len(data) - 3} bytes")

    if len(data) < 3 + length:
        print(f"WARNING: Incomplete frame! Need {3 + length} bytes, have {len(data)}")
        return

    payload = data[3:3+length]
    print()
    print("=== PAYLOAD ===")
    print(f"Response code: 0x{payload[0]:02X} ({payload[0]})")

    # Check if it's a RESP_CODE_OK (0x01 = 1)
    if payload[0] == 0x01:
        print("\nRESP_CODE_OK Response")
        print("  [0] Response code: 1 (RESP_CODE_OK)")
        if len(payload) > 1:
            print(f"  Additional data: {payload[1:].hex()}")

    # Check if it's a SELF_INFO response (0x05 = 5)
    elif payload[0] == 0x05 and len(payload) >= 34:
        print("\nRESP_CODE_SELF_INFO Response Structure:")
        print(f"  [0] Response code: {payload[0]} (RESP_CODE_SELF_INFO)")

        # Format: [RESP_CODE][name_len][name][32-byte public_key]
        name_len = payload[1]
        name = payload[2:2+name_len].decode('utf-8', errors='ignore')
        public_key = payload[2+name_len:2+name_len+32]

        print(f"  [1] Name length: {name_len}")
        print(f"  [2-{1+name_len}] Name: '{name}' ({len(name)} bytes)")
        print(f"  [{2+name_len}-{1+name_len+32}] Public key: {public_key.hex()}")

    # Check if it's a DEVICE_INFO response (0x0D = 13)
    elif payload[0] == 0x0D and len(payload) >= 80:
        print("\nDEVICE_INFO Response Structure:")
        print(f"  [0] Response code: {payload[0]} (RESP_CODE_DEVICE_INFO)")
        print(f"  [1] Firmware version: {payload[1]}")
        print(f"  [2] Max contacts/2: {payload[2]} (= {payload[2]*2} contacts)")
        print(f"  [3] Max channels: {payload[3]}")

        ble_pin = int.from_bytes(payload[4:8], 'little')
        print(f"  [4-7] BLE PIN: {ble_pin}")

        fw_build = payload[8:20].rstrip(b'\x00').decode('utf-8', errors='ignore')
        print(f"  [8-19] Firmware build: '{fw_build}'")

        manufacturer = payload[20:60].rstrip(b'\x00').decode('utf-8', errors='ignore')
        print(f"  [20-59] Manufacturer: '{manufacturer}'")

        fw_version = payload[60:80].rstrip(b'\x00').decode('utf-8', errors='ignore')
        print(f"  [60-79] Firmware version: '{fw_version}'")

    print()
    print("Full payload hex:")
    for i in range(0, len(payload), 16):
        chunk = payload[i:i+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f"  {i:04x}: {hex_part:48s} {ascii_part}")

if __name__ == '__main__':
    import sys

    if len(sys.argv) > 1:
        # Read from file or command line argument
        hex_input = sys.argv[1]
        if hex_input.endswith('.hex'):
            with open(hex_input, 'r') as f:
                hex_input = f.read()
    else:
        print("Paste the hex string (Ctrl+D when done):")
        hex_input = sys.stdin.read()

    analyze_frame(hex_input)
