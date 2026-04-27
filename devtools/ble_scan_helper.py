#!/usr/bin/env python3
"""
BLE Device Scanner Helper for MeshCore Packet Capture Installer
Uses the meshcore library to scan for MeshCore BLE devices
"""

import asyncio
import sys
import json
from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

async def scan_ble_devices():
    """Scan for MeshCore BLE devices using BleakScanner"""
    try:
        # Send status message to stderr so it doesn't interfere with JSON output
        print("Scanning for MeshCore BLE devices...", file=sys.stderr, flush=True)
        
        # Scan for all devices first
        devices = await BleakScanner.discover(timeout=10.0)
        
        # Filter to only MeshCore devices
        meshcore_devices = []
        for device in devices:
            if device.name:
                name = device.name
                if name.startswith("Meshcore-") or name.startswith("MeshCore-"):
                    meshcore_devices.append(device)
        
        devices = meshcore_devices
        
        if not devices:
            print("No MeshCore BLE devices found", file=sys.stderr, flush=True)
            return []
        
        # Format devices for the installer
        formatted_devices = []
        for device in devices:
            device_info = {
                "address": device.address,
                "name": device.name or "Unknown",
                "rssi": None  # RSSI is not easily accessible in this context
            }
            formatted_devices.append(device_info)
        
        # Output as JSON for the installer to parse (stdout only)
        print(json.dumps(formatted_devices), flush=True)
        return formatted_devices
        
    except Exception as e:
        print(f"Error scanning for BLE devices: {e}", file=sys.stderr, flush=True)
        return []

def main():
    """Main function to run the BLE scan"""
    try:
        devices = asyncio.run(scan_ble_devices())
        if not devices:
            sys.exit(1)
    except KeyboardInterrupt:
        print("Scan interrupted by user", file=sys.stderr, flush=True)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr, flush=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
