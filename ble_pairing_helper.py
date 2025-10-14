#!/usr/bin/env python3
"""
BLE Pairing Helper for MeshCore Packet Capture Installer
Checks pairing status and handles PIN-based pairing
"""

import asyncio
import sys
import json
from meshcore import MeshCore

async def check_pairing_and_connect(address, name, pin=None):
    """Check if device is paired and handle pairing if needed"""
    try:
        print(f"Checking pairing status for {name} ({address})...", file=sys.stderr, flush=True)
        
        # Try to connect without PIN first (with timeout)
        try:
            print(f"Attempting to connect to {name} ({address}) without PIN...", file=sys.stderr, flush=True)
            # Try the address as-is first (could be MAC or UUID format)
            meshcore = await asyncio.wait_for(MeshCore.create_ble(address=address, debug=True), timeout=10.0)
            print("Device is already paired and connected successfully", file=sys.stderr, flush=True)
            
            # Wait a moment for the device to stabilize and send self_info
            print("Waiting for device to stabilize...", file=sys.stderr, flush=True)
            await asyncio.sleep(3)
            
            # Verify device communication by checking self_info
            try:
                print("Verifying device communication by checking self_info...", file=sys.stderr, flush=True)
                device_name = meshcore.self_info.get('name', 'Unknown')
                print(f"Device name from self_info: {device_name}", file=sys.stderr, flush=True)
                print("Device communication verified successfully", file=sys.stderr, flush=True)
                await meshcore.disconnect()
                print(json.dumps({"status": "paired", "message": "Device is already paired and communicating properly"}), flush=True)
                return True
            except Exception as info_e:
                print(f"Device connected but self_info check failed: {info_e}", file=sys.stderr, flush=True)
                print("Device may be connected but not fully ready", file=sys.stderr, flush=True)
                await meshcore.disconnect()
                print(json.dumps({"status": "paired", "message": "Device is paired but may need time to be fully ready"}), flush=True)
                return True  # Still consider it paired since connection worked
        except Exception as e:
            error_msg = str(e)
            print(f"Connection attempt failed with error: {error_msg}", file=sys.stderr, flush=True)
            print(f"Error type: {type(e).__name__}", file=sys.stderr, flush=True)
            
            if "Not paired" in error_msg or "NotPermitted" in error_msg:
                print("Device is not paired, pairing required", file=sys.stderr, flush=True)
                print(json.dumps({"status": "not_paired", "message": "Device requires pairing"}), flush=True)
                return False
            elif "No MeshCore device found" in error_msg or "Failed to connect" in error_msg:
                print("Device not found or not in range, may need to be in pairing mode", file=sys.stderr, flush=True)
                print(json.dumps({"status": "not_found", "message": "Device not found or not in range"}), flush=True)
                return False
            elif "TimeoutError" in error_msg or "timeout" in error_msg.lower():
                print("Connection timed out, device may be busy or not responding", file=sys.stderr, flush=True)
                print(json.dumps({"status": "timeout", "message": "Connection timed out"}), flush=True)
                return False
            else:
                print(f"Connection error: {error_msg}", file=sys.stderr, flush=True)
                print(json.dumps({"status": "error", "message": error_msg}), flush=True)
                return False
                
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr, flush=True)
        print(json.dumps({"status": "error", "message": str(e)}), flush=True)
        return False

async def attempt_pairing(address, name, pin):
    """Attempt to pair with the device using the provided PIN"""
    try:
        print(f"Attempting to pair with {name} using PIN...", file=sys.stderr, flush=True)
        
        meshcore = await asyncio.wait_for(MeshCore.create_ble(address=address, pin=pin, debug=False), timeout=60.0)
        print("Pairing successful! Verifying connection...", file=sys.stderr, flush=True)
        await meshcore.disconnect()
        
        # Wait a moment for the connection to fully close
        await asyncio.sleep(2)
        
        # Attempt to reconnect to verify pairing was successful
        print("Verifying pairing by attempting reconnection...", file=sys.stderr, flush=True)
        try:
            meshcore_verify = await asyncio.wait_for(MeshCore.create_ble(address=address, debug=False), timeout=30.0)
            await meshcore_verify.disconnect()
            print("Connection verification successful!", file=sys.stderr, flush=True)
            print(json.dumps({"status": "paired", "message": "Pairing and connection verification successful"}), flush=True)
            return True
        except Exception as verify_e:
            print(f"Connection verification failed: {verify_e}", file=sys.stderr, flush=True)
            print("Pairing may have succeeded but device is not immediately available", file=sys.stderr, flush=True)
            print(json.dumps({"status": "paired", "message": "Pairing successful but connection verification failed - device may need time to become available"}), flush=True)
            return True  # Still consider pairing successful
        
    except Exception as e:
        error_msg = str(e)
        print(f"Pairing failed: {error_msg}", file=sys.stderr, flush=True)
        print(json.dumps({"status": "pairing_failed", "message": error_msg}), flush=True)
        return False

def main():
    """Main function to handle BLE pairing"""
    if len(sys.argv) < 3:
        print(json.dumps({"status": "error", "message": "Usage: script.py <address> <name> [pin]"}))
        sys.exit(1)
    
    address = sys.argv[1]
    name = sys.argv[2]
    pin = sys.argv[3] if len(sys.argv) > 3 else None
    
    try:
        if pin:
            # Attempt pairing with PIN
            success = asyncio.run(attempt_pairing(address, name, pin))
        else:
            # Check pairing status
            success = asyncio.run(check_pairing_and_connect(address, name))
        
        if not success:
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("Operation interrupted by user", file=sys.stderr, flush=True)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr, flush=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
