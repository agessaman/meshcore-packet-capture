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
        
        # Try to connect without PIN first
        try:
            meshcore = await MeshCore.create_ble(address=address, debug=False)
            print("Device is already paired and connected successfully", file=sys.stderr, flush=True)
            await meshcore.disconnect()
            print(json.dumps({"status": "paired", "message": "Device is already paired"}), flush=True)
            return True
        except Exception as e:
            error_msg = str(e)
            if "Not paired" in error_msg or "NotPermitted" in error_msg:
                print("Device is not paired, pairing required", file=sys.stderr, flush=True)
                print(json.dumps({"status": "not_paired", "message": "Device requires pairing"}), flush=True)
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
        
        meshcore = await MeshCore.create_ble(address=address, pin=pin, debug=False)
        print("Pairing successful!", file=sys.stderr, flush=True)
        await meshcore.disconnect()
        print(json.dumps({"status": "paired", "message": "Pairing successful"}), flush=True)
        return True
        
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
