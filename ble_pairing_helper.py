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
    meshcore = None
    try:
        print(f"Checking pairing status for {name} ({address})...", file=sys.stderr, flush=True)
        
        # Try to connect without PIN first (with timeout)
        try:
            print(f"Attempting to connect to {name} ({address}) without PIN...", file=sys.stderr, flush=True)
            
            # Create the connection with a shorter timeout
            meshcore = await asyncio.wait_for(
                MeshCore.create_ble(address=address, debug=True), 
                timeout=15.0
            )
            
            print("Device connected successfully", file=sys.stderr, flush=True)
            
            # Give it a moment to stabilize
            await asyncio.sleep(1)
            
            # Try a simple operation to verify the connection works
            try:
                # Just check if we're still connected
                if meshcore and meshcore.is_connected:
                    print("Connection verified - device is paired and ready to use", file=sys.stderr, flush=True)
                    await meshcore.disconnect()
                    print(json.dumps({"status": "paired", "message": "Device is already paired and ready to use"}), flush=True)
                    return True
                else:
                    print("Connection lost during verification", file=sys.stderr, flush=True)
                    print(json.dumps({"status": "not_paired", "message": "Device connection unstable - may need pairing"}), flush=True)
                    return False
            except Exception as verify_err:
                print(f"Verification error: {verify_err}", file=sys.stderr, flush=True)
                print(json.dumps({"status": "not_paired", "message": "Device requires pairing"}), flush=True)
                return False
                
        except asyncio.TimeoutError:
            print("Connection timed out", file=sys.stderr, flush=True)
            print(json.dumps({"status": "timeout", "message": "Connection timed out"}), flush=True)
            return False
        except EOFError as e:
            print(f"Connection closed unexpectedly (EOFError) - device may need pairing", file=sys.stderr, flush=True)
            print(json.dumps({"status": "not_paired", "message": "Device requires pairing"}), flush=True)
            return False
        except Exception as e:
            error_msg = str(e)
            print(f"Connection attempt failed with error: {error_msg}", file=sys.stderr, flush=True)
            print(f"Error type: {type(e).__name__}", file=sys.stderr, flush=True)
            
            # Check if this is a pairing error
            if "Not paired" in error_msg or "NotPermitted" in error_msg or "NotAuthorized" in error_msg:
                print("Device is not paired, pairing required", file=sys.stderr, flush=True)
                print(json.dumps({"status": "not_paired", "message": "Device requires pairing"}), flush=True)
                return False
            elif "No MeshCore device found" in error_msg or "Failed to connect" in error_msg:
                print("Device not found or not in range", file=sys.stderr, flush=True)
                print(json.dumps({"status": "not_found", "message": "Device not found or not in range"}), flush=True)
                return False
            else:
                print(f"Connection error: {error_msg}", file=sys.stderr, flush=True)
                print(json.dumps({"status": "error", "message": error_msg}), flush=True)
                return False
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr, flush=True)
        print(json.dumps({"status": "error", "message": str(e)}), flush=True)
        return False
    finally:
        # Ensure we always disconnect
        if meshcore:
            try:
                await meshcore.disconnect()
            except:
                pass

async def attempt_pairing(address, name, pin):
    """Attempt to pair with the device using the provided PIN"""
    meshcore = None
    try:
        print(f"Attempting to pair with {name} using PIN...", file=sys.stderr, flush=True)
        
        meshcore = await asyncio.wait_for(
            MeshCore.create_ble(address=address, pin=pin, debug=False), 
            timeout=60.0
        )
        print("Pairing successful! Verifying connection...", file=sys.stderr, flush=True)
        
        # Give it a moment to stabilize
        await asyncio.sleep(2)
        
        await meshcore.disconnect()
        
        # Wait for connection to fully close
        await asyncio.sleep(2)
        
        # Verify pairing by reconnecting
        print("Verifying pairing by attempting reconnection...", file=sys.stderr, flush=True)
        try:
            meshcore_verify = await asyncio.wait_for(
                MeshCore.create_ble(address=address, debug=False), 
                timeout=30.0
            )
            await asyncio.sleep(1)
            await meshcore_verify.disconnect()
            print("Connection verification successful!", file=sys.stderr, flush=True)
            print(json.dumps({"status": "paired", "message": "Pairing and connection verification successful"}), flush=True)
            return True
        except Exception as verify_e:
            print(f"Connection verification failed: {verify_e}", file=sys.stderr, flush=True)
            print("Pairing may have succeeded but device is not immediately available", file=sys.stderr, flush=True)
            print(json.dumps({"status": "paired", "message": "Pairing successful but connection verification failed - device may need time to become available"}), flush=True)
            return True  # Still consider pairing successful
        
    except asyncio.TimeoutError:
        print("Pairing timed out", file=sys.stderr, flush=True)
        print(json.dumps({"status": "pairing_failed", "message": "Pairing timed out"}), flush=True)
        return False
    except Exception as e:
        error_msg = str(e)
        print(f"Pairing failed: {error_msg}", file=sys.stderr, flush=True)
        print(json.dumps({"status": "pairing_failed", "message": error_msg}), flush=True)
        return False
    finally:
        if meshcore:
            try:
                await meshcore.disconnect()
            except:
                pass

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
        
        # Don't exit with error code for not_paired status - let shell script handle it
        if not success and pin is None:
            # This is a pairing check that failed, but we want to return the status
            sys.exit(0)
        elif not success:
            # This is a pairing attempt that failed
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("Operation interrupted by user", file=sys.stderr, flush=True)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr, flush=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
