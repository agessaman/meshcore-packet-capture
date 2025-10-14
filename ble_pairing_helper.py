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
                timeout=20.0
            )
            
            print("BLE connection established, verifying with device query...", file=sys.stderr, flush=True)
            
            # Try to send a command to verify the connection actually works
            # This is where pairing issues will show up
            try:
                result = await asyncio.wait_for(
                    meshcore.commands.send_device_query(),
                    timeout=10.0
                )
                
                if result and result.payload:
                    print(f"Device query successful - device is paired and working", file=sys.stderr, flush=True)
                    model = result.payload.get('model', 'Unknown')
                    fw_version = result.payload.get('fw_version', 'Unknown')
                    print(f"Device info: {model}, firmware: {fw_version}", file=sys.stderr, flush=True)
                    
                    await meshcore.disconnect()
                    print(json.dumps({
                        "status": "paired", 
                        "message": "Device is already paired and ready to use",
                        "model": model,
                        "firmware": fw_version
                    }), flush=True)
                    return True
                else:
                    print("Device query returned no data - may need pairing", file=sys.stderr, flush=True)
                    print(json.dumps({"status": "not_paired", "message": "Device requires pairing"}), flush=True)
                    return False
                    
            except asyncio.TimeoutError:
                print("Device query timed out - likely needs pairing", file=sys.stderr, flush=True)
                print(json.dumps({"status": "not_paired", "message": "Device requires pairing"}), flush=True)
                return False
            except EOFError:
                print("Connection closed during device query - likely needs pairing", file=sys.stderr, flush=True)
                print(json.dumps({"status": "not_paired", "message": "Device requires pairing"}), flush=True)
                return False
            except Exception as cmd_err:
                error_msg = str(cmd_err)
                print(f"Command error: {error_msg}", file=sys.stderr, flush=True)
                
                # Check for pairing-related errors
                if any(keyword in error_msg.lower() for keyword in ['pair', 'auth', 'permission', 'not permitted']):
                    print("Device requires pairing", file=sys.stderr, flush=True)
                    print(json.dumps({"status": "not_paired", "message": "Device requires pairing"}), flush=True)
                    return False
                else:
                    print(json.dumps({"status": "error", "message": error_msg}), flush=True)
                    return False
                
        except asyncio.TimeoutError:
            print("Connection timed out", file=sys.stderr, flush=True)
            print(json.dumps({"status": "timeout", "message": "Connection timed out"}), flush=True)
            return False
        except Exception as e:
            error_msg = str(e)
            print(f"Connection attempt failed: {error_msg}", file=sys.stderr, flush=True)
            print(f"Error type: {type(e).__name__}", file=sys.stderr, flush=True)
            
            # Check if this is clearly a "device not found" error
            if "No MeshCore device found" in error_msg or "not found" in error_msg.lower():
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
        print(f"Attempting to pair with {name} using PIN {pin}...", file=sys.stderr, flush=True)
        
        # First, try to remove any existing pairing to start fresh
        try:
            import subprocess
            print("Removing any existing pairing...", file=sys.stderr, flush=True)
            subprocess.run(['bluetoothctl', 'remove', address], 
                         capture_output=True, timeout=5)
            await asyncio.sleep(1)
        except Exception as e:
            print(f"Could not remove existing pairing (this is OK): {e}", file=sys.stderr, flush=True)
        
        # Connect with PIN
        meshcore = await asyncio.wait_for(
            MeshCore.create_ble(address=address, pin=pin, debug=True), 
            timeout=60.0
        )
        
        print("BLE connection with PIN established, verifying...", file=sys.stderr, flush=True)
        
        # Verify the pairing worked by sending a command
        try:
            result = await asyncio.wait_for(
                meshcore.commands.send_device_query(),
                timeout=10.0
            )
            
            if result and result.payload:
                print("Pairing successful! Device query returned data.", file=sys.stderr, flush=True)
                model = result.payload.get('model', 'Unknown')
                fw_version = result.payload.get('fw_version', 'Unknown')
                print(f"Device info: {model}, firmware: {fw_version}", file=sys.stderr, flush=True)
                
                await meshcore.disconnect()
                
                # Wait a moment for disconnection
                await asyncio.sleep(2)
                
                # Try reconnecting without PIN to confirm pairing persisted
                print("Verifying pairing persisted by reconnecting without PIN...", file=sys.stderr, flush=True)
                try:
                    meshcore_verify = await asyncio.wait_for(
                        MeshCore.create_ble(address=address, debug=False), 
                        timeout=20.0
                    )
                    
                    # Try a command
                    result = await asyncio.wait_for(
                        meshcore_verify.commands.send_device_query(),
                        timeout=10.0
                    )
                    
                    await meshcore_verify.disconnect()
                    
                    print("Pairing verification successful!", file=sys.stderr, flush=True)
                    print(json.dumps({
                        "status": "paired", 
                        "message": "Pairing and connection verification successful",
                        "model": model,
                        "firmware": fw_version
                    }), flush=True)
                    return True
                    
                except Exception as verify_e:
                    print(f"Reconnection test failed: {verify_e}", file=sys.stderr, flush=True)
                    print("Pairing may have succeeded but verification failed", file=sys.stderr, flush=True)
                    print(json.dumps({
                        "status": "paired", 
                        "message": "Pairing successful but verification failed - device should work",
                        "model": model,
                        "firmware": fw_version
                    }), flush=True)
                    return True  # Still consider success
            else:
                print("Device query after pairing returned no data", file=sys.stderr, flush=True)
                print(json.dumps({"status": "pairing_failed", "message": "Pairing completed but device not responding"}), flush=True)
                return False
                
        except asyncio.TimeoutError:
            print("Device query timed out after pairing", file=sys.stderr, flush=True)
            print(json.dumps({"status": "pairing_failed", "message": "Device not responding after pairing"}), flush=True)
            return False
        except Exception as cmd_err:
            error_msg = str(cmd_err)
            print(f"Command error after pairing: {error_msg}", file=sys.stderr, flush=True)
            print(json.dumps({"status": "pairing_failed", "message": f"Pairing may have failed: {error_msg}"}), flush=True)
            return False
        
    except asyncio.TimeoutError:
        print("Pairing connection timed out", file=sys.stderr, flush=True)
        print(json.dumps({"status": "pairing_failed", "message": "Pairing timed out - device may not be in pairing mode"}), flush=True)
        return False
    except Exception as e:
        error_msg = str(e)
        print(f"Pairing failed: {error_msg}", file=sys.stderr, flush=True)
        
        # Check for specific authentication failure
        if "AuthenticationFailed" in error_msg or "Authentication Failed" in error_msg:
            print(json.dumps({
                "status": "pairing_failed", 
                "message": "Authentication failed - PIN may be incorrect, expired, or device not in pairing mode"
            }), flush=True)
        else:
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