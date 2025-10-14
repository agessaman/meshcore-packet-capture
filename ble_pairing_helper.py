#!/usr/bin/env python3
"""
BLE Pairing Helper for MeshCore Packet Capture Installer
Checks pairing status and handles PIN-based pairing
"""

import asyncio
import sys
import json
import platform
import subprocess
from meshcore import MeshCore

def is_linux():
    """Check if running on Linux"""
    return platform.system().lower() == 'linux'

async def check_pairing_and_connect(address, name, pin=None):
    """Check if device is paired and handle pairing if needed"""
    meshcore = None
    try:
        print(f"Checking pairing status for {name} ({address})...", file=sys.stderr, flush=True)
        
        # Try to connect without PIN first (with timeout)
        try:
            print(f"Attempting to connect to {name} ({address}) without PIN...", file=sys.stderr, flush=True)
            
            # Create the connection with a reasonable timeout
            meshcore = await asyncio.wait_for(
                MeshCore.create_ble(address=address, debug=True), 
                timeout=25.0
            )
            
            print("BLE connection established successfully", file=sys.stderr, flush=True)
            
            # Connection succeeded - device is paired
            await meshcore.disconnect()
            
            # Additional safety: Force disconnect on Linux using bluetoothctl if available
            if is_linux():
                try:
                    print("Ensuring already-paired device is fully disconnected...", file=sys.stderr, flush=True)
                    subprocess.run([
                        "bluetoothctl", "disconnect", address
                    ], capture_output=True, timeout=10)
                    await asyncio.sleep(1)
                except (FileNotFoundError, subprocess.TimeoutExpired, Exception) as e:
                    print(f"Could not force disconnect already-paired device via bluetoothctl (this is OK): {e}", file=sys.stderr, flush=True)
            
            print(json.dumps({
                "status": "paired", 
                "message": "Device is already paired and ready to use"
            }), flush=True)
            return True
            
        except EOFError as e:
            # This is the key indicator that pairing is required
            # Device connected but immediately disconnected - needs pairing
            print("Device connected but immediately disconnected - pairing required", file=sys.stderr, flush=True)
            print(json.dumps({
                "status": "not_paired", 
                "message": "Device requires pairing"
            }), flush=True)
            return False
                
        except asyncio.TimeoutError:
            # Timeout could mean device is busy or needs pairing
            print("Connection timed out", file=sys.stderr, flush=True)
            print(json.dumps({
                "status": "timeout", 
                "message": "Connection timed out - device may be busy or require pairing"
            }), flush=True)
            return False
            
        except ConnectionError as e:
            error_msg = str(e)
            print(f"Connection error: {error_msg}", file=sys.stderr, flush=True)
            
            # Check for pairing-related errors
            if any(keyword in error_msg.lower() for keyword in 
                   ['pair', 'auth', 'permission', 'not permitted', 'not authorized']):
                print("Device requires pairing", file=sys.stderr, flush=True)
                print(json.dumps({"status": "not_paired", "message": "Device requires pairing"}), flush=True)
                return False
            else:
                print(json.dumps({"status": "error", "message": error_msg}), flush=True)
                return False
                
        except Exception as e:
            error_msg = str(e)
            error_type = type(e).__name__
            print(f"Connection attempt failed: {error_msg}", file=sys.stderr, flush=True)
            print(f"Error type: {error_type}", file=sys.stderr, flush=True)
            
            # Check if this is clearly a "device not found" error
            if "No MeshCore device found" in error_msg or "not found" in error_msg.lower():
                print("Device not found or not in range", file=sys.stderr, flush=True)
                print(json.dumps({"status": "not_found", "message": "Device not found or not in range"}), flush=True)
                return False
            # Check for pairing errors
            elif any(keyword in error_msg.lower() for keyword in 
                     ['pair', 'auth', 'permission', 'not permitted', 'not authorized']):
                print("Device requires pairing", file=sys.stderr, flush=True)
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
    finally:
        # Ensure we always disconnect
        if meshcore:
            try:
                await meshcore.disconnect()
            except:
                pass

async def attempt_pairing(address, name, pin):
    """Attempt to pair with the device using the provided PIN"""
    if is_linux():
        return await attempt_pairing_linux(address, name, pin)
    else:
        return await attempt_pairing_meshcore(address, name, pin)

async def attempt_pairing_linux(address, name, pin):
    """Attempt to pair with the device using bluetoothctl on Linux"""
    try:
        print(f"Attempting to pair with {name} using PIN {pin} on Linux...", file=sys.stderr, flush=True)
        print(f"Make sure {name} is in pairing mode and displaying the PIN code.", file=sys.stderr, flush=True)
        
        # Remove any existing pairing
        subprocess.run(['bluetoothctl', 'remove', address], 
                      capture_output=True, timeout=5)
        await asyncio.sleep(1)
        
        # Use bluetoothctl with expect-style interaction
        import pexpect
        
        print("Starting bluetoothctl pairing process...", file=sys.stderr, flush=True)
        
        child = pexpect.spawn('bluetoothctl', encoding='utf-8', timeout=30)
        child.logfile = sys.stderr
        
        # Set up agent
        child.sendline('agent on')
        child.expect('Agent registered')
        child.sendline('default-agent')
        
        # First, try to scan and discover the device
        print("Scanning for device...", file=sys.stderr, flush=True)
        child.sendline('scan on')
        child.expect('Discovery started')
        
        # Wait a bit for discovery
        await asyncio.sleep(3)
        
        # Check if device is available
        child.sendline(f'info {address}')
        try:
            child.expect(['Device', 'not available'], timeout=5)
            if 'not available' in child.before + child.after:
                print("Device not available, trying to connect anyway...", file=sys.stderr, flush=True)
        except pexpect.TIMEOUT:
            print("Device info check timed out, proceeding with pairing...", file=sys.stderr, flush=True)
        
        # Stop scanning
        child.sendline('scan off')
        child.expect('Discovery stopped')
        
        # Initiate pairing
        print(f"Initiating pairing with {address}...", file=sys.stderr, flush=True)
        child.sendline(f'pair {address}')
        
        # Wait for PIN/passkey request or confirmation
        index = child.expect([
            'Enter PIN code:',
            'Enter passkey',
            r'Confirm passkey.*\(yes/no\)',
            'Pairing successful',
            'Failed to pair',
            'not available',
            'not found',
            pexpect.TIMEOUT
        ])
        
        if index == 0:  # PIN entry
            print(f"Device is requesting PIN entry. Entering PIN {pin}...", file=sys.stderr, flush=True)
            child.sendline(pin)
            # Wait for result after entering PIN
            result_index = child.expect(['Pairing successful', 'Failed to pair', 'Authentication Failed'], timeout=15)
            if result_index == 0:
                print("PIN accepted, pairing successful!", file=sys.stderr, flush=True)
            elif result_index == 1:
                print("Pairing failed after PIN entry", file=sys.stderr, flush=True)
                child.close()
                print(json.dumps({
                    "status": "pairing_failed",
                    "message": "Pairing failed after PIN entry - PIN may be incorrect"
                }), flush=True)
                return False
            else:  # Authentication Failed
                print("Authentication failed - PIN was incorrect", file=sys.stderr, flush=True)
                child.close()
                print(json.dumps({
                    "status": "pairing_failed",
                    "message": "Authentication failed - PIN was incorrect"
                }), flush=True)
                return False
            
        elif index == 1:  # Passkey entry
            print(f"Device is requesting passkey entry. Entering passkey {pin}...", file=sys.stderr, flush=True)
            child.sendline(pin)
            # Wait for result after entering passkey
            result_index = child.expect(['Pairing successful', 'Failed to pair', 'Authentication Failed'], timeout=15)
            if result_index == 0:
                print("Passkey accepted, pairing successful!", file=sys.stderr, flush=True)
            elif result_index == 1:
                print("Pairing failed after passkey entry", file=sys.stderr, flush=True)
                child.close()
                print(json.dumps({
                    "status": "pairing_failed",
                    "message": "Pairing failed after passkey entry - passkey may be incorrect"
                }), flush=True)
                return False
            else:  # Authentication Failed
                print("Authentication failed - passkey was incorrect", file=sys.stderr, flush=True)
                child.close()
                print(json.dumps({
                    "status": "pairing_failed",
                    "message": "Authentication failed - passkey was incorrect"
                }), flush=True)
                return False
            
        elif index == 2:  # Passkey confirmation
            print(f"Device is requesting passkey confirmation. Confirming...", file=sys.stderr, flush=True)
            child.sendline('yes')
            result_index = child.expect(['Pairing successful', 'Failed to pair'], timeout=10)
            if result_index == 0:
                print("Passkey confirmed, pairing successful!", file=sys.stderr, flush=True)
            else:
                print("Pairing failed after passkey confirmation", file=sys.stderr, flush=True)
                child.close()
                print(json.dumps({
                    "status": "pairing_failed",
                    "message": "Pairing failed after passkey confirmation"
                }), flush=True)
                return False
            
        elif index == 3:  # Already successful
            print("Pairing was already successful!", file=sys.stderr, flush=True)
            pass
            
        elif index in [4, 5, 6]:  # Failed, not available, or not found
            print(f"Device pairing failed: {child.after}", file=sys.stderr, flush=True)
            child.close()
            print(json.dumps({
                "status": "pairing_failed",
                "message": f"Device not available or not in pairing mode. Make sure {name} is in pairing mode and nearby."
            }), flush=True)
            return False
            
        else:  # Timeout
            print("Pairing timed out", file=sys.stderr, flush=True)
            child.close()
            print(json.dumps({
                "status": "pairing_failed",
                "message": "Pairing timed out - device may not be in pairing mode"
            }), flush=True)
            return False
        
        # Trust the device
        child.sendline(f'trust {address}')
        child.expect('trust succeeded')
        
        child.sendline('quit')
        child.close()
        
        print("Pairing successful via bluetoothctl!", file=sys.stderr, flush=True)
        
        # Now verify with meshcore (without PIN)
        await asyncio.sleep(2)
        return await verify_paired_connection(address, name)
        
    except Exception as e:
        print(f"Pairing failed: {e}", file=sys.stderr, flush=True)
        print(json.dumps({
            "status": "pairing_failed",
            "message": str(e)
        }), flush=True)
        return False

async def attempt_pairing_meshcore(address, name, pin):
    """Attempt to pair with the device using meshcore (macOS/Windows)"""
    meshcore = None
    try:
        print(f"Attempting to pair with {name} using PIN {pin} via meshcore...", file=sys.stderr, flush=True)
        
        # First, try to remove any existing pairing to start fresh
        try:
            print("Removing any existing pairing...", file=sys.stderr, flush=True)
            result = subprocess.run(
                ['bluetoothctl', 'remove', address], 
                capture_output=True, 
                timeout=5,
                text=True
            )
            if result.returncode == 0:
                print(f"Existing pairing removed", file=sys.stderr, flush=True)
            await asyncio.sleep(1)
        except FileNotFoundError:
            print("bluetoothctl not found, skipping unpair step", file=sys.stderr, flush=True)
        except Exception as e:
            print(f"Could not remove existing pairing (this is OK): {e}", file=sys.stderr, flush=True)
        
        # Connect with PIN
        print(f"Connecting with PIN...", file=sys.stderr, flush=True)
        meshcore = await asyncio.wait_for(
            MeshCore.create_ble(address=address, pin=pin, debug=True), 
            timeout=60.0
        )
        
        print("BLE connection with PIN established successfully!", file=sys.stderr, flush=True)
        
        # If we get here, pairing succeeded
        await meshcore.disconnect()
        
        # Wait a moment for disconnection
        await asyncio.sleep(2)
        
        # Additional safety: Force disconnect on Linux using bluetoothctl if available
        if is_linux():
            try:
                print("Ensuring device is fully disconnected...", file=sys.stderr, flush=True)
                subprocess.run([
                    "bluetoothctl", "disconnect", address
                ], capture_output=True, timeout=10)
                await asyncio.sleep(1)
            except (FileNotFoundError, subprocess.TimeoutExpired, Exception) as e:
                print(f"Could not force disconnect via bluetoothctl (this is OK): {e}", file=sys.stderr, flush=True)
        
        # Try reconnecting without PIN to confirm pairing persisted
        print("Verifying pairing persisted by reconnecting without PIN...", file=sys.stderr, flush=True)
        try:
            meshcore_verify = await asyncio.wait_for(
                MeshCore.create_ble(address=address, debug=False), 
                timeout=25.0
            )
            
            print("Verification connection successful", file=sys.stderr, flush=True)
            await meshcore_verify.disconnect()
            
            # Additional safety: Force disconnect on Linux using bluetoothctl if available
            if is_linux():
                try:
                    print("Ensuring verification device is fully disconnected...", file=sys.stderr, flush=True)
                    subprocess.run([
                        "bluetoothctl", "disconnect", address
                    ], capture_output=True, timeout=10)
                    await asyncio.sleep(1)
                except (FileNotFoundError, subprocess.TimeoutExpired, Exception) as e:
                    print(f"Could not force disconnect verification device via bluetoothctl (this is OK): {e}", file=sys.stderr, flush=True)
            
            print("Pairing verification successful!", file=sys.stderr, flush=True)
            print(json.dumps({
                "status": "paired", 
                "message": "Pairing and connection verification successful"
            }), flush=True)
            
            # Final safety: Ensure device is completely disconnected before returning
            if is_linux():
                try:
                    print("Final disconnect to ensure device is ready for packet capture...", file=sys.stderr, flush=True)
                    subprocess.run([
                        "bluetoothctl", "disconnect", address
                    ], capture_output=True, timeout=10)
                    await asyncio.sleep(1)
                except (FileNotFoundError, subprocess.TimeoutExpired, Exception) as e:
                    print(f"Could not perform final disconnect via bluetoothctl (this is OK): {e}", file=sys.stderr, flush=True)
            
            return True
            
        except EOFError:
            # Even verification failed with EOF - but initial pairing worked
            print("Verification disconnected immediately, but pairing may have succeeded", file=sys.stderr, flush=True)
            print(json.dumps({
                "status": "paired", 
                "message": "Pairing completed but verification unclear - try using the device"
            }), flush=True)
            
            # Final safety: Ensure device is completely disconnected before returning
            if is_linux():
                try:
                    print("Final disconnect to ensure device is ready for packet capture...", file=sys.stderr, flush=True)
                    subprocess.run([
                        "bluetoothctl", "disconnect", address
                    ], capture_output=True, timeout=10)
                    await asyncio.sleep(1)
                except (FileNotFoundError, subprocess.TimeoutExpired, Exception) as e:
                    print(f"Could not perform final disconnect via bluetoothctl (this is OK): {e}", file=sys.stderr, flush=True)
            
            return True
            
        except Exception as verify_e:
            print(f"Reconnection test failed: {verify_e}", file=sys.stderr, flush=True)
            print("Pairing may have succeeded but verification failed", file=sys.stderr, flush=True)
            print(json.dumps({
                "status": "paired", 
                "message": "Pairing successful but verification failed - device should work"
            }), flush=True)
            
            # Final safety: Ensure device is completely disconnected before returning
            if is_linux():
                try:
                    print("Final disconnect to ensure device is ready for packet capture...", file=sys.stderr, flush=True)
                    subprocess.run([
                        "bluetoothctl", "disconnect", address
                    ], capture_output=True, timeout=10)
                    await asyncio.sleep(1)
                except (FileNotFoundError, subprocess.TimeoutExpired, Exception) as e:
                    print(f"Could not perform final disconnect via bluetoothctl (this is OK): {e}", file=sys.stderr, flush=True)
            
            return True  # Still consider success since initial pairing worked
        
    except asyncio.TimeoutError:
        print("Pairing connection timed out", file=sys.stderr, flush=True)
        print(json.dumps({
            "status": "pairing_failed", 
            "message": "Pairing timed out - device may not be in pairing mode or PIN may be incorrect"
        }), flush=True)
        return False
        
    except EOFError as e:
        print("Connection dropped during pairing - authentication likely failed", file=sys.stderr, flush=True)
        print(json.dumps({
            "status": "pairing_failed", 
            "message": "Pairing failed - PIN may be incorrect or expired"
        }), flush=True)
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
        elif "timeout" in error_msg.lower():
            print(json.dumps({
                "status": "pairing_failed", 
                "message": "Pairing timed out - device may be busy or not responding to pairing request"
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

async def verify_paired_connection(address, name):
    """Verify the device is paired by connecting without PIN"""
    meshcore = None
    try:
        print("Verifying pairing by connecting without PIN...", file=sys.stderr, flush=True)
        meshcore = await asyncio.wait_for(
            MeshCore.create_ble(address=address, debug=False), 
            timeout=25.0
        )
        
        print("Verification connection successful!", file=sys.stderr, flush=True)
        await meshcore.disconnect()
        
        print(json.dumps({
            "status": "paired",
            "message": "Pairing and verification successful"
        }), flush=True)
        return True
        
    except Exception as e:
        print(f"Verification failed: {e}", file=sys.stderr, flush=True)
        print(json.dumps({
            "status": "paired",
            "message": "Pairing succeeded but verification unclear - device should work"
        }), flush=True)
        return True  # Still consider it success since bluetoothctl pairing worked
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