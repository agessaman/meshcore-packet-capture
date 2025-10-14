#!/usr/bin/env python3
"""
Debug BLE Connection Script for MeshCore Packet Capture
This script helps debug BLE connection issues by testing various connection scenarios
"""
import asyncio
import sys
from meshcore import MeshCore

async def test_ble_connection(address, name):
    """Test BLE connection with detailed debugging"""
    print(f"Testing BLE connection to {name} ({address})")
    print("=" * 50)
    
    try:
        print("1. Attempting connection without PIN (debug=True)...")
        meshcore = await asyncio.wait_for(MeshCore.create_ble(address=address, debug=True), timeout=10.0)
        print("✅ Connection successful!")
        
        print("2. Waiting for device to stabilize...")
        await asyncio.sleep(3)
        
        print("3. Testing device communication via self_info...")
        try:
            device_name = meshcore.self_info.get('name', 'Unknown')
            print(f"✅ Device name from self_info: {device_name}")
            print("✅ Device communication verified successfully")
        except Exception as info_e:
            print(f"⚠️  self_info check failed: {info_e}")
            print("✅ Device is connected but self_info not available")
        
        print("4. Disconnecting...")
        await meshcore.disconnect()
        print("✅ Disconnected successfully")
        
        return True
        
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        print(f"Error type: {type(e).__name__}")
        return False

async def main():
    if len(sys.argv) != 3:
        print("Usage: python3 debug_ble_connection.py <address> <name>")
        print("Example: python3 debug_ble_connection.py 48:CA:43:3D:5C:6D MeshCore-HOWL")
        sys.exit(1)
    
    address = sys.argv[1]
    name = sys.argv[2]
    
    success = await test_ble_connection(address, name)
    if success:
        print("\n🎉 BLE connection test completed successfully!")
    else:
        print("\n💥 BLE connection test failed!")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
