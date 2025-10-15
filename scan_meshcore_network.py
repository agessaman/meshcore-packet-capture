#!/usr/bin/env python3
"""
MeshCore Network Scanner

Scans the local network for MeshCore nodes by testing TCP connections
on port 5000 and attempting to connect to each discovered host.

Usage:
    python scan_meshcore_network.py [network] [port]
    python scan_meshcore_network.py                    # Scan 192.168.1.0/24
    python scan_meshcore_network.py 192.168.50.0/24    # Scan specific network
    python scan_meshcore_network.py 192.168.1.0/24 5000 # Scan with custom port
"""

import asyncio
import sys
import ipaddress
import socket
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import subprocess

# Import meshcore from PyPI
import meshcore
from meshcore import EventType

class MeshCoreNetworkScanner:
    def __init__(self, network: str = "192.168.1.0/24", port: int = 5000, timeout: float = 2.0):
        self.network = network
        self.port = port
        self.timeout = timeout
        self.found_nodes = []
        
    def get_local_network(self):
        """Try to detect the local network automatically"""
        try:
            # Get default gateway and infer network
            result = subprocess.run(['route', '-n', 'get', 'default'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'gateway:' in line:
                        gateway = line.split(':')[1].strip()
                        # Convert gateway to network (assume /24)
                        ip = ipaddress.IPv4Address(gateway)
                        network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                        return str(network)
        except:
            pass
        
        # Fallback to common networks
        return "192.168.1.0/24"
    
    def scan_port(self, host: str) -> bool:
        """Check if port is open on host (synchronous)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, self.port))
            sock.close()
            return result == 0
        except:
            return False
    
    async def test_meshcore_node(self, host: str) -> dict:
        """Test if a host is a real MeshCore node"""
        try:
            meshcore_client = await asyncio.wait_for(
                meshcore.MeshCore.create_tcp(host, self.port, debug=False),
                timeout=5.0
            )
            
            if meshcore_client.is_connected:
                device_info = meshcore_client.self_info or {}
                
                # Test device responsiveness
                try:
                    result = await asyncio.wait_for(
                        meshcore_client.commands.send_device_query(),
                        timeout=3.0
                    )
                    responsive = result and hasattr(result, 'type') and result.type != EventType.ERROR
                except:
                    responsive = False
                
                await meshcore_client.disconnect()
                
                return {
                    'host': host,
                    'port': self.port,
                    'is_meshcore': True,
                    'device_info': device_info,
                    'responsive': responsive,
                    'name': device_info.get('name', 'Unknown'),
                    'public_key': device_info.get('public_key', 'Unknown')
                }
            else:
                return {'host': host, 'port': self.port, 'is_meshcore': False}
                
        except asyncio.TimeoutError:
            return {'host': host, 'port': self.port, 'is_meshcore': False, 'error': 'timeout'}
        except Exception as e:
            return {'host': host, 'port': self.port, 'is_meshcore': False, 'error': str(e)}
    
    async def scan_network(self):
        """Scan the network for MeshCore nodes"""
        print(f"🔍 Scanning network: {self.network}")
        print(f"🎯 Target port: {self.port}")
        print(f"⏱️  Timeout: {self.timeout}s per host")
        print("=" * 60)
        
        # Generate list of IPs to scan
        try:
            network = ipaddress.IPv4Network(self.network, strict=False)
            hosts = [str(ip) for ip in network.hosts()]
        except ValueError as e:
            print(f"❌ Invalid network: {e}")
            return []
        
        print(f"📡 Scanning {len(hosts)} hosts...")
        print()
        
        # First pass: Quick port scan to find open ports
        print("🔍 Phase 1: Port scanning...")
        open_hosts = []
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(self.scan_port, host) for host in hosts]
            
            for i, future in enumerate(futures):
                host = hosts[i]
                if future.result():
                    open_hosts.append(host)
                    print(f"  ✅ {host}:{self.port} - Port open")
        
        if not open_hosts:
            print("❌ No open ports found")
            return []
        
        print(f"\n🔍 Phase 2: Testing {len(open_hosts)} hosts for MeshCore nodes...")
        print()
        
        # Second pass: Test each open host for MeshCore
        meshcore_nodes = []
        
        for host in open_hosts:
            print(f"🧪 Testing {host}:{self.port}...", end=" ")
            result = await self.test_meshcore_node(host)
            
            if result.get('is_meshcore'):
                meshcore_nodes.append(result)
                name = result.get('name', 'Unknown')
                responsive = "✅" if result.get('responsive') else "⚠️"
                print(f"✅ MeshCore node found! {responsive} {name}")
            else:
                error = result.get('error', 'not meshcore')
                print(f"❌ {error}")
        
        return meshcore_nodes
    
    def print_results(self, nodes):
        """Print scan results"""
        print("\n" + "=" * 60)
        print("📊 SCAN RESULTS")
        print("=" * 60)
        
        if not nodes:
            print("❌ No MeshCore nodes found on the network")
            return
        
        print(f"🎉 Found {len(nodes)} MeshCore node(s):")
        print()
        
        for i, node in enumerate(nodes, 1):
            print(f"📡 Node {i}: {node['host']}:{node['port']}")
            print(f"   Name: {node.get('name', 'Unknown')}")
            print(f"   Public Key: {node.get('public_key', 'Unknown')[:16]}...")
            print(f"   Responsive: {'✅ Yes' if node.get('responsive') else '⚠️ No'}")
            
            device_info = node.get('device_info', {})
            if device_info:
                print(f"   Device Info:")
                for key, value in device_info.items():
                    if key not in ['name', 'public_key']:
                        print(f"     {key}: {value}")
            print()

async def main():
    """Main scanner function"""
    # Parse command line arguments
    network = "192.168.1.0/24"  # Default
    port = 5000  # Default MeshCore port
    
    if len(sys.argv) > 1:
        network = sys.argv[1]
    if len(sys.argv) > 2:
        port = int(sys.argv[2])
    
    # Auto-detect network if not specified
    if network == "192.168.1.0/24" and len(sys.argv) == 1:
        scanner = MeshCoreNetworkScanner()
        detected_network = scanner.get_local_network()
        if detected_network != "192.168.1.0/24":
            print(f"🔍 Auto-detected network: {detected_network}")
            network = detected_network
    
    print(f"MeshCore Network Scanner")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Create scanner and run
    scanner = MeshCoreNetworkScanner(network, port)
    nodes = await scanner.scan_network()
    scanner.print_results(nodes)
    
    return len(nodes)

if __name__ == "__main__":
    try:
        node_count = asyncio.run(main())
        sys.exit(0 if node_count > 0 else 1)
    except KeyboardInterrupt:
        print("\n\n⏹️  Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Scanner error: {e}")
        sys.exit(1)
