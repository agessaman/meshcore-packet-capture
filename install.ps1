# ============================================================================
# MeshCore Packet Capture - Interactive Installer for Windows
# ============================================================================

param(
    [string]$ConfigUrl = "",
    [string]$Repo = "agessaman/meshcore-packet-capture",
    [string]$Branch = "main"
)

# Script configuration
$ScriptVersion = "1.0.0"
$ErrorActionPreference = "Stop"

# Global variables
$InstallDir = ""
$ConnectionType = ""
$SelectedBleDevice = ""
$SelectedBleName = ""
$SelectedSerialDevice = ""
$TcpHost = ""
$TcpPort = ""
$Iata = ""
$DecoderAvailable = $false
$ServiceInstalled = $false
$DockerInstalled = $false
$UpdatingExisting = $false

# Helper functions for colored output
function Write-Header {
    param([string]$Message)
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Blue
    Write-Host "  $Message" -ForegroundColor Blue
    Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Blue
    Write-Host ""
}

function Write-Success {
    param([string]$Message)
    Write-Host "✓ $Message" -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "✗ $Message" -ForegroundColor Red
}

function Write-Warning {
    param([string]$Message)
    Write-Host "⚠ $Message" -ForegroundColor Yellow
}

function Write-Info {
    param([string]$Message)
    Write-Host "ℹ $Message" -ForegroundColor Blue
}

# Detect available serial devices on Windows
function Get-SerialDevices {
    $devices = @()
    
    try {
        # Get COM ports from WMI
        $comPorts = Get-WmiObject -Class Win32_SerialPort | Where-Object { $_.DeviceID -like "COM*" }
        
        foreach ($port in $comPorts) {
            $devices += $port.DeviceID
        }
        
        # Also check for USB serial adapters
        $usbDevices = Get-WmiObject -Class Win32_PnPEntity | Where-Object { 
            $_.Name -like "*USB Serial*" -or 
            $_.Name -like "*USB-to-Serial*" -or
            $_.Name -like "*FTDI*" -or
            $_.Name -like "*Prolific*" -or
            $_.Name -like "*Silicon Labs*"
        }
        
        foreach ($device in $usbDevices) {
            if ($device.PNPDeviceID -match "COM\d+") {
                $comMatch = [regex]::Match($device.PNPDeviceID, "COM\d+")
                if ($comMatch.Success) {
                    $comPort = $comMatch.Value
                    if ($devices -notcontains $comPort) {
                        $devices += $comPort
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Failed to detect serial devices: $($_.Exception.Message)"
    }
    
    return $devices | Sort-Object
}

# Scan for BLE devices using PowerShell
function Get-BleDevices {
    Write-Info "Scanning for BLE devices..."
    Write-Host "This may take 10-15 seconds..."
    Write-Host ""
    
    # Check if Python and meshcore are available
    try {
        $pythonVersion = python --version 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Python not found - cannot scan for BLE devices"
            return $null
        }
        
        # Check if meshcore and bleak are available
        $importTest = python -c "import meshcore, bleak" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "meshcore or bleak not available - cannot scan for BLE devices"
            Write-Info "BLE scanning requires the meshcore library and its dependencies"
            Write-Info "These will be installed after the main installation completes"
            return $null
        }
    }
    catch {
        Write-Warning "Python not available - cannot scan for BLE devices"
        return $null
    }
    
    # Create a temporary BLE scan helper script
    $tempScript = Join-Path $env:TEMP "ble_scan_helper.py"
    
    $bleScanScript = @'
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
        print("Scanning for MeshCore BLE devices...", file=sys.stderr, flush=True)
        
        # Scan for all devices first, then filter
        devices = await BleakScanner.discover(timeout=10.0)
        
        # Filter to only MeshCore devices
        meshcore_devices = []
        for device in devices:
            if device.name:
                # Check for MeshCore-* or Meshcore-* devices
                if device.name.startswith("MeshCore-") or device.name.startswith("Meshcore-"):
                    meshcore_devices.append(device)
                # Also check for T1000 devices
                elif "T1000" in device.name:
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
        
        # Output as JSON for the installer to parse
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
'@
    
    try {
        Set-Content -Path $tempScript -Value $bleScanScript -Encoding UTF8
        
        # Run the BLE scan helper
        $scanOutput = python $tempScript 2>&1
        $scanResult = $LASTEXITCODE
        
        if ($scanResult -eq 0) {
            try {
                $devices = $scanOutput | ConvertFrom-Json
                
                if ($devices.Count -eq 0) {
                    Write-Warning "No MeshCore BLE devices found"
                    return $null
                }
                
                Write-Success "Found $($devices.Count) MeshCore BLE device(s):"
                Write-Host ""
                
                # Display devices
                for ($i = 0; $i -lt $devices.Count; $i++) {
                    $device = $devices[$i]
                    Write-Host "  $($i + 1)) $($device.name) ($($device.address))"
                }
                
                Write-Host "  $($devices.Count + 1)) Enter device manually"
                Write-Host "  0) Scan again"
                Write-Host ""
                
                while ($true) {
                    $choice = Read-Host "Select device [0-$($devices.Count + 1)]"
                    
                    if ($choice -match '^\d+$' -and [int]$choice -ge 0 -and [int]$choice -le ($devices.Count + 1)) {
                        if ([int]$choice -eq 0) {
                            # Rescan for devices
                            Write-Host ""
                            Write-Info "Rescanning for BLE devices..."
                            return Get-BleDevices
                        }
                        elseif ([int]$choice -eq ($devices.Count + 1)) {
                            # Manual entry
                            $manualMac = Read-Host "Enter BLE device MAC address"
                            $manualName = Read-Host "Enter device name (optional)"
                            if ($manualMac) {
                                return @{
                                    Address = $manualMac
                                    Name = $manualName
                                }
                            }
                        }
                        else {
                            # Selected from list
                            $deviceIndex = [int]$choice - 1
                            return @{
                                Address = $devices[$deviceIndex].address
                                Name = $devices[$deviceIndex].name
                            }
                        }
                    }
                    else {
                        Write-Error "Invalid choice. Please enter a number between 0 and $($devices.Count + 1)"
                    }
                }
            }
            catch {
                Write-Warning "Failed to parse BLE scan results: $($_.Exception.Message)"
                return $null
            }
        }
        else {
            Write-Warning "Failed to scan for BLE devices using meshcore library"
            Write-Info "Error details: $scanOutput"
            return $null
        }
    }
    finally {
        if (Test-Path $tempScript) {
            Remove-Item $tempScript -Force
        }
    }
}

# Check BLE pairing status and handle pairing if needed
function Test-BlePairing {
    param(
        [string]$DeviceAddress,
        [string]$DeviceName
    )
    
    Write-Host ""
    Write-Info "Checking BLE pairing status for $DeviceName ($DeviceAddress)..."
    
    if (-not $DeviceName -or -not $DeviceAddress) {
        Write-Error "Invalid device information: name='$DeviceName', address='$DeviceAddress'"
        return $false
    }
    
    # Use the actual ble_pairing_helper.py script
    $tempScript = Join-Path $InstallDir "ble_pairing_helper.py"
    
    if (-not (Test-Path $tempScript)) {
        Write-Error "BLE pairing helper script not found: $tempScript"
        return $false
    }
    
    try {
        # Check pairing status first
        $pairingOutput = python $tempScript $DeviceAddress $DeviceName 2>&1
        $pairingResult = $LASTEXITCODE
        
        if ($pairingResult -eq 0) {
            $pairingData = $pairingOutput | ConvertFrom-Json
            $pairingStatus = $pairingData.status
            
            if ($pairingStatus -eq "paired") {
                Write-Success "Device is paired and ready to use"
                return $true
            }
            elseif ($pairingStatus -eq "not_found") {
                Write-Warning "Device not found or not in range"
                Write-Info "Make sure your MeshCore device is:"
                Write-Info "  • Powered on and within range"
                Write-Info "  • In pairing mode (if not already paired)"
                Write-Info "  • Not connected to another device"
                return $false
            }
            elseif ($pairingStatus -eq "timeout") {
                Write-Warning "Connection timed out"
                Write-Info "The device may be busy or not responding. Please try again."
                Write-Info "If the device shows as connected, try disconnecting it first."
                return $false
            }
            elseif ($pairingStatus -eq "not_paired") {
                Write-Info "Device requires pairing. You'll need to enter the PIN displayed on your MeshCore device."
                Write-Host ""
                
                # Get PIN from user
                $pin = ""
                while ($true) {
                    $pin = Read-Host "Enter the 6-digit PIN displayed on your MeshCore device"
                    if ($pin -match '^\d{6}$') {
                        break
                    }
                    else {
                        Write-Error "Please enter a 6-digit PIN (numbers only)"
                    }
                }
                
                # Attempt pairing with PIN
                Write-Host ""
                Write-Info "Attempting to pair with device..."
                $pairingOutput = python $tempScript $DeviceAddress $DeviceName $pin 2>&1
                $pairingResult = $LASTEXITCODE
                
                if ($pairingResult -eq 0) {
                    $pairingData = $pairingOutput | ConvertFrom-Json
                    $pairingStatus = $pairingData.status
                    
                    if ($pairingStatus -eq "paired") {
                        Write-Success "BLE pairing successful! Device is now ready to use."
                        return $true
                    }
                    else {
                        Write-Error "BLE pairing failed"
                        return $false
                    }
                }
                else {
                    Write-Error "Failed to attempt BLE pairing"
                    Write-Info "Error details: $pairingOutput"
                    return $false
                }
            }
            else {
                Write-Error "Failed to check pairing status"
                return $false
            }
        }
        else {
            Write-Error "Failed to check BLE pairing status"
            Write-Info "Error details: $pairingOutput"
            return $false
        }
    }
    catch {
        Write-Error "Error during BLE pairing check: $($_.Exception.Message)"
        return $false
    }
}

# Select connection type and configure device
function Select-ConnectionType {
    Write-Host ""
    Write-Header "Device Connection Configuration"
    Write-Host ""
    Write-Info "How would you like to connect to your MeshCore device?"
    Write-Host ""
    Write-Host "  1) Bluetooth Low Energy (BLE) - Recommended for T1000 devices"
    Write-Host "     • Wireless connection"
    Write-Host "     • Works with MeshCore T1000e and compatible devices"
    Write-Host ""
    Write-Host "  2) Serial Connection - For devices with USB/serial interface"
    Write-Host "     • Direct USB or serial cable connection"
    Write-Host "     • More reliable for continuous operation"
    Write-Host ""
    Write-Host "  3) TCP Connection - For network-connected devices"
    Write-Host "     • Connect to your node over the network"
    Write-Host "     • Works with ser2net or other TCP-to-serial bridges"
    Write-Host ""
    
    while ($true) {
        $choice = Read-Host "Select connection type [1-3]"
        
        switch ($choice) {
            "1" {
                $script:ConnectionType = "ble"
                Write-Info "Selected: Bluetooth Low Energy (BLE)"
                Write-Host ""
                
                if (Read-Host "Would you like to scan for nearby BLE devices? (y/N)") -match '^[yY]' {
                    while ($true) {
                        $bleDevice = Get-BleDevices
                        if ($bleDevice) {
                            # Device selected, now handle pairing
                            if (Test-BlePairing $bleDevice.Address $bleDevice.Name) {
                                $script:SelectedBleDevice = $bleDevice.Address
                                $script:SelectedBleName = $bleDevice.Name
                                Write-Success "BLE device configured and paired: $($bleDevice.Name) ($($bleDevice.Address))"
                                break
                            }
                            else {
                                Write-Error "BLE pairing failed. Please try selecting a different device or check your device."
                                continue
                            }
                        }
                        else {
                            # Fallback to manual entry
                            Write-Info "BLE scanning failed or no devices found. Please enter device details manually."
                            $script:SelectedBleDevice = Read-Host "Enter BLE device MAC address"
                            $script:SelectedBleName = Read-Host "Enter device name (optional)"
                            if ($script:SelectedBleDevice) {
                                # Handle pairing for manually entered device
                                if (Test-BlePairing $script:SelectedBleDevice $script:SelectedBleName) {
                                    Write-Success "BLE device configured and paired: $($script:SelectedBleName) ($($script:SelectedBleDevice))"
                                    break
                                }
                                else {
                                    Write-Error "BLE pairing failed. Please check your device and try again."
                                    continue
                                }
                            }
                            else {
                                Write-Error "No BLE device configured"
                                continue
                            }
                        }
                    }
                }
                else {
                    # Manual entry without scanning
                    $script:SelectedBleDevice = Read-Host "Enter BLE device MAC address"
                    $script:SelectedBleName = Read-Host "Enter device name (optional)"
                    if ($script:SelectedBleDevice) {
                        # Handle pairing for manually entered device
                        if (Test-BlePairing $script:SelectedBleDevice $script:SelectedBleName) {
                            Write-Success "BLE device configured and paired: $($script:SelectedBleName) ($($script:SelectedBleDevice))"
                        }
                        else {
                            Write-Error "BLE pairing failed. Please check your device and try again."
                            continue
                        }
                    }
                    else {
                        Write-Error "No BLE device configured"
                        continue
                    }
                }
                break
            }
            "2" {
                $script:ConnectionType = "serial"
                Write-Info "Selected: Serial Connection"
                Write-Host ""
                Select-SerialDevice
                break
            }
            "3" {
                $script:ConnectionType = "tcp"
                Write-Info "Selected: TCP Connection"
                Write-Host ""
                Set-TcpConnection
                break
            }
            default {
                Write-Error "Invalid choice. Please enter 1, 2, or 3"
            }
        }
    }
}

# Interactive device selection for serial devices
function Select-SerialDevice {
    $devices = Get-SerialDevices
    
    Write-Host ""
    Write-Header "Serial Device Selection"
    Write-Host ""
    
    if ($devices.Count -eq 0) {
        Write-Warning "No serial devices detected"
        Write-Host ""
        Write-Host "  1) Enter path manually"
        Write-Host ""
        $choice = Read-Host "Select option [1]"
        $script:SelectedSerialDevice = Read-Host "Enter serial device path" "COM1"
        return
    }
    
    if ($devices.Count -eq 1) {
        Write-Info "Found 1 serial device:"
    }
    else {
        Write-Info "Found $($devices.Count) serial devices:"
    }
    Write-Host ""
    
    for ($i = 0; $i -lt $devices.Count; $i++) {
        Write-Host "  $($i + 1)) $($devices[$i])"
    }
    
    Write-Host "  $($devices.Count + 1)) Enter path manually"
    Write-Host ""
    
    while ($true) {
        $choice = Read-Host "Select device [1-$($devices.Count + 1)]"
        
        if ($choice -match '^\d+$' -and [int]$choice -ge 1 -and [int]$choice -le ($devices.Count + 1)) {
            if ([int]$choice -eq ($devices.Count + 1)) {
                # Manual entry
                $script:SelectedSerialDevice = Read-Host "Enter serial device path" "COM1"
                return
            }
            else {
                # Selected from list
                $script:SelectedSerialDevice = $devices[([int]$choice - 1)]
                return
            }
        }
        else {
            Write-Error "Invalid selection. Please enter a number between 1 and $($devices.Count + 1)"
        }
    }
}

# Configure TCP connection
function Set-TcpConnection {
    Write-Host ""
    Write-Header "TCP Connection Configuration"
    Write-Host ""
    Write-Info "TCP connections work with ser2net or other TCP-to-serial bridges"
    Write-Info "This allows you to access serial devices over the network"
    Write-Host ""
    
    $script:TcpHost = Read-Host "TCP host/address" "localhost"
    $script:TcpPort = Read-Host "TCP port" "5000"
    
    # Validate port number
    if (-not ($script:TcpPort -match '^\d+$') -or [int]$script:TcpPort -lt 1 -or [int]$script:TcpPort -gt 65535) {
        Write-Error "Invalid port number. Using default port 5000"
        $script:TcpPort = "5000"
    }
    
    Write-Success "TCP connection configured: $($script:TcpHost):$($script:TcpPort)"
    Write-Host ""
}

# Prompt for yes/no questions
function Read-YesNo {
    param(
        [string]$Prompt,
        [string]$Default = "n"
    )
    
    if ($Default -eq "y") {
        $promptText = "$Prompt [Y/n]: "
    }
    else {
        $promptText = "$Prompt [y/N]: "
    }
    
    $response = Read-Host $promptText
    if (-not $response) {
        $response = $Default
    }
    
    return $response -match '^[yY]'
}

# Configure MQTT topics for a broker
function Set-MqttTopics {
    param(
        [int]$BrokerNum
    )
    
    $envLocal = Join-Path $InstallDir ".env.local"
    
    Write-Host ""
    Write-Header "MQTT Topic Configuration for Broker $BrokerNum"
    Write-Host ""
    Write-Info "MQTT topics define where different types of data are published."
    Write-Info "You can use template variables: {IATA}, {IATA_lower}, {PUBLIC_KEY}"
    Write-Host ""
    
    # Topic options
    Write-Host "Choose topic configuration:"
    Write-Host "  1) Default pattern (meshcore/{IATA}/{PUBLIC_KEY}/status, meshcore/{IATA}/{PUBLIC_KEY}/packets)"
    Write-Host "  2) Classic pattern (meshcore/status, meshcore/packets, meshcore/raw)"
    Write-Host "  3) Custom topics (enter your own)"
    Write-Host ""
    
    $topicChoice = Read-Host "Select topic configuration [1-3]"
    
    switch ($topicChoice) {
        "1" {
            # Default pattern (IATA + PUBLIC_KEY)
            Add-Content -Path $envLocal -Value ""
            Add-Content -Path $envLocal -Value "# MQTT Topics for Broker $BrokerNum - Default Pattern"
            Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_TOPIC_STATUS=meshcore/{IATA}/{PUBLIC_KEY}/status"
            Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_TOPIC_PACKETS=meshcore/{IATA}/{PUBLIC_KEY}/packets"
            Write-Success "Default pattern topics configured"
        }
        "2" {
            # Classic pattern (simple meshcore topics, needed for map.w0z.is)
            Add-Content -Path $envLocal -Value ""
            Add-Content -Path $envLocal -Value "# MQTT Topics for Broker $BrokerNum - Classic Pattern"
            Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_TOPIC_STATUS=meshcore/status"
            Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_TOPIC_PACKETS=meshcore/packets"
            Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_TOPIC_RAW=meshcore/raw"
            Write-Success "Classic pattern topics configured"
        }
        "3" {
            # Custom topics
            Write-Host ""
            Write-Info "Enter custom topic paths (use {IATA}, {IATA_lower}, {PUBLIC_KEY} for templates)"
            Write-Info "You can also manually edit the .env.local file after installation to customize topics"
            Write-Host ""
            
            $statusTopic = Read-Host "Status topic" "meshcore/{IATA}/{PUBLIC_KEY}/status"
            $packetsTopic = Read-Host "Packets topic" "meshcore/{IATA}/{PUBLIC_KEY}/packets"
            
            Add-Content -Path $envLocal -Value ""
            Add-Content -Path $envLocal -Value "# MQTT Topics for Broker $BrokerNum - Custom"
            Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_TOPIC_STATUS=$statusTopic"
            Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_TOPIC_PACKETS=$packetsTopic"
            Write-Success "Custom topics configured"
        }
        default {
            Write-Error "Invalid choice, using default pattern"
            Add-Content -Path $envLocal -Value ""
            Add-Content -Path $envLocal -Value "# MQTT Topics for Broker $BrokerNum - Default Pattern"
            Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_TOPIC_STATUS=meshcore/{IATA}/{PUBLIC_KEY}/status"
            Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_TOPIC_PACKETS=meshcore/{IATA}/{PUBLIC_KEY}/packets"
        }
    }
}

# Configure MQTT brokers
function Set-MqttBrokers {
    $envLocal = Join-Path $InstallDir ".env.local"
    
    # Ensure .env.local exists with update source info
    if (-not (Test-Path $envLocal)) {
        # Interactive device selection
        Select-ConnectionType
        
        $configContent = @"
# MeshCore Packet Capture Configuration
# This file contains your local overrides to the defaults in .env

# Update source (configured by installer)
PACKETCAPTURE_UPDATE_REPO=$Repo
PACKETCAPTURE_UPDATE_BRANCH=$Branch

# Connection Configuration
PACKETCAPTURE_CONNECTION_TYPE=$ConnectionType
"@
        
        Set-Content -Path $envLocal -Value $configContent
        
        # Add device-specific configuration
        switch ($ConnectionType) {
            "ble" {
                Add-Content -Path $envLocal -Value "PACKETCAPTURE_BLE_DEVICE=$SelectedBleDevice"
                if ($SelectedBleName) {
                    Add-Content -Path $envLocal -Value "PACKETCAPTURE_BLE_NAME=$SelectedBleName"
                }
            }
            "serial" {
                Add-Content -Path $envLocal -Value "PACKETCAPTURE_SERIAL_PORTS=$SelectedSerialDevice"
            }
            "tcp" {
                Add-Content -Path $envLocal -Value "PACKETCAPTURE_TCP_HOST=$TcpHost"
                Add-Content -Path $envLocal -Value "PACKETCAPTURE_TCP_PORT=$TcpPort"
            }
        }
        
        Add-Content -Path $envLocal -Value ""
        Add-Content -Path $envLocal -Value "# Location Code"
        Add-Content -Path $envLocal -Value "PACKETCAPTURE_IATA=XXX"
        Add-Content -Path $envLocal -Value ""
        Add-Content -Path $envLocal -Value "# Advert Settings"
        Add-Content -Path $envLocal -Value "PACKETCAPTURE_ADVERT_INTERVAL_HOURS=11"
    }
    
    # Get IATA from existing config
    $iataLine = Get-Content $envLocal | Where-Object { $_ -match "^PACKETCAPTURE_IATA=" }
    if ($iataLine) {
        $script:Iata = ($iataLine -split "=", 2)[1]
    }
    
    # Always prompt for IATA if it's XXX or empty
    if (-not $script:Iata -or $script:Iata -eq "XXX") {
        Write-Host ""
        Write-Info "IATA code is a 3-letter airport code identifying your geographic region"
        Write-Info "Example: SEA (Seattle), LAX (Los Angeles), NYC (New York), LON (London)"
        Write-Host ""
        
        while (-not $script:Iata -or $script:Iata -eq "XXX") {
            $script:Iata = Read-Host "Enter your IATA code (3 letters)"
            $script:Iata = $script:Iata.ToUpper().Trim()
            
            if (-not $script:Iata) {
                Write-Error "IATA code cannot be empty"
            }
            elseif ($script:Iata -eq "XXX") {
                Write-Error "Please enter your actual IATA code, not XXX"
            }
            elseif ($script:Iata.Length -ne 3) {
                Write-Warning "IATA code should be 3 letters, you entered: $script:Iata"
                if (-not (Read-YesNo "Use '$script:Iata' anyway?" "n")) {
                    $script:Iata = "XXX"  # Reset to force re-prompt
                }
            }
        }
        
        # Update IATA in config
        $content = Get-Content $envLocal
        $content = $content -replace "^PACKETCAPTURE_IATA=.*", "PACKETCAPTURE_IATA=$script:Iata"
        Set-Content -Path $envLocal -Value $content
        Write-Host ""
        Write-Success "IATA code set to: $script:Iata"
        Write-Host ""
    }
    
    Write-Host ""
    Write-Header "MQTT Broker Configuration"
    Write-Host ""
    Write-Info "Enable the LetsMesh.net Packet Analyzer (mqtt-us-v1.letsmesh.net) broker?"
    Write-Host "  • Real-time packet analysis and visualization"
    Write-Host "  • Network health monitoring"
    Write-Host "  • Requires meshcore-decoder for authentication"
    Write-Host ""
    
    if ($DecoderAvailable) {
        if (Read-YesNo "Enable LetsMesh Packet Analyzer?" "y") {
            $letsMeshConfig = @"

# MQTT Broker 1 - LetsMesh.net Packet Analyzer
PACKETCAPTURE_MQTT1_ENABLED=true
PACKETCAPTURE_MQTT1_SERVER=mqtt-us-v1.letsmesh.net
PACKETCAPTURE_MQTT1_PORT=443
PACKETCAPTURE_MQTT1_TRANSPORT=websockets
PACKETCAPTURE_MQTT1_USE_TLS=true
PACKETCAPTURE_MQTT1_USE_AUTH_TOKEN=true
PACKETCAPTURE_MQTT1_TOKEN_AUDIENCE=mqtt-us-v1.letsmesh.net
"@
            Add-Content -Path $envLocal -Value $letsMeshConfig
            Write-Success "LetsMesh Packet Analyzer enabled"
            
            # Configure topics for LetsMesh
            Set-MqttTopics 1
            
            if (Read-YesNo "Would you like to configure additional MQTT brokers?" "n") {
                Set-AdditionalBrokers
            }
        }
        else {
            # User declined LetsMesh, ask if they want to configure a custom broker
            if (Read-YesNo "Would you like to configure a custom MQTT broker?" "y") {
                Set-CustomBroker 1
                
                if (Read-YesNo "Would you like to configure additional MQTT brokers?" "n") {
                    Set-AdditionalBrokers
                }
            }
            else {
                Write-Warning "No MQTT brokers configured - you'll need to edit .env.local manually"
            }
        }
    }
    else {
        # No decoder available, can't use LetsMesh
        Write-Warning "meshcore-decoder not available - cannot use LetsMesh auth token authentication"
        
        if (Read-YesNo "Would you like to configure a custom MQTT broker with username/password?" "y") {
            Set-CustomBroker 1
            
            if (Read-YesNo "Would you like to configure additional MQTT brokers?" "n") {
                Set-AdditionalBrokers
            }
        }
        else {
            Write-Warning "No MQTT brokers configured - you'll need to edit .env.local manually"
        }
    }
}

# Configure additional brokers (starting from MQTT2)
function Set-AdditionalBrokers {
    # Find next available broker number
    $nextBroker = 2
    $envLocal = Join-Path $InstallDir ".env.local"
    
    while ((Get-Content $envLocal -ErrorAction SilentlyContinue | Where-Object { $_ -match "^PACKETCAPTURE_MQTT${nextBroker}_ENABLED=" })) {
        $nextBroker++
    }
    
    $numAdditional = Read-Host "How many additional brokers?" "1"
    
    for ($i = 1; $i -le [int]$numAdditional; $i++) {
        $brokerNum = $nextBroker + $i - 1
        Set-CustomBroker $brokerNum
    }
}

# Configure a single custom MQTT broker
function Set-CustomBroker {
    param([int]$BrokerNum)
    
    $envLocal = Join-Path $InstallDir ".env.local"
    
    Write-Host ""
    Write-Header "Configuring MQTT Broker $BrokerNum"
    
    $server = Read-Host "Server hostname/IP"
    if (-not $server) {
        Write-Warning "Server hostname required - skipping broker $BrokerNum"
        return
    }
    
    Add-Content -Path $envLocal -Value ""
    Add-Content -Path $envLocal -Value "# MQTT Broker $BrokerNum"
    Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_ENABLED=true"
    Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_SERVER=$server"
    
    $port = Read-Host "Port" "1883"
    Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_PORT=$port"
    
    # Transport
    if (Read-YesNo "Use WebSockets transport?" "n") {
        Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_TRANSPORT=websockets"
    }
    
    # TLS
    if (Read-YesNo "Use TLS/SSL encryption?" "n") {
        Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_USE_TLS=true"
        
        if (-not (Read-YesNo "Verify TLS certificates?" "y")) {
            Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_TLS_VERIFY=false"
        }
    }
    
    # Authentication
    Write-Host ""
    Write-Info "Authentication method:"
    Write-Host "  1) Username/Password"
    Write-Host "  2) MeshCore Auth Token (requires meshcore-decoder)"
    Write-Host "  3) None (anonymous)"
    $authType = Read-Host "Choose authentication method [1-3]"
    
    if ($authType -eq "2") {
        if (-not $DecoderAvailable) {
            Write-Error "meshcore-decoder not available - using username/password instead"
            $authType = "1"
        }
        else {
            Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_USE_AUTH_TOKEN=true"
            $tokenAudience = Read-Host "Token audience (optional)"
            if ($tokenAudience) {
                Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_TOKEN_AUDIENCE=$tokenAudience"
            }
        }
    }
    
    if ($authType -eq "1") {
        $username = Read-Host "Username"
        if ($username) {
            Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_USERNAME=$username"
            $password = Read-Host "Password"
            if ($password) {
                Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_PASSWORD=$password"
            }
        }
    }
    
    Write-Success "Broker $BrokerNum configured"
    
    # Configure topics for this broker
    Set-MqttTopics $BrokerNum
}

# Check for old installations
function Test-OldInstallation {
    # Check for old Windows service
    $service = Get-Service -Name "meshcore-capture" -ErrorAction SilentlyContinue
    if ($service) {
        Write-Host ""
        Write-Warning "Old meshcore-capture Windows service detected"
        Write-Host ""
        
        if (Read-YesNo "Would you like to stop and remove the old service?" "y") {
            try {
                Stop-Service -Name "meshcore-capture" -Force -ErrorAction SilentlyContinue
                sc.exe delete "meshcore-capture" 2>$null
                Write-Success "Old service removed"
            }
            catch {
                Write-Error "Failed to remove old service - please remove manually"
            }
        }
        else {
            Write-Warning "Old service left in place - may conflict with new installation"
        }
        Write-Host ""
    }
}

# Install Windows service
function Install-WindowsService {
    Write-Info "Installing Windows service..."
    
    $serviceName = "meshcore-capture"
    $serviceDisplayName = "MeshCore Packet Capture"
    $serviceDescription = "MeshCore Packet Capture Service"
    
    # Build PATH with meshcore-decoder if available
    $servicePath = $env:PATH
    if ($script:DecoderAvailable) {
        try {
            $decoderPath = (Get-Command meshcore-decoder -ErrorAction SilentlyContinue).Source
            if ($decoderPath) {
                $decoderDir = Split-Path $decoderPath -Parent
                if ($decoderDir -and $servicePath -notlike "*$decoderDir*") {
                    $servicePath = "$decoderDir;$servicePath"
                    Write-Info "Added meshcore-decoder to service PATH: $decoderDir"
                }
            }
        }
        catch {
            Write-Warning "Could not determine meshcore-decoder path for service"
        }
    }
    
    # Create service using sc.exe with environment variables
    $scCommand = "sc.exe create `"$serviceName`" binPath= `"$InstallDir\venv\Scripts\python.exe $InstallDir\packet_capture.py`" start= auto DisplayName= `"$serviceDisplayName`""
    
    try {
        Invoke-Expression $scCommand
        
        # Set service description
        sc.exe description $serviceName $serviceDescription 2>$null
        
        # Set environment variables for the service
        if ($servicePath -ne $env:PATH) {
            Write-Info "Setting PATH environment variable for service..."
            sc.exe config $serviceName Environment= "PATH=$servicePath" 2>$null
        }
        
        Write-Success "Windows service installed"
        
        if (Read-YesNo "Start service now?" "y") {
            Start-Service -Name $serviceName
            Write-Success "Service started"
            
            # Wait a moment and check status
            Start-Sleep -Seconds 3
            $serviceStatus = Get-Service -Name $serviceName
            Write-Info "Service status: $($serviceStatus.Status)"
        }
        
        $script:ServiceInstalled = $true
    }
    catch {
        Write-Error "Failed to install Windows service: $($_.Exception.Message)"
        $script:ServiceInstalled = $false
    }
}

# Install Docker
function Install-Docker {
    Write-Info "Installing Docker configuration..."
    
    # Check if Docker is available
    try {
        $dockerVersion = docker --version 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Docker not found"
        }
    }
    catch {
        Write-Error "Docker is not installed or not available in PATH"
        Write-Info "Please install Docker Desktop: https://docs.docker.com/desktop/windows/"
        exit 1
    }
    
    # Check for Docker Compose
    try {
        $composeVersion = docker compose version 2>&1
        if ($LASTEXITCODE -eq 0) {
            $ComposeCmd = "docker compose"
        }
        else {
            $composeVersion = docker-compose --version 2>&1
            if ($LASTEXITCODE -eq 0) {
                $ComposeCmd = "docker-compose"
            }
            else {
                throw "Docker Compose not found"
            }
        }
    }
    catch {
        Write-Error "Docker Compose is not installed or not available in PATH"
        Write-Info "Install Docker Desktop: https://docs.docker.com/desktop/windows/"
        exit 1
    }
    
    Write-Success "Docker and Compose found ($ComposeCmd)"
    
    # Create Docker configuration files
    Write-Info "Creating Docker configuration..."
    
    # Create Dockerfile
    $dockerfileContent = @'
# Use Python 3.11 slim image for smaller size
FROM python:3.11-slim

# Install system dependencies for BLE and serial communication
RUN apt-get update && apt-get install -y \
    bluez \
    libbluetooth-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better Docker layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire project
COPY . .

# Create non-root user for security
RUN useradd -m -u 1000 meshcore && chown -R meshcore:meshcore /app
USER meshcore

# Create data directory for output files
RUN mkdir -p /app/data

# Set default environment variables
ENV PACKETCAPTURE_CONNECTION_TYPE=ble
ENV PACKETCAPTURE_TIMEOUT=30
ENV PACKETCAPTURE_MAX_CONNECTION_RETRIES=5
ENV PACKETCAPTURE_CONNECTION_RETRY_DELAY=5
ENV PACKETCAPTURE_HEALTH_CHECK_INTERVAL=30

# Default command
CMD ["python", "packet_capture.py"]
'@
    
    Set-Content -Path (Join-Path $InstallDir "Dockerfile") -Value $dockerfileContent
    
    # Create docker-compose.yml
    $composeContent = @"
version: '3.8'

services:
  meshcore-capture:
    build: .
    container_name: meshcore-packet-capture
    privileged: true  # Required for BLE access and device communication
    devices:
      # Mount serial devices (uncomment and modify as needed)
      - /dev/ttyUSB0:/dev/ttyUSB0
      - /dev/ttyUSB1:/dev/ttyUSB1
      - /dev/ttyACM0:/dev/ttyACM0
    volumes:
      # Persistent data storage
      - ./data:/app/data
      # Configuration files
      - ./.env.local:/app/.env.local:ro
    environment:
      # Connection settings
      - PACKETCAPTURE_CONNECTION_TYPE=ble
      - PACKETCAPTURE_TIMEOUT=30
      - PACKETCAPTURE_MAX_CONNECTION_RETRIES=5
      - PACKETCAPTURE_CONNECTION_RETRY_DELAY=5
      - PACKETCAPTURE_HEALTH_CHECK_INTERVAL=30
      
      # MQTT settings (configure as needed)
      - PACKETCAPTURE_MQTT1_ENABLED=true
      - PACKETCAPTURE_MQTT1_SERVER=localhost
      - PACKETCAPTURE_MQTT1_PORT=1883
      - PACKETCAPTURE_MQTT1_USERNAME=
      - PACKETCAPTURE_MQTT1_PASSWORD=
      - PACKETCAPTURE_MQTT1_USE_TLS=false
      
      # MQTT reconnection settings
      - PACKETCAPTURE_MAX_MQTT_RETRIES=5
      - PACKETCAPTURE_MQTT_RETRY_DELAY=5
      - PACKETCAPTURE_EXIT_ON_RECONNECT_FAIL=true
      
      # Topic settings
      - PACKETCAPTURE_TOPIC_STATUS=meshcore/status
      - PACKETCAPTURE_TOPIC_PACKETS=meshcore/packets
      - PACKETCAPTURE_TOPIC_RAW=meshcore/raw
      - PACKETCAPTURE_TOPIC_DECODED=meshcore/decoded
      - PACKETCAPTURE_TOPIC_DEBUG=meshcore/debug
      
      # Device settings
      - PACKETCAPTURE_IATA=LOC
      - PACKETCAPTURE_ORIGIN=PacketCapture Docker
      
      # Advert settings
      - PACKETCAPTURE_ADVERT_INTERVAL_HOURS=11
      
      # RF data settings
      - PACKETCAPTURE_RF_DATA_TIMEOUT=15.0
      
      # JWT token renewal settings
      - PACKETCAPTURE_JWT_RENEWAL_INTERVAL=3600
      - PACKETCAPTURE_JWT_RENEWAL_THRESHOLD=300
    networks:
      - meshcore-network
    restart: unless-stopped

networks:
  meshcore-network:
    driver: bridge
"@
    
    Set-Content -Path (Join-Path $InstallDir "docker-compose.yml") -Value $composeContent
    
    # Create .dockerignore
    $dockerignoreContent = @'
# Python cache files
__pycache__/
*.py[cod]
*$py.class
*.so

# Distribution / packaging
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual environments
venv/
env/
ENV/

# IDE files
.vscode/
.idea/
*.swp
*.swo
*~

# OS files
.DS_Store
Thumbs.db

# Git
.git/
.gitignore

# Docker
Dockerfile*
docker-compose*
.dockerignore

# Configuration files (use environment variables instead)
.env.local
config.ini

# Data and logs
data/
*.log
logs/

# Documentation
README.md
CLEANUP_SUMMARY.md

# Old files
old/
'@
    
    Set-Content -Path (Join-Path $InstallDir ".dockerignore") -Value $dockerignoreContent
    
    Write-Success "Docker configuration files created"
    
    # Build Docker image
    Write-Info "Building Docker image..."
    Set-Location $InstallDir
    if (docker build -t meshcore-capture .) {
        Write-Success "Docker image built successfully"
    }
    else {
        Write-Error "Failed to build Docker image"
        exit 1
    }
    
    # Ask if user wants to start the container
    if (Read-YesNo "Start the Docker container now?" "y") {
        Write-Info "Starting Docker container..."
        if (& $ComposeCmd up -d) {
            Write-Success "Docker container started"
            
            # Wait a moment and check logs
            Start-Sleep -Seconds 3
            Write-Info "Container logs:"
            & $ComposeCmd logs --tail=20
        }
        else {
            Write-Error "Failed to start Docker container"
            Write-Info "You can start it manually later with: $ComposeCmd up -d"
        }
    }
    
    $script:DockerInstalled = $true
    Write-Success "Docker installation complete"
}

# Main installation function
function Start-Installation {
    Write-Header "MeshCore Packet Capture Installer v$ScriptVersion"
    
    Write-Host "This installer will help you set up MeshCore Packet Capture."
    Write-Host ""
    
    # Check for old installations and offer to clean up
    Test-OldInstallation
    
    # Determine installation directory
    $defaultInstallDir = Join-Path $env:USERPROFILE ".meshcore-packet-capture"
    $script:InstallDir = Read-Host "Installation directory" $defaultInstallDir
    
    Write-Info "Installation directory: $InstallDir"
    
    # Check if directory exists
    if (Test-Path $InstallDir) {
        if (Read-YesNo "Directory already exists. Reinstall/update?" "n") {
            Write-Info "Updating existing installation..."
            $script:UpdatingExisting = $true
        }
        else {
            Write-Error "Installation cancelled."
            exit 1
        }
    }
    
    # Create installation directory
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Set-Location $InstallDir
    
    # Download or copy files
    Write-Header "Installing Files"
    
    if ($env:LOCAL_INSTALL) {
        # Local install for testing
        Write-Info "Installing from local directory: $env:LOCAL_INSTALL"
        Copy-Item "$env:LOCAL_INSTALL\packet_capture.py" $InstallDir\
        Copy-Item "$env:LOCAL_INSTALL\auth_token.py" $InstallDir\
        Copy-Item "$env:LOCAL_INSTALL\enums.py" $InstallDir\
        Copy-Item "$env:LOCAL_INSTALL\ble_pairing_helper.py" $InstallDir\
        Copy-Item "$env:LOCAL_INSTALL\requirements.txt" $InstallDir\
        if (Test-Path "$env:LOCAL_INSTALL\.env") {
            Copy-Item "$env:LOCAL_INSTALL\.env" $InstallDir\
        }
        if (Test-Path "$env:LOCAL_INSTALL\.env.local") {
            Write-Warning ".env.local found in source - copying as .env.local.example"
            Copy-Item "$env:LOCAL_INSTALL\.env.local" "$InstallDir\.env.local.example"
        }
        Write-Success "Files copied from local directory"
    }
    else {
        # Download from GitHub
        Write-Info "Downloading from GitHub ($Repo @ $Branch)..."
        
        $baseUrl = "https://raw.githubusercontent.com/$Repo/$Branch"
        
        # Download files
        $files = @("packet_capture.py", "auth_token.py", "enums.py", "ble_pairing_helper.py", "requirements.txt")
        
        foreach ($file in $files) {
            Write-Info "Downloading $file..."
            try {
                Invoke-WebRequest -Uri "$baseUrl/$file" -OutFile (Join-Path $InstallDir $file) -UseBasicParsing
            }
            catch {
                Write-Error "Failed to download $file from $Repo/$Branch"
                Write-Error "Please verify the repository and branch exist"
                exit 1
            }
        }
        
        # Verify Python syntax
        Write-Info "Verifying Python syntax..."
        try {
            python -m py_compile (Join-Path $InstallDir "packet_capture.py") 2>$null
            python -m py_compile (Join-Path $InstallDir "ble_pairing_helper.py") 2>$null
        }
        catch {
            Write-Error "Downloaded files have syntax errors"
            Write-Error "The repository may be in an inconsistent state"
            exit 1
        }
        
        Write-Success "Files downloaded and verified"
    }
    
    # Check Python
    Write-Header "Checking Dependencies"
    
    try {
        $pythonVersion = python --version 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Python not found"
        }
    }
    catch {
        Write-Error "Python 3 is not installed. Please install Python 3 and try again."
        exit 1
    }
    Write-Success "Python 3 found: $pythonVersion"
    
    # Set up virtual environment
    Write-Info "Setting up Python virtual environment..."
    if (-not (Test-Path (Join-Path $InstallDir "venv"))) {
        python -m venv (Join-Path $InstallDir "venv")
        Write-Success "Virtual environment created"
    }
    else {
        Write-Success "Using existing virtual environment"
    }
    
    # Install Python dependencies
    Write-Info "Installing Python dependencies..."
    & (Join-Path $InstallDir "venv\Scripts\Activate.ps1")
    & (Join-Path $InstallDir "venv\Scripts\pip.exe") install --quiet --upgrade pip
    & (Join-Path $InstallDir "venv\Scripts\pip.exe") install --quiet -r (Join-Path $InstallDir "requirements.txt")
    Write-Success "Python dependencies installed"
    
    # Check for meshcore-decoder (optional)
    try {
        $decoderVersion = meshcore-decoder --version 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Success "meshcore-decoder found: $decoderVersion"
            $script:DecoderAvailable = $true
        }
        else {
            throw "meshcore-decoder not found"
        }
    }
    catch {
        Write-Warning "meshcore-decoder not found (required for auth token authentication)"
        if (Read-YesNo "Would you like instructions to install it now?" "y") {
            Write-Host ""
            Write-Host "To install meshcore-decoder, run:"
            Write-Host "  # Install Node.js from https://nodejs.org/"
            Write-Host "  npm install -g @michaelhart/meshcore-decoder"
            Write-Host ""
            if (Read-YesNo "Continue without meshcore-decoder (you can install it later)?" "y") {
                $script:DecoderAvailable = $false
            }
            else {
                exit 1
            }
        }
        else {
            $script:DecoderAvailable = $false
        }
    }
    
    # Configuration
    Write-Header "Configuration"
    
    # Check for existing config.ini and offer migration
    if ((Test-Path (Join-Path $InstallDir "config.ini")) -and -not (Test-Path (Join-Path $InstallDir ".env.local"))) {
        Write-Info "Found existing config.ini file"
        if (Read-YesNo "Would you like to migrate your config.ini to the new .env.local format?" "y") {
            Write-Info "Migrating config.ini to .env.local..."
            if (python (Join-Path $InstallDir "migrate_config.py")) {
                Write-Success "Configuration migrated successfully"
                Write-Info "You can now remove config.ini if everything works correctly"
            }
            else {
                Write-Error "Migration failed, continuing with manual configuration"
            }
        }
    }
    
    # Check if config URL was provided
    if ($ConfigUrl) {
        Write-Info "Downloading configuration from: $ConfigUrl"
        try {
            Invoke-WebRequest -Uri $ConfigUrl -OutFile (Join-Path $InstallDir ".env.local") -UseBasicParsing
            Write-Success "Configuration downloaded successfully"
            
            # Convert MCTOMQTT_ prefixes to PACKETCAPTURE_ for compatibility
            $content = Get-Content (Join-Path $InstallDir ".env.local")
            if ($content -match "MCTOMQTT_") {
                Write-Info "Converting MCTOMQTT_ prefixes to PACKETCAPTURE_ for compatibility..."
                $content = $content -replace "^MCTOMQTT_", "PACKETCAPTURE_"
                Set-Content -Path (Join-Path $InstallDir ".env.local") -Value $content
                Write-Success "Configuration converted successfully"
            }
            
            # Show what was downloaded
            Write-Host ""
            Write-Info "Downloaded configuration:"
            Get-Content (Join-Path $InstallDir ".env.local") | Where-Object { $_ -notmatch '^#' -and $_ -ne '' } | Select-Object -First 20
            $lineCount = (Get-Content (Join-Path $InstallDir ".env.local") | Where-Object { $_ -notmatch '^#' -and $_ -ne '' }).Count
            if ($lineCount -gt 20) {
                Write-Host "..."
            }
            Write-Host ""
            
            if (Read-YesNo "Use this configuration?" "y") {
                Write-Success "Using downloaded configuration"
                
                # Always prompt for IATA
                Write-Host ""
                Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                Write-Warning "IATA CODE REQUIRED"
                Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                Write-Host ""
                Write-Info "IATA code is a 3-letter airport code and should match an airport near the reporting location"
                Write-Info "Example: SEA (Seattle), LAX (Los Angeles), NYC (New York), LON (London)"
                Write-Host ""
                
                # Try to extract existing IATA from config
                $existingIata = (Get-Content (Join-Path $InstallDir ".env.local") | Where-Object { $_ -match "^PACKETCAPTURE_IATA=" } | ForEach-Object { ($_ -split "=", 2)[1] })
                
                $script:Iata = ""
                while (-not $script:Iata -or $script:Iata -eq "XXX") {
                    if ($existingIata -and $existingIata -ne "XXX") {
                        $script:Iata = Read-Host "Enter your IATA code" $existingIata
                    }
                    else {
                        $script:Iata = Read-Host "Enter your IATA code (3 letters)"
                    }
                    $script:Iata = $script:Iata.ToUpper().Trim()
                    
                    if (-not $script:Iata) {
                        Write-Error "IATA code cannot be empty"
                    }
                    elseif ($script:Iata -eq "XXX") {
                        Write-Error "Please enter your actual IATA code, not XXX"
                    }
                    elseif ($script:Iata.Length -ne 3) {
                        Write-Warning "IATA code should be 3 letters, you entered: $script:Iata"
                        if (-not (Read-YesNo "Use '$script:Iata' anyway?" "n")) {
                            $script:Iata = ""
                        }
                    }
                }
                
                # Update IATA in config
                $content = Get-Content (Join-Path $InstallDir ".env.local")
                $content = $content -replace "^PACKETCAPTURE_IATA=.*", "PACKETCAPTURE_IATA=$script:Iata"
                Set-Content -Path (Join-Path $InstallDir ".env.local") -Value $content
                Write-Host ""
                Write-Success "IATA code set to: $script:Iata"
                Write-Host ""
                
                # Check if MQTT1 is already configured and offer additional brokers
                if ((Get-Content (Join-Path $InstallDir ".env.local") | Where-Object { $_ -match "^PACKETCAPTURE_MQTT1_ENABLED=true" })) {
                    $mqtt1Server = (Get-Content (Join-Path $InstallDir ".env.local") | Where-Object { $_ -match "^PACKETCAPTURE_MQTT1_SERVER=" } | ForEach-Object { ($_ -split "=", 2)[1] })
                    Write-Host ""
                    Write-Success "MQTT Broker 1 already configured: $mqtt1Server"
                    
                    if (Read-YesNo "Would you like to configure additional MQTT brokers?" "n") {
                        Set-AdditionalBrokers
                    }
                }
                else {
                    # No MQTT configured, offer options
                    Set-MqttBrokers
                }
            }
            else {
                Remove-Item (Join-Path $InstallDir ".env.local") -Force
                Set-MqttBrokers
            }
        }
        catch {
            Write-Error "Failed to download configuration from URL"
            if (Read-YesNo "Continue with interactive configuration?" "y") {
                Set-MqttBrokers
            }
            else {
                exit 1
            }
        }
    }
    elseif ($UpdatingExisting -and (Test-Path (Join-Path $InstallDir ".env.local"))) {
        if (Read-YesNo "Existing configuration found. Reconfigure?" "n") {
            # Back up existing config before reconfiguring
            Copy-Item (Join-Path $InstallDir ".env.local") (Join-Path $InstallDir ".env.local.backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')")
            Remove-Item (Join-Path $InstallDir ".env.local") -Force
            Set-MqttBrokers
        }
        else {
            Write-Info "Keeping existing configuration"
            # Check if MQTT brokers are already configured
            if ((Test-Path (Join-Path $InstallDir ".env.local")) -and (Get-Content (Join-Path $InstallDir ".env.local") | Where-Object { $_ -match "^PACKETCAPTURE_MQTT[1-4]_ENABLED=true" })) {
                Write-Info "MQTT brokers already configured - skipping MQTT configuration"
            }
            else {
                # Still need to configure MQTT brokers if not already configured
                Set-MqttBrokers
            }
        }
    }
    elseif (-not (Test-Path (Join-Path $InstallDir ".env.local"))) {
        Set-MqttBrokers
    }
    
    # Installation method selection
    Write-Header "Installation Method"
    
    Write-Host "Choose your preferred installation method:"
    Write-Host ""
    Write-Host "  1) Windows Service (recommended for production)"
    Write-Host "     • Runs automatically on boot"
    Write-Host "     • Managed by Windows Service Manager"
    Write-Host "     • Automatic restart on failure"
    Write-Host ""
    Write-Host "  2) Docker Container (recommended for development/testing)"
    Write-Host "     • Isolated environment"
    Write-Host "     • Easy to update and manage"
    Write-Host "     • Works on Windows with WSL2 or Docker Desktop"
    Write-Host ""
    Write-Host "  3) Manual installation only"
    Write-Host "     • No automatic startup"
    Write-Host "     • Run manually when needed"
    Write-Host ""
    
    $installMethod = Read-Host "Choose installation method [1-3]"
    
    switch ($installMethod) {
        "1" {
            Install-WindowsService
        }
        "2" {
            Install-Docker
        }
        "3" {
            Write-Info "Manual installation complete"
            if ($script:DecoderAvailable) {
                Write-Info "To run manually: cd $InstallDir && .\venv\Scripts\python.exe packet_capture.py"
                Write-Info "Note: meshcore-decoder is available in your PATH for JWT authentication"
            } else {
                Write-Info "To run manually: cd $InstallDir && .\venv\Scripts\python.exe packet_capture.py"
                Write-Warning "meshcore-decoder not found - JWT authentication will use Python fallback"
            }
        }
        default {
            Write-Error "Invalid selection"
            exit 1
        }
    }
    
    # Final summary
    Write-Header "Installation Complete!"
    Write-Host "Installation directory: $InstallDir"
    Write-Host ""
    Write-Host "Configuration file: $InstallDir\.env.local"
    Write-Host ""
    
    if ($ServiceInstalled) {
        Write-Host "Service management:"
        Write-Host "  Start:   Start-Service meshcore-capture"
        Write-Host "  Stop:    Stop-Service meshcore-capture"
        Write-Host "  Status:  Get-Service meshcore-capture"
        Write-Host "  Logs:    Get-EventLog -LogName Application -Source meshcore-capture"
    }
    elseif ($DockerInstalled) {
        Write-Host "Docker management:"
        Write-Host "  Start:   docker compose -f $InstallDir\docker-compose.yml up -d"
        Write-Host "  Stop:    docker compose -f $InstallDir\docker-compose.yml down"
        Write-Host "  Logs:    docker compose -f $InstallDir\docker-compose.yml logs -f"
        Write-Host "  Status:  docker compose -f $InstallDir\docker-compose.yml ps"
    }
    else {
        if ($script:DecoderAvailable) {
            Write-Host "Manual run: cd $InstallDir && .\venv\Scripts\python.exe packet_capture.py"
            Write-Host "Note: meshcore-decoder is available for JWT authentication"
        } else {
            Write-Host "Manual run: cd $InstallDir && .\venv\Scripts\python.exe packet_capture.py"
            Write-Host "Note: meshcore-decoder not found - JWT authentication will use Python fallback"
        }
    }
    
    Write-Host ""
    Write-Success "Installation complete!"
}

# Run main installation
Start-Installation
