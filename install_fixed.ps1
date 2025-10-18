# ============================================================================
# MeshCore Packet Capture - Interactive Installer for Windows (Fixed Version)
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

# Main installation function
function Start-Installation {
    Write-Host ""
    Write-Host "=======================================================" -ForegroundColor Blue
    Write-Host "  MeshCore Packet Capture Installer v$ScriptVersion" -ForegroundColor Blue
    Write-Host "=======================================================" -ForegroundColor Blue
    Write-Host ""
    
    Write-Host "This installer will help you set up MeshCore Packet Capture."
    Write-Host ""
    
    # Determine installation directory
    $defaultInstallDir = Join-Path $env:USERPROFILE ".meshcore-packet-capture"
    $script:InstallDir = Read-Host "Installation directory" $defaultInstallDir
    
    # Use default if empty
    if (-not $script:InstallDir) {
        $script:InstallDir = $defaultInstallDir
    }
    
    Write-Host "INFO: Installation directory: $InstallDir" -ForegroundColor Blue
    
    # Check if directory exists
    if (Test-Path $InstallDir) {
        $response = Read-Host "Directory already exists. Reinstall/update? (y/N)"
        if ($response -match '^[yY]') {
            Write-Host "INFO: Updating existing installation..." -ForegroundColor Blue
            $script:UpdatingExisting = $true
        }
        else {
            Write-Host "ERROR: Installation cancelled." -ForegroundColor Red
            exit 1
        }
    }
    
    # Create installation directory
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Set-Location $InstallDir
    
    Write-Host ""
    Write-Host "SUCCESS: Installation directory created" -ForegroundColor Green
    
    # Check Python
    Write-Host ""
    Write-Host "INFO: Checking Python installation..." -ForegroundColor Blue
    
    try {
        $pythonVersion = python --version 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Python not found"
        }
    }
    catch {
        Write-Host "ERROR: Python 3 is not installed. Please install Python 3 and try again." -ForegroundColor Red
        exit 1
    }
    Write-Host "SUCCESS: Python 3 found: $pythonVersion" -ForegroundColor Green
    
    # Download files first
    Write-Host ""
    Write-Host "INFO: Downloading application files..." -ForegroundColor Blue
    
    if ($env:LOCAL_INSTALL) {
        # Local install for testing
        Write-Host "INFO: Installing from local directory: $env:LOCAL_INSTALL" -ForegroundColor Blue
        Copy-Item "$env:LOCAL_INSTALL\packet_capture.py" $InstallDir\
        Copy-Item "$env:LOCAL_INSTALL\auth_token.py" $InstallDir\
        Copy-Item "$env:LOCAL_INSTALL\enums.py" $InstallDir\
        Copy-Item "$env:LOCAL_INSTALL\ble_pairing_helper.py" $InstallDir\
        Copy-Item "$env:LOCAL_INSTALL\requirements.txt" $InstallDir\
        if (Test-Path "$env:LOCAL_INSTALL\.env") {
            Copy-Item "$env:LOCAL_INSTALL\.env" $InstallDir\
        }
        Write-Host "SUCCESS: Files copied from local directory" -ForegroundColor Green
    }
    else {
        # Download from GitHub
        Write-Host "INFO: Downloading from GitHub ($Repo @ $Branch)..." -ForegroundColor Blue
        
        $baseUrl = "https://raw.githubusercontent.com/$Repo/$Branch"
        
        # Download files
        $files = @("packet_capture.py", "auth_token.py", "enums.py", "ble_pairing_helper.py", "ble_scan_helper.py", "requirements.txt")
        
        foreach ($file in $files) {
            Write-Host "INFO: Downloading $file..." -ForegroundColor Blue
            try {
                Invoke-WebRequest -Uri "$baseUrl/$file" -OutFile (Join-Path $InstallDir $file) -UseBasicParsing
            }
            catch {
                Write-Host "ERROR: Failed to download $file from $Repo/$Branch" -ForegroundColor Red
                Write-Host "ERROR: Please verify the repository and branch exist" -ForegroundColor Red
                exit 1
            }
        }
        
        Write-Host "SUCCESS: Files downloaded and verified" -ForegroundColor Green
    }
    
    # Set up virtual environment
    Write-Host ""
    Write-Host "INFO: Setting up Python virtual environment..." -ForegroundColor Blue
    if (-not (Test-Path (Join-Path $InstallDir "venv"))) {
        python -m venv (Join-Path $InstallDir "venv")
        Write-Host "SUCCESS: Virtual environment created" -ForegroundColor Green
    }
    else {
        Write-Host "SUCCESS: Using existing virtual environment" -ForegroundColor Green
    }
    
    # Install Python dependencies
    Write-Host "INFO: Installing Python dependencies..." -ForegroundColor Blue
    & (Join-Path $InstallDir "venv\Scripts\Activate.ps1")
    & (Join-Path $InstallDir "venv\Scripts\pip.exe") install --quiet --upgrade pip
    & (Join-Path $InstallDir "venv\Scripts\pip.exe") install --quiet -r (Join-Path $InstallDir "requirements.txt")
    Write-Host "SUCCESS: Python dependencies installed" -ForegroundColor Green
    
    # Configuration
    Write-Host ""
    Write-Host "INFO: Setting up configuration..." -ForegroundColor Blue
    
    # Connection Type Selection
    Write-Host ""
    Write-Host "INFO: Device Connection Configuration" -ForegroundColor Blue
    Write-Host "INFO: How would you like to connect to your MeshCore device?" -ForegroundColor Blue
    Write-Host ""
    Write-Host "  1) Serial Connection - For devices with USB/serial interface" -ForegroundColor Blue
    Write-Host "     - Direct USB or serial cable connection" -ForegroundColor Blue
    Write-Host "     - More reliable for continuous operation" -ForegroundColor Blue
    Write-Host ""
    Write-Host "  2) Bluetooth Low Energy (BLE) - For BLE-capable nodes" -ForegroundColor Blue
    Write-Host "     - Wireless connection" -ForegroundColor Blue
    Write-Host "     - Works with BLE-enabled MeshCore devices" -ForegroundColor Blue
    Write-Host ""
    Write-Host "  3) TCP Connection - For network-connected devices" -ForegroundColor Blue
    Write-Host "     - Connect to your node over the network" -ForegroundColor Blue
    Write-Host "     - Works with ser2net or other TCP-to-serial bridges" -ForegroundColor Blue
    Write-Host ""
    
    $connectionChoice = ""
    while ($connectionChoice -notmatch '^[1-3]$') {
        $connectionChoice = Read-Host "Select connection type [1-3]"
        if ($connectionChoice -notmatch '^[1-3]$') {
            Write-Host "ERROR: Invalid choice. Please enter 1, 2, or 3" -ForegroundColor Red
        }
    }
    
    $script:ConnectionType = ""
    $script:SelectedSerialDevice = ""
    $script:SelectedBleDevice = ""
    $script:SelectedBleName = ""
    $script:TcpHost = ""
    $script:TcpPort = ""
    
    switch ($connectionChoice) {
        "1" {
            $script:ConnectionType = "serial"
            Write-Host "SUCCESS: Selected Serial Connection" -ForegroundColor Green
            
            # Detect serial devices
            Write-Host ""
            Write-Host "INFO: Detecting serial devices..." -ForegroundColor Blue
            
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
                Write-Host "WARNING: Failed to detect serial devices: $($_.Exception.Message)" -ForegroundColor Yellow
            }
            
            if ($devices.Count -eq 0) {
                Write-Host "WARNING: No serial devices detected" -ForegroundColor Yellow
                $script:SelectedSerialDevice = Read-Host "Enter serial device path" "COM1"
            }
            elseif ($devices.Count -eq 1) {
                Write-Host "INFO: Found 1 serial device: $($devices[0])" -ForegroundColor Blue
                $script:SelectedSerialDevice = $devices[0]
            }
            else {
                Write-Host "INFO: Found $($devices.Count) serial devices:" -ForegroundColor Blue
                for ($i = 0; $i -lt $devices.Count; $i++) {
                    Write-Host "  $($i + 1)) $($devices[$i])" -ForegroundColor Blue
                }
                Write-Host "  $($devices.Count + 1)) Enter path manually" -ForegroundColor Blue
                Write-Host ""
                
                while ($true) {
                    $choice = Read-Host "Select device [1-$($devices.Count + 1)]"
                    if ($choice -match '^\d+$' -and [int]$choice -ge 1 -and [int]$choice -le ($devices.Count + 1)) {
                        if ([int]$choice -eq ($devices.Count + 1)) {
                            $script:SelectedSerialDevice = Read-Host "Enter serial device path" "COM1"
                        }
                        else {
                            $script:SelectedSerialDevice = $devices[([int]$choice - 1)]
                        }
                        break
                    }
                    else {
                        Write-Host "ERROR: Invalid selection. Please enter a number between 1 and $($devices.Count + 1)" -ForegroundColor Red
                    }
                }
            }
            Write-Host "SUCCESS: Serial device configured: $script:SelectedSerialDevice" -ForegroundColor Green
        }
        "2" {
            $script:ConnectionType = "ble"
            Write-Host "SUCCESS: Selected Bluetooth Low Energy (BLE)" -ForegroundColor Green
            
            # Scan for BLE devices
            Write-Host ""
            Write-Host "INFO: Scanning for BLE devices..." -ForegroundColor Blue
            
            try {
                # Run the BLE scan helper
                $bleScanScript = Join-Path $InstallDir "ble_scan_helper.py"
                $scanResult = & python $bleScanScript 2>&1
                
                if ($LASTEXITCODE -eq 0 -and $scanResult) {
                    # Parse JSON output
                    $devices = $scanResult | ConvertFrom-Json
                    
                    if ($devices.Count -gt 0) {
                        Write-Host "INFO: Found $($devices.Count) BLE device(s):" -ForegroundColor Blue
                        for ($i = 0; $i -lt $devices.Count; $i++) {
                            $device = $devices[$i]
                            Write-Host "  $($i + 1)) $($device.name) ($($device.address))" -ForegroundColor Blue
                        }
                        Write-Host "  $($devices.Count + 1)) Enter device manually" -ForegroundColor Blue
                        Write-Host ""
                        
                        while ($true) {
                            $choice = Read-Host "Select device [1-$($devices.Count + 1)]"
                            if ($choice -match '^\d+$' -and [int]$choice -ge 1 -and [int]$choice -le ($devices.Count + 1)) {
                                if ([int]$choice -eq ($devices.Count + 1)) {
                                    $script:SelectedBleDevice = Read-Host "Enter BLE device MAC address" ""
                                    $script:SelectedBleName = Read-Host "Enter device name (optional)" ""
                                }
                                else {
                                    $selectedDevice = $devices[([int]$choice - 1)]
                                    $script:SelectedBleDevice = $selectedDevice.address
                                    $script:SelectedBleName = $selectedDevice.name
                                }
                                break
                            }
                            else {
                                Write-Host "ERROR: Invalid selection. Please enter a number between 1 and $($devices.Count + 1)" -ForegroundColor Red
                            }
                        }
                    }
                    else {
                        Write-Host "WARNING: No BLE devices found" -ForegroundColor Yellow
                        $script:SelectedBleDevice = Read-Host "Enter BLE device MAC address" ""
                        $script:SelectedBleName = Read-Host "Enter device name (optional)" ""
                    }
                }
                else {
                    Write-Host "WARNING: BLE scanning failed, using manual entry" -ForegroundColor Yellow
                    $script:SelectedBleDevice = Read-Host "Enter BLE device MAC address" ""
                    $script:SelectedBleName = Read-Host "Enter device name (optional)" ""
                }
            }
            catch {
                Write-Host "WARNING: BLE scanning failed: $($_.Exception.Message)" -ForegroundColor Yellow
                $script:SelectedBleDevice = Read-Host "Enter BLE device MAC address" ""
                $script:SelectedBleName = Read-Host "Enter device name (optional)" ""
            }
            
            if ($script:SelectedBleDevice) {
                Write-Host "SUCCESS: BLE device configured: $script:SelectedBleName ($script:SelectedBleDevice)" -ForegroundColor Green
            }
            else {
                Write-Host "WARNING: No BLE device configured" -ForegroundColor Yellow
            }
        }
        "3" {
            $script:ConnectionType = "tcp"
            Write-Host "SUCCESS: Selected TCP Connection" -ForegroundColor Green
            $script:TcpHost = Read-Host "TCP host/address" "localhost"
            $script:TcpPort = Read-Host "TCP port" "5000"
            
            # Validate port number
            if (-not ($script:TcpPort -match '^\d+$') -or [int]$script:TcpPort -lt 1 -or [int]$script:TcpPort -gt 65535) {
                Write-Host "ERROR: Invalid port number. Using default port 5000" -ForegroundColor Red
                $script:TcpPort = "5000"
            }
            Write-Host "SUCCESS: TCP connection configured: $($script:TcpHost):$($script:TcpPort)" -ForegroundColor Green
        }
    }
    
    # Create basic .env.local file
    $envLocal = Join-Path $InstallDir ".env.local"
    $configContent = @"
# MeshCore Packet Capture Configuration
# This file contains your local overrides to the defaults in .env

# Update source (configured by installer)
PACKETCAPTURE_UPDATE_REPO=$Repo
PACKETCAPTURE_UPDATE_BRANCH=$Branch

# Connection Configuration
PACKETCAPTURE_CONNECTION_TYPE=$script:ConnectionType
"@
    
    # Add device-specific configuration
    switch ($script:ConnectionType) {
        "ble" {
            if ($script:SelectedBleDevice) {
                $configContent += "`nPACKETCAPTURE_BLE_DEVICE=$script:SelectedBleDevice"
            }
            if ($script:SelectedBleName) {
                $configContent += "`nPACKETCAPTURE_BLE_NAME=$script:SelectedBleName"
            }
        }
        "serial" {
            $configContent += "`nPACKETCAPTURE_SERIAL_PORTS=$script:SelectedSerialDevice"
        }
        "tcp" {
            $configContent += "`nPACKETCAPTURE_TCP_HOST=$script:TcpHost"
            $configContent += "`nPACKETCAPTURE_TCP_PORT=$script:TcpPort"
        }
    }
    
    $configContent += @"

# Location Code
PACKETCAPTURE_IATA=XXX

# Advert Settings
PACKETCAPTURE_ADVERT_INTERVAL_HOURS=11
"@
    
    Set-Content -Path $envLocal -Value $configContent
    
    # Configure IATA code
    Write-Host ""
    Write-Host "INFO: IATA code is a 3-letter airport code identifying your geographic region" -ForegroundColor Blue
    Write-Host "INFO: Example: SEA (Seattle), LAX (Los Angeles), NYC (New York), LON (London)" -ForegroundColor Blue
    Write-Host ""
    
    $script:Iata = ""
    while (-not $script:Iata -or $script:Iata -eq "XXX") {
        $script:Iata = Read-Host "Enter your IATA code (3 letters)"
        $script:Iata = $script:Iata.ToUpper().Trim()
        
        if (-not $script:Iata) {
            Write-Host "ERROR: IATA code cannot be empty" -ForegroundColor Red
        }
        elseif ($script:Iata -eq "XXX") {
            Write-Host "ERROR: Please enter your actual IATA code, not XXX" -ForegroundColor Red
        }
        elseif ($script:Iata.Length -ne 3) {
            Write-Host "WARNING: IATA code should be 3 letters, you entered: $script:Iata" -ForegroundColor Yellow
            $response = Read-Host "Use '$script:Iata' anyway? (y/N)"
            if ($response -notmatch '^[yY]') {
                $script:Iata = "XXX"  # Reset to force re-prompt
            }
        }
    }
    
    # Update IATA in config
    $content = Get-Content $envLocal
    $content = $content -replace "^PACKETCAPTURE_IATA=.*", "PACKETCAPTURE_IATA=$script:Iata"
    Set-Content -Path $envLocal -Value $content
    Write-Host "SUCCESS: IATA code set to: $script:Iata" -ForegroundColor Green
    
    # Configure MQTT brokers
    Write-Host ""
    Write-Host "INFO: MQTT Broker Configuration" -ForegroundColor Blue
    Write-Host "INFO: Enable the LetsMesh.net Packet Analyzer (mqtt-us-v1.letsmesh.net) broker?" -ForegroundColor Blue
    Write-Host "  • Real-time packet analysis and visualization" -ForegroundColor Blue
    Write-Host "  • Network health monitoring" -ForegroundColor Blue
    Write-Host "  • Requires meshcore-decoder for authentication" -ForegroundColor Blue
    Write-Host ""
    
    $response = Read-Host "Enable LetsMesh Packet Analyzer? (y/N)"
    if ($response -match '^[yY]') {
        $letsMeshConfig = @"

# MQTT Broker 1 - LetsMesh.net Packet Analyzer
PACKETCAPTURE_MQTT1_ENABLED=true
PACKETCAPTURE_MQTT1_SERVER=mqtt-us-v1.letsmesh.net
PACKETCAPTURE_MQTT1_PORT=443
PACKETCAPTURE_MQTT1_TRANSPORT=websockets
PACKETCAPTURE_MQTT1_USE_TLS=true
PACKETCAPTURE_MQTT1_USE_AUTH_TOKEN=true
PACKETCAPTURE_MQTT1_TOKEN_AUDIENCE=mqtt-us-v1.letsmesh.net
PACKETCAPTURE_MQTT1_KEEPALIVE=120
"@
        Add-Content -Path $envLocal -Value $letsMeshConfig
        Write-Host "SUCCESS: LetsMesh Packet Analyzer enabled" -ForegroundColor Green
        
        # Configure topics for LetsMesh
        Write-Host ""
        Write-Host "INFO: MQTT Topic Configuration for Broker 1" -ForegroundColor Blue
        Write-Host "INFO: MQTT topics define where different types of data are published." -ForegroundColor Blue
        Write-Host "INFO: You can use template variables: {IATA}, {IATA_lower}, {PUBLIC_KEY}" -ForegroundColor Blue
        Write-Host ""
        Write-Host "Choose topic configuration:" -ForegroundColor Blue
        Write-Host "  1) Default pattern (meshcore/{IATA}/{PUBLIC_KEY}/status, meshcore/{IATA}/{PUBLIC_KEY}/packets)" -ForegroundColor Blue
        Write-Host "  2) Classic pattern (meshcore/status, meshcore/packets, meshcore/raw)" -ForegroundColor Blue
        Write-Host "  3) Custom topics (enter your own)" -ForegroundColor Blue
        Write-Host ""
        
        $topicChoice = Read-Host "Select topic configuration [1-3]"
        
        switch ($topicChoice) {
            "1" {
                # Default pattern (IATA + PUBLIC_KEY)
                Add-Content -Path $envLocal -Value ""
                Add-Content -Path $envLocal -Value "# MQTT Topics for Broker 1 - Default Pattern"
                Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT1_TOPIC_STATUS=meshcore/{IATA}/{PUBLIC_KEY}/status"
                Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT1_TOPIC_PACKETS=meshcore/{IATA}/{PUBLIC_KEY}/packets"
                Write-Host "SUCCESS: Default pattern topics configured" -ForegroundColor Green
            }
            "2" {
                # Classic pattern (simple meshcore topics, needed for map.w0z.is)
                Add-Content -Path $envLocal -Value ""
                Add-Content -Path $envLocal -Value "# MQTT Topics for Broker 1 - Classic Pattern"
                Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT1_TOPIC_STATUS=meshcore/status"
                Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT1_TOPIC_PACKETS=meshcore/packets"
                Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT1_TOPIC_RAW=meshcore/raw"
                Write-Host "SUCCESS: Classic pattern topics configured" -ForegroundColor Green
            }
            "3" {
                # Custom topics
                Write-Host ""
                Write-Host "INFO: Enter custom topic paths (use {IATA}, {IATA_lower}, {PUBLIC_KEY} for templates)" -ForegroundColor Blue
                Write-Host "INFO: You can also manually edit the .env.local file after installation to customize topics" -ForegroundColor Blue
                Write-Host ""
                
                $statusTopic = Read-Host "Status topic" "meshcore/{IATA}/{PUBLIC_KEY}/status"
                $packetsTopic = Read-Host "Packets topic" "meshcore/{IATA}/{PUBLIC_KEY}/packets"
                
                Add-Content -Path $envLocal -Value ""
                Add-Content -Path $envLocal -Value "# MQTT Topics for Broker 1 - Custom"
                Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT1_TOPIC_STATUS=$statusTopic"
                Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT1_TOPIC_PACKETS=$packetsTopic"
                Write-Host "SUCCESS: Custom topics configured" -ForegroundColor Green
            }
            default {
                Write-Host "ERROR: Invalid choice, using default pattern" -ForegroundColor Red
                Add-Content -Path $envLocal -Value ""
                Add-Content -Path $envLocal -Value "# MQTT Topics for Broker 1 - Default Pattern"
                Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT1_TOPIC_STATUS=meshcore/{IATA}/{PUBLIC_KEY}/status"
                Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT1_TOPIC_PACKETS=meshcore/{IATA}/{PUBLIC_KEY}/packets"
            }
        }
    }
    else {
        Write-Host "INFO: No MQTT brokers configured - you'll need to edit .env.local manually" -ForegroundColor Yellow
    }
    
    Write-Host "SUCCESS: Configuration file created" -ForegroundColor Green
    
    # Final summary
    Write-Host ""
    Write-Host "=======================================================" -ForegroundColor Blue
    Write-Host "  Installation Complete!" -ForegroundColor Blue
    Write-Host "=======================================================" -ForegroundColor Blue
    Write-Host ""
    Write-Host "Installation directory: $InstallDir"
    Write-Host ""
    Write-Host "Configuration file: $InstallDir\.env.local"
    Write-Host ""
    Write-Host "To run manually: cd $InstallDir && .\venv\Scripts\python.exe packet_capture.py"
    Write-Host ""
    Write-Host "SUCCESS: Installation complete!" -ForegroundColor Green
}

# Run main installation
Start-Installation
