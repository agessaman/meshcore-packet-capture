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
        $files = @("packet_capture.py", "auth_token.py", "enums.py", "ble_pairing_helper.py", "requirements.txt")
        
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
    
    # Create basic .env.local file
    $envLocal = Join-Path $InstallDir ".env.local"
    $configContent = @"
# MeshCore Packet Capture Configuration
# This file contains your local overrides to the defaults in .env

# Update source (configured by installer)
PACKETCAPTURE_UPDATE_REPO=$Repo
PACKETCAPTURE_UPDATE_BRANCH=$Branch

# Connection Configuration
PACKETCAPTURE_CONNECTION_TYPE=serial

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
