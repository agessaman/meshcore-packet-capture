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
    
    # Set up virtual environment
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
    
    # Download files
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
PACKETCAPTURE_IATA=LOC

# Advert Settings
PACKETCAPTURE_ADVERT_INTERVAL_HOURS=11
"@
    
    Set-Content -Path $envLocal -Value $configContent
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
