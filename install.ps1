# ============================================================================
# MeshCore Packet Capture - Interactive Installer for Windows (Fixed Version)
# ============================================================================

param(
    [string]$ConfigUrl = "",
    [string]$Repo = "agessaman/meshcore-packet-capture",
    [string]$Branch = "main"
)

# Script configuration
$ScriptVersion = "1.1.2"
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

# Create version info file with installer version and git hash
function New-VersionInfo {
    $gitHash = "unknown"
    $gitBranch = $Branch
    $gitRepo = $Repo

    # Try to resolve the branch/tag to a specific commit hash via GitHub API
    try {
        $apiUrl = "https://api.github.com/repos/$gitRepo/commits/$gitBranch"
        $response = Invoke-WebRequest -Uri $apiUrl -UseBasicParsing
        $json = $response.Content | ConvertFrom-Json
        $gitHash = $json.sha.Substring(0, 7)
    }
    catch {
        Write-Host "WARNING: Could not fetch git hash from GitHub API" -ForegroundColor Yellow
    }

    # Create version info JSON file
    $versionInfo = @{
        installer_version = $ScriptVersion
        git_hash = $gitHash
        git_branch = $gitBranch
        git_repo = $gitRepo
        install_date = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    } | ConvertTo-Json -Depth 2

    $versionInfo | Out-File -FilePath (Join-Path $InstallDir ".version_info") -Encoding UTF8

    Write-Host "INFO: Version info saved: $ScriptVersion-$gitHash ($gitRepo@$gitBranch)" -ForegroundColor Blue
}

# Helper function for Windows Bluetooth API pairing
function Invoke-BluetoothPairing {
    param(
        [string]$DeviceAddress,
        [string]$Pin
    )
    
    try {
        # Use Windows Bluetooth API via .NET
        Add-Type -TypeDefinition @"
            using System;
            using System.Runtime.InteropServices;
            using System.Text;
            
            public class BluetoothAPI {
                [DllImport("bthprops.cpl", CharSet = CharSet.Unicode)]
                public static extern int BluetoothAuthenticateDevice(IntPtr hwndParent, IntPtr hRadio, ref BLUETOOTH_DEVICE_INFO pbtdi, string pszPasskey, int ulPasskeyLength);
                
                [DllImport("bthprops.cpl", CharSet = CharSet.Unicode)]
                public static extern int BluetoothSetServiceState(IntPtr hRadio, ref BLUETOOTH_DEVICE_INFO pbtdi, ref Guid pGuidService, int dwServiceFlags);
            }
            
            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct BLUETOOTH_DEVICE_INFO {
                public int dwSize;
                public long Address;
                public int ulClassofDevice;
                public bool fConnected;
                public bool fRemembered;
                public bool fAuthenticated;
                public long ftLastSeen;
                public long ftLastUsed;
                [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 248)]
                public string szName;
            }
"@ -ErrorAction SilentlyContinue
        
        # Try to pair using Windows API
        Write-Host "DEBUG: Attempting Windows Bluetooth API pairing..." -ForegroundColor Gray
        
        # This is a simplified approach - in practice, you'd need more complex API calls
        # For now, we'll return false to fall back to other methods
        return $false
        
    } catch {
        Write-Host "DEBUG: Windows Bluetooth API failed: $($_.Exception.Message)" -ForegroundColor Gray
        return $false
    }
}

# Helper function for bluetoothctl pairing
function Invoke-BluetoothctlPairing {
    param(
        [string]$DeviceAddress,
        [string]$Pin
    )
    
    try {
        Write-Host "DEBUG: Attempting bluetoothctl pairing..." -ForegroundColor Gray
        
        # Use bluetoothctl to pair
        $pairingScript = @"
#!/bin/bash
bluetoothctl << EOF
agent on
default-agent
scan on
sleep 5
scan off
pair $DeviceAddress
$Pin
trust $DeviceAddress
untrust $DeviceAddress
exit
EOF
"@
        
        # Save script to temp file
        $tempScript = [System.IO.Path]::GetTempFileName() + ".sh"
        $pairingScript | Out-File -FilePath $tempScript -Encoding UTF8
        
        # Try to run via WSL or Git Bash
        $wslResult = wsl bash $tempScript 2>&1
        $gitBashResult = bash $tempScript 2>&1
        
        # Clean up
        Remove-Item $tempScript -ErrorAction SilentlyContinue
        
        if ($wslResult -match "Pairing successful" -or $gitBashResult -match "Pairing successful") {
                return $true
        } else {
            Write-Host "DEBUG: bluetoothctl pairing failed" -ForegroundColor Gray
                return $false
            }
        
    } catch {
        Write-Host "DEBUG: bluetoothctl approach failed: $($_.Exception.Message)" -ForegroundColor Gray
                return $false
    }
}

# Function to configure additional MQTT brokers
function Configure-AdditionalMqttBrokers {
    $envLocal = Join-Path $InstallDir ".env.local"
    
    # Find next available broker number
    $nextBroker = 2
    while ((Get-Content $envLocal -ErrorAction SilentlyContinue) -match "PACKETCAPTURE_MQTT${nextBroker}_ENABLED=") {
        $nextBroker++
    }
    
    Write-Host ""
    Write-Host "INFO: Configuring Additional MQTT Brokers" -ForegroundColor Blue
    Write-Host ""
    
    $numBrokers = Read-Host "How many additional brokers would you like to configure? [1-3]"
    if ($numBrokers -notmatch '^[1-3]$') {
        $numBrokers = "1"
    }
    
    for ($i = 1; $i -le [int]$numBrokers; $i++) {
        $brokerNum = $nextBroker + $i - 1
        Configure-SingleMqttBroker $brokerNum
    }
}

# Helper function to read a value from .env.local in the install directory
# Also checks backup files if the main file doesn't exist, doesn't have the value, or has placeholder values
function Read-EnvValue {
    param([string]$Key)
    # Ensure we use the install directory, not the working directory
    if (-not $InstallDir) {
        return ""
    }
    $envFile = Join-Path $InstallDir ".env.local"
    $value = ""
    
    # First try the main .env.local file
    if (Test-Path $envFile) {
        $line = Get-Content $envFile | Where-Object { $_ -match "^${Key}=" }
        if ($line) {
            $value = $line -replace "^${Key}=", ""
            $value = $value.Trim('"', "'")
            # If we found a value and it's not a placeholder (XXX, empty, etc.), use it
            if ($value -and $value -ne "XXX") {
                return $value
            }
        }
    }
    
    # If not found or placeholder value, check backup files (most recent first)
    $backupFiles = Get-ChildItem -Path $InstallDir -Filter ".env.local.backup-*" -ErrorAction SilentlyContinue | 
        Sort-Object LastWriteTime -Descending | 
        Select-Object -First 1
    if ($backupFiles) {
        foreach ($backupFile in $backupFiles) {
            $line = Get-Content $backupFile.FullName | Where-Object { $_ -match "^${Key}=" }
            if ($line) {
                $backupValue = $line -replace "^${Key}=", ""
                $backupValue = $backupValue.Trim('"', "'")
                # Only return if we have a non-placeholder value
                if ($backupValue -and $backupValue -ne "XXX") {
                    return $backupValue
                }
            }
        }
    }
    
    # If we got here, return the value from main file (even if XXX) or empty
    # This preserves the behavior for cases where we want to know if it's XXX
    return $value
}

# Function to configure JWT token options (owner public key and client agent)
function Configure-JwtOptions {
    $envLocal = Join-Path $InstallDir ".env.local"
    
    # Read existing values as defaults
    $existingOwnerKey = Read-EnvValue "PACKETCAPTURE_OWNER_PUBLIC_KEY"
    $existingOwnerEmail = Read-EnvValue "PACKETCAPTURE_OWNER_EMAIL"
    
    Write-Host ""
    Write-Host "INFO: JWT Token Configuration (Optional)" -ForegroundColor Blue
    Write-Host ""
    Write-Host "INFO: You can optionally configure owner information for JWT tokens:" -ForegroundColor Blue
    Write-Host ""
    Write-Host "INFO: 1. Owner Public Key: The public key of the owner of the MQTT observer" -ForegroundColor Blue
    Write-Host "INFO:    (64 hex characters, same length as repeater public key)" -ForegroundColor Blue
    Write-Host ""
    Write-Host "INFO: 2. Owner Email: Email address of the owner for Let's Mesh Analyzer (optional)" -ForegroundColor Blue
    Write-Host ""
    Write-Host "INFO: Note: Client agent is automatically set to the build string (same as status messages)" -ForegroundColor Blue
    Write-Host ""
    
    # Prompt for owner public key
    $configureOwner = Read-Host "Would you like to configure an owner public key for JWT tokens? (y/N)"
    if ($configureOwner -match '^[yY]') {
        while ($true) {
            $ownerKey = Read-Host "Enter owner public key (64 hex characters)" $existingOwnerKey
            $ownerKey = $ownerKey.ToUpper().Replace(" ", "").Replace("-", "")
            
            if (-not $ownerKey) {
                Write-Host "WARNING: Owner public key cannot be empty" -ForegroundColor Yellow
                $skip = Read-Host "Skip owner public key configuration? (Y/n)"
                if ($skip -notmatch '^[nN]') {
                    break
                }
            }
            elseif ($ownerKey.Length -ne 64) {
                Write-Host "ERROR: Owner public key must be exactly 64 hex characters (you entered $($ownerKey.Length))" -ForegroundColor Red
                $tryAgain = Read-Host "Try again? (Y/n)"
                if ($tryAgain -match '^[nN]') {
                    break
                }
            }
            elseif ($ownerKey -notmatch '^[0-9A-F]{64}$') {
                Write-Host "ERROR: Owner public key must contain only hexadecimal characters (0-9, A-F)" -ForegroundColor Red
                $tryAgain = Read-Host "Try again? (Y/n)"
                if ($tryAgain -match '^[nN]') {
                    break
                }
            }
            else {
                Add-Content -Path $envLocal -Value "PACKETCAPTURE_OWNER_PUBLIC_KEY=$ownerKey"
                Write-Host "SUCCESS: Owner public key configured" -ForegroundColor Green
                break
            }
        }
    }
    
    # Prompt for owner email
    Write-Host ""
    $configureEmail = Read-Host "Would you like to configure an owner email for Let's Mesh Analyzer? (y/N)"
    if ($configureEmail -match '^[yY]') {
        while ($true) {
            $email = Read-Host "Enter owner email address" $existingOwnerEmail
            $email = $email.ToLower().Replace(" ", "")
            
            if (-not $email) {
                Write-Host "WARNING: Email cannot be empty" -ForegroundColor Yellow
                $skip = Read-Host "Skip email configuration? (Y/n)"
                if ($skip -notmatch '^[nN]') {
                    break
                }
            }
            else {
                # Validate email format using regex
                $emailPattern = '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
                if ($email -match $emailPattern) {
                    Add-Content -Path $envLocal -Value "PACKETCAPTURE_OWNER_EMAIL=$email"
                    Write-Host "SUCCESS: Owner email configured: $email" -ForegroundColor Green
                    break
                }
                else {
                    Write-Host "ERROR: Invalid email format. Please enter a valid email address (e.g., user@example.com)" -ForegroundColor Red
                    $tryAgain = Read-Host "Try again? (Y/n)"
                    if ($tryAgain -match '^[nN]') {
                        break
                    }
                }
            }
        }
    }
    
    # Client agent is automatically set to the build string (same as status messages)
    # No user configuration needed
}

# Function to configure a single MQTT broker
function Configure-SingleMqttBroker {
    param([int]$BrokerNum)
    
    $envLocal = Join-Path $InstallDir ".env.local"
    
        Write-Host ""
    Write-Host "INFO: Configuring MQTT Broker $BrokerNum" -ForegroundColor Blue
        Write-Host ""
    
    # Read existing values from install directory's .env.local as defaults
    $existingServer = Read-EnvValue "PACKETCAPTURE_MQTT${BrokerNum}_SERVER"
    $existingPort = Read-EnvValue "PACKETCAPTURE_MQTT${BrokerNum}_PORT"
    $existingTokenAudience = Read-EnvValue "PACKETCAPTURE_MQTT${BrokerNum}_TOKEN_AUDIENCE"
    $existingUsername = Read-EnvValue "PACKETCAPTURE_MQTT${BrokerNum}_USERNAME"
    $existingPassword = Read-EnvValue "PACKETCAPTURE_MQTT${BrokerNum}_PASSWORD"
    
    # Server configuration
    $server = Read-Host "MQTT Server hostname/IP" $existingServer
    if (-not $server) {
        Write-Host "WARNING: Server hostname required - skipping broker $BrokerNum" -ForegroundColor Yellow
        return
    }
    
    Add-Content -Path $envLocal -Value ""
    Add-Content -Path $envLocal -Value "# MQTT Broker $BrokerNum"
    Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_ENABLED=true"
    Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_SERVER=$server"
    
    # Port configuration
    $portDefault = if ($existingPort) { $existingPort } else { "1883" }
    $port = Read-Host "Port" $portDefault
    if (-not $port) {
        $port = "1883"
    }
    if (-not ($port -match '^\d+$') -or [int]$port -lt 1 -or [int]$port -gt 65535) {
        Write-Host "WARNING: Invalid port number, using default 1883" -ForegroundColor Yellow
        $port = "1883"
    }
    Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_PORT=$port"
    
    # Transport configuration
    Write-Host ""
    $useWebsockets = Read-Host "Use WebSockets transport? (y/N)"
    if ($useWebsockets -match '^[yY]') {
        Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_TRANSPORT=websockets"
    }
    
    # TLS configuration
    Write-Host ""
    $useTls = Read-Host "Use TLS/SSL encryption? (y/N)"
    if ($useTls -match '^[yY]') {
        Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_USE_TLS=true"
        
        $verifyTls = Read-Host "Verify TLS certificates? (Y/n)"
        if ($verifyTls -match '^[nN]') {
            Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_TLS_VERIFY=false"
        }
    }
    
    # Authentication configuration
    Write-Host ""
    Write-Host "Authentication method:" -ForegroundColor Blue
    Write-Host "  1) Username/Password" -ForegroundColor Blue
    Write-Host "  2) MeshCore Auth Token (requires meshcore-decoder)" -ForegroundColor Blue
    Write-Host "  3) None (anonymous)" -ForegroundColor Blue
    
    $authChoice = Read-Host "Choose authentication method [1-3]"
    
    switch ($authChoice) {
        "1" {
            $username = Read-Host "Username" $existingUsername
            if ($username) {
                Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_USERNAME=$username"
                $password = Read-Host "Password" $existingPassword
                if ($password) {
                    Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_PASSWORD=$password"
                }
            }
        }
        "2" {
            Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_USE_AUTH_TOKEN=true"
            $tokenAudience = Read-Host "Token audience (optional)" $existingTokenAudience
            if ($tokenAudience) {
                Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_TOKEN_AUDIENCE=$tokenAudience"
            }
        }
        "3" {
            # No authentication
        }
        default {
            Write-Host "WARNING: Invalid choice, using username/password" -ForegroundColor Yellow
            $username = Read-Host "Username" $existingUsername
            if ($username) {
                Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_USERNAME=$username"
                $password = Read-Host "Password" $existingPassword
                if ($password) {
                    Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_PASSWORD=$password"
                }
            }
        }
    }
    
    # Topic configuration
    Write-Host ""
    Write-Host "INFO: MQTT Topic Configuration for Broker $BrokerNum" -ForegroundColor Blue
    Write-Host "INFO: MQTT topics define where different types of data are published." -ForegroundColor Blue
    Write-Host "INFO: You can use template variables: {IATA}, {IATA_lower}, {PUBLIC_KEY}" -ForegroundColor Blue
    Write-Host ""
    Write-Host "Choose topic configuration:" -ForegroundColor Blue
    Write-Host "  1) Default pattern (meshcore/{IATA}/{PUBLIC_KEY}/status, meshcore/{IATA}/{PUBLIC_KEY}/packets)" -ForegroundColor Blue
    Write-Host "  2) Classic pattern (meshcore/status, meshcore/packets, meshcore/raw)" -ForegroundColor Blue
    Write-Host "  3) Custom topics (enter your own)" -ForegroundColor Blue
    Write-Host ""
    
    $topicChoice = Read-Host "Select topic configuration [1-3]" "1"
    
    switch ($topicChoice) {
        "1" {
            # Default pattern (IATA + PUBLIC_KEY)
            Add-Content -Path $envLocal -Value ""
            Add-Content -Path $envLocal -Value "# MQTT Topics for Broker $BrokerNum - Default Pattern"
            Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_TOPIC_STATUS=meshcore/{IATA}/{PUBLIC_KEY}/status"
            Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_TOPIC_PACKETS=meshcore/{IATA}/{PUBLIC_KEY}/packets"
            Write-Host "SUCCESS: Default pattern topics configured" -ForegroundColor Green
        }
        "2" {
            # Classic pattern (simple meshcore topics, needed for map.w0z.is)
            Add-Content -Path $envLocal -Value ""
            Add-Content -Path $envLocal -Value "# MQTT Topics for Broker $BrokerNum - Classic Pattern"
            Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_TOPIC_STATUS=meshcore/status"
            Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_TOPIC_PACKETS=meshcore/packets"
            Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_TOPIC_RAW=meshcore/raw"
            Write-Host "SUCCESS: Classic pattern topics configured" -ForegroundColor Green
        }
        "3" {
            # Custom topics
            Write-Host ""
            Write-Host "INFO: Enter custom topic paths (use {IATA}, {IATA_lower}, {PUBLIC_KEY} for templates)" -ForegroundColor Blue
            Write-Host "INFO: You can also manually edit the .env.local file after installation to customize topics" -ForegroundColor Blue
            Write-Host ""
            
            # Read existing topic values from install directory's .env.local as defaults
            $existingStatusTopic = Read-EnvValue "PACKETCAPTURE_MQTT${BrokerNum}_TOPIC_STATUS"
            $existingPacketsTopic = Read-EnvValue "PACKETCAPTURE_MQTT${BrokerNum}_TOPIC_PACKETS"
            
            $statusTopicDefault = if ($existingStatusTopic) { $existingStatusTopic } else { "meshcore/{IATA}/{PUBLIC_KEY}/status" }
            $packetsTopicDefault = if ($existingPacketsTopic) { $existingPacketsTopic } else { "meshcore/{IATA}/{PUBLIC_KEY}/packets" }
            
            $statusTopic = Read-Host "Status topic" $statusTopicDefault
            $packetsTopic = Read-Host "Packets topic" $packetsTopicDefault
            
            Add-Content -Path $envLocal -Value ""
            Add-Content -Path $envLocal -Value "# MQTT Topics for Broker $BrokerNum - Custom"
            Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_TOPIC_STATUS=$statusTopic"
            Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_TOPIC_PACKETS=$packetsTopic"
            Write-Host "SUCCESS: Custom topics configured" -ForegroundColor Green
        }
        default {
            Write-Host "ERROR: Invalid choice, using default pattern" -ForegroundColor Red
            Add-Content -Path $envLocal -Value ""
            Add-Content -Path $envLocal -Value "# MQTT Topics for Broker $BrokerNum - Default Pattern"
            Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_TOPIC_STATUS=meshcore/{IATA}/{PUBLIC_KEY}/status"
            Add-Content -Path $envLocal -Value "PACKETCAPTURE_MQTT${BrokerNum}_TOPIC_PACKETS=meshcore/{IATA}/{PUBLIC_KEY}/packets"
        }
    }
    
    Write-Host "SUCCESS: Broker $BrokerNum configured" -ForegroundColor Green
}

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
        # Create version info file
        New-VersionInfo
        
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
        
        # Create version info file
        New-VersionInfo
        
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
    
    # Read existing connection type and map to default choice number
    # Note: PowerShell version has different numbering: 1=serial, 2=ble, 3=tcp
    $existingConnectionType = Read-EnvValue "PACKETCAPTURE_CONNECTION_TYPE"
    $defaultChoice = "1"  # Default to Serial
    if ($existingConnectionType) {
        switch ($existingConnectionType.ToLower()) {
            "serial" { $defaultChoice = "1" }
            "ble" { $defaultChoice = "2" }
            "tcp" { $defaultChoice = "3" }
        }
    }
    
    $connectionChoice = ""
    while ($connectionChoice -notmatch '^[1-3]$') {
        if ($defaultChoice) {
            $connectionChoice = Read-Host "Select connection type [1-3] [$defaultChoice]"
            if ([string]::IsNullOrWhiteSpace($connectionChoice)) {
                $connectionChoice = $defaultChoice
            }
        } else {
            $connectionChoice = Read-Host "Select connection type [1-3]"
        }
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
                # Read existing serial device from install directory's .env.local as default
                $existingSerialDevice = Read-EnvValue "PACKETCAPTURE_SERIAL_PORTS"
                $serialDeviceDefault = if ($existingSerialDevice) { $existingSerialDevice } else { "COM1" }
                $script:SelectedSerialDevice = Read-Host "Enter serial device path" $serialDeviceDefault
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
                            # Manual entry - use existing value as default
                            $existingSerialDevice = Read-EnvValue "PACKETCAPTURE_SERIAL_PORTS"
                            $serialDeviceDefault = if ($existingSerialDevice) { $existingSerialDevice } else { "COM1" }
                            $script:SelectedSerialDevice = Read-Host "Enter serial device path" $serialDeviceDefault
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
            
            # Scan for BLE devices using Windows-native approach
            Write-Host ""
            Write-Host "INFO: Scanning for BLE devices using Windows Bluetooth..." -ForegroundColor Blue
            Write-Host "INFO: This may take 10-15 seconds..." -ForegroundColor Blue
            
            try {
                # Check if Bluetooth is available
                $bluetoothAdapter = Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "OK" }
                if (-not $bluetoothAdapter) {
                    Write-Host "WARNING: No Bluetooth adapter found or Bluetooth is disabled" -ForegroundColor Yellow
                    # Read existing values from install directory's .env.local as defaults
                    $existingBleDevice = Read-EnvValue "PACKETCAPTURE_BLE_DEVICE"
                    $existingBleName = Read-EnvValue "PACKETCAPTURE_BLE_NAME"
                    $script:SelectedBleDevice = Read-Host "Enter BLE device MAC address" $existingBleDevice
                    $script:SelectedBleName = Read-Host "Enter device name (optional)" $existingBleName
                    return
                }
                
                Write-Host "DEBUG: Bluetooth adapter found: $($bluetoothAdapter.FriendlyName)" -ForegroundColor Gray
                
                # Start Bluetooth discovery
                Write-Host "INFO: Starting Bluetooth discovery..." -ForegroundColor Blue
                
                # Use PowerShell to discover Bluetooth devices
                $discoveredDevices = @()
                $startTime = Get-Date
                $timeout = 15
                
                # Check for already paired MeshCore devices first
                Write-Host "INFO: Checking for already paired MeshCore devices..." -ForegroundColor Blue
                $pairedMeshCoreDevices = Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | 
                    Where-Object { $_.FriendlyName -like "*MeshCore*" -and $_.Status -eq "OK" }
                
                if ($pairedMeshCoreDevices.Count -gt 0) {
                    Write-Host "INFO: Found $($pairedMeshCoreDevices.Count) already paired MeshCore device(s):" -ForegroundColor Blue
                    for ($i = 0; $i -lt $pairedMeshCoreDevices.Count; $i++) {
                        $device = $pairedMeshCoreDevices[$i]
                        Write-Host "  $($i + 1)) $($device.FriendlyName) (Already Paired)" -ForegroundColor Blue
                    }
                    Write-Host "  $($pairedMeshCoreDevices.Count + 1)) Enter device manually" -ForegroundColor Blue
                    Write-Host ""
                    
                    while ($true) {
                        $choice = Read-Host "Select device [1-$($pairedMeshCoreDevices.Count + 1)]"
                        if ($choice -match '^\d+$' -and [int]$choice -ge 1 -and [int]$choice -le ($pairedMeshCoreDevices.Count + 1)) {
                            if ([int]$choice -eq ($pairedMeshCoreDevices.Count + 1)) {
                                # Manual entry - use existing values as defaults
                                $existingBleDevice = Read-EnvValue "PACKETCAPTURE_BLE_DEVICE"
                                $existingBleName = Read-EnvValue "PACKETCAPTURE_BLE_NAME"
                                $script:SelectedBleDevice = Read-Host "Enter BLE device MAC address" $existingBleDevice
                                $script:SelectedBleName = Read-Host "Enter device name (optional)" $existingBleName
                            }
                            else {
                                $selectedDevice = $pairedMeshCoreDevices[([int]$choice - 1)]
                                # Extract MAC address from InstanceId if possible
                                $macAddress = $selectedDevice.InstanceId
                                if ($macAddress -match 'DEV_([A-F0-9]{12})') {
                                    $macBytes = $matches[1]
                                    $macParts = @()
                                    for ($i = 0; $i -lt $macBytes.Length; $i += 2) {
                                        $macParts += $macBytes.Substring($i, 2)
                                    }
                                    $macAddress = $macParts -join ':'
                                } else {
                                    # Try to get MAC address from Windows Bluetooth registry
                                    try {
                                        $deviceName = $selectedDevice.FriendlyName
                                        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices"
                                        $deviceKeys = Get-ChildItem $regPath -ErrorAction SilentlyContinue
                                        foreach ($key in $deviceKeys) {
                                            $deviceInfo = Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue
                                            if ($deviceInfo -and $deviceInfo.Name -eq $deviceName) {
                                                $macAddress = $key.PSChildName -replace '(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})', '$1:$2:$3:$4:$5:$6'
                                                break
                                            }
                                        }
                                    } catch {
                                        # If registry lookup fails, prompt user for MAC address
                                        Write-Host "WARNING: Could not extract MAC address automatically" -ForegroundColor Yellow
                                        $macAddress = Read-Host "Enter the MAC address for $($selectedDevice.FriendlyName) (format: XX:XX:XX:XX:XX:XX)"
                                    }
                                }
                                $script:SelectedBleDevice = $macAddress
                                $script:SelectedBleName = $selectedDevice.FriendlyName
                            }
                            break
            }
            else {
                            Write-Host "ERROR: Invalid selection. Please enter a number between 1 and $($pairedMeshCoreDevices.Count + 1)" -ForegroundColor Red
                        }
                    }
                } else {
                    # Start discovery in background for unpaired devices
                    Write-Host "INFO: No paired MeshCore devices found, scanning for unpaired devices..." -ForegroundColor Blue
                    
                    $discoveryJob = Start-Job -ScriptBlock {
                        # Import Bluetooth module if available
                        try {
                            Import-Module -Name Bluetooth -ErrorAction SilentlyContinue
                        } catch {}
                        
                        # Get discovered devices
                        $devices = @()
                        $endTime = (Get-Date).AddSeconds(15)
                        
                        while ((Get-Date) -lt $endTime) {
                            try {
                                # Try different methods to get Bluetooth devices
                                $btDevices = Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | 
                                    Where-Object { $_.Status -eq "OK" -and $_.FriendlyName -like "*MeshCore*" }
                                
                                foreach ($device in $btDevices) {
                                    if ($device.FriendlyName -and $device.FriendlyName -like "*MeshCore*") {
                                        $devices += @{
                                            Name = $device.FriendlyName
                                            Address = $device.InstanceId
                                            Status = $device.Status
                                        }
                                    }
                                }
                                
                                Start-Sleep -Seconds 2
                            } catch {
                                # Continue scanning
                            }
                        }
                        
                        return $devices
                    }
                    
                    # Wait for discovery to complete
                    $completed = Wait-Job $discoveryJob -Timeout $timeout
                    
                    if ($completed) {
                        $discoveredDevices = Receive-Job $discoveryJob
                    } else {
                        Stop-Job $discoveryJob
                        Write-Host "WARNING: Bluetooth discovery timed out" -ForegroundColor Yellow
                    }
                    Remove-Job $discoveryJob
                    
                    # Filter and display results
                    $meshcoreDevices = $discoveredDevices | Where-Object { $_.Name -like "*MeshCore*" } | Sort-Object Name -Unique
                    
                    if ($meshcoreDevices.Count -gt 0) {
                        Write-Host "INFO: Found $($meshcoreDevices.Count) MeshCore device(s):" -ForegroundColor Blue
                        for ($i = 0; $i -lt $meshcoreDevices.Count; $i++) {
                            $device = $meshcoreDevices[$i]
                            Write-Host "  $($i + 1)) $($device.Name) ($($device.Address))" -ForegroundColor Blue
                        }
                        Write-Host "  $($meshcoreDevices.Count + 1)) Enter device manually" -ForegroundColor Blue
                        Write-Host ""
                        
                        while ($true) {
                            $choice = Read-Host "Select device [1-$($meshcoreDevices.Count + 1)]"
                            if ($choice -match '^\d+$' -and [int]$choice -ge 1 -and [int]$choice -le ($meshcoreDevices.Count + 1)) {
                            if ([int]$choice -eq ($meshcoreDevices.Count + 1)) {
                                # Manual entry - use existing values as defaults
                                $existingBleDevice = Read-EnvValue "PACKETCAPTURE_BLE_DEVICE"
                                $existingBleName = Read-EnvValue "PACKETCAPTURE_BLE_NAME"
                                $script:SelectedBleDevice = Read-Host "Enter BLE device MAC address" $existingBleDevice
                                $script:SelectedBleName = Read-Host "Enter device name (optional)" $existingBleName
    }
    else {
                                    $selectedDevice = $meshcoreDevices[([int]$choice - 1)]
                                    # Extract MAC address from Address if it's a Windows device ID
                                    $macAddress = $selectedDevice.Address
                                    if ($macAddress -match 'DEV_([A-F0-9]{12})') {
                                        $macBytes = $matches[1]
                                        $macParts = @()
                                        for ($i = 0; $i -lt $macBytes.Length; $i += 2) {
                                            $macParts += $macBytes.Substring($i, 2)
                                        }
                                        $macAddress = $macParts -join ':'
                                    }
                                    $script:SelectedBleDevice = $macAddress
                                    $script:SelectedBleName = $selectedDevice.Name
                                }
                                break
        }
        else {
                                Write-Host "ERROR: Invalid selection. Please enter a number between 1 and $($meshcoreDevices.Count + 1)" -ForegroundColor Red
                            }
                        }
                    }
                    else {
                        Write-Host "WARNING: No MeshCore BLE devices found" -ForegroundColor Yellow
                        Write-Host "INFO: Make sure your MeshCore device is:" -ForegroundColor Blue
                        Write-Host "  - Powered on and within range" -ForegroundColor Blue
                        Write-Host "  - In pairing mode (if not already paired)" -ForegroundColor Blue
                        Write-Host "  - Not connected to another device" -ForegroundColor Blue
    Write-Host ""
                        # Fallback to manual entry - use existing values as defaults
                        $existingBleDevice = Read-EnvValue "PACKETCAPTURE_BLE_DEVICE"
                        $existingBleName = Read-EnvValue "PACKETCAPTURE_BLE_NAME"
                        $script:SelectedBleDevice = Read-Host "Enter BLE device MAC address" $existingBleDevice
                        $script:SelectedBleName = Read-Host "Enter device name (optional)" $existingBleName
                    }
                }
            }
            catch {
                Write-Host "WARNING: BLE scanning failed: $($_.Exception.Message)" -ForegroundColor Yellow
                Write-Host "INFO: Falling back to manual device entry" -ForegroundColor Blue
                # Use existing values as defaults
                $existingBleDevice = Read-EnvValue "PACKETCAPTURE_BLE_DEVICE"
                $existingBleName = Read-EnvValue "PACKETCAPTURE_BLE_NAME"
                $script:SelectedBleDevice = Read-Host "Enter BLE device MAC address" $existingBleDevice
                $script:SelectedBleName = Read-Host "Enter device name (optional)" $existingBleName
            }
            
            if ($script:SelectedBleDevice) {
                Write-Host "SUCCESS: BLE device configured: $script:SelectedBleName ($script:SelectedBleDevice)" -ForegroundColor Green
                
                # Attempt BLE pairing using Windows-native approach
                Write-Host ""
                Write-Host "INFO: Checking BLE device pairing status..." -ForegroundColor Blue
                
                try {
                    # Check if device is already paired
                    $pairedDevice = Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | 
                        Where-Object { $_.FriendlyName -like "*$script:SelectedBleName*" -or $_.InstanceId -like "*$script:SelectedBleDevice*" }
                    
                    if ($pairedDevice -and $pairedDevice.Status -eq "OK") {
                        Write-Host "SUCCESS: Device is already paired and ready to use" -ForegroundColor Green
    }
    else {
                        Write-Host "INFO: Device requires pairing" -ForegroundColor Blue
                        Write-Host "INFO: Attempting to pair programmatically..." -ForegroundColor Blue
                        
                        # Try programmatic pairing
                        try {
                            $pairingSuccess = $false
                            
                            # Method 1: Try using PowerShell Bluetooth cmdlets (if available)
                            try {
                                Import-Module -Name Bluetooth -ErrorAction SilentlyContinue
                                if (Get-Command -Name "Add-BluetoothDevice" -ErrorAction SilentlyContinue) {
                                    Write-Host "INFO: Using PowerShell Bluetooth cmdlets..." -ForegroundColor Blue
                                    
                                    # Get the PIN from user
                                    $pin = Read-Host "Enter the 6-digit PIN displayed on your MeshCore device"
                                    if ($pin -match '^\d{6}$') {
                                        $pairingResult = Add-BluetoothDevice -Address $script:SelectedBleDevice -Pin $pin -ErrorAction Stop
                                        if ($pairingResult) {
                                            Write-Host "SUCCESS: Device paired successfully using PowerShell cmdlets" -ForegroundColor Green
                                            $pairingSuccess = $true
                                        }
                                    } else {
                                        Write-Host "ERROR: PIN must be 6 digits" -ForegroundColor Red
                                    }
                                }
                            } catch {
                                Write-Host "DEBUG: PowerShell Bluetooth cmdlets not available: $($_.Exception.Message)" -ForegroundColor Gray
                            }
                            
                            # Method 2: Try using Windows Bluetooth API via .NET
                            if (-not $pairingSuccess) {
                                try {
                                    Write-Host "INFO: Using Windows Bluetooth API..." -ForegroundColor Blue
                                    
                                    # Get the PIN from user
                                    $pin = Read-Host "Enter the 6-digit PIN displayed on your MeshCore device"
                                    if ($pin -match '^\d{6}$') {
                                        $pairingSuccess = Invoke-BluetoothPairing -DeviceAddress $script:SelectedBleDevice -Pin $pin
                                        if ($pairingSuccess) {
                                            Write-Host "SUCCESS: Device paired successfully using Windows API" -ForegroundColor Green
                                        }
                                    } else {
                                        Write-Host "ERROR: PIN must be 6 digits" -ForegroundColor Red
                                    }
                                } catch {
                                    Write-Host "DEBUG: Windows Bluetooth API failed: $($_.Exception.Message)" -ForegroundColor Gray
                                }
                            }
                            
                            # Method 3: Try using bluetoothctl (if available via WSL or installed)
                            if (-not $pairingSuccess) {
                                try {
                                    Write-Host "INFO: Trying bluetoothctl approach..." -ForegroundColor Blue
                                    
                                    # Check if bluetoothctl is available
                                    $bluetoothctlPath = Get-Command bluetoothctl -ErrorAction SilentlyContinue
                                    if ($bluetoothctlPath) {
                                        $pin = Read-Host "Enter the 6-digit PIN displayed on your MeshCore device"
                                        if ($pin -match '^\d{6}$') {
                                            $pairingSuccess = Invoke-BluetoothctlPairing -DeviceAddress $script:SelectedBleDevice -Pin $pin
                                            if ($pairingSuccess) {
                                                Write-Host "SUCCESS: Device paired successfully using bluetoothctl" -ForegroundColor Green
                                            }
                                        } else {
                                            Write-Host "ERROR: PIN must be 6 digits" -ForegroundColor Red
                                        }
                                    }
                                } catch {
                                    Write-Host "DEBUG: bluetoothctl approach failed: $($_.Exception.Message)" -ForegroundColor Gray
                                }
                            }
                            
                            # Fallback to manual pairing if all methods failed
                            if (-not $pairingSuccess) {
                                Write-Host "WARNING: Programmatic pairing failed, falling back to manual pairing" -ForegroundColor Yellow
                                Write-Host "INFO: You'll need to pair the device manually using Windows Bluetooth settings" -ForegroundColor Blue
                                Write-Host ""
                                Write-Host "To pair manually:" -ForegroundColor Blue
                                Write-Host "  1. Open Windows Settings > Devices > Bluetooth & other devices" -ForegroundColor Blue
                                Write-Host "  2. Click 'Add Bluetooth or other device'" -ForegroundColor Blue
                                Write-Host "  3. Select 'Bluetooth'" -ForegroundColor Blue
                                Write-Host "  4. Look for your MeshCore device in the list" -ForegroundColor Blue
                                Write-Host "  5. Click on it and enter the PIN when prompted" -ForegroundColor Blue
                                Write-Host "  6. Do NOT check 'Connect automatically' (we want manual connection)" -ForegroundColor Blue
                                Write-Host ""
                                Write-Host "INFO: After pairing, the device will be available for the packet capture application" -ForegroundColor Blue
                                
                                # Ask if user wants to continue
                                $continue = Read-Host "Continue with installation? (y/N)"
                                if ($continue -notmatch '^[yY]') {
                                    Write-Host "INFO: Installation paused. Please pair your device and run the installer again." -ForegroundColor Blue
                                    exit 0
                                }
                            }
                        } catch {
                            Write-Host "WARNING: Pairing attempt failed: $($_.Exception.Message)" -ForegroundColor Yellow
                            Write-Host "INFO: Please pair the device manually using Windows Bluetooth settings" -ForegroundColor Blue
                        }
        }
    }
    catch {
                    Write-Host "WARNING: Could not check pairing status: $($_.Exception.Message)" -ForegroundColor Yellow
                    Write-Host "INFO: You may need to pair the device manually" -ForegroundColor Blue
                }
            }
            else {
                Write-Host "WARNING: No BLE device configured" -ForegroundColor Yellow
            }
        }
        "3" {
            $script:ConnectionType = "tcp"
            Write-Host "SUCCESS: Selected TCP Connection" -ForegroundColor Green
            
            # Read existing values from install directory's .env.local as defaults
            $existingTcpHost = Read-EnvValue "PACKETCAPTURE_TCP_HOST"
            $existingTcpPort = Read-EnvValue "PACKETCAPTURE_TCP_PORT"
            
            # Use existing values as defaults, or fall back to standard defaults
            $tcpHostDefault = if ($existingTcpHost) { $existingTcpHost } else { "localhost" }
            $tcpPortDefault = if ($existingTcpPort) { $existingTcpPort } else { "5000" }
            
            $script:TcpHost = Read-Host "TCP host/address" $tcpHostDefault
            $script:TcpPort = Read-Host "TCP port" $tcpPortDefault
            
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

# Packet Type Filtering (comma-separated list of packet type numbers to upload to MQTT)
# Leave commented out to upload all packet types
# Example: PACKETCAPTURE_UPLOAD_PACKET_TYPES=2,4  (upload only TXT_MSG and ADVERT)
#PACKETCAPTURE_UPLOAD_PACKET_TYPES=

# Logging Settings
PACKETCAPTURE_LOG_LEVEL=INFO
"@
    
    Set-Content -Path $envLocal -Value $configContent
    
    # Always prompt for IATA (allows changing during reconfiguration)
    # Get existing IATA from config (including backup files) to use as default
    $existingIata = Read-EnvValue "PACKETCAPTURE_IATA"
    if ($existingIata) {
        $existingIata = $existingIata.Trim()
    }
    # Clear default if it's XXX or empty
    if (-not $existingIata -or $existingIata -eq "XXX") {
        $existingIata = ""
    }
    
    Write-Host ""
    Write-Host "INFO: IATA code is a 3-letter airport code identifying your geographic region" -ForegroundColor Blue
    Write-Host "INFO: Example: SEA (Seattle), LAX (Los Angeles), NYC (New York), LON (London)" -ForegroundColor Blue
    Write-Host ""
    
    $script:Iata = ""
    while (-not $script:Iata -or $script:Iata -eq "XXX") {
        if ($existingIata) {
            $script:Iata = Read-Host "Enter your IATA code (3 letters) [$existingIata]"
            if ([string]::IsNullOrWhiteSpace($script:Iata)) {
                $script:Iata = $existingIata
            }
        } else {
            $script:Iata = Read-Host "Enter your IATA code (3 letters)"
        }
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
    
    # Configure JWT options (owner public key and email) - global settings
    $ownerKeyExists = (Get-Content $envLocal -ErrorAction SilentlyContinue) -match "^PACKETCAPTURE_OWNER_PUBLIC_KEY="
    $ownerEmailExists = (Get-Content $envLocal -ErrorAction SilentlyContinue) -match "^PACKETCAPTURE_OWNER_EMAIL="
    if (-not $ownerKeyExists -and -not $ownerEmailExists) {
        Configure-JwtOptions
    }
    
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
    
        $topicChoice = Read-Host "Select topic configuration [1-3]" "1" "1"
        
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
                
                # Read existing topic values from install directory's .env.local as defaults
                $existingStatusTopic = Read-EnvValue "PACKETCAPTURE_MQTT1_TOPIC_STATUS"
                $existingPacketsTopic = Read-EnvValue "PACKETCAPTURE_MQTT1_TOPIC_PACKETS"
                
                $statusTopicDefault = if ($existingStatusTopic) { $existingStatusTopic } else { "meshcore/{IATA}/{PUBLIC_KEY}/status" }
                $packetsTopicDefault = if ($existingPacketsTopic) { $existingPacketsTopic } else { "meshcore/{IATA}/{PUBLIC_KEY}/packets" }
                
                $statusTopic = Read-Host "Status topic" $statusTopicDefault
                $packetsTopic = Read-Host "Packets topic" $packetsTopicDefault
                
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
        
        # Ask if user wants to configure additional MQTT brokers
    Write-Host ""
        $addMoreBrokers = Read-Host "Would you like to configure additional MQTT brokers? (y/N)"
        if ($addMoreBrokers -match '^[yY]') {
            Configure-AdditionalMqttBrokers
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
    Write-Host "To run manually: cd $InstallDir; .\venv\Scripts\python.exe packet_capture.py"
    Write-Host ""
    Write-Host "SUCCESS: Installation complete!" -ForegroundColor Green
}

# Run main installation
Start-Installation
