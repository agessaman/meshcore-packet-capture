# Simple version of install.ps1 without custom functions
# This version uses direct Write-Host calls to avoid function scope issues

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

# Simple test function
function Test-Simple {
    Write-Host "Simple test function works" -ForegroundColor Green
}

# Test if we can call functions
Write-Host ""
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Blue
Write-Host "  MeshCore Packet Capture Installer v$ScriptVersion" -ForegroundColor Blue
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Blue
Write-Host ""

Write-Host "This installer will help you set up MeshCore Packet Capture."
Write-Host ""

# Test function call
Test-Simple

Write-Host "Testing direct Write-Host call" -ForegroundColor Blue

# Determine installation directory
$defaultInstallDir = Join-Path $env:USERPROFILE ".meshcore-packet-capture"
$script:InstallDir = Read-Host "Installation directory" $defaultInstallDir

Write-Host "Installation directory: $InstallDir" -ForegroundColor Blue

Write-Host ""
Write-Host "Script execution test complete!" -ForegroundColor Green
Write-Host "If you see this message, the basic script structure is working." -ForegroundColor Green
