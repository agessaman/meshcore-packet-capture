#!/bin/bash
# ============================================================================
# MeshCore Packet Capture - Interactive Installer
# ============================================================================
set -e

SCRIPT_VERSION="1.1.1"
DEFAULT_REPO="agessaman/meshcore-packet-capture"
DEFAULT_BRANCH="main"

# Parse command line arguments
CONFIG_URL=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --config)
            CONFIG_URL="$2"
            shift 2
            ;;
        --repo)
            DEFAULT_REPO="$2"
            shift 2
            ;;
        --branch)
            DEFAULT_BRANCH="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--config URL] [--repo owner/repo] [--branch branch-name]"
            exit 1
            ;;
    esac
done

# Use environment variables if set, otherwise use defaults/args
REPO="${INSTALL_REPO:-$DEFAULT_REPO}"
BRANCH="${INSTALL_BRANCH:-$DEFAULT_BRANCH}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
print_header() {
    echo -e "\n${BLUE}═══════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════${NC}\n"
}

# Create version info file with installer version and git hash
create_version_info() {
    local git_hash="unknown"
    local git_branch="${BRANCH}"
    local git_repo="${REPO}"

    # Try to resolve the branch/tag to a specific commit hash via GitHub API
    if command -v curl >/dev/null 2>&1; then
        # Try to get commit SHA from GitHub API
        local api_url="https://api.github.com/repos/${git_repo}/commits/${git_branch}"
        git_hash=$(curl -fsSL "$api_url" 2>/dev/null | grep -m1 '"sha"' | cut -d'"' -f4 | head -c7)
        [ -z "$git_hash" ] && git_hash="unknown"
    fi

    # Create version info JSON file
    cat > "$INSTALL_DIR/.version_info" <<EOF
{
  "installer_version": "${SCRIPT_VERSION}",
  "git_hash": "${git_hash}",
  "git_branch": "${git_branch}",
  "git_repo": "${git_repo}",
  "install_date": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF

    print_info "Version info saved: ${SCRIPT_VERSION}-${git_hash} (${git_repo}@${git_branch})"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

# Detect available serial devices
detect_serial_devices() {
    local devices=()
    
    if [ "$(uname)" = "Darwin" ]; then
        # macOS: Use /dev/cu.* devices (callout devices, preferred over tty.*)
        # Look for common USB serial adapters
        while IFS= read -r device; do
            devices+=("$device")
        done < <(ls /dev/cu.usb* /dev/cu.wchusbserial* /dev/cu.SLAB_USBtoUART* 2>/dev/null | sort)
    else
        # Linux: Prefer /dev/serial/by-id/ for persistent naming
        if [ -d /dev/serial/by-id ]; then
            while IFS= read -r device; do
                devices+=("$device")
            done < <(ls -1 /dev/serial/by-id/ 2>/dev/null | sed 's|^|/dev/serial/by-id/|')
        fi
        
        # Also check /dev/ttyACM* and /dev/ttyUSB* as fallback
        while IFS= read -r device; do
            # Only add if not already in list via by-id
            local already_added=false
            for existing in "${devices[@]}"; do
                if [ "$(readlink -f "$existing" 2>/dev/null)" = "$device" ]; then
                    already_added=true
                    break
                fi
            done
            if [ "$already_added" = false ]; then
                devices+=("$device")
            fi
        done < <(ls /dev/ttyACM* /dev/ttyUSB* 2>/dev/null | sort)
    fi
    
    printf '%s\n' "${devices[@]}"
}

# Scan for BLE devices using Python helper
scan_ble_devices() {
    echo ""
    print_info "Scanning for BLE devices..."
    echo "This may take 10-15 seconds..."
    echo ""
    
    # Check if Python and meshcore are available
    if ! command -v python3 &> /dev/null; then
        print_warning "Python3 not found - cannot scan for BLE devices"
        return 1
    fi
    
    # Check if meshcore and bleak are available
    if ! python3 -c "import meshcore, bleak" 2>/dev/null; then
        print_warning "meshcore or bleak not available - cannot scan for BLE devices"
        print_info "BLE scanning requires the meshcore library and its dependencies"
        print_info "These will be installed after the main installation completes"
        return 1
    fi
    
    # Create a temporary BLE scan helper script
    local temp_script="/tmp/ble_scan_helper.py"
    cat > "$temp_script" << 'EOF'
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
EOF
    
    # Run the BLE scan helper
    local scan_output
    local scan_error
    if scan_output=$(python3 "$temp_script" 2>/tmp/ble_scan_error); then
        # Parse JSON output
        local devices_json="$scan_output"
        local device_count=$(echo "$devices_json" | python3 -c "import sys, json; data=json.load(sys.stdin); print(len(data))" 2>/dev/null)
        
        # Check if device_count is a valid number
        if ! [[ "$device_count" =~ ^[0-9]+$ ]]; then
            print_warning "Failed to parse BLE scan results"
            return 1
        fi
        
        if [ "$device_count" -eq 0 ]; then
            print_warning "No MeshCore BLE devices found"
            return 1
        fi
        
        print_success "Found $device_count MeshCore BLE device(s):"
        echo ""
        
        # Display devices and store device info
        local i=1
        local device_addresses=()
        local device_names=()
        
        # Parse devices and store in arrays
        while IFS= read -r device_info; do
            local name=$(echo "$device_info" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('name', 'Unknown'))")
            local address=$(echo "$device_info" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('address', 'Unknown'))")
            
            echo "  $i) $name ($address)"
            device_addresses+=("$address")
            device_names+=("$name")
            ((i++))
        done < <(echo "$devices_json" | python3 -c "import sys, json; data=json.load(sys.stdin); [print(json.dumps(device)) for device in data]")
        
        echo "  $((device_count + 1))) Enter device manually"
        echo "  0) Scan again"
        echo ""
        
        while true; do
            local choice=$(prompt_input "Select device [0-$((device_count + 1))]" "1")
            if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 0 ] && [ "$choice" -le $((device_count + 1)) ]; then
                if [ "$choice" -eq 0 ]; then
                    # Rescan for devices
                    echo ""
                    print_info "Rescanning for BLE devices..."
                    return 2  # Special return code to indicate rescan requested
                elif [ "$choice" -eq $((device_count + 1)) ]; then
                    # Manual entry
                    local manual_mac=$(prompt_input "Enter BLE device MAC address" "")
                    local manual_name=$(prompt_input "Enter device name (optional)" "")
                    if [ -n "$manual_mac" ]; then
                        SELECTED_BLE_DEVICE="$manual_mac"
                        SELECTED_BLE_NAME="$manual_name"
                        return 0
                    fi
                else
                    # Selected from list
                    local device_index=$((choice - 1))
                    SELECTED_BLE_DEVICE="${device_addresses[$device_index]}"
                    SELECTED_BLE_NAME="${device_names[$device_index]}"
                    return 0
                fi
            else
                print_error "Invalid choice. Please enter a number between 0 and $((device_count + 1))"
            fi
        done
    else
        print_warning "Failed to scan for BLE devices using meshcore library"
        if [ -f /tmp/ble_scan_error ]; then
            local error_msg=$(cat /tmp/ble_scan_error)
            if [ -n "$error_msg" ]; then
                print_info "Error details: $error_msg"
            fi
            rm -f /tmp/ble_scan_error
        fi
 /tmp/device_list
        return 1
    fi
}

# Check BLE pairing status and handle pairing if needed
handle_ble_pairing() {
    local device_address="$1"
    local device_name="$2"
    
    echo ""
    print_info "Checking BLE pairing status for $device_name ($device_address)..."
    
    # Debug: Show the actual values being passed
    if [ -z "$device_name" ] || [ -z "$device_address" ]; then
        print_error "Invalid device information: name='$device_name', address='$device_address'"
        return 1
    fi
    
    # Use the actual ble_pairing_helper.py script instead of embedded code
    local temp_script="$INSTALL_DIR/ble_pairing_helper.py"
    
    # Check if script exists
    if [ ! -f "$temp_script" ]; then
        print_error "BLE pairing helper script not found at $temp_script"
        print_info "This should have been installed earlier. Continuing without pairing check..."
        return 1
    fi
    
    # Determine which Python to use (prefer venv if it exists, otherwise system)
    local python_cmd="python3"
    if [ -f "$INSTALL_DIR/venv/bin/python3" ]; then
        python_cmd="$INSTALL_DIR/venv/bin/python3"
        print_info "Using virtual environment Python"
    else
        print_info "Using system Python (venv not yet created)"
    fi
    
    # Check if dependencies are available (meshcore and bleak)
    if ! "$python_cmd" -c "import meshcore, bleak" 2>/dev/null; then
        print_warning "BLE dependencies (meshcore/bleak) not yet installed"
        print_info "The virtual environment will be set up after device configuration."
        print_info "You may need to pair the device manually, or re-run the installer after dependencies are installed."
        return 1
    fi
    
    # Pre-pairing disconnect to ensure device is available
    if command -v bluetoothctl &> /dev/null; then
        print_info "Ensuring device is disconnected before pairing check..."
        bluetoothctl disconnect "$device_address" 2>/dev/null || true
        print_info "Waiting for device to become available..."
        sleep 5  # Increased wait time for device to become available
    fi
    
    # Quick pairing check first (shorter timeout - if already paired, we're done)
    local pairing_output
    print_info "Checking if device is already paired..."
    print_info "Device: $device_name ($device_address)"
    
    # Run with explicit stderr redirection and capture
    rm -f /tmp/ble_pairing_error
    
    # Quick check with shorter timeout - just to see if already paired
    if pairing_output=$(timeout 15 "$python_cmd" "$temp_script" "$device_address" "$device_name" 2>/tmp/ble_pairing_error); then
        local pairing_status=$(echo "$pairing_output" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data['status'])" 2>/dev/null)
        
        if [ "$pairing_status" = "paired" ]; then
            print_success "Device is already paired and ready to use"
            rm -f /tmp/ble_pairing_error
            return 0
        fi
        # If not paired, fall through to pairing attempt below
    fi
    
    # If check failed or device not paired, proceed directly to pairing with PIN
    echo ""
    print_info "Device needs to be paired. You'll need to enter the PIN displayed on your MeshCore device."
    print_info "Make sure your device is powered on and showing the 6-digit PIN."
    echo ""
    
    # Get PIN from user
    local pin
    while true; do
        pin=$(prompt_input "Enter the 6-digit PIN displayed on your MeshCore device" "")
        if [[ "$pin" =~ ^[0-9]{6}$ ]]; then
            break
        else
            print_error "Please enter a 6-digit PIN (numbers only)"
        fi
    done
    
    # Attempt pairing with PIN
    echo ""
    print_info "Attempting to pair with device (this may take up to 60 seconds)..."
    rm -f /tmp/ble_pairing_error
    if pairing_output=$(timeout 60 "$python_cmd" "$temp_script" "$device_address" "$device_name" "$pin" 2>/tmp/ble_pairing_error); then
        local pairing_result=$(echo "$pairing_output" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data['status'])" 2>/dev/null)
        
        if [ "$pairing_result" = "paired" ]; then
            print_success "BLE pairing successful! Device is now ready to use."
            rm -f /tmp/ble_pairing_error
            return 0
        else
            print_error "BLE pairing failed"
            if [ -f /tmp/ble_pairing_error ]; then
                local error_msg=$(cat /tmp/ble_pairing_error)
                if [ -n "$error_msg" ]; then
                    print_info "Error details: $error_msg"
                fi
                rm -f /tmp/ble_pairing_error
            fi
            return 1
        fi
    else
        # Check if it was a timeout or other error
        if [ -f /tmp/ble_pairing_error ]; then
            local error_msg=$(cat /tmp/ble_pairing_error)
            if [[ "$error_msg" == *"timeout"* ]] || [[ "$error_msg" == *"Terminated"* ]]; then
                print_error "BLE pairing timed out"
                print_info "The pairing process took too long. The device may be busy or not responding."
                print_info "Make sure:"
                print_info "  • The device is powered on and showing the PIN"
                print_info "  • The device is in pairing mode"
                print_info "  • You entered the correct 6-digit PIN"
                print_info "  • The device is within range"
            elif [[ "$error_msg" == *"not found"* ]] || [[ "$error_msg" == *"not available"* ]]; then
                print_error "Device not found or not available"
                print_info "Make sure your MeshCore device is:"
                print_info "  • Powered on and within range"
                print_info "  • In pairing mode"
                print_info "  • Not connected to another device"
            else
                print_error "Failed to pair with device"
                if [ -n "$error_msg" ]; then
                    print_info "Error details: $error_msg"
                fi
            fi
            rm -f /tmp/ble_pairing_error
        else
            print_error "Failed to pair with device - no error details available"
        fi
        return 1
    fi
}

# Select connection type and configure device
select_connection_type() {
    echo ""
    print_header "Device Connection Configuration"
    echo ""
    print_info "How would you like to connect to your MeshCore device?"
    echo ""
    echo "  1) Bluetooth Low Energy (BLE) - Recommended for T1000 devices"
    echo "     • Wireless connection"
    echo "     • Works with MeshCore T1000e and compatible devices"
    echo ""
    echo "  2) Serial Connection - For devices with USB/serial interface"
    echo "     • Direct USB or serial cable connection"
    echo "     • More reliable for continuous operation"
    echo ""
    echo "  3) TCP Connection - For network-connected devices"
    echo "     • Connect to your node over the network"
    echo "     • Works with ser2net or other TCP-to-serial bridges"
    echo ""
    
    while true; do
        local choice=$(prompt_input "Select connection type [1-3]" "1")
        case $choice in
            1)
                CONNECTION_TYPE="ble"
                print_info "Selected: Bluetooth Low Energy (BLE)"
                echo ""
                
                if prompt_yes_no "Would you like to scan for nearby BLE devices?" "y"; then
                    while true; do
                        if scan_ble_devices; then
                            # Device selected, now handle pairing
                            if handle_ble_pairing "$SELECTED_BLE_DEVICE" "$SELECTED_BLE_NAME"; then
                                print_success "BLE device configured and paired: $SELECTED_BLE_NAME ($SELECTED_BLE_DEVICE)"
                                break
                            else
                                print_error "BLE pairing failed. Please try selecting a different device or check your device."
                                continue
                            fi
                        elif [ $? -eq 2 ]; then
                            # Rescan requested, continue the loop
                            continue
                        else
                            # Fallback to manual entry
                            print_info "BLE scanning failed or no devices found. Please enter device details manually."
                            SELECTED_BLE_DEVICE=$(prompt_input "Enter BLE device MAC address" "")
                            SELECTED_BLE_NAME=$(prompt_input "Enter device name (optional)" "")
                            if [ -n "$SELECTED_BLE_DEVICE" ]; then
                                # Handle pairing for manually entered device
                                if handle_ble_pairing "$SELECTED_BLE_DEVICE" "$SELECTED_BLE_NAME"; then
                                    print_success "BLE device configured and paired: $SELECTED_BLE_NAME ($SELECTED_BLE_DEVICE)"
                                    break
                                else
                                    print_error "BLE pairing failed. Please check your device and try again."
                                    continue
                                fi
                            else
                                print_error "No BLE device configured"
                                continue
                            fi
                        fi
                    done
                else
                    # Manual entry without scanning
                    SELECTED_BLE_DEVICE=$(prompt_input "Enter BLE device MAC address" "")
                    SELECTED_BLE_NAME=$(prompt_input "Enter device name (optional)" "")
                    if [ -n "$SELECTED_BLE_DEVICE" ]; then
                        # Handle pairing for manually entered device
                        if handle_ble_pairing "$SELECTED_BLE_DEVICE" "$SELECTED_BLE_NAME"; then
                            print_success "BLE device configured and paired: $SELECTED_BLE_NAME ($SELECTED_BLE_DEVICE)"
                        else
                            print_error "BLE pairing failed. Please check your device and try again."
                            continue
                        fi
                    else
                        print_error "No BLE device configured"
                        continue
                    fi
                fi
                break
                ;;
            2)
                CONNECTION_TYPE="serial"
                print_info "Selected: Serial Connection"
                echo ""
                select_serial_device
                break
                ;;
            3)
                CONNECTION_TYPE="tcp"
                print_info "Selected: TCP Connection"
                echo ""
                configure_tcp_connection
                break
                ;;
            *)
                print_error "Invalid choice. Please enter 1, 2, or 3"
                ;;
        esac
    done
}

# Interactive device selection
# Sets SELECTED_SERIAL_DEVICE variable
select_serial_device() {
    local devices=()
    # Use readarray instead of mapfile for better compatibility
    if command -v readarray >/dev/null 2>&1; then
        readarray -t devices < <(detect_serial_devices)
    else
        # Fallback for systems without readarray
        while IFS= read -r line; do
            devices+=("$line")
        done < <(detect_serial_devices)
    fi
    
    echo ""
    print_header "Serial Device Selection"
    echo ""
    
    if [ ${#devices[@]} -eq 0 ]; then
        print_warning "No serial devices detected"
        echo ""
        echo "  1) Enter path manually"
        echo ""
        local choice=$(prompt_input "Select option [1]" "1")
        SELECTED_SERIAL_DEVICE=$(prompt_input "Enter serial device path" "/dev/ttyACM0")
        return
    fi
    
    if [ ${#devices[@]} -eq 1 ]; then
        print_info "Found 1 serial device:"
    else
        print_info "Found ${#devices[@]} serial devices:"
    fi
    echo ""
    
    local i=1
    for device in "${devices[@]}"; do
        # Try to get device info
        local info=""
        if [ "$(uname)" = "Darwin" ]; then
            # macOS: device name is usually descriptive
            info="$device"
        else
            # Linux: show both by-id path and resolved device
            if [[ "$device" == /dev/serial/by-id/* ]]; then
                local resolved=$(readlink -f "$device" 2>/dev/null)
                info="$device -> $resolved"
            else
                info="$device"
            fi
        fi
        echo "  $i) $info"
        ((i++))
    done
    
    echo "  $i) Enter path manually"
    echo ""
    
    while true; do
        local choice=$(prompt_input "Select device [1-$i]" "1")
        
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le $i ]; then
            if [ "$choice" -eq $i ]; then
                # Manual entry
                SELECTED_SERIAL_DEVICE=$(prompt_input "Enter serial device path" "/dev/ttyACM0")
                return
            else
                # Selected from list
                SELECTED_SERIAL_DEVICE="${devices[$((choice-1))]}"
                return
            fi
        else
            print_error "Invalid selection. Please enter a number between 1 and $i"
        fi
    done
}

# Configure TCP connection
configure_tcp_connection() {
    echo ""
    print_header "TCP Connection Configuration"
    echo ""
    print_info "TCP connections work with ser2net or other TCP-to-serial bridges"
    print_info "This allows you to access serial devices over the network"
    echo ""
    
    TCP_HOST=$(prompt_input "TCP host/address" "localhost")
    TCP_PORT=$(prompt_input "TCP port" "5000")
    
    # Validate port number
    if ! [[ "$TCP_PORT" =~ ^[0-9]+$ ]] || [ "$TCP_PORT" -lt 1 ] || [ "$TCP_PORT" -gt 65535 ]; then
        print_error "Invalid port number. Using default port 5000"
        TCP_PORT="5000"
    fi
    
    print_success "TCP connection configured: $TCP_HOST:$TCP_PORT"
    echo ""
}

prompt_yes_no() {
    local prompt="$1"
    local default="${2:-n}"
    local response
    
    if [ "$default" = "y" ]; then
        prompt="$prompt [Y/n]: "
    else
        prompt="$prompt [y/N]: "
    fi
    
    # Read from /dev/tty to work when stdin is piped
    read -p "$prompt" response </dev/tty
    response=${response:-$default}
    
    case "$response" in
        [yY][eE][sS]|[yY]) return 0 ;;
        *) return 1 ;;
    esac
}

prompt_input() {
    local prompt="$1"
    local default="$2"
    local response
    
    # Read from /dev/tty to work when stdin is piped
    if [ -n "$default" ]; then
        read -p "$prompt [$default]: " response </dev/tty
        echo "${response:-$default}"
    else
        read -p "$prompt: " response </dev/tty
        echo "$response"
    fi
}

# Configure MQTT topics for a broker
configure_mqtt_topics() {
    local BROKER_NUM=$1
    ENV_LOCAL="$INSTALL_DIR/.env.local"
    
    echo ""
    print_header "MQTT Topic Configuration for Broker $BROKER_NUM"
    echo ""
    print_info "MQTT topics define where different types of data are published."
    print_info "You can use template variables: {IATA}, {IATA_lower}, {PUBLIC_KEY}"
    echo ""
    
    # Topic options
    echo "Choose topic configuration:"
    echo "  1) Default pattern (meshcore/{IATA}/{PUBLIC_KEY}/status, meshcore/{IATA}/{PUBLIC_KEY}/packets)"
    echo "  2) Classic pattern (meshcore/status, meshcore/packets, meshcore/raw)"
    echo "  3) Custom topics (enter your own)"
    echo ""
    
    local topic_choice=$(prompt_input "Select topic configuration [1-3]" "1")
    
    case "$topic_choice" in
        1)
            # Default pattern (IATA + PUBLIC_KEY)
            echo "" >> "$ENV_LOCAL"
            echo "# MQTT Topics for Broker $BROKER_NUM - Default Pattern" >> "$ENV_LOCAL"
            echo "PACKETCAPTURE_MQTT${BROKER_NUM}_TOPIC_STATUS=meshcore/{IATA}/{PUBLIC_KEY}/status" >> "$ENV_LOCAL"
            echo "PACKETCAPTURE_MQTT${BROKER_NUM}_TOPIC_PACKETS=meshcore/{IATA}/{PUBLIC_KEY}/packets" >> "$ENV_LOCAL"
            print_success "Default pattern topics configured"
            ;;
        2)
            # Classic pattern (simple meshcore topics, needed for map.w0z.is)
            echo "" >> "$ENV_LOCAL"
            echo "# MQTT Topics for Broker $BROKER_NUM - Classic Pattern" >> "$ENV_LOCAL"
            echo "PACKETCAPTURE_MQTT${BROKER_NUM}_TOPIC_STATUS=meshcore/status" >> "$ENV_LOCAL"
            echo "PACKETCAPTURE_MQTT${BROKER_NUM}_TOPIC_PACKETS=meshcore/packets" >> "$ENV_LOCAL"
            echo "PACKETCAPTURE_MQTT${BROKER_NUM}_TOPIC_RAW=meshcore/raw" >> "$ENV_LOCAL"
            print_success "Classic pattern topics configured"
            ;;
        3)
            # Custom topics
            echo ""
            print_info "Enter custom topic paths (use {IATA}, {IATA_lower}, {PUBLIC_KEY} for templates)"
            print_info "You can also manually edit the .env.local file after installation to customize topics"
            echo ""
            
            local status_topic=$(prompt_input "Status topic" "meshcore/{IATA}/{PUBLIC_KEY}/status")
            local packets_topic=$(prompt_input "Packets topic" "meshcore/{IATA}/{PUBLIC_KEY}/packets")
            
            echo "" >> "$ENV_LOCAL"
            echo "# MQTT Topics for Broker $BROKER_NUM - Custom" >> "$ENV_LOCAL"
            echo "PACKETCAPTURE_MQTT${BROKER_NUM}_TOPIC_STATUS=$status_topic" >> "$ENV_LOCAL"
            echo "PACKETCAPTURE_MQTT${BROKER_NUM}_TOPIC_PACKETS=$packets_topic" >> "$ENV_LOCAL"
            print_success "Custom topics configured"
            ;;
        *)
            print_error "Invalid choice, using default pattern"
            echo "" >> "$ENV_LOCAL"
            echo "# MQTT Topics for Broker $BROKER_NUM - Default Pattern" >> "$ENV_LOCAL"
            echo "PACKETCAPTURE_MQTT${BROKER_NUM}_TOPIC_STATUS=meshcore/{IATA}/{PUBLIC_KEY}/status" >> "$ENV_LOCAL"
            echo "PACKETCAPTURE_MQTT${BROKER_NUM}_TOPIC_PACKETS=meshcore/{IATA}/{PUBLIC_KEY}/packets" >> "$ENV_LOCAL"
            ;;
    esac
}

# Configure MQTT brokers only (skip device configuration)
configure_mqtt_brokers_only() {
    ENV_LOCAL="$INSTALL_DIR/.env.local"
    
    # Get IATA from existing config
    IATA=$(grep "^PACKETCAPTURE_IATA=" "$ENV_LOCAL" 2>/dev/null | cut -d'=' -f2)
    
    # Always prompt for IATA if it's XXX or empty
    if [ -z "$IATA" ] || [ "$IATA" = "XXX" ]; then
        echo ""
        print_info "IATA code is a 3-letter airport code identifying your geographic region"
        print_info "Example: SEA (Seattle), LAX (Los Angeles), NYC (New York), LON (London)"
        echo ""
        
        while [ -z "$IATA" ] || [ "$IATA" = "XXX" ]; do
            IATA=$(prompt_input "Enter your IATA code (3 letters)" "")
            IATA=$(echo "$IATA" | tr '[:lower:]' '[:upper:]' | tr -d ' ')
            
            if [ -z "$IATA" ]; then
                print_error "IATA code cannot be empty"
            elif [ "$IATA" = "XXX" ]; then
                print_error "Please enter your actual IATA code, not XXX"
            elif [ ${#IATA} -ne 3 ]; then
                print_warning "IATA code should be 3 letters, you entered: $IATA"
                if ! prompt_yes_no "Use '$IATA' anyway?" "n"; then
                    IATA="XXX"  # Reset to force re-prompt
                fi
            fi
        done
        
        # Update IATA in config
        sed -i.bak "s/^PACKETCAPTURE_IATA=.*/PACKETCAPTURE_IATA=$IATA/" "$ENV_LOCAL"
        rm -f "$ENV_LOCAL.bak"
        echo ""
        print_success "IATA code set to: $IATA"
        echo ""
    fi
    
    echo ""
    print_header "MQTT Broker Configuration"
    echo ""
    print_info "Enable the LetsMesh.net Packet Analyzer (US + EU servers) brokers?"
    echo "  • Real-time packet analysis and visualization"
    echo "  • Network health monitoring"
    echo "  • Redundant servers: mqtt-us-v1.letsmesh.net + mqtt-eu-v1.letsmesh.net"
    echo "  • Requires meshcore-decoder for authentication"
    echo ""
    
    if [ "$DECODER_AVAILABLE" = true ]; then
        if prompt_yes_no "Enable LetsMesh Packet Analyzer with redundancy?" "y"; then
            cat >> "$ENV_LOCAL" << EOF

# MQTT Broker 1 - LetsMesh.net Packet Analyzer (US)
PACKETCAPTURE_MQTT1_ENABLED=true
PACKETCAPTURE_MQTT1_SERVER=mqtt-us-v1.letsmesh.net
PACKETCAPTURE_MQTT1_PORT=443
PACKETCAPTURE_MQTT1_TRANSPORT=websockets
PACKETCAPTURE_MQTT1_USE_TLS=true
PACKETCAPTURE_MQTT1_USE_AUTH_TOKEN=true
PACKETCAPTURE_MQTT1_TOKEN_AUDIENCE=mqtt-us-v1.letsmesh.net
PACKETCAPTURE_MQTT1_KEEPALIVE=120

# MQTT Broker 2 - LetsMesh.net Packet Analyzer (EU)
PACKETCAPTURE_MQTT2_ENABLED=true
PACKETCAPTURE_MQTT2_SERVER=mqtt-eu-v1.letsmesh.net
PACKETCAPTURE_MQTT2_PORT=443
PACKETCAPTURE_MQTT2_TRANSPORT=websockets
PACKETCAPTURE_MQTT2_USE_TLS=true
PACKETCAPTURE_MQTT2_USE_AUTH_TOKEN=true
PACKETCAPTURE_MQTT2_TOKEN_AUDIENCE=mqtt-eu-v1.letsmesh.net
PACKETCAPTURE_MQTT2_KEEPALIVE=120
EOF
            print_success "LetsMesh Packet Analyzer enabled with redundancy"
            
            # Configure topics for LetsMesh
            configure_mqtt_topics 1
            
            if prompt_yes_no "Would you like to configure additional MQTT brokers?" "n"; then
                configure_additional_brokers
            fi
        else
            # User declined LetsMesh, ask if they want to configure a custom broker
            if prompt_yes_no "Would you like to configure a custom MQTT broker?" "y"; then
                configure_custom_broker 1
                
                if prompt_yes_no "Would you like to configure additional MQTT brokers?" "n"; then
                    configure_additional_brokers
                fi
            else
                print_warning "No MQTT brokers configured - you'll need to edit .env.local manually"
            fi
        fi
    else
        # No decoder available, can't use LetsMesh
        print_warning "meshcore-decoder not available - cannot use LetsMesh auth token authentication"
        
        if prompt_yes_no "Would you like to configure a custom MQTT broker with username/password?" "y"; then
            configure_custom_broker 1
            
            if prompt_yes_no "Would you like to configure additional MQTT brokers?" "n"; then
                configure_additional_brokers
            fi
        else
            print_warning "No MQTT brokers configured - you'll need to edit .env.local manually"
        fi
    fi
}

# Configure MQTT brokers
configure_mqtt_brokers() {
    ENV_LOCAL="$INSTALL_DIR/.env.local"
    
    # Ensure .env.local exists with update source info
    if [ ! -f "$ENV_LOCAL" ]; then
        # Interactive device selection
        select_connection_type
        
        cat > "$ENV_LOCAL" << EOF
# MeshCore Packet Capture Configuration
# This file contains your local overrides to the defaults in .env

# Update source (configured by installer)
PACKETCAPTURE_UPDATE_REPO=$REPO
PACKETCAPTURE_UPDATE_BRANCH=$BRANCH

# Connection Configuration
PACKETCAPTURE_CONNECTION_TYPE=$CONNECTION_TYPE
EOF

        # Add device-specific configuration
        case $CONNECTION_TYPE in
            "ble")
                echo "PACKETCAPTURE_BLE_DEVICE=$SELECTED_BLE_DEVICE" >> "$ENV_LOCAL"
                if [ -n "$SELECTED_BLE_NAME" ]; then
                    echo "PACKETCAPTURE_BLE_NAME=$SELECTED_BLE_NAME" >> "$ENV_LOCAL"
                fi
                ;;
            "serial")
                echo "PACKETCAPTURE_SERIAL_PORTS=$SELECTED_SERIAL_DEVICE" >> "$ENV_LOCAL"
                ;;
            "tcp")
                echo "PACKETCAPTURE_TCP_HOST=$TCP_HOST" >> "$ENV_LOCAL"
                echo "PACKETCAPTURE_TCP_PORT=$TCP_PORT" >> "$ENV_LOCAL"
                ;;
        esac
        
        cat >> "$ENV_LOCAL" << EOF

# Location Code
PACKETCAPTURE_IATA=XXX

# Advert Settings
PACKETCAPTURE_ADVERT_INTERVAL_HOURS=11

# Logging Settings
PACKETCAPTURE_LOG_LEVEL=INFO
EOF
    fi
    
    # Get IATA from existing config
    IATA=$(grep "^PACKETCAPTURE_IATA=" "$ENV_LOCAL" 2>/dev/null | cut -d'=' -f2)
    
    # Always prompt for IATA if it's XXX or empty
    if [ -z "$IATA" ] || [ "$IATA" = "XXX" ]; then
        echo ""
        print_info "IATA code is a 3-letter airport code identifying your geographic region"
        print_info "Example: SEA (Seattle), LAX (Los Angeles), NYC (New York), LON (London)"
        echo ""
        
        while [ -z "$IATA" ] || [ "$IATA" = "XXX" ]; do
            IATA=$(prompt_input "Enter your IATA code (3 letters)" "")
            IATA=$(echo "$IATA" | tr '[:lower:]' '[:upper:]' | tr -d ' ')
            
            if [ -z "$IATA" ]; then
                print_error "IATA code cannot be empty"
            elif [ "$IATA" = "XXX" ]; then
                print_error "Please enter your actual IATA code, not XXX"
            elif [ ${#IATA} -ne 3 ]; then
                print_warning "IATA code should be 3 letters, you entered: $IATA"
                if ! prompt_yes_no "Use '$IATA' anyway?" "n"; then
                    IATA="XXX"  # Reset to force re-prompt
                fi
            fi
        done
        
        # Update IATA in config
        sed -i.bak "s/^PACKETCAPTURE_IATA=.*/PACKETCAPTURE_IATA=$IATA/" "$ENV_LOCAL"
        rm -f "$ENV_LOCAL.bak"
        echo ""
        print_success "IATA code set to: $IATA"
        echo ""
    fi
    
    echo ""
    print_header "MQTT Broker Configuration"
    echo ""
    print_info "Enable the LetsMesh.net Packet Analyzer (US + EU servers) for redundancy?"
    echo "  • Real-time packet analysis and visualization"
    echo "  • Network health monitoring"
    echo "  • Redundant servers: mqtt-us-v1.letsmesh.net + mqtt-eu-v1.letsmesh.net"
    echo "  • Requires meshcore-decoder for authentication"
    echo ""
    
    if [ "$DECODER_AVAILABLE" = true ]; then
        if prompt_yes_no "Enable LetsMesh Packet Analyzer with redundancy?" "y"; then
            cat >> "$ENV_LOCAL" << EOF

# MQTT Broker 1 - LetsMesh.net Packet Analyzer (US)
PACKETCAPTURE_MQTT1_ENABLED=true
PACKETCAPTURE_MQTT1_SERVER=mqtt-us-v1.letsmesh.net
PACKETCAPTURE_MQTT1_PORT=443
PACKETCAPTURE_MQTT1_TRANSPORT=websockets
PACKETCAPTURE_MQTT1_USE_TLS=true
PACKETCAPTURE_MQTT1_USE_AUTH_TOKEN=true
PACKETCAPTURE_MQTT1_TOKEN_AUDIENCE=mqtt-us-v1.letsmesh.net
PACKETCAPTURE_MQTT1_KEEPALIVE=120

# MQTT Broker 2 - LetsMesh.net Packet Analyzer (EU)
PACKETCAPTURE_MQTT2_ENABLED=true
PACKETCAPTURE_MQTT2_SERVER=mqtt-eu-v1.letsmesh.net
PACKETCAPTURE_MQTT2_PORT=443
PACKETCAPTURE_MQTT2_TRANSPORT=websockets
PACKETCAPTURE_MQTT2_USE_TLS=true
PACKETCAPTURE_MQTT2_USE_AUTH_TOKEN=true
PACKETCAPTURE_MQTT2_TOKEN_AUDIENCE=mqtt-eu-v1.letsmesh.net
PACKETCAPTURE_MQTT2_KEEPALIVE=120
EOF
            print_success "LetsMesh Packet Analyzer brokers enabled"
            
            # Configure topics for LetsMesh
            configure_mqtt_topics 1
            
            if prompt_yes_no "Would you like to configure additional MQTT brokers?" "n"; then
                configure_additional_brokers
            fi
        else
            # User declined LetsMesh, ask if they want to configure a custom broker
            if prompt_yes_no "Would you like to configure a custom MQTT broker?" "y"; then
                configure_custom_broker 1
                
                if prompt_yes_no "Would you like to configure additional MQTT brokers?" "n"; then
                    configure_additional_brokers
                fi
            else
                print_warning "No MQTT brokers configured - you'll need to edit .env.local manually"
            fi
        fi
    else
        # No decoder available, can't use LetsMesh
        print_warning "meshcore-decoder not available - cannot use LetsMesh auth token authentication"
        
        if prompt_yes_no "Would you like to configure a custom MQTT broker with username/password?" "y"; then
            configure_custom_broker 1
            
            if prompt_yes_no "Would you like to configure additional MQTT brokers?" "n"; then
                configure_additional_brokers
            fi
        else
            print_warning "No MQTT brokers configured - you'll need to edit .env.local manually"
        fi
    fi
}

# Configure additional brokers (starting from MQTT2)
configure_additional_brokers() {
    # Find next available broker number
    NEXT_BROKER=2
    while grep -q "^PACKETCAPTURE_MQTT${NEXT_BROKER}_ENABLED=" "$INSTALL_DIR/.env.local" 2>/dev/null; do
        NEXT_BROKER=$((NEXT_BROKER + 1))
    done
    
    NUM_ADDITIONAL=$(prompt_input "How many additional brokers?" "1")
    
    for i in $(seq 1 $NUM_ADDITIONAL); do
        BROKER_NUM=$((NEXT_BROKER + i - 1))
        configure_custom_broker $BROKER_NUM
    done
}

# Configure a single custom MQTT broker
configure_custom_broker() {
    local BROKER_NUM=$1
    ENV_LOCAL="$INSTALL_DIR/.env.local"
    
    echo ""
    print_header "Configuring MQTT Broker $BROKER_NUM"
    
    SERVER=$(prompt_input "Server hostname/IP")
    if [ -z "$SERVER" ]; then
        print_warning "Server hostname required - skipping broker $BROKER_NUM"
        return
    fi
    
    echo "" >> "$ENV_LOCAL"
    echo "# MQTT Broker $BROKER_NUM" >> "$ENV_LOCAL"
    echo "PACKETCAPTURE_MQTT${BROKER_NUM}_ENABLED=true" >> "$ENV_LOCAL"
    echo "PACKETCAPTURE_MQTT${BROKER_NUM}_SERVER=$SERVER" >> "$ENV_LOCAL"
    
    PORT=$(prompt_input "Port" "1883")
    echo "PACKETCAPTURE_MQTT${BROKER_NUM}_PORT=$PORT" >> "$ENV_LOCAL"
    
    # Transport
    if prompt_yes_no "Use WebSockets transport?" "n"; then
        echo "PACKETCAPTURE_MQTT${BROKER_NUM}_TRANSPORT=websockets" >> "$ENV_LOCAL"
    fi
    
    # TLS
    if prompt_yes_no "Use TLS/SSL encryption?" "n"; then
        echo "PACKETCAPTURE_MQTT${BROKER_NUM}_USE_TLS=true" >> "$ENV_LOCAL"
        
        if ! prompt_yes_no "Verify TLS certificates?" "y"; then
            echo "PACKETCAPTURE_MQTT${BROKER_NUM}_TLS_VERIFY=false" >> "$ENV_LOCAL"
        fi
    fi
    
    # Authentication
    echo ""
    print_info "Authentication method:"
    echo "  1) Username/Password"
    echo "  2) MeshCore Auth Token (requires meshcore-decoder)"
    echo "  3) None (anonymous)"
    AUTH_TYPE=$(prompt_input "Choose authentication method [1-3]" "1")
    
    if [ "$AUTH_TYPE" = "2" ]; then
        if [ "$DECODER_AVAILABLE" = false ]; then
            print_error "meshcore-decoder not available - using username/password instead"
            AUTH_TYPE=1
        else
            echo "PACKETCAPTURE_MQTT${BROKER_NUM}_USE_AUTH_TOKEN=true" >> "$ENV_LOCAL"
            TOKEN_AUDIENCE=$(prompt_input "Token audience (optional)" "")
            if [ -n "$TOKEN_AUDIENCE" ]; then
                echo "PACKETCAPTURE_MQTT${BROKER_NUM}_TOKEN_AUDIENCE=$TOKEN_AUDIENCE" >> "$ENV_LOCAL"
            fi
        fi
    fi
    
    if [ "$AUTH_TYPE" = "1" ]; then
        USERNAME=$(prompt_input "Username" "")
        if [ -n "$USERNAME" ]; then
            echo "PACKETCAPTURE_MQTT${BROKER_NUM}_USERNAME=$USERNAME" >> "$ENV_LOCAL"
            PASSWORD=$(prompt_input "Password" "")
            if [ -n "$PASSWORD" ]; then
                echo "PACKETCAPTURE_MQTT${BROKER_NUM}_PASSWORD=$PASSWORD" >> "$ENV_LOCAL"
            fi
        fi
    fi
    
    print_success "Broker $BROKER_NUM configured"
    
    # Configure topics for this broker
    configure_mqtt_topics $BROKER_NUM
}

# Check for old installations
check_old_installation() {
    # Check for old systemd service
    if [ -f /etc/systemd/system/meshcore-capture.service ]; then
        local working_dir=$(grep "WorkingDirectory=" /etc/systemd/system/meshcore-capture.service 2>/dev/null | cut -d'=' -f2)
        
        if [ -n "$working_dir" ] && [ "$working_dir" != "$HOME/.meshcore-packet-capture" ]; then
            echo ""
            print_warning "Old meshcore-capture systemd service detected at: $working_dir"
            echo ""
            
            if prompt_yes_no "Would you like to stop and remove the old service?" "y"; then
                if sudo systemctl stop meshcore-capture.service && sudo systemctl disable meshcore-capture.service && sudo rm -f /etc/systemd/system/meshcore-capture.service && sudo systemctl daemon-reload; then
                    print_success "Old service removed"
                else
                    print_error "Failed to remove old service - please remove manually"
                fi
            else
                print_warning "Old service left in place - may conflict with new installation"
            fi
            echo ""
        fi
    fi
    
    # Check for launchd on macOS
    if [ "$(uname)" = "Darwin" ]; then
        local plist_file="$HOME/Library/LaunchAgents/com.meshcore.packet-capture.plist"
        if [ -f "$plist_file" ] && ! grep -q "$HOME/.meshcore-packet-capture" "$plist_file" 2>/dev/null; then
            echo ""
            print_warning "Old meshcore-capture launchd service detected"
            echo ""
            
            if prompt_yes_no "Would you like to unload and remove the old service?" "y"; then
                launchctl unload "$plist_file" 2>/dev/null || true
                rm -f "$plist_file"
                print_success "Old service removed"
            else
                print_warning "Old service left in place - may conflict with new installation"
            fi
            echo ""
        fi
    fi
}

# Main installation function
main() {
    print_header "MeshCore Packet Capture Installer v${SCRIPT_VERSION}"
    
    echo "This installer will help you set up MeshCore Packet Capture."
    echo ""
    
    # Check for old installations and offer to clean up
    check_old_installation
    
    # Determine installation directory
    DEFAULT_INSTALL_DIR="$HOME/.meshcore-packet-capture"
    INSTALL_DIR=$(prompt_input "Installation directory" "$DEFAULT_INSTALL_DIR")
    INSTALL_DIR="${INSTALL_DIR/#\~/$HOME}"  # Expand tilde
    
    print_info "Installation directory: $INSTALL_DIR"
    
    # Check if directory exists
    UPDATING_EXISTING=false
    if [ -d "$INSTALL_DIR" ]; then
        if prompt_yes_no "Directory already exists. Reinstall/update?" "n"; then
            print_info "Updating existing installation..."
            UPDATING_EXISTING=true
        else
            print_error "Installation cancelled."
            exit 1
        fi
    fi
    
    # Create installation directory
    mkdir -p "$INSTALL_DIR"
    cd "$INSTALL_DIR"
    
    # Download or copy files
    print_header "Installing Files"
    
    if [ -n "${LOCAL_INSTALL}" ]; then
        # Local install for testing
        print_info "Installing from local directory: ${LOCAL_INSTALL}"
        cp "${LOCAL_INSTALL}/packet_capture.py" "$INSTALL_DIR/"
        cp "${LOCAL_INSTALL}/auth_token.py" "$INSTALL_DIR/"
        cp "${LOCAL_INSTALL}/enums.py" "$INSTALL_DIR/"
        cp "${LOCAL_INSTALL}/ble_pairing_helper.py" "$INSTALL_DIR/"
        cp "${LOCAL_INSTALL}/requirements.txt" "$INSTALL_DIR/"
        # meshcore_py no longer needed - using PyPI version
        if [ -f "${LOCAL_INSTALL}/.env" ]; then
            cp "${LOCAL_INSTALL}/.env" "$INSTALL_DIR/"
        fi
        if [ -f "${LOCAL_INSTALL}/.env.local" ]; then
            print_warning ".env.local found in source - copying as .env.local.example"
            cp "${LOCAL_INSTALL}/.env.local" "$INSTALL_DIR/.env.local.example"
        fi
        chmod +x "$INSTALL_DIR/packet_capture.py"
        
        # Create version info file
        create_version_info
        
        print_success "Files copied from local directory"
    else
        # Download from GitHub
        print_info "Downloading from GitHub ($REPO @ $BRANCH)..."
        
        BASE_URL="https://raw.githubusercontent.com/$REPO/$BRANCH"
        
        # Download to temp directory first for verification
        TMP_DIR=$(mktemp -d)
        trap "rm -rf $TMP_DIR" EXIT
        
        print_info "Downloading packet_capture.py..."
        if ! curl -fsSL --retry 3 --retry-delay 2 "$BASE_URL/packet_capture.py" -o "$TMP_DIR/packet_capture.py"; then
            print_error "Failed to download packet_capture.py from $REPO/$BRANCH"
            print_error "Please verify the repository and branch exist"
            exit 1
        fi
        
        print_info "Downloading auth_token.py..."
        if ! curl -fsSL --retry 3 --retry-delay 2 "$BASE_URL/auth_token.py" -o "$TMP_DIR/auth_token.py"; then
            print_error "Failed to download auth_token.py"
            exit 1
        fi
        
        print_info "Downloading enums.py..."
        if ! curl -fsSL --retry 3 --retry-delay 2 "$BASE_URL/enums.py" -o "$TMP_DIR/enums.py"; then
            print_error "Failed to download enums.py"
            exit 1
        fi
        
        print_info "Downloading ble_pairing_helper.py..."
        if ! curl -fsSL --retry 3 --retry-delay 2 "$BASE_URL/ble_pairing_helper.py" -o "$TMP_DIR/ble_pairing_helper.py"; then
            print_error "Failed to download ble_pairing_helper.py"
            exit 1
        fi
        
        print_info "Downloading requirements.txt..."
        if ! curl -fsSL --retry 3 --retry-delay 2 "$BASE_URL/requirements.txt" -o "$TMP_DIR/requirements.txt"; then
            print_error "Failed to download requirements.txt"
            exit 1
        fi
        
        # meshcore_py no longer needed - using PyPI version
        
        # Verify Python syntax before installing
        print_info "Verifying Python syntax..."
        if ! python3 -m py_compile "$TMP_DIR/packet_capture.py" 2>/dev/null; then
            print_error "Downloaded packet_capture.py has syntax errors"
            print_error "The repository may be in an inconsistent state"
            exit 1
        fi
        if ! python3 -m py_compile "$TMP_DIR/ble_pairing_helper.py" 2>/dev/null; then
            print_error "Downloaded ble_pairing_helper.py has syntax errors"
            print_error "The repository may be in an inconsistent state"
            exit 1
        fi
        
        # All downloads successful and verified, now install
        mv "$TMP_DIR/packet_capture.py" "$INSTALL_DIR/packet_capture.py"
        mv "$TMP_DIR/auth_token.py" "$INSTALL_DIR/auth_token.py"
        mv "$TMP_DIR/enums.py" "$INSTALL_DIR/enums.py"
        mv "$TMP_DIR/ble_pairing_helper.py" "$INSTALL_DIR/ble_pairing_helper.py"
        mv "$TMP_DIR/requirements.txt" "$INSTALL_DIR/requirements.txt"
        # meshcore_py no longer needed - using PyPI version
        
        chmod +x "$INSTALL_DIR/packet_capture.py"
        
        # Create version info file
        create_version_info
        
        print_success "Files downloaded and verified"
    fi
    
    # Check Python
    print_header "Checking Dependencies"
    
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is not installed. Please install Python 3 and try again."
        exit 1
    fi
    print_success "Python 3 found: $(python3 --version)"
    
    # Set up virtual environment
    print_info "Setting up Python virtual environment..."
    if [ ! -d "$INSTALL_DIR/venv" ]; then
        python3 -m venv "$INSTALL_DIR/venv"
        print_success "Virtual environment created"
    else
        print_success "Using existing virtual environment"
    fi
    
    # Install Python dependencies
    print_info "Installing Python dependencies..."
    source "$INSTALL_DIR/venv/bin/activate"
    pip install --quiet --upgrade pip
    pip install --quiet -r "$INSTALL_DIR/requirements.txt"
    # meshcore is now installed from PyPI via requirements.txt
    print_success "Python dependencies installed"
    
    # Check for meshcore-decoder (optional)
    if command -v meshcore-decoder &> /dev/null; then
        print_success "meshcore-decoder found: $(which meshcore-decoder)"
        DECODER_AVAILABLE=true
    else
        print_warning "meshcore-decoder not found (required for auth token authentication)"
        if prompt_yes_no "Would you like instructions to install it now?" "y"; then
            echo ""
            echo "To install meshcore-decoder, run:"
            echo "  curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash"
            echo "  # Restart your shell or run: source ~/.bashrc (or ~/.zshrc)"
            echo "  nvm install --lts"
            echo "  npm install -g @michaelhart/meshcore-decoder"
            echo ""
            if prompt_yes_no "Continue without meshcore-decoder (you can install it later)?" "y"; then
                DECODER_AVAILABLE=false
            else
                exit 1
            fi
        else
            DECODER_AVAILABLE=false
        fi
    fi
    
    # Configuration
    print_header "Configuration"
    
    # Check for existing config.ini and offer migration
    if [ -f "$INSTALL_DIR/config.ini" ] && [ ! -f "$INSTALL_DIR/.env.local" ]; then
        print_info "Found existing config.ini file"
        if prompt_yes_no "Would you like to migrate your config.ini to the new .env.local format?" "y"; then
            print_info "Migrating config.ini to .env.local..."
            if python3 "$INSTALL_DIR/migrate_config.py"; then
                print_success "Configuration migrated successfully"
                print_info "You can now remove config.ini if everything works correctly"
            else
                print_error "Migration failed, continuing with manual configuration"
            fi
        fi
    fi
    
    # Check if config URL was provided
    if [ -n "$CONFIG_URL" ]; then
        print_info "Downloading configuration from: $CONFIG_URL"
        if curl -fsSL "$CONFIG_URL" -o "$INSTALL_DIR/.env.local"; then
            print_success "Configuration downloaded successfully"
            
            # Convert MCTOMQTT_ prefixes to PACKETCAPTURE_ for compatibility
            if grep -q "MCTOMQTT_" "$INSTALL_DIR/.env.local"; then
                print_info "Converting MCTOMQTT_ prefixes to PACKETCAPTURE_ for compatibility..."
                sed -i.bak 's/^MCTOMQTT_/PACKETCAPTURE_/g' "$INSTALL_DIR/.env.local"
                rm -f "$INSTALL_DIR/.env.local.bak"
                print_success "Configuration converted successfully"
            fi
            
            # Show what was downloaded
            echo ""
            print_info "Downloaded configuration:"
            cat "$INSTALL_DIR/.env.local" | grep -v '^#' | grep -v '^$' | head -20
            if [ $(cat "$INSTALL_DIR/.env.local" | grep -v '^#' | grep -v '^$' | wc -l) -gt 20 ]; then
                echo "..."
            fi
            echo ""
            
            if prompt_yes_no "Use this configuration?" "y"; then
                print_success "Using downloaded configuration"
                
                # Always prompt for IATA
                echo ""
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                print_warning "IATA CODE REQUIRED"
                echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                echo ""
                print_info "IATA code is a 3-letter airport code and should match an airport near the reporting location"
                print_info "Example: SEA (Seattle), LAX (Los Angeles), NYC (New York), LON (London)"
                echo ""
                
                # Try to extract existing IATA from config
                EXISTING_IATA=$(grep "^PACKETCAPTURE_IATA=" "$INSTALL_DIR/.env.local" 2>/dev/null | cut -d'=' -f2)
                
                IATA=""
                while [ -z "$IATA" ] || [ "$IATA" = "XXX" ]; do
                    if [ -n "$EXISTING_IATA" ] && [ "$EXISTING_IATA" != "XXX" ]; then
                        IATA=$(prompt_input "Enter your IATA code" "$EXISTING_IATA")
                    else
                        IATA=$(prompt_input "Enter your IATA code (3 letters)" "")
                    fi
                    IATA=$(echo "$IATA" | tr '[:lower:]' '[:upper:]' | tr -d ' ')
                    
                    if [ -z "$IATA" ]; then
                        print_error "IATA code cannot be empty"
                    elif [ "$IATA" = "XXX" ]; then
                        print_error "Please enter your actual IATA code, not XXX"
                    elif [ ${#IATA} -ne 3 ]; then
                        print_warning "IATA code should be 3 letters, you entered: $IATA"
                        if ! prompt_yes_no "Use '$IATA' anyway?" "n"; then
                            IATA=""
                        fi
                    fi
                done
                
                # Update IATA in config
                if grep -q "^PACKETCAPTURE_IATA=" "$INSTALL_DIR/.env.local"; then
                    sed -i.bak "s/^PACKETCAPTURE_IATA=.*/PACKETCAPTURE_IATA=$IATA/" "$INSTALL_DIR/.env.local"
                    rm -f "$INSTALL_DIR/.env.local.bak"
                else
                    echo "PACKETCAPTURE_IATA=$IATA" >> "$INSTALL_DIR/.env.local"
                fi
                echo ""
                print_success "IATA code set to: $IATA"
                echo ""
                
                # Check if MQTT1 is already configured and offer additional brokers
                if grep -q "^PACKETCAPTURE_MQTT1_ENABLED=true" "$INSTALL_DIR/.env.local" 2>/dev/null; then
                    MQTT1_SERVER=$(grep "^PACKETCAPTURE_MQTT1_SERVER=" "$INSTALL_DIR/.env.local" 2>/dev/null | cut -d'=' -f2)
                    echo ""
                    print_success "MQTT Broker 1 already configured: $MQTT1_SERVER"
                    
                    if prompt_yes_no "Would you like to configure additional MQTT brokers?" "n"; then
                        configure_additional_brokers
                    fi
                else
                    # No MQTT configured, offer options
                    configure_mqtt_brokers
                fi
            else
                rm -f "$INSTALL_DIR/.env.local"
                configure_mqtt_brokers
            fi
        else
            print_error "Failed to download configuration from URL"
            if prompt_yes_no "Continue with interactive configuration?" "y"; then
                configure_mqtt_brokers
            else
                exit 1
            fi
        fi
    elif [ "$UPDATING_EXISTING" = true ] && [ -f "$INSTALL_DIR/.env.local" ]; then
        if prompt_yes_no "Existing configuration found. Reconfigure?" "n"; then
            # Back up existing config before reconfiguring
            cp "$INSTALL_DIR/.env.local" "$INSTALL_DIR/.env.local.backup-$(date +%Y%m%d-%H%M%S)"
            rm -f "$INSTALL_DIR/.env.local"
            configure_mqtt_brokers
        else
            print_info "Keeping existing configuration"
            # Check if MQTT brokers are already configured
            if [ -f "$INSTALL_DIR/.env.local" ] && grep -q "^PACKETCAPTURE_MQTT[1-4]_ENABLED=true" "$INSTALL_DIR/.env.local" 2>/dev/null; then
                print_info "MQTT brokers already configured - skipping MQTT configuration"
            else
                # Debug: Show what we're checking
                if [ -f "$INSTALL_DIR/.env.local" ]; then
                    print_info "Checking for MQTT brokers in: $INSTALL_DIR/.env.local"
                    print_info "Found MQTT lines:"
                    grep "^PACKETCAPTURE_MQTT[1-4]_ENABLED=" "$INSTALL_DIR/.env.local" 2>/dev/null || echo "  (none found)"
                else
                    print_info "Configuration file not found: $INSTALL_DIR/.env.local"
                fi
                # Still need to configure MQTT brokers if not already configured
                configure_mqtt_brokers_only
            fi
        fi
    elif [ ! -f "$INSTALL_DIR/.env.local" ]; then
        configure_mqtt_brokers
    fi
    
    # Installation method selection
    print_header "Installation Method"
    
    echo "Choose your preferred installation method:"
    echo ""
    echo "  1) System Service (recommended for production)"
    echo "     • Runs automatically on boot"
    echo "     • Managed by systemd (Linux) or launchd (macOS)"
    echo "     • Automatic restart on failure"
    echo ""
    echo "  2) Docker Container (recommended for development/testing)"
    echo "     • Isolated environment"
    echo "     • Easy to update and manage"
    echo "     • Works on Linux, macOS, and Windows"
    echo ""
    echo "  3) Manual installation only"
    echo "     • No automatic startup"
    echo "     • Run manually when needed"
    echo ""
    
    INSTALL_METHOD=$(prompt_input "Choose installation method [1-3]" "1")
    
    case "$INSTALL_METHOD" in
        1)
            install_system_service
            ;;
        2)
            install_docker
            ;;
        3)
            print_info "Manual installation complete"
            print_info "To run manually: cd $INSTALL_DIR && ./venv/bin/python3 packet_capture.py"
            ;;
        *)
            print_error "Invalid selection"
            exit 1
            ;;
    esac
    
    # Final summary
    print_header "Installation Complete!"
    echo "Installation directory: $INSTALL_DIR"
    echo ""
    echo "Configuration file: $INSTALL_DIR/.env.local"
    echo ""
    
    if [ "$SERVICE_INSTALLED" = true ]; then
        case "$SYSTEM_TYPE" in
            systemd)
                echo "Service management:"
                echo "  Start:   sudo systemctl start meshcore-capture"
                echo "  Stop:    sudo systemctl stop meshcore-capture"
                echo "  Status:  sudo systemctl status meshcore-capture"
                echo "  Logs:    sudo journalctl -u meshcore-capture -f"
                echo ""
                echo "Resource monitoring:"
                echo "  CPU usage:  sudo systemctl show meshcore-capture --property=CPUUsageNSec"
                echo "  Memory:     sudo systemctl show meshcore-capture --property=MemoryCurrent"
                echo "  Tasks:      sudo systemctl show meshcore-capture --property=TasksCurrent"
                echo ""
echo "Resource limits (prevent runaway processes):"
echo "  Memory: 512MB limit"
echo "  CPU:     50% limit"
echo "  Tasks:   200 max"
echo ""
echo "Service failure handling:"
echo "  Max failures: 3 within 5 minutes"
echo "  Critical threshold: 5 total failures"
echo "  Auto-restart: systemd will restart on persistent failures"
                ;;
            launchd)
                echo "Service management:"
                echo "  Start:   launchctl start com.meshcore.packet-capture"
                echo "  Stop:    launchctl stop com.meshcore.packet-capture"
                echo "  Status:  launchctl list | grep packet-capture"
                echo "  Logs:    tail -f ~/Library/Logs/meshcore-capture.log"
                ;;
        esac
    elif [ "$DOCKER_INSTALLED" = true ]; then
        echo "Docker management:"
        echo "  Start:   $COMPOSE_CMD -f $INSTALL_DIR/docker-compose.yml up -d"
        echo "  Stop:    $COMPOSE_CMD -f $INSTALL_DIR/docker-compose.yml down"
        echo "  Logs:    $COMPOSE_CMD -f $INSTALL_DIR/docker-compose.yml logs -f"
        echo "  Status:  $COMPOSE_CMD -f $INSTALL_DIR/docker-compose.yml ps"
        echo ""
        echo "Resource monitoring:"
        echo "  Stats:   docker stats meshcore-packet-capture"
        echo "  Top:     docker exec meshcore-packet-capture top"
        echo ""
echo "Resource limits (prevent runaway processes):"
echo "  Memory: 512MB limit, 128MB reserved"
echo "  CPU:     50% limit,   10% reserved"
echo ""
echo "Service failure handling:"
echo "  Max failures: 3 within 5 minutes"
echo "  Critical threshold: 5 total failures"
echo "  Auto-restart: Docker will restart on persistent failures"
    else
        echo "Manual run: cd $INSTALL_DIR && ./venv/bin/python3 packet_capture.py"
    fi
    
    echo ""
    print_success "Installation complete!"
}

# Detect system type
detect_system_type() {
    if command -v systemctl &> /dev/null; then
        echo "systemd"
    elif [ "$(uname)" = "Darwin" ]; then
        echo "launchd"
    else
        echo "unknown"
    fi
}

# Install system service
install_system_service() {
    SYSTEM_TYPE=$(detect_system_type)
    print_info "Detected system type: $SYSTEM_TYPE"
    
    case "$SYSTEM_TYPE" in
        systemd)
            install_systemd_service
            ;;
        launchd)
            install_launchd_service
            ;;
        *)
            print_error "Unsupported system type: $SYSTEM_TYPE"
            print_info "You'll need to manually configure the service"
            SERVICE_INSTALLED=false
            return 1
            ;;
    esac
}

# Install systemd service (Linux)
install_systemd_service() {
    print_info "Installing systemd service..."
    
    local service_file="/tmp/meshcore-capture.service"
    local current_user=$(whoami)
    
    # Build PATH with meshcore-decoder if available
    local service_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    if command -v meshcore-decoder &> /dev/null; then
        local decoder_dir=$(dirname "$(which meshcore-decoder)")
        service_path="${decoder_dir}:${service_path}"
    fi
    
    cat > "$service_file" << EOF
[Unit]
Description=MeshCore Packet Capture
After=time-sync.target network.target
Wants=time-sync.target

[Service]
User=$current_user
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$service_path"
Environment="PACKETCAPTURE_MAX_ACTIVE_TASKS=50"
Environment="PACKETCAPTURE_JWT_CIRCUIT_BREAKER_FAILURES=3"
Environment="PACKETCAPTURE_JWT_CIRCUIT_BREAKER_TIMEOUT=180"
Environment="PACKETCAPTURE_MQTT_RETRY_DELAY_MAX=300"
Environment="PACKETCAPTURE_MQTT_RETRY_BACKOFF_MULTIPLIER=2.0"
Environment="PACKETCAPTURE_MQTT_RETRY_JITTER=true"
Environment="PACKETCAPTURE_CONNECTION_RETRY_DELAY_MAX=300"
Environment="PACKETCAPTURE_CONNECTION_RETRY_BACKOFF_MULTIPLIER=2.0"
Environment="PACKETCAPTURE_CONNECTION_RETRY_JITTER=true"

# Service failure tracking (let systemd restart on persistent failures)
Environment="PACKETCAPTURE_MAX_SERVICE_FAILURES=3"
Environment="PACKETCAPTURE_SERVICE_FAILURE_WINDOW=300"
Environment="PACKETCAPTURE_CRITICAL_FAILURE_THRESHOLD=5"
Environment="PACKETCAPTURE_MAX_CONSECUTIVE_FAILURES=3"
ExecStart=$INSTALL_DIR/venv/bin/python3 $INSTALL_DIR/packet_capture.py
ExecStop=/bin/bash -c 'if [ -f $INSTALL_DIR/.env.local ] && grep -q "PACKETCAPTURE_CONNECTION_TYPE=ble" $INSTALL_DIR/.env.local; then BLE_DEVICE=\$(grep "PACKETCAPTURE_BLE_DEVICE=" $INSTALL_DIR/.env.local | cut -d= -f2); if [ -n "\$BLE_DEVICE" ] && command -v bluetoothctl >/dev/null 2>&1; then echo "Disconnecting BLE device \$BLE_DEVICE..."; bluetoothctl disconnect "\$BLE_DEVICE" 2>/dev/null || true; sleep 2; fi; fi'
KillMode=process
Restart=on-failure
RestartSec=10
Type=exec

# Resource limits to prevent runaway processes
MemoryLimit=512M
CPUQuota=50%
TasksMax=200

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=meshcore-capture

[Install]
WantedBy=multi-user.target
EOF
    
    print_info "Service file created. Installing (requires sudo)..."
    
    if sudo cp "$service_file" /etc/systemd/system/meshcore-capture.service; then
        sudo systemctl daemon-reload
        
        if prompt_yes_no "Enable service to start on boot?" "y"; then
            sudo systemctl enable meshcore-capture.service
            print_success "Service enabled"
        fi
        
        if prompt_yes_no "Start service now?" "y"; then
            sudo systemctl start meshcore-capture.service
            
            print_info "Waiting for service to start..."
            sleep 3
            
            # Check if service is actually running and connected
            print_info "Checking service health..."
            sleep 2
            
            if sudo systemctl is-active --quiet meshcore-capture.service; then
                # Check logs for successful MQTT connection
                if sudo journalctl -u meshcore-capture.service --since "10 seconds ago" | grep -q "Connected to.*MQTT broker"; then
                    print_success "Service started and connected to MQTT successfully"
                    echo ""
                    print_info "Recent logs:"
                    sudo journalctl -u meshcore-capture.service -n 10 --no-pager
                else
                    print_warning "Service started but may not be connected to MQTT yet"
                    echo ""
                    print_info "Recent logs:"
                    sudo journalctl -u meshcore-capture.service -n 15 --no-pager
                    echo ""
                    print_warning "Check logs with: sudo journalctl -u meshcore-capture -f"
                fi
            else
                print_error "Service failed to start"
                echo ""
                sudo systemctl status meshcore-capture.service --no-pager || true
            fi
        fi
        
        SERVICE_INSTALLED=true
        print_success "Systemd service installed"
    else
        print_error "Failed to install service (sudo required)"
        SERVICE_INSTALLED=false
    fi
    
    rm -f "$service_file"
}

# Install launchd service (macOS)
install_launchd_service() {
    print_info "Installing launchd service..."
    
    local plist_file="$HOME/Library/LaunchAgents/com.meshcore.packet-capture.plist"
    mkdir -p "$HOME/Library/LaunchAgents"
    
    # Build PATH with meshcore-decoder if available
    local service_path="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
    if command -v meshcore-decoder &> /dev/null; then
        local decoder_dir=$(dirname "$(which meshcore-decoder)")
        service_path="${decoder_dir}:${service_path}"
    fi
    
    cat > "$plist_file" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.meshcore.packet-capture</string>
    <key>ProgramArguments</key>
    <array>
        <string>$INSTALL_DIR/venv/bin/python3</string>
        <string>$INSTALL_DIR/packet_capture.py</string>
    </array>
    <key>WorkingDirectory</key>
    <string>$INSTALL_DIR</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>$service_path</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$HOME/Library/Logs/meshcore-capture.log</string>
    <key>StandardErrorPath</key>
    <string>$HOME/Library/Logs/meshcore-capture-error.log</string>
</dict>
</plist>
EOF
    
    if prompt_yes_no "Load service now?" "y"; then
        launchctl load "$plist_file"
        print_success "Service loaded"
    fi
    
    SERVICE_INSTALLED=true
    print_success "Launchd service installed"
}

# Install Docker
install_docker() {
    print_info "Installing Docker configuration..."
    
    # Check if Docker is available
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed or not available in PATH"
        print_info "Please install Docker first: https://docs.docker.com/get-docker/"
        exit 1
    fi

    # Determine docker compose command (prefer modern 'docker compose')
    if docker compose version &> /dev/null; then
        COMPOSE_CMD="docker compose"
    elif command -v docker-compose &> /dev/null; then
        COMPOSE_CMD="docker-compose"
    else
        print_error "Docker Compose is not installed or not available in PATH"
        print_info "Install Docker Desktop or Compose Plugin: https://docs.docker.com/compose/install/"
        exit 1
    fi

    print_success "Docker and Compose found (${COMPOSE_CMD})"
    
    # Create Docker configuration files
    print_info "Creating Docker configuration..."
    
    # Create Dockerfile
    cat > "$INSTALL_DIR/Dockerfile" << 'EOF'
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

# Install the local meshcore package in development mode
RUN pip install -e ./meshcore_py

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
EOF
    
    # Create docker-compose.yml
    cat > "$INSTALL_DIR/docker-compose.yml" << EOF
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
    # Resource limits to prevent runaway processes
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.5'
        reservations:
          memory: 128M
          cpus: '0.1'
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
      
      # Resource management settings (prevent runaway processes)
      - PACKETCAPTURE_MAX_ACTIVE_TASKS=50
      - PACKETCAPTURE_JWT_CIRCUIT_BREAKER_FAILURES=3
      - PACKETCAPTURE_JWT_CIRCUIT_BREAKER_TIMEOUT=180
      
      # Exponential backoff settings (prevent server overload)
      - PACKETCAPTURE_MQTT_RETRY_DELAY_MAX=300
      - PACKETCAPTURE_MQTT_RETRY_BACKOFF_MULTIPLIER=2.0
      - PACKETCAPTURE_MQTT_RETRY_JITTER=true
      - PACKETCAPTURE_CONNECTION_RETRY_DELAY_MAX=300
      - PACKETCAPTURE_CONNECTION_RETRY_BACKOFF_MULTIPLIER=2.0
      - PACKETCAPTURE_CONNECTION_RETRY_JITTER=true
      
      # Service failure tracking (let Docker restart on persistent failures)
      - PACKETCAPTURE_MAX_SERVICE_FAILURES=3
      - PACKETCAPTURE_SERVICE_FAILURE_WINDOW=300
      - PACKETCAPTURE_CRITICAL_FAILURE_THRESHOLD=5
      - PACKETCAPTURE_MAX_CONSECUTIVE_FAILURES=3
    networks:
      - meshcore-network
    restart: unless-stopped
    # Uncomment for host networking (may be needed for BLE discovery)
    # network_mode: host

networks:
  meshcore-network:
    driver: bridge
EOF
    
    # Create .dockerignore
    cat > "$INSTALL_DIR/.dockerignore" << 'EOF'
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
var/
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
EOF
    
    print_success "Docker configuration files created"
    
    # Build Docker image
    print_info "Building Docker image..."
    if docker build -t meshcore-capture "$INSTALL_DIR"; then
        print_success "Docker image built successfully"
    else
        print_error "Failed to build Docker image"
        exit 1
    fi
    
    # Ask if user wants to start the container
    if prompt_yes_no "Start the Docker container now?" "y"; then
        print_info "Starting Docker container..."
        cd "$INSTALL_DIR"
        if $COMPOSE_CMD up -d; then
            print_success "Docker container started"
            
            # Wait a moment and check logs
            sleep 3
            print_info "Container logs:"
            $COMPOSE_CMD logs --tail=20
        else
            print_error "Failed to start Docker container"
            print_info "You can start it manually later with: $COMPOSE_CMD up -d"
        fi
    fi
    
    DOCKER_INSTALLED=true
    print_success "Docker installation complete"
}

# Run main
main "$@"
