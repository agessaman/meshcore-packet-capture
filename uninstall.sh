#!/bin/bash
# ============================================================================
# MeshCore Packet Capture - Uninstaller
# ============================================================================
set -e

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

prompt_yes_no() {
    local prompt="$1"
    local default="${2:-n}"
    local response
    
    if [ "$default" = "y" ]; then
        prompt="$prompt [Y/n]: "
    else
        prompt="$prompt [y/N]: "
    fi
    
    read -p "$prompt" response
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
    
    if [ -n "$default" ]; then
        read -p "$prompt [$default]: " response
        echo "${response:-$default}"
    else
        read -p "$prompt: " response
        echo "$response"
    fi
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

# Remove systemd service
remove_systemd_service() {
    local found=false
    for unit in meshcore-capture.service meshcore-packet-capture.service; do
        if [ -f "/etc/systemd/system/$unit" ]; then
            found=true
            print_info "Stopping and removing systemd service $unit (requires sudo)..."
            if sudo systemctl is-active --quiet "$unit"; then
                sudo systemctl stop "$unit"
                print_success "Service stopped"
            fi
            if sudo systemctl is-enabled --quiet "$unit"; then
                sudo systemctl disable "$unit"
                print_success "Service disabled"
            fi
            sudo rm -f "/etc/systemd/system/$unit"
        fi
    done
    if [ "$found" = true ]; then
        sudo systemctl daemon-reload
        print_success "Service removed"
    else
        print_info "No systemd service found"
    fi
}

# Remove launchd service
remove_launchd_service() {
    local label="com.meshcore.meshcore_packet_capture"
    local daemon_plist="/Library/LaunchDaemons/${label}.plist"
    local agent_user="${SUDO_USER:-$(whoami)}"
    local agent_home="$HOME"
    local found=false

    if [ -n "$SUDO_USER" ] && [ "$SUDO_USER" != "root" ]; then
        agent_home=$(eval echo "~$SUDO_USER")
    fi
    local agent_plist="$agent_home/Library/LaunchAgents/${label}.plist"

    if [ -f "$daemon_plist" ]; then
        found=true
        print_info "Stopping and removing system LaunchDaemon..."
        sudo launchctl bootout system "$daemon_plist" 2>/dev/null || sudo launchctl unload "$daemon_plist" 2>/dev/null || true
        sudo rm -f "$daemon_plist"
        print_success "System LaunchDaemon removed"
    fi

    if [ -f "$agent_plist" ]; then
        found=true
        print_info "Stopping and removing BLE LaunchAgent for $agent_user..."
        local agent_uid
        agent_uid=$(id -u "$agent_user" 2>/dev/null || true)
        if [ -n "$agent_uid" ]; then
            sudo -u "$agent_user" launchctl bootout "gui/$agent_uid" "$agent_plist" 2>/dev/null || sudo -u "$agent_user" launchctl unload "$agent_plist" 2>/dev/null || true
        else
            launchctl unload "$agent_plist" 2>/dev/null || true
        fi
        rm -f "$agent_plist"
        print_success "BLE LaunchAgent removed"
    fi

    if [ "$found" = true ]; then
        if prompt_yes_no "Remove log files?" "y"; then
            sudo rm -f /var/log/meshcore-packet-capture.log /var/log/meshcore-packet-capture-error.log 2>/dev/null || true
            rm -f "$agent_home/Library/Logs/meshcore-packet-capture.log" "$agent_home/Library/Logs/meshcore-packet-capture-error.log"
            print_success "Log files removed"
        fi
    else
        print_info "No launchd service found"
    fi
}

# Remove Docker container and images
remove_docker_installation() {
    local container_name="meshcore-packet-capture"
    local image_name="meshcore-packet-capture"
    
    print_info "Checking for Docker installation..."
    
    # Stop and remove container if running
    if docker ps -a --format "table {{.Names}}" | grep -q "^${container_name}$"; then
        print_info "Stopping Docker container..."
        docker stop "$container_name" 2>/dev/null || true
        print_success "Container stopped"
        
        print_info "Removing Docker container..."
        docker rm "$container_name" 2>/dev/null || true
        print_success "Container removed"
    fi
    
    # Remove image if exists
    if docker images --format "table {{.Repository}}" | grep -q "^${image_name}$"; then
        if prompt_yes_no "Remove Docker image?" "y"; then
            docker rmi "$image_name" 2>/dev/null || true
            print_success "Docker image removed"
        fi
    fi
    
    # Remove docker-compose.yml if exists
    if [ -f "$INSTALL_DIR/docker-compose.yml" ]; then
        if prompt_yes_no "Remove docker-compose.yml?" "y"; then
            rm -f "$INSTALL_DIR/docker-compose.yml"
            print_success "docker-compose.yml removed"
        fi
    fi
}

# Main uninstallation
main() {
    print_header "MeshCore Packet Capture Uninstaller"

    echo "This will remove MeshCore Packet Capture from your system."
    echo ""
    
    # Determine installation directory
    DEFAULT_INSTALL_DIR="/opt/meshcore-packet-capture"
    INSTALL_DIR=$(prompt_input "Installation directory" "$DEFAULT_INSTALL_DIR")
    INSTALL_DIR="${INSTALL_DIR/#\~/$HOME}"  # Expand tilde
    
    if [ ! -d "$INSTALL_DIR" ]; then
        print_error "Installation directory not found: $INSTALL_DIR"
        exit 1
    fi
    
    print_warning "This will remove: $INSTALL_DIR"
    if ! prompt_yes_no "Are you sure you want to continue?" "n"; then
        print_info "Uninstallation cancelled"
        exit 0
    fi
    
    # Stop and remove service
    print_header "Removing Service"
    
    SYSTEM_TYPE=$(detect_system_type)
    print_info "Detected system type: $SYSTEM_TYPE"
    
    case "$SYSTEM_TYPE" in
        systemd)
            remove_systemd_service
            ;;
        launchd)
            remove_launchd_service
            ;;
        *)
            print_info "Unknown system type - skipping service removal"
            ;;
    esac
    
    # Handle Docker installation
    if command -v docker &> /dev/null; then
        print_header "Docker Installation"
        remove_docker_installation
    else
        print_info "Docker not found - skipping Docker cleanup"
    fi
    
    # Back up the user configuration before any files are removed.
    print_header "Configuration Files"

    CONFIG_DIR="/etc/meshcore-packet-capture"
    USER_CONFIG="$CONFIG_DIR/config.d/99-user.toml"
    # Honor older/dev locations too: the renamed legacy override, then a
    # bind-mounted/manual .env.local under the install dir.
    [ -f "$USER_CONFIG" ] || USER_CONFIG="$CONFIG_DIR/config.d/00-user.toml"
    [ -f "$USER_CONFIG" ] || USER_CONFIG="$INSTALL_DIR/.env.local"

    if [ -f "$USER_CONFIG" ]; then
        echo "Found user configuration: $USER_CONFIG"
        echo ""
        if prompt_yes_no "Back up your configuration before uninstalling?" "y"; then
            BACKUP_FILE="$HOME/meshcore-capture-config-backup-$(date +%Y%m%d-%H%M%S)-$(basename "$USER_CONFIG")"
            # The user file is root-owned (0640), so copy via sudo, then hand the
            # backup to the invoking user.
            if sudo cp "$USER_CONFIG" "$BACKUP_FILE"; then
                sudo chown "$(id -un):$(id -gn)" "$BACKUP_FILE" 2>/dev/null || true
                print_success "Configuration backed up to: $BACKUP_FILE"
            else
                print_error "Backup failed - leaving configuration in place"
            fi
        fi
    fi
    
    # Remove installation directory (under /opt, owned by the service user -
    # needs sudo). This also removes the bundled venv and any libraries.
    print_header "Removing Files"

    print_info "Removing installation directory..."
    sudo rm -rf "$INSTALL_DIR"
    print_success "Installation directory removed"
    
    # Clean up any remaining system files
    print_header "System Cleanup"
    
    # Remove any remaining log files
    for logf in /var/log/meshcore-packet-capture.log /var/log/meshcore-packet-capture-error.log; do
        if [ -f "$logf" ]; then
            if prompt_yes_no "Remove system log file $logf?" "y"; then
                sudo rm -f "$logf" 2>/dev/null || true
                print_success "Removed $logf"
            fi
        fi
    done

    if [ -d "/etc/meshcore-packet-capture" ]; then
        if prompt_yes_no "Remove system configuration /etc/meshcore-packet-capture?" "y"; then
            sudo rm -rf /etc/meshcore-packet-capture
            print_success "System configuration removed"
        fi
    fi

    if [ -d "/var/lib/meshcore-packet-capture" ]; then
        if prompt_yes_no "Remove state directory /var/lib/meshcore-packet-capture?" "y"; then
            sudo rm -rf /var/lib/meshcore-packet-capture
            print_success "State directory removed"
        fi
    fi

    # Final message
    print_header "Uninstallation Complete"

    echo "MeshCore Packet Capture has been removed."

    echo ""
    print_success "Uninstallation complete!"
    echo ""
    print_info "To reinstall, download the installer first, then run it with sudo:"
    echo "  tmp=\$(mktemp) && curl -fsSL https://raw.githubusercontent.com/agessaman/meshcore-packet-capture/main/install.sh -o \"\$tmp\" && sudo bash \"\$tmp\"; rm -f \"\$tmp\""
}

# Run main
main "$@"
