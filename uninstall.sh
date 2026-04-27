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
    local plist_file="$HOME/Library/LaunchAgents/com.meshcore.packet-capture.plist"
    
    if [ -f "$plist_file" ]; then
        print_info "Stopping and removing launchd service..."
        
        if launchctl list | grep -q com.meshcore.packet-capture; then
            launchctl unload "$plist_file" 2>/dev/null || true
            print_success "Service unloaded"
        fi
        
        rm -f "$plist_file"
        print_success "Service removed"
        
        # Clean up log files
        if prompt_yes_no "Remove log files?" "y"; then
            rm -f "$HOME/Library/Logs/meshcore-capture.log"
            rm -f "$HOME/Library/Logs/meshcore-capture-error.log"
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
    KEEP_CONFIG=false

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
    
    # Handle .env.local
    print_header "Configuration Files"
    
    if [ -f "$INSTALL_DIR/.env.local" ]; then
        echo "Your configuration file contains custom settings:"
        echo ""
        cat "$INSTALL_DIR/.env.local" | head -20
        if [ $(wc -l < "$INSTALL_DIR/.env.local") -gt 20 ]; then
            echo "..."
        fi
        echo ""
        
        if prompt_yes_no "Do you want to back up .env.local before uninstalling?" "y"; then
            BACKUP_FILE="$HOME/meshcore-capture-config-backup-$(date +%Y%m%d-%H%M%S).env"
            cp "$INSTALL_DIR/.env.local" "$BACKUP_FILE"
            print_success "Configuration backed up to: $BACKUP_FILE"
        fi
        
        if ! prompt_yes_no "Remove .env.local configuration file?" "y"; then
            print_info "Keeping .env.local - you'll need to remove it manually"
            KEEP_CONFIG=true
        fi
    fi
    
    # Handle Python virtual environment
    if [ -d "$INSTALL_DIR/venv" ]; then
        print_header "Python Environment"
        if prompt_yes_no "Remove Python virtual environment?" "y"; then
            rm -rf "$INSTALL_DIR/venv"
            print_success "Virtual environment removed"
        fi
    fi
    
    # Handle meshcore_py directory
    if [ -d "$INSTALL_DIR/meshcore_py" ]; then
        print_header "MeshCore Library"
        if prompt_yes_no "Remove meshcore_py library?" "y"; then
            rm -rf "$INSTALL_DIR/meshcore_py"
            print_success "MeshCore library removed"
        fi
    fi
    
    # Remove installation directory
    print_header "Removing Files"
    
    if [ "$KEEP_CONFIG" = true ]; then
        # Remove everything except .env.local
        print_info "Removing installation files (keeping .env.local)..."
        
        find "$INSTALL_DIR" -mindepth 1 -maxdepth 1 ! -name '.env.local' -exec rm -rf {} +
        
        print_warning ".env.local kept at: $INSTALL_DIR/.env.local"
        print_info "To complete removal, manually delete: $INSTALL_DIR"
    else
        # Remove everything
        print_info "Removing installation directory..."
        rm -rf "$INSTALL_DIR"
        print_success "Installation directory removed"
    fi
    
    # Clean up any remaining system files
    print_header "System Cleanup"
    
    # Remove any remaining log files
    for logf in /var/log/meshcore-capture.log /var/log/meshcore-packet-capture.log /var/log/meshcore-packet-capture-error.log; do
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
    
    if [ "$KEEP_CONFIG" = true ]; then
        echo "MeshCore Packet Capture has been removed (configuration kept)."
        echo "Configuration file: $INSTALL_DIR/.env.local"
    else
        echo "MeshCore Packet Capture has been completely removed."
    fi
    
    echo ""
    print_success "Uninstallation complete!"
    echo ""
    print_info "If you want to reinstall, run: curl -fsSL https://raw.githubusercontent.com/agessaman/meshcore-packet-capture/main/install.sh | bash"
}

# Run main
main "$@"
