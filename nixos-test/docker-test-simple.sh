#!/bin/bash
# Simple script to get an interactive Docker shell with Nix

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

IMAGE_NAME="meshcore-packet-capture-nix-test"

# Build the Docker image if it doesn't exist
if ! docker image inspect "$IMAGE_NAME" &>/dev/null; then
    echo "Building Docker image..."
    docker build -f "$SCRIPT_DIR/Dockerfile.nix-test" -t "$IMAGE_NAME" "$REPO_ROOT"
fi

# Run interactive container
echo "Starting interactive container..."
echo "The repository is mounted at /workspace"
echo "Nix is installed and flakes are enabled"
echo ""
docker run -it --rm \
    -v "$REPO_ROOT:/workspace" \
    -w /workspace \
    "$IMAGE_NAME" \
    /bin/bash -c "source /root/.nix-profile/etc/profile.d/nix.sh && /bin/bash"

