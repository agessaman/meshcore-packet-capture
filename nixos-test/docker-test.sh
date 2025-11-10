#!/bin/bash
# Script to test the Nix flake in Docker

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

IMAGE_NAME="meshcore-packet-capture-nix-test"
CONTAINER_NAME="meshcore-packet-capture-test"

# Build the Docker image
echo "Building Docker image..."
docker build -f "$SCRIPT_DIR/Dockerfile.nix-test" -t "$IMAGE_NAME" "$REPO_ROOT"

# Run the container with the repository mounted
echo "Starting container..."
docker run -it --rm \
    --name "$CONTAINER_NAME" \
    -v "$REPO_ROOT:/workspace" \
    -w /workspace \
    "$IMAGE_NAME" \
    /bin/bash -c "
        source /root/.nix-profile/etc/profile.d/nix.sh
        
        echo '=== Testing flake structure ==='
        nix flake show || true
        
        echo ''
        echo '=== Testing package build ==='
        nix build .#packages.x86_64-linux.default --no-link || true
        
        echo ''
        echo '=== Testing module syntax ==='
        nix-instantiate --eval -E '
          let
            pkgs = import <nixpkgs> {};
            lib = pkgs.lib;
            flakeModule = import ./nix/nixos-module.nix { flake-parts-lib = {}; };
            nixosModule = flakeModule.flake.nixosModules.default;
          in
            lib.isFunction nixosModule
        ' --strict || true
        
        echo ''
        echo '=== Testing module with minimal config ==='
        nix-instantiate --eval -E '
          let
            pkgs = import <nixpkgs> {};
            lib = pkgs.lib;
            flakeModule = import ./nix/nixos-module.nix { flake-parts-lib = {}; };
            nixosModule = flakeModule.flake.nixosModules.default;
            eval = import <nixpkgs/nixos/lib/eval-config.nix> {
              modules = [
                nixosModule
                {
                  services.meshcore-packet-capture = {
                    enable = true;
                    connectionType = \"ble\";
                    mqtt1 = {
                      enabled = true;
                      server = \"localhost\";
                      port = 1883;
                    };
                    package = pkgs.hello;  # Use a dummy package for testing
                  };
                }
              ];
            };
          in
            eval.config.services.meshcore-packet-capture.enable
        ' --strict || true
        
        echo ''
        echo '=== Interactive shell available ==='
        echo 'Run: docker exec -it $CONTAINER_NAME /bin/bash'
        /bin/bash
    "

