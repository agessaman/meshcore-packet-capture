# NixOS Testing

This directory contains testing scripts and documentation for the NixOS service module.

## Files

- **`NIXOS.md`** - Complete documentation for using the NixOS service module
- **`test-nixos-config.nix`** - Example NixOS configuration for testing (use with `nixos-shell` from repository root)
- **`Dockerfile.nix-test`** - Docker image with Nix installed for testing without NixOS
- **`docker-test-simple.sh`** - Quick script to get an interactive Docker shell with Nix
- **`docker-test.sh`** - Automated test script that runs various Nix flake tests

## Quick Start

### Testing in Docker (No NixOS Required)

Get an interactive shell:
```bash
cd nixos-test
./docker-test-simple.sh
```

Run automated tests:
```bash
cd nixos-test
./docker-test.sh
```

### Testing with nixos-shell (Requires Nix installed)

From the repository root:
```bash
nixos-shell nixos-test/test-nixos-config.nix
```

## Documentation

See `NIXOS.md` for complete usage instructions and configuration options.

