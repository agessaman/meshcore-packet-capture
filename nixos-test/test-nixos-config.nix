{ config, pkgs, ... }:
let
  # Get the package from the flake using builtins.getFlake
  # This requires the flake to be accessible (either in registry or as a path)
  # Note: This file should be run from the repository root, or paths adjusted accordingly
  repoRoot = toString ../.;
  flake = builtins.getFlake repoRoot;
  # Get the package for the current system
  system = pkgs.system;
  meshcorePackage = flake.packages.${system}.default;
  
  # Import the flake module and extract the NixOS module
  flakeModule = import ../nix/nixos-module.nix { flake-parts-lib = {}; };
  meshcoreModule = flakeModule.flake.nixosModules.default;
in
{
  imports = [
    meshcoreModule
  ];

  # Set system state version to avoid warnings
  system.stateVersion = "24.11";

  services.meshcore-packet-capture = {
    enable = true;
    
    # Override the package to use the flake's package
    package = meshcorePackage;
    
    connectionType = "ble";
    bleDeviceName = "MeshCore-HOWL Ikoka";  # Specific device to connect to
    # OR use bleAddress = "AA:BB:CC:DD:EE:FF"; for a specific address
    
    # Let'sMesh Analyzer - US Server
    mqtt1 = {
      enabled = true;
      server = "mqtt-us-v1.letsmesh.net";
      port = 443;
      transport = "websockets";
      useTLS = true;
      useAuthToken = true;
      tokenAudience = "mqtt-us-v1.letsmesh.net";
      keepalive = 120;
    };
    
    # Let'sMesh Analyzer - EU Server
    mqtt2 = {
      enabled = true;
      server = "mqtt-eu-v1.letsmesh.net";
      port = 443;
      transport = "websockets";
      useTLS = true;
      useAuthToken = true;
      tokenAudience = "mqtt-eu-v1.letsmesh.net";
      keepalive = 120;
    };
    
    # Device private key for Let'sMesh authentication
    # The script will automatically fetch the private key from the device if it supports
    # ENABLE_PRIVATE_KEY_EXPORT. Only provide these if automatic fetching fails:
    # privateKeyFile = "/path/to/your/private/key/file";
    # OR
    # privateKey = "your_private_key_hex_string";
    
    # Optional: Owner information for Let'sMesh Analyzer
    # ownerPublicKey = "dadadadaa3965eb49a7aa8158bd4a4f3a73f711585f8dcffb13a7497e071ddda";
    # ownerEmail = "adam@gessaman.com";
    
    # IATA code for topic templates
    iata = "SEA";  # Replace with your IATA code
  };
}

