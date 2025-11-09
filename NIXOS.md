# NixOS Support

This project includes a NixOS service module that allows you to run MeshCore Packet Capture as a systemd service on NixOS.

## Quick Start

### Recommended Configuration (Let'sMesh Analyzer)

This configuration uploads packets to both Let's Mesh Analyzer servers (US and EU) for redundancy, plus an optional third MQTT broker for your own infrastructure:

Add this to your `/etc/nixos/configuration.nix`:

```nix
{
  imports = [
    (builtins.fetchTarball "https://github.com/agessaman/meshcore-packet-capture/archive/main.tar.gz")
  ];

  services.meshcore-packet-capture = {
    enable = true;
    connectionType = "ble";  # or "serial" or "tcp"
    
    # Connection settings (choose one based on connectionType)
    # For BLE:
    # bleAddress = "AA:BB:CC:DD:EE:FF";  # optional: specific device address
    # bleDeviceName = "MeshCore Device";  # optional: device name to scan for
    
    # For Serial:
    # serialPorts = [ "/dev/ttyUSB0" "/dev/ttyUSB1" ];  # list of ports to try
    
    # For TCP:
    # tcpHost = "localhost";  # TCP server hostname
    # tcpPort = 5000;  # TCP server port
    
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
    
    # Optional: Your own MQTT broker (uncomment and configure as needed)
    # mqtt3 = {
    #   enabled = true;
    #   server = "mqtt.example.com";
    #   port = 1883;
    #   username = "your_username";
    #   password = "your_password";
    #   # or use TLS:
    #   # port = 8883;
    #   # useTLS = true;
    # };
    
    # Device private key for Let'sMesh authentication
    # Required for auth token authentication
    privateKeyFile = "/path/to/your/private/key/file";
    # OR
    # privateKey = "your_private_key_hex_string";
    
    # Optional: Owner information for Let'sMesh Analyzer
    # ownerPublicKey = "YOUR_64_CHAR_HEX_PUBLIC_KEY";  # 64 hex characters
    # ownerEmail = "your.email@example.com";  # Email for Let'sMesh Analyzer
    
    # Optional: IATA code for topic templates
    iata = "SEA";  # Replace with your IATA code
  };
}
```

Then rebuild your system:

```bash
sudo nixos-rebuild switch
```

**Note:** For Let'sMesh Analyzer authentication, you need your device's private key. See the [Authentication](#authentication) section below for details.

### Custom MQTT Broker Configuration

If you prefer to use your own MQTT broker instead of (or in addition to) Let'sMesh Analyzer:

```nix
services.meshcore-packet-capture = {
  enable = true;
  connectionType = "ble";
  
  mqtt1 = {
    enabled = true;
    server = "mqtt.example.com";
    port = 1883;  # or 8883 for TLS
    username = "your_username";
    password = "your_password";
    # Optional: Enable TLS
    # useTLS = true;
    # tlsVerify = true;
  };
};
```

## Using with Flakes

If you're using Nix Flakes, add this to your `flake.nix`:

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    meshcore-packet-capture = {
      url = "github:agessaman/meshcore-packet-capture";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, meshcore-packet-capture }: {
    nixosConfigurations.your-hostname = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        meshcore-packet-capture.nixosModules.default
        {
          services.meshcore-packet-capture = {
            enable = true;
            package = meshcore-packet-capture.packages.${system}.default;
            connectionType = "ble";
            
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
            
            privateKeyFile = "/path/to/your/private/key/file";
            
            # Optional: Owner information for Let'sMesh Analyzer
            # ownerPublicKey = "YOUR_64_CHAR_HEX_PUBLIC_KEY";
            # ownerEmail = "your.email@example.com";
            
            iata = "SEA";
          };
        }
      ];
    };
  };
}
```

## Configuration Options

### Connection Settings

```nix
services.meshcore-packet-capture = {
  connectionType = "ble";  # or "serial" or "tcp"
  bleAddress = "AA:BB:CC:DD:EE:FF";  # optional
  bleDeviceName = "MeshCore Device";  # optional
  serialPorts = [ "/dev/ttyUSB0" "/dev/ttyUSB1" ];  # for serial connection
  tcpHost = "localhost";  # for TCP connection
  tcpPort = 5000;  # for TCP connection
  timeout = 30;
  maxConnectionRetries = 5;  # 0 = infinite
  connectionRetryDelay = 5;
  healthCheckInterval = 30;
};
```

### MQTT Brokers

You can configure up to 4 MQTT brokers. Here's an example with Let'sMesh Analyzer (recommended) plus a custom broker:

```nix
services.meshcore-packet-capture = {
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
  
  # Let'sMesh Analyzer - EU Server (for redundancy)
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
  
  # Your own MQTT broker (optional)
  mqtt3 = {
    enabled = true;
    server = "mqtt.example.com";
    port = 1883;  # or 8883 for TLS
    username = "user";
    password = "pass";
    transport = "tcp";  # or "websockets"
    useTLS = false;  # set to true for TLS
    tlsVerify = true;
    qos = 0;
    retain = false;
    keepalive = 60;
    # Optional topic overrides
    topicStatus = "meshcore/status";
    topicPackets = "meshcore/packets";
    topicRaw = "meshcore/raw";
  };
  
  # mqtt4 can be configured similarly
};
```

### Authentication

For username/password authentication:

```nix
services.meshcore-packet-capture = {
  mqtt1 = {
    username = "your_username";
    password = "your_password";
  };
};
```

For JWT token authentication:

```nix
services.meshcore-packet-capture = {
  mqtt1 = {
    useAuthToken = true;
    tokenAudience = "mqtt.example.com";
  };
  privateKey = "your_private_key_hex_string";
  # OR
  privateKeyFile = "/path/to/private/key/file";
};
```

### Other Settings

```nix
services.meshcore-packet-capture = {
  logLevel = "INFO";  # DEBUG, INFO, WARNING, ERROR, CRITICAL
  verbose = false;
  debug = false;
  enableMqtt = true;
  maxMqttRetries = 5;  # 0 = infinite
  mqttRetryDelay = 5;
  exitOnReconnectFail = true;
  iata = "SEA";  # For topic templates
  origin = "My Device";
  advertIntervalHours = 11;  # 0 = disabled
  uploadPacketTypes = [ 0 1 2 ];  # Filter packet types, null = all
  rfDataTimeout = 15.0;
  outputFile = null;  # Optional output file path
  privateKeyFile = "/path/to/private/key/file";  # Required for auth token auth
  ownerPublicKey = null;  # Optional: 64 hex character owner public key
  ownerEmail = null;  # Optional: Owner email for Let'sMesh Analyzer
  dataDir = "/var/lib/meshcore-packet-capture";
  user = "meshcore";
  group = "meshcore";
};
```

## Permissions

The service automatically adds the service user to the `bluetooth` and `dialout` groups for BLE and serial port access.

## Development

To enter a development shell with all dependencies:

```bash
nix develop
```

## Troubleshooting

### Package not found

If you get an error about `meshcore` package not being found, you may need to update the hash in `nix/packages.nix`. The first time you build, Nix will tell you the correct hash to use.

### BLE not working

Ensure that:
1. Bluetooth is enabled: `services.bluetooth.enable = true;`
2. The service user has proper permissions (automatically handled)
3. Your Bluetooth adapter is properly configured

### Serial port not accessible

Ensure that:
1. The device exists: `ls -l /dev/ttyUSB0`
2. The service user is in the `dialout` group (automatically handled)
3. You've specified the correct port in `serialPorts`

### Service logs

View service logs with:

```bash
journalctl -u meshcore-packet-capture -f
```

## Building the Package

To build just the package (without installing as a service):

```bash
nix build
```

The package will be available at `./result/bin/meshcore-packet-capture`.

