# NixOS Support

This project includes a NixOS service module that allows you to run MeshCore Packet Capture as a systemd service on NixOS.

## Quick Start

Add this to your `/etc/nixos/configuration.nix`:

```nix
{
  imports = [
    (builtins.fetchTarball "https://github.com/agessaman/meshcore-packet-capture/archive/main.tar.gz")
  ];

  services.meshcore-packet-capture = {
    enable = true;
    connectionType = "ble";
    
    mqtt1 = {
      enabled = true;
      server = "mqtt.example.com";
      port = 1883;
      username = "your_username";
      password = "your_password";
    };
  };
}
```

Then rebuild your system:

```bash
sudo nixos-rebuild switch
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
            # ... your configuration
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

You can configure up to 4 MQTT brokers:

```nix
services.meshcore-packet-capture = {
  mqtt1 = {
    enabled = true;
    server = "mqtt.example.com";
    port = 1883;
    username = "user";
    password = "pass";
    transport = "tcp";  # or "websockets"
    useTLS = true;
    tlsVerify = true;
    useAuthToken = false;
    tokenAudience = null;
    clientIdPrefix = null;
    qos = 0;
    retain = false;
    keepalive = 60;
    topicStatus = "meshcore/status";
    topicPackets = "meshcore/packets";
    topicRaw = "meshcore/raw";
    topicDecoded = "meshcore/decoded";
    topicDebug = "meshcore/debug";
  };
  
  # Similar configuration for mqtt2, mqtt3, mqtt4
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

