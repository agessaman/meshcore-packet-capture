{flake-parts-lib, ...}: {
  flake.nixosModules.default = {config, lib, pkgs, ...}: let
    cfg = config.services.meshcore-packet-capture;
    
    # Helper function to create MQTT broker configuration
    mqttBrokerType = num: lib.types.submodule {
      options = {
        enabled = lib.mkEnableOption "Enable MQTT broker ${toString num}";
        server = lib.mkOption {
          type = lib.types.str;
          description = "MQTT broker address";
        };
        port = lib.mkOption {
          type = lib.types.port;
          default = 1883;
          description = "MQTT broker port";
        };
        username = lib.mkOption {
          type = lib.types.nullOr lib.types.str;
          default = null;
          description = "MQTT username";
        };
        password = lib.mkOption {
          type = lib.types.nullOr lib.types.str;
          default = null;
          description = "MQTT password";
        };
        transport = lib.mkOption {
          type = lib.types.enum ["tcp" "websockets"];
          default = "tcp";
          description = "Transport type";
        };
        useTLS = lib.mkOption {
          type = lib.types.bool;
          default = false;
          description = "Enable TLS/SSL encryption";
        };
        tlsVerify = lib.mkOption {
          type = lib.types.bool;
          default = true;
          description = "Verify TLS certificates";
        };
        useAuthToken = lib.mkOption {
          type = lib.types.bool;
          default = false;
          description = "Use auth token authentication";
        };
        tokenAudience = lib.mkOption {
          type = lib.types.nullOr lib.types.str;
          default = null;
          description = "Token audience for auth token";
        };
        clientIdPrefix = lib.mkOption {
          type = lib.types.nullOr lib.types.str;
          default = null;
          description = "Client ID prefix";
        };
        qos = lib.mkOption {
          type = lib.types.int;
          default = 0;
          description = "Quality of Service level";
        };
        retain = lib.mkOption {
          type = lib.types.bool;
          default = false;
          description = "Retain messages";
        };
        keepalive = lib.mkOption {
          type = lib.types.int;
          default = 60;
          description = "Keep-alive interval";
        };
        topicStatus = lib.mkOption {
          type = lib.types.nullOr lib.types.str;
          default = null;
          description = "Status topic";
        };
        topicPackets = lib.mkOption {
          type = lib.types.nullOr lib.types.str;
          default = null;
          description = "Packets topic";
        };
        topicRaw = lib.mkOption {
          type = lib.types.nullOr lib.types.str;
          default = null;
          description = "Raw topic";
        };
        topicDecoded = lib.mkOption {
          type = lib.types.nullOr lib.types.str;
          default = null;
          description = "Decoded topic";
        };
        topicDebug = lib.mkOption {
          type = lib.types.nullOr lib.types.str;
          default = null;
          description = "Debug topic";
        };
      };
    };

    # Build environment variables from configuration
    buildEnvVars = let
      mqttEnvVars = lib.flatten (lib.imap1 (num: broker: [
        "PACKETCAPTURE_MQTT${toString num}_ENABLED=${if broker.enabled then "true" else "false"}"
        "PACKETCAPTURE_MQTT${toString num}_SERVER=${broker.server}"
        "PACKETCAPTURE_MQTT${toString num}_PORT=${toString broker.port}"
      ] ++ lib.optional (broker.username != null) "PACKETCAPTURE_MQTT${toString num}_USERNAME=${broker.username}"
      ++ lib.optional (broker.password != null) "PACKETCAPTURE_MQTT${toString num}_PASSWORD=${broker.password}"
      ++ ["PACKETCAPTURE_MQTT${toString num}_TRANSPORT=${broker.transport}"]
      ++ ["PACKETCAPTURE_MQTT${toString num}_USE_TLS=${if broker.useTLS then "true" else "false"}"]
      ++ ["PACKETCAPTURE_MQTT${toString num}_TLS_VERIFY=${if broker.tlsVerify then "true" else "false"}"]
      ++ ["PACKETCAPTURE_MQTT${toString num}_USE_AUTH_TOKEN=${if broker.useAuthToken then "true" else "false"}"]
      ++ lib.optional (broker.tokenAudience != null) "PACKETCAPTURE_MQTT${toString num}_TOKEN_AUDIENCE=${broker.tokenAudience}"
      ++ lib.optional (broker.clientIdPrefix != null) "PACKETCAPTURE_MQTT${toString num}_CLIENT_ID_PREFIX=${broker.clientIdPrefix}"
      ++ ["PACKETCAPTURE_MQTT${toString num}_QOS=${toString broker.qos}"]
      ++ ["PACKETCAPTURE_MQTT${toString num}_RETAIN=${if broker.retain then "true" else "false"}"]
      ++ ["PACKETCAPTURE_MQTT${toString num}_KEEPALIVE=${toString broker.keepalive}"]
      ++ lib.optional (broker.topicStatus != null) "PACKETCAPTURE_MQTT${toString num}_TOPIC_STATUS=${broker.topicStatus}"
      ++ lib.optional (broker.topicPackets != null) "PACKETCAPTURE_MQTT${toString num}_TOPIC_PACKETS=${broker.topicPackets}"
      ++ lib.optional (broker.topicRaw != null) "PACKETCAPTURE_MQTT${toString num}_TOPIC_RAW=${broker.topicRaw}"
      ++ lib.optional (broker.topicDecoded != null) "PACKETCAPTURE_MQTT${toString num}_TOPIC_DECODED=${broker.topicDecoded}"
      ++ lib.optional (broker.topicDebug != null) "PACKETCAPTURE_MQTT${toString num}_TOPIC_DEBUG=${broker.topicDebug}") [
        cfg.mqtt1
        cfg.mqtt2
        cfg.mqtt3
        cfg.mqtt4
      ]);

      connectionEnvVars = [
        "PACKETCAPTURE_CONNECTION_TYPE=${cfg.connectionType}"
      ] ++ lib.optional (cfg.bleAddress != null) "PACKETCAPTURE_BLE_ADDRESS=${cfg.bleAddress}"
      ++ lib.optional (cfg.bleDeviceName != null) "PACKETCAPTURE_BLE_DEVICE_NAME=${cfg.bleDeviceName}"
      ++ lib.optional (cfg.serialPorts != null) "PACKETCAPTURE_SERIAL_PORTS=${lib.concatStringsSep "," cfg.serialPorts}"
      ++ lib.optional (cfg.tcpHost != null) "PACKETCAPTURE_TCP_HOST=${cfg.tcpHost}"
      ++ lib.optional (cfg.tcpPort != null) "PACKETCAPTURE_TCP_PORT=${toString cfg.tcpPort}"
      ++ lib.optional (cfg.timeout != null) "PACKETCAPTURE_TIMEOUT=${toString cfg.timeout}"
      ++ lib.optional (cfg.maxConnectionRetries != null) "PACKETCAPTURE_MAX_CONNECTION_RETRIES=${toString cfg.maxConnectionRetries}"
      ++ lib.optional (cfg.connectionRetryDelay != null) "PACKETCAPTURE_CONNECTION_RETRY_DELAY=${toString cfg.connectionRetryDelay}"
      ++ lib.optional (cfg.healthCheckInterval != null) "PACKETCAPTURE_HEALTH_CHECK_INTERVAL=${toString cfg.healthCheckInterval}";

      otherEnvVars = [
        "PACKETCAPTURE_LOG_LEVEL=${cfg.logLevel}"
      ] ++ lib.optional (cfg.iata != null) "PACKETCAPTURE_IATA=${cfg.iata}"
      ++ lib.optional (cfg.origin != null) "PACKETCAPTURE_ORIGIN=${cfg.origin}"
      ++ lib.optional (cfg.maxMqttRetries != null) "PACKETCAPTURE_MAX_MQTT_RETRIES=${toString cfg.maxMqttRetries}"
      ++ lib.optional (cfg.mqttRetryDelay != null) "PACKETCAPTURE_MQTT_RETRY_DELAY=${toString cfg.mqttRetryDelay}"
      ++ lib.optional (cfg.exitOnReconnectFail != null) "PACKETCAPTURE_EXIT_ON_RECONNECT_FAIL=${if cfg.exitOnReconnectFail then "true" else "false"}"
      ++ lib.optional (cfg.privateKey != null) "PACKETCAPTURE_PRIVATE_KEY=${cfg.privateKey}"
      ++ lib.optional (cfg.privateKeyFile != null) "PACKETCAPTURE_PRIVATE_KEY_FILE=${cfg.privateKeyFile}"
      ++ lib.optional (cfg.advertIntervalHours != null) "PACKETCAPTURE_ADVERT_INTERVAL_HOURS=${toString cfg.advertIntervalHours}"
      ++ lib.optional (cfg.uploadPacketTypes != null) "PACKETCAPTURE_UPLOAD_PACKET_TYPES=${lib.concatStringsSep "," (map toString cfg.uploadPacketTypes)}"
      ++ lib.optional (cfg.rfDataTimeout != null) "PACKETCAPTURE_RF_DATA_TIMEOUT=${toString cfg.rfDataTimeout}"
      ++ lib.optional (cfg.outputFile != null) "PACKETCAPTURE_OUTPUT_FILE=${cfg.outputFile}"
      ++ lib.optional cfg.verbose "PACKETCAPTURE_VERBOSE=true"
      ++ lib.optional cfg.debug "PACKETCAPTURE_DEBUG=true"
      ++ lib.optional (!cfg.enableMqtt) "PACKETCAPTURE_NO_MQTT=true";

    in connectionEnvVars ++ mqttEnvVars ++ otherEnvVars;
  in {
    options.services.meshcore-packet-capture = {
      enable = lib.mkEnableOption "MeshCore Packet Capture service";

      package = lib.mkOption {
        type = lib.types.package;
        default = pkgs.meshcore-packet-capture;
        defaultText = "pkgs.meshcore-packet-capture";
        description = ''
          The meshcore-packet-capture package to use.
          
          When using this module from a flake, you should override this option directly:
          
          Example:
          services.meshcore-packet-capture.package = self.packages.x86_64-linux.default;
          
          (Replace x86_64-linux with your system architecture if different)
        '';
      };

      user = lib.mkOption {
        type = lib.types.str;
        default = "meshcore";
        description = "User to run the service as";
      };

      group = lib.mkOption {
        type = lib.types.str;
        default = "meshcore";
        description = "Group to run the service as";
      };

      dataDir = lib.mkOption {
        type = lib.types.path;
        default = "/var/lib/meshcore-packet-capture";
        description = "Directory for data files";
      };

      # Connection settings
      connectionType = lib.mkOption {
        type = lib.types.enum ["ble" "serial" "tcp"];
        default = "ble";
        description = "Connection type";
      };

      bleAddress = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Specific BLE device address";
      };

      bleDeviceName = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "BLE device name to scan for";
      };

      serialPorts = lib.mkOption {
        type = lib.types.nullOr (lib.types.listOf lib.types.str);
        default = null;
        description = "Comma-separated list of serial ports to try";
      };

      tcpHost = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = "localhost";
        description = "TCP host address";
      };

      tcpPort = lib.mkOption {
        type = lib.types.nullOr lib.types.port;
        default = 5000;
        description = "TCP port number";
      };

      timeout = lib.mkOption {
        type = lib.types.nullOr lib.types.int;
        default = 30;
        description = "Connection timeout in seconds";
      };

      maxConnectionRetries = lib.mkOption {
        type = lib.types.nullOr lib.types.int;
        default = 5;
        description = "Maximum MeshCore connection retry attempts (0 = infinite)";
      };

      connectionRetryDelay = lib.mkOption {
        type = lib.types.nullOr lib.types.int;
        default = 5;
        description = "Delay between MeshCore reconnection attempts (seconds)";
      };

      healthCheckInterval = lib.mkOption {
        type = lib.types.nullOr lib.types.int;
        default = 30;
        description = "How often to check connection health (seconds)";
      };

      # Logging
      logLevel = lib.mkOption {
        type = lib.types.enum ["DEBUG" "INFO" "WARNING" "ERROR" "CRITICAL"];
        default = "INFO";
        description = "Log level";
      };

      verbose = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Enable verbose output";
      };

      debug = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Enable debug output";
      };

      # MQTT brokers
      mqtt1 = lib.mkOption {
        type = mqttBrokerType 1;
        default = {};
        description = "MQTT broker 1 configuration";
      };

      mqtt2 = lib.mkOption {
        type = mqttBrokerType 2;
        default = {};
        description = "MQTT broker 2 configuration";
      };

      mqtt3 = lib.mkOption {
        type = mqttBrokerType 3;
        default = {};
        description = "MQTT broker 3 configuration";
      };

      mqtt4 = lib.mkOption {
        type = mqttBrokerType 4;
        default = {};
        description = "MQTT broker 4 configuration";
      };

      enableMqtt = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Enable MQTT publishing";
      };

      maxMqttRetries = lib.mkOption {
        type = lib.types.nullOr lib.types.int;
        default = 5;
        description = "Maximum MQTT connection retry attempts (0 = infinite)";
      };

      mqttRetryDelay = lib.mkOption {
        type = lib.types.nullOr lib.types.int;
        default = 5;
        description = "Delay between MQTT reconnection attempts (seconds)";
      };

      exitOnReconnectFail = lib.mkOption {
        type = lib.types.nullOr lib.types.bool;
        default = true;
        description = "Exit when reconnection attempts fail";
      };

      # Private key
      privateKey = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Device private key for auth token authentication (hex string)";
      };

      privateKeyFile = lib.mkOption {
        type = lib.types.nullOr lib.types.path;
        default = null;
        description = "Path to file containing device private key";
      };

      # Other settings
      iata = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = "LOC";
        description = "IATA code for topic templates";
      };

      origin = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Origin identifier";
      };

      advertIntervalHours = lib.mkOption {
        type = lib.types.nullOr lib.types.int;
        default = 11;
        description = "Send flood adverts at this interval (0 = disabled)";
      };

      uploadPacketTypes = lib.mkOption {
        type = lib.types.nullOr (lib.types.listOf lib.types.int);
        default = null;
        description = "List of packet type numbers to upload to MQTT";
      };

      rfDataTimeout = lib.mkOption {
        type = lib.types.nullOr lib.types.float;
        default = 15.0;
        description = "RF data timeout";
      };

      outputFile = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Output file path";
      };
    };

    config = lib.mkIf cfg.enable {
      # Create user and group
      users.users.${cfg.user} = {
        isSystemUser = true;
        group = cfg.group;
        description = "MeshCore Packet Capture service user";
        extraGroups = ["bluetooth" "dialout"]; # For BLE and serial access
      };

      users.groups.${cfg.group} = {};

      # Systemd service
      systemd.services.meshcore-packet-capture = {
        description = "MeshCore Packet Capture Service";
        wantedBy = ["multi-user.target"];
        after = ["network.target" "bluetooth.target"];

        serviceConfig = {
          Type = "simple";
          User = cfg.user;
          Group = cfg.group;
          WorkingDirectory = cfg.dataDir;
          ExecStart = "${cfg.package}/bin/meshcore-packet-capture";
          Restart = "on-failure";
          RestartSec = "10s";
          StandardOutput = "journal";
          StandardError = "journal";
          
          # Environment variables
          Environment = buildEnvVars;
          
          # Security settings
          PrivateTmp = true;
          ProtectSystem = "strict";
          ProtectHome = true;
          ReadWritePaths = [cfg.dataDir];
          
          # Device access
          SupplementaryGroups = ["bluetooth" "dialout"];
        };

        environment = {
          PYTHONUNBUFFERED = "1";
          PYTHONDONTWRITEBYTECODE = "1";
        };
      };

      # Create data directory
      systemd.tmpfiles.rules = [
        "d '${cfg.dataDir}' 0750 ${cfg.user} ${cfg.group} - -"
      ];
    };
  };
}

