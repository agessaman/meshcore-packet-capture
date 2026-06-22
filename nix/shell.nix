{flake-parts-lib, ...}: {
  perSystem = {pkgs, ...}: {
    devShells.default = pkgs.mkShell {
      buildInputs = with pkgs; [
        # Python with all dependencies
        (python3.withPackages (ps: with ps; [
          paho-mqtt
          meshcore
          bleak
          pyserial-asyncio
          pycayennelpp
          pexpect
          pynacl
        ]))

        # System dependencies
        bluez
        bluez.dev
        
        # Development tools
        git
      ];

      shellHook = ''
        export PYTHONPATH="$PWD/src''${PYTHONPATH:+:$PYTHONPATH}"
        echo "MeshCore Packet Capture Development Environment"
        echo "Python: $(python --version)"
        echo ""
        echo "Run: python -m meshcore_packet_capture"
        echo ""
      '';
    };
  };
}

