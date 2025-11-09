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
        ]))
        
        # Node.js for meshcore-decoder
        nodejs_20
        nodePackages.npm
        
        # System dependencies
        bluez
        bluez.dev
        
        # Development tools
        git
      ];

      shellHook = ''
        echo "MeshCore Packet Capture Development Environment"
        echo "Python: $(python --version)"
        echo "Node.js: $(node --version)"
        echo ""
        echo "To run meshcore-decoder, use: npx -y @michaelhart/meshcore-decoder"
        echo ""
      '';
    };
  };
}

