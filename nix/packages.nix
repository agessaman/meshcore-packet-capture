{flake-parts-lib, ...}: {
  perSystem = {pkgs, ...}: {
    packages = let
      # Build meshcore from PyPI if not available in nixpkgs
      # Note: If meshcore is available in nixpkgs, you can override this
      meshcorePackage = pkgs.python3Packages.buildPythonPackage rec {
        pname = "meshcore";
        version = "2.1.10";
        format = "pyproject";
        
        src = pkgs.python3Packages.fetchPypi {
          inherit pname version;
          sha256 = "sha256-mnr5WqH/uKzONI8lcm1GQCSlnhx6WQyqsAr12gsMKEI=";
        };
        
        propagatedBuildInputs = with pkgs.python3Packages; [
          bleak
          pyserial-asyncio
          pycayennelpp
        ];
        
        doCheck = false;
      };

      pythonEnv = pkgs.python3.withPackages (ps: with ps; [
        paho-mqtt
        bleak
        pyserial-asyncio
        pycayennelpp
        pexpect
      ] ++ [meshcorePackage]);

      meshcore-packet-capture = pkgs.stdenv.mkDerivation {
        pname = "meshcore-packet-capture";
        version = "1.0.0";
        src = ./.;

        nativeBuildInputs = [pkgs.makeWrapper];

        buildInputs = [pythonEnv pkgs.nodejs_20];

        installPhase = ''
          mkdir -p $out/bin
          mkdir -p $out/lib/meshcore-packet-capture

          # Copy Python scripts
          cp packet_capture.py $out/lib/meshcore-packet-capture/
          cp enums.py $out/lib/meshcore-packet-capture/
          cp auth_token.py $out/lib/meshcore-packet-capture/
          cp ble_pairing_helper.py $out/lib/meshcore-packet-capture/
          cp ble_scan_helper.py $out/lib/meshcore-packet-capture/
          cp scan_meshcore_network.py $out/lib/meshcore-packet-capture/
          cp debug_ble_connection.py $out/lib/meshcore-packet-capture/
          cp migrate_config.py $out/lib/meshcore-packet-capture/

          # Create wrapper script for the main application
          makeWrapper ${pythonEnv}/bin/python $out/bin/meshcore-packet-capture \
            --set PATH "${pkgs.lib.makeBinPath [pkgs.nodejs_20 pkgs.nodePackages.npm]}:$PATH" \
            --add-flags "$out/lib/meshcore-packet-capture/packet_capture.py" \
            --prefix PYTHONPATH : "$out/lib/meshcore-packet-capture:${pythonEnv}/${pythonEnv.sitePackages}"

          # Create a helper script for meshcore-decoder
          # This will use npx to run it, which handles installation automatically
          makeWrapper ${pkgs.nodejs_20}/bin/npx $out/bin/meshcore-decoder \
            --add-flags "-y" \
            --add-flags "@michaelhart/meshcore-decoder"
        '';

        meta = {
          description = "MeshCore Companion radio packet capture tool";
          homepage = "https://github.com/agessaman/meshcore-packet-capture";
          license = pkgs.lib.licenses.mit;
          platforms = pkgs.lib.platforms.linux;
        };
      };
    in {
      default = meshcore-packet-capture;
      meshcore-packet-capture = meshcore-packet-capture;
    };
  };
}

