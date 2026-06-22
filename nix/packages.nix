{flake-parts-lib, ...}: {
  perSystem = {pkgs, ...}: {
    packages = let
      # Build meshcore from PyPI if not available in nixpkgs
      # Note: If meshcore is available in nixpkgs, you can override this
      meshcorePackage = pkgs.python3Packages.buildPythonPackage rec {
        pname = "meshcore";
        version = "2.2.31";
        format = "pyproject";
        
        src = pkgs.python3Packages.fetchPypi {
          inherit pname version;
          sha256 = "sha256-Z0FkdOY9Kv/y2fPXyH266CaWIWLeHwgC+yqSRLZxog8=";
        };
        
        nativeBuildInputs = with pkgs.python3Packages; [
          hatchling
        ];
        
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
        pynacl
      ] ++ [meshcorePackage]);

      meshcore-packet-capture = pkgs.stdenv.mkDerivation {
        pname = "meshcore-packet-capture";
        version = "2.0.0";
        src = ./.;

        nativeBuildInputs = [pkgs.makeWrapper];

        # JWT signing is pure-Python (pynacl, in pythonEnv); no Node.js required.
        buildInputs = [pythonEnv];

        installPhase = ''
          mkdir -p $out/bin
          mkdir -p $out/lib/meshcore-packet-capture
          cp -r ${../src} $out/lib/meshcore-packet-capture/src

          makeWrapper ${pythonEnv}/bin/python $out/bin/meshcore-packet-capture \
            --prefix PYTHONPATH : "$out/lib/meshcore-packet-capture/src:${pythonEnv}/${pythonEnv.sitePackages}" \
            --add-flags "-m" \
            --add-flags "meshcore_packet_capture"
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

