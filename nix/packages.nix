{flake-parts-lib, ...}: {
  perSystem = {pkgs, ...}: {
    packages = let
      # Build meshcore from PyPI if not available in nixpkgs
      # Note: If meshcore is available in nixpkgs, you can override this
      meshcorePackage = pkgs.python3Packages.buildPythonPackage rec {
        pname = "meshcore";
        version = "2.3.8";
        format = "pyproject";

        src = pkgs.python3Packages.fetchPypi {
          inherit pname version;
          sha256 = "sha256-ItV9u1kYavbtIwP9FJY1AimJpPjchnxymm8KvDStOqs=";
        };
        
        nativeBuildInputs = with pkgs.python3Packages; [
          hatchling
        ];
        
        # meshcore's wheel requires these at runtime; nixpkgs' Python deps
        # check (pythonRuntimeDepsCheck) fails the build if they're not provided.
        propagatedBuildInputs = with pkgs.python3Packages; [
          bleak
          pyserial-asyncio
          pyserial-asyncio-fast
          pycryptodome
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
        cryptography
      ] ++ [meshcorePackage]);

      meshcore-packet-capture = pkgs.stdenv.mkDerivation {
        pname = "meshcore-packet-capture";
        version = "2.1.0";
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
