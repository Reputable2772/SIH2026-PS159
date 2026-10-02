{
  description = "SecureMailScope — AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications";

  inputs = {
    nixpkgs.url = "flake:nixpkgs";
    flake-parts.url = "flake:flake-parts";
  };

  outputs = inputs @ { flake-parts, nixpkgs, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [ "x86_64-linux" "aarch64-linux" ];

      perSystem = { config, self', pkgs, lib, system, ... }: let

      in {
        devShells.default = pkgs.mkShell {
          name = "securemailscope";

          packages = [
            pkgs.python312
            pkgs.python312Packages.pip
            pkgs.python312Packages.virtualenv
            pkgs.python312Packages.setuptools
            pkgs.python312Packages.wheel

            # Network capture & analysis
            pkgs.wireshark       # provides tshark, capinfos, dumpcap
            pkgs.tcpdump
            pkgs.openssl

            # Mail server components for PCAP generation
            pkgs.postfix
            pkgs.dovecot

            # Build tooling
            pkgs.git
            pkgs.just
            pkgs.jq
            pkgs.curl

            # Frontend tooling
            pkgs.nodejs_22
          ];

          shellHook = ''
            if [ ! -d ".venv" ]; then
              echo "  Creating .venv..."
              python -m venv .venv
            fi
            source .venv/bin/activate

            echo ""
            echo "╔══════════════════════════════════════════════════════╗"
            echo "║       SecureMailScope Development Environment        ║"
            echo "║  SIH 2026 — PS 26159 — Cryptographic Posture Tool   ║"
            echo "╚══════════════════════════════════════════════════════╝"
            echo ""
            echo "  Python  : $(python --version)"
            echo "  TShark  : $(tshark --version 2>/dev/null | head -1 || echo 'not found')"
            echo "  Node    : $(node --version)"
            echo ""
            echo "  Commands:"
            echo "    just dev          – Start backend + frontend"
            echo "    just demo         – Run offline demo"
            echo "    just gen-pcaps    – Generate test PCAPs"
            echo "    just benchmark    – Run evaluation suite"
            echo "    just test         – Run automated tests"
            echo ""
            export SECUREMAILSCOPE_ROOT="$(pwd)"
            export PYTHONPATH="$(pwd)/backend:$PYTHONPATH"
          '';
        };

        # Package the backend as a runnable app
        packages.backend = pkgs.stdenv.mkDerivation {
          pname = "securemailscope-backend";
          version = "0.1.0";
          src = ./backend;
          buildInputs = [ pkgs.python312 ];
          installPhase = ''
            mkdir -p $out/bin $out/lib
            cp -r . $out/lib/securemailscope
            cat > $out/bin/securemailscope-backend <<EOF
            #!${pkgs.bash}/bin/bash
            export PYTHONPATH=$out/lib:$PYTHONPATH
            exec ${pkgs.python312}/bin/python -m uvicorn api.main:app --host 0.0.0.0 --port 8000 "\$@"
            EOF
            chmod +x $out/bin/securemailscope-backend
          '';
        };
      };
    };
}
