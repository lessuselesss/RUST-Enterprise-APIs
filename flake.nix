{
  description = "A development environment for a Rust Enterprise API";

  inputs = {
    nixpkgs.url = "github.com/NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github.com/oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        rustToolchain = pkgs.rust-bin.stable.latest.default;

      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            # The Rust toolchain
            rustToolchain
            
            # Tools needed by many build scripts
            pkgs.pkg-config
            pkgs.openssl
            
            # The C compiler and linker
            pkgs.gcc
            
            # Optional but useful tool
            pkgs.cargo-watch 
          ];

          # Environment variables for specific libraries if needed (e.g., openssl)
          # OPENSSL_DIR = pkgs.openssl;
          # PKG_CONFIG_PATH = "${pkgs.openssl}/lib/pkgconfig";

          # A simple prompt to indicate you are in the devShell
          shellHook = ''
            echo "Entering Rust development environment (Nix Flakes)"
          '';
        };
      }
    );
}