{
  description = "A comprehensive Rust development environment for the Circular Protocol Enterprise API";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        # Use the rust-overlay to get a consistent and feature-rich toolchain
        overlays = [ (import rust-overlay).overlays.default ];

        pkgs = import nixpkgs {
          inherit system overlays;
        };

        # Define the Rust toolchain with essential extensions for development
        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "clippy" "rustfmt" ];
        };

      in
      {
        devShells.default = pkgs.mkShell {
          # Allow network access for cargo and integration tests
          __noChroot = true;

          buildInputs = with pkgs; [
            # 1. The Rust toolchain and language server
            rustToolchain
            rust-analyzer

            # 2. Essential Rust development utilities
            cargo-watch

            # 3. Libraries required by common Rust crates (e.g., openssl-sys, ring)
            openssl
            pkg-config

            # 4. A comprehensive set of C/C++ build tools for compiling native dependencies
            gcc
            gnumake
            gpp
            bison
            flex
            libiconv
            autoconf
            automake
            makeWrapper
            libclang # For crates that need to parse C headers (e.g., bindgen)
          ];

          # This hook runs when you enter the shell. It sets up environment variables
          # to help build scripts find the libraries provided by Nix.
          shellHook = ''
            # Make libclang headers available to bindgen
            export LIBCLANG_PATH="${pkgs.libclang.lib}/lib"

            # Make openssl libraries and headers available
            export OPENSSL_DIR="${pkgs.openssl.dev}"
            export OPENSSL_LIB_DIR="${pkgs.openssl.out}/lib"
            export OPENSSL_INCLUDE_DIR="${pkgs.openssl.dev}/include"

            # Add relevant paths to PKG_CONFIG_PATH
            export PKG_CONFIG_PATH="${pkgs.openssl.dev}/lib/pkgconfig:${pkgs.libclang.lib}/pkgconfig"

            echo ""
            echo "Rust Enterprise API dev environment activated."
            echo "------------------------------------------------"
            echo "Toolchain: $(rustc --version)"
            echo "Tools: cargo-watch, clippy, rustfmt, rust-analyzer"
            echo "Network access for cargo is enabled."
            echo ""
          '';
        };
      }
    );
}