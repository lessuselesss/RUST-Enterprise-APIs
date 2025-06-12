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

        # Define common C dependencies here
        commonCDependencies = with pkgs; [
          openssl
          pkg-config
          libclang
        ];

      in
      {
        devShells.default = pkgs.mkShell {
          # Allow network access for cargo and integration tests
          __noChroot = true;

          # nativeBuildInputs are for build-time tools
          nativeBuildInputs = with pkgs; [
            # Rust toolchain and development tools
            rustToolchain
            rust-analyzer
            cargo-watch

            # C/C++ build tools
            clang
            gcc
            gnumake
            gpp
            bison
            flex
            libiconv
            autoconf
            automake
            makeWrapper
          ];

          # buildInputs are for runtime dependencies
          buildInputs = commonCDependencies;

          # This hook runs when you enter the shell
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