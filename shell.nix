let
  # Pinned nixpkgs, deterministic.
  pkgs = import (fetchTarball("https://github.com/NixOS/nixpkgs/archive/8966c43feba2c701ed624302b6a935f97bcbdf88.tar.gz")) {};

in pkgs.mkShell {
  buildInputs = with pkgs; [
    cargo
    rustc
    rustfmt
    rust-analyzer
    clippy
    postgresql
  ];

  # Certain Rust tools won't work without this
  # This can also be fixed by using oxalica/rust-overlay and specifying the rust-src extension
  # See https://discourse.nixos.org/t/rust-src-not-found-and-other-misadventures-of-developing-rust-on-nixos/11570/3?u=samuela. for more details.
  RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";
}
