{
  pkgs ? import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/nixos-unstable.tar.gz") { },
}:

pkgs.mkShell {
  buildInputs = with pkgs; [
    gdb
    rustc
    cargo
    rust-analyzer
    rustfmt
    clippy
  ];
}
