{ pkgs ? import (fetchTarball
  "https://github.com/NixOS/nixpkgs/archive/nixos-unstable.tar.gz") { } }:

pkgs.mkShell {
  buildInputs = with pkgs; [ rustc cargo rust-analyzer rustfmt clippy ];
}
