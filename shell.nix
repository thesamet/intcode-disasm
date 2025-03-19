{
  pkgs ? import <nixpkgs> { },
}:
pkgs.mkShell rec {
  buildInputs = with pkgs; [
    rustup
    pkg-config
    openssl
    aoc-cli
  ];
}
