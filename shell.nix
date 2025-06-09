{
  pkgs ? import <nixpkgs> { },
}:

pkgs.mkShell.override
  {
    stdenv = pkgs.stdenvAdapters.useMoldLinker pkgs.clangStdenv;
  }
  {
    buildInputs = with pkgs; [
      rustup
      pkg-config
      nodejs
      samply

      mold # speeds up linking
    ];
  }
