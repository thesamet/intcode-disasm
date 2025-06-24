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
      playwright-driver.browsers
      playwright-test
      playwright

      mold # speeds up linking
    ];
    shellHook = ''
      export PLAYWRIGHT_BROWSERS_PATH=${pkgs.playwright-driver.browsers}
      export PLAYWRIGHT_SKIP_VALIDATE_HOST_REQUIREMENTS=true
    '';
  }
