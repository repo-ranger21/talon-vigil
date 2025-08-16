{ pkgs }: {
  deps = [
    pkgs.python311Full
    pkgs.replitPackages.prybar-python311
    pkgs.replitPackages.stderred
    pkgs.libxml2
    pkgs.libxslt
    pkgs.zlib
    pkgs.pkg-config
    pkgs.postgresql
  ];
  env = {
    PYTHON_LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [
      pkgs.libxml2
      pkgs.libxslt
      pkgs.zlib
    ];
    PYTHONHOME = "${pkgs.python311Full}";
    PYTHONBIN = "${pkgs.python311Full}/bin/python3.11";
    LANG = "en_US.UTF-8";
  };
}